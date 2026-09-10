//! The authenticator trait and the chain that composes several of them.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    claims::Principal,
    credential::Credential,
    error::AuthError,
    outcome::{Outcome, Verdict},
    request::AuthRequest,
    scope::AuthScope,
};

/// Binds an application's user type and scope type together, so every other
/// generic in this crate takes a single parameter instead of two.
///
/// ```
/// use authn_kit::{AuthProfile, claims::IdentityClaims, scope::NoScope};
/// # #[derive(Clone)] struct User;
/// # impl TryFrom<IdentityClaims> for User {
/// #     type Error = String;
/// #     fn try_from(_: IdentityClaims) -> Result<Self, String> { Ok(User) }
/// # }
/// struct MyApp;
///
/// impl AuthProfile for MyApp {
///     type User = User;
///     type Scope = NoScope;
/// }
/// ```
pub trait AuthProfile: Send + Sync + 'static {
    /// The application's authenticated user type. Satisfied automatically by
    /// any `Clone + Send + Sync` type implementing `TryFrom<IdentityClaims>`.
    type User: Principal;
    /// The application's request-scope type.
    type Scope: AuthScope;
}

/// Everything an authenticator gets to decide with.
pub struct AuthContext<'a, P: AuthProfile> {
    /// The request, minus its body.
    pub request: &'a AuthRequest,
    /// The credential presented on the `Authorization` header, if any. Session
    /// cookies are reached through `request`.
    pub credential: &'a Credential,
    /// The scope this request targets.
    pub scope: &'a P::Scope,
}

impl<'a, P: AuthProfile> AuthContext<'a, P> {
    pub fn new(
        request: &'a AuthRequest,
        credential: &'a Credential,
        scope: &'a P::Scope,
    ) -> Self {
        Self {
            request,
            credential,
            scope,
        }
    }
}

/// One authentication mechanism.
///
/// Implementations are expected to be cheap to call and to return
/// [`Verdict::NotApplicable`] promptly for credentials they do not handle, since
/// every authenticator in a chain may be consulted.
///
/// Note the return type: an authenticator can resolve a principal, decline, or
/// fail — but it cannot declare a request anonymous. That judgement belongs to
/// the scope, and so to [`AuthChain`], which is what keeps a single
/// authenticator from waving requests past a protected route.
#[async_trait]
pub trait Authenticator<P: AuthProfile>: Send + Sync + 'static {
    /// A stable identifier used in logs and diagnostics.
    fn name(&self) -> &'static str;

    /// Examines the request and either resolves a principal, declines, or fails.
    ///
    /// Returning `Err` is *terminal* for the chain — see [`AuthChain`].
    async fn authenticate(
        &self,
        ctx: &AuthContext<'_, P>,
    ) -> Result<Verdict<P::User>, AuthError>;
}

/// How a chain treats a request whose scope reports
/// [`AuthScope::is_public`](crate::scope::AuthScope::is_public).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PublicScopePolicy {
    /// Attempt authentication anyway. A request with no credential is
    /// `Anonymous`; one carrying a *valid* credential is authenticated, so
    /// handlers on public routes can personalise their response; one carrying an
    /// *invalid* credential still fails, so a bad token is never silently
    /// downgraded to anonymous.
    #[default]
    Optional,
    /// Short-circuit to [`Outcome::Anonymous`] without consulting any
    /// authenticator. This reproduces the original's `Login::None` handling,
    /// which returned immediately without inspecting the credential.
    AlwaysAnonymous,
}

/// An ordered list of authenticators, consulted until one claims the request.
///
/// This replaces the original middleware's inline `match` over
/// `Internal`/`Bearer`/`Basic` plus its `api_token_prefix()` callback. Adding a
/// mechanism is now adding an element to this list rather than editing the
/// middleware.
///
/// ## Resolution order
///
/// Authenticators are consulted in registration order. The first to return
/// [`Verdict::Authenticated`] decides the request. An `Err` from any
/// authenticator ends the chain immediately and is returned as-is: the chain
/// **fails closed**, so a rejected `Bearer` token can never fall through to a
/// weaker mechanism.
pub struct AuthChain<P: AuthProfile> {
    authenticators: Vec<Arc<dyn Authenticator<P>>>,
    public_scope_policy: PublicScopePolicy,
}

impl<P: AuthProfile> Default for AuthChain<P> {
    fn default() -> Self {
        Self {
            authenticators: Vec::new(),
            public_scope_policy: PublicScopePolicy::default(),
        }
    }
}

impl<P: AuthProfile> AuthChain<P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an authenticator. Order is significant.
    pub fn with(mut self, authenticator: impl Authenticator<P>) -> Self {
        self.authenticators.push(Arc::new(authenticator));
        self
    }

    /// Appends an already-shared authenticator.
    pub fn with_arc(mut self, authenticator: Arc<dyn Authenticator<P>>) -> Self {
        self.authenticators.push(authenticator);
        self
    }

    pub fn public_scope_policy(mut self, policy: PublicScopePolicy) -> Self {
        self.public_scope_policy = policy;
        self
    }

    /// The registered authenticators, in order, by name.
    pub fn names(&self) -> Vec<&'static str> {
        self.authenticators.iter().map(|a| a.name()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.authenticators.is_empty()
    }

    /// Runs the chain.
    ///
    /// Returns [`Outcome::NotApplicable`] when no authenticator claimed the
    /// request; callers decide whether that is a `401` or an anonymous request.
    pub async fn authenticate(
        &self,
        request: &AuthRequest,
        credential: &Credential,
        scope: &P::Scope,
    ) -> Result<Outcome<P::User>, AuthError> {
        let is_public = scope.is_public();

        if is_public {
            match self.public_scope_policy {
                PublicScopePolicy::AlwaysAnonymous => return Ok(Outcome::Anonymous),
                PublicScopePolicy::Optional if credential.is_none() => {
                    return Ok(Outcome::Anonymous);
                }
                PublicScopePolicy::Optional => {}
            }
        }

        let ctx = AuthContext::new(request, credential, scope);
        for authenticator in &self.authenticators {
            match authenticator.authenticate(&ctx).await? {
                Verdict::NotApplicable => continue,
                Verdict::Authenticated(user) => return Ok(Outcome::Authenticated(user)),
            }
        }

        // Nothing claimed the request. On a public scope that is simply an
        // anonymous visitor; elsewhere the caller turns it into a challenge.
        if is_public {
            return Ok(Outcome::Anonymous);
        }
        Ok(Outcome::NotApplicable)
    }
}
