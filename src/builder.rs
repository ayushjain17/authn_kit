//! Assembling a gateway from a scope resolver and a set of authenticators.

use crate::{
    authenticator::{AuthChain, AuthProfile, Authenticator, PublicScopePolicy},
    error::AuthError,
    gateway::AuthGateway,
    scope::ScopeResolver,
};

/// Builds an [`AuthGateway`].
///
/// The pieces can be assembled directly — `AuthGateway::new(scopes,
/// AuthChain::new().with(a).with(b))` — and that stays supported. This flattens
/// the nesting and adds one thing the manual form cannot: a build-time check
/// that the chain can actually authenticate something.
///
/// ```
/// # use authn_kit::{AuthProfile, AuthnBuilder, DisabledAuthenticator, SingleScope};
/// # use authn_kit::{claims::IdentityClaims, scope::NoScope};
/// # #[derive(Clone)] struct User;
/// # impl TryFrom<IdentityClaims> for User {
/// #     type Error = String;
/// #     fn try_from(_: IdentityClaims) -> Result<Self, String> { Ok(User) }
/// # }
/// # struct MyApp;
/// # impl AuthProfile for MyApp { type User = User; type Scope = NoScope; }
/// let gateway = AuthnBuilder::<MyApp, _>::new(SingleScope)
///     .with(DisabledAuthenticator::development())
///     .build()
///     .unwrap();
///
/// assert_eq!(gateway.authenticator_names(), vec!["disabled"]);
/// ```
pub struct AuthnBuilder<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> {
    scopes: R,
    chain: AuthChain<P>,
}

impl<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> AuthnBuilder<P, R> {
    pub fn new(scopes: R) -> Self {
        Self {
            scopes,
            chain: AuthChain::new(),
        }
    }

    /// Appends an authenticator. Registration order is the order they are
    /// consulted.
    ///
    /// A session authenticator configured to redirect should be registered
    /// **last**: it is the only kind that turns an *absent* credential into a
    /// response, which is the role the original's trailing
    /// `.unwrap_or_else(|| authenticate(...))` played.
    pub fn with(mut self, authenticator: impl Authenticator<P>) -> Self {
        self.chain = self.chain.with(authenticator);
        self
    }

    /// Appends an authenticator only when `condition` holds.
    ///
    /// For the common shape where a mechanism is enabled by configuration —
    /// `.with_if(static_tokens_configured, api_token_authenticator)`.
    pub fn with_if(self, condition: bool, authenticator: impl Authenticator<P>) -> Self {
        if condition {
            self.with(authenticator)
        } else {
            self
        }
    }

    /// How requests to a scope reporting
    /// [`is_public`](crate::scope::AuthScope::is_public) are treated.
    pub fn public_scope_policy(mut self, policy: PublicScopePolicy) -> Self {
        self.chain = self.chain.public_scope_policy(policy);
        self
    }

    /// Finishes the gateway.
    ///
    /// Fails when no authenticator was registered. An empty chain would refuse
    /// every request on a protected scope, which is never what the caller meant
    /// and is otherwise only discovered in production.
    pub fn build(self) -> Result<AuthGateway<P, R>, AuthError> {
        if self.chain.is_empty() {
            return Err(AuthError::internal(
                "no authenticators registered: the gateway would refuse every \
                 request on a protected scope",
            ));
        }
        Ok(AuthGateway::new(self.scopes, self.chain))
    }
}
