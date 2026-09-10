//! The framework-agnostic middleware core.
//!
//! Everything a web framework's middleware must do — resolve the request's
//! scope, extract the credential, run the chain, decide what an unclaimed
//! request means — happens here, on owned data, in a `Send` future. A framework
//! adapter is then only a translation layer: native request in, [`AuthRequest`]
//! out; [`AuthError`] in, native response out.
//!
//! This is the split the original lacked. `AuthNMiddleware::call` interleaved
//! actix plumbing (`ServiceRequest`, `HttpResponse`, `LocalBoxFuture`,
//! `app_data::<Data<AppState>>().unwrap()`) with the dispatch logic, so none of
//! the logic could be tested — or reused — without actix.

use crate::{
    authenticator::{AuthChain, AuthProfile},
    credential::Credential,
    error::AuthError,
    outcome::Outcome,
    request::AuthRequest,
    scope::ScopeResolver,
};

/// Ties a [`ScopeResolver`] to an [`AuthChain`] and answers the one question a
/// middleware asks: *who, if anyone, is making this request?*
pub struct AuthGateway<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> {
    scopes: R,
    chain: AuthChain<P>,
}

/// Reports the registered mechanisms, which is what an operator wants in a
/// startup log line to confirm the chain is configured as intended.
impl<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> std::fmt::Debug
    for AuthGateway<P, R>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthGateway")
            .field("authenticators", &self.chain.names())
            .finish_non_exhaustive()
    }
}

impl<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> AuthGateway<P, R> {
    pub fn new(scopes: R, chain: AuthChain<P>) -> Self {
        Self { scopes, chain }
    }

    /// The registered authenticators, in order, by name. Useful for a
    /// startup-time log line and for the configuration checks in later phases.
    pub fn authenticator_names(&self) -> Vec<&'static str> {
        self.chain.names()
    }

    /// Resolves the request's scope without authenticating it.
    pub fn scope_of(&self, request: &AuthRequest) -> P::Scope {
        self.scopes.resolve(request)
    }

    /// Authenticates `request`, extracting the credential from its
    /// `Authorization` header.
    ///
    /// * `Ok(Some(user))` — authenticated.
    /// * `Ok(None)` — a public scope with no identity; the handler runs
    ///   anonymously.
    /// * `Err(_)` — rejected, or an unclaimed request on a protected scope.
    pub async fn authenticate(
        &self,
        request: &AuthRequest,
    ) -> Result<Option<P::User>, AuthError> {
        let credential = Credential::from_request(request);
        self.authenticate_with(request, &credential).await
    }

    /// As [`Self::authenticate`], with a credential the caller supplies. Lets an
    /// adapter source a credential from somewhere other than the `Authorization`
    /// header — a client certificate, say, or a bespoke header.
    pub async fn authenticate_with(
        &self,
        request: &AuthRequest,
        credential: &Credential,
    ) -> Result<Option<P::User>, AuthError> {
        let scope = self.scopes.resolve(request);

        match self.chain.authenticate(request, credential, &scope).await? {
            Outcome::Authenticated(user) => Ok(Some(user)),
            Outcome::Anonymous => Ok(None),
            // No authenticator claimed the request on a scope that requires one.
            // The chain only reports this for a non-public scope, so it is
            // always a challenge rather than an anonymous visit.
            Outcome::NotApplicable => Err(AuthError::unauthenticated(format!(
                "no authenticator claimed the request (scheme: {}, scope: {scope})",
                credential.scheme().unwrap_or("none"),
            ))),
        }
    }
}
