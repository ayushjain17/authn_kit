//! Browser-session authentication from a cookie.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;

use crate::{
    authenticator::{AuthContext, AuthProfile, Authenticator},
    error::AuthError,
    oidc::{IdTokenCodec, LoginFlow, NonceCheck, OidcProvider, SessionCodec},
    outcome::Verdict,
    scope::AuthScope,
};

/// Authenticates a request from its session cookie.
///
/// The cookie's name comes from
/// [`AuthScope::session_cookie_name`](crate::scope::AuthScope::session_cookie_name),
/// reproducing the original's cookie-per-scope naming (`user`, `org_<id>`).
///
/// ## Position in the chain
///
/// This belongs **last**. When configured to challenge, it is the only
/// authenticator that turns an *absent* credential into a response, which is
/// precisely the role the original's `.unwrap_or_else(|| authenticate(...))`
/// played at the end of its dispatch.
pub struct SessionAuthenticator<P: AuthProfile, C: SessionCodec = IdTokenCodec> {
    provider: Arc<OidcProvider>,
    codec: C,
    /// When present, an unauthenticated browser navigation is redirected into
    /// the login flow instead of being refused. When absent, this authenticator
    /// declines and the gateway returns `401` — the right behaviour for a
    /// service with no interactive login.
    login: Option<Arc<LoginFlow<C>>>,
    profile: PhantomData<P>,
}

impl<P: AuthProfile> SessionAuthenticator<P, IdTokenCodec> {
    pub fn new(provider: Arc<OidcProvider>) -> Self {
        Self::with_codec(provider, IdTokenCodec)
    }
}

impl<P: AuthProfile, C: SessionCodec> SessionAuthenticator<P, C> {
    pub fn with_codec(provider: Arc<OidcProvider>, codec: C) -> Self {
        Self {
            provider,
            codec,
            login: None,
            profile: PhantomData,
        }
    }

    /// Redirects unauthenticated browser navigations into `login`.
    pub fn with_login_redirect(mut self, login: Arc<LoginFlow<C>>) -> Self {
        self.login = Some(login);
        self
    }

    /// Builds a redirect into the login flow, returning the user to where they
    /// were.
    ///
    /// Only for `GET`: redirecting a `POST` into a login round-trip silently
    /// discards the request body, since the browser returns from the provider
    /// with a `GET`. The original redirected any method, so an expired session
    /// turned a mutation into a no-op that looked like a success.
    fn challenge(&self, ctx: &AuthContext<'_, P>, fallback: AuthError) -> AuthError {
        let Some(login) = &self.login else {
            return fallback;
        };
        if ctx.request.method() != "GET" {
            return fallback;
        }

        let mut destination = ctx.request.path().to_string();
        if !ctx.request.query().is_empty() {
            destination.push('?');
            destination.push_str(ctx.request.query());
        }

        match login.authorize(&destination) {
            Ok(redirect) => AuthError::redirect(redirect.location, redirect.cookies),
            Err(error) => error,
        }
    }
}

#[async_trait]
impl<P: AuthProfile, C: SessionCodec> Authenticator<P> for SessionAuthenticator<P, C> {
    fn name(&self) -> &'static str {
        "session"
    }

    async fn authenticate(
        &self,
        ctx: &AuthContext<'_, P>,
    ) -> Result<Verdict<P::User>, AuthError> {
        let cookie_name = ctx.scope.session_cookie_name();

        let Some(raw) = ctx.request.cookie(&cookie_name) else {
            // A client presenting some other credential is doing API
            // authentication; it is not this authenticator's request to answer,
            // and must never be redirected into an interactive login.
            if !ctx.credential.is_none() {
                return Ok(Verdict::NotApplicable);
            }
            return Err(
                self.challenge(ctx, AuthError::unauthenticated("no session cookie"))
            );
        };

        let session = match self.codec.decode(raw) {
            Ok(session) => session,
            Err(error) => return Err(self.challenge(ctx, error)),
        };

        // `Present` rather than a value match: the nonce this token was minted
        // with belonged to a login attempt that completed long ago. Requiring
        // its presence still rejects tokens minted outside an authorization
        // request, which is what the original's `verify_presence` checked.
        match self
            .provider
            .verify_id_token(&session.id_token, NonceCheck::Present)
            .await
        {
            Ok(claims) => P::User::try_from(claims)
                .map(Verdict::Authenticated)
                .map_err(|e| {
                    AuthError::internal(format!("session identity conversion: {e}"))
                }),
            // An expired or otherwise unusable session is a re-login, not a dead
            // end — but only for a navigation, and only if a login flow exists.
            Err(error) if error.status() == 401 => Err(self.challenge(ctx, error)),
            Err(error) => Err(error),
        }
    }
}
