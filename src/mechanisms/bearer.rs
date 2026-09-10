//! `Authorization: Bearer <jwt>` validated as an OIDC ID token.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use secrecy::ExposeSecret;

use crate::{
    authenticator::{AuthContext, AuthProfile, Authenticator},
    credential::Credential,
    error::AuthError,
    oidc::{NonceCheck, OidcProvider},
    outcome::Verdict,
};

/// Whether a compact JWS has the three non-empty dot-separated segments RFC 7515
/// §3.1 requires.
///
/// This check is what keeps chain order irrelevant. An API key, an opaque
/// session handle or a random string is **declined**, not rejected, so this
/// authenticator can sit either side of a mechanism that also claims `Bearer`
/// without changing any outcome. The original achieved the same separation by
/// checking the API-token prefix inside `process_bearer_token`.
fn is_compact_jws(token: &str) -> bool {
    let mut segments = token.split('.');
    let has_three = matches!(
        (segments.next(), segments.next(), segments.next(), segments.next()),
        (Some(a), Some(b), Some(c), None)
            if !a.is_empty() && !b.is_empty() && !c.is_empty()
    );
    has_three
}

/// Validates a bearer ID token against the OIDC provider.
pub struct BearerAuthenticator<P: AuthProfile> {
    provider: Arc<OidcProvider>,
    profile: PhantomData<P>,
}

impl<P: AuthProfile> BearerAuthenticator<P> {
    pub fn new(provider: Arc<OidcProvider>) -> Self {
        Self {
            provider,
            profile: PhantomData,
        }
    }
}

impl<P: AuthProfile> std::fmt::Debug for BearerAuthenticator<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerAuthenticator")
    }
}

#[async_trait]
impl<P: AuthProfile> Authenticator<P> for BearerAuthenticator<P> {
    fn name(&self) -> &'static str {
        "bearer"
    }

    async fn authenticate(
        &self,
        ctx: &AuthContext<'_, P>,
    ) -> Result<Verdict<P::User>, AuthError> {
        let Credential::Bearer(token) = ctx.credential else {
            return Ok(Verdict::NotApplicable);
        };
        let token = token.expose_secret();
        if !is_compact_jws(token) {
            return Ok(Verdict::NotApplicable);
        }

        // Unlike the original's synchronous bearer path, this can refresh the
        // provider's keys and retry, so a JWKS rotation no longer invalidates
        // every outstanding token until the process restarts.
        let claims = self
            .provider
            .verify_id_token(token, NonceCheck::Present)
            .await?;

        P::User::try_from(claims)
            .map(Verdict::Authenticated)
            .map_err(|e| AuthError::internal(format!("bearer identity conversion: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::is_compact_jws;

    /// The guard that keeps chain order irrelevant: anything that is not a
    /// compact JWS must be declined by this authenticator, never rejected, so it
    /// can sit either side of another mechanism that also claims `Bearer`.
    #[test]
    fn jwt_shape_detection_is_strict() {
        assert!(is_compact_jws("header.payload.signature"));
        assert!(is_compact_jws("a.b.c"));

        for not_a_jwt in [
            "sptok_abc123", // an API key
            "opaque-token", // an opaque session handle
            "a.b",          // two segments
            "a.b.c.d",      // four segments
            "a..c",         // empty middle segment
            ".b.c",
            "a.b.",
            "",
        ] {
            assert!(!is_compact_jws(not_a_jwt), "accepted {not_a_jwt:?}");
        }
    }
}
