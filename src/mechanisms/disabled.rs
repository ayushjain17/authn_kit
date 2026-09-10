//! An authenticator that authenticates everything, for local development.

use std::marker::PhantomData;

use async_trait::async_trait;

use crate::{
    authenticator::{AuthContext, AuthProfile, Authenticator},
    claims::{ClaimSource, IdentityClaims},
    error::AuthError,
    outcome::Verdict,
};

/// Resolves every request to a fixed identity.
///
/// The replacement for the original `DisabledAuthenticator`, with one
/// difference: the identity is **supplied by the caller** rather than being
/// `User::default()`. The original's default — `user@superposition.io` — looked
/// exactly like a real signed-in user everywhere downstream, so a service
/// accidentally deployed with `AUTH_PROVIDER=DISABLED` would authorise requests
/// under a plausible-looking identity with nothing in the logs to distinguish
/// it.
///
/// Register it only behind an explicit configuration switch. It performs no
/// authentication whatsoever.
pub struct DisabledAuthenticator<P: AuthProfile> {
    claims: IdentityClaims,
    profile: PhantomData<P>,
}

impl<P: AuthProfile> DisabledAuthenticator<P> {
    /// Authenticates every request as the identity described by `claims`.
    pub fn new(claims: IdentityClaims) -> Self {
        Self {
            claims,
            profile: PhantomData,
        }
    }

    /// A conspicuously-named development identity.
    ///
    /// The name is deliberate: if this reaches a real environment, it should be
    /// obvious in audit logs rather than blend in.
    pub fn development() -> Self {
        Self::new(
            IdentityClaims::new(ClaimSource::StaticToken)
                .with_subject("authn-disabled")
                .with_preferred_username("authn-disabled")
                .with_email("authn-disabled@invalid"),
        )
    }
}

impl<P: AuthProfile> std::fmt::Debug for DisabledAuthenticator<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisabledAuthenticator")
            .field("subject", &self.claims.subject)
            .finish()
    }
}

#[async_trait]
impl<P: AuthProfile> Authenticator<P> for DisabledAuthenticator<P> {
    fn name(&self) -> &'static str {
        "disabled"
    }

    async fn authenticate(
        &self,
        _ctx: &AuthContext<'_, P>,
    ) -> Result<Verdict<P::User>, AuthError> {
        P::User::try_from(self.claims.clone())
            .map(Verdict::Authenticated)
            .map_err(|e| {
                AuthError::internal(format!(
                    "disabled-auth identity could not be converted: {e}"
                ))
            })
    }
}
