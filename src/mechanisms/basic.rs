//! `Authorization: Basic` exchanged with the provider's token endpoint.
//!
//! Two grants sit behind the same header, selected by `X-Grant-Type` exactly as
//! the original did: absent means `client_credentials`, `password` means ROPC,
//! anything else is a `400`.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use openidconnect::{
    ClientId, ClientSecret, OAuth2TokenResponse, ResourceOwnerPassword,
    ResourceOwnerUsername, TokenResponse,
};
use secrecy::ExposeSecret;

use crate::{
    authenticator::{AuthContext, AuthProfile, Authenticator},
    cache::{CacheConfig, CredentialCache},
    claims::{ClaimSource, IdentityClaims},
    credential::Credential,
    error::AuthError,
    oidc::{NonceCheck, OidcProvider},
    outcome::Verdict,
    scope::AuthScope,
};

/// The header selecting which grant a `Basic` pair is validated under.
pub const GRANT_TYPE_HEADER: &str = "x-grant-type";

/// Validates a `Basic` credential by exchanging it at the token endpoint.
pub struct BasicAuthenticator<P: AuthProfile> {
    provider: Arc<OidcProvider>,
    cache: CredentialCache<P::User>,
    allow_password_grant: bool,
    profile: PhantomData<P>,
}

impl<P: AuthProfile> BasicAuthenticator<P> {
    /// Enables the `client_credentials` grant only.
    ///
    /// The resource-owner password grant is **off by default**, unlike the
    /// original. OAuth 2.1 removes it: it requires the client to handle the
    /// user's password directly, which defeats federated login, blocks MFA, and
    /// many providers (Google among them) reject it outright. Enable it with
    /// [`Self::with_password_grant`] only for a provider and deployment that
    /// genuinely need it.
    pub fn new(provider: Arc<OidcProvider>) -> Self {
        Self {
            provider,
            cache: CredentialCache::default(),
            allow_password_grant: false,
            profile: PhantomData,
        }
    }

    pub fn with_password_grant(mut self, allow: bool) -> Self {
        self.allow_password_grant = allow;
        self
    }

    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache = CredentialCache::new(config);
        self
    }

    async fn password_grant(
        &self,
        ctx: &AuthContext<'_, P>,
        id: &str,
        secret: &str,
    ) -> Result<P::User, AuthError> {
        let key = CredentialCache::<P::User>::key(
            ctx.scope.cache_discriminator(),
            "basic-password",
            id,
            secret,
        );
        if let Some(user) = self.cache.get(&key) {
            return Ok(user);
        }

        let state = self.provider.snapshot();
        // `exchange_password` borrows both, so they must outlive the request.
        let username = ResourceOwnerUsername::new(id.to_string());
        let password = ResourceOwnerPassword::new(secret.to_string());
        let mut request = state
            .client()
            .exchange_password(&username, &password)
            .map_err(|e| {
                AuthError::internal(format!("provider advertises no token endpoint: {e}"))
            })?;
        for scope in self.provider.config().scopes() {
            request = request.add_scope(scope.clone());
        }

        let response = request.request_async(self.provider.http_client()).await?;
        let expires_in = response.expires_in();
        let id_token = response
            .id_token()
            .ok_or_else(|| AuthError::upstream("token response carried no id_token"))?
            .to_string();

        // `Skip`: a password-grant token is minted outside an authorization
        // request, so there is no nonce for it to carry.
        let claims = self
            .provider
            .verify_id_token(&id_token, NonceCheck::Skip)
            .await?;
        let user = P::User::try_from(claims).map_err(|e| {
            AuthError::internal(format!("password-grant identity conversion: {e}"))
        })?;

        self.cache.insert(key, user.clone(), expires_in);
        Ok(user)
    }

    async fn client_credentials_grant(
        &self,
        ctx: &AuthContext<'_, P>,
        id: &str,
        secret: &str,
    ) -> Result<P::User, AuthError> {
        let key = CredentialCache::<P::User>::key(
            ctx.scope.cache_discriminator(),
            "basic-client-credentials",
            id,
            secret,
        );
        if let Some(user) = self.cache.get(&key) {
            return Ok(user);
        }

        // The exchange must run as *the caller's* client, not ours: that is what
        // proves their credentials.
        let client = self.provider.machine_client(
            ClientId::new(id.to_string()),
            ClientSecret::new(secret.to_string()),
        );
        // No scopes are requested, matching the original. A machine grant needs
        // none to prove the credentials, and providers differ on whether they
        // reject scopes a machine client has not been consented for.
        let response = client
            .exchange_client_credentials()
            .map_err(|e| {
                AuthError::internal(format!("provider advertises no token endpoint: {e}"))
            })?
            .request_async(self.provider.http_client())
            .await?;

        // There is no user identity in a machine grant; the validated `client_id`
        // *is* the principal. The original invented `service-account-<id>` here.
        // Emitting the raw client id instead leaves that naming decision to the
        // application's `TryFrom`, where it belongs.
        let claims = IdentityClaims::new(ClaimSource::ClientCredentials)
            .with_subject(id)
            .with_client_id(id)
            .with_preferred_username(id);
        let user = P::User::try_from(claims).map_err(|e| {
            AuthError::internal(format!("client-credentials identity conversion: {e}"))
        })?;

        self.cache.insert(key, user.clone(), response.expires_in());
        Ok(user)
    }
}

impl<P: AuthProfile> std::fmt::Debug for BasicAuthenticator<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuthenticator")
            .field("password_grant", &self.allow_password_grant)
            .field("cached", &self.cache.len())
            .finish()
    }
}

#[async_trait]
impl<P: AuthProfile> Authenticator<P> for BasicAuthenticator<P> {
    fn name(&self) -> &'static str {
        "basic"
    }

    async fn authenticate(
        &self,
        ctx: &AuthContext<'_, P>,
    ) -> Result<Verdict<P::User>, AuthError> {
        let Credential::Basic { id, secret } = ctx.credential else {
            return Ok(Verdict::NotApplicable);
        };
        let secret = secret.expose_secret();

        let user = match ctx.request.header(GRANT_TYPE_HEADER) {
            None | Some("client_credentials") => {
                self.client_credentials_grant(ctx, id, secret).await?
            }
            Some("password") if self.allow_password_grant => {
                self.password_grant(ctx, id, secret).await?
            }
            Some("password") => {
                return Err(AuthError::unsupported(
                    "the resource-owner password grant is not enabled",
                ));
            }
            Some(other) => {
                return Err(AuthError::malformed_credential(format!(
                    "unsupported {GRANT_TYPE_HEADER}: {other}"
                )));
            }
        };

        Ok(Verdict::Authenticated(user))
    }
}
