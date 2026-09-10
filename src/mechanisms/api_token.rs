//! API-token authentication: `Authorization: Bearer <prefix><key>`.
//!
//! Two mechanisms behind one prefix, tried in order, exactly as the original's
//! `ApiTokenConfig` did:
//!
//! 1. **Static tokens** — a configured list, compared in constant time. No
//!    network, no cryptography beyond the comparison.
//! 2. **A [`TokenValidator`] fallback** — anything that can turn an unrecognised
//!    key into claims. The `introspection` feature ships an RFC 7662
//!    implementation; a database-backed one would fit equally well.
//!
//! The static half lives in core with no heavy dependencies. In the original all
//! of this lived inside the OIDC authenticator, constructed *after*
//! `fetch_provider_metadata().await?` — so an identity provider unreachable at
//! boot panicked the process and took static tokens down with it, when they are
//! the one credential you would most want to survive an IdP outage.

use std::{
    collections::HashSet,
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::{
    authenticator::{AuthContext, AuthProfile, Authenticator},
    cache::{CacheConfig, CredentialCache},
    claims::{ClaimSource, IdentityClaims},
    credential::Credential,
    error::AuthError,
    outcome::Verdict,
    scope::AuthScope,
};

/// Default cap on how long a validated API key stays cached, regardless of the
/// expiry the validator reports.
///
/// Remote validation exists so revocation takes effect quickly, so caching is
/// capped to keep revocation lag small even for long-lived tokens.
pub const DEFAULT_MAX_CACHE_TTL: Duration = Duration::from_secs(300);

/// Validates an API key that carried the configured prefix but matched no static
/// token.
///
/// Keeps the HTTP-bearing part of API-token authentication out of core: the
/// authenticator holds a `dyn TokenValidator`, and the `introspection` feature
/// supplies one.
#[async_trait]
pub trait TokenValidator: Send + Sync + 'static {
    /// A stable name, used in cache keys and logs.
    fn name(&self) -> &'static str;

    /// Resolves `api_key` to claims, or explains why it is not valid.
    ///
    /// `scope` is the request scope's discriminator, for validators that are
    /// realm-aware.
    async fn validate(
        &self,
        api_key: &str,
        scope: Option<&str>,
    ) -> Result<IdentityClaims, AuthError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StaticTokenError {
    #[error(
        "static token list must be a JSON array of \
         {{\"token\", \"principal\"[, \"email\", \"scopes\"]}}: {0}"
    )]
    Malformed(String),
    #[error("static token prefix must not be empty")]
    EmptyPrefix,
    #[error("static token for principal {0:?} has an empty token value")]
    EmptyToken(String),
}

/// One entry of the configured token list, as it appears in JSON.
#[derive(Debug, Deserialize)]
pub struct StaticTokenSpec {
    /// The secret presented as the API key, after the prefix is stripped.
    pub token: String,
    /// The identity to authenticate as.
    pub principal: String,
    /// Optional email; defaults to `principal`.
    #[serde(default)]
    pub email: Option<String>,
    /// Scopes this token is valid for, matched against
    /// [`AuthScope::cache_discriminator`]. `None` means every scope.
    ///
    /// Generalises the original's SaaS-only `org` field, which was inert in the
    /// single-realm configuration and could hold only one value.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

struct StaticToken {
    secret: SecretString,
    claims: IdentityClaims,
    scopes: Option<HashSet<String>>,
}

impl StaticToken {
    /// Whether this token may be used for `scope`. A token with no scope list is
    /// valid everywhere; otherwise the scope's discriminator must be listed.
    fn permits(&self, scope: Option<&str>) -> bool {
        match (&self.scopes, scope) {
            (None, _) => true,
            (Some(allowed), Some(scope)) => allowed.contains(scope),
            (Some(_), None) => false,
        }
    }

    /// Constant-time comparison, so response timing does not reveal how many
    /// leading bytes of a guess were correct.
    ///
    /// Length is not hidden — `ct_eq` requires equal lengths — but token values
    /// are high-entropy secrets, so leaking a length reveals nothing usable.
    fn matches(&self, candidate: &str) -> bool {
        let expected = self.secret.expose_secret().as_bytes();
        let candidate = candidate.as_bytes();
        expected.len() == candidate.len() && bool::from(expected.ct_eq(candidate))
    }
}

/// Authenticates `Authorization: Bearer <prefix><key>`.
///
/// ## Why the prefix is required
///
/// This authenticator and an OIDC bearer authenticator both claim the `Bearer`
/// scheme. The prefix is what tells them apart, so the chain's outcome does not
/// depend on registration order: a prefixed token is unambiguously an API token,
/// and an unprefixed one is unambiguously not.
///
/// The original achieved the same disambiguation inside `process_bearer_token`
/// via the authenticator's `api_token_prefix()` callback; making the prefix
/// mandatory here preserves that property without the trait method.
pub struct ApiTokenAuthenticator<P: AuthProfile> {
    prefix: String,
    tokens: Vec<StaticToken>,
    fallback: Option<Arc<dyn TokenValidator>>,
    cache: CredentialCache<P::User>,
    max_cache_ttl: Duration,
    profile: PhantomData<P>,
}

impl<P: AuthProfile> ApiTokenAuthenticator<P> {
    /// Builds from the token list, e.g. a secret decrypted from a KMS.
    ///
    /// A malformed list is an error rather than a warning, so a configuration
    /// mistake fails startup instead of silently disabling authentication —
    /// matching the original's `parse_static_tokens`.
    pub fn new(
        prefix: impl Into<String>,
        specs: Vec<StaticTokenSpec>,
    ) -> Result<Self, StaticTokenError> {
        let prefix = prefix.into();
        if prefix.is_empty() {
            return Err(StaticTokenError::EmptyPrefix);
        }

        let tokens = specs
            .into_iter()
            .map(|spec| {
                if spec.token.is_empty() {
                    return Err(StaticTokenError::EmptyToken(spec.principal));
                }
                let email = spec.email.unwrap_or_else(|| spec.principal.clone());
                let claims = IdentityClaims::new(ClaimSource::StaticToken)
                    .with_subject(spec.principal.clone())
                    .with_preferred_username(spec.principal)
                    .with_email(email);

                Ok(StaticToken {
                    secret: SecretString::from(spec.token),
                    claims,
                    scopes: spec.scopes.map(|s| s.into_iter().collect()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            prefix,
            tokens,
            fallback: None,
            cache: CredentialCache::default(),
            max_cache_ttl: DEFAULT_MAX_CACHE_TTL,
            profile: PhantomData,
        })
    }

    /// Adds a validator consulted when no static token matches.
    ///
    /// Without one, an unrecognised key carrying the prefix is rejected
    /// outright; with one, it falls through — which is what the original did
    /// between its static list and RFC 7662 introspection.
    pub fn with_fallback(mut self, validator: Arc<dyn TokenValidator>) -> Self {
        self.fallback = Some(validator);
        self
    }

    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache = CredentialCache::new(config);
        self
    }

    /// Caps how long a fallback-validated key stays cached, regardless of the
    /// expiry the validator reports. Remote validation exists so revocation
    /// takes effect quickly, so the cache must not outlive that intent.
    pub fn with_max_cache_ttl(mut self, ttl: Duration) -> Self {
        self.max_cache_ttl = ttl;
        self
    }

    /// Time until `expires_at`, capped at the configured maximum. `None` when
    /// the validator reported no expiry, leaving the cache its own fallback.
    fn cache_ttl(&self, expires_at: Option<SystemTime>) -> Option<Duration> {
        let remaining = expires_at?.duration_since(SystemTime::now()).ok()?;
        Some(remaining.min(self.max_cache_ttl))
    }

    /// Builds from the JSON array the original stored in
    /// `OIDC_API_STATIC_TOKENS`. A blank value yields no tokens.
    pub fn from_json(
        prefix: impl Into<String>,
        json: &str,
    ) -> Result<Self, StaticTokenError> {
        let json = json.trim();
        let specs = if json.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(json)
                .map_err(|e| StaticTokenError::Malformed(e.to_string()))?
        };
        Self::new(prefix, specs)
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

/// Shows the prefix and how many tokens are loaded, never the token values —
/// this is the type an operator would log at startup to confirm configuration.
impl<P: AuthProfile> std::fmt::Debug for ApiTokenAuthenticator<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiTokenAuthenticator")
            .field("prefix", &self.prefix)
            .field("static_tokens", &self.tokens.len())
            .field("fallback", &self.fallback.as_ref().map(|v| v.name()))
            .finish()
    }
}

#[async_trait]
impl<P: AuthProfile> Authenticator<P> for ApiTokenAuthenticator<P> {
    fn name(&self) -> &'static str {
        "static-token"
    }

    async fn authenticate(
        &self,
        ctx: &AuthContext<'_, P>,
    ) -> Result<Verdict<P::User>, AuthError> {
        let Credential::Bearer(token) = ctx.credential else {
            return Ok(Verdict::NotApplicable);
        };

        // Not carrying our prefix: this is somebody else's bearer token.
        let Some(key) = token.expose_secret().strip_prefix(self.prefix.as_str()) else {
            return Ok(Verdict::NotApplicable);
        };

        let scope = ctx.scope.cache_discriminator();
        let matched = self
            .tokens
            .iter()
            .find(|candidate| candidate.permits(scope) && candidate.matches(key));

        // A static hit needs no cache: the comparison is already local.
        if let Some(token) = matched {
            return P::User::try_from(token.claims.clone())
                .map(Verdict::Authenticated)
                .map_err(|e| {
                    AuthError::internal(format!(
                        "static token principal could not be converted: {e}"
                    ))
                });
        }

        let Some(validator) = &self.fallback else {
            // The prefix marked this as an API token, so it is a *bad* API token
            // rather than something a later authenticator might handle. Falling
            // through would have the next mechanism try to parse an API key as a
            // JWT and report a confusing error.
            return Err(AuthError::invalid_credential(
                "no static token matches the presented api key for this scope",
            ));
        };

        let cache_key = CredentialCache::<P::User>::key(scope, validator.name(), "", key);
        if let Some(user) = self.cache.get(&cache_key) {
            return Ok(Verdict::Authenticated(user));
        }

        let claims = validator.validate(key, scope).await?;
        let ttl = self.cache_ttl(claims.expires_at);
        let user = P::User::try_from(claims).map_err(|e| {
            AuthError::internal(format!(
                "api token principal could not be converted: {e}"
            ))
        })?;

        self.cache.insert(cache_key, user.clone(), ttl);
        Ok(Verdict::Authenticated(user))
    }
}
