//! Static configuration for an OIDC provider.
//!
//! Every value is supplied by the caller. Nothing here reads the environment —
//! the original scattered `get_from_env_unsafe` and `get_from_env_or_default`
//! calls through the authenticator, the token cache and the API-token config,
//! which made the code untestable without a populated process environment and
//! meant a typo in a variable name surfaced as a panic at boot.

use std::time::Duration;

use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl, Scope};

/// Default minimum interval between provider-metadata refreshes.
///
/// Bounds how often a burst of verification failures can hit the issuer's
/// discovery endpoint. Identity providers rotate signing keys on the order of
/// hours, so a few seconds of debounce costs nothing in recovery time.
pub const DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum OidcConfigError {
    #[error("invalid issuer url: {0}")]
    IssuerUrl(String),
    #[error("invalid redirect url: {0}")]
    RedirectUrl(String),
}

/// How an OIDC client identifies itself and what it asks for.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub(crate) issuer_url: IssuerUrl,
    pub(crate) client_id: ClientId,
    pub(crate) client_secret: Option<ClientSecret>,
    pub(crate) redirect_url: RedirectUrl,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) min_refresh_interval: Duration,
    pub(crate) use_pkce: bool,
}

impl OidcConfig {
    /// The scopes the original requested on the authorization endpoint.
    /// `openid` is required by OIDC Core; the original omitted it from
    /// `new_redirect` and relied on the provider inferring it.
    pub const DEFAULT_SCOPES: [&'static str; 3] = ["openid", "email", "profile"];

    pub fn new(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Result<Self, OidcConfigError> {
        let issuer_url = IssuerUrl::new(issuer_url.into())
            .map_err(|e| OidcConfigError::IssuerUrl(e.to_string()))?;
        let redirect_url = RedirectUrl::new(redirect_url.into())
            .map_err(|e| OidcConfigError::RedirectUrl(e.to_string()))?;

        Ok(Self {
            issuer_url,
            client_id: ClientId::new(client_id.into()),
            client_secret: None,
            redirect_url,
            scopes: Self::DEFAULT_SCOPES
                .iter()
                .map(|s| Scope::new((*s).to_string()))
                .collect(),
            min_refresh_interval: DEFAULT_MIN_REFRESH_INTERVAL,
            use_pkce: true,
        })
    }

    pub fn with_client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(ClientSecret::new(secret.into()));
        self
    }

    /// Replaces the requested scopes wholesale.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(|s| Scope::new(s.into())).collect();
        self
    }

    pub fn with_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// PKCE (RFC 7636) is on by default. OAuth 2.1 requires it of all clients,
    /// confidential ones included; the original used none. Disable only for a
    /// provider that rejects the parameters outright.
    pub fn with_pkce(mut self, use_pkce: bool) -> Self {
        self.use_pkce = use_pkce;
        self
    }

    pub fn issuer_url(&self) -> &IssuerUrl {
        &self.issuer_url
    }

    pub fn redirect_url(&self) -> &RedirectUrl {
        &self.redirect_url
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn uses_pkce(&self) -> bool {
        self.use_pkce
    }

    pub fn min_refresh_interval(&self) -> Duration {
        self.min_refresh_interval
    }
}
