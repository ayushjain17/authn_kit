//! RFC 7662 OAuth 2.0 Token Introspection.
//!
//! Forwards an opaque API key to a configured endpoint, which answers whether it
//! is active and returns its claims. Modelled on the RFC alone, so any provider
//! — Keycloak, Okta, Hydra, or a small bespoke service — can serve it.
//!
//! Introspection is an **OAuth 2.0** mechanism, not an OIDC one, so this sits
//! behind its own feature and needs no identity provider. When the `oidc`
//! feature is also enabled, the endpoint discovered in provider metadata
//! (RFC 8414 `introspection_endpoint`) can be passed in as the URL.

use std::{
    collections::BTreeMap,
    time::{Duration, UNIX_EPOCH},
};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    claims::{ClaimSource, IdentityClaims},
    error::AuthError,
    mechanisms::api_token::TokenValidator,
};

/// Validates API keys against an RFC 7662 introspection endpoint.
pub struct IntrospectionValidator {
    endpoint: String,
    /// The verbatim `Authorization` header value presented to the endpoint,
    /// which RFC 7662 §2.1 requires to be protected.
    ///
    /// Verbatim rather than derived, so any scheme the endpoint expects works —
    /// `Bearer <token>`, `Basic <base64>`, or something bespoke. This is why the
    /// request is built by hand rather than through `openidconnect`, which would
    /// authenticate with this service's own OAuth client credentials.
    auth_header: SecretString,
    http: reqwest::Client,
}

impl IntrospectionValidator {
    /// Builds a validator with its own pooled HTTP client.
    pub fn new(
        endpoint: impl Into<String>,
        auth_header: impl Into<String>,
    ) -> Result<Self, AuthError> {
        // Redirects disabled: the endpoint is a configured URL, and following a
        // redirect would forward the API key and our endpoint credential to a
        // host we never configured.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AuthError::internal(format!("could not build http client: {e}"))
            })?;

        Ok(Self::with_client(endpoint, auth_header, http))
    }

    /// Builds a validator reusing an existing client — for instance the one
    /// [`OidcProvider`](crate::oidc::OidcProvider) already holds.
    pub fn with_client(
        endpoint: impl Into<String>,
        auth_header: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_header: SecretString::from(auth_header.into()),
            http,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl std::fmt::Debug for IntrospectionValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionValidator")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TokenValidator for IntrospectionValidator {
    fn name(&self) -> &'static str {
        "introspection"
    }

    async fn validate(
        &self,
        api_key: &str,
        _scope: Option<&str>,
    ) -> Result<IdentityClaims, AuthError> {
        let response = self
            .http
            .post(&self.endpoint)
            .header(
                reqwest::header::AUTHORIZATION,
                self.auth_header.expose_secret(),
            )
            .form(&[("token", api_key)])
            .send()
            .await
            .map_err(|e| {
                AuthError::upstream(format!("introspection request failed: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(AuthError::upstream(format!(
                "introspection endpoint returned status {}",
                response.status()
            )));
        }

        // Parsed as a generic object so every claim the endpoint returns
        // survives into `IdentityClaims::extra`, rather than only the handful
        // the original modelled.
        let body: serde_json::Value = response.json().await.map_err(|e| {
            AuthError::upstream(format!("could not parse introspection response: {e}"))
        })?;

        claims_from_response(body)
    }
}

/// Maps an RFC 7662 response onto [`IdentityClaims`].
///
/// `active` is the only REQUIRED member (§2.2). An inactive token is the
/// client's problem (401); a malformed response is the endpoint's (503).
fn claims_from_response(body: serde_json::Value) -> Result<IdentityClaims, AuthError> {
    let serde_json::Value::Object(map) = body else {
        return Err(AuthError::upstream(
            "introspection response was not a JSON object",
        ));
    };

    match map.get("active").and_then(serde_json::Value::as_bool) {
        Some(true) => {}
        Some(false) => {
            return Err(AuthError::invalid_credential("token is not active"));
        }
        None => {
            return Err(AuthError::upstream(
                "introspection response omitted the required `active` member",
            ));
        }
    }

    let string = |key: &str| {
        map.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };

    let mut claims = IdentityClaims::new(ClaimSource::Introspection);
    claims.subject = string("sub");
    claims.preferred_username = string("username");
    claims.email = string("email");
    claims.client_id = string("client_id");
    claims.scope = string("scope");
    claims.expires_at = map
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .map(|exp| UNIX_EPOCH + Duration::from_secs(exp));
    claims.extra = map.into_iter().collect::<BTreeMap<_, _>>();

    // An active token with nothing identifying it cannot produce a principal.
    // The original reported this as "inactive"; it is really a malformed
    // response, and saying so makes the misconfiguration findable.
    if claims.best_effort_username().is_none() {
        return Err(AuthError::upstream(
            "introspection reported an active token carrying no identity claim",
        ));
    }

    Ok(claims)
}
