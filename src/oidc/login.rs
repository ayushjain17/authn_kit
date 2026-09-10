//! The OIDC authorization-code login flow.
//!
//! Framework-agnostic throughout: [`LoginFlow::authorize`] and
//! [`LoginFlow::complete`] return *data* describing the redirect and the cookies
//! to emit, and an adapter renders them. The original interleaved this with
//! actix — building `HttpResponse::Found()` inline, reading `HttpRequest`
//! cookies, and mounting itself as a `Scope` — so none of the protocol logic
//! could be tested or reused.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, TokenResponse, core::CoreResponseType,
};
use serde::{Deserialize, Serialize};

use crate::{
    claims::IdentityClaims,
    cookie::CookieDirective,
    error::AuthError,
    oidc::{
        provider::{NonceCheck, OidcProvider},
        session::{CookieSettings, IdTokenCodec, Session, SessionCodec},
    },
};

/// Where a user may be sent after a successful login.
///
/// The original took `state.redirect_uri` — a field of the base64-encoded
/// `state` query parameter, and therefore attacker-supplied — and placed it
/// verbatim in a `Location` header. This crate does not put the destination in
/// `state` at all (see [`ProtectionData`]), but the destination an application
/// passes to [`LoginFlow::authorize`] may itself have come from a `?next=`
/// parameter, so it is validated here too.
#[derive(Clone, Debug, Default)]
pub enum RedirectPolicy {
    /// Only same-origin paths. The default, and correct for almost every service.
    #[default]
    RelativeOnly,
    /// Same-origin paths, plus absolute URLs whose origin is listed.
    Allowlist(Vec<String>),
}

impl RedirectPolicy {
    pub fn validate(&self, destination: &str) -> Result<(), AuthError> {
        let rejected = |reason: &str| {
            Err(AuthError::malformed_credential(format!(
                "rejected login redirect {destination:?}: {reason}"
            )))
        };

        // A control character can split the header and inject a second one.
        if destination.chars().any(|c| c.is_control()) {
            return rejected("contains a control character");
        }

        if destination.starts_with('/') {
            // `//evil.example` is protocol-relative: the browser reads it as an
            // absolute URL to another origin. `/\evil.example` is the same trick
            // through a backslash, which several browsers normalise to `/`.
            if destination.starts_with("//") || destination.starts_with("/\\") {
                return rejected("protocol-relative url");
            }
            return Ok(());
        }

        match self {
            Self::RelativeOnly => rejected("only relative paths are permitted"),
            Self::Allowlist(origins) => {
                if origins
                    .iter()
                    .any(|origin| is_within_origin(destination, origin))
                {
                    Ok(())
                } else {
                    rejected("origin is not allow-listed")
                }
            }
        }
    }
}

/// Whether `url` sits under `origin`, matching on an origin boundary so that
/// `https://evil.example.com` does not pass for an allow-listed
/// `https://evil.example`.
fn is_within_origin(url: &str, origin: &str) -> bool {
    let origin = origin.trim_end_matches('/');
    match url.strip_prefix(origin) {
        Some("") => true,
        Some(rest) => {
            rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#')
        }
        None => false,
    }
}

/// The single-use secrets binding one authorization request to its callback,
/// carried in a short-lived `HttpOnly` cookie.
///
/// The destination lives here rather than in the `state` query parameter, which
/// is the key difference from the original. `state` is now an opaque random
/// token and nothing else, so the post-login redirect target never leaves the
/// server and cannot be influenced by whoever crafts the callback URL.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProtectionData {
    /// Matched against the `state` returned by the provider (CSRF defence).
    pub csrf: CsrfToken,
    /// Matched against the ID token's `nonce` claim (token-replay defence).
    pub nonce: Nonce,
    /// The PKCE code verifier, presented at the token endpoint. `None` when PKCE
    /// is disabled.
    pub pkce_verifier: Option<String>,
    /// Where to send the user once login completes.
    pub destination: String,
}

impl ProtectionData {
    /// Serialises to the opaque value carried in the protection cookie.
    fn encode(&self) -> Result<String, AuthError> {
        let json = serde_json::to_vec(self).map_err(|e| {
            AuthError::internal(format!("could not serialise protection data: {e}"))
        })?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }

    /// Parses a protection-cookie value.
    fn decode(raw: &str) -> Result<Self, AuthError> {
        let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|e| {
            AuthError::unauthenticated(format!("bad protection cookie: {e}"))
        })?;
        serde_json::from_slice(&bytes).map_err(|e| {
            AuthError::unauthenticated(format!("bad protection cookie payload: {e}"))
        })
    }
}

/// What the caller should send the browser to begin a login.
#[derive(Debug)]
pub struct AuthorizationRedirect {
    /// The provider's authorization endpoint, fully parameterised.
    pub location: String,
    /// Cookies to set: the protection cookie, and a clear of any stale session.
    pub cookies: Vec<CookieDirective>,
}

/// The provider's callback, parsed from the query string.
#[derive(Debug)]
pub enum CallbackParams {
    Success {
        code: AuthorizationCode,
        state: CsrfToken,
    },
    /// An RFC 6749 §4.1.2.1 error response — most commonly `access_denied`,
    /// which is simply the user declining consent.
    ///
    /// The original modelled no such case: its `LoginParams` required `code` and
    /// `state`, so a user clicking "Deny" produced a deserialisation failure and
    /// an opaque `400`.
    Failure {
        error: String,
        description: Option<String>,
    },
}

impl CallbackParams {
    /// Parses a callback query string (without the leading `?`).
    pub fn from_query(query: &str) -> Result<Self, AuthError> {
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut description = None;

        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                "error_description" => description = Some(value.into_owned()),
                _ => {}
            }
        }

        if let Some(error) = error {
            return Ok(Self::Failure { error, description });
        }
        match (code, state) {
            (Some(code), Some(state)) => Ok(Self::Success {
                code: AuthorizationCode::new(code),
                state: CsrfToken::new(state),
            }),
            _ => Err(AuthError::malformed_credential(
                "callback carried neither an authorization code nor an error",
            )),
        }
    }
}

/// A completed login.
#[derive(Debug)]
pub struct LoginComplete {
    /// The verified identity, ready for the application's `TryFrom`.
    pub claims: IdentityClaims,
    /// Where to send the browser next.
    pub redirect_to: String,
    /// Cookies to set: the new session, and a clear of the spent protection
    /// cookie.
    pub cookies: Vec<CookieDirective>,
}

/// Drives the authorization-code flow.
pub struct LoginFlow<C: SessionCodec = IdTokenCodec> {
    provider: std::sync::Arc<OidcProvider>,
    codec: C,
    session: CookieSettings,
    protection: CookieSettings,
    redirect_policy: RedirectPolicy,
}

impl LoginFlow<IdTokenCodec> {
    /// A flow storing the ID token directly in the session cookie, as the
    /// original did.
    pub fn new(provider: std::sync::Arc<OidcProvider>) -> Self {
        Self::with_codec(provider, IdTokenCodec)
    }
}

impl<C: SessionCodec> LoginFlow<C> {
    pub fn with_codec(provider: std::sync::Arc<OidcProvider>, codec: C) -> Self {
        Self {
            provider,
            codec,
            session: CookieSettings::session("session"),
            protection: CookieSettings::protection("authn_protection"),
            redirect_policy: RedirectPolicy::default(),
        }
    }

    pub fn with_session_cookie(mut self, settings: CookieSettings) -> Self {
        self.session = settings;
        self
    }

    pub fn with_protection_cookie(mut self, settings: CookieSettings) -> Self {
        self.protection = settings;
        self
    }

    pub fn with_redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    pub fn session_cookie(&self) -> &CookieSettings {
        &self.session
    }

    pub fn protection_cookie(&self) -> &CookieSettings {
        &self.protection
    }

    /// Begins a login, sending the user to the provider.
    ///
    /// `destination` is where they return to afterwards; it is validated against
    /// the configured [`RedirectPolicy`] *before* the redirect is issued, so a
    /// bad destination fails fast rather than at callback time.
    pub fn authorize(
        &self,
        destination: &str,
    ) -> Result<AuthorizationRedirect, AuthError> {
        self.redirect_policy.validate(destination)?;

        let state = self.provider.snapshot();
        let config = self.provider.config();

        let (challenge, verifier) = if config.uses_pkce() {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            (Some(challenge), Some(verifier.secret().clone()))
        } else {
            (None, None)
        };

        let mut request = state.client().authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in config.scopes() {
            request = request.add_scope(scope.clone());
        }
        if let Some(challenge) = challenge {
            request = request.set_pkce_challenge(challenge);
        }

        let (url, csrf, nonce) = request.url();

        let protection = ProtectionData {
            csrf,
            nonce,
            pkce_verifier: verifier,
            destination: destination.to_string(),
        };

        Ok(AuthorizationRedirect {
            location: url.to_string(),
            cookies: vec![
                self.protection.set(protection.encode()?),
                // Drop any stale session before starting a new login, so a
                // failed attempt cannot leave the previous identity in place.
                self.session.clear(),
            ],
        })
    }

    /// Completes a login from the provider's callback.
    ///
    /// Verifies, in order: that the provider did not report an error, that the
    /// returned `state` matches the protection cookie (CSRF), that the code
    /// exchanges successfully with the PKCE verifier, and that the resulting ID
    /// token's `nonce` matches the one minted for this attempt.
    pub async fn complete(
        &self,
        callback: CallbackParams,
        protection_cookie: Option<&str>,
    ) -> Result<LoginComplete, AuthError> {
        let (code, returned_state) = match callback {
            CallbackParams::Success { code, state } => (code, state),
            CallbackParams::Failure { error, description } => {
                let detail = description.unwrap_or_else(|| error.clone());
                return Err(match error.as_str() {
                    "access_denied" => AuthError::unauthenticated(format!(
                        "user declined sign-in: {detail}"
                    )),
                    _ => AuthError::upstream(format!(
                        "provider reported {error} during sign-in: {detail}"
                    )),
                });
            }
        };

        let raw = protection_cookie
            .ok_or_else(|| AuthError::unauthenticated("protection cookie is missing"))?;
        let protection = ProtectionData::decode(raw)?;

        if returned_state.secret() != protection.csrf.secret() {
            return Err(AuthError::unauthenticated(
                "callback state does not match the protection cookie",
            ));
        }

        let state = self.provider.snapshot();
        let mut request = state.client().exchange_code(code).map_err(|e| {
            AuthError::internal(format!("provider advertises no token endpoint: {e}"))
        })?;
        if let Some(verifier) = protection.pkce_verifier {
            request = request.set_pkce_verifier(PkceCodeVerifier::new(verifier));
        }

        let response = request.request_async(self.provider.http_client()).await?;

        let id_token = response
            .id_token()
            .ok_or_else(|| AuthError::upstream("token response carried no id_token"))?
            .to_string();

        let claims = self
            .provider
            .verify_id_token(&id_token, NonceCheck::Matches(&protection.nonce))
            .await?;

        let session = Session {
            id_token,
            expires_at: claims.expires_at,
        };

        Ok(LoginComplete {
            claims,
            redirect_to: protection.destination,
            cookies: vec![
                self.session.set(self.codec.encode(&session)?),
                // The protection cookie is single-use; leaving it would let a
                // replayed callback be re-validated against it.
                self.protection.clear(),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protection() -> ProtectionData {
        ProtectionData {
            csrf: CsrfToken::new("csrf-value".to_string()),
            nonce: Nonce::new("nonce-value".to_string()),
            pkce_verifier: Some("verifier-value".to_string()),
            destination: "/admin/organisations".to_string(),
        }
    }

    #[test]
    fn protection_data_round_trips_through_a_cookie_value() {
        let decoded = ProtectionData::decode(&protection().encode().unwrap()).unwrap();

        assert_eq!(decoded.csrf.secret(), "csrf-value");
        assert_eq!(decoded.nonce.secret(), "nonce-value");
        assert_eq!(decoded.pkce_verifier.as_deref(), Some("verifier-value"));
        assert_eq!(decoded.destination, "/admin/organisations");
    }

    /// The encoded value goes into a cookie verbatim, and RFC 6265 excludes
    /// `;`, `,`, space and `"` from a cookie value.
    #[test]
    fn encoded_protection_data_is_cookie_safe() {
        let encoded = ProtectionData {
            csrf: CsrfToken::new("a+b/c=".to_string()),
            nonce: Nonce::new("n".to_string()),
            pkce_verifier: None,
            destination: "/x?y=z&w=1".to_string(),
        }
        .encode()
        .unwrap();

        for forbidden in [';', ',', ' ', '"', '='] {
            assert!(!encoded.contains(forbidden), "contains {forbidden:?}");
        }
    }

    #[test]
    fn a_corrupt_protection_cookie_is_rejected_as_unauthenticated() {
        for raw in ["not-base64!!!", "", "YWJj"] {
            let error =
                ProtectionData::decode(raw).expect_err(&format!("accepted {raw:?}"));
            assert_eq!(error.status(), 401);
        }
    }
}
