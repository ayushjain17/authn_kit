//! Session representation and the cookie settings that carry it.

use std::time::{Duration, SystemTime};

use crate::{
    cookie::{CookieDirective, SameSite},
    error::AuthError,
};

/// An authenticated browser session.
#[derive(Clone, Debug)]
pub struct Session {
    /// The ID token minted by the provider. Re-verified on each request rather
    /// than trusted, so a revoked or expired token stops working without any
    /// server-side state.
    pub id_token: String,
    /// When the underlying token expires, when the provider reported it.
    pub expires_at: Option<SystemTime>,
}

/// Converts a [`Session`] to and from the opaque string stored in the cookie.
///
/// One implementation ships today ([`IdTokenCodec`]). The trait exists because
/// the JWT-in-a-cookie approach has a real ceiling — browsers cap a cookie at
/// roughly 4KB, and an ID token carrying group memberships can exceed it — so
/// encrypting the payload or swapping in an opaque server-side handle is a
/// predictable next step.
///
/// **Known limitation:** both methods are synchronous, so a codec backed by a
/// network store (Redis, a database) does not fit. That is deliberate for now —
/// making them async would complicate every call site to serve an
/// implementation nobody has asked for yet.
pub trait SessionCodec: Send + Sync + 'static {
    fn encode(&self, session: &Session) -> Result<String, AuthError>;
    fn decode(&self, raw: &str) -> Result<Session, AuthError>;
}

/// Stores the ID token verbatim as the cookie value.
///
/// This is what the original did — `Cookie::build(login_type.to_string(),
/// r.to_string())` where `r` was the `CoreIdToken`.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdTokenCodec;

impl SessionCodec for IdTokenCodec {
    fn encode(&self, session: &Session) -> Result<String, AuthError> {
        Ok(session.id_token.clone())
    }

    fn decode(&self, raw: &str) -> Result<Session, AuthError> {
        if raw.is_empty() {
            return Err(AuthError::unauthenticated("empty session cookie"));
        }
        Ok(Session {
            id_token: raw.to_string(),
            expires_at: None,
        })
    }
}

/// How a cookie this crate emits should be scoped and protected.
///
/// Every attribute the original hard-coded is a field here. In particular
/// `secure` is configurable: the original set `.secure(true)` unconditionally,
/// which means the browser never sends the cookie back over plain HTTP and local
/// development against `http://localhost` simply does not work.
#[derive(Clone, Debug)]
pub struct CookieSettings {
    pub name: String,
    pub path: String,
    pub domain: Option<String>,
    pub max_age: Duration,
    pub secure: bool,
    pub same_site: Option<SameSite>,
}

impl CookieSettings {
    /// Settings for the session cookie. Defaults to a one-day lifetime, matching
    /// the original's `Duration::days(1)`.
    pub fn session(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: "/".to_string(),
            domain: None,
            max_age: Duration::from_secs(24 * 60 * 60),
            secure: true,
            // `Lax` rather than `Strict`, and this is not a compromise: the
            // provider returns the user by a cross-site top-level navigation, and
            // `Strict` withholds cookies on exactly that. The original carried a
            // `TODO: figure out why this does not work for our case` above a
            // commented-out `SameSite::Strict`; this is why.
            same_site: Some(SameSite::Lax),
        }
    }

    /// Settings for the short-lived login-protection cookie, which holds the
    /// CSRF token, the nonce and the PKCE verifier.
    ///
    /// Ten minutes is ample for a human to complete a login and bounds how long
    /// a stolen verifier is useful. The original gave this cookie **seven days**
    /// and left `http_only` commented out, so the PKCE verifier — had there been
    /// one — would have been readable from JavaScript for a week.
    pub fn protection(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: "/".to_string(),
            domain: None,
            max_age: Duration::from_secs(10 * 60),
            secure: true,
            same_site: Some(SameSite::Lax),
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn with_domain(mut self, domain: Option<String>) -> Self {
        self.domain = domain;
        self
    }

    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Set `false` only for local development over plain HTTP.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn with_same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.same_site = same_site;
        self
    }

    /// Builds the `Set-Cookie` directive carrying `value`.
    ///
    /// Always `HttpOnly`: nothing this crate puts in a cookie — session token,
    /// CSRF token, nonce, PKCE verifier — has any legitimate reason to be
    /// readable from JavaScript.
    pub fn set(&self, value: impl Into<String>) -> CookieDirective {
        CookieDirective::set(self.name.clone(), value)
            .with_path(self.path.clone())
            .with_domain_opt(self.domain.clone())
            .with_max_age(self.max_age)
            .with_http_only(true)
            .with_secure(self.secure)
            .with_same_site(self.same_site)
    }

    /// Builds the directive that removes this cookie from the client.
    pub fn clear(&self) -> CookieDirective {
        CookieDirective::clear(self.name.clone())
            .with_path(self.path.clone())
            .with_domain_opt(self.domain.clone())
            .with_secure(self.secure)
            .with_same_site(self.same_site)
    }
}
