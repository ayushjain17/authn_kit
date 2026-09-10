//! A framework-neutral description of a cookie to set or clear.
//!
//! Authentication flows need to emit cookies (a session, a CSRF/nonce
//! protection cookie) from code that must not depend on actix or axum. An
//! [`AuthError::Redirect`](crate::error::AuthError::Redirect) or a successful
//! login carries these, and the framework adapter renders them.

use std::{fmt::Display, time::Duration};

/// The `SameSite` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum_macros::Display)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// A cookie the caller should set on the outgoing response.
///
/// Unlike the original, `secure` and `same_site` are *fields*, not constants.
/// The original hard-coded `.secure(true)` on every cookie — which silently
/// breaks any plain-HTTP local development — and left `SameSite` unset with a
/// `TODO`. Both are now decisions the application makes once, in config.
#[derive(Clone, Debug)]
pub struct CookieDirective {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub max_age: Option<Duration>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<SameSite>,
}

impl CookieDirective {
    /// A cookie carrying `value`. Defaults to the conservative posture —
    /// `HttpOnly`, `Secure`, `SameSite=Lax` — which callers relax explicitly.
    pub fn set(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            path: None,
            domain: None,
            max_age: None,
            http_only: true,
            secure: true,
            same_site: Some(SameSite::Lax),
        }
    }

    /// An expiry directive that removes `name` from the client.
    pub fn clear(name: impl Into<String>) -> Self {
        Self {
            value: String::new(),
            max_age: Some(Duration::ZERO),
            ..Self::set(name, "")
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Sets or clears the domain, for callers threading through an
    /// already-optional value.
    pub fn with_domain_opt(mut self, domain: Option<String>) -> Self {
        self.domain = domain;
        self
    }

    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn with_same_site(mut self, same_site: Option<SameSite>) -> Self {
        self.same_site = same_site;
        self
    }
}

/// Renders the `Set-Cookie` field value per RFC 6265 §4.1.
///
/// Cookie *syntax* is a wire format, not a framework concern, so it lives here
/// and every adapter that lacks a typed cookie builder can use it directly.
impl Display for CookieDirective {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.name, self.value)?;
        if let Some(path) = &self.path {
            write!(f, "; Path={path}")?;
        }
        if let Some(domain) = &self.domain {
            write!(f, "; Domain={domain}")?;
        }
        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={}", max_age.as_secs())?;
        }
        if self.http_only {
            f.write_str("; HttpOnly")?;
        }
        if self.secure {
            f.write_str("; Secure")?;
        }
        if let Some(same_site) = self.same_site {
            write!(f, "; SameSite={same_site}")?;
        }
        Ok(())
    }
}
