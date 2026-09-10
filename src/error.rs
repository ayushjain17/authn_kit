//! The authentication failure type.
//!
//! This is the single most important departure from the original design. There,
//! every fallible path returned `Result<User, HttpResponse>` — an actix
//! response *as the error type* — which made the entire module unusable outside
//! actix and forced presentation decisions (status codes, HTML bodies) into
//! protocol code. Here, failures are described semantically and each framework
//! adapter renders them.

use crate::cookie::CookieDirective;

/// Why authentication did not produce a principal.
///
/// Each variant separates a **client-facing** message, returned in the HTTP
/// response, from an **operator-facing** detail that is logged and never sent to
/// the client. The original conflated these in places, at times returning
/// internal reasons to callers and at times returning a misleading status (a
/// missing session cookie was reported as `400 Bad Request`).
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No usable credential was presented. For an API this is a `401`; for a
    /// browser flow an authenticator will usually return [`Self::Redirect`]
    /// instead, to start an interactive login.
    #[error("unauthenticated: {detail}")]
    Unauthenticated { detail: String },

    /// A credential was presented but is invalid, expired or revoked. `401`.
    #[error("invalid credential: {detail}")]
    InvalidCredential { detail: String },

    /// A credential was presented but could not be parsed — an undecodable
    /// `Basic` payload, or an unsupported grant selector. `400`, because the
    /// client can fix it by sending a well-formed request.
    #[error("malformed credential: {detail}")]
    MalformedCredential { detail: String },

    /// The principal authenticated, but not for the scope this request targets.
    /// `403`.
    #[error("scope denied: {detail}")]
    ScopeDenied { detail: String },

    /// Interactive login is required. The adapter emits a `302` to `location`,
    /// applying `cookies` — typically setting a CSRF/nonce protection cookie and
    /// clearing any stale session cookie.
    #[error("redirect to {location}")]
    Redirect {
        location: String,
        cookies: Vec<CookieDirective>,
    },

    /// The configured provider cannot serve this mechanism at all — for example
    /// an identity provider that rejects the password grant outright. `501`.
    #[error("unsupported: {detail}")]
    Unsupported { detail: String },

    /// A dependency needed to decide the request was unreachable or errored, so
    /// the answer is unknown rather than negative. `503`, which distinguishes
    /// "we could not check your token" from "your token is bad" — a distinction
    /// clients need in order to retry correctly.
    #[error("upstream failure: {detail}")]
    Upstream { detail: String },

    /// Misconfiguration or an internal fault. `500`.
    #[error("internal error: {detail}")]
    Internal { detail: String },
}

impl AuthError {
    pub fn unauthenticated(detail: impl Into<String>) -> Self {
        Self::Unauthenticated {
            detail: detail.into(),
        }
    }

    pub fn invalid_credential(detail: impl Into<String>) -> Self {
        Self::InvalidCredential {
            detail: detail.into(),
        }
    }

    pub fn malformed_credential(detail: impl Into<String>) -> Self {
        Self::MalformedCredential {
            detail: detail.into(),
        }
    }

    pub fn scope_denied(detail: impl Into<String>) -> Self {
        Self::ScopeDenied {
            detail: detail.into(),
        }
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn upstream(detail: impl Into<String>) -> Self {
        Self::Upstream {
            detail: detail.into(),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::Internal {
            detail: detail.into(),
        }
    }

    pub fn redirect(location: impl Into<String>, cookies: Vec<CookieDirective>) -> Self {
        Self::Redirect {
            location: location.into(),
            cookies,
        }
    }

    /// The HTTP status an adapter should render this as.
    pub fn status(&self) -> u16 {
        match self {
            Self::Unauthenticated { .. } | Self::InvalidCredential { .. } => 401,
            Self::MalformedCredential { .. } => 400,
            Self::ScopeDenied { .. } => 403,
            Self::Redirect { .. } => 302,
            Self::Unsupported { .. } => 501,
            Self::Upstream { .. } => 503,
            Self::Internal { .. } => 500,
        }
    }

    /// The message safe to return to the client. Never includes the operator
    /// detail, which may name internal hosts, configuration or upstream errors.
    pub fn client_message(&self) -> &'static str {
        match self {
            Self::Unauthenticated { .. } => "Authentication required",
            Self::InvalidCredential { .. } => "Invalid or expired credentials",
            Self::MalformedCredential { .. } => "Malformed credentials",
            Self::ScopeDenied { .. } => "Not authorised for this resource",
            Self::Redirect { .. } => "Redirecting to sign in",
            Self::Unsupported { .. } => "Authentication method not supported",
            Self::Upstream { .. } => "Authentication service unavailable",
            Self::Internal { .. } => "Internal authentication error",
        }
    }

    /// The operator-facing detail, for logs only.
    pub fn detail(&self) -> &str {
        match self {
            Self::Unauthenticated { detail }
            | Self::InvalidCredential { detail }
            | Self::MalformedCredential { detail }
            | Self::ScopeDenied { detail }
            | Self::Unsupported { detail }
            | Self::Upstream { detail }
            | Self::Internal { detail } => detail,
            Self::Redirect { location, .. } => location,
        }
    }

    /// Whether the failure is the service's fault rather than the client's, and
    /// so warrants an error-level log and an alert.
    pub fn is_service_fault(&self) -> bool {
        matches!(self, Self::Upstream { .. } | Self::Internal { .. })
    }
}
