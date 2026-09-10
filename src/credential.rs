//! The credential presented on a request, normalised away from any one web
//! framework's header types.

use base64::{Engine, engine::general_purpose};
use secrecy::SecretString;

use crate::request::AuthRequest;

/// A credential extracted from an incoming request.
///
/// Deliberately dumb: it records *what was presented*, not what it means. The
/// original middleware decided, inline, that a `Bearer` token carrying a given
/// prefix was an API key and that a `Basic` pair on one particular path was a
/// webhook dispatcher. Those are policy decisions belonging to individual
/// [`Authenticator`](crate::authenticator::Authenticator) implementations, which
/// can inspect the full request to make them.
#[derive(Clone)]
pub enum Credential {
    /// `Authorization: Bearer <token>`.
    Bearer(SecretString),
    /// `Authorization: Basic <base64(id:secret)>`, decoded and split.
    Basic { id: String, secret: SecretString },
    /// An `Authorization` scheme this crate does not model structurally, e.g.
    /// `Authorization: Internal <token>`. The scheme is preserved verbatim so an
    /// application-supplied authenticator can claim it.
    Other { scheme: String, value: SecretString },
    /// A recognised scheme whose payload could not be parsed — a `Basic` value
    /// that is not base64, not UTF-8, or carries no `:` separator.
    ///
    /// This is a *distinct* state rather than an error, because the original
    /// and a stricter service reasonably disagree about it. The original
    /// silently fell through to cookie authentication
    /// ([`process_basic_auth`] returned `None`), so a junk `Authorization`
    /// header alongside a valid session cookie succeeded as the cookie's user.
    /// Modelling it explicitly lets each authenticator choose: return
    /// [`Verdict::NotApplicable`](crate::outcome::Verdict) to reproduce that, or
    /// [`AuthError::MalformedCredential`](crate::error::AuthError) to reject it.
    ///
    /// [`process_basic_auth`]: https://docs.rs/
    Malformed {
        scheme: String,
        detail: &'static str,
    },
    /// No `Authorization` header was present. Session cookies still live on
    /// [`AuthRequest`], so a cookie-backed authenticator handles this case
    /// rather than a distinct variant.
    None,
}

impl Credential {
    /// Parses the `Authorization` header of `request`.
    ///
    /// Two deliberate departures from the original's inline parsing at
    /// `AuthNMiddleware::call`:
    ///
    /// * **Scheme matching is case-insensitive.** The original compared against
    ///   the literals `"Bearer"`, `"Basic"` and `"Internal"`, so a client sending
    ///   the RFC-legal `authorization: bearer <token>` fell through to cookie
    ///   authentication and was silently treated as unauthenticated. RFC 9110
    ///   §11.1 defines the scheme as case-insensitive.
    /// * **The parameter is split off at the first space only**, so a payload
    ///   containing spaces survives. The original's `split(' ')` took just the
    ///   second element and discarded the rest.
    pub fn from_request(request: &AuthRequest) -> Self {
        request
            .header("authorization")
            .map(Self::from_authorization_header)
            .unwrap_or(Self::None)
    }

    /// Parses a raw `Authorization` header value.
    pub fn from_authorization_header(header: &str) -> Self {
        let header = header.trim();
        let Some((scheme, parameter)) = header.split_once(' ') else {
            // A lone token with no scheme. The original mapped this to `None`
            // (fall through to cookie auth); preserved here.
            return Self::None;
        };

        let parameter = parameter.trim();
        let lowercase = scheme.to_ascii_lowercase();
        match lowercase.as_str() {
            "bearer" => Self::Bearer(SecretString::from(parameter.to_string())),
            "basic" => Self::parse_basic(parameter),
            _ => Self::Other {
                scheme: lowercase,
                value: SecretString::from(parameter.to_string()),
            },
        }
    }

    /// Decodes an RFC 7617 `Basic` payload: `base64(user-id ":" password)`.
    ///
    /// The password may itself contain `:`, so the split is on the *first* one
    /// only — matching the original's `splitn(2, ':')`.
    fn parse_basic(parameter: &str) -> Self {
        let malformed = |detail| Self::Malformed {
            scheme: "basic".to_string(),
            detail,
        };

        let Ok(decoded) = general_purpose::STANDARD.decode(parameter) else {
            return malformed("not valid base64");
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return malformed("not valid UTF-8");
        };
        let Some((id, secret)) = decoded.split_once(':') else {
            return malformed("missing ':' separator");
        };

        Self::Basic {
            id: id.to_string(),
            secret: SecretString::from(secret.to_string()),
        }
    }

    /// The `Authorization` scheme name, lowercased, or `None` when no
    /// `Authorization` header was presented.
    pub fn scheme(&self) -> Option<&str> {
        match self {
            Self::Bearer(_) => Some("bearer"),
            Self::Basic { .. } => Some("basic"),
            Self::Other { scheme, .. } | Self::Malformed { scheme, .. } => Some(scheme),
            Self::None => None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// Redacts the secret. `SecretString` already prevents accidental disclosure via
/// `Debug`, but spelling the impl out keeps that guarantee explicit for the
/// `Basic` variant's plaintext `id`, which is *not* secret and is useful in logs.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::Basic { id, .. } => {
                write!(f, "Basic {{ id: {id:?}, secret: <redacted> }}")
            }
            Self::Other { scheme, .. } => {
                write!(f, "Other {{ scheme: {scheme:?}, value: <redacted> }}")
            }
            Self::Malformed { scheme, detail } => {
                write!(f, "Malformed {{ scheme: {scheme:?}, detail: {detail:?} }}")
            }
            Self::None => f.write_str("None"),
        }
    }
}
