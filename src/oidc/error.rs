//! Classifying `openidconnect` failures into [`AuthError`].
//!
//! The distinction that matters operationally is *whose fault is this*: a
//! rejected token is the client's problem (401), an unreachable issuer is ours
//! (503). The original collapsed most of these into
//! `ErrorInternalServerError("Failed to authenticate user")`, so a JWKS outage
//! and a forged token were indistinguishable in both the response and the logs.
//!
//! Each mapping is a `From` impl so call sites can use `?` directly.

use openidconnect::{
    ClaimsVerificationError, DiscoveryError, RequestTokenError,
    SignatureVerificationError, StandardErrorResponse, core::CoreErrorResponseType,
};

use crate::error::AuthError;

/// Discovery failed: the issuer could not be reached, or answered with something
/// that is not valid provider metadata.
///
/// Almost always a service fault — the client had no part in it. The one
/// exception is a malformed configured URL, which is ours to fix.
impl<E: std::error::Error> From<DiscoveryError<E>> for AuthError {
    fn from(error: DiscoveryError<E>) -> Self {
        match error {
            DiscoveryError::UrlParse(e) => {
                Self::internal(format!("malformed discovery url: {e}"))
            }
            DiscoveryError::Parse(e) => {
                Self::upstream(format!("could not parse provider metadata: {e}"))
            }
            DiscoveryError::Request(e) => {
                Self::upstream(format!("discovery request failed: {e}"))
            }
            DiscoveryError::Response(status, _, e) => Self::upstream(format!(
                "discovery endpoint returned status {status}: {e}"
            )),
            DiscoveryError::Validation(e) => {
                Self::upstream(format!("provider metadata failed validation: {e}"))
            }
            other => Self::upstream(format!("discovery failed: {other}")),
        }
    }
}

/// ID-token verification failed.
///
/// Reported as [`AuthError::InvalidCredential`], but see
/// [`is_possibly_stale_keys`]: a key-related signature failure is the one case a
/// caller should retry after refreshing the JWKS, because the likeliest cause is
/// the provider having rotated its signing keys since discovery.
impl From<ClaimsVerificationError> for AuthError {
    fn from(error: ClaimsVerificationError) -> Self {
        match error {
            ClaimsVerificationError::Expired(detail) => {
                Self::invalid_credential(format!("token expired: {detail}"))
            }
            ClaimsVerificationError::InvalidAudience(detail) => {
                Self::invalid_credential(format!("wrong audience: {detail}"))
            }
            ClaimsVerificationError::InvalidIssuer(detail) => {
                Self::invalid_credential(format!("wrong issuer: {detail}"))
            }
            ClaimsVerificationError::InvalidNonce(detail) => {
                Self::invalid_credential(format!("nonce mismatch: {detail}"))
            }
            ClaimsVerificationError::InvalidAuthTime(detail) => {
                Self::invalid_credential(format!("authentication too old: {detail}"))
            }
            ClaimsVerificationError::SignatureVerification(detail) => {
                Self::invalid_credential(format!("signature verification: {detail}"))
            }
            ClaimsVerificationError::Unsupported(detail) => {
                Self::unsupported(format!("unsupported token: {detail}"))
            }
            other => Self::invalid_credential(format!("claims verification: {other}")),
        }
    }
}

/// A token-endpoint exchange failed.
///
/// Maps the standard OAuth error codes so callers can tell "your credentials are
/// wrong" (401) from "this provider does not offer that grant" (501) from "the
/// token endpoint is down" (503).
impl<E: std::error::Error>
    From<RequestTokenError<E, StandardErrorResponse<CoreErrorResponseType>>>
    for AuthError
{
    fn from(
        error: RequestTokenError<E, StandardErrorResponse<CoreErrorResponseType>>,
    ) -> Self {
        match error {
            RequestTokenError::ServerResponse(response) => match response.error() {
                CoreErrorResponseType::UnsupportedGrantType => Self::unsupported(
                    "the identity provider does not support this grant type",
                ),
                CoreErrorResponseType::InvalidGrant
                | CoreErrorResponseType::InvalidClient
                | CoreErrorResponseType::UnauthorizedClient => {
                    Self::invalid_credential("credentials rejected by the provider")
                }
                other => Self::upstream(format!("token endpoint error: {other:?}")),
            },
            RequestTokenError::Request(e) => {
                Self::upstream(format!("token request failed: {e}"))
            }
            RequestTokenError::Parse(e, _) => {
                Self::upstream(format!("could not parse token response: {e}"))
            }
            RequestTokenError::Other(detail) => {
                Self::upstream(format!("token exchange failed: {detail}"))
            }
        }
    }
}

/// Whether a verification failure might be explained by stale signing keys, and
/// so is worth one retry after refreshing provider metadata.
///
/// A predicate rather than a conversion, so it stays a named function.
///
/// Only the failures fresh keys could actually change qualify:
///
/// * `NoMatchingKey` — the token's `kid` is absent from our JWKS, the canonical
///   signature of a rotation we have not picked up.
/// * `CryptoError` — a key with that `kid` exists but does not verify, which is
///   what a provider that rotates *without* changing `kid` looks like.
/// * `AmbiguousKeyId` — more than one key matched; a fresh set may not be
///   ambiguous.
///
/// Everything else — an expired token, a wrong audience, an unsupported or
/// disallowed algorithm, a missing signature — fails identically against fresh
/// keys, so retrying only doubles the load on the issuer. The original drew no
/// such distinction: it refreshed and retried on *any* verification error,
/// including ones that could never succeed.
pub fn is_possibly_stale_keys(error: &ClaimsVerificationError) -> bool {
    matches!(
        error,
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey
                | SignatureVerificationError::CryptoError(_)
                | SignatureVerificationError::AmbiguousKeyId(_)
        )
    )
}
