//! Mapping OIDC ID-token claims onto [`IdentityClaims`].
//!
//! This is the generic replacement for the original `try_user_from`, which
//! hard-coded `email` and `preferred_username` into a `superposition_types::User`
//! and dropped everything else the provider sent. Here every claim survives:
//! the standard ones are named, and the rest — group memberships, tenant ids,
//! whatever the provider adds — stay reachable through
//! [`IdentityClaims::extra`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::{AdditionalClaims, GenderClaim, IdTokenClaims};

use crate::claims::{ClaimSource, IdentityClaims};

/// Converts verified ID-token claims into source-agnostic identity claims.
///
/// Generic over the provider's additional claims and gender claim type, so it
/// serves both `CoreIdTokenClaims` and any application-specific claim set.
pub fn identity_from_id_token_claims<AC, GC>(
    claims: &IdTokenClaims<AC, GC>,
) -> IdentityClaims
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    let mut identity = IdentityClaims::new(ClaimSource::IdToken)
        .with_subject(claims.subject().as_str())
        .with_expires_at(to_system_time(claims.expiration().timestamp()));

    if let Some(email) = claims.email() {
        identity = identity.with_email(email.as_str());
    }
    if let Some(username) = claims.preferred_username() {
        identity = identity.with_preferred_username(username.as_str());
    }
    // `name` is a localised claim; `None` selects the untagged default, which is
    // what a provider returns when the request carried no language preference.
    if let Some(name) = claims.name().and_then(|name| name.get(None)) {
        identity = identity.with_name(name.as_str());
    }

    identity.extra = flatten_claims(claims);
    identity
}

/// Serialises the whole claim set and keeps its top-level members, so nothing
/// the provider sent is lost. Failure here is not an error: the named claims are
/// already extracted, and `extra` is a best-effort escape hatch.
fn flatten_claims<AC, GC>(
    claims: &IdTokenClaims<AC, GC>,
) -> std::collections::BTreeMap<String, serde_json::Value>
where
    AC: AdditionalClaims,
    GC: GenderClaim,
{
    match serde_json::to_value(claims) {
        Ok(serde_json::Value::Object(map)) => map.into_iter().collect(),
        _ => Default::default(),
    }
}

/// Unix seconds to `SystemTime`, clamping a negative timestamp to the epoch.
fn to_system_time(unix_seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(unix_seconds.max(0) as u64)
}
