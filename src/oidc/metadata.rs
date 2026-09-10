//! Provider metadata, extended with the RFC 8414 introspection endpoint.

use openidconnect::{
    AdditionalProviderMetadata, IntrospectionUrl, ProviderMetadata,
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
        CoreGrantType, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
};
use serde::{Deserialize, Serialize};

/// Provider metadata beyond OIDC Core discovery: the RFC 7662 introspection
/// endpoint, defined by RFC 8414. OPTIONAL — a provider may support
/// introspection without advertising it — hence `Option`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IntrospectionMetadata {
    #[serde(default)]
    pub introspection_endpoint: Option<IntrospectionUrl>,
}

impl AdditionalProviderMetadata for IntrospectionMetadata {}

/// OIDC provider metadata carrying the introspection endpoint alongside the
/// standard Core fields.
///
/// Three type parameters shorter than the original's equivalent alias:
/// `openidconnect` 4.x folded `CoreJsonWebKeyType` and `CoreJsonWebKeyUse` into
/// `CoreJsonWebKey`.
pub type OidcProviderMetadata = ProviderMetadata<
    IntrospectionMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// The introspection endpoint the provider advertises (RFC 8414
/// `introspection_endpoint`), if any.
///
/// Keeps the metadata-digging in one place so callers deal only in URLs.
pub fn discovered_introspection_endpoint(
    metadata: &OidcProviderMetadata,
) -> Option<String> {
    metadata
        .additional_metadata()
        .introspection_endpoint
        .as_ref()
        .map(|url| url.url().as_str().to_string())
}
