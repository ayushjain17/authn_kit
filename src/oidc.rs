//! OpenID Connect provider support.
//!
//! This module owns everything that talks to an OpenID Provider: discovery,
//! the JWKS-backed client, ID-token verification and claim extraction. It knows
//! nothing about web frameworks, HTTP middleware or any application's user type
//! — an ID token becomes [`IdentityClaims`](crate::claims::IdentityClaims), and
//! the application's `TryFrom` turns that into its own principal.
//!
//! Only the "simple" single-issuer topology is modelled. The original's SaaS
//! per-organisation issuer variant is deliberately not carried over.

mod claims;
mod config;
pub mod error;
mod login;
mod metadata;
mod provider;
mod session;

pub use claims::identity_from_id_token_claims;
pub use config::{OidcConfig, OidcConfigError};
pub use login::{
    AuthorizationRedirect, CallbackParams, LoginComplete, LoginFlow, ProtectionData,
    RedirectPolicy,
};
pub use metadata::{
    IntrospectionMetadata, OidcProviderMetadata, discovered_introspection_endpoint,
};
pub use provider::{NonceCheck, OidcClient, OidcProvider, ProviderState};
pub use session::{CookieSettings, IdTokenCodec, Session, SessionCodec};
