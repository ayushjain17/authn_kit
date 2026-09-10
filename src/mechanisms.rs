//! Ready-made [`Authenticator`](crate::authenticator::Authenticator)
//! implementations.
//!
//! Each is an independent chain element. Adding a mechanism means registering
//! one more, not editing a middleware — which is the whole reason the original's
//! `Authenticator` trait had to grow `api_token_prefix()` and
//! `authenticate_with_api_token()` methods that most implementations did not
//! want.

pub mod api_token;
#[cfg(feature = "oidc")]
pub mod basic;
#[cfg(feature = "oidc")]
pub mod bearer;
pub mod disabled;
#[cfg(feature = "introspection")]
pub mod introspection;
#[cfg(feature = "oidc")]
pub mod session;

pub use api_token::{
    ApiTokenAuthenticator, StaticTokenError, StaticTokenSpec, TokenValidator,
};
#[cfg(feature = "oidc")]
pub use basic::BasicAuthenticator;
#[cfg(feature = "oidc")]
pub use bearer::BearerAuthenticator;
pub use disabled::DisabledAuthenticator;
#[cfg(feature = "introspection")]
pub use introspection::IntrospectionValidator;
#[cfg(feature = "oidc")]
pub use session::SessionAuthenticator;
