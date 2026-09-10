// Dev-dependencies count as "unused" in the lib-test target, which has no unit
// tests of its own, so the lint is scoped to non-test builds where it is
// accurate.
#![cfg_attr(not(test), deny(unused_crate_dependencies))]

//! Framework- and protocol-agnostic authentication primitives for Rust web
//! services.
//!
//! `authn_kit` separates the four concerns that web-service authentication
//! usually tangles together:
//!
//! | Concern | Abstraction |
//! |---|---|
//! | What credential did the client present? | [`Credential`], built by a framework adapter |
//! | Is it valid, and who does it identify? | [`Authenticator`], composed by [`AuthChain`] |
//! | What does "who" mean to this application? | [`IdentityClaims`] → your type, via `TryFrom` |
//! | How is a failure rendered? | [`AuthError`], rendered by a framework adapter |
//!
//! Nothing in this crate's core depends on a web framework, and every future it
//! produces is `Send`, so the same authenticators serve actix-web and axum.
//!
//! # Defining your user type
//!
//! There is no trait of ours to implement. Write the conversion you would write
//! anyway, and [`Principal`] follows by blanket impl:
//!
//! ```
//! use authn_kit::claims::IdentityClaims;
//!
//! #[derive(Clone, Debug, PartialEq)]
//! pub struct User {
//!     pub email: String,
//!     pub username: String,
//! }
//!
//! impl TryFrom<IdentityClaims> for User {
//!     type Error = String;
//!
//!     fn try_from(claims: IdentityClaims) -> Result<Self, Self::Error> {
//!         Ok(Self {
//!             email: claims.email.clone().ok_or("email claim not found")?,
//!             username: claims
//!                 .best_effort_username()
//!                 .ok_or("no usable identity claim")?
//!                 .to_string(),
//!         })
//!     }
//! }
//! ```
//!
//! # Binding it together
//!
//! ```
//! use authn_kit::{AuthProfile, scope::NoScope};
//! # use authn_kit::claims::IdentityClaims;
//! # #[derive(Clone)] pub struct User;
//! # impl TryFrom<IdentityClaims> for User {
//! #     type Error = String;
//! #     fn try_from(_: IdentityClaims) -> Result<Self, String> { Ok(User) }
//! # }
//! pub struct MyService;
//!
//! impl AuthProfile for MyService {
//!     type User = User;
//!     type Scope = NoScope;
//! }
//! ```

pub mod adapters;
pub mod authenticator;
pub mod builder;
pub mod cache;
pub mod claims;
pub mod cookie;
pub mod credential;
#[cfg(feature = "env")]
pub mod env;
pub mod error;
pub mod gateway;
pub mod mechanisms;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod outcome;
pub mod request;
pub mod scope;

pub use authenticator::{
    AuthChain, AuthContext, AuthProfile, Authenticator, PublicScopePolicy,
};
pub use builder::AuthnBuilder;
pub use cache::{CacheConfig, CacheKey, CredentialCache};
pub use claims::{ClaimSource, IdentityClaims, Principal};
pub use cookie::{CookieDirective, SameSite};
pub use credential::Credential;
pub use error::AuthError;
pub use gateway::AuthGateway;
pub use mechanisms::{ApiTokenAuthenticator, DisabledAuthenticator};
pub use outcome::{Outcome, Verdict};
pub use request::{AuthRequest, AuthRequestBuilder};
pub use scope::{AuthScope, NoScope, ScopeResolver, SingleScope};
