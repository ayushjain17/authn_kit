//! Framework adapters.
//!
//! Each adapter does exactly two things: build an [`AuthRequest`] from the
//! framework's native request type, and render an [`AuthError`] as the
//! framework's native response. No authentication logic lives here — that is the
//! point of the split.
//!
//! [`AuthRequest`]: crate::request::AuthRequest
//! [`AuthError`]: crate::error::AuthError

#[cfg(feature = "actix")]
pub mod actix;
#[cfg(feature = "axum")]
pub mod axum;
