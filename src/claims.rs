//! Source-agnostic identity claims, and the [`Principal`] trait that maps them
//! onto an application's own user type.
//!
//! Every authentication mechanism this crate ships — OIDC ID tokens, JWT access
//! tokens, RFC 7662 introspection, the `client_credentials` grant, static API
//! tokens — normalises what it learns into a single [`IdentityClaims`]. An
//! application then writes *one* `TryFrom<IdentityClaims>` for its user type and
//! that conversion serves all of them.

use std::{collections::BTreeMap, fmt::Display, time::SystemTime};

use serde::{Deserialize, Serialize};

/// Which mechanism produced a set of claims.
///
/// Applications can branch on this in their [`Principal`] conversion — for
/// example to require an email for interactive logins while accepting a bare
/// `sub` for machine-to-machine tokens, which is exactly the distinction the
/// original code had to hard-code in four separate places.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSource {
    /// OIDC ID token, verified against the provider's JWKS.
    #[default]
    IdToken,
    /// OAuth 2.0 JWT access token, verified against the provider's JWKS.
    AccessToken,
    /// RFC 7662 token introspection response.
    Introspection,
    /// OAuth 2.0 `client_credentials` grant; there is no human identity here,
    /// only a validated `client_id`.
    ClientCredentials,
    /// A locally configured static API token bound to a fixed identity.
    StaticToken,
}

/// Normalised identity claims, independent of the mechanism that produced them.
///
/// The named fields cover what essentially every provider supplies. Anything
/// else — custom claims, group/role lists, tenant identifiers — is reachable
/// through [`IdentityClaims::extra`], so an application is never blocked by this
/// struct not modelling a claim it needs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IdentityClaims {
    /// The `sub` claim: the provider's stable identifier for the principal.
    /// Absent only for mechanisms that carry no subject.
    pub subject: Option<String>,
    /// The `email` claim, when present and the provider supplies one.
    pub email: Option<String>,
    /// The `preferred_username` claim.
    pub preferred_username: Option<String>,
    /// The `name` claim: human-readable display name.
    pub name: Option<String>,
    /// For `client_credentials`, the validated `client_id`. `None` otherwise.
    pub client_id: Option<String>,
    /// Space-delimited OAuth scopes granted to the credential, if reported.
    pub scope: Option<String>,
    /// When the underlying credential expires, if the provider reported it.
    /// Used to bound cache entries as well as by applications that mirror
    /// session lifetime onto the credential.
    pub expires_at: Option<SystemTime>,
    /// Which mechanism produced these claims.
    pub source: ClaimSource,
    /// Every claim the provider returned, including those mapped above. Lets an
    /// application read provider-specific claims without this crate having to
    /// model them.
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl IdentityClaims {
    /// Starts a claim set for the given source. Fields are then filled in with
    /// the `with_*` setters.
    pub fn new(source: ClaimSource) -> Self {
        Self {
            source,
            ..Default::default()
        }
    }

    /// Reads a claim from [`Self::extra`] by name, deserialising it into `T`.
    /// Returns `None` when the claim is absent or is not shaped like a `T`.
    pub fn extra_claim<T: serde::de::DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.extra
            .get(name)
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
    }

    /// The granted scopes, split on whitespace per RFC 6749 §3.3.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.iter().flat_map(|s| s.split_whitespace())
    }

    /// A best-effort display identity: `preferred_username`, else `email`, else
    /// `sub`, else `client_id`.
    ///
    /// Offered as a convenience for the common conversion; a [`Principal`] impl
    /// is free to ignore it and demand specific claims instead.
    pub fn best_effort_username(&self) -> Option<&str> {
        self.preferred_username
            .as_deref()
            .or(self.email.as_deref())
            .or(self.subject.as_deref())
            .or(self.client_id.as_deref())
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn with_preferred_username(mut self, username: impl Into<String>) -> Self {
        self.preferred_username = Some(username.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_extra(
        mut self,
        name: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.extra.insert(name.into(), value);
        self
    }
}

/// An application's authenticated user type.
///
/// This is deliberately *only* a blanket alias over `TryFrom<IdentityClaims>`:
/// implement that conversion for your user type and it becomes usable as a
/// principal throughout this crate. There is nothing else to implement, and no
/// trait of ours to import at the definition site.
///
/// ```
/// use authn_kit::claims::IdentityClaims;
///
/// #[derive(Clone)]
/// struct User {
///     email: String,
///     username: String,
/// }
///
/// impl TryFrom<IdentityClaims> for User {
///     type Error = String;
///
///     fn try_from(claims: IdentityClaims) -> Result<Self, Self::Error> {
///         let email = claims.email.clone().ok_or("email claim not found")?;
///         let username = claims
///             .best_effort_username()
///             .ok_or("no usable identity claim")?
///             .to_string();
///         Ok(Self { email, username })
///     }
/// }
/// ```
pub trait Principal:
    Clone + Send + Sync + 'static + TryFrom<IdentityClaims, Error: Display>
{
}

impl<T> Principal for T where
    T: Clone + Send + Sync + 'static + TryFrom<IdentityClaims, Error: Display>
{
}
