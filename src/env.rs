//! Reading configuration from environment variables.
//!
//! Entirely optional. Every type in this crate is constructed from explicit
//! values, which is what makes them testable without a populated process
//! environment — the property the original lacked, with `get_from_env_unsafe`
//! calls scattered through the authenticator, the token cache and the API-token
//! config.
//!
//! This module is a convenience layer on top, for services that would otherwise
//! write the same twenty `std::env::var` calls. Two differences from the
//! original's approach:
//!
//! * **Names are generic**, not `OIDC_*`-prefixed application names, and the
//!   prefix is configurable — so an existing deployment can keep the variable
//!   names it already sets.
//! * **Nothing panics.** The original's `get_from_env_unsafe(..).unwrap()` meant
//!   a missing or malformed variable aborted the process with a backtrace
//!   instead of a message naming the variable.
//!
//! Secrets are deliberately *not* required to come from the environment: read
//! `client_secret` and the static-token list from a KMS or secret manager and
//! override them on the returned builder.

use std::{str::FromStr, time::Duration};

use crate::error::AuthError;

/// Default prefix for every variable this module reads.
///
/// A prefix is mandatory, not decorative: without one, generic suffixes like
/// `OIDC_CLIENT_ID` or `SESSION_COOKIE_NAME` would collide with the host
/// application's own variables, or with another library's.
pub const DEFAULT_PREFIX: &str = "AUTHN_";

#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error("{name} is not set")]
    Missing { name: String },
    #[error("{name} is not valid UTF-8")]
    NotUnicode { name: String },
    #[error("{name} could not be parsed: {detail}")]
    Invalid { name: String, detail: String },
    #[error(
        "an environment prefix is required, so that generic names such as \
         OIDC_CLIENT_ID cannot collide with the application's own variables"
    )]
    EmptyPrefix,
}

impl From<EnvError> for AuthError {
    fn from(error: EnvError) -> Self {
        Self::internal(error.to_string())
    }
}

/// Reads configuration from the environment under a common prefix.
///
/// | Suffix | Meaning |
/// |---|---|
/// | `OIDC_ISSUER_URL` | the OpenID Provider's issuer URL |
/// | `OIDC_CLIENT_ID` | this service's client id |
/// | `OIDC_CLIENT_SECRET` | client secret (prefer a secret manager) |
/// | `OIDC_REDIRECT_URL` | the login callback URL |
/// | `OIDC_SCOPES` | space- or comma-separated scopes |
/// | `API_TOKEN_PREFIX` | prefix marking a bearer token as an API key |
/// | `API_STATIC_TOKENS` | JSON array of static tokens (prefer a secret manager) |
/// | `INTROSPECTION_ENDPOINT` | RFC 7662 endpoint |
/// | `INTROSPECTION_AUTH_HEADER` | verbatim `Authorization` for that endpoint |
/// | `SESSION_COOKIE_NAME` | session cookie name |
/// | `COOKIE_SECURE` | `false` only for local plain-HTTP development |
/// | `COOKIE_DOMAIN` | cookie domain |
/// | `MAX_CACHE_TTL_SECS` | cap on caching a remotely-validated token |
#[derive(Clone, Debug)]
pub struct EnvConfig {
    prefix: String,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvConfig {
    /// Reads under [`DEFAULT_PREFIX`].
    pub fn new() -> Self {
        Self {
            prefix: DEFAULT_PREFIX.to_string(),
        }
    }

    /// Reads under a different prefix, so a deployment can keep the variable
    /// names it already sets — `"OIDC_"`, for instance.
    ///
    /// The prefix must be non-empty: every suffix this module reads is
    /// deliberately generic, so an unprefixed `OIDC_CLIENT_ID` or
    /// `SESSION_COOKIE_NAME` would be liable to collide with the host
    /// application's own configuration, or with another library's.
    ///
    /// A trailing `_` is appended when absent, so `"MYAPP"` and `"MYAPP_"` both
    /// read `MYAPP_OIDC_CLIENT_ID`.
    pub fn with_prefix(prefix: impl Into<String>) -> Result<Self, EnvError> {
        let prefix = prefix.into();
        let trimmed = prefix.trim();
        if trimmed.is_empty() {
            return Err(EnvError::EmptyPrefix);
        }

        let prefix = if trimmed.ends_with('_') {
            trimmed.to_string()
        } else {
            format!("{trimmed}_")
        };
        Ok(Self { prefix })
    }

    /// The prefix every variable is read under.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The full variable name for a suffix, e.g. `AUTHN_OIDC_ISSUER_URL`.
    pub fn name(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.prefix)
    }

    /// The raw value of a variable, if set and non-empty.
    ///
    /// An empty value counts as unset: a deployment that sets a variable to the
    /// empty string almost always means "not configured", and treating it as a
    /// present-but-blank value turns that into a confusing downstream failure.
    pub fn get(&self, suffix: &str) -> Result<Option<String>, EnvError> {
        let name = self.name(suffix);
        match std::env::var(&name) {
            Ok(value) if value.trim().is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(EnvError::NotUnicode { name }),
        }
    }

    /// As [`Self::get`], failing when the variable is unset.
    pub fn require(&self, suffix: &str) -> Result<String, EnvError> {
        self.get(suffix)?.ok_or_else(|| EnvError::Missing {
            name: self.name(suffix),
        })
    }

    /// A parsed value, or `None` when unset.
    pub fn parse<T>(&self, suffix: &str) -> Result<Option<T>, EnvError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        let Some(raw) = self.get(suffix)? else {
            return Ok(None);
        };
        raw.trim()
            .parse()
            .map(Some)
            .map_err(|e: T::Err| EnvError::Invalid {
                name: self.name(suffix),
                detail: e.to_string(),
            })
    }

    /// A parsed value, or `default` when unset. A malformed value is still an
    /// error rather than silently falling back — the original logged a warning
    /// and used the default, so a typo went unnoticed.
    pub fn parse_or<T>(&self, suffix: &str, default: T) -> Result<T, EnvError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        Ok(self.parse(suffix)?.unwrap_or(default))
    }

    /// A duration given in seconds.
    pub fn duration_secs(&self, suffix: &str) -> Result<Option<Duration>, EnvError> {
        Ok(self.parse::<u64>(suffix)?.map(Duration::from_secs))
    }

    /// A list, accepting either spaces or commas as separators.
    pub fn list(&self, suffix: &str) -> Result<Option<Vec<String>>, EnvError> {
        Ok(self.get(suffix)?.map(|raw| {
            raw.split([' ', ','])
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        }))
    }

    /// Whether a mechanism is configured, without reading its value — for
    /// deciding whether to fetch the corresponding secret from a secret manager.
    pub fn is_set(&self, suffix: &str) -> bool {
        matches!(self.get(suffix), Ok(Some(_)))
    }
}

#[cfg(feature = "oidc")]
mod oidc_env {
    use super::{EnvConfig, EnvError};
    use crate::oidc::OidcConfig;

    impl EnvConfig {
        /// Builds an [`OidcConfig`] from the environment.
        ///
        /// The client secret is read from `<prefix>OIDC_CLIENT_SECRET` when
        /// present, but a deployment holding it in a secret manager should leave
        /// that unset and call
        /// [`with_client_secret`](OidcConfig::with_client_secret) on the result.
        pub fn oidc_config(&self) -> Result<OidcConfig, EnvError> {
            let mut config = OidcConfig::new(
                self.require("OIDC_ISSUER_URL")?,
                self.require("OIDC_CLIENT_ID")?,
                self.require("OIDC_REDIRECT_URL")?,
            )
            .map_err(|e| EnvError::Invalid {
                name: self.name("OIDC_ISSUER_URL"),
                detail: e.to_string(),
            })?;

            if let Some(secret) = self.get("OIDC_CLIENT_SECRET")? {
                config = config.with_client_secret(secret);
            }
            if let Some(scopes) = self.list("OIDC_SCOPES")? {
                config = config.with_scopes(scopes);
            }
            if let Some(interval) = self.duration_secs("OIDC_MIN_REFRESH_SECS")? {
                config = config.with_min_refresh_interval(interval);
            }
            Ok(config)
        }
    }
}
