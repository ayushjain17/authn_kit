//! The builder and the environment layer.

use std::{fmt::Display, time::Duration};

use authn_kit::{
    AuthProfile, AuthRequest, AuthScope, AuthnBuilder, DisabledAuthenticator,
    IdentityClaims, ScopeResolver, SingleScope, scope::NoScope,
};

// ---------------------------------------------------------------- fixture

#[derive(Clone, Debug, PartialEq, Eq)]
struct User(String);

impl TryFrom<IdentityClaims> for User {
    type Error = String;

    fn try_from(claims: IdentityClaims) -> Result<Self, Self::Error> {
        Ok(Self(
            claims
                .best_effort_username()
                .ok_or("no identity")?
                .to_string(),
        ))
    }
}

struct TestApp;

impl AuthProfile for TestApp {
    type User = User;
    type Scope = NoScope;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Tenant(String);

impl Display for Tenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AuthScope for Tenant {}

struct TenantApp;

impl AuthProfile for TenantApp {
    type User = User;
    type Scope = Tenant;
}

struct HeaderScopes;

impl ScopeResolver for HeaderScopes {
    type Scope = Tenant;

    fn resolve(&self, request: &AuthRequest) -> Tenant {
        Tenant(request.header("x-tenant").unwrap_or("default").to_string())
    }
}

// ---------------------------------------------------------------- builder

/// A gateway with no authenticators refuses every request on a protected scope.
/// That is never intended, and without this check it surfaces only in
/// production.
#[test]
fn an_empty_chain_is_a_construction_error() {
    let error = AuthnBuilder::<TestApp, _>::new(SingleScope)
        .build()
        .unwrap_err();

    assert_eq!(error.status(), 500);
    assert!(
        error.detail().contains("no authenticators"),
        "{}",
        error.detail()
    );
}

#[test]
fn authenticators_are_reported_in_registration_order() {
    let gateway = AuthnBuilder::<TestApp, _>::new(SingleScope)
        .with(DisabledAuthenticator::development())
        .with(DisabledAuthenticator::development())
        .build()
        .unwrap();

    assert_eq!(gateway.authenticator_names(), vec!["disabled", "disabled"]);
}

#[test]
fn with_if_skips_a_mechanism_that_is_not_configured() {
    let enabled = AuthnBuilder::<TestApp, _>::new(SingleScope)
        .with_if(true, DisabledAuthenticator::development())
        .build()
        .unwrap();
    assert_eq!(enabled.authenticator_names().len(), 1);

    let disabled = AuthnBuilder::<TestApp, _>::new(SingleScope)
        .with_if(false, DisabledAuthenticator::development())
        .build();
    // Skipping the only mechanism leaves an empty chain, which is caught.
    assert!(disabled.is_err());
}

#[test]
fn the_scope_resolver_reaches_the_gateway() {
    let gateway = AuthnBuilder::<TenantApp, _>::new(HeaderScopes)
        .with(DisabledAuthenticator::development())
        .build()
        .unwrap();

    let request = AuthRequest::builder().header("x-tenant", "acme").build();
    assert_eq!(gateway.scope_of(&request), Tenant("acme".into()));
}

// -------------------------------------------------------------------- env

#[cfg(feature = "env")]
mod env {
    use authn_kit::env::{EnvConfig, EnvError};

    /// Each test uses its own prefix, so the shared process environment cannot
    /// make them race against one another.
    fn set(prefix: &str, suffix: &str, value: &str) {
        // SAFETY: single-threaded within a test, and the prefix is unique to it.
        unsafe { std::env::set_var(format!("{prefix}{suffix}"), value) };
    }

    /// A prefix is mandatory: the suffixes are generic enough that an unprefixed
    /// `OIDC_CLIENT_ID` would be liable to collide with the host application's
    /// own configuration.
    #[test]
    fn an_empty_prefix_is_rejected() {
        assert!(matches!(
            EnvConfig::with_prefix("").unwrap_err(),
            EnvError::EmptyPrefix
        ));
        assert!(matches!(
            EnvConfig::with_prefix("   ").unwrap_err(),
            EnvError::EmptyPrefix
        ));
    }

    #[test]
    fn a_trailing_separator_is_supplied_when_missing() {
        assert_eq!(EnvConfig::with_prefix("MYAPP").unwrap().prefix(), "MYAPP_");
        assert_eq!(EnvConfig::with_prefix("MYAPP_").unwrap().prefix(), "MYAPP_");
        assert_eq!(EnvConfig::new().prefix(), "AUTHN_");
    }

    #[test]
    fn reads_values_under_a_configurable_prefix() {
        set("AK_T1_", "OIDC_CLIENT_ID", "my-client");
        let env = EnvConfig::with_prefix("AK_T1_").unwrap();

        assert_eq!(env.name("OIDC_CLIENT_ID"), "AK_T1_OIDC_CLIENT_ID");
        assert_eq!(
            env.get("OIDC_CLIENT_ID").unwrap().as_deref(),
            Some("my-client")
        );
        assert_eq!(env.get("ABSENT").unwrap(), None);
    }

    /// A variable set to the empty string means "not configured" in practice;
    /// treating it as a present blank value turns it into a confusing failure
    /// further downstream.
    #[test]
    fn an_empty_value_counts_as_unset() {
        set("AK_T2_", "OIDC_CLIENT_ID", "   ");
        let env = EnvConfig::with_prefix("AK_T2_").unwrap();

        assert_eq!(env.get("OIDC_CLIENT_ID").unwrap(), None);
        assert!(!env.is_set("OIDC_CLIENT_ID"));
    }

    /// The original's `get_from_env_unsafe(..).unwrap()` aborted the process
    /// with a backtrace; this names the variable.
    #[test]
    fn a_missing_required_value_names_the_variable() {
        let env = EnvConfig::with_prefix("AK_T3_").unwrap();
        let error = env.require("OIDC_ISSUER_URL").unwrap_err();

        assert!(matches!(error, EnvError::Missing { .. }));
        assert!(error.to_string().contains("AK_T3_OIDC_ISSUER_URL"));
    }

    /// The original logged a warning and silently used the default, so a typo in
    /// a numeric override went unnoticed.
    #[test]
    fn a_malformed_value_is_an_error_not_a_silent_default() {
        set("AK_T4_", "MAX_CACHE_TTL_SECS", "not-a-number");
        let env = EnvConfig::with_prefix("AK_T4_").unwrap();

        let error = env.parse_or::<u64>("MAX_CACHE_TTL_SECS", 300).unwrap_err();
        assert!(matches!(error, EnvError::Invalid { .. }));
        assert!(error.to_string().contains("AK_T4_MAX_CACHE_TTL_SECS"));
    }

    #[test]
    fn parse_or_falls_back_only_when_unset() {
        set("AK_T5_", "MAX_CACHE_TTL_SECS", "60");
        let env = EnvConfig::with_prefix("AK_T5_").unwrap();

        assert_eq!(env.parse_or::<u64>("MAX_CACHE_TTL_SECS", 300).unwrap(), 60);
        assert_eq!(env.parse_or::<u64>("ABSENT", 300).unwrap(), 300);
    }

    #[test]
    fn lists_accept_spaces_or_commas() {
        set("AK_T6_", "SPACED", "openid email profile");
        set("AK_T6_", "COMMAD", "openid, email ,profile");
        let env = EnvConfig::with_prefix("AK_T6_").unwrap();

        let expected = vec!["openid", "email", "profile"];
        assert_eq!(env.list("SPACED").unwrap().unwrap(), expected);
        assert_eq!(env.list("COMMAD").unwrap().unwrap(), expected);
        assert_eq!(env.list("ABSENT").unwrap(), None);
    }

    #[test]
    fn durations_are_read_in_seconds() {
        set("AK_T7_", "TTL_SECS", "45");
        let env = EnvConfig::with_prefix("AK_T7_").unwrap();

        assert_eq!(
            env.duration_secs("TTL_SECS").unwrap(),
            Some(std::time::Duration::from_secs(45))
        );
    }

    #[cfg(feature = "oidc")]
    #[test]
    fn builds_an_oidc_config_from_the_environment() {
        set("AK_T8_", "OIDC_ISSUER_URL", "https://idp.example");
        set("AK_T8_", "OIDC_CLIENT_ID", "my-client");
        set(
            "AK_T8_",
            "OIDC_REDIRECT_URL",
            "https://app.example/callback",
        );
        set("AK_T8_", "OIDC_SCOPES", "openid,groups");
        let env = EnvConfig::with_prefix("AK_T8_").unwrap();

        let config = env.oidc_config().unwrap();

        assert_eq!(config.issuer_url().as_str(), "https://idp.example");
        let scopes: Vec<&str> = config.scopes().iter().map(|s| s.as_str()).collect();
        assert_eq!(scopes, vec!["openid", "groups"]);
    }

    /// Secrets belong in a secret manager: `oidc_config` works without the
    /// secret variable set, and the caller supplies it afterwards.
    #[cfg(feature = "oidc")]
    #[test]
    fn the_client_secret_may_come_from_elsewhere() {
        set("AK_T9_", "OIDC_ISSUER_URL", "https://idp.example");
        set("AK_T9_", "OIDC_CLIENT_ID", "my-client");
        set(
            "AK_T9_",
            "OIDC_REDIRECT_URL",
            "https://app.example/callback",
        );
        let env = EnvConfig::with_prefix("AK_T9_").unwrap();

        let config = env.oidc_config().unwrap().with_client_secret("from-kms");
        assert_eq!(config.issuer_url().as_str(), "https://idp.example");
    }
}

#[allow(dead_code)]
fn _duration_is_used(_: Duration) {}
