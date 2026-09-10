#![cfg(feature = "introspection")]
//! RFC 7662 introspection, and its interaction with static tokens.

#[path = "support/mock_introspection.rs"]
mod mock_introspection;

use std::{fmt::Display, sync::Arc, time::Duration};

use authn_kit::{
    ApiTokenAuthenticator, AuthContext, AuthError, AuthProfile, AuthRequest, AuthScope,
    Authenticator, CacheConfig, ClaimSource, Credential, IdentityClaims, Verdict,
    mechanisms::{IntrospectionValidator, TokenValidator},
};
use mock_introspection::MockIntrospection;
use secrecy::SecretString;

// ---------------------------------------------------------------- fixture

#[derive(Clone, Debug, PartialEq, Eq)]
struct User {
    email: String,
    username: String,
}

impl TryFrom<IdentityClaims> for User {
    type Error = String;

    fn try_from(claims: IdentityClaims) -> Result<Self, Self::Error> {
        let username = claims
            .best_effort_username()
            .ok_or("no identity")?
            .to_string();
        Ok(Self {
            email: claims.email.clone().unwrap_or_else(|| username.clone()),
            username,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Scope;

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("global")
    }
}

impl AuthScope for Scope {}

struct TestApp;

impl AuthProfile for TestApp {
    type User = User;
    type Scope = Scope;
}

const ACTIVE: &str = r#"{
    "active": true,
    "sub": "svc-1",
    "username": "reporting-service",
    "email": "reporting@example.com",
    "scope": "config:read config:write",
    "client_id": "reporting",
    "exp": 4102444800,
    "custom_tenant": "acme"
}"#;

const STATIC_TOKENS: &str = r#"[{"token": "local-secret", "principal": "svc-local"}]"#;

fn validator(idp: &MockIntrospection) -> Arc<IntrospectionValidator> {
    Arc::new(
        IntrospectionValidator::new(idp.url.clone(), "Bearer endpoint-credential")
            .unwrap(),
    )
}

fn authenticator(idp: &MockIntrospection) -> ApiTokenAuthenticator<TestApp> {
    ApiTokenAuthenticator::from_json("sptok_", STATIC_TOKENS)
        .unwrap()
        .with_fallback(validator(idp))
}

async fn run(
    auth: &ApiTokenAuthenticator<TestApp>,
    token: &str,
) -> Result<Verdict<User>, AuthError> {
    let request = AuthRequest::default();
    let credential = Credential::Bearer(SecretString::from(token.to_string()));
    auth.authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
}

// ------------------------------------------------------------ claim mapping

#[tokio::test]
async fn maps_an_active_response_onto_identity_claims() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let claims = validator(&idp).validate("key", None).await.unwrap();

    assert_eq!(claims.source, ClaimSource::Introspection);
    assert_eq!(claims.subject.as_deref(), Some("svc-1"));
    assert_eq!(
        claims.preferred_username.as_deref(),
        Some("reporting-service")
    );
    assert_eq!(claims.email.as_deref(), Some("reporting@example.com"));
    assert_eq!(claims.client_id.as_deref(), Some("reporting"));
    assert_eq!(
        claims.scopes().collect::<Vec<_>>(),
        vec!["config:read", "config:write"]
    );
    assert!(claims.expires_at.is_some());
}

/// The original modelled four response fields and discarded the rest, so a
/// custom claim could not reach the application without editing the auth module.
#[tokio::test]
async fn preserves_non_standard_response_claims() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let claims = validator(&idp).validate("key", None).await.unwrap();

    assert_eq!(
        claims.extra_claim::<String>("custom_tenant").as_deref(),
        Some("acme")
    );
}

// ------------------------------------------------------------ request shape

#[tokio::test]
async fn presents_the_configured_authorization_header_verbatim() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    validator(&idp).validate("the-api-key", None).await.unwrap();

    let recorded = idp.requests().pop().unwrap();
    // Verbatim, not re-derived: the endpoint may expect any scheme.
    assert_eq!(
        recorded.authorization.as_deref(),
        Some("Bearer endpoint-credential")
    );
    assert_eq!(
        recorded.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(recorded.body, "token=the-api-key");
}

// -------------------------------------------------------------- failures

#[tokio::test]
async fn an_inactive_token_is_the_clients_problem() {
    let idp = MockIntrospection::start(200, r#"{"active": false}"#).await;
    let error = validator(&idp).validate("key", None).await.unwrap_err();

    assert_eq!(error.status(), 401);
    assert!(!error.is_service_fault());
}

/// "We could not check your token" must be distinguishable from "your token is
/// bad", so a client knows whether retrying is worthwhile.
#[tokio::test]
async fn endpoint_failures_are_service_faults() {
    let cases = [
        (500, ACTIVE, "upstream error"),
        (200, "not json at all", "unparseable body"),
        (
            200,
            r#"{"sub": "x"}"#,
            "missing the required `active` member",
        ),
        (200, r#"{"active": true}"#, "active but no identity claim"),
        (200, r#"["not", "an", "object"]"#, "not an object"),
    ];

    for (status, body, why) in cases {
        let idp = MockIntrospection::start(status, body).await;
        let error = validator(&idp).validate("key", None).await.unwrap_err();

        assert_eq!(error.status(), 503, "for {why}");
        assert!(error.is_service_fault(), "for {why}");
    }
}

// ------------------------------------------------------- combined with static

/// Static tokens are checked first and locally, so a static hit never touches
/// the network — the ordering the original had inside `ApiTokenConfig`.
#[tokio::test]
async fn a_static_token_short_circuits_introspection() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let auth = authenticator(&idp);

    let verdict = run(&auth, "sptok_local-secret").await.unwrap();

    assert_eq!(
        verdict,
        Verdict::Authenticated(User {
            email: "svc-local".into(),
            username: "svc-local".into()
        })
    );
    assert_eq!(
        idp.call_count(),
        0,
        "introspection should not have been called"
    );
}

#[tokio::test]
async fn an_unknown_key_falls_through_to_introspection() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let auth = authenticator(&idp);

    let verdict = run(&auth, "sptok_remote-secret").await.unwrap();

    assert_eq!(
        verdict,
        Verdict::Authenticated(User {
            email: "reporting@example.com".into(),
            username: "reporting-service".into()
        })
    );
    assert_eq!(idp.call_count(), 1);
    // The prefix is stripped before the key reaches the endpoint.
    assert_eq!(idp.requests()[0].body, "token=remote-secret");
}

/// Without a fallback the behaviour is the 5a one: a prefixed but unrecognised
/// key is a bad API key, not something a later mechanism should try to parse.
#[tokio::test]
async fn without_a_fallback_an_unknown_key_is_rejected() {
    let auth =
        ApiTokenAuthenticator::<TestApp>::from_json("sptok_", STATIC_TOKENS).unwrap();

    let error = run(&auth, "sptok_unknown").await.unwrap_err();
    assert_eq!(error.status(), 401);
}

#[tokio::test]
async fn a_bearer_token_without_the_prefix_is_never_introspected() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let auth = authenticator(&idp);

    let verdict = run(&auth, "header.payload.signature").await.unwrap();

    assert_eq!(verdict, Verdict::NotApplicable);
    assert_eq!(idp.call_count(), 0);
}

// ---------------------------------------------------------------- caching

#[tokio::test]
async fn introspection_results_are_cached() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let auth = authenticator(&idp);

    for _ in 0..3 {
        assert!(matches!(
            run(&auth, "sptok_remote-secret").await,
            Ok(Verdict::Authenticated(_))
        ));
    }

    assert_eq!(
        idp.call_count(),
        1,
        "the endpoint was called more than once"
    );
}

#[tokio::test]
async fn distinct_keys_are_cached_separately() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let auth = authenticator(&idp);

    run(&auth, "sptok_key-one").await.unwrap();
    run(&auth, "sptok_key-two").await.unwrap();

    assert_eq!(idp.call_count(), 2);
}

/// The response's `exp` is in 2100, but revocation is the point of introspection,
/// so caching is capped regardless of how long-lived the token claims to be.
#[tokio::test]
async fn caching_is_capped_below_a_distant_token_expiry() {
    let idp = MockIntrospection::start(200, ACTIVE).await;
    let auth = ApiTokenAuthenticator::<TestApp>::from_json("sptok_", STATIC_TOKENS)
        .unwrap()
        .with_fallback(validator(&idp))
        // Shorter than the safety margin, so the entry is never cached at all —
        // which is the observable end of "the cap is applied, not the `exp`".
        .with_max_cache_ttl(Duration::from_secs(5))
        .with_cache_config(CacheConfig {
            refresh_margin: Duration::from_secs(30),
            ..CacheConfig::default()
        });

    run(&auth, "sptok_remote-secret").await.unwrap();
    run(&auth, "sptok_remote-secret").await.unwrap();

    assert_eq!(
        idp.call_count(),
        2,
        "the distant `exp` was used instead of the cap"
    );
}
