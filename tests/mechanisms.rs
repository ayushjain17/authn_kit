//! Static tokens, the disabled authenticator, and the credential cache.

use std::{fmt::Display, time::Duration};

use authn_kit::{
    ApiTokenAuthenticator, AuthChain, AuthContext, AuthError, AuthProfile, AuthRequest,
    AuthScope, Authenticator, CacheConfig, ClaimSource, Credential, CredentialCache,
    DisabledAuthenticator, IdentityClaims, Outcome, Verdict,
    mechanisms::api_token::{StaticTokenError, StaticTokenSpec},
};
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
        Ok(Self {
            email: claims.email.clone().ok_or("email claim not found")?,
            username: claims
                .best_effort_username()
                .ok_or("no identity")?
                .to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Scope {
    Global,
    Tenant(String),
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => f.write_str("global"),
            Self::Tenant(id) => write!(f, "tenant_{id}"),
        }
    }
}

impl AuthScope for Scope {
    fn cache_discriminator(&self) -> Option<&str> {
        match self {
            Self::Global => None,
            Self::Tenant(id) => Some(id),
        }
    }
}

struct TestApp;

impl AuthProfile for TestApp {
    type User = User;
    type Scope = Scope;
}

const TOKENS: &str = r#"[
    {"token": "unscoped-secret", "principal": "svc-any"},
    {"token": "acme-secret", "principal": "svc-acme", "email": "acme@example.com",
     "scopes": ["acme"]},
    {"token": "multi-secret", "principal": "svc-multi", "scopes": ["acme", "globex"]}
]"#;

fn authenticator() -> ApiTokenAuthenticator<TestApp> {
    ApiTokenAuthenticator::from_json("sptok_", TOKENS).unwrap()
}

fn bearer(value: &str) -> Credential {
    Credential::Bearer(SecretString::from(value.to_string()))
}

async fn run(
    auth: &ApiTokenAuthenticator<TestApp>,
    credential: &Credential,
    scope: &Scope,
) -> Result<Verdict<User>, AuthError> {
    let request = AuthRequest::default();
    auth.authenticate(&AuthContext::new(&request, credential, scope))
        .await
}

// ------------------------------------------------------------ static tokens

#[tokio::test]
async fn matches_an_unscoped_token_in_any_scope() {
    let auth = authenticator();

    for scope in [
        Scope::Global,
        Scope::Tenant("acme".into()),
        Scope::Tenant("x".into()),
    ] {
        let verdict = run(&auth, &bearer("sptok_unscoped-secret"), &scope)
            .await
            .unwrap();
        assert_eq!(
            verdict,
            Verdict::Authenticated(User {
                email: "svc-any".into(),
                username: "svc-any".into(),
            }),
            "in {scope}"
        );
    }
}

#[test]
fn email_defaults_to_the_principal() {
    // `svc-acme` declares an email; `svc-any` does not and falls back.
    let specs: Vec<StaticTokenSpec> = serde_json::from_str(TOKENS).unwrap();
    assert_eq!(specs[0].email, None);
    assert_eq!(specs[1].email.as_deref(), Some("acme@example.com"));
}

#[tokio::test]
async fn scoped_token_is_confined_to_its_scopes() {
    let auth = authenticator();
    let credential = bearer("sptok_acme-secret");

    let verdict = run(&auth, &credential, &Scope::Tenant("acme".into()))
        .await
        .unwrap();
    assert!(matches!(verdict, Verdict::Authenticated(_)));

    // Another tenant, and the global scope, must both be refused.
    for scope in [Scope::Tenant("globex".into()), Scope::Global] {
        let error = run(&auth, &credential, &scope).await.unwrap_err();
        assert_eq!(error.status(), 401, "in {scope}");
    }
}

#[tokio::test]
async fn a_token_may_list_several_scopes() {
    let auth = authenticator();
    let credential = bearer("sptok_multi-secret");

    for scope in [Scope::Tenant("acme".into()), Scope::Tenant("globex".into())] {
        assert!(
            matches!(
                run(&auth, &credential, &scope).await,
                Ok(Verdict::Authenticated(_))
            ),
            "in {scope}"
        );
    }
    assert!(
        run(&auth, &credential, &Scope::Tenant("other".into()))
            .await
            .is_err()
    );
}

/// A bearer token without our prefix belongs to another mechanism, so this
/// authenticator must decline rather than reject — otherwise registering it
/// before an OIDC authenticator would break every OIDC bearer token.
#[tokio::test]
async fn declines_bearer_tokens_without_the_prefix() {
    let auth = authenticator();

    for value in [
        "eyJhbGciOiJSUzI1NiJ9.payload.sig",
        "other_prefix-secret",
        "",
    ] {
        let verdict = run(&auth, &bearer(value), &Scope::Global).await.unwrap();
        assert_eq!(verdict, Verdict::NotApplicable, "for {value:?}");
    }
}

#[tokio::test]
async fn declines_credentials_that_are_not_bearer() {
    let auth = authenticator();
    let credentials = [
        Credential::None,
        Credential::Basic {
            id: "a".into(),
            secret: SecretString::from("b".to_string()),
        },
        Credential::Other {
            scheme: "internal".into(),
            value: SecretString::from("t".to_string()),
        },
    ];

    for credential in credentials {
        assert_eq!(
            run(&auth, &credential, &Scope::Global).await.unwrap(),
            Verdict::NotApplicable
        );
    }
}

/// The prefix marks the token as an API key, so a non-matching key is a *bad*
/// API key — not something a later authenticator should try to parse as a JWT.
#[tokio::test]
async fn a_prefixed_but_unknown_token_is_rejected_rather_than_passed_on() {
    let auth = authenticator();

    let error = run(&auth, &bearer("sptok_wrong"), &Scope::Global)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 401);
}

#[tokio::test]
async fn a_near_miss_does_not_authenticate() {
    let auth = authenticator();

    for value in [
        "sptok_unscoped-secre",   // one byte short
        "sptok_unscoped-secretX", // one byte long
        "sptok_Unscoped-secret",  // case differs
    ] {
        assert!(
            run(&auth, &bearer(value), &Scope::Global).await.is_err(),
            "{value}"
        );
    }
}

// ------------------------------------------------------------ construction

#[test]
fn a_malformed_token_list_fails_construction() {
    let error = ApiTokenAuthenticator::<TestApp>::from_json("sptok_", "{not an array}")
        .unwrap_err();
    assert!(matches!(error, StaticTokenError::Malformed(_)));
}

#[test]
fn an_empty_token_list_is_permitted() {
    let auth = ApiTokenAuthenticator::<TestApp>::from_json("sptok_", "  ").unwrap();
    assert_eq!(auth.token_count(), 0);
}

#[test]
fn an_empty_prefix_is_rejected() {
    let error = ApiTokenAuthenticator::<TestApp>::from_json("", TOKENS).unwrap_err();
    assert!(matches!(error, StaticTokenError::EmptyPrefix));
}

#[test]
fn an_empty_token_value_is_rejected() {
    let error = ApiTokenAuthenticator::<TestApp>::from_json(
        "sptok_",
        r#"[{"token": "", "principal": "svc"}]"#,
    )
    .unwrap_err();
    assert!(matches!(error, StaticTokenError::EmptyToken(p) if p == "svc"));
}

// -------------------------------------------------------------- chain order

/// Because the prefix disambiguates, a static-token authenticator can sit either
/// side of a bearer authenticator without changing the outcome.
#[tokio::test]
async fn prefix_makes_chain_order_irrelevant() {
    struct JwtShaped;

    #[async_trait::async_trait]
    impl Authenticator<TestApp> for JwtShaped {
        fn name(&self) -> &'static str {
            "jwt-shaped"
        }

        async fn authenticate(
            &self,
            ctx: &AuthContext<'_, TestApp>,
        ) -> Result<Verdict<User>, AuthError> {
            use secrecy::ExposeSecret;
            match ctx.credential {
                // Only claims things that look like a JWT.
                Credential::Bearer(t) if t.expose_secret().split('.').count() == 3 => {
                    Ok(Verdict::Authenticated(User {
                        email: "jwt@example.com".into(),
                        username: "jwt".into(),
                    }))
                }
                _ => Ok(Verdict::NotApplicable),
            }
        }
    }

    let api_key = bearer("sptok_unscoped-secret");
    let jwt = bearer("header.payload.signature");

    for static_first in [true, false] {
        let chain = if static_first {
            AuthChain::<TestApp>::new()
                .with(authenticator())
                .with(JwtShaped)
        } else {
            AuthChain::<TestApp>::new()
                .with(JwtShaped)
                .with(authenticator())
        };

        let via_api_key = chain
            .authenticate(&AuthRequest::default(), &api_key, &Scope::Global)
            .await
            .unwrap();
        let via_jwt = chain
            .authenticate(&AuthRequest::default(), &jwt, &Scope::Global)
            .await
            .unwrap();

        assert_eq!(
            via_api_key,
            Outcome::Authenticated(User {
                email: "svc-any".into(),
                username: "svc-any".into()
            }),
            "static_first={static_first}"
        );
        assert_eq!(
            via_jwt,
            Outcome::Authenticated(User {
                email: "jwt@example.com".into(),
                username: "jwt".into()
            }),
            "static_first={static_first}"
        );
    }
}

// ---------------------------------------------------------------- disabled

#[tokio::test]
async fn disabled_authenticator_authenticates_everything() {
    let auth = DisabledAuthenticator::<TestApp>::development();
    let request = AuthRequest::default();

    let verdict = auth
        .authenticate(&AuthContext::new(
            &request,
            &Credential::None,
            &Scope::Global,
        ))
        .await
        .unwrap();

    let Verdict::Authenticated(user) = verdict else {
        panic!("expected Authenticated");
    };
    // Conspicuously named, so it cannot be mistaken for a real principal in an
    // audit log — unlike the original's `user@superposition.io`.
    assert_eq!(user.username, "authn-disabled");
    assert_eq!(user.email, "authn-disabled@invalid");
}

#[tokio::test]
async fn disabled_authenticator_reports_an_unconvertible_identity() {
    // No email claim, and this fixture's `TryFrom` requires one.
    let auth = DisabledAuthenticator::<TestApp>::new(
        IdentityClaims::new(ClaimSource::StaticToken).with_subject("x"),
    );
    let request = AuthRequest::default();

    let error = auth
        .authenticate(&AuthContext::new(
            &request,
            &Credential::None,
            &Scope::Global,
        ))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 500);
}

// ------------------------------------------------------------------- cache

fn alice() -> User {
    User {
        email: "alice@example.com".into(),
        username: "alice".into(),
    }
}

fn cache() -> CredentialCache<User> {
    CredentialCache::new(CacheConfig {
        refresh_margin: Duration::ZERO,
        fallback_ttl: Duration::from_secs(60),
        max_entries: 4,
    })
}

#[test]
fn cache_round_trips_a_principal() {
    let cache = cache();
    let key = CredentialCache::<User>::key(None, "basic", "alice", "secret");

    assert_eq!(cache.get(&key), None);
    cache.insert(key.clone(), alice(), Some(Duration::from_secs(60)));
    assert_eq!(cache.get(&key), Some(alice()));
}

/// Every component of the key must separate entries. The scope one is the
/// important case: the original left passing it to each call site, so a
/// mechanism that forgot would serve one tenant's principal to another.
#[test]
fn every_key_component_separates_entries() {
    let cache = cache();
    let base = CredentialCache::<User>::key(Some("acme"), "basic", "alice", "secret");
    cache.insert(base.clone(), alice(), Some(Duration::from_secs(60)));

    let variants = [
        CredentialCache::<User>::key(Some("globex"), "basic", "alice", "secret"),
        CredentialCache::<User>::key(None, "basic", "alice", "secret"),
        CredentialCache::<User>::key(Some("acme"), "api-token", "alice", "secret"),
        CredentialCache::<User>::key(Some("acme"), "basic", "bob", "secret"),
        CredentialCache::<User>::key(Some("acme"), "basic", "alice", "rotated"),
    ];

    for variant in variants {
        assert_eq!(cache.get(&variant), None);
    }
    assert_eq!(cache.get(&base), Some(alice()));
}

/// A token expiring sooner than the safety margin is not worth caching: the
/// entry would be stale before it could be used.
#[test]
fn a_token_expiring_within_the_safety_margin_is_not_cached() {
    let cache = CredentialCache::<User>::new(CacheConfig {
        refresh_margin: Duration::from_secs(30),
        ..CacheConfig::default()
    });
    let key = CredentialCache::<User>::key(None, "basic", "alice", "secret");

    cache.insert(key.clone(), alice(), Some(Duration::from_secs(10)));

    assert_eq!(cache.get(&key), None);
    assert!(cache.is_empty());
}

/// The original called `retain` over the whole map on every insert and had no
/// size limit at all.
#[test]
fn cache_is_bounded() {
    let cache = cache();

    for index in 0..50 {
        let key = CredentialCache::<User>::key(
            None,
            "basic",
            &format!("user-{index}"),
            "secret",
        );
        cache.insert(key, alice(), Some(Duration::from_secs(60)));
    }

    assert!(cache.len() <= 4, "cache grew to {}", cache.len());
}

/// Under pressure the cache must keep serving its hot credentials. Dropping new
/// entries instead (the simpler policy) means a full cache silently stops
/// caching at all, and every request revalidates against the provider.
#[test]
fn eviction_keeps_the_most_recently_used() {
    let cache = cache(); // max_entries = 4
    let hot = CredentialCache::<User>::key(None, "basic", "hot", "secret");

    cache.insert(hot.clone(), alice(), Some(Duration::from_secs(60)));
    for name in ["cold-a", "cold-b", "cold-c"] {
        let key = CredentialCache::<User>::key(None, "basic", name, "secret");
        cache.insert(key, alice(), Some(Duration::from_secs(60)));
    }

    // Touch the hot entry so it is the most recently used.
    assert_eq!(cache.get(&hot), Some(alice()));

    // Two more inserts force two evictions.
    for name in ["new-a", "new-b"] {
        let key = CredentialCache::<User>::key(None, "basic", name, "secret");
        cache.insert(key, alice(), Some(Duration::from_secs(60)));
    }

    assert_eq!(cache.get(&hot), Some(alice()), "the hot entry was evicted");
    assert!(cache.len() <= 4);
}

#[test]
fn re_inserting_an_existing_key_does_not_evict() {
    let cache = cache();
    let keys: Vec<_> = ["a", "b", "c", "d"]
        .iter()
        .map(|name| CredentialCache::<User>::key(None, "basic", name, "secret"))
        .collect();
    for key in &keys {
        cache.insert(key.clone(), alice(), Some(Duration::from_secs(60)));
    }

    // Refreshing an entry already present must not push anything out.
    cache.insert(keys[0].clone(), alice(), Some(Duration::from_secs(60)));

    for key in &keys {
        assert_eq!(cache.get(key), Some(alice()));
    }
}

#[test]
fn an_entry_can_be_invalidated() {
    let cache = cache();
    let key = CredentialCache::<User>::key(None, "basic", "alice", "secret");
    cache.insert(key.clone(), alice(), Some(Duration::from_secs(60)));

    cache.invalidate(&key);

    assert_eq!(cache.get(&key), None);
}
