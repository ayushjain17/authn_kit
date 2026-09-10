//! Behavioural tests for the framework-agnostic core.
//!
//! These use only the public API, which doubles as a check that the crate is
//! actually usable from outside without reaching into private modules.

use std::{
    fmt::Display,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use authn_kit::{
    AuthChain, AuthContext, AuthError, AuthProfile, AuthRequest, AuthScope,
    Authenticator, ClaimSource, CookieDirective, Credential, IdentityClaims, Outcome,
    PublicScopePolicy, SameSite, Verdict,
};
use secrecy::SecretString;

// ---------------------------------------------------------------- test fixture

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
                .ok_or("no usable identity claim")?
                .to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Scope {
    Public,
    Tenant(String),
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Tenant(id) => write!(f, "tenant_{id}"),
        }
    }
}

impl AuthScope for Scope {
    fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    fn cache_discriminator(&self) -> Option<&str> {
        match self {
            Self::Public => None,
            Self::Tenant(id) => Some(id),
        }
    }
}

struct TestApp;

impl AuthProfile for TestApp {
    type User = User;
    type Scope = Scope;
}

/// An authenticator whose behaviour is scripted, recording whether it ran.
struct Scripted {
    name: &'static str,
    calls: Arc<AtomicUsize>,
    result: fn() -> Result<Verdict<User>, AuthError>,
}

impl Scripted {
    fn new(
        name: &'static str,
        result: fn() -> Result<Verdict<User>, AuthError>,
    ) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                name,
                calls: calls.clone(),
                result,
            },
            calls,
        )
    }
}

#[async_trait]
impl Authenticator<TestApp> for Scripted {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn authenticate(
        &self,
        _ctx: &AuthContext<'_, TestApp>,
    ) -> Result<Verdict<User>, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.result)()
    }
}

fn alice() -> User {
    User {
        email: "alice@example.com".into(),
        username: "alice".into(),
    }
}

fn bearer() -> Credential {
    Credential::Bearer(SecretString::from("token".to_string()))
}

// ------------------------------------------------------------------ principal

#[test]
fn principal_is_derived_from_try_from() {
    let claims = IdentityClaims::new(ClaimSource::IdToken)
        .with_email("alice@example.com")
        .with_preferred_username("alice");

    assert_eq!(User::try_from(claims).unwrap(), alice());
}

#[test]
fn principal_conversion_reports_missing_claims() {
    let claims =
        IdentityClaims::new(ClaimSource::ClientCredentials).with_client_id("svc");

    assert_eq!(
        User::try_from(claims).unwrap_err(),
        "email claim not found".to_string()
    );
}

#[test]
fn username_falls_back_across_claims_in_order() {
    let base = IdentityClaims::new(ClaimSource::Introspection);
    assert_eq!(base.best_effort_username(), None);

    let with_client = base.clone().with_client_id("svc");
    assert_eq!(with_client.best_effort_username(), Some("svc"));

    let with_subject = with_client.clone().with_subject("sub-1");
    assert_eq!(with_subject.best_effort_username(), Some("sub-1"));

    let with_email = with_subject.clone().with_email("a@example.com");
    assert_eq!(with_email.best_effort_username(), Some("a@example.com"));

    let with_preferred = with_email.with_preferred_username("alice");
    assert_eq!(with_preferred.best_effort_username(), Some("alice"));
}

#[test]
fn extra_claims_are_reachable_without_being_modelled() {
    let claims = IdentityClaims::new(ClaimSource::IdToken)
        .with_extra("groups", serde_json::json!(["admin", "dev"]))
        .with_scope("openid email profile");

    assert_eq!(
        claims.extra_claim::<Vec<String>>("groups"),
        Some(vec!["admin".to_string(), "dev".to_string()])
    );
    assert_eq!(claims.extra_claim::<Vec<String>>("absent"), None);
    assert_eq!(
        claims.scopes().collect::<Vec<_>>(),
        vec!["openid", "email", "profile"]
    );
}

// -------------------------------------------------------------------- request

#[test]
fn header_lookup_is_case_insensitive() {
    let request = AuthRequest::builder()
        .header("X-Org-Id", "acme")
        .header("x-org-id", "second")
        .build();

    assert_eq!(request.header("x-org-id"), Some("acme"));
    assert_eq!(request.header("X-ORG-ID"), Some("acme"));
    assert_eq!(request.header_all("X-Org-Id").len(), 2);
    assert_eq!(request.header("absent"), None);
}

/// The original `get_query_param` used `segment.contains("org=")`, so a lookup
/// for `org` also matched `other_org=...`.
#[test]
fn query_param_matches_whole_names_only() {
    let request = AuthRequest::builder()
        .query("other_org=wrong&org=right")
        .build();

    assert_eq!(request.query_param("org"), Some("right"));
    assert_eq!(request.query_param("other_org"), Some("wrong"));
    assert_eq!(request.query_param("or"), None);
}

/// The original took `nth(1)` after splitting the segment on *every* `=`, which
/// truncated base64 and JWT values at their first padding character.
#[test]
fn query_param_preserves_values_containing_equals() {
    let request = AuthRequest::builder()
        .query("state=aGVsbG8=&code=x")
        .build();

    assert_eq!(request.query_param("state"), Some("aGVsbG8="));
    assert_eq!(request.query_param("code"), Some("x"));
}

#[test]
fn path_param_aligns_pattern_against_path() {
    let request = AuthRequest::builder()
        .path("/admin/acme/workspaces")
        .route_pattern(Some("/admin/{org_id}/workspaces".to_string()))
        .build();

    assert_eq!(request.path_param("{org_id}"), Some("acme"));
    assert_eq!(request.path_param("{absent}"), None);
}

#[test]
fn path_param_is_none_without_a_route_pattern() {
    let request = AuthRequest::builder().path("/admin/acme").build();

    assert_eq!(request.path_param("{org_id}"), None);
}

#[test]
fn cookies_round_trip() {
    let request = AuthRequest::builder()
        .cookie("session", "jwt-value")
        .build();

    assert_eq!(request.cookie("session"), Some("jwt-value"));
    assert_eq!(request.cookie("absent"), None);
}

// ------------------------------------------------------------------ chain

#[tokio::test]
async fn chain_skips_authenticators_that_decline() {
    let (declines, declined_calls) =
        Scripted::new("declines", || Ok(Verdict::NotApplicable));
    let (accepts, accepted_calls) =
        Scripted::new("accepts", || Ok(Verdict::Authenticated(alice())));

    let chain = AuthChain::<TestApp>::new().with(declines).with(accepts);
    let outcome = chain
        .authenticate(
            &AuthRequest::default(),
            &bearer(),
            &Scope::Tenant("acme".into()),
        )
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::Authenticated(alice()));
    assert_eq!(declined_calls.load(Ordering::SeqCst), 1);
    assert_eq!(accepted_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn chain_stops_at_the_first_authenticator_that_claims_the_request() {
    let (first, _) = Scripted::new("first", || Ok(Verdict::Authenticated(alice())));
    let (second, second_calls) = Scripted::new("second", || Ok(Verdict::NotApplicable));

    let chain = AuthChain::<TestApp>::new().with(first).with(second);
    chain
        .authenticate(
            &AuthRequest::default(),
            &bearer(),
            &Scope::Tenant("acme".into()),
        )
        .await
        .unwrap();

    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
}

/// A rejected credential must never fall through to a weaker mechanism.
#[tokio::test]
async fn chain_fails_closed_on_error() {
    let (rejects, _) = Scripted::new("rejects", || {
        Err(AuthError::invalid_credential("bad signature"))
    });
    let (fallback, fallback_calls) =
        Scripted::new("fallback", || Ok(Verdict::Authenticated(alice())));

    let chain = AuthChain::<TestApp>::new().with(rejects).with(fallback);
    let error = chain
        .authenticate(
            &AuthRequest::default(),
            &bearer(),
            &Scope::Tenant("acme".into()),
        )
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn chain_reports_not_applicable_when_nothing_claims_a_protected_request() {
    let (declines, _) = Scripted::new("declines", || Ok(Verdict::NotApplicable));

    let chain = AuthChain::<TestApp>::new().with(declines);
    let outcome = chain
        .authenticate(
            &AuthRequest::default(),
            &Credential::None,
            &Scope::Tenant("acme".into()),
        )
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::NotApplicable);
}

#[tokio::test]
async fn public_scope_without_a_credential_is_anonymous() {
    let (never, never_calls) =
        Scripted::new("never", || Ok(Verdict::Authenticated(alice())));

    let chain = AuthChain::<TestApp>::new().with(never);
    let outcome = chain
        .authenticate(&AuthRequest::default(), &Credential::None, &Scope::Public)
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::Anonymous);
    assert_eq!(never_calls.load(Ordering::SeqCst), 0);
}

/// Optional auth: a public route still resolves a principal when one is offered.
#[tokio::test]
async fn public_scope_with_a_valid_credential_still_authenticates() {
    let (accepts, _) = Scripted::new("accepts", || Ok(Verdict::Authenticated(alice())));

    let chain = AuthChain::<TestApp>::new().with(accepts);
    let outcome = chain
        .authenticate(&AuthRequest::default(), &bearer(), &Scope::Public)
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::Authenticated(alice()));
}

/// ...and an invalid one is never silently downgraded to anonymous.
#[tokio::test]
async fn public_scope_with_an_invalid_credential_fails() {
    let (rejects, _) =
        Scripted::new("rejects", || Err(AuthError::invalid_credential("bad")));

    let chain = AuthChain::<TestApp>::new().with(rejects);
    let error = chain
        .authenticate(&AuthRequest::default(), &bearer(), &Scope::Public)
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
}

#[tokio::test]
async fn always_anonymous_policy_reproduces_the_original_behaviour() {
    let (never, never_calls) =
        Scripted::new("never", || Err(AuthError::invalid_credential("bad")));

    let chain = AuthChain::<TestApp>::new()
        .public_scope_policy(PublicScopePolicy::AlwaysAnonymous)
        .with(never);
    let outcome = chain
        .authenticate(&AuthRequest::default(), &bearer(), &Scope::Public)
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::Anonymous);
    assert_eq!(never_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn empty_chain_declines_rather_than_panicking() {
    let chain = AuthChain::<TestApp>::new();
    assert!(chain.is_empty());

    let outcome = chain
        .authenticate(
            &AuthRequest::default(),
            &bearer(),
            &Scope::Tenant("acme".into()),
        )
        .await
        .unwrap();

    assert_eq!(outcome, Outcome::NotApplicable);
}

// -------------------------------------------------------------------- errors

#[test]
fn error_statuses_distinguish_client_and_service_faults() {
    let cases: Vec<(AuthError, u16, bool)> = vec![
        (AuthError::unauthenticated("no cookie"), 401, false),
        (AuthError::invalid_credential("bad sig"), 401, false),
        (AuthError::malformed_credential("bad base64"), 400, false),
        (AuthError::scope_denied("wrong org"), 403, false),
        (AuthError::unsupported("no password grant"), 501, false),
        (AuthError::upstream("idp timeout"), 503, true),
        (AuthError::internal("missing config"), 500, true),
        (AuthError::redirect("https://idp/auth", vec![]), 302, false),
    ];

    for (error, status, is_fault) in cases {
        assert_eq!(error.status(), status, "{error}");
        assert_eq!(error.is_service_fault(), is_fault, "{error}");
    }
}

/// Operator detail must never reach the client.
#[test]
fn client_messages_do_not_leak_internal_detail() {
    let error = AuthError::upstream("connect to https://internal-idp.svc:8443 refused");

    assert_eq!(error.client_message(), "Authentication service unavailable");
    assert!(error.detail().contains("internal-idp.svc"));
    assert!(!error.client_message().contains("internal-idp.svc"));
}

// ---------------------------------------------------------------- credential

#[test]
fn credential_debug_redacts_secrets_but_keeps_the_public_id() {
    let basic = Credential::Basic {
        id: "client-42".into(),
        secret: SecretString::from("hunter2".to_string()),
    };

    let rendered = format!("{basic:?}");
    assert!(rendered.contains("client-42"));
    assert!(!rendered.contains("hunter2"));
    assert!(!format!("{:?}", bearer()).contains("token"));
}

#[test]
fn credential_reports_its_scheme() {
    assert_eq!(bearer().scheme(), Some("bearer"));
    assert_eq!(Credential::None.scheme(), None);
    assert!(Credential::None.is_none());

    let internal = Credential::Other {
        scheme: "internal".into(),
        value: SecretString::from("t".to_string()),
    };
    assert_eq!(internal.scheme(), Some("internal"));
}

// ============================================================ exhaustive chain
//
// `AuthChain::authenticate` branches on four independent inputs, giving a
// decision space of 2 x 2 x 2 x 3 = 24 cases. That is small enough to enumerate
// rather than sample, so the table below is the specification: every row states
// the outcome *and* whether the chain was allowed to consult the authenticator
// at all.
//
// The script has three arms, not four, because `Verdict` gives an authenticator
// no way to declare a request anonymous. An earlier revision folded that into a
// single `Outcome` type, and this table is what caught it: an authenticator
// could return `Anonymous` on a *protected* scope and the chain would propagate
// it, waving the request through unauthenticated.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    Authenticate,
    Decline,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Authenticated,
    Anonymous,
    NotApplicable,
    Failed,
}

struct Programmed {
    script: Script,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Authenticator<TestApp> for Programmed {
    fn name(&self) -> &'static str {
        "programmed"
    }

    async fn authenticate(
        &self,
        _ctx: &AuthContext<'_, TestApp>,
    ) -> Result<Verdict<User>, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.script {
            Script::Authenticate => Ok(Verdict::Authenticated(alice())),
            Script::Decline => Ok(Verdict::NotApplicable),
            Script::Fail => Err(AuthError::invalid_credential("scripted failure")),
        }
    }
}

async fn run_case(
    public: bool,
    policy: PublicScopePolicy,
    credential: Credential,
    script: Script,
) -> (Expect, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let chain = AuthChain::<TestApp>::new()
        .public_scope_policy(policy)
        .with(Programmed {
            script,
            calls: calls.clone(),
        });

    let scope = if public {
        Scope::Public
    } else {
        Scope::Tenant("acme".into())
    };
    let expect = match chain
        .authenticate(&AuthRequest::default(), &credential, &scope)
        .await
    {
        Ok(Outcome::Authenticated(_)) => Expect::Authenticated,
        Ok(Outcome::Anonymous) => Expect::Anonymous,
        Ok(Outcome::NotApplicable) => Expect::NotApplicable,
        Err(_) => Expect::Failed,
    };
    (expect, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn chain_decision_table_is_exhaustive() {
    use Expect as E;
    use PublicScopePolicy::{AlwaysAnonymous, Optional};
    use Script as S;

    // (public, policy, credential_present, script) => (outcome, times consulted)
    let table = [
        // -- protected scope: the policy and credential guards do not apply -----
        (false, Optional, false, S::Authenticate, E::Authenticated, 1),
        (false, Optional, false, S::Decline, E::NotApplicable, 1),
        (false, Optional, false, S::Fail, E::Failed, 1),
        (false, Optional, true, S::Authenticate, E::Authenticated, 1),
        (false, Optional, true, S::Decline, E::NotApplicable, 1),
        (false, Optional, true, S::Fail, E::Failed, 1),
        (
            false,
            AlwaysAnonymous,
            false,
            S::Authenticate,
            E::Authenticated,
            1,
        ),
        (
            false,
            AlwaysAnonymous,
            false,
            S::Decline,
            E::NotApplicable,
            1,
        ),
        (false, AlwaysAnonymous, false, S::Fail, E::Failed, 1),
        (
            false,
            AlwaysAnonymous,
            true,
            S::Authenticate,
            E::Authenticated,
            1,
        ),
        (
            false,
            AlwaysAnonymous,
            true,
            S::Decline,
            E::NotApplicable,
            1,
        ),
        (false, AlwaysAnonymous, true, S::Fail, E::Failed, 1),
        // -- public + AlwaysAnonymous: short-circuits, never consults -----------
        (
            true,
            AlwaysAnonymous,
            false,
            S::Authenticate,
            E::Anonymous,
            0,
        ),
        (true, AlwaysAnonymous, false, S::Decline, E::Anonymous, 0),
        (true, AlwaysAnonymous, false, S::Fail, E::Anonymous, 0),
        (
            true,
            AlwaysAnonymous,
            true,
            S::Authenticate,
            E::Anonymous,
            0,
        ),
        (true, AlwaysAnonymous, true, S::Decline, E::Anonymous, 0),
        (true, AlwaysAnonymous, true, S::Fail, E::Anonymous, 0),
        // -- public + Optional, no credential: nothing to check -----------------
        (true, Optional, false, S::Authenticate, E::Anonymous, 0),
        (true, Optional, false, S::Decline, E::Anonymous, 0),
        (true, Optional, false, S::Fail, E::Anonymous, 0),
        // -- public + Optional, credential offered: validate it -----------------
        (true, Optional, true, S::Authenticate, E::Authenticated, 1),
        (true, Optional, true, S::Decline, E::Anonymous, 1),
        (true, Optional, true, S::Fail, E::Failed, 1),
    ];

    assert_eq!(
        table.len(),
        24,
        "decision space must be covered exhaustively"
    );

    for (public, policy, has_credential, script, expected, expected_calls) in table {
        let credential = if has_credential {
            bearer()
        } else {
            Credential::None
        };
        let (outcome, calls) = run_case(public, policy, credential, script).await;

        let case = format!(
            "public={public} policy={policy:?} credential={has_credential} script={script:?}"
        );
        assert_eq!(outcome, expected, "outcome for {case}");
        assert_eq!(calls, expected_calls, "consultations for {case}");
    }
}

// ------------------------------------------------------- structural invariants
//
// The table pins current behaviour. These pin the properties that must hold for
// *any* future change to the chain, including ones that legitimately alter a
// table row.

/// P1 - the chain never invents an identity: `Authenticated` out implies
/// `Authenticated` in.
#[tokio::test]
async fn chain_never_fabricates_a_principal() {
    for script in [Script::Decline, Script::Fail] {
        for public in [true, false] {
            for has_credential in [true, false] {
                let credential = if has_credential {
                    bearer()
                } else {
                    Credential::None
                };
                let (outcome, _) =
                    run_case(public, PublicScopePolicy::Optional, credential, script)
                        .await;
                assert_ne!(
                    outcome,
                    Expect::Authenticated,
                    "script={script:?} public={public} credential={has_credential}"
                );
            }
        }
    }
}

/// P2 - a failing authenticator is terminal, whatever follows it in the chain.
#[tokio::test]
async fn chain_error_is_terminal_regardless_of_position() {
    for trailing in [Script::Authenticate, Script::Decline] {
        let after = Arc::new(AtomicUsize::new(0));
        let chain = AuthChain::<TestApp>::new()
            .with(Programmed {
                script: Script::Fail,
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .with(Programmed {
                script: trailing,
                calls: after.clone(),
            });

        let result = chain
            .authenticate(
                &AuthRequest::default(),
                &bearer(),
                &Scope::Tenant("acme".into()),
            )
            .await;

        assert!(result.is_err(), "trailing={trailing:?}");
        assert_eq!(after.load(Ordering::SeqCst), 0, "trailing={trailing:?}");
    }
}

/// P3 - nothing after the deciding authenticator is consulted, so authenticators
/// may perform side effects (cache writes, IdP calls) without coordination.
#[tokio::test]
async fn chain_consults_nobody_after_a_decision() {
    let after = Arc::new(AtomicUsize::new(0));
    let chain = AuthChain::<TestApp>::new()
        .with(Programmed {
            script: Script::Authenticate,
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .with(Programmed {
            script: Script::Authenticate,
            calls: after.clone(),
        });

    chain
        .authenticate(
            &AuthRequest::default(),
            &bearer(),
            &Scope::Tenant("acme".into()),
        )
        .await
        .unwrap();

    assert_eq!(after.load(Ordering::SeqCst), 0);
}

/// P4 - a protected scope never resolves to an anonymous request.
///
/// `Verdict` makes the failure mode unrepresentable rather than merely absent,
/// but the property is worth pinning: it must survive any future widening of
/// what an authenticator may return.
#[tokio::test]
async fn protected_scope_never_resolves_to_anonymous() {
    for policy in [
        PublicScopePolicy::Optional,
        PublicScopePolicy::AlwaysAnonymous,
    ] {
        for has_credential in [true, false] {
            for script in [Script::Authenticate, Script::Decline, Script::Fail] {
                let credential = if has_credential {
                    bearer()
                } else {
                    Credential::None
                };
                let (outcome, _) = run_case(false, policy, credential, script).await;

                assert_ne!(
                    outcome,
                    Expect::Anonymous,
                    "policy={policy:?} credential={has_credential} script={script:?}"
                );
            }
        }
    }
}

// --------------------------------------------------------------- cookies
//
// `CookieDirective`'s `Display` is the whole of the axum adapter's cookie
// rendering, so it is pinned here rather than only end-to-end through actix.

/// These are RFC 6265bis wire values, not Rust identifiers. `Display` is derived
/// from the variant names, so renaming a variant would silently change the
/// emitted header; this test makes that a compile-and-test failure instead.
#[test]
fn same_site_renders_the_rfc_attribute_values() {
    assert_eq!(SameSite::Strict.to_string(), "Strict");
    assert_eq!(SameSite::Lax.to_string(), "Lax");
    assert_eq!(SameSite::None.to_string(), "None");
}

#[test]
fn cookie_defaults_to_the_conservative_posture() {
    assert_eq!(
        CookieDirective::set("session", "abc").to_string(),
        "session=abc; HttpOnly; Secure; SameSite=Lax"
    );
}

#[test]
fn cookie_renders_every_attribute_in_order() {
    let cookie = CookieDirective::set("session", "abc")
        .with_path("/app")
        .with_domain("example.com")
        .with_max_age(Duration::from_secs(600))
        .with_same_site(Some(SameSite::Strict));

    assert_eq!(
        cookie.to_string(),
        concat!(
            "session=abc; Path=/app; Domain=example.com; Max-Age=600; ",
            "HttpOnly; Secure; SameSite=Strict"
        )
    );
}

/// The original hard-coded `.secure(true)` on every cookie, which silently
/// breaks plain-HTTP local development. Each attribute is now opt-out.
#[test]
fn cookie_attributes_can_be_relaxed() {
    let cookie = CookieDirective::set("session", "abc")
        .with_http_only(false)
        .with_secure(false)
        .with_same_site(None);

    assert_eq!(cookie.to_string(), "session=abc");
}

#[test]
fn cleared_cookie_expires_immediately() {
    assert_eq!(
        CookieDirective::clear("session").to_string(),
        "session=; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
    );
}
