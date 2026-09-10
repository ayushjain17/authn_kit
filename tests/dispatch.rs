//! Credential parsing and gateway dispatch.
//!
//! These cover the logic the original held inline in `AuthNMiddleware::call` and
//! `process_basic_auth`, where it could not be reached without an actix request
//! and a populated `AppState`.

use std::fmt::Display;

use async_trait::async_trait;
use authn_kit::{
    AuthChain, AuthContext, AuthError, AuthGateway, AuthProfile, AuthRequest, AuthScope,
    Authenticator, Credential, IdentityClaims, ScopeResolver, Verdict,
};
use base64::{Engine, engine::general_purpose};
use secrecy::ExposeSecret;

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
}

struct TestApp;

impl AuthProfile for TestApp {
    type User = User;
    type Scope = Scope;
}

/// Mirrors the shape of the original `get_login_type`: a path-derived decision
/// with a header-supplied tenant id.
struct PathScopes;

impl ScopeResolver for PathScopes {
    type Scope = Scope;

    fn resolve(&self, request: &AuthRequest) -> Scope {
        if request.path().starts_with("/health") {
            return Scope::Public;
        }
        Scope::Tenant(request.header("x-org-id").unwrap_or("default").to_string())
    }
}

/// Accepts any `Bearer` credential, declines everything else.
struct BearerOnly;

#[async_trait]
impl Authenticator<TestApp> for BearerOnly {
    fn name(&self) -> &'static str {
        "bearer-only"
    }

    async fn authenticate(
        &self,
        ctx: &AuthContext<'_, TestApp>,
    ) -> Result<Verdict<User>, AuthError> {
        match ctx.credential {
            Credential::Bearer(token) if token.expose_secret() == "good" => {
                Ok(Verdict::Authenticated(User("alice".into())))
            }
            Credential::Bearer(_) => Err(AuthError::invalid_credential("bad token")),
            _ => Ok(Verdict::NotApplicable),
        }
    }
}

fn basic(payload: &str) -> String {
    format!("Basic {}", general_purpose::STANDARD.encode(payload))
}

fn parse(header: &str) -> Credential {
    Credential::from_authorization_header(header)
}

// ------------------------------------------------------- credential parsing

#[test]
fn parses_bearer() {
    let Credential::Bearer(token) = parse("Bearer abc123") else {
        panic!("expected Bearer");
    };
    assert_eq!(token.expose_secret(), "abc123");
}

/// RFC 9110 §11.1 defines the auth scheme as case-insensitive. The original
/// compared against the literal `"Bearer"`, so `bearer <token>` fell through to
/// cookie authentication and the caller was silently treated as unauthenticated.
#[test]
fn scheme_matching_is_case_insensitive() {
    for header in ["Bearer t", "bearer t", "BEARER t", "BeArEr t"] {
        assert!(
            matches!(parse(header), Credential::Bearer(_)),
            "failed for {header:?}"
        );
    }
}

/// The original's `split(' ')` took only the second element, truncating any
/// parameter containing a space.
#[test]
fn bearer_parameter_may_contain_spaces() {
    let Credential::Bearer(token) = parse("Bearer a b c") else {
        panic!("expected Bearer");
    };
    assert_eq!(token.expose_secret(), "a b c");
}

#[test]
fn parses_basic() {
    let Credential::Basic { id, secret } = parse(&basic("alice:hunter2")) else {
        panic!("expected Basic");
    };
    assert_eq!(id, "alice");
    assert_eq!(secret.expose_secret(), "hunter2");
}

/// RFC 7617 allows `:` inside the password; the split is on the first one only.
#[test]
fn basic_password_may_contain_colons() {
    let Credential::Basic { id, secret } = parse(&basic("alice:a:b:c")) else {
        panic!("expected Basic");
    };
    assert_eq!(id, "alice");
    assert_eq!(secret.expose_secret(), "a:b:c");
}

#[test]
fn basic_with_unparseable_payload_is_malformed_not_an_error() {
    let cases = [
        ("Basic !!!not-base64!!!", "not valid base64"),
        // base64 of the bytes 0xFF 0xFE, which are not valid UTF-8.
        ("Basic //4=", "not valid UTF-8"),
        (&basic("no-colon-here"), "missing ':' separator"),
    ];

    for (header, expected) in cases {
        let Credential::Malformed { scheme, detail } = parse(header) else {
            panic!("expected Malformed for {header:?}");
        };
        assert_eq!(scheme, "basic");
        assert_eq!(detail, expected, "for {header:?}");
    }
}

#[test]
fn unknown_schemes_are_preserved_verbatim() {
    let Credential::Other { scheme, value } = parse("Internal s3cret") else {
        panic!("expected Other");
    };
    assert_eq!(scheme, "internal");
    assert_eq!(value.expose_secret(), "s3cret");
}

/// A header with no space carries no parameter. The original mapped this to
/// `None` — fall through to cookie authentication — and that is preserved.
#[test]
fn header_without_a_parameter_yields_no_credential() {
    for header in ["Bearer", "", "   "] {
        assert!(parse(header).is_none(), "failed for {header:?}");
    }
}

#[test]
fn absent_authorization_header_yields_no_credential() {
    let request = AuthRequest::builder().path("/x").build();
    assert!(Credential::from_request(&request).is_none());
}

#[test]
fn credential_is_read_from_the_request_case_insensitively() {
    let request = AuthRequest::builder()
        .header("AUTHORIZATION", "Bearer t")
        .build();
    assert!(matches!(
        Credential::from_request(&request),
        Credential::Bearer(_)
    ));
}

// -------------------------------------------------------------- gateway

fn gateway() -> AuthGateway<TestApp, PathScopes> {
    AuthGateway::new(PathScopes, AuthChain::<TestApp>::new().with(BearerOnly))
}

#[tokio::test]
async fn gateway_returns_the_principal_on_success() {
    let request = AuthRequest::builder()
        .path("/config")
        .header("authorization", "Bearer good")
        .build();

    assert_eq!(
        gateway().authenticate(&request).await.unwrap(),
        Some(User("alice".into()))
    );
}

#[tokio::test]
async fn gateway_returns_no_principal_for_an_anonymous_public_request() {
    let request = AuthRequest::builder().path("/health").build();

    assert_eq!(gateway().authenticate(&request).await.unwrap(), None);
}

#[tokio::test]
async fn gateway_challenges_an_unclaimed_protected_request() {
    let request = AuthRequest::builder()
        .path("/config")
        .header("authorization", "Internal whatever")
        .build();

    let error = gateway().authenticate(&request).await.unwrap_err();

    assert_eq!(error.status(), 401);
    // The detail names the scheme and scope, so an operator can tell "no
    // authenticator handles this scheme" from "the credential was rejected".
    assert!(error.detail().contains("internal"), "{}", error.detail());
    assert!(
        error.detail().contains("tenant_default"),
        "{}",
        error.detail()
    );
}

#[tokio::test]
async fn gateway_propagates_a_rejection_unchanged() {
    let request = AuthRequest::builder()
        .path("/config")
        .header("authorization", "Bearer wrong")
        .build();

    let error = gateway().authenticate(&request).await.unwrap_err();

    assert_eq!(error.status(), 401);
    assert_eq!(error.detail(), "bad token");
}

#[tokio::test]
async fn gateway_resolves_scope_from_the_request() {
    let request = AuthRequest::builder()
        .path("/config")
        .header("x-org-id", "acme")
        .build();

    assert_eq!(gateway().scope_of(&request), Scope::Tenant("acme".into()));
}

#[test]
fn gateway_reports_its_authenticators() {
    assert_eq!(gateway().authenticator_names(), vec!["bearer-only"]);
}
