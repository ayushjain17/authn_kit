#![cfg(feature = "oidc")]
//! End-to-end OIDC tests against a real (if small) OpenID Provider.
//!
//! Discovery, JWKS retrieval and signature verification all run for real here,
//! so what is exercised is `openidconnect`'s behaviour and ours together —
//! rather than a mock of the client, which would mostly test the mock.

#[path = "support/mock_idp.rs"]
mod mock_idp;

use std::{fmt::Display, sync::Arc};

use authn_kit::{
    AuthContext, AuthProfile, AuthRequest, AuthScope, Authenticator, ClaimSource,
    Credential, IdentityClaims, Verdict,
    mechanisms::{BasicAuthenticator, BearerAuthenticator, SessionAuthenticator},
    oidc::{CallbackParams, LoginFlow, NonceCheck, OidcConfig, OidcProvider},
};
use mock_idp::{CLIENT_ID, CLIENT_SECRET, MockIdp, PendingCode, REDIRECT_URL};
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
        // A machine grant carries no human identity, so the principal is named
        // after the validated client. This mirrors the `service-account-<id>`
        // naming the original derived inside the auth module itself.
        if claims.source == ClaimSource::ClientCredentials {
            let client = claims
                .client_id
                .clone()
                .ok_or("client_id claim not found")?;
            return Ok(Self {
                email: format!("{client}@service.local"),
                username: format!("service-account-{client}"),
            });
        }

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
struct Scope;

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("session")
    }
}

impl AuthScope for Scope {}

struct TestApp;

impl AuthProfile for TestApp {
    type User = User;
    type Scope = Scope;
}

async fn provider_for(idp: &MockIdp) -> Arc<OidcProvider> {
    let config = OidcConfig::new(idp.issuer.clone(), CLIENT_ID, REDIRECT_URL)
        .unwrap()
        .with_client_secret(CLIENT_SECRET);
    Arc::new(
        OidcProvider::discover(config)
            .await
            .expect("discovery should succeed"),
    )
}

fn alice() -> User {
    User {
        email: "alice@example.com".into(),
        username: "alice".into(),
    }
}

// ------------------------------------------------------- discovery + verify

#[tokio::test]
async fn discovers_the_provider_and_its_keys() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;

    let state = provider.snapshot();
    assert_eq!(state.metadata().issuer().as_str(), idp.issuer);
    assert_eq!(
        state.introspection_endpoint().as_deref(),
        Some(format!("{}/introspect", idp.issuer).as_str())
    );
}

#[tokio::test]
async fn verifies_a_well_formed_id_token() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;
    let token = idp.mint_id_token("alice", "alice@example.com", Some("n-1"));

    let claims = provider
        .verify_id_token(&token, NonceCheck::Present)
        .await
        .expect("token should verify");

    assert_eq!(claims.subject.as_deref(), Some("alice"));
    assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
    assert_eq!(User::try_from(claims).unwrap(), alice());
}

#[tokio::test]
async fn rejects_an_expired_token() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;
    let token = idp.mint_expired_id_token("alice", "alice@example.com");

    let error = provider
        .verify_id_token(&token, NonceCheck::Present)
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
    assert!(error.detail().contains("expired"), "{}", error.detail());
}

#[tokio::test]
async fn rejects_a_token_minted_for_another_audience() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;
    let token = idp.mint_id_token_for_audience(
        "alice",
        "alice@example.com",
        Some("n-1"),
        "some-other-client",
    );

    let error = provider
        .verify_id_token(&token, NonceCheck::Present)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 401);
}

#[tokio::test]
async fn nonce_checks_behave_as_named() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;

    let with_nonce = idp.mint_id_token("alice", "alice@example.com", Some("n-1"));
    let without_nonce = idp.mint_id_token("alice", "alice@example.com", None);

    // Present: requires a nonce, any value.
    assert!(
        provider
            .verify_id_token(&with_nonce, NonceCheck::Present)
            .await
            .is_ok()
    );
    assert!(
        provider
            .verify_id_token(&without_nonce, NonceCheck::Present)
            .await
            .is_err()
    );

    // Skip: accepts a token minted outside an authorization request.
    assert!(
        provider
            .verify_id_token(&without_nonce, NonceCheck::Skip)
            .await
            .is_ok()
    );

    // Matches: binds the token to one specific login attempt.
    let expected = openidconnect::Nonce::new("n-1".to_string());
    let wrong = openidconnect::Nonce::new("n-2".to_string());
    assert!(
        provider
            .verify_id_token(&with_nonce, NonceCheck::Matches(&expected))
            .await
            .is_ok()
    );
    assert!(
        provider
            .verify_id_token(&with_nonce, NonceCheck::Matches(&wrong))
            .await
            .is_err()
    );
}

/// An empty JWKS is what an un-picked-up key rotation looks like. Verification
/// must fail closed after the refresh-and-retry, not succeed and not hang.
#[tokio::test]
async fn a_token_signed_by_an_unpublished_key_is_refused() {
    let idp = MockIdp::start_with_keys(false).await;
    let provider = provider_for(&idp).await;
    let token = idp.mint_id_token("alice", "alice@example.com", Some("n-1"));

    let error = provider
        .verify_id_token(&token, NonceCheck::Present)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 401);
}

// ---------------------------------------------------------------- bearer

#[tokio::test]
async fn bearer_authenticator_accepts_a_valid_id_token() {
    let idp = MockIdp::start().await;
    let auth = BearerAuthenticator::<TestApp>::new(provider_for(&idp).await);
    let token = idp.mint_id_token("alice", "alice@example.com", Some("n-1"));

    let request = AuthRequest::default();
    let credential = Credential::Bearer(SecretString::from(token));
    let verdict = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap();

    assert_eq!(verdict, Verdict::Authenticated(alice()));
}

#[tokio::test]
async fn bearer_authenticator_declines_non_jwt_tokens() {
    let idp = MockIdp::start().await;
    let auth = BearerAuthenticator::<TestApp>::new(provider_for(&idp).await);
    let request = AuthRequest::default();

    // Everything that is not a compact JWS: API keys, opaque handles, and every
    // malformed segment count. Declining rather than rejecting is what lets this
    // authenticator sit either side of another `Bearer` claimant.
    for value in [
        "sptok_apikey",
        "opaque",
        "a.b",
        "a.b.c.d",
        "a..c",
        ".b.c",
        "a.b.",
        "",
    ] {
        let credential = Credential::Bearer(SecretString::from(value.to_string()));
        let verdict = auth
            .authenticate(&AuthContext::new(&request, &credential, &Scope))
            .await
            .unwrap();
        assert_eq!(verdict, Verdict::NotApplicable, "for {value:?}");
    }
}

#[tokio::test]
async fn bearer_authenticator_rejects_an_expired_token() {
    let idp = MockIdp::start().await;
    let auth = BearerAuthenticator::<TestApp>::new(provider_for(&idp).await);
    let token = idp.mint_expired_id_token("alice", "alice@example.com");

    let request = AuthRequest::default();
    let credential = Credential::Bearer(SecretString::from(token));
    let error = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
}

// ---------------------------------------------------------------- session

#[tokio::test]
async fn session_authenticator_accepts_a_valid_cookie() {
    let idp = MockIdp::start().await;
    let auth = SessionAuthenticator::<TestApp>::new(provider_for(&idp).await);
    let token = idp.mint_id_token("alice", "alice@example.com", Some("n-1"));

    let request = AuthRequest::builder().cookie("session", token).build();
    let verdict = auth
        .authenticate(&AuthContext::new(&request, &Credential::None, &Scope))
        .await
        .unwrap();

    assert_eq!(verdict, Verdict::Authenticated(alice()));
}

#[tokio::test]
async fn session_authenticator_without_a_login_flow_declines_rather_than_redirects() {
    let idp = MockIdp::start().await;
    let auth = SessionAuthenticator::<TestApp>::new(provider_for(&idp).await);

    let request = AuthRequest::builder().method("GET").path("/config").build();
    let error = auth
        .authenticate(&AuthContext::new(&request, &Credential::None, &Scope))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
}

/// A client presenting an API credential is doing API authentication and must
/// never be bounced into an interactive login.
#[tokio::test]
async fn session_authenticator_ignores_requests_carrying_another_credential() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;
    let auth = SessionAuthenticator::<TestApp>::new(provider.clone())
        .with_login_redirect(Arc::new(LoginFlow::new(provider)));

    let request = AuthRequest::builder().method("GET").path("/config").build();
    let credential = Credential::Bearer(SecretString::from("sptok_key".to_string()));
    let verdict = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap();

    assert_eq!(verdict, Verdict::NotApplicable);
}

#[tokio::test]
async fn session_authenticator_redirects_an_unauthenticated_navigation() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;
    let auth = SessionAuthenticator::<TestApp>::new(provider.clone())
        .with_login_redirect(Arc::new(LoginFlow::new(provider)));

    let request = AuthRequest::builder()
        .method("GET")
        .path("/admin/workspaces")
        .query("page=2")
        .build();
    let error = auth
        .authenticate(&AuthContext::new(&request, &Credential::None, &Scope))
        .await
        .unwrap_err();

    let authn_kit::AuthError::Redirect { location, cookies } = error else {
        panic!("expected a redirect, got {error:?}");
    };
    assert!(
        location.starts_with(&format!("{}/authorize", idp.issuer)),
        "{location}"
    );
    assert!(
        location.contains("code_challenge"),
        "PKCE missing: {location}"
    );
    assert!(location.contains("client_id=test-client"));
    // The protection cookie, and a clear of any stale session.
    assert_eq!(cookies.len(), 2);
}

/// Redirecting a mutation into a login round-trip silently discards its body,
/// because the browser returns from the provider with a `GET`. The original
/// redirected any method.
#[tokio::test]
async fn session_authenticator_never_redirects_a_mutation() {
    let idp = MockIdp::start().await;
    let provider = provider_for(&idp).await;
    let auth = SessionAuthenticator::<TestApp>::new(provider.clone())
        .with_login_redirect(Arc::new(LoginFlow::new(provider)));

    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let request = AuthRequest::builder()
            .method(method)
            .path("/config")
            .build();
        let error = auth
            .authenticate(&AuthContext::new(&request, &Credential::None, &Scope))
            .await
            .unwrap_err();

        assert_eq!(error.status(), 401, "for {method}");
    }
}

// -------------------------------------------------------------- login flow

#[tokio::test]
async fn authorize_url_carries_every_required_parameter() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let redirect = flow.authorize("/admin/organisations").unwrap();

    for expected in [
        "response_type=code",
        "client_id=test-client",
        "code_challenge",
        "code_challenge_method=S256",
        "state=",
        "nonce=",
        "scope=",
    ] {
        assert!(redirect.location.contains(expected), "missing {expected}");
    }
    // The destination must not appear in the URL: it lives in the protection
    // cookie, so it can never be influenced by whoever crafts the callback.
    assert!(
        !redirect.location.contains("organisations"),
        "{}",
        redirect.location
    );
}

#[tokio::test]
async fn authorize_rejects_an_off_origin_destination() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let error = flow.authorize("https://evil.example/steal").unwrap_err();
    assert_eq!(error.status(), 400);
}

// ==================================================== login round trip
//
// The whole authorization-code flow, end to end: `authorize` mints the state,
// nonce and PKCE challenge; the provider honours the code only if the verifier
// hashes to that challenge; and `complete` binds the returned ID token to the
// nonce it issued.

/// Pulls a query parameter out of the authorization URL.
fn param(location: &str, name: &str) -> String {
    let query = location
        .split_once('?')
        .expect("authorize url has a query")
        .1;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("authorize url has no {name}"))
}

fn cookie_value(cookies: &[authn_kit::CookieDirective], name: &str) -> String {
    cookies
        .iter()
        .find(|cookie| cookie.name == name)
        .unwrap_or_else(|| panic!("no {name} cookie"))
        .value
        .clone()
}

#[tokio::test]
async fn a_full_login_round_trip_succeeds() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let redirect = flow.authorize("/admin/organisations").unwrap();
    let state = param(&redirect.location, "state");
    let nonce = param(&redirect.location, "nonce");
    let challenge = param(&redirect.location, "code_challenge");
    let protection = cookie_value(&redirect.cookies, "authn_protection");

    // The provider will honour this code only for a verifier hashing to the
    // challenge we just sent it.
    idp.register_code(
        "the-code",
        PendingCode {
            nonce: Some(nonce),
            code_challenge: Some(challenge),
        },
    );

    let callback =
        CallbackParams::from_query(&format!("code=the-code&state={state}")).unwrap();
    let complete = flow.complete(callback, Some(&protection)).await.unwrap();

    assert_eq!(complete.claims.email.as_deref(), Some("alice@example.com"));
    assert_eq!(complete.redirect_to, "/admin/organisations");
    assert_eq!(User::try_from(complete.claims).unwrap(), alice());

    // A new session, and the spent protection cookie cleared.
    let session = complete
        .cookies
        .iter()
        .find(|c| c.name == "session")
        .unwrap();
    assert!(!session.value.is_empty());
    let cleared = complete
        .cookies
        .iter()
        .find(|c| c.name == "authn_protection")
        .unwrap();
    assert_eq!(cleared.max_age, Some(std::time::Duration::ZERO));

    // PKCE really was exercised, not merely requested.
    let token_request = idp.token_requests().pop().unwrap();
    assert_eq!(token_request.grant_type, "authorization_code");
    assert!(token_request.param("code_verifier").is_some());
}

/// The provider rejects the exchange when the verifier does not match, which is
/// the property PKCE exists for.
#[tokio::test]
async fn a_mismatched_pkce_verifier_is_refused() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let redirect = flow.authorize("/admin").unwrap();
    let state = param(&redirect.location, "state");
    let nonce = param(&redirect.location, "nonce");
    let protection = cookie_value(&redirect.cookies, "authn_protection");

    // Register the code against a challenge this login attempt cannot satisfy.
    idp.register_code(
        "the-code",
        PendingCode {
            nonce: Some(nonce),
            code_challenge: Some("a-different-challenge".to_string()),
        },
    );

    let callback =
        CallbackParams::from_query(&format!("code=the-code&state={state}")).unwrap();
    let error = flow
        .complete(callback, Some(&protection))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
}

#[tokio::test]
async fn a_callback_state_that_does_not_match_the_cookie_is_refused() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let redirect = flow.authorize("/admin").unwrap();
    let protection = cookie_value(&redirect.cookies, "authn_protection");

    let callback = CallbackParams::from_query("code=the-code&state=forged").unwrap();
    let error = flow
        .complete(callback, Some(&protection))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
    assert!(error.detail().contains("state"), "{}", error.detail());
}

#[tokio::test]
async fn a_callback_without_the_protection_cookie_is_refused() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let callback = CallbackParams::from_query("code=c&state=s").unwrap();
    let error = flow.complete(callback, None).await.unwrap_err();

    assert_eq!(error.status(), 401);
}

/// A user declining consent is an RFC 6749 error response, not a malformed
/// request. The original's `LoginParams` required `code`, so this produced an
/// opaque 400.
#[tokio::test]
async fn a_declined_login_is_reported_as_unauthenticated() {
    let idp = MockIdp::start().await;
    let flow = LoginFlow::new(provider_for(&idp).await);

    let callback = CallbackParams::from_query(
        "error=access_denied&error_description=The+user+declined",
    )
    .unwrap();
    let error = flow.complete(callback, None).await.unwrap_err();

    assert_eq!(error.status(), 401);
    assert!(error.detail().contains("declined"), "{}", error.detail());
}

// ======================================================== basic auth grants

fn basic(id: &str, secret: &str) -> Credential {
    Credential::Basic {
        id: id.to_string(),
        secret: SecretString::from(secret.to_string()),
    }
}

#[tokio::test]
async fn client_credentials_authenticates_a_machine() {
    let idp = MockIdp::start().await;
    idp.register_client("reporting", "machine-secret");
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await);

    let request = AuthRequest::default();
    let credential = basic("reporting", "machine-secret");
    let verdict = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap();

    assert_eq!(
        verdict,
        Verdict::Authenticated(User {
            email: "reporting@service.local".into(),
            username: "service-account-reporting".into(),
        })
    );

    // The exchange runs as the *caller's* client, which is what proves their
    // credentials rather than ours.
    let token_request = idp.token_requests().pop().unwrap();
    assert_eq!(token_request.grant_type, "client_credentials");
    assert_eq!(
        token_request.basic_credentials(),
        Some(("reporting".to_string(), "machine-secret".to_string()))
    );
    // Parity with the original: a machine grant requests no scopes.
    assert!(token_request.param("scope").is_none());
}

#[tokio::test]
async fn client_credentials_rejects_a_bad_secret() {
    let idp = MockIdp::start().await;
    idp.register_client("reporting", "machine-secret");
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await);

    let request = AuthRequest::default();
    let credential = basic("reporting", "wrong");
    let error = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
}

#[tokio::test]
async fn client_credentials_results_are_cached() {
    let idp = MockIdp::start().await;
    idp.register_client("reporting", "machine-secret");
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await);
    let request = AuthRequest::default();
    let credential = basic("reporting", "machine-secret");

    for _ in 0..3 {
        auth.authenticate(&AuthContext::new(&request, &credential, &Scope))
            .await
            .unwrap();
    }

    assert_eq!(
        idp.token_requests().len(),
        1,
        "the token endpoint was re-hit"
    );
}

/// The password grant is off unless explicitly enabled: OAuth 2.1 removes it.
#[tokio::test]
async fn the_password_grant_is_refused_unless_enabled() {
    let idp = MockIdp::start().await;
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await);

    let request = AuthRequest::builder()
        .header("x-grant-type", "password")
        .build();
    let credential = basic("alice", "pw");
    let error = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 501);
    assert_eq!(
        idp.token_requests().len(),
        0,
        "no exchange should be attempted"
    );
}

#[tokio::test]
async fn the_password_grant_authenticates_when_enabled() {
    let idp = MockIdp::start().await;
    idp.register_user("alice", "correct-horse", "alice", "alice@example.com");
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await)
        .with_password_grant(true);

    let request = AuthRequest::builder()
        .header("x-grant-type", "password")
        .build();
    let credential = basic("alice", "correct-horse");
    let verdict = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap();

    assert_eq!(verdict, Verdict::Authenticated(alice()));
    assert_eq!(idp.token_requests()[0].grant_type, "password");
}

#[tokio::test]
async fn the_password_grant_rejects_bad_credentials() {
    let idp = MockIdp::start().await;
    idp.register_user("alice", "correct-horse", "alice", "alice@example.com");
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await)
        .with_password_grant(true);

    let request = AuthRequest::builder()
        .header("x-grant-type", "password")
        .build();
    let credential = basic("alice", "wrong");
    let error = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 401);
}

/// `X-Grant-Type` selects the grant; anything unrecognised is the client's
/// mistake to fix, so a 400 rather than a 500. Parity with the original.
#[tokio::test]
async fn an_unrecognised_grant_type_is_a_bad_request() {
    let idp = MockIdp::start().await;
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await);

    let request = AuthRequest::builder()
        .header("x-grant-type", "device_code")
        .build();
    let credential = basic("a", "b");
    let error = auth
        .authenticate(&AuthContext::new(&request, &credential, &Scope))
        .await
        .unwrap_err();

    assert_eq!(error.status(), 400);
}

#[tokio::test]
async fn basic_authenticator_declines_other_credentials() {
    let idp = MockIdp::start().await;
    let auth = BasicAuthenticator::<TestApp>::new(provider_for(&idp).await);
    let request = AuthRequest::default();

    for credential in [
        Credential::None,
        Credential::Bearer(SecretString::from("t".to_string())),
    ] {
        let verdict = auth
            .authenticate(&AuthContext::new(&request, &credential, &Scope))
            .await
            .unwrap();
        assert_eq!(verdict, Verdict::NotApplicable);
    }
}
