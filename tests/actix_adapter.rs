#![cfg(feature = "actix")]
//! actix adapter: request translation, error rendering, and an end-to-end run
//! of the middleware.

use std::{fmt::Display, time::Duration};

use actix_web::{
    App, HttpMessage, HttpRequest, HttpResponse,
    cookie::Cookie,
    http::{StatusCode, header},
    test, web,
};
use async_trait::async_trait;
use authn_kit::{
    AuthChain, AuthContext, AuthError, AuthGateway, AuthProfile, AuthRequest, AuthScope,
    Authenticator, CookieDirective, Credential, IdentityClaims, SameSite, ScopeResolver,
    Verdict,
    adapters::actix::{ActixAuthn, error_to_response},
};
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
    Protected,
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Protected => f.write_str("protected"),
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

struct PathScopes;

impl ScopeResolver for PathScopes {
    type Scope = Scope;

    fn resolve(&self, request: &AuthRequest) -> Scope {
        if request.path().starts_with("/health") {
            Scope::Public
        } else {
            Scope::Protected
        }
    }
}

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
            Credential::Bearer(t) if t.expose_secret() == "good" => {
                Ok(Verdict::Authenticated(User("alice".into())))
            }
            Credential::Bearer(_) => Err(AuthError::invalid_credential("bad token")),
            _ => Ok(Verdict::NotApplicable),
        }
    }
}

fn gateway() -> AuthGateway<TestApp, PathScopes> {
    AuthGateway::new(PathScopes, AuthChain::<TestApp>::new().with(BearerOnly))
}

async fn whoami(req: HttpRequest) -> HttpResponse {
    match req.extensions().get::<User>() {
        Some(user) => HttpResponse::Ok().body(user.0.clone()),
        None => HttpResponse::Ok().body("anonymous"),
    }
}

// ------------------------------------------------------ request translation

#[actix_rt::test]
async fn translates_an_actix_request() {
    let request = test::TestRequest::get()
        .uri("/admin/acme/workspaces?org=acme&state=aGk=")
        .insert_header(("X-Org-Id", "acme"))
        .insert_header((header::AUTHORIZATION, "Bearer good"))
        .cookie(Cookie::new("session", "jwt-value"))
        .to_srv_request();

    let translated = AuthRequest::from(&request);

    assert_eq!(translated.method(), "GET");
    assert_eq!(translated.path(), "/admin/acme/workspaces");
    assert_eq!(translated.query(), "org=acme&state=aGk=");
    assert_eq!(translated.header("x-org-id"), Some("acme"));
    assert_eq!(translated.query_param("state"), Some("aGk="));
    assert_eq!(translated.cookie("session"), Some("jwt-value"));
    assert!(matches!(
        Credential::from_request(&translated),
        Credential::Bearer(_)
    ));
}

// --------------------------------------------------------- error rendering

#[actix_rt::test]
async fn renders_each_error_with_its_status() {
    let cases = [
        (AuthError::unauthenticated("x"), 401),
        (AuthError::malformed_credential("x"), 400),
        (AuthError::scope_denied("x"), 403),
        (AuthError::unsupported("x"), 501),
        (AuthError::upstream("x"), 503),
        (AuthError::internal("x"), 500),
    ];

    for (error, expected) in cases {
        assert_eq!(error_to_response(&error).status().as_u16(), expected);
    }
}

#[actix_rt::test]
async fn rendered_body_carries_the_client_message_not_the_detail() {
    let error = AuthError::upstream("connect to https://internal-idp.svc refused");
    let response = error_to_response(&error);

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();

    assert!(body.contains("Authentication service unavailable"));
    assert!(!body.contains("internal-idp.svc"));
}

#[actix_rt::test]
async fn renders_a_redirect_with_its_cookies() {
    let error = AuthError::redirect(
        "https://idp.example/authorize?x=1",
        vec![
            CookieDirective::set("protection", "state-value")
                .with_path("/app")
                .with_max_age(Duration::from_secs(600))
                .with_same_site(Some(SameSite::Strict)),
            CookieDirective::clear("session"),
        ],
    );

    let response = error_to_response(&error);

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "https://idp.example/authorize?x=1"
    );

    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
        .collect();

    assert_eq!(cookies.len(), 2);
    let protection = cookies
        .iter()
        .find(|c| c.starts_with("protection="))
        .unwrap();
    assert!(protection.contains("Path=/app"));
    assert!(protection.contains("Max-Age=600"));
    assert!(protection.contains("HttpOnly"));
    assert!(protection.contains("Secure"));
    assert!(protection.contains("SameSite=Strict"));

    let session = cookies.iter().find(|c| c.starts_with("session=")).unwrap();
    assert!(session.contains("Max-Age=0"));
}

// -------------------------------------------------------------- end to end

#[actix_rt::test]
async fn middleware_authenticates_and_exposes_the_principal() {
    let app = test::init_service(
        App::new()
            .wrap(ActixAuthn::new(gateway()))
            .route("/config", web::get().to(whoami)),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/config")
        .insert_header((header::AUTHORIZATION, "Bearer good"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(test::read_body(response).await, "alice");
}

#[actix_rt::test]
async fn middleware_rejects_a_bad_credential_without_calling_the_handler() {
    let app = test::init_service(
        App::new()
            .wrap(ActixAuthn::new(gateway()))
            .route("/config", web::get().to(whoami)),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/config")
        .insert_header((header::AUTHORIZATION, "Bearer wrong"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    assert!(body.contains("Invalid or expired credentials"));
    assert!(!body.contains("bad token"));
}

#[actix_rt::test]
async fn middleware_challenges_an_unauthenticated_protected_request() {
    let app = test::init_service(
        App::new()
            .wrap(ActixAuthn::new(gateway()))
            .route("/config", web::get().to(whoami)),
    )
    .await;

    let request = test::TestRequest::get().uri("/config").to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A public route runs the handler with no principal inserted — the handler can
/// tell, which the original made impossible by inserting a default user.
#[actix_rt::test]
async fn middleware_runs_public_routes_anonymously() {
    let app = test::init_service(
        App::new()
            .wrap(ActixAuthn::new(gateway()))
            .route("/health", web::get().to(whoami)),
    )
    .await;

    let request = test::TestRequest::get().uri("/health").to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(test::read_body(response).await, "anonymous");
}
