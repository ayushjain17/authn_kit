//! Wiring `authn_kit` into an actix-web service.
//!
//! Compiled by CI, so it cannot drift from the API the way a README snippet can.
//! Run with:
//!
//! ```sh
//! cargo run -p authn_kit --example actix_service --features actix,full
//! ```
//!
//! It demonstrates the four things every consumer has to decide:
//!
//! 1. what a principal is, and how claims become one (`TryFrom<IdentityClaims>`)
//! 2. what a scope is, and how a request maps to one (`ScopeResolver`)
//! 3. which mechanisms are enabled, and in what order (`AuthnBuilder`)
//! 4. how failures are rendered (the adapter, automatically)

use std::{fmt::Display, sync::Arc};

use actix_web::{App, HttpMessage, HttpRequest, HttpResponse, HttpServer, web};
use authn_kit::{
    ApiTokenAuthenticator, AuthProfile, AuthRequest, AuthScope, AuthnBuilder,
    ClaimSource, DisabledAuthenticator, IdentityClaims, ScopeResolver,
    adapters::actix::ActixAuthn,
    env::EnvConfig,
    mechanisms::{BearerAuthenticator, IntrospectionValidator, SessionAuthenticator},
    oidc::{LoginFlow, OidcProvider},
};

// ---------------------------------------------------------------- 1. principal

/// The application's user type. Implementing `TryFrom<IdentityClaims>` is the
/// only thing required to make it usable throughout the crate.
#[derive(Clone, Debug)]
struct User {
    email: String,
    username: String,
}

impl TryFrom<IdentityClaims> for User {
    type Error = String;

    fn try_from(claims: IdentityClaims) -> Result<Self, Self::Error> {
        // Branching on the source is how one conversion serves every mechanism.
        // A machine grant carries no human identity, so it is named after the
        // validated client rather than rejected for having no email.
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

// -------------------------------------------------------------------- 2. scope

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Scope {
    Public,
    Global,
    Org(String),
}

impl Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => f.write_str("none"),
            Self::Global => f.write_str("user"),
            Self::Org(id) => write!(f, "org_{id}"),
        }
    }
}

impl AuthScope for Scope {
    fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Mixed into credential-cache keys, so a credential validated for one
    /// organisation can never be served from cache for another.
    fn cache_discriminator(&self) -> Option<&str> {
        match self {
            Self::Org(id) => Some(id),
            _ => None,
        }
    }
}

/// Maps a request to a scope. This is where an application's own routing
/// conventions live — the crate has no opinion about them.
struct Scopes;

impl ScopeResolver for Scopes {
    type Scope = Scope;

    fn resolve(&self, request: &AuthRequest) -> Scope {
        let path = request.path();
        if path.starts_with("/health") {
            return Scope::Public;
        }
        if path.contains("/organisations") || path.contains("/authz/admin") {
            return Scope::Global;
        }
        match request.header("x-org-id") {
            Some(org) => Scope::Org(org.to_string()),
            None => Scope::Global,
        }
    }
}

struct MyService;

impl AuthProfile for MyService {
    type User = User;
    type Scope = Scope;
}

// ------------------------------------------------------------------ 3. wiring

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Configuration comes from the environment here for brevity; secrets would
    // normally be decrypted from a secret manager and passed in explicitly.
    let env = EnvConfig::with_prefix("AUTHN_").expect("prefix is non-empty");

    let gateway = match env.get("OIDC_ISSUER_URL").ok().flatten() {
        // No provider configured: development mode, everything authenticates as
        // a conspicuously-named identity.
        None => AuthnBuilder::<MyService, _>::new(Scopes)
            .with(DisabledAuthenticator::development())
            .build()
            .expect("chain is non-empty"),

        Some(_) => {
            let config = env.oidc_config().expect("oidc configuration");
            let provider =
                Arc::new(OidcProvider::discover(config).await.expect("discovery"));
            let login = Arc::new(LoginFlow::new(provider.clone()));

            // Order matters only in that the session authenticator goes last:
            // it is the one that turns an absent credential into a redirect.
            // The others decline anything that is not theirs, so their relative
            // order is irrelevant.
            AuthnBuilder::<MyService, _>::new(Scopes)
                .with_if(
                    env.is_set("API_TOKEN_PREFIX"),
                    api_tokens(&env, provider.clone()),
                )
                .with(BearerAuthenticator::new(provider.clone()))
                .with(
                    SessionAuthenticator::new(provider)
                        .with_login_redirect(login.clone()),
                )
                .build()
                .expect("chain is non-empty")
        }
    };

    log::info!("authenticators: {:?}", gateway.authenticator_names());
    let authn = ActixAuthn::new(gateway);

    HttpServer::new(move || {
        App::new()
            .wrap(authn.clone())
            .route("/health", web::get().to(whoami))
            .route("/config", web::get().to(whoami))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

/// Static tokens, falling through to RFC 7662 introspection when configured.
fn api_tokens(
    env: &EnvConfig,
    provider: Arc<OidcProvider>,
) -> ApiTokenAuthenticator<MyService> {
    let prefix = env.require("API_TOKEN_PREFIX").expect("api token prefix");
    let statics = env
        .get("API_STATIC_TOKENS")
        .ok()
        .flatten()
        .unwrap_or_default();

    let mut authenticator =
        ApiTokenAuthenticator::from_json(prefix, &statics).expect("static token list");

    // Prefer an explicitly configured endpoint; otherwise use the one the
    // provider advertises in its discovery metadata (RFC 8414).
    let endpoint = env
        .get("INTROSPECTION_ENDPOINT")
        .ok()
        .flatten()
        .or_else(|| provider.snapshot().introspection_endpoint());

    if let (Some(endpoint), Ok(header)) =
        (endpoint, env.require("INTROSPECTION_AUTH_HEADER"))
    {
        let validator = IntrospectionValidator::with_client(
            endpoint,
            header,
            provider.http_client().clone(),
        );
        authenticator = authenticator.with_fallback(Arc::new(validator));
    }

    authenticator
}

// ----------------------------------------------------------------- 4. handler

/// A public route runs with no principal inserted, so a handler can tell an
/// anonymous visitor from an authenticated one.
async fn whoami(request: HttpRequest) -> HttpResponse {
    match request.extensions().get::<User>() {
        Some(user) => {
            HttpResponse::Ok().body(format!("{} <{}>", user.username, user.email))
        }
        None => HttpResponse::Ok().body("anonymous"),
    }
}
