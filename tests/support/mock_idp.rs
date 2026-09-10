//! A minimal OpenID Provider, served from a throwaway TCP listener.
//!
//! Enough of one to exercise discovery, JWKS retrieval, ID-token verification
//! and the token endpoint for real, rather than mocking the `openidconnect`
//! client and ending up testing the mock. No new dependencies: it answers a
//! handful of routes over a `tokio` listener.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use base64::Engine;
use openidconnect::{
    Audience, EndUserEmail, EndUserUsername, IssuerUrl, JsonWebKeyId, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, PrivateSigningKey, StandardClaims,
    SubjectIdentifier,
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub const SIGNING_KEY_PEM: &str = include_str!("../data/test_signing_key.pem");
pub const CLIENT_ID: &str = "test-client";
pub const CLIENT_SECRET: &str = "test-secret";
pub const REDIRECT_URL: &str = "https://app.example/oidc/callback";

/// An authorization code the provider will honour, and what it was issued
/// against.
#[derive(Clone, Debug, Default)]
pub struct PendingCode {
    /// Echoed into the minted ID token's `nonce` claim.
    pub nonce: Option<String>,
    /// When set, the token request must present a `code_verifier` that hashes to
    /// it, so PKCE is genuinely verified rather than merely sent.
    pub code_challenge: Option<String>,
}

/// A token request the endpoint received, kept for assertions.
#[derive(Clone, Debug)]
pub struct TokenRequest {
    pub grant_type: String,
    pub params: HashMap<String, String>,
    pub authorization: Option<String>,
}

impl TokenRequest {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// Client credentials from a `Basic` header (`client_secret_basic`).
    pub fn basic_credentials(&self) -> Option<(String, String)> {
        let encoded = self.authorization.as_ref()?.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (id, secret) = decoded.split_once(':')?;
        // RFC 6749 §2.3.1 form-encodes the two components before base64.
        Some((form_decode(id), form_decode(secret)))
    }
}

fn form_decode(input: &str) -> String {
    url::form_urlencoded::parse(format!("v={input}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| input.to_string())
}

#[derive(Default)]
struct IdpState {
    codes: HashMap<String, PendingCode>,
    /// `(username, password)` -> `(subject, email)`
    users: HashMap<(String, String), (String, String)>,
    clients: HashSet<(String, String)>,
    token_requests: Vec<TokenRequest>,
}

/// A running mock provider. Dropping it shuts the listener down.
pub struct MockIdp {
    pub issuer: String,
    signing_key: Arc<CoreRsaPrivateSigningKey>,
    state: Arc<Mutex<IdpState>>,
    _shutdown: tokio::task::JoinHandle<()>,
}

impl MockIdp {
    /// Binds an ephemeral port and serves discovery, JWKS and the token endpoint
    /// until dropped.
    pub async fn start() -> Self {
        Self::start_with_keys(true).await
    }

    /// `publish_key = false` serves an **empty** JWKS, so a token this provider
    /// signed fails verification with `NoMatchingKey` — the shape of a key
    /// rotation not yet picked up.
    pub async fn start_with_keys(publish_key: bool) -> Self {
        let signing_key = Arc::new(
            CoreRsaPrivateSigningKey::from_pem(
                SIGNING_KEY_PEM,
                Some(JsonWebKeyId::new("test-key".to_string())),
            )
            .expect("test signing key should parse"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());

        let jwks = if publish_key {
            CoreJsonWebKeySet::new(vec![signing_key.as_verification_key()])
        } else {
            CoreJsonWebKeySet::new(vec![])
        };
        let jwks_body = serde_json::to_string(&jwks).unwrap();
        let discovery_body = discovery_document(&issuer);

        let state = Arc::new(Mutex::new(IdpState::default()));
        let served_state = state.clone();
        let served_key = signing_key.clone();
        let served_issuer = issuer.clone();

        let shutdown = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let Some(request) = read_request(&mut socket).await else {
                    continue;
                };
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();

                let (status, body) = if path.contains("openid-configuration") {
                    (200, discovery_body.clone())
                } else if path.contains("jwks") {
                    (200, jwks_body.clone())
                } else if path.contains("token") {
                    handle_token(&request, &served_state, &served_key, &served_issuer)
                } else {
                    (200, String::from("{}"))
                };

                let response = format!(
                    "HTTP/1.1 {status} STATUS\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        Self {
            issuer,
            signing_key,
            state,
            _shutdown: shutdown,
        }
    }

    /// Registers an authorization code the token endpoint will honour.
    pub fn register_code(&self, code: &str, pending: PendingCode) {
        self.state
            .lock()
            .unwrap()
            .codes
            .insert(code.to_string(), pending);
    }

    /// Registers credentials the resource-owner password grant will accept.
    pub fn register_user(
        &self,
        username: &str,
        password: &str,
        subject: &str,
        email: &str,
    ) {
        self.state.lock().unwrap().users.insert(
            (username.to_string(), password.to_string()),
            (subject.to_string(), email.to_string()),
        );
    }

    /// Registers a client the `client_credentials` grant will accept.
    pub fn register_client(&self, client_id: &str, client_secret: &str) {
        self.state
            .lock()
            .unwrap()
            .clients
            .insert((client_id.to_string(), client_secret.to_string()));
    }

    /// Every token request the endpoint received.
    pub fn token_requests(&self) -> Vec<TokenRequest> {
        self.state.lock().unwrap().token_requests.clone()
    }

    /// Mints a signed ID token for `subject`, valid for an hour.
    pub fn mint_id_token(
        &self,
        subject: &str,
        email: &str,
        nonce: Option<&str>,
    ) -> String {
        self.mint_id_token_for_audience(subject, email, nonce, CLIENT_ID)
    }

    pub fn mint_id_token_for_audience(
        &self,
        subject: &str,
        email: &str,
        nonce: Option<&str>,
        audience: &str,
    ) -> String {
        sign_id_token(
            &self.signing_key,
            &self.issuer,
            subject,
            Some(email),
            nonce,
            audience,
            3600,
        )
    }

    /// An expired token, for exercising the expiry path.
    pub fn mint_expired_id_token(&self, subject: &str, email: &str) -> String {
        sign_id_token(
            &self.signing_key,
            &self.issuer,
            subject,
            Some(email),
            Some("n"),
            CLIENT_ID,
            -3600,
        )
    }
}

/// Serves the token endpoint. Returns `(status, body)`.
fn handle_token(
    request: &str,
    state: &Arc<Mutex<IdpState>>,
    signing_key: &CoreRsaPrivateSigningKey,
    issuer: &str,
) -> (u16, String) {
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    let params: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    let authorization = request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_string())
    });

    let grant_type = params.get("grant_type").cloned().unwrap_or_default();
    let recorded = TokenRequest {
        grant_type: grant_type.clone(),
        params: params.clone(),
        authorization,
    };
    let credentials = recorded.basic_credentials();
    state.lock().unwrap().token_requests.push(recorded);

    match grant_type.as_str() {
        "authorization_code" => {
            let Some(code) = params.get("code") else {
                return oauth_error("invalid_request");
            };
            let Some(pending) = state.lock().unwrap().codes.get(code).cloned() else {
                return oauth_error("invalid_grant");
            };

            // Verify PKCE properly rather than merely observing that a verifier
            // was sent: the presented verifier must hash to the challenge issued
            // with this code.
            if let Some(expected) = &pending.code_challenge {
                let Some(verifier) = params.get("code_verifier") else {
                    return oauth_error("invalid_grant");
                };
                let derived = PkceCodeChallenge::from_code_verifier_sha256(
                    &PkceCodeVerifier::new(verifier.clone()),
                );
                if derived.as_str() != expected {
                    return oauth_error("invalid_grant");
                }
            }

            let id_token = sign_id_token(
                signing_key,
                issuer,
                "alice",
                Some("alice@example.com"),
                pending.nonce.as_deref(),
                CLIENT_ID,
                3600,
            );
            token_response(Some(&id_token))
        }

        "password" => {
            let key = (
                params.get("username").cloned().unwrap_or_default(),
                params.get("password").cloned().unwrap_or_default(),
            );
            let Some((subject, email)) = state.lock().unwrap().users.get(&key).cloned()
            else {
                return oauth_error("invalid_grant");
            };

            // A password-grant token is minted outside an authorization request,
            // so it carries no nonce.
            let id_token = sign_id_token(
                signing_key,
                issuer,
                &subject,
                Some(&email),
                None,
                CLIENT_ID,
                3600,
            );
            token_response(Some(&id_token))
        }

        "client_credentials" => {
            let Some(credentials) = credentials else {
                return oauth_error("invalid_client");
            };
            if !state.lock().unwrap().clients.contains(&credentials) {
                return oauth_error("invalid_client");
            }
            // A machine grant has no end user, so no ID token.
            token_response(None)
        }

        _ => oauth_error("unsupported_grant_type"),
    }
}

fn token_response(id_token: Option<&str>) -> (u16, String) {
    let mut body = serde_json::json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    });
    if let Some(id_token) = id_token {
        body["id_token"] = serde_json::Value::String(id_token.to_string());
    }
    (200, body.to_string())
}

fn oauth_error(code: &str) -> (u16, String) {
    (400, serde_json::json!({ "error": code }).to_string())
}

fn sign_id_token(
    signing_key: &CoreRsaPrivateSigningKey,
    issuer: &str,
    subject: &str,
    email: Option<&str>,
    nonce: Option<&str>,
    audience: &str,
    expires_in_secs: i64,
) -> String {
    let now = chrono::Utc::now();
    let mut standard = StandardClaims::new(SubjectIdentifier::new(subject.to_string()))
        .set_preferred_username(Some(EndUserUsername::new(subject.to_string())));
    if let Some(email) = email {
        standard = standard.set_email(Some(EndUserEmail::new(email.to_string())));
    }

    let mut claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.to_string()).unwrap(),
        vec![Audience::new(audience.to_string())],
        now + chrono::Duration::seconds(expires_in_secs),
        now - chrono::Duration::seconds(60),
        standard,
        Default::default(),
    );
    if let Some(nonce) = nonce {
        claims = claims.set_nonce(Some(Nonce::new(nonce.to_string())));
    }

    CoreIdToken::new(
        claims,
        signing_key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("token should sign")
    .to_string()
}

/// Reads headers, then exactly `Content-Length` bytes of body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 2048];

    loop {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);

        let text = String::from_utf8_lossy(&raw);
        let Some(headers_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let expected: usize = text[..headers_end]
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);

        if raw.len() >= headers_end + 4 + expected {
            break;
        }
    }

    Some(String::from_utf8_lossy(&raw).into_owned())
}

fn discovery_document(issuer: &str) -> String {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": [
            "authorization_code", "password", "client_credentials",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post",
        ],
    })
    .to_string()
}
