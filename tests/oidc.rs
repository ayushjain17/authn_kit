#![cfg(feature = "oidc")]
//! OIDC provider unit tests.
//!
//! Everything here runs without a network: configuration validation, claim
//! mapping, error classification, and metadata parsing. The flows that actually
//! talk to an issuer are covered against a mock provider in a later phase.

use std::time::{Duration, UNIX_EPOCH};

use authn_kit::{
    AuthError, ClaimSource,
    oidc::{
        OidcConfig, OidcConfigError, OidcProviderMetadata,
        discovered_introspection_endpoint, error::is_possibly_stale_keys,
        identity_from_id_token_claims,
    },
};
use chrono::{DateTime, Utc};
use openidconnect::{
    Audience, ClaimsVerificationError, EndUserEmail, EndUserName, EndUserUsername,
    IssuerUrl, LocalizedClaim, SignatureVerificationError, StandardClaims,
    SubjectIdentifier, core::CoreIdTokenClaims,
};

// ------------------------------------------------------------------- config

#[test]
fn config_rejects_a_malformed_issuer_url() {
    let error = OidcConfig::new("not a url", "client", "https://app.example/callback")
        .unwrap_err();
    assert!(matches!(error, OidcConfigError::IssuerUrl(_)));
}

#[test]
fn config_rejects_a_malformed_redirect_url() {
    let error =
        OidcConfig::new("https://idp.example", "client", "not a url").unwrap_err();
    assert!(matches!(error, OidcConfigError::RedirectUrl(_)));
}

/// OIDC Core requires the `openid` scope on the authorization request. The
/// original's `new_redirect` added only `email` and `profile`, relying on the
/// provider to infer the rest.
#[test]
fn config_requests_openid_by_default() {
    let config =
        OidcConfig::new("https://idp.example", "client", "https://app.example/cb")
            .unwrap();

    let scopes: Vec<&str> = config.scopes().iter().map(|s| s.as_str()).collect();
    assert!(scopes.contains(&"openid"), "got {scopes:?}");
    assert!(scopes.contains(&"email"));
    assert!(scopes.contains(&"profile"));
}

/// OAuth 2.1 requires PKCE of all clients, confidential ones included. The
/// original used none.
#[test]
fn config_enables_pkce_by_default() {
    let config =
        OidcConfig::new("https://idp.example", "client", "https://app.example/cb")
            .unwrap();
    assert!(config.uses_pkce());
    assert!(!config.with_pkce(false).uses_pkce());
}

#[test]
fn config_scopes_and_refresh_interval_are_overridable() {
    let config =
        OidcConfig::new("https://idp.example", "client", "https://app.example/cb")
            .unwrap()
            .with_scopes(["openid", "groups"])
            .with_min_refresh_interval(Duration::from_secs(5));

    let scopes: Vec<&str> = config.scopes().iter().map(|s| s.as_str()).collect();
    assert_eq!(scopes, vec!["openid", "groups"]);
    assert_eq!(config.min_refresh_interval(), Duration::from_secs(5));
}

// ------------------------------------------------------------ claim mapping

fn claims_at(expiry: i64) -> CoreIdTokenClaims {
    let mut name = LocalizedClaim::new();
    name.insert(None, EndUserName::new("Alice Example".to_string()));

    let standard = StandardClaims::new(SubjectIdentifier::new("sub-123".to_string()))
        .set_email(Some(EndUserEmail::new("alice@example.com".to_string())))
        .set_preferred_username(Some(EndUserUsername::new("alice".to_string())))
        .set_name(Some(name));

    CoreIdTokenClaims::new(
        IssuerUrl::new("https://idp.example".to_string()).unwrap(),
        vec![Audience::new("client-id".to_string())],
        DateTime::<Utc>::from_timestamp(expiry, 0).unwrap(),
        DateTime::<Utc>::from_timestamp(expiry - 3600, 0).unwrap(),
        standard,
        Default::default(),
    )
}

#[test]
fn maps_standard_claims_onto_identity_claims() {
    let identity = identity_from_id_token_claims(&claims_at(1_800_000_000));

    assert_eq!(identity.source, ClaimSource::IdToken);
    assert_eq!(identity.subject.as_deref(), Some("sub-123"));
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert_eq!(identity.preferred_username.as_deref(), Some("alice"));
    assert_eq!(identity.name.as_deref(), Some("Alice Example"));
    assert_eq!(
        identity.expires_at,
        Some(UNIX_EPOCH + Duration::from_secs(1_800_000_000))
    );
}

/// The original's `try_user_from` read exactly two claims and discarded the
/// rest, so an application could not reach group memberships or tenant ids
/// without editing the auth module.
#[test]
fn preserves_every_claim_the_provider_sent() {
    let identity = identity_from_id_token_claims(&claims_at(1_800_000_000));

    assert_eq!(
        identity.extra_claim::<String>("iss").as_deref(),
        Some("https://idp.example")
    );
    assert_eq!(
        identity.extra_claim::<String>("sub").as_deref(),
        Some("sub-123")
    );
    assert_eq!(identity.extra_claim::<i64>("exp"), Some(1_800_000_000));
    assert!(identity.extra.contains_key("aud"));
}

#[test]
fn identity_falls_back_to_the_subject_when_no_username_is_present() {
    let standard = StandardClaims::new(SubjectIdentifier::new("sub-only".to_string()));
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new("https://idp.example".to_string()).unwrap(),
        vec![Audience::new("client-id".to_string())],
        DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap(),
        DateTime::<Utc>::from_timestamp(1_799_996_400, 0).unwrap(),
        standard,
        Default::default(),
    );

    let identity = identity_from_id_token_claims(&claims);
    assert_eq!(identity.best_effort_username(), Some("sub-only"));
    assert_eq!(identity.email, None);
}

// ---------------------------------------------------- error classification
//
// Exhaustive over both error enums: refreshing the JWKS must be attempted for
// exactly the failures fresh keys could change, and for no others. The original
// refreshed on *any* verification error, so an expired token — which will fail
// identically against fresh keys — triggered a discovery request.

#[test]
fn only_key_related_signature_failures_warrant_a_refresh() {
    let signature_cases = [
        (SignatureVerificationError::NoMatchingKey, true),
        (SignatureVerificationError::CryptoError("bad".into()), true),
        (
            SignatureVerificationError::AmbiguousKeyId("dup".into()),
            true,
        ),
        (SignatureVerificationError::NoSignature, false),
        (
            SignatureVerificationError::UnsupportedAlg("none".into()),
            false,
        ),
        (
            SignatureVerificationError::DisallowedAlg("HS256".into()),
            false,
        ),
        (
            SignatureVerificationError::InvalidKey("wrong type".into()),
            false,
        ),
        (SignatureVerificationError::Other("?".into()), false),
    ];

    for (inner, expected) in signature_cases {
        let rendered = format!("{inner:?}");
        let error = ClaimsVerificationError::SignatureVerification(inner);
        assert_eq!(is_possibly_stale_keys(&error), expected, "for {rendered}");
    }
}

#[test]
fn non_signature_failures_never_warrant_a_refresh() {
    let cases = [
        ClaimsVerificationError::Expired("yesterday".into()),
        ClaimsVerificationError::InvalidAudience("other".into()),
        ClaimsVerificationError::InvalidIssuer("other".into()),
        ClaimsVerificationError::InvalidNonce("mismatch".into()),
        ClaimsVerificationError::InvalidSubject("nope".into()),
        ClaimsVerificationError::InvalidAuthContext("nope".into()),
        ClaimsVerificationError::InvalidAuthTime("too old".into()),
        ClaimsVerificationError::Unsupported("encrypted".into()),
        ClaimsVerificationError::Other("?".into()),
    ];

    for error in cases {
        assert!(!is_possibly_stale_keys(&error), "for {error}");
    }
}

/// A rejected token is the client's problem; an unsupported token shape is a
/// configuration problem. The original returned 500 for essentially all of them.
#[test]
fn verification_failures_map_to_client_facing_statuses() {
    assert_eq!(
        AuthError::from(ClaimsVerificationError::Expired("x".into())).status(),
        401
    );
    assert_eq!(
        AuthError::from(ClaimsVerificationError::InvalidAudience("x".into())).status(),
        401
    );
    assert_eq!(
        AuthError::from(ClaimsVerificationError::InvalidNonce("x".into())).status(),
        401
    );
    assert_eq!(
        AuthError::from(ClaimsVerificationError::Unsupported("x".into())).status(),
        501
    );
    // Never a service fault: none of these implicate our infrastructure.
    assert!(
        !AuthError::from(ClaimsVerificationError::Expired("x".into())).is_service_fault()
    );
}

// ----------------------------------------------------------------- metadata

/// A minimal but realistic discovery document, plus the RFC 8414
/// `introspection_endpoint` that OIDC Core discovery does not define.
const DISCOVERY_DOC: &str = r#"{
    "issuer": "https://idp.example",
    "authorization_endpoint": "https://idp.example/authorize",
    "token_endpoint": "https://idp.example/token",
    "jwks_uri": "https://idp.example/jwks",
    "introspection_endpoint": "https://idp.example/introspect",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"]
}"#;

#[test]
fn metadata_exposes_the_advertised_introspection_endpoint() {
    let metadata: OidcProviderMetadata = serde_json::from_str(DISCOVERY_DOC).unwrap();

    assert_eq!(
        discovered_introspection_endpoint(&metadata).as_deref(),
        Some("https://idp.example/introspect")
    );
}

/// Introspection is OPTIONAL in RFC 8414: a provider may support it without
/// advertising it, and many advertise nothing at all. Its absence must parse
/// cleanly rather than failing discovery.
#[test]
fn metadata_without_introspection_still_parses() {
    let without = DISCOVERY_DOC.replace(
        "\"introspection_endpoint\": \"https://idp.example/introspect\",",
        "",
    );
    let metadata: OidcProviderMetadata = serde_json::from_str(&without).unwrap();

    assert_eq!(discovered_introspection_endpoint(&metadata), None);
}

// ========================================================== login flow
//
// `authorize` and `complete` need a live issuer and are covered against a mock
// provider in a later phase. Everything below is the logic around them, which
// is where the security-relevant decisions actually live.

use authn_kit::{
    CookieDirective,
    oidc::{
        CallbackParams, CookieSettings, IdTokenCodec, RedirectPolicy, Session,
        SessionCodec,
    },
};

// --------------------------------------------------------- redirect policy
//
// The original placed `state.redirect_uri` — a field of the attacker-supplied
// `state` parameter — directly into a `Location` header. This crate keeps the
// destination out of `state` entirely, and validates it besides.

#[test]
fn relative_policy_accepts_same_origin_paths() {
    let policy = RedirectPolicy::RelativeOnly;

    for destination in ["/", "/admin/organisations", "/a?b=c#d"] {
        assert!(
            policy.validate(destination).is_ok(),
            "rejected {destination:?}"
        );
    }
}

#[test]
fn relative_policy_rejects_every_way_out_of_the_origin() {
    let policy = RedirectPolicy::RelativeOnly;

    let attacks = [
        ("https://evil.example", "absolute url"),
        ("http://evil.example/x", "absolute url"),
        ("//evil.example", "protocol-relative"),
        ("//evil.example/path", "protocol-relative"),
        (r"/\evil.example", "backslash protocol-relative"),
        ("evil.example", "schemeless absolute"),
        (
            "/path\nLocation: https://evil.example",
            "header injection via newline",
        ),
        (
            "/path\rSet-Cookie: x=1",
            "header injection via carriage return",
        ),
    ];

    for (destination, why) in attacks {
        let error = policy
            .validate(destination)
            .expect_err(&format!("accepted {destination:?} ({why})"));
        assert_eq!(error.status(), 400);
    }
}

#[test]
fn allowlist_policy_accepts_listed_origins_and_relative_paths() {
    let policy = RedirectPolicy::Allowlist(vec!["https://app.example".to_string()]);

    for destination in [
        "https://app.example",
        "https://app.example/",
        "https://app.example/admin",
        "https://app.example?next=1",
        "/still-relative",
    ] {
        assert!(
            policy.validate(destination).is_ok(),
            "rejected {destination:?}"
        );
    }
}

/// Prefix matching without an origin boundary is the classic allow-list bypass:
/// `https://app.example.evil.com` starts with `https://app.example`.
#[test]
fn allowlist_policy_matches_on_an_origin_boundary() {
    let policy = RedirectPolicy::Allowlist(vec!["https://app.example".to_string()]);

    for destination in [
        "https://app.example.evil.com",
        "https://app.examplex/admin",
        "https://evil.example",
    ] {
        assert!(
            policy.validate(destination).is_err(),
            "accepted {destination:?}"
        );
    }
}

// ------------------------------------------------------------- callback

#[test]
fn parses_a_successful_callback() {
    let CallbackParams::Success { code, state } =
        CallbackParams::from_query("code=abc123&state=xyz789").unwrap()
    else {
        panic!("expected Success");
    };

    assert_eq!(code.secret(), "abc123");
    assert_eq!(state.secret(), "xyz789");
}

/// A user clicking "Deny" is an RFC 6749 §4.1.2.1 error response, not a
/// malformed request. The original's `LoginParams` required `code` and `state`,
/// so this produced a deserialisation failure and an opaque 400.
#[test]
fn parses_a_provider_error_callback() {
    let CallbackParams::Failure { error, description } = CallbackParams::from_query(
        "error=access_denied&error_description=The+user+denied+the+request",
    )
    .unwrap() else {
        panic!("expected Failure");
    };

    assert_eq!(error, "access_denied");
    assert_eq!(description.as_deref(), Some("The user denied the request"));
}

#[test]
fn percent_encoded_callback_values_are_decoded() {
    let CallbackParams::Success { code, .. } =
        CallbackParams::from_query("code=a%2Bb%2Fc&state=s").unwrap()
    else {
        panic!("expected Success");
    };

    assert_eq!(code.secret(), "a+b/c");
}

#[test]
fn callback_without_code_or_error_is_rejected() {
    for query in ["", "state=only", "unrelated=1"] {
        let error =
            CallbackParams::from_query(query).expect_err(&format!("accepted {query:?}"));
        assert_eq!(error.status(), 400);
    }
}

// -------------------------------------------------------------- cookies

/// The original gave the protection cookie `Duration::days(7)` and left
/// `http_only` commented out — so the PKCE verifier, had there been one, would
/// have been readable from JavaScript for a week.
#[test]
fn protection_cookie_is_short_lived_and_script_inaccessible() {
    let rendered = CookieSettings::protection("authn_protection")
        .set("payload")
        .to_string();

    assert!(rendered.starts_with("authn_protection=payload"));
    assert!(rendered.contains("Max-Age=600"));
    assert!(rendered.contains("HttpOnly"));
    assert!(rendered.contains("Secure"));
}

/// `SameSite=Lax`, not `Strict`: the provider returns the user by a cross-site
/// top-level navigation, and `Strict` withholds cookies on exactly that. This is
/// the answer to the original's `TODO: figure out why this does not work`.
#[test]
fn login_cookies_use_lax_same_site_so_the_callback_carries_them() {
    assert!(
        CookieSettings::protection("p")
            .set("v")
            .to_string()
            .contains("SameSite=Lax")
    );
    assert!(
        CookieSettings::session("s")
            .set("v")
            .to_string()
            .contains("SameSite=Lax")
    );
}

#[test]
fn session_cookie_secure_flag_can_be_relaxed_for_local_http() {
    let rendered = CookieSettings::session("session")
        .with_secure(false)
        .set("token")
        .to_string();

    assert!(!rendered.contains("Secure"));
    assert!(rendered.contains("HttpOnly"));
}

#[test]
fn clearing_a_cookie_targets_the_same_path() {
    let settings = CookieSettings::session("session").with_path("/app");
    let cleared: CookieDirective = settings.clear();

    let rendered = cleared.to_string();
    assert!(rendered.starts_with("session="));
    assert!(rendered.contains("Path=/app"));
    assert!(rendered.contains("Max-Age=0"));
}

// -------------------------------------------------------------- codec

#[test]
fn id_token_codec_round_trips() {
    let codec = IdTokenCodec;
    let session = Session {
        id_token: "header.payload.sig".to_string(),
        expires_at: None,
    };

    let encoded = codec.encode(&session).unwrap();
    assert_eq!(encoded, "header.payload.sig");
    assert_eq!(
        codec.decode(&encoded).unwrap().id_token,
        "header.payload.sig"
    );
}

#[test]
fn id_token_codec_rejects_an_empty_cookie() {
    assert_eq!(IdTokenCodec.decode("").unwrap_err().status(), 401);
}
