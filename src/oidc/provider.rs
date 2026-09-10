//! The OIDC provider: discovery, the JWKS-backed client, and token verification.

use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use openidconnect::{
    ClientId, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenVerifier, Nonce,
    RedirectUrl,
    core::{CoreClient, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKey},
    reqwest,
};

use crate::{
    claims::IdentityClaims,
    error::AuthError,
    oidc::{
        claims::identity_from_id_token_claims,
        config::OidcConfig,
        error::is_possibly_stale_keys,
        metadata::{OidcProviderMetadata, discovered_introspection_endpoint},
    },
};

/// The client type produced by [`CoreClient::from_provider_metadata`].
///
/// `openidconnect` 4.x tracks which endpoints are configured in the type, so the
/// concrete state has to be spelled out to store one in a struct: the
/// authorization endpoint is always present in discovery metadata, the token and
/// user-info endpoints are optional in the spec and so are "maybe set", and the
/// device/introspection/revocation endpoints are not configured here.
pub type OidcClient = CoreClient<
    EndpointSet,      // authorization
    EndpointNotSet,   // device authorization
    EndpointNotSet,   // introspection
    EndpointNotSet,   // revocation
    EndpointMaybeSet, // token
    EndpointMaybeSet, // user info
>;

/// An immutable snapshot of everything discovery produced.
///
/// Swapped atomically as a unit, so a reader can never observe metadata from one
/// fetch alongside a client built from another.
pub struct ProviderState {
    metadata: OidcProviderMetadata,
    client: OidcClient,
    fetched_at: Instant,
}

impl ProviderState {
    pub fn client(&self) -> &OidcClient {
        &self.client
    }

    pub fn metadata(&self) -> &OidcProviderMetadata {
        &self.metadata
    }

    /// The RFC 8414 introspection endpoint the provider advertises, if any.
    /// Consumed by the API-token flow.
    pub fn introspection_endpoint(&self) -> Option<String> {
        discovered_introspection_endpoint(&self.metadata)
    }

    /// How long ago this snapshot was fetched.
    pub fn age(&self) -> Duration {
        self.fetched_at.elapsed()
    }
}

/// How strictly the `nonce` claim is checked.
///
/// The original expressed this as two free functions, `verify_presence` and
/// `presence_no_check`, passed around as callbacks. Naming the three cases makes
/// it obvious at each call site which guarantee is in force.
pub enum NonceCheck<'a> {
    /// The nonce must equal this value. Used on the authorization-code callback,
    /// where the nonce was minted by us and stored in the protection cookie.
    /// This is the only variant that actually binds a token to a login attempt.
    Matches(&'a Nonce),
    /// A nonce must be present, but its value is not checked. Used when
    /// re-validating a session token whose originating nonce is long gone.
    Present,
    /// No nonce requirement. Used for tokens minted outside an authorization
    /// request, such as the password grant, which has no nonce to carry.
    Skip,
}

/// A discovered OpenID Provider, and the client built from it.
///
/// Cheap to share: [`Self::snapshot`] clones an `Arc`, where the original cloned
/// the entire `CoreClient` — JWKS included — out of an `RwLock` on every single
/// request.
pub struct OidcProvider {
    config: OidcConfig,
    http: reqwest::Client,
    /// The lock is held only long enough to clone the `Arc` out, never across an
    /// `.await`, and a poisoned lock is recovered from rather than propagated:
    /// a panic elsewhere must not take authentication down with it.
    state: RwLock<Arc<ProviderState>>,
    /// Serialises refreshes so a burst of failures produces one discovery
    /// request rather than one per request.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl OidcProvider {
    /// Discovers the provider's metadata and builds a client from it.
    pub async fn discover(config: OidcConfig) -> Result<Self, AuthError> {
        // Redirects are disabled: the discovery and token endpoints are
        // configuration-derived URLs, and following a redirect from one of them
        // would let a compromised issuer point us at an arbitrary host.
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                AuthError::internal(format!("could not build http client: {e}"))
            })?;

        let state = Self::fetch_state(&config, &http).await?;

        Ok(Self {
            config,
            http,
            state: RwLock::new(Arc::new(state)),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// The shared HTTP client, for flows that talk to the provider directly
    /// (token introspection, for one).
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    /// Builds a client configured with *another party's* credentials.
    ///
    /// The `client_credentials` grant authenticates the caller's `client_id` and
    /// `client_secret`, not this service's, so the exchange has to run against a
    /// client carrying theirs. Reuses the currently-discovered metadata, so no
    /// network call is involved.
    pub fn machine_client(
        &self,
        client_id: ClientId,
        client_secret: openidconnect::ClientSecret,
    ) -> OidcClient {
        build_client(
            self.snapshot().metadata().clone(),
            client_id,
            Some(client_secret),
            self.config.redirect_url().clone(),
        )
    }

    /// The current provider snapshot. Clones an `Arc`, so it is safe to hold
    /// across an `.await` and never keeps the lock.
    pub fn snapshot(&self) -> Arc<ProviderState> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn store(&self, state: ProviderState) {
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(state);
    }

    async fn fetch_state(
        config: &OidcConfig,
        http: &reqwest::Client,
    ) -> Result<ProviderState, AuthError> {
        let metadata =
            OidcProviderMetadata::discover_async(config.issuer_url.clone(), http).await?;

        let client = build_client(
            metadata.clone(),
            config.client_id.clone(),
            config.client_secret.clone(),
            config.redirect_url.clone(),
        );

        Ok(ProviderState {
            metadata,
            client,
            fetched_at: Instant::now(),
        })
    }

    /// Re-runs discovery and swaps in a client built from the fresh metadata.
    ///
    /// Called when verification fails in a way that stale JWKS would explain, so
    /// a long-lived process recovers from key rotation without a restart.
    ///
    /// Two properties the original lacked:
    ///
    /// * **Single-flight** — concurrent callers serialise on a mutex, and all
    ///   but the first observe the completed refresh and return. The original
    ///   issued one discovery request per failing request, so a key rotation
    ///   under load meant a burst of identical fetches at the issuer.
    /// * **Debounced** — a refresh newer than `min_refresh_interval` is treated
    ///   as already done. Without this, a genuinely-forged token stream would
    ///   pin the issuer's discovery endpoint indefinitely.
    pub async fn refresh(&self) -> Result<(), AuthError> {
        let observed = self.snapshot();
        if observed.age() < self.config.min_refresh_interval {
            return Ok(());
        }

        let _guard = self.refresh_lock.lock().await;

        // Re-check under the lock: whoever held it before us may have refreshed
        // already, in which case there is nothing to do.
        let current = self.snapshot();
        if !Arc::ptr_eq(&observed, &current)
            || current.age() < self.config.min_refresh_interval
        {
            return Ok(());
        }

        self.store(Self::fetch_state(&self.config, &self.http).await?);
        Ok(())
    }

    /// Verifies an ID token and returns its claims.
    ///
    /// On a signature failure — the signature that stale JWKS would explain —
    /// refreshes provider metadata once and retries. Other failures (expiry,
    /// audience, issuer, nonce) are returned immediately, since fresh keys
    /// cannot change the outcome.
    ///
    /// The original had this recovery only in the login callback and the
    /// password grant. Bearer-token and session-cookie validation were
    /// synchronous and so *could not* refresh, meaning a key rotation invalidated
    /// every existing session and API token until a fresh interactive login or a
    /// process restart.
    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: NonceCheck<'_>,
    ) -> Result<IdentityClaims, AuthError> {
        let id_token: CoreIdToken = token.parse().map_err(|e| {
            AuthError::invalid_credential(format!("malformed id token: {e}"))
        })?;

        let state = self.snapshot();
        let first = verify(&id_token, &state.client().id_token_verifier(), &nonce);

        let error = match first {
            Ok(claims) => return Ok(identity_from_id_token_claims(&claims)),
            Err(error) => error,
        };

        if !is_possibly_stale_keys(&error) {
            return Err(error.into());
        }

        log::info!(
            "authn: id-token signature did not verify; refreshing provider keys and retrying"
        );
        self.refresh().await?;

        let state = self.snapshot();
        verify(&id_token, &state.client().id_token_verifier(), &nonce)
            .map(|claims| identity_from_id_token_claims(&claims))
            .map_err(AuthError::from)
    }
}

fn verify(
    id_token: &CoreIdToken,
    verifier: &IdTokenVerifier<'_, CoreJsonWebKey>,
    nonce: &NonceCheck<'_>,
) -> Result<CoreIdTokenClaims, openidconnect::ClaimsVerificationError> {
    let claims = match nonce {
        NonceCheck::Matches(expected) => id_token.claims(verifier, *expected),
        NonceCheck::Present => id_token.claims(verifier, require_nonce_present),
        NonceCheck::Skip => id_token.claims(verifier, skip_nonce_check),
    }?;
    Ok(claims.clone())
}

fn require_nonce_present(nonce: Option<&Nonce>) -> Result<(), String> {
    if nonce.is_some() {
        Ok(())
    } else {
        Err("missing nonce claim".to_string())
    }
}

fn skip_nonce_check(_: Option<&Nonce>) -> Result<(), String> {
    Ok(())
}

fn build_client(
    metadata: OidcProviderMetadata,
    client_id: ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    redirect_url: RedirectUrl,
) -> OidcClient {
    CoreClient::from_provider_metadata(metadata, client_id, client_secret)
        .set_redirect_uri(redirect_url)
}
