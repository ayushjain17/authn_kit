//! A bounded, TTL-based cache for validated credentials.
//!
//! Credentials presented on every request — a `Basic` pair, an API token —
//! otherwise round-trip to the identity provider each time. This memoises the
//! resolved principal until shortly before the underlying token would expire.
//!
//! Three changes from the original `TokenExchangeCache`, all of which matter:
//!
//! * **The key hashes with BLAKE3, not `DefaultHasher`.** The original hashed
//!   the credential to a `u64` with SipHash. A 64-bit collision between two
//!   credentials would resolve one principal's request to a *different*
//!   principal's cached identity — an authentication bypass, however unlikely.
//!   256 bits puts that beyond reach.
//! * **The scope is part of the key by construction**, not by each caller
//!   remembering to pass it. The original left it to the call site: the simple
//!   authenticator passed `None`, the SaaS one passed the org. A future
//!   authenticator passing `None` by mistake would serve one tenant's principal
//!   to another.
//! * **It is bounded and prunes lazily.** The original called `retain` over the
//!   whole map on *every* insert, holding the write lock — O(n) per write, with
//!   no size limit.

use std::{
    collections::HashMap,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Default seconds to drop a cached principal before the token's actual expiry,
/// covering clock skew and in-flight latency.
pub const DEFAULT_REFRESH_MARGIN: Duration = Duration::from_secs(30);

/// Default TTL when the provider omits `expires_in`, which RFC 6749 §5.1 only
/// RECOMMENDS rather than requires.
pub const DEFAULT_FALLBACK_TTL: Duration = Duration::from_secs(60);

/// Default cap on cached entries.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub refresh_margin: Duration,
    pub fallback_ttl: Duration,
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            refresh_margin: DEFAULT_REFRESH_MARGIN,
            fallback_ttl: DEFAULT_FALLBACK_TTL,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// `(scope, mechanism, principal, BLAKE3(secret))`.
///
/// The secret is hashed rather than stored, so a memory dump does not yield
/// usable credentials, and rotating a secret is automatically a miss.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CacheKey {
    scope: Option<String>,
    mechanism: &'static str,
    principal: String,
    digest: [u8; 32],
}

struct Entry<U> {
    value: U,
    expires_at: Instant,
    /// Logical clock reading of the last read or write, for LRU eviction.
    /// Atomic so a cache hit can record use while holding only a read lock,
    /// keeping reads concurrent.
    last_used: AtomicU64,
}

pub struct CredentialCache<U> {
    entries: RwLock<HashMap<CacheKey, Entry<U>>>,
    config: CacheConfig,
    /// Monotonic logical clock; cheaper than `Instant` and enough to order uses.
    clock: AtomicU64,
}

impl<U: Clone> Default for CredentialCache<U> {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

impl<U: Clone> CredentialCache<U> {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
            clock: AtomicU64::new(0),
        }
    }

    /// Monotonic logical clock reading, used to order accesses for LRU.
    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    /// Builds a key.
    ///
    /// `scope` should come from
    /// [`AuthScope::cache_discriminator`](crate::scope::AuthScope::cache_discriminator),
    /// and `mechanism` from [`Authenticator::name`](crate::authenticator::Authenticator::name),
    /// so a `username` under one mechanism can never collide with a `client_id`
    /// under another.
    ///
    /// Unkeyed BLAKE3 is deliberate: an attacker who could precompute digests
    /// would still need the preimage to authenticate, so a per-process key would
    /// add cost without adding protection.
    pub fn key(
        scope: Option<&str>,
        mechanism: &'static str,
        principal: &str,
        secret: &str,
    ) -> CacheKey {
        CacheKey {
            scope: scope.map(str::to_string),
            mechanism,
            principal: principal.to_string(),
            digest: *blake3::hash(secret.as_bytes()).as_bytes(),
        }
    }

    /// The cached principal, if present and not yet expired.
    ///
    /// Records the access for LRU purposes without taking the write lock.
    pub fn get(&self, key: &CacheKey) -> Option<U> {
        let tick = self.tick();
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries
            .get(key)
            .filter(|entry| Instant::now() < entry.expires_at)
            .map(|entry| {
                entry.last_used.store(tick, Ordering::Relaxed);
                entry.value.clone()
            })
    }

    /// Caches `value` for `expires_in` minus the safety margin, or the fallback
    /// TTL when the provider gave no expiry.
    ///
    /// Pruning happens only at capacity rather than on every write. If expiring
    /// entries does not free room, the least-recently-used entry is evicted, so
    /// a full cache keeps serving its hot credentials instead of falling off a
    /// cliff where every request revalidates against the provider.
    pub fn insert(&self, key: CacheKey, value: U, expires_in: Option<Duration>) {
        let ttl = expires_in
            .unwrap_or(self.config.fallback_ttl)
            .saturating_sub(self.config.refresh_margin);
        if ttl.is_zero() || self.config.max_entries == 0 {
            return;
        }

        let tick = self.tick();
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());

        if entries.len() >= self.config.max_entries && !entries.contains_key(&key) {
            let now = Instant::now();
            entries.retain(|_, entry| entry.expires_at > now);

            // Still full: evict the coldest entry. The scan is O(n), but only on
            // a write that actually hits the ceiling.
            while entries.len() >= self.config.max_entries {
                let coldest = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                    .map(|(key, _)| key.clone());
                match coldest {
                    Some(coldest) => {
                        entries.remove(&coldest);
                    }
                    None => break,
                }
            }
        }

        entries.insert(
            key,
            Entry {
                value,
                expires_at: Instant::now() + ttl,
                last_used: AtomicU64::new(tick),
            },
        );
    }

    /// Drops a specific entry, for logout or explicit revocation.
    pub fn invalidate(&self, key: &CacheKey) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
