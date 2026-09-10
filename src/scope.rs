//! Request scoping: the generic replacement for the original `Login` enum.
//!
//! The original baked one application's tenancy model into the authentication
//! layer — `Login::{None, Global, Org(String)}` — and hard-coded the rules that
//! produced it (paths containing `/organisations`, `/authz/admin` or
//! `/admin/settings` are "global"; everything else reads an organisation id from
//! an `x-org-id` header). None of that is authentication's business.
//!
//! Here an application defines its own scope type and the rule that derives one
//! from a request. Single-tenant services use [`NoScope`] and never think about
//! it again.

use std::{fmt::Display, hash::Hash};

use crate::request::AuthRequest;

/// An application's notion of "which realm does this request authenticate
/// against". Used to key credential caches and to name session cookies.
pub trait AuthScope: Clone + Eq + Hash + Display + Send + Sync + 'static {
    /// Whether this scope requires no authentication at all.
    ///
    /// The original signalled this with `Login::None` and then returned
    /// `User::default()` — a fully-formed identity, `user@superposition.io`,
    /// indistinguishable downstream from that user having genuinely signed in.
    /// Here a public scope yields [`Outcome::Anonymous`](crate::outcome::Outcome),
    /// so authorization can tell the two apart.
    fn is_public(&self) -> bool {
        false
    }

    /// A stable discriminator mixed into credential-cache keys, so a credential
    /// validated for one tenant can never be served from cache for another.
    /// `None` for single-realm deployments.
    fn cache_discriminator(&self) -> Option<&str> {
        None
    }

    /// The name of the session cookie for this scope. Defaults to the scope's
    /// `Display`, matching the original's cookie-per-scope behaviour.
    fn session_cookie_name(&self) -> String {
        self.to_string()
    }
}

/// Derives the scope of a request. Supplied by the application.
pub trait ScopeResolver: Send + Sync + 'static {
    type Scope: AuthScope;

    fn resolve(&self, request: &AuthRequest) -> Self::Scope;
}

/// The scope of a single-tenant service: one realm, never public.
///
/// Public routes in a single-tenant service are better handled by not wrapping
/// them in the middleware at all; [`AuthScope::is_public`] exists for services
/// whose public routes are interleaved with protected ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct NoScope;

impl Display for NoScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("session")
    }
}

impl AuthScope for NoScope {}

/// Resolves every request to [`NoScope`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SingleScope;

impl ScopeResolver for SingleScope {
    type Scope = NoScope;

    fn resolve(&self, _request: &AuthRequest) -> Self::Scope {
        NoScope
    }
}
