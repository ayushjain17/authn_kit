//! What an authenticator concluded, and what the chain concluded.
//!
//! These are deliberately two types. An individual authenticator can only ever
//! say "this is who the credential identifies" or "this credential is not mine"
//! — anything else is a failure, reported as an
//! [`AuthError`](crate::error::AuthError). Deciding that a request may proceed
//! *without* an identity is a judgement about the route's scope, and belongs to
//! the chain alone.
//!
//! Folding both into one enum lets any authenticator in the chain wave a request
//! through anonymously, including on a scope that requires authentication. Two
//! types make that unrepresentable rather than merely untested.

/// What one authenticator concluded about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<U> {
    /// The credential was valid and identifies this principal.
    Authenticated(U),
    /// This authenticator does not handle the credential presented, and the
    /// chain should consult the next one.
    ///
    /// This is what makes authenticators composable. The original middleware had
    /// a single authenticator and dispatched between mechanisms inline —
    /// matching `Bearer`/`Basic`/`Internal` in a `match`, and asking the
    /// authenticator for an `api_token_prefix()` so it could strip the prefix
    /// itself — so every new mechanism meant editing the middleware.
    NotApplicable,
}

impl<U> Verdict<U> {
    pub fn is_applicable(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }

    pub fn principal(self) -> Option<U> {
        match self {
            Self::Authenticated(user) => Some(user),
            Self::NotApplicable => None,
        }
    }

    pub fn map<V>(self, f: impl FnOnce(U) -> V) -> Verdict<V> {
        match self {
            Self::Authenticated(user) => Verdict::Authenticated(f(user)),
            Self::NotApplicable => Verdict::NotApplicable,
        }
    }
}

/// What the chain concluded about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<U> {
    /// An authenticator resolved this principal.
    Authenticated(U),
    /// The request targets a public scope and carries no identity. Explicitly
    /// *not* a failure — and distinct from a default-constructed user, which is
    /// how the original represented it.
    ///
    /// Only ever produced for a scope reporting
    /// [`AuthScope::is_public`](crate::scope::AuthScope::is_public).
    Anonymous,
    /// No authenticator claimed the request. The caller turns this into a
    /// challenge — a `401`, or a redirect into an interactive login.
    NotApplicable,
}

impl<U> Outcome<U> {
    pub fn is_applicable(&self) -> bool {
        !matches!(self, Self::NotApplicable)
    }

    pub fn principal(self) -> Option<U> {
        match self {
            Self::Authenticated(user) => Some(user),
            Self::Anonymous | Self::NotApplicable => None,
        }
    }

    pub fn map<V>(self, f: impl FnOnce(U) -> V) -> Outcome<V> {
        match self {
            Self::Authenticated(user) => Outcome::Authenticated(f(user)),
            Self::Anonymous => Outcome::Anonymous,
            Self::NotApplicable => Outcome::NotApplicable,
        }
    }
}

impl<U> From<Verdict<U>> for Outcome<U> {
    fn from(verdict: Verdict<U>) -> Self {
        match verdict {
            Verdict::Authenticated(user) => Self::Authenticated(user),
            Verdict::NotApplicable => Self::NotApplicable,
        }
    }
}
