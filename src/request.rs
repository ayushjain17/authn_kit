//! An owned, `Send` view of the parts of an HTTP request authentication needs.
//!
//! ## Why not `http::request::Parts`?
//!
//! It would be the obvious lingua franca, but actix-web 4.x is built on
//! `http 0.2` while axum 0.8 is on `http 1.x`. Putting `http` types in this
//! crate's public API would force a version choice that one of the two adapters
//! must lose. An owned struct sidesteps the split entirely.
//!
//! ## Why owned?
//!
//! actix's `HttpRequest` is `!Send`, which is precisely why the original code
//! threaded `LocalBoxFuture` through every signature and, in doing so, made
//! itself unusable from axum. Snapshotting the handful of fields authentication
//! actually reads — *before* entering any async block — makes every future in
//! this crate `Send` without the adapter having to fight its framework.

use std::collections::HashMap;

/// The request fields authentication decisions are made from.
///
/// Built by a framework adapter via [`AuthRequestBuilder`]. Header names are
/// normalised to lowercase on insertion, so lookups are case-insensitive as
/// RFC 9110 requires.
#[derive(Clone, Debug, Default)]
pub struct AuthRequest {
    method: String,
    path: String,
    route_pattern: Option<String>,
    query: String,
    headers: HashMap<String, Vec<String>>,
    cookies: HashMap<String, String>,
}

impl AuthRequest {
    pub fn builder() -> AuthRequestBuilder {
        AuthRequestBuilder::default()
    }

    /// The HTTP method, uppercased.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The concrete request path, e.g. `/admin/acme/workspaces`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The matched route pattern, e.g. `/admin/{org_id}/workspaces`, when the
    /// framework resolved one. Scope resolvers should prefer this over
    /// [`Self::path`]: matching on concrete paths makes an exclusion list
    /// sensitive to identifiers that happen to contain a reserved word.
    pub fn route_pattern(&self) -> Option<&str> {
        self.route_pattern.as_deref()
    }

    /// The raw query string, without the leading `?`.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The first value of `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Every value of `name`, for headers that legitimately repeat.
    pub fn header_all(&self, name: &str) -> &[String] {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The value of cookie `name`.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str)
    }

    /// The first value of query parameter `name`.
    ///
    /// Unlike the original `get_query_param`, this matches whole parameter names
    /// and splits on the *first* `=` only. The original used `contains()` on the
    /// segment, so a lookup for `org` also matched a parameter named
    /// `other_org`, and it took `nth(1)` after splitting on every `=`, silently
    /// truncating any value containing one — which base64 and JWT values do.
    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query.split('&').find_map(|segment| {
            let (key, value) = segment.split_once('=')?;
            (key == name).then_some(value)
        })
    }

    /// Resolves a path parameter by aligning the matched route pattern against
    /// the concrete path, e.g. `param = "{org_id}"` against pattern
    /// `/admin/{org_id}/x` and path `/admin/acme/x` yields `acme`.
    pub fn path_param(&self, param: &str) -> Option<&str> {
        let position = self
            .route_pattern
            .as_ref()?
            .split('/')
            .position(|segment| segment == param)?;
        self.path.split('/').nth(position)
    }
}

/// Builds an [`AuthRequest`]. Framework adapters own the mapping from their
/// native request type into this.
#[derive(Debug, Default)]
pub struct AuthRequestBuilder {
    request: AuthRequest,
}

impl AuthRequestBuilder {
    pub fn method(mut self, method: impl AsRef<str>) -> Self {
        self.request.method = method.as_ref().to_ascii_uppercase();
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.request.path = path.into();
        self
    }

    pub fn route_pattern(mut self, pattern: Option<String>) -> Self {
        self.request.route_pattern = pattern;
        self
    }

    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.request.query = query.into();
        self
    }

    /// Appends a header value, lowercasing the name.
    pub fn header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.request
            .headers
            .entry(name.as_ref().to_ascii_lowercase())
            .or_default()
            .push(value.into());
        self
    }

    pub fn cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request.cookies.insert(name.into(), value.into());
        self
    }

    pub fn build(self) -> AuthRequest {
        self.request
    }
}
