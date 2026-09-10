//! axum adapter.
//!
//! Deliberately minimal at this stage. Its job right now is to *prove* that the
//! core carries no actix dependency: if anything in [`crate::gateway`],
//! [`crate::authenticator`] or the authenticators themselves leaked an actix
//! type or a non-`Send` future, this module would not compile.
//!
//! Discovering that at the end of the project would mean reworking the error and
//! future plumbing across the whole crate; discovering it here costs nothing.

use axum::{
    body::Body,
    http::{HeaderMap, Response, StatusCode, header},
    response::IntoResponse,
};

use crate::{
    authenticator::AuthProfile, error::AuthError, gateway::AuthGateway,
    request::AuthRequest, scope::ScopeResolver,
};

/// Builds an [`AuthRequest`] from axum request parts.
///
/// axum does not model cookies natively, so the `Cookie` header is parsed here,
/// per RFC 6265 §4.2.1 (`name=value` pairs separated by `"; "`).
impl From<&axum::http::request::Parts> for AuthRequest {
    fn from(parts: &axum::http::request::Parts) -> Self {
        let mut builder = Self::builder()
            .method(parts.method.as_str())
            .path(parts.uri.path())
            .route_pattern(
                parts
                    .extensions
                    .get::<axum::extract::MatchedPath>()
                    .map(|matched| matched.as_str().to_string()),
            )
            .query(parts.uri.query().unwrap_or_default());

        for (name, value) in &parts.headers {
            if let Ok(value) = value.to_str() {
                builder = builder.header(name.as_str(), value);
            }
        }

        for (name, value) in cookies_from_headers(&parts.headers) {
            builder = builder.cookie(name, value);
        }

        builder.build()
    }
}

fn cookies_from_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// Renders an [`AuthError`] as an axum response.
///
/// Only [`AuthError::client_message`] reaches the client; the operator detail is
/// logged. Cookie syntax comes from [`CookieDirective`]'s `Display`, which axum
/// needs because it has no typed cookie builder of its own.
impl IntoResponse for AuthError {
    fn into_response(self) -> Response<Body> {
        if self.is_service_fault() {
            log::error!("authn: {}", self.detail());
        } else {
            log::debug!("authn: {}", self.detail());
        }

        if let AuthError::Redirect { location, cookies } = &self {
            let mut builder = Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, location);
            for directive in cookies {
                builder = builder.header(header::SET_COOKIE, directive.to_string());
            }
            return builder
                .body(Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }

        let status = StatusCode::from_u16(self.status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            axum::Json(serde_json::json!({ "message": self.client_message() })),
        )
            .into_response()
    }
}

/// Authenticates a request and returns the principal, for use from an axum
/// middleware or extractor.
///
/// Kept as a free function rather than a `tower::Layer` while this module is a
/// compile-time proof; the layer arrives with the fully supported axum adapter.
pub async fn authenticate<P, R>(
    gateway: &AuthGateway<P, R>,
    parts: &axum::http::request::Parts,
) -> Result<Option<P::User>, AuthError>
where
    P: AuthProfile,
    R: ScopeResolver<Scope = P::Scope>,
{
    let request = AuthRequest::from(parts);
    gateway.authenticate(&request).await
}
