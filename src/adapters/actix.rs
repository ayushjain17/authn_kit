//! actix-web adapter.
//!
//! Replaces `AuthNMiddleware` and the `AuthNHandler: Transform` impl. Compare
//! the two and the difference is that everything here is translation: there is
//! no `match` on authentication schemes, no prefix stripping, no `AppState`, and
//! no decision about what any credential means.

use std::{
    future::{Ready, ready},
    rc::Rc,
    sync::Arc,
};

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, EitherBody},
    cookie::{Cookie, SameSite as ActixSameSite, time::Duration as CookieDuration},
    dev::{
        Extensions, Service, ServiceRequest, ServiceResponse, Transform, forward_ready,
    },
    http::{StatusCode, header},
};
use futures_util::future::LocalBoxFuture;

use crate::{
    authenticator::AuthProfile,
    cookie::{CookieDirective, SameSite},
    error::AuthError,
    gateway::AuthGateway,
    request::AuthRequest,
    scope::ScopeResolver,
};

/// Builds an [`AuthRequest`] from an actix request.
///
/// Every field is copied out *before* any async work begins, which is what frees
/// the rest of the crate from actix's `!Send` request type — and so from the
/// `LocalBoxFuture` that made the original unusable outside actix.
impl From<&ServiceRequest> for AuthRequest {
    fn from(request: &ServiceRequest) -> Self {
        let mut builder = Self::builder()
            .method(request.method().as_str())
            .path(request.path())
            .route_pattern(request.match_pattern())
            .query(request.query_string());

        for (name, value) in request.headers() {
            if let Ok(value) = value.to_str() {
                builder = builder.header(name.as_str(), value);
            }
        }

        if let Ok(cookies) = request.cookies() {
            for cookie in cookies.iter() {
                builder = builder.cookie(cookie.name(), cookie.value());
            }
        }

        builder.build()
    }
}

/// Both conversions live in this module rather than in [`crate::cookie`], so
/// they are gated by the `actix` feature without needing a `cfg` attribute and
/// the core stays free of framework imports.
impl From<SameSite> for ActixSameSite {
    fn from(same_site: SameSite) -> Self {
        match same_site {
            SameSite::Strict => Self::Strict,
            SameSite::Lax => Self::Lax,
            SameSite::None => Self::None,
        }
    }
}

impl From<&CookieDirective> for Cookie<'static> {
    fn from(directive: &CookieDirective) -> Self {
        let mut cookie = Cookie::build(directive.name.clone(), directive.value.clone())
            .http_only(directive.http_only)
            .secure(directive.secure)
            .finish();

        if let Some(path) = &directive.path {
            cookie.set_path(path.clone());
        }
        if let Some(domain) = &directive.domain {
            cookie.set_domain(domain.clone());
        }
        if let Some(max_age) = directive.max_age {
            cookie.set_max_age(
                CookieDuration::try_from(max_age).unwrap_or(CookieDuration::ZERO),
            );
        }
        if let Some(same_site) = directive.same_site {
            cookie.set_same_site(ActixSameSite::from(same_site));
        }
        cookie
    }
}

/// Renders an [`AuthError`] as an actix response.
///
/// Only [`AuthError::client_message`] reaches the client; the operator detail is
/// logged. The original returned whatever `HttpResponse` the failing code
/// happened to construct, which in places meant an internal reason or a
/// misleading status.
pub fn error_to_response(error: &AuthError) -> HttpResponse {
    if error.is_service_fault() {
        log::error!("authn: {}", error.detail());
    } else {
        log::debug!("authn: {}", error.detail());
    }

    if let AuthError::Redirect { location, cookies } = error {
        let mut response = HttpResponse::Found();
        response.insert_header((header::LOCATION, location.clone()));
        for directive in cookies {
            response.cookie(Cookie::from(directive));
        }
        return response.finish();
    }

    let status =
        StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    HttpResponse::build(status)
        .json(serde_json::json!({ "message": error.client_message() }))
}

/// Derives additional request extensions from an authenticated principal.
///
/// See [`ActixAuthn::with_extensions`].
pub type ExtensionHook<P> =
    Arc<dyn Fn(&<P as AuthProfile>::User, &mut Extensions) + Send + Sync>;

/// actix middleware factory.
///
/// ```ignore
/// App::new().wrap(ActixAuthn::new(gateway))
/// ```
pub struct ActixAuthn<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> {
    gateway: Arc<AuthGateway<P, R>>,
    extensions: Option<ExtensionHook<P>>,
}

impl<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> ActixAuthn<P, R> {
    pub fn new(gateway: AuthGateway<P, R>) -> Self {
        Self::from_arc(Arc::new(gateway))
    }

    pub fn from_arc(gateway: Arc<AuthGateway<P, R>>) -> Self {
        Self {
            gateway,
            extensions: None,
        }
    }

    /// Runs `hook` after a successful authentication, so an application can put
    /// values derived from the principal into request extensions.
    ///
    /// The principal itself is always inserted; this is for everything an
    /// application wants *alongside* it — a narrower user type that existing
    /// extractors already expect, or marker types recording *how* the request
    /// authenticated, so later middleware can branch on it.
    ///
    /// Without this, such values could only come from a second middleware whose
    /// entire job was translation, or by rewriting every downstream consumer.
    pub fn with_extensions<F>(mut self, hook: F) -> Self
    where
        F: Fn(&P::User, &mut Extensions) + Send + Sync + 'static,
    {
        self.extensions = Some(Arc::new(hook));
        self
    }
}

impl<P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> Clone for ActixAuthn<P, R> {
    fn clone(&self) -> Self {
        Self {
            gateway: self.gateway.clone(),
            extensions: self.extensions.clone(),
        }
    }
}

impl<S, B, P, R> Transform<S, ServiceRequest> for ActixAuthn<P, R>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    P: AuthProfile,
    R: ScopeResolver<Scope = P::Scope>,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = ActixAuthnMiddleware<S, P, R>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ActixAuthnMiddleware {
            service: Rc::new(service),
            gateway: self.gateway.clone(),
            extensions: self.extensions.clone(),
        }))
    }
}

pub struct ActixAuthnMiddleware<S, P: AuthProfile, R: ScopeResolver<Scope = P::Scope>> {
    service: Rc<S>,
    gateway: Arc<AuthGateway<P, R>>,
    extensions: Option<ExtensionHook<P>>,
}

impl<S, B, P, R> Service<ServiceRequest> for ActixAuthnMiddleware<S, P, R>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    P: AuthProfile,
    R: ScopeResolver<Scope = P::Scope>,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        // Snapshot what authentication needs, then drop every borrow of the
        // actix request before awaiting anything.
        let auth_request = AuthRequest::from(&request);
        let gateway = self.gateway.clone();
        let service = self.service.clone();
        let hook = self.extensions.clone();

        Box::pin(async move {
            match gateway.authenticate(&auth_request).await {
                Ok(Some(user)) => {
                    {
                        let mut extensions = request.extensions_mut();
                        if let Some(hook) = &hook {
                            hook(&user, &mut extensions);
                        }
                        extensions.insert::<P::User>(user);
                    }
                    service.call(request).await.map(|r| r.map_into_left_body())
                }
                // A public scope with no identity: the handler runs, and no
                // principal is inserted. Extractors for `P::User` fail, which is
                // the correct signal — unlike the original, which inserted a
                // default-constructed user indistinguishable from a real one.
                Ok(None) => service.call(request).await.map(|r| r.map_into_left_body()),
                Err(error) => Ok(request
                    .into_response(error_to_response(&error).map_into_right_body())),
            }
        })
    }
}
