# authn_kit

Framework- and protocol-agnostic authentication for Rust web services.

Works with actix-web and axum from the same code, because nothing in the core
knows about either.

## The four things you decide

| Decision | What you write |
|---|---|
| What is a principal? | `impl TryFrom<IdentityClaims> for YourUser` |
| What is a scope? | `impl AuthScope` + `impl ScopeResolver` |
| Which mechanisms, in what order? | `AuthnBuilder::new(scopes).with(..)` |
| How are failures rendered? | nothing — the adapter does it |

## Defining a principal

There is no trait of ours to implement. Write the conversion you would write
anyway:

```rust
impl TryFrom<IdentityClaims> for User {
    type Error = String;

    fn try_from(claims: IdentityClaims) -> Result<Self, Self::Error> {
        Ok(Self {
            email: claims.email.clone().ok_or("email claim not found")?,
            username: claims.best_effort_username().ok_or("no identity")?.to_string(),
        })
    }
}
```

One conversion serves every mechanism. `IdentityClaims::source` says where the
claims came from — an ID token, introspection, a static token, a machine grant —
so you can branch when a machine principal needs different treatment from a
human one.

## Wiring it up

```rust
let gateway = AuthnBuilder::<MyService, _>::new(Scopes)
    .with(api_token_authenticator)                     // Bearer <prefix>...
    .with(BearerAuthenticator::new(provider.clone()))  // Bearer <jwt>
    .with(SessionAuthenticator::new(provider)          // session cookie
        .with_login_redirect(login))
    .build()?;

App::new().wrap(ActixAuthn::new(gateway))
```

A complete, compiling version is in
[`examples/actix_service.rs`](examples/actix_service.rs).

## How the chain resolves a request

Authenticators are consulted in registration order. Each returns
`Verdict::Authenticated` or `Verdict::NotApplicable`, or fails.

- The **first to authenticate** decides the request; nothing after it runs.
- A **failure is terminal** — the chain fails closed, so a rejected `Bearer`
  token can never fall through to a weaker mechanism.
- If **nothing claims** the request, the caller gets a challenge (`401`, or a
  redirect into login).

Order is mostly *not* load-bearing, because each mechanism declines what is not
its own: the API-token authenticator requires its prefix, and the bearer
authenticator requires a compact JWS. The exception is a session authenticator
configured to redirect — it is the only one that turns an *absent* credential
into a response, so **register it last**.

An authenticator cannot declare a request anonymous. That is a judgement about
the scope, and belongs to the chain alone — which is what stops one mechanism
waving requests past a protected route.

## Features

| Feature | Brings in |
|---|---|
| `actix` | the actix-web adapter |
| `axum` | the axum adapter |
| `oidc` | OpenID Connect: discovery, login flow, session and bearer authenticators |
| `introspection` | RFC 7662 token introspection |
| `env` | `EnvConfig`, for reading configuration from the environment |
| `full` | every mechanism (`oidc`, `introspection`, `env`) — no adapter |

Nothing is on by default: pick your framework, and pay only for the mechanisms
you use. Static API tokens and the disabled authenticator need no feature at all
— a service using only shared-secret tokens never compiles the OIDC tree.

Choose mechanisms at compile time and the *provider* at runtime: the chain holds
`Arc<dyn Authenticator<P>>`, so `full` plus a `match` on your configuration is
the normal shape.

## Configuration

Every type is built from explicit values, which is what makes them testable
without a populated environment. `EnvConfig` is an optional convenience on top:

```rust
let env = EnvConfig::with_prefix("AUTHN_")?;          // prefix is mandatory
let config = env.oidc_config()?                       // reads AUTHN_OIDC_*
    .with_client_secret(secret_from_kms);             // secrets stay out of env
```

The prefix cannot be empty: the suffixes are generic (`OIDC_CLIENT_ID`,
`SESSION_COOKIE_NAME`) and would otherwise collide with the host application's
own variables.

## Migrating an existing service

Replacing a hand-rolled authentication layer is mostly a matter of finding the
places where behaviour is *implied* rather than stated, because those are what
change silently:

- **Session cookie names.** They are derived from `AuthScope`'s `Display`. If the
  names differ from what the previous implementation used, every browser presents
  a cookie nothing reads, and every logged-in user is signed out on deploy.
- **Principal strings.** Whatever your authorization layer keys off — an email, a
  username, a `service-account-<id>` convention — has to come out of your
  `TryFrom<IdentityClaims>` byte for byte, or existing policy rules stop matching.
- **Machine grants carry no human identity.** `client_credentials` yields a
  `client_id` and nothing else, so branch on `IdentityClaims::source` rather than
  demanding an email everywhere.
- **Routes excluded from authentication.** This crate yields
  `Outcome::Anonymous` and inserts no principal, where a previous implementation
  may have supplied a default user. If handlers on those routes extract a user
  type, give them one explicitly with an authenticator that claims that scope.

## Security posture

- **PKCE** on by default (RFC 7636); OAuth 2.1 requires it of confidential
  clients too.
- The **post-login destination never leaves the server** — it lives in the
  `HttpOnly` protection cookie, not the `state` parameter, so the redirect target
  cannot be influenced by whoever crafts the callback. `RedirectPolicy` validates
  it besides.
- **Cookies are `HttpOnly`**, with `Secure` and `SameSite` configurable.
  `SameSite=Lax`, not `Strict`: the provider returns the user by a cross-site
  top-level navigation, and `Strict` withholds cookies on exactly that.
- **Constant-time** comparison for static tokens, **BLAKE3** digests for cache
  keys, and the scope is part of every cache key by construction, so a credential
  validated for one tenant cannot be served from cache for another.
- **JWKS rotation self-heals**: verification refreshes provider metadata and
  retries once, but only for failures fresh keys could actually change.
- Failures separate a **client-facing message** from an **operator-facing
  detail**; only the former reaches the client.
