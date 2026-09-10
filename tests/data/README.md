# Test fixtures

`test_signing_key.pem` is a **throwaway RSA key generated for the test suite**.
It exists only so `tests/support/mock_idp.rs` can sign ID tokens for the
in-process mock OpenID Provider, giving the OIDC tests real signature
verification rather than a mocked client.

It signs nothing outside `cargo test`, corresponds to no deployment, and grants
access to nothing. Secret-scanning hits on this file are false positives.
