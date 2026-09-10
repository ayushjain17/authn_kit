# Feature combinations that must all build and test cleanly. Framework adapters
# are mutually exclusive in practice, so each is checked separately.
ADAPTERS := actix axum
MECHANISMS := oidc introspection env full

.PHONY: default check fmt lint test test-matrix build-matrix example clean

default: check test

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --features actix,axum,full -- -D warnings

check: fmt lint

test:
	cargo test --features actix,full

# Every feature combination compiles on its own. Catches a `cfg` that only works
# when some other feature happens to be enabled.
build-matrix:
	cargo build --no-default-features
	@for f in $(ADAPTERS) $(MECHANISMS); do \
		echo "==> building --features $$f"; \
		cargo build --no-default-features --features $$f || exit 1; \
	done
	cargo build --features actix,full
	cargo build --features axum,full

test-matrix: build-matrix
	cargo test --features actix,full
	cargo test --features axum,full

example:
	cargo build --example actix_service --features actix,full

clean:
	cargo clean
