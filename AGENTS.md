# Repository Guidelines

## Project Structure & Module Organization
- `src/main.rs` boots the Axum HTTP server on `DEFAULT_PORT`.
- `src/lib.rs` hosts the router, mnemonic/key derivation helpers, and identity page rendering.
- `static/` serves bundled HTML, CSS, and media assets.
- `docs/` contains protocol references; expand there when contributor notes need more depth.
- `tests/` holds async integration tests that exercise public endpoints.
- `target/` is Cargo output; never commit its contents.

## Build, Test, and Development Commands
- `cargo check` performs fast type-checking before heavier builds.
- `cargo fmt` formats sources; run `cargo fmt -- --check` in CI locally.
- `cargo clippy -- -D warnings` enforces lint cleanliness.
- `cargo test` runs the Tokio-based integration suite.
- `cargo run` launches the local server on `http://127.0.0.1:3000`; use `RUST_LOG=mostro_webtool=debug` for verbose traces.

## Coding Style & Naming Conventions
- Follow Rust 2024 defaults: 4-space indentation and `rustfmt` output as canonical style.
- Modules and files stay `snake_case`; types and enums use `CamelCase`; constants match `SCREAMING_SNAKE_CASE` like `TRADE_MIN_INDEX`.
- Group new HTTP routes and helpers in dedicated modules under `src/` once they grow beyond `lib.rs`.
- Use structured logging via `tracing::info!` and `tracing::error!`, avoiding ad-hoc `println!`.

## Testing Guidelines
- Place full-stack tests in `tests/` (example: `tests/trade_key_api.rs`).
- Name cases after behavior (`trade_key_endpoint_returns_expected_payload`).
- Use `tokio::test` for async scenarios and `serde_json` to assert payloads.
- Cover both happy-path and error responses for every new endpoint or service function.

## Commit & Pull Request Guidelines
- Write imperative, message-case subjects (`Add Mostrod pubkey field`).
- Keep commits scoped; add body details when touching multiple modules or configs.
- PRs should describe context, solution, and validation (`cargo test`, manual `curl`, screenshots).
- Link related issues and list any follow-up tasks or deferred work.

## Security & Secrets
- Never commit live mnemonics or keys; rely on generated samples like `SAMPLE_MNEMONIC`.
- Scrub logs before sharing traces; sensitive errors should reuse `AppError` patterns already present.
