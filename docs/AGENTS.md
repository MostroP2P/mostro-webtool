# Repository Guidelines

## Project Structure & Module Organization
- Root `Cargo.toml` defines the `mostro-message` crate (Rust 2024 edition) and workspace metadata.
- Application entry point lives in `src/main.rs`; add new modules under `src/` using `mod` declarations in `main.rs` or a `lib.rs` if you split logic.
- Build artifacts land in `target/`; treat this directory as disposable and do not commit it.

## Build, Test, and Development Commands
- `cargo run` — compile and execute the binary for quick local checks.
- `cargo build --release` — produce an optimized binary before benchmarking or shipping.
- `cargo check` — fast validation that the crate compiles without building artifacts; use it for pre-commit sanity.
- `cargo fmt` / `cargo fmt --check` — apply or verify rustfmt formatting across the crate.

## Coding Style & Naming Conventions
- Follow Rust defaults: 4-space indentation, `snake_case` for files/functions, `CamelCase` for types, and `SCREAMING_SNAKE_CASE` for constants.
- Run `cargo fmt` before pushing; rustfmt is the canonical formatter for this repo.
- Prefer module files such as `src/messages/mod.rs` when logic grows; keep public APIs minimal and document them with `///` comments when exposed.

## Testing Guidelines
- Place unit tests inside the relevant module with `#[cfg(test)]` blocks; integration tests should live under `tests/` (create the directory as needed).
- Execute `cargo test` locally; aim for meaningful coverage on new modules and ensure tests run cleanly before submitting PRs.
- When adding async or network-dependent tests, gate them with feature flags so `cargo test` remains fast by default.

## Commit & Pull Request Guidelines
- The repository history is empty; adopt short, imperative commit subjects (e.g., `Add message parser`) with optional body explaining rationale.
- Reference relevant issue IDs in commit bodies or PR descriptions when applicable.
- Pull requests should describe scope, testing performed (`cargo test`, `cargo fmt --check`), and include screenshots or logs if behavior changes.
- Keep PRs focused; factor out refactors or formatting-only changes into separate commits for easier review.
