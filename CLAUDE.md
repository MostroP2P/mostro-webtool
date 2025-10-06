# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mostro-webtool** is a web-based key derivation and Mostro message builder tool. It generates BIP39 mnemonics, derives identity and trade keys following the Mostro protocol's derivation scheme, and provides an interactive UI for constructing Mostro protocol messages (orders, disputes, etc.).

The application is built with:
- **Axum** web framework (async HTTP server)
- **nostr-sdk** for BIP39 mnemonic generation and NIP-06 key derivation
- **mostro-core** for Mostro protocol definitions
- Single-page application with embedded HTML/CSS/JavaScript

## Key Architecture Concepts

### Key Derivation Scheme

The tool implements the Mostro protocol's specific BIP44 derivation path:
- **Base path**: `m/44'/1237'/38383'/0`
- **Identity key**: Index 0 (`m/44'/1237'/38383'/0/0`)
- **Trade keys**: Index ≥ 1 (`m/44'/1237'/38383'/0/n` where n ≥ 1)

Constants in `src/lib.rs`:
- `MOSTRO_ACCOUNT_INDEX = 38383`
- `BRANCH_INDEX = 0`
- `IDENTITY_KEY_INDEX = 0`
- `TRADE_MIN_INDEX = 1`

### Application Structure

- `src/main.rs`: Entry point that initializes tracing and starts the Axum server on port 3000
- `src/lib.rs`: Contains all business logic:
  - HTTP router setup (`app()` function)
  - Key derivation logic (`derive_keys_for_index`)
  - HTML rendering functions (`render_identity_page`, `render_error_page`)
  - API handlers (`index`, `derive_trade_key`)
  - Mostro protocol constants (actions, message types, order kinds, statuses)
- `static/`: Static assets (logo image)
- `tests/trade_key_api.rs`: Integration tests for the API endpoints

### Routes

- `GET /`: Serves the main interactive page with generated mnemonic and keys
- `POST /api/trade-key`: Derives a trade key for a given mnemonic and index
- `/static/*`: Serves static files

## Development Commands

### Build and Check
```bash
cargo check              # Fast type-checking
cargo build              # Compile the project
cargo clippy             # Run linter
cargo fmt                # Format code
cargo fmt -- --check     # Check formatting without modifying files
```

### Running the Application
```bash
cargo run                                    # Start server on http://127.0.0.1:3000
RUST_LOG=mostro_webtool=debug cargo run     # Run with debug logging
```

### Testing
```bash
cargo test                   # Run all tests
cargo test -- --nocapture    # Run tests with output visible
```

### Single Test Execution
```bash
cargo test trade_key_endpoint_returns_expected_payload
cargo test static_logo_is_served
```

## Code Style

- Uses **Rust 2024 edition**
- Follow `rustfmt` defaults (4-space indentation)
- Constants: `SCREAMING_SNAKE_CASE`
- Functions/variables: `snake_case`
- Types/structs: `CamelCase`
- Use structured logging via `tracing::info!` and `tracing::error!`
- Avoid `println!` in favor of tracing macros

## Important Notes

### Security Considerations
- The mnemonic is generated client-side on page load (server-side in the HTML template)
- Private keys are never logged or persisted
- The tool is designed for local/educational use - remind users to keep mnemonics secure
- Test constants like `SAMPLE_MNEMONIC` in `tests/` should never be used for real funds

### Message Builder
The embedded JavaScript in `render_identity_page()` builds Mostro protocol messages with:
- Wrapper fields: `version`, `action`, `id`, `request_id`, `trade_index`
- Payload variants: `order`, `dispute`, `cant-do`, `rate`, `dm`, `restore`
- Actions are defined in the `ACTIONS` constant (40+ action types)
- Order statuses and kinds are defined in `ORDER_STATUSES` and `ORDER_KINDS`

### Adding New Routes
When adding HTTP endpoints:
1. Add handler function in `src/lib.rs`
2. Update the `app()` function to include the new route
3. Add integration tests in `tests/` following the pattern in `trade_key_api.rs`
4. Use `Json<T>` for request/response bodies with derived `Serialize`/`Deserialize`

### Error Handling
- Custom error types: `IdentityError` (mnemonic/derivation errors), `AppError` (general application errors)
- API errors return `(StatusCode, Json<ErrorResponse>)` tuples
- HTML errors use `AppError` which implements `IntoResponse` to render error pages
