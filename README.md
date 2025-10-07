# Mostro Web Tool 🧌

![Mostro-webtool-logo](static/mostro-web-tool-logo.png)

A web-based tool for generating deterministic keys and building Mostro protocol messages with NIP-59 gift wrap encryption.

## Overview

**Mostro Web Tool** is a development and testing utility for the Mostro P2P exchange protocol. It provides:

- **BIP39 Mnemonic Generation**: Creates deterministic seed phrases for reproducible key derivation
- **Hierarchical Key Derivation**: Implements Mostro's BIP44 derivation scheme (`m/44'/1237'/38383'/0`)
- **Message Builder**: Interactive UI for constructing Mostro protocol messages (orders, disputes, ratings, etc.)
- **NIP-59 Gift Wrap**: Automatically encrypts and wraps messages following the Nostr NIP-59 specification
- **API Endpoints**: REST API for key derivation and message signing

This tool is intended for **development, testing, and educational purposes**. For production use, integrate these features directly into your Mostro client application.

## Features

### 🔑 Key Management

- **Identity Key** (index 0): Used for reputation tracking and seal signing
- **Trade Keys** (index ≥ 1): One-time-use keys that rotate per trade for privacy
- Follows Mostro's key derivation standard: `m/44'/1237'/38383'/0/{index}`
- Compatible with any BIP39-compliant wallet that supports custom derivation paths

### 📝 Message Builder

- Interactive form for all Mostro actions (40+ action types)
- Support for orders, disputes, ratings, direct messages, and session restoration
- Real-time message preview with JSON formatting
- Automatic signature generation using trade keys
- Validates message structure against `mostro-core` types

### 🎁 NIP-59 Gift Wrap

- Implements standard NIP-59 encryption
- Three-layer security:
  1. **Rumor**: Signed with trade key, contains `(message, signature)` tuple
  2. **Seal**: Encrypted and signed with identity key
  3. **Gift Wrap**: Encrypted and signed with ephemeral key for metadata privacy
- Compatible with Mostro daemon (mostrod) and other NIP-59 implementations

## Prerequisites

- **Rust**: 1.90.0 or later
- **Cargo**: 1.90.0 or later

## Installation

```bash
# Clone the repository
git clone https://github.com/MostroP2P/mostro-webtool.git
cd mostro-webtool

# Build the project
cargo build --release

# Run the server
cargo run --release
```

The server will start on `http://127.0.0.1:3000`

## Usage

### Web Interface

1. Open `http://127.0.0.1:3000` in your browser
2. The tool will generate a new mnemonic automatically (or enter your own)
3. View your identity key (index 0) and current trade key
4. Build messages using the interactive form:
   - Select message type (Order, Dispute, Rate, etc.)
   - Choose an action (e.g., `new-order`, `take-sell`)
   - Fill in required fields
   - Add optional payload (order details, dispute info, etc.)
5. Click "Send to Mostro" to create a signed gift wrap event
6. The tool will publish to your configured Nostr relay

### Key Rotation

- Use the **+** / **-** buttons to navigate between trade key indices
- Each trade should use a new index for privacy
- The web interface tracks your current trade index automatically

### API Usage

#### Derive Trade Key

```bash
POST /api/trade-key
Content-Type: application/json

{
  "mnemonic": "your twelve word mnemonic",
  "index": 2
}
```

Response:
```json
{
  "index": 2,
  "derivation_path": "m/44'/1237'/38383'/0/2",
  "public_key": "02a1b2c3...",
  "private_key": "a1a2b3c4..."
}
```

#### Build Gift Wrap

```bash
POST /api/build-gift-wrap
Content-Type: application/json

{
  "mnemonic": "your mnemonic phrase",
  "trade_index": 1,
  "mostro_pubkey": "npub1...",
  "message_json": "{\"order\":{\"version\":1,\"action\":\"new-order\",...}}"
}
```

Response:
```json
{
  "gift_wrap_event": {
    "id": "event_id",
    "kind": 1059,
    "pubkey": "ephemeral_key",
    "content": "encrypted_content",
    ...
  }
}
```

## Architecture

```
mostro-webtool/
├── src/
│   ├── main.rs           # Entry point, server initialization
│   └── lib.rs            # Core logic, routes, key derivation, gift wrap
├── tests/
│   ├── trade_key_api.rs  # API endpoint tests
│   └── gift_wrap_test.rs # NIP-59 encryption tests
├── static/               # Static assets (logo, etc.)
├── docs/                 # Protocol documentation
│   └── protocol/         # Mostro protocol specs
└── Cargo.toml           # Dependencies and metadata
```

### Key Components

- **Axum**: Async web framework for HTTP server
- **nostr-sdk**: BIP39 mnemonic generation, NIP-06 key derivation, NIP-59 gift wrap
- **mostro-core**: Mostro protocol types and message validation
- **bip39**: Mnemonic phrase generation and validation

## Development

### Build and Check

```bash
# Type-check only (fast)
cargo check

# Full compilation
cargo build

# Release build (optimized)
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test gift_wrap_test

# Run with output
cargo test -- --nocapture
```

### Code Quality

```bash
# Run linter
cargo clippy

# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Running with Logs

```bash
# Enable debug logging
RUST_LOG=mostro_webtool=debug cargo run

# Enable trace logging (very verbose)
RUST_LOG=mostro_webtool=trace cargo run
```

## Key Derivation Scheme

Mostro uses a specific BIP44 derivation path for key management:

```
m/44'/1237'/38383'/0/{index}
│    │      │       │   │
│    │      │       │   └─ Key index
│    │      │       └───── Branch (always 0)
│    │      └───────────── Mostro account index
│    └──────────────────── Nostr Coin type (1237)
└───────────────────────── Purpose (BIP44)
```

### Key Types

- **Identity Key** (index 0): `m/44'/1237'/38383'/0/0`
  - Signs the seal in gift wrap events
  - Links trades to your reputation
  - Persistent across all trades

- **Trade Keys** (index ≥ 1): `m/44'/1237'/38383'/0/1`, `m/44'/1237'/38383'/0/2`, ...
  - Sign individual messages
  - Rotate for each trade
  - Provide forward secrecy

### Privacy Modes

**Standard Mode**: Use identity key (index 0) for seal signing to build reputation

**Full Privacy Mode**: Use trade key for seal signing (no reputation tracking)

## Protocol Documentation

Detailed protocol specifications are available in the [`docs/protocol/`](docs/protocol/) directory.

## Security Considerations

⚠️ **Important Security Notes**:

- This tool is for **development and testing** only
- Never use production funds with test mnemonics
- Store mnemonics securely (use a password manager)
- The web interface generates mnemonics **in the browser** - for production, use a hardware wallet
- Private keys are **never logged** or persisted by the server
- Gift wrap events use ephemeral keys for metadata privacy

## Testing

The project includes comprehensive test coverage:

### Test Suites

```bash
# Run all tests
cargo test

# Gift wrap encryption tests
cargo test --test gift_wrap_test

# API endpoint tests
cargo test --test trade_key_api
```

### Test Coverage

- ✅ Key derivation with BIP39 mnemonics
- ✅ Trade key rotation (indices 1-10)
- ✅ NIP-59 gift wrap creation
- ✅ Rumor extraction and signature verification
- ✅ Seal signing with identity key
- ✅ Message serialization and deserialization
- ✅ trade_index injection and validation

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Resources

- [Mostro Protocol](https://mostro.network/protocol)
- [NIP-59 Specification](https://github.com/nostr-protocol/nips/blob/master/59.md)
- [NIP-06 Specification](https://github.com/nostr-protocol/nips/blob/master/06.md)
- [BIP39 Standard](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP44 Standard](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)

## Support

For questions, issues, or feature requests:

- Open an issue on GitHub
- Join the Mostro community discussions
- Check the [docs/](docs/) directory for detailed documentation
