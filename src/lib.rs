use std::fmt;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bip39::{Language, Mnemonic};
use mostro_core::message::Message as MostroMessage;
use nostr_sdk::prelude::{
    Event, EventBuilder, FromMnemonic, JsonUtil, Keys, PublicKey, Tags, nip06, nip59,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tower_http::services::ServeDir;
use tracing_subscriber::{EnvFilter, fmt::SubscriberBuilder};

const MAIN_COLOR: &str = "#8dc63f";
const MAIN_COLOR_DARK: &str = "#4a7f1f";
const MOSTRO_BASE_PATH: &str = "m/44'/1237'/38383'/0";
const IDENTITY_PATH: &str = "m/44'/1237'/38383'/0/0";
const MOSTRO_ACCOUNT_INDEX: u32 = 38_383;
const BRANCH_INDEX: u32 = 0;
const IDENTITY_KEY_INDEX: u32 = 0;
const TRADE_MIN_INDEX: u32 = 1;
const DEFAULT_TRADE_INDEX: u32 = TRADE_MIN_INDEX;

const ACTIONS: &[&str] = &[
    "new-order",
    "take-sell",
    "take-buy",
    "pay-invoice",
    "fiat-sent",
    "fiat-sent-ok",
    "release",
    "released",
    "cancel",
    "canceled",
    "cooperative-cancel-initiated-by-you",
    "cooperative-cancel-initiated-by-peer",
    "dispute-initiated-by-you",
    "dispute-initiated-by-peer",
    "cooperative-cancel-accepted",
    "buyer-invoice-accepted",
    "purchase-completed",
    "hold-invoice-payment-accepted",
    "hold-invoice-payment-settled",
    "hold-invoice-payment-canceled",
    "waiting-seller-to-pay",
    "waiting-buyer-invoice",
    "add-invoice",
    "buyer-took-order",
    "rate",
    "rate-user",
    "rate-received",
    "cant-do",
    "dispute",
    "admin-cancel",
    "admin-canceled",
    "admin-settle",
    "admin-settled",
    "admin-add-solver",
    "admin-take-dispute",
    "admin-took-dispute",
    "payment-failed",
    "invoice-updated",
    "send-dm",
    "trade-pubkey",
    "restore-session",
    "last-trade-index",
    "orders",
];

const MESSAGE_TYPES: &[&str] = &["order", "dispute", "cant-do", "rate", "dm", "restore"];
const ORDER_KINDS: &[&str] = &["buy", "sell"];
const ORDER_STATUSES: &[&str] = &[
    "active",
    "canceled",
    "canceled-by-admin",
    "settled-by-admin",
    "completed-by-admin",
    "dispute",
    "expired",
    "fiat-sent",
    "settled-hold-invoice",
    "pending",
    "success",
    "waiting-buyer-invoice",
    "waiting-payment",
    "cooperatively-canceled",
];

pub const DEFAULT_PORT: u16 = 3000;

pub fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "mostro_webtool=info,axum::rejection=trace".into());
    SubscriberBuilder::default()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .init();
}

pub fn app() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/trade-key", post(derive_trade_key))
        .route("/api/build-gift-wrap", post(build_gift_wrap))
        .route("/api/decrypt-gift-wrap", post(decrypt_gift_wrap))
        .nest_service("/static", ServeDir::new("static"))
}

async fn index() -> Result<Html<String>, AppError> {
    let ctx = IdentityContext::new()?;
    Ok(Html(render_identity_page(&ctx)))
}

#[derive(Deserialize)]
struct TradeKeyRequest {
    mnemonic: String,
    index: u32,
}

#[derive(Serialize)]
struct TradeKeyResponse {
    index: u32,
    derivation_path: String,
    public_key: String,
    private_key: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn derive_trade_key(
    Json(payload): Json<TradeKeyRequest>,
) -> Result<Json<TradeKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Derive key for any index: 0 = identity key, >= 1 = trade keys
    let keys = derive_keys_for_index(payload.mnemonic.as_str(), payload.index)
        .map_err(identity_error_to_response)?;

    let response = TradeKeyResponse {
        index: payload.index,
        derivation_path: trade_derivation_path(payload.index),
        public_key: keys.public_key().to_hex(),
        private_key: keys.secret_key().to_secret_hex(),
    };

    Ok(Json(response))
}

#[derive(Deserialize, Debug)]
struct GiftWrapRequest {
    mnemonic: String,
    trade_index: u32,
    mostro_pubkey: String,
    message_json: String,
}

#[derive(Serialize)]
struct GiftWrapResponse {
    gift_wrap_event: JsonValue,
}

#[derive(Deserialize, Debug)]
struct DecryptGiftWrapRequest {
    mnemonic: String,
    trade_index: u32,
    gift_wrap_events: Vec<JsonValue>,
}

#[derive(Serialize)]
struct DecryptGiftWrapResponse {
    rumor_content: JsonValue,
    timestamp: u64,
    events_count: usize,
}

async fn build_gift_wrap(
    Json(payload): Json<GiftWrapRequest>,
) -> Result<Json<GiftWrapResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Parse mostro pubkey
    let mostro_pubkey = PublicKey::from_hex(&payload.mostro_pubkey).map_err(|e| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("Invalid Mostro pubkey: {}", e),
        )
    })?;

    // Derive identity key (index 0) for seal signing
    let identity_keys = derive_keys_for_index(&payload.mnemonic, IDENTITY_KEY_INDEX)
        .map_err(identity_error_to_response)?;

    // Derive trade key for content signature
    let trade_keys = derive_keys_for_index(&payload.mnemonic, payload.trade_index)
        .map_err(identity_error_to_response)?;

    // Log the incoming message JSON for debugging
    tracing::info!("Payload message: {}", payload.message_json);
    // Parse message JSON into MostroMessage
    // Use serde directly to get detailed error messages
    let mut message: MostroMessage = serde_json::from_str(&payload.message_json).map_err(|e| {
        tracing::error!("Failed to parse Mostro message: {} | JSON: {}", e, payload.message_json);
        json_error(
            StatusCode::BAD_REQUEST,
            format!("Invalid Mostro message: {}", e),
        )
    })?;

    // Ensure trade_index is set correctly from API payload
    // The trade_index tells mostrod which trade key to expect for signature verification
    match &mut message {
        MostroMessage::Order(ref mut kind)
        | MostroMessage::Dispute(ref mut kind)
        | MostroMessage::CantDo(ref mut kind)
        | MostroMessage::Rate(ref mut kind)
        | MostroMessage::Dm(ref mut kind)
        | MostroMessage::Restore(ref mut kind) => {
            kind.trade_index = Some(payload.trade_index as i64);
        }
    }

    // Build gift wrap using helper function
    let gift_wrap = create_gift_wrap(
        &identity_keys,
        &trade_keys,
        &mostro_pubkey,
        &message,
    )
    .await
    .map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create gift wrap: {}", e),
        )
    })?;

    // Serialize to JSON
    let event_json: JsonValue = serde_json::from_str(&gift_wrap.as_json()).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize gift wrap: {}", e),
        )
    })?;

    Ok(Json(GiftWrapResponse {
        gift_wrap_event: event_json,
    }))
}

async fn decrypt_gift_wrap(
    Json(payload): Json<DecryptGiftWrapRequest>,
) -> Result<Json<DecryptGiftWrapResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if we have any events
    if payload.gift_wrap_events.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "No gift wrap events provided",
        ));
    }

    // Derive trade key for decryption
    let trade_keys = derive_keys_for_index(&payload.mnemonic, payload.trade_index)
        .map_err(identity_error_to_response)?;

    // Store all decrypted messages with their timestamps
    let mut decrypted_messages: Vec<(JsonValue, u64)> = Vec::new();

    // Decrypt each gift wrap event
    for (index, gift_wrap_json_value) in payload.gift_wrap_events.iter().enumerate() {
        // Parse the gift wrap event from JSON
        let gift_wrap_json = serde_json::to_string(gift_wrap_json_value).map_err(|e| {
            json_error(
                StatusCode::BAD_REQUEST,
                format!("Invalid gift wrap event at index {}: {}", index, e),
            )
        })?;

        let gift_wrap_event = Event::from_json(&gift_wrap_json).map_err(|e| {
            json_error(
                StatusCode::BAD_REQUEST,
                format!("Failed to parse gift wrap event at index {}: {}", index, e),
            )
        })?;

        // Unwrap the gift wrap to get the rumor
        let unwrapped = match nip59::UnwrappedGift::from_gift_wrap(&trade_keys, &gift_wrap_event).await {
            Ok(u) => u,
            Err(e) => {
                // Log the error but continue with other events
                tracing::warn!("Failed to decrypt gift wrap event at index {}: {}", index, e);
                continue;
            }
        };

        // Extract the rumor content and timestamp
        let rumor = unwrapped.rumor;
        let timestamp = rumor.created_at.as_u64();
        let content_str = rumor.content;

        // Parse the content as JSON - it should be a tuple (message, signature)
        // Note: Mostro responses may have null signatures, so we use Option<String>
        let content_tuple: (JsonValue, Option<String>) = serde_json::from_str(&content_str).map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse rumor content at index {}: {}", index, e),
            )
        })?;

        // Store the message and its timestamp
        decrypted_messages.push((content_tuple.0, timestamp));
    }

    // Check if we successfully decrypted any messages
    if decrypted_messages.is_empty() {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to decrypt any gift wrap events",
        ));
    }

    // Sort by timestamp (descending - newest first)
    decrypted_messages.sort_by(|a, b| b.1.cmp(&a.1));

    // Return the most recent message
    let (latest_message, latest_timestamp) = decrypted_messages.into_iter().next().unwrap();

    Ok(Json(DecryptGiftWrapResponse {
        rumor_content: latest_message,
        timestamp: latest_timestamp,
        events_count: payload.gift_wrap_events.len(),
    }))
}

#[derive(Debug)]
struct IdentityContext {
    mnemonic_phrase: String,
    identity_key_hex: String,
    identity_secret_hex: String,
    trade_index: u32,
    trade_key_hex: String,
    trade_secret_hex: String,
}

impl IdentityContext {
    fn new() -> Result<Self, IdentityError> {
        let mnemonic =
            Mnemonic::generate_in(Language::English, 12).map_err(IdentityError::Mnemonic)?;
        let phrase = mnemonic.to_string();

        let identity_keys = derive_keys_for_index(phrase.as_str(), IDENTITY_KEY_INDEX)?;
        let trade_keys = derive_keys_for_index(phrase.as_str(), DEFAULT_TRADE_INDEX)?;

        let identity_key_hex = identity_keys.public_key().to_hex();
        let identity_secret_hex = identity_keys.secret_key().to_secret_hex();
        let trade_key_hex = trade_keys.public_key().to_hex();
        let trade_secret_hex = trade_keys.secret_key().to_secret_hex();

        Ok(Self {
            mnemonic_phrase: phrase,
            identity_key_hex,
            identity_secret_hex,
            trade_index: DEFAULT_TRADE_INDEX,
            trade_key_hex,
            trade_secret_hex,
        })
    }

    fn trade_derivation_path(&self) -> String {
        trade_derivation_path(self.trade_index)
    }
}

#[derive(Debug)]
enum IdentityError {
    Mnemonic(bip39::Error),
    Derivation(nip06::Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(err) => write!(f, "failed to generate mnemonic seed: {err}"),
            Self::Derivation(err) => write!(f, "failed to derive identity key: {err}"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn derive_keys_for_index(mnemonic: &str, index: u32) -> Result<Keys, IdentityError> {
    let trimmed = mnemonic.trim();
    Keys::from_mnemonic_advanced(
        trimmed,
        None::<&str>,
        Some(MOSTRO_ACCOUNT_INDEX),
        Some(BRANCH_INDEX),
        Some(index),
    )
    .map_err(IdentityError::Derivation)
}

fn trade_derivation_path(index: u32) -> String {
    format!("{}/{index}", MOSTRO_BASE_PATH)
}

/// Creates a NIP-59 gift wrap event for Mostro protocol
///
/// This implements the Mostro-specific NIP-59 flow as documented in docs/protocol/key_management.md
///
/// The structure is:
/// 1. Rumor: Custom JSON with content = [message, signature]
/// 2. Seal: Encrypts rumor, signed with IDENTITY KEY (index 0)
/// 3. Gift Wrap: Encrypts seal, signed with EPHEMERAL KEY
///
/// Key Usage:
/// - Identity Key (index 0): Signs the seal - links to user reputation
/// - Trade Key (index N): Signs the message - proves ownership of trade key, rotates per trade
/// - Ephemeral Key (random): Signs gift wrap - provides metadata privacy
async fn create_gift_wrap(
    identity_keys: &Keys,
    trade_keys: &Keys,
    recipient_pubkey: &PublicKey,
    message: &MostroMessage,
) -> Result<Event, Box<dyn std::error::Error>> {
    // ========================================================================
    // STEP 1: Create the signature for the message
    // ========================================================================
    // Per docs/protocol/key_management.md line 46:
    // "index N signature of the sha256 hash of the serialized first element of content"
    //
    // We sign ONLY the message object with the trade key
    // This proves we control the trade key without revealing it in plaintext

    // Serialize the message to JSON string (compact, no whitespace)
    let message_str = message.as_json().map_err(|e| {
        format!("Failed to serialize message: {}", e)
    })?;

    // Sign the message using MostroMessage::sign() which handles the SHA256 hashing internally
    let signature = MostroMessage::sign(message_str.clone(), trade_keys);

    // ========================================================================
    // STEP 2: Create the rumor content as serialized (message, signature) tuple
    // ========================================================================
    // The rumor content must be a STRING containing the serialized tuple.
    // This allows standard NIP-59 tools to work with our custom format.
    //
    // The content will be: "[{message_object}, \"signature_hex\"]"
    // When deserialized, it becomes: (MostroMessage, Signature)

    let content = serde_json::to_string(&(message, signature))
        .map_err(|e| format!("Failed to serialize message and signature: {}", e))?;

    // ========================================================================
    // STEP 3: Build the rumor using EventBuilder
    // ========================================================================
    // Use EventBuilder::text_note() to create a proper UnsignedEvent
    // with kind=1 and content as a string

    let rumor = EventBuilder::text_note(content).build(trade_keys.public_key());

    // ========================================================================
    // STEP 4: Create the gift wrap using EventBuilder::gift_wrap()
    // ========================================================================
    // This handles:
    // - Creating the seal (kind 13) signed with identity_keys
    // - Encrypting the rumor into the seal
    // - Creating the gift wrap (kind 1059) with ephemeral keys
    // - Encrypting the seal into the gift wrap

    let gift_wrap = EventBuilder::gift_wrap(identity_keys, recipient_pubkey, rumor, Tags::default())
        .await
        .map_err(|e| format!("Failed to create gift wrap: {}", e))?;

    Ok(gift_wrap)
}

fn json_error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
}

fn identity_error_to_response(err: IdentityError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match &err {
        IdentityError::Mnemonic(_) => StatusCode::INTERNAL_SERVER_ERROR,
        IdentityError::Derivation(_) => StatusCode::BAD_REQUEST,
    };
    json_error(status, err.to_string())
}

#[derive(Debug)]
struct AppError {
    message: String,
}

impl From<IdentityError> for AppError {
    fn from(value: IdentityError) -> Self {
        Self {
            message: value.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let html = render_error_page(&self.message);
        (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
    }
}

fn render_identity_page(ctx: &IdentityContext) -> String {
    let actions_json = serde_json::to_string(&ACTIONS).unwrap();
    let message_types_json = serde_json::to_string(&MESSAGE_TYPES).unwrap();
    let order_kinds_json = serde_json::to_string(&ORDER_KINDS).unwrap();
    let order_statuses_json = serde_json::to_string(&ORDER_STATUSES).unwrap();
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mostro Message Builder</title>
<style>
:root {{
  --main-color: {main_color};
  --main-color-dark: {main_color_dark};
}}
* {{
  box-sizing: border-box;
}}
body {{
  margin: 0;
  min-height: 100vh;
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: linear-gradient(135deg, var(--main-color) 0%, var(--main-color-dark) 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  color: #fff;
}}
.container {{
  width: min(760px, 100%);
}}
.brand-logo {{
  display: flex;
  justify-content: center;
  align-items: center;
  margin-bottom: 1.5rem;
}}
.brand-logo img {{
  width: 40%;
  height: auto;
  display: block;
}}
form {{
  background: rgba(0, 0, 0, 0.9);
  border: 1px solid #7f7f7f;
  border-radius: 20px;
  padding: 2.5rem 2rem;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(10px);
}}
fieldset {{
  border: 1px solid #7f7f7f;
  border-radius: 16px;
  padding: 1.5rem;
  margin: 0;
}}
legend {{
  margin-left: 1rem;
  padding: 0 0.75rem;
  font-size: 1.1rem;
  font-weight: 700;
  color: #fff;
  letter-spacing: 0.05em;
}}
.label-input {{
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  margin-bottom: 1.5rem;
}}
.label-row {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}}
label {{
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.8rem;
  font-weight: 600;
  color: #f5f5f5;
}}
.key-state {{
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: rgba(141, 198, 63, 0.2);
  color: var(--main-color);
  border: 1px solid rgba(141, 198, 63, 0.45);
  border-radius: 999px;
  padding: 0.35rem 0.75rem;
}}
.key-row {{
  display: flex;
  align-items: stretch;
  gap: 0.75rem;
  flex-wrap: wrap;
}}
.key-input {{
  flex: 1 1 0;
  min-width: 240px;
  width: 100%;
}}
input[type="text"],
input[type="number"],
select {{
  background: rgba(33, 51, 13, 0.9);
  border: 1px solid rgba(255, 255, 255, 0.25);
  border-radius: 14px;
  padding: 0.95rem 1.1rem;
  font-size: 1rem;
  color: #fff;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
  outline: none;
}}
select {{
  cursor: pointer;
}}
.toggle-key, .copy-key, .trade-step {{
  background: rgba(255, 255, 255, 0.08);
  color: #fff;
  border: 1px solid rgba(255, 255, 255, 0.25);
  border-radius: 12px;
  padding: 0.75rem 1.2rem;
  font-size: 0.9rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  cursor: pointer;
  transition: background 0.2s ease, transform 0.2s ease, border-color 0.2s ease;
  flex: 0 0 auto;
}}
.toggle-key:hover, .copy-key:hover, .trade-step:hover {{
  background: rgba(141, 198, 63, 0.25);
  border-color: rgba(141, 198, 63, 0.6);
  transform: translateY(-1px);
}}
.toggle-key:active, .copy-key:active, .trade-step:active {{
  transform: translateY(0);
}}
.trade-controls {{
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}}
.trade-step {{
  min-width: 3rem;
  text-align: center;
}}
.trade-step[disabled] {{
  opacity: 0.45;
  cursor: not-allowed;
  transform: none;
  border-color: rgba(255, 255, 255, 0.2);
}}
.trade-index {{
  font-size: 0.85rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: rgba(255, 255, 255, 0.85);
}}
.message-builder {{
  margin-top: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 1.6rem;
}}
.message-columns {{
  display: grid;
  gap: 1.5rem;
}}
.message-columns.two {{
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
}}
.message-column {{
  display: flex;
  flex-direction: column;
}}
.payload-fields {{
  display: flex;
  flex-direction: column;
  gap: 1rem;
}}
.payload-note {{
  font-size: 0.85rem;
  color: rgba(255, 255, 255, 0.7);
}}
.payload-group {{
  display: grid;
  gap: 1rem;
}}
.payload-row {{
  display: grid;
  gap: 0.75rem;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
}}
.message-preview {{
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}}
.preview-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}}
.message-actions {{
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}}
.json-preview {{
  background: rgba(0, 0, 0, 0.45);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 14px;
  padding: 1.5rem;
  max-height: 360px;
  overflow: auto;
  font-size: 0.9rem;
  color: #d7f9b6;
  line-height: 1.5;
}}
.json-preview code {{
  white-space: pre;
  font-family: 'Fira Code', 'JetBrains Mono', 'SFMono-Regular', Menlo, monospace;
}}
.textarea-input {{
  width: 100%;
  min-height: 140px;
  resize: vertical;
  background: rgba(33, 51, 13, 0.9);
  border: 1px solid rgba(255, 255, 255, 0.25);
  border-radius: 14px;
  padding: 0.95rem 1.1rem;
  font-size: 0.95rem;
  color: #fff;
}}
input[type="text"]:focus,
input[type="number"]:focus,
select:focus,
.textarea-input:focus {{
  border-color: var(--main-color);
  box-shadow: 0 0 0 3px rgba(141, 198, 63, 0.35);
}}
.helper {{
  font-size: 0.9rem;
  color: rgba(255, 255, 255, 0.75);
  margin-top: 0.25rem;
}}
.helper.warning {{
  color: #ffb4b4;
}}
.path-display {{
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  margin: 0.85rem 0 1.4rem;
  padding: 0.5rem 1rem;
  border-radius: 999px;
  background: rgba(141, 198, 63, 0.2);
  color: #fff;
  font-size: 0.85rem;
  letter-spacing: 0.04em;
}}
code {{
  background: rgba(0, 0, 0, 0.4);
  padding: 0.2rem 0.45rem;
  border-radius: 6px;
  color: var(--main-color);
  font-size: 0.85rem;
}}
.send-section {{
  margin-top: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  align-items: center;
}}
.send-button {{
  background: var(--main-color);
  color: #000;
  border: 2px solid var(--main-color);
  border-radius: 14px;
  padding: 1rem 2.5rem;
  font-size: 1.05rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  cursor: pointer;
  transition: all 0.2s ease;
  text-transform: uppercase;
}}
.send-button:hover {{
  background: var(--main-color-dark);
  border-color: var(--main-color-dark);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(141, 198, 63, 0.4);
}}
.send-button:active {{
  transform: translateY(0);
}}
.send-button:disabled {{
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}}
.send-status {{
  padding: 0.75rem 1.5rem;
  border-radius: 12px;
  font-size: 0.9rem;
  letter-spacing: 0.04em;
  text-align: center;
  min-width: 300px;
}}
.send-status.info {{
  background: rgba(59, 130, 246, 0.2);
  border: 1px solid rgba(59, 130, 246, 0.5);
  color: #93c5fd;
}}
.send-status.success {{
  background: rgba(141, 198, 63, 0.2);
  border: 1px solid rgba(141, 198, 63, 0.5);
  color: var(--main-color);
}}
.send-status.error {{
  background: rgba(239, 68, 68, 0.2);
  border: 1px solid rgba(239, 68, 68, 0.5);
  color: #fca5a5;
}}
.response-status {{
  font-size: 0.85rem;
  padding: 0.4rem 0.9rem;
  border-radius: 999px;
  letter-spacing: 0.04em;
  font-weight: 600;
}}
.response-status.listening {{
  background: rgba(59, 130, 246, 0.2);
  border: 1px solid rgba(59, 130, 246, 0.5);
  color: #93c5fd;
}}
.response-status.received {{
  background: rgba(141, 198, 63, 0.2);
  border: 1px solid rgba(141, 198, 63, 0.5);
  color: var(--main-color);
}}
.response-status.timeout {{
  background: rgba(251, 191, 36, 0.2);
  border: 1px solid rgba(251, 191, 36, 0.5);
  color: #fcd34d;
}}
.response-status.error {{
  background: rgba(239, 68, 68, 0.2);
  border: 1px solid rgba(239, 68, 68, 0.5);
  color: #fca5a5;
}}
@media (max-width: 640px) {{
  body {{
    padding: 1.5rem;
  }}
  form {{
    padding: 1.75rem 1.5rem;
  }}
  legend {{
    font-size: 1rem;
  }}
  .key-row {{
    gap: 0.5rem;
  }}
  .trade-controls {{
    gap: 0.5rem;
  }}
}}
</style>
</head>
<body>
  <div class="container">
    <div class="brand-logo">
      <img src="/static/mostro-web-tool-logo.png" alt="Mostro Web Tool logo">
    </div>
    <form>
      <fieldset>
        <legend>Keys</legend>
        <div class="helper">Mostro derivation path in use:</div>
        <div class="path-display">{base_path}</div>
        <div class="label-input">
          <label for="mnemonic">Mnemonic Seed</label>
          <input id="mnemonic" type="text" value="{mnemonic}" spellcheck="false">
          <p class="helper">Random 12-word BIP39 seed generated when the page loads. You can edit or paste your own mnemonic.</p>
          <p class="helper warning" id="mnemonic-error" hidden></p>
        </div>
        <div class="label-input">
          <div class="label-row">
            <label for="identity">Identity Key</label>
            <span class="key-state" id="identity-state">Public</span>
          </div>
          <div class="key-row">
            <input class="key-input" id="identity" type="text" value="{identity}" readonly spellcheck="false" data-private="{identity_private}">
            <button class="toggle-key" id="toggle-identity" type="button">Show Private Key</button>
            <button class="copy-key" id="copy-identity" type="button">Copy</button>
          </div>
          <p class="helper">Derived from <code>{identity_path}</code>. Share only the public key, keep the seed private.</p>
        </div>
        <div class="label-input">
          <div class="label-row">
            <label for="trade-key">Trade Key</label>
            <span class="key-state" id="trade-state">Public</span>
          </div>
          <div class="helper">Trade derivation path:</div>
          <div class="path-display" id="trade-path">{trade_path}</div>
          <div class="trade-controls">
            <button class="trade-step" id="trade-decrement" type="button" aria-label="Previous trade key">-</button>
            <span class="trade-index" id="trade-index">Trade #{trade_index}</span>
            <button class="trade-step" id="trade-increment" type="button" aria-label="Next trade key">+</button>
          </div>
          <div class="key-row">
            <input class="key-input" id="trade-key" type="text" value="{trade_public}" readonly spellcheck="false" data-private="{trade_private}" data-index="{trade_index}" data-min-index="{trade_min_index}">
            <button class="toggle-key" id="toggle-trade" type="button">Show Private Key</button>
            <button class="copy-key" id="copy-trade" type="button">Copy</button>
          </div>
          <p class="helper">Adjust the index to explore trade keys without affecting identity key derivations.</p>
          <p class="helper warning" id="trade-error" hidden></p>
        </div>
        <div class="label-input">
          <label for="mostro-pubkey">Mostro Pubkey</label>
          <input id="mostro-pubkey" name="mostro-pubkey" type="text" placeholder="Enter Mostro pubkey" required spellcheck="false">
          <p class="helper">Provide the destination Mostro daemon public key to build messages correctly.</p>
        </div>
      </fieldset>
      <fieldset class="message-builder">
        <legend>Message</legend>
        <div class="helper">Compose a Mostro message wrapper and payload using the selections below.</div>
        <div class="message-columns two">
          <div class="message-column">
            <div class="label-input">
              <label for="message-type">Message Kind</label>
              <select id="message-type" data-wrapper-field="message-type"></select>
              <p class="helper">Choose the top-level wrapper (order, dispute, etc.).</p>
            </div>
            <div class="label-input">
              <label for="message-action">Action</label>
              <select id="message-action" data-wrapper-field="action"></select>
              <p class="helper" id="action-hint">Select an action to tailor payload fields.</p>
            </div>
            <div class="label-input">
              <label for="message-version">Version</label>
              <input id="message-version" data-wrapper-field="version" type="number" min="1" step="1" value="1">
            </div>
            <div class="label-input">
              <label for="message-id">Message ID</label>
              <input id="message-id" data-wrapper-field="id" type="text" placeholder="Optional UUID">
            </div>
            <div class="label-input">
              <label for="message-request-id">Request ID</label>
              <input id="message-request-id" data-wrapper-field="request_id" type="number" min="0" step="1" placeholder="Optional">
            </div>
            <div class="label-input">
              <label for="message-trade-index">Trade Index</label>
              <input id="message-trade-index" data-wrapper-field="trade_index" type="number" min="0" step="1" placeholder="Optional">
            </div>
            <div class="label-input">
              <label for="payload-mode">Payload Builder</label>
              <select id="payload-mode">
                <option value="none">No payload</option>
                <option value="order">Order payload</option>
                <option value="custom">Custom JSON</option>
              </select>
              <p class="helper" id="payload-hint">Choose how to build the payload for the selected action.</p>
            </div>
          </div>
          <div class="message-column">
            <div id="payload-fields" class="payload-fields">
              <p class="payload-note" id="payload-empty-note">Select an action to load payload fields or switch to custom JSON.</p>
              <div class="payload-group" id="payload-order" data-payload-section="order" hidden>
                <div class="payload-row">
                  <div class="label-input">
                    <label for="order-id">Order ID</label>
                    <input id="order-id" data-order-field="id" type="text" placeholder="Optional UUID">
                  </div>
                  <div class="label-input">
                    <label for="order-kind">Kind</label>
                    <select id="order-kind" data-order-field="kind"></select>
                  </div>
                  <div class="label-input">
                    <label for="order-status">Status</label>
                    <select id="order-status" data-order-field="status"></select>
                  </div>
                </div>
                <div class="payload-row">
                  <div class="label-input">
                    <label for="order-amount">Sats Amount</label>
                    <input id="order-amount" data-order-field="amount" type="number" step="1" min="0" value="0">
                  </div>
                  <div class="label-input">
                    <label for="order-fiat-code">Fiat Code</label>
                    <input id="order-fiat-code" data-order-field="fiat_code" type="text" value="USD">
                  </div>
                  <div class="label-input">
                    <label for="order-fiat-amount">Fiat Amount</label>
                    <input id="order-fiat-amount" data-order-field="fiat_amount" type="number" step="1" min="0" value="0">
                  </div>
                </div>
                <div class="payload-row">
                  <div class="label-input">
                    <label for="order-payment-method">Payment Method</label>
                    <input id="order-payment-method" data-order-field="payment_method" type="text" placeholder="e.g. bank transfer" required>
                  </div>
                  <div class="label-input">
                    <label for="order-premium">Premium</label>
                    <input id="order-premium" data-order-field="premium" type="number" step="1" value="0">
                  </div>
                  <div class="label-input">
                    <label for="order-created-at">Created At (timestamp)</label>
                    <input id="order-created-at" data-order-field="created_at" type="number" step="1" placeholder="Optional">
                  </div>
                </div>
                <div class="payload-row">
                  <div class="label-input">
                    <label for="order-min-amount">Min Amount</label>
                    <input id="order-min-amount" data-order-field="min_amount" type="number" step="1" placeholder="Optional">
                  </div>
                  <div class="label-input">
                    <label for="order-max-amount">Max Amount</label>
                    <input id="order-max-amount" data-order-field="max_amount" type="number" step="1" placeholder="Optional">
                  </div>
                  <div class="label-input">
                    <label for="order-expires-at">Expires At (timestamp)</label>
                    <input id="order-expires-at" data-order-field="expires_at" type="number" step="1" placeholder="Optional">
                  </div>
                </div>
                <div class="payload-row">
                  <div class="label-input">
                    <label for="order-buyer-trade">Buyer Trade Pubkey</label>
                    <input id="order-buyer-trade" data-order-field="buyer_trade_pubkey" type="text" placeholder="Optional">
                  </div>
                  <div class="label-input">
                    <label for="order-seller-trade">Seller Trade Pubkey</label>
                    <input id="order-seller-trade" data-order-field="seller_trade_pubkey" type="text" placeholder="Optional">
                  </div>
                  <div class="label-input">
                    <label for="order-buyer-invoice">Buyer Invoice</label>
                    <input id="order-buyer-invoice" data-order-field="buyer_invoice" type="text" placeholder="Optional">
                  </div>
                </div>
              </div>
              <div class="payload-group" id="payload-custom" data-payload-section="custom" hidden>
                <label for="payload-json" class="payload-note">Provide a JSON object representing the payload variant.</label>
                <textarea id="payload-json" class="textarea-input" placeholder='{{"order": {{ ... }}}}'></textarea>
              </div>
            </div>
          </div>
        </div>
        <div class="message-preview">
          <div class="preview-header">
            <span class="helper">Generated Message Preview</span>
            <div class="message-actions">
              <button class="copy-key" id="copy-message" type="button">Copy JSON</button>
            </div>
          </div>
          <pre class="json-preview"><code id="message-preview">{{}}</code></pre>
        </div>
        <div class="send-section">
          <button class="send-button" id="send-to-mostro" type="button">Send to Mostro</button>
          <div class="send-status" id="send-status" hidden>
            <span id="status-text">Ready</span>
          </div>
        </div>
        <div class="message-preview" id="response-container" hidden>
          <div class="preview-header">
            <span class="helper">Message Response</span>
            <div class="message-actions">
              <span class="response-status" id="response-status">Waiting for response...</span>
              <button class="copy-key" id="copy-response" type="button">Copy JSON</button>
            </div>
          </div>
          <pre class="json-preview"><code id="message-response">{{}}</code></pre>
        </div>
      </fieldset>
    </form>
  </div>
  <script>
    async function copyText(value) {{
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        try {{
          await navigator.clipboard.writeText(value);
          return true;
        }} catch (_) {{
          // Continue to fallback
        }}
      }}

      try {{
        const temp = document.createElement('textarea');
        temp.value = value;
        temp.setAttribute('readonly', '');
        temp.style.position = 'absolute';
        temp.style.left = '-9999px';
        document.body.appendChild(temp);
        temp.select();
        document.execCommand('copy');
        document.body.removeChild(temp);
        return true;
      }} catch (_) {{
        return false;
      }}
    }}

    (function() {{
      const identityInput = document.getElementById('identity');
      const identityState = document.getElementById('identity-state');
      const identityToggle = document.getElementById('toggle-identity');
      const identityCopy = document.getElementById('copy-identity');
      const mnemonicInput = document.getElementById('mnemonic');
      const mostroPubkey = document.getElementById('mostro-pubkey');
      if (!identityInput || !identityState || !identityToggle || !identityCopy || !mnemonicInput || !mostroPubkey) return;

      let identityPublic = identityInput.value;
      let identityPrivate = identityInput.dataset.private || '';
      let identityShowingPrivate = false;

      const updateIdentityDisplay = () => {{
        identityInput.value = identityShowingPrivate ? identityPrivate : identityPublic;
        identityState.textContent = identityShowingPrivate ? 'Private' : 'Public';
        identityToggle.textContent = identityShowingPrivate ? 'Show Public Key' : 'Show Private Key';
      }};

      identityInput.addEventListener('input', () => {{
        identityShowingPrivate = false;
        identityState.textContent = 'Custom';
        identityToggle.textContent = 'Show Private Key';
      }});

      identityToggle.addEventListener('click', () => {{
        identityShowingPrivate = !identityShowingPrivate;
        updateIdentityDisplay();
      }});

      identityCopy.addEventListener('click', async () => {{
        const originalLabel = identityCopy.textContent;
        const ok = await copyText(identityInput.value);
        identityCopy.textContent = ok ? 'Copied!' : 'Copy Failed';
        setTimeout(() => {{
          identityCopy.textContent = originalLabel;
        }}, 1500);
      }});

      updateIdentityDisplay();

      const tradeInput = document.getElementById('trade-key');
      const tradeState = document.getElementById('trade-state');
      const tradeToggle = document.getElementById('toggle-trade');
      const tradeCopy = document.getElementById('copy-trade');
      const tradeIncrement = document.getElementById('trade-increment');
      const tradeDecrement = document.getElementById('trade-decrement');
      const tradeIndexDisplay = document.getElementById('trade-index');
      const tradePath = document.getElementById('trade-path');
      const tradeError = document.getElementById('trade-error');
      if (!tradeInput || !tradeState || !tradeToggle || !tradeCopy || !tradeIncrement || !tradeDecrement || !tradeIndexDisplay || !tradePath || !tradeError) {{
        return;
      }}

      let tradePublic = tradeInput.value;
      let tradePrivate = tradeInput.dataset.private || '';
      const tradeMinIndex = Number(tradeInput.dataset.minIndex || '1');
      let tradeIndex = Number(tradeInput.dataset.index || tradeMinIndex);
      let tradeShowingPrivate = false;
      let tradeLoading = false;

      const updateTradeDisplay = () => {{
        tradeInput.value = tradeShowingPrivate ? tradePrivate : tradePublic;
        tradeState.textContent = tradeShowingPrivate ? 'Private' : 'Public';
        tradeToggle.textContent = tradeShowingPrivate ? 'Show Public Key' : 'Show Private Key';
      }};

      const updateTradeControls = () => {{
        tradeIndexDisplay.textContent = `Trade #${{tradeIndex}}`;
        tradeIncrement.disabled = tradeLoading;
        tradeDecrement.disabled = tradeLoading || tradeIndex <= tradeMinIndex;
      }};

      const resetTradeCopyLabel = () => {{
        tradeCopy.textContent = 'Copy';
      }};

      tradeToggle.addEventListener('click', () => {{
        tradeShowingPrivate = !tradeShowingPrivate;
        updateTradeDisplay();
      }});

      tradeCopy.addEventListener('click', async () => {{
        const originalLabel = tradeCopy.textContent;
        const ok = await copyText(tradeInput.value);
        tradeCopy.textContent = ok ? 'Copied!' : 'Copy Failed';
        setTimeout(() => {{
          tradeCopy.textContent = originalLabel;
        }}, 1500);
      }});

      tradeIncrement.addEventListener('click', () => {{
        void requestTradeKey(tradeIndex + 1);
      }});

      tradeDecrement.addEventListener('click', () => {{
        if (tradeIndex > tradeMinIndex) {{
          void requestTradeKey(tradeIndex - 1);
        }}
      }});

      async function requestTradeKey(nextIndex) {{
        if (tradeLoading || nextIndex < tradeMinIndex) {{
          return;
        }}

        tradeLoading = true;
        resetTradeCopyLabel();
        tradeError.hidden = true;
        tradeError.textContent = '';
        updateTradeControls();

        try {{
          const response = await fetch('/api/trade-key', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ mnemonic: mnemonicInput.value, index: nextIndex }})
          }});

          if (!response.ok) {{
            const data = await response.json().catch(() => null);
            const message = data && data.error ? data.error : 'Failed to derive trade key';
            throw new Error(message);
          }}

          const data = await response.json();
          tradeIndex = Number(data.index);
          tradePublic = data.public_key;
          tradePrivate = data.private_key;
          tradeInput.dataset.index = String(tradeIndex);
          tradeInput.dataset.private = tradePrivate;
          tradePath.textContent = data.derivation_path;

          updateTradeDisplay();
          updateTradeControls();
        }} catch (error) {{
          tradeError.textContent = error instanceof Error ? error.message : 'Failed to derive trade key';
          tradeError.hidden = false;
        }} finally {{
          tradeLoading = false;
          updateTradeControls();
        }}
      }}

      updateTradeDisplay();
      updateTradeControls();

      // Mnemonic change handler - regenerate keys when mnemonic is edited
      const mnemonicError = document.getElementById('mnemonic-error');
      let mnemonicTimeout = null;

      mnemonicInput.addEventListener('input', () => {{
        // Clear previous timeout
        if (mnemonicTimeout) {{
          clearTimeout(mnemonicTimeout);
        }}

        // Clear any previous error
        if (mnemonicError) {{
          mnemonicError.hidden = true;
          mnemonicError.textContent = '';
        }}

        // Debounce: wait 500ms after user stops typing
        mnemonicTimeout = setTimeout(async () => {{
          const newMnemonic = mnemonicInput.value.trim();

          // Basic validation: check if it's not empty and has words
          if (!newMnemonic) {{
            if (mnemonicError) {{
              mnemonicError.textContent = 'Mnemonic cannot be empty';
              mnemonicError.hidden = false;
            }}
            return;
          }}

          const words = newMnemonic.split(/\s+/);
          if (words.length !== 12 && words.length !== 24) {{
            if (mnemonicError) {{
              mnemonicError.textContent = 'Mnemonic must be 12 or 24 words';
              mnemonicError.hidden = false;
            }}
            return;
          }}

          try {{
            // Derive identity key (index 0) and trade key (index 1) in parallel
            const [identityResponse, tradeResponse] = await Promise.all([
              fetch('/api/trade-key', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ mnemonic: newMnemonic, index: 0 }})
              }}),
              fetch('/api/trade-key', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ mnemonic: newMnemonic, index: 1 }})
              }})
            ]);

            // Check if both requests succeeded
            if (!identityResponse.ok) {{
              const error = await identityResponse.json();
              throw new Error(error.error || 'Failed to derive identity key');
            }}

            if (!tradeResponse.ok) {{
              const error = await tradeResponse.json();
              throw new Error(error.error || 'Failed to derive trade key');
            }}

            // Parse responses
            const identityData = await identityResponse.json();
            const tradeData = await tradeResponse.json();

            // Update identity key variables
            identityPublic = identityData.public_key;
            identityPrivate = identityData.private_key;
            identityInput.value = identityPublic;
            identityInput.dataset.private = identityPrivate;
            identityShowingPrivate = false;
            updateIdentityDisplay();

            // Update trade key
            tradePublic = tradeData.public_key;
            tradePrivate = tradeData.private_key;
            tradeIndex = 1;
            tradeInput.value = tradePublic;
            tradeInput.dataset.index = '1';
            tradeInput.dataset.private = tradePrivate;
            tradePath.textContent = tradeData.derivation_path;
            tradeShowingPrivate = false;
            updateTradeDisplay();
            updateTradeControls();

            // Clear any error
            if (mnemonicError) {{
              mnemonicError.hidden = true;
              mnemonicError.textContent = '';
            }}

          }} catch (error) {{
            if (mnemonicError) {{
              mnemonicError.textContent = error.message || 'Failed to regenerate keys';
              mnemonicError.hidden = false;
            }}
            console.error('Mnemonic change error:', error);
          }}
        }}, 500);
      }});
    }})();
    (function() {{
      const ACTIONS = JSON.parse('{actions}');
      const MESSAGE_TYPES = JSON.parse('{message_types}');
      const ORDER_KINDS = JSON.parse('{order_kinds}');
      const ORDER_STATUSES = JSON.parse('{order_statuses}');

      const ID_REQUIRED_ACTIONS = new Set([
        'take-sell','take-buy','fiat-sent','fiat-sent-ok','release','released','dispute','admin-cancel','admin-canceled','admin-settle','admin-settled','rate','rate-received','admin-take-dispute','admin-took-dispute','dispute-initiated-by-you','dispute-initiated-by-peer','waiting-buyer-invoice','purchase-completed','hold-invoice-payment-accepted','hold-invoice-payment-settled','hold-invoice-payment-canceled','waiting-seller-to-pay','buyer-took-order','buyer-invoice-accepted','cooperative-cancel-initiated-by-you','cooperative-cancel-initiated-by-peer','cooperative-cancel-accepted','cancel','invoice-updated','admin-add-solver','send-dm','trade-pubkey','canceled','payment-failed','pay-invoice','add-invoice'
      ]);

      const messageTypeSelect = document.getElementById('message-type');
      const actionSelect = document.getElementById('message-action');
      const versionInput = document.getElementById('message-version');
      const idInput = document.getElementById('message-id');
      const requestIdInput = document.getElementById('message-request-id');
      const tradeIndexInput = document.getElementById('message-trade-index');
      const payloadModeSelect = document.getElementById('payload-mode');
      const payloadFields = document.getElementById('payload-fields');
      const payloadHint = document.getElementById('payload-hint');
      const actionHint = document.getElementById('action-hint');
      const previewCode = document.getElementById('message-preview');
      const copyMessageBtn = document.getElementById('copy-message');
      const orderKindSelect = document.getElementById('order-kind');
      const orderStatusSelect = document.getElementById('order-status');
      const orderFiatCodeInput = document.getElementById('order-fiat-code');
      const orderIdInput = document.getElementById('order-id');
      const payloadEmptyNote = document.getElementById('payload-empty-note');
      const payloadOrderSection = document.getElementById('payload-order');
      const payloadCustomSection = document.getElementById('payload-custom');

      if (!messageTypeSelect || !actionSelect || !payloadModeSelect || !payloadFields || !payloadHint || !previewCode) {{
        return;
      }}

      function titleCase(value) {{
        return value
          .split('-')
          .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
          .join(' ');
      }}

      function populateSelect(select, values) {{
        if (!select) return;
        select.innerHTML = '';
        values.forEach((value) => {{
          const option = document.createElement('option');
          option.value = value;
          option.textContent = titleCase(value);
          select.appendChild(option);
        }});
      }}

      populateSelect(messageTypeSelect, MESSAGE_TYPES);
      populateSelect(actionSelect, ACTIONS);
      populateSelect(orderKindSelect, ORDER_KINDS);
      populateSelect(orderStatusSelect, ORDER_STATUSES);
      if (orderStatusSelect) {{
        orderStatusSelect.value = 'pending';
      }}

      messageTypeSelect.value = MESSAGE_TYPES[0] ?? '';
      actionSelect.value = ACTIONS[0] ?? '';

      orderKindSelect?.addEventListener('change', updatePreview);
      orderStatusSelect?.addEventListener('change', updatePreview);
      orderFiatCodeInput?.addEventListener('input', () => {{
        orderFiatCodeInput.value = orderFiatCodeInput.value.toUpperCase();
        updatePreview();
      }});
      orderIdInput?.addEventListener('input', updatePreview);
      orderIdInput?.addEventListener('change', updatePreview);

      let latestPreview = '{{}}';

      function setPayloadSection(mode) {{
        if (payloadEmptyNote) {{
          payloadEmptyNote.hidden = mode !== 'none';
        }}
        if (payloadOrderSection) {{
          payloadOrderSection.hidden = mode !== 'order';
        }}
        if (payloadCustomSection) {{
          payloadCustomSection.hidden = mode !== 'custom';
        }}
        payloadModeSelect.value = mode;
        if (payloadHint) {{
          if (mode === 'order') {{
            payloadHint.textContent = 'Populate the order payload fields to describe the new order.';
          }} else if (mode === 'custom') {{
            payloadHint.textContent = 'Paste or type a JSON object to use as payload content.';
          }} else {{
            payloadHint.textContent = 'Most actions do not require a payload.';
          }}
        }}
      }}

      function parseInteger(value) {{
        if (value === undefined || value === null || value === '') {{
          return undefined;
        }}
        const parsed = Number(value);
        return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
      }}

      function collectOrderPayload() {{
        if (payloadOrderSection?.hidden) {{
          return null;
        }}
        const data = {{}};
        payloadOrderSection.querySelectorAll('[data-order-field]').forEach((input) => {{
          const key = input.getAttribute('data-order-field');
          if (!key) return;
          const value = input.value.trim();
          if (!value) {{
            if (['amount', 'fiat_amount', 'premium'].includes(key)) {{
              data[key] = 0;
            }}
            return;
          }}
          switch (key) {{
            case 'amount':
            case 'fiat_amount':
            case 'premium':
            case 'min_amount':
            case 'max_amount':
            case 'created_at':
            case 'expires_at':
              const numeric = parseInteger(value);
              if (numeric !== undefined) {{
                data[key] = numeric;
              }}
              break;
            default:
              data[key] = value;
          }}
        }});

        // Ensure all required fields are present (SmallOrder struct requirements)
        if (!('amount' in data)) {{
          data.amount = 0;
        }}
        if (!('fiat_amount' in data)) {{
          data.fiat_amount = 0;
        }}
        if (!('premium' in data)) {{
          data.premium = 0;
        }}
        if (!('fiat_code' in data)) {{
          data.fiat_code = 'USD';
        }} else if (typeof data.fiat_code === 'string') {{
          data.fiat_code = data.fiat_code.toUpperCase();
        }}
        if (!('payment_method' in data)) {{
          data.payment_method = '';
        }}

        return Object.keys(data).length > 0 ? {{ order: data }} : null;
      }}

      function collectCustomPayload() {{
        if (payloadCustomSection?.hidden) {{
          return null;
        }}
        const textarea = document.getElementById('payload-json');
        if (!textarea) return null;
        const value = textarea.value.trim();
        if (!value) return null;
        try {{
          const parsed = JSON.parse(value);
          payloadHint.textContent = 'Custom payload parsed successfully.';
          return parsed;
        }} catch (error) {{
          payloadHint.textContent = 'Invalid JSON payload: ' + error.message;
          return null;
        }}
      }}

      function buildPayload() {{
        const mode = payloadModeSelect.value;
        if (mode === 'order') return collectOrderPayload();
        if (mode === 'custom') return collectCustomPayload();
        return null;
      }}

      function buildWrapper() {{
        const action = actionSelect.value;
        const wrapper = {{
          version: parseInteger(versionInput.value) ?? 1,
          action,
        }};

        const idValue = idInput.value.trim();
        if (idValue) {{
          wrapper.id = idValue;
        }}

        const requestId = parseInteger(requestIdInput.value);
        if (requestId !== undefined) {{
          wrapper.request_id = requestId;
        }}

        const tradeIndex = parseInteger(tradeIndexInput.value);
        if (tradeIndex !== undefined) {{
          wrapper.trade_index = tradeIndex;
        }}

        const payload = buildPayload();
        if (payload && Object.keys(payload).length > 0) {{
          wrapper.payload = payload;
        }}

        return wrapper;
      }}

      function updatePreview() {{
        const messageKind = messageTypeSelect.value || 'order';
        const wrapper = buildWrapper();
        const output = {{ [messageKind]: wrapper }};
        latestPreview = JSON.stringify(output, null, 2);
        previewCode.textContent = latestPreview;
      }}

      function onActionChanged() {{
        const action = actionSelect.value;
        const requiresId = ID_REQUIRED_ACTIONS.has(action);
        idInput.required = requiresId;
        actionHint.textContent = requiresId
          ? 'This action requires a message id (UUID).'
          : 'Select an action to tailor payload fields.';

        const defaultMode = action === 'new-order' ? 'order' : 'none';
        setPayloadSection(defaultMode);
        updatePreview();
      }}

      payloadModeSelect.addEventListener('change', () => {{
        setPayloadSection(payloadModeSelect.value);
        updatePreview();
      }});

      actionSelect.addEventListener('change', onActionChanged);
      messageTypeSelect.addEventListener('change', updatePreview);

      [versionInput, idInput, requestIdInput, tradeIndexInput].forEach((input) => {{
        input?.addEventListener('input', updatePreview);
      }});

      payloadFields.addEventListener('input', updatePreview, true);
      payloadFields.addEventListener('change', updatePreview, true);

      copyMessageBtn?.addEventListener('click', async () => {{
        const original = copyMessageBtn.textContent;
        const ok = await copyText(latestPreview);
        copyMessageBtn.textContent = ok ? 'Copied!' : 'Copy Failed';
        setTimeout(() => {{ copyMessageBtn.textContent = original; }}, 1500);
      }});

      onActionChanged();
      updatePreview();
    }})();

    // Gift Wrap and Relay Publishing
    (function() {{
      const sendButton = document.getElementById('send-to-mostro');
      const sendStatus = document.getElementById('send-status');
      const statusText = document.getElementById('status-text');
      const mostroPubkeyInput = document.getElementById('mostro-pubkey');
      const mnemonicInput = document.getElementById('mnemonic');
      const tradeKeyInput = document.getElementById('trade-key');

      if (!sendButton || !sendStatus || !statusText) return;

      function showStatus(message, type) {{
        sendStatus.hidden = false;
        sendStatus.className = 'send-status ' + type;
        statusText.textContent = message;
      }}

      function hideStatus() {{
        sendStatus.hidden = true;
      }}

      async function buildGiftWrapEvent() {{
        const mostroPubkey = mostroPubkeyInput.value.trim();
        if (!mostroPubkey) {{
          throw new Error('Mostro pubkey is required');
        }}

        const mnemonic = mnemonicInput.value;
        const tradeIndex = parseInt(tradeKeyInput.dataset.index);

        // Build message from current form state
        const messageKind = document.getElementById('message-type').value || 'order';
        const action = document.getElementById('message-action').value;
        const versionInput = document.getElementById('message-version');
        const idInput = document.getElementById('message-id');
        const requestIdInput = document.getElementById('message-request-id');
        const tradeIndexInput = document.getElementById('message-trade-index');

        const wrapper = {{
          version: parseInt(versionInput.value) || 1,
          action,
        }};

        const idValue = idInput.value.trim();
        if (idValue) wrapper.id = idValue;

        const requestId = parseInt(requestIdInput.value);
        if (!isNaN(requestId)) wrapper.request_id = requestId;

        const msgTradeIndex = parseInt(tradeIndexInput.value);
        if (!isNaN(msgTradeIndex)) wrapper.trade_index = msgTradeIndex;

        // Get payload if any
        const payloadMode = document.getElementById('payload-mode').value;
        if (payloadMode === 'order') {{
          const payload = collectOrderPayload();
          if (payload) wrapper.payload = payload;
        }} else if (payloadMode === 'custom') {{
          const payload = collectCustomPayload();
          if (payload) wrapper.payload = payload;
        }}

        const message = {{ [messageKind]: wrapper }};

        // Call API to build gift wrap
        const response = await fetch('/api/build-gift-wrap', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            mnemonic,
            trade_index: tradeIndex,
            mostro_pubkey: mostroPubkey,
            message_json: JSON.stringify(message)
          }})
        }});

        if (!response.ok) {{
          const error = await response.json();
          throw new Error(error.error || 'Failed to build gift wrap');
        }}

        const data = await response.json();
        return data.gift_wrap_event;
      }}

      function collectOrderPayload() {{
        const orderSection = document.getElementById('payload-order');
        if (!orderSection || orderSection.hidden) return null;

        const data = {{}};
        orderSection.querySelectorAll('[data-order-field]').forEach((input) => {{
          const key = input.getAttribute('data-order-field');
          if (!key) return;
          const value = input.value.trim();
          if (!value) {{
            if (['amount', 'fiat_amount', 'premium'].includes(key)) data[key] = 0;
            return;
          }}
          switch (key) {{
            case 'amount':
            case 'fiat_amount':
            case 'premium':
            case 'min_amount':
            case 'max_amount':
            case 'created_at':
            case 'expires_at':
              const numeric = parseInt(value);
              if (!isNaN(numeric)) data[key] = numeric;
              break;
            default:
              data[key] = value;
          }}
        }});

        // Ensure all required fields are present (SmallOrder struct requirements)
        if (!('amount' in data)) data.amount = 0;
        if (!('fiat_amount' in data)) data.fiat_amount = 0;
        if (!('premium' in data)) data.premium = 0;
        if (!('fiat_code' in data)) data.fiat_code = 'USD';
        else if (typeof data.fiat_code === 'string') data.fiat_code = data.fiat_code.toUpperCase();
        if (!('payment_method' in data)) data.payment_method = '';

        return Object.keys(data).length > 0 ? {{ order: data }} : null;
      }}

      function collectCustomPayload() {{
        const customSection = document.getElementById('payload-custom');
        if (!customSection || customSection.hidden) return null;
        const textarea = document.getElementById('payload-json');
        if (!textarea) return null;
        const value = textarea.value.trim();
        if (!value) return null;
        try {{
          return JSON.parse(value);
        }} catch (error) {{
          throw new Error('Invalid JSON payload: ' + error.message);
        }}
      }}

      async function publishToRelay(giftWrapEvent) {{
        const relay = 'wss://relay.mostro.network';

        return new Promise((resolve, reject) => {{
          const ws = new WebSocket(relay);
          let timeout;

          ws.onopen = () => {{
            // Send EVENT command
            ws.send(JSON.stringify(['EVENT', giftWrapEvent]));

            // Set timeout for response
            timeout = setTimeout(() => {{
              ws.close();
              reject(new Error('Relay response timeout'));
            }}, 30000);
          }};

          ws.onmessage = (event) => {{
            try {{
              const data = JSON.parse(event.data);
              if (data[0] === 'OK') {{
                clearTimeout(timeout);
                const eventId = data[1];
                const accepted = data[2];
                const message = data[3] || '';

                ws.close();

                if (accepted) {{
                  resolve(eventId);
                }} else {{
                  reject(new Error('Relay rejected event: ' + message));
                }}
              }} else if (data[0] === 'NOTICE') {{
                clearTimeout(timeout);
                ws.close();
                reject(new Error('Relay notice: ' + data[1]));
              }}
            }} catch (err) {{
              clearTimeout(timeout);
              ws.close();
              reject(new Error('Failed to parse relay response'));
            }}
          }};

          ws.onerror = (error) => {{
            clearTimeout(timeout);
            reject(new Error('WebSocket connection error'));
          }};

          ws.onclose = (event) => {{
            clearTimeout(timeout);
            if (!event.wasClean) {{
              reject(new Error('Connection closed unexpectedly'));
            }}
          }};
        }});
      }}

      sendButton.addEventListener('click', async () => {{
        try {{
          sendButton.disabled = true;
          hideStatus();

          // Validate Mostro pubkey
          if (!mostroPubkeyInput.value.trim()) {{
            throw new Error('Please enter Mostro pubkey');
          }}

          // Step 1: Build gift wrap
          showStatus('Building gift wrap event...', 'info');
          const giftWrapEvent = await buildGiftWrapEvent();

          // Step 2: Connect to relay and publish
          showStatus('Connecting to relay...', 'info');
          const eventId = await publishToRelay(giftWrapEvent);

          // Success
          showStatus('Event published successfully! ID: ' + eventId, 'success');

          // Step 3: Start listening for response
          const tradePublicKey = tradeKeyInput.value;
          listenForResponse(tradePublicKey);

        }} catch (error) {{
          showStatus('Error: ' + error.message, 'error');
          console.error('Send error:', error);
        }} finally {{
          sendButton.disabled = false;
        }}
      }});
    }})();

    // Response Listener
    (function() {{
      const responseContainer = document.getElementById('response-container');
      const responseStatus = document.getElementById('response-status');
      const responseCode = document.getElementById('message-response');
      const copyResponseBtn = document.getElementById('copy-response');
      const mnemonicInput = document.getElementById('mnemonic');
      const tradeKeyInput = document.getElementById('trade-key');

      if (!responseContainer || !responseStatus || !responseCode || !copyResponseBtn) return;

      let latestResponse = '{{}}';

      copyResponseBtn.addEventListener('click', async () => {{
        const original = copyResponseBtn.textContent;
        const ok = await copyText(latestResponse);
        copyResponseBtn.textContent = ok ? 'Copied!' : 'Copy Failed';
        setTimeout(() => {{ copyResponseBtn.textContent = original; }}, 1500);
      }});

      window.listenForResponse = function(tradePubkey) {{
        responseContainer.hidden = false;
        responseStatus.className = 'response-status listening';
        responseStatus.textContent = 'Listening for responses...';
        responseCode.textContent = '{{}}';
        latestResponse = '{{}}';

        const relay = 'wss://relay.mostro.network';
        const ws = new WebSocket(relay);
        let timeout;
        let subscriptionId = 'sub-' + Date.now();
        let collectedEvents = [];

        ws.onopen = () => {{
          // Subscribe to gift wrap events (kind 1059) directed to our trade pubkey
          const filter = {{}};
          filter.kinds = [1059];
          filter['#p'] = [tradePubkey];
          // No limit - we want all events
          ws.send(JSON.stringify(['REQ', subscriptionId, filter]));

          // Set 30-second timeout
          timeout = setTimeout(() => {{
            ws.close();
            if (collectedEvents.length === 0) {{
              responseStatus.className = 'response-status timeout';
              responseStatus.textContent = 'Timeout (no response)';
            }}
          }}, 30000);
        }};

        ws.onmessage = async (event) => {{
          try {{
            const data = JSON.parse(event.data);

            // Collect EVENT messages
            if (data[0] === 'EVENT' && data[1] === subscriptionId) {{
              const giftWrapEvent = data[2];
              collectedEvents.push(giftWrapEvent);

              // Update status with count
              responseStatus.className = 'response-status listening';
              responseStatus.textContent = 'Received ' + collectedEvents.length + ' event(s)...';
            }}

            // Wait for EOSE (End Of Stored Events)
            if (data[0] === 'EOSE' && data[1] === subscriptionId) {{
              clearTimeout(timeout);

              // Check if we have any events
              if (collectedEvents.length === 0) {{
                responseStatus.className = 'response-status timeout';
                responseStatus.textContent = 'No responses found';
                ws.send(JSON.stringify(['CLOSE', subscriptionId]));
                ws.close();
                return;
              }}

              // Update status
              responseStatus.className = 'response-status listening';
              responseStatus.textContent = 'Decrypting ' + collectedEvents.length + ' event(s)...';

              // Decrypt all gift wrap events using our API
              const tradeIndex = parseInt(tradeKeyInput.dataset.index);
              const decryptResponse = await fetch('/api/decrypt-gift-wrap', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                  mnemonic: mnemonicInput.value,
                  trade_index: tradeIndex,
                  gift_wrap_events: collectedEvents
                }})
              }});

              if (!decryptResponse.ok) {{
                const error = await decryptResponse.json();
                throw new Error(error.error || 'Failed to decrypt responses');
              }}

              const decryptData = await decryptResponse.json();
              latestResponse = JSON.stringify(decryptData.rumor_content, null, 2);
              responseCode.textContent = latestResponse;

              // Format timestamp
              const date = new Date(decryptData.timestamp * 1000);
              const timeStr = date.toLocaleString();

              responseStatus.className = 'response-status received';
              responseStatus.textContent = 'Latest response (' + timeStr + ')';

              // Close subscription
              ws.send(JSON.stringify(['CLOSE', subscriptionId]));
              ws.close();
            }}
          }} catch (error) {{
            clearTimeout(timeout);
            responseStatus.className = 'response-status error';
            responseStatus.textContent = 'Error: ' + error.message;
            console.error('Response error:', error);
            ws.close();
          }}
        }};

        ws.onerror = (error) => {{
          clearTimeout(timeout);
          responseStatus.className = 'response-status error';
          responseStatus.textContent = 'WebSocket error';
        }};

        ws.onclose = () => {{
          clearTimeout(timeout);
        }};
      }};
    }})();
  </script>
</body>
</html>"#,
        main_color = MAIN_COLOR,
        main_color_dark = MAIN_COLOR_DARK,
        base_path = MOSTRO_BASE_PATH,
        mnemonic = ctx.mnemonic_phrase,
        identity = ctx.identity_key_hex,
        identity_private = ctx.identity_secret_hex,
        identity_path = IDENTITY_PATH,
        trade_path = ctx.trade_derivation_path(),
        trade_public = ctx.trade_key_hex,
        trade_private = ctx.trade_secret_hex,
        trade_index = ctx.trade_index,
        trade_min_index = TRADE_MIN_INDEX,
        actions = actions_json,
        message_types = message_types_json,
        order_kinds = order_kinds_json,
        order_statuses = order_statuses_json,
    )
}

fn render_error_page(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mostro Message Builder &mdash; Error</title>
<style>
body {{
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, {main_color} 0%, {main_color_dark} 100%);
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  color: #fff;
}}
section {{
  background: rgba(0, 0, 0, 0.85);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 18px;
  padding: 2rem 2.5rem;
  max-width: 520px;
  text-align: center;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
}}
h1 {{
  font-size: 1.6rem;
  margin-bottom: 1rem;
}}
p {{
  color: rgba(255, 255, 255, 0.78);
  line-height: 1.5;
}}
</style>
</head>
<body>
  <section>
    <h1>Something went wrong</h1>
    <p>{message}</p>
  </section>
</body>
</html>"#,
        main_color = MAIN_COLOR,
        main_color_dark = MAIN_COLOR_DARK,
        message = message,
    )
}
