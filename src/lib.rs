use std::fmt;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bip39::{Language, Mnemonic};
use nostr_sdk::prelude::{FromMnemonic, Keys, nip06};
use serde::{Deserialize, Serialize};
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
    if payload.index < TRADE_MIN_INDEX {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!("Trade key index must be at least {TRADE_MIN_INDEX}"),
        ));
    }

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
input[type="text"] {{
  background: rgba(33, 51, 13, 0.9);
  border: 1px solid rgba(255, 255, 255, 0.25);
  border-radius: 14px;
  padding: 0.95rem 1.1rem;
  font-size: 1rem;
  color: #fff;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
  outline: none;
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
input[type="text"]:focus {{
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
    <form>
      <fieldset>
        <legend>Keys</legend>
        <div class="helper">Mostro derivation path in use:</div>
        <div class="path-display">{base_path}</div>
        <div class="label-input">
          <label for="mnemonic">Mnemonic Seed</label>
          <input id="mnemonic" type="text" value="{mnemonic}" readonly spellcheck="false">
          <p class="helper">Random 12-word BIP39 seed generated when the page loads. Securely back it up.</p>
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
      </fieldset>
    </form>
  </div>
  <script>
    (function() {{
      const identityInput = document.getElementById('identity');
      const identityState = document.getElementById('identity-state');
      const identityToggle = document.getElementById('toggle-identity');
      const identityCopy = document.getElementById('copy-identity');
      const mnemonicInput = document.getElementById('mnemonic');
      if (!identityInput || !identityState || !identityToggle || !identityCopy || !mnemonicInput) return;

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

      const identityPublic = identityInput.value;
      const identityPrivate = identityInput.dataset.private || '';
      let identityShowingPrivate = false;

      const updateIdentityDisplay = () => {{
        identityInput.value = identityShowingPrivate ? identityPrivate : identityPublic;
        identityState.textContent = identityShowingPrivate ? 'Private' : 'Public';
        identityToggle.textContent = identityShowingPrivate ? 'Show Public Key' : 'Show Private Key';
      }};

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
