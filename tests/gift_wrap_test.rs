use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mostro_core::message::Message as MostroMessage;
use mostro_webtool::app;
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use tower::ServiceExt;

const SAMPLE_MNEMONIC: &str =
    "leader monkey parrot ring guide accident before fence cannon height naive bean";

// Helper function to derive identity and trade keys
fn get_test_keys(trade_index: u32) -> (Keys, Keys) {
    let identity_keys = Keys::from_mnemonic_advanced(
        SAMPLE_MNEMONIC,
        None::<&str>,
        Some(38_383),
        Some(0),
        Some(0),
    )
    .unwrap();

    let trade_keys = Keys::from_mnemonic_advanced(
        SAMPLE_MNEMONIC,
        None::<&str>,
        Some(38_383),
        Some(0),
        Some(trade_index),
    )
    .unwrap();

    (identity_keys, trade_keys)
}

// Helper function to create a test Mostro message
fn create_test_message() -> MostroMessage {
    use mostro_core::message::{Action, Payload};
    use mostro_core::order::{Kind as OrderKind, SmallOrder, Status};

    let order = SmallOrder {
        id: None,
        kind: Some(OrderKind::Buy),
        status: Some(Status::Pending),
        amount: 1000,
        fiat_code: "USD".to_string(),
        min_amount: None,
        max_amount: None,
        fiat_amount: 100,
        payment_method: "bank transfer".to_string(),
        premium: 0,
        buyer_trade_pubkey: None,
        seller_trade_pubkey: None,
        buyer_invoice: None,
        created_at: Some(1234567890),
        expires_at: None,
    };

    MostroMessage::new_order(
        None,
        Some(1),
        Some(1),
        Action::NewOrder,
        Some(Payload::Order(order)),
    )
}

// Helper function to call the build-gift-wrap API
async fn call_build_gift_wrap_api(
    message: &MostroMessage,
    mostro_pubkey: &str,
    trade_index: u32,
) -> Event {
    let router = app();
    let message_json = message.as_json().unwrap();

    let payload = json!({
        "mnemonic": SAMPLE_MNEMONIC,
        "trade_index": trade_index,
        "mostro_pubkey": mostro_pubkey,
        "message_json": message_json,
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/build-gift-wrap")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap();

    // Parse the gift_wrap_event as Event
    let event_json = serde_json::to_string(&value["gift_wrap_event"]).unwrap();
    Event::from_json(&event_json).unwrap()
}

#[tokio::test]
async fn test_gift_wrap_contains_valid_rumor() {
    let trade_index = 1u32;
    let (identity_keys, trade_keys) = get_test_keys(trade_index);

    // Create a test message
    let message = create_test_message();

    // Build gift wrap
    let gift_wrap = call_build_gift_wrap_api(
        &message,
        &identity_keys.public_key().to_hex(),
        trade_index,
    )
    .await;

    // Verify it's a gift wrap event
    assert_eq!(gift_wrap.kind, Kind::GiftWrap);

    // Extract rumor using standard NIP-59 function
    let unwrapped = nip59::extract_rumor(&identity_keys, &gift_wrap)
        .await
        .unwrap();

    // Verify rumor pubkey matches trade key
    assert_eq!(
        unwrapped.rumor.pubkey,
        trade_keys.public_key(),
        "Rumor should be signed with trade key (index {})",
        trade_index
    );

    // Verify rumor kind is 1
    assert_eq!(unwrapped.rumor.kind, Kind::Custom(1));

    // Parse rumor content as (message, signature) tuple
    // The content is a serialized string: "[{message}, \"signature\"]"
    let (message_from_rumor, signature): (MostroMessage, Signature) =
        serde_json::from_str(&unwrapped.rumor.content).unwrap();

    // Verify message matches
    assert_eq!(
        message.as_json().unwrap(),
        message_from_rumor.as_json().unwrap(),
        "Message in rumor should match original"
    );

    // Verify signature is valid
    let is_valid = MostroMessage::verify_signature(
        message.as_json().unwrap(),
        trade_keys.public_key(),
        signature,
    );
    assert!(is_valid, "Signature should be valid");
}

#[tokio::test]
async fn test_gift_wrap_seal_signed_with_identity_key() {
    let trade_index = 1u32;
    let (identity_keys, _trade_keys) = get_test_keys(trade_index);

    // Create a test message
    let message = create_test_message();

    // Build gift wrap
    let gift_wrap = call_build_gift_wrap_api(
        &message,
        &identity_keys.public_key().to_hex(),
        trade_index,
    )
    .await;

    // Extract rumor using standard NIP-59 function
    let unwrapped = nip59::extract_rumor(&identity_keys, &gift_wrap)
        .await
        .unwrap();

    // Verify the sender (seal signer) is the identity key
    assert_eq!(
        unwrapped.sender,
        identity_keys.public_key(),
        "Seal should be signed with identity key (index 0)"
    );
}

#[tokio::test]
async fn test_gift_wrap_signature_verification() {
    let trade_index = 1u32;
    let (identity_keys, trade_keys) = get_test_keys(trade_index);

    // Create a test message
    let message = create_test_message();
    let message_str = message.as_json().unwrap();

    // Build gift wrap
    let gift_wrap = call_build_gift_wrap_api(
        &message,
        &identity_keys.public_key().to_hex(),
        trade_index,
    )
    .await;

    // Extract rumor using standard NIP-59 function
    let unwrapped = nip59::extract_rumor(&identity_keys, &gift_wrap)
        .await
        .unwrap();

    // Parse rumor content as (message, signature) tuple
    let (_, signature): (MostroMessage, Signature) =
        serde_json::from_str(&unwrapped.rumor.content).unwrap();

    // Verify signature using MostroMessage::verify_signature
    let is_valid = MostroMessage::verify_signature(
        message_str,
        trade_keys.public_key(),
        signature,
    );

    assert!(
        is_valid,
        "Signature should be valid for trade key (index {})",
        trade_index
    );
}

#[tokio::test]
async fn test_gift_wrap_with_different_trade_indices() {
    let (identity_keys, _) = get_test_keys(1);

    for trade_index in [1, 2, 5, 10] {
        let (_, trade_keys) = get_test_keys(trade_index);
        let message = create_test_message();

        // Build gift wrap
        let gift_wrap = call_build_gift_wrap_api(
            &message,
            &identity_keys.public_key().to_hex(),
            trade_index,
        )
        .await;

        // Extract rumor using standard NIP-59 function
        let unwrapped = nip59::extract_rumor(&identity_keys, &gift_wrap)
            .await
            .unwrap();

        assert_eq!(
            unwrapped.rumor.pubkey,
            trade_keys.public_key(),
            "Rumor should use correct trade key for index {}",
            trade_index
        );

        // Verify sender is always identity key
        assert_eq!(
            unwrapped.sender,
            identity_keys.public_key(),
            "Seal should always be signed with identity key"
        );
    }
}

#[tokio::test]
async fn test_gift_wrap_message_contains_trade_index() {
    let trade_index = 5u32; // Use a non-default trade index
    let (identity_keys, _trade_keys) = get_test_keys(trade_index);

    // Create a test message
    let message = create_test_message();

    // Build gift wrap
    let gift_wrap = call_build_gift_wrap_api(
        &message,
        &identity_keys.public_key().to_hex(),
        trade_index,
    )
    .await;

    // Extract rumor using standard NIP-59 function
    let unwrapped = nip59::extract_rumor(&identity_keys, &gift_wrap)
        .await
        .unwrap();

    // Parse rumor content as (message, signature) tuple
    let (message_from_rumor, _): (MostroMessage, Signature) =
        serde_json::from_str(&unwrapped.rumor.content).unwrap();

    // Verify the message has the correct trade_index
    let inner = message_from_rumor.get_inner_message_kind();
    assert_eq!(
        inner.trade_index,
        Some(trade_index as i64),
        "Message should contain trade_index = {}",
        trade_index
    );
}
