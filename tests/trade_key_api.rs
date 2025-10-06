use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mostro_webtool::app;
use nostr_sdk::prelude::{FromMnemonic, Keys};
use serde_json::{Value, json};
use tower::ServiceExt;

const SAMPLE_MNEMONIC: &str =
    "leader monkey parrot ring guide accident before fence cannon height naive bean";

#[tokio::test]
async fn trade_key_endpoint_returns_expected_payload() {
    let router = app();
    let index = 2u32;
    let payload = json!({
        "mnemonic": SAMPLE_MNEMONIC,
        "index": index,
    });

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/trade-key")
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

    assert_eq!(value["index"], index);

    let expected_keys = Keys::from_mnemonic_advanced(
        SAMPLE_MNEMONIC,
        None::<&str>,
        Some(38_383),
        Some(0),
        Some(index),
    )
    .unwrap();

    assert_eq!(value["public_key"], expected_keys.public_key().to_hex());
    assert_eq!(
        value["private_key"],
        expected_keys.secret_key().to_secret_hex()
    );
    assert_eq!(
        value["derivation_path"],
        format!("m/44'/1237'/38383'/0/{index}")
    );
}

#[tokio::test]
async fn trade_key_endpoint_rejects_identity_index() {
    let router = app();
    let payload = json!({
        "mnemonic": SAMPLE_MNEMONIC,
        "index": 0,
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/trade-key")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let bytes = BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value["error"].as_str().unwrap().contains("at least 1"));
}
