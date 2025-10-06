use std::net::SocketAddr;

use tokio::net::TcpListener;

use mostro_webtool::{DEFAULT_PORT, app, init_tracing};

#[tokio::main]
async fn main() {
    init_tracing();

    let app = app();

    let addr = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT));
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    tracing::info!("listening on http://{}", listener.local_addr().unwrap());

    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(error = %err, "server error");
    }
}
