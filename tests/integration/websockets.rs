use std::sync::Arc;

use futures::SinkExt;
use rustls::ClientConfig;
use serde_json::json;
use serial_test::serial;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};

use crate::proxyutils::{
    BACKEND_PORT, ProxyBuilder, TLS_PORT,
};
use tokio::net::TcpListener;
use wiremocket::{Mock, prelude::ValidJsonMatcher};

use crate::certutils::TEST_CERTS;


#[tokio::test]
#[serial]
async fn test_ws_backend() {
    let addr = format!("127.0.0.1:{BACKEND_PORT}");
    let listener = TcpListener::bind(addr).await.unwrap();
    let ws_server = wiremocket::MockServer::builder()
        .listener(listener)
        .build().await;

    rustls::crypto::aws_lc_rs::default_provider().install_default()
        .expect("Failed to install Rustls crypto provider");

    let mock = Mock::given(ValidJsonMatcher).expect(1..);
    ws_server.register(mock).await;

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let config = ClientConfig::builder()
        .with_root_certificates(TEST_CERTS.caroot.store.clone())
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(config));

    let proxy_uri = format!("wss://localhost:{TLS_PORT}/");

    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(connector)).await.unwrap();

    let msg = json!({"message": "heartbeat"});

    stream.send(Message::text(msg.to_string())).await.unwrap();

    stream.send(Message::Close(None)).await.unwrap();

    std::mem::drop(stream);

    ws_server.verify().await;
}

