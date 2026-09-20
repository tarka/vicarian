use std::sync::Arc;

use futures::SinkExt;
use rustls::ClientConfig;
use serde_json::json;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};

use crate::proxyutils::ProxyBuilder;
use tokio::net::TcpListener;
use wiremocket::{Mock, prelude::ValidJsonMatcher};

use crate::certutils::TEST_CERTS;


#[tokio::test]
async fn test_ws_backend() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .run().await.unwrap();

    let addr = format!("127.0.0.1:{}", proxy.backend_port);
    let listener = TcpListener::bind(addr).await.unwrap();
    let ws_server = wiremocket::MockServer::builder()
        .listener(listener)
        .build().await;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mock = Mock::given(ValidJsonMatcher).expect(1..);
    ws_server.register(mock).await;

    let config = ClientConfig::builder()
        .with_root_certificates(TEST_CERTS.caroot.store.clone())
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(config));

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);

    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(connector)).await.unwrap();

    let msg = json!({"message": "heartbeat"});

    stream.send(Message::text(msg.to_string())).await.unwrap();

    stream.send(Message::Close(None)).await.unwrap();

    std::mem::drop(stream);

    ws_server.verify().await;
}
