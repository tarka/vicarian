use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use rustls::ClientConfig;
use serde_json::json;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};

use crate::proxyutils::ProxyBuilder;
use tokio::net::TcpListener;
use wiremocket::{Mock, prelude::ValidJsonMatcher, responder::echo_response};

use crate::certutils::TEST_CERTS;


#[tokio::test]
#[test_log::test]
async fn test_ws_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .with_mock_ports(&[port])
        .run().await.unwrap();

    let ws_server = wiremocket::MockServer::builder()
        .listener(listener)
        .build().await;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mock = Mock::given(ValidJsonMatcher)
        .set_responder(echo_response())
        .expect(1..);
    ws_server.register(mock).await;

    let config = ClientConfig::builder()
        .with_root_certificates(TEST_CERTS.caroot.store.clone())
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(config));

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);

    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(connector)).await.unwrap();

    let msg = json!({"message": "heartbeat"}).to_string();


    stream.send(Message::text(&msg)).await.unwrap();

    let reply = stream.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::text(&msg));

    stream.send(Message::Close(None)).await.unwrap();

    // Drain closing stream before verify
    while stream.next().await.is_some() {}

    ws_server.verify().await;
}
