use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rustls::ClientConfig;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};
use wiremocket::{Mock, prelude::ValidJsonMatcher, responder::echo_response};

use crate::certutils::TEST_CERTS;
use crate::proxyutils::ProxyBuilder;

fn test_connector() -> Connector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = ClientConfig::builder()
        .with_root_certificates(TEST_CERTS.caroot.store.clone())
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

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

    let mock = Mock::given(ValidJsonMatcher)
        .set_responder(echo_response())
        .expect(1..);
    ws_server.register(mock).await;

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);
    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(test_connector())).await.unwrap();

    let msg = json!({"message": "heartbeat"}).to_string();

    stream.send(Message::text(&msg)).await.unwrap();

    let reply = stream.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::text(&msg));

    stream.send(Message::Close(None)).await.unwrap();

    // Drain closing stream before verify
    while stream.next().await.is_some() {}

    ws_server.verify().await;
}

// #4: Binary payloads and large frames
#[tokio::test]
#[test_log::test]
async fn test_ws_binary_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .with_mock_ports(&[port])
        .run().await.unwrap();

    let ws_server = wiremocket::MockServer::builder()
        .listener(listener)
        .build().await;

    let mock = Mock::given(wiremocket::prelude::path(""))
        .set_responder(echo_response())
        .expect(1..);
    ws_server.register(mock).await;

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);
    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(test_connector())).await.unwrap();

    // 64 KiB binary payload containing non-UTF8 arbitrary bytes
    let mut payload = vec![0u8; 64 * 1024];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    stream.send(Message::binary(payload.clone())).await.unwrap();

    let reply = stream.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::binary(payload));

    stream.send(Message::Close(None)).await.unwrap();
    while stream.next().await.is_some() {}

    ws_server.verify().await;
}

// #5: Multi-message streaming over a single connection
#[tokio::test]
#[test_log::test]
async fn test_ws_multi_message_streaming() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .with_mock_ports(&[port])
        .run().await.unwrap();

    let ws_server = wiremocket::MockServer::builder()
        .listener(listener)
        .build().await;

    let mock = Mock::given(ValidJsonMatcher)
        .set_responder(echo_response())
        .expect(1..);
    ws_server.register(mock).await;

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);
    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(test_connector())).await.unwrap();

    for i in 0..10 {
        let msg = json!({"sequence": i, "data": "ping"}).to_string();
        stream.send(Message::text(&msg)).await.unwrap();
        let reply = stream.next().await.unwrap().unwrap();
        assert_eq!(reply, Message::text(&msg));
    }

    stream.send(Message::Close(None)).await.unwrap();
    while stream.next().await.is_some() {}

    ws_server.verify().await;
}

// #6: Concurrent WebSocket connections through the proxy
#[tokio::test]
#[test_log::test]
async fn test_ws_concurrent_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .with_mock_ports(&[port])
        .run().await.unwrap();

    let ws_server = wiremocket::MockServer::builder()
        .listener(listener)
        .build().await;

    let mock = Mock::given(ValidJsonMatcher)
        .set_responder(echo_response())
        .expect(5..);
    ws_server.register(mock).await;

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);

    let mut handles = Vec::new();
    for client_id in 0..5 {
        let uri = proxy_uri.clone();
        handles.push(tokio::spawn(async move {
            let (mut stream, _response) = connect_async_tls_with_config(uri, None, false, Some(test_connector())).await.unwrap();
            let msg = json!({"client_id": client_id}).to_string();

            stream.send(Message::text(&msg)).await.unwrap();
            let reply = stream.next().await.unwrap().unwrap();
            assert_eq!(reply, Message::text(&msg));

            stream.send(Message::Close(None)).await.unwrap();
            while stream.next().await.is_some() {}
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    ws_server.verify().await;
}

// #7a: Failure scenario: Backend is down, proxy returns 502 Bad Gateway
#[tokio::test]
#[test_log::test]
async fn test_ws_backend_down_502() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // Ensure port is closed and nothing is listening

    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .with_mock_ports(&[port])
        .run().await.unwrap();

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);
    let res = connect_async_tls_with_config(proxy_uri, None, false, Some(test_connector())).await;

    match res {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 502);
        }
        other => panic!("Expected HTTP 502 Bad Gateway, got: {:?}", other),
    }
}

// #7b: Teardown scenario: Backend disconnects abruptly, client promptly detects EOF without hanging
#[tokio::test]
#[test_log::test]
async fn test_ws_backend_abrupt_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let proxy = ProxyBuilder::new().await
        .with_simple_config("localhost_simple")
        .with_mock_ports(&[port])
        .run().await.unwrap();

    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            if let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await {
                let _ = ws.send(Message::text("hello from closing backend")).await;
                // Intentionally drop WebSocket stream abruptly without a clean closing handshake
                drop(ws);
            }
        }
    });

    let proxy_uri = format!("wss://localhost:{}/", proxy.tls_port);
    let (mut stream, _response) = connect_async_tls_with_config(proxy_uri, None, false, Some(test_connector())).await.unwrap();

    let first_msg = stream.next().await.unwrap().unwrap();
    assert_eq!(first_msg, Message::text("hello from closing backend"));

    // Client should promptly observe connection closure rather than hanging indefinitely
    let res = tokio::time::timeout(Duration::from_secs(5), async {
        while stream.next().await.is_some() {}
    }).await;

    assert!(res.is_ok(), "Client timed out waiting for backend disconnect");
}
