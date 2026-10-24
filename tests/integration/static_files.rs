#![cfg(feature = "integration_tests")]

use std::time::Duration;

use http::header::AUTHORIZATION;
use reqwest::{Client, header::{VIA, CONTENT_TYPE, STRICT_TRANSPORT_SECURITY}};

use crate::certutils::TEST_CERTS;
use crate::proxyutils::{Proxy, ProxyBuilder};

#[tokio::test]
async fn test_static_file_serving() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let ct = response.headers().get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap());
    assert!(ct.unwrap_or("").starts_with("text/html"));
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
async fn test_static_file_with_explicit_path() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/index.html", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
async fn test_static_css_file() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/css/style.css", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let ct = response.headers().get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap());
    assert!(ct.unwrap_or("").starts_with("text/css"));
    let body = response.text().await.unwrap();
    assert!(body.contains("background"));
}

#[tokio::test]
async fn test_static_js_file() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/js/app.js", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let ct = response.headers().get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap());
    assert!(ct.unwrap_or("").starts_with("text/javascript") || ct.unwrap_or("").starts_with("application/javascript"));
    let body = response.text().await.unwrap();
    assert!(body.contains("static server"));
}

#[tokio::test]
async fn test_static_binary_file() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/assets/logo.png", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let ct = response.headers().get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap());
    assert!(ct.unwrap_or("").starts_with("image/png"));
    let body = response.bytes().await.unwrap();
    assert_eq!(200, body.len());
}

#[tokio::test]
async fn test_static_nested_path() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/subdir/page.html", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Subdir page"));
}

#[tokio::test]
async fn test_static_404() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/nonexistent.txt", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
async fn test_static_auth_required() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static_auth")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    // Without auth: should return 401
    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
async fn test_static_auth_valid() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static_auth")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    // With valid auth: should return 200
    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/", proxy.tls_port))
        .header(AUTHORIZATION, "Bearer my_auth_key")
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
async fn test_static_auth_invalid() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static_auth")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    // With invalid auth: should return 401
    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/", proxy.tls_port))
        .header(AUTHORIZATION, "Bearer wrong_key")
        .send()
        .await
        .unwrap();

    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
async fn test_static_compression_gzip() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/large.html", proxy.tls_port))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding")
        .map(|v| v.to_str().unwrap());
    assert_eq!(Some("gzip"), content_encoding);

    let body = response.text().await.unwrap();
    assert!(body.len() < 2000);
}

#[tokio::test]
async fn test_static_compression_brotli() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/large.html", proxy.tls_port))
        .header("Accept-Encoding", "br")
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding")
        .map(|v| v.to_str().unwrap());
    assert_eq!(Some("br"), content_encoding);
}

#[tokio::test]
async fn test_static_no_compression_without_accept_encoding() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/large.html", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding");
    assert!(content_encoding.is_none());
}

#[tokio::test]
async fn test_static_preserves_vicarian_headers() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());

    let via = response.headers().get(VIA)
        .map(|v| v.to_str().unwrap());
    assert!(via.is_some());
    assert!(via.unwrap().contains("Vicarian"));

    let hsts = response.headers().get(STRICT_TRANSPORT_SECURITY)
        .map(|v| v.to_str().unwrap());
    assert_eq!(Some("max-age=31536000; includeSubDomains"), hsts);
}

#[tokio::test]
async fn test_static_directory_listing() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/css/", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("style.css"));
}

#[tokio::test]
async fn test_static_fallback_page() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/some/unknown/path", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
async fn test_static_context_path() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/css/style.css", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("background"));
}

#[tokio::test]
async fn test_static_head_request() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let client = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let response = client.head(format!("https://www.example.com:{}/index.html", proxy.tls_port))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_static_multiple_files_concurrent() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let tls_port = proxy.tls_port;
    let example_com = format!("127.0.0.1:{tls_port}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let client = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let handles: Vec<_> = vec![
        "/index.html",
        "/css/style.css",
        "/js/app.js",
        "/assets/logo.png",
        "/subdir/page.html",
        "/large.html",
    ].into_iter()
    .map(|path| {
        let client = client.clone();
        tokio::spawn(async move {
            client.get(format!("https://www.example.com:{tls_port}{path}"))
                .send()
                .await
        })
    })
    .collect();

    for handle in handles {
        let response = handle.await.unwrap().unwrap();
        assert_eq!(200, response.status().as_u16());
    }
}

/// Read the proxy process's captured stdout and stderr.
fn proxy_output(proxy: &Proxy) -> String {
    let dir = proxy.dir.path();
    let stdout = std::fs::read_to_string(dir.join("stdout")).unwrap_or_default();
    let stderr = std::fs::read_to_string(dir.join("stderr")).unwrap_or_default();
    format!("{stdout}\n{stderr}")
}

// Serves a static file and returns the proxy's captured log output.
async fn serve_and_collect_logs(proxy: &Proxy) -> String {
    let example_com = format!("127.0.0.1:{}", proxy.tls_port).parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{}/index.html", proxy.tls_port))
        .send()
        .await
        .unwrap();
    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));

    // Give the proxy a moment to flush log output to the captured files.
    tokio::time::sleep(Duration::from_millis(200)).await;
    proxy_output(proxy)
}

#[tokio::test]
async fn test_static_request_log_filtered_at_info() {
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .with_verbose(1) // -v => INFO
        .run()
        .await
        .unwrap();

    let logs = serve_and_collect_logs(&proxy).await;

    // Sanity check: vicarian's own INFO access log for the request is
    // present, so the absence of SWS logs is not because logging is off.
    assert!(logs.contains("access:"), "expected vicarian INFO access log in: {logs}");

    // static-web-server logs each request at INFO under the target
    // `static_web_server::log_addr`, which is capped at WARN.
    assert!(!logs.contains("static_web_server::log_addr"),
            "static_web_server::log_addr must not be logged at INFO level:\n{logs}");
}

#[tokio::test]
async fn test_static_request_log_filtered_at_debug() {
    // The harness default is -vv (DEBUG). The `static_web_server::log_addr=warn`
    // cap must also hold here: SWS logs each request at INFO, which would
    // otherwise appear at DEBUG level.
    let proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run()
        .await
        .unwrap();

    let logs = serve_and_collect_logs(&proxy).await;

    // Sanity check: DEBUG logging is active.
    let request_log = format!("Request: https://www.example.com:{}/index.html", proxy.tls_port);
    assert!(logs.contains(&request_log),
            "expected vicarian DEBUG request log {request_log:?} in: {logs}");

    assert!(!logs.contains("static_web_server::log_addr"),
            "static_web_server::log_addr must stay capped at WARN even at DEBUG level:\n{logs}");
}
