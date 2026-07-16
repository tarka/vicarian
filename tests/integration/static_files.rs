#![cfg(feature = "integration_tests")]

#[path = "../utils/certs.rs"]
mod certutils;
#[path = "../utils/proxy.rs"]
mod proxyutils;

use http::header::AUTHORIZATION;
use proxyutils::{ProxyBuilder, TLS_PORT};
use reqwest::{Client, redirect, header::{VIA, CONTENT_TYPE, STRICT_TRANSPORT_SECURITY}};
use serial_test::serial;

use crate::certutils::TEST_CERTS;

#[tokio::test]
#[serial]
async fn test_static_file_serving() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/"))
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
#[serial]
async fn test_static_file_with_explicit_path() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/index.html"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
#[serial]
async fn test_static_css_file() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/css/style.css"))
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
#[serial]
async fn test_static_js_file() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/js/app.js"))
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
#[serial]
async fn test_static_binary_file() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/assets/logo.png"))
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
#[serial]
async fn test_static_nested_path() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/subdir/page.html"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Subdir page"));
}

#[tokio::test]
#[serial]
async fn test_static_404() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/nonexistent.txt"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
#[serial]
async fn test_static_auth_required() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static_auth")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    // Without auth: should return 401
    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_static_auth_valid() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static_auth")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    // With valid auth: should return 200
    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/"))
        .header(AUTHORIZATION, "Bearer my_auth_key")
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
#[serial]
async fn test_static_auth_invalid() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static_auth")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    // With invalid auth: should return 401
    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/"))
        .header(AUTHORIZATION, "Bearer wrong_key")
        .send()
        .await
        .unwrap();

    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_static_compression_gzip() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/large.html"))
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
#[serial]
async fn test_static_compression_brotli() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/large.html"))
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
#[serial]
async fn test_static_no_compression_without_accept_encoding() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/large.html"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let content_encoding = response.headers().get("Content-Encoding");
    assert!(content_encoding.is_none());
}

#[tokio::test]
#[serial]
async fn test_static_preserves_vicarian_headers() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/"))
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
#[serial]
async fn test_static_directory_listing() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/css/"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("style.css"));
}

#[tokio::test]
#[serial]
async fn test_static_fallback_page() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/some/unknown/path"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("Welcome to the static server"));
}

#[tokio::test]
#[serial]
async fn test_static_context_path() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/css/style.css"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.contains("background"));
}

#[tokio::test]
#[serial]
async fn test_static_head_request() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.reqcert.clone();

    let client = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .http2_prior_knowledge()
        .build()
        .unwrap();

    let response = client.head(format!("https://www.example.com:{TLS_PORT}/index.html"))
        .send()
        .await
        .unwrap();

    assert_eq!(200, response.status().as_u16());
    let body = response.text().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
#[serial]
async fn test_static_multiple_files_concurrent() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_static")
        .run_with_static()
        .await
        .unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
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
            client.get(format!("https://www.example.com:{TLS_PORT}{path}"))
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
