#![cfg(feature = "integration_tests")]

#[path = "../utils/certs.rs"]
mod certutils;
#[path = "../utils/proxy.rs"]
mod proxyutils;

use reqwest::{Client, redirect};
use serial_test::serial;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use proxyutils::{
    BACKEND_PORT, INSECURE_PORT, ProxyBuilder, TLS_PORT, mock_server,
};

use crate::certutils::TEST_CERTS;

// NOTE: We use unwrap rather than result here as we can save the run
// files on failure (see Proxy::drop()).
//
// Tests run serially currently as we use the same port across runs
// for simplicity. Once we have more tests we may need to look into
// parallelising. This is also configured for `nextest` under
// $CRATE/.config/nextest.toml

#[tokio::test]
#[serial]
async fn test_redirect_http() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    // Look for a redirect from the non-TLS port.
    let ready = Client::builder()
        .redirect(redirect::Policy::none())
        .build().unwrap()
        .get(format!("http://localhost:{INSECURE_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(301, ready.status().as_u16());
    let loc = ready.headers().get("Location").unwrap()
        .to_str().unwrap().to_string();
    let tls = format!("https://localhost:{TLS_PORT}/status");
    assert_eq!(tls, loc);
}

#[tokio::test]
#[serial]
async fn test_dns_override() {
    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.cert.clone();
    let ready = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    // No backend, so fails
    assert_eq!(502, ready.status().as_u16());
}

#[tokio::test]
#[serial]
async fn test_mocked_backend() {
    let backend_server = mock_server(BACKEND_PORT).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_simple")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = TEST_CERTS.caroot.cert.clone();

    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("OK"))
        .mount(&backend_server).await;

    let response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert)
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/status"))
        .send().await.unwrap();

    assert_eq!(200, response.status().as_u16());
    assert!(response.text().await.unwrap().contains("OK"));
}

#[tokio::test]
#[serial]
async fn test_vhosts() {
    let backend_server1 = mock_server(BACKEND_PORT).await.unwrap();
    let backend_server2 = mock_server(BACKEND_PORT+1).await.unwrap();

    let _proxy = ProxyBuilder::new().await
        .with_simple_config("example_com_vhosts")
        .run().await.unwrap();

    let example_com = format!("127.0.0.1:{TLS_PORT}").parse().unwrap();
    let root_cert = &TEST_CERTS.caroot.cert;

    // www.example.com

    Mock::given(method("GET"))
        .and(path("/host"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("www"))
        .mount(&backend_server1).await;

    let www_response = Client::builder()
        .resolve("www.example.com", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .get(format!("https://www.example.com:{TLS_PORT}/host"))
        .send().await.unwrap();

    assert_eq!(200, www_response.status().as_u16());
    assert!(www_response.text().await.unwrap().contains("www"));

    // test.example.com

    Mock::given(method("GET"))
        .and(path("/host"))
        .respond_with(ResponseTemplate::new(200)
                      .set_body_string("test"))
        .mount(&backend_server2).await;

    let test_response = Client::builder()
        .resolve("test.example.com", example_com)
        .add_root_certificate(root_cert.clone())
        .build().unwrap()
        .get(format!("https://test.example.com:{TLS_PORT}/host"))
        .send().await.unwrap();

    assert_eq!(200, test_response.status().as_u16());
    assert!(test_response.text().await.unwrap().contains("test"));
}
