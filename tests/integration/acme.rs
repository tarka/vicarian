#![cfg(feature = "integration_tests")]

// End-to-end ACME tests against Let's Encrypt Pebble.
//
// These tests are skipped when the Pebble binaries aren't installed. See
// `tests/utils/pebble.rs` for the environment variables used to locate them.

use std::{path::Path, time::Duration};

use anyhow::{Result, bail};
use reqwest::{Certificate, Client};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use crate::{
    proxyutils::{Proxy, ProxyBuilder, mock_server},
    utils_pebble::{ChallengeDns, Http01Forwarder, PebbleServer},
};

const DOMAIN: &str = "test.acme.example.com";
const CONTACT: &str = "admin@example.com";
const STARTUP_ATTEMPTS: usize = 300;
const STARTUP_INTERVAL: Duration = Duration::from_millis(50);

fn acme_config(acme_dir: &Path, provider_url: &str, backend_port: u16) -> String {
    format!(
        r#"
listen {{}}

acme "pebble" {{
    contact = "{CONTACT}"
    directory = "{}"
    profile = "classic"
    provider_url = "{provider_url}"
    challenge {{
        type = "http-01"
    }}
}}

vhost "{DOMAIN}" {{
    tls = "pebble"

    backend "/" {{
        type = "proxy"
        url = "http://127.0.0.1:{backend_port}"
    }}
}}
"#,
        acme_dir.display()
    )
}

async fn wait_for_issued_cert(tls_port: u16, root: Certificate) -> Result<String> {
    let addr = format!("127.0.0.1:{tls_port}").parse().unwrap();
    let client = Client::builder()
        .resolve(DOMAIN, addr)
        .add_root_certificate(root)
        .build()?;

    for _ in 0..STARTUP_ATTEMPTS {
        match client
            .get(format!("https://{DOMAIN}:{tls_port}/status"))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => return Ok(resp.text().await?),
            _ => tokio::time::sleep(STARTUP_INTERVAL).await,
        }
    }
    bail!("Timed out waiting for Pebble-issued certificate to be served by proxy")
}

async fn mock_backend() -> wiremock::MockServer {
    let backend = mock_server().await.unwrap();
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ACME OK"))
        .mount(&backend)
        .await;
    backend
}

async fn proxy_with_acme(builder: ProxyBuilder, acme_dir: &Path, pebble: &PebbleServer, backend_port: u16) -> Proxy {
    let hcl = acme_config(acme_dir, &pebble.directory_url, backend_port);
    builder
        .with_config_contents(&hcl)
        .unwrap()
        .with_envs([("SSL_CERT_FILE", pebble.ca_pem_path.to_str().unwrap())])
        .run()
        .await
        .unwrap()
}

// Full HTTP-01 flow: Pebble resolves the domain to localhost, makes a real
// validation request (through a Host-rewriting forwarder), and Vicarian must
// serve the correct key authorization before Pebble will issue a cert.
#[tokio::test]
async fn test_acme_http01_pebble_full_validation() {
    let Some(dns) = ChallengeDns::start().await.unwrap() else {
        return;
    };

    let builder = ProxyBuilder::new().await;
    let backend = mock_backend().await;
    let forwarder = Http01Forwarder::start(builder.insecure_port).await.unwrap();

    let dnsserver = format!("127.0.0.1:{}", dns.dns_port);
    let Some(pebble) = PebbleServer::start(forwarder.port, false, Some(&dnsserver))
        .await
        .unwrap()
    else {
        return;
    };

    let acme_dir = builder.dir.path().join("acme");
    let proxy = proxy_with_acme(builder, &acme_dir, &pebble, backend.address().port()).await;

    let body = wait_for_issued_cert(proxy.tls_port, pebble.issued_root_cert().unwrap())
        .await
        .unwrap();
    assert_eq!("ACME OK", body);

    let observed = forwarder.observed();
    assert!(
        !observed.is_empty(),
        "Pebble never made an HTTP-01 validation request"
    );
    for (token, key_auth) in observed {
        assert!(
            key_auth.starts_with(&format!("{token}.")),
            "Unexpected key authorization for token {token}: {key_auth}"
        );
    }
}

// Exercise the ACME protocol flow with Pebble's validation short-circuited.
// This variant only needs the `pebble` binary (no DNS/challenge server) and
// verifies account creation, ordering, issuance and cert installation.
#[tokio::test]
async fn test_acme_http01_pebble_always_valid() {
    let builder = ProxyBuilder::new().await;
    let backend = mock_backend().await;

    let Some(pebble) = PebbleServer::start(builder.insecure_port, true, None)
        .await
        .unwrap()
    else {
        return;
    };

    let acme_dir = builder.dir.path().join("acme");
    let proxy = proxy_with_acme(builder, &acme_dir, &pebble, backend.address().port()).await;

    let body = wait_for_issued_cert(proxy.tls_port, pebble.issued_root_cert().unwrap())
        .await
        .unwrap();
    assert_eq!("ACME OK", body);

    // The cert and account credentials should have been cached on disk.
    assert!(acme_dir.join(DOMAIN).join(format!("{DOMAIN}.crt")).is_file());
    assert!(acme_dir.join(DOMAIN).join(format!("{DOMAIN}.key")).is_file());
    assert!(acme_dir.join(CONTACT).join(format!("{CONTACT}.conf")).is_file());
}
