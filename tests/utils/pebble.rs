//! Helpers for running a Let's Encrypt [Pebble](https://github.com/letsencrypt/pebble)
//! ACME test server from integration tests.
//!
//! Pebble is not a Rust dependency: the tests look for a `pebble` (and, for
//! full HTTP-01 validation, a `pebble-challtestsrv`) executable on `PATH`.
//! The paths can be overridden with `VICARIAN_PEBBLE_BIN` and
//! `VICARIAN_CHALLTESTSRV_BIN`. When the binaries are not available the
//! tests skip rather than fail, so the normal `cargo test` suite stays
//! self-contained.
//!
//! Everything else is generated at runtime: the ACME endpoint's TLS
//! certificate (signed by a throw-away CA) and Pebble's JSON config. This
//! means the tests don't depend on Pebble's source tree being installed.

use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use reqwest::Certificate;
use serde_json::json;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    task::JoinHandle,
};
use tracing::info;

const STARTUP_ATTEMPTS: usize = 200;
const STARTUP_INTERVAL: Duration = Duration::from_millis(25);

fn find_binary(env_override: &str, name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env_override) {
        let p = PathBuf::from(p);
        return if p.is_file() { Some(p) } else { None };
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// Generate a throw-away CA and a `localhost` server certificate for
/// Pebble's ACME/management HTTPS endpoints.
fn gen_tls_material(dir: &Path) -> Result<(String, PathBuf, PathBuf)> {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Vicarian Pebble test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()])?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    let ca_path = dir.join("pebble-ca.pem");
    let cert_path = dir.join("pebble-cert.pem");
    let key_path = dir.join("pebble-key.pem");
    std::fs::write(&ca_path, ca_pem.as_bytes())?;
    std::fs::write(&cert_path, leaf_cert.pem().as_bytes())?;
    std::fs::write(&key_path, leaf_key.serialize_pem().as_bytes())?;

    Ok((ca_pem, cert_path, key_path))
}

async fn wait_for_port(port: u16) -> Result<()> {
    for _ in 0..STARTUP_ATTEMPTS {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(STARTUP_INTERVAL).await;
    }
    bail!("Timed out waiting for test server on port {port}")
}

async fn fetch_root_ca(client: &reqwest::Client, management_port: u16) -> Result<String> {
    let url = format!("https://127.0.0.1:{management_port}/roots/0");
    for _ in 0..STARTUP_ATTEMPTS {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let pem = resp.text().await?;
                if pem.contains("BEGIN CERTIFICATE") {
                    return Ok(pem);
                }
            }
            _ => {}
        }
        tokio::time::sleep(STARTUP_INTERVAL).await;
    }
    bail!("Timed out fetching Pebble's root certificate from {url}")
}

fn immutable_dir() -> TempDir {
    tempfile::tempdir_in("target/test_runs").expect("Failed to create Pebble test dir")
}

/// A running Pebble ACME server.
pub struct PebbleServer {
    _dir: TempDir,
    child: Child,
    pub directory_url: String,
    /// PEM CA certificate for Pebble's ACME endpoint. Point `SSL_CERT_FILE`
    /// at this path so instant-acme trusts the endpoint.
    pub ca_pem_path: PathBuf,
    /// Root used to sign issued certificates (fetched from Pebble at startup).
    pub issued_root_pem: String,
}

impl PebbleServer {
    /// Start Pebble. Panics if no `pebble` binary is available.
    ///
    /// `http_port` is the port Pebble will use for HTTP-01 validation
    /// requests; it must be reachable (directly or through the
    /// [`Http01Forwarder`]) by Pebble's validation authority.
    pub async fn start(
        http_port: u16,
        always_valid: bool,
        dnsserver: Option<&str>,
    ) -> Result<Option<Self>> {
        let Some(exe) = find_binary("VICARIAN_PEBBLE_BIN", "pebble") else {
            panic!("No pebble binary found on PATH");
        };

        let dir = immutable_dir();
        let dir_path = std::fs::canonicalize(dir.path())?;
        let (ca_pem, cert_path, key_path) = gen_tls_material(&dir_path)?;

        let ports = crate::proxyutils::allocate_port_block(2)?;
        let acme_port = ports[0];
        let management_port = ports[1];

        // Long validity so the freshly issued cert isn't immediately in its
        // renewal window. The `profiles` block is understood by newer
        // Pebble versions; older ones ignore the unknown field.
        let config = json!({
            "pebble": {
                "listenAddress": format!("0.0.0.0:{acme_port}"),
                "managementListenAddress": format!("0.0.0.0:{management_port}"),
                "certificate": cert_path.to_str().unwrap(),
                "privateKey": key_path.to_str().unwrap(),
                "httpPort": http_port,
                "tlsPort": 5001,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": false,
                "domainBlocklist": [],
                "certificateValidityPeriod": 7_776_000,
                "profiles": {
                    "default": {"description": "default", "validityPeriod": 7_776_000},
                    "classic": {"description": "classic", "validityPeriod": 7_776_000},
                    "tlsserver": {"description": "tlsserver", "validityPeriod": 3_888_000},
                    "shortlived": {"description": "shortlived", "validityPeriod": 518_400}
                },
                "retryAfter": {"authz": 1, "order": 1}
            }
        });
        let config_path = dir_path.join("pebble-config.json");
        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

        let stdout = std::fs::File::create(dir_path.join("pebble.stdout"))?;
        let stderr = std::fs::File::create(dir_path.join("pebble.stderr"))?;

        let mut cmd = Command::new(exe);
        cmd.arg("-config").arg(&config_path)
            .arg("-strict=false")
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .env("PEBBLE_AUTHZREUSE", "0")
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true);
        if always_valid {
            cmd.env("PEBBLE_VA_ALWAYS_VALID", "1");
        }
        if let Some(dnsserver) = dnsserver {
            cmd.arg("-dnsserver").arg(dnsserver);
        }

        let child = cmd.spawn()?;
        wait_for_port(acme_port).await?;
        wait_for_port(management_port).await?;

        let client = reqwest::Client::builder()
            .add_root_certificate(Certificate::from_pem(ca_pem.as_bytes())?)
            .build()?;
        let issued_root_pem = fetch_root_ca(&client, management_port).await?;

        Ok(Some(Self {
            _dir: dir,
            child,
            directory_url: format!("https://localhost:{acme_port}/dir"),
            ca_pem_path: dir_path.join("pebble-ca.pem"),
            issued_root_pem,
        }))
    }

    /// Certificate object that trusts certificates issued by this Pebble.
    pub fn issued_root_cert(&self) -> Result<Certificate> {
        Ok(Certificate::from_pem(self.issued_root_pem.as_bytes())?)
    }
}

impl Drop for PebbleServer {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self._dir.disable_cleanup(true);
        }
        let _ = self.child.start_kill();
    }
}

/// A `pebble-challtestsrv` instance used only as a fake DNS resolver for
/// Pebble's HTTP-01 validation authority. Its own HTTP-01/TLS challenge
/// listeners are disabled.
pub struct ChallengeDns {
    _dir: TempDir,
    child: Child,
    pub dns_port: u16,
}

impl ChallengeDns {
    /// Start the DNS resolver. Returns `Ok(None)` if the binary is missing.
    pub async fn start() -> Result<Option<Self>> {
        let Some(exe) = find_binary("VICARIAN_CHALLTESTSRV_BIN", "pebble-challtestsrv") else {
            info!("Skipping Pebble HTTP-01 validation test: no pebble-challtestsrv binary found");
            return Ok(None);
        };

        let dir = immutable_dir();
        let ports = crate::proxyutils::allocate_port_block(2)?;
        let dns_port = ports[0];
        let management_port = ports[1];

        let stdout = std::fs::File::create(dir.path().join("challtestsrv.stdout"))?;
        let stderr = std::fs::File::create(dir.path().join("challtestsrv.stderr"))?;

        // The DNS flag was renamed from -dns01 to -dnsserver in later
        // Pebble releases; sniff the help output so both work.
        let help = Command::new(&exe).arg("-h").output().await?;
        let help = format!(
            "{}{}",
            String::from_utf8_lossy(&help.stdout),
            String::from_utf8_lossy(&help.stderr)
        );
        let dns_flag = if help.contains("-dnsserver") {
            "-dnsserver"
        } else {
            "-dns01"
        };

        let child = Command::new(exe)
            .arg(dns_flag).arg(format!("127.0.0.1:{dns_port}"))
            .arg("-management").arg(format!("127.0.0.1:{management_port}"))
            .arg("-defaultIPv4").arg("127.0.0.1")
            // Pebble tries AAAA first; don't give it ::1 since the forwarder
            // listens on IPv4.
            .arg("-defaultIPv6").arg("")
            .arg("-http01").arg("")
            .arg("-https01").arg("")
            .arg("-tlsalpn01").arg("")
            .arg("-doh").arg("")
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()?;

        wait_for_port(dns_port).await?;

        Ok(Some(Self { _dir: dir, child, dns_port }))
    }
}

impl Drop for ChallengeDns {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self._dir.disable_cleanup(true);
        }
        let _ = self.child.start_kill();
    }
}

/// A tiny HTTP forwarder that sits between Pebble's validation authority and
/// Vicarian's cleartext listener.
///
/// Pebble sends `Host: <domain>:<validation-port>`, but Vicarian keys HTTP-01
/// challenges on the Host header verbatim (i.e. without a port), so real
/// validation needs the port stripped. The forwarder also records the
/// challenge responses it observes so tests can assert the endpoint returned
/// a well-formed key authorization.
pub struct Http01Forwarder {
    _dir: TempDir,
    task: JoinHandle<()>,
    pub port: u16,
    observed: Arc<Mutex<Vec<(String, String)>>>,
}

impl Http01Forwarder {
    /// Start a forwarder which sends requests to `target_port` (Vicarian's
    /// insecure listener).
    pub async fn start(target_port: u16) -> Result<Self> {
        let ports = crate::proxyutils::allocate_port_block(1)?;
        let port = ports[0];
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_clone = observed.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    break;
                };
                let observed = observed_clone.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_one(&mut client, target_port, observed).await {
                        info!("HTTP-01 forwarder error: {e}");
                    }
                });
            }
        });

        Ok(Self {
            _dir: immutable_dir(),
            task,
            port,
            observed,
        })
    }

    /// (token, key authorization) pairs seen by Pebble's validation requests.
    pub fn observed(&self) -> Vec<(String, String)> {
        self.observed.lock().unwrap().clone()
    }
}

impl Drop for Http01Forwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward_one(
    client: &mut TcpStream,
    target_port: u16,
    observed: Arc<Mutex<Vec<(String, String)>>>,
) -> Result<()> {
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            bail!("Client closed before sending a request");
        }
        request.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_subslice(&request, b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let head = String::from_utf8_lossy(&request[..header_end]);
    let mut lines = head.lines();
    let request_line = lines.next().context("Missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().context("Missing request path")?;

    let host = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("host") {
                Some(value.trim())
            } else {
                None
            }
        })
        .unwrap_or("localhost");

    // Strip the port: Vicarian looks up challenges by the bare hostname.
    let bare_host = match host.rsplit_once(':') {
        Some((h, _port)) => h,
        None => host,
    };

    let token = path.rsplit('/').next().unwrap_or("").to_string();
    let forwarded = format!(
        "{method} {path} HTTP/1.1\r\nHost: {bare_host}\r\nConnection: close\r\n\r\n"
    );

    let mut upstream = TcpStream::connect(("127.0.0.1", target_port)).await?;
    upstream.write_all(forwarded.as_bytes()).await?;
    let _ = upstream.shutdown().await;

    let mut response = Vec::new();
    upstream.read_to_end(&mut response).await?;

    if let Some(body_start) = find_subslice(&response, b"\r\n\r\n") {
        let key_auth = String::from_utf8_lossy(&response[body_start + 4..]).into_owned();
        observed.lock().unwrap().push((token, key_auth));
    }

    client.write_all(&response).await?;
    let _ = client.shutdown().await;
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
