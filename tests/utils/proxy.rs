
mod certs;

use std::sync::LazyLock;
use std::thread::panicking;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use camino::Utf8PathBuf;
use nix::{sys::signal::{Signal, kill}, unistd::Pid};
use tempfile::{TempDir, tempdir_in};
use tokio::{fs::{File, copy, create_dir_all}};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tracing_log::log::info;
use wiremock::MockServer;

pub const INSECURE_PORT: u16 = 8080;
pub const TLS_PORT: u16 = 8443;
pub const BACKEND_PORT: u16 = 9090;

pub struct ProxyBuilder {
    pub dir: TempDir,
    pub config: Option<Utf8PathBuf>,
}

pub struct Proxy {
    pub dir: TempDir,
    pub _config: Utf8PathBuf,
    pub process: Child,
}

impl ProxyBuilder {
    pub async fn new() -> Self {
        create_dir_all("target/test_runs").await.unwrap();
        let dir = tempdir_in("target/test_runs").unwrap();
        Self {
            dir,
            config: None,
        }
    }

    pub fn with_simple_config(mut self, confname: &str) -> Self {
        let path = format!("tests/data/config/{confname}.corn");
        self.config = Some(Utf8PathBuf::from(path));
        self
    }

    pub async fn run(self) -> Result<Proxy> {
        if self.config.is_none() {
            bail!("No config provided")
        }

        // Force creation of the test certs.
        let _ = LazyLock::force(&certs::TEST_CERTS);

        let process = self.run_proxy().await?;
        Ok(Proxy {
            dir: self.dir,
            _config: self.config.unwrap(),
            process,
        })
    }

    async fn run_proxy(&self) -> Result<Child> {
        info!("Starting Test Proxy");
        let exe = env!("CARGO_BIN_EXE_vicarian");

        let out_file = self.dir.path().join("stdout");
        let err_file = self.dir.path().join("stderr");
        let stdout = File::create(out_file).await?;
        let stderr = File::create(err_file).await?;

        // Checked above
        let config = self.config.as_ref().unwrap();
        let fname = config.components().last().ok_or(anyhow!("No filename"))?;
        let copied = self.dir.path().join(fname);
        copy(&config, copied).await.unwrap();

        let child = Command::new(exe)
            .arg("-vv")
            .arg("-c").arg(config)
            .stdout(stdout.into_std().await)
            .stderr(stderr.into_std().await)
            .spawn()?;

        for _ in 0..20 { // 2 second timeout
            let conn1 = TcpStream::connect(format!("localhost:{INSECURE_PORT}")).await;
            let conn2 = TcpStream::connect(format!("localhost:{TLS_PORT}")).await;

            if conn1.is_ok() && conn2.is_ok() {
                info!("Test Proxy Ready");
                return Ok(child);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("Failed to start proxy server")
    }
}

impl Proxy {
    fn child_cleanup(&self) {
        let pid = Pid::from_raw(self.process.id().unwrap().try_into().unwrap());
        kill(pid, Signal::SIGINT).unwrap();
        println!("Killed process {}", pid);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if panicking() {
            self.dir.disable_cleanup(true);
        }
        self.child_cleanup();
    }
}

pub async fn mock_server(port: u16) -> Result<MockServer> {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(addr).await?;
    let server = MockServer::builder()
        .listener(listener.into_std()?).start().await;
    Ok(server)
}
