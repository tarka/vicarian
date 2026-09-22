pub mod certs;

use std::ops::Deref;
use std::sync::{LazyLock, Mutex};
use std::thread::panicking;
use std::time::Duration;

use anyhow::{Result, bail};
use camino::Utf8PathBuf;
use fslock::LockFile;
use nix::{sys::signal::{Signal, kill}, unistd::Pid};
use tempfile::{TempDir, tempdir_in};
use tokio::{fs::{File, create_dir_all}};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tracing::info;
use wiremock::MockServer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyPorts {
    pub insecure_port: u16,
    pub tls_port: u16,
}

const PORT_RANGE_START: u16 = 20000;
const PORT_RANGE_END: u16 = 32000;
const PORTS_PER_TEST: u16 = 4;

static PROCESS_PORT_MUTEX: Mutex<()> = Mutex::new(());

// Checks if a port can be bound on IPv4 and IPv6 localhost and 0.0.0.0.
// Returns the bound listener on 127.0.0.1 if successful (kept open temporarily
// to prevent races while validating the rest of the port block).
fn try_bind_port(port: u16) -> Option<std::net::TcpListener> {
    // Attempt to bind IPv6 dual-stack (which covers both IPv6 and IPv4)
    // or fall back to IPv4 wildcard 0.0.0.0.
    if let Ok(l) = std::net::TcpListener::bind(("[::]", port)) {
        Some(l)
    } else {
        std::net::TcpListener::bind(("0.0.0.0", port)).ok()
    }
}

// Allocate a block of 4 consecutive free ports for a test.
// Guaranteed not to clash with any existing system daemon, and synchronized
// across threads and processes using both an in-process mutex and an fslock file lock.
pub fn allocate_proxy_ports() -> Result<ProxyPorts> {
    let _process_guard = PROCESS_PORT_MUTEX.lock().unwrap();

    let lock_dir = std::path::Path::new("target/test_runs");
    std::fs::create_dir_all(lock_dir)?;
    let lock_file_path = lock_dir.join("port_allocator.lock");
    let mut file_lock = LockFile::open(&lock_file_path)?;
    file_lock.lock()?;

    let state_file_path = lock_dir.join("port_allocator.state");
    let mut next_port = if state_file_path.exists() {
        std::fs::read_to_string(&state_file_path)
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .unwrap_or(PORT_RANGE_START)
    } else {
        PORT_RANGE_START
    };

    if !(PORT_RANGE_START..PORT_RANGE_END).contains(&next_port) {
        next_port = PORT_RANGE_START;
    }

    let mut attempts = 0;
    let max_attempts = (PORT_RANGE_END - PORT_RANGE_START) as usize;

    while attempts < max_attempts {
        if next_port + PORTS_PER_TEST > PORT_RANGE_END {
            next_port = PORT_RANGE_START;
        }

        let base = next_port;
        next_port += PORTS_PER_TEST;
        attempts += PORTS_PER_TEST as usize;

        // Try to bind all 4 ports in the block
        let mut listeners = Vec::with_capacity(PORTS_PER_TEST as usize);
        let mut all_free = true;

        for offset in 0..PORTS_PER_TEST {
            match try_bind_port(base + offset) {
                Some(l) => listeners.push(l),
                None => {
                    all_free = false;
                    break;
                }
            }
        }

        if all_free {
            // Persist the state
            let _ = std::fs::write(&state_file_path, next_port.to_string());

            return Ok(ProxyPorts {
                insecure_port: base,
                tls_port: base + 1,
            });
        }
    }

    bail!("Failed to allocate a block of free ports after searching range {PORT_RANGE_START}..{PORT_RANGE_END}");
}

pub struct ProxyBuilder {
    pub dir: TempDir,
    pub config: Option<Utf8PathBuf>,
    pub ports: ProxyPorts,
    pub mock_ports: Vec<u16>,
}

pub struct Proxy {
    pub dir: TempDir,
    pub _config: Utf8PathBuf,
    pub process: Child,
    pub ports: ProxyPorts,
}

impl Deref for ProxyBuilder {
    type Target = ProxyPorts;
    fn deref(&self) -> &Self::Target {
        &self.ports
    }
}

impl Deref for Proxy {
    type Target = ProxyPorts;
    fn deref(&self) -> &Self::Target {
        &self.ports
    }
}

impl ProxyBuilder {
    pub async fn new() -> Self {
        create_dir_all("target/test_runs").await.unwrap();
        let dir = tempdir_in("target/test_runs").unwrap();

        let ports = tokio::task::spawn_blocking(allocate_proxy_ports).await
            .expect("Blocking task panicked")
            .expect("Failed to allocate test ports");

        Self {
            dir,
            config: None,
            ports,
            mock_ports: Vec::new()
        }
    }

    pub fn with_simple_config(mut self, confname: &str) -> Self {
        let path = format!("tests/data/config/{confname}.hcl");
        self.config = Some(Utf8PathBuf::from(path));
        self
    }

    pub fn with_mock_ports(self, mock_ports: &[u16]) -> Self
    {
        Self {
            mock_ports: mock_ports.into(),
            ..self
        }
    }

    pub fn with_mock_servers(self, mocks: &[&MockServer]) -> Self
    {
        let mock_ports = mocks.iter()
            .map(|m| m.address().port())
            .collect::<Vec<u16>>();
        self.with_mock_ports(&mock_ports)
    }


    pub async fn run(self) -> Result<Proxy> {
        if self.config.is_none() {
            bail!("No config provided")
        }

        // Force creation of the test certs.
        let _ = LazyLock::force(&certs::TEST_CERTS);

        let process = self.run_proxy().await?;
        let fname = self.config.as_ref().unwrap().components().next_back().unwrap();
        let copied = self.dir.path().join(fname);
        Ok(Proxy {
            dir: self.dir,
            _config: Utf8PathBuf::from_path_buf(copied).unwrap(),
            process,
            ports: self.ports,
        })
    }

    async fn run_proxy(&self) -> Result<Child> {
        info!("Starting Test Proxy on ports HTTP:{} TLS:{}", self.ports.insecure_port, self.ports.tls_port);
        let exe = env!("CARGO_BIN_EXE_vicarian");
        let out_file = self.dir.path().join("stdout");
        let err_file = self.dir.path().join("stderr");
        let stdout = File::create(out_file).await?;
        let stderr = File::create(err_file).await?;

        // Tests use env() in the HCL to extract backends
        let mockenv: Vec<_> = self.mock_ports.iter()
            .enumerate()
            .map(|(c, p)| {
                (format!("VICARIAN_TEST_BACKEND_URL_{}", c+1),
                 format!("http://127.0.0.1:{p}"))
            })
            .collect();
        println!("ENV = {mockenv:?}");

        let mut child = Command::new(exe)
            .arg("-vv")
            .arg("-c").arg(self.config.as_ref().unwrap())
            // Port flags override the listen ports from the config file,
            // enabling parallel tests to each use their own unique port block.
            .arg("--insecure-port").arg(self.ports.insecure_port.to_string())
            .arg("--tls-port").arg(self.ports.tls_port.to_string())
            .envs(mockenv)
            .stdout(stdout.into_std().await)
            .stderr(stderr.into_std().await)
            .spawn()?;

        for _ in 0..100 { // 2 second timeout
            if let Ok(Some(status)) = child.try_wait() {
                bail!("Proxy server exited early with status: {status}");
            }
            let conn1 = TcpStream::connect(format!("localhost:{}", self.ports.insecure_port)).await;
            let conn2 = TcpStream::connect(format!("localhost:{}", self.ports.tls_port)).await;

            if conn1.is_ok() && conn2.is_ok() {
                info!("Test Proxy Ready");
                return Ok(child);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        bail!("Failed to start proxy server")
    }
}

impl Proxy {
    fn child_cleanup(&self) {
        if let Some(id) = self.process.id() {
            let pid = Pid::from_raw(id as i32);
            let _ = kill(pid, Signal::SIGINT);
            println!("Killed process {}", pid);
        }
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

pub async fn mock_server() -> Result<MockServer> {
    let addr = "127.0.0.1:0";
    let listener = TcpListener::bind(addr).await?;
    let server = MockServer::builder()
        .listener(listener.into_std()?).start().await;
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_allocate_proxy_ports_distinct() {
        let ports1 = allocate_proxy_ports().unwrap();
        let ports2 = allocate_proxy_ports().unwrap();

        let set1: HashSet<u16> = [ports1.insecure_port, ports1.tls_port].into_iter().collect();
        let set2: HashSet<u16> = [ports2.insecure_port, ports2.tls_port].into_iter().collect();

        assert_eq!(set1.len(), 2, "Ports within ports1 must be distinct");
        assert_eq!(set2.len(), 2, "Ports within ports2 must be distinct");
        assert!(set1.is_disjoint(&set2), "Allocated port blocks must not overlap");
    }

    #[tokio::test]
    async fn test_allocate_proxy_ports_concurrent() {
        let handles: Vec<_> = (0..10)
            .map(|_| tokio::spawn(async { allocate_proxy_ports().unwrap() }))
            .collect();

        let mut all_ports = HashSet::new();
        for h in handles {
            let p = h.await.unwrap();
            assert!(all_ports.insert(p.insecure_port));
            assert!(all_ports.insert(p.tls_port));
        }
        assert_eq!(all_ports.len(), 20);
    }
}

