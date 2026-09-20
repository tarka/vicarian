#![allow(unused)]

pub mod certs;

use std::ops::Deref;
use std::sync::{LazyLock, Mutex};
use std::thread::panicking;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use camino::Utf8PathBuf;
use fslock::LockFile;
use nix::{sys::signal::{Signal, kill}, unistd::Pid};
use tempfile::{TempDir, tempdir_in};
use tokio::{fs::{File, copy, create_dir_all}};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tracing::info;
use wiremock::MockServer;

pub const INSECURE_PORT: u16 = 18080;
pub const TLS_PORT: u16 = 18443;
pub const BACKEND_PORT: u16 = 19090;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyPorts {
    pub insecure_port: u16,
    pub tls_port: u16,
    pub backend_port: u16,
    pub backend_port_2: u16,
}

const PORT_RANGE_START: u16 = 20000;
const PORT_RANGE_END: u16 = 32000;
const PORTS_PER_TEST: u16 = 4;

static PROCESS_PORT_MUTEX: Mutex<()> = Mutex::new(());

/// Checks if a port can be bound on IPv4 and IPv6 localhost and 0.0.0.0.
/// Returns the bound listener on 127.0.0.1 if successful (kept open temporarily
/// to prevent races while validating the rest of the port block).
fn try_bind_port(port: u16) -> Option<std::net::TcpListener> {
    // Attempt to bind IPv6 dual-stack (which covers both IPv6 and IPv4)
    // or fall back to IPv4 wildcard 0.0.0.0.
    if let Ok(l) = std::net::TcpListener::bind(("[::]", port)) {
        Some(l)
    } else {
        std::net::TcpListener::bind(("0.0.0.0", port)).ok()
    }
}

/// Allocate a block of 4 consecutive free ports for a test.
/// Guaranteed not to clash with any existing system daemon, and synchronized
/// across threads and processes using both an in-process mutex and an fslock file lock.
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
            // Drop the temporary listeners so Vicarian and mock servers can bind
            drop(listeners);
            let _ = file_lock.unlock();

            return Ok(ProxyPorts {
                insecure_port: base,
                tls_port: base + 1,
                backend_port: base + 2,
                backend_port_2: base + 3,
            });
        }
    }

    let _ = file_lock.unlock();
    bail!("Failed to allocate a block of free ports after searching range {}..{}", PORT_RANGE_START, PORT_RANGE_END)
}

pub struct ProxyBuilder {
    pub dir: TempDir,
    pub config: Option<Utf8PathBuf>,
    pub ports: ProxyPorts,
}

pub struct Proxy {
    pub dir: TempDir,
    pub _config: Utf8PathBuf,
    pub process: Child,
    pub ports: ProxyPorts,
}

pub struct StaticProxy {
    pub dir: TempDir,
    pub static_root: Utf8PathBuf,
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

impl Deref for StaticProxy {
    type Target = ProxyPorts;
    fn deref(&self) -> &Self::Target {
        &self.ports
    }
}

impl ProxyBuilder {
    pub async fn new() -> Self {
        create_dir_all("target/test_runs").await.unwrap();
        let dir = tempdir_in("target/test_runs").unwrap();
        let ports = allocate_proxy_ports().expect("Failed to allocate test ports");
        Self {
            dir,
            config: None,
            ports,
        }
    }

    pub fn with_simple_config(mut self, confname: &str) -> Self {
        let path = format!("tests/data/config/{confname}.hcl");
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
        let fname = self.config.as_ref().unwrap().components().next_back().unwrap();
        let copied = self.dir.path().join(fname);
        Ok(Proxy {
            dir: self.dir,
            _config: Utf8PathBuf::from_path_buf(copied).unwrap(),
            process,
            ports: self.ports,
        })
    }

    pub async fn run_with_static(self) -> Result<StaticProxy> {
        if self.config.is_none() {
            bail!("No config provided")
        }

        let static_root = self.dir.path().join("public");
        copy_dir_all("tests/data/static", &static_root).await?;

        // Force creation of the test certs.
        let _ = LazyLock::force(&certs::TEST_CERTS);

        let process = self.run_proxy().await?;
        Ok(StaticProxy {
            dir: self.dir,
            static_root: static_root.try_into().unwrap(),
            process,
            ports: self.ports,
        })
    }

    pub async fn mock_server(&self) -> Result<MockServer> {
        mock_server(self.ports.backend_port).await
    }

    pub async fn mock_server_2(&self) -> Result<MockServer> {
        mock_server(self.ports.backend_port_2).await
    }

    async fn run_proxy(&self) -> Result<Child> {
        info!("Starting Test Proxy on ports HTTP:{} TLS:{}", self.ports.insecure_port, self.ports.tls_port);
        let exe = env!("CARGO_BIN_EXE_vicarian");
        let out_file = self.dir.path().join("stdout");
        let err_file = self.dir.path().join("stderr");
        let stdout = File::create(out_file).await?;
        let stderr = File::create(err_file).await?;

        // Checked above
        let config = self.config.as_ref().unwrap();
        let fname = config.components().next_back().ok_or(anyhow!("No filename"))?;
        let copied = self.dir.path().join(fname);

        // Rewrite default ports in test config to the assigned dynamic ports
        let content = tokio::fs::read_to_string(config).await?;
        let content = content
            .replace("18080", &self.ports.insecure_port.to_string())
            .replace("18443", &self.ports.tls_port.to_string())
            .replace("19090", &self.ports.backend_port.to_string())
            .replace("19091", &self.ports.backend_port_2.to_string());
        tokio::fs::write(&copied, content).await?;

        let mut child = Command::new(exe)
            .arg("-vv")
            .arg("-c").arg(&copied)
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
            let pid = Pid::from_raw(id.try_into().unwrap());
            let _ = kill(pid, Signal::SIGINT);
            println!("Killed process {}", pid);
        }
    }

    pub async fn mock_server(&self) -> Result<MockServer> {
        mock_server(self.ports.backend_port).await
    }

    pub async fn mock_server_2(&self) -> Result<MockServer> {
        mock_server(self.ports.backend_port_2).await
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

impl StaticProxy {
    fn child_cleanup(&self) {
        if let Some(id) = self.process.id() {
            let pid = Pid::from_raw(id.try_into().unwrap());
            let _ = kill(pid, Signal::SIGINT);
            println!("Killed process {}", pid);
        }
    }
}

impl Drop for StaticProxy {
    fn drop(&mut self) {
        if panicking() {
            self.dir.disable_cleanup(true);
        }
        self.child_cleanup();
    }
}

async fn copy_dir_all(src: &str, dst: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().await?.is_dir() {
            Box::pin(copy_dir_all(entry_path.to_str().unwrap(), &dst_path)).await?;
        } else {
            tokio::fs::copy(&entry_path, &dst_path).await?;
        }
    }
    Ok(())
}

pub async fn mock_server(port: u16) -> Result<MockServer> {
    let addr = format!("127.0.0.1:{port}");
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

        let set1: HashSet<u16> = [ports1.insecure_port, ports1.tls_port, ports1.backend_port, ports1.backend_port_2].into_iter().collect();
        let set2: HashSet<u16> = [ports2.insecure_port, ports2.tls_port, ports2.backend_port, ports2.backend_port_2].into_iter().collect();

        assert_eq!(set1.len(), 4, "Ports within ports1 must be distinct");
        assert_eq!(set2.len(), 4, "Ports within ports2 must be distinct");
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
            assert!(all_ports.insert(p.backend_port));
            assert!(all_ports.insert(p.backend_port_2));
        }
        assert_eq!(all_ports.len(), 40);
    }
}

