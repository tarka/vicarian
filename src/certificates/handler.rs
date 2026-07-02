use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::listeners::TlsAccept;
use pingora_rustls::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing_log::log::{debug, info};

use crate::certificates::store::CertStore;


#[derive(Debug)]
pub struct CertHandler {
    certstore: Arc<CertStore>,
}

impl CertHandler {
    pub fn new(certstore: Arc<CertStore>) -> Self {
        Self {
            certstore
        }
    }
}


impl ResolvesServerCert for CertHandler {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?.to_string();
        info!("TLS Host is {host}; loading certs with Rustls");

        // FIXME: This should be a `get()` in CertStore, but papaya
        // guard lifetimes make it pointless (we'd have to generate a
        // guard here anyway). There may be another way to do it
        // cleanly?
        let host_cert = self.certstore.by_host(&host)
            .or_else(|| self.certstore.by_wildcard(&host))
            .expect("Certificate for host not found");
        debug!("Found certificate for {host}");

        info!("Found {host} cert");
        Some(host_cert.cert())
    }

}

pub struct DummyCallbackHandler {}

#[async_trait]
impl TlsAccept for DummyCallbackHandler {

}
