use std::sync::Arc;

use rustls::{
    server::{
        ClientHello,
        ResolvesServerCert,
    },
    sign::CertifiedKey,
};
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
        Some(host_cert.cert.clone())
    }

}

// #[async_trait]
// impl TlsAccept for CertHandler {

//     // NOTE:This is all boringssl specific as pingora doesn't
//     // currently support dynamic certs with rustls.
//     async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
//         let host = ssl.servername(NameType::HOST_NAME)
//             .map(str::to_string)
//             .expect("No servername in TLS handshake");

//         debug!("TLS Host is {host}; loading certs");

//         let cert = self.certstore.by_host(&host)
//             .or_else(|| self.certstore.by_wildcard(&host))
//             .expect("Certificate for host not found");
//         debug!("Found certificate for {host}");

//         ssl.set_private_key(&cert.key)
//             .expect("Failed to set private key");
//         ssl.set_certificate(&cert.certs[0])
//             .expect("Failed to set certificate");

//         if cert.certs.len() > 1 {
//             for c in cert.certs[1..].iter() {
//                 ssl.add_chain_cert(c)
//                     .expect("Failed to add chain certificate");
//             }
//         }
//     }

// }
