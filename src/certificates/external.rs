use std::sync::Arc;

use anyhow::Result;
use futures_lite::{stream, StreamExt};

use crate::{
    RunContext,
    certificates::HostCertificate,
    config::TlsConfig,
};

/// Externally managed certificates
// TODO: Need a better name
pub struct ExternalProvider {
    _context: Arc<RunContext>,
    certs: Vec<Arc<HostCertificate>>,
}

impl ExternalProvider {
    pub async fn new(context: Arc<RunContext>) -> Result<Self> {
        let file_certs: Vec<HostCertificate> = stream::iter(context.config.vhosts.iter())
            .filter_map(|vhost| match &vhost.tls {
                TlsConfig::Files(tcf) => Some(tcf),
                _ => None,
            })
            .then(|tfc| HostCertificate::new(
                tfc.keyfile.clone(),
                tfc.certfile.clone(),
                tfc.reload))
            .try_collect().await?;

        let certs = file_certs.into_iter()
            .map(Arc::new)
            .collect();

        Ok(Self {
            _context: context,
            certs,
        })
    }


    pub fn read_certs(&self) -> Vec<Arc<HostCertificate>> {
        self.certs.clone()
    }
}
