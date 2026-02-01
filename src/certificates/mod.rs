pub mod acme;
pub mod handler;
pub mod host;
pub mod store;
pub mod watcher;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Result;
use futures::future::try_join_all;
use futures_lite::{stream, StreamExt};
use crate::{
    RunContext,
    certificates::{acme::AcmeRuntime, store::CertStore, watcher::CertWatcher}, config::TlsConfig,
};

pub use host::HostCertificate;


/// Externally managed certificates
// TODO: Need a better name
pub struct CertificateRuntime {
    acme: Arc<AcmeRuntime>,
    certstore: Arc<CertStore>,
    context: Arc<RunContext>,
}

impl CertificateRuntime  {
    pub fn new(context: Arc<RunContext>) -> Result<Self> {
        let certstore = Arc::new(CertStore::new(context.clone())?);
        let acme = Arc::new(AcmeRuntime::new(certstore.clone(), context.clone())?);

        Ok(Self {
            acme,
            context,
            certstore,
        })
    }

    pub fn acme(&self) -> &Arc<AcmeRuntime> {
        &self.acme
    }

    pub fn certstore(&self) -> &Arc<CertStore> {
        &self.certstore
    }

    async fn load_local_certs(&self) -> Result<Vec<HostCertificate>> {
        let iter = self.context.config.vhosts.iter();
        let certs: Vec<HostCertificate> = stream::iter(iter)
            .filter_map(|vhost| match &vhost.tls {
                TlsConfig::Files(tcf) => Some(tcf),
                _ => None,
            })
            .then(|tfc| HostCertificate::new(
                tfc.keyfile.clone(),
                tfc.certfile.clone(),
                tfc.reload))
            .try_collect().await?;

        Ok(certs)
    }

    pub async fn run_indefinitely(&self) -> Result<()> {
        let certs = self.load_local_certs().await?;
        self.certstore.upsert_all(certs)?;

        let mut certwatcher = CertWatcher::new(self.certstore.clone(), self.context.clone());

        let acme = self.acme.clone();
        let acme_handle = tokio::spawn(async move {
            acme.run().await
        });

        let watcher_handle = tokio::spawn(async move {
            certwatcher.watch().await
        });

        try_join_all(vec![acme_handle, watcher_handle]).await?;

        Ok(())
    }

}
