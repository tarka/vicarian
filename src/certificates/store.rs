use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;
use papaya::HashMap as Papaya;
use tracing::info;

use crate::{
    RunContext,
    certificates::HostCertificate,
    errors::Error,
};


// TODO: We currently use papaya to store lookup tables for multiple
// server support. However we don't actually support multiple servers
// in the config at the moment. This may change, so this is left in
// place for now.
//
// TODO: It _might_ be possible to return references rather than Arcs
// here, which would enforce the store as being the source of
// truth. But a bit fiddly for MVP version.
#[derive(Debug)]
pub struct CertStore {
    _context: Arc<RunContext>,
    by_host: Papaya<String, HostCertificate>,
    by_file: Papaya<Utf8PathBuf, HostCertificate>,
}

impl CertStore {

    pub fn new(_context: Arc<RunContext>) -> Result<Self> {
        info!("Loading host certificates");

        let certstore = Self {
            _context,
            by_host: Papaya::new(),
            by_file: Papaya::new(),
        };
        Ok(certstore)
    }

    pub fn by_host(&self, host: &str) -> Option<HostCertificate> {
        let pmap = self.by_host.pin();
        pmap.get(&host.to_lowercase())
            .cloned()
    }

    /// Takes a host and returns a matching wildcard, if any.
    pub fn by_wildcard(&self, host: &str) -> Option<HostCertificate> {
        host.split_once('.')
            .and_then(|(_host, domain)| {
                let wildcard = format!("*.{domain}");
                self.by_host(&wildcard)
            })

    }

    pub fn by_file(&self, file: &Utf8PathBuf) -> Option<HostCertificate> {
        let pmap = self.by_file.pin();
        pmap.get(file)
            .cloned()
    }

    pub fn upsert(&self, newcert: HostCertificate) -> Result<()> {
        for hostname in newcert.hostnames().iter() {
            let host = hostname.clone();

            info!("Updating/inserting certificate for {host}");
            self.by_host.pin().update_or_insert(host, |_old| newcert.clone(), newcert.clone());
        }

        let keyfile = newcert.keyfile().to_path_buf();
        let certfile = newcert.certfile().to_path_buf();
        let by_file = self.by_file.pin();
        by_file.update_or_insert(keyfile, |_old| newcert.clone(), newcert.clone());
        by_file.update_or_insert(certfile, |_old| newcert.clone(), newcert.clone());

        Ok(())
    }

    pub fn upsert_all(&self, newcerts: Vec<HostCertificate>) -> Result<()> {
        for hc in newcerts {
            self.upsert(hc)?;
        }
        Ok(())
    }

    pub fn update(&self, newcert: HostCertificate) -> Result<()> {
        for hostname in newcert.hostnames().iter() {
            info!("Updating certificate for {hostname}");
            self.by_host.pin().update(hostname.clone(), |_old| newcert.clone())
                .ok_or_else(|| Error::HostNotFoundInCertStore(hostname.clone()))?;
        }

        let keyfile = newcert.keyfile().to_path_buf();
        let certfile = newcert.certfile().to_path_buf();
        let by_file = self.by_file.pin();
        by_file.update(keyfile.clone(), |_old| newcert.clone())
            .ok_or_else(|| Error::FileNotFoundInCertStore(keyfile))?;
        by_file.update(certfile.clone(), |_old| newcert.clone())
            .ok_or_else(|| Error::FileNotFoundInCertStore(certfile))?;

        Ok(())
    }

    pub fn watchlist(&self) -> Vec<Utf8PathBuf> {
        let by_host = self.by_host.pin();
        by_host.values()
            .filter_map(|h| if h.watch() {
                Some(vec![h.keyfile().to_path_buf(), h.certfile().to_path_buf()])
            } else {
                None
            })
            .flatten()
            .collect()
    }

}
