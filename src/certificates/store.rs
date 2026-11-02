use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwap;
use camino::{Utf8Path, Utf8PathBuf};
use tracing::info;
use unicase::UniCase;

use crate::{
    RunContext,
    certificates::HostCertificate,
};

#[derive(Clone, Debug)]
pub struct CertStoreData {
    by_host: HashMap<UniCase<String>, HostCertificate>,
    by_file: HashMap<Utf8PathBuf, HostCertificate>,
}

#[derive(Debug)]
pub struct CertStore {
    data: ArcSwap<CertStoreData>,
}

impl CertStore {

    pub fn new(_context: Arc<RunContext>) -> Result<Self> {
        info!("Loading host certificates");

        let certstore = Self {
            data: ArcSwap::from_pointee(CertStoreData {
                by_host: HashMap::new(),
                by_file: HashMap::new(),
            }),
        };
        Ok(certstore)
    }

    pub fn by_host(&self, host: &str) -> Option<HostCertificate> {
        let host = UniCase::new(host.to_string());
        let data = self.data.load();
        data.by_host.get(&host)
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

    pub fn by_file(&self, file: &Utf8Path) -> Option<HostCertificate> {
        let data = self.data.load();
        data.by_file.get(file)
            .cloned()
    }

    pub fn upsert(&self, newcert: HostCertificate) -> Result<()> {
        self.data.rcu(|curr| {
            let new_by_host = newcert.hostnames().iter()
                .map(|h| (UniCase::new(h.clone()), newcert.clone()))
                .collect::<Vec<_>>();
            let new_by_file = [
                (newcert.keyfile().to_path_buf(), newcert.clone()),
                (newcert.certfile().to_path_buf(), newcert.clone()),
            ];

            let mut updated = (**curr).clone();
            updated.by_host.extend(new_by_host.clone());
            updated.by_file.extend(new_by_file.clone());
            updated
        });

        Ok(())
    }

    pub fn upsert_all(&self, newcerts: Vec<HostCertificate>) -> Result<()> {
        for hc in newcerts {
            self.upsert(hc)?;
        }
        Ok(())
    }

    pub fn watchlist(&self) -> Vec<Utf8PathBuf> {
        self.data.load().by_host
            .values()
            .filter(|h| h.watch())
            .flat_map(|h| [
                h.keyfile().to_path_buf(),
                h.certfile().to_path_buf()
            ])
            .collect()
    }

}
