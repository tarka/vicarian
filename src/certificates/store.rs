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

type HostMapping = Vec<(UniCase<String>, HostCertificate)>;
type FileMapping = Vec<(Utf8PathBuf, HostCertificate)>;

fn to_host_map(newcert: &HostCertificate) -> HostMapping {
    newcert.hostnames().iter()
        .map(|h| (UniCase::new(h.clone()), newcert.clone()))
        .collect()
}

fn to_file_map(newcert: &HostCertificate) -> FileMapping {
    vec![
        (newcert.keyfile().to_path_buf(), newcert.clone()),
        (newcert.certfile().to_path_buf(), newcert.clone()),
    ]
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
        self.data.load().by_host
            .get(&host)
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

    fn rcu(&self, by_host: HostMapping, by_file: FileMapping) {
        self.data.rcu(|curr| {
            let mut updated = (**curr).clone();
            updated.by_host.extend(by_host.clone());
            updated.by_file.extend(by_file.clone());
            updated
        });
    }

    pub fn upsert(&self, newcert: HostCertificate) -> Result<()> {
        let new_by_host = to_host_map(&newcert);
        let new_by_file = to_file_map(&newcert);

        self.rcu(new_by_host, new_by_file);

        Ok(())
    }

    pub fn upsert_all(&self, newcerts: Vec<HostCertificate>) -> Result<()> {
        let new_by_host = newcerts.iter()
            .flat_map(to_host_map)
            .collect();
        let new_by_file = newcerts.iter()
            .flat_map(to_file_map)
            .collect();

        self.rcu(new_by_host, new_by_file);

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
