pub mod acme;
pub mod external;
pub mod handler;
pub mod store;
pub mod watcher;
#[cfg(test)]
mod tests;

use std::{
    fs, hash::{Hash, Hasher}, iter, sync::Arc
};

use anyhow::{anyhow, bail, Context, Result};
// use boring::{
//     asn1::{Asn1Time, Asn1TimeRef},
//     x509::GeneralNameRef,
// };
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, TimeDelta, Utc};

use futures::future::try_join_all;
use itertools::Itertools;
use rustls::{crypto::CryptoProvider, sign::CertifiedKey};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
// use pingora_boringssl::{
//     pkey::{PKey, Private},
//     x509::X509,
// };
use tracing_log::log::info;
use x509_parser::{prelude::{FromDer, GeneralName, X509Certificate}, time::ASN1Time};

use crate::{
    RunContext,
    certificates::{acme::AcmeRuntime, store::CertStore, watcher::CertWatcher},
    errors::VicarianError,
};

pub type PrivateKey = PrivateKeyDer<'static>;
pub type Certificate = CertificateDer<'static>;

#[derive(Debug)]
pub struct HostCertificate {
    hostnames: Vec<String>,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    pub(crate) expires: DateTime<Utc>,
    watch: bool,
    cert: Arc<CertifiedKey>,
    // key: PKey<Private>,
    // certs: Vec<X509>,
}

impl HostCertificate {

    /// Load and check a public/private keypair & certs. Checks are
    /// performed, and Error::CertificateMismatch may be returned; as
    /// this may be expected (e.g. while certs are being updated) it
    /// should be checked for if necessary.
    pub fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf, watch: bool) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        let cert0 = certs[0].clone();
        let (_, x509) = X509Certificate::from_der(&cert0)?;

        let subject = x509.subject()
            .iter_common_name()
            .filter_map(|cn| cn.as_str().ok())
            .map(str::to_string)
            .collect::<Vec<String>>();

        let aliases = x509.subject_alternative_name()?
            .map(|sans| sans.value.general_names.iter())
            .unwrap_or(Vec::new().iter())
            .filter_map(|gn| match gn {
                GeneralName::DNSName(san) => Some(san.to_string()),
                _ => None,
            })
            .collect_vec();

        let hostnames: Vec<String> = subject.into_iter()
            .chain(aliases)
            .unique() // Subject may also appear in aliases
            .collect();

        let crypto = CryptoProvider::get_default()
            .ok_or(anyhow!("Failed to find default crypto provider in rustls"))?;
        let cert = Arc::new(CertifiedKey::from_der(certs, key, crypto)?);
        cert.keys_match()?;

        let expires = asn1time_to_datetime(&x509.validity.not_after)?;

        info!("Loaded certificate {:?}, expires {}", hostnames, expires);
        Ok(HostCertificate {
            hostnames,
            keyfile,
            certfile,
            cert,
            expires,
            watch,
        })
    }

    /// Generates a fresh certificate from an existing one. This is
    /// effectively a reload.
    pub fn from(hc: &Arc<HostCertificate>) -> Result<HostCertificate> {
        HostCertificate::new(hc.keyfile.clone(), hc.certfile.clone(), hc.watch)
    }

    pub fn expires_in_secs(&self) -> i64 {
        let now = Utc::now();
        let diff = self.expires - now;
        diff.num_seconds()
    }

    pub fn is_expiring_in_secs(&self, secs: i64) -> bool {
        let in_secs = Utc::now() + TimeDelta::seconds(secs);
        in_secs >= self.expires
    }
}

impl PartialEq<HostCertificate> for HostCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.cert.cert[0] == other.cert.cert[0]
    }
}

impl Eq for HostCertificate {
}

impl Hash for HostCertificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cert.cert.hash(state)
    }
}


fn asn1time_to_datetime(asn1: &ASN1Time) -> Result<DateTime<Utc>> {
    let secs = asn1.to_datetime().to_utc().unix_timestamp();
    let datetime = DateTime::<Utc>::from_timestamp(secs, 0)
        .ok_or(anyhow!("Failed to create DateTime from timestamp"))?;
    Ok(datetime)
}


fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PrivateKey, Vec<Certificate>)> {
    let key = PrivateKeyDer::from_pem_file(keyfile.to_path_buf())?;
    let certs = CertificateDer::pem_file_iter(certfile.to_path_buf())?
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    Ok((key, certs))
}

// fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PKey<Private>, Vec<X509>)> {
//     let kdata = fs::read(keyfile)
//         .context("Failed to load keyfile {keyfile}")?;
//     let cdata = fs::read(certfile)
//         .context("Failed to load certfile {certfile}")?;

//     let key = PKey::private_key_from_pem(&kdata)?;
//     let certs = X509::stack_from_pem(&cdata)?;
//     if certs.is_empty() {
//         bail!("No certificates found in TLS .crt file");
//     }

//     // Verify that the private key and cert match
//     let cert_pubkey = certs[0].public_key()?;
//     if !key.public_eq(&cert_pubkey) {
//         let err = VicarianError::CertificateMismatch(
//             keyfile.to_path_buf(),
//             certfile.to_path_buf())
//             .into();
//         return Err(err)
//     }

//     OK((key, certs))
// }


pub async fn run_indefinitely(certstore: Arc<CertStore>, acme: Arc<AcmeRuntime>, context: Arc<RunContext>) -> Result<()> {
    let acme_handle = tokio::spawn(async move {
        acme.run().await
    });

    let mut certwatcher = CertWatcher::new(certstore.clone(), context.clone());
    let watcher_handle = tokio::spawn(async move {
        certwatcher.watch().await
    });

    try_join_all(vec![acme_handle, watcher_handle]).await?;

    Ok(())
}
