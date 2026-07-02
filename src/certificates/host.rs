use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use camino::{Utf8Path, Utf8PathBuf};

use itertools::Itertools;
use pingora_rustls::{CertificateDer, CryptoProvider, PrivateKeyDer};
use rustls::{pki_types::pem::PemObject, sign::CertifiedKey};
use time::OffsetDateTime;
use tracing_log::log::info;
use x509_parser::{extensions::GeneralName, prelude::{FromDer, X509Certificate}};

use crate::errors::VicarianError;

pub type PrivateKey = PrivateKeyDer<'static>;
pub type Certificate = CertificateDer<'static>;

#[derive(Debug)]
pub struct HostCertificateInner {
    hostnames: Vec<String>,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    // Pingora Rustls expects an arc, so we double up here.
    cert: Arc<CertifiedKey>,
    hashkey: Vec<u8>,
    expires: OffsetDateTime,
    watch: bool,
}

impl HostCertificateInner {

    /// Load and check a public/private keypair & certs. Checks are
    /// performed, and Error::CertificateMismatch may be returned; as
    /// this may be expected (e.g. while certs are being updated) it
    /// should be checked for if necessary.
    pub async fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf, watch: bool) -> Result<Self> {
        let (key, certs) = load_hostcert(&keyfile, &certfile).await?;
        let hashkey = key.secret_der().to_owned();

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

        let expires = get_not_after(&x509)?;

        let crypto = CryptoProvider::get_default()
            .ok_or(anyhow!("Failed to find default crypto provider in rustls"))?;
        let cert = CertifiedKey::from_der(certs, key, crypto)
            .map_err(|e| match e {
                rustls::Error::InconsistentKeys(_) => {
                    VicarianError::CertificateMismatch(
                        keyfile.to_path_buf(),
                        certfile.to_path_buf())
                },
                _ => {
                    VicarianError::RustlsError(e)
                },
            })?;


        info!("Loaded certificate {:?}, expires {}", hostnames, expires);
        Ok(HostCertificateInner {
            hostnames,
            keyfile,
            certfile,
            cert: Arc::new(cert),
            hashkey,
            expires,
            watch,
        })
    }

}

/// A certificate and private key pair for a host.
///
/// This struct manages the lifecycle of a host certificate, including its
/// hostnames, private key, certificate chain, and expiration date.
///
/// `HostCertificate` uses an internal `Arc` to share the underlying certificate data.
/// Cloning a `HostCertificate` is a cheap operation that increments the reference count.
#[derive(Debug)]
pub struct HostCertificate {
    inner: Arc<HostCertificateInner>,
}


impl HostCertificate {

    /// Load and check a public/private keypair & certs. Checks are
    /// performed, and Error::CertificateMismatch may be returned; as
    /// this may be expected (e.g. while certs are being updated) it
    /// should be checked for if necessary.
    pub async fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf, watch: bool) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(HostCertificateInner::new(keyfile, certfile, watch).await?),
        })
    }

    /// Generates a fresh certificate from an existing one. This is
    /// effectively a reload.
    pub async fn from(hc: &HostCertificate) -> Result<HostCertificate> {
        HostCertificate::new(hc.keyfile().to_path_buf(), hc.certfile().to_path_buf(), hc.watch()).await
    }

    pub fn hostnames(&self) -> &[String] {
        &self.inner.hostnames
    }

    pub fn keyfile(&self) -> &Utf8Path {
        &self.inner.keyfile
    }

    // pub fn key(&self) -> &PKey<Private> {
    //     &self.inner.key
    // }

    pub fn certfile(&self) -> &Utf8Path {
        &self.inner.certfile
    }

    pub fn cert(&self) -> Arc<CertifiedKey> {
        self.inner.cert.clone()
    }

    pub fn expires(&self) -> &OffsetDateTime {
        &self.inner.expires
    }

    pub fn watch(&self) -> bool {
        self.inner.watch
    }
}

impl Clone for HostCertificate {
    /// Performs a cheap clone of the `HostCertificate` by incrementing the internal reference count.
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner)
        }
    }
}

// When parsing a certificate, validity dates are already available as Asn1DateTime
pub(crate) fn get_not_after(cert: &X509Certificate) -> Result<OffsetDateTime> {
    let validity = cert.validity();
    let not_after = validity.not_after.to_datetime();
    Ok(not_after)
}

impl PartialEq<HostCertificate> for HostCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.inner.hashkey == other.inner.hashkey
    }
}

impl Eq for HostCertificate {
}

impl Hash for HostCertificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hashkey.hash(state)
    }
}

pub(crate) async fn load_hostcert(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PrivateKey, Vec<Certificate>)> {
    let kdata = tokio::fs::read(keyfile).await
        .context("Failed to load keyfile {keyfile}")?;
    let cdata = tokio::fs::read(certfile).await
        .context("Failed to load certfile {certfile}")?;

    let key = PrivateKeyDer::from_pem_slice(&kdata)?;
    let certs = CertificateDer::pem_slice_iter(&cdata)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    Ok((key, certs))
}

// pub(crate) async fn load_hostcert(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PKey<Private>, Vec<X509>)> {
//     let kdata = tokio::fs::read(keyfile).await
//         .context("Failed to load keyfile {keyfile}")?;
//     let cdata = tokio::fs::read(certfile).await
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

//     Ok((key, certs))
// }
