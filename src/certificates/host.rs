use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use pingora_boringssl::x509::GeneralNameRef;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};

use itertools::Itertools;
use pingora_boringssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use time::OffsetDateTime;
use tracing_log::log::info;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::errors::VicarianError;

#[derive(Debug)]
pub struct HostCertificateInner {
    hostnames: Vec<String>,
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
    expires: DateTime<Utc>,
    watch: bool,
}

impl HostCertificateInner {

    /// Load and check a public/private keypair & certs. Checks are
    /// performed, and Error::CertificateMismatch may be returned; as
    /// this may be expected (e.g. while certs are being updated) it
    /// should be checked for if necessary.
    pub async fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf, watch: bool) -> Result<Self> {
        let (key, certs) = load_hostcert(&keyfile, &certfile).await?;

        let subject_p = certs[0].subject_name().entries().next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|os| os.to_string());

        let alts = certs[0].subject_alt_names();
        let aliases = alts.iter()
            .flatten()
            .filter_map(GeneralNameRef::dnsname)
            .map(str::to_owned);

        let hostnames: Vec<String> = subject_p.into_iter()
            .chain(aliases)
            .unique() // Subject may also appear in aliases
            .collect();

        let expires = get_not_after(certs[0].to_der()?.as_slice())?;

        info!("Loaded certificate {:?}, expires {}", hostnames, expires);
        Ok(HostCertificateInner {
            hostnames,
            keyfile,
            key,
            certfile,
            certs,
            expires,
            watch,
        })
    }

}

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

    pub fn key(&self) -> &PKey<Private> {
        &self.inner.key
    }

    pub fn certfile(&self) -> &Utf8Path {
        &self.inner.certfile
    }

    pub fn certs(&self) -> &[X509] {
        &self.inner.certs
    }

    pub fn expires(&self) -> &DateTime<Utc> {
        &self.inner.expires
    }

    pub fn watch(&self) -> bool {
        self.inner.watch
    }
}

pub fn offset_to_chrono(odt: OffsetDateTime) -> Result<DateTime<Utc>> {
    let secs = odt.unix_timestamp();
    let nanos = odt.nanosecond();

    DateTime::<Utc>::from_timestamp(secs, nanos)
        .ok_or(anyhow!("Failed to convert OffsetDateTime: {odt:?}"))

}

// When parsing a certificate, validity dates are already available as Asn1DateTime
pub(crate) fn get_not_after(der_data: &[u8]) -> Result<DateTime<Utc>> {
    let (_, cert) = X509Certificate::from_der(der_data)?;
    let validity = cert.validity();

    // Asn1DateTime has to_datetime() that returns chrono::DateTime<Utc>
    let not_after = offset_to_chrono(validity.not_after.to_datetime())?;

    Ok(not_after)
}

impl PartialEq<HostCertificate> for HostCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.certs()[0].signature().as_slice() == other.certs()[0].signature().as_slice()
    }
}

impl Eq for HostCertificate {
}

impl Hash for HostCertificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.certs()[0].signature().as_slice()
            .hash(state)
    }
}

pub(crate) async fn load_hostcert(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PKey<Private>, Vec<X509>)> {
    let kdata = tokio::fs::read(keyfile).await
        .context("Failed to load keyfile {keyfile}")?;
    let cdata = tokio::fs::read(certfile).await
        .context("Failed to load certfile {certfile}")?;

    let key = PKey::private_key_from_pem(&kdata)?;
    let certs = X509::stack_from_pem(&cdata)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    // Verify that the private key and cert match
    let cert_pubkey = certs[0].public_key()?;
    if !key.public_eq(&cert_pubkey) {
        let err = VicarianError::CertificateMismatch(
            keyfile.to_path_buf(),
            certfile.to_path_buf())
            .into();
        return Err(err)
    }

    Ok((key, certs))
}
