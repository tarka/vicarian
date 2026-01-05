#![allow(unused)]

use std::{fs::{self, create_dir_all}, sync::LazyLock};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use fslock::LockFile;
use pingora_boringssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

pub const CERT_BASE: &'static str = "target/certs";

fn lock_dir(dir: &Utf8Path) -> Result<LockFile> {
    let _ = create_dir_all(&dir); // Ignore errs
    let lockfile = dir.with_extension(".lock");
    Ok(LockFile::open(lockfile.as_os_str())?)
}

pub struct CaCert {
    pub issuer: Issuer<'static, KeyPair>,
    pub cert: reqwest::Certificate,
}

pub struct LocalCert {
    pub keyfile: Utf8PathBuf,
    pub key: PKey<Private>,
    pub certfile: Utf8PathBuf,
    pub certs: Vec<X509>,
}

fn gen_ca() -> Result<CaCert> {
    let mut params = CertificateParams::default();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CountryName, "AU");
    params.distinguished_name.push(DnType::OrganizationName, "Haltcondition CA");

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose ::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let key = key_pair.serialize_pem();

    let cert = params.self_signed(&key_pair)?;
    let issuer = Issuer::new(params, key_pair);

    let certdir = Utf8PathBuf::from(CERT_BASE);
    let certfile = certdir.join("CA.crt");
    let cakey = certdir.join("CA.key");

    let certpem = cert.pem();

    fs::write(&certfile, &certpem)?;
    fs::write(&cakey, &key)?;

    let reqcert = reqwest::Certificate::from_pem(certpem.as_bytes())?;

    let cacert = CaCert {
        cert: reqcert,
        issuer,
    };

    Ok(cacert)
}

fn load_ca(certfile: Utf8PathBuf, cakey: Utf8PathBuf) -> Result<CaCert> {
    let keypem = String::from_utf8(fs::read(&cakey)?)?;
    let key = KeyPair::from_pem(&keypem)?;
    let capem = String::from_utf8(fs::read(&certfile)?)?;
    let issuer = Issuer::from_ca_cert_pem(&capem, key)?;

    let reqcert = reqwest::Certificate::from_pem(capem.as_bytes())?;

    let cacert = CaCert {
        issuer,
        cert: reqcert,
    };

    Ok(cacert)
}

fn get_root_ca() -> Result<CaCert> {
    let certdir = Utf8PathBuf::from(CERT_BASE);
    let cafile = certdir.join("CA.crt");
    let cakey = certdir.join("CA.key");

    let mut lock = lock_dir(&certdir)?;
    lock.lock()?;

    let issuer = if cafile.exists() && cakey.exists() {
        lock.unlock()?;
        load_ca(cafile, cakey)?

    } else {
        let ca = gen_ca()?;
        lock.unlock()?;

        ca
    };

    Ok(issuer)
}

fn gen_cert(host: &str, ca: &CaCert) -> Result<()>
{
    let base = Utf8PathBuf::try_from(CERT_BASE)?;
    let keyfile = base.join(host).with_added_extension("key");
    let certfile = base.join(host).with_added_extension("crt");

    let sans = vec![host.to_string()];

    let keypair = KeyPair::generate()?;
    let mut params = CertificateParams::new(sans)?;
    params.distinguished_name = DistinguishedName::new();

    let cert = params.signed_by(&keypair, &ca.issuer)?;

    let cert_pem = cert.pem();
    let key_pem = keypair.serialize_pem();

    std::fs::write(&keyfile, &key_pem)?;
    std::fs::write(&certfile, &cert_pem)?;

    Ok(())
}

fn load_cert(keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<LocalCert> {
    let kdata = fs::read(&keyfile)
        .context("Failed to load keyfile {keyfile}")?;
    let cdata = fs::read(&certfile)
        .context("Failed to load certfile {certfile}")?;

    let key = PKey::private_key_from_pem(&kdata)?;
    let certs = X509::stack_from_pem(&cdata)?;
    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }

    let lc = LocalCert {
            keyfile,
            certfile,
            key,
            certs,
        };

    Ok(lc)
}

fn get_cert(host: &str, ca: &CaCert) -> Result<LocalCert> {
    let certdir = Utf8PathBuf::from(CERT_BASE);
    let certfile = certdir.join(host).with_added_extension("crt");
    let keyfile = certdir.join(host).with_added_extension("key");

    let mut lock = lock_dir(&certdir)?;
    lock.lock()?;

    let localcert = if certfile.exists() && keyfile.exists() {
        lock.unlock()?;
        load_cert(keyfile, certfile)?

    } else {
        gen_cert(host, ca)?;
        load_cert(keyfile, certfile)?

    };

    Ok(localcert)
}

pub struct TestCerts {
    pub caroot: CaCert,
    pub www_example: LocalCert,
}

impl TestCerts {
    fn new() -> Result<Self> {
        create_dir_all(CERT_BASE)?;

        let caroot = get_root_ca()?;
        let www_example = get_cert("www.example.com", &caroot)?;

        Ok(Self {
            caroot,
            www_example,
        })
    }
}

pub static TEST_CERTS: LazyLock<TestCerts> = LazyLock::new(|| TestCerts::new().unwrap());

