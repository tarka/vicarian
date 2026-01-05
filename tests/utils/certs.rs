
use std::{fs::{self, create_dir_all}};

use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use fslock::LockFile;
use pingora_boringssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256
};

pub const CERT_BASE: &'static str = "target/certs";

fn lock_dir(dir: &Utf8Path) -> Result<LockFile> {
    let _ = create_dir_all(&dir); // Ignore errs
    let lockfile = dir.with_extension(".lock");
    Ok(LockFile::open(lockfile.as_os_str())?)
}

struct Ca {
    cert: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

fn gen_ca() -> Result<Ca> {
    let mut params = CertificateParams::default();

    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CountryName, "AU");
    params.distinguished_name.push(DnType::OrganizationName, "Haltcondition CA");

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose ::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let cert = params.self_signed(&key_pair)?;
    let issuer = Issuer::new(params, key_pair);

    let ca = Ca {
        cert, issuer,
    };

    Ok(ca)
}

fn load_ca(cafile: &Utf8Path, cakey: &Utf8Path) -> Result<Issuer<'static, KeyPair>> {
    let keypem = String::from_utf8(fs::read(&cakey)?)?;
    let key = KeyPair::from_pem(&keypem)?;
    let capem = String::from_utf8(fs::read(&cafile)?)?;
    let issuer = Issuer::from_ca_cert_pem(&capem, key)?;
    Ok(issuer)
}

fn get_root_ca() -> Result<Issuer<'static, KeyPair>> {
    let certdir = Utf8PathBuf::from(CERT_BASE);
    let cafile = certdir.join("CA.crt");
    let cakey = certdir.join("CA.key");

    let mut lock = lock_dir(&certdir)?;
    lock.lock()?;

    let issuer = if cafile.exists() && cakey.exists() {
        lock.unlock()?;

        load_ca(&cafile, &cakey)?


    } else {
        let ca = gen_ca()?;
        let crt = ca.cert.pem();
        let key = ca.issuer.key().serialize_pem();
        fs::write(&cafile, &crt)?;
        fs::write(&cakey, &key)?;
        lock.unlock()?;

        ca.issuer
    };

    Ok(issuer)
}

fn gen_cert(host: &str,
            name: &str,
            ca: &CertifiedIssuer<'static, KeyPair>)
            -> Result<()>
{
    let base = Utf8PathBuf::try_from(CERT_BASE)?;
    let keyfile = base.join(name).with_extension("key");
    let certfile = base.join(name).with_extension("crt");

    if ! (keyfile.exists() && certfile.exists()) {
        let sans = vec![host.to_string()];

	let keypair = KeyPair::generate()?;
	let mut params = CertificateParams::new(sans)?;
        params.distinguished_name = DistinguishedName::new();

        //let cert = params.self_signed(&keypair)?;
        let cert = params.signed_by(&keypair, &ca)?;

        let cert_pem = cert.pem();
        let key_pem = keypair.serialize_pem();

        std::fs::write(&keyfile, &key_pem)?;
        std::fs::write(&certfile, &cert_pem)?;
    }

    Ok(())
}

struct LocalCert {
    keyfile: Utf8PathBuf,
    key: PKey<Private>,
    certfile: Utf8PathBuf,
    certs: Vec<X509>,
}

struct TestCerts {
    pub root: CertifiedIssuer<'static, KeyPair>,
    pub www_example: LocalCert,
}

// impl TestCerts {
//     pub fn new() -> Self {
//     }
// }



// fn test_cert(key: &str, cert: &str, watch: bool) -> HostCertificate {
//     let keyfile = Utf8PathBuf::from(key);
//     let certfile = Utf8PathBuf::from(cert);
//     HostCertificate::new(keyfile, certfile, watch)
//         .expect("Failed to create test HostCertificate")
// }















// struct TestCerts {
//     pub vicarian_ss1: Arc<HostCertificate>,
//     pub vicarian_ss2: Arc<HostCertificate>,
//     pub www_ss: Arc<HostCertificate>,
// }

// pub static TEST_CERTS: LazyLock<TestCerts> = LazyLock::new(|| TestCerts::new().unwrap());


// impl TestCerts {
//     fn new() -> Result<Self> {
//         create_dir_all(CERT_BASE)?;

//         let vicarian_ss1 = {
//             let not_before = time::OffsetDateTime::now_utc();
//             let not_after = not_before.clone()
//                 .checked_add(time::Duration::days(365)).unwrap();

//             let host = "vicarian.example.com";
//             let name = "snakeoil-1";

//             gen_cert(host, name, true, not_before, not_after)?
//         };

//         let vicarian_ss2 = {
//             let host = "vicarian.example.com";
//             let name = "snakeoil-2";
//             let not_before = time::OffsetDateTime::now_utc();
//             let not_after = not_before.clone()
//                 .checked_add(time::Duration::days(720)).unwrap();
//             gen_cert(host, name, true, not_before, not_after)?
//         };

//         let www_ss = {
//             let not_before = time::OffsetDateTime::now_utc();
//             let not_after = not_before.clone()
//                 .checked_add(time::Duration::days(720)).unwrap();
//             let name = "www.example.com";
//             gen_cert(name, name, false, not_before, not_after)?
//         };

//         Ok(Self {
//             vicarian_ss1,
//             vicarian_ss2,
//             www_ss,
//         })
//     }
// }

// fn gen_cert(host: &str,
//             name: &str,
//             watch: bool,
//             not_before: time::OffsetDateTime,
//             not_after: time::OffsetDateTime)
//             -> Result<Arc<HostCertificate>>
// {
//     let base = Utf8PathBuf::try_from(CERT_BASE)?;
//     let keyfile = base.join(name).with_extension("key");
//     let certfile = base.join(name).with_extension("crt");

//     if ! (keyfile.exists() && certfile.exists()) {
//         let sans = vec![host.to_string()];

// 	let key = KeyPair::generate()?;
// 	let mut params = CertificateParams::new(sans)?;
//         params.distinguished_name = DistinguishedName::new();
//         params.not_before = not_before;
//         params.not_after = not_after;

//         let cert = params.self_signed(&key)?;

//         let cert_pem = cert.pem();
//         let key_pem = key.serialize_pem();

//         std::fs::write(&keyfile, &key_pem)?;
//         std::fs::write(&certfile, &cert_pem)?;

//     }

//     let host_certificate = HostCertificate::new(keyfile, certfile, watch)?;

//     Ok(Arc::new(host_certificate))
// }
