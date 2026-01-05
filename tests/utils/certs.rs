
use std::{
    fs::create_dir_all,
    io::Write,
    sync::LazyLock
};

use anyhow::Result;
use boring::asn1::Asn1Time;
use chrono::TimeZone;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use tempfile::{NamedTempFile, tempdir};

pub const CERT_BASE: &'static str = "target/certs";

// // Common test utils
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

