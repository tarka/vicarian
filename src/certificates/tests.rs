#[path = "../../tests/utils/certs.rs"]
mod certutils;

use std::{
    fs,
    io::Write,
    sync::{Arc, LazyLock},
};

use anyhow::Result;
use boring::asn1::Asn1Time;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::TimeZone;
use tempfile::{NamedTempFile, tempdir};
use test_log::test;
use tracing_log::log::info;

use crate::{
    RunContext, certificates::{
        HostCertificate, acme::to_txt_name, asn1time_to_datetime, load_certs, store::CertStore, tests::certutils::LocalCert, watcher::{CertWatcher, RELOAD_GRACE}
    }, config::Config, errors::VicarianError
};

use certutils::TEST_CERTS;

// NOTE: Some of this sort-of overlaps with the integration-test utils
// in /tests/utils/certs.rs; may be worth merging at some point?

struct TestHostCerts {
    pub snakeoil_1: Arc<HostCertificate>,
    pub snakeoil_2: Arc<HostCertificate>,
    pub www_example: Arc<HostCertificate>,
    pub wildcard_example: Arc<HostCertificate>,
}

impl TestHostCerts {
    fn new() -> Result<Self> {
        let snakeoil_1 = from_localcert(&TEST_CERTS.snakeoil_1, true)?;
        let snakeoil_2 = from_localcert(&TEST_CERTS.snakeoil_2, true)?;
        let www_example = from_localcert(&TEST_CERTS.www_example, false)?;
        let wildcard_example = from_localcert(&TEST_CERTS.wildcard_example, false)?;

        Ok(Self {
            snakeoil_1,
            snakeoil_2,
            www_example,
            wildcard_example,
        })
    }
}

static TEST_HOST_CERTS: LazyLock<TestHostCerts> = LazyLock::new(|| TestHostCerts::new().unwrap());

fn from_localcert(lc: &LocalCert, watch: bool) -> Result<Arc<HostCertificate>> {
    let hc = futures::executor::block_on(
        HostCertificate::new(lc.keyfile.clone(),
                             lc.certfile.clone(),
                             watch))?;
    Ok(Arc::new(hc))
}

#[tokio::test]
async fn test_load_certs_valid_pair() -> Result<()> {
    let so = &TEST_HOST_CERTS.snakeoil_1;
    let result = load_certs(&so.keyfile, &so.certfile).await;
    assert!(result.is_ok());

    let (key, certs) = result.unwrap();
    assert!(!certs.is_empty());

    let cert_pubkey = certs[0].public_key()?;
    assert!(key.public_eq(&cert_pubkey));

    Ok(())
}

#[tokio::test]
async fn test_load_certs_invalid_pair() -> Result<()> {
    let so1 = TEST_HOST_CERTS.snakeoil_1.clone();
    let so2 = TEST_HOST_CERTS.snakeoil_2.clone();
    let key_path = &so1.keyfile;
    let other_cert_path = &so2.certfile;

    let result = load_certs(key_path, other_cert_path).await;
    assert!(result.is_err());
    let err: VicarianError = result.unwrap_err().downcast()?;
    assert!(matches!(err, VicarianError::CertificateMismatch(_, _)));

    Ok(())
}

#[tokio::test]
async fn test_load_certs_nonexistent_files() {
    let key_path = Utf8Path::new("nonexistent.key");
    let cert_path = Utf8Path::new("nonexistent.crt");

    let result = load_certs(key_path, cert_path).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_load_certs_empty_cert_file() -> Result<()> {
    let mut empty_cert_file = NamedTempFile::new()?;
    empty_cert_file.write_all(b"")?;
    let empty_cert_path = Utf8PathBuf::from(empty_cert_file.path().to_str().unwrap());

    let so1 = TEST_HOST_CERTS.snakeoil_1.clone();

    let result = load_certs(&so1.keyfile, &empty_cert_path).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No certificates found in TLS .crt file"));

    Ok(())
}


#[tokio::test]
#[test_log::test]
async fn test_cert_watcher_file_updates() -> Result<()> {
    let temp_dir = tempdir()?;
    let key_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("test.key")).unwrap();
    let cert_path = Utf8PathBuf::from_path_buf(temp_dir.path().join("test.crt")).unwrap();

    let context = Arc::new(RunContext::new(crate::config::Config::default()));

    let so1 = TEST_HOST_CERTS.snakeoil_1.clone();
    tokio::fs::copy(&so1.keyfile, &key_path).await?;
    tokio::fs::copy(&so1.certfile, &cert_path).await?;

    let hc = Arc::new(HostCertificate::new(key_path.clone(), cert_path.clone(), true).await?);
    let certs = vec![hc.clone()];
    let store = Arc::new(CertStore::new(certs, context.clone())?);
    let original_host = hc.hostnames[0].clone();

    let original_cert = store.by_host(&original_host).unwrap();
    let original_expiry = original_cert.certs[0].not_after().to_string();

    let mut watcher = CertWatcher::new(store.clone(), context.clone());

    // Start the watcher in a separate task
    let watcher_handle = tokio::spawn(async move {
        watcher.watch().await
    });

    // Wait for the watcher to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Update the files
    println!("Updating cert files");
    let so2 = TEST_HOST_CERTS.snakeoil_2.clone();
    tokio::fs::copy(&so2.keyfile, &key_path).await?;
    tokio::fs::copy(&so2.certfile, &cert_path).await?;

    // Wait for the watcher to process the event
    tokio::time::sleep(RELOAD_GRACE + std::time::Duration::from_millis(500)).await;

    info!("Checking updated certs");
    let updated_cert = store.by_host(&original_host).unwrap();
    let updated_expiry = updated_cert.certs[0].not_after().to_string();

    assert_ne!(original_expiry, updated_expiry);

    // Stop the watcher
    context.quit()?;
    watcher_handle.await??;

    Ok(())
}

#[tokio::test]
async fn test_by_host() {
    let cert = TEST_HOST_CERTS.snakeoil_1.clone();
    let certs = vec![cert.clone()];
    let context = Arc::new(RunContext::new(Config::default()));
    let store = CertStore::new(certs, context).unwrap();
    let found = store.by_host(&cert.hostnames[0]).unwrap();

    assert_eq!(found, cert);
}

#[tokio::test]
async fn test_by_file() {
    let cert = TEST_HOST_CERTS.snakeoil_1.clone();
    let certs = vec![cert.clone()];
    let context = Arc::new(RunContext::new(Config::default()));
    let store = CertStore::new(certs, context).unwrap();
    let found = store.by_file(&"target/certs/snakeoil-1.key".into()).unwrap();

    assert_eq!(found, cert);
}

#[tokio::test]
async fn test_watchlist() -> Result<()> {
    let hc1 = TEST_HOST_CERTS.snakeoil_1.clone();
    let hc2 = TEST_HOST_CERTS.www_example.clone();

    let context = Arc::new(RunContext::new(Config::default()));
    let certs = vec![hc1, hc2];
    let store = CertStore::new(certs, context)?;
    let watchlist = store.watchlist();

    assert_eq!(watchlist.len(), 2);
    assert!(watchlist.contains(&Utf8PathBuf::from("target/certs/snakeoil-1.key")));
    assert!(watchlist.contains(&Utf8PathBuf::from("target/certs/snakeoil-1.crt")));
    Ok(())
}

#[tokio::test]
async fn test_file_update_success() -> Result<()> {

    let temp_dir = tempdir()?;
    let key_path = temp_dir.path().join("test.key");
    let cert_path = temp_dir.path().join("test.crt");
    let cert = TEST_HOST_CERTS.snakeoil_1.clone();
    fs::copy(&cert.keyfile, &key_path)?;
    fs::copy(&cert.certfile, &cert_path)?;


    let certs = vec![cert.clone()];
    let context = Arc::new(RunContext::new(Config::default()));
    let store = CertStore::new(certs, context)?;
    let original_host = cert.hostnames[0].clone();

    // The original cert is snakeoil
    let first_cert = store.by_host(&original_host).unwrap();
    assert_eq!("snakeoil.example.com", first_cert.hostnames[0]);

    // Now update the files to snakeoil-2
    let cert = TEST_HOST_CERTS.snakeoil_2.clone();
    fs::copy(&cert.keyfile, &key_path)?;
    fs::copy(&cert.certfile, &cert_path)?;
    let newcert = Arc::new(HostCertificate::from(&first_cert).await?);

    store.update(newcert)?;

    let updated_cert_from_file = HostCertificate::new(
        Utf8PathBuf::from_path_buf(key_path).unwrap(),
        Utf8PathBuf::from_path_buf(cert_path).unwrap(),
        true
    ).await?;
    let new_host = updated_cert_from_file.hostnames[0].clone();

    // The store should have updated the certificate.
    let updated_cert_from_store = store.by_host(&new_host).expect("Cert not found for new host");
    assert_eq!(updated_cert_from_store.hostnames[0], new_host);

    // The old entry should not exist anymore if the host has changed.
    if original_host != new_host {
        assert!(store.by_host(&original_host).is_none(), "Old host entry should be removed");
    }

    Ok(())
}

#[test]
fn test_asn1time_to_datetime() -> Result<()> {
    let past = chrono::DateTime::parse_from_rfc3339("2023-01-01 00:00:00+00:00")? // Jan 1, 2023
        .timestamp();
    let asn1_time = Asn1Time::from_unix(past).expect("Failed to create ASN.1 time");
    let datetime = asn1time_to_datetime(asn1_time.as_ref()).expect("Failed to convert ASN.1 time");

    let expected = chrono::Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).single().expect("Invalid date");
    assert_eq!(datetime, expected);
    Ok(())
}

#[test]
fn test_asn1time_to_datetime_epoch() {
    // Test conversion of ASN.1 time at Unix epoch
    let asn1_time = Asn1Time::from_unix(0).expect("Failed to create ASN.1 time");
    let datetime = asn1time_to_datetime(asn1_time.as_ref()).expect("Failed to convert ASN.1 time");

    let expected = chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).single().expect("Invalid date");
    assert_eq!(datetime, expected);
}

#[test]
fn test_asn1time_to_datetime_future() -> Result<()> {
    let datetime = chrono::DateTime::parse_from_rfc3339("2038-01-19 03:14:07+00:00")? // Jan 1, 2023
        .timestamp();
    let asn1_time = Asn1Time::from_unix(datetime).expect("Failed to create ASN.1 time"); // Year 2038
    let datetime = asn1time_to_datetime(asn1_time.as_ref()).expect("Failed to convert ASN.1 time");

    let expected = chrono::Utc.with_ymd_and_hms(2038, 1, 19, 3, 14, 7).single().expect("Invalid date");
    assert_eq!(datetime, expected);

    Ok(())
}

#[test]
fn test_to_txt_name() {
    let domain = "example.com";

    assert_eq!("_acme-challenge.www", to_txt_name(domain, "www.example.com"));
    assert_eq!("_acme-challenge.www.dev", to_txt_name(domain, "www.dev.example.com"));
    assert_eq!("_acme-challenge", to_txt_name(domain, "example.com"));
    assert_eq!("_acme-challenge", to_txt_name(domain, "example.com."));
    assert_eq!("_acme-challenge", to_txt_name(domain, ""));

    assert_eq!("_acme-challenge", to_txt_name(domain, "*.example.com"));
    assert_eq!("_acme-challenge.dev", to_txt_name(domain, "*.dev.example.com"));

}

#[tokio::test]
async fn test_wildcard() -> Result<()> {
    let wildcard = TEST_HOST_CERTS.wildcard_example.clone();

    assert!(wildcard.hostnames.contains(&"*.example.com".to_string()));

    let context = Arc::new(RunContext::new(Config::default()));
    let store = CertStore::new(vec![wildcard.clone()], context)?;

    {
        let by_host = store.by_host(&"otherhost.example.com".to_string());
        assert!(by_host.is_none());
        let by_wildcard = store.by_wildcard("otherhost.example.com").unwrap();
        assert_eq!(Some(&"*.example.com".to_string()), by_wildcard.hostnames.first());
    }

    {
        let by_host = store.by_host(&"*.example.com".to_string()).unwrap();
        assert_eq!(Some(&"*.example.com".to_string()), by_host.hostnames.first());
        let by_wildcard = store.by_wildcard("realhost.example.com").unwrap();
        assert_eq!(Some(&"*.example.com".to_string()), by_wildcard.hostnames.first());
    }

    Ok(())
}
