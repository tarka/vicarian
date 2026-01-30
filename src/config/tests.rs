use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

#[test]
fn test_tls_files_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-tls-files.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    assert_eq!(8443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Files(
        TlsFilesConfig {
            keyfile: _,  // FIXME: Match Utf8PathBuf?
            certfile: _,
            reload: true,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_dns01_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-dns01.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Acme(
        TlsAcmeConfig {
            contact: _,
            acme_provider: AcmeProvider::LetsEncrypt,
            directory: _,
            challenge: AcmeChallenge::Dns01(DnsProvider {
                wildcard: false,
                dns_provider: zone_update::Provider::PorkBun(_)
            }),
            profile: AcmeProfile::TlsServer,
        })));

    assert_eq!("/", config.vhosts[0].backends[0].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_http01_example_config() -> Result<()> {
    let file = Utf8PathBuf::from("examples/vicarian-http01.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("www.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Acme(
        TlsAcmeConfig {
            contact: _,
            acme_provider: AcmeProvider::LetsEncrypt,
            directory: _,
            challenge: AcmeChallenge::Http01,
            profile: AcmeProfile::ShortLived,
        })));

    assert_eq!("/copyparty", config.vhosts[0].backends[1].context.as_ref().unwrap());

    Ok(())
}

#[test]
fn test_wildcard_example_config() -> Result<()> {
    unsafe {
        std::env::set_var("DNS_KEY", "my-key");
        std::env::set_var("DNS_SECRET", "my-secret");
    }
    let file = Utf8PathBuf::from("examples/vicarian-wildcard-tls.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("files.example.com", config.vhosts[0].hostname);

    Ok(())
}

#[test]
fn test_no_optionals() -> Result<()> {
    let file = Utf8PathBuf::from("tests/data/config/no-optionals.corn");
    let config = Config::from_file(&file)?;
    assert_eq!("host01.example.com", config.vhosts[0].hostname);

    assert_eq!(443, config.listen.tls_port);
    assert!(matches!(&config.vhosts[0].tls, TlsConfig::Files(
        TlsFilesConfig {
            keyfile: _,
            certfile: _,
            reload: true,
        })));

    Ok(())
}

#[test]
fn test_extract_files() -> Result<()> {
    let file = Utf8PathBuf::from("tests/data/config/no-optionals.corn");
    let config = Config::from_file(&file)?;


    let files = if let TlsConfig::Files(tfc) = &config.vhosts[0].tls {
        tfc
    } else {
        panic!("Expected TLS files");
    };
    assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.key"), files.keyfile);
    assert_eq!(Utf8PathBuf::from("/etc/ssl/certs/host01.example.com.crt"), files.certfile);
    assert!(files.reload);

    Ok(())
}


// #[test]
// fn test_get_if_addr() -> Result<()> {
//     let ifname = "lo";

//     let v4: IpAddr = Ipv4Addr::LOCALHOST.into();
//     let v6: IpAddr = Ipv6Addr::LOCALHOST.into();

//     let addrs = get_if_addrs(ifname)?;
//     assert_eq!(2, addrs.len());

//     assert!(addrs.contains(&v4));
//     assert!(addrs.contains(&v6));

//     Ok(())
// }

// #[test]
// fn test_get_if_expansion() -> Result<()> {
//     let addrs = vec!["if#lo".to_string()];

//     let v4: IpAddr = Ipv4Addr::LOCALHOST.into();
//     let v6: IpAddr = Ipv6Addr::LOCALHOST.into();

//     let ips = expand_listen_addrs(&addrs)?;

//     assert_eq!(2, ips.len());

//     assert!(ips.contains(&v4));
//     assert!(ips.contains(&v6));

//     Ok(())
// }

// #[test]
// fn test_get_mixed_if_expansion() -> Result<()> {
//     let addrs = vec![
//         "if#lo".to_string(),
//         "10.1.1.1".to_string(),
//         "[fc00::1]".to_string(),
//     ];

//     let v4: IpAddr = Ipv4Addr::LOCALHOST.into();
//     let v6: IpAddr = Ipv6Addr::LOCALHOST.into();
//     let ten: IpAddr = Ipv4Addr::new(10,1,1,1).into();
//     let fc00: IpAddr = Ipv6Addr::new(0xfc00,0,0,0,0,0,0,1).into();

//     let ips = expand_listen_addrs(&addrs)?;
//     assert_eq!(4, ips.len());

//     assert!(ips.contains(&v4));
//     assert!(ips.contains(&v6));
//     assert!(ips.contains(&ten));
//     assert!(ips.contains(&fc00));

//     Ok(())
// }

// #[test]
// fn test_collapse_dups() -> Result<()> {
//     let addrs = vec![
//         "if#lo".to_string(),
//         "10.1.1.1".to_string(),
//         "::1".to_string(),
//     ];

//     let v4: IpAddr = Ipv4Addr::LOCALHOST.into();
//     let v6: IpAddr = Ipv6Addr::LOCALHOST.into();
//     let ten: IpAddr = Ipv4Addr::new(10,1,1,1).into();

//     let ips = expand_listen_addrs(&addrs)?;
//     assert_eq!(3, ips.len());

//     assert!(ips.contains(&v4));
//     assert!(ips.contains(&v6));
//     assert!(ips.contains(&ten));

//     Ok(())
// }

#[test]
fn test_get_invalid_prefix() -> Result<()> {
    let addrs = vec![
        "if#lo".to_string(),
        "10.1.1.1".to_string(),
        "typo#eth0".to_string(),
        "[fc00::1]".to_string(),
    ];
    let result = expand_listen_addrs(&addrs);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_strip_brackets() {
    assert_eq!("192.168.1.1", strip_brackets("192.168.1.1"));
    assert_eq!("::1", strip_brackets("[::1]"));
    assert_eq!("2001:db8::1", strip_brackets("[2001:db8::1]"));
    assert_eq!("[invalid", strip_brackets("[invalid"));
}
