mod cli;
mod hcl;

#[cfg(test)]
mod tests;

use std::{net::{IpAddr, SocketAddr, SocketAddrV6}};

use anyhow::{Context, Result, anyhow};
use camino::Utf8PathBuf;

use itertools::Itertools;
use nix::sys::socket::SockaddrStorage;
use serde::{Deserialize, Deserializer};

pub use cli::CliOptions;

// Ideally we should define internal structs here and specialised
// deserialisers in hcl.rs, however YAGNE applies so we just re-export
// the deserialised types.
pub use hcl::{
    Config,
    AcmeChallenge,
    DnsProvider,
    TlsConfig,
    Backend,
    Vhost,
    BackendType,
    StaticBackend,
    ProxyBackend,
    TlsAcmeConfig,
};

pub const DEFAULT_CONFIG_FILE: &str = "/etc/vicarian/vicarian.hcl";

const SPECIAL_ADDRESS_DELIMITER: char = '#';
const SPECIAL_ADDRESS_INTERFACE: &str = "if";

// pub for tests
pub trait ValidateSanitise: Sized {
    fn validate_and_sanitise(self) -> Result<Self>;
}

fn deserialize_canonical<'de, D>(deserializer: D) -> std::result::Result<Utf8PathBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let path = Utf8PathBuf::deserialize(deserializer)?;
    // Attempt to turn into full path, but use the short version otherwise.
    let cpath = path.canonicalize_utf8()
        .unwrap_or(path);
    Ok(cpath)
}


fn strip_trailing_slashes(s: String) -> String {
    if s.len() > 1 {
        s.trim_end_matches('/').to_string()
    } else {
        s
    }
}

fn default_path() -> String {
    "/".to_string()
}

fn validate_path(s: &String) -> Result<()> {
    s.starts_with('/').then_some(())
        .ok_or(anyhow!("No leading slash in context path: {s}"))?;
    (!s.is_empty()).then_some(())
        .ok_or(anyhow!("Context path cannot be empty"))?;

    Ok(())
}


fn strip_brackets(before: &str) -> &str {
    before.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(before)
}

fn to_sockaddr(addr: Option<SockaddrStorage>) -> Option<SocketAddr> {
    let in_addr = addr?;
    if let Some(sai) = in_addr.as_sockaddr_in() {
        Some(SocketAddr::new(sai.ip().into(), 0))

    } else if let Some(sai6) = in_addr.as_sockaddr_in6() {
        let ip6 = SocketAddrV6::new(sai6.ip(), 0,
                                    sai6.flowinfo(),
                                    sai6.scope_id());
        Some(ip6.into())

    } else {
        None
    }
}

pub(crate) fn expand_listen_addrs(addrs: &[String]) -> Result<Vec<SocketAddr>> {
    let ips = addrs.iter()
        .map(|addr_str| {
            if let Some((pref, body)) = addr_str.split_once(SPECIAL_ADDRESS_DELIMITER) {
                match pref {
                    SPECIAL_ADDRESS_INTERFACE => get_if_addrs(body),
                    _ => Err(anyhow!("Unexpected address prefix: {pref}"))
                }
            } else {
                let addr = strip_brackets(addr_str);
                let addr: IpAddr = addr.parse()
                    .context(format!("Parsing listening address {addr_str}"))?;
                let sock = SocketAddr::new(addr, 0);
                Ok(vec![sock])
            }
        })
        .collect::<Result<Vec<Vec<SocketAddr>>>>()?
        .into_iter()
        .flatten()
        .unique()
        .collect();

    Ok(ips)
}


fn get_if_addrs(ifname: &str) -> Result<Vec<SocketAddr>> {
    let addrs = nix::ifaddrs::getifaddrs()?;
    let ifaddrs = addrs
        .filter(|ifaddr| ifaddr.interface_name == ifname)
        .filter_map(|ifaddr| to_sockaddr(ifaddr.address))
        .collect();

    Ok(ifaddrs)
}
