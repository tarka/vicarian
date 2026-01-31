#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr, SocketAddrV6, ToSocketAddrs};

use anyhow::{Context, Result, anyhow};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{ArgAction, Parser};
use http::Uri;
use itertools::Itertools;
use nix::sys::socket::SockaddrStorage;
use serde::{Deserialize, Deserializer};
use serde_default_utils::{default_bool, serde_inline_default};
use strum_macros::IntoStaticStr;
use tracing_log::log::info;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "vicarian",
    about = "A reverse proxy.",
    version,
)]
pub struct CliOptions {
    /// Verbosity.
    ///
    /// Can be specified multiple times to increase logging.
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Config file
    ///
    /// Override the config file location
    #[arg(short = 'c', long)]
    pub config: Option<Utf8PathBuf>,
}

impl CliOptions {
    pub fn from_args() -> CliOptions {
        CliOptions::parse()
    }
}

pub const DEFAULT_CONFIG_FILE: &str = "/etc/vicarian/vicarian.corn";

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

#[derive(Copy, Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    #[default]
    LetsEncrypt,
    // TODO:
    // ZeroSsl,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AcmeProfile {
    ShortLived,
    #[default]
    TlsServer,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DnsProvider {
    #[serde(default = "default_bool::<false>")]
    pub wildcard: bool,
    pub dns_provider: zone_update::Provider,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum AcmeChallenge {
    #[serde(rename = "dns-01")]
    Dns01(DnsProvider),
    #[serde(rename = "http-01")]
    Http01,
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsAcmeConfig {
    #[serde(default)]
    pub acme_provider: AcmeProvider,
    pub challenge: AcmeChallenge,
    // TODO: Need a method to default Utf8PathBuf here.
    #[serde_inline_default("/var/lib/vicarian/acme".to_string())]
    pub directory: String,
    pub contact: String,
    #[serde(default)]
    pub profile: AcmeProfile,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFilesConfig {
    #[serde(deserialize_with = "deserialize_canonical")]
    pub keyfile: Utf8PathBuf,
    #[serde(deserialize_with = "deserialize_canonical")]
    pub certfile: Utf8PathBuf,
    #[serde(default = "default_bool::<true>")]
    pub reload: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum TlsConfig {
    Files(TlsFilesConfig),
    Acme(TlsAcmeConfig),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub context: Option<String>,
    #[serde(with = "http_serde::uri")]
    pub url: Uri,
    #[serde(default = "default_bool::<false>")]
    pub trust: bool,
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vhost {
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain.
    pub hostname: String,
    #[serde_inline_default(Vec::new())]
    pub aliases: Vec<String>,
    #[serde_inline_default("[::]".to_string())]
    pub listen: String,
    pub tls: TlsConfig,
    pub backends: Vec<Backend>,
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    addrs: Vec<String>,
    pub insecure_port: Option<u16>,
    pub tls_port: u16,
}

impl Listen {

    /// Resolve iface and hostname addresses
    pub fn addrs(&self) -> Result<Vec<SocketAddr>> {
        expand_listen_addrs(&self.addrs)
    }

}

impl Default for Listen {
    fn default() -> Self {
        Self {
            addrs: vec!["[::]".to_string()],
            insecure_port: None,
            tls_port: 443
        }
    }
}

#[serde_inline_default]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listen: Listen,
    pub vhosts: Vec<Vhost>,
    #[serde(default = "default_bool::<false>")]
    pub dev_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Default::default(),
            vhosts: Vec::new(),
            dev_mode: true,
        }
    }
}

impl Config {

    pub fn from_file(file: &Utf8Path) -> Result<Self> {
        info!("Loading config {file}");
        let key = std::fs::read_to_string(file)
            .context("Error loading config file {file}")?;
        let config = corn::from_str(&key)?;
        Ok(config)
    }

}

fn strip_brackets(before: &str) -> &str {
    before.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(before)
}

const SPECIAL_ADDRESS_DELIMITER: char = '#';
const SPECIAL_ADDRESS_INTERFACE: &str = "if";

fn expand_listen_addrs(addrs: &[String]) -> Result<Vec<SocketAddr>> {
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
        .filter_map(|ifaddr| ifaddr.address
                    .and_then(|addr| addr.to_socket_addrs().ok()
                              .and_then(|mut addr| addr.next())))
        .collect();

    Ok(ifaddrs)
}
