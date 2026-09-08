
use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{Context as AnyhowContext, Result, anyhow};
use camino::Utf8Path;
use hcl::{
    Body, Value,
    eval::{Context, Evaluate, FuncArgs, FuncDef, ParamType}
};
use http::Uri;
use itertools::Itertools;
//use pingora_core::OkOrErr;
use serde::Deserialize;
use serde_default_utils::default_bool;
use tracing_log::log::info;

use crate::config::{AcmeChallenge, AcmeProfile, AcmeProvider, Backend, TlsAcmeConfig, TlsConfig, TlsFilesConfig, Vhost};

use super::{
    deserialize_canonical,
    expand_listen_addrs,
    ValidateSanitise,
};

#[derive(Debug)]
pub struct Config {
    pub listen: Listen,
    pub vhosts: Vec<Vhost>,
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
        let file = std::fs::read_to_string(file)
            .context("Error loading config file {file}")?;

        // Parse into native hcl-rs structures, then process any directives:
        let body = hcl::parse(&file)?;
        let eval_ctx = build_eval_context();
        let evaled: Body = body.evaluate(&eval_ctx)?;

        // Convert to the intermediate 'raw' config before performing
        // any validation/expansion.
        let raw: RawConfig = hcl::from_body(evaled)?;

        // Conversion from Raw* to final versions
        let listen = Listen::try_from(raw.listen)?;

        // Wrap `acme` and `cert` blocks in an enum.
        let acme = raw.acme.into_iter()
            .map(|(k, v)| (k, TlsConfig::Acme(v)));
        let tls = raw.cert.into_iter()
            .map(|(k, v)| (k, TlsConfig::Cert(v)))
            .chain(acme)
            .collect::<HashMap<String, TlsConfig>>();

        let vhosts = raw.vhosts.into_iter()
            .map(|(hostname, rv)| {
                // Inline the matching TLS declaration
                let tls = tls.get(&rv.tls)
                    .ok_or(anyhow!("No matching TLS declaration for '{}'", rv.tls))?
                    .clone();

                let backends = rv.backends.into_iter()
                    .sorted_by(|a, b| a.0.cmp(&b.0))
                    .map(|(k, v)| Backend { path: k, ..v })
                    .collect();

                Ok(Vhost {
                    hostname,
                    aliases: rv.aliases,
                    tls,
                    backends,
                })
            })
            .collect::<Result<Vec<Vhost>>>()?;

        let config = Config {
            listen,
            vhosts,
            dev_mode: raw.dev_mode,
        }
        .validate_and_sanitise()?;

        Ok(config)
    }
}

impl ValidateSanitise for Config {
    fn validate_and_sanitise(self) -> Result<Self> {
        let vhosts = self.vhosts.into_iter()
            .map(ValidateSanitise::validate_and_sanitise)
            .collect::<Result<Vec<Vhost>>>()?;

        Ok(Self {
            vhosts,
            ..self
        })
    }
}

// Wire in the HCL functions
fn build_eval_context() -> Context<'static> {
    let mut ctx = Context::new();
    let mut decfn = |(name, func)| ctx.declare_func(name, func);

    decfn(env_fn());

    ctx
}

fn env_fn() -> (&'static str, FuncDef) {
    // Register the env() function
    let env_func = FuncDef::builder()
        .param(ParamType::String)
        .build(|args: FuncArgs| {
            let var_name = args[0]
                .as_str()
                .ok_or_else(|| "env() argument must be a string".to_string())?;
            let value = std::env::var(var_name).unwrap_or_default();
            Ok(Value::from(value))
        });
    ("env", env_func)
}


// Rather than use struggle with serde/config mapping we use an
// intermediate struct that better matches the HCL schema and
// restructure during validation/transform.
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    acme: HashMap<String, TlsAcmeConfig>,

    #[serde(default)]
    cert: HashMap<String, TlsFilesConfig>,

    #[serde(default)]
    listen: RawListen,

    #[serde(default, rename = "vhost")]
    vhosts: HashMap<String, RawVhost>,

    #[serde(default)]
    dev_mode: bool,
}


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawListen {
    addrs: Vec<String>,
    insecure_port: Option<u16>,
    tls_port: u16,
}

impl Default for RawListen {
    fn default() -> Self {
        Self {
            addrs: vec!["[::]".to_string()],
            insecure_port: None,
            tls_port: 443
        }
    }
}

// #[derive(Clone, Debug, Deserialize)]
// pub struct AcmeConfig {
//     #[serde(default)]
//     pub acme_provider: AcmeProvider,
//     pub profile: AcmeProfile,
//     pub contact: String,
//     pub challenge: AcmeChallenge
// }

#[derive(Debug, Deserialize)]
pub struct DnsProvider {
    #[serde(default = "default_bool::<false>")]
    pub wildcard: bool,
    pub dns_provider: zone_update::Provider,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
    #[serde(default)]
    pub insecure_port: Option<u16>,
    #[serde(default)]
    pub tls_port: u16,
}

impl TryFrom<RawListen> for Listen {
    type Error = anyhow::Error;
    fn try_from(raw: RawListen) -> Result<Self> {
        Ok(Listen {
            addrs: expand_listen_addrs(&raw.addrs)?,
            insecure_port: raw.insecure_port,
            tls_port: raw.tls_port,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawVhost {
    pub tls: String,
    /// This should the FQDN, especially if using ACME as it is used
    /// to calculate the domain. Populated from the `vhost` block label.
    // #[serde(default)]
    // pub hostname: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Key is the label from `backend "<path>" { ... }`, i.e. the path.
    #[serde(default, rename = "backend")]
    pub backends: HashMap<String, Backend>,
}
