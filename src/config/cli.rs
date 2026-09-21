use camino::Utf8PathBuf;
use clap::{ArgAction, Parser};

#[derive(Clone, Debug, Default, Parser)]
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

    /// HTTP port.
    ///
    /// This is usually specified in the configuration file; providing
    /// it here overrides any value or default.  This is only used for
    /// redirection to HTTPS and ACME/Letsencrypt certificate
    /// generation.
    pub insecure_port: Option<u16>,

    /// HTTPS/TLS port override.
    ///
    /// This is usually specified in the configuration file; providing
    /// it here overrides any value or default.
    pub tls_port: Option<u16>,
}

impl CliOptions {
    pub fn from_args() -> CliOptions {
        CliOptions::parse()
    }
}
