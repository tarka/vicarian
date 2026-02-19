mod certificates;
mod config;
mod errors;
mod mdns;
mod proxy;

use std::sync::Arc;
use std::thread;

use anyhow::Result;
use camino::Utf8PathBuf;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use tokio::sync::watch;
use tracing::level_filters::LevelFilter;
use tracing_log::log::info;

use crate::{
    certificates::CertificateRuntime,
    config::{Config, DEFAULT_CONFIG_FILE},
};

fn init_logging(level: u8) -> Result<()> {
    let log_level = match level {
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        3 => LevelFilter::TRACE,
        _ => LevelFilter::WARN,
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Logging initialised");
    Ok(())
}

pub struct RunContext {
    pub config: Config,
    pub quit_rx: watch::Receiver<bool>,
    quit_tx: watch::Sender<bool>,
}

impl RunContext {
    pub fn new(config: Config) -> Self {
        let (quit_tx, quit_rx) = watch::channel(false);
        Self {
            config,
            quit_tx, quit_rx,
        }
    }

    pub fn quit(&self) -> Result<()> {
        info!("Sending quit signal to runtimes");
        self.quit_tx.send(true)?;
        Ok(())
    }
}

fn system_setup() -> Result<()> {
    let (_soft, hard) = getrlimit(Resource::RLIMIT_NOFILE)?;
    info!("Increasing NOFILE to {hard}");
    setrlimit(Resource::RLIMIT_NOFILE, hard, hard)?;

    rustls::crypto::aws_lc_rs::default_provider().install_default()
        .expect("Failed to install Rustls crypto provider");

    Ok(())
}

fn main() -> Result<()> {
    let cli = config::CliOptions::from_args();

    init_logging(cli.verbose)?;
    info!("Starting");

    system_setup()?;

    let config_file = cli.config
        .unwrap_or(Utf8PathBuf::from(DEFAULT_CONFIG_FILE));
    let config = Config::from_file(&config_file)?;

    let context = Arc::new(RunContext::new(config));

    ///// Runtime start

    let cert_runtime = Arc::new(CertificateRuntime::new(context.clone())?);
    let cert_handle = {
        let crt = cert_runtime.clone();

        thread::spawn(move || -> Result<()> {
            info!("Starting Certificate Management runtime");
            let trt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .enable_io()
                .build()?;

            trt.block_on(
                crt.run_indefinitely()
            )?;

            Ok(())
        })
    };

    info!("Starting Vicarian");
    proxy::run_indefinitely(cert_runtime.clone(), context.clone())?;

    context.quit()?;
    cert_handle.join()
        .expect("Failed to finalise certificate management tasks")?;

    info!("Vicarian finished.");
    Ok(())
}
