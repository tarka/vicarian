use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::sync::OnceCell;
use tracing_log::log::{debug, info};

use crate::RunContext;

const UPKEEP_TIMEOUT: Duration = Duration::from_secs(60);

static METRICS: OnceCell<Metrics> = OnceCell::const_new();

#[derive(Debug)]
pub struct Metrics {
    pub handle: PrometheusHandle,
    context: Arc<RunContext>,
}

impl Metrics {
    pub fn install_global(context: Arc<RunContext>) -> Result<&'static Self> {
        let handle = PrometheusBuilder::new()
            .with_recommended_naming(true)
            .install_recorder()?;
        let metrics = Self {
            handle,
            context,
        };

        METRICS.set(metrics)?;

        let mref = METRICS.get()
            .ok_or(anyhow!("Failed to get metrics after setting"))?;

        Ok(mref)
    }

    pub fn get() -> &'static Metrics {
        METRICS.get()
            // Almost certainly a startup-order bug, so panic
            .expect("Attempt to retreive metrics before setup")
    }

    pub async fn run(&self) {
        debug!("Starting Metrics runtime");

        let mut quit_rx = self.context.quit_rx.clone();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(UPKEEP_TIMEOUT) => {
                    debug!("Running metrics upkeep task");
                    let handle = self.handle.clone(); // Uses inner-arc pattern
                    tokio::task::spawn_blocking(move || handle.run_upkeep());
                }

                _ = quit_rx.changed() => {
                    info!("Quitting ACME runtime");
                    break;
                },
            };
        }
    }

}
