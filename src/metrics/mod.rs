use std::{sync::Arc, time::Duration};

use anyhow::Result;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_log::log::info;

use crate::RunContext;

const UPKEEP_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Metrics {
    handle: PrometheusHandle,
    context: Arc<RunContext>,
}

impl Metrics {
    pub fn new(context: Arc<RunContext>) -> Result<Self> {
        let handle = PrometheusBuilder::new()
            .with_recommended_naming(true)
            .install_recorder()?;

        Ok(Self {
            handle,
            context,
        })
    }

    pub async fn run(&self) {
        info!("Starting Metrics runtime");

        let mut quit_rx = self.context.quit_rx.clone();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(UPKEEP_TIMEOUT) => {
                    info!("Running metrics upkeep task"); // FIXME: Move to trace level
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
