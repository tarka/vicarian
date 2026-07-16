use std::{sync::Arc, time::Duration};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::header;
use metrics::{counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::sync::OnceLock;
use tracing_log::log::{debug, info};

use crate::{RunContext, config::Backend, proxy::Handler};

const UPKEEP_TIMEOUT: Duration = Duration::from_secs(60);

pub const METRIC_ACME_NEXT_RENEWAL_TIMESTAMP_SECS: &str = "vicarian_acme_next_renewal_timestamp_secs";
pub const METRIC_ACME_RENEW_ERROR_TOTAL: &str = "vicarian_acme_renew_error_total";
pub const METRIC_ACME_RENEW_SUCCESS_TOTAL: &str = "vicarian_acme_renew_success_total";
pub const METRIC_ACME_HTTP01_ENDPOINT_TOTAL: &str = "vicarian_acme_http01_endpoint_total";
pub const METRIC_ACME_HTTP01_NOTFOUND_TOTAL: &str = "vicarian_acme_http01_notfound_total";
pub const METRIC_AUTH_INVALID_TOTAL: &str = "vicarian_auth_invalid_total";
pub const METRIC_AUTH_VALID_TOTAL: &str = "vicarian_auth_valid_total";
pub const METRIC_HTTP_REDIRECTS_TOTAL: &str = "vicarian_http_redirects_total";
pub const METRIC_HTTP_REQUESTS_TOTAL: &str = "vicarian_http_requests_total";
pub const METRIC_METRICS_SCRAPE_TOTAL: &str = "vicarian_metrics_scrape_total";
pub const METRIC_TLS_REQUESTS_TOTAL: &str = "vicarian_tls_requests_total";

static METRICS: OnceLock<Metrics> = OnceLock::new();

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

        let metrics = METRICS.get_or_init(|| Self {
            handle,
            context,
        });

        metrics.describe_metrics();

        Ok(metrics)
    }

    pub fn get() -> &'static Metrics {
        METRICS.get()
            // Almost certainly a startup-order bug, so panic
            .expect("Attempt to retreive metrics before setup")
    }

    fn describe_metrics(&self) {
        counter!(METRIC_ACME_HTTP01_ENDPOINT_TOTAL).absolute(0);
        describe_counter!(
            METRIC_ACME_HTTP01_ENDPOINT_TOTAL,
            "Total number of ACME HTTP-01 challenge endpoint requests"
        );

        counter!(METRIC_ACME_HTTP01_NOTFOUND_TOTAL).absolute(0);
        describe_counter!(
            METRIC_ACME_HTTP01_NOTFOUND_TOTAL,
            "Total number of ACME HTTP-01 challenge not found responses"
        );

        counter!(METRIC_AUTH_INVALID_TOTAL).absolute(0);
        describe_counter!(
            METRIC_AUTH_INVALID_TOTAL,
            "Total number of invalid authentication attempts"
        );

        counter!(METRIC_AUTH_VALID_TOTAL).absolute(0);
        describe_counter!(
            METRIC_AUTH_VALID_TOTAL,
            "Total number of valid authentication attempts"
        );

        counter!(METRIC_HTTP_REDIRECTS_TOTAL).absolute(0);
        describe_counter!(
            METRIC_HTTP_REDIRECTS_TOTAL,
            "Total number of HTTP redirects served"
        );

        counter!(METRIC_HTTP_REQUESTS_TOTAL).absolute(0);
        describe_counter!(
            METRIC_HTTP_REQUESTS_TOTAL,
            "Total number of HTTP requests received"
        );

        counter!(METRIC_METRICS_SCRAPE_TOTAL).absolute(0);
        describe_counter!(
            METRIC_METRICS_SCRAPE_TOTAL,
            "Total number of metrics endpoint scrapes"
        );

        counter!(METRIC_TLS_REQUESTS_TOTAL).absolute(0);
        describe_counter!(
            METRIC_TLS_REQUESTS_TOTAL,
            "Total number of TLS handshake requests"
        );

        gauge!(METRIC_ACME_NEXT_RENEWAL_TIMESTAMP_SECS).set(0);
        describe_gauge!(
            METRIC_ACME_NEXT_RENEWAL_TIMESTAMP_SECS,
            "Unix timestamp of the next ACME certificate renewal"
        );
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

pub struct MetricsHandler;

impl MetricsHandler {
    // Just for consistency
    pub fn new(_backend: &Backend) -> Self {
        Self
    }
}

#[async_trait]
impl Handler for MetricsHandler {
    async fn handle(&self, session: &mut Session) -> Result<()> {
        counter!(METRIC_METRICS_SCRAPE_TOTAL).increment(1);
        debug!("Replying to metrics endpoint");

        let metrics = Metrics::get();
        let scraped = metrics.handle.render();
        let body = Bytes::copy_from_slice(scraped.as_bytes());

        let mut header = ResponseHeader::build(200, Some(body.len()))?;
        header.insert_header(header::CONTENT_TYPE, "text/plain")?;
        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(body), true).await?;

        Ok(())

    }
}
