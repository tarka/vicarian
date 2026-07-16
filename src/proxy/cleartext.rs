use std::sync::Arc;

use async_trait::async_trait;
use http::{
    Response, StatusCode, header,
    uri::{Builder, Scheme},
};
use metrics::counter;
use pingora_core::{apps::http_app::ServeHttp, protocols::http::ServerSession};
use tracing::{debug, info};

use crate::{
    certificates::acme::AcmeRuntime,
    metrics::{
        METRIC_ACME_HTTP01_ENDPOINT_TOTAL, METRIC_ACME_HTTP01_NOTFOUND_TOTAL,
        METRIC_HTTP_REDIRECTS_TOTAL,
        METRIC_HTTP_REQUESTS_TOTAL,
    },
    proxy::rewrite_port,
};


const REDIRECT_BODY: &[u8] = "<html><body>301 Moved Permanently</body></html>".as_bytes();
const ACME_HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";
const TOKEN_NOT_FOUND: &[u8] = "<html><body>ACME token not found in request path</body></html>".as_bytes();

fn token_not_found() -> Response<Vec<u8>> {
    counter!(METRIC_ACME_HTTP01_NOTFOUND_TOTAL).increment(1);
    Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(TOKEN_NOT_FOUND.to_vec())
            .expect("Failed to send 404 response to token")
}

fn bad_request(msg: &str) -> Response<Vec<u8>> {
    let body = format!("<html><body><h1>400 Bad Request</h1><p>{msg}</p></body></html>").into_bytes();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CONTENT_LENGTH, body.len())
        .body(body)
        .expect("Failed to send 400 response")
}


pub struct CleartextHandler {
    acme: Arc<AcmeRuntime>,
    port: String,
}

impl CleartextHandler {
    pub fn new(acme: Arc<AcmeRuntime>, tls_port: u16) -> Self {
        Self {
            acme,
            port: tls_port.to_string()
        }
    }
}

impl CleartextHandler {

    async fn redirect_to_tls(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        counter!(METRIC_HTTP_REDIRECTS_TOTAL).increment(1);

        let Some(host_header) = session.get_header(header::HOST) else {
            return bad_request("Missing Host header");
        };
        let Ok(host) = host_header.to_str() else {
            return bad_request("Invalid Host header");
        };
        let path = session.req_header().uri.clone();

        // Uri::Authority doesn't allow port overrides, so mangle the string
        let new_host = rewrite_port(host, &self.port);

        // TODO: `host` may not be full authority (i.e. including
        // uname:pw section). Does it matter?
        let location = Builder::from(path)
            .scheme(Scheme::HTTPS)
            .authority(new_host)
            .build()
            .expect("Failed to convert URI to HTTPS");

        debug!("Redirect to {location}");
        let body = REDIRECT_BODY.to_owned();
        Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::LOCATION, location.to_string())
            .body(body)
            .expect("Failed to create HTTP->HTTPS redirect response")
    }

    async fn acme_challenge(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        counter!(METRIC_ACME_HTTP01_ENDPOINT_TOTAL).increment(1);

        let Some(host_header) = session.get_header(header::HOST) else {
            return bad_request("Missing Host header");
        };
        let Ok(fqdn) = host_header.to_str() else {
            return bad_request("Invalid Host header");
        };

        let path = session.req_header().uri.path_and_query()
            .expect("Failed to find already matched path?");

        let path_token = match path.path().strip_prefix(ACME_HTTP01_PREFIX) {
            Some(token) => token,
            None => return token_not_found(),
        };

        let key_auth = if let Some(toks) = self.acme.challenge_tokens(fqdn)
            && toks.token == path_token
        {
            toks.key_auth
        } else {
            return token_not_found()
        };

        let body = key_auth.as_bytes().to_vec();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, body.len())
            .body(body)
            .expect("Failed to create HTTP->HTTPS redirect response")
    }
}

#[async_trait]
impl ServeHttp for CleartextHandler {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        counter!(METRIC_HTTP_REQUESTS_TOTAL).increment(1);

        // URI in practice == /the/path/to/resource
        let path_p = session.req_header().uri.path_and_query();
        if let Some(pq) = path_p
            && pq.path().starts_with(ACME_HTTP01_PREFIX)
        {
            info!("Received ACME challenge request: {pq}");
            self.acme_challenge(session).await
        } else {
            self.redirect_to_tls(session).await
        }
    }
}
