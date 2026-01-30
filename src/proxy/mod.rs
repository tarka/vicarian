mod router;
mod services;
#[cfg(test)]
mod tests;

use std::{net::IpAddr, sync::Arc};

use anyhow::Result;
use pingora_core::{
    listeners::tls::TlsSettings,
    services::listening::Service,
    server::Server as PingoraServer,
};
use tracing::info;

use crate::{
    certificates::{
        acme::AcmeRuntime, handler::CertHandler, store::CertStore
    }, config::{AcmeChallenge, TlsAcmeConfig, TlsConfig}, proxy::services::{
        CleartextHandler, Vicarian
    }, RunContext
};


pub fn run_indefinitely(certstore: Arc<CertStore>, acme: Arc<AcmeRuntime>, context: Arc<RunContext>) -> Result<()> {
    info!("Starting Proxy");

    let mut pingora_server = PingoraServer::new(None)?;
    pingora_server.bootstrap();

    // TODO: Currently single-server; support vhosts here in the future?

    let addrs = context.config.listen.addrs()?;

    let tls_proxy = {
        let vicarian = Vicarian::new(certstore.clone(), context.clone());

        let mut pingora_proxy = pingora_proxy::http_proxy_service(
            &pingora_server.configuration,
            vicarian);

        for addr in &addrs {
            let cert_handler = CertHandler::new(certstore.clone());
            let mut tls_settings = TlsSettings::with_callbacks(Box::new(cert_handler))?;
            tls_settings.enable_h2();

            //let addr_port = format!("{}:{}", ip_socket_str(&addr), context.config.listen.tls_port);
            let addr_port = (addr.clone(), context.config.listen.tls_port);
            pingora_proxy.add_tls_with_settings(&addr_port, None, tls_settings);
        }
        pingora_proxy
    };
    pingora_server.add_service(tls_proxy);

    let has_http01 = context.config.vhosts.iter()
        .any(|vh| matches!(vh.tls, TlsConfig::Acme(
            TlsAcmeConfig { challenge: AcmeChallenge::Http01, .. })));

    if has_http01 || context.config.listen.insecure_port.is_some() {
        let insecure_port = context.config.listen.insecure_port
            .unwrap_or(80);

        let redirector = CleartextHandler::new(acme, context.config.listen.tls_port);
        let mut service = Service::new("HTTP->HTTPS Redirector".to_string(), redirector);

        for addr in addrs {
            //let addr_port = format!("{}:{}", ip_socket_str(&addr), insecure_port);
            let addr_port = (addr, insecure_port);
            service.add_tcp(&addr_port);
        }
        pingora_server.add_service(service);
    };

    pingora_server.run(pingora_core::server::RunArgs::default());

    Ok(())
}

fn rewrite_port(host: &str, newport: &str) -> String {
    let port_i = if let Some(i) = host.rfind(':') {
        i
    } else {
        return host.to_string();
    };
    if host[port_i + 1..].parse::<u16>().is_err() {
        // Not an int, assume not port ':'
        return host.to_string();
    }
    let host_only = &host[0..port_i];

    format!("{host_only}:{newport}")
}

fn strip_port(host_header: &str) -> &str {
    if let Some(i) = host_header.rfind(':') {
        &host_header[0..i]
    } else {
        host_header
    }
}

// fn ip_socket_str(addr: &IpAddr) -> String {
//     match addr {
//         IpAddr::V4(_) => addr.to_string(),
//         IpAddr::V6(_) => format!("[{addr}]"),
//     }
// }
