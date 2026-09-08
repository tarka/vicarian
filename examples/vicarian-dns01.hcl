// An ACME DNS-01 provider using Porkbun. Secrets are read from the
// environment; see the README for using a systemd EnvironmentFile.
acme "le-porkbun" {
    acme_provider = "letsencrypt"    // Default
    contact = "admin@example.com"

    challenge {
        type = "dns-01"
        dns_provider {
            name = "porkbun"
            key = env("PORKBUN_KEY")
            secret = env("PORKBUN_SECRET")
        }
    }
}

listen {
    addrs = [
        "[::]"            // Default; this listens to IPv4 & IPv6 from everywhere
    ]
    insecure_port = 80    // Default
    tls_port = 443        // Default
}

vhost "files.example.com" {
    // Optional aliases for this host. These will be added to
    // the generated TLS certificate.
    aliases = [
        "docs.example.com",
        "pics.example.com",
    ]

    tls = "le-porkbun"

    // A service that does not allow a custom root/context,
    // so we must place at root.
    backend "/" {
        type = "proxy"
        url = "http://localhost:8443"
        // This service enforces TLS with a self-signed cert, so
        // we need to disable certificate verification.
        //
        // Looking at you Unifi Controller.
        trust = true
    }

    // A better behaved service that allows a custom root.
    backend "/copyparty" {
        type = "proxy"
        url = "http://localhost:9090"
    }
}
