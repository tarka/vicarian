// An ACME HTTP-01 provider.
acme "le-http01" {
    contact = "admin@example.com"
    profile = "shortlived"
    challenge {
        type = "http-01"
    }
}

listen {
    addrs = [
        "[::]"  // Default; this covers IPv4 & IPv6
    ]
    tls_port = 443 // Default
    // Default; this is implied by the ACME config
    // Non-ACME traffic will redirect to TLS
    // insecure_port = 80
}

vhost "www.example.com" {
    // Optional aliases for this host. These will be added to
    // the generated TLS certificate.
    aliases = [
        "docs.example.com",
        "pics.example.com",
    ]

    // This implicitly enables port 80 above
    tls = "le-http01"

    // A service that does not allow a custom root/context,
    // so we must place at root.
    backend "/" {
        type = "proxy"
        url = "https://localhost:8443"
        // This service enforces TLS with a self-signed cert, so
        // we need to disable certificate verification.
        trust = true
    }

    // A better behaved service that allows a custom root.
    backend "/copyparty" {
        type = "proxy"
        url = "http://localhost:9090"
    }
}
