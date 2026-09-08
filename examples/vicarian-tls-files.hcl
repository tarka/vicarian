// Classic pre-made certificate files.
cert "snakeoil" {
    keyfile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    certfile = "/etc/ssl/private/ssl-cert-snakeoil.key"
    reload = true
}

listen {
    addrs = [
        "[::]"   // Default; this covers IPv4 & IPv6
    ]
    insecure_port = 8080 // Default is 80
    tls_port = 8443 // Default is 443
}

vhost "files.example.com" {
    // Optional aliases for this host
    aliases = [
        "docs.example.com",
        "pics.example.com",
    ]

    tls = "snakeoil"

    // A service that does not allow a custom root/context,
    // so we must place at root.
    backend "/" {
        type = "proxy"
        url = "http://localhost:8443"
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
