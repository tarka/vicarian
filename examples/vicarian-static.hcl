// This is a basic example configuration using the system-wide
// "snakeoil" certificates. For examples of configurations using
// LetsEncrypt/ACME see /usr/share/doc/vicarian/examples/

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

vhost "www.example.com" {
    // Optional aliases for this host
    aliases = [
        "customer.example.com",
    ]

    tls = "snakeoil"

    // A static site page
    backend "/" {
        type = "static"
        root = "/var/www/html"
    }

    // A proxied backend
    backend "/customer" {
        type = "proxy"
        url = "http://localhost:9090"
    }
}
