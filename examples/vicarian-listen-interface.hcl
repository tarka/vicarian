// Classic pre-made certificate files.
cert "snakeoil" {
    keyfile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    certfile = "/etc/ssl/private/ssl-cert-snakeoil.key"
    reload = true
}

listen {
    addrs = [
        // We can listen on interfaces using the `if#` prefix:
        "if#lo",
        "if#eth0",
    ]
}

vhost "files.example.com" {
    tls = "snakeoil"

    backend "/" {
        type = "proxy"
        url = "http://localhost:9090"
    }
}
