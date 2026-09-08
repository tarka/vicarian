// Classic pre-made certificate files.
cert "snakeoil" {
    keyfile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    certfile = "/etc/ssl/private/ssl-cert-snakeoil.key"
    reload = true
}

vhost "files.example.com" {
    tls = "snakeoil"

    backend "/" {
        type = "proxy"
        url = "http://localhost:8080"
    }

    // Serve prometheus metrics under /metrics.
    backend "/metrics" {
        type = "metrics"
        auth_key = "secret_key"
    }
}
