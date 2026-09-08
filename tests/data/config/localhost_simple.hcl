listen {
    insecure_port = 18080
    tls_port = 18443
}

cert "localhost" {
    keyfile = "target/certs/localhost.key"
    certfile = "target/certs/localhost.crt"
    reload = true
}

vhost "localhost" {
    tls = "localhost"

    backend "/" {
        type = "proxy"
        url = "http://127.0.0.1:19090"
    }
}
