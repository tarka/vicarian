listen {
    // Set on the commandline
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
