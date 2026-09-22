listen {
    insecure_port = env("HTTP_PORT")
    tls_port = env("HTTPS_PORT")
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
        url = "http://127.0.0.1:19091"
    }
}
