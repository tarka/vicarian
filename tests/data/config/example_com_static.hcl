listen {
    insecure_port = 18080
    tls_port = 18443
}

cert "www.example.com" {
    keyfile = "target/certs/www.example.com.key"
    certfile = "target/certs/www.example.com.crt"
    reload = true
}

vhost "www.example.com" {
    tls = "www.example.com"

    backend "/" {
        type = "static"
        root = "tests/data/static"
    }
}
