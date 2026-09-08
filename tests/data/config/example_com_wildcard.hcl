listen {
    insecure_port = 18080
    tls_port = 18443
}

cert "_.example.com" {
    keyfile = "target/certs/_.example.com.key"
    certfile = "target/certs/_.example.com.crt"
    reload = true
}

vhost "www.example.com" {
    tls = "_.example.com"

    backend "/" {
        type = "proxy"
        url = "http://127.0.0.1:19090"
    }
}
