listen {
    // Set on the commandline
}

cert "www.example.com" {
    keyfile = "target/certs/www.example.com.key"
    certfile = "target/certs/www.example.com.crt"
    reload = true
}

vhost "www.example.com" {
    tls = "www.example.com"

    backend "/" {
        type = "proxy"
        url = "http://127.0.0.1:19090"
    }
}
