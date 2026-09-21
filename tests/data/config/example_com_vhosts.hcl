listen {
    addrs = [
        "if#lo"
    ]
    // Set on the commandline
}

cert "www.example.com" {
    keyfile = "target/certs/www.example.com.key"
    certfile = "target/certs/www.example.com.crt"
}

cert "test.example.com" {
    keyfile = "target/certs/test.example.com.key"
    certfile = "target/certs/test.example.com.crt"
}

vhost "www.example.com" {
    tls = "www.example.com"

    backend "/" {
        type = "proxy"
        url = "http://127.0.0.1:19090"
    }
}

vhost "test.example.com" {
    tls = "test.example.com"

    backend "/" {
        type = "proxy"
        url = "http://127.0.0.1:19091"
    }
}
