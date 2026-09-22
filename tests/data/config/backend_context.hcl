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

    backend "/api" {
        type = "proxy"
        url = env("VICARIAN_TEST_BACKEND_URL_1")
    }
}
