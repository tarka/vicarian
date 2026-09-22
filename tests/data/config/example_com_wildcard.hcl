listen {
    // Set on the commandline
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
        url = env("VICARIAN_TEST_BACKEND_URL_1")
    }
}
