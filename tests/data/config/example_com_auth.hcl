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

    backend "/metrics" {
        type = "metrics"
        auth_key = "my_auth_key"
    }
}
