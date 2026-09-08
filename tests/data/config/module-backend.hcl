cert "host01.example.com" {
    keyfile = "/etc/ssl/certs/host01.example.com.key"
    certfile = "/etc/ssl/certs/host01.example.com.crt"
}

vhost "host01.example.com" {
    tls = "host01.example.com"

    backend "/" {
        type = "metrics"
    }
}
