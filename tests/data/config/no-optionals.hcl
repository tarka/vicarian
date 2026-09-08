cert "host01" {
    keyfile = "/etc/ssl/certs/host01.example.com.key"
    certfile = "/etc/ssl/certs/host01.example.com.crt"
}

vhost "host01.example.com" {
    tls = "host01"

    backend "/" {
        type = "proxy"
        url = "http://localhost:8080"
    }
}
