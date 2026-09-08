// An ACME DNS-01 provider with wildcard support; reused across all
// the vhosts below.
acme "le-wildcard" {
    acme_provider = "letsencrypt"
    profile = "shortlived"
    contact = "admin@haltcondition.net"
    challenge {
        type = "dns-01"
        wildcard = true
        dns_provider {
            name = "porkbun"
            key = env("DNS_KEY")
            secret = env("DNS_SECRET")
        }
    }
}

listen {
    addrs = [ "[::]" ]
    insecure_port = 80
}

// This will generate the certificate *.example.com
vhost "files.example.com" {
    tls = "le-wildcard"

    backend "/" {
        type = "proxy"
        url = "http://192.168.20.27:9090"
    }
}

// All the following hosts will share a
// common *.files.example.com certificate.
vhost "images.files.example.com" {
    tls = "le-wildcard"

    backend "/" {
        type = "proxy"
        url = "http://192.168.20.27:9191"
    }
}

vhost "docs.files.example.com" {
    tls = "le-wildcard"

    backend "/" {
        type = "proxy"
        url = "http://192.168.20.175:8188"
    }
}

vhost "downloads.files.example.com" {
    tls = "le-wildcard"

    backend "/" {
        type = "proxy"
        url = "http://192.168.20.73:8080"
    }
}
