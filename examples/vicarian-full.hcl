//////////////////////////////////////////////////////////////////////////////
//
// Declarations section
//
//////////////////////////////////////////////////////////////////////////////
//
// Vicarian is TLS-first; unsecured HTTP (i.e. port 80 by default, see
// `listen` below) is only used for ACME/Letsencrypt HTTP
// authentication; all other traffic is redirected to TLS (i.e. port
// 443). TLS requires certificates; there are 3 methods of providing them:
//
// * `acme` (e.g. Letencrypt) with HTTP-01; requires Vicarian to be
//   listening internet-accessible port.
//
// * `acme` using DNS-01; can be behind a firewall, but requires your
//   DNS provider be supported.
//
// * `cert`, which is just a link to files generated externally.
//
// Unlike most other HTTP proxies we declare our TLS configuration
// up-front and then reference it in the vhost blocks. This allows
// Acme DNS-01 configuration to re-used across hosts (the expected
// use-case for Vicarian).

// A definition of an ACME DNS-01 provider; there can be multiple of these
// and be reused in multiple vhosts.
acme "le-porkbun" {
    acme_provider = "letsencrypt"    // Default
    // Optional; 'classic' (default), 'tlsserver', or 'shortlived'.
    // See https://letsencrypt.org/docs/profiles/
    profile = "shortlived"
    contact = "admin@haltcondition.net"  // Required
    challenge {
        type = "dns-01"
        wildcard = true   // Default is false
        dns_provider {
            // This is a DNS provider defined in the `Provider` enum
            // in the zone-update crate.
            // See https://github.com/tarka/zone-update/blob/main/docs/PROVIDERS.md
            name = "porkbun"

            // env() fetches data from environment variables.
            key = env("PORKBUN_KEY")
            secret = env("PORKBUN_SECRET")
        }
    }
}

// A definition of an ACME HTTP-01 provider; generally you only need one of these.
acme "le-http01" {
    contact = "admin@haltcondition.net"
    profile = "classic"
    challenge {
        type = "http-01"
    }
}

// Classic pre-made certificate files. You would need one of these for each vhost
// unless using a wild-card certificate.
cert "snakeoil" {
    keyfile = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    certfile = "/etc/ssl/private/ssl-cert-snakeoil.key"
    reload = true // Optional; defaults to true
}

//////////////////////////////////////////////////////////////////////////////
//
// Server and Vhost configuration.
//
//////////////////////////////////////////////////////////////////////////////

// The `listen` directive; this defines addresss and interfaces to listen on.
//
// Optional; if not present it defaults to the values below.
listen {
    // The addresses to listen on. IP addresses (e.g. "127.0.0.1") and hostnames
    // (e.g. "localhost") are valid. You can also specify an interface by
    // prefacing with `if#`; e.g. "if#eth0". This will be expanded to all
    // addresses on that interface.
    addrs = [
        "[::]"            // Default; this listens to IPv4 & IPv6 from everywhere
    ]
    insecure_port = 80    // Default
    tls_port = 443        // Default
}

// Vhost configuration. At least one is required. The primary name is in the block,
// aliases can also be provided.
vhost "haltcondition.net" {
    // Optional
    aliases = [
        "www.haltcondition.net",
    ]

    // Required; inserts one of the TLS configuration declared above.
    tls = "le-porkbun"

    // Backend declaration; it contains the path (context) it is mapping to.
    // Multiple backends/paths can be provided.
    backend "/" {
        // The backend type; "proxy", "static", or "metrics".
        // See below for other examples.
        type = "proxy"
        // Required for type = "proxy"
        url = "http://192.168.20.27:9191"
    }

    backend "/html" {
        // Serves static files.
        type = "static"
        // Required for type = "static"
        root = "/var/www/haltcondition.net"
    }

    backend "/metrics" {
        // Prometheus-compatible metrics; see METRICS.md for details.
        type = "metrics"
        // An authorisation key for this path; if present the `Authorization` header
        // will be checked for this key.
        auth_key = env("my-secret-key")
    }
}

vhost "vicarian.org" {
    // Optional
    aliases = [
        "www.vicarian.org",
    ]

    // Required; inserts the definition defined above
    tls = "le-http01"

    backend "/" {
        type = "proxy"
        url = "http://192.168.20.27:9192"
    }

    backend "/trusted" {
        type = "proxy"
        url = "https://127.0.0.1:4443"
        // `trust` bypasses TLS cert checks, allowing backends with self-signed certificates.
        trust = true
    }

    backend "/html" {
        type = "static"
        root = "/var/www/vicarian.org"
    }
}
