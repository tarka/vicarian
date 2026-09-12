# Vicarian

[Vicarian](https://vicarian.org/) is a TLS-first reverse proxy server with
built-in ACME support. It is currently targeted at self-hosting and SOHO
installations; in particular it supports provisioning TLS certificates
behind-the-firewall via ACME DNS-01 and the
[zone-update](https://github.com/tarka/zone-update/) library.

Vicarian aims to have sensible defaults without additional configuration.

## Project Status

[![Crates.io](https://img.shields.io/crates/v/vicarian)](https://crates.io/crates/vicarian)
[![GitHub CI](https://github.com/tarka/vicarian/actions/workflows/tests.yml/badge.svg)](https://github.com/tarka/vicarian/actions)
[![License](https://img.shields.io/crates/l/vicarian)](https://github.com/tarka/vicarian/blob/master/README.md#License)

This software should be consider beta; the core feature-set is largely complete,
and most development should be for more niche features.

Only Linux is currently supported (x86_64 and Arm64). Testing for other
platforms is welcome.

## Features

- **TLS-first**: Port-80/HTTP can be enabled, but will always redirect to the
  configured TLS server. The exception to this is when the HTTP-01 ACME is
  enabled; Vicarian will serve any challenge responses directly.
- **Native ACME Support**: Vicarian has first-class support for
  ACME/LetsEncrypt, including DNS-01. LetEncrypt [certificate
  profiles](https://letsencrypt.org/docs/profiles/) are supported; `tlsserver`
  is the default.
- **Multiple DNS Providers**: Multiple DNS providers are supported for DNS-01
  via the [zone-update](https://github.com/tarka/zone-update/)
  sibling-project. See that project for a list of supported
  providers. (Contributions of provider support are very welcome.)
- **Dynamic Certificate Loading**: Where TLS certificates are maintained
  externally Vicarian will dynamically reload certificates when they are
  updated.
- **Simple backend routing**: Traffic can be routed to multiple backend services
  based on URL paths.
- **Basic path rewriting**: This may work with some simple apps that don't
  support contexts natively, but is likely to fail with more complex apps that
  have hardcoded paths.
- **Virtual hosts**: Hosting of multiple domains and domain aliases is
  supported, along with certificate generation for host aliases.
- **Bearer authorization**: Basic `Authorization: Bearer <key>` support for
  protecting backend services.
- **Separated secrets**: ACME DNS requires DNS-provider secrets to be
  configured. These can be placed in a separate secure file using systemd
  [EnvironmentFile](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=)
  and environment injection via [HCL function calls](https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md); see
  [vicarian-full.hcl](examples/vicarian-full.hcl) for an example.
- **Wildcards**: Wildcard ACME certificate generation.
- **Prometheus Metrics**: Built-in support for exporting Prometheus metrics.
  See [METRICS.md](METRICS.md) for configuration and visualization details.
- **Static Files**: Built-in support for static-file serving, utilising embedded
  [static-web-server](https://static-web-server.net/).

### To-dos

- Access & error logs
- [Happy Eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs) support
- Docker images.

### Possible Future Features

The following may be implemented at some point depending on interest and
resources.

- TLS-ALPN-01 ACME support.
- Other ACME providers (e.g. ZeroSSL)
- HTTP3/Quic support.
- [h2c](https://httpwg.org/specs/rfc7540.html#versioning) backend support
  (avoids a lot of proxy security corner-cases, but there's not much support in
  backend server software).
- Basic [12-factor](https://12factor.net/config)-style configuration.
- Further secret-retrieval options;
  [Vault](https://www.hashicorp.com/en/products/vault)/[OpenBao](https://openbao.org/),
  TPM2/[systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html),
  etc.

### Probably-not features

Vicarian is very opinionated and tries to do the sensible thing by
default. Ideally if a particular header or setting was usually required by, say,
`nginx` then it should be the default. e.g. `X-Forwarded-For` and
[HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
are always set. Consequently there are no plans to add a large number of
features and settings.

Other notable non-features:

- Load-balancing, round-robin, complex rewrite rules, etc.
- Advanced connection tuning

## Installation

### Release Binaries

Tarballs are available on the [Github release page](https://github.com/tarka/vicarian/releases). 
These contain binaries, documentation, example configuration files, and an example
systemd configuration:

```
├── bin
│   └── vicarian
├── etc
│   ├── systemd
│   │   └── system
│   │       └── vicarian.service
│   └── vicarian
│       ├── examples
│       │   └── vicarian-full.hcl
│       │   ├── vicarian-dns01.hcl
│       │   ├── vicarian-http01.hcl
│       │   ├── ...
│       ├── secrets
│       └── vicarian.hcl
├── LICENSE
└── README.md
```

### Packages

Debian & Ubuntu packages are available from
[vicarian.org](https://vicarian.org/debian/):

    # Download the repository key:
    curl -fsSL https://vicarian.org/debian/vicarian-repo.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/vicarian-repo-archive-keyring.gpg

    # Add the APT source
    echo "deb [signed-by=/etc/apt/keyrings/vicarian-repo-archive-keyring.gpg] https://vicarian.org/debian stable main" | sudo tee /etc/apt/sources.list.d/vicarian.list

    # Install Vicarian
    sudo apt update && sudo apt install vicarian

### Install from crates.io

```bash
cargo install vicarian
```

The binary will be available at
`~/.crates/bin/vicarian`. [cargo-binstall](https://github.com/cargo-bins/cargo-binstall)
is also supported.

## Running

### Systemd Service

An example `systemd` service in provided in `systemd/vicarian.service`. The
systemd service sets the `CAP_NET_BIND_SERVICE` flag which allows binding to
ports 80/443 without root.

## Configuration

Vicarian currently uses a syntax based on
[HCL](https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md)/[Terraform](https://developer.hashicorp.com/terraform/language/syntax/configuration)
configuration syntax. The default configuration file is located at
`/etc/vicarian/vicarian.hcl`, but can be changed with the `--config` flag.

### Basic Configuration Structure

The full configuration structure is documented in
[vicarian-full.hcl](examples/vicarian-full.hcl) example file; this and the other
example files should be considered the syntax reference; they are all run
through the parser as part of the test suite. A basic working configuration with
HTTP-based Let's Encrypt TLS would look like:

```hcl
// Declare an ACME HTTP-01 provider for use in the vhost.
acme "le-http01" {
    contact = "admin@example.com"
    profile = "shortlived"
    challenge {
        type = "http-01"
    }
}

listen {
    addrs = [
        "[::]"  // Default; this covers IPv4 & IPv6
    ]
    tls_port = 443 // Default
    // Default; this is implied by the ACME config
    // Non-ACME traffic will redirect to TLS
    insecure_port = 80
}

vhost "www.example.com" {
    // Optional aliases for this host. These will be added to
    // the generated TLS certificate.
    aliases = [
        "docs.example.com",
        "pics.example.com",
    ]

    // This implicitly enables port 80 above
    tls = "le-http01"

    // A service that does not allow a custom root/context,
    // so we must place at root.
    backend "/" {
        type = "proxy"
        url = "https://localhost:8443"
        // This service enforces TLS with a self-signed cert, so
        // we need to disable certificate verification.
        trust = true
    }

    // A better behaved service that allows a custom root.
    backend "/copyparty" {
        type = "proxy"
        url = "http://localhost:9090"
    }
}
```


## Contributing

Contributions, bug reports, fixes, etc. are welcome.

Additionally, a useful contributions would be to add additional DNS provider
APIs to the [zone-update](https://github.com/tarka/zone-update/) project.

### Code of Conduct

The project follows the Rust Code of Conduct; [this can be found online](https://www.rust-lang.org/conduct.html).

### Tech stack

As well as the usual dependencies Vicarian also uses:

- [Pingora](https://github.com/cloudflare/pingora) for HTTP/TLS proxying.
- [instant-acme](https://github.com/djc/instant-acme) for ACME/LetEncrypt support.
- [static-web-server](https://static-web-server.net/) for static file support.
- [hcl-rs](https://github.com/martinohmann/hcl-rs) for configuration.

### AI Contribution Policy

This project will not accept runtime code generated by AI/LLMs.

## Security Notes

- Vicarian binds to ports 80 and 443 by default, requiring appropriate permissions
- The systemd service uses `CAP_NET_BIND_SERVICE` to bind to privileged ports without full root privileges
- Private keys are stored in PEM format and should be properly secured
- When using ACME with DNS-01 challenges, ensure DNS provider API credentials are stored securely

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
