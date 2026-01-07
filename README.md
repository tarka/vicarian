# Vicarian

Vicarian is a TLS-only (sort-of; see below) reverse proxy server with built-in
ACME support. It is currently targeted at self-hosting and SOHO installations;
in particular it supports provisioning TLS certificates behind-the-firewall via
ACME DNS-01 and the [zone-update](https://github.com/tarka/zone-update/)
library.

Vicarian aims to have sensible defaults without additional configuration.

## Project Status

[![Crates.io](https://img.shields.io/crates/v/vicarian)](https://crates.io/crates/vicarian)
[![Docs.rs](https://docs.rs/vicarian/badge.svg)](https://docs.rs/vicarian)
[![GitHub CI](https://github.com/tarka/vicarian/actions/workflows/tests.yml/badge.svg)](https://github.com/tarka/vicarian/actions)
[![License](https://img.shields.io/crates/l/vicarian)](https://github.com/tarka/vicarian/blob/main/README.md#License)

This software should be consider pre-alpha; the feature-set is
[MVP](https://en.wikipedia.org/wiki/Minimum_viable_product) and is still in
active development. It should not be considered production-ready and no warranty
is expressed or implied. It is very-much a work-in-progress and virtually every
part of it subject to change without notice.

Only Linux is currently supported (x86_64 and Arm64). Testing for other
platforms is welcome.

## Features

### Current features

- **TLS-only**: More accurately 'TLS-first'. Port-80/HTTP can be enabled, but
  will always redirect to the configured TLS server.
- **Native ACME Support**: Vicarian has first-class support for
  ACME/LetsEncrypt, including DNS-01. LetEncrypt [certificate
  profiles](https://letsencrypt.org/docs/profiles/) are supported; `tlsserver`
  is the default.
- **Multiple DNS-01 Providers**: Multiple DNS providers are supported for DNS-01
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
- **Virtual hosts**

### To-dos

- Access & error logs
- Static file support. (Pingora itself doesn't support static-file
  serving. There are 3rd-party crates that support this but they appear
  unmaintained at the moment; they will need to be evaluated. If you wish to
  serve a static website one workaround is to use e.g `python3 -m http-server
  --bind localhost 8080` to create a static backend. This is how
  [vicarian.org](https://vicarian.org/) and
  [haltcondition.net](https://haltcondition.net/) are served currently.)

### Possible Future Features

The following may be implemented at some point depending on interest and
resources.

- [Happy Eyeballs](https://en.wikipedia.org/wiki/Happy_Eyeballs) support
- TLS-ALPN-01 ACME support.
- Other ACME providers (e.g. ZeroSSL)
- Prometheus stats.

### Probably-not features

Vicarian is very opinionated and tries to do the correct thing by
default. Ideally if a particular header or setting was usually required in say
`nginx` then it should be the default. e.g. `X-Forwarded-For` and
[HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
are always set. Consequently there are no plans to add a large number of
features and settings.

Notable non-features:

- Wildcard ACME certs; these are better generated externally and distributed to
  multiple servers.
- Load-balancing, round-robin, complex rewrite rules, etc.
- Advanced connection tuning

## Installation

### Release Binaries

Tarballs are available on the [Github release page](https://github.com/tarka/vicarian/releases). 
These contain binaries, documentation, example configuration files, and an example
systemd configuration.

### Install from crates.io

```bash
cargo install vicarian
```

The binary will be available at `~/.crates/bin/vicarian`.

## Running

### Systemd Service

An example `systemd` service in provided in `systemd/vicarian.service`. The
systemd service sets the `CAP_NET_BIND_SERVICE` flag which allows binding to
ports 80/443 without root.

## Configuration

Vicarian currently uses the [corn](https://cornlang.dev/) configuration
language. The default configuration file is located at
`/etc/vicarian/vicarian.corn`, but can be changed with the `--config` flag.

### Basic Configuration Structure

The full configuration structure is documented in
[CONFIGURATION.md](CONFIGURATION.md), and additional examples are available in
the `examples` directory, but a basic working configuration with HTTP-based
Let's Encrypt TLS would look like:

```corn
{
    listen = {
        addr = "[::]"  // Default; this covers IPv4 & IPv6
        insecure_port = 80 // Disabled by default, this will redirect to HTTPS
        tls_port = 443 // Default
    }

    vhosts = [
        {
            hostname = "example.com"

            tls = {
                acme = {
                    contact = "admin@example.com"
                    challenge.type = "http-01"
                }
            }

            backends = [
                {
                    context = "/"
                    url = "http://localhost:8080"
                }
                {
                    context = "/app2"
                    url = "https://localhost:8443"
                    trust = true
                }
            ]
        }
    ]
}
```

## Contributing

Contributions, bug reports, fixes, etc. are welcome.

Additionally, a useful contributions would be to add additional DNS provider
APIs to the [zone-update](https://github.com/tarka/zone-update/) project.

### Code of Conduct

The project follows the Rust Code of Conduct; [this can be found online](https://www.rust-lang.org/conduct.html).

### AI Contribution Policy

LLM and related 'AI' technologies can be useful for software development, but
best-practices on their usage are still evolving. For this reason this project
will not accept runtime code generated by AI. Generation of _draft_
documentation and test code is acceptable, but should be reviewed by the
submitter before raising a PR. After all, if you can't be bothered to review it
why should anybody else?

## Security Notes

- Vicarian binds to ports 80 and 443 by default, requiring appropriate permissions
- The systemd service uses `CAP_NET_BIND_SERVICE` to bind to privileged ports without full root privileges
- Private keys are stored in PEM format and should be properly secured
- When using ACME with DNS-01 challenges, ensure DNS provider API credentials are stored securely

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
