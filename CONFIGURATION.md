# Vicarian Configuration Documentation

Vicarian's configuration is defined in a [Corn](https://cornlang.dev) file, by
default in `/etc/vicarian/vicarian.corn`. This file defines how the proxy should
behave, including TLS settings, backend services, and routing.

## Basic Structure

A minimal Vicarian configuration file would look something like this:

```corn
{
    listen = {
        addrs = [
            "[::]"  // This covers IPv4 & IPv6
        ]
        insecure_port = 80 // Default
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
                    path = "/"
                    url = "http://localhost:8080"
                }
                {
                    path = "/app2"
                    url = "https://localhost:8443"
                    trust = true
                }
                {
                    path = "/metrics"
                    url = "module://metrics"
                    auth_key = "secret_key"
                }
                {
                    path = "/static"
                    url = "module://static"
                    static_root = "/var/www/static"
                }
           ]
        }
    ]
}
```

## Configuration Fields

### listen (global)
- **Type**: Object
- **Optional**: Yes (uses default values if not specified)
- **Description**: Network listening configuration for the proxy.
- **Fields**:
  - addrs: The IP addresses to bind the server to (default: `"[::]"`), or
    interface name(s) prefixed with `if#`; e.g. `"if#eth0"`.
  - insecure_port: The HTTP port to listen on (default: 80)
  - tls_port: The HTTPS port to listen on (default: 443)

### vhosts
- **Type**: Array of objects
- **Required**: Yes
- **Description**: List of virtual hosts (domains) that this server will handle.

### hostname (within vhost)
- **Type**: String
- **Required**: Yes (within each vhost)
- **Description**: The primary hostname for this virtual host. Used for TLS certificate generation when using ACME.
- **Example**: `hostname = "example.com"`

### aliases (within vhost)
- **Type**: Array of strings
- **Default**: Empty array
- **Description**: Additional domain names that should be handled by this virtual host.
- **Example**: `aliases = ["www.example.com", "api.example.com"]`

### tls (within vhost)
- **Type**: Object
- **Required**: Yes (within each vhost)
- **Description**: TLS configuration for HTTPS connections for this virtual host.
- **Fields**:
  - acme: Configuration for ACME certificate provisioning
  - files: Configuration for using existing certificate files

### backends (within vhost)
- **Type**: Array of objects
- **Required**: Yes (within each vhost)
- **Description**: List of backend services that this virtual host will proxy requests to.
- **Fields**:
  - path (also accepts `context`): The URL path prefix this backend handles (default: "/")
  - url: The backend service URL
  - trust: Whether to skip certificate verification for TLS backends (default: false)
  - auth_key: If set, requires `Authorization: Bearer <key>` to access this backend. (optional)
  - static_root: Path to the directory containing static files. Required when `url` is `module://static`. (optional)

## TLS Configuration

### TLS with Certificate Files

```corn
tls = {
  files = {
    keyfile = "/path/to/private.key"
    certfile = "/path/to/certificate.crt"
    reload = true
  }
}
```

**Fields**:
- keyfile: Path to the private key file (required)
- certfile: Path to the certificate file (required)
- reload: Whether to watch for changes and reload certificates (default: true)

### TLS with ACME HTTP provisioning

```corn
tls = {
  acme = {
    acme_provider = "letsencrypt"  // Default & only supported provider
    contact = "admin@example.com"
    challenge.type = "http-01"
    profile = "shortlived"  // or "tlsserver"
    directory = "/var/lib/vicarian/acme"  // Default
  }
}
```

**Fields**:
- acme_provider: ACME provider (default: "letsencrypt")
- contact: Email address for certificate notifications (required)
- challenge.type: Challenge type - "http-01" or "dns-01" (required)
- profile: Certificate profile - "shortlived" for short-lived certs, "tlsserver" for long-lived (default: "tlsserver")
- directory: Directory to store ACME account and certificate data (default: "/var/lib/vicarian/acme")

### TLS with ACME DNS provisioning

```corn
tls = {
  acme = {
    acme_provider = "letsencrypt"  // Default & only supported provider
    contact = "admin@example.com"
    challenge = {
      type = "dns-01"
      dns_provider = {
        name = "porkbun"
        key = $env_PORKBUN_KEY
        secret = $env_PORKBUN_SECRET
      }
    }
    profile = "tlsserver"
    wildcard = false
  }
}
```

**Fields**:
- acme_provider: ACME provider (default: "letsencrypt")
- contact: Email address for certificate notifications (required)
- challenge.type: Challenge type - must be "dns-01" for DNS challenges
- challenge.dns_provider: DNS provider configuration (required for DNS-01)
  - name: DNS provider name (e.g., "porkbun")
  - key: API key for the DNS provider
  - secret: API secret for the DNS provider
- profile: Certificate profile - "shortlived" or "tlsserver" (default: "tlsserver")
- wildcard: Whether to generate a wildcard certificate. (default: false)

## Backend Configuration

Each backend entry has the following fields:

### path
- **Type**: String
- **Default**: "/"
- **Description**: The URL path prefix that this backend will handle. For example, if `path = "/api"`, requests to `/api/endpoint` will be forwarded to the backend.

### url
- **Type**: String (URI)
- **Required**: Yes
- **Description**: The URL of the backend service to proxy requests to.

### trust
- **Type**: Boolean
- **Default**: false
- **Description**: Set to true if the backend uses a self-signed certificate or certificate that can't be verified by the system's CA store.

### auth_key
- **Type**: String
- **Default**: None
- **Description**: If set, Vicarian will require an `Authorization: Bearer <key>` header with the specified key to allow access to this backend.

### static_root
- **Type**: String (filesystem path)
- **Default**: None
- **Description**: Path to the directory containing static files to serve. This field is required when using the `module://static` backend. The path is relative to the current working directory when Vicarian starts.
- **Example**: `static_root = "/var/www/static"`

## Special Backend Modules

Vicarian supports builtin backend modules that can be used in place of a standard URL. These are specified using the `module://` scheme.

### Metrics Module

The `metrics` module provides a Prometheus-compatible metrics endpoint.
See [METRICS.md](METRICS.md) for configuration details and available metrics.

```corn
backends = [
    {
        path = "/metrics"
        url = "module://metrics"
        auth_key = "secret_key" // Optional
    }
]
```

### Static Files Module

The `static` module serves files from a local directory as a static file server. It supports directory listing, fallback pages, and automatic compression.

```corn
backends = [
    {
        path = "/"
        url = "module://static"
        static_root = "/var/www/html"
        auth_key = "secret_key" // Optional
    }
]
```

**Fields**:
- path: The URL path prefix for serving static files (default: "/")
- url: Must be `module://static` to enable static file serving
- static_root: Path to the directory containing static files (required)
- auth_key: If set, requires `Authorization: Bearer <key>` to access files (optional)

**Features**:
- **Directory listing**: When a directory is requested and no index file exists, a directory listing is generated.
- **Fallback page**: If an `index.html` file exists in the static root, it is served for requests that don't match any file (useful for SPAs).
- **Content-Type detection**: File types are automatically determined based on file extension.
- **Compression**: Responses are compressed when the client supports it (gzip, brotli).
- **HEAD requests**: Supported—returns headers without a body.
- **Security headers**: Automatically adds `Strict-Transport-Security` and `Via` headers to all responses.

## Additional Configuration Options

### dev_mode (global)
- **Type**: Boolean
- **Default**: false
- **Description**: Enables development mode with relaxed security settings. This should not be used in production environments.

## Environment Variables

Configuration supports environment variable substitution using the `$env_VARIABLE_NAME` syntax. This allows sensitive information like API keys to be kept out of configuration files.

```corn
let {
    $env_PORKBUN_KEY = "fallback value"
    $env_PORKBUN_SECRET = "fallback value"

} in {
    // Configuration here can use $env_VARIABLE_NAME
}
```
