use std::path::PathBuf;
use camino::Utf8PathBuf;


/// Domain and transient errors across the proxy.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("TLS Key & Cert don't match: {0}, {1}")]
    CertificateMismatch(Utf8PathBuf, Utf8PathBuf),

    #[error(transparent)]
    RustlsError(#[from] rustls::Error),

    #[error("No leading slash in context path: {0}")]
    NoLeadingSlash(String),

    #[error("Context path cannot be empty")]
    EmptyContextPath,

    #[error("Unexpected address prefix: {0}")]
    UnexpectedAddressPrefix(String),

    #[error("No matching TLS declaration for '{0}'")]
    NoMatchingTlsDeclaration(String),

    #[error("No valid scheme (`http`, `https`) in URI {0}")]
    InvalidUriScheme(String),

    #[error("No hostname in URI {0}")]
    NoHostnameInUri(String),

    #[error("Duplicate paths in backend")]
    DuplicateBackendPaths,

    #[cfg_attr(not(test), allow(dead_code))]
    #[error("Failed to find '{0}' in vhost")]
    BackendNotFound(String),

    #[cfg_attr(not(test), allow(dead_code))]
    #[error("Vhost not found: {0}")]
    VhostNotFound(String),

    #[error("Unexpected backend type: {0}")]
    UnexpectedBackendType(String),

    #[error("Failed to find default crypto provider in rustls")]
    MissingCryptoProvider,

    #[error("No certificates found in TLS .crt file")]
    NoCertificatesFound,

    #[error("Invalid path encoding: {0:#?}")]
    InvalidPathEncoding(PathBuf),

    #[error("Path not found in store: {0}")]
    PathNotFoundInStore(Utf8PathBuf),

    #[error("Matching host for {0} not found in cert store")]
    HostNotFoundInCertStore(String),

    #[error("File {0} not found in cert store")]
    FileNotFoundInCertStore(Utf8PathBuf),

    #[error("Failed to find base domain for {0}")]
    BaseDomainNotFound(String),

    #[error("Invalid host for wildcard certificate: {0}")]
    InvalidWildcardHost(String),

    #[error("No supported profile {0}")]
    UnsupportedAcmeProfile(String),

    #[error("Failed to lock {0}: {1}")]
    LockError(String, String),

    #[error("Nothing expiring; this shouldn't really happen. Exiting.")]
    NothingExpiring,

    #[error("Failed to renew {0} due to unexpected upstream status {1}")]
    UnexpectedAcmeAuthStatus(String, String),

    #[error("No {0} challenge found")]
    AcmeChallengeNotFound(String),

    #[error("Unexpected order status: {0}")]
    UnexpectedAcmeOrderStatus(String),

    #[error("Failed to find record {0} in public DNS")]
    DnsRecordNotFound(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
