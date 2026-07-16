use anyhow::Result;
use http::{uri::Builder, Uri};
use test_log::test;

use crate::{
    config::{Backend, ValidateSanitise},
    proxy::{rewrite_port, router::{Router, RouterBackend}, strip_port}
};

fn backend(path: &str, port: u16) -> Backend {
    Backend {
        path: path.to_string(),
        url: Uri::try_from(format!("http://localhost:{port}")).unwrap(),
        trust: false,
        auth_key: None,
        static_root: None,
    }
}

impl From<Backend> for RouterBackend {
    fn from(b: Backend) -> Self {
        RouterBackend {
            config: b,
            handler: None,
        }
    }
}

#[test]
fn test_uri_rewrite() -> Result<()> {
    let uri = Uri::from_static("http://example.com/a/path?param=value");
    let changed = Builder::from(uri)
        .scheme("https")
        .build()?;
    assert_eq!("https://example.com/a/path?param=value", changed.to_string());
    Ok(())
}

#[test]
fn test_host_port_rewrite() -> Result<()> {
    let replaced = rewrite_port("example.com:8080", "8443");
    assert_eq!("example.com:8443", replaced);
    let replaced = rewrite_port("example.com", "8443");
    assert_eq!("example.com", replaced);
    Ok(())
}

#[test]
fn test_port_strip() -> Result<()> {
    let host_header = "example.com:8443";
    let host = strip_port(host_header);
    assert_eq!("example.com", host);

    Ok(())
}

#[test]
fn test_no_port_strip() -> Result<()> {
    let host_header = "example.com";
    let host = strip_port(host_header);
    assert_eq!("example.com", host);

    Ok(())
}

#[test]
fn test_strip_port_ipv6() -> Result<()> {
    let host = strip_port("[::1]:8080");
    assert_eq!("[::1]", host);

    let host = strip_port("[::1]");
    assert_eq!("[::1]", host);

    Ok(())
}

#[test]
fn test_router() -> Result<()> {
    let backends = vec![
        backend("/", 1010),
        backend("/service", 2020),
        backend("/service/subservice/", 3030),
        backend("/other_service/", 4040),
    ].validate_and_sanitise()?;

    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let matched = router.lookup("/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/base/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("base/path", matched._rest);

    let matched = router.lookup("/service").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/service/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/service/some/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("/some/path", matched._rest);

    let matched = router.lookup("/service/subservice").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/service/subservice/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/service/subservice/ss/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("/ss/path", matched._rest);

    let matched = router.lookup("/other_service/some/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:4040"), matched.backend.config.url);
    assert_eq!("/some/path", matched._rest);

    Ok(())
}


#[test]
fn test_router_overlapping_prefixes() -> Result<()> {
    let backends = vec![
        backend("/api", 1010),
        backend("/api/v2", 2020),
        backend("/", 9999),
    ].validate_and_sanitise()?;

    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let matched = router.lookup("/api/v2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api/v2/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/api/v2/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("/deep", matched._rest);

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/api/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/deep", matched._rest);

    Ok(())
}

#[test]
fn test_router_prefix_ambiguity() -> Result<()> {
    let backends = vec![
        backend("/api", 1010),
        backend("/api2", 2020),
        backend("/api1", 3030),
        backend("/", 9999),
    ].validate_and_sanitise()?;

    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/api/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/deep", matched._rest);

    let matched = router.lookup("/api2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api2/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/api2/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("/deep", matched._rest);

    let matched = router.lookup("/api1").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api1/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("/", matched._rest);

    let matched = router.lookup("/api1/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("/deep", matched._rest);

    let matched = router.lookup("/other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    assert_eq!("other", matched._rest);

    Ok(())
}

#[test]
fn test_router_empty_backends() -> Result<()> {
    let backends: Vec<RouterBackend> = vec![];
    let router = Router::new(backends);
    assert!(router.lookup("/anything").is_none());
    Ok(())
}

#[test]
fn test_router_no_default_backend() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    assert!(router.lookup("/service").is_some());

    assert!(router.lookup("/other").is_none());
    assert!(router.lookup("/").is_none());
    Ok(())
}

#[test]
fn test_router_empty_context() {
    let result = vec![
        Backend {
            path: "".to_string(),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
            static_root: None,
        },
    ].validate_and_sanitise();
    assert!(result.is_err());
}

#[test]
fn test_router_single_slash_context() -> Result<()> {
    let backends = vec![
        backend("/", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/anything").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("anything", matched._rest);
    Ok(())
}

#[test]
fn test_router_none_context_is_root() -> Result<()> {
    let backends = vec![
        backend("/", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/anything").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("anything", matched._rest);
    Ok(())
}

#[test]
fn test_router_duplicate_contexts() -> Result<()> {
    let result = vec![
        backend("/x", 1010),
        backend("/x", 2020),
    ].validate_and_sanitise();
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_router_three_level_overlap() -> Result<()> {
    let backends = vec![
        backend("/api", 1010),
        backend("/api/v2", 2020),
        backend("/api/v2/deep", 3030),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let matched = router.lookup("/api/v2/deep/extra").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.config.url);
    assert_eq!("/extra", matched._rest);

    let matched = router.lookup("/api/v2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api/v3").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/v3", matched._rest);

    let matched = router.lookup("/other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    assert_eq!("other", matched._rest);

    Ok(())
}

#[test]
fn test_router_query_string() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service?foo=bar").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("?foo=bar", matched._rest);
    Ok(())
}

#[test]
fn test_router_fragment() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service#section").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("#section", matched._rest);
    Ok(())
}

#[test]
fn test_router_path_traversal() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service/../other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/../other", matched._rest);
    Ok(())
}

#[test]
fn test_rewrite_port_ipv6() -> Result<()> {
    let replaced = rewrite_port("[::1]:8080", "443");
    assert_eq!("[::1]:443", replaced);

    let replaced = rewrite_port("[::1]", "443");
    assert_eq!("[::1]", replaced);

    Ok(())
}

#[test]
fn test_rewrite_port_edge_cases() -> Result<()> {
    let replaced = rewrite_port("a:b:c", "80");
    assert_eq!("a:b:c", replaced);

    let replaced = rewrite_port("", "80");
    assert_eq!("", replaced);

    Ok(())
}

#[test]
fn test_router_empty_path() -> Result<()> {
    let backends = vec![
        backend("/", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);
    Ok(())
}

#[test]
fn test_router_double_slash_prefix() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("//").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    let matched = router.lookup("//service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    Ok(())
}

#[test]
fn test_router_double_slash_in_path() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service//foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("//foo", matched._rest);
    Ok(())
}

#[test]
fn test_router_multiple_trailing_slashes() -> Result<()> {
    let backends = vec![
        backend("/service///", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/foo", matched._rest);
    Ok(())
}

#[test]
fn test_router_case_sensitivity() -> Result<()> {
    let backends = vec![
        backend("/Service", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/Service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/foo", matched._rest);
    let matched = router.lookup("/service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    Ok(())
}

#[test]
fn test_router_url_encoded_path() -> Result<()> {
    let backends = vec![
        backend("/service", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service/path%2Fwith%2Fslashes").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/path%2Fwith%2Fslashes", matched._rest);
    Ok(())
}

#[test]
fn test_router_context_with_dot() -> Result<()> {
    let backends = vec![
        backend("/api.v2", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/api.v2/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/foo", matched._rest);
    let matched = router.lookup("/api/v2/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    Ok(())
}

#[test]
fn test_router_context_dot_and_dotdot() -> Result<()> {
    let backends = vec![
        backend("/.", 1010),
        backend("/..", 2020),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/.").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    let matched = router.lookup("/..").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.config.url);
    Ok(())
}

#[test]
fn test_router_context_whitespace() -> Result<()> {
    let backends = vec![
        backend("/service ", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/service /foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/foo", matched._rest);
    let matched = router.lookup("/service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    Ok(())
}

#[test]
fn test_router_params_empty_match() -> Result<()> {
    let backends = vec![
        backend("/exact", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());
    let matched = router.lookup("/exact").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);
    Ok(())
}

#[test]
fn test_router_prefix_no_match_fallback_to_root() -> Result<()> {
    let backends = vec![
        backend("/api", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("", matched._rest);

    let matched = router.lookup("/api/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("/deep", matched._rest);

    let matched = router.lookup("/api2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    assert_eq!("api2", matched._rest);

    let matched = router.lookup("/api2/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    assert_eq!("api2/deep", matched._rest);

    let matched = router.lookup("/other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);
    assert_eq!("other", matched._rest);

    Ok(())
}

#[test]
fn test_router_query_string_with_overlapping_prefix() -> Result<()> {
    let backends = vec![
        backend("/api", 1010),
        backend("/api/v2", 2020),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    // "/api?version=2" should match /api, not /api/v2
    let matched = router.lookup("/api?version=2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);
    assert_eq!("?version=2", matched._rest);

    Ok(())
}

#[test]
fn test_router_uri_is_prefix_of_backend() -> Result<()> {
    let backends = vec![
        backend("/service/deep", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    // URI is a prefix of the backend path, not the other way around
    assert!(router.lookup("/service").is_none());
    assert!(router.lookup("/service/").is_none());
    assert!(router.lookup("/service/d").is_none());

    // Exact and sub-path should work
    assert!(router.lookup("/service/deep").is_some());
    assert!(router.lookup("/service/deep/more").is_some());

    Ok(())
}

#[test]
fn test_router_very_long_path() -> Result<()> {
    let backends = vec![
        backend("/svc", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let long_suffix = "/a".repeat(5000);
    let long_path = format!("/svc{long_suffix}");
    let matched = router.lookup(&long_path).unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.config.url);

    // Unmatched long path falls to root
    let unmatched_long = format!("/other{long_suffix}");
    let matched = router.lookup(&unmatched_long).unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);

    Ok(())
}

#[test]
fn test_router_many_backends() -> Result<()> {
    let mut backends: Vec<RouterBackend> = (0..100).map(|i| {
        backend(&format!("/svc{i:03}"), 1000 + i).into()
    }).collect();
    backends.push(backend("/", 9999).into());

    let router = Router::new(backends);

    let m = router.lookup("/svc000/x").unwrap();
    assert_eq!(1000, m.backend.config.url.port_u16().unwrap());

    let m = router.lookup("/svc050").unwrap();
    assert_eq!(1050, m.backend.config.url.port_u16().unwrap());

    let m = router.lookup("/svc099/deep/path").unwrap();
    assert_eq!(1099, m.backend.config.url.port_u16().unwrap());

    // Non-matching falls to root
    let m = router.lookup("/svc100").unwrap();
    assert_eq!(9999, m.backend.config.url.port_u16().unwrap());

    Ok(())
}

#[test]
fn test_router_encoded_slash_in_prefix_position() -> Result<()> {
    let backends = vec![
        backend("/api", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    // "%2Fapi" is NOT "/api" — should fall through to root
    let matched = router.lookup("/%2Fapi").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.config.url);

    Ok(())
}

#[test]
fn test_router_reverse_input_order() -> Result<()> {
    // Deliberately reverse-alphabetical
    let backends = vec![
        backend("/z", 3030),
        backend("/m", 2020),
        backend("/a", 1010),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let m = router.lookup("/a/x").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), m.backend.config.url);

    let m = router.lookup("/m/x").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), m.backend.config.url);

    let m = router.lookup("/z/x").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), m.backend.config.url);

    Ok(())
}

#[test]
fn test_router_rest_leading_slash_asymmetry() -> Result<()> {
    let backends = vec![
        backend("/svc", 1010),
        backend("/", 9999),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    // Sub-path under named backend: rest INCLUDES leading slash
    let m = router.lookup("/svc/foo").unwrap();
    assert_eq!("/foo", m._rest);

    // Fallback to root: rest does NOT include leading slash
    // because "/" is consumed as the matched prefix
    let m = router.lookup("/other/foo").unwrap();
    assert_eq!("other/foo", m._rest);

    Ok(())
}

#[test]
fn test_router_single_char_segments() -> Result<()> {
    let backends = vec![
        backend("/a", 1010),
        backend("/b", 2020),
    ].validate_and_sanitise()?;
    let router = Router::new(backends.into_iter().map(|b| b.into()).collect());

    let m = router.lookup("/a").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), m.backend.config.url);
    assert_eq!("", m._rest);

    let m = router.lookup("/b/x").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), m.backend.config.url);
    assert_eq!("/x", m._rest);

    // "/c" shouldn't match either
    assert!(router.lookup("/c").is_none());

    // "/ab" should NOT match "/a" (boundary guard)
    assert!(router.lookup("/ab").is_none());

    Ok(())
}
