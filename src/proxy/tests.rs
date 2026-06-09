use anyhow::Result;
use http::{uri::Builder, Uri};
use test_log::test;

use crate::{
    config::{Backend, UrlPath},
    proxy::{rewrite_port, router::Router, strip_port}
};

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
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:2020"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/service/subservice/")?),
            url: Uri::from_static("http://localhost:3030"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/other_service/")?),
            url: Uri::from_static("http://localhost:4040"),
            trust: false,
            auth_key: None,
        },
    ];

    let router = Router::new(&backends);

    let matched = router.lookup("/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/base/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("base/path", matched._path);

    let matched = router.lookup("/service").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/service/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/service/some/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/some/path", matched._path);

    let matched = router.lookup("/service/subservice").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/service/subservice/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/service/subservice/ss/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/ss/path", matched._path);

    let matched = router.lookup("/other_service/some/path").unwrap();
    assert_eq!(Uri::from_static("http://localhost:4040"), matched.backend.url);
    assert_eq!("/some/path", matched._path);

    Ok(())
}


#[test]
fn test_router_overlapping_prefixes() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/api")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/api/v2")?),
            url: Uri::from_static("http://localhost:2020"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];

    let router = Router::new(&backends);

    let matched = router.lookup("/api/v2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api/v2/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/api/v2/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/deep", matched._path);

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/api/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/deep", matched._path);

    Ok(())
}

#[test]
fn test_router_prefix_ambiguity() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/api")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/api2")?),
            url: Uri::from_static("http://localhost:2020"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/api1")?),
            url: Uri::from_static("http://localhost:3030"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];

    let router = Router::new(&backends);

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/api/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/deep", matched._path);

    let matched = router.lookup("/api2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api2/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/api2/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("/deep", matched._path);

    let matched = router.lookup("/api1").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api1/").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/", matched._path);

    let matched = router.lookup("/api1/deep").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/deep", matched._path);

    let matched = router.lookup("/other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    assert_eq!("other", matched._path);

    Ok(())
}

#[test]
fn test_router_empty_backends() -> Result<()> {
    let backends: Vec<Backend> = vec![];
    let router = Router::new(&backends);
    assert!(router.lookup("/anything").is_none());
    Ok(())
}

#[test]
fn test_router_no_default_backend() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    assert!(router.lookup("/service").is_some());

    assert!(router.lookup("/other").is_none());
    assert!(router.lookup("/").is_none());
    Ok(())
}

#[test]
#[should_panic]
fn test_router_empty_context() {
    let _backends = [
        Backend {
            context: Some(UrlPath::try_new("").unwrap()),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
}

#[test]
fn test_router_single_slash_context() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/anything").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("anything", matched._path);
    Ok(())
}

#[test]
fn test_router_none_context_is_root() -> Result<()> {
    let backends = vec![
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/anything").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("anything", matched._path);
    Ok(())
}

#[test]
fn test_router_duplicate_contexts() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/x")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/x")?),
            url: Uri::from_static("http://localhost:2020"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/x").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("", matched._path);
    Ok(())
}

#[test]
fn test_router_three_level_overlap() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/api")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/api/v2")?),
            url: Uri::from_static("http://localhost:2020"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/api/v2/deep")?),
            url: Uri::from_static("http://localhost:3030"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);

    let matched = router.lookup("/api/v2/deep/extra").unwrap();
    assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
    assert_eq!("/extra", matched._path);

    let matched = router.lookup("/api/v2").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);

    let matched = router.lookup("/api/v3").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/v3", matched._path);

    let matched = router.lookup("/other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    assert_eq!("other", matched._path);

    Ok(())
}

#[test]
fn test_router_query_string() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service?foo=bar").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("?foo=bar", matched._path);
    Ok(())
}

#[test]
fn test_router_fragment() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service#section").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("#section", matched._path);
    Ok(())
}

#[test]
fn test_router_path_traversal() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service/../other").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/../other", matched._path);
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
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);
    Ok(())
}

#[test]
fn test_router_double_slash_prefix() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("//").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    let matched = router.lookup("//service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    Ok(())
}

#[test]
fn test_router_double_slash_in_path() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service//foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("//foo", matched._path);
    Ok(())
}

#[test]
fn test_router_multiple_trailing_slashes() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service///")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/foo", matched._path);
    Ok(())
}

#[test]
fn test_router_case_sensitivity() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/Service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/Service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/foo", matched._path);
    let matched = router.lookup("/service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    Ok(())
}

#[test]
fn test_router_url_encoded_path() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service/path%2Fwith%2Fslashes").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/path%2Fwith%2Fslashes", matched._path);
    Ok(())
}

#[test]
fn test_router_context_with_dot() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/api.v2")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/api.v2/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/foo", matched._path);
    let matched = router.lookup("/api/v2/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    Ok(())
}

#[test]
fn test_router_context_dot_and_dotdot() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/.")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: Some(UrlPath::try_new("/..")?),
            url: Uri::from_static("http://localhost:2020"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/.").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    let matched = router.lookup("/..").unwrap();
    assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
    Ok(())
}

#[test]
fn test_router_context_whitespace() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/service ")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
        Backend {
            context: None,
            url: Uri::from_static("http://localhost:9999"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/service /foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("/foo", matched._path);
    let matched = router.lookup("/service/foo").unwrap();
    assert_eq!(Uri::from_static("http://localhost:9999"), matched.backend.url);
    Ok(())
}

#[test]
fn test_router_params_empty_match() -> Result<()> {
    let backends = vec![
        Backend {
            context: Some(UrlPath::try_new("/exact")?),
            url: Uri::from_static("http://localhost:1010"),
            trust: false,
            auth_key: None,
        },
    ];
    let router = Router::new(&backends);
    let matched = router.lookup("/exact").unwrap();
    assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
    assert_eq!("", matched._path);
    Ok(())
}
