use std::sync::Arc;

use itertools::Itertools;
use tracing::debug;

use crate::{config::Backend, proxy::Handler};


pub struct RouterBackend {
    pub config: Backend,
    pub handler: Option<Box<dyn Handler>>,
}

pub struct Router {
    backends: Vec<Arc<RouterBackend>>,
}

pub struct Match {
    pub backend: Arc<RouterBackend>,
    pub _rest: String,
}


impl Router {

    pub fn new(backends: Vec<RouterBackend>) -> Self {
        // We store the lookups as a sorted vec and do a binary search
        // through it below. This is simpler than using a radix-trie,
        // and faster with a small numbers of entries (< ~1k).
        let sorted = backends.into_iter()
            .map(Arc::new)
            .sorted_by(|a, b| a.config.path.cmp(&b.config.path))
            .collect();

        Router {
            backends: sorted,
        }
    }

    fn to_match(&self, pos: usize, uri_path: &str) -> Match {
        let backend = &self.backends[pos];
        let rest = &uri_path[backend.config.path.len()..];
        Match {
            backend: backend.clone(),
            _rest: rest.to_string(),
        }
    }

    pub fn lookup(&self, uri_path: &str) -> Option<Match> {
        debug!("Looking up {uri_path}");
        // From `binary_search_by()`:
        //
        //     If the value is found then [`Result::Ok`] is returned,
        //     containing the index of the matching element.
        //     ...
        //     If the value is not found then [`Result::Err`] is
        //     returned, containing the index where a matching element
        //     could be inserted while maintaining sorted order.
        //
        // Thus Err(pos) one after the closest partial match, so we
        // walk backwards to find the longest actual match.
        let matched = self.backends
            .binary_search_by(|b| b.config.path.as_str().cmp(uri_path));

        match matched {
            Ok(pos) => {
                debug!("Exact match: {}", self.backends[pos].config.path);
                Some(self.to_match(pos, uri_path))
            }

            Err(pos) => {
                debug!("Miss; finding closest");
                for i in (0..pos).rev() {
                    let prefix = &self.backends[i].config.path;

                    debug!("Comparing {prefix}");
                    if uri_path.starts_with(prefix.as_str()) {
                        let remainder = &uri_path[prefix.len()..];

                        // Either we're the root fallback or the
                        // remainder is non-path content. This ensures
                        // e.g. /api2 doesn't match /api.
                        if prefix == "/" || remainder.starts_with(['/', '?', '#']) {
                            debug!("Matched {prefix}");
                            return Some(self.to_match(i, uri_path))
                        }
                    }
                }
                debug!("No Match");
                None
            }
        }

    }
}
