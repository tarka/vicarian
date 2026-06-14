use std::sync::Arc;

use itertools::Itertools;
use tracing::{debug, info};

use crate::config::Backend;

pub struct Match {
    pub backend: Arc<Backend>,
    pub _rest: String,
}

#[derive(Debug)]
struct Entry {
    prefix: String,
    backend: Arc<Backend>,
}
#[derive(Debug)]
pub struct Router {
    prefixes: Vec<Entry>,
}
impl Router {

    pub fn new(backends: &Vec<Backend>) -> Self {
        // We store the lookups as a sorted vec and do a binary search
        // through it below. This is simpler than using a radix-trie,
        // and faster with a small numbers of entries (< ~1k).
        let prefixes = backends.iter()
            .map(|b| {
                let backend = Arc::new(b.clone());
                let prefix = b.path.clone()
                        .unwrap_or("/".to_string());
                info!("Inserting path {prefix}");
                Entry {
                    prefix,
                    backend,
                }
            })
            .sorted_by(|a, b| a.prefix.cmp(&b.prefix))
            .collect();

        Router {
            prefixes,
        }
    }

    fn to_match(&self, pos: usize, uri_path: &str) -> Match {
        let prefix = &self.prefixes[pos];
        let rest = &uri_path[prefix.prefix.len()..];
        Match {
            backend: prefix.backend.clone(),
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
        let matched = self.prefixes
            .binary_search_by(|entry| entry.prefix.as_str().cmp(uri_path));

        match matched {
            Ok(pos) => {
                debug!("Exact match: {}", self.prefixes[pos].prefix);
                Some(self.to_match(pos, uri_path))
            }

            Err(pos) => {
                debug!("Miss; finding closest");
                for i in (0..pos).rev() {
                    let prefix = &self.prefixes[i].prefix;

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
