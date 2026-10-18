//! Simultaneous original descriptors for the installed Mac runtime Book.
//! This is capacity accounting, not authority to open an additional path.

// protected_app_once: install ancestry4 + app/payload7 + fixed code group10.
const PROTECTED_APP: usize = 4 + 7 + 10;
// inspect separately opens runtime ancestry7 and its manifest1.
const RUNTIME_ROOT: usize = 7 + 1;
const LAUNCH_ORIGINALS: usize = 5; // python/bin/python3 + core + one bootstrap.
const STORE_ORIGINALS: usize = 14; // Union of retained Store paths and ancestors.
const HISTORY_ORIGINALS: usize = 2; // tools and tools/gh.
// walk opens a leaf at depth16; Store paths admit their additional prefix.
pub(crate) const WALK_DEPTH: usize = 16;
pub(crate) const LIVE_FDS: usize = PROTECTED_APP + RUNTIME_ROOT + LAUNCH_ORIGINALS
    + STORE_ORIGINALS + HISTORY_ORIGINALS + WALK_DEPTH + 1;

pub(crate) fn admits_next(live: usize) -> bool { live < LIVE_FDS }

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, path::Path};

    fn retained(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().flat_map(|path| Path::new(path).ancestors())
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| path.to_str().unwrap().to_owned()).collect()
    }

    #[test]
    fn admitted_deep_paths_fit_after_retained_siblings_without_unbounded_growth() {
        // Independent path vectors, not generated from the new budget. The full
        // path grammar is covered by runtime tests; this is capacity DATA only.
        let launch = retained(&["python/bin/python3", "core.zip", "engine_bootstrap.py"]);
        let store = retained(&["store", "store/bin/ruby", "store/bin/bundle",
            "store/lib/ruby/gems/3.3.0/gems/bundler-4.0.16/exe/bundle", "store/ca.pem", "store/tooling"]);
        let history = retained(&["tools/gh"]);
        let leaf = "store/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/file";
        let depth = Path::new(leaf).components().count();
        assert_eq!((launch.len(), store.len(), history.len(), depth), (5, 14, 2, 17));
        let fixed = Path::new("/Library/Application Support/MobileReleaseKit").components().count()
            + 7 + 10 + Path::new("/Library/Application Support/MobileReleaseKit/versions/release/runtime").components().count() + 1;
        assert_eq!(fixed, 29);
        // Directory iteration is not ordered. Previously visited sibling roots
        // remain live while the next deepest path is being inspected.
        let passive_peak = fixed + launch.len() + depth;
        let store_peak = passive_peak + store.len(); // Conservative shared-prefix overcount.
        assert_eq!((passive_peak, store_peak), (51, 65));
        assert!(passive_peak > 48); // Reproduces the old admitted-layout shortfall.
        for peak in [passive_peak, store_peak, store_peak + history.len()] {
            for live_before_open in 0..peak { assert!(admits_next(live_before_open)); }
        }
        assert_eq!(LIVE_FDS, 67);
        assert!(!admits_next(LIVE_FDS));
        assert!(!admits_next(usize::MAX));
    }
}
