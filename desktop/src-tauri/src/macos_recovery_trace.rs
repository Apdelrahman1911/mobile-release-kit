//! Nonshipping, fixed-size failure DATA. Never writes private worker channels.
use std::{cell::Cell, panic::Location};

#[derive(Clone, Copy)]
pub struct Comparison {
    pub original: usize,
    pub parent: Option<usize>,
    pub role: u8,
    pub exact: bool,
    pub expected: [i128; 12],
    pub actual: [i128; 12],
    pub named: [i128; 12],
}

#[derive(Clone, Copy)]
struct Check {
    reason: &'static str,
    site: &'static Location<'static>,
    comparison: Option<Comparison>,
}

#[derive(Clone, Copy)]
struct ParentFailure {
    reason: &'static str,
    check: Option<Check>,
}

thread_local! {
    static LAST: Cell<Option<Check>> = const { Cell::new(None) };
    static FIRST_PARENT: Cell<Option<ParentFailure>> = const { Cell::new(None) };
    static PENDING: Cell<Option<(&'static Location<'static>, Comparison)>> = const { Cell::new(None) };
}
const _: () = assert!(std::mem::size_of::<Option<Check>>()
    + std::mem::size_of::<Option<ParentFailure>>()
    + std::mem::size_of::<Option<(&'static Location<'static>, Comparison)>>() <= 2048);

pub fn reset() {
    LAST.set(None);
    FIRST_PARENT.set(None);
    PENDING.set(None);
}

pub fn comparison(site: &'static Location<'static>, value: Comparison) {
    PENDING.set(Some((site, value)));
}

pub fn check_refused(reason: &'static str, site: &'static Location<'static>) {
    let comparison = PENDING.take().and_then(|(at, value)|
        (reason == "original-correspondence" && at == site).then_some(value));
    LAST.set(Some(Check { reason, site, comparison }));
}

pub fn note_parent(reason: &'static str) {
    if FIRST_PARENT.get().is_none() {
        let check = LAST.get().filter(|value| value.reason == reason);
        FIRST_PARENT.set(Some(ParentFailure { reason, check }));
    }
}

fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn render(reason: &'static str) -> Option<String> {
    if !label(reason) { return None; }
    let check = FIRST_PARENT.get().filter(|value| value.reason == reason).and_then(|value| value.check);
    let (site, identity) = if let Some(check) = check {
        // The basename and line identify frozen source; never emit local paths.
        let file = check.site.file().rsplit('/').next()?;
        if file.len() > 64 || !file.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') {
            return None;
        }
        let site = format!("{{\"file\":\"{file}\",\"line\":{},\"column\":{}}}", check.site.line(), check.site.column());
        let identity = if let Some(value) = check.comparison {
            let parent = value.parent.map_or_else(|| "null".to_owned(), |n| n.to_string());
            format!("{{\"original\":{},\"parent\":{parent},\"role\":{},\"exact\":{},\"expected\":{:?},\"actual\":{:?},\"named\":{:?}}}",
                value.original, value.role, value.exact, value.expected, value.actual, value.named)
        } else { "null".to_owned() };
        (site, identity)
    } else { ("null".to_owned(), "null".to_owned()) };
    let line = format!("MRK_RECOVERY_DIAGNOSTIC={{\"schemaVersion\":1,\"scope\":\"outer-parent-failure-data\",\"reason\":\"{reason}\",\"check\":{site},\"comparison\":{identity},\"workerContextClaimed\":false}}\n");
    (line.len() <= 4096).then_some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_parent_failure_matches_its_check_and_preserves_native_samples() {
        reset();
        let site = Location::caller();
        let value = Comparison { original: 7, parent: Some(3), role: 0, exact: true,
            expected: [1; 12], actual: [1; 12], named: [2; 12] };
        comparison(site, value);
        check_refused("original-correspondence", site);
        note_parent("original-correspondence");
        check_refused("later-close", site);
        note_parent("later-close");
        let output = render("original-correspondence").unwrap();
        assert!(output.contains("\"original\":7") && output.contains("\"parent\":3"));
        assert!(output.contains("\"named\":[2, 2, 2") && output.contains("\"actual\":[1, 1, 1"));
        assert!(!output.contains("/Users/") && output.len() <= 4096);
        assert!(render("later-close").unwrap().contains("\"check\":null"));
    }

    #[test]
    fn unmatched_errors_are_reported_without_inventing_source_or_worker_context() {
        reset();
        check_refused("ignored-optional-check", Location::caller());
        note_parent("native-read");
        let output = render("native-read").unwrap();
        assert!(output.contains("\"reason\":\"native-read\""));
        assert!(output.contains("\"check\":null,\"comparison\":null"));
        assert!(output.contains("\"workerContextClaimed\":false"));
        for wrong in ["", "path/contents", "line\nfeed", "UPPERCASE"] {
            assert!(render(wrong).is_none());
        }
        reset();
        comparison(Location::caller(), Comparison { original: usize::MAX, parent: None, role: 255, exact: false,
            expected: [i128::MIN; 12], actual: [i128::MAX; 12], named: [i128::MIN; 12] });
        // A pending sample cannot leak into a different source location/reason.
        check_refused("read-bound", Location::caller());
        note_parent("read-bound");
        assert!(render("read-bound").unwrap().contains("\"comparison\":null"));
    }
}
