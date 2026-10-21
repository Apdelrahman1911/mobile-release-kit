//! Pure History runtime storage accounting, not source or execution authority.
//! The native caller still authenticates and walks every original inventory row.
use crate::macos_install_record as data;

pub(crate) const CODE_CONTROL_RESERVE: usize = data::CONTROL_LIMIT;
// The shared application service is now included in every Document census.
// Its retained rows/reply reservations are not spare space in the historical
// 64MiB-minus-48MiB code partition. Keep code independent and use the existing
// complete 64MiB session allowance for Document plus this operation's DATA.
// This is a finite representation bound (192MiB including code), not RSS.
pub(crate) const SHARED_DATA_LIMIT: usize = 64 * 1024 * 1024;
const TREE_CONTROL_LIMIT: usize = 88 * 1024 * 1024;
const PARSE_CONTROL_LIMIT: usize = 64 * 1024 * 1024;
const NAME_COPIES: usize = 7;

/// Charge every retained Document/source/owner/frame byte, with the complete
/// fixed code reservation separate. No private credential quota is enlarged.
pub(crate) fn admission_bytes(document: usize, future: usize) -> Option<usize> {
    let other = future.checked_sub(CODE_CONTROL_RESERVE)?;
    if document.checked_add(other)? > SHARED_DATA_LIMIT { return None; }
    document.checked_add(future)
}

/// The raw input can retain up to twice its byte limit while Vec grows. Parsing
/// (120k bounded nodes, key/string copies and inventory reserialization) and
/// the indexed walk are separate phases. Both retain raw bytes and the original
/// ledger. This checks the containing reservation against actual target types.
pub(crate) fn code_storage_bytes(record_cell: usize, native_frame: usize) -> Option<usize> {
    data::RUNTIME_RECORD_LIMIT.checked_mul(record_cell)?
        .checked_add(native_frame)?
        .checked_add(17 * 65536 + 128 * 1024)?
        .checked_add(data::MANIFEST_LIMIT.checked_mul(2)?)?
        .checked_add(TREE_CONTROL_LIMIT.max(PARSE_CONTROL_LIMIT))
        .filter(|bytes| *bytes <= CODE_CONTROL_RESERVE)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TreeQuote { pub(crate) names: usize, pub(crate) bytes: usize }

/// No retained planner collection: sorted paths make directory descendants
/// contiguous. A parent already shared with the preceding file is charged once.
/// Duplicate/file-directory names are rejected, never used as storage credit.
/// `row` reports the actual owned path/hash capacities, not serialized lengths.
pub(crate) fn tree_quote<T>(files: &[T], file_capacity: usize,
    row: impl for<'a> Fn(&'a T) -> (&'a str, usize, usize)) -> Option<TreeQuote> {
    if files.is_empty() || files.len() > data::FILE_LIMIT || file_capacity < files.len() { return None; }
    let mut previous = "";
    for file in files {
        let (path, capacity, _) = row(file);
        if !path.is_ascii() || !crate::runtime::safe_payload_path(path) || path.len() > 512
            || path <= previous || capacity < path.len() { return None; }
        previous = path;
    }
    let mut names = 0usize;
    let mut strings = 0usize;
    // The consumed Vec backing can coexist with moved PayloadFile map values;
    // the map's own value cells are included in the per-name node debit below.
    let mut other = file_capacity.checked_mul(std::mem::size_of::<T>())?;
    previous = "";
    for file in files {
        let (path, capacity, hash_capacity) = row(file);
        names = names.checked_add(1)?;
        strings = strings.checked_add(capacity)?;
        other = other.checked_add(hash_capacity)?;
        let mut prefix = path;
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            // A file cannot also supply a directory, even if punctuation places
            // a different file between it and its purported child in sort order.
            if files.binary_search_by(|file| row(file).0.cmp(parent)).is_ok() { return None; }
            if !previous.strip_prefix(parent).is_some_and(|tail| tail.starts_with('/')) {
                names = names.checked_add(1)?;
                strings = strings.checked_add(parent.len())?;
            }
            prefix = parent;
        }
        if names > data::ENTRY_LIMIT { return None; }
        previous = path;
    }
    // Payload path + map key + folded + observed + constructed walk path +
    // immediate roster + historical Book name. Full paths overcharge the last
    // two basename copies. Directory names need no more than these same seven.
    let bytes = strings.checked_mul(NAME_COPIES)?
        .checked_add(names.checked_mul(NAME_COPIES * 256)?)?
        .checked_add(other)?;
    (bytes <= TREE_CONTROL_LIMIT).then_some(TreeQuote { names, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn quote(paths: &[String]) -> Option<TreeQuote> {
        tree_quote(paths, paths.len(), |path| (path.as_str(), path.capacity(), 64))
    }
    fn oracle(paths: &[String]) -> usize {
        let mut names = BTreeSet::new();
        for path in paths {
            let mut path = path.as_str();
            loop {
                names.insert(path);
                match path.rsplit_once('/') { Some((parent, _)) => path = parent, None => break }
            }
        }
        names.len()
    }

    #[test]
    fn measured_and_full_file_inventories_count_unique_owned_names() {
        for count in [8_622, data::FILE_LIMIT] {
            let paths: Vec<_> = (0..count).map(|i| format!("store/bundle/ruby/3.3.0/gems/example/lib/{i:05}.rb")).collect();
            let value = quote(&paths).unwrap();
            assert_eq!(value.names, oracle(&paths));
            assert_eq!(value.names, count + 7);
            assert!(value.bytes < TREE_CONTROL_LIMIT);
        }
        let mut paths: Vec<_> = ["a-/leaf", "a.b", "a/b/leaf", "a/bb/leaf", "a/c", "aa/b", "b/z"]
            .into_iter().map(str::to_owned).collect();
        paths.sort();
        assert_eq!(quote(&paths).unwrap().names, oracle(&paths));
        // Shared prefixes stop being a false 8,192-name cap; all file bodies
        // remain independently required by the native complete walk.
        assert!(quote(&vec!["same".into(), "same".into()]).is_none());
    }

    #[test]
    fn tree_shape_capacity_and_overflow_refuse_before_index_allocation() {
        for paths in [vec![], vec!["b", "a"], vec!["a", "a-/other", "a/child"],
            vec!["a/../b"], vec!["a//b"], vec!["é"], vec!["/absolute"]] {
            assert!(quote(&paths.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_none());
        }
        assert!(quote(&vec!["x".repeat(513)]).is_none());
        assert!(quote(&vec![vec!["x"; 18].join("/")]).is_none());
        let paths = vec!["x".repeat(512)];
        assert!(quote(&paths).is_some());
        assert!(tree_quote(&paths, 0, |p| (p.as_str(), p.capacity(), 64)).is_none());
        assert!(tree_quote(&paths, 1, |p| (p.as_str(), p.len() - 1, 64)).is_none());
        assert!(tree_quote(&paths, usize::MAX, |p| (p.as_str(), p.capacity(), 64)).is_none());
        assert!(tree_quote(&paths, 1, |p| (p.as_str(), usize::MAX, 64)).is_none());
        assert!(tree_quote(&paths, 1, |p| (p.as_str(), p.capacity(), usize::MAX)).is_none());
        let paths: Vec<_> = (0..=data::FILE_LIMIT).map(|i| format!("{i:05}")).collect();
        assert!(quote(&paths).is_none());
        let paths: Vec<_> = (0..data::FILE_LIMIT).map(|i| format!("{i:05}/a/b")).collect();
        assert!(quote(&paths).is_none()); // Too many distinct owned directories.
        let paths: Vec<_> = (0..data::FILE_LIMIT).map(|i| format!("{i:05}/leaf")).collect();
        assert_eq!(quote(&paths).unwrap().names, data::ENTRY_LIMIT);
        let paths = vec!["x".to_owned()];
        let fixed = NAME_COPIES * 256 + std::mem::size_of::<String>();
        let capacity = (TREE_CONTROL_LIMIT - fixed) / NAME_COPIES;
        let hash = (TREE_CONTROL_LIMIT - fixed) % NAME_COPIES;
        assert_eq!(tree_quote(&paths, 1, |p| (p.as_str(), capacity, hash)).unwrap().bytes, TREE_CONTROL_LIMIT);
        assert!(tree_quote(&paths, 1, |p| (p.as_str(), capacity, hash + 1)).is_none());
    }

    #[test]
    fn original_backing_and_full_control_reservations_stay_separate() {
        assert_eq!(SHARED_DATA_LIMIT, 64 * 1024 * 1024);
        let peak = 192 * 1024 * 1024;
        for extra in [0, 1, 512 * 1024, SHARED_DATA_LIMIT] {
            let future = CODE_CONTROL_RESERVE + extra;
            let backing = SHARED_DATA_LIMIT - extra;
            assert_eq!(admission_bytes(backing, future), Some(peak));
            if backing > 0 { assert_eq!(admission_bytes(backing - 1, future), Some(peak - 1)); }
            assert!(admission_bytes(backing + 1, future).is_none());
        }
        assert!(admission_bytes(0, CODE_CONTROL_RESERVE - 1).is_none());
        assert!(admission_bytes(usize::MAX, CODE_CONTROL_RESERVE).is_none());
        assert!(admission_bytes(0, usize::MAX).is_none());
        assert!(code_storage_bytes(256, 16384).is_some());
        assert!(code_storage_bytes(usize::MAX, 0).is_none());
        assert!(code_storage_bytes(0, usize::MAX).is_none());
    }
}
