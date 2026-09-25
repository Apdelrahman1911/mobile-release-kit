//! Point-in-time, read-only native project selection. This wrapper deliberately
//! has no runtime-security, file-content, creation, deletion or process API.
//! Keep the entire book in the original SourceBook outside its blocking worker.
use super::{Call, CloseOutcome, Error, FileIdentity, FileKind, Kind, Metadata, NativeBook, Original, Result, MAX_ORIGINALS};
use std::{collections::BTreeSet, ptr::null_mut};

const PATH_BYTES: usize = 4096;
// Retain every original parent plus the original token; leave room for the
// current-context token checks. Never enlarge NativeBook's shared48-slot bound.
const COMPONENTS: usize = MAX_ORIGINALS - 4;

fn spelling(path: &str) -> Result<(String, Vec<String>)> {
    if path.len() > PATH_BYTES { return Err(Error::Bounds); }
    let ordinary = path.strip_prefix(r"\\?\").unwrap_or(path);
    let (drive, components) = super::decode::dos_location(ordinary)?;
    if components.len() > COMPONENTS { return Err(Error::Bounds); }
    Ok((drive, components))
}

/// Pure spelling validation for the original native picker's result. No
/// canonicalization, registry/environment selection or filesystem access.
pub fn project_path_hint(path: &str) -> Result<()> { spelling(path).map(|_| ()) }

struct Directory { original: Original, name: String, metadata: Option<Metadata> }

pub struct ProjectBook {
    native: NativeBook,
    directories: Vec<Directory>,
    begun: bool,
    final_attempted: bool,
}
impl Default for ProjectBook { fn default() -> Self { Self::new() } }
impl ProjectBook {
    pub fn new() -> Self {
        Self { native: NativeBook::new(), directories: Vec::new(), begun: false, final_attempted: false }
    }
    pub fn never_started(&self) -> bool { !self.begun && self.directories.is_empty() && self.native.never_started() }
    pub fn settled(&self) -> bool { self.final_attempted && self.native.settled() }

    /// The original book is retained even if this worker unwinds. A definite
    /// returning error still settles every independent original exactly once;
    /// neither STOP nor a late successful call can erase an acquisition.
    pub fn probe_once(&mut self, path: &str, stop: &mut dyn FnMut() -> bool) -> Result<FileIdentity> {
        if !self.never_started() { return Err(if self.native.is_unknown() { Error::Unknown } else { Error::State }); }
        let (drive, components) = spelling(path)?;
        self.directories.try_reserve_exact(components.len() + 1).map_err(|_| Error::Bounds)?;
        self.begun = true;
        let result = self.probe(&drive, components, stop);
        if self.settle_once() != CloseOutcome::Settled { return Err(Error::Unknown); }
        checkpoint(stop)?;
        result
    }

    /// Observation on repeat, never a replacement close or a renewed cleanup
    /// attempt. The owner supplies its existing absolute cleanup endpoint.
    pub fn settle_once(&mut self) -> CloseOutcome {
        if self.final_attempted {
            return if self.native.settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown };
        }
        self.final_attempted = true;
        self.native.settle_once()
    }

    fn probe(&mut self, drive: &str, components: Vec<String>, stop: &mut dyn FnMut() -> bool) -> Result<FileIdentity> {
        checkpoint(stop)?;
        self.native.observe_user_once()?;
        checkpoint(stop)?;
        let device = self.native.mapping(drive)?; // actual fixed-drive mapping, not a caller device path
        checkpoint(stop)?;
        let root_name = format!("{device}\\");
        let original = self.native.reserve(Kind::Directory, None, &root_name, root_name.clone())?;
        self.directories.push(Directory { original, name: String::new(), metadata: None });
        // NativeBook registers/pins the result cell before entry; adopting this
        // root precedes the first STOP inspection after the original call.
        self.native.call(Call::Open(self.directories[0].original.index), null_mut(), Vec::new())?;
        checkpoint(stop)?;
        self.native.noninherited(self.directories[0].original.index)?;
        self.admit(0, stop)?;

        for name in components {
            checkpoint(stop)?;
            let parent = self.directories.len() - 1;
            let original = self.native.open_child(&self.directories[parent].original, &name, FileKind::Directory)?;
            // Capacity was reserved before any native acquisition; the actual
            // returned original is retained before observing a late STOP.
            self.directories.push(Directory { original, name, metadata: None });
            checkpoint(stop)?;
            self.admit(parent + 1, stop)?;
        }
        for parent in 0..self.directories.len() - 1 { self.same_parent(parent, stop)?; }
        for index in (0..self.directories.len()).rev() { self.postcheck(index, stop)?; }
        checkpoint(stop)?;
        if self.native.mapping(drive)? != device { return Err(Error::Unsafe); }
        checkpoint(stop)?;
        self.native.recheck_user()?;
        checkpoint(stop)?;
        Ok(self.metadata(self.directories.len() - 1)?.identity)
    }

    fn metadata(&self, index: usize) -> Result<&Metadata> {
        self.directories.get(index).and_then(|record| record.metadata.as_ref()).ok_or(Error::State)
    }
    fn sample(&mut self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<Metadata> {
        let original = &self.directories.get(index).ok_or(Error::State)?.original;
        checkpoint(stop)?;
        self.native.local_ntfs(original)?;
        checkpoint(stop)?;
        // Includes full128-bit identity, ordinary attributes, case-sensitivity
        // refusal and exact canonical native name on the SAME original handle.
        let metadata = self.native.metadata(original)?;
        checkpoint(stop)?;
        self.native.no_alternate_streams(original)?;
        checkpoint(stop)?;
        Ok(metadata)
    }
    fn admit(&mut self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let metadata = self.sample(index, stop)?;
        if metadata.kind != FileKind::Directory
            || index > 0 && metadata.identity.volume_serial != self.metadata(index - 1)?.identity.volume_serial
            || self.directories.iter().filter_map(|record| record.metadata.as_ref()).any(|prior| prior.identity == metadata.identity) {
            return Err(Error::Unsafe);
        }
        self.directories[index].metadata = Some(metadata);
        Ok(())
    }
    fn postcheck(&mut self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        let actual = self.sample(index, stop)?;
        if !same_directory(self.metadata(index)?, &actual) { return Err(Error::Unsafe); }
        Ok(())
    }
    fn same_parent(&mut self, parent: usize, stop: &mut dyn FnMut() -> bool) -> Result<()> {
        // One cursor per original parent, drained to actual EOF. Unrelated
        // siblings grant no open/follow authority; selected-name/full-ID checks
        // below bind this edge without reopening the child by a pathname.
        let selected = self.directories[parent + 1].name.clone();
        let mut names = BTreeSet::new();
        let mut found = false;
        loop {
            checkpoint(stop)?;
            let batch = self.native.next_ancestor_entries(&self.directories[parent].original, &selected)?;
            checkpoint(stop)?;
            let Some(batch) = batch else { break };
            for entry in batch {
                if !names.insert(entry.name.to_ascii_lowercase()) { return Err(Error::Unsafe); }
                if entry.name == "." || entry.name == ".." {
                    let expected = if entry.name == "." { parent } else { parent.saturating_sub(1) };
                    if entry.kind != FileKind::Directory || entry.file_id != self.metadata(expected)?.identity.file_id { return Err(Error::Unsafe); }
                } else if entry.name.eq_ignore_ascii_case(&selected) {
                    if found || !selected_edge(&entry, &selected, self.metadata(parent + 1)?) { return Err(Error::Unsafe); }
                    found = true;
                }
            }
        }
        if !found { return Err(Error::Unsafe); }
        self.postcheck(parent, stop)
    }
}

fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<()> {
    if stop() { Err(Error::Unavailable) } else { Ok(()) }
}
fn same_directory(expected: &Metadata, actual: &Metadata) -> bool {
    // An ordinary project is mutable. Sibling timestamp/link churn is not an
    // identity change; metadata() independently vetoes unsafe native states.
    expected.kind == FileKind::Directory && actual.kind == FileKind::Directory
        && expected.identity == actual.identity && expected.attributes == actual.attributes
}
fn selected_edge(entry: &super::DirectoryEntry, name: &str, target: &Metadata) -> bool {
    entry.name == name && entry.kind == FileKind::Directory && target.kind == FileKind::Directory
        && entry.file_id == target.identity.file_id && entry.attributes == target.attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_spelling_is_bounded_local_and_never_normalized() {
        for path in [r"C:\Users\owner\project", r"D:\project", r"\\?\C:\Users\owner\project", "C:\\prøject"] {
            assert!(project_path_hint(path).is_ok());
        }
        for path in ["", "relative", r"C:", r"C:\", r"C:project", r"\\server\project", r"\\.\C:\project",
            r"C:\project\", r"C:\project\\child", r"C:\project\..\child", r"C:\project\.\child",
            r"C:\project:stream", r"C:\NUL.txt", r"C:\project.", r"C:\project ", "C:\\nul\0project"] {
            assert!(project_path_hint(path).is_err());
        }
        assert!(project_path_hint(&format!("C:\\{}", vec!["a"; COMPONENTS].join("\\"))).is_ok());
        assert!(project_path_hint(&format!("C:\\{}", vec!["a"; COMPONENTS + 1].join("\\"))).is_err());
        assert!(project_path_hint(&format!("C:\\{}", "a".repeat(256))).is_err());
    }
    #[test]
    fn project_identity_checks_full_ids_without_immutable_runtime_policy() {
        let id = FileIdentity { volume_serial: u64::MAX, file_id: [0xff; 16] };
        let original = Metadata { identity: id, kind: FileKind::Directory, attributes: 0x10,
            size: 0, allocation_size: 0, links: 1, creation: 1, write: 2, change: 3 };
        let mut later = original.clone(); later.write += 1; later.change += 1; later.links += 1;
        assert!(same_directory(&original, &later));
        for byte in 0..16 {
            let mut altered = original.clone(); altered.identity.file_id[byte] -= 1;
            assert!(!same_directory(&original, &altered));
        }
        let mut altered = original.clone(); altered.identity.volume_serial -= 1;
        assert!(!same_directory(&original, &altered));
        let mut entry = super::super::DirectoryEntry { name: "project".into(), file_id: id.file_id,
            kind: FileKind::Directory, attributes: 0x10 };
        assert!(selected_edge(&entry, "project", &original));
        entry.name = "PROJECT".into(); assert!(!selected_edge(&entry, "project", &original));
        entry.name = "project".into(); entry.file_id[15] -= 1; assert!(!selected_edge(&entry, "project", &original));
        entry.file_id = id.file_id; entry.kind = FileKind::File; assert!(!selected_edge(&entry, "project", &original));
    }
    #[test]
    fn refused_spelling_and_early_stop_never_acquire_a_native_original() {
        let mut book = ProjectBook::new();
        assert!(book.never_started()); assert!(!book.settled());
        assert_eq!(book.probe_once(r"C:\project\..\other", &mut || false), Err(Error::Unsafe));
        assert!(book.never_started());
        assert_eq!(book.probe_once(r"C:\project", &mut || true), Err(Error::Unavailable));
        assert!(book.settled());
        assert_eq!(book.probe_once(r"C:\project", &mut || false), Err(Error::State));
        assert_eq!(book.settle_once(), CloseOutcome::Settled);
        assert!(book.native.slots.is_empty()); // DATA-only; no token/open/close was invoked.
    }
}
