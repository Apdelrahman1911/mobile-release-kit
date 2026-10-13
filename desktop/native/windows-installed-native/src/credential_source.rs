//! Bounded read-only credential capture through the EXISTING ProjectBook.
//! No worker, path capability, writer, retry or replacement native book lives here.
use super::{Call, CloseOutcome, Error, FileIdentity, FileKind, Kind, Metadata, NativeBook, Original,
    ProjectBook, Result, SecurityFacts, MAX_ORIGINALS};
use std::{collections::BTreeSet, mem::size_of, ptr::null_mut};

const ROOTS: usize = 64;
const ORIGINS: usize = 32;
// Same capacity as the longest existing project chain: retain room for the
// original primary token and the before/after current-thread token observations.
const NODES: usize = MAX_ORIGINALS - 3;
const CHILDREN: usize = 35; // Existing next_selected_entries bound; not widened.
const MAX_MATERIAL: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    Native(Error), SourceChanged, ProjectOverlap, ExclusionUnconfirmed, MaterialLimit,
}
impl From<Error> for CredentialError { fn from(error: Error) -> Self { Self::Native(error) } }
type SourceResult<T> = std::result::Result<T, CredentialError>;

/// Comparison hints only; every registration is freshly proved on originals.
pub struct RegisteredProject<'a> { pub path: &'a str, pub identity: FileIdentity }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryFacts { identity: FileIdentity, attributes: u32 }
impl DirectoryFacts {
    fn of(metadata: &Metadata) -> Result<Self> {
        if metadata.kind != FileKind::Directory { return Err(Error::Unsafe); }
        Ok(Self { identity: metadata.identity, attributes: metadata.attributes })
    }
}

/// Private point-in-time hint, never serializable or authority to recapture bytes.
/// Only successful capture plus consuming settlement returns this value.
pub struct CredentialOrigin {
    path: String, ancestry: Vec<DirectoryFacts>, leaf: Metadata, security: SecurityFacts,
}
impl CredentialOrigin {
    pub fn retained_bytes(&self) -> Option<usize> {
        size_of::<Self>().checked_add(self.path.capacity())?
            .checked_add(self.ancestry.capacity().checked_mul(size_of::<DirectoryFacts>())?)?
            .checked_add(self.security.retained_heap_bytes()?)
    }
}
pub struct CredentialSnapshot { pub bytes: Vec<u8>, pub origin: CredentialOrigin }

enum Expected { Directory(DirectoryFacts), File(Metadata, SecurityFacts) }
struct Node {
    parent: Option<usize>, drive: usize, name: String, kind: FileKind,
    original: Option<Original>, metadata: Option<Metadata>, security: Option<SecurityFacts>,
    expected: Option<Expected>, children: Vec<usize>, names: Vec<String>,
}
struct Drive { name: String, device: Option<String> }
struct Root { node: usize, identity: FileIdentity }
enum Purpose {
    Capture { path: String, chain: Vec<usize>, limit: usize },
    Probe { project: usize, origins: Vec<Vec<usize>> },
}
pub(super) struct Roster { drives: Vec<Drive>, nodes: Vec<Node>, roots: Vec<Root>, purpose: Purpose }

fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<()> {
    if stop() { Err(Error::Unavailable) } else { Ok(()) }
}
fn same_directory(expected: &Metadata, actual: &Metadata) -> bool {
    // A user project is mutable, not an immutable installed runtime. Unrelated
    // sibling timestamp/link churn does not replace its native directory object.
    DirectoryFacts::of(expected).ok().zip(DirectoryFacts::of(actual).ok())
        .is_some_and(|(expected, actual)| expected == actual)
}
fn selected_edge(entry: &super::DirectoryEntry, name: &str, target: &Metadata) -> bool {
    entry.name == name && entry.kind == target.kind && entry.file_id == target.identity.file_id
        && entry.attributes == target.attributes
}
fn accepted_read(expected: usize, used: usize, received: usize) -> SourceResult<bool> {
    if received == 0 {
        return if used == expected { Ok(true) } else { Err(CredentialError::SourceChanged) };
    }
    if used.checked_add(received).filter(|total| *total <= expected).is_none() {
        return Err(CredentialError::SourceChanged);
    }
    Ok(false)
}
fn retained_path(path: &str) -> Result<String> {
    super::project::spelling(path)?;
    let mut retained = String::new();
    retained.try_reserve_exact(path.len()).map_err(|_| Error::Bounds)?;
    retained.push_str(path); Ok(retained)
}

impl Roster {
    fn new(purpose: Purpose) -> Result<Self> {
        let mut nodes = Vec::new(); nodes.try_reserve_exact(NODES).map_err(|_| Error::Bounds)?;
        let mut drives = Vec::new(); drives.try_reserve_exact(NODES).map_err(|_| Error::Bounds)?;
        let mut roots = Vec::new(); roots.try_reserve_exact(ROOTS).map_err(|_| Error::Bounds)?;
        Ok(Self { drives, nodes, roots, purpose })
    }
    fn push_node(&mut self, parent: Option<usize>, drive: usize, name: String, kind: FileKind) -> Result<usize> {
        if self.nodes.len() >= NODES { return Err(Error::Bounds); }
        let index = self.nodes.len();
        self.nodes.push(Node { parent, drive, name, kind, original: None, metadata: None, security: None,
            expected: None, children: Vec::new(), names: Vec::new() });
        Ok(index)
    }
    fn path(&mut self, path: &str, kind: FileKind) -> Result<Vec<usize>> {
        let (drive, components) = super::project::spelling(path)?;
        let drive = match self.drives.iter().position(|prior| prior.name == drive) {
            Some(index) => index,
            None => { self.drives.push(Drive { name: drive, device: None }); self.drives.len() - 1 },
        };
        let root = match self.nodes.iter().position(|node| node.parent.is_none() && node.drive == drive) {
            Some(index) => index,
            None => self.push_node(None, drive, String::new(), FileKind::Directory)?,
        };
        let mut chain = Vec::new();
        chain.try_reserve_exact(components.len() + 1).map_err(|_| Error::Bounds)?;
        chain.push(root);
        for (offset, name) in components.iter().enumerate() {
            let parent = *chain.last().ok_or(Error::State)?;
            let kind = if offset + 1 == components.len() { kind } else { FileKind::Directory };
            let found = self.nodes.iter().position(|node| node.parent == Some(parent) && node.name == *name);
            let index = match found {
                Some(index) => {
                    if self.nodes[index].kind != kind { return Err(Error::Unsafe); }
                    index
                },
                None => {
                    // Do not merge a case alias. Full-ID and native long-name
                    // checks also refuse non-ASCII/drive aliases after acquisition.
                    if self.nodes.iter().any(|node| node.parent == Some(parent) && node.name.eq_ignore_ascii_case(name)) {
                        return Err(Error::Unsafe);
                    }
                    self.push_node(Some(parent), drive, name.clone(), kind)?
                },
            };
            chain.push(index);
        }
        Ok(chain)
    }
    fn freeze(&mut self) -> Result<()> {
        // Complete selected-name rosters precede ALL native work. Every parent's
        // one original cursor will see precisely this immutable selection.
        for parent in 0..self.nodes.len() {
            let count = self.nodes.iter().filter(|node| node.parent == Some(parent)).count();
            if count > CHILDREN { return Err(Error::Bounds); }
            self.nodes[parent].children.try_reserve_exact(count).map_err(|_| Error::Bounds)?;
            self.nodes[parent].names.try_reserve_exact(count).map_err(|_| Error::Bounds)?;
            for child in 0..self.nodes.len() {
                if self.nodes[child].parent == Some(parent) {
                    let name = self.nodes[child].name.clone();
                    self.nodes[parent].children.push(child); self.nodes[parent].names.push(name);
                }
            }
            if count != 0 { super::loader::selected_names(&self.nodes[parent].names)?; }
        }
        Ok(())
    }
    fn capture(path: &str, projects: &[RegisteredProject<'_>], limit: usize) -> SourceResult<Self> {
        if projects.len() > ROOTS { return Err(Error::Bounds.into()); }
        if limit == 0 || limit > MAX_MATERIAL { return Err(CredentialError::MaterialLimit); }
        let path = retained_path(path)?;
        let mut roster = Self::new(Purpose::Capture { path: path.clone(), chain: Vec::new(), limit })?;
        for project in projects {
            let chain = roster.path(project.path, FileKind::Directory)?;
            roster.roots.push(Root { node: *chain.last().ok_or(Error::State)?, identity: project.identity });
        }
        let chain = roster.path(&path, FileKind::File)?;
        roster.purpose = Purpose::Capture { path, chain, limit };
        roster.freeze()?; Ok(roster)
    }
    fn expect_directory(&mut self, index: usize, expected: DirectoryFacts) -> SourceResult<()> {
        match &self.nodes[index].expected {
            None => { self.nodes[index].expected = Some(Expected::Directory(expected)); Ok(()) },
            Some(Expected::Directory(prior)) if *prior == expected => Ok(()),
            _ => Err(CredentialError::ExclusionUnconfirmed),
        }
    }
    fn expect_file(&mut self, index: usize, origin: &CredentialOrigin) -> SourceResult<()> {
        match &self.nodes[index].expected {
            None => {
                self.nodes[index].expected = Some(Expected::File(origin.leaf.clone(), origin.security.clone())); Ok(())
            },
            Some(Expected::File(leaf, security)) if *leaf == origin.leaf && *security == origin.security => Ok(()),
            _ => Err(CredentialError::ExclusionUnconfirmed),
        }
    }
    fn probe(path: &str, origins: &[&CredentialOrigin]) -> SourceResult<Self> {
        if origins.len() > ORIGINS { return Err(Error::Bounds.into()); }
        let mut chains = Vec::new(); chains.try_reserve_exact(origins.len()).map_err(|_| Error::Bounds)?;
        let mut roster = Self::new(Purpose::Probe { project: 0, origins: Vec::new() })?;
        let chain = roster.path(path, FileKind::Directory)?;
        let project = *chain.last().ok_or(Error::State)?;
        for origin in origins {
            let chain = roster.path(&origin.path, FileKind::File)?;
            if chain.len().checked_sub(1) != Some(origin.ancestry.len()) { return Err(CredentialError::ExclusionUnconfirmed); }
            for (&index, &expected) in chain.iter().zip(&origin.ancestry) { roster.expect_directory(index, expected)?; }
            roster.expect_file(*chain.last().ok_or(Error::State)?, origin)?;
            chains.push(chain);
        }
        roster.purpose = Purpose::Probe { project, origins: chains };
        roster.freeze()?; Ok(roster)
    }
    fn metadata(&self, index: usize) -> Result<&Metadata> {
        self.nodes.get(index).and_then(|node| node.metadata.as_ref()).ok_or(Error::State)
    }
    fn original(&self, index: usize) -> Result<&Original> {
        self.nodes.get(index).and_then(|node| node.original.as_ref()).ok_or(Error::State)
    }
    fn sample(&self, native: &mut NativeBook, index: usize, stop: &mut dyn FnMut() -> bool)
        -> Result<(Metadata, Option<SecurityFacts>)> {
        let original = self.original(index)?;
        checkpoint(stop)?; native.local_ntfs(original)?;
        checkpoint(stop)?; let metadata = native.metadata(original)?;
        checkpoint(stop)?; native.no_alternate_streams(original)?;
        checkpoint(stop)?;
        let security = if self.nodes[index].kind == FileKind::File {
            // Original current-user binding, not a caller-provided owner SID.
            let security = native.credential_security(original)?; checkpoint(stop)?; Some(security)
        } else { None };
        Ok((metadata, security))
    }
    fn record_mapping(&mut self, index: usize, device: String) -> Result<()> {
        if index >= self.drives.len() || self.drives[index].device.is_some()
            || self.drives[..index].iter().any(|drive| drive.device.is_none()) { return Err(Error::State); }
        let duplicate = self.drives[..index].iter().any(|drive| drive.device.as_ref() == Some(&device));
        self.drives[index].device = Some(device); // Retain the actual returning mapping.
        // All mappings precede every directory open. A second spelling of the
        // same drive is a refused source, not an uncertain native acquisition.
        if duplicate { Err(Error::Unsafe) } else { Ok(()) }
    }
    fn acquire(&mut self, native: &mut NativeBook, stop: &mut dyn FnMut() -> bool) -> SourceResult<()> {
        checkpoint(stop)?; native.observe_user_once()?; checkpoint(stop)?;
        for index in 0..self.drives.len() {
            let device = native.mapping(&self.drives[index].name)?;
            self.record_mapping(index, device)?; checkpoint(stop)?;
        }
        for index in 0..self.nodes.len() {
            checkpoint(stop)?;
            if let Some(parent) = self.nodes[index].parent {
                let original = match (self.nodes[index].kind, &self.purpose) {
                    (FileKind::File, Purpose::Probe { .. }) =>
                        native.open_metadata_child(self.original(parent)?, &self.nodes[index].name)?,
                    (kind, _) => native.open_child(self.original(parent)?, &self.nodes[index].name, kind)?,
                };
                self.nodes[index].original = Some(original);
            } else {
                let drive = &self.drives[self.nodes[index].drive];
                let device = drive.device.as_ref().ok_or(Error::State)?;
                let name = format!("{device}\\");
                let original = native.reserve(Kind::Directory, None, &name, name.clone())?;
                self.nodes[index].original = Some(original); // Retain before native entry.
                native.call(Call::Open(self.original(index)?.index), null_mut(), Vec::new())?;
                checkpoint(stop)?; native.noninherited(self.original(index)?.index)?;
            }
            // NativeBook already owns any acquired result even if the composed
            // open failed after adoption. STOP never precedes scalar capture.
            checkpoint(stop)?;
            let (metadata, security) = self.sample(native, index, stop)?;
            if metadata.kind != self.nodes[index].kind
                || self.nodes[index].parent.is_some_and(|parent|
                    self.metadata(parent).map(|prior| prior.identity.volume_serial != metadata.identity.volume_serial).unwrap_or(true))
                || self.nodes[..index].iter().filter_map(|prior| prior.metadata.as_ref())
                    .any(|prior| prior.identity == metadata.identity) {
                return Err(Error::Unsafe.into());
            }
            for root in &self.roots {
                if root.node == index && root.identity != metadata.identity { return Err(CredentialError::SourceChanged); }
            }
            self.check_expected(index, &metadata, security.as_ref())?;
            self.nodes[index].metadata = Some(metadata); self.nodes[index].security = security;
        }
        self.exclusion()?;
        for index in 0..self.nodes.len() {
            if !self.nodes[index].children.is_empty() { self.same_parent(native, index, stop)?; }
        }
        Ok(())
    }
    fn check_expected(&self, index: usize, actual: &Metadata, security: Option<&SecurityFacts>) -> SourceResult<()> {
        let matches = match &self.nodes[index].expected {
            None => true,
            Some(Expected::Directory(expected)) => DirectoryFacts::of(actual)? == *expected,
            Some(Expected::File(expected, expected_security)) => expected == actual && security == Some(expected_security),
        };
        if matches { Ok(()) } else { Err(CredentialError::ExclusionUnconfirmed) }
    }
    fn exclusion(&self) -> SourceResult<()> {
        match &self.purpose {
            Purpose::Capture { chain, .. } => {
                for &index in chain.iter().take(chain.len().saturating_sub(1)) {
                    let actual = self.metadata(index)?.identity;
                    if self.roots.iter().any(|root| root.identity == actual) { return Err(CredentialError::ProjectOverlap); }
                }
            },
            Purpose::Probe { project, origins } => {
                let project = self.metadata(*project)?.identity;
                for chain in origins {
                    for &index in chain.iter().take(chain.len().saturating_sub(1)) {
                        if self.metadata(index)?.identity == project { return Err(CredentialError::ProjectOverlap); }
                    }
                }
            },
        }
        Ok(())
    }
    fn same_parent(&self, native: &mut NativeBook, parent: usize, stop: &mut dyn FnMut() -> bool) -> SourceResult<()> {
        let children = &self.nodes[parent].children;
        let names = &self.nodes[parent].names;
        let mut seen = BTreeSet::new();
        let mut found = vec![false; children.len()];
        loop {
            checkpoint(stop)?;
            let entries = native.next_selected_entries(self.original(parent)?, names)?;
            checkpoint(stop)?;
            let Some(entries) = entries else { break };
            for entry in entries {
                if !seen.insert(entry.name.to_ascii_lowercase()) { return Err(Error::Unsafe.into()); }
                if entry.name == "." || entry.name == ".." {
                    let expected = if entry.name == "." { parent } else { self.nodes[parent].parent.unwrap_or(parent) };
                    if entry.kind != FileKind::Directory || entry.file_id != self.metadata(expected)?.identity.file_id {
                        return Err(Error::Unsafe.into());
                    }
                } else {
                    for (offset, &child) in children.iter().enumerate() {
                        if entry.name.eq_ignore_ascii_case(&names[offset]) {
                            if found[offset] || !selected_edge(&entry, &names[offset], self.metadata(child)?) {
                                return Err(Error::Unsafe.into());
                            }
                            found[offset] = true;
                        }
                    }
                }
            }
        }
        if found.iter().any(|found| !found) { return Err(Error::Unsafe.into()); }
        Ok(())
    }
    fn postcheck(&self, native: &mut NativeBook, stop: &mut dyn FnMut() -> bool) -> SourceResult<()> {
        for index in (0..self.nodes.len()).rev() {
            let (actual, security) = self.sample(native, index, stop)?;
            let expected = self.metadata(index)?;
            let matches = match self.nodes[index].kind {
                FileKind::Directory => same_directory(expected, &actual),
                FileKind::File => *expected == actual && self.nodes[index].security == security,
            };
            if !matches { return Err(CredentialError::SourceChanged); }
        }
        for drive in &self.drives {
            checkpoint(stop)?;
            if native.mapping(&drive.name)? != *drive.device.as_ref().ok_or(Error::State)? {
                return Err(CredentialError::SourceChanged);
            }
        }
        checkpoint(stop)?; native.recheck_user()?; checkpoint(stop)?; Ok(())
    }
    fn capture_result(&self, native: &mut NativeBook, stop: &mut dyn FnMut() -> bool) -> SourceResult<CredentialSnapshot> {
        let (path, chain, limit) = match &self.purpose {
            Purpose::Capture { path, chain, limit } => (path, chain, *limit),
            _ => return Err(Error::State.into()),
        };
        let leaf = *chain.last().ok_or(Error::State)?;
        let metadata = self.metadata(leaf)?;
        let size = usize::try_from(metadata.size).map_err(|_| CredentialError::MaterialLimit)?;
        if size == 0 || size > limit { return Err(CredentialError::MaterialLimit); }
        let capacity = size.checked_add(1).ok_or(CredentialError::MaterialLimit)?;
        let mut bytes = Vec::new(); bytes.try_reserve_exact(capacity).map_err(|_| Error::Bounds)?;
        loop {
            checkpoint(stop)?;
            let remaining = capacity.checked_sub(bytes.len()).ok_or(CredentialError::SourceChanged)?;
            if remaining == 0 { return Err(CredentialError::SourceChanged); }
            let part = native.read_next(self.original(leaf)?, remaining.min(super::BUFFER))?;
            checkpoint(stop)?;
            if accepted_read(size, bytes.len(), part.len())? {
                break; // Only definite original ReadFile EOF can end the snapshot.
            }
            bytes.extend_from_slice(&part);
        }
        self.postcheck(native, stop)?;
        let mut ancestry = Vec::new();
        ancestry.try_reserve_exact(chain.len().saturating_sub(1)).map_err(|_| Error::Bounds)?;
        for &index in chain.iter().take(chain.len().saturating_sub(1)) {
            ancestry.push(DirectoryFacts::of(self.metadata(index)?)?);
        }
        let origin = CredentialOrigin { path: retained_path(path)?, ancestry, leaf: metadata.clone(),
            security: self.nodes[leaf].security.as_ref().ok_or(Error::State)?.clone() };
        Ok(CredentialSnapshot { bytes, origin })
    }
}

impl ProjectBook {
    fn begin_credentials(&mut self, roster: Roster) -> SourceResult<()> {
        if !self.never_started() {
            return Err(if self.native.is_unknown() { Error::Unknown } else { Error::State }.into());
        }
        self.credential = Some(roster); self.begun = true; Ok(())
    }
    fn finish_credentials<T>(&mut self, result: SourceResult<T>, stop: &mut dyn FnMut() -> bool) -> SourceResult<T> {
        let settlement = self.settle_once();
        if settlement != CloseOutcome::Settled
            || matches!(result, Err(CredentialError::Native(Error::Unknown | Error::State))) {
            return Err(Error::Unknown.into());
        }
        checkpoint(stop)?; result
    }
    pub fn capture_credential_once(&mut self, path: &str, projects: &[RegisteredProject<'_>], limit: usize,
        stop: &mut dyn FnMut() -> bool) -> SourceResult<CredentialSnapshot> {
        if !self.never_started() {
            return Err(if self.native.is_unknown() { Error::Unknown } else { Error::State }.into());
        }
        self.begin_credentials(Roster::capture(path, projects, limit)?)?;
        let result = (|| {
            let roster = self.credential.as_mut().ok_or(Error::State)?;
            roster.acquire(&mut self.native, stop)?;
            roster.capture_result(&mut self.native, stop)
        })();
        self.finish_credentials(result, stop)
    }
    pub fn probe_excluding_credentials_once(&mut self, path: &str, origins: &[&CredentialOrigin],
        stop: &mut dyn FnMut() -> bool) -> SourceResult<FileIdentity> {
        if origins.is_empty() { return self.probe_once(path, stop).map_err(Into::into); }
        if !self.never_started() {
            return Err(if self.native.is_unknown() { Error::Unknown } else { Error::State }.into());
        }
        self.begin_credentials(Roster::probe(path, origins)?)?;
        let result = (|| {
            let roster = self.credential.as_mut().ok_or(Error::State)?;
            roster.acquire(&mut self.native, stop)?;
            roster.postcheck(&mut self.native, stop)?;
            let project = match &roster.purpose { Purpose::Probe { project, .. } => *project, _ => return Err(Error::State.into()) };
            Ok(roster.metadata(project)?.identity)
        })();
        self.finish_credentials(result, stop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(kind: FileKind, value: u8) -> Metadata {
        Metadata { identity: FileIdentity { volume_serial: u64::MAX, file_id: [value; 16] },
            kind, attributes: if kind == FileKind::Directory { 0x10 } else { 0x20 },
            size: if kind == FileKind::File { 3 } else { 0 }, allocation_size: 4096, links: 1,
            creation: 1, write: 2, change: 3 }
    }
    #[test]
    fn source_roster_shares_only_exact_parents_and_bounds_the_complete_selection() {
        let projects = [RegisteredProject { path: r"C:\Users\owner\project", identity: metadata(FileKind::Directory, 1).identity }];
        let roster = Roster::capture(r"C:\Users\owner\private\key.jks", &projects, MAX_MATERIAL).unwrap();
        assert_eq!(roster.nodes.len(), 6);
        assert_eq!(roster.nodes.iter().filter(|node| node.name == "owner").count(), 1);
        assert_eq!(roster.nodes[2].names, ["project", "private"]);
        assert!(matches!(Roster::capture(r"C:\Users\OWNER\key.jks", &projects, 4), Err(CredentialError::Native(Error::Unsafe))));
        let paths: Vec<_> = (0..36).map(|n| format!(r"C:\p{n}")).collect();
        let projects: Vec<_> = paths.iter().map(|path| RegisteredProject {
            path, identity: metadata(FileKind::Directory, 1).identity }).collect();
        assert!(matches!(Roster::capture(r"C:\private\key.jks", &projects, 4), Err(CredentialError::Native(Error::Bounds))));
        let paths: Vec<_> = (0..24).map(|n| format!(r"C:\p{n}\nested")).collect();
        let projects: Vec<_> = paths.iter().map(|path| RegisteredProject {
            path, identity: metadata(FileKind::Directory, 1).identity }).collect();
        assert!(matches!(Roster::capture(r"C:\private\key.jks", &projects, 4), Err(CredentialError::Native(Error::Bounds))));
    }
    #[test]
    fn duplicate_actual_drive_mapping_is_refused_before_any_directory_original() {
        let projects = [RegisteredProject { path: r"C:\project", identity: metadata(FileKind::Directory, 1).identity }];
        let mut roster = Roster::capture(r"D:\private\key.jks", &projects, 4).unwrap();
        assert_eq!(roster.record_mapping(0, r"\Device\HarddiskVolume1".into()), Ok(()));
        assert_eq!(roster.record_mapping(1, r"\Device\HarddiskVolume1".into()), Err(Error::Unsafe));
        assert!(roster.nodes.iter().all(|node| node.original.is_none()));
        assert_eq!(roster.drives[1].device.as_deref(), Some(r"\Device\HarddiskVolume1"));
        let mut distinct = Roster::capture(r"D:\private\key.jks", &projects, 4).unwrap();
        assert_eq!(distinct.record_mapping(0, r"\Device\HarddiskVolume1".into()), Ok(()));
        assert_eq!(distinct.record_mapping(1, r"\Device\HarddiskVolume2".into()), Ok(()));
        assert_eq!(distinct.record_mapping(1, r"\Device\HarddiskVolume3".into()), Err(Error::State));
    }
    #[test]
    fn credential_origin_counts_spare_path_ancestry_and_security_heap_capacity() {
        let owner = super::super::security::sid_at(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], 0, 12).unwrap();
        let mut origin = CredentialOrigin { path: r"C:\private\key.jks".into(),
            ancestry: vec![DirectoryFacts::of(&metadata(FileKind::Directory, 1)).unwrap()],
            leaf: metadata(FileKind::File, 2),
            security: SecurityFacts { owner, control: 0, revision: 2, aces: Vec::new() } };
        let before = origin.retained_bytes().unwrap(); let previous = origin.path.capacity();
        origin.path.reserve_exact(128);
        assert_eq!(origin.retained_bytes().unwrap() - before, origin.path.capacity() - previous);
        let before = origin.retained_bytes().unwrap(); let previous = origin.ancestry.capacity();
        origin.ancestry.reserve_exact(8);
        assert_eq!(origin.retained_bytes().unwrap() - before,
            (origin.ancestry.capacity() - previous) * size_of::<DirectoryFacts>());
        origin.security.aces.try_reserve_exact(3).unwrap();
        origin.security.aces.push(super::super::AceFact { allow: true, flags: 0, mask: 0, sid: origin.security.owner.clone() });
        let expected = size_of::<CredentialOrigin>() + origin.path.capacity()
            + origin.ancestry.capacity() * size_of::<DirectoryFacts>() + origin.security.retained_heap_bytes().unwrap();
        assert_eq!(origin.retained_bytes(), Some(expected));
        assert!(expected > size_of::<CredentialOrigin>() + origin.path.len() + origin.ancestry.len() * size_of::<DirectoryFacts>());
    }
    #[test]
    fn selected_edges_and_terminal_directory_facts_keep_all_native_identity_bits() {
        let expected = metadata(FileKind::Directory, 0xff);
        let mut actual = expected.clone(); actual.change += 1; actual.links += 1;
        assert!(same_directory(&expected, &actual));
        for byte in 0..16 {
            let mut altered = expected.clone(); altered.identity.file_id[byte] -= 1;
            assert!(!same_directory(&expected, &altered));
        }
        actual.identity.volume_serial -= 1; assert!(!same_directory(&expected, &actual));
        let file = metadata(FileKind::File, 2);
        let mut edge = super::super::DirectoryEntry { name: "key.jks".into(), kind: FileKind::File,
            file_id: file.identity.file_id, attributes: file.attributes };
        assert!(selected_edge(&edge, "key.jks", &file));
        edge.name = "KEY.JKS".into(); assert!(!selected_edge(&edge, "key.jks", &file));
        edge.name = "key.jks".into(); edge.kind = FileKind::Directory; assert!(!selected_edge(&edge, "key.jks", &file));
    }
    #[test]
    fn exclusion_checks_each_root_without_lexical_prefix_shortcuts() {
        let identity = metadata(FileKind::Directory, 7).identity;
        let projects = [RegisteredProject { path: r"C:\other", identity: metadata(FileKind::Directory, 2).identity },
            RegisteredProject { path: r"C:\project", identity }];
        let mut roster = Roster::capture(r"C:\project\private\key.jks", &projects, 4).unwrap();
        for (index, node) in roster.nodes.iter_mut().enumerate() {
            node.metadata = Some(metadata(node.kind, (index + 1) as u8));
        }
        let root = roster.roots[1].node;
        roster.nodes[root].metadata.as_mut().unwrap().identity = identity;
        assert_eq!(roster.exclusion(), Err(CredentialError::ProjectOverlap));
        roster.roots[1].identity.file_id[15] -= 1;
        assert!(roster.exclusion().is_ok());
    }
    #[test]
    fn origin_revalidation_rejects_changed_ancestry_leaf_and_security_without_recapture() {
        let owner = super::super::security::sid_at(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], 0, 12).unwrap();
        // Private test DATA, not a source proof and never sent to a native call.
        let mut origin = CredentialOrigin { path: r"C:\private\key.jks".into(),
            ancestry: vec![DirectoryFacts::of(&metadata(FileKind::Directory, 1)).unwrap(),
                DirectoryFacts::of(&metadata(FileKind::Directory, 2)).unwrap()],
            leaf: metadata(FileKind::File, 3),
            security: SecurityFacts { owner, control: 0, revision: 2, aces: Vec::new() } };
        let roster = Roster::probe(r"C:\project", &[&origin]).unwrap();
        let leaf = roster.nodes.iter().position(|node| node.name == "key.jks").unwrap();
        assert!(roster.check_expected(leaf, &origin.leaf, Some(&origin.security)).is_ok());
        let mut changed = origin.leaf.clone(); changed.change += 1;
        assert_eq!(roster.check_expected(leaf, &changed, Some(&origin.security)), Err(CredentialError::ExclusionUnconfirmed));
        changed = origin.leaf.clone(); changed.identity.file_id[15] += 1;
        assert_eq!(roster.check_expected(leaf, &changed, Some(&origin.security)), Err(CredentialError::ExclusionUnconfirmed));
        let mut changed = origin.security.clone(); changed.control ^= 1;
        assert_eq!(roster.check_expected(leaf, &origin.leaf, Some(&changed)), Err(CredentialError::ExclusionUnconfirmed));
        let parent = roster.nodes[leaf].parent.unwrap();
        let changed = metadata(FileKind::Directory, 4);
        assert_eq!(roster.check_expected(parent, &changed, None), Err(CredentialError::ExclusionUnconfirmed));
        origin.ancestry.pop();
        assert!(matches!(Roster::probe(r"C:\project", &[&origin]), Err(CredentialError::ExclusionUnconfirmed)));
    }
    #[test]
    fn snapshot_accepts_only_exact_original_eof_and_refuses_excess_or_short_reads() {
        assert_eq!(accepted_read(3, 0, 2), Ok(false));
        assert_eq!(accepted_read(3, 2, 1), Ok(false));
        assert_eq!(accepted_read(3, 3, 0), Ok(true));
        for (expected, used, received) in [(3, 2, 0), (3, 3, 1), (3, 0, 4), (usize::MAX, usize::MAX, 1)] {
            assert_eq!(accepted_read(expected, used, received), Err(CredentialError::SourceChanged));
        }
    }
    #[test]
    fn refused_rosters_and_early_stop_make_no_native_call_or_retry_authority() {
        let mut book = ProjectBook::new();
        assert!(matches!(book.capture_credential_once(r"C:\a\..\key.jks", &[], 4, &mut || false),
            Err(CredentialError::Native(Error::Unsafe))));
        assert!(book.never_started());
        assert!(matches!(book.capture_credential_once(r"C:\private\key.jks", &[], 0, &mut || false),
            Err(CredentialError::MaterialLimit)));
        assert!(book.never_started());
        assert!(matches!(book.capture_credential_once(r"C:\private\key.jks", &[], 4, &mut || true),
            Err(CredentialError::Native(Error::Unavailable))));
        assert!(book.settled()); assert!(book.native.slots.is_empty());
        assert!(matches!(book.capture_credential_once(r"C:\private\key.jks", &[], 4, &mut || false),
            Err(CredentialError::Native(Error::State))));
        assert_eq!(book.settle_once(), CloseOutcome::Settled);
    }
    #[test]
    fn unknown_settlement_dominates_stop_and_never_publishes_a_success() {
        let mut book = ProjectBook::new();
        book.native.mark_interrupted();
        assert_eq!(book.finish_credentials(Ok::<_, CredentialError>(()), &mut || true),
            Err(CredentialError::Native(Error::Unknown)));
        assert!(!book.settled());
        assert_eq!(book.settle_once(), CloseOutcome::Unknown);
    }
}
