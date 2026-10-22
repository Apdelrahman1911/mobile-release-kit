//! Independent comparisons for one fixed public local-Git fixture. These are
//! not SourceBook/ACK receipts. The outer original additionally compares the
//! complete bounded Git tree (including every loose-object original).
use super::super::{
    directory, file_fact, identity, FileFact, CONFIG, IGNORE_PREFIX, KEEP, SOURCE, VERSION,
};
use super::Case;
use std::{
    fs::OpenOptions,
    io::Read,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const UNTRACKED: &[u8] = b"MRK public untracked Upstream fixture: never staged or sent.\n";
const FILES: [(&str, &[u8]); 6] = [
    ("app/build.gradle.kts", SOURCE),
    ("release/mobile-release.json", CONFIG),
    ("version.properties", VERSION),
    ("keep.txt", KEEP),
    (".gitignore", IGNORE_PREFIX),
    ("untracked.txt", UNTRACKED),
];
const DIRS: [(&str, &[&str]); 3] = [
    (
        ".",
        &[
            ".git",
            "app",
            "release",
            "version.properties",
            "keep.txt",
            ".gitignore",
            "untracked.txt",
        ],
    ),
    ("app", &["build.gradle.kts"]),
    ("release", &["mobile-release.json"]),
];
// Native comparison only; the outer existing Fixtures additionally retains
// and rechecks the complete <=128-entry Git tree and every loose object.
const ORIGINALS: [&str; 5] = [
    "HEAD",
    "refs/heads/main",
    "logs/HEAD",
    "logs/refs/heads/main",
    "config",
];
const REF: &str = "refs/heads/observer-local";
#[derive(Clone, PartialEq, Eq)]
pub(in super::super) struct Fixture {
    case: Case,
    files: [FileFact; 6],
    dirs: [[u64; 9]; 3],
    originals: [FileFact; 5],
    index: FileFact,
    git: [u64; 9],
    target: String,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct After {
    index: FileFact,
    created: Vec<FileFact>,
    git: [u64; 9],
}
impl Fixture {
    pub(in super::super) fn capture(root: &Path, uid: u32, case: Case) -> Result<Self, ()> {
        if uid == 0 {
            return Err(());
        }
        let files = FILES
            .iter()
            .map(|(p, b)| file_fact(&root.join(p), b, uid))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        let dirs = DIRS
            .iter()
            .map(|(p, n)| dir(&root.join(p), uid, n))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        let originals = ORIGINALS
            .iter()
            .map(|p| read(&root.join(".git").join(p), uid, 65536).map(|v| v.0))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        if !fixture_config(&read(&root.join(".git/config"), uid, 4096)?.1)
            || read(&root.join(".git/HEAD"), uid, 64)?.1 != b"ref: refs/heads/main\n"
        {
            return Err(());
        }
        for p in [REF, "logs/refs/heads/observer-local"] {
            if !matches!(std::fs::symlink_metadata(root.join(".git").join(p)),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
            {
                return Err(());
            }
        }
        let bytes = read(&root.join(".git/refs/heads/main"), uid, 64)?.1;
        let target = std::str::from_utf8(&bytes)
            .map_err(|_| ())?
            .strip_suffix('\n')
            .filter(|v| crate::git_fetch_protocol::oid(v))
            .ok_or(())?
            .to_owned();
        Ok(Self {
            case,
            files,
            dirs,
            originals,
            index: read(&root.join(".git/index"), uid, 65536)?.0,
            git: git_parent(&root.join(".git"), uid)?,
            target,
        })
    }
    pub(super) fn target(&self) -> &str {
        &self.target
    }
    pub(in super::super) fn root_identity(&self) -> [u64; 6] {
        self.dirs[0][..6].try_into().expect("six")
    }
    pub(in super::super) fn app(&self) -> [u64; 6] {
        self.dirs[1][..6].try_into().expect("six")
    }
    pub(in super::super) fn release(&self) -> [u64; 6] {
        self.dirs[2][..6].try_into().expect("six")
    }
    pub(in super::super) fn ignore(&self) -> FileFact {
        self.files[4].clone()
    }
    pub(in super::super) fn config(&self) -> FileFact {
        self.files[1].clone()
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>()
            .checked_add(self.target.capacity())?
            .checked_add(self.index.sha256.capacity())?;
        for f in self.files.iter().chain(self.originals.iter()) {
            n = n.checked_add(f.sha256.capacity())?;
        }
        Some(n)
    }
    pub(super) fn after(&self, root: &Path, uid: u32) -> Result<After, ()> {
        for ((p, b), old) in FILES.iter().zip(&self.files) {
            if file_fact(&root.join(p), b, uid)? != *old {
                return Err(());
            }
        }
        for ((p, n), old) in DIRS.iter().zip(&self.dirs) {
            if dir(&root.join(p), uid, n)? != *old {
                return Err(());
            }
        }
        for (p, old) in ORIGINALS.iter().zip(&self.originals) {
            if read(&root.join(".git").join(p), uid, 65536)?.0 != *old {
                return Err(());
            }
        }
        let index = read(&root.join(".git/index"), uid, 65536)?.0;
        let mut created = Vec::new();
        if self.case == Case::Index {
            if index.identity[0] != self.index.identity[0]
                || index.identity[1] == self.index.identity[1]
                || index.identity[2..6] != self.index.identity[2..6]
                || index.sha256 == self.index.sha256
            {
                return Err(());
            }
            for p in [REF, "logs/refs/heads/observer-local"] {
                if !matches!(std::fs::symlink_metadata(root.join(".git").join(p)),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
                {
                    return Err(());
                }
            }
        } else {
            if index != self.index {
                return Err(());
            }
            let (reference, bytes) = read(&root.join(".git").join(REF), uid, 64)?;
            if bytes != format!("{}\n", self.target).as_bytes() {
                return Err(());
            }
            let (log, bytes) = read(&root.join(".git/logs").join(REF), uid, 4096)?;
            let expected_prefix = format!(
                "{} {} MRK Upstream Fixture <upstream-fixture@example.invalid> ",
                "0".repeat(40),
                self.target
            );
            let suffix = b"\tMRK: create reviewed branch\n";
            if !bytes.starts_with(expected_prefix.as_bytes())
                || !bytes.ends_with(suffix)
                || bytes.iter().filter(|c| **c == b'\n').count() != 1
            {
                return Err(());
            }
            created.push(reference);
            created.push(log);
        }
        let git = git_parent(&root.join(".git"), uid)?;
        if !successor(&self.git, &git) {
            return Err(());
        }
        Ok(After {
            index,
            created,
            git,
        })
    }
    pub(super) fn verify_unchanged(&self, root: &Path, uid: u32, after: &After) -> Result<(), ()> {
        if self.after(root, uid)? == *after {
            Ok(())
        } else {
            Err(())
        }
    }
}
impl After {
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>()
            .checked_add(self.index.sha256.capacity())?
            .checked_add(
                self.created
                    .capacity()
                    .checked_mul(std::mem::size_of::<FileFact>())?,
            )?;
        for f in &self.created {
            n = n.checked_add(f.sha256.capacity())?;
        }
        Some(n)
    }
}
fn dir(path: &Path, uid: u32, names: &[&str]) -> Result<[u64; 9], ()> {
    let before = identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)?;
    let actual = directory(path, uid, 0o700, names)?;
    if actual.as_slice() != &before[..6]
        || identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != before
    {
        return Err(());
    }
    Ok(before)
}
fn git_parent(path: &Path, uid: u32) -> Result<[u64; 9], ()> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err(());
    }
    identity(&meta)
}
fn successor(old: &[u64; 9], new: &[u64; 9]) -> bool {
    old[..5] == new[..5]
}
pub(super) fn fixture_config(raw: &[u8]) -> bool {
    // Only the task-owned init result: fixed core/user values plus the two
    // boolean filesystem probes. Retain these exact bytes as the prefix.
    if raw.is_empty()
        || raw.len() > 4096
        || !raw.ends_with(b"\n")
        || !raw.iter().all(|c| matches!(*c, 9 | 10 | 32..=126))
    {
        return false;
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let (mut section, mut sections, mut seen) = (0u8, 0u8, 0u16);
    for line in text.lines() {
        if matches!(line, "[core]" | "[user]") {
            section = if line == "[core]" { 1 } else { 2 };
            if sections & section != 0 {
                return false;
            }
            sections |= section;
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return false;
        };
        let (name, value) = (
            name.trim_matches([' ', '\t']),
            value.trim_matches([' ', '\t']),
        );
        let bit = match (section, name, value) {
            (1, "repositoryformatversion", "0") => 1,
            (1, "filemode", "true") => 2,
            (1, "bare", "false") => 4,
            (1, "logallrefupdates", "true") => 8,
            (2, "name", "MRK Upstream Fixture") => 16,
            (2, "email", "upstream-fixture@example.invalid") => 32,
            (1, "ignorecase", "true" | "false") => 64,
            (1, "precomposeunicode", "true" | "false") => 128,
            _ => return false,
        };
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
    }
    sections == 3 && seen & 63 == 63
}
fn read(path: &Path, uid: u32, maximum: u64) -> Result<(FileFact, Vec<u8>), ()> {
    if maximum > 65536 {
        return Err(());
    }
    let before = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !before.is_file()
        || before.uid() != uid
        || before.nlink() != 1
        || before.len() > maximum
        || !matches!(before.mode() & 0o7777, 0o600 | 0o644 | 0o444 | 0o400)
    {
        return Err(());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ())?;
    let result = (|| {
        let original = identity(&before)?;
        if identity(&f.metadata().map_err(|_| ())?)? != original {
            return Err(());
        }
        mrk_macos_installed_native::empty_acl(f.as_fd()).map_err(|_| ())?;
        mrk_macos_installed_native::no_xattrs(f.as_fd()).map_err(|_| ())?;
        let mut bytes = Vec::with_capacity(before.len() as usize + 1);
        (&mut f)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        if bytes.len() as u64 != before.len()
            || identity(&f.metadata().map_err(|_| ())?)? != original
            || identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)? != original
        {
            return Err(());
        }
        Ok((
            FileFact {
                identity: original,
                sha256: super::super::digest(&bytes),
            },
            bytes,
        ))
    })();
    if nix::unistd::close(OwnedFd::from(f)).is_err() {
        return Err(());
    }
    result
}
