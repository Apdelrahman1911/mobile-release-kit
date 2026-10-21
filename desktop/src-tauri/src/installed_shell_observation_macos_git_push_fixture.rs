//! Fixed public fixture comparisons. These reads run only before work or after
//! actual original retirement; none can mint a Git/native/Store receipt.
use super::super::{directory, file_fact, FileFact, CONFIG, IGNORE_PREFIX, KEEP, SOURCE, VERSION};
use super::{Case, DATA_FILE, DATA_LIMIT};
use crate::git_fetch_protocol as wire;
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::Read,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const UNTRACKED: &[u8] = b"MRK public untracked Push fixture: never staged or sent.\n";
const READ_LIMIT: u64 = 64 * 1024;
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
const ORIGINALS: [&str; 8] = [
    "HEAD",
    "config",
    "index",
    "refs/heads/main",
    "logs/HEAD",
    "logs/refs/heads/main",
    "refs/remotes/origin/main",
    "logs/refs/remotes/origin/main",
];
#[derive(Clone)]
pub(crate) struct Fixture {
    files: [FileFact; 6],
    dirs: [[u64; 6]; 3],
    originals: [FileFact; 8],
    data: FileFact,
    base: String,
    target: String,
}
impl Fixture {
    pub(crate) fn capture(root: &Path, uid: u32, case: Case) -> Result<Self, ()> {
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
            .map(|(p, n)| directory(&root.join(p), uid, 0o700, n))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        let (data, bytes) = read(&root.join(".git").join(DATA_FILE), uid, DATA_LIMIT)?;
        if data.identity[2] & 0o7777 != 0o600 {
            return Err(());
        }
        let v = crate::git_read_protocol::strict_json(&bytes).map_err(|_| ())?;
        if !crate::git_read_protocol::keys(
            &v,
            &["schemaVersion", "case", "base", "target", "other"],
        ) || v["schemaVersion"] != 1
            || v["case"] != case.name()
        {
            return Err(());
        }
        let base = v["base"]
            .as_str()
            .filter(|v| wire::oid(v))
            .ok_or(())?
            .to_owned();
        let target = v["target"]
            .as_str()
            .filter(|v| wire::oid(v))
            .ok_or(())?
            .to_owned();
        if base == target
            || v["other"]
                .as_str()
                .is_none_or(|v| !wire::oid(v) || v == base || v == target)
        {
            return Err(());
        }
        let originals = ORIGINALS
            .iter()
            .map(|p| read(&root.join(".git").join(p), uid, 65536).map(|v| v.0))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        if read(&root.join(".git/HEAD"), uid, 2048)?.1 != b"ref: refs/heads/main\n"
            || read(&root.join(".git/refs/heads/main"), uid, 64)?.1
                != format!("{target}\n").as_bytes()
        {
            return Err(());
        }
        let (_, body) = read(&root.join(".git/refs/remotes/origin/main"), uid, 64)?;
        if body != format!("{base}\n").as_bytes() {
            return Err(());
        }
        directory(&root.join(".git/objects/pack"), uid, 0o700, &[])?;
        Ok(Self {
            files,
            dirs,
            originals,
            data,
            base,
            target,
        })
    }
    pub(crate) fn base(&self) -> &str {
        &self.base
    }
    pub(crate) fn target(&self) -> &str {
        &self.target
    }
    pub(crate) fn root_identity(&self) -> [u64; 6] {
        self.dirs[0]
    }
    pub(crate) fn app(&self) -> [u64; 6] {
        self.dirs[1]
    }
    pub(crate) fn release(&self) -> [u64; 6] {
        self.dirs[2]
    }
    pub(crate) fn ignore(&self) -> FileFact {
        self.files[4].clone()
    }
    pub(crate) fn config(&self) -> FileFact {
        self.files[1].clone()
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.files
            .iter()
            .chain(&self.originals)
            .chain([&self.data])
            .try_fold(
                std::mem::size_of::<Self>()
                    .checked_add(self.base.capacity())?
                    .checked_add(self.target.capacity())?,
                |n, f| n.checked_add(f.sha256.capacity()),
            )
    }
    pub(crate) fn verify(
        &self,
        root: &Path,
        uid: u32,
        case: Case,
        result: &Value,
    ) -> Result<(), ()> {
        for ((p, b), old) in FILES.iter().zip(&self.files) {
            if &file_fact(&root.join(p), b, uid)? != old {
                return Err(());
            }
        }
        for ((p, n), old) in DIRS.iter().zip(&self.dirs) {
            if &directory(&root.join(p), uid, 0o700, n)? != old {
                return Err(());
            }
        }
        for (p, old) in ORIGINALS.iter().zip(&self.originals) {
            if &read(&root.join(".git").join(p), uid, 65536)?.0 != old {
                return Err(());
            }
        }
        if read(&root.join(".git").join(DATA_FILE), uid, DATA_LIMIT)?.0 != self.data {
            return Err(());
        }
        // Push never updates the last-fetched tracking ref or any original
        // local object/HEAD/index/log. The setup's complete loose-object
        // inventory is additionally compared by the SAME outer Fixtures.
        directory(&root.join(".git/objects/pack"), uid, 0o700, &[])?;
        if case == Case::Pack
            && (result["state"] != "succeeded" || result["effectPhase"] != "remote-returned")
        {
            return Err(());
        }
        Ok(())
    }
}
/// One bounded original File and one explicit close on every result. The
/// project/native ancestors have already been held by the observer/SourceBook;
/// this is independent readback of fixed task-created, nonsecret paths only.
fn read(path: &Path, uid: u32, maximum: u64) -> Result<(FileFact, Vec<u8>), ()> {
    if maximum > READ_LIMIT {
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
        let identity = super::super::identity(&before)?;
        if super::super::identity(&f.metadata().map_err(|_| ())?)? != identity {
            return Err(());
        }
        mrk_macos_installed_native::empty_acl(f.as_fd()).map_err(|_| ())?;
        mrk_macos_installed_native::no_xattrs(f.as_fd()).map_err(|_| ())?;
        let mut b = Vec::with_capacity(before.len() as usize + 1);
        (&mut f)
            .take(maximum + 1)
            .read_to_end(&mut b)
            .map_err(|_| ())?;
        if b.len() as u64 != before.len()
            || super::super::identity(&f.metadata().map_err(|_| ())?)? != identity
            || super::super::identity(&std::fs::symlink_metadata(path).map_err(|_| ())?)?
                != identity
        {
            return Err(());
        }
        Ok((
            FileFact {
                identity,
                sha256: super::super::digest(&b),
            },
            b,
        ))
    })();
    if nix::unistd::close(OwnedFd::from(f)).is_err() {
        return Err(());
    }
    result
}
