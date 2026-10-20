//! Only fixed task-owned public fixture bytes. Never reads/replaces the real
//! user's SDK or grants a source permit; ordinary SourceSlots reopens/reproves.
use super::super::{directory, file_fact, FileFact, CONFIG, IGNORE_PREFIX, KEEP, VERSION};
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
};
const APP: &[u8]=b"plugins { id(\"com.android.application\") }\nandroid { compileSdk = 35; buildToolsVersion = \"35.0.0\"; defaultConfig { applicationId = \"org.example.mrk.observed\" } }\nkotlin { jvmToolchain(17) }\n";
const ROOT: &[u8] = b"plugins { id(\"com.android.application\") version \"8.9.2\" apply false }\n";
const WRAPPER: &[u8]=b"distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.5-bin.zip\ndistributionSha256Sum=6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854\n";
const FILES: [(&str, &[u8]); 7] = [
    ("app/build.gradle.kts", APP),
    ("build.gradle.kts", ROOT),
    ("gradle/wrapper/gradle-wrapper.properties", WRAPPER),
    ("release/mobile-release.json", CONFIG),
    ("version.properties", VERSION),
    ("keep.txt", KEEP),
    (".gitignore", IGNORE_PREFIX),
];
const DIRS: [(&str, &[&str]); 5] = [
    (
        ".",
        &[
            "app",
            "build.gradle.kts",
            "gradle",
            "release",
            "version.properties",
            "keep.txt",
            ".gitignore",
        ],
    ),
    ("app", &["build.gradle.kts"]),
    ("gradle", &["wrapper"]),
    ("gradle/wrapper", &["gradle-wrapper.properties"]),
    ("release", &["mobile-release.json"]),
];
const PLATFORM_SHA: &str = "2c3764446f335ad2cc44383a0360fe247620b7c774ec100d5087771ac8ed3b28";
#[derive(Clone)]
pub(crate) struct Fixture {
    files: [FileFact; 7],
    dirs: [[u64; 6]; 5],
    source: FileFact,
    drift_started: bool,
    drifted: bool,
}
impl Fixture {
    pub(crate) fn capture(root: &Path, uid: u32, case: Case) -> Result<Self, ()> {
        let files = FILES
            .iter()
            .map(|(path, bytes)| file_fact(&root.join(path), bytes, uid))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        let dirs = DIRS
            .iter()
            .map(|(path, names)| directory(&root.join(path), uid, 0o700, names))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ())?;
        let source = source_file(case, uid, None)?;
        if source.identity[6] != 257 || source.sha256 != PLATFORM_SHA {
            return Err(());
        }
        Ok(Self {
            files,
            dirs,
            source,
            drift_started: false,
            drifted: false,
        })
    }
    pub(super) fn verify(&self, root: &Path, uid: u32, case: Case) -> Result<(), ()> {
        for ((path, bytes), before) in FILES.iter().zip(&self.files) {
            if &file_fact(&root.join(path), bytes, uid)? != before {
                return Err(());
            }
        }
        for ((path, names), before) in DIRS.iter().zip(&self.dirs) {
            if &directory(&root.join(path), uid, 0o700, names)? != before {
                return Err(());
            }
        }
        if source_file(case, uid, None)? != self.source || self.drift_started != self.drifted {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn root_identity(&self) -> [u64; 6] {
        self.dirs[0]
    }
    pub(crate) fn app(&self) -> [u64; 6] {
        self.dirs[1]
    }
    pub(crate) fn release(&self) -> [u64; 6] {
        self.dirs[4]
    }
    pub(crate) fn ignore(&self) -> FileFact {
        self.files[6].clone()
    }
    pub(crate) fn config(&self) -> FileFact {
        self.files[3].clone()
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.files
            .iter()
            .chain(std::iter::once(&self.source))
            .try_fold(std::mem::size_of::<Self>(), |n, f| {
                n.checked_add(f.sha256.capacity())
            })
    }
}
/// All source ancestors and the exact original file stay held through this
/// task-only byte substitution. Independent one-close attempts run on every path;
/// any uncertain close returns Err and the observation cannot retry/pass.
fn source_file(case: Case, uid: u32, change: Option<&FileFact>) -> Result<FileFact, ()> {
    use nix::{
        fcntl::{openat, AtFlags, OFlag},
        sys::stat::Mode,
    };
    let root = sources_root().ok_or(())?;
    let name = root.file_name().and_then(|s| s.to_str()).ok_or(())?;
    let names = [name, case.name(), "sdk", "platforms", "android-35"];
    let mut held: Vec<File> = Vec::with_capacity(7);
    let value = (|| {
        held.push(
            OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY)
                .open("/private/tmp")
                .map_err(|_| ())?,
        );
        let base = held[0].metadata().map_err(|_| ())?;
        if !base.is_dir() || base.uid() != 0 || base.mode() & 0o7777 != 0o1777 {
            return Err(());
        }
        for name in names {
            let fd = openat(
                held.last().ok_or(())?.as_fd(),
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ())?;
            held.push(File::from(fd));
            let file = held.last().ok_or(())?;
            let m = file.metadata().map_err(|_| ())?;
            if !m.is_dir() || m.uid() != uid || m.mode() & 0o022 != 0 {
                return Err(());
            }
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
        }
        let flags = (if change.is_some() {
            OFlag::O_RDWR
        } else {
            OFlag::O_RDONLY
        }) | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC;
        held.push(File::from(
            openat(
                held.last().ok_or(())?.as_fd(),
                "source.properties",
                flags,
                Mode::empty(),
            )
            .map_err(|_| ())?,
        ));
        let check = |held: &[File]| -> Result<FileFact, ()> {
            let file = held.last().ok_or(())?;
            let m = file.metadata().map_err(|_| ())?;
            if !m.is_file()
                || m.uid() != uid
                || m.mode() & 0o7777 != 0o644
                || m.nlink() != 1
                || m.len() != 257
            {
                return Err(());
            }
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
            for (i, name) in names
                .iter()
                .chain(std::iter::once(&"source.properties"))
                .enumerate()
            {
                let edge =
                    nix::sys::stat::fstatat(held[i].as_fd(), *name, AtFlags::AT_SYMLINK_NOFOLLOW)
                        .map_err(|_| ())?;
                let next = held[i + 1].metadata().map_err(|_| ())?;
                if edge.st_dev as u64 != next.dev()
                    || edge.st_ino != next.ino()
                    || edge.st_mode as u32 != next.mode()
                    || edge.st_uid != next.uid()
                    || edge.st_gid != next.gid()
                    || edge.st_nlink as u64 != next.nlink()
                {
                    return Err(());
                }
            }
            Ok(FileFact {
                identity: super::super::identity(&m)?,
                sha256: String::new(),
            })
        };
        let mut before = check(&held)?;
        let mut bytes = [0u8; 258];
        let file = held.last_mut().ok_or(())?;
        let mut size = 0usize;
        loop {
            let n = file.read(&mut bytes[size..]).map_err(|_| ())?;
            if n == 0 {
                break;
            }
            size += n;
            if size == bytes.len() {
                return Err(());
            }
        }
        before.sha256 = super::super::digest(&bytes[..size]);
        if size as u64 != before.identity[6] || check(&held)?.identity != before.identity {
            return Err(());
        }
        if let Some(expected) = change {
            if case != Case::SourceDrift
                || &before != expected
                || size != 257
                || before.sha256 != PLATFORM_SHA
                || bytes[256] != b'\n'
            {
                return Err(());
            }
            // Preserve size so the original SourceSlots reads and rejects the
            // changed hash, rather than an unrelated early size/budget refusal.
            // One positioned byte write on this held File; no truncate/reopen.
            if held.last().ok_or(())?.write_at(b" ", 256).map_err(|_| ())? != 1 {
                return Err(());
            }
            held.last().ok_or(())?.sync_all().map_err(|_| ())?;
            let mut after = check(&held)?;
            if after.identity[0..7] != before.identity[0..7] {
                return Err(());
            }
            bytes[256] = b' ';
            after.sha256 = super::super::digest(&bytes[..257]);
            if after.sha256 == before.sha256 {
                return Err(());
            }
            // Actual positioned readback, no new descriptor/cursor owner.
            let mut readback = [0u8; 258];
            if held
                .last()
                .ok_or(())?
                .read_at(&mut readback, 0)
                .map_err(|_| ())?
                != 257
                || readback[..257] != bytes[..257]
                || check(&held)?.identity != after.identity
            {
                return Err(());
            }
            Ok(after)
        } else {
            Ok(before)
        }
    })();
    let mut closed = true;
    while let Some(file) = held.pop() {
        if nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_err() {
            closed = false;
        }
    }
    if closed {
        value
    } else {
        Err(())
    }
}
impl Observation {
    pub(super) fn tool_verify(&self) -> Result<(), ()> {
        let (fixture, uid) = {
            let r = self.record().ok_or(())?;
            (r.fixture.tools.clone().ok_or(())?, r.fixture.uid)
        };
        let c = self.tool_setup.as_ref().ok_or(())?;
        fixture.verify(&self.project_path, uid, c.case)
    }
    pub(super) fn tool_drift(&self) -> Result<(), ()> {
        let c = self.tool_setup.as_ref().ok_or(())?;
        let (before, uid) = {
            let mut r = self.record().ok_or(())?;
            let uid = r.fixture.uid;
            let f = r.fixture.tools.as_mut().ok_or(())?;
            if c.case != Case::SourceDrift || f.drift_started || f.drifted {
                return Err(());
            }
            f.drift_started = true;
            (f.source.clone(), uid)
        };
        let result = source_file(c.case, uid, Some(&before));
        let mut r = self.record().ok_or(())?;
        let f = r.fixture.tools.as_mut().ok_or(())?;
        let after = result?;
        if !f.drift_started || f.drifted || f.source != before {
            return Err(());
        }
        f.source = after;
        f.drifted = true;
        Ok(())
    }
}
