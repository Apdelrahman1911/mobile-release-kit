//! Two fixed comparison files, retained inside the existing observer Record.
//! Raw FDs are never duplicated, handed off, or implicitly closed by Drop.
//! A failed/uncertain close is absorbing; process exit is not a close receipt.
use super::{application_for, NAME};
use nix::{
    fcntl::{self, AtFlags, OFlag},
    libc,
    sys::stat::{self as nixstat, Mode},
};
use serde_json::Value;
use std::{
    ffi::OsStr,
    fs::File,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
};

const LIMIT: usize = 4096;
pub(in super::super) const PHASE_LINE_LIMIT: usize = 512;
pub(in super::super) const NATIVE: &str = "cli-native.jsonl";
pub(in super::super) const DRIVER: &str = "cli-driver.jsonl";

// Apply before the general JSON parser: the 4 KiB file bound alone would
// permit hundreds of tiny maps. Every one of the eight fixed phase shapes
// fits this smaller bound; neither a grant nor arbitrary payload belongs here.
pub(in super::super) fn phase_line(raw: &[u8]) -> Result<&[u8], ()> {
    if raw.is_empty() || raw.len() > PHASE_LINE_LIMIT {
        return Err(());
    }
    Ok(raw)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}
fn stat(file: &File) -> Result<(Stamp, u64, u64), ()> {
    let s = file.metadata().map_err(|_| ())?;
    Ok((
        Stamp {
            dev: s.dev(),
            ino: s.ino(),
            mode: s.mode(),
            uid: s.uid(),
            gid: s.gid(),
        },
        s.len(),
        s.nlink(),
    ))
}
struct Held {
    fd: Option<File>,
    parent: Option<usize>,
    name: Vec<u8>,
    stamp: Stamp,
    directory: bool,
}
pub(in super::super) struct Files {
    held: Vec<Held>,
    native: usize,
    driver: usize,
    application: PathBuf,
    sent: Vec<u8>,
    received: Vec<u8>,
    rows: usize,
    row_limit: usize,
    closed: bool,
    unknown: bool,
}
impl Files {
    pub(in super::super) fn capture(project: &Path, uid: u32) -> Result<Self, ()> { Self::capture_case(project,uid,NAME) }
    pub(in super::super) fn capture_backup(project:&Path,uid:u32)->Result<Self,()> {
        Self::capture_case(project,uid,super::super::vault::upload_key::cli::SCOPE)
    }
    pub(in super::super) fn capture_tools(project:&Path,uid:u32)->Result<Self,()> {
        Self::capture_case(project,uid,super::super::tool_setup::Case::CancelInTransfer.name())
    }
    pub(in super::super) fn retained_bytes(&self)->Option<usize> {
        let mut n=std::mem::size_of::<Self>().checked_add(self.held.capacity().checked_mul(std::mem::size_of::<Held>())?)?
            .checked_add(self.application.capacity())?.checked_add(self.sent.capacity())?.checked_add(self.received.capacity())?;
        for h in &self.held { n=n.checked_add(h.name.capacity())?; }
        // One original bounded phase read and parsed comparison, never a tool
        // archive or a new application-service response budget.
        n.checked_add(2*(LIMIT+1)+4096)
    }
    fn capture_case(project:&Path,uid:u32,name:&str)->Result<Self,()> {
        let row_limit=if name==NAME {4} else if name==super::super::vault::upload_key::cli::SCOPE {7} else if name==super::super::tool_setup::Case::CancelInTransfer.name() {3} else{return Err(());};
        let mut f = Self {
            held: Vec::with_capacity(16),
            native: 0,
            driver: 0,
            application: application_for(uid,name).ok_or(())?,
            sent: Vec::with_capacity(LIMIT),
            received: Vec::with_capacity(LIMIT),
            rows: 0, row_limit,
            closed: false,
            unknown: false,
        };
        // Retain failed setup too: there is one explicit close pass. Failed
        // closes leave their original numeric identity in this forgotten owner.
        let result = (|| {
            let state = project.parent().ok_or(())?.join("state").join(name);
            let parent = f.path(&state, uid)?;
            f.native = f.open(Some(parent), NATIVE.as_bytes(), uid, false, true)?;
            f.driver = f.open(Some(parent), DRIVER.as_bytes(), uid, false, false)?;
            if stat(f.fd(f.native)?)?.1 != 0 || stat(f.fd(f.driver)?)?.1 != 0 {
                return Err(());
            }
            let path = f.application.clone();
            f.path(&path, uid)?;
            f.current()
        })();
        if result.is_err() {
            if f.close().is_err() {
                std::mem::forget(f);
            }
            return Err(());
        }
        Ok(f)
    }
    fn path(&mut self, path: &Path, uid: u32) -> Result<usize, ()> {
        if !path.is_absolute() || path.as_os_str().len() > 512 {
            return Err(());
        }
        let mut parent = None;
        for part in path.components() {
            use std::path::Component;
            let bytes = match part {
                Component::RootDir => b"/".as_slice(),
                Component::Normal(n) => n.as_bytes(),
                _ => return Err(()),
            };
            let found = self
                .held
                .iter()
                .position(|h| h.directory && h.parent == parent && h.name.as_slice() == bytes);
            parent = Some(if let Some(i) = found {
                i
            } else {
                self.open(parent, bytes, uid, true, false)?
            });
        }
        parent.ok_or(())
    }
    fn open(
        &mut self,
        parent: Option<usize>,
        name: &[u8],
        uid: u32,
        directory: bool,
        write: bool,
    ) -> Result<usize, ()> {
        if self.held.len() >= 16 {
            return Err(());
        } // Both absolute chains, fixed names only.
        if name.contains(&0) {
            return Err(());
        }
        let name = name.to_vec();
        let flags = OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_NONBLOCK
            | if directory {
                OFlag::O_RDONLY | OFlag::O_DIRECTORY
            } else if write {
                OFlag::O_RDWR
            } else {
                OFlag::O_RDONLY
            };
        let opened = if let Some(p) = parent {
            fcntl::openat(
                self.fd(p)?.as_fd(),
                OsStr::from_bytes(&name),
                flags,
                Mode::empty(),
            )
        } else {
            fcntl::open(OsStr::from_bytes(&name), flags, Mode::empty())
        }
        .map_err(|_| ())?;
        let i = self.held.len();
        self.held.push(Held {
            fd: Some(File::from(opened)),
            parent,
            name,
            stamp: Stamp {
                dev: 0,
                ino: 0,
                mode: 0,
                uid: 0,
                gid: 0,
            },
            directory,
        });
        let (s, size, links) = stat(self.fd(i)?)?;
        self.held[i].stamp = s;
        let valid = if directory {
            s.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
                && (s.uid == 0 || s.uid == uid)
                && (s.mode & 0o7022 == 0 || s.uid == 0 && s.mode & 0o7777 == 0o1777)
        } else {
            s.mode == libc::S_IFREG as u32 | 0o600
                && s.uid == uid
                && links == 1
                && size <= LIMIT as u64
        };
        if !valid {
            return Err(());
        }
        if !directory {
            mrk_macos_installed_native::empty_acl(self.fd(i)?.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(self.fd(i)?.as_fd()).map_err(|_| ())?;
        }
        self.one(i)?;
        Ok(i)
    }
    fn fd(&self, i: usize) -> Result<&File, ()> {
        self.held.get(i).and_then(|h| h.fd.as_ref()).ok_or(())
    }
    fn one(&self, i: usize) -> Result<u64, ()> {
        let h = self.held.get(i).ok_or(())?;
        let (held, size, links) = stat(self.fd(i)?)?;
        if held != h.stamp || !h.directory && (size > LIMIT as u64 || links != 1) {
            return Err(());
        }
        let named = if let Some(p) = h.parent {
            let s = nixstat::fstatat(
                self.fd(p)?.as_fd(),
                OsStr::from_bytes(&h.name),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| ())?;
            Stamp {
                dev: s.st_dev as u64,
                ino: s.st_ino as u64,
                mode: s.st_mode as u32,
                uid: s.st_uid,
                gid: s.st_gid,
            }
        } else {
            let s = std::fs::symlink_metadata("/").map_err(|_| ())?;
            Stamp {
                dev: s.dev(),
                ino: s.ino(),
                mode: s.mode(),
                uid: s.uid(),
                gid: s.gid(),
            }
        };
        if named != held {
            return Err(());
        }
        Ok(size)
    }
    pub(in super::super) fn current(&self) -> Result<(), ()> {
        if self.closed || self.unknown {
            return Err(());
        }
        for i in 0..self.held.len() {
            self.one(i)?;
        }
        Ok(())
    }
    pub(in super::super) fn application(&self) -> Result<PathBuf, ()> {
        self.current()?;
        Ok(self.application.clone())
    }
    fn read(&self, i: usize) -> Result<Vec<u8>, ()> {
        self.current()?;
        let size = self.one(i)? as usize;
        let mut raw = vec![0u8; LIMIT + 1];
        let n = self.fd(i)?.read_at(&mut raw, 0).map_err(|_| ())?;
        if n > LIMIT {
            return Err(());
        }
        raw.truncate(n);
        self.current()?;
        // A partial append may be observed, but never interpreted as complete.
        if raw.len() < size {
            return Err(());
        }
        Ok(raw)
    }
    pub(in super::super) fn poll(&mut self, index: usize, phase: &str) -> Result<Option<Value>, ()> {
        if index >= self.row_limit || index != self.rows {
            return Err(());
        }
        let raw = self.read(self.driver)?;
        if !raw.starts_with(&self.received) {
            return Err(());
        }
        let Some(end) = raw[self.received.len()..].iter().position(|b| *b == b'\n') else {
            return Ok(None);
        };
        let end = self.received.len() + end;
        // At most this next monotonic complete line; no future phase prewrite.
        if end + 1 != raw.len() {
            return Err(());
        }
        let line = phase_line(&raw[self.received.len()..end])?;
        let v = crate::protocol::strict_json(line).map_err(|_| ())?;
        if v.get("phase").and_then(Value::as_str) != Some(phase) {
            return Err(());
        }
        self.received.extend_from_slice(&raw[self.received.len()..]);
        self.rows += 1;
        Ok(Some(v))
    }
    pub(in super::super) fn send(&mut self, v: &Value) -> Result<(), ()> {
        self.current()?;
        let mut raw = crate::edit_protocol::bounded(v, PHASE_LINE_LIMIT).map_err(|_| ())?;
        raw.push(b'\n');
        if self.sent.len() + raw.len() > LIMIT || self.read(self.native)? != self.sent {
            return Err(());
        }
        let mut offset = 0;
        while offset < raw.len() {
            let result = self
                .fd(self.native)?
                .write_at(&raw[offset..], (self.sent.len() + offset) as u64);
            let Ok(n) = result else {
                self.unknown = true;
                return Err(());
            };
            if n == 0 || n > raw.len() - offset {
                self.unknown = true;
                return Err(());
            }
            offset += n;
        }
        if self.fd(self.native)?.sync_all().is_err() {
            self.unknown = true;
            return Err(());
        }
        self.sent.extend_from_slice(&raw);
        if self.read(self.native)? != self.sent {
            self.unknown = true;
            return Err(());
        }
        Ok(())
    }
    pub(in super::super) fn finish_backup(&mut self)->Result<(),()> {
        if self.row_limit!=7 || self.rows!=7 || self.sent.iter().filter(|b|**b==b'\n').count()!=7 {return Err(());}
        self.current()?;self.close()
    }
    pub(in super::super) fn close(&mut self) -> Result<(), ()> {
        if self.closed || self.unknown {
            return Err(());
        }
        let current = self.current().is_ok();
        // Close children before parents, each attempted once. A failed close
        // never triggers another close of a descriptor that could be reused.
        let mut ok = current;
        for h in self.held.iter_mut().rev() {
            if let Some(fd) = h.fd.take() {
                if nix::unistd::close(OwnedFd::from(fd)).is_err() {
                    ok = false;
                }
            }
        }
        self.closed = ok;
        self.unknown = !ok;
        if ok {
            Ok(())
        } else {
            Err(())
        }
    }
    pub(in super::super) fn closed(&self) -> bool {
        self.closed && !self.unknown && self.held.iter().all(|h| h.fd.is_none())
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        // No implicit close of unsettled originals. The explicit sole pass
        // above is the only successful retirement; failure stays unqualified.
        for h in &mut self.held {
            if let Some(file) = h.fd.take() {
                std::mem::forget(file);
            }
        }
    }
}
