//! Read-only Push facet of the SAME GitLocal SourceBook. The helper writes
//! only its original private view/body; no original ref/index/log replacement
//! is admitted here. All held source FDs retain the existing one-close routes.
use super::*;

struct Edge {
    parent: usize,
    name: Vec<u8>,
    original: Option<(usize, wire::Snapshot)>,
    maximum: u64,
}
pub(super) struct State {
    kind: wire::Kind,
    shell: (usize, wire::Snapshot),
    current: Option<Edge>,
    tracking: Option<Edge>,
    packed: Option<Edge>,
}
impl State {
    pub(super) fn extra(kind: wire::Kind, review: Option<&wire::Review>) -> Option<usize> {
        if !kind.is_push() {
            return Some(0);
        }
        match review {
            None => Some(2), // protected /bin/sh, same Book root
            Some(wire::Review::Push(r)) if r.action.local_kind() == kind && r.valid() => r
                .branch
                .split('/')
                .count()
                .checked_add(r.tracking_ref.as_deref().map_or(0, |v| v.split('/').count()))?
                .checked_add(8),
            _ => None,
        }
    }
    pub(super) fn working_bytes() -> Option<usize> {
        // Original Book's unchanged128 slots already include every descriptor.
        // Fixed wrappers/hashes and streaming checks are additional, not alias
        // or post-close credit. Body's two leases live in original helper C/A/W.
        std::mem::size_of::<Self>()
            .checked_add(3 * std::mem::size_of::<Edge>())?
            .checked_add(4 * (PATH_LIMIT + 2048))?
            .checked_add(32768 + 4096)
    }
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}

impl GitLocalSources {
    fn push_edge(
        &mut self,
        parent: usize,
        name: &[u8],
        uid: u32,
        maximum: u64,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Edge, Reason> {
        checkpoint(stop)?;
        let original = match stat::fstatat(
            self.book.fd(parent)?,
            OsStr::from_bytes(name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Err(nix::errno::Errno::ENOENT) => None,
            Ok(_) => {
                let index = self.file(parent, name, uid, maximum, false, stop)?;
                Some((index, self.snapshot(index, maximum, stop)?))
            }
            Err(_) => return Err(Reason::SourceRefused),
        };
        checkpoint(stop)?;
        Ok(Edge {
            parent,
            name: copy_bytes(name)?,
            original,
            maximum,
        })
    }
    fn push_reference(
        &mut self,
        name: &str,
        uid: u32,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Edge, Reason> {
        let parts: Vec<_> = name.split('/').collect();
        if !(3..=32).contains(&parts.len()) {
            return Err(Reason::SourceRefused);
        }
        let mut parent = self.git.ok_or(Reason::SourceChanged)?;
        for part in &parts[..parts.len() - 1] {
            checkpoint(stop)?;
            match stat::fstatat(self.book.fd(parent)?, *part, AtFlags::AT_SYMLINK_NOFOLLOW) {
                Err(nix::errno::Errno::ENOENT) => {
                    // A packed ref may have no loose parent. Retain the FIRST
                    // absent forward edge, never create or rediscover it.
                    return Ok(Edge {
                        parent,
                        name: copy_bytes(part.as_bytes())?,
                        original: None,
                        maximum: 65,
                    });
                }
                Ok(_) => parent = self.book.child(parent, part.as_bytes(), false, stop)?,
                Err(_) => return Err(Reason::SourceRefused),
            }
        }
        self.push_edge(
            parent,
            parts.last().ok_or(Reason::SourceRefused)?.as_bytes(),
            uid,
            65,
            stop,
        )
    }
    pub(super) fn capture_push(&mut self, kind: wire::Kind, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        if self.push.is_some() || !kind.is_push() {
            return Err(Reason::SourceChanged);
        }
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?.clone();
        let mut nominated=crate::runtime::git_push::matches_tool_for(kind, &native.tool);
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        {if kind==wire::Kind::Push && self.push_observation.is_some(){nominated=self.observed_push_tool(stop)?;}}
        if !nominated {
            return Err(Reason::SourceRefused);
        }
        let bin = self.book.child(0, b"bin", false, stop)?;
        let d = self.book.directory(bin)?;
        if d.uid != 0 || d.mode & 0o7022 != 0 {
            return Err(Reason::SourceRefused);
        }
        let shell = self.file(bin, b"sh", 0, wire::TOOL_LIMIT, true, stop)?;
        self.push = Some(State {
            kind,
            shell: (shell, self.snapshot(shell, wire::TOOL_LIMIT, stop)?),
            current: None,
            tracking: None,
            packed: None,
        });
        let Some(review) = self
            .review
            .as_ref()
            .and_then(wire::Review::push_details)
            .cloned()
        else {
            return Ok(());
        };
        if !review.valid() || review.action.local_kind() != kind
            || native.files.head.sha256 != hash(format!("ref: {}\n", review.branch).as_bytes())
        {
            return Err(Reason::SourceChanged);
        }
        let git = self.git.ok_or(Reason::SourceChanged)?;
        let packed = self.push_edge(git, b"packed-refs", native.uid, 65536, stop)?;
        self.push.as_mut().ok_or(Reason::SourceChanged)?.packed = Some(packed);
        // First publication has NO configured remote/tracking source. The
        // same original current ref and packed/config/HEAD/index sources stay
        // mandatory; no invented tracking path or expected-zero local file.
        let references = [Some((review.branch.as_str(), &review.head, true)),
            review.tracking_ref.as_deref().map(|name| (name, &review.expected_remote_oid, false))];
        for (name, expected, is_current) in references.into_iter().flatten() {
            let edge = self.push_reference(name, native.uid, stop)?;
            if let Some((_, snapshot)) = &edge.original {
                if snapshot.sha256 != hash(format!("{expected}\n").as_bytes()) {
                    return Err(Reason::SourceChanged);
                }
            } else if !self
                .push
                .as_ref()
                .and_then(|s| s.packed.as_ref())
                .is_some_and(|p| p.original.is_some())
            {
                return Err(Reason::SourceChanged);
            }
            // The unchanged native packed source plus original core's fresh
            // complete tracking calculation bind a packed OID. Absence alone
            // is never accepted as an existing selected branch.
            let state = self.push.as_mut().ok_or(Reason::SourceChanged)?;
            if is_current {
                state.current = Some(edge);
            } else {
                state.tracking = Some(edge);
            }
        }
        Ok(())
    }
    pub(super) fn post_push(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let Some(state) = &self.push else {
            return Ok(());
        };
        if self.snapshot(state.shell.0, wire::TOOL_LIMIT, stop)? != state.shell.1 {
            return Err(Reason::SourceChanged);
        }
        for edge in [&state.current, &state.tracking, &state.packed]
            .into_iter()
            .flatten()
        {
            if let Some((index, snapshot)) = &edge.original {
                if self.snapshot(*index, edge.maximum, stop)? != *snapshot {
                    return Err(Reason::SourceChanged);
                }
            } else {
                checkpoint(stop)?;
                if !matches!(
                    stat::fstatat(
                        self.book.fd(edge.parent)?,
                        OsStr::from_bytes(&edge.name),
                        AtFlags::AT_SYMLINK_NOFOLLOW
                    ),
                    Err(nix::errno::Errno::ENOENT)
                ) {
                    return Err(Reason::SourceChanged);
                }
                checkpoint(stop)?;
            }
        }
        Ok(())
    }
    pub(super) fn push_returned(
        &self,
        publication: &GitLocalPublication,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let state = self.push.as_ref().ok_or(Reason::SourceChanged)?;
        let native = self.native.as_ref().ok_or(Reason::SourceChanged)?;
        let review = self.review.as_ref().ok_or(Reason::SourceChanged)?;
        publication.push_for(
            self.operation_id.as_deref().ok_or(Reason::SourceChanged)?,
            native,
            review,
        )?;
        if state.kind != review.action() || state.current.is_none() || state.packed.is_none()
            || match state.kind {
                wire::Kind::Push => state.tracking.is_none(),
                wire::Kind::PushNewBranch => state.tracking.is_some(),
                _ => true,
            } {
            return Err(Reason::SourceChanged);
        }
        self.post_push(stop) // NO source successor exception or original write.
    }
}
