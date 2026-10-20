//! Private Fetch arm of the original GitLocal wire. These bounded comparisons
//! are neither a Connection credential grant nor a SourceBook publication or
//! join witness. The original native owners construct and consume them.
use super::*;
use crate::git_fetch_protocol as fetch;
use zeroize::Zeroizing;

pub(crate) const PROTOCOL: &str = "mrk-git-remote/1";
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const ACK_LIMIT: usize = 4096;
pub(crate) const OUTPUT_LIMIT: usize = 32 * 1024;
pub(crate) const CHANNEL_BACKING: usize = 8 * 1024 * 1024;
pub(crate) const HELPER_BACKING: usize = 16 * 1024 * 1024;
pub(crate) const REMOTE_BACKING: usize = CHANNEL_BACKING + HELPER_BACKING;

/// Same original admission, with separately charged remote call records.
/// Do not credit discarded reviews, retained jobs, Connection or other facets.
pub(crate) fn admission_bytes(document: usize, future: usize) -> Option<usize> {
    let ordinary = future.checked_sub(REMOTE_BACKING)?;
    super::admission_bytes(document, ordinary)?.checked_add(REMOTE_BACKING)
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Target {
    pub(crate) repository: String,
    pub(crate) login: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
    pub(crate) reference: String,
    pub(crate) oid: Option<String>,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        crate::github_connection_protocol::coordinate(&self.repository)
            && fetch::login(&self.login)
            && crate::github_connection_protocol::numeric_id(&self.account_id)
            && crate::github_connection_protocol::numeric_id(&self.repository_id)
            && fetch::reference(&self.reference)
            && self.oid.as_deref().is_none_or(fetch::oid)
    }
    pub(crate) fn matches_review(&self, r: &fetch::Review) -> bool {
        self.valid()
            && r.valid()
            && self.repository == r.repository
            && self.login == r.login
            && self.account_id == r.account_id
            && self.repository_id == r.repository_id
            && self.reference == r.reference
            && self.oid.as_deref().is_none_or(|v| v == r.candidate_ref_oid)
    }
}

// Python's core identity spelling, not the read::FileIdentity tuple order.
// dev,ino,mode,size,mtime,ctime[,uid,gid[,nlink]]. These contain no paths/bytes.
pub(crate) type CoreFile = [u64; 6];
pub(crate) type CoreDirectory = [u64; 8];
pub(crate) type CoreOwnedFile = [u64; 9];
fn file(v: &[u64], size: u64) -> bool {
    v.len() >= 6
        && v[0] != 0
        && v[1] != 0
        && v[2] & 0o170000 == 0o100000
        && v[2] & 0o7022 == 0
        && v[3] <= size
        && v[4] <= i64::MAX as u64
        && v[5] <= i64::MAX as u64
}
fn directory(v: &[u64]) -> bool {
    v.len() >= 6
        && v[0] != 0
        && v[1] != 0
        && v[2] & 0o170000 == 0o040000
        && v[2] & 0o7022 == 0
        && v[4] <= i64::MAX as u64
        && v[5] <= i64::MAX as u64
}

/// Only the real candidate job may construct this from its held, fsynced
/// keep marker. The wire codec cannot create/unlink/adopt any filesystem path.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Keep {
    pub(crate) pack_oid: String,
    pub(crate) review_digest: String,
    pub(crate) identity: CoreOwnedFile,
    pub(crate) parent_before: CoreDirectory,
    pub(crate) parent_after: CoreDirectory,
}
impl Keep {
    pub(crate) fn body(&self) -> Vec<u8> {
        format!("mrk-git-fetch/1 {}\n", self.review_digest).into_bytes()
    }
    pub(crate) fn valid(&self, intent: &fetch::Intent, native: &Native) -> bool {
        intent.valid()
            && self.pack_oid == intent.pack_oid
            && self.review_digest == intent.review_digest
            && file(&self.identity, 256)
            && self.identity[2] == 0o100600
            && self.identity[3] == self.body().len() as u64
            && self.identity[6] == u64::from(native.uid)
            && self.identity[7] == u64::from(native.gid)
            && self.identity[8] == 1
            && directory(&self.parent_before)
            && directory(&self.parent_after)
            && self.parent_before[..3] == self.parent_after[..3]
            && self.parent_before[6..] == self.parent_after[6..]
            && self.parent_before[6] == u64::from(native.uid)
    }
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reference {
    pub(crate) name: String,
    pub(crate) oid: String,
    pub(crate) identity: CoreFile,
    pub(crate) parent: CoreFile,
}
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Log {
    pub(crate) kind: String,
    pub(crate) identity: Option<CoreFile>,
    pub(crate) sha256: String,
}
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Returned {
    pub(crate) phase: fetch::Effect,
    pub(crate) pack: CoreOwnedFile,
    pub(crate) index: Option<CoreOwnedFile>,
    pub(crate) reference: Option<Reference>,
    pub(crate) log: Option<Log>,
    pub(crate) log_parent: Option<CoreDirectory>,
}
impl Returned {
    pub(crate) fn valid(&self, i: &fetch::Intent, native: &Native) -> bool {
        use fetch::Effect as E;
        let content = |v: &CoreOwnedFile, bytes| {
            file(v, fetch::FILE_LIMIT)
                && v[3] == bytes
                && v[6] == u64::from(native.uid)
                && v[7] == u64::from(native.gid)
                && matches!(v[8], 1 | 2)
        };
        if !i.valid()
            || !content(&self.pack, i.pack_bytes)
            || !self.index.as_ref().is_none_or(|v| {
                content(v, i.index_bytes) && (v[0], v[1]) != (self.pack[0], self.pack[1])
            })
        {
            return false;
        }
        if !match self.phase {
            E::PackLinked | E::IndexLinkEntered => self.index.is_none() && self.reference.is_none(),
            E::ObjectsLinked | E::RefSendEntered => {
                self.index.is_some() && self.reference.is_none()
            }
            E::RefPublished => self.index.is_some() && self.reference.is_some(),
            E::NotPublished | E::PackLinkEntered => false,
        } {
            return false;
        }
        match &self.reference {
            None => self.log.is_none() && self.log_parent.is_none(),
            Some(r) => {
                r.name == i.target_ref
                    && r.oid == i.candidate_ref_oid
                    && file(&r.identity, 41)
                    && r.identity[3] == 41
                    && directory(&r.parent)
                    && self.log.as_ref().is_some_and(|l| {
                        read::digest(&l.sha256)
                            && match l.kind.as_str() {
                                "absent" => l.identity.is_none() && l.sha256 == hash(b"absent"),
                                "file" => l
                                    .identity
                                    .as_ref()
                                    .is_some_and(|v| file(v, 128 * 1024 + 2048)),
                                _ => false,
                            }
                    })
                    && match &self.log_parent {
                        Some(p) => directory(p) && p[6] == u64::from(native.uid),
                        None => self.log.as_ref().is_some_and(|l| l.kind == "absent"),
                    }
            } // The original SourceBook must additionally prove the absent parent edge.
        }
    }
}

impl Request {
    pub(crate) fn from_fetch_original(
        id: &str,
        action: &Action,
        context: &Context,
        native: &Native,
        clock: Clock,
        binding: Option<ApplyBinding>,
        target: Target,
    ) -> Result<Self, BridgeError> {
        let Action::Fetch(selected) = action else {
            return Err(BridgeError::protocol());
        };
        need(
            valid_id(id)
                && action.valid()
                && valid_id(&context.project_id)
                && valid_id(&context.revision)
                && native.valid()
                && target.valid()
                && target.reference == selected.reference
                && clock.work_end_ns > 0
                && clock.hard_end_ns <= i64::MAX as u64
                && clock.hard_end_ns.checked_sub(clock.work_end_ns) == Some(10_000_000_000),
        )?;
        let phase = match &binding {
            None => {
                need(target.oid.is_none())?;
                Phase::Prepare
            }
            Some(b) => {
                let Review::Fetch(r) = &b.review else {
                    return Err(BridgeError::protocol());
                };
                let index = native
                    .files
                    .index
                    .as_ref()
                    .map(|v| v.sha256.clone())
                    .unwrap_or_else(|| hash(b"absent"));
                need(
                    r.matches(selected)
                        && !r.up_to_date()
                        && target.matches_review(r)
                        && target.oid.as_deref() == Some(r.candidate_ref_oid.as_str())
                        && r.expected_index == index
                        && (1..=u64::MAX - 2).contains(&b.journal_revision),
                )?;
                Phase::Apply
            }
        };
        let value = json!({"protocol":PROTOCOL,"id":id,"phase":phase,"action":action,
            "reviewDigest":binding.as_ref().map(|b| b.review.review_digest()),
            "journalRevision":binding.as_ref().map(|b| b.journal_revision),
            "context":context,"native":native,"clock":clock,"target":target});
        let mut bytes = serde_json::to_vec(&value).map_err(|_| BridgeError::protocol())?;
        bytes.push(b'\n');
        need(bytes.len() <= REQUEST_LIMIT)?;
        let digest = hash(&bytes);
        Ok(Self {
            id: id.into(),
            action: action.clone(),
            context: context.clone(),
            clock,
            phase,
            binding,
            digest,
            native: Some(native.clone()),
            initialization: None,
            switch_sources: None,
            rename_sources: None,
            fast_forward_sources: None,
            fetch_target: Some(target),
            bytes,
        })
    }

    /// Called only under the actual original Connection/Doc claim. The token
    /// is borrowed, never placed in Value, Debug, an event or a public result.
    pub(crate) fn fetch_go(&self, token: &str) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        need(
            self.action.kind() == Kind::Fetch
                && self.fetch_target.as_ref().is_some_and(Target::valid)
                && !token.is_empty()
                && token.len() <= 4096
                && token.bytes().all(|c| (0x21..=0x7e).contains(&c)),
        )?;
        #[derive(Serialize)]
        struct Go<'a> {
            protocol: &'a str,
            kind: &'a str,
            id: &'a str,
            digest: &'a str,
            token: &'a str,
        }
        struct BoundedGo<'a>(&'a mut Vec<u8>);
        impl std::io::Write for BoundedGo<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > GO_LIMIT.saturating_sub(1 + self.0.len()) {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(GO_LIMIT));
        serde_json::to_writer(
            BoundedGo(&mut bytes),
            &Go {
                protocol: PROTOCOL,
                kind: "go",
                id: &self.id,
                digest: &self.digest,
                token,
            },
        )
        .map_err(|_| BridgeError::protocol())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub(crate) fn fetch_ack(
        &self,
        candidate: &Candidate,
        revision: u64,
        keep: &Keep,
    ) -> Result<Vec<u8>, BridgeError> {
        let binding = self.binding.as_ref().ok_or_else(BridgeError::protocol)?;
        let Intent::Fetch(intent) = &candidate.intent else {
            return Err(BridgeError::protocol());
        };
        need(
            self.action.kind() == Kind::Fetch
                && candidate.request_digest == self.digest
                && candidate.intent.matches(&binding.review)
                && revision == binding.journal_revision + 1
                && self.native.as_ref().is_some_and(|n| keep.valid(intent, n)),
        )?;
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"kind":"ack","id":self.id,
            "digest":self.digest,"candidateDigest":candidate.digest,"journalRevision":revision,"keep":keep}))
            .map_err(|_| BridgeError::protocol())?;
        bytes.push(b'\n');
        need(bytes.len() <= ACK_LIMIT)?;
        Ok(bytes)
    }

    pub(super) fn fetch_terminal(
        &self,
        bytes: &[u8],
        candidate: Option<&Candidate>,
    ) -> Result<Terminal, BridgeError> {
        let Action::Fetch(action) = &self.action else {
            return Err(BridgeError::protocol());
        };
        let target = self
            .fetch_target
            .as_ref()
            .ok_or_else(BridgeError::protocol)?;
        let native = self
            .native
            .as_ref()
            .filter(|n| n.valid())
            .ok_or_else(BridgeError::protocol)?;
        need(self.initialization.is_none())?;
        if let Some(c) = candidate {
            let b = self.binding.as_ref().ok_or_else(BridgeError::protocol)?;
            need(c.request_digest == self.digest && c.intent.matches(&b.review))?;
        }
        let mut row = frame(bytes, OUTPUT_LIMIT - READY_LIMIT - CANDIDATE_LIMIT)?;
        need(
            keys(
                &row,
                &[
                    "protocol",
                    "kind",
                    "id",
                    "digest",
                    "phase",
                    "action",
                    "status",
                    "reason",
                    "result",
                    "publication",
                    "firstFailureNs",
                    "cleanupEndNs",
                    "control",
                ],
            ) && row["protocol"] == PROTOCOL
                && row["kind"] == "terminal"
                && row["id"] == self.id
                && row["digest"] == self.digest,
        )?;
        let control: crate::github_connection_protocol::GitHubReadControl = serde_json::from_value(
            row.as_object_mut()
                .ok_or_else(BridgeError::protocol)?
                .remove("control")
                .ok_or_else(BridgeError::protocol)?,
        )
        .map_err(|_| BridgeError::protocol())?;
        need(control.valid())?;
        let returned = if row["publication"].is_null() {
            None
        } else {
            Some(
                serde_json::from_value::<Returned>(row["publication"].clone())
                    .map_err(|_| BridgeError::protocol())?,
            )
        };
        // Legacy enum remains unchanged on the wire. Only this exact Fetch
        // decoder translates a rich private return into its internal tag.
        row["publication"] = json!(if returned.is_some() {
            Publication::FetchReturned
        } else {
            Publication::NotReported
        });
        let mut terminal: Terminal =
            serde_json::from_value(row).map_err(|_| BridgeError::protocol())?;
        terminal.fetch_publication = returned;
        terminal.fetch_control = Some(control);
        need(
            terminal.phase == self.phase
                && terminal.action == Kind::Fetch
                && terminal.cleanup_end_ns > 0
                && terminal.cleanup_end_ns <= self.clock.hard_end_ns,
        )?;
        if let Some(first) = terminal.first_failure_ns {
            need(
                first > 0
                    && first <= terminal.cleanup_end_ns
                    && terminal.cleanup_end_ns - first <= 10_000_000_000,
            )?;
        }
        let failure = |v: &str| read::reason(v) || fetch::reason(v);
        if terminal.status != read::Outcome::Ok {
            need(
                terminal.reason.as_deref().is_some_and(failure)
                    && terminal.result.is_null()
                    && terminal.fetch_publication.is_none()
                    && (terminal.first_failure_ns.is_some()
                        || terminal.status == read::Outcome::CleanupUnknown),
            )?;
        } else if self.phase == Phase::Prepare {
            need(
                terminal.reason.is_none()
                    && candidate.is_none()
                    && terminal.first_failure_ns.is_none()
                    && terminal.cleanup_end_ns == self.clock.hard_end_ns
                    && terminal.fetch_publication.is_none()
                    && keys(&terminal.result, &["review", "diff"])
                    && terminal.result["diff"].is_null(),
            )?;
            let Review::Fetch(review) = Review::decode(&terminal.result["review"])? else {
                return Err(BridgeError::protocol());
            };
            need(review.matches(action) && target.matches_review(&review))?;
        } else {
            need(terminal.reason.is_none() && keys(&terminal.result, fetch::RESULT_KEYS))?;
            let result: fetch::Mutation = serde_json::from_value(terminal.result.clone())
                .map_err(|_| BridgeError::protocol())?;
            need(
                result.valid(action, &self.id)
                    && !matches!(
                        result.reason.as_deref(),
                        Some("unknown" | "cleanup-unknown")
                    ),
            )?;
            match (&result.intent, candidate) {
                (None, None) => need(terminal.fetch_publication.is_none())?,
                (Some(i), Some(c)) => need(c.intent == Intent::Fetch(i.clone()))?,
                _ => return Err(BridgeError::protocol()),
            }
            if let Some(returned) = &terminal.fetch_publication {
                let intent = result.intent.as_ref().ok_or_else(BridgeError::protocol)?;
                need(returned.valid(intent, native) && returned.phase == result.effect_phase)?;
            }
            if result.state == "succeeded" {
                need(
                    terminal.first_failure_ns.is_none()
                        && terminal.cleanup_end_ns == self.clock.hard_end_ns
                        && terminal
                            .fetch_publication
                            .as_ref()
                            .is_some_and(|v| v.reference.is_some()),
                )?;
            } else {
                need(terminal.first_failure_ns.is_some())?;
            }
        }
        if terminal.status == read::Outcome::Ok
            && (self.phase == Phase::Prepare || terminal.result["state"] == "succeeded")
        {
            need(
                terminal
                    .fetch_control
                    .as_ref()
                    .is_some_and(|c| c.reason == crate::github_connection_protocol::Reason::None),
            )?;
        }
        Ok(terminal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_quote_preserves_both_independent_old_caps_and_code_minimum() {
        const M: usize = 1024 * 1024;
        let c = crate::macos_history_inventory::CODE_CONTROL_RESERVE;
        assert_eq!(
            admission_bytes(16 * M, c + 16 * M + REMOTE_BACKING),
            Some(c + 56 * M)
        );
        assert_eq!(admission_bytes(16 * M + 1, c + REMOTE_BACKING), None);
        assert_eq!(admission_bytes(0, c + 16 * M + REMOTE_BACKING + 1), None);
        assert_eq!(admission_bytes(0, c + REMOTE_BACKING - 1), None);
        assert_eq!(admission_bytes(0, REMOTE_BACKING - 1), None);
        assert_eq!(admission_bytes(usize::MAX, usize::MAX), None);
        assert_eq!(
            admission_bytes(7 * M, c + 9 * M + REMOTE_BACKING),
            super::super::admission_bytes(7 * M, c + 9 * M)
                .and_then(|n| n.checked_add(REMOTE_BACKING))
        );
    }
}
