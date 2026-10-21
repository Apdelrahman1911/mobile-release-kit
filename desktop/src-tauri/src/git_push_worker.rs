//! Push-only private wire on the original GitLocal input/output jobs. Tokens
//! are borrowed into the original bounded writer, never a Value or public
//! projection. Returned transport DATA is not native finality or retry credit.
use super::*;
use crate::git_push_protocol as push;
use zeroize::Zeroizing;

pub(crate) const PROTOCOL: &str = "mrk-git-push/1";
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const ACK_LIMIT: usize = 4096;
pub(crate) const OUTPUT_LIMIT: usize = 32 * 1024;
pub(crate) const CHANNEL_BACKING: usize = 8 * 1024 * 1024;
pub(crate) const HELPER_BACKING: usize = 16 * 1024 * 1024;
pub(crate) const BODY_BACKING: usize = 16 * 1024 * 1024;
pub(crate) const REMOTE_BACKING: usize = CHANNEL_BACKING + HELPER_BACKING + BODY_BACKING;
// Original body call slots include seven checks of four stat results, not
// twenty-four guessed stat rows. One body stream, no Fetch pack/index spool.
pub(crate) const BODY_CALLS: usize = 24_000;
pub(crate) const BODY_CALL_BYTES: usize = 512;
pub(crate) const BODY_REMAINDER: usize = 2 * 1024 * 1024;
pub(crate) const BODY_LEASES: usize = 2;

pub(crate) fn admission_bytes(document: usize, future: usize) -> Option<usize> {
    if BODY_CALLS
        .checked_mul(BODY_CALL_BYTES)?
        .checked_add(BODY_REMAINDER)?
        > BODY_BACKING
    {
        return None;
    }
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
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        crate::github_connection_protocol::coordinate(&self.repository)
            && crate::git_fetch_protocol::login(&self.login)
            && crate::github_connection_protocol::numeric_id(&self.account_id)
            && crate::github_connection_protocol::numeric_id(&self.repository_id)
    }
    pub(crate) fn matches_review(&self, r: &push::Review) -> bool {
        self.valid()
            && r.valid()
            && self.repository == r.repository
            && self.login == r.login
            && self.account_id == r.account_id
            && self.repository_id == r.repository_id
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Body {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) pack_bytes: u64,
    pub(crate) pack_sha1: String,
    pub(crate) objects: u32,
}
impl Body {
    pub(crate) fn valid(&self) -> bool {
        (33..=push::BODY_LIMIT).contains(&self.bytes)
            && self.pack_bytes >= 32
            && self.pack_bytes < self.bytes
            && self.bytes - self.pack_bytes <= push::COMMAND_LIMIT
            && read::digest(&self.sha256)
            && crate::git_fetch_protocol::oid(&self.pack_sha1)
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Response {
    pub(crate) outcome: String,
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
    pub(crate) progress_bytes: u64,
}
impl Response {
    fn valid(&self) -> bool {
        self.outcome == "ok"
            && read::digest(&self.sha256)
            && (1..=push::METADATA_LIMIT).contains(&self.bytes)
            && self.progress_bytes <= 64 * 1024
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Returned {
    pub(crate) body: Body,
    pub(crate) advertisement: String,
    pub(crate) response: Response,
    pub(crate) after: String,
}
impl Returned {
    pub(crate) fn valid(&self, intent: &push::Intent) -> bool {
        intent.valid()
            && self.body.valid()
            && self.response.valid()
            && read::digest(&self.advertisement)
            && read::digest(&self.after)
    }
}

impl Request {
    pub(crate) fn from_push_original(
        id: &str,
        action: &Action,
        context: &Context,
        native: &Native,
        clock: Clock,
        binding: Option<ApplyBinding>,
        target: Target,
    ) -> Result<Self, BridgeError> {
        let Action::Push(selected) = action else {
            return Err(BridgeError::protocol());
        };
        need(
            valid_id(id)
                && action.valid()
                && valid_id(&context.project_id)
                && valid_id(&context.revision)
                && native.valid()
                && target.valid()
                && clock.work_end_ns > 0
                && clock.hard_end_ns <= i64::MAX as u64
                && clock.hard_end_ns.checked_sub(clock.work_end_ns) == Some(10_000_000_000),
        )?;
        // Attached born HEAD is mandatory in both closed Push kinds; no
        // detached or unborn fallback. Selected OIDs remain DATA, checked by Git too.
        need(
            native.files.head.sha256 == hash(format!("ref: {}\n", selected.local_ref).as_bytes()),
        )?;
        let phase = match &binding {
            None => Phase::Prepare,
            Some(b) => {
                let Review::Push(r) = &b.review else {
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
                        && target.matches_review(r)
                        && r.expected_index == index
                        && (1..=u64::MAX - 2).contains(&b.journal_revision),
                )?;
                Phase::Apply
            }
        };
        let value = json!({"protocol":PROTOCOL,"id":id,"phase":phase,"action":action,
            "reviewDigest":binding.as_ref().map(|b| b.review.review_digest()),
            "journalRevision":binding.as_ref().map(|b| b.journal_revision),"context":context,
            "native":native,"clock":clock,"target":target});
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
            fetch_target: None,
            push_target: Some(target),
            bytes,
        })
    }

    /// Exact selected Connection's original token borrow, under its real GO
    /// claim. No token clone, JSON Value, debug representation or renderer path.
    pub(crate) fn push_go(&self, token: &str) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        need(
            self.action.kind().is_push()
                && self.push_target.as_ref().is_some_and(Target::valid)
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
        struct Bounded<'a>(&'a mut Vec<u8>);
        impl std::io::Write for Bounded<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > GO_LIMIT.saturating_sub(1 + self.0.len()) {
                    return Err(std::io::ErrorKind::InvalidData.into());
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
            Bounded(&mut bytes),
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

    pub(crate) fn push_ack(
        &self,
        candidate: &Candidate,
        revision: u64,
    ) -> Result<Vec<u8>, BridgeError> {
        let binding = self.binding.as_ref().ok_or_else(BridgeError::protocol)?;
        need(
            self.action.kind().is_push()
                && matches!(candidate.intent, Intent::Push(_))
                && candidate.request_digest == self.digest
                && candidate.intent.matches(&binding.review)
                && binding.journal_revision.checked_add(1) == Some(revision),
        )?;
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"kind":"ack","id":self.id,
            "digest":self.digest,"candidateDigest":candidate.digest,"journalRevision":revision}))
        .map_err(|_| BridgeError::protocol())?;
        bytes.push(b'\n');
        need(bytes.len() <= ACK_LIMIT)?;
        Ok(bytes)
    }

    pub(super) fn push_terminal(
        &self,
        bytes: &[u8],
        candidate: Option<&Candidate>,
    ) -> Result<Terminal, BridgeError> {
        let Action::Push(action) = &self.action else {
            return Err(BridgeError::protocol());
        };
        let target = self
            .push_target
            .as_ref()
            .filter(|v| v.valid())
            .ok_or_else(BridgeError::protocol)?;
        need(
            self.initialization.is_none()
                && self.fetch_target.is_none()
                && self.native.as_ref().is_some_and(Native::valid),
        )?;
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
                    "transmission",
                    "firstFailureNs",
                    "cleanupEndNs",
                    "control",
                ],
            ) && row["protocol"] == PROTOCOL
                && row["kind"] == "terminal"
                && row["id"] == self.id
                && row["digest"] == self.digest,
        )?;
        let object = row.as_object_mut().ok_or_else(BridgeError::protocol)?;
        let control: crate::github_connection_protocol::GitHubReadControl =
            serde_json::from_value(object.remove("control").ok_or_else(BridgeError::protocol)?)
                .map_err(|_| BridgeError::protocol())?;
        need(control.valid())?;
        let value = object
            .remove("transmission")
            .ok_or_else(BridgeError::protocol)?;
        let returned = if value.is_null() {
            None
        } else {
            Some(serde_json::from_value::<Returned>(value).map_err(|_| BridgeError::protocol())?)
        };
        // Only this private decoder maps transport DATA into an internal tag.
        // An ordinary GitLocal/Fetch child cannot serialize the Push tag.
        object.insert(
            "publication".into(),
            json!(if returned.is_some() {
                Publication::PushReturned
            } else {
                Publication::NotReported
            }),
        );
        let mut terminal: Terminal =
            serde_json::from_value(row).map_err(|_| BridgeError::protocol())?;
        terminal.push_transmission = returned;
        terminal.push_control = Some(control);
        need(
            terminal.phase == self.phase
                && terminal.action == self.action.kind()
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
        let reason = |v: &str| read::reason(v) || push::reason(v);
        if terminal.status != read::Outcome::Ok {
            need(
                terminal.reason.as_deref().is_some_and(reason)
                    && terminal.result.is_null()
                    && terminal.push_transmission.is_none()
                    && (terminal.first_failure_ns.is_some()
                        || terminal.status == read::Outcome::CleanupUnknown),
            )?;
        } else if self.phase == Phase::Prepare {
            need(
                terminal.reason.is_none()
                    && candidate.is_none()
                    && terminal.first_failure_ns.is_none()
                    && terminal.cleanup_end_ns == self.clock.hard_end_ns
                    && terminal.push_transmission.is_none()
                    && keys(&terminal.result, &["review", "diff"])
                    && terminal.result["diff"].is_null(),
            )?;
            let Review::Push(review) = Review::decode(&terminal.result["review"])? else {
                return Err(BridgeError::protocol());
            };
            need(review.matches(action) && target.matches_review(&review))?;
        } else {
            need(terminal.reason.is_none() && keys(&terminal.result, push::RESULT_KEYS))?;
            let result: push::Mutation = serde_json::from_value(terminal.result.clone())
                .map_err(|_| BridgeError::protocol())?;
            need(
                result.valid(action, &self.id)
                    && !matches!(
                        result.reason.as_deref(),
                        Some("unknown" | "cleanup-unknown")
                    ),
            )?;
            match (&result.intent, candidate) {
                (None, None) => need(terminal.push_transmission.is_none())?,
                (Some(i), Some(c)) => need(c.intent == Intent::Push(i.clone()))?,
                _ => return Err(BridgeError::protocol()),
            }
            if let Some(returned) = &terminal.push_transmission {
                let i = result.intent.as_ref().ok_or_else(BridgeError::protocol)?;
                need(returned.valid(i) && result.effect_phase == push::Effect::RemoteReturned)?;
            }
            if result.state == "succeeded" {
                need(
                    terminal.first_failure_ns.is_none()
                        && terminal.cleanup_end_ns == self.clock.hard_end_ns
                        && terminal.push_transmission.is_some(),
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
                    .push_control
                    .as_ref()
                    .is_some_and(|c| c.reason == crate::github_connection_protocol::Reason::None),
            )?;
        }
        if terminal.status == read::Outcome::Ok && self.phase == Phase::Prepare {
            // The private worker grammar deliberately carries diff:null. Only
            // file/index reviews have a public diff; do not make ReadyReview
            // expose a fabricated diff or a different public prepared shape.
            terminal
                .result
                .as_object_mut()
                .ok_or_else(BridgeError::protocol)?
                .remove("diff");
        }
        Ok(terminal)
    }
}

#[cfg(test)]
#[path = "git_push_worker_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path="git_push_new_branch_worker_tests.rs"]
mod new_branch_tests;
