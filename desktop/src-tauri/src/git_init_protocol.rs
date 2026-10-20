//! Closed initialization DATA for the existing GitLocal owner. No GitRead
//! observation, existing index, native permission or publication is invented.
use crate::{error::BridgeError, git_local_protocol as local, git_read_protocol as read};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const REVIEW_KEYS: &[&str] = &[
    "action",
    "expectedRevision",
    "initialBranch",
    "objectFormat",
    "reviewDigest",
];
pub(crate) const INTENT_KEYS: &[&str] = &[
    "action",
    "expectedRevision",
    "initialBranch",
    "objectFormat",
    "candidateManifest",
    "candidateHead",
    "candidateConfig",
];
pub(crate) const PREFIX: &str = ".mrk-git-init-";
pub(crate) const DIRECTORY_NAMES: &[&str] = &[
    "",
    "objects",
    "objects/info",
    "objects/pack",
    "refs",
    "refs/heads",
    "refs/tags",
];
pub(crate) const CONFIG_LIMIT: u64 = 8192;
// Initialization-only addition to the original working reservation: a bounded
// 4096-name scan (256KiB names + Vec headers), 64KiB native block, manifest,
// path/snapshot copies and allocator slack. Not charged as RSS or refunded
// merely because the child says it returned.
pub(crate) const MANIFEST_BACKING: usize = 1024 * 1024;
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn fixed(branch: &str, format: &str) -> bool {
    branch == "main" && format == "sha1"
}
fn need(ok: bool) -> Result<(), BridgeError> {
    if ok {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Kind {
    #[serde(rename = "initialize")]
    Initialize,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        self.kind == Kind::Initialize
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action: Kind,
    pub(crate) expected_revision: String,
    pub(crate) initial_branch: String,
    pub(crate) object_format: String,
    pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        self.action == Kind::Initialize
            && fixed(&self.initial_branch, &self.object_format)
            && read::digest(&self.expected_revision)
            && read::digest(&self.review_digest)
    }
    pub(crate) fn matches(&self, action: &Action) -> bool {
        self.valid() && action.valid()
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action: Kind,
    pub(crate) expected_revision: String,
    pub(crate) initial_branch: String,
    pub(crate) object_format: String,
    pub(crate) candidate_manifest: String,
    pub(crate) candidate_head: String,
    pub(crate) candidate_config: String,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        self.action == Kind::Initialize
            && fixed(&self.initial_branch, &self.object_format)
            && read::digest(&self.expected_revision)
            && read::digest(&self.candidate_manifest)
            && self.candidate_head == hash(b"ref: refs/heads/main\n")
            && read::digest(&self.candidate_config)
    }
    pub(crate) fn matches(&self, review: &Review) -> bool {
        self.valid()
            && review.valid()
            && self.expected_revision == review.expected_revision
            && self.initial_branch == review.initial_branch
            && self.object_format == review.object_format
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    initial_branch: String,
    object_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) candidate: Option<Intent>,
}
impl Journal {
    pub(crate) fn preparing(review: &Review) -> Self {
        Self {
            initial_branch: review.initial_branch.clone(),
            object_format: review.object_format.clone(),
            candidate: None,
        }
    }
    pub(crate) fn valid(&self, revision: &str) -> bool {
        fixed(&self.initial_branch, &self.object_format)
            && self.candidate.as_ref().is_none_or(|v| {
                v.valid()
                    && v.expected_revision == revision
                    && v.initial_branch == self.initial_branch
                    && v.object_format == self.object_format
            })
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        self.initial_branch == other.initial_branch && self.object_format == other.object_format
    }
    pub(crate) fn accepts(&self, intent: &Intent) -> bool {
        self.candidate.is_none()
            && intent.valid()
            && intent.initial_branch == self.initial_branch
            && intent.object_format == self.object_format
    }
}

/// Same held SourceBook directories, produced only after the actual Preparing
/// ACK. No public command accepts this name, directory identity or tool path.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CandidateSources {
    pub(crate) name: String,
    pub(crate) outer: read::DirectoryIdentity,
    pub(crate) worktree: read::DirectoryIdentity,
    pub(crate) git: read::DirectoryIdentity,
    pub(crate) template: read::DirectoryIdentity,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Native {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) root: String,
    pub(crate) directory: read::DirectoryIdentity,
    pub(crate) tool: read::Snapshot,
    pub(crate) candidate: Option<CandidateSources>,
}
fn dir(v: read::DirectoryIdentity, uid: u32) -> bool {
    v.0 != 0 && v.1 != 0 && v.2 & 0o170000 == 0o40000 && v.2 & 0o7022 == 0 && v.3 == uid
}
pub(crate) fn candidate_name(value: &str) -> bool {
    value.strip_prefix(PREFIX).is_some_and(|v| {
        v.len() == 32
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl Native {
    pub(crate) fn valid(&self, phase: local::Phase) -> bool {
        let t = &self.tool;
        self.uid != 0
            && self.root.starts_with('/')
            && !self.root.contains('\\')
            && self.root[1..].split('/').count() <= 62
            && read::text(&self.root, 4096, false)
            && self.root[1..]
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && dir(self.directory, self.uid)
            && self.directory.4 == self.gid
            && t.identity.0 != 0
            && t.identity.1 != 0
            && t.identity.2 & 0o170000 == 0o100000
            && t.identity.2 & 0o7022 == 0
            && t.identity.2 & 0o111 != 0
            && t.identity.3 == 0
            && t.identity.5 == 1
            && t.identity.6 > 0
            && t.identity.6 <= read::TOOL_LIMIT
            && read::digest(&t.sha256)
            && match (phase, &self.candidate) {
                (local::Phase::Prepare, None) => true,
                (local::Phase::Apply, Some(c)) => {
                    candidate_name(&c.name)
                        && [c.outer, c.worktree, c.git, c.template].iter().all(|d| {
                            dir(*d, self.uid)
                                && d.0 == self.directory.0
                                && d.1 != self.directory.1
                                && d.2 & 0o7777 == 0o700
                        })
                        && [c.outer.1, c.worktree.1, c.git.1, c.template.1]
                            .iter()
                            .enumerate()
                            .all(|(i, v)| {
                                [c.outer.1, c.worktree.1, c.git.1, c.template.1][..i]
                                    .iter()
                                    .all(|o| o != v)
                            })
                }
                _ => false,
            }
    }
}

/// Same finite Python candidate comparison; never a publication/close receipt.
pub(crate) fn manifest_digest(
    directories: &[(String, read::DirectoryIdentity)],
    files: &[(String, read::Snapshot)],
) -> Result<String, BridgeError> {
    need(
        directories.len() == DIRECTORY_NAMES.len()
            && directories
                .iter()
                .zip(DIRECTORY_NAMES)
                .all(|((name, _), expected)| name == expected)
            && files.len() == 2
            && files[0].0 == "HEAD"
            && files[1].0 == "config",
    )?;
    let values: Vec<_> = files
        .iter()
        .map(|(name, snapshot)| {
            let v = snapshot.identity;
            serde_json::json!([name, [v.0, v.1, v.2, v.6, v.7, v.8], snapshot.sha256])
        })
        .collect();
    let value = serde_json::json!({"domain":"mrk-git-init-candidate/1", "directories":directories, "files":values});
    Ok(hash(
        &serde_json::to_vec(&value).map_err(|_| BridgeError::protocol())?,
    ))
}

pub(crate) fn reason(value: &str) -> bool {
    matches!(
        value,
        "git-already-present" | "git-init-layout" | "git-init-candidate"
    )
}
pub(crate) fn validate_applied(
    request: &local::Request,
    terminal: &local::Terminal,
    candidate: Option<&local::Candidate>,
) -> Result<(), BridgeError> {
    let result = &terminal.result;
    need(result["observation"].is_null())?;
    if result["state"] == "succeeded" {
        need(
            candidate.is_some()
                && terminal.publication == local::Publication::InitReturned
                && result["reason"].is_null()
                && terminal.first_failure_ns.is_none()
                && terminal.cleanup_end_ns == request.clock.hard_end_ns,
        )
    } else {
        need(
            result["reason"]
                .as_str()
                .is_some_and(|v| reason(v) || read::reason(v))
                && terminal.first_failure_ns.is_some()
                && (terminal.publication == local::Publication::NotReported
                    || candidate.is_some()
                        && terminal.publication == local::Publication::InitReturned),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn native(apply: bool) -> Native {
        let directory = (1, 2, 0o40700, 501, 20);
        let mut value = Native {
            uid: 501,
            gid: 20,
            root: "/private/project".into(),
            directory,
            tool: read::Snapshot {
                identity: (1, 3, 0o100755, 0, 0, 1, 3, 1, 1),
                sha256: "f".repeat(64),
            },
            candidate: None,
        };
        if apply {
            value.candidate = Some(CandidateSources {
                name: format!("{PREFIX}{}", "a".repeat(32)),
                outer: (1, 10, 0o40700, 501, 20),
                worktree: (1, 11, 0o40700, 501, 20),
                git: (1, 12, 0o40700, 501, 20),
                template: (1, 13, 0o40700, 501, 20),
            });
        }
        value
    }
    fn review() -> Review {
        Review {
            action: Kind::Initialize,
            expected_revision: "a".repeat(64),
            initial_branch: "main".into(),
            object_format: "sha1".into(),
            review_digest: "b".repeat(64),
        }
    }
    fn intent() -> Intent {
        Intent {
            action: Kind::Initialize,
            expected_revision: "a".repeat(64),
            initial_branch: "main".into(),
            object_format: "sha1".into(),
            candidate_manifest: "c".repeat(64),
            candidate_head: hash(b"ref: refs/heads/main\n"),
            candidate_config: "d".repeat(64),
        }
    }
    fn frame(value: serde_json::Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn request(apply: bool) -> local::Request {
        local::Request::from_init_original(
            "init-original",
            &local::Action::Initialize(Action {
                kind: Kind::Initialize,
            }),
            &read::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "document-1".into(),
            },
            &native(apply),
            read::Clock {
                work_end_ns: 45_000_000_000,
                hard_end_ns: 55_000_000_000,
            },
            apply.then(|| local::ApplyBinding {
                review: local::Review::Initialize(review()),
                journal_revision: 1,
            }),
        )
        .unwrap()
    }
    fn terminal(
        r: &local::Request,
        result: serde_json::Value,
        publication: &str,
    ) -> serde_json::Value {
        json!({"protocol":local::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,"phase":r.phase,
            "action":"initialize","status":"ok","reason":null,"result":result,"publication":publication,
            "firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns})
    }
    #[test]
    fn initialize_action_has_no_invented_source_revision_or_arbitrary_branch() {
        assert!(serde_json::from_str::<Action>(r#"{"kind":"initialize"}"#)
            .unwrap()
            .valid());
        for value in [
            r#"{"kind":"initialize","expectedRevision":"none"}"#,
            r#"{"kind":"initialize","branch":"other"}"#,
            r#"{"kind":"commit"}"#,
        ] {
            assert!(serde_json::from_str::<Action>(value).is_err());
        }
        let command = json!({"projectId":"project-1","expectedDocumentRevision":1,"action":{"kind":"initialize"}});
        assert!(matches!(
            local::decode_command("git_local_prepare", &serde_json::to_vec(&command).unwrap()),
            Ok(local::Command::Prepare(_))
        ));
        for key in [
            "expectedRevision",
            "paths",
            "message",
            "identity",
            "initialBranch",
            "native",
            "force",
        ] {
            let mut value = command.clone();
            value["action"][key] = json!(null);
            assert!(local::decode_command(
                "git_local_prepare",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err());
        }
    }
    #[test]
    fn init_review_and_journal_are_exact_and_candidate_cannot_rearm() {
        let review = Review {
            action: Kind::Initialize,
            expected_revision: "a".repeat(64),
            initial_branch: "main".into(),
            object_format: "sha1".into(),
            review_digest: "b".repeat(64),
        };
        let intent = Intent {
            action: Kind::Initialize,
            expected_revision: review.expected_revision.clone(),
            initial_branch: "main".into(),
            object_format: "sha1".into(),
            candidate_manifest: "c".repeat(64),
            candidate_head: hash(b"ref: refs/heads/main\n"),
            candidate_config: "d".repeat(64),
        };
        assert!(intent.matches(&review));
        let mut row = Journal::preparing(&review);
        assert!(row.accepts(&intent));
        row.candidate = Some(intent.clone());
        assert!(row.valid(&review.expected_revision));
        assert!(!row.accepts(&intent));
        assert!(!row.valid(&"e".repeat(64)));
        let mut wrong = intent;
        wrong.initial_branch = "other".into();
        assert!(!wrong.valid());
    }
    #[test]
    fn init_private_data_requires_the_fixed_phase_tool_and_distinct_same_filesystem_directories() {
        assert!(native(false).valid(local::Phase::Prepare));
        assert!(native(true).valid(local::Phase::Apply));
        assert!(!native(false).valid(local::Phase::Apply));
        assert!(!native(true).valid(local::Phase::Prepare));
        let mut value = native(true);
        value.candidate.as_mut().unwrap().git = value.directory;
        assert!(!value.valid(local::Phase::Apply));
        let mut value = native(true);
        let same = value.candidate.as_ref().unwrap().worktree;
        value.candidate.as_mut().unwrap().git = same;
        assert!(!value.valid(local::Phase::Apply));
        let mut value = native(true);
        value.candidate.as_mut().unwrap().git.0 = 2;
        assert!(!value.valid(local::Phase::Apply));
        let mut value = native(true);
        value.tool.identity.3 = 501;
        assert!(!value.valid(local::Phase::Apply));
        let mut value = native(true);
        value.candidate.as_mut().unwrap().outer.2 = 0o40755;
        assert!(!value.valid(local::Phase::Apply));
    }
    #[test]
    fn init_original_codec_requires_exact_ack_and_returned_publication_without_fake_index_or_observation(
    ) {
        // Inert private DATA; never SourceBook, a real ACK or a joined witness.
        let r = request(false);
        assert!(r.native.is_none() && r.initialization.is_some());
        assert!(r
            .terminal(
                &frame(terminal(&r, json!({"review":review()}), "not-reported")),
                None
            )
            .is_ok());
        let mut bad = terminal(&r, json!({"review":review()}), "not-reported");
        bad["result"]["diff"] = json!({});
        assert!(r.terminal(&frame(bad), None).is_err());
        let r = request(true);
        let c = r
            .candidate(&frame(
                json!({"protocol":local::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
            "reviewDigest":review().review_digest,"intent":intent()}),
            ))
            .unwrap();
        assert!(r.ack(&c, 2).is_ok());
        assert!(r.ack(&c, 1).is_err());
        assert!(r.ack(&c, 3).is_err());
        let result = json!({"operationId":r.id,"action":"initialize","state":"succeeded","settlement":"settled",
            "reason":null,"observation":null,"intent":intent()});
        let good = terminal(&r, result, "init-returned");
        assert!(r.terminal(&frame(good.clone()), Some(&c)).is_ok());
        assert!(r.terminal(&frame(good.clone()), None).is_err());
        for publication in [
            "not-reported",
            "index-returned",
            "ref-returned",
            "rename-ref-returned",
        ] {
            let mut bad = good.clone();
            bad["publication"] = json!(publication);
            assert!(r.terminal(&frame(bad), Some(&c)).is_err());
        }
        for (key, value) in [
            ("observation", json!({})),
            ("intent", json!(null)),
            ("reason", json!("unknown")),
            ("expectedIndex", json!("a".repeat(64))),
        ] {
            let mut bad = good.clone();
            bad["result"][key] = value;
            assert!(r.terminal(&frame(bad), Some(&c)).is_err());
        }
        let mut bad = good;
        bad["firstFailureNs"] = json!(1);
        assert!(r.terminal(&frame(bad), Some(&c)).is_err());
    }
}
