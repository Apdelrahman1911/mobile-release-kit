//! Typed future-tag comparison inside the existing hosted-dispatch protocol.
//! This is not tag write authority, a source owner, or a new journal namespace.
use super::{canonical, hex, strings, uuid, CleanupCandidate, OriginalSource, Prepared, Version};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) candidate_id: String,
    pub(crate) row_sha256: String,
    pub(crate) final_commit: String,
}
impl Selection {
    pub(crate) fn valid(&self) -> bool {
        uuid(&self.candidate_id) && hex(&self.row_sha256, 64) && hex(&self.final_commit, 40)
    }
    pub(super) fn heap(&self) -> Option<usize> {
        strings(&[&self.candidate_id, &self.row_sha256, &self.final_commit])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TagCandidate {
    pub(crate) candidate_id: String,
    pub(crate) row_sha256: String,
    pub(crate) platform: super::Platform,
    pub(crate) source: OriginalSource,
    pub(crate) identity_revision: String,
    pub(crate) base_version: Version,
    pub(crate) version: Version,
    pub(crate) future_tag: String,
}
impl TagCandidate {
    fn valid(&self) -> bool {
        uuid(&self.candidate_id)
            && hex(&self.row_sha256, 64)
            && self.source.valid()
            && self.identity_revision == self.source.configuration_sha256
            && crate::version_allocation_state_native::future_tag::reference(&self.future_tag)
            && automatic_version(&self.base_version, self.platform)
            && automatic_version(&self.version, self.platform)
    }
    fn heap(&self) -> Option<usize> {
        self.source.heap()?.checked_add(strings(&[
            &self.candidate_id,
            &self.row_sha256,
            &self.identity_revision,
            &self.base_version.name,
            &self.version.name,
            &self.future_tag,
        ])?)
    }
}

fn automatic_version(value: &Version, platform: super::Platform) -> bool {
    !value.name.is_empty()
        && value.name.len() <= 64
        && (2..=3).contains(&value.name.split('.').count())
        && value.name.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
        && (1..=2_100_000_000).contains(&value.build)
        && (platform == super::Platform::Android || value.build <= 9999)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Candidate {
    PlayCleanup(CleanupCandidate),
    VersionTag(TagCandidate),
}
impl Candidate {
    pub(crate) fn candidate_id(&self) -> &str {
        match self {
            Self::PlayCleanup(c) => &c.candidate_id,
            Self::VersionTag(c) => &c.candidate_id,
        }
    }
    pub(crate) fn source(&self) -> &OriginalSource {
        match self {
            Self::PlayCleanup(c) => &c.source,
            Self::VersionTag(c) => &c.source,
        }
    }
    pub(crate) fn base_version(&self) -> &Version {
        match self {
            Self::PlayCleanup(c) => &c.base_version,
            Self::VersionTag(c) => &c.base_version,
        }
    }
    pub(crate) fn tag(&self) -> Option<&TagCandidate> {
        match self {
            Self::VersionTag(c) => Some(c),
            _ => None,
        }
    }
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::PlayCleanup(c) => c.valid() && c.platform != super::Platform::Ios,
            Self::VersionTag(c) => c.valid(),
        }
    }
    pub(super) fn heap(&self) -> Option<usize> {
        match self {
            Self::PlayCleanup(c) => c.heap(),
            Self::VersionTag(c) => c.heap(),
        }
    }
}

pub(super) fn prepared_shape(p: &Prepared) -> bool {
    match (&p.target.version_tag, &p.candidate) {
        (None, Candidate::PlayCleanup(_)) => {
            p.journal_blob.as_ref().is_some_and(|s| hex(s, 40))
                && p.journal_sha256.as_ref().is_some_and(|s| hex(s, 64))
                && p.journal_revision.is_some_and(|n| n > 0)
        }
        (Some(s), Candidate::VersionTag(c)) => {
            s.valid()
                && c.valid()
                && s.candidate_id == c.candidate_id
                && s.row_sha256 == c.row_sha256
                && s.final_commit == p.source_sha
                && p.source_sha != c.source.commit
                && p.saved_config_sha256 == c.identity_revision
                && p.journal_blob.is_none()
                && p.journal_sha256.is_none()
                && p.journal_revision.is_none()
        }
        _ => false,
    }
}

pub(super) fn confirmation(p: &Prepared, c: &TagCandidate) -> String {
    format!("Dispatch a future-tag binding for {} to {} in {}? Reserved version {} (build {}) came from branch source {}. The tag name does not determine that number. The protected workflow must prove the exact version-only commit and claim this candidate once. It creates only an absent lightweight tag; it never moves an existing tag. Creating it may trigger your other automation. This job does not build, sign, access Stores or upload. Candidate builds remain branch-triggered. The configured branch {} is mutable; a changed dispatch head must refuse. An acknowledgement is not a tag receipt or a run ID. Stopping cannot undo a sent request.",
        c.future_tag, p.source_sha, p.target.scope.repository, c.version.name, c.version.build, c.source.commit, p.branch)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Binding {
    Unclaimed,
    ClaimedTagAbsent,
    ClaimedTagMatches,
    Mismatch,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TagObservation {
    pub(crate) counter_commit: String,
    pub(crate) ledger_sha256: String,
    pub(crate) binding: Binding,
    assurance: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum Observation {
    PlayCleanup(super::CleanupObservation),
    VersionTag(TagObservation),
}
impl Observation {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::PlayCleanup(o) => o.valid(),
            Self::VersionTag(o) => {
                hex(&o.counter_commit, 40)
                    && hex(&o.ledger_sha256, 64)
                    && o.assurance == "later-binding-read-not-creation-proof"
            }
        }
    }
    pub(crate) fn purpose(&self) -> crate::service_play_cleanup_protocol::Purpose {
        match self {
            Self::PlayCleanup(_) => crate::service_play_cleanup_protocol::Purpose::PlayCleanup,
            Self::VersionTag(_) => crate::service_play_cleanup_protocol::Purpose::VersionTag,
        }
    }
    pub(super) fn heap(&self) -> Option<usize> {
        match self {
            Self::PlayCleanup(o) => o.heap(),
            Self::VersionTag(o) => strings(&[&o.counter_commit, &o.ledger_sha256, &o.assurance]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_has_no_tag_command_path_token_or_platform_authority() {
        let v = serde_json::json!({"candidateId":"00000000-0000-4000-8000-000000000001","rowSha256":"a".repeat(64),"finalCommit":"b".repeat(40)});
        let s: Selection = serde_json::from_value(v.clone()).unwrap();
        assert!(s.valid());
        for key in ["tag", "token", "command", "ref", "force"] {
            let mut bad = v.clone();
            bad[key] = serde_json::json!("untrusted");
            assert!(serde_json::from_value::<Selection>(bad).is_err());
        }
        assert!(canonical(&s).unwrap().len() < 256);
    }
    fn tag_prepared() -> Prepared {
        let mut p = super::super::tests::prepared();
        let c = match &p.candidate {
            Candidate::PlayCleanup(c) => c.clone(),
            _ => panic!("old fixture"),
        };
        let mut source = c.source;
        source.configuration_sha256 = p.saved_config_sha256.clone();
        p.candidate = Candidate::VersionTag(TagCandidate {
            candidate_id: c.candidate_id.clone(),
            row_sha256: "a".repeat(64),
            platform: super::super::Platform::Ios,
            source,
            identity_revision: p.saved_config_sha256.clone(),
            base_version: c.base_version,
            version: Version {
                name: "1.0.0".into(),
                build: 2,
            },
            future_tag: "refs/tags/release-1".into(),
        });
        p.target.version_tag = Some(Selection {
            candidate_id: c.candidate_id,
            row_sha256: "a".repeat(64),
            final_commit: p.source_sha.clone(),
        });
        p.journal_blob = None;
        p.journal_sha256 = None;
        p.journal_revision = None;
        p.confirmation = p.confirmation();
        assert!(p.valid());
        p
    }
    #[test]
    fn prepared_tag_is_exact_branch_bound_body_and_once_key_excludes_final_commit() {
        let p = tag_prepared();
        let raw = canonical(&p).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(v.get("journalBlob").is_none());
        assert!(raw.len() <= super::super::PREPARED_LIMIT);
        assert!(serde_json::from_slice::<Prepared>(&raw).unwrap().valid());
        let mut changed = p.clone();
        changed.source_sha = "f".repeat(40);
        changed.target.version_tag.as_mut().unwrap().final_commit = changed.source_sha.clone();
        changed.confirmation = changed.confirmation();
        assert!(changed.valid());
        assert_eq!(changed.once_key(), p.once_key());
        assert_ne!(changed.digest().unwrap(), p.digest().unwrap());
        let old = super::super::tests::prepared();
        assert_ne!(p.once_key(), old.once_key());
        assert!(!p.target.same_scope(&old.target));
        for key in ["journalBlob", "journalSha256", "journalRevision"] {
            let mut bad = v.clone();
            bad[key] = serde_json::Value::Null;
            assert!(serde_json::from_value::<Prepared>(bad).is_err());
        }
        let mut wrong = p.clone();
        wrong.journal_revision = Some(1);
        assert!(!wrong.valid());
        let Candidate::VersionTag(c) = &mut wrong.candidate else {
            panic!("tag")
        };
        c.source.source_ref = c.future_tag.clone();
        wrong.journal_revision = None;
        assert!(!wrong.valid());
    }
    #[test]
    fn pending_discovery_is_typed_but_has_no_prepare_or_dispatch_selection() {
        use super::super::{decode_command, Command};
        let mut v = serde_json::json!({"sessionId":"session-1","expectedRevision":2,"expectedConnectionRevision":3,"purpose":"version-tag"});
        assert!(matches!(
            decode_command("github_play_cleanup_pending", &v),
            Ok(Command::Pending(_))
        ));
        assert!(decode_command("github_play_cleanup_prepare", &v).is_err());
        v["versionTag"] = serde_json::to_value(tag_prepared().target.version_tag.unwrap()).unwrap();
        assert!(decode_command("github_play_cleanup_pending", &v).is_err());
        v.as_object_mut().unwrap().remove("purpose");
        assert!(decode_command("github_play_cleanup_prepare", &v).is_ok());
        for value in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"command":"tag"}),
        ] {
            v["versionTag"] = value;
            assert!(decode_command("github_play_cleanup_prepare", &v).is_err());
        }
    }
    #[test]
    fn automatic_tag_versions_keep_two_or_three_components_and_platform_ceilings() {
        let p = tag_prepared();
        let Candidate::VersionTag(mut c) = p.candidate else {
            panic!("tag")
        };
        for name in ["1.2", "1.2.3", "0.0"] {
            c.version.name = name.into();
            assert!(c.valid());
        }
        for name in ["1", "01.2", "1.2-beta", "1.2.3.4", "1.2\n"] {
            c.version.name = name.into();
            assert!(!c.valid());
        }
        c.version.name = "1.2".into();
        c.version.build = 10000;
        assert!(!c.valid());
        c.platform = super::super::Platform::Android;
        assert!(c.valid());
    }
}
