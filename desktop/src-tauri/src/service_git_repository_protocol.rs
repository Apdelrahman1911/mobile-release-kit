//! Five closed, explicitly delegated LOCAL repository actions. These are
//! comparison DATA only: no native source, Git command, review or grant can be
//! reconstructed from a CLI request. The original GitLocal owner remains the
//! only executor; network actions and arbitrary file selections are absent.
use crate::{service_git_protocol as p, service_protocol::Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CONSENT: &str = "agent-local-git-repository-once-v1";
pub const RAW_LIMIT: usize = 8 * 1024;
pub const ACCESS_LIMIT: usize = 8 * 1024;

pub(crate) fn oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn reference(value: &str) -> bool {
    value.starts_with("refs/")
        && value.len() <= 1024
        && !value.contains("..")
        && !value.contains("@{")
        && !value
            .chars()
            .any(|c| c <= ' ' || c == '\u{7f}' || "~^:?*[\\".contains(c))
        && value.split('/').all(|v| {
            !v.is_empty() && !v.starts_with('.') && !v.ends_with('.') && !v.ends_with(".lock")
        })
}
pub(crate) fn branch(value: &str) -> bool {
    value.starts_with("refs/heads/") && reference(value)
}
pub(crate) fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && value.split('/').count() <= 16
        && branch(&format!("refs/heads/{value}"))
}
pub(crate) fn tracking_ref(value: &str) -> bool {
    value.strip_prefix("refs/remotes/").is_some_and(|tail| {
        !tail.is_empty()
            && tail.contains('/')
            && tail.rsplit('/').next() != Some("HEAD")
            && value.split('/').count() <= 32
            && branch(&format!("refs/heads/{tail}"))
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    // A struct variant makes Serde enforce deny_unknown_fields for this tag.
    // An internally tagged unit variant silently ignores extra object fields.
    Initialize {},
    BranchCreate {
        expected_revision: String,
        expected_reference_revision: String,
        name: String,
    },
    BranchSwitch {
        expected_revision: String,
        expected_reference_revision: String,
        name: String,
    },
    BranchRename {
        expected_revision: String,
        expected_reference_revision: String,
        name: String,
    },
    FastForward {
        expected_revision: String,
        expected_reference_revision: String,
        target_ref: String,
        target_oid: String,
    },
}
impl Action {
    pub fn validate(&self) -> Result<(), Error> {
        let valid = match self {
            Self::Initialize {} => true,
            Self::BranchCreate {
                expected_revision,
                expected_reference_revision,
                name: selected,
            }
            | Self::BranchSwitch {
                expected_revision,
                expected_reference_revision,
                name: selected,
            }
            | Self::BranchRename {
                expected_revision,
                expected_reference_revision,
                name: selected,
            } => {
                p::digest(expected_revision)
                    && p::digest(expected_reference_revision)
                    && name(selected)
            }
            Self::FastForward {
                expected_revision,
                expected_reference_revision,
                target_ref,
                target_oid,
            } => {
                p::digest(expected_revision)
                    && p::digest(expected_reference_revision)
                    && tracking_ref(target_ref)
                    && oid(target_oid)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
    // Retained source selection has exact bounded string capacity, including
    // a decode buffer that happened to reserve more than its visible length.
    fn compact(self) -> Self {
        fn exact(s: String) -> String {
            s.into_boxed_str().into_string()
        }
        match self {
            Self::Initialize {} => Self::Initialize {},
            Self::BranchCreate {
                expected_revision,
                expected_reference_revision,
                name,
            } => Self::BranchCreate {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                name: exact(name),
            },
            Self::BranchSwitch {
                expected_revision,
                expected_reference_revision,
                name,
            } => Self::BranchSwitch {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                name: exact(name),
            },
            Self::BranchRename {
                expected_revision,
                expected_reference_revision,
                name,
            } => Self::BranchRename {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                name: exact(name),
            },
            Self::FastForward {
                expected_revision,
                expected_reference_revision,
                target_ref,
                target_oid,
            } => Self::FastForward {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                target_ref: exact(target_ref),
                target_oid: exact(target_oid),
            },
        }
    }
    pub(crate) fn revisions(&self) -> Option<(&str, &str)> {
        match self {
            Self::Initialize {} => None,
            Self::BranchCreate {
                expected_revision,
                expected_reference_revision,
                ..
            }
            | Self::BranchSwitch {
                expected_revision,
                expected_reference_revision,
                ..
            }
            | Self::BranchRename {
                expected_revision,
                expected_reference_revision,
                ..
            }
            | Self::FastForward {
                expected_revision,
                expected_reference_revision,
                ..
            } => Some((expected_revision, expected_reference_revision)),
        }
    }
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Initialize {} => "initialize",
            Self::BranchCreate { .. } => "branch-create",
            Self::BranchSwitch { .. } => "branch-switch",
            Self::BranchRename { .. } => "branch-rename",
            Self::FastForward { .. } => "fast-forward",
        }
    }
    pub(crate) fn history_action(&self) -> crate::service_protocol::Action {
        use crate::service_protocol::Action as H;
        match self {
            Self::Initialize {} => H::GitInitialize,
            Self::BranchCreate { .. } => H::GitBranchCreate,
            Self::BranchSwitch { .. } => H::GitBranchSwitch,
            Self::BranchRename { .. } => H::GitBranchRename,
            Self::FastForward { .. } => H::GitFastForward,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub action: Action,
    pub selection_sha256: String,
}
impl Selection {
    pub(crate) fn new(action: Action) -> Result<Self, Error> {
        action.validate()?;
        let bytes = serde_json::to_vec(&action).map_err(|_| Error::InvalidRequest)?;
        if bytes.len() > 2048 {
            return Err(Error::InvalidRequest);
        }
        let mut hash = Sha256::new();
        hash.update(b"mrk-agent-git-repository-selection/1\0");
        hash.update(bytes);
        Ok(Self {
            action: action.compact(),
            selection_sha256: crate::service_protocol::hex(&hash.finalize()),
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        if Self::new(self.action.clone())?.selection_sha256 != self.selection_sha256 {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

// Required-null is used only by this new schema; the older Git schemas keep
// their exact existing decoder behavior. It never supplies a missing default.
fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

pub type Query = p::Query;
pub type Prepare = p::Prepare;
pub type Start = p::Start;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub enabled: bool,
    pub remaining_ms: u64,
    pub consumed: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub project_id: Option<crate::service_protocol::Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub grant_id: Option<crate::service_protocol::Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub selection: Option<Selection>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self::from_parts(p::Access::<Selection>::empty_shared())
    }
    pub(crate) fn from_parts(v: p::Access<Selection>) -> Self {
        Self {
            enabled: v.enabled,
            remaining_ms: v.remaining_ms,
            consumed: v.consumed,
            project_id: v.project_id,
            grant_id: v.grant_id,
            selection: v.selection,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        p::access_shape(
            self.enabled,
            self.remaining_ms,
            self.consumed,
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.selection.is_some(),
        )?;
        if let Some(selection) = &self.selection {
            selection.validate()?;
        }
        p::encoded_bound(self, ACCESS_LIMIT - 1024)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub service_instance: crate::service_protocol::Id,
    pub project_id: crate::service_protocol::Id,
    pub access: Access,
}
impl Scope {
    pub fn validate(&self) -> Result<(), Error> {
        self.access.validate()?;
        if self
            .access
            .project_id
            .as_ref()
            .is_some_and(|v| v != &self.project_id)
        {
            return Err(Error::InvalidRequest);
        }
        p::encoded_bound(self, ACCESS_LIMIT - 512)
    }
}

/// Bounded review facts copied ONLY after original native Prepare settlement.
/// No file contents, diff, candidate path, process output or receipt is copied.
/// The original full review stays with GitLocal; Start accepts only its IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub review_id: String,
    pub source_revision: String,
    #[serde(deserialize_with = "required_nullable")]
    pub reference_revision: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub expected_index: Option<String>,
    pub review_digest: String,
    pub document_revision: u32,
    pub registration_generation: u32,
    pub preview: Preview,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Preview {
    Initialize {
        initial_branch: String,
        object_format: String,
    },
    BranchCreate {
        head: String,
        #[serde(deserialize_with = "required_nullable")]
        branch: Option<String>,
        target_ref: String,
    },
    BranchSwitch {
        head: String,
        branch: String,
        target_ref: String,
        target_oid: String,
        changed_path_count: u32,
    },
    BranchRename {
        head: String,
        branch: String,
        target_ref: String,
        config_moved: bool,
        logging: bool,
    },
    FastForward {
        head: String,
        branch: String,
        target_ref: String,
        target_oid: String,
        changed_path_count: u32,
    },
}
impl Review {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let init = matches!(self.preview, Preview::Initialize { .. });
        if !p::native_id(&self.review_id)
            || !p::digest(&self.source_revision)
            || !p::digest(&self.review_digest)
            || !(1..u32::MAX).contains(&self.document_revision)
            || !(1..u32::MAX).contains(&self.registration_generation)
            || self.reference_revision.is_some() == init
            || self.expected_index.is_some() == init
            || self
                .reference_revision
                .as_deref()
                .is_some_and(|v| !p::digest(v))
            || self
                .expected_index
                .as_deref()
                .is_some_and(|v| !p::digest(v))
        {
            return Err(Error::InvalidRequest);
        }
        let valid = match &self.preview {
            Preview::Initialize {
                initial_branch,
                object_format,
            } => initial_branch == "main" && object_format == "sha1",
            Preview::BranchCreate {
                head,
                branch: current,
                target_ref,
            } => {
                oid(head)
                    && current.as_deref().is_none_or(branch)
                    && branch(target_ref)
                    && current.as_deref() != Some(target_ref.as_str())
            }
            Preview::BranchSwitch {
                head,
                branch: current,
                target_ref,
                target_oid,
                changed_path_count,
            } => {
                oid(head)
                    && oid(target_oid)
                    && head.len() == target_oid.len()
                    && branch(current)
                    && branch(target_ref)
                    && current != target_ref
                    && *changed_path_count <= 256
            }
            Preview::BranchRename {
                head,
                branch: current,
                target_ref,
                ..
            } => {
                oid(head)
                    && branch(current)
                    && branch(target_ref)
                    && !current.eq_ignore_ascii_case(target_ref)
                    && current.rsplit_once('/').map(|v| v.0)
                        == target_ref.rsplit_once('/').map(|v| v.0)
            }
            Preview::FastForward {
                head,
                branch: current,
                target_ref,
                target_oid,
                changed_path_count,
            } => {
                oid(head)
                    && oid(target_oid)
                    && head.len() == target_oid.len()
                    && head != target_oid
                    && branch(current)
                    && tracking_ref(target_ref)
                    && *changed_path_count <= 256
            }
        };
        if valid {
            p::encoded_bound(self, 4096)
        } else {
            Err(Error::InvalidRequest)
        }
    }
    pub(crate) fn matches(&self, selected: &Selection) -> bool {
        if self.validate().is_err() || selected.validate().is_err() {
            return false;
        }
        match (&selected.action, &self.preview) {
            (Action::Initialize {}, Preview::Initialize { .. }) => true,
            (Action::BranchCreate { name, .. }, Preview::BranchCreate { target_ref, .. })
            | (Action::BranchSwitch { name, .. }, Preview::BranchSwitch { target_ref, .. })
            | (Action::BranchRename { name, .. }, Preview::BranchRename { target_ref, .. }) => {
                selected.action.revisions()
                    == Some((
                        self.source_revision.as_str(),
                        self.reference_revision.as_deref().unwrap_or(""),
                    ))
                    && target_ref == &format!("refs/heads/{name}")
            }
            (
                Action::FastForward {
                    target_ref,
                    target_oid,
                    ..
                },
                Preview::FastForward {
                    target_ref: actual_ref,
                    target_oid: actual_oid,
                    ..
                },
            ) => {
                selected.action.revisions()
                    == Some((
                        self.source_revision.as_str(),
                        self.reference_revision.as_deref().unwrap_or(""),
                    ))
                    && target_ref == actual_ref
                    && target_oid == actual_oid
            }
            _ => false,
        }
    }
}

pub type Status = p::Status<Selection, Review>;
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        self.selection.validate()?;
        if self
            .review
            .as_ref()
            .is_some_and(|r| !r.matches(&self.selection))
        {
            return Err(Error::InvalidRequest);
        }
        self.validate_progress()?;
        p::encoded_bound(self, p::STATUS_BYTES - 512)
    }
}

#[cfg(test)]
#[path = "service_git_repository_protocol_tests.rs"]
mod tests;

#[path = "service_git_repository_shared.rs"]
pub(crate) mod shared;
