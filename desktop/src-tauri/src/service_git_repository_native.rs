//! Fixed projections from the original joined GitLocal review. No Deserialize
//! of a native action, source, journal, receipt, or permission lives here.
use super::*;
use crate::{
    git_branch_protocol as branch, git_fast_forward_protocol as ff, git_init_protocol as init,
    git_rename_protocol as rename, git_switch_protocol as switch, git_upstream_protocol as upstream,
};

pub(super) fn action(selected: &repository::Action) -> Result<local::Action, BridgeError> {
    selected.validate().map_err(public)?;
    let action = match selected {
        repository::Action::SetUpstream {expected_revision,expected_reference_revision,branch,head,remote,repository,identity}=>
            local::Action::Upstream(upstream::Action {kind:upstream::Kind::SetUpstream,
                expected_revision:expected_revision.clone(),expected_reference_revision:expected_reference_revision.clone(),
                branch:branch.clone(),head:head.clone(),remote:remote.clone(),repository:repository.clone(),
                identity:identity.as_ref().map(|i|upstream::Identity{name:i.name.clone(),email:i.email.clone()})}),
        repository::Action::Initialize {} => local::Action::Initialize(init::Action {
            kind: init::Kind::Initialize,
        }),
        repository::Action::BranchCreate {
            expected_revision,
            expected_reference_revision,
            name,
        } => local::Action::Branch(branch::Action {
            kind: branch::Kind::Create,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            name: name.clone(),
        }),
        repository::Action::BranchSwitch {
            expected_revision,
            expected_reference_revision,
            name,
        } => local::Action::Switch(switch::Action {
            kind: switch::Kind::Switch,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            name: name.clone(),
        }),
        repository::Action::BranchRename {
            expected_revision,
            expected_reference_revision,
            name,
        } => local::Action::Rename(rename::Action {
            kind: rename::Kind::Rename,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            name: name.clone(),
        }),
        repository::Action::FastForward {
            expected_revision,
            expected_reference_revision,
            target_ref,
            target_oid,
        } => local::Action::FastForward(ff::Action {
            kind: ff::Kind::FastForward,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            target_ref: target_ref.clone(),
            target_oid: target_oid.clone(),
        }),
    };
    if action.valid() {
        Ok(action)
    } else {
        Err(BridgeError::invalid())
    }
}

/// Called only by the existing reconcile AFTER its genuine Supervisor
/// receipt, original gate and expiry checks. The full review stays there.
pub(in crate::asset_session) fn review(
    scope: &requests::NativeScope,
    original: &local::Review,
    review_id: String,
    document_revision: u32,
    registration_generation: u32,
) -> Option<shared::Reviewed> {
    if !original.valid()
        || document_revision != scope.document_revision
        || registration_generation != scope.registration
    {
        return None;
    }
    let selected = match &scope.selection {
        shared::Selected::Files(_) => {
            let local::Review::Files(details) = original else {
                return None;
            };
            if !commit::review_matches(scope, details) {
                return None;
            }
            return Some(
                wire::Review {
                    review_id,
                    expected_index: details.expected_index.clone(),
                    review_digest: details.review_digest.clone(),
                    document_revision,
                    registration_generation,
                }
                .into(),
            );
        }
        shared::Selected::Repository(selected) => selected,
        shared::Selected::Remote(_) => return super::super::remote::review(scope,original,review_id,document_revision,registration_generation).map(Into::into),
    };
    let actual = action(&selected.action).ok()?;
    let (reference_revision, preview) = match (original, &actual) {
        (local::Review::Upstream(v),local::Action::Upstream(a)) if v.matches(a)=>(Some(v.expected_reference_revision.clone()),
            repository::Preview::SetUpstream {head:v.head.clone(),branch:v.branch.clone(),remote:v.remote.clone(),repository:v.repository.clone(),
                config_changed:!v.additions.is_empty(),missing_directory_count:u32::try_from(v.missing_directories.len()).ok()?,unchanged:v.unchanged}),
        (local::Review::Initialize(v), local::Action::Initialize(a)) if v.matches(a) => (
            None,
            repository::Preview::Initialize {
                initial_branch: v.initial_branch.clone(),
                object_format: v.object_format.clone(),
            },
        ),
        (local::Review::Branch(v), local::Action::Branch(a)) if v.matches(a) => (
            Some(v.expected_reference_revision.clone()),
            repository::Preview::BranchCreate {
                head: v.head.clone(),
                branch: v.branch.clone(),
                target_ref: v.target_ref.clone(),
            },
        ),
        (local::Review::Switch(v), local::Action::Switch(a)) if v.matches(a) => (
            Some(v.expected_reference_revision.clone()),
            repository::Preview::BranchSwitch {
                head: v.head.clone(),
                branch: v.branch.clone(),
                target_ref: v.target_ref.clone(),
                target_oid: v.target_oid.clone(),
                changed_path_count: u32::try_from(v.paths.len()).ok()?,
            },
        ),
        (local::Review::Rename(v), local::Action::Rename(a)) if v.matches(a) => (
            Some(v.expected_reference_revision.clone()),
            repository::Preview::BranchRename {
                head: v.head.clone(),
                branch: v.branch.clone(),
                target_ref: v.target_ref.clone(),
                config_moved: v.config_moved,
                logging: v.logging,
            },
        ),
        (local::Review::FastForward(v), local::Action::FastForward(a)) if v.matches(a) => (
            Some(v.expected_reference_revision.clone()),
            repository::Preview::FastForward {
                head: v.head.clone(),
                branch: v.branch.clone(),
                target_ref: v.target_ref.clone(),
                target_oid: v.target_oid.clone(),
                changed_path_count: u32::try_from(v.paths.len()).ok()?,
            },
        ),
        _ => return None,
    };
    let value = repository::Review {
        review_id,
        source_revision: original.expected_revision().into(),
        reference_revision,
        expected_index: original.expected_index().map(str::to_owned),
        review_digest: original.review_digest().into(),
        document_revision,
        registration_generation,
        preview,
    };
    value.matches(selected).then(|| value.into())
}
