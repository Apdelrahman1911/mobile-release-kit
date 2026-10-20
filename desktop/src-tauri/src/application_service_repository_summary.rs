//! Same-host publication of an original, already-settled Git Observe.
//! No service/Store lock, native callback, queued work or filesystem IO here.
use super::{ApplicationHost, NativeProject, Phase};
use crate::{
    git_read_protocol as native, service_protocol::Error, service_repository_summary as data,
};

fn project(value: &native::Projection) -> Option<data::Captured> {
    if value.phase != native::Phase::Settled
        || value.outcome != Some(native::Outcome::Ok)
        || value.reason.is_some()
        || value.action.kind != native::Kind::Observe
        || !value.action.valid()
    {
        return None;
    }
    // Reuse the actual closed native result validator. Borrow the bounded
    // original Value; never clone the full paths/diff/remote/result backing.
    native::validate_result(&value.action, &value.result).ok()?;
    let raw = &value.result["observation"];
    let rows = raw["changes"].as_array()?;
    let mut changes = data::Changes {
        total: rows.len().try_into().ok()?,
        index: 0,
        worktree: 0,
        untracked: 0,
        conflicts: 0,
    };
    for row in rows {
        let index = row["index"].as_str()?;
        let worktree = row["worktree"].as_str()?;
        changes.index += u16::from(!matches!(index, " " | "?" | "!"));
        changes.worktree += u16::from(!matches!(worktree, " " | "?" | "!"));
        changes.untracked += u16::from(index == "?" && worktree == "?");
        changes.conflicts += u16::from(row["conflict"].as_bool()?);
    }
    let head = if raw["unborn"].as_bool()? {
        data::Head::Unborn
    } else if raw["detached"].as_bool()? {
        data::Head::Detached
    } else {
        data::Head::Attached
    };
    let tracking = &value.result["tracking"];
    let state = match tracking["state"].as_str()? {
        "detached" => data::TrackingState::Detached,
        "not-configured" => data::TrackingState::NotConfigured,
        "unsupported" => data::TrackingState::Unsupported,
        "unborn" => data::TrackingState::Unborn,
        "gone" => data::TrackingState::Gone,
        "shallow" => data::TrackingState::Shallow,
        "limit" => data::TrackingState::Limit,
        "complete" => data::TrackingState::Complete,
        _ => return None,
    };
    let count = |field: &str| -> Option<Option<u16>> {
        if tracking[field].is_null() {
            Some(None)
        } else {
            Some(Some(tracking[field].as_u64()?.try_into().ok()?))
        }
    };
    let observation = data::Observation {
        operation_id: value.operation_id.clone(),
        head,
        changes,
        tracking: data::Tracking {
            state,
            ahead: count("ahead")?,
            behind: count("behind")?,
        },
        restriction_count: raw["restrictions"].as_array()?.len().try_into().ok()?,
    };
    observation.validate().ok()?;
    Some(data::Captured {
        observation,
        observation_revision: raw["revision"].as_str()?.to_owned(),
        reference_revision: value.result["referenceRevision"].as_str()?.to_owned(),
    })
}

impl ApplicationHost {
    /// Only the retained relay's genuine Document callback supplies these
    /// arguments. The Document is still held through native registry comparison
    /// and this TRY-only Host check. The two nested sections are bounded DATA;
    /// there is no Service lock, read-grant renewal, IO or new original owner.
    pub(crate) fn publish_repository_summary(
        &self,
        original: &NativeProject,
        value: &native::Projection,
    ) {
        let control = match self.try_native_lock() {
            Ok(control) => control,
            Err(Error::Busy) => return,
            Err(_) => {
                self.repository_summary.retire();
                return;
            }
        };
        if control.available().is_err() {
            self.repository_summary.retire();
            return;
        }
        if control.service.is_none() || !matches!(control.phase, Phase::Ready | Phase::Listening) {
            return;
        }
        let Some(bound) = control.registered.get(&original.runtime_id) else {
            return;
        };
        if !original.valid()
            || !bound.same_registration(original)
            || value.context.project_id != original.runtime_id
            || value.context.generation != original.registration_generation
        {
            self.repository_summary.retire();
            return;
        }
        let Some(root) = original.canonical_root.to_str() else {
            self.repository_summary.retire();
            return;
        };
        let source = data::Source {
            runtime_id: original.runtime_id.clone(),
            canonical_root: root.to_owned(),
            device: original.device,
            inode: original.inode,
            registration_generation: original.registration_generation,
        };
        match project(value) {
            Some(captured) => self.repository_summary.publish(source, captured),
            None => self
                .repository_summary
                .unavailable(source, &value.operation_id),
        }
    }
    /// Before any possibly blocked cleanup/Host lock. Losing the original relay
    /// or native currentness cannot be repaired by a later cached status copy.
    pub(crate) fn repository_summary_relay_lost(&self) {
        self.repository_summary.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_protocol::Id;
    use serde_json::json;

    fn finished() -> native::Projection {
        native::Projection {
            operation_id: "git-read-1".into(),
            context: native::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "document-1".into(),
            },
            action: native::Action {
                kind: native::Kind::Observe,
                expected_revision: None,
                paths: vec![],
                staged: false,
            },
            phase: native::Phase::Settled,
            outcome: Some(native::Outcome::Ok),
            reason: None,
            result: json!({"observation":{"revision":"a".repeat(64),"head":"b".repeat(40),"branch":"refs/heads/branch-sentinel",
                "unborn":false,"detached":false,"changes":[
                    {"path":"path-sentinel/file","index":"M","worktree":" ","kind":"file","conflict":false},
                    {"path":"untracked-sentinel","index":"?","worktree":"?","kind":"file","conflict":false},
                    {"path":"conflict-sentinel","index":"U","worktree":"U","kind":"file","conflict":true}],
                "remotes":["remote-sentinel"],"restrictions":["conflicts"]},
                "referenceRevision":"c".repeat(64),"basis":"local-refs-no-fetch",
                "tracking":{"state":"complete","remote":"remote-sentinel","mergeRef":"refs/heads/merge-sentinel",
                    "localRef":"refs/remotes/remote-sentinel/branch","head":"d".repeat(40),"ahead":2,"behind":3}}),
        }
    }
    #[test]
    fn completed_original_projection_drops_paths_refs_revisions_and_remote_names() {
        let captured = project(&finished()).unwrap();
        assert_eq!(
            captured.observation.changes,
            data::Changes {
                total: 3,
                index: 2,
                worktree: 1,
                untracked: 1,
                conflicts: 1
            }
        );
        assert_eq!(
            captured.observation.tracking.state,
            data::TrackingState::Complete
        );
        let encoded = serde_json::to_string(&captured.observation).unwrap();
        for excluded in [
            "sentinel",
            "refs/",
            &"a".repeat(64),
            &"b".repeat(40),
            &"c".repeat(64),
            &"d".repeat(40),
        ] {
            assert!(!encoded.contains(excluded));
        }
        assert_eq!(captured.observation.operation_id, "git-read-1");
    }
    #[test]
    fn running_unknown_other_actions_and_malformed_observations_never_project_cleanliness() {
        for field in 0..8 {
            let mut value = finished();
            match field {
                0 => value.phase = native::Phase::Running,
                1 => value.phase = native::Phase::CleanupUnknown,
                2 => value.outcome = Some(native::Outcome::Cancelled),
                3 => value.reason = Some("unknown".into()),
                4 => value.action.kind = native::Kind::Diff,
                5 => {
                    value.result["tracking"]
                        .as_object_mut()
                        .unwrap()
                        .remove("behind");
                }
                6 => value.result["observation"]["changes"][2]["conflict"] = json!(false),
                _ => value.result["basis"] = json!("fresh-remote"),
            }
            assert!(project(&value).is_none());
        }
    }
    #[test]
    fn unborn_detached_and_incomplete_tracking_keep_the_original_limits_visible() {
        let mut value = finished();
        value.result["observation"]["unborn"] = json!(true);
        value.result["observation"]["head"] = json!(null);
        value.result["tracking"] = json!({"state":"unborn","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null});
        let out = project(&value).unwrap().observation;
        assert_eq!(out.head, data::Head::Unborn);
        assert_eq!(out.tracking.ahead, None);
        value = finished();
        value.result["observation"]["detached"] = json!(true);
        value.result["observation"]["branch"] = json!(null);
        value.result["tracking"] = json!({"state":"detached","remote":null,"mergeRef":null,"localRef":null,"head":null,"ahead":null,"behind":null});
        assert_eq!(
            project(&value).unwrap().observation.head,
            data::Head::Detached
        );
        value = finished();
        value.result["tracking"]["state"] = json!("shallow");
        value.result["tracking"]["ahead"] = json!(null);
        value.result["tracking"]["behind"] = json!(null);
        assert_eq!(
            project(&value).unwrap().observation.tracking.state,
            data::TrackingState::Shallow
        );
    }
    fn original() -> NativeProject {
        NativeProject {
            runtime_id: "project-1".into(),
            canonical_root: "/private/root-sentinel".into(),
            device: 11,
            inode: 12,
            registration_generation: 1,
            document_identity: std::sync::Arc::new(()),
            input_revision: 1,
        }
    }
    fn view(host: &ApplicationHost, original: &NativeProject) -> data::View {
        host.repository_summary.view(
            Id::parse(&"1".repeat(32)).unwrap(),
            &original.runtime_id,
            original.canonical_root.to_str().unwrap(),
            original.device,
            original.inode,
        )
    }
    #[test]
    fn dormant_or_busy_host_does_not_start_a_service_and_loss_never_waits_for_control() {
        let host = ApplicationHost::new();
        let original = original();
        host.publish_repository_summary(&original, &finished());
        assert_eq!(view(&host, &original).capture, data::Capture::Unobserved);
        let control = host.control.lock().unwrap();
        host.publish_repository_summary(&original, &finished());
        host.repository_summary_relay_lost();
        assert!(
            control.service.is_none() && control.store.is_none() && control.phase == Phase::Dormant
        );
        drop(control);
        assert_eq!(view(&host, &original).capture, data::Capture::Unavailable);
    }
    #[test]
    fn same_initialized_service_projects_without_service_lock_or_store_write_and_rematches_native_registration(
    ) {
        use crate::{
            application_service::{tests::with_state_locked, ApplicationService},
            application_state_store::{Fixture, Namespace, PrivateStateDirectory},
        };
        use std::sync::Arc;
        let f = Fixture::new();
        let host = ApplicationHost::new();
        let original = original();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = Arc::new(
            ApplicationService::open_with_observations(
                store.clone(),
                host.android_tools.clone(),
                host.repository_summary.clone(),
            )
            .unwrap(),
        );
        // Actual Store/Service, inert native-registration DATA. This is not a
        // native picker/Git-read/Host-startup qualification fixture.
        {
            let mut control = host.control.lock().unwrap();
            control.service = Some(service.clone());
            control.phase = Phase::Ready;
            control
                .registered
                .insert(original.runtime_id.clone(), original.clone());
        }
        let before = store.read(Namespace::Projects).unwrap();
        with_state_locked(&service, || {
            host.publish_repository_summary(&original, &finished())
        });
        assert_eq!(view(&host, &original).capture, data::Capture::Observed);
        assert!(!service.read_access_status().unwrap().enabled);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(before.revision, after.revision);
        assert_eq!(before.bytes, after.bytes);
        let mut foreign = original.clone();
        foreign.document_identity = Arc::new(());
        with_state_locked(&service, || {
            host.publish_repository_summary(&foreign, &finished())
        });
        assert_eq!(view(&host, &original).capture, data::Capture::Unavailable);
        with_state_locked(&service, || host.repository_summary_relay_lost());
        service.stop().unwrap();
        store.close().unwrap();
    }
}
