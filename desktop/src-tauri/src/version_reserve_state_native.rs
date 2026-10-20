//! The enrolled candidate slot on the SAME Store/NativeUse. The original
//! SOURCE inspection calls prepare off Doc; its actual join precedes GO.
//! Remote steps use the existing allocation Jobs. No token, second allocator,
//! opener, reset, unbounded parser or local-mutex distributed claim lives here.
use super::*;
use crate::{
    application_service_host::{NativeStateLease, NativeStateReady},
    supervisor::{VersionReserveControl, VersionReserveJoined},
};
use std::{sync::Mutex, time::Instant};

pub(crate) fn unknown_failure() -> StateError {
    unknown()
}
pub(crate) fn pending(port: &VersionAllocationStatePort) -> Result<bool> {
    Ok(port.enrolled()?.pending.is_some())
}

pub(crate) const STATE_BYTES: usize = 256 * 1024;
// Same bounded state quote reviewed for enrollment: full failed <=1MiB read,
// 4096-node Seed before DOM/canonical clones, typed before/after/attempt copies.
// SOURCE code128MiB and its wire/native quote are separate; not a process RSS cap.
pub(crate) const RETAINED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum Selection {
    /// Explicit Reserve/Retry: create only if this project has never selected;
    /// otherwise reuse the full exact request. It never replaces a candidate.
    InitialOrRetry,
    /// Separate explicit new-candidate action, bound to the native review of
    /// the exact previous request. Pending/unknown rows can never take this arm.
    New { previous_request_sha256: String },
}

struct Capture {
    snapshot: Option<Snapshot>,
    port: Option<Arc<Mutex<VersionAllocationStatePort>>>,
    entered: bool,
    failure: Option<StateError>,
    unsupported: bool,
}
impl Capture {
    fn new() -> Self {
        Self {
            snapshot: None,
            port: None,
            entered: false,
            failure: None,
            unsupported: false,
        }
    }
    fn load(
        &mut self,
        store: Arc<PrivateStateDirectory>,
        project: ProjectBinding,
        repository: &str,
        repository_id: &str,
    ) -> Result<()> {
        need(!self.entered && self.snapshot.is_none() && self.port.is_none())?;
        self.entered = true; // No replay if the original read/parse return is lost.
        let result = (|| {
            self.snapshot = Some(store.read(Namespace::VersionAllocations)?);
            let snapshot = self.snapshot.as_ref().ok_or_else(unknown)?;
            if snapshot.bytes.len() > STATE_BYTES {
                self.unsupported = true;
                return Err(Error::Unavailable.into());
            }
            let state = State::parse_original(snapshot, true).map_err(|error| {
                self.unsupported = error.code == Error::Unavailable;
                error
            })?;
            let mapping = state
                .enrollments
                .iter()
                .find(|e| e.local_project_id == project.project_id.as_str())
                .ok_or_else(|| StateError::from(Error::Unavailable))?;
            let row = state.enrolled(project.project_id.as_str(), &mapping.authority_project_id)?;
            need(
                row.authority.repository == repository
                    && row.authority.repository_id == repository_id
                    && row.authority.protected_branch,
            )?;
            let mut port = VersionAllocationStatePort::new(
                store,
                project,
                serde_json::to_value(&row.authority).map_err(|_| unknown())?,
            )?;
            port.bounded = true;
            port.bound = state
                .candidate(port.project.project_id.as_str())
                .map(|c| c.request.clone());
            port.state = Some(state);
            // No fallible work follows this transfer before the original port
            // is retained. Snapshot ownership is never replaced by a re-read.
            port.snapshot = self.snapshot.take();
            self.port = Some(Arc::new(Mutex::new(port)));
            Ok(())
        })();
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }
    fn select(&mut self, template: Value, selection: &Selection) -> Result<()> {
        let result = self.select_original(template, selection);
        if let Err(error) = result {
            self.failure.get_or_insert(error);
        }
        result
    }
    fn select_original(&mut self, mut template: Value, selection: &Selection) -> Result<()> {
        need(
            self.failure.is_none()
                && closed(
                    &template,
                    &[
                        "identityRevision",
                        "source",
                        "baseVersion",
                        "platforms",
                        "policy",
                        "storeContextRevision",
                    ],
                ),
        )?;
        let mut port = self
            .port
            .as_ref()
            .ok_or_else(unknown)?
            .lock()
            .map_err(|_| unknown())?;
        template["projectId"] = json!(port.authority.project_id);
        need(
            ((template["policy"]["schemaVersion"] == 2 && template["platforms"] == json!(["ios"]))
                 || (template["policy"]["schemaVersion"] == 3 && template["platforms"] == json!(["android"]))
                 || (template["policy"]["schemaVersion"] == 4 && template["platforms"] == json!(["android","ios"])))
                && template["source"]["ref"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("refs/heads/") && full_ref(v)),
        )?;
        let selected = port
            .state()?
            .candidate(port.project.project_id.as_str())
            .map(|c| c.request.clone());
        match (selection, selected.as_ref()) {
            (Selection::InitialOrRetry, None) => {
                port.select_new(template, None)?;
            }
            (Selection::InitialOrRetry, Some(previous)) => {
                template["candidateId"] = previous.0["candidateId"].clone();
                need(template == previous.0)?;
                port.admit_request(&previous.0)?;
            }
            (
                Selection::New {
                    previous_request_sha256,
                },
                Some(previous),
            ) => {
                need(
                    previous.request_hash()? == *previous_request_sha256
                        && port.enrolled()?.pending.is_none(),
                )?;
                port.select_new(template, Some(&previous.0))?;
            }
            _ => return Err(Error::Conflict.into()),
        }
        Ok(())
    }
}

struct Custody {
    lease: Option<Arc<NativeStateLease>>,
    capture: Capture,
    entered: bool,
    retirement_entered: bool,
    retirement_result: Option<Result<()>>,
}
impl Custody {
    fn new() -> Self {
        Self {
            lease: None,
            capture: Capture::new(),
            entered: false,
            retirement_entered: false,
            retirement_result: None,
        }
    }
    /// The original state preparation never entered at all. This does not
    /// stand in for retirement after a Source or NativeUse was admitted.
    fn never_entered(&self, control: &VersionReserveControl) -> bool {
        control.never_admitted()
            && !self.entered
            && self.lease.is_none()
            && !self.capture.entered
            && self.capture.snapshot.is_none()
            && self.capture.port.is_none()
            && self.capture.failure.is_none()
            && !self.capture.unsupported
            && !self.retirement_entered
            && self.retirement_result.is_none()
    }
}
pub(crate) struct StateHold {
    ready: Arc<NativeStateReady>,
    control: Arc<VersionReserveControl>,
    custody: Mutex<Custody>,
}
impl StateHold {
    /// No IO. Retain on the original invocation BEFORE its inspection starts.
    pub(crate) fn new(ready: Arc<NativeStateReady>, control: Arc<VersionReserveControl>) -> Self {
        Self {
            ready,
            control,
            custody: Mutex::new(Custody::new()),
        }
    }
    /// ONLY original Resources.inspection's registered blocking body calls it.
    /// A failure samples F before that original job returns to an async observer.
    pub(crate) fn prepare(
        &self,
        template: Value,
        selection: &Selection,
        repository: &str,
        repository_id: &str,
    ) -> Result<()> {
        let result = (|| {
            need(self.control.current())?;
            let mut c = self.custody.lock().map_err(|_| unknown())?;
            need(!c.entered && c.lease.is_none() && !c.retirement_entered)?;
            c.entered = true;
            c.lease = Some(Arc::new(self.ready.begin_use()?));
            let lease = c.lease.as_ref().ok_or_else(unknown)?.clone();
            lease.store().check_native_use(lease.native_use())?;
            need(self.control.current())?;
            c.capture.load(
                lease.store().clone(),
                lease.project_binding().clone(),
                repository,
                repository_id,
            )?;
            need(self.control.current())?;
            c.capture.select(template, selection)?;
            need(self.control.current())?;
            Ok(())
        })();
        if let Err(error) = result {
            let at = Instant::now();
            self.control.state_failed(error, at);
        }
        result
    }
    pub(crate) fn port(&self) -> Result<Arc<Mutex<VersionAllocationStatePort>>> {
        let c = self.custody.lock().map_err(|_| unknown())?;
        need(c.entered && c.capture.failure.is_none() && !c.retirement_entered)?;
        c.capture.port.clone().ok_or_else(unknown)
    }
    pub(crate) fn check_use(&self) -> Result<()> {
        let c = self.custody.lock().map_err(|_| unknown())?;
        need(c.entered && !c.retirement_entered && c.capture.failure.is_none())?;
        let lease = c.lease.as_ref().ok_or_else(unknown)?;
        lease.store().check_native_use(lease.native_use())
    }
    /// Redacted comparison only, after joins; even a refused retry retains the
    /// original selected identity. Never re-read/reset state to mint this hash.
    pub(crate) fn selected_hash(&self) -> Result<Option<String>> {
        let c = self.custody.lock().map_err(|_| unknown())?;
        let Some(port) = &c.capture.port else {
            return Ok(None);
        };
        let port = port.lock().map_err(|_| unknown())?;
        port.bound.as_ref().map(|r| r.request_hash()).transpose()
    }
    pub(crate) fn ready(&self) -> &Arc<NativeStateReady> {
        &self.ready
    }
    pub(crate) fn unsupported_size(&self) -> bool {
        self.custody.lock().is_ok_and(|c| c.capture.unsupported)
    }
    pub(crate) fn failure(&self) -> Option<StateError> {
        match self.custody.lock() {
            Err(_) => Some(unknown()),
            Ok(c) => c.capture.failure.or_else(|| {
                c.capture.port.as_ref().and_then(|p| {
                    p.lock()
                        .map(|p| p.failure())
                        .unwrap_or_else(|_| Some(unknown()))
                })
            }),
        }
    }
    /// Original all-jobs SOURCE+observer return, NOT a terminal/ACK/DTO. The
    /// calling Doc retains this final blocking handle before releasing it.
    /// Remember the primitive's returned fact even when the return is too late;
    /// no retry or Drop can release an ambiguous use or gain deadline credit.
    pub(crate) fn retire_original(&self, joined: &VersionReserveJoined) -> Result<()> {
        need(joined.matches(&self.control, self))?;
        self.control.check_cleanup().map_err(|_| unknown())?;
        let mut c = self.custody.lock().map_err(|_| unknown())?;
        self.control.check_cleanup().map_err(|_| unknown())?;
        need(!c.retirement_entered)?;
        c.retirement_entered = true;
        let result = if let Some(lease) = &c.lease {
            lease.store().retire_native_use(lease.native_use())
        } else {
            Ok(())
        };
        c.retirement_result = Some(result);
        drop(c);
        if let Err(error) = result {
            self.control.state_failed(error, Instant::now());
        }
        self.control.check_cleanup().map_err(|_| unknown())?;
        result
    }
    pub(crate) fn retired(&self) -> bool {
        !self.control.uncertain()
            && self
                .custody
                .lock()
                .is_ok_and(|c| matches!(c.retirement_result, Some(Ok(()))))
    }
    /// Only the same original, unpoisoned, entirely unentered custody. The
    /// caller additionally requires a refused outcome and no joined Source.
    pub(crate) fn never_entered(&self) -> bool {
        self.custody
            .lock()
            .is_ok_and(|c| c.never_entered(&self.control))
    }
}

#[cfg(test)]
mod tests {
    // Actual tempStore codec/CAS only; no NativeUse or native admission proof.
    use super::*;
    use crate::application_state_store::Fixture;
    fn template() -> Value {
        let mut v = super::super::tests::request();
        for key in ["candidateId", "projectId"] {
            v.as_object_mut().unwrap().remove(key);
        }
        v["platforms"] = json!(["ios"]);
        v["policy"]["schemaVersion"] = json!(2);
        v["policy"]["storeScope"] = json!(ios_inventory::POLICY_SCOPE);
        v["storeContextRevision"] = json!("a".repeat(64));
        v
    }
    #[test]
    fn native_namespace_selection_retries_exact_request_without_renumber_or_reset() {
        let f = Fixture::new();
        let (store, mut old) = super::super::tests::prepared(&f);
        let previous = old.selected_request().unwrap().clone();
        let mut input = template();
        input["projectId"] = json!(old.authority.project_id);
        old.select_new(input, Some(&previous)).unwrap();
        let selected = old.selected_request().unwrap().clone();
        let revision = old.snapshot().unwrap().revision;
        let mut captured = Capture::new();
        captured
            .load(
                store.clone(),
                old.project.clone(),
                &old.authority.repository,
                &old.authority.repository_id,
            )
            .unwrap();
        captured
            .select(template(), &Selection::InitialOrRetry)
            .unwrap();
        let current = captured.port.as_ref().unwrap().lock().unwrap();
        assert_eq!(current.selected_request().unwrap(), &selected);
        assert_eq!(current.snapshot().unwrap().revision, revision);
        drop(current);
        let mut drift = template();
        drift["source"]["tree"] = json!("f".repeat(40));
        assert!(captured.select(drift, &Selection::InitialOrRetry).is_err());
        assert_eq!(
            store.read(Namespace::VersionAllocations).unwrap().revision,
            revision
        );
        assert!(captured
            .load(
                store.clone(),
                old.project.clone(),
                &old.authority.repository,
                &old.authority.repository_id
            )
            .is_err());
        store.close().unwrap();
    }
    #[test]
    fn native_enrollment_repository_substitution_preserves_full_snapshot_before_refusal() {
        let f = Fixture::new();
        let (store, old) = super::super::tests::prepared(&f);
        let before = store.read(Namespace::VersionAllocations).unwrap();
        let mut captured = Capture::new();
        assert!(captured
            .load(
                store.clone(),
                old.project.clone(),
                &old.authority.repository,
                "999"
            )
            .is_err());
        assert_eq!(captured.snapshot.as_ref().unwrap().bytes, before.bytes);
        assert!(captured.port.is_none() && captured.failure.is_some());
        assert_eq!(
            store.read(Namespace::VersionAllocations).unwrap().revision,
            before.revision
        );
        store.close().unwrap();
    }
    #[test]
    fn unentered_reserve_state_is_not_confused_with_entered_or_unknown_custody() {
        // Same original custody predicate; no invented Ready, use or join.
        let control = VersionReserveControl::new(Instant::now()).unwrap();
        control.stop(); // Known refusal before the Source has been admitted.
        assert!(Custody::new().never_entered(&control));
        let mut entered = Custody::new();
        entered.entered = true;
        assert!(!entered.never_entered(&control));
        let mut read = Custody::new();
        read.capture.entered = true;
        assert!(!read.never_entered(&control));
        let mut snapshot = Custody::new();
        snapshot.capture.snapshot = Some(Snapshot {
            revision: Revision(0),
            bytes: Vec::new(),
        });
        assert!(!snapshot.never_entered(&control));
        let mut failed = Custody::new();
        failed.capture.failure = Some(Error::Unavailable.into());
        assert!(!failed.never_entered(&control));
        let mut retirement = Custody::new();
        retirement.retirement_entered = true;
        assert!(!retirement.never_entered(&control));
        retirement.retirement_result = Some(Ok(()));
        assert!(!retirement.never_entered(&control));
        control.unknown();
        assert!(!Custody::new().never_entered(&control));
    }
}
