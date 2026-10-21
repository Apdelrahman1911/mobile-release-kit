//! Authority-free, read-only facet of the SAME VersionAllocations namespace.
//! Full original snapshots precede bounded parsing. No fake protected Authority,
//! state write, migration, reset, enrollment or allocator is available here.
use super::*;
use crate::{
    application_service_host::{NativeStateLease, NativeStateReady},
    error::BridgeError,
    github_connection_session::publication::refused,
    github_publication_protocol::Reason,
};

pub(crate) const SNAPSHOT_WORK: usize = 5 * 1024 * 1024;
pub(crate) struct Proof {
    original: Arc<Snapshot>,
    project: ProjectBinding,
    repository_id: String,
}
impl Proof {
    pub(crate) fn project_id(&self) -> &str {
        self.project.project_id.as_str()
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.original
            .bytes
            .capacity()
            .checked_add(self.project.canonical_root.capacity())?
            .checked_add(self.project.project_id.retained_bytes())?
            .checked_add(self.repository_id.capacity())?
            .checked_add(std::mem::size_of::<Self>())
    }
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.project == other.project
            && self.repository_id == other.repository_id
            && self.original.revision == other.original.revision
            && self.original.bytes == other.original.bytes
    }
}
fn inspect(
    snapshot: &Snapshot,
    project: &ProjectBinding,
    repository: &str,
) -> std::result::Result<(), BridgeError> {
    if snapshot.bytes.len() > 256 * 1024 {
        return Err(refused(Reason::CounterStateUnavailable));
    }
    let state = State::parse_original(snapshot, true)
        .map_err(|_| refused(Reason::CounterStateUnavailable))?;
    let id = project.project_id.as_str();
    if state
        .authorities
        .iter()
        .any(|r| r.authority.repository_id == repository || r.authority.project_id == id)
        || state
            .enrollments
            .iter()
            .any(|r| r.local_project_id == id || r.authority_project_id == id)
        || state
            .candidates
            .iter()
            .any(|r| r.local_project_id == id || r.request.project() == id)
    {
        return Err(refused(Reason::CounterKnownAuthority));
    }
    Ok(())
}
pub(crate) struct Custody {
    ready: Arc<NativeStateReady>,
    repository: String,
    previous: Option<Arc<Proof>>,
    lease: Option<Arc<NativeStateLease>>,
    original: Option<Arc<Snapshot>>,
    post: Option<Snapshot>,
    final_post: Option<Snapshot>,
    proof: Option<Arc<Proof>>,
    entered: bool,
    rechecked: bool,
    retirement: Option<Result<()>>,
    retirement_entered: bool,
    native_failure: Option<StateError>,
    uncertain: bool,
}
impl Custody {
    pub(crate) fn new(
        ready: Arc<NativeStateReady>,
        repository: String,
        previous: Option<Arc<Proof>>,
    ) -> Self {
        Self {
            ready,
            repository,
            previous,
            lease: None,
            original: None,
            post: None,
            final_post: None,
            proof: None,
            entered: false,
            rechecked: false,
            retirement: None,
            retirement_entered: false,
            native_failure: None,
            uncertain: false,
        }
    }
    fn native_error(&mut self, error: StateError) -> BridgeError {
        if self.native_failure.is_none() {
            self.native_failure = Some(error);
        }
        if error.effect == crate::application_state_store::Effect::Unknown
            || error.durability == crate::application_state_store::Durability::Unknown
            || error.cleanup == crate::application_state_store::Cleanup::Unknown
            || error.code == Error::StateUnknown
        {
            self.uncertain = true;
            BridgeError::cleanup_unknown()
        } else {
            refused(Reason::CounterStateUnavailable)
        }
    }
    /// Original fixed blocking load job only. Retain every returned original
    /// before checks; a refused parser never gets to relabel the slot empty.
    pub(crate) fn load(&mut self) -> std::result::Result<(), BridgeError> {
        if self.entered || self.lease.is_some() || self.original.is_some() {
            return Err(BridgeError::cleanup_unknown());
        }
        self.entered = true;
        let lease = self.ready.begin_use().map_err(|e| self.native_error(e))?;
        self.lease = Some(Arc::new(lease));
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .clone();
        lease
            .store()
            .check_native_use(lease.native_use())
            .map_err(|e| self.native_error(e))?;
        self.original = Some(Arc::new(
            lease
                .store()
                .read(Namespace::VersionAllocations)
                .map_err(|e| self.native_error(e))?,
        ));
        let original = self
            .original
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        inspect(original, lease.project_binding(), &self.repository)?;
        let proof = Arc::new(Proof {
            original: original.clone(),
            project: lease.project_binding().clone(),
            repository_id: self.repository.clone(),
        });
        if self
            .previous
            .as_ref()
            .is_some_and(|old| !old.matches(&proof))
        {
            return Err(refused(Reason::CounterStateChanged));
        }
        self.proof = Some(proof);
        Ok(())
    }
    /// Fresh actual Store read before this original GO, not snapshot-shaped
    /// renderer DATA. Both physical reads remain retained through retirement.
    pub(crate) fn recheck(&mut self) -> std::result::Result<(), BridgeError> {
        if !self.entered || self.rechecked || self.proof.is_none() {
            return Err(BridgeError::cleanup_unknown());
        }
        self.rechecked = true;
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .clone();
        lease
            .store()
            .check_native_use(lease.native_use())
            .map_err(|e| self.native_error(e))?;
        self.post = Some(
            lease
                .store()
                .read(Namespace::VersionAllocations)
                .map_err(|e| self.native_error(e))?,
        );
        let original = self
            .original
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let post = self
            .post
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?;
        if post.revision != original.revision || post.bytes != original.bytes {
            return Err(refused(Reason::CounterStateChanged));
        }
        inspect(post, lease.project_binding(), &self.repository)
    }
    pub(crate) fn proof_before_go(&self) -> Option<Arc<Proof>> {
        self.rechecked.then(|| self.proof.clone()).flatten()
    }
    /// Caller must be the SAME publication's actual management finalizer after
    /// driver/watchdog and all these fixed jobs returned. No Drop implements it.
    pub(crate) fn retire(&mut self) -> std::result::Result<(), BridgeError> {
        if self.retirement_entered || self.uncertain {
            return Err(BridgeError::cleanup_unknown());
        }
        self.retirement_entered = true;
        let mut source = Ok(());
        if self.proof.is_some() {
            if let Some(lease) = self.lease.clone() {
                match lease.store().read(Namespace::VersionAllocations) {
                    Ok(value) => {
                        self.final_post = Some(value);
                        let v = self.final_post.as_ref().unwrap();
                        if self
                            .original
                            .as_ref()
                            .is_none_or(|o| o.revision != v.revision || o.bytes != v.bytes)
                        {
                            source = Err(refused(Reason::CounterStateChanged));
                            self.proof = None;
                        }
                    }
                    Err(error) => {
                        source = Err(self.native_error(error));
                        self.proof = None;
                    }
                }
            }
        }
        if self.uncertain {
            return Err(BridgeError::cleanup_unknown());
        }
        let result = self.lease.as_ref().map_or(Ok(()), |lease| {
            lease.store().retire_native_use(lease.native_use())
        });
        self.retirement = Some(result);
        result.map_err(|_| BridgeError::cleanup_unknown())?;
        source
    }
    pub(crate) fn retired(&self) -> bool {
        self.retirement.as_ref().is_some_and(|v| v.is_ok())
    }
    pub(crate) fn retired_proof(&self) -> Option<Arc<Proof>> {
        self.retirement
            .as_ref()
            .is_some_and(|v| v.is_ok())
            .then(|| self.proof_before_go())
            .flatten()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn project() -> ProjectBinding {
        ProjectBinding {
            project_id: Id::parse(&"a".repeat(32)).unwrap(),
            canonical_root: "/inert/project".into(),
            device: 1,
            inode: 2,
        }
    }
    #[test]
    fn empty_and_legacy_originals_are_read_without_migration_or_authority() {
        let p = project();
        let empty = Snapshot {
            revision: Revision(0),
            bytes: vec![],
        };
        assert!(inspect(&empty, &p, "22").is_ok());
        for version in 1..=3 {
            let mut v = json!({"schemaVersion":version,"protocol":PROTOCOL,"authorities":[]});
            if version >= 2 {
                v["enrollments"] = json!([]);
            }
            if version >= 3 {
                v["candidates"] = json!([]);
            }
            let mut bytes = canonical(&v, STATE_LIMIT).unwrap();
            bytes.push(b'\n');
            let original = Snapshot {
                revision: Revision(7),
                bytes,
            };
            let retained = original.bytes.clone();
            assert!(inspect(&original, &p, "22").is_ok());
            assert_eq!(original.bytes, retained);
            assert_eq!(original.revision, Revision(7));
        }
    }
    #[test]
    fn existing_repository_any_alias_and_oversize_do_not_mean_empty() {
        let p = project();
        let other = "b".repeat(32);
        let v = json!({"schemaVersion":1,"protocol":PROTOCOL,"authorities":[{"authority":{"projectId":other,"repository":"renamed/elsewhere","repositoryId":"22","ledgerId":"00000000-0000-4000-8000-000000000007","genesisSha256":"c".repeat(64),"protectedBranch":true},"checkpoint":{"sequence":0,"headSha256":"c".repeat(64),"commit":"d".repeat(40)},"pending":null}]});
        let mut bytes = canonical(&v, STATE_LIMIT).unwrap();
        bytes.push(b'\n');
        assert_eq!(
            inspect(
                &Snapshot {
                    revision: Revision(2),
                    bytes
                },
                &p,
                "22"
            )
            .unwrap_err()
            .code,
            "github_setup_publication_refused_counter_known_authority"
        );
        let original = Snapshot {
            revision: Revision(2),
            bytes: vec![b' '; 256 * 1024 + 1],
        };
        assert!(inspect(&original, &p, "99").is_err());
        assert_eq!(original.bytes.len(), 256 * 1024 + 1);
    }
    #[test]
    fn same_bytes_revision_aba_is_not_a_new_native_read_match() {
        let make = |revision, bytes| Proof {
            original: Arc::new(Snapshot {
                revision: Revision(revision),
                bytes,
            }),
            project: project(),
            repository_id: "22".into(),
        };
        let first = make(1, vec![]);
        assert!(!first.matches(&make(2, vec![])));
        assert!(!first.matches(&make(1, vec![b' '])));
        assert!(first.matches(&make(1, vec![])));
    }
}
