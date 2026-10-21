//! Native-only access to the SAME already initialized service. This does not
//! start the CLI endpoint, grant agent access, register a caller root or mint a
//! replacement Ready/use. Document custody compares its original Ready Arc.
use super::*;

impl ApplicationHost {
    pub(crate) fn native_state_service(
        &self,
        ready: &NativeStateReady,
        current: &NativeProject,
    ) -> Result<Arc<ApplicationService>, Error> {
        let state = self.try_native_lock()?;
        state.available()?;
        if !matches!(state.phase, Phase::Ready | Phase::Listening) {
            return Err(Error::Busy);
        }
        if !Arc::ptr_eq(&self.identity, &ready.owner)
            || state.source_epoch != ready.source_epoch
            || !ready.original.same_input(current)
            || !state
                .registered
                .get(&current.runtime_id)
                .is_some_and(|original| original.same_input(current))
            || !state
                .store
                .as_ref()
                .is_some_and(|store| Arc::ptr_eq(store, &ready.store))
        {
            return Err(Error::Conflict);
        }
        let service = state.service.as_ref().ok_or(Error::Unavailable)?;
        if !Arc::ptr_eq(service.state_directory(), &ready.store) {
            return Err(Error::Conflict);
        }
        Ok(service.clone()) // check AND clone under this one original guard.
    }
}
impl NativeStateReady {
    #[cfg(test)]
    pub(crate) fn closed_apple_census_data() -> Arc<Self> {
        // No Host registration/startup or original Source proof. The actual
        // closed StateDirectory makes this comparison incapable of NativeUse.
        let value = Arc::new(Self {
            owner: Arc::new(()), source_epoch: 0,
            original: NativeProject { runtime_id: "never-registered-census".into(),
                canonical_root: "/never-opened-census".into(), device: 0, inode: 0,
                registration_generation: 0, document_identity: Arc::new(()), input_revision: 0 },
            store: Arc::new(PrivateStateDirectory::closed_apple_census_data()),
            project: ProjectBinding { project_id: p::Id::parse(&"a".repeat(32)).unwrap(),
                canonical_root: "/never-opened-census".into(), device: 0, inode: 0 },
        });
        assert!(value.begin_use().is_err());
        value
    }

    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.original.runtime_id.capacity())?
            .checked_add(self.original.canonical_root.capacity())?
            .checked_add(self.project.project_id.retained_bytes())?
            .checked_add(self.project.canonical_root.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_state_store::Fixture;

    // Actual reference Store/Service, with explicitly synthetic native facts.
    // No native startup/picker, agent grant, private credential or key is used.
    fn ready_data(
        fixture: &Fixture,
    ) -> (ApplicationHost, NativeStateReady, Arc<ApplicationService>) {
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
        let project = NativeProject {
            runtime_id: "inert-project".into(),
            canonical_root: fixture.app.parent().unwrap().join("inert-project"),
            device: 1,
            inode: 2,
            registration_generation: 3,
            document_identity: Arc::new(()),
            input_revision: 4,
        };
        let binding = service
            .register_native(
                &project.runtime_id,
                &project.canonical_root,
                project.device,
                project.inode,
            )
            .unwrap();
        let host = ApplicationHost::new();
        let source_epoch = {
            let mut state = host.control.lock().unwrap();
            state.phase = Phase::Ready;
            state.store = Some(store.clone());
            state.service = Some(service.clone());
            state
                .registered
                .insert(project.runtime_id.clone(), project.clone());
            state.source_epoch
        };
        let ready = NativeStateReady {
            owner: host.identity.clone(),
            source_epoch,
            original: project,
            store,
            project: binding,
        };
        (host, ready, service)
    }
    fn close(ready: NativeStateReady, service: Arc<ApplicationService>) {
        service.stop().unwrap();
        ready.store.close().unwrap();
    }

    #[test]
    fn same_guard_service_access_never_grants_cli_or_accepts_foreign_registration() {
        let fixture = Fixture::new();
        let (host, ready, service) = ready_data(&fixture);
        let current = ready.original.clone();
        assert!(Arc::ptr_eq(
            &host.native_state_service(&ready, &current).unwrap(),
            &service
        ));
        assert!(!host.status().unwrap().enabled);
        for foreign in [
            NativeProject {
                document_identity: Arc::new(()),
                ..current.clone()
            },
            NativeProject {
                registration_generation: 9,
                ..current.clone()
            },
            NativeProject {
                input_revision: 9,
                ..current.clone()
            },
            NativeProject {
                inode: 9,
                ..current.clone()
            },
        ] {
            assert_eq!(
                host.native_state_service(&ready, &foreign).err(),
                Some(Error::Conflict)
            );
        }
        let other = ApplicationHost::new();
        assert!(other.native_state_service(&ready, &current).is_err());
        host.control
            .lock()
            .unwrap()
            .registered
            .remove(&current.runtime_id);
        assert_eq!(
            host.native_state_service(&ready, &current).err(),
            Some(Error::Conflict)
        );
        close(ready, service);
    }

    #[test]
    fn accessor_is_try_only_and_rejects_phase_epoch_and_replaced_original_store() {
        let fixture = Fixture::new();
        let other_fixture = Fixture::new();
        let (host, ready, service) = ready_data(&fixture);
        {
            let _held = host.control.lock().unwrap();
            assert_eq!(
                host.native_state_service(&ready, &ready.original).err(),
                Some(Error::Busy)
            );
        }
        for phase in [
            Phase::Dormant,
            Phase::Starting,
            Phase::Retiring,
            Phase::Closed,
        ] {
            host.control.lock().unwrap().phase = phase;
            assert!(host.native_state_service(&ready, &ready.original).is_err());
        }
        {
            let mut state = host.control.lock().unwrap();
            state.phase = Phase::Listening;
            state.source_epoch += 1;
        }
        assert_eq!(
            host.native_state_service(&ready, &ready.original).err(),
            Some(Error::Conflict)
        );
        let other_store = Arc::new(PrivateStateDirectory::open(&other_fixture.app).unwrap());
        {
            let mut state = host.control.lock().unwrap();
            state.source_epoch = ready.source_epoch;
            state.store = Some(other_store.clone());
        }
        assert_eq!(
            host.native_state_service(&ready, &ready.original).err(),
            Some(Error::Conflict)
        );
        other_store.close().unwrap();
        close(ready, service);
    }

    #[test]
    fn original_ready_use_blocks_store_close_until_explicit_original_retirement() {
        let fixture = Fixture::new();
        let (host, ready, service) = ready_data(&fixture);
        let ready = Arc::new(ready);
        let original = ready.begin_use().unwrap();
        assert!(Arc::ptr_eq(original.store(), ready.store()));
        assert!(host.native_state_service(&ready, &ready.original).is_ok());
        assert_eq!(ready.store.close().err().unwrap().code, Error::Busy);
        assert_eq!(ready.begin_use().err().unwrap().code, Error::Busy);
        ready.store.check_native_use(original.native_use()).unwrap();
        // Synthetic parent-after-joins edge only; this is NOT a proof that a
        // real key producer or its final journal write has joined.
        ready
            .store
            .retire_native_use(original.native_use())
            .unwrap();
        assert_eq!(
            ready
                .store
                .check_native_use(original.native_use())
                .err()
                .unwrap()
                .code,
            Error::Conflict
        );
        drop(original);
        service.stop().unwrap();
        ready.store.close().unwrap();
    }
}
