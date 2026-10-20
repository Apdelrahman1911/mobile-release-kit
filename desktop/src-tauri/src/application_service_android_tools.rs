//! Projection of the SAME catalogue Status already returned to the native
//! Desktop relay. No socket/client invokes a Document or native tool method.
use super::{ApplicationHost, Phase as HostPhase};
use crate::{
    android_build_protocol as build, android_toolchain_catalog as native,
    service_android_tools as data, service_protocol::Error,
};

/// Typed native DATA only; this is not an input from a renderer or CLI.
fn project(status: &native::Status) -> Option<data::Catalogue> {
    if status.schema_version != 1
        || !(1..u32::MAX).contains(&status.status_revision)
        || status.catalog_generation == u32::MAX
        || status.entries.len() > data::ROW_LIMIT
        || status.operation_id.as_ref().is_some_and(|id| {
            id.len() != 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return None;
    }
    // Complete bounded native row validation precedes the small projection.
    // Hashes/UID participate only in exact selected-row comparison below.
    for (index, row) in status.entries.iter().enumerate() {
        if !row.valid(status.catalog_generation)
            || status.entries[..index]
                .iter()
                .any(|old| old.instance == row.instance)
        {
            return None;
        }
    }
    let availability = match status.availability {
        build::Availability::Available => data::Availability::Available,
        build::Availability::Busy => data::Availability::Busy,
        build::Availability::Shutdown => data::Availability::Shutdown,
        build::Availability::CleanupUnknown => data::Availability::CleanupUnknown,
        build::Availability::DocumentLost => data::Availability::DocumentLost,
        build::Availability::UnsupportedPlatform => data::Availability::UnsupportedPlatform,
        build::Availability::RuntimeUnqualified => data::Availability::RuntimeUnqualified,
        build::Availability::ToolchainUnqualified => data::Availability::ToolchainUnqualified,
    };
    let phase = match status.phase {
        native::Phase::Idle => data::Phase::Idle,
        native::Phase::Reading => data::Phase::Reading,
        native::Phase::Stopping => data::Phase::Stopping,
        native::Phase::Ready => data::Phase::Ready,
        native::Phase::Refused => data::Phase::Refused,
        native::Phase::Cancelled => data::Phase::Cancelled,
        native::Phase::Unknown => data::Phase::Unknown,
    };
    let reason = match status.reason {
        native::Reason::None => data::Reason::None,
        native::Reason::NotInspected => data::Reason::NotInspected,
        native::Reason::Cancelled => data::Reason::Cancelled,
        native::Reason::TimedOut => data::Reason::TimedOut,
        native::Reason::DocumentLost => data::Reason::DocumentLost,
        native::Reason::Shutdown => data::Reason::Shutdown,
        native::Reason::CatalogChanged => data::Reason::CatalogChanged,
        native::Reason::CatalogUnavailable => data::Reason::CatalogUnavailable,
        native::Reason::CleanupUnknown => data::Reason::CleanupUnknown,
    };
    let unknown = phase == data::Phase::Unknown
        || reason == data::Reason::CleanupUnknown
        || availability == data::Availability::CleanupUnknown;
    let observed_selection = match status.selected.as_ref().filter(|_| !unknown) {
        None => None,
        Some(selected) => {
            if phase != data::Phase::Ready
                || !selected.valid()
                || selected.catalog_generation != status.catalog_generation
            {
                return None;
            }
            let row = status.entries.iter().find(|row| {
                row.status == native::RowStatus::VerifiedThisSession
                    && row.selection.as_ref() == Some(selected)
            })?;
            let v = row.versions.as_ref()?;
            Some(data::Selected {
                instance: selected.instance.clone(),
                versions: data::Versions {
                    jdk_vendor: v.jdk_vendor.clone(),
                    jdk_version: v.jdk_version.clone(),
                    gradle_version: v.gradle_version.clone(),
                    agp_version: v.agp_version.clone(),
                    sdk_platform: v.sdk_platform.clone(),
                    sdk_build_tools_version: v.sdk_build_tools_version.clone(),
                },
            })
        }
    };
    let result = data::Catalogue {
        status_revision: status.status_revision,
        catalog_generation: status.catalog_generation,
        availability,
        phase,
        reason,
        row_count: u8::try_from(status.entries.len()).ok()?,
        observed_selection,
    };
    result.validate().ok()?;
    Some(result)
}

impl ApplicationHost {
    /// The existing retained relay calls this only AFTER the original native
    /// status method returned and dropped its Document/registry guards.
    pub(crate) fn publish_android_tools_catalogue(&self, status: &native::Status) {
        let initialized = match self.try_native_lock() {
            Ok(state) => {
                state.available().is_ok()
                    && state.service.is_some()
                    && matches!(state.phase, HostPhase::Ready | HostPhase::Listening)
            }
            Err(Error::Busy) => return, // Historical observation, never a currentness promise.
            Err(_) => {
                self.android_tools.unavailable();
                return;
            }
        }; // No Host or Service-state lock crosses projection/publication.
        if !initialized {
            return;
        }
        match project(status) {
            Some(observation) => self.android_tools.publish(observation),
            None => self.android_tools.unavailable(),
        }
    }
    /// Bounded memory-only loss barrier. In particular it never waits behind
    /// an older Host/Service caller's storage IO or constructs a dormant host.
    pub(crate) fn android_tools_relay_lost(&self) {
        self.android_tools.unavailable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_protocol::Id;

    fn selected() -> native::Status {
        let selection = build::MacToolchainSelection {
            instance: "a".repeat(32),
            owner_uid: 501,
            catalog_generation: 1,
            record_sha256: "b".repeat(64),
            inventory_sha256: "c".repeat(64),
            os_provider_sha256: "d".repeat(64),
        };
        native::Status {
            schema_version: 1,
            status_revision: 1,
            catalog_generation: 1,
            operation_id: Some("e".repeat(32)),
            availability: build::Availability::Available,
            phase: native::Phase::Ready,
            reason: native::Reason::None,
            entries: vec![native::Row {
                instance: selection.instance.clone(),
                occupants: 7,
                status: native::RowStatus::VerifiedThisSession,
                recovery: None,
                versions: Some(native::Versions {
                    jdk_vendor: "Example".into(),
                    jdk_version: "21".into(),
                    gradle_version: "8.13".into(),
                    agp_version: "8.9.2".into(),
                    sdk_platform: "35".into(),
                    sdk_build_tools_version: "35.0.0".into(),
                }),
                selection: Some(selection.clone()),
            }],
            selected: Some(selection),
        }
    }
    #[test]
    fn selected_versions_require_exact_original_row_and_drop_private_comparisons() {
        let status = selected();
        let value = project(&status).unwrap();
        assert_eq!(
            value
                .observed_selection
                .as_ref()
                .unwrap()
                .versions
                .gradle_version,
            "8.13"
        );
        let encoded = String::from_utf8(serde_json::to_vec(&value).unwrap()).unwrap();
        for omitted in [
            "ownerUid",
            "operationId",
            "recordSha256",
            "inventorySha256",
            "osProviderSha256",
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(32),
        ] {
            assert!(!encoded.contains(omitted));
        }
        for field in 0..4 {
            let mut changed = status.clone();
            let source = changed.selected.as_mut().unwrap();
            match field {
                0 => source.owner_uid += 1,
                1 => source.record_sha256 = "f".repeat(64),
                2 => source.inventory_sha256 = "f".repeat(64),
                _ => source.os_provider_sha256 = "f".repeat(64),
            }
            assert!(project(&changed).is_none());
        }
    }
    #[test]
    fn metadata_recovery_never_becomes_selected_or_project_compatibility() {
        let mut status = selected();
        let selection = status.selected.take().unwrap();
        let row = &mut status.entries[0];
        row.status = native::RowStatus::RecoveryRequired;
        row.selection = None;
        row.recovery = Some(native::Comparison::of(&selection));
        let value = project(&status).unwrap();
        assert_eq!(value.row_count, 1);
        assert!(value.observed_selection.is_none());
        status.selected = Some(selection);
        assert!(project(&status).is_none());
    }
    #[test]
    fn unknown_idle_and_bad_native_rows_do_not_claim_tools_ready() {
        let mut status = selected();
        status.phase = native::Phase::Unknown;
        status.reason = native::Reason::CleanupUnknown;
        status.availability = build::Availability::CleanupUnknown;
        let unknown = project(&status).unwrap();
        assert_eq!(unknown.phase, data::Phase::Unknown);
        assert!(unknown.observed_selection.is_none());
        status = selected();
        status.phase = native::Phase::Idle;
        status.reason = native::Reason::NotInspected;
        status.catalog_generation = 0;
        status.operation_id = None;
        status.entries.clear();
        status.selected = None;
        status.availability = build::Availability::UnsupportedPlatform;
        let idle = project(&status).unwrap();
        assert_eq!(idle.phase, data::Phase::Idle);
        assert_eq!(idle.availability, data::Availability::UnsupportedPlatform);
        let mut duplicated = selected();
        duplicated.entries.push(duplicated.entries[0].clone());
        assert!(project(&duplicated).is_none());
        let mut oversized = selected();
        oversized.entries = vec![oversized.entries[0].clone(); data::ROW_LIMIT + 1];
        assert!(project(&oversized).is_none());
        let mut bad = selected();
        bad.entries[0].versions.as_mut().unwrap().jdk_vendor = "/private/sentinel".into();
        assert!(project(&bad).is_none());
    }
    #[test]
    fn dormant_host_and_busy_control_never_start_or_queue_a_catalogue_operation() {
        let host = ApplicationHost::new();
        let id = Id::parse(&"1".repeat(32)).unwrap();
        host.publish_android_tools_catalogue(&selected());
        assert_eq!(
            host.android_tools.view(id.clone()).capture,
            data::Capture::Unobserved
        );
        let guard = host.control.lock().unwrap();
        host.publish_android_tools_catalogue(&selected()); // Must return while this actual guard is held.
        host.android_tools_relay_lost(); // Same loss barrier remains independent of Control.
        assert!(
            guard.service.is_none() && guard.store.is_none() && guard.phase == HostPhase::Dormant
        );
        drop(guard);
        assert_eq!(
            host.android_tools.view(id).capture,
            data::Capture::Unavailable
        );
    }
    #[test]
    fn initialized_service_shares_the_cell_without_a_service_lock_or_write() {
        use crate::{
            application_service::{tests::with_state_locked, ApplicationService},
            application_state_store::{Fixture, Namespace, PrivateStateDirectory},
        };
        use std::sync::Arc;
        let f = Fixture::new();
        let host = ApplicationHost::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = Arc::new(
            ApplicationService::open_with_android_tools(store.clone(), host.android_tools.clone())
                .unwrap(),
        );
        // Actual Store/Service fixture only. This does not qualify native
        // startup, a selected tool, or an original catalogue operation.
        {
            let mut control = host.control.lock().unwrap();
            control.service = Some(service.clone());
            control.phase = HostPhase::Ready;
        }
        let before = store.read(Namespace::Projects).unwrap();
        with_state_locked(&service, || {
            host.publish_android_tools_catalogue(&selected())
        });
        assert_eq!(
            host.android_tools
                .view(Id::parse(&"1".repeat(32)).unwrap())
                .capture,
            data::Capture::Observed
        );
        with_state_locked(&service, || host.android_tools_relay_lost());
        assert!(!service.read_access_status().unwrap().enabled);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!(before.revision, after.revision);
        assert_eq!(before.bytes, after.bytes);
        service.stop().unwrap();
        store.close().unwrap();
    }
}
