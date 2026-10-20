// Included INSIDE application_state_store::native. This extends the SAME
// original Book/Directory/flock; it is not a Git command or another journal DB.

#[derive(Clone, Copy, PartialEq, Eq)]
enum GitUpgradePoint {
    AppleReady,
    IntentDurable,
    NamespaceDurable,
    CandidateDurable,
    ReservationRenamed,
    ReservationDurable,
    IntentRemoved,
}

#[cfg(test)]
thread_local! {
    static GIT_UPGRADE_CUT: std::cell::Cell<Option<GitUpgradePoint>> = const {
        std::cell::Cell::new(None)
    };
}

fn git_upgrade_checkpoint(point: GitUpgradePoint) -> Result<()> {
    #[cfg(test)]
    if GIT_UPGRADE_CUT.with(|cut| cut.get() == Some(point)) {
        GIT_UPGRADE_CUT.with(|cut| cut.set(None));
        return Err(StateError::unknown(Effect::Applied));
    }
    let _ = point;
    Ok(())
}

impl PrivateStateDirectory {
    /// Explicit, local Git-state setup only. The genuine native parent must
    /// consent to the fixed schema change and retain/join this IO job using its
    /// original NativeUse, outside Document/Edit/Host locks. Neither the token
    /// nor an agent read grant authorizes Git publication or provider work.
    ///
    /// V1 first completes the existing empty Apple namespace upgrade, under
    /// this SAME Book guard. That prerequisite has no provider effect. A later
    /// failure never rolls it back or reports that no state change occurred.
    pub(crate) fn enable_git_operations(&self, original: &NativeUse) -> Result<Snapshot> {
        let mut book = self.lock()?;
        if !native_use_is_current(&book, original) {
            return Err(Error::Conflict.into());
        }
        let apple_completed = book.version == StoreVersion::V1;
        if apple_completed {
            Self::enable_apple_provisioning_locked(&mut book)?;
            if let Err(error) = git_upgrade_checkpoint(GitUpgradePoint::AppleReady) {
                book.poisoned = true;
                return Err(error);
            }
        }

        let preflight: Result<(Vec<u8>, Option<Snapshot>)> = (|| {
            book.check()?;
            let dir = book.directory()?.file()?;
            for name in UPGRADE_FILES {
                if named(dir, name)?.is_some() {
                    return Err(Error::RecoveryRequired.into());
                }
            }
            let (_, reservation) = read_private(
                dir,
                "reservation",
                MAX_RESERVATION_BYTES,
                Some(book.reservation),
            )?;
            if StoreVersion::parse(&reservation)? != book.version {
                return Err(Error::Conflict.into());
            }
            if !matches!(book.version, StoreVersion::V2 | StoreVersion::V3) {
                return Err(Error::RecoveryRequired.into());
            }

            // Only fixed namespace IDs/revisions and encoded-state digests.
            // No record payloads, source paths or Git command arguments enter
            // this schema-upgrade fence.
            let mut intent = Vec::with_capacity(8 + 32 + 4 * (1 + 8 + 32));
            intent.extend_from_slice(b"MRKGTU01");
            intent.extend_from_slice(&Sha256::digest(RESERVATION_V2));
            let mut git = None;
            for &namespace in book.version.namespaces() {
                if named(dir, namespace.intent())?.is_some()
                    || named(dir, namespace.candidate())?.is_some()
                {
                    return Err(Error::RecoveryRequired.into());
                }
                let held = *book
                    .originals
                    .get(&namespace)
                    .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
                let (_, bytes) =
                    read_private(dir, namespace.file(), MAX_BYTES + HEADER, Some(held))?;
                let snapshot = decode(namespace, &bytes)?;
                if namespace == Namespace::GitOperations {
                    git = Some(snapshot);
                } else {
                    intent.push(namespace.tag());
                    intent.extend_from_slice(&snapshot.revision.0.to_be_bytes());
                    intent.extend_from_slice(&Sha256::digest(&bytes));
                }
            }
            if book.version == StoreVersion::V2 {
                for name in [
                    Namespace::GitOperations.file(),
                    Namespace::GitOperations.candidate(),
                    Namespace::GitOperations.intent(),
                ] {
                    if named(dir, name)?.is_some() {
                        return Err(Error::RecoveryRequired.into());
                    }
                }
            }
            Ok((intent, git))
        })();
        let (intent_bytes, already_enabled) = match preflight {
            Ok(value) => value,
            Err(mut error) => {
                book.poisoned = true;
                if apple_completed {
                    // The prerequisite really committed. The combined request
                    // did not complete, so preserve its applied/unknown result
                    // rather than returning a second-stage no-effect refusal.
                    error.code = Error::StateUnknown;
                    error.effect = Effect::Applied;
                    error.durability = Durability::Unknown;
                }
                return Err(error);
            }
        };
        if let Some(snapshot) = already_enabled {
            // V3 re-enable is only a validated read. Never initialize over an
            // existing operation journal, even when it is currently empty.
            return Ok(snapshot);
        }

        let encoded = encode(Namespace::GitOperations, Revision(0), &[])?;
        let mut effect = if apple_completed {
            Effect::Applied
        } else {
            Effect::Unknown
        };
        let result = (|| {
            let dir = book.directory()?.file()?;
            let intent = create_private(dir, GIT_UPGRADE_INTENT, &intent_bytes)?;
            effect = Effect::Applied;
            sync(dir)?;
            git_upgrade_checkpoint(GitUpgradePoint::IntentDurable)?;
            let git = create_private(dir, Namespace::GitOperations.file(), &encoded)?;
            sync(dir)?;
            git_upgrade_checkpoint(GitUpgradePoint::NamespaceDurable)?;
            let candidate = create_private(dir, RESERVATION_V3_CANDIDATE, RESERVATION_V3)?;
            sync(dir)?;
            git_upgrade_checkpoint(GitUpgradePoint::CandidateDurable)?;

            book.check()?;
            if named(dir, GIT_UPGRADE_INTENT)? != Some(intent)
                || named(dir, RESERVATION_V3_CANDIDATE)? != Some(candidate)
                || named(dir, Namespace::GitOperations.file())? != Some(git)
            {
                return Err(Error::Conflict.into());
            }
            for &namespace in &NAMESPACES_V2 {
                if named(dir, namespace.file())? != book.originals.get(&namespace).copied() {
                    return Err(Error::Conflict.into());
                }
            }
            fcntl::renameat(dir, RESERVATION_V3_CANDIDATE, dir, "reservation")
                .map_err(|_| StateError::unknown(effect))?;
            git_upgrade_checkpoint(GitUpgradePoint::ReservationRenamed)?;
            sync(dir)?;
            let (published, actual) =
                read_private(dir, "reservation", MAX_RESERVATION_BYTES, None)?;
            let (current_git, actual_git) = read_private(
                dir,
                Namespace::GitOperations.file(),
                MAX_BYTES + HEADER,
                Some(git),
            )?;
            if !published.same_object(candidate)
                || actual != RESERVATION_V3
                || actual_git != encoded
            {
                return Err(StateError::unknown(effect));
            }
            book.directory()?.check()?;
            let lock = book
                .lock
                .as_ref()
                .ok_or_else(|| StateError::from(Error::StateUnknown))?;
            if key(lock)? != book.lock_key || named(dir, "owner.lock")? != Some(book.lock_key) {
                return Err(StateError::unknown(effect));
            }
            for &namespace in &NAMESPACES_V2 {
                if named(dir, namespace.file())? != book.originals.get(&namespace).copied() {
                    return Err(StateError::unknown(effect));
                }
            }
            git_upgrade_checkpoint(GitUpgradePoint::ReservationDurable)?;
            remove_original(dir, GIT_UPGRADE_INTENT, intent)?;
            git_upgrade_checkpoint(GitUpgradePoint::IntentRemoved)?;
            sync(dir)?;
            Ok((published, current_git))
        })();
        match result {
            Ok((reservation, git)) => {
                book.reservation = reservation;
                book.version = StoreVersion::V3;
                book.originals.insert(Namespace::GitOperations, git);
                Ok(Snapshot {
                    revision: Revision(0),
                    bytes: Vec::new(),
                })
            }
            Err(mut error) => {
                // Do not erase partial publications or turn a final unlink
                // into a receipt of the directory sync that did not return.
                book.poisoned = true;
                error.code = Error::StateUnknown;
                error.effect = effect;
                error.durability = Durability::Unknown;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod git_upgrade_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    // Compare the actual original encoded files, not a reconstructed semantic
    // empty state. This helper also observes retained files after a live fence;
    // it does not restore the poisoned Store or grant production read access.
    fn original_rows(
        store: &PrivateStateDirectory,
        namespaces: &[Namespace],
    ) -> Vec<(Namespace, FileKey, Vec<u8>)> {
        let book = store.book.lock().unwrap();
        let dir = book.directory().unwrap().file().unwrap();
        namespaces
            .iter()
            .map(|&namespace| {
                let (key, bytes) = read_private(
                    dir,
                    namespace.file(),
                    MAX_BYTES + HEADER,
                    Some(book.originals[&namespace]),
                )
                .unwrap();
                (namespace, key, bytes)
            })
            .collect()
    }

    fn seed_rows(store: &PrivateStateDirectory, namespaces: &[Namespace]) {
        for &namespace in namespaces {
            store
                .replace(namespace, Revision(0), &[namespace.tag(), 1])
                .unwrap();
            store
                .replace(namespace, Revision(1), &[namespace.tag(), 2])
                .unwrap();
        }
    }

    fn private_fixture_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn ordinary_v1_and_v2_git_reads_do_not_enable_or_poison_state() {
        for apple_enabled in [false, true] {
            let f = tests::Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            if apple_enabled {
                let native = store.begin_native_use().unwrap();
                store.enable_apple_provisioning(&native).unwrap();
                store.retire_native_use(&native).unwrap();
            }
            let names = if apple_enabled {
                &NAMESPACES_V2[..]
            } else {
                &NAMESPACES[..]
            };
            seed_rows(&store, names);
            let before = original_rows(&store, names);
            assert_eq!(
                store.read(Namespace::GitOperations).err().unwrap().code,
                Error::Unavailable
            );
            assert_eq!(
                store
                    .replace(Namespace::GitOperations, Revision(0), b"not enabled")
                    .err()
                    .unwrap()
                    .code,
                Error::Unavailable
            );
            assert!(!store.book.lock().unwrap().poisoned);
            assert_eq!(before, original_rows(&store, names));
            let expected = if apple_enabled {
                RESERVATION_V2
            } else {
                RESERVATION
            };
            assert_eq!(
                std::fs::read(f.app.join(DIRECTORY).join("reservation")).unwrap(),
                expected
            );
            assert!(!f
                .app
                .join(DIRECTORY)
                .join(Namespace::GitOperations.file())
                .exists());
            store.close().unwrap();
            let reopened = PrivateStateDirectory::open(&f.app).unwrap();
            assert_eq!(before, original_rows(&reopened, names));
            assert_eq!(
                reopened.read(Namespace::GitOperations).err().unwrap().code,
                Error::Unavailable
            );
            reopened.close().unwrap();
        }
    }

    #[test]
    fn v1_to_v3_preserves_originals_and_both_reenable_paths_are_read_only() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        seed_rows(&store, &NAMESPACES);
        let old = original_rows(&store, &NAMESPACES);
        let lock = store.book.lock().unwrap().lock_key;
        store.begin_endpoint().unwrap();
        let native = store.begin_native_use().unwrap();
        let first = store.enable_git_operations(&native).unwrap();
        assert_eq!(first.revision, Revision(0));
        assert!(first.bytes.is_empty());
        assert_eq!(old, original_rows(&store, &NAMESPACES));
        assert_eq!(
            store.read(Namespace::AppleProvisioning).unwrap().revision,
            Revision(0)
        );
        assert!(store
            .read(Namespace::AppleProvisioning)
            .unwrap()
            .bytes
            .is_empty());
        assert_eq!(lock, store.book.lock().unwrap().lock_key);
        assert_eq!(
            PrivateStateDirectory::open(&f.app).err().unwrap().code,
            Error::Busy
        );
        seed_rows(
            &store,
            &[Namespace::AppleProvisioning, Namespace::GitOperations],
        );
        let all = original_rows(&store, &NAMESPACES_V3);
        let reservation = store.book.lock().unwrap().reservation;
        assert_eq!(
            store.enable_git_operations(&native).unwrap().revision,
            Revision(2)
        );
        assert_eq!(
            store.enable_apple_provisioning(&native).unwrap().revision,
            Revision(2)
        );
        assert_eq!(all, original_rows(&store, &NAMESPACES_V3));
        assert_eq!(reservation, store.book.lock().unwrap().reservation);
        assert_eq!(
            std::fs::read(f.app.join(DIRECTORY).join("reservation")).unwrap(),
            RESERVATION_V3
        );
        assert_eq!(
            store
                .replace(Namespace::GitOperations, Revision(1), b"stale")
                .err()
                .unwrap()
                .code,
            Error::Conflict
        );
        assert!(!store.book.lock().unwrap().poisoned);
        assert_eq!(store.close().err().unwrap().code, Error::Busy);
        store.endpoint_settled(true).unwrap();
        assert_eq!(store.close().err().unwrap().code, Error::Busy);
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(all, original_rows(&reopened, &NAMESPACES_V3));
        let native = reopened.begin_native_use().unwrap();
        assert_eq!(
            reopened.enable_apple_provisioning(&native).unwrap().bytes,
            [4, 2]
        );
        assert_eq!(
            reopened.enable_git_operations(&native).unwrap().bytes,
            [5, 2]
        );
        assert_eq!(all, original_rows(&reopened, &NAMESPACES_V3));
        reopened
            .replace(
                Namespace::GitOperations,
                Revision(2),
                b"retained publication reference",
            )
            .unwrap();
        reopened.retire_native_use(&native).unwrap();
        reopened.close().unwrap();
        let final_store = PrivateStateDirectory::open(&f.app).unwrap();
        let final_row = final_store.read(Namespace::GitOperations).unwrap();
        assert_eq!(final_row.revision, Revision(3));
        assert_eq!(final_row.bytes, b"retained publication reference");
        final_store.close().unwrap();
    }

    #[test]
    fn v2_to_v3_preserves_all_four_nonempty_originals() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        store.enable_apple_provisioning(&native).unwrap();
        seed_rows(&store, &NAMESPACES_V2);
        let before = original_rows(&store, &NAMESPACES_V2);
        let enabled = store.enable_git_operations(&native).unwrap();
        assert_eq!(enabled.revision, Revision(0));
        assert!(enabled.bytes.is_empty());
        assert_eq!(before, original_rows(&store, &NAMESPACES_V2));
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(before, original_rows(&reopened, &NAMESPACES_V2));
        assert_eq!(
            reopened.read(Namespace::GitOperations).unwrap().revision,
            Revision(0)
        );
        reopened.close().unwrap();
    }

    #[test]
    fn wrong_or_retired_native_use_cannot_start_either_upgrade() {
        let a = tests::Fixture::new();
        let b = tests::Fixture::new();
        let first = PrivateStateDirectory::open(&a.app).unwrap();
        let second = PrivateStateDirectory::open(&b.app).unwrap();
        let native = first.begin_native_use().unwrap();
        let other = second.begin_native_use().unwrap();
        assert_eq!(
            first.enable_git_operations(&other).err().unwrap().code,
            Error::Conflict
        );
        assert!(!first.book.lock().unwrap().poisoned);
        first.retire_native_use(&native).unwrap();
        assert_eq!(
            first.enable_git_operations(&native).err().unwrap().code,
            Error::Conflict
        );
        assert_eq!(
            std::fs::read(a.app.join(DIRECTORY).join("reservation")).unwrap(),
            RESERVATION
        );
        assert!(!a
            .app
            .join(DIRECTORY)
            .join(Namespace::AppleProvisioning.file())
            .exists());
        assert!(!a
            .app
            .join(DIRECTORY)
            .join(Namespace::GitOperations.file())
            .exists());
        first.close().unwrap();
        second.retire_native_use(&other).unwrap();
        second.close().unwrap();
    }

    #[test]
    fn each_durable_cut_retains_old_rows_and_rejects_mixed_restart() {
        for point in [
            GitUpgradePoint::IntentDurable,
            GitUpgradePoint::NamespaceDurable,
            GitUpgradePoint::CandidateDurable,
            GitUpgradePoint::ReservationRenamed,
            GitUpgradePoint::ReservationDurable,
        ] {
            let f = tests::Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            let native = store.begin_native_use().unwrap();
            store.enable_apple_provisioning(&native).unwrap();
            seed_rows(&store, &NAMESPACES_V2);
            let before = original_rows(&store, &NAMESPACES_V2);
            GIT_UPGRADE_CUT.with(|cut| cut.set(Some(point)));
            let error = store.enable_git_operations(&native).err().unwrap();
            assert_eq!(
                (error.code, error.effect, error.durability),
                (Error::StateUnknown, Effect::Applied, Durability::Unknown)
            );
            assert_eq!(
                store.read(Namespace::Projects).err().unwrap().code,
                Error::RecoveryRequired
            );
            assert_eq!(before, original_rows(&store, &NAMESPACES_V2));
            assert!(f.app.join(DIRECTORY).join(GIT_UPGRADE_INTENT).exists());
            assert_eq!(store.close().err().unwrap().code, Error::Busy);
            store.retire_native_use(&native).unwrap();
            store.close().unwrap();
            assert_eq!(
                PrivateStateDirectory::open(&f.app).err().unwrap().code,
                Error::RecoveryRequired
            );
        }
    }

    #[test]
    fn lost_final_sync_keeps_live_unknown_but_reopen_only_checks_current_v3() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        GIT_UPGRADE_CUT.with(|cut| cut.set(Some(GitUpgradePoint::IntentRemoved)));
        let error = store.enable_git_operations(&native).err().unwrap();
        assert_eq!(
            (error.code, error.effect, error.durability),
            (Error::StateUnknown, Effect::Applied, Durability::Unknown)
        );
        assert_eq!(
            store.enable_git_operations(&native).err().unwrap().code,
            Error::RecoveryRequired
        );
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        // No previous-operation receipt is reconstructed by this successful
        // current-layout read. The original operation remained unacknowledged.
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(
            reopened.read(Namespace::GitOperations).unwrap().revision,
            Revision(0)
        );
        let before = original_rows(&reopened, &NAMESPACES_V3);
        let native = reopened.begin_native_use().unwrap();
        reopened.enable_git_operations(&native).unwrap();
        reopened.enable_apple_provisioning(&native).unwrap();
        assert_eq!(before, original_rows(&reopened, &NAMESPACES_V3));
        reopened.retire_native_use(&native).unwrap();
        reopened.close().unwrap();
    }

    #[test]
    fn completed_apple_prerequisite_is_not_rolled_back_or_reported_no_effect() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        seed_rows(&store, &NAMESPACES);
        let before = original_rows(&store, &NAMESPACES);
        let native = store.begin_native_use().unwrap();
        GIT_UPGRADE_CUT.with(|cut| cut.set(Some(GitUpgradePoint::AppleReady)));
        let error = store.enable_git_operations(&native).err().unwrap();
        assert_eq!(
            (error.code, error.effect, error.durability),
            (Error::StateUnknown, Effect::Applied, Durability::Unknown)
        );
        assert_eq!(before, original_rows(&store, &NAMESPACES));
        assert_eq!(
            std::fs::read(f.app.join(DIRECTORY).join("reservation")).unwrap(),
            RESERVATION_V2
        );
        assert!(!f.app.join(DIRECTORY).join(GIT_UPGRADE_INTENT).exists());
        assert!(!f
            .app
            .join(DIRECTORY)
            .join(Namespace::GitOperations.file())
            .exists());
        assert_eq!(
            store.enable_git_operations(&native).err().unwrap().code,
            Error::RecoveryRequired
        );
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(before, original_rows(&reopened, &NAMESPACES));
        assert_eq!(
            reopened
                .read(Namespace::AppleProvisioning)
                .unwrap()
                .revision,
            Revision(0)
        );
        assert_eq!(
            reopened.read(Namespace::GitOperations).err().unwrap().code,
            Error::Unavailable
        );
        reopened.close().unwrap();
    }

    #[test]
    fn uncertain_apple_prerequisite_never_starts_git_phase() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let before = original_rows(&store, &NAMESPACES);
        let native = store.begin_native_use().unwrap();
        APPLE_UPGRADE_CUT.with(|cut| cut.set(Some(AppleUpgradePoint::ReservationRenamed)));
        let error = store.enable_git_operations(&native).err().unwrap();
        assert_eq!(
            (error.code, error.effect, error.durability),
            (Error::StateUnknown, Effect::Applied, Durability::Unknown)
        );
        assert_eq!(before, original_rows(&store, &NAMESPACES));
        assert!(!f.app.join(DIRECTORY).join(GIT_UPGRADE_INTENT).exists());
        assert!(!f
            .app
            .join(DIRECTORY)
            .join(Namespace::GitOperations.file())
            .exists());
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        assert_eq!(
            PrivateStateDirectory::open(&f.app).err().unwrap().code,
            Error::RecoveryRequired
        );
    }

    #[test]
    fn fixed_name_collisions_are_preserved_without_implicit_apple_setup() {
        for apple_enabled in [false, true] {
            for name in [
                GIT_UPGRADE_INTENT,
                RESERVATION_V3_CANDIDATE,
                Namespace::GitOperations.file(),
                Namespace::GitOperations.candidate(),
                Namespace::GitOperations.intent(),
            ] {
                let f = tests::Fixture::new();
                let store = PrivateStateDirectory::open(&f.app).unwrap();
                let native = store.begin_native_use().unwrap();
                if apple_enabled {
                    store.enable_apple_provisioning(&native).unwrap();
                }
                let names = if apple_enabled {
                    &NAMESPACES_V2[..]
                } else {
                    &NAMESPACES[..]
                };
                let before = original_rows(&store, names);
                let path = f.app.join(DIRECTORY).join(name);
                private_fixture_file(&path, b"foreign synthetic state");
                assert_eq!(
                    store.enable_git_operations(&native).err().unwrap().code,
                    Error::RecoveryRequired
                );
                assert_eq!(std::fs::read(&path).unwrap(), b"foreign synthetic state");
                assert_eq!(before, original_rows(&store, names));
                let expected = if apple_enabled {
                    RESERVATION_V2
                } else {
                    RESERVATION
                };
                assert_eq!(
                    std::fs::read(f.app.join(DIRECTORY).join("reservation")).unwrap(),
                    expected
                );
                if !apple_enabled {
                    assert!(!f
                        .app
                        .join(DIRECTORY)
                        .join(Namespace::AppleProvisioning.file())
                        .exists());
                }
                store.retire_native_use(&native).unwrap();
                store.close().unwrap();
                assert_eq!(
                    PrivateStateDirectory::open(&f.app).err().unwrap().code,
                    Error::RecoveryRequired
                );
            }
        }
    }

    #[test]
    fn v3_missing_any_established_namespace_never_reinitializes_it() {
        for missing in NAMESPACES_V3 {
            let f = tests::Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            let native = store.begin_native_use().unwrap();
            store.enable_git_operations(&native).unwrap();
            seed_rows(&store, &NAMESPACES_V3);
            store.retire_native_use(&native).unwrap();
            store.close().unwrap();
            let path = f.app.join(DIRECTORY).join(missing.file());
            let retained = path.with_extension("retained");
            let bytes = std::fs::read(&path).unwrap();
            std::fs::rename(&path, &retained).unwrap();
            assert!(PrivateStateDirectory::open(&f.app).is_err());
            assert!(!path.exists());
            assert_eq!(std::fs::read(retained).unwrap(), bytes);
        }
    }

    #[test]
    fn v3_reenable_and_restart_refuse_every_unfinished_upgrade_marker() {
        for name in UPGRADE_FILES {
            for enable_apple in [false, true] {
                let f = tests::Fixture::new();
                let store = PrivateStateDirectory::open(&f.app).unwrap();
                let native = store.begin_native_use().unwrap();
                store.enable_git_operations(&native).unwrap();
                seed_rows(&store, &NAMESPACES_V3);
                let before = original_rows(&store, &NAMESPACES_V3);
                let path = f.app.join(DIRECTORY).join(name);
                private_fixture_file(&path, b"unresolved synthetic upgrade");
                let result = if enable_apple {
                    store.enable_apple_provisioning(&native)
                } else {
                    store.enable_git_operations(&native)
                };
                assert_eq!(result.err().unwrap().code, Error::RecoveryRequired);
                assert_eq!(before, original_rows(&store, &NAMESPACES_V3));
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    b"unresolved synthetic upgrade"
                );
                store.retire_native_use(&native).unwrap();
                store.close().unwrap();
                assert_eq!(
                    PrivateStateDirectory::open(&f.app).err().unwrap().code,
                    Error::RecoveryRequired
                );
            }
        }
    }

    #[test]
    fn v3_cannot_adopt_an_old_namespace_header_as_git_state() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        store.enable_git_operations(&native).unwrap();
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        let path = f.app.join(DIRECTORY).join(Namespace::GitOperations.file());
        let wrong_tag = encode(Namespace::Projects, Revision(0), &[]).unwrap();
        private_fixture_file(&path, &wrong_tag);
        assert_eq!(
            PrivateStateDirectory::open(&f.app).err().unwrap().code,
            Error::RecoveryRequired
        );
        assert_eq!(std::fs::read(path).unwrap(), wrong_tag);
    }

    #[test]
    fn changed_original_or_symlink_refuses_before_git_write() {
        for name in [
            "reservation",
            Namespace::Projects.file(),
            Namespace::AppleProvisioning.file(),
        ] {
            for use_symlink in [false, true] {
                let f = tests::Fixture::new();
                let store = PrivateStateDirectory::open(&f.app).unwrap();
                let native = store.begin_native_use().unwrap();
                store.enable_apple_provisioning(&native).unwrap();
                let path = f.app.join(DIRECTORY).join(name);
                let bytes = std::fs::read(&path).unwrap();
                let retained = path.with_extension("retained");
                std::fs::rename(&path, &retained).unwrap();
                if use_symlink {
                    symlink(&retained, &path).unwrap();
                } else {
                    private_fixture_file(&path, &bytes);
                }
                assert!(store.enable_git_operations(&native).is_err());
                assert!(store.book.lock().unwrap().poisoned);
                assert!(!f.app.join(DIRECTORY).join(GIT_UPGRADE_INTENT).exists());
                assert!(!f
                    .app
                    .join(DIRECTORY)
                    .join(Namespace::GitOperations.file())
                    .exists());
                assert_eq!(std::fs::read(&retained).unwrap(), bytes);
                store.retire_native_use(&native).unwrap();
                store.close().unwrap();
            }
        }
    }

    #[test]
    fn unknown_original_read_close_fences_before_upgrade_creation() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        store.enable_apple_provisioning(&native).unwrap();
        READ_CLOSE_UNKNOWN.with(|cut| cut.set(true));
        let error = store.enable_git_operations(&native).err().unwrap();
        assert_eq!(
            (error.code, error.effect, error.cleanup),
            (Error::StateUnknown, Effect::None, Cleanup::Unknown)
        );
        assert!(store.book.lock().unwrap().poisoned);
        assert!(!f.app.join(DIRECTORY).join(GIT_UPGRADE_INTENT).exists());
        assert_eq!(
            store.read(Namespace::AppleProvisioning).err().unwrap().code,
            Error::RecoveryRequired
        );
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
    }

    #[test]
    fn intent_created_before_failed_write_is_retained_as_unknown() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        store.enable_apple_provisioning(&native).unwrap();
        let before = original_rows(&store, &NAMESPACES_V2);
        CREATE_PRE_SYNC_REFUSAL.with(|cut| cut.set(true));
        let error = store.enable_git_operations(&native).err().unwrap();
        assert_eq!(
            (error.code, error.effect, error.durability),
            (Error::StateUnknown, Effect::Unknown, Durability::Unknown)
        );
        assert_eq!(before, original_rows(&store, &NAMESPACES_V2));
        assert_eq!(
            std::fs::read(f.app.join(DIRECTORY).join(GIT_UPGRADE_INTENT)).unwrap(),
            b""
        );
        assert!(!f
            .app
            .join(DIRECTORY)
            .join(Namespace::GitOperations.file())
            .exists());
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        assert_eq!(
            PrivateStateDirectory::open(&f.app).err().unwrap().code,
            Error::RecoveryRequired
        );
    }
}
