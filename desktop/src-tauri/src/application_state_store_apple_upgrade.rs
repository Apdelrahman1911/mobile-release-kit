// Included INSIDE application_state_store::native. All operations below use the
// SAME original Book/Directory/flock and the existing no-follow/close helpers.
// There is no opener, arbitrary pathname, repair or automatic upgrade here.

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppleUpgradePoint {
    IntentDurable,
    NamespaceDurable,
    CandidateDurable,
    ReservationRenamed,
    ReservationDurable,
    IntentRemoved,
}

#[cfg(test)]
thread_local! {
    static APPLE_UPGRADE_CUT: std::cell::Cell<Option<AppleUpgradePoint>> = const {
        std::cell::Cell::new(None)
    };
}

fn apple_upgrade_checkpoint(point: AppleUpgradePoint) -> Result<()> {
    #[cfg(test)]
    if APPLE_UPGRADE_CUT.with(|cut| cut.get() == Some(point)) {
        APPLE_UPGRADE_CUT.with(|cut| cut.set(None));
        return Err(StateError::unknown(Effect::Applied));
    }
    let _ = point;
    Ok(())
}

impl PrivateStateDirectory {
    /// Fixed, explicitly consented local schema upgrade, NOT startup/read
    /// behavior. The native parent must retain its original NativeUse before
    /// calling, outside Document/Edit/Host locks, and must join this IO job.
    /// A NativeStateLease is not itself consent to invoke this method.
    pub(crate) fn enable_apple_provisioning(&self, original: &NativeUse) -> Result<Snapshot> {
        let mut book = self.lock()?;
        if !native_use_is_current(&book, original) {
            return Err(Error::Conflict.into());
        }
        Self::enable_apple_provisioning_locked(&mut book)
    }

    // Fixed prerequisite for the explicit Git upgrade. The caller has already
    // checked the SAME NativeUse and retains this SAME Book guard throughout;
    // neither stage reopens the directory or borrows another operation's use.
    fn enable_apple_provisioning_locked(book: &mut Book) -> Result<Snapshot> {
        let preflight = (|| {
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
            // Validate every current original, not only the newly requested
            // namespace. Old revisions and exact encoded bytes are preserved.
            let mut intent = Vec::with_capacity(8 + 32 + 3 * (1 + 8 + 32));
            intent.extend_from_slice(b"MRKAPU01");
            intent.extend_from_slice(&Sha256::digest(RESERVATION));
            let mut apple = None;
            for &namespace in book.version.namespaces() {
                if named(dir, namespace.intent())?.is_some()
                    || named(dir, namespace.candidate())?.is_some()
                {
                    return Err(Error::RecoveryRequired.into());
                }
                let original = *book
                    .originals
                    .get(&namespace)
                    .ok_or_else(|| StateError::from(Error::RecoveryRequired))?;
                let (_, bytes) =
                    read_private(dir, namespace.file(), MAX_BYTES + HEADER, Some(original))?;
                let snapshot = decode(namespace, &bytes)?;
                if namespace == Namespace::AppleProvisioning {
                    apple = Some(snapshot);
                } else {
                    intent.push(namespace.tag());
                    intent.extend_from_slice(&snapshot.revision.0.to_be_bytes());
                    intent.extend_from_slice(&Sha256::digest(&bytes));
                }
            }
            for namespace in [Namespace::AppleProvisioning, Namespace::GitOperations] {
                if !book.version.supports(namespace) {
                    for name in [namespace.file(), namespace.candidate(), namespace.intent()] {
                        if named(dir, name)?.is_some() {
                            return Err(Error::RecoveryRequired.into());
                        }
                    }
                }
            }
            Ok((intent, apple))
        })();
        let (intent_bytes, already_enabled) = match preflight {
            Ok(value) => value,
            Err(error) => {
                book.poisoned = true;
                return Err(error);
            }
        };
        if let Some(snapshot) = already_enabled {
            // Explicitly enabling an already enabled store is only a read;
            // never replace its rows with the initial empty namespace.
            return Ok(snapshot);
        }

        let encoded = encode(Namespace::AppleProvisioning, Revision(0), &[])?;
        let mut effect = Effect::Unknown;
        let result = (|| {
            let dir = book.directory()?.file()?;
            let intent = create_private(dir, APPLE_UPGRADE_INTENT, &intent_bytes)?;
            effect = Effect::Applied;
            sync(dir)?;
            apple_upgrade_checkpoint(AppleUpgradePoint::IntentDurable)?;
            let apple = create_private(dir, Namespace::AppleProvisioning.file(), &encoded)?;
            sync(dir)?;
            apple_upgrade_checkpoint(AppleUpgradePoint::NamespaceDurable)?;
            let candidate = create_private(dir, RESERVATION_V2_CANDIDATE, RESERVATION_V2)?;
            sync(dir)?;
            apple_upgrade_checkpoint(AppleUpgradePoint::CandidateDurable)?;

            book.check()?;
            if named(dir, APPLE_UPGRADE_INTENT)? != Some(intent)
                || named(dir, RESERVATION_V2_CANDIDATE)? != Some(candidate)
                || named(dir, Namespace::AppleProvisioning.file())? != Some(apple)
            {
                return Err(Error::Conflict.into());
            }
            for &namespace in &NAMESPACES {
                if named(dir, namespace.file())? != book.originals.get(&namespace).copied() {
                    return Err(Error::Conflict.into());
                }
            }
            // Original intent is durable BEFORE this irreversible publication.
            fcntl::renameat(dir, RESERVATION_V2_CANDIDATE, dir, "reservation")
                .map_err(|_| StateError::unknown(effect))?;
            apple_upgrade_checkpoint(AppleUpgradePoint::ReservationRenamed)?;
            sync(dir)?;
            let (published, actual) = read_private(dir, "reservation", MAX_RESERVATION_BYTES, None)?;
            let (current_apple, actual_apple) = read_private(
                dir,
                Namespace::AppleProvisioning.file(),
                MAX_BYTES + HEADER,
                Some(apple),
            )?;
            if !published.same_object(candidate)
                || actual != RESERVATION_V2
                || actual_apple != encoded
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
            for &namespace in &NAMESPACES {
                if named(dir, namespace.file())? != book.originals.get(&namespace).copied() {
                    return Err(StateError::unknown(effect));
                }
            }
            apple_upgrade_checkpoint(AppleUpgradePoint::ReservationDurable)?;
            remove_original(dir, APPLE_UPGRADE_INTENT, intent)?;
            apple_upgrade_checkpoint(AppleUpgradePoint::IntentRemoved)?;
            sync(dir)?;
            Ok((published, current_apple))
        })();
        match result {
            Ok((reservation, apple)) => {
                book.reservation = reservation;
                book.version = StoreVersion::V2;
                book.originals.insert(Namespace::AppleProvisioning, apple);
                Ok(Snapshot {
                    revision: Revision(0),
                    bytes: Vec::new(),
                })
            }
            Err(mut error) => {
                // Even a successful reservation rename is not complete when
                // original close/readback/sync/intent cleanup is unconfirmed.
                // Retain every file; no rollback, retry or repair is attempted.
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
mod apple_upgrade_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn old_rows(store: &PrivateStateDirectory) -> Vec<(Namespace, FileKey, Revision, Vec<u8>)> {
        NAMESPACES
            .into_iter()
            .map(|namespace| {
                let snapshot = store.read(namespace).unwrap();
                let original = store.book.lock().unwrap().originals[&namespace];
                (namespace, original, snapshot.revision, snapshot.bytes)
            })
            .collect()
    }

    #[test]
    fn v1_apple_unavailable_does_not_upgrade_or_poison_old_namespaces() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(
            store.read(Namespace::AppleProvisioning).err().unwrap().code,
            Error::Unavailable
        );
        assert_eq!(
            store
                .replace(Namespace::AppleProvisioning, Revision(0), b"not enabled")
                .err()
                .unwrap()
                .code,
            Error::Unavailable
        );
        store
            .replace(
                Namespace::Projects,
                Revision(0),
                b"public synthetic references",
            )
            .unwrap();
        assert_eq!(
            std::fs::read(f.app.join(DIRECTORY).join("reservation")).unwrap(),
            RESERVATION
        );
        assert!(!f
            .app
            .join(DIRECTORY)
            .join(Namespace::AppleProvisioning.file())
            .exists());
        assert!(!store.book.lock().unwrap().poisoned);
        store.close().unwrap();
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(
            reopened.read(Namespace::Projects).unwrap().revision,
            Revision(1)
        );
        assert_eq!(
            reopened
                .read(Namespace::AppleProvisioning)
                .err()
                .unwrap()
                .code,
            Error::Unavailable
        );
        reopened.close().unwrap();
    }

    #[test]
    fn explicit_upgrade_preserves_old_originals_and_same_lock_and_endpoint() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        for namespace in NAMESPACES {
            store
                .replace(namespace, Revision(0), &[namespace.tag()])
                .unwrap();
        }
        let before = old_rows(&store);
        let lock = store.book.lock().unwrap().lock_key;
        store.begin_endpoint().unwrap();
        let native = store.begin_native_use().unwrap();
        let enabled = store.enable_apple_provisioning(&native).unwrap();
        assert_eq!(enabled.revision, Revision(0));
        assert!(enabled.bytes.is_empty());
        assert_eq!(before, old_rows(&store));
        assert_eq!(lock, store.book.lock().unwrap().lock_key);
        assert_eq!(
            PrivateStateDirectory::open(&f.app).err().unwrap().code,
            Error::Busy
        );
        assert_eq!(store.close().err().unwrap().code, Error::Busy);
        store
            .replace(
                Namespace::AppleProvisioning,
                Revision(0),
                b"synthetic reference-only row",
            )
            .unwrap();
        let same = store.enable_apple_provisioning(&native).unwrap();
        assert_eq!(same.revision, Revision(1));
        assert_eq!(same.bytes, b"synthetic reference-only row");
        store.endpoint_settled(true).unwrap();
        assert_eq!(store.close().err().unwrap().code, Error::Busy);
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(before, old_rows(&reopened));
        assert_eq!(
            reopened.read(Namespace::AppleProvisioning).unwrap().bytes,
            same.bytes
        );
        reopened.close().unwrap();
    }

    #[test]
    fn upgrade_cuts_preserve_original_rows_and_refuse_mixed_restart() {
        for point in [
            AppleUpgradePoint::IntentDurable,
            AppleUpgradePoint::NamespaceDurable,
            AppleUpgradePoint::CandidateDurable,
            AppleUpgradePoint::ReservationRenamed,
            AppleUpgradePoint::ReservationDurable,
        ] {
            let f = tests::Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            let before = old_rows(&store);
            let native = store.begin_native_use().unwrap();
            APPLE_UPGRADE_CUT.with(|cut| cut.set(Some(point)));
            let error = store.enable_apple_provisioning(&native).err().unwrap();
            assert_eq!(
                (error.code, error.effect, error.durability),
                (Error::StateUnknown, Effect::Applied, Durability::Unknown)
            );
            assert_eq!(
                store.read(Namespace::Projects).err().unwrap().code,
                Error::RecoveryRequired
            );
            for (namespace, key, revision, bytes) in before {
                let path = f.app.join(DIRECTORY).join(namespace.file());
                assert_eq!(
                    std::fs::read(path).unwrap(),
                    encode(namespace, revision, &bytes).unwrap()
                );
                assert_eq!(store.book.lock().unwrap().originals[&namespace], key);
            }
            store.retire_native_use(&native).unwrap();
            store.close().unwrap();
            assert!(f.app.join(DIRECTORY).join(APPLE_UPGRADE_INTENT).exists());
            assert_eq!(
                PrivateStateDirectory::open(&f.app).err().unwrap().code,
                Error::RecoveryRequired
            );
        }
    }

    #[test]
    fn lost_final_unlink_sync_keeps_live_unknown_without_inventing_restart_receipt() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        APPLE_UPGRADE_CUT.with(|cut| cut.set(Some(AppleUpgradePoint::IntentRemoved)));
        let error = store.enable_apple_provisioning(&native).err().unwrap();
        assert_eq!(error.code, Error::StateUnknown);
        assert_eq!(
            store.enable_apple_provisioning(&native).err().unwrap().code,
            Error::RecoveryRequired
        );
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
        // Exact complete v2 is indistinguishable from an acknowledged upgrade
        // after restart. Reopening validates CURRENT layout only; no receipt of
        // the previous final fsync/operation is reconstructed or returned.
        let reopened = PrivateStateDirectory::open(&f.app).unwrap();
        assert_eq!(
            reopened
                .read(Namespace::AppleProvisioning)
                .unwrap()
                .revision,
            Revision(0)
        );
        reopened.close().unwrap();
    }

    #[test]
    fn missing_v2_and_unexpected_v1_namespace_are_not_empty_initialization() {
        for enabled in [false, true] {
            let f = tests::Fixture::new();
            let store = PrivateStateDirectory::open(&f.app).unwrap();
            if enabled {
                let native = store.begin_native_use().unwrap();
                store.enable_apple_provisioning(&native).unwrap();
                store.retire_native_use(&native).unwrap();
            }
            store.close().unwrap();
            let path = f
                .app
                .join(DIRECTORY)
                .join(Namespace::AppleProvisioning.file());
            if enabled {
                std::fs::rename(&path, path.with_extension("retained")).unwrap();
            } else {
                std::fs::write(
                    &path,
                    encode(Namespace::AppleProvisioning, Revision(0), &[]).unwrap(),
                )
                .unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(PrivateStateDirectory::open(&f.app).is_err());
            assert_eq!(path.exists(), !enabled);
        }
    }

    #[test]
    fn changed_reservation_refuses_upgrade_before_any_new_file() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let native = store.begin_native_use().unwrap();
        let path = f.app.join(DIRECTORY).join("reservation");
        std::fs::rename(&path, path.with_extension("retained")).unwrap();
        std::fs::write(&path, RESERVATION).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            store.enable_apple_provisioning(&native).err().unwrap().code,
            Error::Conflict
        );
        assert!(!f.app.join(DIRECTORY).join(APPLE_UPGRADE_INTENT).exists());
        assert!(!f
            .app
            .join(DIRECTORY)
            .join(Namespace::AppleProvisioning.file())
            .exists());
        store.retire_native_use(&native).unwrap();
        store.close().unwrap();
    }
}
