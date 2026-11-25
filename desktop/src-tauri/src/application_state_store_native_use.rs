// Included INSIDE application_state_store::native. This is a lifetime guard on
// the same original Book, not another filesystem owner or an execution receipt.

/// Original native-use reservation. Only the actual parent retains this token;
/// its all-jobs-joined gate may retire it. Dropping it does NOT settle anything.
/// In particular, a pre-final-journal-CAS witness cannot release this guard.
pub(crate) struct NativeUse {
    identity: std::sync::Arc<()>,
}

fn native_use_is_current(book: &Book, original: &NativeUse) -> bool {
    book.native_use
        .as_ref()
        .is_some_and(|held| std::sync::Arc::ptr_eq(held, &original.identity))
}

impl PrivateStateDirectory {
    /// Call off Document/Edit/Host locks and retain before releasing any job.
    pub(crate) fn begin_native_use(&self) -> Result<NativeUse> {
        let mut book = self.lock()?;
        book.check()?;
        if book.native_use.is_some() {
            return Err(Error::Busy.into());
        }
        let identity = std::sync::Arc::new(());
        book.native_use = Some(identity.clone());
        Ok(NativeUse { identity })
    }

    /// Same original use only; no filesystem IO or grant. The fixed journal
    /// port calls this before its ordinary Store read/replace. Actual parent
    /// admission seals its finite job roster before retiring the use, so a
    /// late unregistered writer cannot borrow an already settled token.
    pub(crate) fn check_native_use(&self, original: &NativeUse) -> Result<()> {
        let book = self.lock()?;
        if native_use_is_current(&book, original) {
            Ok(())
        } else {
            Err(Error::Conflict.into())
        }
    }

    /// Cleanup only. The parent must have joined every original job, including
    /// the final journal write, before calling this with its retained token.
    /// No Drop, child result, deserialized status or boolean can call it for the
    /// parent. A poisoned storage result does not itself make a joined IO task
    /// live again, so only the memory identity is checked here, not filesystem
    /// health. A poisoned mutex still leaves the original guard unresolved.
    pub(crate) fn retire_native_use(&self, original: &NativeUse) -> Result<()> {
        let mut book = self.lock()?;
        if !native_use_is_current(&book, original) {
            return Err(Error::Conflict.into());
        }
        book.native_use = None;
        Ok(())
    }
}

#[cfg(test)]
mod native_use_tests {
    use super::*;

    #[test]
    fn native_use_blocks_close_and_requires_same_original_once() {
        let a = tests::Fixture::new();
        let b = tests::Fixture::new();
        let first = PrivateStateDirectory::open(&a.app).unwrap();
        let second = PrivateStateDirectory::open(&b.app).unwrap();
        let original = first.begin_native_use().unwrap();
        let other = second.begin_native_use().unwrap();
        assert_eq!(first.begin_native_use().err().unwrap().code, Error::Busy);
        assert_eq!(first.close().err().unwrap().code, Error::Busy);
        assert_eq!(
            first.check_native_use(&other).err().unwrap().code,
            Error::Conflict
        );
        assert_eq!(
            first.enable_apple_provisioning(&other).err().unwrap().code,
            Error::Conflict
        );
        first.check_native_use(&original).unwrap();
        assert_eq!(
            second.retire_native_use(&original).err().unwrap().code,
            Error::Conflict
        );
        assert_eq!(
            first.retire_native_use(&other).err().unwrap().code,
            Error::Conflict
        );
        assert_eq!(second.close().err().unwrap().code, Error::Busy);
        first.retire_native_use(&original).unwrap();
        assert_eq!(
            first.check_native_use(&original).err().unwrap().code,
            Error::Conflict
        );
        assert_eq!(
            first.retire_native_use(&original).err().unwrap().code,
            Error::Conflict
        );
        first.close().unwrap();
        second.retire_native_use(&other).unwrap();
        second.close().unwrap();
    }

    #[test]
    fn native_use_drop_never_releases_book_or_the_original_lock() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let original = store.begin_native_use().unwrap();
        drop(original);
        assert_eq!(store.close().err().unwrap().code, Error::Busy);
        assert_eq!(store.begin_native_use().err().unwrap().code, Error::Busy);
        assert_eq!(
            PrivateStateDirectory::open(&f.app).err().unwrap().code,
            Error::Busy
        );
        // Test teardown only. No token is reconstructed and no production
        // settlement is claimed: dropping the whole synthetic store releases
        // its OS descriptors as process exit would. The API never said closed.
        drop(store);
    }

    #[test]
    fn native_use_guard_survives_storage_failure_until_original_cleanup() {
        let f = tests::Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let original = store.begin_native_use().unwrap();
        store.book.lock().unwrap().poisoned = true;
        assert_eq!(store.close().err().unwrap().code, Error::Busy);
        assert_eq!(
            store.read(Namespace::Projects).err().unwrap().code,
            Error::RecoveryRequired
        );
        // This models the parent AFTER its actual IO job joined, not a native
        // finality proof or recovery of the failed storage operation.
        store.retire_native_use(&original).unwrap();
        store.close().unwrap();
    }
}
