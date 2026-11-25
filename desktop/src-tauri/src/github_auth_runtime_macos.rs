//! GitHubAuth-only extension of the existing slots!/Book implementation.
//! Included after its distinct slots! invocation in installed_runtime_macos.
//! This checks the SAME held Python/core/bootstrap originals; it does not lend
//! History's gh nomination or create an alternative runtime/process stack.
use super::*;
// Pure existing code-storage accounting, not History's provider nomination.
use crate::macos_history_inventory as inventory_storage;

impl GitHubAuthRuntimeSlots {
    pub(crate) fn working_reservation_bytes() -> Option<usize> {
        inventory_storage::code_storage_bytes(
            std::mem::size_of::<Record>(),
            native::vault_filesystem::SNAPSHOT_FRAME_BYTES,
        )?;
        inventory_storage::CODE_CONTROL_RESERVE
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(128 * 1024)
    }
    pub(crate) fn reserve_once(&mut self) -> Result<usize> {
        if !self.never_started() {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let records = crate::macos_install_record::RUNTIME_RECORD_LIMIT;
        let original = self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?;
        if original.records.capacity() != 0 {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        original
            .records
            .try_reserve_exact(records)
            .map_err(native_error)?;
        if original.records.capacity() > records {
            return Err(AdmissionFailure::Bounds);
        }
        Self::working_reservation_bytes().ok_or(AdmissionFailure::Bounds)
    }
    pub(crate) fn source_runtime_fd_bound() -> usize {
        MAC_RUNTIME_FDS
    }
}

impl GitHubAuthInstalledRuntime {
    pub(crate) fn post_original(
        &mut self,
        end: Instant,
        stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>),
    ) -> Result<()> {
        let result = (|| {
            if !self.original.inspected
                || !self.original.prepared
                || !self.original.admission_custody_ready()
            {
                return Err(AdmissionFailure::AlreadyUsed);
            }
            self.original.point(end, stop)?;
            native::real_user().map_err(native_error)?;
            for (index, record) in self.original.records.iter().enumerate() {
                if record.state == State::Owned {
                    self.original.check_name(index, end, stop)?;
                }
            }
            self.original.point(end, stop)
        })();
        if let Err(failure) = result.as_ref() {
            self.original.note_acl(*failure, Instant::now());
        }
        publish(self.original.first_failure());
        result
    }
}
