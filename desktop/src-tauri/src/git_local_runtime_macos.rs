//! GitLocal-only extension of the EXISTING installed slots!/Book. The reviewed
//! fixed bootstrap must be in the genuine installed inventory; no alternate
//! runtime, test witness, caller flag or passive-domain loan qualifies it.
use super::*;

impl GitLocalRuntimeSlots {
    pub(crate) fn arm_fetch_once(&mut self)->Result<()> {
        if !self.never_started(){return Err(AdmissionFailure::AlreadyUsed)}
        let book=self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?;
        if book.tool_ca_required||book.tool_ca.is_some()||book.fetch_helper_required||book.fetch_helper.is_some(){return Err(AdmissionFailure::AlreadyUsed)}
        book.tool_ca_required=true;book.fetch_helper_required=true;Ok(())
    }
    pub(crate) fn working_reservation_bytes() -> Option<usize> {
        crate::macos_history_inventory::code_storage_bytes(std::mem::size_of::<Record>(), native::vault_filesystem::SNAPSHOT_FRAME_BYTES)?;
        crate::macos_history_inventory::CODE_CONTROL_RESERVE
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(crate::git_local_protocol::DATA_BACKING)?
            .checked_add(crate::asset_source::GitLocalSources::working_bytes()?)?
            .checked_add(crate::git_local_state::STATE_BACKING)
    }
    pub(crate) fn reserve_once(&mut self) -> Result<usize> {
        if !self.never_started() {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let records = crate::macos_install_record::RUNTIME_RECORD_LIMIT;
        let book = self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?;
        if book.records.capacity() != 0 {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        book.records.try_reserve_exact(records).map_err(native_error)?;
        if book.records.capacity() > records {
            return Err(AdmissionFailure::Bounds);
        }
        Self::working_reservation_bytes().ok_or(AdmissionFailure::Bounds)
    }
    pub(crate) fn source_runtime_fd_bound() -> usize {
        MAC_RUNTIME_FDS
    }
}
impl GitLocalInstalledRuntime {
    pub(crate) fn post_original(
        &mut self,
        end: Instant,
        stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>),
    ) -> Result<()> {
        let result = (|| {
            if !self.original.inspected || !self.original.prepared || !self.original.admission_custody_ready() {
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
        if let Err(failure) = &result {
            self.original.note_acl(*failure, Instant::now());
        }
        publish(self.original.first_failure());
        result
    }
}
