//! Installed qualification observation of the SAME retained native run. No
//! fixture can construct a candidate, replace a receipt or open a tool here.
use super::*;
use crate::asset_session::InstalledUploadProducerSample;

impl UploadKeyRun {
    pub(crate) fn installed_upload_sample(&self) -> Option<InstalledUploadProducerSample> {
        let owner = &self.session;
        if owner.domain != SavedCommandDomain::GenerateUploadKey {
            return None;
        }
        let original_final = original_joined(owner);
        let resources = owner.resources.try_lock().ok()?;
        let input = owner.upload_key.writer.try_lock().ok()?;
        let receive = owner.upload_key.receive.as_ref()?;
        let backing = receive.backing.try_lock().ok()?;
        Some(InstalledUploadProducerSample {
            ready: receive.ready.load(Ordering::SeqCst),
            go_claimed: input.as_ref().is_some_and(|i| i.send_claimed),
            go_sent: input.as_ref().is_some_and(|i| i.sent),
            // Actual original stdout task return, not ReceiveBook's later
            // candidate-admission latch (which remains false on a STOP).
            reader_joined: resources.stdout.is_none()
                && !resources.out_failed
                && resources.out_end.is_some(),
            result_complete: receive.complete.load(Ordering::SeqCst) && backing.eof,
            candidate: owner.upload_key.candidate.try_lock().ok()?.is_some(),
            inspector_started: resources.inspection_started,
            inspector_joined: resources.inspection_started
                && resources.inspection_joined
                && !resources.inspection_failed
                && resources.inspection.is_none()
                && resources.inspection_error.is_none(),
            acquisition_started: resources.acquisition_started,
            acquisition_joined: resources.acquisition_started
                && resources.acquisition_joined
                && !resources.acquisition_failed
                && resources.acquisition.is_none()
                && resources.acquisition_error.is_none(),
            driver_joined: owner.driver_joined.load(Ordering::SeqCst)
                && !owner.driver_failed.load(Ordering::SeqCst)
                && matches!(owner.driver_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
            manager_joined: !owner.manager_failed.load(Ordering::SeqCst)
                && matches!(owner.manager_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
            watchdog_joined: owner.watchdog_joined.load(Ordering::SeqCst)
                && !owner.watchdog_failed.load(Ordering::SeqCst)
                && matches!(
                    owner.watchdog_return.try_lock().ok()?.as_ref(),
                    Some(Ok(true))
                ),
            // This is the original moved M2/SH tail's known() observation,
            // not a local inference from pipe EOF or a parsed terminal frame.
            tail_closed: owner
                .android_close
                .as_ref()
                .is_some_and(|tail| tail.known()),
            original_final,
            cleanup_unknown: owner.resource_unknown.load(Ordering::SeqCst),
            private_disposed: owner.upload_key.disposed.load(Ordering::SeqCst),
        })
    }
}
