//! One original offline-prerequisite owner, private to the fixed installer.
//! No standalone invocation, callback executor, destination, lease or new worker.
#![forbid(unsafe_code)]

use std::sync::{Mutex, MutexGuard, OnceLock};
use mrk_windows_installed_native::{CloseOutcome, Error as NativeError,
    OfflineWebView2Mode, OfflineWebView2Owner, OfflineWebView2Report,
    WebView2CleanupError, WebView2SupportOutput, WebView2SupportDisposition};
use crate::windows_installer_controller::ActiveInstallerGuard;

static OWNER: OnceLock<Mutex<OriginalPrerequisite>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub(crate) struct OfflineWebView2Prepared {
    mode: OfflineWebView2Mode,
    support: WebView2SupportOutput,
}
impl OfflineWebView2Prepared {
    pub(crate) fn mode(self) -> OfflineWebView2Mode { self.mode }
    pub(crate) fn retained_support(self) -> WebView2SupportOutput { self.support }
    pub(crate) fn retained_support_help(self) -> String { support_recovery_help(self.support) }
}

fn support_disposition(output: WebView2SupportOutput) -> &'static str {
    match output.disposition {
        WebView2SupportDisposition::NoOwnedOutputRecorded => "no-owned-output-recorded",
        WebView2SupportDisposition::RetainedBeforeVendor => "retained-before-vendor",
        WebView2SupportDisposition::RetainedVendorMayHaveRun => "retained-vendor-may-have-run",
        WebView2SupportDisposition::CreationUncertain => "creation-uncertain",
    }
}
fn support_recovery_help(output: WebView2SupportOutput) -> String {
    let disposition = match output.disposition {
        WebView2SupportDisposition::NoOwnedOutputRecorded =>
            "No owned support output was recorded. This does not prove that a folder is absent.",
        WebView2SupportDisposition::RetainedBeforeVendor =>
            "A support folder created before installer entry was deliberately retained. The app will not delete or adopt it.",
        WebView2SupportDisposition::RetainedVendorMayHaveRun =>
            "Support output was retained and runtime installation may have changed system state. This is not a rollback; do not remove shared updater files.",
        WebView2SupportDisposition::CreationUncertain =>
            "Support-folder creation is unconfirmed. Do not delete, reuse or assume that the possible output is absent.",
    };
    let accounting = if output.census_complete {
        "The displayed counts describe the completed bounded observation, not future updater activity."
    } else {
        "Contents and counts were not fully observed; zero does not prove the folder is empty."
    };
    format!("{disposition} {accounting} This installer attempt will not retry automatically. Review the recorded outcome and current runtime state before starting a separate attempt.")
}

#[derive(Clone, Debug)]
pub(crate) enum OfflineWebView2Error {
    InstallerGuard, AcquisitionUnavailable, NativeConstruction(NativeError),
    AlreadyStarted, OwnerUnavailable, Failed(OfflineWebView2FailureReport),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineWebView2FailureTrigger {
    PrerequisiteReturned(NativeError), PostReturnGuard, InvalidCompletion,
}
#[derive(Clone, Debug)]
pub(crate) struct OfflineWebView2FailureReport {
    pub trigger: OfflineWebView2FailureTrigger,
    /// Exact retained fixed-helper Result. Its admission can refuse before native
    /// entry; an actual successful native return stays Some(Ok(())) after STOP.
    pub returned: Option<Result<(), NativeError>>,
    pub native_first_before_cleanup: Option<NativeError>,
    pub native_first_after_cleanup: Option<NativeError>,
    pub settlement: CloseOutcome,
    pub cleanup_errors: Vec<WebView2CleanupError>,
    pub observations: OfflineWebView2Report,
}
impl OfflineWebView2Error {
    /// Closed DATA only; never include paths, profile contents or vendor logs.
    pub(crate) fn recovery_help(&self) -> String {
        match self {
            Self::Failed(report) => support_recovery_help(report.observations.support),
            _ => "This installer attempt cannot be resumed or retried automatically. Review its preserved result before starting a separate attempt.".to_owned(),
        }
    }
    pub(crate) fn diagnostic_line(&self) -> String {
        let class = |error: NativeError| match error {
            NativeError::Unavailable => "unavailable", NativeError::Unsafe => "unsafe",
            NativeError::Bounds => "bounds", NativeError::State => "state", NativeError::Unknown => "unknown",
        };
        let detail = match self {
            Self::InstallerGuard => "class=installer-guard;finality=unobserved".to_owned(),
            Self::AcquisitionUnavailable => "class=acquisition-unavailable;finality=unobserved".to_owned(),
            Self::NativeConstruction(error) => format!("class={};phase=construction;nativeEffects=false", class(*error)),
            Self::AlreadyStarted => "class=already-started;finality=unobserved".to_owned(),
            Self::OwnerUnavailable => "class=owner-unavailable;finality=unobserved".to_owned(),
            Self::Failed(report) => {
                let output = report.observations.support;
                let exit = report.observations.vendor_exit_code.map_or_else(|| "unobserved".to_owned(), |code| code.to_string());
                let (trigger, failure_class) = match report.trigger {
                    OfflineWebView2FailureTrigger::PrerequisiteReturned(error) => ("prerequisite-returned", class(error)),
                    OfflineWebView2FailureTrigger::PostReturnGuard => ("post-return-guard", "installer-guard"),
                    OfflineWebView2FailureTrigger::InvalidCompletion => ("invalid-completion", "state"),
                };
                let returned = match report.returned { None => "unobserved", Some(Ok(())) => "ok", Some(Err(error)) => class(error) };
                format!("class={};trigger={};prerequisiteReturn={};nativeFirstBeforeCleanup={};nativeFirstAfterCleanup={};originalsUnknown={};cleanupErrors={};vendorMayHaveRun={};vendorExit={};processDependenciesPending={};supportCreated={};supportRetained={};supportCensusComplete={};supportEntries={};supportBytes={};supportOverBudget={};supportDisposition={};automaticRetry=false",
                    failure_class, trigger, returned, report.native_first_before_cleanup.map_or("none", class),
                    report.native_first_after_cleanup.map_or("none", class),
                    report.settlement == CloseOutcome::Unknown, report.cleanup_errors.len(),
                    report.observations.vendor_may_have_run, exit, report.observations.process_dependencies_pending,
                    output.created, output.retained, output.census_complete, output.entries, output.bytes, output.over_budget,
                    support_disposition(output))
            },
        };
        format!("MRK_WINDOWS_OFFLINE_WEBVIEW2_FAILURE_V1={detail}\n")
    }
}

struct OriginalPrerequisite {
    native: OfflineWebView2Owner,
    // Actual direct native return, retained BEFORE another guard sample, cleanup,
    // diagnostic formatting or result mapping. A DTO cannot populate this field.
    returned: Option<Result<(), NativeError>>,
    reported: Option<Result<OfflineWebView2Prepared, OfflineWebView2Error>>,
}
impl OriginalPrerequisite {
    fn fail(&mut self, boundary: &ActiveInstallerGuard<'_>, trigger: OfflineWebView2FailureTrigger) -> OfflineWebView2Error {
        let before = self.native.first_failure();
        let settlement = self.native.fail_and_settle_once(boundary);
        OfflineWebView2Error::Failed(OfflineWebView2FailureReport {
            trigger, returned: self.returned, native_first_before_cleanup: before,
            native_first_after_cleanup: self.native.first_failure(), settlement,
            cleanup_errors: self.native.cleanup_errors().to_vec(), observations: self.native.report(),
        })
    }
}

/// Call only while the original controller retains its acquired-input return,
/// caller, ARMED/GO state and original watchdog JoinHandle. No new controller is
/// created here. Required ordering: acquisition -> prerequisite -> publication.
pub(crate) fn prepare_for_installer(boundary: &ActiveInstallerGuard<'_>)
    -> Result<OfflineWebView2Prepared, OfflineWebView2Error> {
    prepare_with_route(boundary, PrerequisiteRoute::Automatic)
}

/// Fixed app-libtest qualification entry, not an installation or public UI API.
/// The dependency's existing qualification-result feature supplies the narrow
/// native method. The original acquisition and prerequisite owners still decide.
#[cfg(test)]
pub(crate) fn prepare_existing_for_fixture_once(boundary: &ActiveInstallerGuard<'_>)
    -> Result<OfflineWebView2Prepared, OfflineWebView2Error> {
    prepare_with_route(boundary, PrerequisiteRoute::ExistingOnlyFixture)
}

enum PrerequisiteRoute {
    Automatic,
    #[cfg(test)]
    ExistingOnlyFixture,
}
fn prepare_with_route(boundary: &ActiveInstallerGuard<'_>, route: PrerequisiteRoute)
    -> Result<OfflineWebView2Prepared, OfflineWebView2Error> {
    boundary.require_acquired_inputs().map_err(|_| OfflineWebView2Error::InstallerGuard)?;
    if OWNER.get().is_some() { return Err(OfflineWebView2Error::AlreadyStarted); }
    // Fixed helper obtains row49 hash from the ACTUAL OriginalAcquisition.expected
    // and invokes inert native construction. That acquisition loan ends BEFORE
    // registering/locking this owner (the run lock order is prerequisite->acquisition).
    let native = crate::windows_input_acquisition::for_installer_prerequisite(boundary)?;
    let original = OriginalPrerequisite { native, returned: None, reported: None };
    if OWNER.set(Mutex::new(original)).is_err() { return Err(OfflineWebView2Error::AlreadyStarted); }
    let mut original = OWNER.get().ok_or(OfflineWebView2Error::OwnerUnavailable)?.try_lock()
        .map_err(|_| OfflineWebView2Error::OwnerUnavailable)?;
    if original.returned.is_some() || original.reported.is_some() { return Err(OfflineWebView2Error::AlreadyStarted); }
    // The fixed helper borrows the actual acquisition and returns prepare_once's
    // Result DIRECTLY. It must not call an after-boundary before this retention.
    let returned = match route {
        PrerequisiteRoute::Automatic =>
            crate::windows_input_acquisition::run_installer_prerequisite_once(&mut original.native, boundary),
        #[cfg(test)]
        PrerequisiteRoute::ExistingOnlyFixture =>
            crate::windows_input_acquisition::run_existing_installer_prerequisite_once(&mut original.native, boundary),
    };
    original.returned = Some(returned);
    let reported = match returned {
        Err(first) => Err(original.fail(boundary, OfflineWebView2FailureTrigger::PrerequisiteReturned(first))),
        Ok(()) => {
            let facts = original.native.report();
            match facts.mode {
                Some(mode) => match boundary.after_return(Ok(OfflineWebView2Prepared { mode, support: facts.support }), ()) {
                    Ok(prepared) => Ok(prepared),
                    // Native Ok is already retained. A late guard failure is a
                    // separate cause, not permission to invent a native Err or
                    // discard known output/finality. Once-settled originals are
                    // only queried again by fail, never re-consumed.
                    Err(()) => Err(original.fail(boundary, OfflineWebView2FailureTrigger::PostReturnGuard)),
                },
                None => Err(original.fail(boundary, OfflineWebView2FailureTrigger::InvalidCompletion)),
            }
        },
    };
    original.reported = Some(reported.clone()); reported
}

/// An ordinary mutex loan of the ACTUAL completed owner, not a new deadline or
/// privilege ticket. The same actual controller guard remains borrowed with it.
/// Integration lock order is publication -> prerequisite -> acquisition.
pub(crate) struct CompletedPrerequisite<'loan, 'guard> {
    original: MutexGuard<'static, OriginalPrerequisite>,
    _boundary: &'loan ActiveInstallerGuard<'guard>,
}
impl CompletedPrerequisite<'_, '_> {
    pub(crate) fn native(&self) -> &OfflineWebView2Owner { &self.original.native }
}
pub(crate) fn borrow_for_activation<'loan, 'guard>(boundary: &'loan ActiveInstallerGuard<'guard>)
    -> Result<CompletedPrerequisite<'loan, 'guard>, OfflineWebView2Error> {
    boundary.require_acquired_inputs().map_err(|_| OfflineWebView2Error::InstallerGuard)?;
    let original = OWNER.get().ok_or(OfflineWebView2Error::OwnerUnavailable)?.try_lock()
        .map_err(|_| OfflineWebView2Error::OwnerUnavailable)?;
    if !matches!(original.returned, Some(Ok(()))) || !matches!(original.reported, Some(Ok(_))) {
        return Err(OfflineWebView2Error::OwnerUnavailable);
    }
    boundary.check().map_err(|_| OfflineWebView2Error::InstallerGuard)?;
    Ok(CompletedPrerequisite { original, _boundary: boundary })
}

#[cfg(test)]
mod report_tests {
    use super::*;

    // Closed report DATA only. These cannot construct an acquisition, an actual
    // controller guard, native completion, or permission to activate a shell.
    #[test]
    fn post_return_guard_report_keeps_actual_success_and_retained_output() {
        let report = OfflineWebView2FailureReport {
            trigger: OfflineWebView2FailureTrigger::PostReturnGuard,
            returned: Some(Ok(())),
            native_first_before_cleanup: None,
            native_first_after_cleanup: Some(NativeError::State),
            settlement: CloseOutcome::Settled,
            cleanup_errors: Vec::new(),
            observations: OfflineWebView2Report {
                mode: Some(OfflineWebView2Mode::Installed), vendor_may_have_run: true,
                process_signalled: true, owned_job_empty: true, vendor_exit_code: Some(0),
                process_dependencies_pending: false,
                support: WebView2SupportOutput { created: true, retained: true, census_complete: true,
                    disposition: WebView2SupportDisposition::RetainedVendorMayHaveRun,
                    entries: 2, bytes: 17, over_budget: false },
            },
        };
        let line = OfflineWebView2Error::Failed(report.clone()).diagnostic_line();
        assert_eq!(report.returned, Some(Ok(())));
        assert_eq!(report.observations.mode, Some(OfflineWebView2Mode::Installed));
        assert!(line.contains("class=installer-guard;trigger=post-return-guard;prerequisiteReturn=ok;"));
        assert!(line.contains("nativeFirstBeforeCleanup=none;nativeFirstAfterCleanup=state;originalsUnknown=false;cleanupErrors=0;"));
        assert!(line.contains("vendorMayHaveRun=true;vendorExit=0;processDependenciesPending=false;"));
        assert!(line.contains("supportCreated=true;supportRetained=true;supportCensusComplete=true;supportEntries=2;supportBytes=17;supportOverBudget=false;supportDisposition=retained-vendor-may-have-run;automaticRetry=false"));
        let recovery = OfflineWebView2Error::Failed(report).recovery_help();
        assert!(recovery.contains("not a rollback") && recovery.contains("not retry automatically"));
    }

    #[test]
    fn prerequisite_error_and_unknown_dependencies_are_reported_separately() {
        let report = OfflineWebView2FailureReport {
            trigger: OfflineWebView2FailureTrigger::PrerequisiteReturned(NativeError::Unsafe),
            returned: Some(Err(NativeError::Unsafe)),
            native_first_before_cleanup: Some(NativeError::Unsafe),
            native_first_after_cleanup: Some(NativeError::Unsafe),
            settlement: CloseOutcome::Unknown,
            cleanup_errors: vec![WebView2CleanupError {
                original: mrk_windows_installed_native::WebView2Original::Process,
                record: 0, error: NativeError::Unknown,
            }],
            observations: OfflineWebView2Report {
                vendor_may_have_run: true, process_dependencies_pending: true,
                support: WebView2SupportOutput { created: true, retained: true,
                    disposition: WebView2SupportDisposition::RetainedVendorMayHaveRun, ..Default::default() },
                ..Default::default()
            },
        };
        let line = OfflineWebView2Error::Failed(report.clone()).diagnostic_line();
        assert_eq!(report.returned, Some(Err(NativeError::Unsafe)));
        assert!(line.contains("class=unsafe;trigger=prerequisite-returned;prerequisiteReturn=unsafe;"));
        assert!(line.contains("nativeFirstBeforeCleanup=unsafe;nativeFirstAfterCleanup=unsafe;originalsUnknown=true;cleanupErrors=1;"));
        assert!(line.contains("vendorExit=unobserved;processDependenciesPending=true;"));
        assert!(line.contains("supportCreated=true;supportRetained=true;supportCensusComplete=false;"));
        assert!(line.contains("supportDisposition=retained-vendor-may-have-run;automaticRetry=false"));
        let recovery = OfflineWebView2Error::Failed(report).recovery_help();
        assert!(recovery.contains("zero does not prove the folder is empty"));
        let before_vendor = WebView2SupportOutput { created: true, retained: true,
            disposition: WebView2SupportDisposition::RetainedBeforeVendor, ..Default::default() };
        assert_eq!(support_disposition(before_vendor), "retained-before-vendor");
        assert!(support_recovery_help(before_vendor).contains("will not delete or adopt it"));
        let uncertain = WebView2SupportOutput { retained: true,
            disposition: WebView2SupportDisposition::CreationUncertain, ..Default::default() };
        assert!(support_recovery_help(uncertain).contains("creation is unconfirmed"));
        assert!(support_recovery_help(WebView2SupportOutput::default()).contains("does not prove that a folder is absent"));
    }
}
