//! Focused DATA regression cases for the actual production helpers. These tests
//! make NO native call, fabricate no HANDLE, launch no installer, and cannot
//! supply an acquisition, machine-runtime or process-finality capability.
use super::*;

#[test]
fn machine_version_is_exact_and_old_is_not_present() -> Result<()> {
    for absent in ["", "0.0.0.0"] { assert_eq!(Version::parse(absent)?, None); }
    assert!(!Version::parse("119.0.2151.97")?.ok_or(Error::State)?.supported());
    assert!(Version::parse("120.0.2210.91")?.ok_or(Error::State)?.supported());
    assert!(Version::parse("65535.65535.65535.65535")?.ok_or(Error::State)?.supported());
    for invalid in ["120", "120.0.0", "120.0.0.1.2", "120..0.1", "0120.0.0.1", "120.00.0.1",
        "120.0.0.-1", "120.0.0.+1", "120.0.0.65536", "120.0.0.1 ", " 120.0.0.1", "0.1.0.0",
        "120.0.0.1\0", "120.0.0.\u{0661}"] {
        assert!(Version::parse(invalid).is_err(), "{invalid:?}");
    }
    Ok(())
}

fn registry_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

#[test]
fn registration_requires_exact_type_width_and_termination() -> Result<()> {
    let bytes = registry_bytes("120.0.0.1");
    assert_eq!(registry_version(REG::REG_SZ, bytes.len(), &bytes)?.ok_or(Error::State)?.text, "120.0.0.1");
    assert_eq!(registry_version(REG::REG_SZ, 0, &[])?, None);
    assert_eq!(registry_version(REG::REG_SZ, 2, &[0, 0])?, None);
    assert!(registry_version(REG::REG_EXPAND_SZ, bytes.len(), &bytes).is_err());
    assert!(registry_version(REG::REG_SZ, bytes.len() - 1, &bytes).is_err());
    assert!(registry_version(REG::REG_SZ, bytes.len() + 2, &bytes).is_err());
    assert!(registry_version(REG::REG_SZ, bytes.len() - 2, &bytes).is_err());
    assert!(registry_version(REG::REG_SZ, 130, &[0; 130]).is_err());
    let embedded = registry_bytes("120.0.\0.1");
    assert!(registry_version(REG::REG_SZ, embedded.len(), &embedded).is_err());
    assert!(registry_version(REG::REG_SZ, 4, &[0x00, 0xd8, 0, 0]).is_err());
    Ok(())
}

#[test]
fn root_exit_and_exit_zero_are_not_owned_job_finality() -> Result<()> {
    assert!(completed_exit(false, 0).is_err());
    assert!(completed_exit(true, F::STILL_ACTIVE as u32).is_err());
    assert!(completed_exit(true, 3010).is_err()); // no reboot-code success rewrite
    completed_exit(true, 0)?;
    let size = size_of::<J::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32;
    assert!(!owned_job_empty(size, 2, 1, true)?); // root exited, owned descendant remains
    assert!(owned_job_empty(size, 2, 0, true)?);
    assert!(owned_job_empty(size, 0, 0, false)?); // job never had an assigned child
    assert!(owned_job_empty(size, 0, 0, true).is_err());
    assert!(owned_job_empty(size - 1, 2, 0, true).is_err());
    assert!(owned_job_empty(size, 1, 2, true).is_err());
    assert!(owned_job_empty(size, OWNED_PROCESSES + 1, OWNED_PROCESSES + 1, true).is_err());
    Ok(())
}

#[test]
fn clean_launch_environment_is_closed_and_doubly_terminated() -> Result<()> {
    let actual = clean_environment("C:\\Windows\\System32", "C:\\Windows", "C:\\Windows\\MRK-WebView2-test")?;
    let expected = "PATH=C:\\Windows\\System32\0SystemRoot=C:\\Windows\0TEMP=C:\\Windows\\MRK-WebView2-test\0TMP=C:\\Windows\\MRK-WebView2-test\0windir=C:\\Windows\0\0";
    assert_eq!(actual, expected.encode_utf16().collect::<Vec<_>>());
    assert!(clean_environment(&"x".repeat(4 * NAME_UNITS), "C:\\Windows", "C:\\Windows\\MRK-WebView2-test").is_err());
    let mut process = VendorProcess::new();
    assert!(process.configure("C:\\Program Files\\bad\".exe", "C:\\Windows\\MRK-WebView2-test",
        "C:\\Windows", "C:\\Windows\\System32").is_err());
    assert!(process.launch.is_none() && !process.create_entered && !process.resume_entered);
    Ok(())
}

struct BoundaryData { stop: Cell<bool>, producing: Cell<usize>, settlement: Cell<usize> }
impl BoundaryData {
    fn stopped() -> Self { Self { stop: Cell::new(true), producing: Cell::new(0), settlement: Cell::new(0) } }
}
impl InstallerBoundary for BoundaryData {
    fn producing_boundary(&self) -> Result<()> {
        self.producing.set(self.producing.get() + 1);
        if self.stop.get() { Err(Error::State) } else { Ok(()) }
    }
    fn settlement_boundary(&self) { self.settlement.set(self.settlement.get() + 1); }
}

#[test]
fn returned_error_precedes_later_stop_and_clean_settlement_cannot_clear_it() {
    let boundary = BoundaryData::stopped();
    let mut paths = PathBook::new(); // inert book: no registry, token or file operation
    assert_eq!(paths.after::<()>(&boundary, Err(Error::Unsafe)), Err(Error::Unsafe));
    assert_eq!(boundary.producing.get(), 0);
    assert_eq!(paths.first, Some(Error::Unsafe));
    assert_eq!(paths.before(&boundary), Err(Error::State));
    let mut errors = Vec::new();
    assert_eq!(paths.settle(&boundary, WebView2Original::Input, &mut errors), CloseOutcome::Settled);
    assert!(errors.is_empty() && paths.native.slots.is_empty());
    assert_eq!(paths.first, Some(Error::Unsafe));
    assert_eq!(paths.before(&boundary), Err(Error::State));

    let mut stopped_success = PathBook::new();
    assert_eq!(stopped_success.after(&boundary, Ok(())), Err(Error::State));
    assert_eq!(stopped_success.first, Some(Error::State));
}

#[test]
fn unknown_is_absorbing_and_output_accounting_is_not_finality() {
    let boundary = BoundaryData::stopped();
    let mut paths = PathBook::new();
    paths.latch(Error::Unknown); // DATA classification only: no native original fabricated
    assert_eq!(paths.before(&boundary), Err(Error::Unknown));
    let mut errors = Vec::new();
    assert_eq!(paths.settle(&boundary, WebView2Original::Input, &mut errors), CloseOutcome::Unknown);
    assert!(!paths.native.settled());
    assert_eq!(boundary.producing.get(), 0);

    let mut process = VendorProcess::new();
    assert!(!process.finality());
    let accounted_output = WebView2SupportOutput { created: true, retained: true,
        disposition: WebView2SupportDisposition::RetainedVendorMayHaveRun,
        census_complete: true, entries: 1, bytes: 12, over_budget: false };
    assert!(accounted_output.census_complete && !process.finality());
    // Never-started process storage can settle without any native call. No
    // support field participates in that result, and it cannot grant Complete.
    assert_eq!(process.settle(&boundary, &mut errors), CloseOutcome::Settled);
    assert!(process.finality() && !process.create_entered && !process.signalled && !process.exit_zero);
}

#[test]
fn unknown_process_retains_dependent_books_but_not_independent_observations() {
    let boundary = BoundaryData::stopped();
    let mut errors = Vec::new();
    let mut unknown = VendorProcess::new();
    unknown.latch(Error::Unknown); // closed DATA classification, no HANDLE/frame invented
    assert_eq!(unknown.settle(&boundary, &mut errors), CloseOutcome::Unknown);
    assert!(!unknown.finality());
    for role in [WebView2Original::Input, WebView2Original::System, WebView2Original::Support] {
        let mut paths = PathBook::new();
        assert_eq!(paths.settle_process_dependency(&boundary, &unknown, role, &mut errors), CloseOutcome::Unknown);
        assert!(!paths.settled && !paths.native.retiring && paths.native.slots.is_empty());
        assert_eq!(paths.settle_process_dependency(&boundary, &unknown, role, &mut errors), CloseOutcome::Unknown);
        assert!(!paths.settled && !paths.native.retiring); // no hidden retry/consume
    }
    // A genuinely independent, never-opened machine observation may settle. It
    // does not change the unresolved process or release its dependency books.
    let mut independent = MachineObservation::new();
    assert_eq!(independent.settle(&boundary, false, &mut errors), CloseOutcome::Settled);
    assert!(!unknown.finality());

    let mut clean = VendorProcess::new();
    assert_eq!(clean.settle(&boundary, &mut errors), CloseOutcome::Settled);
    let mut paths = PathBook::new();
    assert_eq!(paths.settle_process_dependency(&boundary, &clean, WebView2Original::Input, &mut errors), CloseOutcome::Settled);
    assert!(paths.settled && paths.native.settled());
    assert_eq!(paths.settle_process_dependency(&boundary, &clean, WebView2Original::Input, &mut errors), CloseOutcome::Settled);
    assert!(errors.is_empty() && boundary.producing.get() == 0 && boundary.settlement.get() == 0);
}

#[cfg(feature = "qualification-result")]
#[test]
fn existing_only_route_refuses_installation_without_a_fallback() {
    // Policy DATA only. Neither arm can supply a machine-presence receipt,
    // construct the acquisition/owner, or invoke the bundled executable.
    assert_eq!(PreparationRoute::ExistingOnly.permit_install(), Err(Error::Unavailable));
    assert_eq!(PreparationRoute::InstallIfNeeded.permit_install(), Ok(()));
}
