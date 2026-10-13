//! Fixed no-WebView prerequisite observation in the original fresh account.
//! The same production inspector owns every native input until explicit close.
//! A completed unavailable observation is NOT GUI admission or a passing case.
use super::*;
use super::qualification_result::{digest, fixed_path, need, normal_ui_deadline, unhex, write_ui_child, UiRequest, UiRole};

#[test]
#[ignore = "fixed ordinary-account normal UI prerequisite probe; original owner and separate finalizer required"]
fn hosted_normal_ui_prerequisites_contract() -> Result<()> {
    let end = normal_ui_deadline()?; // Original parent's remaining endpoint, once.
    let raw = std::env::var("MRK_WINDOWS_NORMAL_UI_REQUEST").map_err(|_| Error::State)?;
    let request = UiRequest::parse(raw.as_bytes())?;
    request.compiled()?;
    need(request.role == UiRole::Prerequisite)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    need(image.to_str() == Some(request.app.path.as_str()))?;
    request.role.process_args(&image, false)?;
    let output = fixed_path(&std::env::var("MRK_WINDOWS_NORMAL_UI_OUTPUT").map_err(|_| Error::State)?)?;
    request.at_root(output.parent().ok_or(Error::Unsafe)?)?;
    let account = unhex(&std::env::var("MRK_WINDOWS_ORDINARY_SID").map_err(|_| Error::State)?)?;
    need(super::ordinary_owner::ui_local_sid(&account) && std::time::Instant::now() < end)?;

    let mut original = super::ui::Prerequisites::new(); // Retained BEFORE inspect.
    let observed = original.inspect();
    let account_matched = original.observed_user_sid() == Some(account.as_slice());
    let before_end = std::time::Instant::now() < end;
    // A refusal still explicitly settles the same original inspector. Never
    // Drop-as-close, an elevated-runner observation, or replacement inspection.
    let closed = original.settle_once();
    if closed != CloseOutcome::Settled || !original.settled()
        || matches!(observed, Err(super::ui::UiError::CleanupUnknown)) {
        super::qualification_result::diagnostic_data("ui-prerequisite-originals", None, true, None);
        loop { std::thread::park(); std::hint::black_box((&mut original, &request, &account, &observed)); }
    }
    need(account_matched && before_end && std::time::Instant::now() < end)?;
    let refusal = original.managed_refusal(&observed); // Copied only after the ORIGINAL inspector settled.
    let request_sha = digest(raw.as_bytes())?;
    let account_sha = digest(&account)?;
    let value = match &observed {
        Ok(facts) => {
            need(facts.ordinary_context && facts.interactive_desktop && facts.managed_runtime
                && facts.override_free && facts.private_parent)?;
            request.probe_result(&request_sha, &account_sha, None, Some(&facts.runtime_version), None)?
        }
        Err(error) => request.probe_result(&request_sha, &account_sha, Some(error.label()), None, refusal.as_ref())?,
    };
    need(std::time::Instant::now() < end)?;
    write_ui_child(&request, &value, end)?;
    need(std::time::Instant::now() < end)
}
