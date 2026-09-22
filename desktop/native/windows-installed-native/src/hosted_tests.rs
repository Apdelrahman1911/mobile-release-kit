//! One fixed, explicitly ignored, read-only native contract on a disposable host.
//! No production admission override, account preparation, file mutation or launcher.
//! A returned Book settlement is not a production Resources/worker-join proof.
use super::*;

// This module is cfg(test). The caller reaches this only after its one original
// settlement gate. No native call, later GetLastError, or success receipt here.
pub(super) fn write_unavailable(book: &NativeBook, observation: &Result<bool>, output: &mut impl std::io::Write) {
    if !book.settled() || !matches!(observation, Err(Error::Unavailable)) { return; }
    let Some((call, returned)) = book.first_unavailable else { return; };
    let (api, selector, kind) = match call {
        Call::Architecture => ("IsWow64Process2", "null", "boolean"),
        Call::Folder => ("SHGetFolderPathW", "null", "hresult"),
        Call::WindowsDirectory => ("GetSystemWindowsDirectoryW", "null", "count"),
        Call::SystemDirectory => ("GetSystemDirectoryW", "null", "count"),
        Call::Mapping => ("QueryDosDeviceW", "null", "count"),
        Call::Open(_) => ("NtCreateFile", "null", "ntstatus"),
        Call::ProcessToken(_) => ("OpenProcessToken", "null", "boolean"),
        Call::Info(class, size) => {
            let selector = match class {
                FS::FileBasicInfo if size == size_of::<FS::FILE_BASIC_INFO>() => r#""FileBasicInfo""#,
                FS::FileStandardInfo if size == size_of::<FS::FILE_STANDARD_INFO>() => r#""FileStandardInfo""#,
                FS::FileAttributeTagInfo if size == size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>() => r#""FileAttributeTagInfo""#,
                FS::FileIdInfo if size == size_of::<FS::FILE_ID_INFO>() => r#""FileIdInfo""#,
                FS::FileCaseSensitiveInfo if size == size_of::<FS::FILE_CASE_SENSITIVE_INFO>() => r#""FileCaseSensitiveInfo""#,
                _ => return,
            };
            ("GetFileInformationByHandleEx", selector, "boolean")
        }
        Call::HandleInfo => ("GetHandleInformation", "null", "boolean"),
        Call::FinalName => ("GetFinalPathNameByHandleW", "null", "count"),
        Call::VolumeName => ("GetVolumeInformationByHandleW", "null", "boolean"),
        Call::VolumeDevice => ("NtQueryVolumeInformationFile", r#""FileFsDeviceInformation""#, "ntstatus"),
        Call::Streams => ("NtQueryInformationFile", r#""FileStreamInformation""#, "ntstatus"),
        Call::Security => ("GetKernelObjectSecurity", "null", "boolean"),
        Call::Token(class) => {
            let selector = match class {
                S::TokenStatistics => r#""TokenStatistics""#,
                S::TokenType => r#""TokenType""#,
                S::TokenElevation => r#""TokenElevation""#,
                S::TokenElevationType => r#""TokenElevationType""#,
                S::TokenUIAccess => r#""TokenUIAccess""#,
                S::TokenVirtualizationEnabled => r#""TokenVirtualizationEnabled""#,
                S::TokenUser => r#""TokenUser""#,
                S::TokenIntegrityLevel => r#""TokenIntegrityLevel""#,
                S::TokenGroups => r#""TokenGroups""#,
                S::TokenPrivileges => r#""TokenPrivileges""#,
                _ => return,
            };
            ("GetTokenInformation", selector, "boolean")
        }
        Call::Privilege(name) => {
            let selector = match name {
                PrivilegeName::ChangeNotify => r#""lookup-1""#,
                PrivilegeName::Shutdown => r#""lookup-2""#,
                PrivilegeName::Undock => r#""lookup-3""#,
                PrivilegeName::IncreaseWorkingSet => r#""lookup-4""#,
                PrivilegeName::TimeZone => r#""lookup-5""#,
            };
            ("LookupPrivilegeValueW", selector, "boolean")
        }
        Call::Read(_) => ("ReadFile", "null", "boolean"),
        Call::Entries => ("GetFileInformationByHandleEx", r#""FileIdExtdDirectoryInfo""#, "boolean"),
        Call::DriveType | Call::ThreadToken(_) | Call::Close(_) | Call::FileType => return,
    };
    // Pair the original API with its actual return class. A malformed synthetic
    // pair, pending result or permitted EOF is not a printable terminal failure.
    let (value, error) = match (kind, returned) {
        ("boolean", Returned::Boolean(0, error)) if error != F::ERROR_IO_PENDING
            && !(matches!(call, Call::Entries) && error == F::ERROR_NO_MORE_FILES) => (0i64, Some(error)),
        ("count", Returned::Count(0, error)) if error != F::ERROR_IO_PENDING => (0i64, Some(error)),
        ("ntstatus", Returned::Nt(value)) if (value as u32 >> 30) == 3 => (i64::from(value), None),
        ("hresult", Returned::Hresult(value)) if value != F::S_OK && value != HRESULT_PENDING => (i64::from(value), None),
        _ => return,
    };
    let error = match error { Some(value) => value.to_string(), None => "null".to_owned() };
    let line = format!("MRK_WINDOWS_INSTALLED_NATIVE_UNAVAILABLE={{\"api\":\"{api}\",\"selector\":{selector},\"resultKind\":\"{kind}\",\"result\":{value},\"win32Error\":{error}}}\n");
    // One bounded write attempt, no write_all/flush/retry. Missing or partial
    // output stays incomplete evidence; the original observation still fails.
    if line.len() < 512 { let _ = output.write(line.as_bytes()); }
}

fn require_fact(value: bool) -> Result<()> {
    if value { Ok(()) } else { Err(Error::Unsafe) }
}
pub(super) fn hosted_source() -> Result<&'static str> {
    let source = option_env!("GITHUB_SHA").ok_or(Error::State)?;
    require_fact(source.len() == 40 && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))?;
    for (name, expected) in [
        ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1"),
        ("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("RUNNER_OS", "Windows"), ("RUNNER_ARCH", "X64"), ("ImageOS", "win25-vs2026"),
        ("GITHUB_RUN_ATTEMPT", "1"), ("GITHUB_SHA", source),
    ] {
        require_fact(std::env::var(name).as_deref() == Ok(expected))?;
    }
    Ok(source)
}
fn scalar(book: &mut NativeBook, index: usize, class: S::TOKEN_INFORMATION_CLASS) -> Result<u32> {
    let completed = book.token(index, class)?;
    require_fact(completed.count()? == 4)?;
    decode::u32_at(completed.bytes(4)?, 0)
}
fn statistics(book: &mut NativeBook, index: usize) -> Result<TokenIdentity> {
    let completed = book.token(index, S::TokenStatistics)?;
    security::statistics(completed.bytes(completed.count()?)?)
}
pub(super) fn actual_elevated_primary_refusal(book: &mut NativeBook, index: usize) -> Result<()> {
    // These are actual, bounded, completed observations of the SAME original
    // opened by observe_user_once, not fixture values or another token handle.
    book.absent_thread_token()?;
    let before = statistics(book, index)?;
    require_fact(scalar(book, index, S::TokenType)? == S::TokenPrimary as u32)?;
    require_fact(scalar(book, index, S::TokenElevation)? == 1)?;
    require_fact([S::TokenElevationTypeDefault as u32, S::TokenElevationTypeFull as u32]
        .contains(&scalar(book, index, S::TokenElevationType)?))?;
    // Elevated==1 is a specific production-policy refusal even when UAC is
    // disabled (Default), not permission to accept an arbitrary native error.
    require_fact(matches!(book.recheck_user(), Err(Error::Unsafe)))?;
    require_fact(statistics(book, index)? == before)?;
    book.absent_thread_token()?;
    require_fact(book.process_token == Some(index) && book.user.is_none() && !book.is_unknown())?;
    require_fact(matches!(book.known_locations_once(), Err(Error::State)) && !book.roots_started)?;
    require_fact(book.slots.iter().all(|s| !matches!(s.kind, Kind::Directory | Kind::File)))
}
fn admitted_root_facts(book: &mut NativeBook, index: usize, token: TokenIdentity) -> Result<()> {
    book.recheck_user()?;
    let locations = book.known_locations_once()?;
    let root = book.open_volume(&locations.program_files)?;
    let before = book.metadata(&root)?;
    let security_before = book.security(&root, AuthorityScope::AncestorOutsideVersion)?;
    // One OS-derived volume original only: no tree walk, child file, read cursor,
    // mutable fixture, alias fallback, root reopen or protected-version claim.
    book.local_ntfs(&root)?;
    for location in [&locations.program_files, &locations.windows, &locations.system] {
        book.recheck_location(location)?;
    }
    let after = book.metadata(&root)?;
    let security_after = book.security(&root, AuthorityScope::AncestorOutsideVersion)?;
    require_fact(before.kind == FileKind::Directory && after.kind == FileKind::Directory
        && before.identity == after.identity && security_before == security_after)?;
    book.recheck_user()?;
    require_fact(book.process_token == Some(index) && book.user.as_ref().map(|f| f.identity) == Some(token))?;
    require_fact(matches!(book.known_locations_once(), Err(Error::State)))
}

#[test]
#[ignore = "fixed disposable Windows hosted native contract only; never a production admission"]
fn hosted_native_read_only_contract() -> Result<()> {
    let source = hosted_source()?;
    let mut book = NativeBook::new();
    // No panicking assertions or early test return between native entry and the
    // single explicit settlement below. Failed observations still take that path.
    let observation = (|| -> Result<bool> {
        require_fact(book.never_started())?;
        require_fact(matches!(book.known_locations_once(), Err(Error::State)) && book.never_started())?;
        let observed = book.observe_user_once().map(|f| f.identity);
        let index = book.process_token.ok_or(Error::State)?;
        require_fact(book.slot(index)?.state == SlotState::Owned && !book.is_unknown())?;
        require_fact(matches!(book.observe_user_once(), Err(Error::State)))?;
        match observed {
            Ok(token) => { admitted_root_facts(&mut book, index, token)?; Ok(true) }
            Err(Error::Unsafe) => { actual_elevated_primary_refusal(&mut book, index)?; Ok(false) }
            Err(error) => Err(error), // unavailable, bounds, state and Unknown fail
        }
    })();
    // Measure before settle_once: a merely reserved probe retired to NoHandle
    // during cleanup must never be counted as an actual no-thread-token receipt.
    let primary = book.slots.iter().filter(|s| s.kind == Kind::ProcessToken && s.state == SlotState::Owned).count();
    let absent = book.slots.iter().filter(|s| s.kind == Kind::ThreadToken && s.state == SlotState::NoHandle).count();
    let owned = book.slots.iter().filter(|s| s.state == SlotState::Owned).count();
    let exact_slots = book.slots.len() == owned + absent;
    let settlement = book.settle_once();
    // Pending/Unknown keeps the original arena/slots through the unchanged Book
    // Drop fallback. It does not print a success receipt or promote process exit.
    if settlement != CloseOutcome::Settled || !book.settled() { return Err(Error::Unknown); }
    if matches!(observation, Err(Error::Unavailable)) {
        write_unavailable(&book, &observation, &mut std::io::stderr().lock());
    }
    let admitted = observation?;
    let closed = book.slots.iter().filter(|s| s.state == SlotState::Closed).count();
    require_fact(exact_slots && primary == 1 && owned == closed
        && closed == if admitted { 2 } else { 1 }
        && absent == if admitted { 6 } else { 4 })?;
    if std::env::var_os("MRK_WINDOWS_ORDINARY_OUTPUT").is_some() {
        // A result-file route never accepts the legacy elevated negative case.
        // Every unchanged native observation/count/settlement gate is above.
        require_fact(admitted)?;
        let user = book.user.as_ref().ok_or(Error::State)?.user.bytes();
        return super::ordinary_owner::write_native_result(user);
    }
    let outcome = if admitted { "ordinary-admitted" } else { "elevated-primary-refused" };
    // Deliberately only public predicates/counts; never token/SID/account names,
    // paths, security descriptors, identifiers, privilege lists or raw handles.
    println!("\nMRK_WINDOWS_INSTALLED_NATIVE_V1 {{\"sourceSha\":\"{}\",\"context\":\"{}\",\"contextContracts\":1,\"admitted\":{},\"refused\":{},\"rootContracts\":{},\"rootNotExecuted\":{},\"primaryOriginals\":{},\"absentThreadReceipts\":{},\"closedOriginals\":{},\"unknown\":0,\"bookSettled\":true}}",
        source, outcome, usize::from(admitted), usize::from(!admitted), usize::from(admitted),
        usize::from(!admitted), primary, absent, closed);
    Ok(())
}
