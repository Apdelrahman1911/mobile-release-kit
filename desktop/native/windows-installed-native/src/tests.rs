//! Inert source-contract definitions, not native success evidence. These tests
//! never call invoke(), NativeBook::call(), an original read/open/close operation,
//! or any OS API. Only production state transitions and bounded DATA decoders run.
use super::*;
use windows_sys::Win32::System::SystemServices as SS;

// Every arena/handle below is an inert fixture, never entered into the OS. It is
// therefore safe to release these allocations, unlike real unresolved storage.
struct Inert { book: NativeBook }
impl Inert { fn new() -> Self { Self { book: NativeBook::new() } } }
impl Drop for Inert {
    fn drop(&mut self) {
        if let Some(frame) = self.book.active.take() { drop(ManuallyDrop::into_inner(frame)); }
        for slot in self.book.slots.drain(..) { drop(ManuallyDrop::into_inner(slot)); }
    }
}
fn enter_inert(book: &mut NativeBook, call: Call, handle: F::HANDLE) -> Result<()> {
    assert!(book.active.is_none());
    let token_length = match call {
        Call::Token(class) => token_information_length(class)?,
        _ => 0,
    };
    let output_handle = match call {
        Call::Open(i) | Call::ProcessToken(i) | Call::ThreadToken(i) => book.slot(i)?.output.get(),
        _ => null_mut(),
    };
    book.active = Some(ManuallyDrop::new(Box::pin(Arena {
        call, token_length, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
        input: Vec::new(), handle, output_handle, unicode: F::UNICODE_STRING::default(),
        attributes: OBJECT_ATTRIBUTES::default(), directory: false,
        bytes: UnsafeCell::new(Aligned([0; BUFFER])), count: UnsafeCell::new(u32::MAX),
        iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK {
            Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX,
        }), _pin: PhantomPinned,
    })));
    book.mark_entered(call)
}
fn return_inert(book: &mut NativeBook, returned: Returned, output: Option<F::HANDLE>,
    status: i32, information: usize) -> Result<Complete> {
    let frame = book.arena()?;
    // SAFETY: fixture allocations have never been passed to native code. There
    // is no concurrent writer and these are their real, pinned output addresses.
    unsafe {
        if let Some(value) = output {
            assert!(!frame.output_handle.is_null()); *frame.output_handle = value;
        }
        *frame.iosb.get() = IO::IO_STATUS_BLOCK {
            Anonymous: IO::IO_STATUS_BLOCK_0 { Status: status }, Information: information,
        };
    }
    frame.returned.set(Some(returned)); frame.phase.set(Phase::Returned);
    let call = frame.call;
    book.finish(call, returned)
}
fn own_inert(book: &mut NativeBook, original: &Original, number: usize) -> Result<()> {
    enter_inert(book, Call::Open(original.index), null_mut())?;
    return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(number as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize)?;
    Ok(())
}

#[test]
fn original_destinations_are_stable_registered_and_book_bound() -> Result<()> {
    let mut owner = ordinary_owner::ProcessFacts::new();
    assert!(!owner.passed() && !owner.returned);
    assert_eq!(owner.begin_close(false), Err(Error::State));
    assert_eq!(owner.begin_terminate(), Err(Error::State));
    owner.begin()?;
    assert_eq!((owner.process, owner.thread), (SlotState::Acquiring, SlotState::Acquiring));
    assert_eq!(owner.begin(), Err(Error::State));
    assert!(!owner.returned && !owner.passed()); // An unreturned create is not absence.
    // Same transition used by both native enumeration methods, with no native
    // invocation: cursor purpose and owned name may be selected only once.
    let mut mode = DirectoryMode::Unstarted;
    assert_eq!(mode.bind(DirectoryMode::Unstarted), Err(Error::State));
    mode.bind(DirectoryMode::Ancestor("Program Files".to_owned()))?;
    mode.bind(DirectoryMode::Ancestor("Program Files".to_owned()))?;
    assert_eq!(mode.bind(DirectoryMode::Ancestor("Other".to_owned())), Err(Error::State));
    assert_eq!(mode.bind(DirectoryMode::Ancestor("program files".to_owned())), Err(Error::State));
    assert_eq!(mode.bind(DirectoryMode::Strict), Err(Error::State));
    let mut strict = DirectoryMode::Unstarted;
    strict.bind(DirectoryMode::Strict)?; strict.bind(DirectoryMode::Strict)?;
    assert_eq!(strict.bind(DirectoryMode::Ancestor("Program Files".to_owned())), Err(Error::State));
    // A terminal cursor refuses before even changing its mode. Keep the slot
    // Reserved so a broken guard still cannot invoke native code with a fake
    // handle; the unchanged mode/ended assertions detect that regression.
    let mut cursor = Inert::new();
    let directory = cursor.book.reserve(Kind::Directory, None, "cursor", "cursor".to_owned())?;
    cursor.book.slot_mut(directory.index)?.directory_ended = true;
    assert!(matches!(cursor.book.next_entries(&directory), Err(Error::State)));
    assert!(matches!(cursor.book.next_ancestor_entries(&directory, "Program Files"), Err(Error::State)));
    assert_eq!(cursor.book.slot(directory.index)?.directory_mode, DirectoryMode::Unstarted);
    assert!(cursor.book.slot(directory.index)?.directory_ended);
    assert!(!cursor.book.started && cursor.book.active.is_none());
    cursor.book.mark_interrupted();
    assert!(matches!(cursor.book.next_ancestor_entries(&directory, ".."), Err(Error::Unknown)));
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    assert!(book.never_started());
    assert!(book.first_unavailable.is_none());
    let first = book.reserve(Kind::File, None, "first", "first".to_owned())?;
    let destination = book.slot(first.index)?.output.get();
    for i in 0..32 {
        let name = format!("entry-{i}"); book.reserve(Kind::File, None, &name, name.clone())?;
    }
    assert_eq!(book.slot(first.index)?.output.get(), destination);
    assert!(matches!(book.reserve(Kind::File, None, "first", "first".to_owned()), Err(Error::State)));
    let mut other = Inert::new();
    let foreign = other.book.reserve(Kind::File, None, "foreign", "foreign".to_owned())?;
    assert_eq!(book.index(&foreign), Err(Error::State));
    enter_inert(book, Call::Open(first.index), null_mut())?;
    assert_eq!(book.arena()?.output_handle, destination);
    assert_eq!(book.state(&first)?, SlotState::Acquiring);
    assert!(book.started && book.active.is_some());
    return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(11usize as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize)?;
    assert_eq!(book.state(&first)?, SlotState::Owned);
    assert!(book.active.is_none());
    Ok(())
}

#[test]
fn pending_and_lost_completion_keep_the_exact_arena_and_slots() -> Result<()> {
    // Same absorbing native owner decisions; no clock/worker/API is called.
    for timeout in [false, true] {
        let mut owner = ordinary_owner::ProcessFacts::new(); owner.begin()?;
        if timeout {
            owner.creation(true, 0, (101, 102, 201, 202), false)?;
            assert_eq!(owner.wait(F::WAIT_TIMEOUT, false), Err(Error::Unsafe));
        } else {
            assert_eq!(owner.creation(true, 0, (101, 102, 201, 202), true), Err(Error::Unsafe));
        }
        owner.begin_terminate()?;
        assert_eq!(owner.begin_terminate(), Err(Error::State)); // At most one terminate.
        owner.wait(F::WAIT_OBJECT_0, true)?; owner.exited(true, 0)?;
        owner.begin_close(true)?; owner.closed(true, true)?;
        owner.begin_close(false)?; owner.closed(false, true)?;
        assert!(!owner.passed()); // Late success cannot clear a deadline/failure.
    }
    let mut pending = ordinary_owner::ProcessFacts::new(); pending.begin()?;
    assert_eq!(pending.creation(false, F::ERROR_IO_PENDING, (0, 0, 0, 0), false), Err(Error::Unknown));
    assert!(pending.unknown && !pending.passed());
    assert_eq!(pending.begin_close(false), Err(Error::State));
    for (call, returned) in [
        (Call::Open(0), Returned::Nt(F::STATUS_PENDING)),
        (Call::ProcessToken(0), Returned::Boolean(0, F::ERROR_IO_PENDING)),
        (Call::Read(1), Returned::Boolean(0, F::ERROR_IO_PENDING)),
        (Call::FinalName, Returned::Count(0, F::ERROR_IO_PENDING)),
        (Call::Folder, Returned::Hresult(HRESULT_PENDING)),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let kind = if matches!(call, Call::ProcessToken(_)) { Kind::ProcessToken } else { Kind::File };
        let key = book.reserve(kind, None, "pending", "pending".to_owned())?;
        let acquiring = matches!(call, Call::Open(_) | Call::ProcessToken(_));
        if !acquiring { own_inert(book, &key, 21)?; }
        let destination = book.slot(key.index)?.output.get();
        enter_inert(book, call, if acquiring { null_mut() } else { 21usize as F::HANDLE })?;
        let arena = book.arena()? as *const Arena;
        assert!(matches!(return_inert(book, returned, None, F::STATUS_PENDING, usize::MAX), Err(Error::Unknown)));
        assert!(book.is_unknown());
        assert!(book.first_unavailable.is_none());
        assert_eq!(book.arena()? as *const Arena, arena);
        assert_eq!(book.slot(key.index)?.output.get(), destination);
        assert_eq!(book.state(&key)?, if acquiring { SlotState::Acquiring } else { SlotState::Owned });
        assert!(!book.settled());
    }
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let key = book.reserve(Kind::File, None, "lost", "lost".to_owned())?;
    enter_inert(book, Call::Open(key.index), null_mut())?;
    // Simulated loss only; no real worker exists in these definitions.
    book.mark_interrupted();
    assert!(matches!(return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(22usize as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize), Err(Error::Unknown)));
    assert_eq!(book.state(&key)?, SlotState::Acquiring); // Unknown never promotes
    assert!(book.active.is_some());
    assert!(book.first_unavailable.is_none());
    Ok(())
}

#[test]
fn acquisition_needs_a_definite_consistent_receipt() -> Result<()> {
    use std::time::Duration;
    // The actual next-effect gate is rechecked after an absence query returns,
    // not only before that query or after account creation has already occurred.
    for query_returned_seconds in [89, 90, 91] {
        let mut deadline_latched = false; let mut account_additions = 0;
        ordinary_owner::next_effect(Duration::from_secs(1), &mut deadline_latched)?;
        if ordinary_owner::next_effect(Duration::from_secs(query_returned_seconds), &mut deadline_latched).is_ok() {
            account_additions += 1;
        }
        assert_eq!(account_additions, if query_returned_seconds < 90 { 1 } else { 0 });
        assert_eq!(deadline_latched, query_returned_seconds >= 90);
        if deadline_latched {
            assert_eq!(ordinary_owner::next_effect(Duration::ZERO, &mut deadline_latched), Err(Error::Unsafe));
        }
    }
    for (ok, error, outputs, unknown) in [
        (false, F::ERROR_ACCESS_DENIED, (0, 0, 0, 0), false),
        (false, 0, (0, 0, 0, 0), true),
        (false, F::ERROR_ACCESS_DENIED, (101, 0, 0, 0), true),
        (true, 0, (0, 0, 0, 0), true),
        (true, 0, (101, 0, 201, 202), true),
        (true, 0, (101, 101, 201, 202), true),
        (true, 0, (101, 102, 0, 202), true),
        (true, 0, (101, 102, 201, 201), true),
    ] {
        let mut owner = ordinary_owner::ProcessFacts::new(); owner.begin()?;
        assert_eq!(owner.creation(ok, error, outputs, false),
            Err(if unknown { Error::Unknown } else { Error::Unavailable }));
        assert_eq!(owner.unknown, unknown);
        assert_eq!(owner.creation(true, 0, (101, 102, 201, 202), false), Err(Error::State));
        assert!(!owner.passed());
    }
    for (status, handle, io, information, no_handle) in [
        (F::STATUS_ACCESS_DENIED, null_mut(), F::STATUS_PENDING, usize::MAX, true),
        (F::STATUS_ACCESS_DENIED, 31usize as F::HANDLE, F::STATUS_PENDING, usize::MAX, false),
        (F::STATUS_SUCCESS, null_mut(), F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false),
        (F::STATUS_SUCCESS, F::INVALID_HANDLE_VALUE, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false),
        (F::STATUS_SUCCESS, 32usize as F::HANDLE, F::STATUS_PENDING, WP::FILE_OPENED as usize, false),
        (F::STATUS_SUCCESS, 33usize as F::HANDLE, F::STATUS_SUCCESS, usize::MAX, false),
        (1, null_mut(), F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let key = book.reserve(Kind::File, None, "receipt", "receipt".to_owned())?;
        enter_inert(book, Call::Open(key.index), null_mut())?;
        let result = return_inert(book, Returned::Nt(status), Some(handle), io, information);
        if no_handle {
            assert!(matches!(result, Err(Error::Unavailable)));
            assert_eq!(book.state(&key)?, SlotState::NoHandle);
            assert!(book.active.is_none() && !book.is_unknown());
            assert!(matches!(book.reserve(Kind::File, None, "receipt", "receipt".to_owned()), Err(Error::State)));
            assert!(matches!(book.first_unavailable, Some((Call::Open(i), Returned::Nt(value))) if i == key.index && value == status));
            book.retiring = true; // the only inert original is already NoHandle
            assert!(book.settled());
            let mut output = Vec::<u8>::new();
            hosted_tests::write_unavailable(book, &Err(Error::Unavailable), &mut output);
            let expected = format!("MRK_WINDOWS_INSTALLED_NATIVE_UNAVAILABLE={{\"api\":\"NtCreateFile\",\"selector\":null,\"resultKind\":\"ntstatus\",\"result\":{status},\"win32Error\":null}}\n");
            assert_eq!(output.as_slice(), expected.as_bytes());
        } else {
            assert!(matches!(result, Err(Error::Unknown)));
            assert!(book.active.is_some() && book.is_unknown());
            assert!(book.first_unavailable.is_none());
        }
    }
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let first = book.reserve(Kind::File, None, "one", "one".to_owned())?;
    own_inert(book, &first, 34)?;
    let second = book.reserve(Kind::File, None, "two", "two".to_owned())?;
    enter_inert(book, Call::Open(second.index), null_mut())?;
    assert!(matches!(return_inert(book, Returned::Nt(F::STATUS_SUCCESS), Some(34usize as F::HANDLE),
        F::STATUS_SUCCESS, WP::FILE_OPENED as usize), Err(Error::Unknown)));
    assert_eq!(book.state(&first)?, SlotState::Owned);
    assert!(book.first_unavailable.is_none());

    // Completed original-scalar families and every fixed public selector. These
    // frames are inert; no native query, path, token or privilege is observed.
    for (call, returned, api, selector, kind, value, error) in [
        (Call::Architecture, Returned::Boolean(0, 5), "IsWow64Process2", "null", "boolean", 0i64, "5"),
        (Call::HandleInfo, Returned::Boolean(0, 0), "GetHandleInformation", "null", "boolean", 0, "0"),
        (Call::Info(FS::FileBasicInfo, size_of::<FS::FILE_BASIC_INFO>()), Returned::Boolean(0, 5), "GetFileInformationByHandleEx", r#""FileBasicInfo""#, "boolean", 0, "5"),
        (Call::Info(FS::FileStandardInfo, size_of::<FS::FILE_STANDARD_INFO>()), Returned::Boolean(0, 5), "GetFileInformationByHandleEx", r#""FileStandardInfo""#, "boolean", 0, "5"),
        (Call::Info(FS::FileAttributeTagInfo, size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()), Returned::Boolean(0, 5), "GetFileInformationByHandleEx", r#""FileAttributeTagInfo""#, "boolean", 0, "5"),
        (Call::Info(FS::FileIdInfo, size_of::<FS::FILE_ID_INFO>()), Returned::Boolean(0, 5), "GetFileInformationByHandleEx", r#""FileIdInfo""#, "boolean", 0, "5"),
        (Call::Info(FS::FileCaseSensitiveInfo, size_of::<FS::FILE_CASE_SENSITIVE_INFO>()), Returned::Boolean(0, 5), "GetFileInformationByHandleEx", r#""FileCaseSensitiveInfo""#, "boolean", 0, "5"),
        (Call::VolumeName, Returned::Boolean(0, 5), "GetVolumeInformationByHandleW", "null", "boolean", 0, "5"),
        (Call::Security, Returned::Boolean(0, 5), "GetKernelObjectSecurity", "null", "boolean", 0, "5"),
        (Call::Token(S::TokenStatistics), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenStatistics""#, "boolean", 0, "5"),
        (Call::Token(S::TokenType), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenType""#, "boolean", 0, "5"),
        (Call::Token(S::TokenElevation), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenElevation""#, "boolean", 0, "5"),
        (Call::Token(S::TokenElevationType), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenElevationType""#, "boolean", 0, "5"),
        (Call::Token(S::TokenUIAccess), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenUIAccess""#, "boolean", 0, "5"),
        (Call::Token(S::TokenVirtualizationEnabled), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenVirtualizationEnabled""#, "boolean", 0, "5"),
        (Call::Token(S::TokenUser), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenUser""#, "boolean", 0, "5"),
        (Call::Token(S::TokenIntegrityLevel), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenIntegrityLevel""#, "boolean", 0, "5"),
        (Call::Token(S::TokenGroups), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenGroups""#, "boolean", 0, "5"),
        (Call::Token(S::TokenPrivileges), Returned::Boolean(0, 5), "GetTokenInformation", r#""TokenPrivileges""#, "boolean", 0, "5"),
        (Call::Token(S::TokenElevation), Returned::Boolean(0, F::ERROR_BAD_LENGTH), "GetTokenInformation", r#""TokenElevation""#, "boolean", 0, "24"),
        (Call::Token(S::TokenUser), Returned::Boolean(0, F::ERROR_INSUFFICIENT_BUFFER), "GetTokenInformation", r#""TokenUser""#, "boolean", 0, "122"),
        (Call::Privilege(PrivilegeName::ChangeNotify), Returned::Boolean(0, 5), "LookupPrivilegeValueW", r#""lookup-1""#, "boolean", 0, "5"),
        (Call::Privilege(PrivilegeName::Shutdown), Returned::Boolean(0, 5), "LookupPrivilegeValueW", r#""lookup-2""#, "boolean", 0, "5"),
        (Call::Privilege(PrivilegeName::Undock), Returned::Boolean(0, 5), "LookupPrivilegeValueW", r#""lookup-3""#, "boolean", 0, "5"),
        (Call::Privilege(PrivilegeName::IncreaseWorkingSet), Returned::Boolean(0, 5), "LookupPrivilegeValueW", r#""lookup-4""#, "boolean", 0, "5"),
        (Call::Privilege(PrivilegeName::TimeZone), Returned::Boolean(0, 5), "LookupPrivilegeValueW", r#""lookup-5""#, "boolean", 0, "5"),
        (Call::Read(1), Returned::Boolean(0, u32::MAX), "ReadFile", "null", "boolean", 0, "4294967295"),
        (Call::Entries, Returned::Boolean(0, 5), "GetFileInformationByHandleEx", r#""FileIdExtdDirectoryInfo""#, "boolean", 0, "5"),
        (Call::WindowsDirectory, Returned::Count(0, 5), "GetSystemWindowsDirectoryW", "null", "count", 0, "5"),
        (Call::SystemDirectory, Returned::Count(0, 5), "GetSystemDirectoryW", "null", "count", 0, "5"),
        (Call::Mapping, Returned::Count(0, 5), "QueryDosDeviceW", "null", "count", 0, "5"),
        (Call::FinalName, Returned::Count(0, u32::MAX), "GetFinalPathNameByHandleW", "null", "count", 0, "4294967295"),
        (Call::VolumeDevice, Returned::Nt(F::STATUS_ACCESS_DENIED), "NtQueryVolumeInformationFile", r#""FileFsDeviceInformation""#, "ntstatus", i64::from(F::STATUS_ACCESS_DENIED), "null"),
        (Call::Streams, Returned::Nt(F::STATUS_ACCESS_DENIED), "NtQueryInformationFile", r#""FileStreamInformation""#, "ntstatus", i64::from(F::STATUS_ACCESS_DENIED), "null"),
        (Call::Folder, Returned::Hresult(i32::MIN), "SHGetFolderPathW", "null", "hresult", i64::from(i32::MIN), "null"),
        (Call::Folder, Returned::Hresult(1), "SHGetFolderPathW", "null", "hresult", 1, "null"),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        enter_inert(book, call, null_mut())?;
        assert!(matches!(return_inert(book, returned, None, F::STATUS_PENDING, usize::MAX), Err(Error::Unavailable)));
        assert!(book.first_unavailable.is_some() && book.active.is_none() && !book.is_unknown());
        let mut output = Vec::<u8>::new();
        hosted_tests::write_unavailable(book, &Err(Error::Unavailable), &mut output);
        assert!(output.is_empty()); // not retired/settled yet
        book.retiring = true; // no slots or native originals in this fixture
        assert!(book.settled());
        hosted_tests::write_unavailable(book, &Err(Error::Unavailable), &mut output);
        let expected = format!("MRK_WINDOWS_INSTALLED_NATIVE_UNAVAILABLE={{\"api\":\"{api}\",\"selector\":{selector},\"resultKind\":\"{kind}\",\"result\":{value},\"win32Error\":{error}}}\n");
        assert_eq!(output.as_slice(), expected.as_bytes());
        assert!(output.len() < 512 && output.iter().filter(|&&b| b == b'\n').count() == 1);
    }

    // These completed receipts are success/absence/EOF, never Unavailable.
    for (call, returned) in [
        (Call::HandleInfo, Returned::Boolean(1, 0)),
        (Call::FinalName, Returned::Count(1, 0)),
        (Call::Folder, Returned::Hresult(F::S_OK)),
        (Call::VolumeDevice, Returned::Nt(F::STATUS_SUCCESS)),
        (Call::Entries, Returned::Boolean(0, F::ERROR_NO_MORE_FILES)),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        enter_inert(book, call, null_mut())?;
        return_inert(book, returned, None, F::STATUS_SUCCESS, 0)?;
        assert!(book.first_unavailable.is_none());
    }
    {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let original = book.reserve(Kind::ThreadToken, None, "", String::new())?;
        enter_inert(book, Call::ThreadToken(original.index), null_mut())?;
        return_inert(book, Returned::Boolean(0, F::ERROR_NO_TOKEN), Some(null_mut()), 0, 0)?;
        assert_eq!(book.state(&original)?, SlotState::NoHandle);
        assert!(book.first_unavailable.is_none());
    }
    {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let original = book.reserve(Kind::ProcessToken, None, "", String::new())?;
        enter_inert(book, Call::ProcessToken(original.index), null_mut())?;
        let complete = return_inert(book, Returned::Boolean(0, 5), Some(null_mut()), 0, 0)?;
        assert_eq!(book.state(&original)?, SlotState::NoHandle);
        assert!(book.first_unavailable.is_none()); // finish leaves this decision to its caller
        // The live observe_user_once edge is source-inspected, never invoked or
        // refactored here. Copy only this inert original's completed scalar.
        let returned = complete.arena.returned()?;
        assert!(matches!(returned, Returned::Boolean(0, 5)));
        book.remember_unavailable(complete.arena.call, returned);
        book.retiring = true;
        assert!(book.settled());
        let mut output = Vec::<u8>::new();
        hosted_tests::write_unavailable(book, &Err(Error::Unsafe), &mut output);
        assert!(output.is_empty()); // a masked initial failure is not emitted
        hosted_tests::write_unavailable(book, &Err(Error::Unavailable), &mut output);
        assert_eq!(output.as_slice(), b"MRK_WINDOWS_INSTALLED_NATIVE_UNAVAILABLE={\"api\":\"OpenProcessToken\",\"selector\":null,\"resultKind\":\"boolean\",\"result\":0,\"win32Error\":5}\n");
    }

    // Unrepresentable or mismatched scalar pairs cannot fabricate a diagnostic.
    // Inject only DATA into the private recorder, not a native return decision.
    for (call, returned) in [
        (Call::Folder, Returned::Nt(F::STATUS_ACCESS_DENIED)),
        (Call::VolumeDevice, Returned::Hresult(i32::MIN)),
        (Call::FinalName, Returned::Boolean(0, 5)),
        (Call::HandleInfo, Returned::Count(0, 5)),
        (Call::Info(FS::FileBasicInfo, 0), Returned::Boolean(0, 5)),
        (Call::Info(i32::MAX, 1), Returned::Boolean(0, 5)),
        (Call::Token(i32::MAX), Returned::Boolean(0, 5)),
        (Call::HandleInfo, Returned::Boolean(1, 0)),
        (Call::HandleInfo, Returned::Boolean(0, F::ERROR_IO_PENDING)),
        (Call::FinalName, Returned::Count(0, F::ERROR_IO_PENDING)),
        (Call::VolumeDevice, Returned::Nt(F::STATUS_PENDING)),
        (Call::VolumeDevice, Returned::Nt(1)),
        (Call::Folder, Returned::Hresult(HRESULT_PENDING)),
        (Call::Entries, Returned::Boolean(0, F::ERROR_NO_MORE_FILES)),
        (Call::ThreadToken(0), Returned::Boolean(0, F::ERROR_NO_TOKEN)),
        (Call::Close(0), Returned::Boolean(0, 5)),
        (Call::DriveType, Returned::Scalar(0)),
        (Call::FileType, Returned::Scalar(0)),
    ] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        book.remember_unavailable(call, returned);
        book.retiring = true;
        let mut output = Vec::<u8>::new();
        hosted_tests::write_unavailable(book, &Err(Error::Unavailable), &mut output);
        assert!(output.is_empty());
    }

    // First record survives another completed refusal and a completed inert
    // close. No settle_once or other live original method is invoked.
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let original = book.reserve(Kind::File, None, "diagnostic", "diagnostic".to_owned())?;
    own_inert(book, &original, 35)?;
    for (call, returned) in [
        (Call::HandleInfo, Returned::Boolean(0, 5)),
        (Call::FinalName, Returned::Count(0, 122)),
    ] {
        enter_inert(book, call, 35usize as F::HANDLE)?;
        assert!(matches!(return_inert(book, returned, None, 0, 0), Err(Error::Unavailable)));
        assert!(matches!(book.first_unavailable, Some((Call::HandleInfo, Returned::Boolean(0, 5)))));
    }
    book.retiring = true;
    enter_inert(book, Call::Close(original.index), 35usize as F::HANDLE)?;
    return_inert(book, Returned::Boolean(1, 0), None, 0, 0)?;
    assert!(book.settled());
    assert!(matches!(book.first_unavailable, Some((Call::HandleInfo, Returned::Boolean(0, 5)))));
    for observation in [Ok(true), Ok(false), Err(Error::Unsafe), Err(Error::Bounds), Err(Error::State), Err(Error::Unknown)] {
        let mut output = Vec::<u8>::new();
        hosted_tests::write_unavailable(book, &observation, &mut output);
        assert!(output.is_empty());
    }
    struct Writer { limit: usize, fail: bool, writes: usize, flushes: usize, bytes: Vec<u8> }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.fail { return Err(std::io::ErrorKind::BrokenPipe.into()); }
            let count = self.limit.min(bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]); Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1; Err(std::io::ErrorKind::Other.into())
        }
    }
    let observation: Result<bool> = Err(Error::Unavailable);
    for (limit, fail) in [(0, false), (7, false), (512, false), (512, true)] {
        let mut output = Writer { limit, fail, writes: 0, flushes: 0, bytes: Vec::new() };
        hosted_tests::write_unavailable(book, &observation, &mut output);
        assert_eq!((output.writes, output.flushes), (1, 0));
        assert_eq!(observation, Err(Error::Unavailable));
        if fail { assert!(output.bytes.is_empty()); }
        else if limit < 512 { assert_eq!(output.bytes.len(), limit); }
        else { assert!(output.bytes.len() < 512 && output.bytes.ends_with(b"\n")); }
    }
    book.unknown = true; // inert failed settlement must be silent, even with a record
    let mut output = Vec::<u8>::new();
    hosted_tests::write_unavailable(book, &observation, &mut output);
    assert!(output.is_empty());
    Ok(())
}

#[test]
fn close_retires_before_entry_and_failure_is_never_retried() -> Result<()> {
    use std::time::Duration;
    for closed in [false, true] {
        let mut owner = ordinary_owner::ProcessFacts::new(); owner.begin()?;
        owner.creation(true, 0, (101, 102, 201, 202), false)?;
        assert_eq!(owner.exited(true, 0), Err(Error::State));
        assert_eq!(owner.begin_close(false), Err(Error::State));
        owner.wait(F::WAIT_OBJECT_0, false)?; owner.exited(true, 0)?;
        let mut deadline_latched = false;
        assert_eq!(ordinary_owner::next_effect(Duration::from_secs(90), &mut deadline_latched), Err(Error::Unsafe));
        // Expiry refuses new effects, not the same original's once-only close.
        owner.begin_close(true)?;
        assert_eq!(owner.thread, SlotState::Closing);
        assert_eq!(owner.closed(true, closed), if closed { Ok(()) } else { Err(Error::Unknown) });
        assert_eq!(owner.begin_close(true), Err(Error::State));
        assert_eq!(owner.closed(true, true), Err(Error::State));
        owner.begin_close(false)?; owner.closed(false, true)?;
        assert_eq!(owner.passed(), closed);
        assert_eq!(owner.begin_close(false), Err(Error::State));
        assert_eq!(ordinary_owner::next_effect(Duration::ZERO, &mut deadline_latched), Err(Error::Unsafe));
        assert!(!(owner.passed() && !deadline_latched)); // Closed alone is not the owner's success gate.
    }
    // Already-settled originals do not authorize a late account deletion:
    // retirement's same-SID/Users observations must return within the same clock.
    for query_returned_seconds in [89, 90, 91] {
        let mut deadline_latched = false; let mut deletions = 0;
        ordinary_owner::next_effect(Duration::from_secs(1), &mut deadline_latched)?;
        if ordinary_owner::next_effect(Duration::from_secs(query_returned_seconds), &mut deadline_latched).is_ok() {
            deletions += 1;
        }
        assert_eq!(deletions, if query_returned_seconds < 90 { 1 } else { 0 });
        if deadline_latched {
            assert_eq!(ordinary_owner::next_effect(Duration::ZERO, &mut deadline_latched), Err(Error::Unsafe));
        }
    }
    let mut fixture = Inert::new(); let book = &mut fixture.book;
    let first = book.reserve(Kind::File, None, "close-one", "close-one".to_owned())?;
    own_inert(book, &first, 41)?;
    let other = book.reserve(Kind::File, None, "close-two", "close-two".to_owned())?;
    own_inert(book, &other, 42)?;
    book.retiring = true;
    enter_inert(book, Call::Close(first.index), 41usize as F::HANDLE)?;
    assert_eq!(book.state(&first)?, SlotState::Closing);
    // SAFETY: inert cell, not a native borrower or OS write destination.
    assert!(unsafe { *book.slot(first.index)?.output.get() }.is_null());
    assert_eq!(book.arena()?.handle, 41usize as F::HANDLE);
    assert!(matches!(return_inert(book, Returned::Boolean(0, F::ERROR_INVALID_HANDLE), None, 0, 0), Err(Error::Unknown)));
    assert_eq!(book.state(&first)?, SlotState::Unknown);
    assert!(book.active.is_none()); // completed close has no pending output buffer
    enter_inert(book, Call::Close(other.index), 42usize as F::HANDLE)?;
    return_inert(book, Returned::Boolean(1, 0), None, 0, 0)?;
    assert_eq!(book.state(&other)?, SlotState::Closed);
    assert!(book.is_unknown() && !book.settled());
    assert!(matches!(enter_inert(book, Call::Close(first.index), 41usize as F::HANDLE), Err(Error::Unknown)));
    assert!(matches!(return_inert(book, Returned::Boolean(1, 0), None, 0, 0), Err(Error::Unknown)));
    assert_eq!(book.state(&first)?, SlotState::Unknown);
    assert!(book.first_unavailable.is_none());
    Ok(())
}

fn put16(raw: &mut [u8], at: usize, value: u16) { raw[at..at+2].copy_from_slice(&value.to_le_bytes()); }
fn put32(raw: &mut [u8], at: usize, value: u32) { raw[at..at+4].copy_from_slice(&value.to_le_bytes()); }
fn put64(raw: &mut [u8], at: usize, value: u64) { raw[at..at+8].copy_from_slice(&value.to_le_bytes()); }
fn sid(authority: u8, sub: &[u32]) -> Vec<u8> {
    let mut raw = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, authority];
    for n in sub { raw.extend_from_slice(&n.to_le_bytes()); } raw
}
fn descriptor(owner: &[u8], aces: &[(u8, u8, u32, Vec<u8>)]) -> Vec<u8> {
    let mut raw = vec![0; size_of::<S::SECURITY_DESCRIPTOR_RELATIVE>()];
    raw[offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Revision)] = 1;
    put16(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Control), S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT);
    let owner_at = raw.len(); raw.extend_from_slice(owner);
    let acl_at = raw.len(); raw.resize(acl_at + size_of::<S::ACL>(), 0);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner), owner_at as u32);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl), acl_at as u32);
    raw[acl_at + offset_of!(S::ACL, AclRevision)] = 2;
    put16(&mut raw, acl_at + offset_of!(S::ACL, AceCount), aces.len() as u16);
    for (kind, flags, mask, principal) in aces {
        let at = raw.len(); let size = offset_of!(S::ACCESS_ALLOWED_ACE, SidStart) + principal.len();
        raw.resize(at + size, 0);
        raw[at + offset_of!(S::ACE_HEADER, AceType)] = *kind;
        raw[at + offset_of!(S::ACE_HEADER, AceFlags)] = *flags;
        put16(&mut raw, at + offset_of!(S::ACE_HEADER, AceSize), size as u16);
        put32(&mut raw, at + offset_of!(S::ACCESS_ALLOWED_ACE, Mask), *mask);
        raw[at + offset_of!(S::ACCESS_ALLOWED_ACE, SidStart)..at+size].copy_from_slice(principal);
    }
    let size = raw.len() - acl_at;
    put16(&mut raw, acl_at + offset_of!(S::ACL, AclSize), size as u16); raw
}
fn ordinary_descriptor(owner: &[u8], group: &[u8], aces: &[(u8, u8, u32, Vec<u8>)]) -> Vec<u8> {
    let mut raw = descriptor(owner, aces);
    let at = raw.len(); raw.extend_from_slice(group);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Group), at as u32);
    put16(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Control),
        S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT | S::SE_DACL_PROTECTED);
    raw
}

#[test]
fn acl_distinguishes_sibling_creation_from_replacement_and_mutation() -> Result<()> {
    use std::time::Duration;
    let mut deadline_latched = false; let mut grants = 0;
    // First mutation is timely; its original observation returns at the budget
    // boundary. Neither the next grant nor an invented fresh clock is admitted.
    for elapsed in [Duration::from_secs(89), Duration::from_secs(90), Duration::ZERO] {
        if ordinary_owner::next_effect(elapsed, &mut deadline_latched).is_ok() { grants += 1; }
    }
    assert_eq!(grants, 1); assert!(deadline_latched);
    let account = sid(5, &[21, 11, 22, 33, 1001]);
    let users = vec![sid(5, &[32, 545])];
    let absent = windows_sys::Win32::NetworkManagement::NetManagement::NERR_UserNotFound;
    assert!(ordinary_owner::fresh_account(absent, true, 0, &account, &users));
    for (status, null, added) in [(0, true, 0), (absent, false, 0), (absent, true, 2224)] {
        assert!(!ordinary_owner::fresh_account(status, null, added, &account, &users));
    }
    for groups in [Vec::new(), vec![sid(5, &[32, 544])],
        vec![sid(5, &[32, 545]), sid(5, &[32, 544])]] {
        assert!(!ordinary_owner::fresh_account(absent, true, 0, &account, &groups));
    }
    assert!(!ordinary_owner::fresh_account(absent, true, 0, &sid(5, &[18]), &users));
    let owner = sid(5, &[18]); let everyone = sid(1, &[0]);
    let allow = SS::ACCESS_ALLOWED_ACE_TYPE as u8; let deny = SS::ACCESS_DENIED_ACE_TYPE as u8;
    let raw = descriptor(&owner, &[(allow, 0, F::GENERIC_READ, everyone.clone())]);
    let facts = security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion)?;
    assert_eq!(facts.owner.bytes(), owner.as_slice()); assert_eq!(facts.aces.len(), 1);
    for right in [FS::DELETE, FS::FILE_DELETE_CHILD, FS::WRITE_DAC, FS::WRITE_OWNER,
        FS::FILE_WRITE_EA, FS::FILE_WRITE_ATTRIBUTES, FS::FILE_WRITE_DATA, FS::FILE_APPEND_DATA, F::GENERIC_WRITE] {
        let raw = descriptor(&owner, &[(deny, 0, right, everyone.clone()), (allow, 0, right, everyone.clone())]);
        assert_eq!(security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    }
    let sibling = descriptor(&owner, &[(allow, 0, FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA, everyone.clone())]);
    assert!(security::descriptor(&sibling, FileKind::Directory, AuthorityScope::AncestorOutsideVersion).is_ok());
    assert_eq!(security::descriptor(&sibling, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let replacement = descriptor(&owner, &[(allow, 0, FS::FILE_DELETE_CHILD, everyone.clone())]);
    assert_eq!(security::descriptor(&replacement, FileKind::Directory, AuthorityScope::AncestorOutsideVersion), Err(Error::Unsafe));
    let flags = (S::OBJECT_INHERIT_ACE | S::INHERIT_ONLY_ACE) as u8;
    let inherited = descriptor(&owner, &[(allow, flags, F::GENERIC_ALL, everyone.clone())]);
    assert!(security::descriptor(&inherited, FileKind::Directory, AuthorityScope::AncestorOutsideVersion).is_ok());
    let unsupported = descriptor(&owner, &[(255, flags, F::GENERIC_READ, everyone.clone())]);
    assert_eq!(security::descriptor(&unsupported, FileKind::Directory, AuthorityScope::AncestorOutsideVersion), Err(Error::Unsafe));
    let unknown_mask = descriptor(&owner, &[(deny, 0, 0x02000000, everyone.clone())]);
    assert_eq!(security::descriptor(&unknown_mask, FileKind::File, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let untrusted_owner = descriptor(&everyone, &[(allow, 0, F::GENERIC_READ, everyone.clone())]);
    assert_eq!(security::descriptor(&untrusted_owner, FileKind::File, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));

    // Exact CPython3.14 mode0700 shape: D:P plus SY/BA/OWNER RIGHTS OICI FA.
    // This exercises only the qualification policy, never a native grant.
    use ordinary_owner::{AclImage, InputCheck, InputRole, InputTrace};
    let parent = sid(5, &[21, 11, 22, 33, 500]);
    let admins = sid(5, &[32, 544]); let owner_rights = sid(3, &[4]);
    assert_eq!(owner_rights, [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0]);
    let oi_ci = (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) as u8;
    let python_aces = vec![(allow, oi_ci, FS::FILE_ALL_ACCESS, owner.clone()),
        (allow, oi_ci, FS::FILE_ALL_ACCESS, admins.clone()),
        (allow, oi_ci, FS::FILE_ALL_ACCESS, owner_rights.clone())];
    let fresh = || { let mut trace = InputTrace::default(); trace.at(InputRole::AclRoot, Some(3)); trace };
    let fault = |actual: &InputTrace, check| {
        let mut expected = fresh(); expected.record(check, None); assert_eq!(actual.first, expected.first);
    };
    for trusted in [&parent, &owner, &admins] {
        for directory in [false, true] {
            let mut trace = fresh();
            let raw = ordinary_descriptor(trusted, &admins, &python_aces);
            AclImage::parse_traced(&raw, &mut trace)?.base(&parent, &account, directory, &mut trace)?;
            assert!(trace.first.is_none());
        }
    }
    for (selected_owner, group, check) in [
        (&everyone, &admins, InputCheck::AclOwner), (&account, &admins, InputCheck::AclOwner),
        (&owner_rights, &admins, InputCheck::AclOwner), (&parent, &account, InputCheck::AclGroup),
    ] {
        let mut trace = fresh();
        let raw = ordinary_descriptor(selected_owner, group, &python_aces);
        assert_eq!(AclImage::parse_traced(&raw, &mut trace)?.base(&parent, &account, true, &mut trace), Err(Error::Unsafe));
        fault(&trace, check);
    }
    // Neither a creator-authority prefix nor another effective mutator gains
    // admission merely because exact OWNER RIGHTS is also present.
    for foreign in [everyone.clone(), sid(3, &[0]), sid(3, &[5]), sid(3, &[4, 0]), sid(5, &[4])] {
        let mut aces = python_aces.clone(); aces.push((allow, oi_ci, FS::FILE_ALL_ACCESS, foreign));
        let mut trace = fresh(); let raw = ordinary_descriptor(&parent, &admins, &aces);
        assert_eq!(AclImage::parse_traced(&raw, &mut trace)?.base(&parent, &account, true, &mut trace), Err(Error::Unsafe));
        fault(&trace, InputCheck::AclMutation);
    }
    for (kind, flags, mask, principal, expected) in [
        (allow, 0, FS::FILE_GENERIC_READ, account.clone(), Some(InputCheck::AclAccount)),
        (deny, 0, FS::FILE_GENERIC_READ, account.clone(), Some(InputCheck::AclAccount)),
        (allow, oi_ci, 0x02000000, owner_rights.clone(), Some(InputCheck::AclMask)),
        (deny, oi_ci, 0x02000000, owner_rights.clone(), Some(InputCheck::AclMask)),
        (allow, oi_ci, F::GENERIC_ALL, owner_rights, None),
        (deny, 0, FS::FILE_ALL_ACCESS, everyone.clone(), None),
        (allow, oi_ci | S::INHERIT_ONLY_ACE as u8, FS::FILE_ALL_ACCESS, everyone.clone(), None),
        (allow, 0, FS::FILE_GENERIC_READ, everyone, None),
    ] {
        let mut aces = python_aces.clone(); aces.push((kind, flags, mask, principal));
        let mut trace = fresh(); let raw = ordinary_descriptor(&parent, &admins, &aces);
        let result = AclImage::parse_traced(&raw, &mut trace)?.base(&parent, &account, true, &mut trace);
        if let Some(check) = expected { assert_eq!(result, Err(Error::Unsafe)); fault(&trace, check); }
        else { result?; assert!(trace.first.is_none()); }
    }
    Ok(())
}

#[test]
fn acl_bounds_and_actual_trusted_sid_are_required() -> Result<()> {
    let before = ordinary_stamp();
    let mut after = before.clone(); after.change += 1;
    assert!(ordinary_owner::acl_stamp(&before, &after));
    after.change = before.change - 1;
    assert!(!ordinary_owner::acl_stamp(&before, &after));
    for field in 0..8 {
        let mut changed = before.clone(); changed.change += 1;
        match field {
            0 => changed.volume += 1, 1 => changed.id[15] ^= 0x80,
            2 => changed.creation += 1, 3 => changed.write += 1,
            4 => changed.size += 1, 5 => changed.allocation += 1,
            6 => changed.links += 1, _ => changed.attributes ^= FS::FILE_ATTRIBUTE_HIDDEN,
        }
        assert!(!ordinary_owner::acl_stamp(&before, &changed));
    }
    let owner = sid(5, &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464]);
    let mut raw = descriptor(&owner, &[]);
    assert!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion).is_ok());
    assert_eq!(security::descriptor(&raw[..raw.len()-1], FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let acl_at = decode::u32_at(&raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl))?;
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl), 0);
    assert_eq!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl), acl_at);
    put32(&mut raw, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Group), acl_at);
    assert_eq!(security::descriptor(&raw, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let system = sid(5, &[18]);
    let mut overlapping = descriptor(&system, &[(SS::ACCESS_ALLOWED_ACE_TYPE as u8, 0, F::GENERIC_READ, system.clone())]);
    let dacl = decode::u32_at(&overlapping, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Dacl))? as usize;
    // Valid trusted owner SID, but illegally borrowed from inside its DACL ACE.
    let owner_in_ace = dacl + size_of::<S::ACL>() + offset_of!(S::ACCESS_ALLOWED_ACE, SidStart);
    put32(&mut overlapping, offset_of!(S::SECURITY_DESCRIPTOR_RELATIVE, Owner), owner_in_ace as u32);
    assert_eq!(security::descriptor(&overlapping, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));
    let lookalike = descriptor(&sid(5, &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478465]), &[]);
    assert_eq!(security::descriptor(&lookalike, FileKind::Directory, AuthorityScope::ImmutableVersion), Err(Error::Unsafe));

    use ordinary_owner::{AclImage, InputCheck, InputRole, InputTrace};
    let parent = sid(5, &[21, 11, 22, 33, 500]); let account = sid(5, &[21, 11, 22, 33, 1001]);
    let admins = sid(5, &[32, 544]); let allow = SS::ACCESS_ALLOWED_ACE_TYPE as u8;
    let oi_ci = (S::OBJECT_INHERIT_ACE | S::CONTAINER_INHERIT_ACE) as u8;
    let aces = vec![(allow, oi_ci, FS::FILE_ALL_ACCESS, system),
        (allow, oi_ci, FS::FILE_ALL_ACCESS, admins.clone()),
        (allow, oi_ci, FS::FILE_ALL_ACCESS, sid(3, &[4]))];
    let raw = ordinary_descriptor(&parent, &admins, &aces);
    let fresh = || { let mut trace = InputTrace::default(); trace.at(InputRole::AclRoot, Some(3)); trace };
    let image = AclImage::parse_traced(&raw, &mut fresh())?;
    // These are the actual live initializer's pure operands, not an object
    // SECURITY_INFORMATION mask or a copied self-relative control word.
    for (control, value) in [
        (0x8004_u16, 0_u16), (0x9004, 0x1000),
        (0x8104, 0), (0x9104, 0x1000), // unrelated AUTO_INHERIT_REQ
        (0x8404, 0), (0x9404, 0x1000), // unrelated AUTO_INHERITED
        (0x8504, 0), (0x9504, 0x1000), // both unrelated control bits
    ] {
        let mut original = raw.clone(); put16(&mut original, 2, control);
        let selected = AclImage::parse_traced(&original, &mut fresh())?;
        assert_eq!(selected.dacl_control(), (0x1000, value));
    }
    let (expected, acl) = image.add(&account, FS::FILE_TRAVERSE, &mut fresh())?;
    let mut added = aces.clone(); added.push((allow, 0, FS::FILE_TRAVERSE, account.clone()));
    let raw_after = ordinary_descriptor(&parent, &admins, &added);
    let acl_at = decode::u32_at(&raw_after, 16)? as usize;
    let acl_size = decode::u16_at(&raw_after, acl_at + 2)? as usize;
    assert_eq!(&raw_after[acl_at..acl_at + acl_size], &acl.0[..acl_size]);
    let mut after = before.clone(); after.change += 1;
    for stamp in [&before, &after] {
        let mut trace = fresh(); expected.readback(&before, stamp, &raw, &raw_after, &mut trace)?;
        assert!(trace.first.is_none()); // Exact equality remains admitted.
    }
    // Reproduce the observed 0x9004 -> 0x8004 loss, and reject the reverse
    // unrequested protection change. Exact equality still passes in both cases.
    for (original_control, wrong_control) in [(0x9004, 0x8004), (0x8004, 0x9004)] {
        let mut original = raw.clone(); put16(&mut original, 2, original_control);
        let selected = AclImage::parse_traced(&original, &mut fresh())?;
        let (expected_control, _) = selected.add(&account, FS::FILE_TRAVERSE, &mut fresh())?;
        let mut matching = raw_after.clone(); put16(&mut matching, 2, original_control);
        let mut matching_trace = fresh();
        expected_control.readback(&before, &after, &original, &matching, &mut matching_trace)?;
        assert!(matching_trace.first.is_none());
        let mut wrong = matching.clone(); put16(&mut wrong, 2, wrong_control);
        let mut trace = fresh();
        assert_eq!(expected_control.readback(&before, &after, &original, &wrong, &mut trace), Err(Error::Unsafe));
        let mut wanted = fresh();
        assert_eq!(wanted.control(original_control, wrong_control), Err(Error::Unsafe));
        assert_eq!(trace.first, wanted.first);
    }
    // A pre-existing inherited sequence stays byte-identical and in order;
    // the one explicit noninheriting account ACE precedes it, never propagates.
    let inherited: Vec<_> = aces.iter().map(|(k, f, m, s)| (*k, *f | S::INHERITED_ACE as u8, *m, s.clone())).collect();
    let inherited_raw = ordinary_descriptor(&parent, &admins, &inherited);
    let inherited_image = AclImage::parse_traced(&inherited_raw, &mut fresh())?;
    let (inherited_expected, _) = inherited_image.add(&account, FS::FILE_TRAVERSE, &mut fresh())?;
    let mut inherited_added = inherited; inherited_added.insert(0, (allow, 0, FS::FILE_TRAVERSE, account));
    inherited_expected.readback(&before, &after, &inherited_raw,
        &ordinary_descriptor(&parent, &admins, &inherited_added), &mut fresh())?;

    for check in [InputCheck::AclStamp, InputCheck::AclControl, InputCheck::AclOwnerEqual,
        InputCheck::AclGroupEqual, InputCheck::AclRevision, InputCheck::AclAces, InputCheck::AclChanged, InputCheck::AclLayout] {
        let mut selected = raw_after.clone(); let mut stamp = after.clone();
        match check {
            InputCheck::AclStamp => stamp.id[15] ^= 0x80,
            InputCheck::AclControl => { let value = decode::u16_at(&selected, 2)?; put16(&mut selected, 2, value ^ S::SE_DACL_AUTO_INHERITED); }
            InputCheck::AclOwnerEqual => { let at = decode::u32_at(&selected, 4)? as usize; selected[at + parent.len() - 1] ^= 1; }
            InputCheck::AclGroupEqual => { let at = decode::u32_at(&selected, 8)? as usize; selected[at + admins.len() - 1] ^= 1; }
            InputCheck::AclRevision => selected[acl_at] = 4,
            InputCheck::AclAces => { let mut reordered = added.clone(); reordered.swap(0, 2); selected = ordinary_descriptor(&parent, &admins, &reordered); }
            InputCheck::AclLayout => selected[0] = 0,
            InputCheck::AclChanged => (),
            _ => unreachable!(),
        }
        let selected_before = if check == InputCheck::AclChanged { &selected } else { &raw };
        let mut trace = fresh();
        assert_eq!(expected.readback(&before, &stamp, selected_before, &selected, &mut trace), Err(Error::Unsafe));
        let mut wanted = fresh();
        if check == InputCheck::AclControl {
            assert_eq!(wanted.control(decode::u16_at(&raw_after, 2)?, decode::u16_at(&selected, 2)?), Err(Error::Unsafe));
        } else { wanted.record(check, None); }
        assert_eq!(trace.first, wanted.first);
    }
    for field in [0usize, 8, acl_at, acl_at + 8] {
        let mut malformed = raw_after.clone();
        match field {
            0 => malformed.truncate(19),
            8 => put32(&mut malformed, 8, 0),
            at if at == acl_at => put16(&mut malformed, at + 4, 1025),
            at => malformed[at] = 255,
        }
        let mut trace = fresh();
        assert!(AclImage::parse_traced(&malformed, &mut trace).is_err());
        let mut wanted = fresh(); wanted.record(InputCheck::AclLayout, None);
        assert_eq!(trace.first, wanted.first);
    }
    let mut trace = fresh();
    assert!(matches!(image.add(&vec![0; BUFFER], FS::FILE_TRAVERSE, &mut trace), Err(Error::Unsafe)));
    let mut wanted = fresh(); wanted.record(InputCheck::AclCapacity, None);
    assert_eq!(trace.first, wanted.first);
    Ok(())
}

fn token_sid(header: usize, field: usize, attributes: usize, flags: u32, principal: &[u8]) -> Vec<u8> {
    let mut raw = vec![0; header + principal.len()]; raw[header..].copy_from_slice(principal);
    let address = raw.as_ptr() as usize + header;
    put64(&mut raw, field, address as u64); put32(&mut raw, attributes, flags); raw
}
#[test]
fn token_context_pointer_bounds_and_enableable_authority_are_checked() -> Result<()> {
    let mut wait = ordinary_owner::ProcessFacts::new(); wait.begin()?;
    wait.creation(true, 0, (101, 102, 201, 202), false)?;
    // 259 (STILL_ACTIVE) is not a wait finality receipt or a successful exit.
    assert_eq!(wait.wait(259, false), Err(Error::Unknown));
    assert_eq!(wait.exited(true, 0), Err(Error::State));
    assert_eq!(wait.begin_close(false), Err(Error::State));
    for (ok, code) in [(true, 259), (true, 1), (false, 0)] {
        let mut owner = ordinary_owner::ProcessFacts::new(); owner.begin()?;
        owner.creation(true, 0, (101, 102, 201, 202), false)?;
        owner.wait(F::WAIT_OBJECT_0, false)?;
        assert_eq!(owner.exited(ok, code), if ok { Ok(()) } else { Err(Error::Unknown) });
        owner.begin_close(true)?; owner.closed(true, true)?;
        owner.begin_close(false)?; owner.closed(false, true)?;
        assert!(!owner.passed());
    }
    // Literal target expectations are independent of the production selector.
    // DWORD is the fixed output for both UIAccess and VirtualizationEnabled.
    for (actual, expected) in [
        (size_of::<S::TOKEN_STATISTICS>(), 56usize),
        (size_of::<S::TOKEN_TYPE>(), 4),
        (size_of::<S::TOKEN_ELEVATION>(), 4),
        (size_of::<S::TOKEN_ELEVATION_TYPE>(), 4),
        (size_of::<u32>(), 4),
    ] { assert_eq!(actual, expected); }
    assert_eq!(offset_of!(S::TOKEN_ELEVATION, TokenIsElevated), 0);
    assert_eq!(BUFFER, 65_536);
    assert_eq!(size_of::<Aligned>(), 65_536);
    for (class, expected) in [
        (S::TokenStatistics, 56u32),
        (S::TokenType, 4),
        (S::TokenElevation, 4),
        (S::TokenElevationType, 4),
        (S::TokenUIAccess, 4),
        (S::TokenVirtualizationEnabled, 4),
        (S::TokenUser, 65_536),
        (S::TokenIntegrityLevel, 65_536),
        (S::TokenGroups, 65_536),
        (S::TokenPrivileges, 65_536),
    ] {
        assert_eq!(token_information_length(class)?, expected);
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        enter_inert(book, Call::Token(class), null_mut())?;
        assert_eq!(book.arena()?.token_length, expected);
        let arena = book.arena()? as *const Arena;
        let buffer = book.arena()?.buffer();
        assert_eq!(buffer as usize % 8, 0);
        let completed = return_inert(book, Returned::Boolean(1, 0), None, F::STATUS_PENDING, usize::MAX)?;
        assert_eq!(completed.arena.as_ref().get_ref() as *const Arena, arena);
        assert_eq!(completed.arena.buffer(), buffer);
        // Initialized allocation extent only, not a successful native payload.
        assert_eq!(completed.bytes(65_536)?.len(), 65_536);
        assert!(matches!(completed.bytes(65_537), Err(Error::Unsafe)));
        assert_eq!(completed.count(), Err(Error::Unsafe)); // untouched sentinel
        assert!(book.active.is_none() && !book.is_unknown());
    }
    for (class, header) in [
        (S::TokenUser, size_of::<S::TOKEN_USER>()),
        (S::TokenIntegrityLevel, size_of::<S::TOKEN_MANDATORY_LABEL>()),
        (S::TokenGroups, size_of::<S::TOKEN_GROUPS>()),
        (S::TokenPrivileges, size_of::<S::TOKEN_PRIVILEGES>()),
    ] { assert!(token_information_length(class)? as usize > header); }
    for class in [-1, 0, S::TokenOwner, i32::MAX] {
        assert_eq!(token_information_length(class), Err(Error::State));
        let mut fixture = Inert::new();
        assert_eq!(enter_inert(&mut fixture.book, Call::Token(class), null_mut()), Err(Error::State));
        assert!(fixture.book.never_started());
    }
    // Complete's generic initialized-buffer bound is not the separate exact
    // 4/56-byte consumer check. All of these counts are inert DATA, not OS output.
    for count in [0u32, 4, 56, 65_536, 65_537, u32::MAX] {
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        enter_inert(book, Call::Token(S::TokenUser), null_mut())?;
        // SAFETY: this fixture arena has never been passed to native code.
        unsafe { *book.arena()?.count.get() = count; }
        let completed = return_inert(book, Returned::Boolean(1, 0), None, F::STATUS_PENDING, usize::MAX)?;
        assert_eq!(completed.count(), if count <= 65_536 { Ok(count as usize) } else { Err(Error::Unsafe) });
    }

    let allowed = [101, 102, 103, 104, 105];
    let identity = TokenIdentity { token_id: 1, authentication_id: 2, modified_id: 3, groups: 1, privileges: 1 };
    let mut statistics = vec![0u8; 56];
    put32(&mut statistics, offset_of!(S::TOKEN_STATISTICS, TokenType), S::TokenPrimary as u32);
    put32(&mut statistics, offset_of!(S::TOKEN_STATISTICS, GroupCount), identity.groups);
    put32(&mut statistics, offset_of!(S::TOKEN_STATISTICS, PrivilegeCount), identity.privileges);
    put64(&mut statistics, offset_of!(S::TOKEN_STATISTICS, TokenId), identity.token_id);
    put64(&mut statistics, offset_of!(S::TOKEN_STATISTICS, AuthenticationId), identity.authentication_id);
    put64(&mut statistics, offset_of!(S::TOKEN_STATISTICS, ModifiedId), identity.modified_id);
    assert_eq!(security::statistics(&statistics), Ok(identity));
    assert_eq!(security::statistics(&statistics[..55]), Err(Error::Unsafe));
    statistics.push(0);
    assert_eq!(security::statistics(&statistics), Err(Error::Unsafe));
    let user_field = offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid);
    let mut user = token_sid(size_of::<S::TOKEN_USER>(), user_field,
        offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes), 0, &sid(5, &[21, 11, 22, 33, 1001]));
    let mut integrity = token_sid(size_of::<S::TOKEN_MANDATORY_LABEL>(),
        offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Sid),
        offset_of!(S::TOKEN_MANDATORY_LABEL, Label) + offset_of!(S::SID_AND_ATTRIBUTES, Attributes),
        (SS::SE_GROUP_INTEGRITY | SS::SE_GROUP_INTEGRITY_ENABLED) as u32, &sid(16, &[8192]));
    let group_header = offset_of!(S::TOKEN_GROUPS, Groups);
    let group_attribute = group_header + offset_of!(S::SID_AND_ATTRIBUTES, Attributes);
    let mut groups = token_sid(group_header + size_of::<S::SID_AND_ATTRIBUTES>(),
        group_header + offset_of!(S::SID_AND_ATTRIBUTES, Sid), group_attribute,
        SS::SE_GROUP_USE_FOR_DENY_ONLY as u32, &sid(5, &[32, 544]));
    put32(&mut groups, offset_of!(S::TOKEN_GROUPS, GroupCount), 1);
    let privilege = offset_of!(S::TOKEN_PRIVILEGES, Privileges);
    let mut privileges = vec![0; privilege + size_of::<S::LUID_AND_ATTRIBUTES>()];
    put32(&mut privileges, offset_of!(S::TOKEN_PRIVILEGES, PrivilegeCount), 1);
    put64(&mut privileges, privilege + offset_of!(S::LUID_AND_ATTRIBUTES, Luid), allowed[0]);
    let check = |u: &[u8], i: &[u8], g: &[u8], p: &[u8], elevated: u32| security::token_facts(identity,
        S::TokenPrimary as u32, elevated, S::TokenElevationTypeLimited as u32, 0, 0, u, i, g, p, &allowed);
    assert!(check(&user, &integrity, &groups, &privileges, 0).is_ok());
    assert_eq!(check(&user, &integrity, &groups, &privileges, 1), Err(Error::Unsafe));
    let address = user.as_ptr() as usize;
    for pointer in [0, address, address + user.len(), address + size_of::<S::TOKEN_USER>() + 1] {
        put64(&mut user, user_field, pointer as u64);
        assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    }
    put64(&mut user, user_field, (address + size_of::<S::TOKEN_USER>()) as u64);
    put32(&mut integrity, size_of::<S::TOKEN_MANDATORY_LABEL>() + 8, 12288); // high, not medium
    assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    put32(&mut integrity, size_of::<S::TOKEN_MANDATORY_LABEL>() + 8, 8192);
    for flags in [0, SS::SE_GROUP_ENABLED as u32, (SS::SE_GROUP_ENABLED | SS::SE_GROUP_USE_FOR_DENY_ONLY) as u32] {
        put32(&mut groups, group_attribute, flags);
        assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    }
    put32(&mut groups, group_attribute, SS::SE_GROUP_USE_FOR_DENY_ONLY as u32);
    put64(&mut privileges, privilege + offset_of!(S::LUID_AND_ATTRIBUTES, Luid), 999); // present but disabled
    assert_eq!(check(&user, &integrity, &groups, &privileges, 0), Err(Error::Unsafe));
    Ok(())
}

fn entry(name: &str, id: [u8; 16]) -> Vec<u8> {
    let text: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let header = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileName);
    let mut raw = vec![0; header + text.len()]; raw[header..].copy_from_slice(&text);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileNameLength), text.len() as u32);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    let at = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileId); raw[at..at+16].copy_from_slice(&id); raw
}
#[test]
fn metadata_and_directory_keep_the_full_identity_not_a_low_half() -> Result<()> {
    // Path equality can hide Windows separator differences. The owner compares
    // exact DOS name text, so check the shared construction's actual spelling.
    let directories = ordinary_owner::fixed_directories(std::path::Path::new(r"C:\owned"));
    assert_eq!(directories.len(), 4);
    for ((role, path), (expected_role, expected_path)) in directories.iter().zip([
        ("target", r"C:\owned\target"),
        ("target/x86_64-pc-windows-msvc", r"C:\owned\target\x86_64-pc-windows-msvc"),
        ("target/x86_64-pc-windows-msvc/debug", r"C:\owned\target\x86_64-pc-windows-msvc\debug"),
        ("target/x86_64-pc-windows-msvc/debug/deps", r"C:\owned\target\x86_64-pc-windows-msvc\debug\deps"),
    ]) {
        assert_eq!(*role, expected_role);
        assert_eq!(path.to_str(), Some(expected_path));
    }
    // Pure first-fault DATA: no OriginalFile/close/native calls. A later cached
    // error reset, failed predicate or phase change cannot replace the cause.
    use ordinary_owner::{InputCheck, InputRole, InputStatus, InputTrace};
    let mut trace = InputTrace::default();
    assert_eq!(trace.need(false, InputCheck::NameExact), Err(Error::Unsafe));
    assert!(trace.first.is_none()); // Existing untraced helper callers stay disabled.
    trace.at(InputRole::Request, Some(3));
    let mut cached_error = u32::MAX;
    trace.record(InputCheck::ReadReturned, Some(InputStatus::Win32(cached_error)));
    let first = trace.first;
    cached_error = 0;
    trace.at(InputRole::Artifact, Some(39));
    trace.record(InputCheck::ReadReturned, Some(InputStatus::Win32(cached_error)));
    assert_eq!(trace.need(false, InputCheck::ArtifactStable), Err(Error::Unsafe));
    assert_eq!(trace.control(0, u16::MAX), Err(Error::Unsafe));
    trace.at(InputRole::AclOutput, Some(39));
    trace.record(InputCheck::AclSetReturned, Some(InputStatus::Win32(997)));
    assert_eq!(trace.first, first);
    let mut output = Vec::new();
    ordinary_owner::write_refusal(&mut output, "original-file-close", None, true, trace.first).unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    assert!(text.contains("\"role\":\"Request\",\"slot\":3,\"check\":\"ReadReturned\""));
    assert!(text.contains("\"status\":{\"domain\":\"win32\",\"code\":4294967295}"));
    assert!(!text.contains("\"control\"")); // A later ACL mismatch cannot attach facts to the first cause.
    assert!(text.ends_with("\"unknown\":true,\"cleanupNotRetried\":true}\n"));
    let mut predicate = InputTrace::default(); predicate.at(InputRole::Ancestor, None);
    assert_eq!(predicate.need(false, InputCheck::NameExact), Err(Error::Unsafe));
    output.clear();
    ordinary_owner::write_refusal(&mut output, "original-inputs", None, false, predicate.first).unwrap();
    assert!(std::str::from_utf8(&output).unwrap().contains("\"check\":\"NameExact\",\"status\":null"));
    let mut hash = InputTrace::default(); hash.at(InputRole::Command, Some(39));
    hash.record(InputCheck::HashReturned, Some(InputStatus::NtStatus(i32::MIN)));
    output.clear();
    ordinary_owner::write_refusal(&mut output, "account-original-retirement",
        Some((false, u32::MAX, Some(u32::MAX), [u32::MAX; 8])), false, hash.first).unwrap();
    // Leaves32 bytes beyond this worst numeric record for every closed label's
    // length difference, optional null ordinal, and all current stage strings.
    assert!(output.len() + 32 <= 768);
    assert!(std::str::from_utf8(&output).unwrap().contains("\"domain\":\"ntstatus\",\"code\":-2147483648"));
    // Control facts are u16 numbers only, on the first control mismatch. Later
    // native status/role changes cannot replace them; initializer BOOLs carry
    // no invented GetLastError. Disabled traces still remain disabled.
    let mut disabled = InputTrace::default();
    assert_eq!(disabled.control(0, u16::MAX), Err(Error::Unsafe)); assert!(disabled.first.is_none());
    let mut control = InputTrace::default(); control.at(InputRole::AclArtifact, None);
    control.control(u16::MAX, u16::MAX)?; assert!(control.first.is_none());
    assert_eq!(control.control(u16::MAX, u16::MAX - 1), Err(Error::Unsafe));
    let control_first = control.first;
    control.at(InputRole::Parent, Some(40));
    control.record(InputCheck::DescriptorReturned, Some(InputStatus::Win32(u32::MAX)));
    assert_eq!(control.control(0, 1), Err(Error::Unsafe)); assert_eq!(control.first, control_first);
    output.clear();
    ordinary_owner::write_refusal(&mut output, "account-original-retirement",
        Some((false, u32::MAX, Some(u32::MAX), [u32::MAX; 8])), false, control.first).unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    assert!(text.contains("\"role\":\"AclArtifact\",\"slot\":null,\"check\":\"AclControl\",\"status\":null"));
    assert!(text.contains("\"control\":{\"expected\":65535,\"observed\":65534}"));
    assert!(output.len() + 32 <= 768);
    for check in [InputCheck::AclInitialize, InputCheck::AclDacl, InputCheck::AclControlInput, InputCheck::AclDeadline,
        InputCheck::AclTransitions, InputCheck::ParentPrimary, InputCheck::ParentUser,
        InputCheck::ParentIdentity, InputCheck::ParentSettlement] {
        let mut trace = InputTrace::default(); trace.at(InputRole::AclOutput, Some(40));
        assert_eq!(trace.need(false, check), Err(Error::Unsafe)); output.clear();
        ordinary_owner::write_refusal(&mut output, "exact-acl", None, false, trace.first).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.contains("\"slot\":null") && text.contains("\"status\":null") && !text.contains("\"control\""));
    }
    for check in [InputCheck::OutputCreate, InputCheck::AclSetReturned, InputCheck::DescriptorReturned] {
        for code in [0, 997, u32::MAX] {
            let mut trace = InputTrace::default(); trace.at(InputRole::AclOutput, Some(39));
            trace.record(check, Some(InputStatus::Win32(code))); let first = trace.first;
            trace.record(InputCheck::ParentSettlement, None); assert_eq!(trace.first, first);
            output.clear(); ordinary_owner::write_refusal(&mut output, "original-acl-operation", None, true, first).unwrap();
            let text = std::str::from_utf8(&output).unwrap();
            assert!(text.contains(&format!("\"domain\":\"win32\",\"code\":{code}")));
            assert!(text.ends_with("\"unknown\":true,\"cleanupNotRetried\":true}\n"));
        }
    }
    let mut too_small = [0u8; 16];
    assert!(ordinary_owner::write_refusal(&mut std::io::Cursor::new(&mut too_small[..]),
        "original-inputs", None, false, first).is_err());
    let stamp = ordinary_stamp();
    let raw = ordinary_request(&stamp);
    let binding = ordinary_owner::Binding::parse(raw.as_bytes())?;
    assert!(binding.matches(&stamp));
    let mut changed = stamp.clone(); changed.id[15] ^= 0x80;
    assert!(!binding.matches(&changed));
    changed = stamp.clone(); changed.change += 1;
    assert!(ordinary_owner::acl_stamp(&stamp, &changed));
    assert!(!binding.matches(&changed)); // Requires the separate exact ACL transition.
    for altered in [raw.replace("attempt=1", "attempt=2"), raw.replace("runId=123456", "runId=0"),
        raw.replace("artifactBytes=37", "artifactBytes=0"), raw.replace("sourceSha=", "other="),
        raw.replace('\n', "\r\n"), raw.clone() + "extra=1\n",
        raw.replace("C:\\owned\\native.exe", "\\\\host\\share\\native.exe"),
        raw.replace("artifactIdentity=", "commandSha256=")] {
        assert!(ordinary_owner::Binding::parse(altered.as_bytes()).is_err());
    }
    let mut basic = vec![0; size_of::<FS::FILE_BASIC_INFO>()];
    let mut standard = vec![0; size_of::<FS::FILE_STANDARD_INFO>()];
    let mut tag = vec![0; size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()];
    let mut id = vec![0; size_of::<FS::FILE_ID_INFO>()];
    put32(&mut basic, offset_of!(FS::FILE_BASIC_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    put32(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks), 1);
    put64(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, EndOfFile), 37);
    put64(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, AllocationSize), 4096);
    put32(&mut tag, offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    put64(&mut id, offset_of!(FS::FILE_ID_INFO, VolumeSerialNumber), 0x1122334455667788);
    let mut full = [0u8; 16]; full[0] = 1; full[15] = 0x80;
    let at = offset_of!(FS::FILE_ID_INFO, FileId); id[at..at+16].copy_from_slice(&full);
    let before = decode::metadata(FileKind::File, &basic, &standard, &tag, &id)?;
    assert_eq!(before.identity, FileIdentity { volume_serial: 0x1122334455667788, file_id: full });
    put64(&mut basic, offset_of!(FS::FILE_BASIC_INFO, LastAccessTime), 1234);
    assert_eq!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id)?, before);
    id[at+15] = 0x81;
    assert_ne!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id)?.identity, before.identity);
    standard[offset_of!(FS::FILE_STANDARD_INFO, Directory)] = 2; // not a Rust bool
    assert_eq!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id), Err(Error::Unsafe));
    let mut raw = entry("original.dll", full);
    // Undefined ordinary ReparsePointTag is not read as an authority assertion.
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, ReparsePointTag), 0xdeadbeef);
    let entries = decode::directory(&raw)?;
    assert_eq!(entries.len(), 1); assert_eq!(entries[0].file_id, full);
    assert_eq!(decode::directory(&raw[..raw.len()-1]), Err(Error::Unsafe));
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset), 8);
    assert_eq!(decode::directory(&raw), Err(Error::Unsafe));
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset), 0);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), 0x80000000);
    assert_eq!(decode::directory(&raw), Err(Error::Unsafe));

    // Ordinary Windows roots contain unrelated junctions. Return their bounded
    // DATA only in ancestor mode; never authorize opening/following one.
    let mut sibling = entry("unrelated-link", full);
    put32(&mut sibling, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes),
        FS::FILE_ATTRIBUTE_DIRECTORY | FS::FILE_ATTRIBUTE_REPARSE_POINT);
    let aligned = (sibling.len() + 7) & !7;
    sibling.resize(aligned, 0);
    put32(&mut sibling, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset), aligned as u32);
    let mut target_id = full; target_id[0] = 2;
    let mut target = entry("Program Files", target_id);
    put32(&mut target, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), FS::FILE_ATTRIBUTE_DIRECTORY);
    sibling.extend_from_slice(&target);
    let ancestors = decode::ancestor_directory(&sibling, "Program Files")?;
    assert_eq!(ancestors.len(), 2);
    assert_eq!(ancestors[1].name, "Program Files");
    assert_eq!(ancestors[1].file_id, target_id);
    assert_ne!(ancestors[0].attributes & FS::FILE_ATTRIBUTE_REPARSE_POINT, 0);
    assert_eq!(decode::directory(&sibling), Err(Error::Unsafe));
    for selected in ["unrelated-link", "UNRELATED-LINK"] {
        assert_eq!(decode::ancestor_directory(&sibling, selected), Err(Error::Unsafe));
    }
    assert_eq!(decode::ancestor_directory(&sibling[..sibling.len()-1], "Program Files"), Err(Error::Unsafe));
    let mut malformed = sibling.clone();
    put32(&mut malformed, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset), 8);
    assert_eq!(decode::ancestor_directory(&malformed, "Program Files"), Err(Error::Unsafe));
    let mut zero_id = sibling.clone();
    let id_at = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileId);
    zero_id[id_at..id_at+16].fill(0);
    assert_eq!(decode::ancestor_directory(&zero_id, "Program Files"), Err(Error::Unsafe));
    assert_eq!(decode::ancestor_directory(&vec![0; BUFFER + 1], "Program Files"), Err(Error::Bounds));
    assert_eq!(decode::ancestor_directory(&sibling, ".."), Err(Error::Unsafe));
    // Unknown unrelated attributes remain DATA; strict parsing remains closed.
    put32(&mut sibling, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), 0x80000000);
    assert!(decode::ancestor_directory(&sibling, "Program Files").is_ok());
    assert_eq!(decode::directory(&sibling), Err(Error::Unsafe));
    // The selected entry may never use this relaxation, even before open_child.
    put32(&mut sibling, aligned + offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes),
        FS::FILE_ATTRIBUTE_DIRECTORY | FS::FILE_ATTRIBUTE_REPARSE_POINT);
    assert_eq!(decode::ancestor_directory(&sibling, "Program Files"), Err(Error::Unsafe));
    Ok(())
}

fn stream(name: &str) -> Vec<u8> {
    let text: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let header = offset_of!(N::FILE_STREAM_INFORMATION, StreamName);
    let mut raw = vec![0; header + text.len()]; raw[header..].copy_from_slice(&text);
    put32(&mut raw, offset_of!(N::FILE_STREAM_INFORMATION, StreamNameLength), text.len() as u32); raw
}
#[test]
fn stream_and_component_refusals_cannot_be_treated_as_absence() -> Result<()> {
    assert!(ordinary_owner::complete_write(true, 37, 37, true));
    for (returned, count, bytes, closed) in [
        (false, 37, 37, true), (true, 36, 37, true), (true, 38, 37, true),
        (true, 37, 37, false), (true, 0, 0, true), (true, 65537, 65537, true),
    ] {
        assert!(!ordinary_owner::complete_write(returned, count, bytes, closed));
    }
    let unnamed = stream("::$DATA");
    assert_eq!(decode::streams(&unnamed, FileKind::File), Ok(()));
    assert_eq!(decode::streams(&[], FileKind::Directory), Ok(()));
    assert_eq!(decode::streams(&[], FileKind::File), Err(Error::Unsafe));
    assert_eq!(decode::streams(&stream(":hidden:$DATA"), FileKind::File), Err(Error::Unsafe));
    assert_eq!(decode::streams(&unnamed[..unnamed.len()-1], FileKind::File), Err(Error::Unsafe));
    let mut multiple = unnamed.clone();
    put32(&mut multiple, offset_of!(N::FILE_STREAM_INFORMATION, NextEntryOffset), 8);
    assert_eq!(decode::streams(&multiple, FileKind::File), Err(Error::Unsafe));
    for name in ["", ".", "..", "NUL", "COM1.txt", "LPT¹", "trailing.", "trailing ", "a:b", "a\\b", "a\0b"] {
        assert!(!decode::component(name));
    }
    for name in ["C:\\Program Files", "D:\\Windows\\System32"] { assert!(decode::dos_location(name).is_ok()); }
    for name in ["\\\\host\\share", "C:relative", "C:\\", "C:\\Windows\\..", "C:\\Windows\\"] {
        assert!(decode::dos_location(name).is_err());
    }
    let mapped: Vec<u8> = "\\Device\\HarddiskVolume3\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(decode::mapping(&mapped)?, "\\Device\\HarddiskVolume3");
    let subst: Vec<u8> = "\\??\\C:\\elsewhere\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(decode::mapping(&subst), Err(Error::Unsafe));
    Ok(())
}

// Fixed in-memory ordinary-owner fixtures. Never create an Account, Launch or
// OriginalFile: even the positive cases call only the live driver's pure gates.
fn ordinary_stamp() -> ordinary_owner::Stamp {
    ordinary_owner::Stamp { volume: 77, id: [0x11; 16], creation: 100, write: 200,
        change: 300, size: 37, allocation: 4096, links: 1, attributes: FS::FILE_ATTRIBUTE_NORMAL }
}
fn ordinary_request(stamp: &ordinary_owner::Stamp) -> String {
    format!("MRK_WINDOWS_ORDINARY_REQUEST_V1\nsourceSha={}\nsourceTree={}\nrunId=123456\nattempt=1\nartifact=C:\\owned\\native.exe\nartifactBytes=37\nartifactSha256={}\ncommandSha256={}\nartifactIdentity={}\n",
        "1".repeat(40), "2".repeat(40), "3".repeat(64), "4".repeat(64), stamp.wire())
}
