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
pub(super) fn enter_inert(book: &mut NativeBook, call: Call, handle: F::HANDLE) -> Result<()> {
    assert!(book.active.is_none());
    let token_length = match call {
        Call::Token(class) => token_information_length(class)?,
        _ => 0,
    };
    let output_handle = match call.acquisition_output() {
        Some(i) => book.slot(i)?.output.get(), _ => null_mut(),
    };
    book.active = Some(ManuallyDrop::new(Box::pin(Arena {
        call, token_length, phase: Cell::new(Phase::Prepared), returned: Cell::new(None),
        completion_refusal: Cell::new(None),
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

// Recorder fixtures are DATA only; they neither call admission nor fabricate a
// successful original. Production keeps the same recorder inside NativeBook.
pub(super) fn admission_trace(role: AdmissionRole) -> AdmissionTrace {
    let trace = AdmissionTrace::new(); trace.active.set(true); trace.role.set(role); trace
}
pub(super) fn admission_fault(trace: &AdmissionTrace, role: AdmissionRole, operation: AdmissionOp,
    check: AdmissionCheck, index: Option<u16>) {
    assert_eq!(trace.first.get(), Some(PublicationAdmissionObservation { role, operation, check, index }));
}

#[test]
fn original_destinations_are_stable_registered_and_book_bound() -> Result<()> {
    {
        use super::{AdmissionRole as R, AdmissionOp as O};
        let book = NativeBook::new(); let trace = &book.admission;
        assert_eq!(trace.at(O::Metadata).need(false, C::FileId), Err(Error::Unsafe));
        assert!(trace.first.get().is_none()); // Ordinary/default book is unarmed.
        trace.active.set(true); trace.role.set(R::Version);
        let outer = trace.at(O::Metadata);
        assert_eq!(outer.result(Ok(37), C::OutputCount), Ok(37));
        for error in [Error::Unavailable, Error::Bounds, Error::State, Error::Unknown] {
            assert_eq!(outer.result::<()>(Err(error), C::OutputCount), Err(error));
            assert!(trace.first.get().is_none());
        }
        let leaf = outer.role(R::Manifest).index(AdmissionIndex::Directory, 7);
        let later = Cell::new(false);
        let first = (|| {
            leaf.need(false, C::Span)?;
            later.set(true); outer.need(false, C::MetadataChanged)
        })();
        assert_eq!(outer.result(first, C::MetadataSize), Err(Error::Unsafe));
        assert!(!later.get());
        admission_fault(trace, R::Manifest, O::Metadata, C::Span, Some(7));
        let saved = trace.first.get();
        trace.role.set(R::Installer);
        assert_eq!(trace.at(O::InstallerPolicy).need(false, C::Elevated), Err(Error::Unsafe));
        trace.active.set(false);
        assert_eq!(trace.at(O::Owner).need(false, C::OrderFresh), Err(Error::Unsafe));
        assert_eq!(trace.first.get(), saved); // First leaf, not last wrapper/context.
        assert!(NativeBook::new().admission.first.get().is_none());
        assert_eq!(Refusal::none().need(false, C::FileId), Err(Error::Unsafe));

        for (kind, limit) in [(AdmissionIndex::Directory, 8192), (AdmissionIndex::Ace, 2048),
            (AdmissionIndex::Group, 256), (AdmissionIndex::Privilege, 64)] {
            assert_eq!(kind.limit(), limit);
            for index in [0, limit - 1, limit, usize::MAX] {
                let row = admission_trace(R::Groups);
                assert_eq!(row.at(O::InstallerPolicy).index(kind, index).need(false, C::Span), Err(Error::Unsafe));
                let expected = if index < limit { Some(index as u16) } else { None };
                admission_fault(&row, R::Groups, O::InstallerPolicy, C::Span, expected);
                let line = row.first.get().ok_or(Error::State)?.diagnostic_line().ok_or(Error::State)?;
                let ordinal = expected.map_or_else(|| "none".to_owned(), |n| n.to_string());
                assert!(line.ends_with(&format!(";index={ordinal}\n")));
            }
        }
        for labels in [AdmissionRole::ALL.iter().map(|v| v.label()).collect::<Vec<_>>(),
            AdmissionOp::ALL.iter().map(|v| v.label()).collect(), AdmissionCheck::ALL.iter().map(|v| v.label()).collect()] {
            let mut seen = std::collections::BTreeSet::new();
            for label in labels {
                assert!(!label.is_empty() && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
                assert!(seen.insert(label));
            }
        }
        let role = AdmissionRole::ALL.iter().copied().max_by_key(|v| v.label().len()).ok_or(Error::State)?;
        let operation = AdmissionOp::ALL.iter().copied().max_by_key(|v| v.label().len()).ok_or(Error::State)?;
        let check = AdmissionCheck::ALL.iter().copied().max_by_key(|v| v.label().len()).ok_or(Error::State)?;
        let largest = PublicationAdmissionObservation { role, operation, check, index: Some(8191) };
        let line = largest.diagnostic_line().ok_or(Error::State)?;
        assert!(line.is_ascii() && line.len() <= 256 && line.ends_with('\n'));
        assert_eq!(line.bytes().filter(|b| *b == b'\n').count(), 1);
        assert!(256 + line.len() <= 512); // Base line has its own unchanged256 bound.
    }
    {
        use qualification_fixture::{fixture_capacity,CursorEpoch};
        fixture_capacity(19,8,37,2)?; // Publisher peak39, not a forty-slot expansion.
        // New source stage:19 root +5 input +8 PF +5 source dirs +2 leaves.
        fixture_capacity(19,8,19+5+8+5,2)?;
        // Independent103-object observation: one branch and leaf at a time.
        fixture_capacity(19,8,19+5+8+1+4,1)?;
        // Fullwalk's ten retained prereqs fit with one serial proof original;
        // six more simultaneous originals are deliberately NOT admitted.
        fixture_capacity(19,0,38,1)?;
        assert!(fixture_capacity(19,0,38,6).is_err());
        for (a,b,held,leaves) in [(20,8,37,2),(19,9,37,2),(19,8,39,2),(19,8,37,3),(1,1,usize::MAX,1)] {
            assert!(fixture_capacity(a,b,held,leaves).is_err());
        }
        let mut cursor=CursorEpoch::default();
        assert!(!cursor.begin(0)?);
        assert!(cursor.begin(0).is_err() && cursor.begin(1).is_err());
        cursor.complete()?;
        assert!(cursor.begin(0).is_err()); // known EOF alone does not authorize a restart
        assert!(cursor.begin(1)?); cursor.complete()?;
        assert!(cursor.begin(1).is_err() && cursor.begin(53).is_err());
        assert!(cursor.begin(52)?);cursor.complete()?;
        assert!(cursor.complete().is_err());
    }
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
fn loader_roles_and_shared_cursor_cannot_be_retargeted() -> Result<()> {
    assert_eq!(SystemImage::ALL.len(), 31);
    for image in SystemImage::ALL {
        assert_eq!(SystemImage::from_name(image.name()), Some(*image));
        assert_eq!(SystemImage::from_name(&image.name().to_ascii_uppercase()), Some(*image));
    }
    for name in ["python314.dll", "kernel32.dll:stream", "api-ms-win-core-path-l1-1-0.dll", "..\\kernel32.dll", "kernel32.dll "] {
        assert_eq!(SystemImage::from_name(name), None);
    }
    let names = vec!["Program Files".to_owned(), "Windows".to_owned()];
    loader::selected_names(&names)?;
    for bad in [Vec::new(), vec!["Windows".to_owned(), "WINDOWS".to_owned()], vec!["..".to_owned()],
        (0..36).map(|n| format!("name{n}")).collect()] {
        assert!(loader::selected_names(&bad).is_err());
    }
    let mut mode = DirectoryMode::Unstarted;
    mode.bind(DirectoryMode::Selected(names.clone()))?;
    mode.bind(DirectoryMode::Selected(names.clone()))?;
    assert!(mode.bind(DirectoryMode::Selected(vec!["Windows".to_owned()])).is_err());
    assert!(mode.bind(DirectoryMode::Strict).is_err());
    assert!(mode.bind(DirectoryMode::Ancestor("Windows".to_owned())).is_err());
    let mut fixture = Inert::new();
    let parent = fixture.book.reserve(Kind::Directory, None, "payload", "\\Device\\HarddiskVolume1\\payload".to_owned())?;
    let mut system = KnownLocation { book: Arc::clone(&fixture.book.identity), kind: LocationKind::System,
        path: "C:\\Windows\\System32".to_owned(), drive: "C:".to_owned(), device: "\\Device\\HarddiskVolume1".to_owned(),
        components: vec!["Windows".to_owned(), "System32".to_owned()] };
    let before = fixture.book.slots.len();
    assert!(matches!(fixture.book.open_system_image(&system, &parent, SystemImage::Kernel32, "kernel32.dll"), Err(Error::Unsafe)));
    assert!(matches!(fixture.book.open_system_image(&system, &parent, SystemImage::Kernel32, "python314.dll"), Err(Error::State)));
    system.kind = LocationKind::ProgramFiles;
    assert!(matches!(fixture.book.open_system_image(&system, &parent, SystemImage::Kernel32, "kernel32.dll"), Err(Error::State)));
    system.kind = LocationKind::System; system.book = Arc::new(());
    assert!(matches!(fixture.book.open_system_image(&system, &parent, SystemImage::Kernel32, "kernel32.dll"), Err(Error::State)));
    assert_eq!(fixture.book.slots.len(), before);
    assert!(!fixture.book.started && fixture.book.active.is_none());
    assert!(fixture.book.slot(parent.index)?.system_image.is_none());
    fixture.book.slot_mut(parent.index)?.directory_ended = true;
    assert!(matches!(fixture.book.next_selected_entries(&parent, &names), Err(Error::State)));
    assert_eq!(fixture.book.slot(parent.index)?.directory_mode, DirectoryMode::Unstarted);
    Ok(()) // Every original is inert; no native call occurred.
}

#[test]
fn os_image_link_policy_never_weakens_payload_metadata_or_loader_acl() -> Result<()> {
    let mut basic = vec![0; size_of::<FS::FILE_BASIC_INFO>()];
    let mut standard = vec![0; size_of::<FS::FILE_STANDARD_INFO>()];
    let mut tag = vec![0; size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()];
    let mut id = vec![0; size_of::<FS::FILE_ID_INFO>()];
    put32(&mut basic, offset_of!(FS::FILE_BASIC_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    put32(&mut tag, offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes), FS::FILE_ATTRIBUTE_NORMAL);
    put64(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, EndOfFile), 37);
    put64(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, AllocationSize), 4096);
    id[offset_of!(FS::FILE_ID_INFO, FileId)] = 1;
    for links in [0, 1, 2, u32::MAX] {
        put32(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks), links);
        assert_eq!(decode::metadata(FileKind::File, &basic, &standard, &tag, &id).is_ok(), links == 1);
        let os = decode::Observed::new(Refusal::none());
        assert_eq!(os.system_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_ok(), links > 0);
        assert!(os.system_image_metadata(FileKind::Directory, &basic, &standard, &tag, &id).is_err());
    }
    put32(&mut standard, offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks), 2);
    standard[offset_of!(FS::FILE_STANDARD_INFO, DeletePending)] = 1;
    assert!(decode::Observed::new(Refusal::none()).system_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_err());
    standard[offset_of!(FS::FILE_STANDARD_INFO, DeletePending)] = 0;
    put32(&mut basic, offset_of!(FS::FILE_BASIC_INFO, FileAttributes), FS::FILE_ATTRIBUTE_REPARSE_POINT);
    put32(&mut tag, offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes), FS::FILE_ATTRIBUTE_REPARSE_POINT);
    assert!(decode::Observed::new(Refusal::none()).system_image_metadata(FileKind::File, &basic, &standard, &tag, &id).is_err());
    let owner = sid(5, &[18]); let everyone = sid(1, &[0]);
    for right in [FS::FILE_WRITE_DATA, FS::FILE_APPEND_DATA, FS::DELETE, FS::FILE_DELETE_CHILD, FS::WRITE_DAC, FS::WRITE_OWNER] {
        let raw = descriptor(&owner, &[(0, 0, right, everyone.clone())]);
        for kind in [FileKind::Directory, FileKind::File] {
            assert!(security::descriptor(&raw, kind, AuthorityScope::ImmutableVersion).is_err());
        }
    }
    let selected = vec!["kernel32.dll".to_owned()];
    let mut raw = entry("kernel32.dll", [1; 16]);
    put32(&mut raw, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes), FS::FILE_ATTRIBUTE_REPARSE_POINT);
    assert!(decode::Observed::new(Refusal::none()).selected_directory(&raw, &selected).is_err());
    let unselected = vec!["user32.dll".to_owned()];
    assert!(decode::Observed::new(Refusal::none()).selected_directory(&raw, &unselected).is_ok());
    Ok(())
}

#[test]
fn pending_and_lost_completion_keep_the_exact_arena_and_slots() -> Result<()> {
    {
        use qualification_fixture::mutation_return;
        assert_eq!(mutation_return(1,0),Ok(()));
        assert_eq!(mutation_return(0,0),Err(Error::Unknown));
        assert_eq!(mutation_return(0,F::ERROR_IO_PENDING),Err(Error::Unknown));
        assert_eq!(mutation_return(0,F::ERROR_ALREADY_EXISTS),Err(Error::Unavailable));
        assert!(mutation_return(1,F::ERROR_ALREADY_EXISTS).is_err());
        // Same shared arena/finish for the post-mutation cursor: a pending
        // borrowed observer cannot close/adopt the filesystem original.
        let mut fixture=Inert::new();let book=&mut fixture.book;
        enter_inert(book,Call::Info(FS::FileIdExtdDirectoryRestartInfo,BUFFER),71usize as F::HANDLE)?;
        let arena=book.arena()? as *const Arena;
        assert!(matches!(return_inert(book,Returned::Boolean(0,F::ERROR_IO_PENDING),None,
            F::STATUS_PENDING,usize::MAX),Err(Error::Unknown)));
        assert_eq!(book.arena()? as *const Arena,arena);
        assert!(book.slots.is_empty() && book.is_unknown() && !book.settled());
    }
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
        assert_eq!(book.arena()?.completion_refusal.get(), None);
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
    assert_eq!(book.arena()?.completion_refusal.get(), None);
    assert!(book.first_unavailable.is_none());
    Ok(())
}

#[test]
fn acquisition_needs_a_definite_consistent_receipt() -> Result<()> {
    {
        use qualification_fixture::{AggregateClock,AGGREGATE_MS,SECOND_FLOOR_MS};
        let origin=700u64;
        let mut first=AggregateClock::new(origin,origin,false)?;
        first.observe(origin+60_000,0)?;
        assert_eq!((first.origin,first.deadline),(origin,origin+AGGREGATE_MS));
        // The entry origin is not replaced by a delayed intent publication.
        let before=ordinary_stamp().wire();
        let invocation=qualification_fixture::invocation(&"1".repeat(40),&"2".repeat(40),"123456",37,
            &"3".repeat(64),&before,&"4".repeat(64),&"5".repeat(64),origin)?;
        assert_eq!(invocation.get("originTickMs")?,"700");
        assert_eq!(invocation.get("deadlineTickMs")?,"210700");
        assert!(AggregateClock::new(u64::MAX-AGGREGATE_MS+1,u64::MAX-AGGREGATE_MS+1,false).is_err());
        assert!(AggregateClock::new(origin,origin-1,false).is_err());
        assert!(AggregateClock::new(origin,origin+AGGREGATE_MS-SECOND_FLOOR_MS+1,true).is_err());
        let mut second=AggregateClock::new(origin,origin+109_999,true)?;
        assert_eq!(second.prelaunch_at(origin+110_000)?,origin+110_000);
        assert!(second.prelaunch_at(origin+110_000).is_err()); // sole original launch
        assert!(second.observe(origin+110_001,0).is_err());
        let mut insufficient=AggregateClock::new(origin,origin+109_999,true)?;
        assert!(insufficient.prelaunch_at(origin+110_001).is_err());
        assert!(insufficient.prelaunch_at(origin+110_000).is_err()); // no renewed budget
        let mut backward=AggregateClock::new(origin,origin,false)?;
        backward.observe(origin+10,0)?;
        assert!(backward.observe(origin+9,0).is_err());
        assert!(backward.observe(origin+11,0).is_err());
    }
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
    for (status, handle, io, information, no_handle, refusal) in [
        (F::STATUS_ACCESS_DENIED, null_mut(), F::STATUS_PENDING, usize::MAX, true, None),
        (F::STATUS_ACCESS_DENIED, 31usize as F::HANDLE, F::STATUS_PENDING, usize::MAX, false, None),
        (F::STATUS_SUCCESS, null_mut(), F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false, Some(CompletionRefusal::OpenInvalidHandle)),
        (F::STATUS_SUCCESS, F::INVALID_HANDLE_VALUE, F::STATUS_PENDING, usize::MAX, false, Some(CompletionRefusal::OpenInvalidHandle)),
        (F::STATUS_SUCCESS, 32usize as F::HANDLE, F::STATUS_PENDING, usize::MAX, false, Some(CompletionRefusal::OpenIoStatus)),
        (F::STATUS_SUCCESS, 33usize as F::HANDLE, F::STATUS_SUCCESS, usize::MAX, false, Some(CompletionRefusal::OpenNotOpened)),
        (1, null_mut(), F::STATUS_SUCCESS, WP::FILE_OPENED as usize, false, None),
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
            assert_eq!(book.arena()?.completion_refusal.get(), refusal);
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
    assert_eq!(book.arena()?.completion_refusal.get(), Some(CompletionRefusal::OpenDuplicate));
    // A later recorder cannot replace the original rejecting predicate.
    assert_eq!(book.completion_unknown::<()>(CompletionRefusal::TokenDuplicate), Err(Error::Unknown));
    assert_eq!(book.arena()?.completion_refusal.get(), Some(CompletionRefusal::OpenDuplicate));

    for flavor in 0..4 {
        for (handle, refusal) in [(null_mut(), Some(CompletionRefusal::TokenInvalidHandle)),
            (F::INVALID_HANDLE_VALUE, Some(CompletionRefusal::TokenInvalidHandle)),
            (34usize as F::HANDLE, Some(CompletionRefusal::TokenDuplicate)), (35usize as F::HANDLE, None)] {
            let mut fixture = Inert::new(); let book = &mut fixture.book;
            let held = book.reserve(Kind::File, None, "held", "held".to_owned())?;
            own_inert(book, &held, 34)?;
            let key = book.reserve(if flavor == 1 { Kind::ThreadToken } else { Kind::ProcessToken }, None, "", String::new())?;
            let call = match flavor {
                0 => Call::ProcessToken(key.index), 1 => Call::ThreadToken(key.index),
                2 => Call::QualificationSourceToken(key.index), _ => Call::QualificationRestrictedToken(key.index),
            };
            enter_inert(book, call, null_mut())?;
            assert_eq!(book.arena()?.output_handle, book.slot(key.index)?.output.get());
            let result = return_inert(book, Returned::Boolean(1, 0), Some(handle), 0, 0);
            if let Some(expected) = refusal {
                assert!(matches!(result, Err(Error::Unknown)));
                assert_eq!(book.arena()?.completion_refusal.get(), Some(expected));
                assert_eq!(book.state(&key)?, SlotState::Acquiring);
            } else {
                assert!(result.is_ok());
                assert!(book.active.is_none() && !book.is_unknown());
                assert_eq!(book.state(&key)?, SlotState::Owned);
            }
        }
    }
    for restricted in [false, true] {
        for returned in [Returned::Boolean(0, F::ERROR_IO_PENDING), Returned::Boolean(0, 0),
            Returned::Boolean(1, F::ERROR_ACCESS_DENIED), Returned::Scalar(0), Returned::Count(1, 0), Returned::Nt(0)] {
            let mut fixture = Inert::new(); let book = &mut fixture.book;
            let key = book.reserve(Kind::ProcessToken, None, "", String::new())?;
            let call = if restricted { Call::QualificationRestrictedToken(key.index) } else { Call::QualificationSourceToken(key.index) };
            enter_inert(book, call, null_mut())?;
            assert!(matches!(return_inert(book, returned, None, 0, 0), Err(Error::Unknown)));
            assert!(book.active.is_some() && book.is_unknown());
            assert_eq!(book.state(&key)?, SlotState::Acquiring);
            assert_eq!(book.arena()?.completion_refusal.get(), None); // no output predicate was reached
        }
        let mut fixture = Inert::new(); let book = &mut fixture.book;
        let key = book.reserve(Kind::ProcessToken, None, "", String::new())?;
        let call = if restricted { Call::QualificationRestrictedToken(key.index) } else { Call::QualificationSourceToken(key.index) };
        enter_inert(book, call, null_mut())?;
        return_inert(book, Returned::Boolean(0, F::ERROR_ACCESS_DENIED), Some(null_mut()), 0, 0)?;
        assert_eq!(book.state(&key)?, SlotState::NoHandle);
        assert!(book.active.is_none() && !book.is_unknown());
    }

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
    {
        let mut clock=qualification_fixture::AggregateClock::new(1,1,false)?;
        clock.observe(clock.deadline-1,0)?;
        assert!(qualification_result::complete_fixture_write(true,131072,131072,true));
        assert!(clock.observe(clock.deadline,0).is_err());
        assert!(clock.observe(2,0).is_err());
        // A known once-only close stays known, but cannot promote late success.
        assert!(clock.latched && qualification_result::complete_fixture_write(true,131072,131072,true));
        assert!(!qualification_result::complete_fixture_write(true,131072,131072,false));
        assert!(!qualification_result::complete_fixture_write(false,131072,131072,true));
    }
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
    {
        use qualification_fixture::{fixture_descriptor,check_descriptor};
        for directory in [false,true] {
            let trusted=fixture_descriptor(directory,false)?;
            let sealed=fixture_descriptor(directory,true)?;
            check_descriptor(&trusted,directory,false)?;check_descriptor(&sealed,directory,true)?;
            assert!(check_descriptor(&trusted,directory,true).is_err());
            assert!(check_descriptor(&sealed,directory,false).is_err());
            let acl=decode::u32_at(&sealed,16)? as usize;
            let users=acl+8+(8+ordinary_owner::system_sid().len())+(8+ordinary_owner::builtin(544).len());
            for flag in [S::OBJECT_INHERIT_ACE,S::CONTAINER_INHERIT_ACE,S::INHERITED_ACE] {
                let mut wrong=sealed.clone();wrong[users+1]=flag as u8;
                assert!(check_descriptor(&wrong,directory,true).is_err());
            }
            for mask in [FS::FILE_WRITE_DATA,FS::FILE_WRITE_ATTRIBUTES,FS::DELETE,FS::FILE_DELETE_CHILD,FS::WRITE_DAC,FS::WRITE_OWNER] {
                let mut wrong=sealed.clone();put32(&mut wrong,users+4,mask);
                assert!(check_descriptor(&wrong,directory,true).is_err());
            }
        }
    }
    {
        use qualification_fixture::{fixture_descriptor,production_descriptor,PAYLOAD_NAMES};
        for name in PAYLOAD_NAMES {
            let image=name.ends_with(".exe")||name.ends_with(".dll")||name.ends_with(".pyd");
            let mut raw=fixture_descriptor(false,true)?;
            let acl=decode::u32_at(&raw,16)? as usize;
            let users=acl+8+(8+ordinary_owner::system_sid().len())+(8+ordinary_owner::builtin(544).len());
            put32(&mut raw,users+4,FS::FILE_GENERIC_READ|if image {FS::FILE_GENERIC_EXECUTE}else{0});
            production_descriptor(&raw,false,Some(name))?;
            let mut wrong=raw.clone();
            put32(&mut wrong,users+4,FS::FILE_GENERIC_READ|if image {0}else{FS::FILE_GENERIC_EXECUTE});
            assert!(production_descriptor(&wrong,false,Some(name)).is_err());
            for flag in [S::OBJECT_INHERIT_ACE,S::CONTAINER_INHERIT_ACE,S::INHERITED_ACE] {
                let mut wrong=raw.clone();wrong[users+1]=flag as u8;
                assert!(production_descriptor(&wrong,false,Some(name)).is_err());
            }
            for extra in [FS::FILE_WRITE_DATA,FS::FILE_APPEND_DATA,FS::FILE_WRITE_EA,FS::FILE_WRITE_ATTRIBUTES,
                FS::DELETE,FS::FILE_DELETE_CHILD,FS::WRITE_DAC,FS::WRITE_OWNER] {
                let mut wrong=raw.clone();let mask=decode::u32_at(&wrong,users+4)?;
                put32(&mut wrong,users+4,mask|extra);
                assert!(production_descriptor(&wrong,false,Some(name)).is_err());
            }
            assert!(production_descriptor(&fixture_descriptor(false,false)?,false,Some(name)).is_err());
        }
        production_descriptor(&fixture_descriptor(true,true)?,true,None)?;
        assert!(production_descriptor(&fixture_descriptor(true,false)?,true,None).is_err());
        assert!(production_descriptor(&fixture_descriptor(false,true)?,false,Some("python/Python.exe")).is_err());
        assert!(production_descriptor(&fixture_descriptor(false,true)?,false,None).is_err());
    }
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
    {
        use super::{AdmissionRole as R, AdmissionOp as O};
        let owner = sid(5, &[18]); let everyone = sid(1, &[0]);
        let allow = SS::ACCESS_ALLOWED_ACE_TYPE as u8; let deny = SS::ACCESS_DENIED_ACE_TYPE as u8;
        let sibling = descriptor(&owner, &[(allow, 0, F::GENERIC_READ, everyone.clone()),
            (allow, 0, FS::FILE_WRITE_DATA, everyone.clone())]);
        for (scope, role, operation) in [(AuthorityScope::AncestorOutsideVersion, R::Target, O::SecurityAncestor),
            (AuthorityScope::ImmutableVersion, R::Version, O::SecurityVersion)] {
            let trace = admission_trace(role);
            let observed = security::Observed::new(trace.at(operation)).descriptor(&sibling, FileKind::Directory, scope);
            assert_eq!(observed, security::descriptor(&sibling, FileKind::Directory, scope));
            if scope == AuthorityScope::ImmutableVersion {
                assert_eq!(observed, Err(Error::Unsafe));
                admission_fault(&trace, role, operation, C::AceDangerousRights, Some(1));
            } else { assert!(observed.is_ok() && trace.first.get().is_none()); }
        }
        // Each row has later bad DATA as well: the original first leaf wins.
        for (kind, flags, mask, expected) in [
            (255, 0x80, 0x08000000, C::AceType),
            (allow, 0x80, 0x08000000, C::AceFlags),
            (allow, S::INHERIT_ONLY_ACE as u8, 0x08000000, C::AceInheritance),
            (deny, 0, 0x08000000, C::AceMask),
            (allow, (S::OBJECT_INHERIT_ACE | S::INHERIT_ONLY_ACE) as u8, 0x08000000, C::AceMask),
            (allow, 0, FS::WRITE_DAC, C::AceDangerousRights),
        ] {
            let raw = descriptor(&owner, &[(kind, flags, mask, everyone.clone())]);
            let trace = admission_trace(R::Manifest);
            let observed = security::Observed::new(trace.at(O::SecurityVersion)).descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion);
            assert_eq!(observed, security::descriptor(&raw, FileKind::File, AuthorityScope::ImmutableVersion));
            assert_eq!(observed, Err(Error::Unsafe));
            admission_fault(&trace, R::Manifest, O::SecurityVersion, expected, Some(0));
        }
        for (raw, expected) in [(vec![0; 19], C::DescriptorSize),
            (descriptor(&everyone, &[]), C::OwnerTrust)] {
            let trace = admission_trace(R::Volume);
            let observed = security::Observed::new(trace.at(O::SecurityAncestor)).descriptor(&raw, FileKind::Directory, AuthorityScope::AncestorOutsideVersion);
            assert_eq!(observed, security::descriptor(&raw, FileKind::Directory, AuthorityScope::AncestorOutsideVersion));
            admission_fault(&trace, R::Volume, O::SecurityAncestor, expected, None);
        }
    }
    {
        use qualification_fixture::{fixture_descriptor,check_descriptor};
        let raw=fixture_descriptor(true,true)?;
        for control in [S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT,
            S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT|S::SE_DACL_PROTECTED|S::SE_OWNER_DEFAULTED,
            S::SE_SELF_RELATIVE|S::SE_DACL_PRESENT|S::SE_DACL_PROTECTED|S::SE_DACL_AUTO_INHERITED] {
            let mut wrong=raw.clone();put16(&mut wrong,2,control);
            assert!(check_descriptor(&wrong,true,true).is_err());
        }
        let mut wrong_owner=raw.clone();let at=decode::u32_at(&raw,4)? as usize;
        put32(&mut wrong_owner,at+12,545); // Users is not a trusted owner
        assert!(check_descriptor(&wrong_owner,true,true).is_err());
        let mut absent_group=raw.clone();put32(&mut absent_group,8,0);
        assert!(check_descriptor(&absent_group,true,true).is_err());
        let acl=decode::u32_at(&raw,16)? as usize;
        let mut unsupported=raw.clone();unsupported[acl+8]=255;
        assert!(check_descriptor(&unsupported,true,true).is_err());
        let mut wrong_revision=raw.clone();wrong_revision[acl]=4;
        assert!(check_descriptor(&wrong_revision,true,true).is_err());
    }
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
    {
        // The fixture's private elevated route never manufactures ordinary
        // TokenFacts, clears refusal, or enables either public discovery route.
        // Review admits synthetic qualification attempts, not ordinary/product authority.
        assert!(ordinary_owner::FULLWALK_PREREQUISITES_REVIEWED);
        let mut elevated=Inert::new();
        let token=elevated.book.reserve(Kind::ProcessToken,None,"token","token".to_owned())?;
        enter_inert(&mut elevated.book,Call::ProcessToken(token.index),null_mut())?;
        return_inert(&mut elevated.book,Returned::Boolean(1,0),Some(73usize as F::HANDLE),F::STATUS_PENDING,usize::MAX)?;
        elevated.book.process_token=Some(token.index);
        assert!(elevated.book.user.is_none() && !elevated.book.roots_started);
        assert!(matches!(elevated.book.known_locations_once(),Err(Error::State)));
        let location=KnownLocation {book:Arc::clone(&elevated.book.identity),kind:LocationKind::ProgramFiles,
            path:r"C:\Program Files".to_owned(),drive:"C:".to_owned(),device:r"\Device\HarddiskVolume3".to_owned(),
            components:vec!["Program Files".to_owned()]};
        assert!(matches!(elevated.book.open_volume(&location),Err(Error::State)));
        assert!(elevated.book.user.is_none() && !elevated.book.roots_started && elevated.book.active.is_none());
    }
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
        let trace = admission_trace(AdmissionRole::User);
        assert_eq!(completed.bytes_in(65_537, trace.at(AdmissionOp::TokenData)), Err(Error::Unsafe));
        admission_fault(&trace, AdmissionRole::User, AdmissionOp::TokenData, C::OutputBytes, None);
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
        let expected = if count <= 65_536 { Ok(count as usize) } else { Err(Error::Unsafe) };
        assert_eq!(completed.count(), expected);
        let trace = admission_trace(AdmissionRole::User);
        assert_eq!(completed.count_in(trace.at(AdmissionOp::TokenData)), expected);
        if expected.is_err() { admission_fault(&trace, AdmissionRole::User, AdmissionOp::TokenData, C::OutputCount, None); }
        else { assert!(trace.first.get().is_none()); }
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
    for role in [AdmissionRole::StatisticsBefore, AdmissionRole::StatisticsAfter] {
        for (group_count, privilege_count, check) in [(1, 1, None), (257, 65, Some(C::StatisticsGroups)),
            (1, 65, Some(C::StatisticsPrivileges))] {
            let mut raw = statistics.clone();
            put32(&mut raw, offset_of!(S::TOKEN_STATISTICS, GroupCount), group_count);
            put32(&mut raw, offset_of!(S::TOKEN_STATISTICS, PrivilegeCount), privilege_count);
            let trace = admission_trace(role);
            assert_eq!(security::Observed::new(trace.at(AdmissionOp::TokenData)).statistics(&raw), security::statistics(&raw));
            if let Some(check) = check { admission_fault(&trace, role, AdmissionOp::TokenData, check, None); }
            else { assert!(trace.first.get().is_none()); }
        }
    }
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
    {
        use qualification_fixture::{observation_roles,ObservedObject,source_unchanged,observations_unchanged};
        // Independent DATA rows, not synthetic created/sealed Object receipts.
        let roles=observation_roles(false);
        let mut before:Vec<_>=roles.iter().enumerate().map(|(ordinal,role)| {
            let mut stamp=ordinary_stamp();stamp.id=[(ordinal+1) as u8;16];
            stamp.attributes=if ordinal<9 {FS::FILE_ATTRIBUTE_DIRECTORY}else{FS::FILE_ATTRIBUTE_ARCHIVE};
            ObservedObject {role:role.clone(),directory:ordinal<9,stamp,security:"1".repeat(64),
                sha:if ordinal<9 {"-".to_owned()}else{"2".repeat(64)},
                inventory:if ordinal<9 {"3".repeat(64)}else{"-".to_owned()}}
        }).collect();
        let stage:Vec<_>=observation_roles(true).iter().map(|role|before.iter().find(|o|o.role==*role).unwrap().clone()).collect();
        before[0].stamp.write+=1;before[0].stamp.change+=1;before[0].stamp.allocation+=4096;before[0].inventory="4".repeat(64);
        source_unchanged(&stage,&before)?;observations_unchanged(&before,&before)?;
        for ordinal in 0..103 {
            for field in 0..13 {
                let mut changed=before.clone();let object=&mut changed[ordinal];
                match field {
                    0=>object.stamp.volume+=1,1=>object.stamp.id[15]^=128,2=>object.stamp.creation+=1,
                    3=>object.stamp.write+=1,4=>object.stamp.change+=1,5=>object.stamp.size+=1,
                    6=>object.stamp.allocation+=4096,7=>object.security="5".repeat(64),
                    8=>object.sha="6".repeat(64),9=>object.inventory="7".repeat(64),
                    10=>object.stamp.links+=1,11=>object.stamp.attributes^=FS::FILE_ATTRIBUTE_HIDDEN,
                    _=>object.directory=!object.directory,
                }
                assert!(observations_unchanged(&before,&changed).is_err());
                if stage.iter().any(|o|o.role==changed[ordinal].role) && !(ordinal==0 && matches!(field,3|4|5|6|9)) {
                    assert!(source_unchanged(&stage,&changed).is_err());
                }
            }
        }
        let mut changed=before.clone();changed[1].stamp.write+=1;
        assert!(source_unchanged(&stage,&changed).is_err()); // no source timestamp exemption
        let mut changed=before.clone();changed[0].inventory=stage[0].inventory.clone();
        assert!(source_unchanged(&stage,&changed).is_err()); // must be the new versions child inventory
        assert!(source_unchanged(&stage[..51],&before).is_err());
        assert!(observations_unchanged(&before[..102],&before[..102]).is_err());
    }
    {
        use qualification_fixture::{parse_stamp,stamp_text,same_object,child_change,payload_change,exact_entries,original_epoch};
        let before=ordinary_stamp();assert_eq!(parse_stamp(&stamp_text(&before))?,before);
        let mut high=before.clone();high.id[15]^=0x80;assert!(!same_object(&before,&high));
        assert!(original_epoch(&before.wire(),&high.wire()).is_err());
        let mut after=before.clone();after.change+=1;
        original_epoch(&before.wire(),&after.wire())?;
        for key in 0..9 {
            let text=stamp_text(&before);let mut fields:Vec<_>=text.split(':').map(str::to_owned).collect();
            match key {0|2|3|4|8=>fields[key]="0".to_owned(),1=>fields[1]="0".repeat(32),
                5|6=>fields[key]="18446744073709551615".to_owned(),_=>fields[7]="2".to_owned()};
            assert!(parse_stamp(&fields.join(":")).is_err());
        }
        assert!(payload_change(&before,&after,37));
        let mut allocation=after.clone();allocation.allocation=1;assert!(!payload_change(&before,&allocation,37));
        let mut directory=before.clone();directory.attributes=FS::FILE_ATTRIBUTE_DIRECTORY;directory.size=0;
        let mut changed=directory.clone();changed.write+=1;changed.change+=1;changed.allocation+=4096;
        assert!(child_change(&directory,&changed));
        changed.creation+=1;assert!(!child_change(&directory,&changed));
        let mut expected=std::collections::BTreeMap::new();expected.insert("core.zip".to_owned(),before.clone());
        let leaf=DirectoryEntry {name:"core.zip".to_owned(),file_id:before.id,kind:FileKind::File,attributes:before.attributes};
        assert_eq!(exact_entries(&[leaf.clone()],&expected,&directory,None)?,1);
        for entry in [DirectoryEntry {file_id:high.id,..leaf.clone()},
            DirectoryEntry {name:"Core.zip".to_owned(),..leaf.clone()},
            DirectoryEntry {name:"foreign.zip".to_owned(),..leaf.clone()},
            DirectoryEntry {attributes:FS::FILE_ATTRIBUTE_REPARSE_POINT,..leaf.clone()}] {
            assert!(exact_entries(&[entry],&expected,&directory,None).is_err());
        }
        assert!(exact_entries(&[leaf.clone(),leaf],&expected,&directory,None).is_err());
        assert!(exact_entries(&[],&expected,&directory,None).is_err());
    }
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
    // Fixed fullwalk request/result DATA reuses this existing inert control;
    // no writer, OriginalFile, account, token query or process is entered.
    use qualification_result::FullwalkRequest;
    // Reviewed prerequisites admit this synthetic attempt, not runtime enablement.
    assert!(ordinary_owner::FULLWALK_PREREQUISITES_REVIEWED);
    let fullwalk_raw = fullwalk_request();
    let fullwalk = FullwalkRequest::parse(fullwalk_raw.as_bytes())?;
    fullwalk.at_root(std::path::Path::new(r"C:\owned"))?;
    assert!(fullwalk.at_root(std::path::Path::new(r"C:\other")).is_err());
    assert!(fullwalk.app.matches(&stamp));
    assert!(!fullwalk.owner.matches(&stamp));
    let mut app_after = stamp.clone(); app_after.change += 1;
    fullwalk.app_after(&app_after.wire())?;
    assert!(!fullwalk.app.matches(&app_after)); // pre-ACL binding is never rewritten
    for field in 0..4 {
        let mut changed = app_after.clone();
        match field {
            0 => changed.id[15] ^= 0x80, 1 => changed.change = stamp.change - 1,
            2 => changed.attributes ^= FS::FILE_ATTRIBUTE_HIDDEN, _ => changed.creation += 1,
        }
        assert!(fullwalk.app_after(&changed.wire()).is_err());
    }
    let alias = fullwalk_raw.replace(&format!("ownerArtifactIdentity={}", fullwalk.owner.identity),
        &format!("ownerArtifactIdentity={}", app_after.wire()));
    assert!(FullwalkRequest::parse(alias.as_bytes()).is_err()); // same pair, distinct ChangeTime is still one original
    for altered in [
        fullwalk_raw.replace("role=protected-version-fullwalk", "role=ordinary"),
        fullwalk_raw.replace(qualification_result::FULLWALK_CHILD, ordinary_owner::CHILD),
        fullwalk_raw.replace("attempt=1", "attempt=2"),
        fullwalk_raw.replace("appArtifactBytes=37", "appArtifactBytes=536870913"),
        fullwalk_raw.replace("ownerArtifactBytes=37", "ownerArtifactBytes=134217729"),
        fullwalk_raw.replace("payloadFiles=45", "payloadFiles=2048"),
        fullwalk_raw.replace("payloadBytes=987654", "payloadBytes=1073741825"),
        fullwalk_raw.replace("publicationReceiptBytes=233", "publicationReceiptBytes=0"),
        fullwalk_raw.replace("appCompileArgvSha256=", "ownerCompileArgvSha256="),
        fullwalk_raw.replace("mobile_release_desktop-", "mrk_windows_installed_native-"),
        fullwalk_raw.replace("versionIdentity=77:", "versionIdentity=0:"),
        fullwalk_raw.replace('\n', "\r\n"), fullwalk_raw.clone() + "extra=1\n",
    ] { assert!(FullwalkRequest::parse(altered.as_bytes()).is_err()); }
    for (field, value) in [("appArtifactBytes=37", "appArtifactBytes=536870912"),
        ("ownerArtifactBytes=37", "ownerArtifactBytes=134217728")] {
        assert!(FullwalkRequest::parse(fullwalk_raw.replace(field, value).as_bytes()).is_ok());
    }
    assert!(ordinary_owner::Binding::parse(raw.replace("artifactBytes=37", "artifactBytes=134217729").as_bytes()).is_err());
    let request_hash = "5".repeat(64); let account_hash = "6".repeat(64);
    let actual = fullwalk.expected(&account_hash, 123);
    let record = fullwalk.result(&request_hash, &actual)?;
    assert!(record.len() <= 4096 && record.ends_with('\n'));
    assert_eq!(fullwalk.accept_result(record.as_bytes(), &request_hash, &account_hash)?, 123);
    assert!(record.contains("\"entries\":123") && record.contains("\"inspectionComplete\":true,\"bookSettled\":true"));
    assert!(record.contains(&format!("\"fileId\":\"{}\"", "22".repeat(16))));
    assert!(!record.contains("C:\\") && !record.contains("S-1-") && !record.contains("\"closed\":true"));
    for field in 0..15 {
        let mut changed = actual.clone();
        match field {
            0 => changed.target = "aarch64-apple-darwin".to_owned(),
            1 => changed.manifest_sha256 = "0".repeat(64),
            2 => changed.protocol_sha256 = "0".repeat(64),
            3 => changed.inventory_sha256 = "0".repeat(64),
            4 => changed.core_sha256 = "0".repeat(64),
            5 => changed.files += 1,
            6 => changed.payload_bytes += 1,
            7 => changed.version_identity.file_id[15] ^= 0x80,
            8 => changed.selected_identities[0].file_id[15] ^= 0x80,
            9 => changed.selected_identities.swap(0, 1),
            10 => changed.account_sid_sha256 = "wrong".to_owned(),
            11 => changed.entries = changed.files,
            12 => changed.entries = 8193,
            13 => changed.selected_identities[1] = changed.selected_identities[0],
            _ => changed.version_identity.volume_serial = 0,
        }
        assert!(fullwalk.result(&request_hash, &changed).is_err());
    }
    for altered in [
        String::new(), record[..record.len() - 1].to_owned(), record.clone() + "{}\n",
        record.replace("\"entries\":123", "\"entries\":00123"),
        record.replace("\"inspectionComplete\":true", "\"inspectionComplete\":false"),
        record.replace("\"bookSettled\":true", "\"bookSettled\":false"),
        record.replace("\"writeCalls\":1", "\"writeCalls\":2"),
        record.replace("original-child-exit-zero-required", "self-closed"),
        record.replace(&account_hash, &"0".repeat(64)),
        record.replace(&format!("\"fileId\":\"{}\"", "22".repeat(16)), &format!("\"fileId\":\"{}80\"", "22".repeat(15))),
    ] { assert!(fullwalk.accept_result(altered.as_bytes(), &request_hash, &account_hash).is_err()); }
    assert!(fullwalk.accept_result(record.as_bytes(), &"0".repeat(64), &account_hash).is_err());
    assert!(fullwalk.accept_result(record.as_bytes(), &request_hash, &"0".repeat(64)).is_err());

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
    for (directory, pending, check) in [(0, 0, None), (2, 1, Some(C::DirectoryBoolean)), (0, 1, Some(C::DeletePending))] {
        let mut row = standard.clone();
        row[offset_of!(FS::FILE_STANDARD_INFO, Directory)] = directory;
        row[offset_of!(FS::FILE_STANDARD_INFO, DeletePending)] = pending;
        let trace = admission_trace(AdmissionRole::Manifest);
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Metadata)).metadata(FileKind::File, &basic, &row, &tag, &id),
            decode::metadata(FileKind::File, &basic, &row, &tag, &id));
        if let Some(check) = check { admission_fault(&trace, AdmissionRole::Manifest, AdmissionOp::Metadata, check, None); }
        else { assert!(trace.first.get().is_none()); }
    }
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
    {
        let trace = admission_trace(AdmissionRole::Volume);
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Directory)).ancestor_directory(&sibling, "Program Files")?, ancestors);
        assert!(trace.first.get().is_none());
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Directory)).directory(&sibling), decode::directory(&sibling));
        admission_fault(&trace, AdmissionRole::Volume, AdmissionOp::Directory, C::Attributes, Some(0));
        let trace = admission_trace(AdmissionRole::ProgramFiles);
        let short = &sibling[..sibling.len() - 1];
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Directory)).ancestor_directory(short, "Program Files"),
            decode::ancestor_directory(short, "Program Files"));
        admission_fault(&trace, AdmissionRole::ProgramFiles, AdmissionOp::Directory, C::Span, Some(1));
    }
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
    {
        use qualification_fixture::{profile_route,DISPATCH,PROFILE,PRODUCTION_DISPATCH,PRODUCTION_PROFILE,
            PRECHECK_FIELDS,HELPER_FIELDS,PRODUCTION_PRECHECK_HEADER,PRODUCER_EXIT_HEADER,PRODUCER_EXIT_FIELDS,
            OBSERVATION_HEADER,OBSERVATION_FIELDS,Wire};
        let old="refs/heads/verify/desktop-windows-installed-native";
        let new="refs/heads/verify/desktop-windows-runtime-publication";
        assert_eq!(profile_route(DISPATCH,old)?,PROFILE);assert_eq!(profile_route(PRODUCTION_DISPATCH,new)?,PRODUCTION_PROFILE);
        for (scope,reference) in [(DISPATCH,new),(PRODUCTION_DISPATCH,old),("windows-installed-native",new),
            (PRODUCTION_DISPATCH,"refs/heads/main"),("",new)] {assert!(profile_route(scope,reference).is_err());}
        assert_eq!(PRECHECK_FIELDS.len()+HELPER_FIELDS.len(),56);
        for (header,keys) in [(PRODUCER_EXIT_HEADER,PRODUCER_EXIT_FIELDS.as_slice()),
            (OBSERVATION_HEADER,OBSERVATION_FIELDS.as_slice())] {
            let mut values=Wire {values:std::collections::BTreeMap::new()};
            for key in keys {
                values.put(key,if key.ends_with("Sha256") {"1".repeat(64)}
                    else if matches!(*key,"sourceSha"|"sourceTree") {"2".repeat(40)}else{"x".to_owned()});
            }
            let raw=values.encoded(header,keys,65536)?;Wire::parse(&raw,header,keys,65536)?;
            assert!(Wire::parse(&raw,PRODUCTION_PRECHECK_HEADER,keys,65536).is_err());
            let mut extra=raw.clone();extra.extend(b"extra=1\n");assert!(Wire::parse(&extra,header,keys,65536).is_err());
        }
    }
    {
        use qualification_result::complete_fixture_write;
        use qualification_fixture::{payload_path,roster,number,Wire,PAYLOAD_NAMES,INVOCATION_HEADER,INVOCATION_FIELDS};
        for bytes in [65536usize,65537,128<<20] {
            assert!(complete_fixture_write(true,bytes as u32,bytes,true));
            assert!(!complete_fixture_write(true,(bytes-1) as u32,bytes,true));
            assert!(!complete_fixture_write(true,bytes as u32,bytes,false));
        }
        assert!(!complete_fixture_write(true,(128<<20)+1,(128<<20)+1,true));
        assert!(!ordinary_owner::complete_write(true,65537,65537,true)); // legacy result ceiling unchanged
        let raw="MRK_WINDOWS_FULLWALK_ROSTER_V1\n".to_owned()+&PAYLOAD_NAMES.iter()
            .map(|name|format!("file={name}|37|{}\n","1".repeat(64))).collect::<String>();
        let rows=roster(raw.as_bytes())?;assert_eq!(rows.len(),47);
        assert_eq!(rows.iter().map(|p|p.path.as_str()).collect::<Vec<_>>(),PAYLOAD_NAMES.to_vec());
        let base=qualification_result::fixed_path(r"C:\fixture\runtime")?;
        for name in PAYLOAD_NAMES {
            let path=payload_path(&base,name)?;
            let expected=format!(r"C:\fixture\runtime\{}",name.replace('/',"\\"));
            assert_eq!(path.to_str(),Some(expected.as_str()));
            assert_eq!(qualification_result::fixed_path(&expected)?,path);
        }
        for wrong in ["", "core.zip/", "extra.py", "../core.zip", "python/../core.zip",
            "python/Python.exe", "python//python.exe", r"python\python.exe", r"C:\python.exe"] {
            assert_eq!(payload_path(&base,wrong),Err(Error::Unsafe));
        }
        for wrong in [raw.replacen("android_build_bootstrap.py","../android_build_bootstrap.py",1),
            raw.replacen("python/python.exe","python/Python.exe",1),
            raw.replacen("|37|","|037|",1),raw.replacen("|37|","|0|",1),
            raw.replacen("|37|","|134217729|",1),raw.clone()+"file=extra|1|bad\n",
            raw.replace('\n',"\r\n")] {assert!(roster(wrong.as_bytes()).is_err());}
        for scalar in ["", "+1", "01", "-1", "true", "18446744073709551616"] {
            assert!(number(scalar,u64::MAX).is_err());
        }
        assert_eq!(number("0",u64::MAX)?,0);
        let value=qualification_fixture::invocation(&"1".repeat(40),&"2".repeat(40),"123456",37,
            &"3".repeat(64),&ordinary_stamp().wire(),&"4".repeat(64),&"5".repeat(64),700)?;
        let encoded=value.encoded(INVOCATION_HEADER,&INVOCATION_FIELDS,4096)?;
        assert_eq!(Wire::parse(&encoded,INVOCATION_HEADER,&INVOCATION_FIELDS,4096)?.get("originTickMs")?,"700");
        let text=String::from_utf8(encoded).unwrap();
        for wrong in [text.replace('\n',"\r\n"),text.clone()+"extra=1\n",
            text.replacen("profile=","profile=x\nprofile=",1),text.replacen("runId=123456","runId=\0",1)] {
            assert!(Wire::parse(wrong.as_bytes(),INVOCATION_HEADER,&INVOCATION_FIELDS,4096).is_err());
        }
    }
    assert!(ordinary_owner::complete_write(true, 37, 37, true));
    for (returned, count, bytes, closed) in [
        (false, 37, 37, true), (true, 36, 37, true), (true, 38, 37, true),
        (true, 37, 37, false), (true, 0, 0, true), (true, 65537, 65537, true),
    ] {
        assert!(!ordinary_owner::complete_write(returned, count, bytes, closed));
    }
    // The reporting path uses the same once-only write predicate and an
    // absorbing ORIGINAL end. Synthetic time is DATA, not a native deadline run.
    let start = std::time::Instant::now();
    let end = start + std::time::Duration::from_secs(12);
    let mut latched = false;
    qualification_result::reporting_effect(start, end, &mut latched)?;
    assert!(ordinary_owner::complete_write(true, 4096, 4096, true));
    assert!(!ordinary_owner::complete_write(true, 4095, 4096, true)); // no short-write retry
    assert!(!ordinary_owner::complete_write(true, 4096, 4096, false)); // no inferred close
    assert_eq!(qualification_result::reporting_effect(end, end, &mut latched), Err(Error::Unsafe));
    assert_eq!(qualification_result::reporting_effect(start, end, &mut latched), Err(Error::Unsafe));
    // A same-original close may complete, but even a complete write cannot make
    // the latched reporting boundary pass after the fact.
    assert!(!(ordinary_owner::complete_write(true, 4096, 4096, true) && !latched));
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
    for (raw, kind, check) in [(Vec::new(), FileKind::Directory, None), (unnamed.clone(), FileKind::File, None),
        (Vec::new(), FileKind::File, Some(C::StreamMissing)), (stream(":hidden:$DATA"), FileKind::File, Some(C::StreamName)),
        (multiple, FileKind::File, Some(C::StreamFrame))] {
        let trace = admission_trace(AdmissionRole::Manifest);
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Streams)).streams(&raw, kind), decode::streams(&raw, kind));
        if let Some(check) = check { admission_fault(&trace, AdmissionRole::Manifest, AdmissionOp::Streams, check, None); }
        else { assert!(trace.first.get().is_none()); }
    }
    for (raw, count, check) in [(vec![b'x', 0, 0, 0], Some(1), None),
        (vec![0], None, Some(C::Utf16Width)), (vec![0, 0xd8], None, Some(C::Utf16Encoding)),
        (vec![b'x', 0], None, Some(C::Terminator)), (vec![0, 0], None, Some(C::TextLength)),
        (vec![b'x', 0, 0, 0], Some(2), Some(C::TextLength))] {
        let trace = admission_trace(AdmissionRole::ProgramFiles);
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Location)).terminated(&raw, count), decode::terminated(&raw, count));
        if let Some(check) = check { admission_fault(&trace, AdmissionRole::ProgramFiles, AdmissionOp::Location, check, None); }
        else { assert!(trace.first.get().is_none()); }
    }
    for (raw, check) in [(mapped, None), (subst, Some(C::MappingDevice))] {
        let trace = admission_trace(AdmissionRole::ProgramFiles);
        assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Mapping)).mapping(&raw), decode::mapping(&raw));
        if let Some(check) = check { admission_fault(&trace, AdmissionRole::ProgramFiles, AdmissionOp::Mapping, check, None); }
        else { assert!(trace.first.get().is_none()); }
    }
    let trace = admission_trace(AdmissionRole::Manifest);
    assert_eq!(decode::Observed::new(trace.at(AdmissionOp::Read)).span(&[], usize::MAX, 1), Err(Error::Bounds));
    assert!(trace.first.get().is_none()); // Overflow is still Bounds, not Unsafe.
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

// Pure fullwalk fixture for the existing metadata control. These synthetic
// bindings are never offered to the native writer or treated as publication.
fn fullwalk_request() -> String {
    let app = ordinary_stamp(); let mut owner = app.clone(); owner.id = [0x12; 16];
    let fields = [
        ("role", "protected-version-fullwalk".to_owned()),
        ("test", qualification_result::FULLWALK_CHILD.to_owned()),
        ("sourceSha", "1".repeat(40)), ("sourceTree", "2".repeat(40)), ("runId", "123456".to_owned()), ("attempt", "1".to_owned()),
        ("appArtifact", r"C:\owned\target\x86_64-pc-windows-msvc\debug\deps\mobile_release_desktop-1111111111111111.exe".to_owned()),
        ("appArtifactBytes", "37".to_owned()), ("appArtifactSha256", "3".repeat(64)), ("appArtifactIdentity", app.wire()),
        ("appCommandSha256", "4".repeat(64)), ("appCompileMessagesBytes", "123".to_owned()),
        ("appCompileMessagesSha256", "5".repeat(64)), ("appCompileArgvSha256", "6".repeat(64)),
        ("ownerArtifact", r"C:\owned\target\x86_64-pc-windows-msvc\debug\deps\mrk_windows_installed_native-2222222222222222.exe".to_owned()),
        ("ownerArtifactBytes", "37".to_owned()), ("ownerArtifactSha256", "7".repeat(64)), ("ownerArtifactIdentity", owner.wire()),
        ("ownerCommandSha256", "8".repeat(64)), ("ownerCompileMessagesBytes", "234".to_owned()),
        ("ownerCompileMessagesSha256", "9".repeat(64)), ("ownerCompileArgvSha256", "a".repeat(64)),
        ("manifestSha256", "b".repeat(64)), ("protocolSha256", "c".repeat(64)),
        ("inventorySha256", "d".repeat(64)), ("coreSha256", "e".repeat(64)),
        ("payloadFiles", "45".to_owned()), ("payloadBytes", "987654".to_owned()),
        ("publicationReceiptBytes", "233".to_owned()), ("publicationReceiptSha256", "f".repeat(64)),
        ("versionIdentity", format!("77:{}", "21".repeat(16))),
        ("selectedPythonIdentity", format!("77:{}", "22".repeat(16))),
        ("selectedBootstrapIdentity", format!("77:{}", "23".repeat(16))),
        ("selectedCoreIdentity", format!("77:{}", "24".repeat(16))),
    ];
    let mut raw = "MRK_WINDOWS_FULLWALK_REQUEST_V1\n".to_owned();
    for (name, value) in fields { raw.push_str(name); raw.push('='); raw.push_str(&value); raw.push('\n'); }
    raw
}

#[test]
fn passive_request_and_result_preserve_roles_and_original_finality() -> Result<()> {
    use qualification_result::{FullwalkRequest, InputTrace, PassiveFacts, PASSIVE_CHILD, FULLWALK_CHILD};
    let old_raw = fullwalk_request();
    let raw = old_raw.replace("MRK_WINDOWS_FULLWALK_REQUEST_V1", "MRK_WINDOWS_INSTALLED_PASSIVE_REQUEST_V1")
        .replace("role=protected-version-fullwalk", "role=installed-passive")
        .replace(FULLWALK_CHILD, PASSIVE_CHILD).replace("payloadFiles=45", "payloadFiles=46");
    let parse = |bytes: &[u8]| FullwalkRequest::parse_passive(bytes, &mut InputTrace::default());
    let request = parse(raw.as_bytes())?;
    let old = FullwalkRequest::parse(old_raw.as_bytes())?;
    assert!(parse(old_raw.as_bytes()).is_err());
    assert!(FullwalkRequest::parse(raw.as_bytes()).is_err());
    assert_ne!(qualification_result::passive_command(&request.app.path),
        qualification_result::fullwalk_command(&request.app.path));
    assert!(qualification_result::passive_command(&request.app.path)
        .ends_with(&format!("{PASSIVE_CHILD} --exact --ignored --nocapture --test-threads=1")));
    for changed in [
        raw.replace("MRK_WINDOWS_INSTALLED_PASSIVE_REQUEST_V1", "MRK_WINDOWS_FULLWALK_REQUEST_V1"),
        raw.replace("role=installed-passive", "role=protected-version-fullwalk"),
        raw.replace(PASSIVE_CHILD, FULLWALK_CHILD), raw.replace(PASSIVE_CHILD, qualification_result::PASSIVE_OWNER),
        raw.replace("appCommandSha256=", "ownerCommandSha256="),
        raw.replace(&format!("appCommandSha256={}", "4".repeat(64)), "appCommandSha256=not-a-command-digest"),
        raw.replace("attempt=1", "attempt=2"), raw.clone() + "extra=1\n", raw.replace('\n', "\r\n"),
    ] { assert!(parse(changed.as_bytes()).is_err()); }
    let request_sha = "5".repeat(64); let account_sha = "6".repeat(64);
    let facts = PassiveFacts { version: request.expected(&account_sha, 543), completed_methods: 5,
        settled_owners: 9, payload_images: 23, system_images: 23, stopped_before_claim: true, stopped_owned_child: true };
    let output = request.passive_result(&request_sha, &facts)?;
    assert_eq!(request.accept_passive_result(output.as_bytes(), &request_sha, &account_sha)?, 543);
    assert!(request.result(&request_sha, &facts.version).is_err());
    assert!(old.passive_result(&request_sha, &facts).is_err());
    assert!(old.accept_result(output.as_bytes(), &request_sha, &account_sha).is_err());
    let old_output = old.result(&request_sha, &old.expected(&account_sha, 543))?;
    assert!(request.accept_passive_result(old_output.as_bytes(), &request_sha, &account_sha).is_err());
    for field in 0..10 {
        let mut changed = facts.clone();
        match field {
            0 => changed.completed_methods = 4, 1 => changed.settled_owners = 8,
            2 => changed.payload_images = 21, 3 => changed.payload_images = 34,
            4 => changed.system_images = 0, 5 => changed.system_images = 32,
            6 => changed.stopped_before_claim = false, 7 => changed.stopped_owned_child = false,
            8 => changed.version.selected_identities[0].file_id[15] ^= 0x80,
            _ => changed.version.entries = MAX_ENTRIES + 1,
        }
        assert!(request.passive_result(&request_sha, &changed).is_err());
    }
    for changed in [
        output.replace("\"settledOriginalOwners\":9", "\"settledOriginalOwners\":8"),
        output.replace("\"settledOriginalOwners\":9", "\"settledOriginalOwners\":9,\"settledOriginalOwners\":9"),
        output.replace("\"stoppedBeforeClaim\":true", "\"stoppedBeforeClaim\":false"),
        output.replace("\"stoppedOwnedChild\":true", "\"stoppedOwnedChild\":false"),
        output.replace("\"productionEnabled\":false", "\"productionEnabled\":true"),
        output.replace("\"bookSettled\":true", "\"bookSettled\":false"),
        output.replace("\"payloadImages\":23", "\"payloadImages\":023"),
        output.replace(PASSIVE_CHILD, FULLWALK_CHILD), output.trim_end().to_owned(),
    ] { assert!(request.accept_passive_result(changed.as_bytes(), &request_sha, &account_sha).is_err()); }
    assert!(request.accept_passive_result(output.as_bytes(), &"7".repeat(64), &account_sha).is_err());
    assert!(request.accept_passive_result(output.as_bytes(), &request_sha, &"8".repeat(64)).is_err());
    Ok(())
}

#[test]
fn passive_setup_profile_is_disjoint_from_publication_and_fullwalk() -> Result<()> {
    use qualification_fixture::{profile_route, DISPATCH, PRODUCTION_DISPATCH, PASSIVE_DISPATCH, PASSIVE_PROFILE,
        passive_precheck_fields, PASSIVE_PRECHECK_HEADER, PRECHECK_HEADER, PRODUCTION_PRECHECK_HEADER,
        PASSIVE_SETUP_EXIT_HEADER, PRODUCER_EXIT_HEADER, PRODUCER_EXIT_FIELDS,
        PASSIVE_STAGE, PASSIVE_OBSERVE, PASSIVE_SETUP_PROOFS, Wire};
    let reference = "refs/heads/verify/desktop-windows-installed-passive";
    assert_eq!(profile_route(PASSIVE_DISPATCH, reference)?, PASSIVE_PROFILE);
    for (scope, reference) in [(DISPATCH, reference), (PRODUCTION_DISPATCH, reference),
        (PASSIVE_DISPATCH, "refs/heads/verify/desktop-windows-runtime-publication"),
        (PASSIVE_DISPATCH, "refs/heads/verify/desktop-windows-installed-native"), (PASSIVE_DISPATCH, "refs/heads/main")] {
        assert!(profile_route(scope, reference).is_err());
    }
    assert_ne!(PASSIVE_STAGE, qualification_fixture::STAGE_INPUT);
    assert_ne!(PASSIVE_OBSERVE, qualification_fixture::OBSERVE_BEFORE);
    assert_eq!(PASSIVE_SETUP_PROOFS.map(|proof| proof.0), ["stage", "stageExit", "helperSuccessExit"]);
    let fields = passive_precheck_fields();
    assert_eq!(fields.len(), 55);
    assert!(!fields.iter().any(|field| field.starts_with("ordinary") || field.starts_with("fullwalk")));
    for (header, keys, wrong_headers) in [
        (PASSIVE_PRECHECK_HEADER, fields.as_slice(), [PRECHECK_HEADER, PRODUCTION_PRECHECK_HEADER]),
        (PASSIVE_SETUP_EXIT_HEADER, PRODUCER_EXIT_FIELDS.as_slice(), [PRODUCER_EXIT_HEADER, PASSIVE_PRECHECK_HEADER]),
    ] {
        let mut wire = Wire { values: std::collections::BTreeMap::new() };
        for key in keys {
            wire.put(key, if key.ends_with("Sha256") { "1".repeat(64) }
                else if matches!(*key, "sourceSha" | "sourceTree") { "2".repeat(40) } else { "x".to_owned() });
        }
        let raw = wire.encoded(header, keys, 16384)?;
        Wire::parse(&raw, header, keys, 16384)?;
        for wrong in wrong_headers { assert!(Wire::parse(&raw, wrong, keys, 16384).is_err()); }
        let mut duplicate = raw; duplicate.extend_from_slice(b"profile=x\n");
        assert!(Wire::parse(&duplicate, header, keys, 16384).is_err());
    }
    Ok(())
}
