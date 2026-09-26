//! Inert, std-only contracts. May be run with rustc --test on a non-Windows
//! host; no native entry, observer process, dispatcher, or deadline is created.
#![allow(dead_code)]
#[path = "../src/ui_startup_data.rs"]
mod ui_startup_data;
#[path = "../src/ui_observer_diagnostic_data.rs"]
mod data;
#[path = "../../../src-tauri/src/windows_startup.rs"]
mod windows_startup;

const JOURNAL: &str = include_str!("../src/observer_diagnostic.rs");
const RESULT: &str = include_str!("../src/qualification_result.rs");
const OWNER: &str = include_str!("../src/ordinary_owner_ui.rs");
const OBSERVER: &str = include_str!("../../../src-tauri/src/installed_shell_observation_windows.rs");
const STARTUP: &str = include_str!("../../../src-tauri/src/shell_windows.rs");
const SHELL: &str = include_str!("../../../src-tauri/src/shell.rs");
const BOOK: &str = include_str!("../src/lib.rs");

fn between<'a>(source: &'a str, begin: &str, end: &str) -> &'a str {
    source.split_once(begin).unwrap().1.split_once(end).unwrap().0
}
fn ordered(source: &str, fragments: &[&str]) {
    let mut rest = source;
    for fragment in fragments { rest = rest.split_once(fragment).unwrap_or_else(|| panic!("missing order fragment {fragment}")).1; }
}

#[test]
fn append_sharing_is_private_and_existing_file_open_is_unchanged() {
    let ordinary = between(RESULT, "pub(super) fn open_traced(", "fn info(");
    assert!(ordinary.contains("FS::FILE_SHARE_READ | if directory { FS::FILE_SHARE_WRITE } else { 0 }"));
    assert!(!ordinary.contains("APPEND_ACCESS"));
    let open = between(JOURNAL, "fn open(&mut self, parent_create:", "fn named(");
    for expected in [
        "if parent_create { FS::FILE_GENERIC_READ } else { APPEND_ACCESS }",
        "FS::FILE_SHARE_READ | if parent_create { FS::FILE_SHARE_WRITE } else { 0 }",
        "if parent_create { FS::CREATE_NEW } else { FS::OPEN_EXISTING }",
        "b.state = SlotState::Acquiring; b.active = true;",
        "b.state = SlotState::Unknown; return Err(Error::Unknown);",
    ] { assert!(open.contains(expected), "{expected}"); }
    assert!(JOURNAL.contains("const APPEND_ACCESS: u32 = FS::FILE_APPEND_DATA | FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::SYNCHRONIZE;"));
    for forbidden in ["FS::FILE_SHARE_DELETE", "FS::FILE_WRITE_DATA", "FS::GENERIC_WRITE", "FS::CREATE_ALWAYS",
        "FS::TRUNCATE_EXISTING", "SetFilePointer", "SetEndOfFile", "DeleteFile", "MoveFile", "CreateThread"] {
        assert!(!JOURNAL.contains(forbidden), "{forbidden}");
    }
    assert!(JOURNAL.contains("fullwalk_digest(request_raw.as_bytes(), end, false)? == values[1]"));
    assert!(JOURNAL.contains("self.volume == stamp.volume && self.id == stamp.id && self.creation == stamp.creation"));
    let append = between(JOURNAL, "fn append(&mut self, raw:", "fn close(");
    assert_eq!(append.matches("self.original.write(").count(), 1);
    ordered(append, &["self.check(permitted)?", "self.original.write(raw, data::RECORD_LIMIT)?", "self.check(permitted)"]);
    let native_attempt = JOURNAL.split_once("fn append_original(").unwrap().1;
    ordered(native_attempt, &["let mut file = JournalFile::new", "data::append_once(", "if observed == R::Unresolved",
        "std::hint::black_box((&mut file, self, permitted))", "need(observed == R::Complete)?", "file.check(permitted)?", "self.bytes.store(next"]);
}

#[test]
fn same_original_precedes_launch_survives_finality_and_has_exact_output_roster() {
    let run = between(OWNER, "fn run_prerequisite_traced(", "#[cfg(test)]");
    ordered(run, &["observer_diagnostic = Some(ObserverDiagnosticOriginal::new", ".create(&request_sha)?",
        "launch = Some(Launch::ui_traced", ".bind_ui_diagnostic(role, &output, diagnostic)?", ".enter_traced(",
        ".finish_traced(", "output_poststate(", "value.close().is_err()", "close_files_traced(&mut files", "ObserverDiagnosticOriginal::is_closed"]);
    assert!(run.contains("&& files.len() + usize::from(observer_diagnostic.is_some()) <= 48"));
    for parked in run.split("loop { std::thread::park();").skip(1) {
        assert!(parked.split_once(")); }").unwrap().0.contains("observer_diagnostic"));
    }
    let inventory = between(OWNER, "fn output_poststate(", "// Qualification-only, same-thread DATA.");
    ordered(inventory, &["diagnostic.is_some() == matches!(role, UiRole::ProjectDraft | UiRole::QuitPassive | UiRole::DocumentLoss)",
        "let name = diagnostic.name()", "observer_journal_poststate(native, &entries[at].0, diagnostic, false)?",
        "entries.push((original, metadata))"]);
    let journal = between(OWNER, "fn observer_journal_poststate(", "fn observer_failure_poststate(");
    ordered(journal, &["native.open_child(parent, &diagnostic.name(), FileKind::File)?", "native.metadata(&original)?",
        "diagnostic.poststate(failure)?", "metadata.identity.file_id == stamp.id", "native.no_alternate_streams(&original)?",
        "native.metadata(&original)? == metadata", "ObserverProjection::decode(&raw)"]);
    for bound in ["seen.len() <= 6", "need(seen == expected)", "need(parts.len() < 16)"] { assert!(inventory.contains(bound)); }
    assert!(OWNER.contains("need(creates.len() < 4)")); assert!(OWNER.contains("need(files.len() < 48)"));
    // Worst admitted owner: ancestors16 + request1 + fixed dirs4 + apps2 +
    // compiler streams2 + publication1 + output1 + fixture dirs3 + payload
    // writer/read pairs8 + result1 + diagnostic1 =40 <= the unchanged48.
    assert_eq!(16 + 1 + 4 + 2 + 2 + 1 + 1 + 3 + 8 + 1 + 1, 40);
    // Largest inventory: root/ancestors16 + fixture dirs3 + files4 + journal1.
    assert!(16 + 3 + 4 + 1 <= 48);
    // Output adds exactly one leaf, not a directory. Project branch remains
    // the largest per-directory inventory at four children plus dot entries.
    assert!(3 + 2 <= 6 && 4 + 2 == 6);
    let post = between(JOURNAL, "pub(crate) fn poststate(", "pub(crate) fn close(");
    assert!(post.contains("self.file.read(&permitted)?"));
    assert!(post.contains("raw.len() == before.size as usize"));
    assert!(!post.contains("serde") && !post.contains("from_utf8") && !post.contains("lines()"));
}

#[test]
fn diagnostic_allowance_is_upfront_and_each_real_native_call_is_gated() {
    let clock = between(JOURNAL, "impl ObserverDiagnosticClock {", "const APPEND_ACCESS");
    for expected in ["entry.checked_add(data::EXECUTION_MS)", "entry.checked_add(data::DIAGNOSTIC_MS)",
        "execution_end.checked_add", "execution_latched", "diagnostic_latched", "data::window_sample"] { assert!(clock.contains(expected)); }
    assert!(!clock.contains("Instant::now().checked_add"));
    let call = between(BOOK, "fn call(&mut self, call:", "fn mark_entered(");
    ordered(call, &["self.observer_inventory_effect(call)?", "self.active = Some", "self.mark_entered(call)?",
        "let returned = unsafe { invoke(frame) }", "frame.returned.set(Some(returned))", "self.finish(call, returned)",
        "if !matches!(original, Err(Error::Unknown))", "let timely = self.observer_inventory_effect(call)"]);
    let failure = between(BOOK, "fn observer_failure_inventory(", "fn observer_inventory_effect(");
    for expected in ["!child_final || !self.never_started()", "gate.order.select_failure(child_final, true)", "gate.clock.permitted(true)"] {
        assert!(failure.contains(expected));
    }
    let gate = between(BOOK, "fn observer_inventory_effect(", "fn remember_unavailable(");
    assert!(gate.contains("if matches!(call, Call::Close(_)) { return Ok(()); }"));
    assert!(gate.contains("gate.order.attempted()"));
    for forbidden in ["Call::Token(", "Call::Read(", "Call::Entries", "gate.failure = false"] { assert!(!gate.contains(forbidden)); }
    let create = between(JOURNAL, "pub(crate) fn create(", "pub(crate) fn binding(");
    assert!(create.contains("clock.permitted(false)")); assert!(!create.contains("&|| true"));
    let read = between(JOURNAL, "fn read(&mut self, permitted:", "fn close(");
    ordered(read, &["self.stamp(permitted)?", "self.check(permitted)?", "FS::ReadFile(", "F::GetLastError()",
        "b.state = SlotState::Unknown; return Err(Error::Unknown)", "self.check(permitted)?", "self.stamp(permitted)? == before"]);
    assert_eq!(read.matches("FS::ReadFile(").count(), 1);
    let run = between(OWNER, "fn run_prerequisite_traced(", "#[cfg(test)]");
    ordered(run, &["Clock::new(entry_tick)", "ObserverDiagnosticClock::new(entry_tick, clock.end)", "inventory.bind_observer_inventory(",
        "let root =", "capture.output = Some((out, files[out].stamp_traced(trace)?))", ".enter_traced(", ".finish_traced(",
        "output_poststate(", "!capture.claimed", "capture.claimed = true", "observer_child_final(", "inventory.never_started()",
        "inventory.observer_failure_inventory(child_final)?", "observer_failure_poststate(", "!capture.unresolved", "inventory.prerequisite_settle(trace)"]);
    let parent = between(OWNER, "fn observer_failure_poststate(", "fn output_poststate(");
    assert!(!parent.contains(".stamp(") && !parent.contains("stamp_traced(") && !parent.contains("next_entries(") && !parent.contains("read_next("));
    for expected in ["body.state == SlotState::Owned && !body.active", "metadata.identity.file_id == cached.1.id", "metadata.creation == cached.1.creation",
        "native.metadata(original)? == *before", "native.mapping(&drive)? == device"] { assert!(parent.contains(expected)); }
    let finality = between(OWNER, "fn observer_child_final(", "fn observer_capture_frame(");
    for expected in ["value.return_recorded", "facts.returned", "facts.created", "facts.signaled", "facts.exit.is_some()", "unknown: facts.unknown",
        "facts.process == SlotState::Closed", "facts.thread == SlotState::Closed", "}.admitted()"] { assert!(finality.contains(expected)); }
}

#[test]
fn refusal_and_snapshots_do_not_hold_record_across_diagnostic_io() {
    let refuse = between(OBSERVER, "fn fail(&self, reason:", "pub(super) fn diagnostic(");
    assert!(refuse.contains("diagnostic.refuse(reason)"));
    for forbidden in ["self.record", ".lock(", ".progress(", ".startup("] { assert!(!refuse.contains(forbidden)); }
    let snapshot = between(OBSERVER, "fn diagnostic_snapshot(", "fn diagnostic_progress(");
    assert!(snapshot.contains("self.record.try_lock()"));
    ordered(snapshot, &["let snapshot = match self.record.try_lock()", "Err(_) => None };", "match snapshot"]);
    assert!(!snapshot.contains(".progress(") && !snapshot.contains(".startup("));
    let main = OBSERVER.split_once("pub(crate) fn main()").unwrap().1;
    ordered(main, &["native::normal_ui_deadline()", "native::require_normal_ui_qualification()", "native::ObserverDiagnostic::admit(end)",
        "diagnostic.admitted()", "super::run_builder(", "diagnostic.builder_returned("]);
    assert!(OBSERVER.contains("DocumentBinding::exit_cleanup_end"));
    assert!(SHELL.contains("windows_startup.bind_observer_diagnostic(q.diagnostic())"));
    assert!(SHELL.contains("q.bind_diagnostic_document(document.clone())"));
    let order = between(STARTUP, "fn with_order<T>(", "fn diagnostic_end(");
    assert!(!order.contains("self.publish(") && !order.contains("observer_word"));
    let drop = between(STARTUP, "impl Drop for OriginalCall", "impl Startup {");
    assert!(drop.contains("self.startup.publish_property()"));
    assert!(!drop.contains("observer_word") && !drop.contains("self.startup.publish()"));
    let publish = between(STARTUP, "fn publish(&self)", "fn publish_property(");
    ordered(publish, &["self.publish_property()", "self.observer_word(word)"]);
    let refusal = between(STARTUP, "fn refuse(&self, event:", "pub(super) fn lost(");
    ordered(refusal, &["self.with_order(", "self.publish()"]);
    assert!(STARTUP.contains("diagnostic.startup(word, &|| self.diagnostic_end().is_some())"));
}
