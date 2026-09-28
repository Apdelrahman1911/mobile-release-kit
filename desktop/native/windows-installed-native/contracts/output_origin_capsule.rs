//! Inert DATA/ownership contracts; no CNG, process, file, key or clock is created.
//! Compile/run only under the separately accepted local validation command.
#![allow(dead_code)]
#[path = "../src/ui_startup_data.rs"]
mod ui_startup_data;
#[path = "../src/ui_observer_diagnostic_data.rs"]
mod ui_observer_diagnostic_data;
#[path = "../src/output_origin_capsule_data.rs"]
mod output_origin_capsule_data;
use output_origin_capsule_data as data;
#[path = "../src/output_origin_capsule_public_key.rs"]
mod public_key;

use data::{Binding, Capture, Failure, HandleOrder, HandleState, Phase, Reply, Stage, Step};
use ui_observer_diagnostic_data::Projection;

const ROW: &[u8] = b"{\"schema\":1,\"sequence\":1,\"event\":1,\"step\":1,\"pending\":0,\"pendingStep\":0,\"dispatch\":0,\"flags\":0,\"startup\":null,\"refusal\":0,\"coverageIncomplete\":false}\n";
const NATIVE: &str = include_str!("../src/output_origin_capsule.rs");
const OWNER: &str = include_str!("../src/ordinary_owner_ui.rs");
const LIB: &str = include_str!("../src/lib.rs");
const DATA: &str = include_str!("../src/output_origin_capsule_data.rs");
const PUBLIC: &str = include_str!("../src/output_origin_capsule_public_key.rs");

fn binding() -> Binding {
    Binding::parse(&"a".repeat(40), &"b".repeat(40), "18446744073709551615", &"c".repeat(64)).unwrap()
}
fn capture(leaf: &str) -> Capture {
    let mut value = Capture::default(); value.journal_returned(Projection::decode(ROW));
    value.record_once(Some(binding()), 0x9988_7710, Some((0x1122_3344_5566_7788, [0x19; 16])), [0x27; 16], leaf);
    value
}
fn frame(value: &Capture, reply: &Reply) -> Vec<u8> {
    let mut output = [0; data::FRAME_BYTES];
    let length = data::frame(value.public_context().unwrap(), reply, &mut output).unwrap();
    output[..length].to_vec()
}
fn between<'a>(source: &'a str, begin: &str, end: &str) -> &'a str {
    source.split_once(begin).unwrap().1.split_once(end).unwrap().0
}
fn ordered(source: &str, parts: &[&str]) {
    let mut rest = source;
    for part in parts { rest = rest.split_once(part).unwrap_or_else(|| panic!("missing fixed source fragment")).1; }
}

#[test]
fn fixed_layout_preserves_exact_private_data_without_normalizing() {
    let leaf = "a\u{301}\u{1f680}Z ";
    let mut value = capture(leaf); assert_eq!(value.begin_seal(), Ok(()));
    let bytes = value.private_buffer();
    assert!(bytes[..8] == *b"MRKODC1\0"); assert!(bytes[8..12] == [1, 0, 1, 1]);
    assert!(bytes[12..16] == 0x9988_7710u32.to_le_bytes());
    assert!(bytes[16..36] == [0xaa; 20] && bytes[36..56] == [0xbb; 20]);
    assert!(bytes[56..64] == u64::MAX.to_le_bytes() && bytes[64..96] == [0xcc; 32]);
    assert!(bytes[96..104] == 0x1122_3344_5566_7788u64.to_le_bytes());
    assert!(bytes[104..120] == [0x19; 16] && bytes[120..136] == [0x27; 16]);
    let units: Vec<_> = leaf.encode_utf16().collect();
    assert!(bytes[136..138] == (units.len() as u16).to_le_bytes());
    for (index, unit) in units.iter().enumerate() {
        assert!(bytes[138 + index * 2..140 + index * 2] == unit.to_le_bytes());
    }
    assert!(bytes[138 + units.len() * 2..].iter().all(|byte| *byte == 0));
    let mut composed = capture("\u{e1}\u{1f680}Z ");
    assert!(composed.private_buffer() != bytes);
    assert_eq!(data::PLAINTEXT_BYTES, 688); assert_eq!(data::CIPHERTEXT_BYTES, 768);
    assert!(data::PLAINTEXT_BYTES <= data::CIPHERTEXT_BYTES - 2 * 32 - 2);
}

#[test]
fn utf16_unit_boundary_is_not_character_or_utf8_byte_count() {
    for leaf in ["x".repeat(255), "\u{e9}".repeat(255), "\u{1f680}".repeat(127) + "x"] {
        let mut value = capture(&leaf); assert_eq!(value.begin_seal(), Ok(()));
        assert!(value.private_buffer()[136..138] == 255u16.to_le_bytes());
    }
    for leaf in [String::new(), "x".repeat(256), "\u{1f680}".repeat(128), "\u{1f680}".repeat(127) + "ab"] {
        let mut value = capture(&leaf);
        assert_eq!(value.begin_seal(), Err(Failure::data(Stage::LeafBounds)));
        assert_eq!(value.begin_seal(), Err(Failure::data(Stage::AlreadyClaimed)));
    }
}

#[test]
fn source_tree_run_and_request_bindings_are_canonical_and_bounded() {
    let (source, tree, request) = ("a".repeat(40), "b".repeat(40), "c".repeat(64));
    assert!(Binding::parse(&source, &tree, "1", &request).is_some());
    assert!(Binding::parse(&source, &tree, "18446744073709551615", &request).is_some());
    for run in ["", "0", "01", "-1", "+1", " 1", "1 ", "1\n", "18446744073709551616", "999999999999999999999"] {
        assert!(Binding::parse(&source, &tree, run, &request).is_none());
    }
    for bad in ["a".repeat(39), "a".repeat(41), "A".repeat(40), "g".repeat(40)] {
        assert!(Binding::parse(&bad, &tree, "1", &request).is_none());
        assert!(Binding::parse(&source, &bad, "1", &request).is_none());
    }
    for bad in ["c".repeat(63), "c".repeat(65), "C".repeat(64), "z".repeat(64)] {
        assert!(Binding::parse(&source, &tree, "1", &bad).is_none());
    }
}

#[test]
fn first_capture_and_checked_journal_are_separate_immutable_history() {
    let mut value = capture("inert-first");
    let first = *value.private_buffer();
    value.journal_returned(Projection::decode(b""));
    value.record_once(None, 0, None, [0; 16], "must-not-overwrite");
    assert!(value.private_buffer() == &first);
    let public = frame(&value, &Reply::Incomplete { key_id: None, failure: Failure::data(Stage::Recipient) });
    let text = std::str::from_utf8(&public).unwrap();
    assert!(text.contains("\"checkedJournalContext\":{\"bytes\":"));
    assert!(text.contains("\"records\":1,\"reason\":0"));
    assert!(text.contains("\"inventoryComplete\":false"));
    assert!(!text.contains("inert-first") && !text.contains("must-not-overwrite"));
    assert_eq!(value.begin_seal(), Ok(()));
    assert_eq!(value.begin_seal(), Err(Failure::data(Stage::AlreadyClaimed)));

    let mut missing_journal = Capture::default();
    missing_journal.record_once(Some(binding()), 16, Some((1, [2; 16])), [3; 16], "inert");
    assert_eq!(missing_journal.begin_seal(), Err(Failure::data(Stage::JournalSnapshot)));
    missing_journal.journal_returned(Projection::decode(ROW)); // Not a retry.
    assert!(data::frame(missing_journal.public_context().unwrap(),
        &Reply::Sealed { key_id: [0x52; 32], ciphertext: [0x61; data::CIPHERTEXT_BYTES] },
        &mut [0; data::FRAME_BYTES]).is_none());
    for missing in [Stage::Binding, Stage::OutputMetadata] {
        let mut value = Capture::default(); value.journal_returned(Projection::decode(ROW));
        value.record_once(if missing == Stage::Binding { None } else { Some(binding()) },
            16, if missing == Stage::OutputMetadata { None } else { Some((1, [2; 16])) }, [3; 16], "inert");
        assert_eq!(value.begin_seal(), Err(Failure::data(missing)));
        assert!(value.private_buffer().iter().all(|byte| *byte == 0));
    }
}

#[test]
fn bounded_frame_contains_ciphertext_and_public_context_but_no_private_payload() {
    let value = capture("inert-private-\r\n\"leaf\u{1f680}");
    let key = [0x52; 32]; let ciphertext = [0x61; data::CIPHERTEXT_BYTES];
    let raw = frame(&value, &Reply::Sealed { key_id: key, ciphertext });
    assert!(raw.len() <= data::FRAME_BYTES);
    let text = std::str::from_utf8(&raw).unwrap();
    assert!(text.starts_with("\nMRK_WINDOWS_UI_OUTPUT_ORIGIN_CAPSULE_V1={"));
    assert!(text.ends_with("}\n"));
    for public in [format!("\"source\":\"{}\"", "a".repeat(40)), format!("\"tree\":\"{}\"", "b".repeat(40)),
        "\"run\":\"18446744073709551615\",\"attempt\":1,\"role\":\"project-draft\"".to_owned(),
        format!("\"request\":\"{}\"", "c".repeat(64)), format!("\"keySha256\":\"{}\"", "52".repeat(32))] {
        assert!(text.contains(&public));
    }
    let hex = text.split_once("\"ciphertextHex\":\"").unwrap().1.split_once('"').unwrap().0;
    assert_eq!(hex.len(), 1536); assert!(hex == "61".repeat(768));
    for forbidden in ["inert-private", "leaf", "1919191919191919", "2727272727272727", "MRKODC1",
        "plaintextHex", "plaintextSha", "privateKey", "creatorPid"] { assert!(!text.contains(forbidden)); }

    let raw = frame(&value, &Reply::Incomplete { key_id: Some(key), failure: Failure::native(Stage::Encrypt, i32::MIN) });
    let text = std::str::from_utf8(&raw).unwrap();
    assert!(text.contains("\"status\":\"incomplete\",\"stage\":\"encrypt\",\"ntstatus\":2147483648"));
    assert!(!text.contains("ciphertextHex"));
}

#[test]
fn maximum_scalar_journal_context_still_fits_one_fixed_frame() {
    let mut row = ui_observer_diagnostic_data::Row::decode(ROW).unwrap();
    row.sequence = u8::MAX; row.snapshot.dispatch = u16::MAX; row.snapshot.flags = u16::MAX;
    row.startup = Some(u64::MAX); row.coverage_incomplete = false;
    let mut value = Capture::default();
    value.journal_returned(Projection { bytes: u32::MAX, records: u8::MAX, reason: u8::MAX,
        last: Some(row), observer_refusal: Some(row), startup_refusal: Some(row), directory_fence: None });
    value.record_once(Some(binding()), 16, Some((1, [2; 16])), [3; 16], "inert");
    let raw = frame(&value, &Reply::Sealed { key_id: [0xff; 32], ciphertext: [0xff; data::CIPHERTEXT_BYTES] });
    assert!(raw.len() <= 4096); assert!(raw.ends_with(b"}\n"));
    assert!(std::mem::size_of::<Capture>() + std::mem::size_of::<Reply>()
        + data::FRAME_BYTES + data::PUBLIC_BLOB_BYTES < 16 * 1024);
}

#[test]
fn seal_order_stops_on_unknown_and_closes_known_failures_without_retry() {
    let all = [Phase::Open, Phase::Import, Phase::Encrypt, Phase::Destroy, Phase::Close];
    let mut seen = Vec::new();
    assert_eq!(data::seal_once(|phase| { seen.push(phase); Step::Good }), Step::Good);
    assert_eq!(seen, all);
    for (index, failed) in all[..3].iter().copied().enumerate() {
        let refusal = Failure::data(Stage::Clock); let mut seen = Vec::new();
        let result = data::seal_once(|phase| { seen.push(phase); if phase == failed { Step::Refused(refusal) } else { Step::Good } });
        assert_eq!(result, Step::Refused(refusal));
        let mut expected = all[..=index].to_vec(); expected.extend([Phase::Destroy, Phase::Close]);
        assert_eq!(seen, expected);
    }
    for (index, unknown) in all.iter().copied().enumerate() {
        let mut seen = Vec::new();
        assert_eq!(data::seal_once(|phase| { seen.push(phase); if phase == unknown { Step::Unresolved } else { Step::Good } }), Step::Unresolved);
        assert_eq!(seen, all[..=index]);
    }
    let mut seen = Vec::new();
    assert_eq!(data::seal_once(|phase| {
        seen.push(phase);
        match phase { Phase::Encrypt => Step::Refused(Failure::native(Stage::Encrypt, -1)),
            Phase::Destroy => Step::Unresolved, _ => Step::Good }
    }), Step::Unresolved);
    assert_eq!(seen, all[..4]);
    let first = Failure::native(Stage::Encrypt, -1);
    assert_eq!(data::seal_once(|phase| match phase {
        Phase::Encrypt => Step::Refused(first), Phase::Destroy | Phase::Close => Step::Refused(Failure::data(Stage::Clock)),
        _ => Step::Good }), Step::Refused(first));
}

#[test]
fn original_handle_slots_reject_contradictory_and_duplicate_acquisition_or_close() {
    for (status, present, expected) in [(0, true, HandleState::Owned), (-1, false, HandleState::NoHandle),
        (0, false, HandleState::Unknown), (-1, true, HandleState::Unknown)] {
        let mut slot = HandleOrder::new(); assert!(slot.acquire_enter());
        assert_eq!(slot.acquire_return(status, present), expected);
        if expected == HandleState::Owned {
            assert!(!slot.settled()); assert_eq!(slot.close_enter(), Some(true));
            assert!(slot.close_return(0)); assert!(slot.settled()); assert_eq!(slot.close_enter(), Some(false));
        } else if expected == HandleState::NoHandle {
            assert!(slot.settled()); assert_eq!(slot.close_enter(), Some(false));
        } else { assert!(!slot.settled()); assert_eq!(slot.close_enter(), None); }
    }
    let mut not_entered = HandleOrder::new();
    assert_eq!(not_entered.acquire_return(0, true), HandleState::Unknown); assert_eq!(not_entered.close_enter(), None);
    let mut duplicate = HandleOrder::new(); assert!(duplicate.acquire_enter()); assert!(!duplicate.acquire_enter());
    assert_eq!(duplicate.acquire_return(0, true), HandleState::Unknown); assert!(!duplicate.settled());
    let mut duplicate_close = HandleOrder::new(); assert!(duplicate_close.acquire_enter());
    assert_eq!(duplicate_close.acquire_return(0, true), HandleState::Owned);
    assert_eq!(duplicate_close.close_enter(), Some(true)); assert_eq!(duplicate_close.close_enter(), None);
    assert!(!duplicate_close.close_return(0)); assert!(!duplicate_close.settled());
    let mut failed_close = HandleOrder::new(); assert!(failed_close.acquire_enter());
    assert_eq!(failed_close.acquire_return(0, true), HandleState::Owned); assert_eq!(failed_close.close_enter(), Some(true));
    assert!(!failed_close.close_return(-1)); assert_eq!(failed_close.close_enter(), None); assert!(!failed_close.settled());
}

#[test]
fn existing_upfront_diagnostic_latch_is_absorbing_while_known_closes_still_run() {
    use std::sync::atomic::AtomicBool;
    for stop in [Phase::Open, Phase::Import, Phase::Encrypt] {
        let latch = AtomicBool::new(false); let mut seen = Vec::new(); let mut expired = false;
        let result = data::seal_once(|phase| {
            if phase == stop { expired = true; }
            let permitted = ui_observer_diagnostic_data::window_sample(100, 110_100,
                if expired { 110_100 } else { 110_099 }, true, &latch);
            if !matches!(phase, Phase::Destroy | Phase::Close) && !permitted {
                return Step::Refused(Failure::data(Stage::Clock));
            }
            seen.push(phase); // Real-effect script: original closes may consume late.
            if permitted { Step::Good } else { Step::Refused(Failure::data(Stage::Clock)) }
        });
        assert_eq!(result, Step::Refused(Failure::data(Stage::Clock)));
        assert!(seen.ends_with(&[Phase::Destroy, Phase::Close]));
        assert!(!ui_observer_diagnostic_data::window_sample(100, 110_100, 101, true, &latch));
    }
}

#[test]
fn public_blob_has_one_documented_format_and_no_private_key_selector() {
    let mut blob = [0; data::PUBLIC_BLOB_BYTES];
    for (index, word) in [0x3141_5352u32, 6144, 3, 768, 0, 0].into_iter().enumerate() {
        blob[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    blob[24..27].copy_from_slice(&[1, 0, 1]); blob[27] = 0x80; blob[794] = 1;
    assert!(data::public_blob_valid(&blob));
    for index in [0, 4, 8, 12, 16, 20, 24, 25, 26, 27, 794] {
        let mut changed = blob; changed[index] ^= if index == 27 { 0x80 } else { 1 };
        assert!(!data::public_blob_valid(&changed));
    }
    if let Some(key) = public_key::PINNED_PUBLIC_KEY.as_ref() { assert!(data::public_blob_valid(&key.blob)); }
    assert!(PUBLIC.contains("static PINNED_PUBLIC_KEY"));
    for forbidden in ["PRIVATE KEY", "std::env", "std::fs", "http", "include_bytes!"] { assert!(!PUBLIC.contains(forbidden)); }
}

#[test]
fn actual_native_and_owner_wiring_retains_originals_and_never_promotes_failure() {
    for module in ["output_origin_capsule_data", "output_origin_capsule_public_key", "output_origin_capsule"] {
        assert!(LIB.contains(&format!("#[cfg(all(test, feature = \"desktop-ui\"))]\nmod {module};")));
    }
    assert_eq!(NATIVE.matches("BC::BCrypt").count(), 5);
    for call in ["BCryptOpenAlgorithmProvider", "BCryptImportKeyPair", "BCryptEncrypt", "BCryptDestroyKey", "BCryptCloseAlgorithmProvider"] {
        assert_eq!(NATIVE.matches(&format!("BC::{call}(")).count(), 1);
    }
    for fixed in ["BC::MS_PRIMITIVE_PROVIDER, 0", "BC::BCRYPT_RSAPUBLIC_BLOB", "data::PUBLIC_BLOB_BYTES as u32, 0",
        "pszAlgId: BC::BCRYPT_SHA256_ALGORITHM", "pbLabel: null_mut(), cbLabel: 0",
        "data::CIPHERTEXT_BYTES as u32", "BC::BCRYPT_PAD_OAEP", "value.active = Some(phase)",
        "value.returns[index] = Some(status)", "value.key_order.close_return(status)",
        "value.algorithm_order.close_return(status)", "std::hint::black_box((&mut original, &mut *capture))"] {
        assert!(NATIVE.contains(fixed));
    }
    ordered(NATIVE, &["let mut original = std::pin::pin!(Original::new(public))", "data::seal_once(",
        "original.as_ref().get_ref().settled()", "std::hint::black_box((&mut original, &mut *capture))", "clear_private(capture); reply"]);
    for forbidden in ["BCryptGenRandom", "BCryptGenerateKeyPair", "std::fs", "std::env", "unreachable!", "CreateThread", "println!", "eprintln!"] {
        assert!(!NATIVE.contains(forbidden));
    }
    let inventory = between(OWNER, "fn output_poststate(", "// BEGIN OUTPUT SOURCE RELATION ADAPTER");
    ordered(inventory, &["observer_journal_poststate(native, &entries[at].0, diagnostic, false, read_trace)?",
        "capture.origin.journal_returned(observed)", "projection = Some(observed)",
        "children.iter().find(|(p, name, _, _)| *p == index && *name == entry.name).ok_or(Error::Unsafe).map_err(|error|",
        "observer_output_origin_refused(role, position, capture.binding.as_ref()",
        "&entry, &mut capture.origin)", "error", "need(seen == expected)", "fixture.verified = true",
        "capture.projection = projection"]);
    let adapter = between(OWNER, "// BEGIN OUTPUT ORIGIN CAPSULE ADAPTER", "// END OUTPUT ORIGIN CAPSULE ADAPTER");
    for forbidden in ["native.", "open_child(", "next_entries(", "UserDataFolder(", "read_next(", "to_lowercase(", "to_owned(", ".clone("] {
        assert!(!adapter.contains(forbidden));
    }
    assert!(adapter.contains("role != UiRole::ProjectDraft || position != 0 || entry.kind != FileKind::Directory"));
    assert!(adapter.contains("original != Err(Error::Unsafe) || capture.unresolved || !capture.origin.selected()"));
    assert!(adapter.contains("original // Neither crypto nor delivery"));
    let run = between(OWNER, "pub(super) fn run(", "fn run_prerequisite_traced(");
    ordered(run, &["run_prerequisite_traced(", "observer_capture_frame(role, &capture", "prerequisite_sink(",
        "observer_output_origin_returned(role, original, &mut capture", "crate::output_origin_capsule::seal(private",
        "clock.permitted(true)", "return original"]);
    assert!(OWNER.contains("observer_output_origin_capsule_contract()?;"));
    assert!(!DATA.contains("derive(Debug)") && !DATA.contains("format!(\"{leaf"));
}
