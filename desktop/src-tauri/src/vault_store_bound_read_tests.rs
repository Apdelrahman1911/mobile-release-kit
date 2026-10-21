//! The same real bound predicates and read owner on macOS and Linux.
//! Inert DATA only: no file, credential or native success is manufactured.
use super::*;

fn id(byte: u8) -> Id { Id::from_bytes([byte; 16]).unwrap() }

#[test]
fn stored_record_read_checks_original_witness_and_allowance_before_body() {
    // Inert comparison DATA: no large allocation or native file is needed
    // to prove that a new prefix cannot enlarge the admitted read.
    let length = 1024;
    let control = crate::vault_crypto::CONTROL_BYTES;
    let allowance = control + length;
    let revision = format::Revision::new(id(7), 1).unwrap();
    let mut witness = ReadWitness::lifecycle_data(id(8), revision);
    witness.file.bytes = length as u64;
    let bound = fixed_record_read_bound(FixedRecordRead::Stored(&witness), witness, length, allowance).unwrap();
    assert!(bound.before(Some(witness.root), witness.file, witness.record.record_name().as_bytes(), length, true).is_ok());
    assert!(bound.capacity(length).is_ok());
    assert!(bound.capacity(length + 1).is_err());
    for (requested, available) in [
        (format::RECORD_LIMIT, allowance), (length + 1, allowance),
        (length, allowance - 1), (length, control - 1),
        (length, format::WORKING_BYTES + 1), (usize::MAX, format::WORKING_BYTES),
    ] { assert!(ordinary_record_read_limit(requested, available).is_err()); }
    // The original remaining24MiB Load budget cannot accept a generic32MiB
    // body. This is an example of an existing allowance, not a new global cap.
    let remaining = 24 * 1024 * 1024;
    assert!(ordinary_record_read_limit(format::RECORD_LIMIT, remaining).is_err());
    assert!(ordinary_record_read_limit(remaining - control, remaining).is_ok());
    // Ordinary record capacity is not confused with Apple's key ceiling.
    assert!(ordinary_record_read_limit(format::RECORD_LIMIT, format::WORKING_BYTES).is_ok());
    assert!(apple_key_read_limit(length, format::WORKING_BYTES).is_err());
    for change in 0..7 {
        let mut changed = witness;
        match change {
            0 => changed.root.ino += 1,
            1 => changed.file.common.ino += 1,
            2 => changed.file.ctime.1 += 1,
            3 => changed.file.mtime.1 += 1,
            4 => changed.file.bytes += 1,
            5 => changed.record = id(9),
            _ => changed.revision = format::Revision::new(id(10), 2).unwrap(),
        }
        assert!(fixed_record_read_bound(FixedRecordRead::Stored(&witness), changed,
            changed.file.bytes as usize, format::WORKING_BYTES).is_err());
    }
    let mut renamed = witness.file; renamed.common.ino += 1;
    assert!(bound.before(Some(witness.root), renamed, witness.record.record_name().as_bytes(), length, true).is_err());
    assert!(bound.before(None, witness.file, witness.record.record_name().as_bytes(), length, true).is_err());
    assert!(bound.before(Some(witness.root), witness.file, id(9).record_name().as_bytes(), length, true).is_err());
    assert!(bound.before(Some(witness.root), witness.file, witness.record.record_name().as_bytes(), length, false).is_err());
}
#[test]
fn new_record_read_matches_reserved_intent_and_exact_sealed_length() {
    let length = 1024;
    let allowance = crate::vault_crypto::CONTROL_BYTES + length;
    let revision = format::Revision::new(id(7), 1).unwrap();
    let mut witness = ReadWitness::lifecycle_data(id(8), revision);
    witness.file.bytes = length as u64;
    let expected = || FixedRecordRead::New { record: witness.record, revision, length };
    assert!(fixed_record_read_bound(expected(), witness, length, allowance).is_ok());
    let mut grown = witness; grown.file.bytes += 1;
    // Even abundant available memory cannot authorize a different NEW.
    assert!(fixed_record_read_bound(expected(), grown, length + 1, format::WORKING_BYTES).is_err());
    let mut changed = witness; changed.record = id(9);
    assert!(fixed_record_read_bound(expected(), changed, length, allowance).is_err());
    changed = witness; changed.revision = format::Revision::new(id(10), 2).unwrap();
    assert!(fixed_record_read_bound(expected(), changed, length, allowance).is_err());
    assert!(fixed_record_read_bound(expected(), witness, length, allowance - 1).is_err());
    let identity = format::Identity::new(id(1), id(2)).unwrap();
    let new = format::IntentPrefix::new(identity, Mutation::New, id(3), witness.record,
        None, Some(revision), [5; 32], length).unwrap();
    assert!(new_record_read_intent(&new, witness.record, revision, length));
    assert!(!new_record_read_intent(&new, witness.record, revision, length + 1));
    assert!(!new_record_read_intent(&new, id(9), revision, length));
    assert!(!new_record_read_intent(&new, witness.record, changed.revision, length));
    let replace = format::IntentPrefix::new(identity, Mutation::Replace, id(3), witness.record,
        Some(revision), Some(changed.revision), [5; 32], length).unwrap();
    assert!(!new_record_read_intent(&replace, witness.record, changed.revision, length));
    // The actual entry refuses a book without a successful NEW before IO.
    let mut book = StoreBook::new();
    assert!(matches!(book.read_new_bound_record(witness.record, revision, length, allowance,
        &mut || false), Err(Problem::State)));
    assert!(book.originals.is_empty() && book.storage_outcome().is_none());
}
#[test]
fn read_refusal_and_stop_never_erase_already_known_new_effect() {
    for stopped in [false, true] {
        // Synthetic mutation-state DATA only. No vault, key or native
        // mutation exists; exercise the real StoreBook read finish path.
        let mut progress = MutationProgress::new(Mutation::New);
        progress.begin_intent().unwrap();
        progress.intent_durable_returned().unwrap();
        progress.enter_effect().unwrap();
        progress.applied_returned().unwrap();
        progress.enter_effect_sync().unwrap();
        progress.effect_sync_returned(true).unwrap();
        progress.enter_clear(true).unwrap();
        progress.clear_sync_returned(true).unwrap();
        progress.cleanup_returned(true);
        assert!(progress.success());
        let outcome = progress.outcome;
        let mut book = StoreBook::new(); book.mutation = Some(progress);
        let result = book.work(Work::ReadRecord, &mut || stopped,
            |_, _| ordinary_record_read_limit(format::RECORD_LIMIT, crate::vault_crypto::CONTROL_BYTES + 1024));
        assert_eq!(result, Err(if stopped { Problem::Stopped } else { Problem::Bounds }));
        assert_eq!(book.storage_outcome(), Some(outcome));
        assert_eq!(outcome, StorageOutcome { effect: Effect::KnownApplied,
            durability: Durability::Confirmed, cleanup: Cleanup::Known });
        assert!(book.in_flight.is_none() && book.originals.is_empty());
        assert!(!book.mutation.as_ref().unwrap().success());
        assert!(book.begin(Work::Mutate).is_err()); // No automatic NEW retry.
    }
}
