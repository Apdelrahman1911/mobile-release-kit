//! Synthetic unit glue tests only. They do not qualify libsodium interoperability,
//! live GitHub behavior, native loans, final GO, transport, or memory erasure.

use super::*;
use crypto_box::SecretKey;
use std::cell::Cell;

std::thread_local! {
    static CRYPTO_CALLS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

pub(super) fn record_rng_construction() {
    CRYPTO_CALLS.with(|calls| {
        let (rng, seal) = calls.get();
        calls.set((rng + 1, seal));
    });
}

pub(super) fn record_seal_call() {
    CRYPTO_CALLS.with(|calls| {
        let (rng, seal) = calls.get();
        calls.set((rng, seal + 1));
    });
}

fn crypto_calls() -> (usize, usize) {
    CRYPTO_CALLS.with(Cell::get)
}

fn fixture_secret() -> SecretKey {
    SecretKey::from_bytes([0x35; 32])
}

fn ascii_base64(bytes: &[u8]) -> String {
    let mut encoded = vec![0u8; ((bytes.len() + 2) / 3) * 4];
    let written = STANDARD
        .encode_slice(bytes, &mut encoded)
        .unwrap_or_else(|_| panic!("synthetic Base64 encoding failed"));
    assert_eq!(written, encoded.len());
    String::from_utf8(encoded)
        .unwrap_or_else(|_| panic!("synthetic Base64 was not ASCII"))
}

fn fixture_public_key() -> String {
    ascii_base64(fixture_secret().public_key().as_bytes())
}

fn seeded_body(envelope: &[u8], key_id: &str, seed_byte: u8) -> SealedBody {
    seal_with_entropy(envelope, &fixture_public_key(), key_id, |seed| {
        seed.fill(seed_byte);
        Ok(())
    })
    .unwrap_or_else(|_| panic!("synthetic sealing failed"))
}

fn body_fields(sealed: SealedBody) -> (String, String, usize) {
    sealed.with_transport_body(|bytes| {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .unwrap_or_else(|_| panic!("synthetic body was not JSON"));
        let fields = value.as_object()
            .unwrap_or_else(|| panic!("synthetic body was not an object"));
        assert_eq!(fields.len(), 2);
        let encrypted = fields.get("encrypted_value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("encrypted_value missing"));
        let key_id = fields.get("key_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("key_id missing"));
        let compact = format!(
            "{{\"encrypted_value\":\"{}\",\"key_id\":\"{}\"}}",
            encrypted, key_id,
        );
        assert_eq!(bytes, compact.as_bytes());
        (encrypted.to_owned(), key_id.to_owned(), bytes.len())
    })
}

fn decode_ciphertext(encoded: &str) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; (encoded.len() / 4) * 3]);
    let count = STANDARD.decode_slice(encoded.as_bytes(), bytes.as_mut_slice())
        .unwrap_or_else(|_| panic!("synthetic ciphertext Base64 failed"));
    bytes.truncate(count);
    assert_eq!(ascii_base64(bytes.as_slice()), encoded);
    bytes
}

fn open_fixture(encoded: &str) -> Zeroizing<Vec<u8>> {
    let ciphertext = decode_ciphertext(encoded);
    Zeroizing::new(
        fixture_secret().unseal(ciphertext.as_slice())
            .unwrap_or_else(|_| panic!("same-library synthetic open failed")),
    )
}

fn assert_rejected_before_entropy(
    envelope: &[u8],
    public_key: &str,
    key_id: &str,
    expected: Error,
) {
    let entropy_calls = Cell::new(0usize);
    let before = crypto_calls();
    let result = seal_with_entropy(envelope, public_key, key_id, |_seed| {
        entropy_calls.set(entropy_calls.get() + 1);
        Err(Error::Random)
    });
    match result {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("invalid synthetic input was accepted"),
    }
    assert_eq!(entropy_calls.get(), 0);
    assert_eq!(crypto_calls(), before);
}

#[test]
fn preserves_original_utf8_order_whitespace_and_escape_bytes() {
    // Deliberately not normalized. Full group validation belongs to the caller.
    let original = r#" { "values":{"example":"é\u0061🙂"}, "kind":"synthetic", "protocol":"mrk-github-input-group/1" } "#;
    let (encoded, key_id, _) = body_fields(seeded_body(original.as_bytes(), "key-1", 0x19));
    assert_eq!(key_id, "key-1");
    assert_eq!(open_fixture(&encoded).as_slice(), original.as_bytes());
}

#[test]
fn accepts_one_byte_at_defensive_minimum_without_parsing_json() {
    let (encoded, _, _) = body_fields(seeded_body(b"x", "K", 0x21));
    assert_eq!(decode_ciphertext(&encoded).len(), 49);
    assert_eq!(open_fixture(&encoded).as_slice(), b"x");
}

#[test]
fn rejects_empty_envelope_before_entropy() {
    assert_rejected_before_entropy(b"", &fixture_public_key(), "K", Error::Envelope);
}

#[test]
fn rejects_invalid_utf8_before_entropy() {
    let samples: [&[u8]; 4] = [&[0xff], &[0xc0, 0x80], &[0xed, 0xa0, 0x80], &[0xe2, 0x82]];
    for sample in samples {
        assert_rejected_before_entropy(sample, &fixture_public_key(), "K", Error::Envelope);
    }
}

#[test]
fn rejects_48001_bytes_before_entropy() {
    let original = vec![b'a'; 48_001];
    assert_rejected_before_entropy(&original, &fixture_public_key(), "K", Error::Size);
}

#[test]
fn measures_utf8_bytes_instead_of_characters() {
    let original = "é".repeat(24_001);
    assert_eq!(original.chars().count(), 24_001);
    assert_eq!(original.len(), 48_002);
    assert_rejected_before_entropy(original.as_bytes(), &fixture_public_key(), "K", Error::Size);
}

#[test]
fn accepts_48000_utf8_bytes_with_exact_maximum_body() {
    let original = "é".repeat(24_000);
    let id = "K".repeat(128);
    let sealed = seeded_body(original.as_bytes(), &id, 0x22);
    assert!(sealed.retained_capacity() <= MAX_PUT_BODY_BYTES);
    let (encoded, observed_id, body_bytes) = body_fields(sealed);
    assert_eq!(original.len(), 48_000);
    assert_eq!(encoded.len(), 64_064);
    assert_eq!(decode_ciphertext(&encoded).len(), 48_048);
    assert_eq!(body_bytes, 64_226);
    assert_eq!(observed_id, id);
    assert_eq!(open_fixture(&encoded).as_slice(), original.as_bytes());
}

#[test]
fn rejects_noncanonical_recipient_text_before_entropy() {
    let good = fixture_public_key();
    let mut variants = vec![
        String::new(),
        "AQ==".to_owned(),
        good[..43].to_owned(),
        format!("{}=", good),
        format!("{}\n", good),
    ];
    for replacement in [" ", "\t", "\r", "\n", "-", "_", "="] {
        let mut changed = good.clone();
        changed.replace_range(0..1, replacement);
        variants.push(changed);
    }
    let mut non_ascii = good.clone();
    non_ascii.replace_range(0..2, "é");
    assert_eq!(non_ascii.len(), 44);
    variants.push(non_ascii);
    for key in variants {
        assert_rejected_before_entropy(b"x", &key, "K", Error::PublicKey);
    }
}

#[test]
fn rejects_nonzero_base64_trailing_bits_before_entropy() {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bad = fixture_public_key().into_bytes();
    assert_eq!(bad[43], b'=');
    let value = ALPHABET.iter().position(|byte| *byte == bad[42])
        .unwrap_or_else(|| panic!("synthetic key digit missing"));
    assert_eq!(value & 3, 0);
    bad[42] = ALPHABET[value | 1];
    let bad = String::from_utf8(bad)
        .unwrap_or_else(|_| panic!("synthetic key was not ASCII"));
    assert_rejected_before_entropy(b"x", &bad, "K", Error::PublicKey);
}

#[test]
fn rejects_31_and_33_decoded_bytes_even_with_44_text_bytes() {
    for bytes in [vec![0x35; 31], vec![0x35; 33]] {
        let encoded = ascii_base64(&bytes);
        assert_eq!(encoded.len(), 44);
        assert_rejected_before_entropy(b"x", &encoded, "K", Error::PublicKey);
    }
}

#[test]
fn rejects_low_order_and_noncanonical_field_aliases_before_entropy() {
    let zero = [0u8; 32];
    let mut one = zero;
    one[0] = 1;
    let mut p_minus_one = [0xff; 32];
    p_minus_one[0] = 0xec;
    p_minus_one[31] = 0x7f;
    let mut modulus = p_minus_one;
    modulus[0] = 0xed;
    let mut p_plus_one = modulus;
    p_plus_one[0] = 0xee;
    let mut high_bit_zero = zero;
    high_bit_zero[31] = 0x80;
    let mut high_bit_one = one;
    high_bit_one[31] = 0x80;
    for key in [zero, one, p_minus_one, modulus, p_plus_one, high_bit_zero, high_bit_one] {
        assert_rejected_before_entropy(b"x", &ascii_base64(&key), "K", Error::PublicKey);
    }
}

#[test]
fn rejects_invalid_key_id_before_entropy() {
    for id in [
        "", " ", " leading", "trailing ", "has space", "has\tcontrol",
        "has\nnewline", "has\rreturn", "has\"quote", "has\\slash",
        "\0", "\u{1f}", "\u{7f}", "é",
    ] {
        assert_rejected_before_entropy(b"x", &fixture_public_key(), id, Error::KeyId);
    }
    let long_id = "K".repeat(129);
    assert_rejected_before_entropy(b"x", &fixture_public_key(), &long_id, Error::KeyId);
}

#[test]
fn preserves_every_allowed_graphic_ascii_key_id_byte() {
    let id: String = (b'!'..=b'~')
        .filter(|byte| *byte != b'"' && *byte != b'\\')
        .map(char::from)
        .collect();
    let (_, observed_id, _) = body_fields(seeded_body(b"x", &id, 0x23));
    assert_eq!(observed_id, id);
}

#[test]
fn partial_entropy_failure_does_not_construct_rng_or_seal() {
    let entropy_calls = Cell::new(0usize);
    let before = crypto_calls();
    let result = seal_with_entropy(b"x", &fixture_public_key(), "K", |seed| {
        entropy_calls.set(entropy_calls.get() + 1);
        seed[..16].fill(0xa5);
        Err(Error::Random)
    });
    assert!(matches!(result, Err(Error::Random)));
    assert_eq!(entropy_calls.get(), 1);
    assert_eq!(crypto_calls(), before);
}

#[test]
fn all_zero_successful_entropy_stops_without_retry() {
    let entropy_calls = Cell::new(0usize);
    let before = crypto_calls();
    let result = seal_with_entropy(b"x", &fixture_public_key(), "K", |seed| {
        entropy_calls.set(entropy_calls.get() + 1);
        seed.fill(0);
        Ok(())
    });
    assert!(matches!(result, Err(Error::Random)));
    assert_eq!(entropy_calls.get(), 1);
    assert_eq!(crypto_calls(), before);
}

#[test]
fn one_nonzero_seed_constructs_one_rng_and_calls_seal_once() {
    let entropy_calls = Cell::new(0usize);
    let before = crypto_calls();
    let result = seal_with_entropy(b"x", &fixture_public_key(), "K", |seed| {
        entropy_calls.set(entropy_calls.get() + 1);
        seed.fill(0x24);
        Ok(())
    });
    let sealed = result.unwrap_or_else(|_| panic!("synthetic sealing failed"));
    assert_eq!(entropy_calls.get(), 1);
    assert_eq!(crypto_calls(), (before.0 + 1, before.1 + 1));
    let (encoded, _, _) = body_fields(sealed);
    assert_eq!(open_fixture(&encoded).as_slice(), b"x");
}

#[test]
fn deterministic_seed_injection_is_test_only_and_reproducible() {
    let (first, _, _) = body_fields(seeded_body(b"synthetic", "K", 0x25));
    let (second, _, _) = body_fields(seeded_body(b"synthetic", "K", 0x25));
    assert_eq!(first, second);
}

#[test]
fn different_injected_seeds_change_ephemeral_ciphertext() {
    let (first, _, _) = body_fields(seeded_body(b"synthetic", "K", 0x26));
    let (second, _, _) = body_fields(seeded_body(b"synthetic", "K", 0x27));
    assert_ne!(first, second);
}

#[test]
fn same_library_open_rejects_wrong_recipient() {
    let (encoded, _, _) = body_fields(seeded_body(b"synthetic", "K", 0x28));
    let ciphertext = decode_ciphertext(&encoded);
    let wrong = SecretKey::from_bytes([0x72; 32]);
    assert!(wrong.unseal(ciphertext.as_slice()).is_err());
}

#[test]
fn same_library_open_rejects_tampered_ciphertext() {
    let (encoded, _, _) = body_fields(seeded_body(b"synthetic", "K", 0x29));
    let mut ciphertext = decode_ciphertext(&encoded);
    match ciphertext.last_mut() {
        Some(byte) => *byte ^= 1,
        None => panic!("synthetic ciphertext missing"),
    }
    assert!(fixture_secret().unseal(ciphertext.as_slice()).is_err());
}

#[test]
fn padding_and_exact_seal_overhead_follow_original_byte_length() {
    for (size, encoded_bytes, padding) in [(1, 68, 2), (2, 68, 1), (3, 68, 0), (4, 72, 2)] {
        let original = vec![b'x'; size];
        let (encoded, _, _) = body_fields(seeded_body(&original, "K", 0x30));
        assert_eq!(decode_ciphertext(&encoded).len(), size + 48);
        assert_eq!(encoded.len(), encoded_bytes);
        assert_eq!(encoded.bytes().rev().take_while(|byte| *byte == b'=').count(), padding);
        assert_eq!(open_fixture(&encoded).as_slice(), original.as_slice());
    }
}

#[test]
fn checked_size_limits_reject_extreme_values() {
    let maximum = Lengths::new(48_000, 128)
        .unwrap_or_else(|_| panic!("synthetic maximum lengths failed"));
    assert_eq!((maximum.ciphertext, maximum.encoded, maximum.body), (48_048, 64_064, 64_226));
    for (envelope, id) in [(0, 1), (48_001, 1), (usize::MAX, 1), (1, 0), (1, 129), (1, usize::MAX)] {
        assert!(matches!(Lengths::new(envelope, id), Err(Error::Size)));
    }
    assert!(matches!(reserve_body(MAX_PUT_BODY_BYTES + 1), Err(Error::Size)));
    assert!(matches!(reserve_body(usize::MAX), Err(Error::Size)));
}

#[test]
fn retained_capacity_reports_actual_private_vec_capacity() {
    let sealed = seeded_body(b"synthetic", "K", 0x31);
    assert_eq!(sealed.retained_capacity(), sealed.bytes.capacity());
    assert!(sealed.retained_capacity() >= sealed.bytes.len());
    assert!(sealed.retained_capacity() <= MAX_PUT_BODY_BYTES);
}

#[test]
fn consuming_transport_callback_runs_once_and_may_refuse() {
    let sealed = seeded_body(b"synthetic", "K", 0x32);
    let callbacks = Cell::new(0usize);
    let result: Result<(), &'static str> = sealed.with_transport_body(|bytes| {
        callbacks.set(callbacks.get() + 1);
        assert!(!bytes.is_empty() && bytes.len() <= MAX_PUT_BODY_BYTES);
        Err("synthetic final-owner refusal")
    });
    assert_eq!(callbacks.get(), 1);
    assert_eq!(result, Err("synthetic final-owner refusal"));
}

#[test]
fn bounded_append_rejects_overflow_without_partial_write() {
    let mut bytes = [0xa5u8; 4];
    let before = bytes;
    let mut cursor = 3usize;
    assert_eq!(append_bytes(&mut bytes, &mut cursor, b"xx"), Err(Error::Size));
    assert_eq!(cursor, 3);
    assert_eq!(bytes, before);
    cursor = usize::MAX;
    assert_eq!(append_bytes(&mut bytes, &mut cursor, b"x"), Err(Error::Size));
    assert_eq!(cursor, usize::MAX);
    assert_eq!(bytes, before);
}
