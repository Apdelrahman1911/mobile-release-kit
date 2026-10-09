//! This group calls the actual linked canonical C library. It is not a pure
//! source test, an actual entropy-failure fixture, or parent-process finality.
//! Run only under separately admitted Mac controls, with --test-threads=1.
use super::*;
use std::io::Cursor;

#[test]
fn canonical_return_paths_wipe_input_and_refuse_low_order_key() {
    establish_policy().expect("fixed child policy");
    // RFC7748 Alice public key: public DATA, not an application credential.
    const PUBLIC: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    ];
    for size in [0usize, 3, protocol::MAX_PLAINTEXT] {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"MRKSEAL1");
        wire.extend_from_slice(&(size as u32).to_be_bytes());
        wire.extend_from_slice(&PUBLIC);
        wire.resize(REQUEST_HEADER + size, 0x5a);
        let mut input = Wiped::<INPUT_STORAGE>::allocate().unwrap();
        let mut output = Wiped::<MAX_CIPHERTEXT>::allocate().unwrap();
        let request = protocol::read_request(&mut Cursor::new(wire), &mut input.bytes).unwrap();
        seal_captured(&mut input, request, &mut output).unwrap();
        assert!(input.wiped && input.bytes.iter().all(|byte| *byte == 0));
        assert!(output.bytes[..32].iter().any(|byte| *byte != 0));
        assert!(output.bytes[request.ciphertext_bytes()..].iter().all(|byte| *byte == 0));
        let mut framed = Vec::new();
        protocol::write_response(&mut framed, request, &output.bytes[..request.ciphertext_bytes()]).unwrap();
        assert_eq!(framed.len(), 12 + size + 48);
        output.wipe();
        assert!(output.bytes.iter().all(|byte| *byte == 0));
    }

    let mut wire = Vec::new();
    wire.extend_from_slice(b"MRKSEAL1");
    wire.extend_from_slice(&3u32.to_be_bytes());
    wire.extend_from_slice(&[0u8; 32]); // canonical low-order rejection, no local blacklist
    wire.extend_from_slice(&[0, 0xff, 0x80]);
    let mut input = Wiped::<INPUT_STORAGE>::allocate().unwrap();
    let mut output = Wiped::<MAX_CIPHERTEXT>::allocate().unwrap();
    let request = protocol::read_request(&mut Cursor::new(wire), &mut input.bytes).unwrap();
    assert_eq!(seal_captured(&mut input, request, &mut output), Err(Failure::Seal));
    assert!(input.wiped && input.bytes.iter().all(|byte| *byte == 0));
    assert!(output.wiped && output.bytes.iter().all(|byte| *byte == 0));

    // Explicitly DATA-only first-error assertion using the production reducer.
    // It does not synthesize an actual failing canonical close.
    let mut failure = Some(Failure::Seal);
    first(&mut failure, Err(Failure::RandomClose));
    assert_eq!(failure, Some(Failure::Seal));
}
