use super::*;
use std::io::Cursor;

fn frame(declared: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MRKSEAL1");
    bytes.extend_from_slice(&declared.to_be_bytes());
    bytes.extend(0u8..32u8); // public, non-cryptographic framing fixture
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn fixed_request_and_response_frames_are_exact_and_bounded() {
    assert_eq!((MAX_INPUT_FRAME, MAX_OUTPUT_FRAME, INPUT_STORAGE), (49_196, 49_212, 49_197));
    assert_eq!((PUBLIC_KEY_BYTES, SEAL_BYTES), (32, 48));
    for size in [0usize, 1, 4, MAX_PLAINTEXT] {
        let plain: Vec<u8> = (0..size).map(|i| ((i * 37) & 255) as u8).collect();
        let wire = frame(size as u32, &plain);
        let mut original = Cursor::new(wire.as_slice());
        let mut storage = [0u8; INPUT_STORAGE];
        let request = read_request(&mut original, &mut storage).unwrap();
        assert_eq!(request.plaintext_bytes(), size);
        assert_eq!(request.ciphertext_bytes(), size + 48);
        assert_eq!(original.position() as usize, wire.len());
        assert_eq!(&storage[REQUEST_HEADER..REQUEST_HEADER + size], plain.as_slice());
        let key: Vec<u8> = (0u8..32).collect();
        assert_eq!(&storage[REQUEST_PREFIX..REQUEST_HEADER], key.as_slice());

        // These bytes are DATA, not ciphertext or a simulated sodium success.
        let ciphertext = vec![0x5a; size + 48];
        let mut response = Vec::new();
        write_response(&mut response, request, &ciphertext).unwrap();
        assert_eq!(&response[..8], b"MRKBOX01");
        assert_eq!(&response[8..12], &((size + 48) as u32).to_be_bytes());
        assert_eq!(&response[12..], ciphertext.as_slice());
        assert_eq!(response.len(), 12 + size + 48);
    }
}

struct AtEndInterrupted {
    original: Cursor<Vec<u8>>,
    interrupted: bool,
}
impl Read for AtEndInterrupted {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.original.position() as usize == self.original.get_ref().len() && !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.original.read(bytes)
    }
}

struct ReadFailure;
impl Read for ReadFailure {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Other))
    }
}

#[test]
fn fixed_request_refuses_truncation_trailing_and_oversize_before_body() {
    let mut storage = [0u8; INPUT_STORAGE];
    let complete = frame(3, &[0x00, 0xff, 0x80]);
    for length in 0..complete.len() {
        let mut original = Cursor::new(&complete[..length]);
        assert_eq!(read_request(&mut original, &mut storage), Err(Refusal::Truncated));
    }
    let mut wrong = complete.clone();
    wrong[7] = b'2';
    assert_eq!(read_request(&mut Cursor::new(wrong), &mut storage), Err(Refusal::Header));
    for size in [MAX_PLAINTEXT as u32 + 1, u32::MAX] {
        let oversized = frame(size, &[0x7f; 8]);
        let mut original = Cursor::new(oversized);
        assert_eq!(read_request(&mut original, &mut storage), Err(Refusal::InputLimit));
        assert_eq!(original.position(), REQUEST_HEADER as u64); // no body read
    }
    let mut trailing = complete.clone();
    trailing.extend_from_slice(&[0x91, 0x92]);
    let mut original = Cursor::new(trailing);
    assert_eq!(read_request(&mut original, &mut storage), Err(Refusal::Trailing));
    assert_eq!(original.position() as usize, complete.len() + 1);
    assert_eq!(storage[complete.len()], 0x91); // inside the SAME full wipe buffer
    assert_eq!(read_request(&mut ReadFailure, &mut storage), Err(Refusal::Read));
    let mut interrupted = AtEndInterrupted { original: Cursor::new(complete), interrupted: false };
    assert_eq!(read_request(&mut interrupted, &mut storage).unwrap().plaintext_bytes(), 3);
    assert!(interrupted.interrupted);
}

struct FailAfter { bytes: Vec<u8>, allowance: usize, calls: usize }
impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.allowance == 0 { return Err(io::Error::from(io::ErrorKind::Other)); }
        let count = self.allowance.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        self.allowance -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
struct WriteZero;
impl Write for WriteZero {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { Ok(0) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn fixed_response_rejects_wrong_length_and_preserves_write_failure() {
    let mut storage = [0u8; INPUT_STORAGE];
    let request = read_request(&mut Cursor::new(frame(3, &[0, 1, 2])), &mut storage).unwrap();
    for size in [0, 48, 50, 52, MAX_CIPHERTEXT + 1] {
        let mut output = FailAfter { bytes: Vec::new(), allowance: usize::MAX, calls: 0 };
        assert_eq!(write_response(&mut output, request, &vec![0x5a; size]), Err(Refusal::OutputLength));
        assert_eq!(output.calls, 0);
        assert!(output.bytes.is_empty());
    }
    let mut output = FailAfter { bytes: Vec::new(), allowance: 15, calls: 0 };
    assert_eq!(write_response(&mut output, request, &[0x5a; 51]), Err(Refusal::Write));
    assert_eq!(output.bytes.len(), 15);
    assert_eq!(&output.bytes[..8], b"MRKBOX01");
    assert_eq!(&output.bytes[12..], &[0x5a; 3]);
    assert_eq!(write_response(&mut WriteZero, request, &[0x5a; 51]), Err(Refusal::Write));
    // A partial output is never an accepted helper original or retry grant.
}
