//! Real anonymous pipes around the production client, with fictional wire DATA.
//! No helper, installed image, native admission, Keychain, document, grant or
//! success receipt is created. These tests do not qualify those boundaries.
use super::*;
use nix::errno::Errno;

fn nonblocking(fd: &OwnedFd) {
    let flags = OFlag::from_bits(fcntl(fd, FcntlArg::F_GETFL).unwrap()).unwrap();
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
}

fn request() -> RequestEnvelope {
    RequestEnvelope::Vault(Request {
        operation: wire::Operation::Initialize,
        nonce: [1; 16], vault: [2; 16], generation: [3; 16],
        work: 11, maximum_cleanup: 12, initial_key: Zeroizing::new([0x53; 32]),
    })
}

fn book() -> LookupBook {
    let mut book = LookupBook::new();
    // Deliberately no slots, child, charge or native receipt. The fixture owns
    // only an encoded request and real pipe ends; it cannot grant helper use.
    book.entered = true;
    book.work = Some(Instant::now() + Duration::from_secs(10));
    book.cleanup = Some(Instant::now() + Duration::from_secs(12));
    book.request = Some(request());
    assert!(book.request.as_ref().unwrap().encode(&mut book.request_bytes));
    book
}

fn input_pipe(book: &mut LookupBook) -> OwnedFd {
    let (read, write) = unistd::pipe().unwrap();
    nonblocking(&read);
    assert!(book.pipes[0].retain(Some(write)));
    assert!(book.pipes[0].nonblocking());
    read
}

fn output_pipe(book: &mut LookupBook, index: usize) -> OwnedFd {
    let (read, write) = unistd::pipe().unwrap();
    nonblocking(&write);
    assert!(book.pipes[index].retain(Some(read)));
    assert!(book.pipes[index].nonblocking());
    write
}

fn sent_book() -> LookupBook {
    let mut book = book();
    let read = input_pipe(&mut book);
    book.go = true;
    book.write_control();
    let mut observed = Zeroizing::new([0; wire::REQUEST_BYTES]);
    assert_eq!(unistd::read(&read, &mut observed[..]), Ok(wire::REQUEST_BYTES));
    assert!(Request::decode(&observed[..]).is_some());
    assert!(book.write_attempted && book.request_sent);
    book
}

fn close(book: &mut LookupBook) {
    // Explicit close of only fixture-created retained originals, even on
    // refusal. LookupBook intentionally does not invent Drop close receipts.
    for pipe in &mut book.pipes { assert!(pipe.close()); }
    assert!(book.pipes.iter().all(Pipe::settled));
}

fn no_candidate(book: &mut LookupBook) {
    assert!(book.candidate.is_none());
    assert!(!book.resources_settled());
    assert!(book.consume_settled_key(|_| panic!("fixture cannot grant a vault key")).is_err());
    assert!(book.consume_settled_local(|_| panic!("fixture cannot grant a local key")).is_err());
}

#[test]
fn no_go_then_interruption_closes_input_without_sending_secret() {
    let mut book = book();
    let read = input_pipe(&mut book);
    let mut observed = [0; local::REQUEST_BYTES];
    book.write_control();
    assert_eq!(unistd::read(&read, &mut observed), Err(Errno::EAGAIN));
    assert!(!book.write_attempted && !book.request_sent);
    assert!(book.request_bytes.iter().any(|byte| *byte != 0));

    book.interrupt(); // The same retirement used after lost document/STOP.
    assert_eq!(book.problem(), Some(Problem::Interrupted));
    assert!(book.request_bytes.iter().all(|byte| *byte == 0));
    let RequestEnvelope::Vault(request) = book.request.as_ref().unwrap() else { panic!("vault DATA"); };
    assert!(request.initial_key.iter().all(|byte| *byte == 0));
    book.go = true; // Even a stale GO flag must not revive failed input.
    book.write_control();
    assert_eq!(unistd::read(&read, &mut observed), Ok(0));
    assert!(!book.write_attempted && !book.request_sent && !book.stop_attempted);
    no_candidate(&mut book);
    close(&mut book);
}

#[test]
fn go_sends_exactly_one_frame_and_wipes_both_client_secret_copies() {
    let mut book = book();
    let read = input_pipe(&mut book);
    let expected = book.request_bytes.clone();
    book.go = true; // Pipe-only DATA fixture, not claim_go/native authority.
    book.write_control();
    let mut observed = Zeroizing::new([0; local::REQUEST_BYTES]);
    assert_eq!(unistd::read(&read, &mut observed[..]), Ok(wire::REQUEST_BYTES));
    assert!(observed[..wire::REQUEST_BYTES] == expected[..wire::REQUEST_BYTES]);
    assert!(book.write_attempted && book.request_sent && book.problem().is_none());
    assert!(book.request_bytes.iter().all(|byte| *byte == 0));
    let RequestEnvelope::Vault(request) = book.request.as_ref().unwrap() else { panic!("vault DATA"); };
    assert!(request.initial_key.iter().all(|byte| *byte == 0));
    book.write_control();
    assert_eq!(unistd::read(&read, &mut observed[..]), Err(Errno::EAGAIN));
    no_candidate(&mut book);
    close(&mut book);
}

#[test]
fn full_nonblocking_input_pipe_refuses_once_closes_and_wipes_request() {
    let mut book = book();
    let read = input_pipe(&mut book);
    let mut filled = 0;
    // Saturate only this disposable pipe. Both loops are finite; a large
    // platform capacity is a fixture refusal, never an unbounded retry.
    for size in [4096, wire::REQUEST_BYTES] {
        let filler = vec![0x46; size];
        let mut full = false;
        for _ in 0..256 {
            match unistd::write(book.pipes[0].original().unwrap(), &filler) {
                Ok(n) => { assert_eq!(n, size); filled += n; }
                Err(Errno::EAGAIN) => { full = true; break; }
                other => panic!("fixture pipe fill refused: {other:?}"),
            }
        }
        assert!(full, "bounded fixture pipe capacity");
    }
    book.go = true;
    book.write_control();
    assert_eq!(book.problem(), Some(Problem::CleanupUnknown));
    assert!(book.write_attempted && !book.request_sent && book.uncertain);
    assert!(book.pipes[0].settled() && book.request_bytes.iter().all(|byte| *byte == 0));
    let RequestEnvelope::Vault(request) = book.request.as_ref().unwrap() else { panic!("vault DATA"); };
    assert!(request.initial_key.iter().all(|byte| *byte == 0));
    let first = book.problem_at();
    book.write_control();
    assert_eq!(book.problem_at(), first);
    let mut observed = [0; 4096];
    let mut remaining = filled;
    while remaining != 0 {
        let n = unistd::read(&read, &mut observed).unwrap();
        assert!(n != 0 && n <= remaining && observed[..n].iter().all(|byte| *byte == 0x46));
        remaining -= n;
    }
    assert_eq!(unistd::read(&read, &mut observed), Ok(0));
    no_candidate(&mut book);
    close(&mut book);
}

#[test]
fn stderr_secret_is_discarded_and_latches_a_closed_protocol_error() {
    let mut book = book();
    let write = output_pipe(&mut book, 2);
    let secret = b"FICTIONAL-STDERR-CREDENTIAL-DO-NOT-REFLECT";
    assert_eq!(unistd::write(&write, secret), Ok(secret.len()));
    book.read_pipes();
    assert!(book.stderr_seen);
    assert_eq!(book.problem(), Some(Problem::Protocol));
    assert_eq!(format!("{:?}", book.problem()), "Some(Protocol)");
    assert!(book.used == 0 && book.output.iter().all(|byte| *byte == 0));
    assert!(book.request_bytes.iter().all(|byte| *byte == 0));
    let first = book.problem_at();
    drop(write);
    book.read_pipes();
    assert!(book.pipes[2].eof);
    assert_eq!(book.problem_at(), first);
    no_candidate(&mut book);
    close(&mut book);
}

fn failed_terminal() -> Vec<u8> {
    // A canonical failed envelope, with no native receipts/key. Parsing this
    // positively is not proof of native/helper/process settlement.
    let mut bytes = vec![0; wire::TERMINAL_BYTES];
    bytes[..8].copy_from_slice(b"MRKVKT01");
    for (at, value) in [(8, 1u32), (12, 1), (100, 1)] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[16..32].copy_from_slice(&[1; 16]);
    bytes[32..48].copy_from_slice(&[2; 16]);
    bytes[48..64].copy_from_slice(&[3; 16]);
    for (at, value) in [(64, 11u64), (72, 12), (88, 12)] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn receive(book: &mut LookupBook, bytes: &[u8]) {
    let write = output_pipe(book, 1);
    // Interleaved bounded writes/reads avoid relying on Darwin pipe capacity.
    for chunk in bytes.chunks(1024) {
        assert_eq!(unistd::write(&write, chunk), Ok(chunk.len()));
        book.read_pipes();
    }
    drop(write);
    book.read_pipes();
}

#[test]
fn fragmented_failed_reply_is_parsed_but_cannot_release_a_key_or_refund() {
    let mut book = sent_book();
    receive(&mut book, &failed_terminal());
    assert!(book.terminal_seen && book.pipes[1].eof && !book.output_failed);
    assert_eq!(book.problem(), Some(Problem::Unavailable));
    assert!(!book.native_settled() && !book.dispose_settled_storage());
    no_candidate(&mut book);
    close(&mut book);
}

#[test]
fn reply_binding_truncation_and_trailing_data_are_refused_over_real_pipes() {
    let original = failed_terminal();
    // Version, operation, nonce, vault, generation, work/cleanup bound, reserved
    // Boolean, and candidate cell. Each mismatch is independently refused.
    for offset in [8, 12, 16, 32, 48, 64, 72, 100, wire::TERMINAL_BYTES - 1] {
        let mut bytes = original.clone(); bytes[offset] ^= 0x80;
        let mut book = sent_book();
        receive(&mut book, &bytes);
        assert_eq!(book.problem(), Some(Problem::Protocol), "binding offset {offset}");
        assert!(book.output_failed && !book.terminal_seen);
        no_candidate(&mut book);
        close(&mut book);
    }
    for length in [0, 7, wire::TERMINAL_BYTES - 1] {
        let mut book = sent_book();
        receive(&mut book, &original[..length]);
        assert_eq!(book.problem(), Some(Problem::Protocol), "truncation length {length}");
        assert!(book.output_failed && !book.terminal_seen && book.pipes[1].eof);
        no_candidate(&mut book);
        close(&mut book);
    }
    let mut bytes = original; bytes.push(1);
    let mut book = sent_book();
    receive(&mut book, &bytes);
    assert!(book.output_failed && book.terminal_seen);
    // The parsed first failure stays first when extra bytes are subsequently
    // refused; a later protocol violation does not rewrite its timestamp.
    assert_eq!(book.problem(), Some(Problem::Unavailable));
    no_candidate(&mut book);
    close(&mut book);
}

#[test]
fn late_join_after_stop_wipes_output_without_minting_a_candidate() {
    let mut book = book();
    book.output[..32].fill(0x53); book.used = 32;
    book.interrupt();
    let first = book.problem_at();
    book.driver_returned = true;
    book.driver_result = Some(Err(Problem::Interrupted));
    book.child_joined(Err(Problem::Interrupted));
    assert!(book.joined && book.output.iter().all(|byte| *byte == 0));
    assert!(book.request_bytes.iter().all(|byte| *byte == 0));
    assert_eq!(book.problem(), Some(Problem::Interrupted));
    assert_eq!(book.problem_at(), first);
    no_candidate(&mut book);
    close(&mut book);
}
