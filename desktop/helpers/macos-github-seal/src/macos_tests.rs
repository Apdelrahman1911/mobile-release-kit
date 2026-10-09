//! Actual linked canonical calls plus eight sequential public-fixture child
//! originals under the same separately admitted Mac owner and 10-second cap.
//! Build-parent evidence is NOT installed Desktop two-phase admission.
//! Run only with the admitted sibling release helper and --test-threads=1.
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

    diagnostic_data_checks();
    framed_build_parent_and_entropy_denial();
}

// Only this cfg(test) module links the two additional canonical observation/
// decryption interfaces. The production helper still declares exactly four.
unsafe extern "C" {
    fn crypto_box_seal_open(m: *mut c_uchar, c: *const c_uchar, clen: c_ulonglong,
        pk: *const c_uchar, sk: *const c_uchar) -> c_int;
    fn randombytes_implementation_name() -> *const std::ffi::c_char;
}

const DEVICE_TEST: &str = "macos::tests::canonical_entropy_device_access";
const DENIED_ENV: &str = "MRK_SEAL_TEST_ENTROPY_DENIED";
const DENIED_POLICY: &str = "(version 1)(allow default)(deny network*)(deny file-read-data (literal \"/dev/urandom\") (literal \"/dev/random\"))";
const ALICE_PUBLIC: [u8; 32] = [
    0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
    0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a,
];
// RFC7748 section6.1 published Alice private test vector, NOT a credential.
const ALICE_PRIVATE: [u8; 32] = [
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
];

#[derive(Clone, Copy)]
enum Case { Good(usize), Trailing, LowOrder, DeviceControl, DeviceDenied, EntropyDenied }
struct Capture { status: std::process::ExitStatus, output: Vec<u8>, error: Vec<u8> }

// Closed observations only. Never format bytes, paths, environment, keys or
// ciphertext, and never interpret a lexical token as an authenticated cause.
fn diagnostic_case(case: Case) -> &'static str {
    match case {
        Case::Good(0) => "good-empty",
        Case::Good(3) => "good-binary3",
        Case::Good(protocol::MAX_PLAINTEXT) => "good-max",
        Case::Good(_) => "invalid-case",
        Case::Trailing => "trailing",
        Case::LowOrder => "low-order",
        Case::DeviceControl => "device-control",
        Case::DeviceDenied => "device-denied",
        Case::EntropyDenied => "entropy-denied",
    }
}
fn diagnostic_tokens(error: &[u8]) -> u16 {
    // Actual successful capture admits at most1024. An unrelated oversized
    // DATA input remains unclassified without scanning an unbounded slice.
    if error.len() > 1024 { return 0; }
    let contains = |needle: &[u8]| error.windows(needle.len()).any(|part| part == needle);
    let line_prefix = |prefix: &[u8]| error.split(|byte| *byte == b'\n').any(|line| line.starts_with(prefix));
    let flags = [
        line_prefix(b"sandbox-exec:"),
        contains(b"sandbox_apply") || contains(b"sandbox_init"),
        contains(b"Operation not permitted"),
        contains(b"Permission denied"),
        line_prefix(b"dyld:") || line_prefix(b"dyld["),
        contains(b"Library not loaded:"),
        contains(b"Symbol not found:"),
        contains(b"panicked at"),
        contains(b"fatal runtime error:"),
        contains(b"memory allocation of"),
    ];
    let mut mask = 0u16;
    for (index, present) in flags.into_iter().enumerate() {
        if present { mask |= 1u16 << index; }
    }
    mask
}
fn diagnostic_data_checks() {
    // Synthetic diagnostic DATA only, not a sandbox/loader/runtime verdict.
    assert_eq!(diagnostic_tokens(b""), 0);
    assert_eq!(diagnostic_tokens(b"unknown /private/never-render-this\xff"), 0);
    assert_eq!(diagnostic_tokens(&[b'x'; 1025]), 0);
    assert_eq!(diagnostic_tokens(b"sandbox-exec: sandbox_apply: Operation not permitted\n"), 7);
    assert_eq!(diagnostic_tokens(b"Permission denied\ndyld[1]: Library not loaded: /private/hidden\nSymbol not found: hidden\n"), 120);
    assert_eq!(diagnostic_tokens(b"thread 'fixed' panicked at /private/hidden\nfatal runtime error: hidden\nmemory allocation of hidden\n"), 896);
    assert_eq!(diagnostic_tokens(b"prefix sandbox-exec: hidden\nprefix dyld: hidden"), 0);
    assert_eq!(diagnostic_case(Case::Good(0)), "good-empty");
    assert_eq!(diagnostic_case(Case::Good(3)), "good-binary3");
    assert_eq!(diagnostic_case(Case::Good(protocol::MAX_PLAINTEXT)), "good-max");
    assert_eq!(diagnostic_case(Case::Good(1)), "invalid-case");
}
fn report_captured(case: Case, captured: &Capture) {
    use std::os::unix::process::ExitStatusExt;
    // Called only after capture_case returned all actual parent pipe closes and
    // wait. These are not the aborting helper's internal close/wipe receipts.
    // At most8 lines, each below256 bytes. libtest hides captured output on
    // success; on failure its existing bounded transcript retains these facts.
    eprintln!("MRK_SEAL_CHILD_DIAGNOSTIC_V1 case={} code={} signal={} stdoutBytes={} stderrBytes={} tokenMask={:03x} parentPipesAndWait=returned",
        diagnostic_case(case), captured.status.code().unwrap_or(-1), captured.status.signal().unwrap_or(0),
        captured.output.len(), captured.error.len(), diagnostic_tokens(&captured.error));
}

fn pipe_original<T: IntoRawFd>(pipe: T) -> OriginalFile {
    // SAFETY: consume the one ChildStdin/Stdout/Stderr backing. This is the SAME
    // descriptor, not a duplicate or a drop-only close observation.
    OriginalFile { file: Some(unsafe { File::from_raw_fd(pipe.into_raw_fd()) }) }
}
fn note(failure: &mut Option<&'static str>, result: Result<(), &'static str>) {
    if let Err(error) = result { if failure.is_none() { *failure = Some(error); } }
}
fn stop_failed(child: &mut std::process::Child, waited: &mut Option<std::process::ExitStatus>,
    failure: &mut Option<&'static str>) {
    if failure.is_none() || waited.is_some() { return; }
    match child.try_wait() {
        Ok(Some(status)) => *waited = Some(status),
        Ok(None) => note(failure, child.kill().map_err(|_| "child-kill")),
        Err(_) => { note(failure, Err("child-wait")); let _ = child.kill(); },
    }
}
fn read_bounded(pipe: &mut OriginalFile, bytes: &mut [u8], cap: usize)
    -> Result<usize, &'static str> {
    use std::io::{ErrorKind, Read};
    // Storage was reserved before spawn, including exactly one overflow byte.
    let mut used = 0;
    loop {
        if used > cap { return Err("pipe-overflow"); }
        match pipe.original().read(&mut bytes[used..]) {
            Ok(0) => return Ok(used),
            Ok(count) => used += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err("pipe-read"),
        }
    }
}
fn fixed_buffer(cap: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(cap + 1).map_err(|_| "buffer-allocation")?;
    if bytes.capacity() > cap + 1 { return Err("buffer-capacity"); }
    bytes.resize(cap + 1, 0); Ok(bytes)
}
fn public_plaintext(size: usize) -> Vec<u8> {
    if size == 3 { vec![0, 0xff, 0x80] } else { vec![0x5a; size] }
}

// Eight fixed test cases only; no caller-visible executor or helper selector.
// The existing 10-second C/A/W original owns this entire process group, including
// blocking I/O/error cleanup. No renewed child timer, thread or process group.
fn capture_case(case: Case, current: &std::path::Path, helper: &std::path::Path)
    -> Result<Capture, &'static str> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let probe = matches!(case, Case::DeviceControl | Case::DeviceDenied);
    let denied = matches!(case, Case::DeviceDenied | Case::EntropyDenied);
    let target = if probe { current } else { helper };
    let mut command = if denied {
        let mut value = Command::new("/usr/bin/sandbox-exec");
        value.args(["-p", DENIED_POLICY]).arg(target); value
    } else { Command::new(target) };
    command.env_clear().env("LANG", "C").env("LC_ALL", "C");
    if probe {
        command.args([DEVICE_TEST, "--exact", "--test-threads=1"]);
        if denied { command.env(DENIED_ENV, "1"); }
    }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut frame = Vec::new();
    frame.try_reserve_exact(protocol::MAX_INPUT_FRAME + 1).map_err(|_| "frame-allocation")?;
    if frame.capacity() > protocol::MAX_INPUT_FRAME + 1 { return Err("frame-capacity"); }
    if !probe {
        let size = match case { Case::Good(value) => value, _ => 3 };
        let plaintext = public_plaintext(size);
        frame.extend_from_slice(b"MRKSEAL1");
        frame.extend_from_slice(&(size as u32).to_be_bytes());
        frame.extend_from_slice(if matches!(case, Case::LowOrder) { &[0u8; 32] } else { &ALICE_PUBLIC });
        frame.extend_from_slice(&plaintext);
        if matches!(case, Case::Trailing) { frame.push(0x7f); }
    }
    let output_cap = if probe { 4096 } else { protocol::MAX_OUTPUT_FRAME };
    let mut output = fixed_buffer(output_cap)?;
    let mut error = fixed_buffer(1024)?;
    let mut child = command.spawn().map_err(|_| "child-spawn")?;
    // Nothing below asserts/panics on a result while this child is unsettled.
    let mut input = child.stdin.take().map(pipe_original);
    let mut out = child.stdout.take().map(pipe_original);
    let mut err = child.stderr.take().map(pipe_original);
    let mut failure = None; let mut waited = None;
    if input.is_none() || out.is_none() || err.is_none() { note(&mut failure, Err("child-pipes")); }
    if let Some(pipe) = input.as_mut() {
        note(&mut failure, pipe.original().write_all(&frame).map_err(|_| "input-write"));
        note(&mut failure, if pipe.consume_close() { Ok(()) } else { Err("input-close") });
    }
    // Real complete write and original close precede any successful response.
    stop_failed(&mut child, &mut waited, &mut failure);
    let mut output_used = 0; let mut error_used = 0;
    if let Some(pipe) = out.as_mut() {
        match read_bounded(pipe, &mut output, output_cap) {
            Ok(size) => output_used = size, Err(reason) => note(&mut failure, Err(reason)),
        }
        note(&mut failure, if pipe.consume_close() { Ok(()) } else { Err("output-close") });
    }
    stop_failed(&mut child, &mut waited, &mut failure);
    if let Some(pipe) = err.as_mut() {
        match read_bounded(pipe, &mut error, 1024) {
            Ok(size) => error_used = size, Err(reason) => note(&mut failure, Err(reason)),
        }
        note(&mut failure, if pipe.consume_close() { Ok(()) } else { Err("error-close") });
    }
    stop_failed(&mut child, &mut waited, &mut failure);
    if waited.is_none() {
        match child.wait() { Ok(status) => waited = Some(status), Err(_) => note(&mut failure, Err("child-wait")) }
    }
    if let Some(reason) = failure { return Err(reason); }
    let status = waited.ok_or("child-not-waited")?;
    output.truncate(output_used); error.truncate(error_used);
    Ok(Capture { status, output, error })
}

fn probe_passed(value: &Capture) -> bool {
    let Ok(text) = std::str::from_utf8(&value.output) else { return false; };
    let lines: Vec<&str> = text.split('\n').filter(|line| !line.is_empty()).collect();
    if !value.status.success() || !value.error.is_empty() || lines.len() != 3
        || lines[0] != "running 1 test" || lines[1] != format!("test {DEVICE_TEST} ... ok") {
        return false;
    }
    let Some(time) = lines[2].strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in ")
        .and_then(|value| value.strip_suffix('s')) else { return false; };
    let Some((whole, fraction)) = time.split_once('.') else { return false; };
    !whole.is_empty() && whole.len() <= 6 && !fraction.is_empty() && fraction.len() <= 6
        && whole.bytes().chain(fraction.bytes()).all(|byte| byte.is_ascii_digit())
}

#[test]
fn canonical_entropy_device_access() {
    use std::os::unix::fs::FileTypeExt;
    establish_policy().expect("fixed probe child policy");
    let denied = match std::env::var(DENIED_ENV) {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => panic!("closed test-only device expectation"),
    };
    let mut outcomes = [false; 2];
    for (index, path) in ["/dev/urandom", "/dev/random"].iter().enumerate() {
        outcomes[index] = match File::open(path) {
            Ok(file) => {
                let is_device = file.metadata().is_ok_and(|value| value.file_type().is_char_device());
                let mut original = OriginalFile { file: Some(file) };
                let closed = original.consume_close();
                !denied && is_device && closed
            }
            Err(error) => denied && matches!(error.raw_os_error(), Some(1 | 13)),
        };
    }
    // Assert only after both possible acquired device originals were closed.
    assert_eq!(outcomes, [true, true], "actual fixed entropy device access");
}

fn framed_build_parent_and_entropy_denial() {
    use std::os::unix::process::ExitStatusExt;
    // Library-provided static name; compare only the expected ten bytes.
    let name = unsafe { randombytes_implementation_name() };
    assert!(!name.is_null());
    let mut backend = [0u8; 10];
    for (offset, slot) in backend.iter_mut().enumerate() {
        // Canonical API returns a static NUL-terminated C string. Stop at its
        // actual NUL; never read beyond a shorter unexpected backend name.
        *slot = unsafe { name.add(offset).read() } as u8;
        if *slot == 0 { break; }
    }
    assert_eq!(&backend, b"sysrandom\0");
    let current = std::env::current_exe().expect("actual test executable");
    let name = current.file_name().and_then(|v| v.to_str()).unwrap();
    let suffix = name.strip_prefix("mrk_github_seal-").expect("exact Cargo test name");
    assert!(suffix.len() == 16 && suffix.bytes().all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)));
    let deps = current.parent().unwrap(); assert_eq!(deps.file_name().unwrap(), "deps");
    let release = deps.parent().unwrap(); assert_eq!(release.file_name().unwrap(), "release");
    let helper = release.join("mrk-github-seal");
    let cases = [Case::Good(0), Case::Good(3), Case::Good(protocol::MAX_PLAINTEXT),
        Case::Trailing, Case::LowOrder, Case::DeviceControl, Case::DeviceDenied, Case::EntropyDenied];
    let mut closed_originals = 0;
    for case in cases {
        let captured = capture_case(case, &current, &helper).expect("actual child IO/close/wait");
        closed_originals += 1;
        report_captured(case, &captured);
        assert!(captured.error.is_empty(), "no child diagnostic accepted");
        match case {
            Case::Good(size) => {
                assert_eq!(captured.status.code(), Some(0));
                assert_eq!(captured.output.len(), 12 + size + SEAL_BYTES);
                assert_eq!(&captured.output[..8], b"MRKBOX01");
                assert_eq!(u32::from_be_bytes(captured.output[8..12].try_into().unwrap()) as usize, size + SEAL_BYTES);
                let mut plaintext = vec![0; size.max(1)];
                let ciphertext = &captured.output[12..];
                // SAFETY: exact n+48 canonical ciphertext, separate n-byte
                // writable output (one valid byte for n=0), fixed32-byte keys.
                assert_eq!(unsafe { crypto_box_seal_open(plaintext.as_mut_ptr(), ciphertext.as_ptr(),
                    ciphertext.len() as c_ulonglong, ALICE_PUBLIC.as_ptr(), ALICE_PRIVATE.as_ptr()) }, 0);
                assert!(&plaintext[..size] == public_plaintext(size), "public plaintext roundtrip");
                let mut changed = ciphertext.to_vec(); changed[0] ^= 1;
                assert_ne!(unsafe { crypto_box_seal_open(plaintext.as_mut_ptr(), changed.as_ptr(),
                    changed.len() as c_ulonglong, ALICE_PUBLIC.as_ptr(), ALICE_PRIVATE.as_ptr()) }, 0);
            }
            Case::Trailing | Case::LowOrder => {
                assert_eq!(captured.status.code(), Some(1)); assert!(captured.output.is_empty());
            }
            Case::DeviceControl | Case::DeviceDenied => assert!(probe_passed(&captured)),
            Case::EntropyDenied => {
                assert_eq!(captured.status.signal(), Some(6)); assert!(captured.output.is_empty());
                // Abort proves NO returned wipe/random-close/child-FD close.
                // The actual parent pipes/EOF/wait above are separate facts.
            }
        }
    }
    assert_eq!(closed_originals, 8);
}
