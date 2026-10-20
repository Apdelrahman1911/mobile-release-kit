//! One private profile trailer on the ORIGINAL Apple stdout reader.
//!
//! The same Session reserves this backing before GO. JSON ends at its existing
//! terminal frame; the trailer never enters serde, a String, a status or an
//! event. A valid trailer is only bounded DATA. The original reader/child/source
//! joins and durable save-armed ACK are separately required by SavePermit.
use super::*;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(super) const PROFILE_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8] = b"MRK-APPLE-PROFILE/1\n";
const HEADER_BYTES: usize = MAGIC.len() + 4 + 32 + 32;
const JSON_BYTES: usize = 256 * 1024;
const READ_BYTES: usize = 4096;
const TAIL_BYTES: usize = HEADER_BYTES + PROFILE_BYTES;
pub(super) const OUTPUT_BYTES: usize = JSON_BYTES + TAIL_BYTES;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReaderState {
    Reserved,
    AwaitingPipe,
    Reading,
    Absent,
    Returned,
}

pub(super) struct ReceiveBook {
    // This mutex protects only bounded memory. No filesystem, Document, vault,
    // or journal lock is acquired under it; reader queue sends are outside it.
    backing: Mutex<Backing>,
    pub(super) failed: AtomicBool,
}

pub(super) struct Backing {
    bytes: Zeroizing<Vec<u8>>,
    json: Zeroizing<Vec<u8>>,
    request: Option<[u8; 32]>,
    save_mode: bool,
    state: ReaderState,
    terminal: bool,
    length: usize,
    header: Option<Header>,
    eof: bool,
    closed: bool,
    drained: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) length: usize,
    pub(super) sha256: [u8; 32],
}

fn invalid() -> BridgeError {
    crate::apple_provisioning_protocol::invalid()
}

impl Header {
    fn parse(raw: &[u8], request: &[u8; 32], save_mode: bool) -> Result<Self, BridgeError> {
        if raw.len() != HEADER_BYTES || !raw.starts_with(MAGIC) {
            return Err(invalid());
        }
        let at = MAGIC.len();
        let length =
            u32::from_be_bytes(raw[at..at + 4].try_into().map_err(|_| invalid())?) as usize;
        let sha256 = raw[at + 4..at + 36].try_into().map_err(|_| invalid())?;
        if length > PROFILE_BYTES
            || !save_mode && length != 0
            || &raw[at + 36..] != request
            || length == 0 && sha256 != <[u8; 32]>::from(Sha256::digest([]))
        {
            return Err(invalid());
        }
        Ok(Self { length, sha256 })
    }
}

impl ReceiveBook {
    pub(super) fn reserved(save_mode: bool) -> Result<Arc<Self>, BridgeError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut json = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(TAIL_BYTES).map_err(|_| invalid())?;
        json.try_reserve_exact(JSON_BYTES).map_err(|_| invalid())?;
        // Charge actual fixed allocations; an allocator rounding outside the
        // admitted quote is unavailable, never silently treated as that quote.
        if bytes.capacity() != TAIL_BYTES || json.capacity() != JSON_BYTES {
            return Err(invalid());
        }
        bytes.resize(TAIL_BYTES, 0);
        Ok(Arc::new(Self {
            backing: Mutex::new(Backing {
                bytes,
                json,
                request: None,
                save_mode,
                state: ReaderState::Reserved,
                terminal: false,
                length: 0,
                header: None,
                eof: false,
                closed: false,
                drained: false,
            }),
            failed: AtomicBool::new(false),
        }))
    }

    pub(super) fn bind_request(&self, raw: &[u8]) -> Result<(), BridgeError> {
        let mut b = self.backing.try_lock().map_err(|_| invalid())?;
        if self.failed.load(Ordering::SeqCst)
            || !matches!(b.state, ReaderState::Reserved | ReaderState::AwaitingPipe)
            || b.request.is_some()
            || raw.is_empty()
            || raw.len() > crate::apple_provisioning_protocol::REQUEST_LIMIT
            || !raw.ends_with(b"\n")
        {
            return Err(invalid());
        }
        b.request = Some(Sha256::digest(raw).into());
        Ok(())
    }

    pub(super) fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }

    pub(super) fn retained_bytes() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(TAIL_BYTES)?
            .checked_add(JSON_BYTES)?
            .checked_add(READ_BYTES)
    }

    /// Comparison only. This does not inspect/claim native task handles.
    pub(super) fn returned_matches(&self, length: usize, sha256: &[u8; 32]) -> bool {
        !self.failed.load(Ordering::SeqCst)
            && self.backing.try_lock().is_ok_and(|b| {
                b.state == ReaderState::Returned
                    && b.eof
                    && b.closed
                    && !b.drained
                    && b.header
                        .is_some_and(|h| h.length == length && &h.sha256 == sha256)
                    && b.length == HEADER_BYTES + length
                    && b.json.is_empty()
            })
    }

    pub(super) fn seal_profile(
        &self,
        reserved: &mut crate::vault_crypto::ReservedAppleProfile,
        key: &crate::vault_crypto::VaultKey,
        allowance: usize,
        expected: Header,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if !self.returned_matches(expected.length, &expected.sha256) || expected.length == 0 {
            return Err(Error::Authentication);
        }
        let b = self.backing.try_lock().map_err(|_| Error::Authentication)?;
        if b.drained || b.header != Some(expected) || self.failed.load(Ordering::SeqCst) {
            return Err(Error::Authentication);
        }
        // Only the fixed AppleProfile codec can consume this borrow. Neither
        // the destination nor a renderer obtains an arbitrary bytes getter.
        reserved.seal_profile(
            key,
            &b.bytes[HEADER_BYTES..HEADER_BYTES + expected.length],
            allowance,
        )
    }

    pub(super) fn matches_readback(
        &self,
        record: &crate::vault_crypto::AuthenticatedRecord,
        expected: Header,
    ) -> bool {
        if expected.length == 0 || !self.returned_matches(expected.length, &expected.sha256) {
            return false;
        }
        self.backing.try_lock().is_ok_and(|b| {
            !b.drained
                && b.header == Some(expected)
                && record.descriptor.kind == crate::asset_commands::Kind::AppleProfile
                && record.file.as_ref().is_some_and(|file| {
                    file.bytes() == &b.bytes[HEADER_BYTES..HEADER_BYTES + expected.length]
                })
        })
    }

    /// The parent calls only after its actual all-jobs/private-consumer cut.
    /// Content is consumed here, not returned through a public bytes getter.
    pub(super) fn drain(&self, permit_no_pipe: bool) -> bool {
        if self.failed.load(Ordering::SeqCst) {
            return false;
        }
        let Ok(mut b) = self.backing.try_lock() else {
            return false;
        };
        if b.drained {
            return true;
        }
        let returned = b.state == ReaderState::Returned
            && b.eof
            && b.closed
            && b.header
                .is_some_and(|h| b.length == HEADER_BYTES + h.length);
        let absent = permit_no_pipe
            && b.state == ReaderState::Absent
            && b.length == 0
            && b.header.is_none()
            && b.json.is_empty();
        if !returned && !absent {
            return false;
        }
        b.bytes.zeroize();
        b.json.zeroize();
        b.drained = true;
        true
    }
}

impl Backing {
    fn tail(&mut self, data: &[u8]) -> Result<(), BridgeError> {
        if !self.terminal || self.drained || self.eof || self.state != ReaderState::Reading {
            return Err(invalid());
        }
        let end = self.length.checked_add(data.len()).ok_or_else(invalid)?;
        if end > TAIL_BYTES {
            return Err(invalid());
        }
        self.bytes[self.length..end].copy_from_slice(data);
        self.length = end;
        if self.header.is_none() && self.length >= HEADER_BYTES {
            self.header = Some(Header::parse(
                &self.bytes[..HEADER_BYTES],
                self.request.as_ref().ok_or_else(invalid)?,
                self.save_mode,
            )?);
        }
        if self
            .header
            .is_some_and(|h| self.length > HEADER_BYTES + h.length)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn finish(&mut self) -> bool {
        self.eof = true;
        self.terminal
            && self.json.is_empty()
            && self.header.is_some_and(|h| {
                self.length == HEADER_BYTES + h.length
                    && <[u8; 32]>::from(Sha256::digest(&self.bytes[HEADER_BYTES..self.length]))
                        == h.sha256
            })
    }
}

/// This is dispatched from the existing read_output function ONLY for the
/// closed profile modes. It owns the same Pipe, Guard and ReadEnd; there is no
/// new task/FD/output channel. Partial/unknown bytes remain in the original book.
pub(super) async fn read<T: AsyncRead + Unpin + OriginalClose>(
    inner: Arc<Inner>,
    owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>,
    book: Arc<ReceiveBook>,
    mut guard: Guard,
) -> ReadEnd {
    let admitted = book.backing.try_lock().is_ok_and(|mut b| {
        if b.state != ReaderState::Reserved || book.failed.load(Ordering::SeqCst) {
            return false;
        }
        b.state = ReaderState::AwaitingPipe;
        true
    });
    if !admitted {
        book.fail();
        inner.unknown(&owner);
        return ReadEnd {
            frames: 0,
            eof: false,
            closed: false,
            failed: true,
            decoder_settled: false,
        };
    }
    match pipe_state(&owner).await {
        Some(true) => {
            if let Ok(mut b) = book.backing.try_lock() {
                if b.request.is_some() && b.state == ReaderState::AwaitingPipe {
                    b.state = ReaderState::Reading;
                } else {
                    book.fail();
                }
            } else {
                book.fail();
            }
        }
        other => {
            if other == Some(false) {
                if let Ok(mut b) = book.backing.try_lock() {
                    b.state = ReaderState::Absent;
                } else {
                    book.fail();
                }
            } else {
                book.fail();
            }
            guard.complete = other.is_some() && !book.failed.load(Ordering::SeqCst);
            return ReadEnd {
                frames: 0,
                eof: false,
                closed: false,
                failed: book.failed.load(Ordering::SeqCst),
                decoder_settled: false,
            };
        }
    }
    let mut pipe = slot.lock().await;
    let mut buffer = Zeroizing::new([0u8; READ_BYTES]);
    let mut decoder = OutputDecoder::new(&owner).ok();
    let mut failed = book.failed.load(Ordering::SeqCst) || decoder.is_none();
    let mut eof = false;
    let mut frames = 0usize;
    let mut public_bytes = 0usize;
    let mut terminal = false;
    let mut decoder_settled = false;
    loop {
        let Some(reader) = pipe.io.as_mut() else {
            failed = true;
            break;
        };
        match reader.read(&mut buffer[..]).await {
            Ok(0) => {
                eof = true;
                decoder_settled = terminal && decoder.as_mut().is_some_and(OutputDecoder::finish);
                if !decoder_settled || !book.backing.try_lock().is_ok_and(|mut b| b.finish()) {
                    failed = true;
                }
                break;
            }
            Ok(count) => {
                let previous = owner
                    .output_bytes
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        Some(n.saturating_add(count))
                    })
                    .unwrap_or(usize::MAX);
                if previous.saturating_add(count) > OUTPUT_BYTES {
                    failed = true;
                }
                if !failed {
                    let mut at = 0;
                    while at < count && !failed {
                        if terminal {
                            if !book
                                .backing
                                .try_lock()
                                .is_ok_and(|mut b| b.tail(&buffer[at..count]).is_ok())
                            {
                                failed = true;
                            }
                            at = count;
                        } else {
                            let (frame, end) = {
                                let Ok(mut b) = book.backing.try_lock() else {
                                    failed = true;
                                    break;
                                };
                                let mut frame = None;
                                let mut end = false;
                                while at < count {
                                    if public_bytes == JSON_BYTES || b.json.len() == JSON_BYTES {
                                        failed = true;
                                        break;
                                    }
                                    let byte = buffer[at];
                                    at += 1;
                                    public_bytes += 1;
                                    b.json.push(byte);
                                    if byte == b'\n' {
                                        frames += 1;
                                        if frames > owner.context.frame_limit() {
                                            failed = true;
                                            break;
                                        }
                                        frame = decoder
                                            .as_mut()
                                            .and_then(|d| d.push(&b.json, &owner).ok());
                                        end = matches!(
                                            &frame,
                                            Some(Frame::AppleProvisioning(
                                                crate::apple_provisioning_protocol::Frame::Terminal(
                                                    _
                                                )
                                            ))
                                        );
                                        b.json.zeroize();
                                        b.json.clear();
                                        if frame.is_none() {
                                            failed = true;
                                        }
                                        break;
                                    }
                                }
                                (frame, end)
                            }; // No receive mutex survives the original queue await.
                            if let Some(frame) = frame {
                                if !enqueue_frame(&inner, &owner, frame).await {
                                    failed = true;
                                }
                            }
                            if end && !failed {
                                terminal = true;
                                if let Ok(mut b) = book.backing.try_lock() {
                                    b.terminal = true;
                                } else {
                                    failed = true;
                                }
                            }
                        }
                    }
                }
                buffer[..count].zeroize();
                if failed {
                    book.fail();
                    owner.resource_unknown.store(true, Ordering::SeqCst);
                    inner.stop(&owner, Reason::ProtocolError);
                    inner.unknown(&owner);
                    // Drain through the same fixed stack buffer, without
                    // decoding/logging or retaining unbounded error text.
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    let closed = close_original(&mut pipe);
    if failed || !closed || !eof {
        book.fail();
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.stop(&owner, Reason::ProtocolError);
        inner.unknown(&owner);
    } else if let Ok(mut b) = book.backing.try_lock() {
        b.closed = true;
        b.state = ReaderState::Returned;
    } else {
        failed = true;
        book.fail();
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.unknown(&owner);
    }
    guard.complete = true;
    ReadEnd {
        frames,
        eof,
        closed,
        failed: failed || !closed,
        decoder_settled: decoder_settled && !failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trailer(request: &[u8], profile: &[u8]) -> Vec<u8> {
        let mut raw = MAGIC.to_vec();
        raw.extend((profile.len() as u32).to_be_bytes());
        raw.extend(Sha256::digest(profile));
        raw.extend(Sha256::digest(request));
        raw.extend(profile);
        raw
    }

    fn reading(save: bool) -> Arc<ReceiveBook> {
        let book = ReceiveBook::reserved(save).unwrap();
        book.bind_request(b"synthetic request\n").unwrap();
        {
            let mut b = book.backing.try_lock().unwrap();
            b.state = ReaderState::Reading;
            b.terminal = true;
        }
        book
    }

    #[test]
    fn exact_fragmented_private_data_is_not_a_join_or_save_permission() {
        let book = reading(true);
        let body = b"not a provisioning profile: synthetic private fixture";
        let raw = trailer(b"synthetic request\n", body);
        let mut b = book.backing.try_lock().unwrap();
        for chunk in raw.chunks(3) {
            b.tail(chunk).unwrap();
        }
        assert!(b.finish());
        assert!(b.header.unwrap().length == body.len());
        drop(b);
        assert!(!book.returned_matches(body.len(), &Sha256::digest(body).into()));
        assert!(!book.drain(false)); // Original native close/return never occurred.
    }

    #[test]
    fn original_request_digest_and_non_save_mode_are_exact() {
        let raw = trailer(b"other request\n", b"profile");
        assert!(reading(true)
            .backing
            .try_lock()
            .unwrap()
            .tail(&raw)
            .is_err());
        let raw = trailer(b"synthetic request\n", b"profile");
        assert!(reading(false)
            .backing
            .try_lock()
            .unwrap()
            .tail(&raw)
            .is_err());
        let book = reading(false);
        let mut b = book.backing.try_lock().unwrap();
        b.tail(&trailer(b"synthetic request\n", b"")).unwrap();
        assert!(b.finish());
    }

    #[test]
    fn truncation_trailing_digest_and_missing_terminal_refuse() {
        let raw = trailer(b"synthetic request\n", b"profile");
        let book = reading(true);
        let mut b = book.backing.try_lock().unwrap();
        b.tail(&raw[..raw.len() - 1]).unwrap();
        assert!(!b.finish());
        drop(b);
        let mut corrupt = raw.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let book = reading(true);
        let mut b = book.backing.try_lock().unwrap();
        b.tail(&corrupt).unwrap();
        assert!(!b.finish());
        drop(b);
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(reading(true)
            .backing
            .try_lock()
            .unwrap()
            .tail(&trailing)
            .is_err());
        let book = reading(true);
        let mut b = book.backing.try_lock().unwrap();
        b.terminal = false;
        assert!(b.tail(&raw).is_err());
    }

    #[test]
    fn fixed_allocation_one_request_and_unknown_never_retire() {
        let book = ReceiveBook::reserved(true).unwrap();
        assert!(ReceiveBook::retained_bytes().unwrap() > OUTPUT_BYTES);
        {
            let b = book.backing.try_lock().unwrap();
            assert_eq!(b.bytes.capacity(), TAIL_BYTES);
            assert_eq!(b.json.capacity(), JSON_BYTES);
        }
        book.bind_request(b"one\n").unwrap();
        assert!(book.bind_request(b"two\n").is_err());
        book.fail();
        assert!(!book.drain(true));
        assert!(!book.returned_matches(0, &Sha256::digest([]).into()));
    }
}
