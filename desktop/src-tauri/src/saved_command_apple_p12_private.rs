//! Fixed P12 body on the SAME original Apple stdout Pipe/Guard. There is no
//! second reader/task, raw-body getter, generic private channel or DTO finality.
//! Storage backing is retained before GO and through every partial/error path.
use super::*;
use crate::{
    apple_provisioning_journal::P12OutputMetadata,
    asset_commands::{AppleP12Password, APPLE_P12_PRIVATE_FRAME_BYTES},
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"MRK-APPLE-P12-TRANSFER/1\n";
const HEADER: usize = MAGIC.len() + 4 + 32 + 32;
const BODY_LIMIT: usize = HEADER + APPLE_P12_PRIVATE_FRAME_BYTES;
const JSON_LIMIT: usize = 768 * 1024;
const READ_BYTES: usize = 4096;
pub(super) const OUTPUT_LIMIT: usize = BODY_LIMIT + JSON_LIMIT;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReaderState {
    Reserved,
    AwaitingPipe,
    Reading,
    Absent,
    Returned,
}
struct Backing {
    body: Zeroizing<Vec<u8>>,
    json: Zeroizing<Vec<u8>>,
    request: Option<[u8; 32]>,
    output: Option<P12OutputMetadata>,
    verified: bool,
    used: usize,
    state: ReaderState,
    ack_entered: bool,
    ack_returned: bool,
    terminal: bool,
    eof: bool,
    closed: bool,
    drained: bool,
}
pub(super) struct ReceiveBook {
    backing: Mutex<Backing>,
    failed: AtomicBool,
}
fn invalid() -> BridgeError {
    wire::invalid()
}
impl ReceiveBook {
    pub(super) fn reserved() -> Result<Arc<Self>, BridgeError> {
        let mut body = Zeroizing::new(Vec::new());
        let mut json = Zeroizing::new(Vec::new());
        body.try_reserve_exact(BODY_LIMIT).map_err(|_| invalid())?;
        json.try_reserve_exact(JSON_LIMIT).map_err(|_| invalid())?;
        if body.capacity() != BODY_LIMIT || json.capacity() != JSON_LIMIT {
            return Err(invalid());
        }
        body.resize(BODY_LIMIT, 0);
        Ok(Arc::new(Self {
            backing: Mutex::new(Backing {
                body,
                json,
                request: None,
                output: None,
                verified: false,
                used: 0,
                state: ReaderState::Reserved,
                ack_entered: false,
                ack_returned: false,
                terminal: false,
                eof: false,
                closed: false,
                drained: false,
            }),
            failed: AtomicBool::new(false),
        }))
    }
    pub(super) fn retained_bytes() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(BODY_LIMIT)?
            .checked_add(JSON_LIMIT)?
            .checked_add(READ_BYTES)?
            .checked_add(std::mem::size_of::<P12OutputMetadata>() + 4 * 64)
    }
    pub(super) fn bind_request(&self, bytes: &[u8]) -> Result<(), BridgeError> {
        let mut b = self.backing.try_lock().map_err(|_| invalid())?;
        if self.failed.load(Ordering::SeqCst)
            || b.request.is_some()
            || !matches!(b.state, ReaderState::Reserved | ReaderState::AwaitingPipe)
            || bytes.is_empty()
            || bytes.len() > wire::REQUEST_LIMIT
            || !bytes.ends_with(b"\n")
        {
            return Err(invalid());
        }
        b.request = Some(Sha256::digest(bytes).into());
        Ok(())
    }
    pub(super) fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }
    fn begin(&self, output: &P12OutputMetadata) -> Result<(), BridgeError> {
        let mut b = self.backing.try_lock().map_err(|_| invalid())?;
        if self.failed.load(Ordering::SeqCst)
            || b.state != ReaderState::Reading
            || b.output.is_some()
            || b.used != 0
            || b.terminal
            || b.eof
            || b.drained
            || b.request.is_none()
            || !output.bounded()
        {
            return Err(invalid());
        }
        b.output = Some(output.clone());
        Ok(())
    }
    fn copy_body(&self, bytes: &[u8]) -> Result<(usize, bool), BridgeError> {
        let mut b = self.backing.try_lock().map_err(|_| invalid())?;
        if self.failed.load(Ordering::SeqCst) {
            return Err(invalid());
        }
        b.copy_body(bytes)
    }
    pub(super) fn begin_ack(&self, output: &P12OutputMetadata) -> Result<(), BridgeError> {
        let mut b = self.backing.try_lock().map_err(|_| invalid())?;
        if self.failed.load(Ordering::SeqCst)
            || b.ack_entered
            || !b.body_complete(output)
            || b.drained
        {
            return Err(invalid());
        }
        b.ack_entered = true;
        Ok(())
    }
    pub(super) fn end_ack(&self, output: &P12OutputMetadata, returned: bool) -> bool {
        let ok = self.backing.try_lock().is_ok_and(|mut b| {
            if self.failed.load(Ordering::SeqCst)
                || !b.ack_entered
                || b.ack_returned
                || !b.body_complete(output)
                || !returned
            {
                return false;
            }
            b.ack_returned = true;
            true
        });
        if !ok {
            self.fail();
        }
        ok
    }
    pub(super) fn custody_matches(&self, output: &P12OutputMetadata) -> bool {
        !self.failed.load(Ordering::SeqCst)
            && self
                .backing
                .try_lock()
                .is_ok_and(|b| !b.drained && b.body_complete(output))
    }
    pub(super) fn returned_matches(&self, output: &P12OutputMetadata) -> bool {
        !self.failed.load(Ordering::SeqCst)
            && self.backing.try_lock().is_ok_and(|b| {
                b.state == ReaderState::Returned
                    && b.eof
                    && b.closed
                    && b.terminal
                    && b.json.is_empty()
                    && b.ack_entered
                    && b.ack_returned
                    && !b.drained
                    && b.body_complete(output)
            })
    }
    pub(super) fn no_body_returned(&self) -> bool {
        // This comparison cannot alone authorize derived-material disposal.
        !self.failed.load(Ordering::SeqCst)
            && self.backing.try_lock().is_ok_and(|b| {
                !b.drained
                    && b.output.is_none()
                    && !b.verified
                    && b.used == 0
                    && !b.ack_entered
                    && !b.ack_returned
                    && b.json.is_empty()
                    && (b.state == ReaderState::Absent
                        || b.state == ReaderState::Returned && b.eof && b.closed && b.terminal)
            })
    }
    pub(super) fn seal_p12(
        &self,
        reserved: &mut crate::vault_crypto::ReservedAppleP12,
        key: &crate::vault_crypto::VaultKey,
        password: &AppleP12Password,
        allowance: usize,
        output: &P12OutputMetadata,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if !self.returned_matches(output) {
            return Err(Error::Authentication);
        }
        let b = self.backing.try_lock().map_err(|_| Error::Authentication)?;
        if b.drained || !b.body_complete(output) || self.failed.load(Ordering::SeqCst) {
            return Err(Error::Authentication);
        }
        password.seal_new(reserved, key, &b.body[HEADER..b.used], allowance)
    }
    pub(super) fn matches_readback(
        &self,
        record: &crate::vault_crypto::AuthenticatedRecord,
        password: &AppleP12Password,
        output: &P12OutputMetadata,
    ) -> bool {
        self.returned_matches(output)
            && self.backing.try_lock().is_ok_and(|b| {
                !b.drained
                    && b.body_complete(output)
                    && password.matches_authenticated_readback(record, &b.body[HEADER..b.used])
            })
    }
    pub(super) fn drain_saved(&self, output: &P12OutputMetadata) -> bool {
        self.returned_matches(output) && self.drain()
    }
    pub(super) fn drain_no_save(&self, output: Option<&P12OutputMetadata>) -> bool {
        // Parent separately proves save slot NEVER entered and ALL original
        // work/IO/jobs returned. Known assembled derived output may be erased;
        // source stored key is untouched. Partial/uncertain receive refuses.
        (match output {
            Some(out) => self.returned_matches(out),
            None => self.no_body_returned(),
        }) && self.drain()
    }
    pub(super) fn drained(&self) -> bool {
        !self.failed.load(Ordering::SeqCst) && self.backing.try_lock().is_ok_and(|b| b.drained)
    }
    fn drain(&self) -> bool {
        if self.failed.load(Ordering::SeqCst) {
            return false;
        }
        let Ok(mut b) = self.backing.try_lock() else {
            return false;
        };
        if b.drained {
            return false;
        }
        b.body.zeroize();
        b.json.zeroize();
        b.drained = true;
        true
    }
}
impl Backing {
    fn body_complete(&self, expected: &P12OutputMetadata) -> bool {
        self.output.as_ref() == Some(expected)
            && self.verified
            && self.used == HEADER + expected.frame_bytes as usize
    }
    fn copy_body(&mut self, bytes: &[u8]) -> Result<(usize, bool), BridgeError> {
        let expected = self.output.as_ref().ok_or_else(invalid)?;
        if self.state != ReaderState::Reading
            || self.terminal
            || self.eof
            || self.drained
            || self.verified
        {
            return Err(invalid());
        }
        let end = HEADER
            .checked_add(expected.frame_bytes as usize)
            .ok_or_else(invalid)?;
        let count = bytes
            .len()
            .min(end.checked_sub(self.used).ok_or_else(invalid)?);
        if count == 0 || end > BODY_LIMIT {
            return Err(invalid());
        }
        self.body[self.used..self.used + count].copy_from_slice(&bytes[..count]);
        self.used += count;
        if self.used >= HEADER {
            let at = MAGIC.len();
            let raw = &self.body[..HEADER];
            if !raw.starts_with(MAGIC)
                || u32::from_be_bytes(raw[at..at + 4].try_into().map_err(|_| invalid())?)
                    != expected.frame_bytes
                || raw[at + 4..at + 36] != self.request.ok_or_else(invalid)?
                || hex(&raw[at + 36..]) != expected.frame_sha256
            {
                return Err(invalid());
            }
        }
        if self.used != end {
            return Ok((count, false));
        }
        let metadata = crate::asset_commands::apple_p12_output_metadata(&self.body[HEADER..end])
            .map_err(|_| invalid())?;
        if hex(&metadata.frame_sha256) != expected.frame_sha256
            || metadata.frame_bytes != expected.frame_bytes as usize
            || metadata.p12_bytes != expected.p12_bytes as usize
            || hex(&metadata.p12_sha256) != expected.p12_sha256
            || hex(&metadata.leaf_sha256) != expected.certificate_sha256
            || hex(&metadata.spki_sha256) != expected.public_key_sha256
        {
            return Err(invalid());
        }
        self.verified = true;
        Ok((count, true))
    }
    fn finish(&mut self) -> bool {
        self.eof = true;
        self.terminal
            && self.json.is_empty()
            && match &self.output {
                Some(out) => self.body_complete(out),
                None => self.used == 0 && !self.verified && !self.ack_entered,
            }
    }
}

// The read/EOF/close implementation below is the existing fixed SavedCommand
// private reader, dispatched only for p12-save on its SAME original pipe.
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
            if !book.backing.try_lock().is_ok_and(|mut b| {
                if b.request.is_none() || b.state != ReaderState::AwaitingPipe {
                    return false;
                }
                b.state = ReaderState::Reading;
                true
            }) {
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
    let mut frames = 0;
    let mut public_bytes = 0;
    let mut terminal = false;
    let mut decoder_settled = false;
    let mut withheld: Option<Frame> = None;
    loop {
        let Some(reader) = pipe.io.as_mut() else {
            failed = true;
            break;
        };
        match reader.read(&mut buffer[..]).await {
            Ok(0) => {
                eof = true;
                decoder_settled = terminal
                    && withheld.is_none()
                    && decoder.as_mut().is_some_and(OutputDecoder::finish);
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
                if previous.saturating_add(count) > OUTPUT_LIMIT {
                    failed = true;
                }
                let mut at = 0;
                while at < count && !failed {
                    if withheld.is_some() {
                        match book.copy_body(&buffer[at..count]) {
                            Ok((copied, complete)) => {
                                at += copied;
                                if complete {
                                    let Some(frame) = withheld.take() else {
                                        failed = true;
                                        break;
                                    };
                                    if !enqueue_frame(&inner, &owner, frame).await {
                                        failed = true;
                                    }
                                }
                            }
                            Err(_) => failed = true,
                        }
                    } else {
                        let frame = {
                            let Ok(mut b) = book.backing.try_lock() else {
                                failed = true;
                                break;
                            };
                            let mut frame = None;
                            while at < count {
                                if terminal
                                    || public_bytes == JSON_LIMIT
                                    || b.json.len() == wire::CERTIFICATE_IDENTITY_LIMIT
                                {
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
                                    frame =
                                        decoder.as_mut().and_then(|d| d.push(&b.json, &owner).ok());
                                    b.json.zeroize();
                                    b.json.clear();
                                    if frame.is_none() {
                                        failed = true;
                                    }
                                    break;
                                }
                            }
                            frame
                        }; // Original queue await is outside bounded memory lock.
                        if let Some(frame) = frame {
                            if let Frame::AppleProvisioning(wire::Frame::Event(event)) = &frame {
                                if let wire::EventData::P12(wire::P12Event::Output(output)) =
                                    &event.data
                                {
                                    if book.begin(output).is_err() {
                                        failed = true;
                                    } else {
                                        withheld = Some(frame);
                                    }
                                    continue;
                                }
                            }
                            let end = matches!(
                                &frame,
                                Frame::AppleProvisioning(wire::Frame::Terminal(_))
                            );
                            if !enqueue_frame(&inner, &owner, frame).await {
                                failed = true;
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
                    // Continue bounded original drain, never log P12 bytes.
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
    }
    if let Ok(mut b) = book.backing.try_lock() {
        b.closed = closed;
        if !failed && closed && eof {
            b.state = ReaderState::Returned;
        }
    } else {
        book.fail();
        failed = true;
    }
    guard.complete = closed;
    ReadEnd {
        frames,
        eof,
        closed,
        failed: failed || book.failed.load(Ordering::SeqCst),
        decoder_settled,
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn fixture() -> (Arc<ReceiveBook>, P12OutputMetadata, Vec<u8>) {
        // Binary framing DATA only: not a PKCS12, pipe, native join or permit.
        let mut frame = b"MRK-APPLE-P12/1\n".to_vec();
        frame.extend(4u32.to_be_bytes());
        frame.extend([21; 32]);
        frame.extend([22; 32]);
        frame.extend(b"DATA");
        let metadata = crate::asset_commands::apple_p12_output_metadata(&frame).unwrap();
        let output = P12OutputMetadata {
            frame_bytes: metadata.frame_bytes as u32,
            frame_sha256: hex(&metadata.frame_sha256),
            p12_bytes: metadata.p12_bytes as u32,
            p12_sha256: hex(&metadata.p12_sha256),
            certificate_sha256: hex(&metadata.leaf_sha256),
            public_key_sha256: hex(&metadata.spki_sha256),
        };
        let book = ReceiveBook::reserved().unwrap();
        let request = b"{}\n";
        book.bind_request(request).unwrap();
        book.backing.lock().unwrap().state = ReaderState::Reading;
        let mut transfer = MAGIC.to_vec();
        transfer.extend(output.frame_bytes.to_be_bytes());
        transfer.extend(Sha256::digest(request));
        transfer.extend(metadata.frame_sha256);
        transfer.extend(frame);
        (book, output, transfer)
    }

    #[test]
    fn p12_receiver_requires_complete_body_ack_eof_and_close_on_original_backing() {
        let (book, output, transfer) = fixture();
        book.begin(&output).unwrap();
        assert!(book.copy_body(&transfer[..HEADER - 1]).unwrap() == (HEADER - 1, false));
        assert!(!book.custody_matches(&output));
        assert!(!book.no_body_returned());
        assert!(book.copy_body(&transfer[HEADER - 1..]).unwrap().1);
        assert!(book.custody_matches(&output));
        assert!(!book.returned_matches(&output));
        book.begin_ack(&output).unwrap();
        assert!(book.end_ack(&output, true));
        assert!(!book.returned_matches(&output));
        {
            let mut backing = book.backing.lock().unwrap();
            backing.terminal = true;
            assert!(backing.finish());
            backing.state = ReaderState::Returned;
        }
        assert!(!book.returned_matches(&output));
        book.backing.lock().unwrap().closed = true;
        assert!(book.returned_matches(&output));
        assert!(book.drain_no_save(Some(&output)));
        assert!(book.drained());
        assert!(!book.drain_no_save(Some(&output)));
        assert!(book
            .backing
            .lock()
            .unwrap()
            .body
            .iter()
            .all(|byte| *byte == 0));
        // Above is only the receive half. Production still requires the
        // nonconstructible same-owner never-SAVE/all-jobs proof to call drain.
    }

    #[test]
    fn p12_receiver_partial_wrong_request_or_lost_ack_never_becomes_empty_or_reusable() {
        for fault in 0..3 {
            let (book, output, mut transfer) = fixture();
            book.begin(&output).unwrap();
            match fault {
                0 => {
                    let end = transfer.len() - 1;
                    assert!(!book.copy_body(&transfer[..end]).unwrap().1);
                }
                1 => {
                    transfer[MAGIC.len() + 4] ^= 1;
                    assert!(book.copy_body(&transfer).is_err());
                    book.fail(); // Same absorbing cut as the actual reader.
                }
                _ => {
                    assert!(book.copy_body(&transfer).unwrap().1);
                    book.begin_ack(&output).unwrap();
                    assert!(!book.end_ack(&output, false));
                }
            }
            assert!(!book.returned_matches(&output));
            assert!(!book.no_body_returned());
            assert!(!book.drain_no_save(None));
            assert!(!book.drain_no_save(Some(&output)));
            assert!(!book.drained());
            assert!(book.backing.lock().unwrap().used > 0);
        }
    }
}
