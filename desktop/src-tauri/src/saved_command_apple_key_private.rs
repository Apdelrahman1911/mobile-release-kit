//! One private key body on the ORIGINAL Apple stdout reader, before Terminal.
//!
//! The receiver exists before GO. A body-complete ACK acknowledges only this
//! receiver's custody; it says nothing about EOF, producer/reader joins, NEW,
//! journal durability or public CSR availability. Failure never substitutes an
//! empty trailer or permits another generation. No raw key getter exists.
use super::*;
use crate::{
    apple_provisioning_journal::KeyOutputMetadata,
    asset_commands::{
        AppleDistributionKeyFields, APPLE_KEY_CONSTRUCTION_BYTES, APPLE_KEY_PRIVATE_FRAME_LIMIT,
    },
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"MRK-APPLE-KEY-TRANSFER/1\n";
const HEADER: usize = MAGIC.len() + 4 + 32 + 32;
const BODY_LIMIT: usize = HEADER + APPLE_KEY_PRIVATE_FRAME_LIMIT;
const JSON_LIMIT: usize = 256 * 1024;
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
    output: Option<KeyOutputMetadata>,
    fields: Option<AppleDistributionKeyFields>,
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
    // Bounded memory only. No journal, vault, Document or IO lock is acquired
    // while this mutex is held; original queue sends occur after dropping it.
    backing: Mutex<Backing>,
    failed: AtomicBool,
}
fn invalid() -> BridgeError {
    crate::apple_provisioning_protocol::invalid()
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
                fields: None,
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
        // The fields constructor quote already includes its input frame. The
        // original receive body is that input, not a second secret copy.
        std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(HEADER)?
            .checked_add(APPLE_KEY_CONSTRUCTION_BYTES)?
            .checked_add(JSON_LIMIT)?
            .checked_add(READ_BYTES)?
            .checked_add(std::mem::size_of::<KeyOutputMetadata>() + 3 * 64)
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
    fn begin(&self, output: &KeyOutputMetadata) -> Result<(), BridgeError> {
        let mut b = self.backing.try_lock().map_err(|_| invalid())?;
        if self.failed.load(Ordering::SeqCst)
            || b.state != ReaderState::Reading
            || b.output.is_some()
            || b.used != 0
            || b.terminal
            || b.eof
            || b.drained
            || b.request.is_none()
            || !output.valid()
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
    /// The SAME writer irreversibly enters its one custody ACK before its
    /// first write poll. This does NOT require/claim future EOF or any join.
    pub(super) fn begin_ack(&self, output: &KeyOutputMetadata) -> Result<(), BridgeError> {
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
    pub(super) fn end_ack(&self, output: &KeyOutputMetadata, returned: bool) -> bool {
        let result = self.backing.try_lock().is_ok_and(|mut b| {
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
        if !result {
            self.fail();
        }
        result
    }
    pub(super) fn custody_matches(&self, output: &KeyOutputMetadata) -> bool {
        !self.failed.load(Ordering::SeqCst)
            && self
                .backing
                .try_lock()
                .is_ok_and(|b| !b.drained && b.body_complete(output))
    }
    pub(super) fn returned_matches(&self, output: &KeyOutputMetadata) -> bool {
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
        // Comparison only. The parent must ALSO prove the actual generator
        // was never entered. Empty/failed output alone cannot mint that proof.
        !self.failed.load(Ordering::SeqCst)
            && self.backing.try_lock().is_ok_and(|b| {
                !b.drained
                    && b.output.is_none()
                    && b.fields.is_none()
                    && b.used == 0
                    && !b.ack_entered
                    && !b.ack_returned
                    && b.json.is_empty()
                    && (b.state == ReaderState::Absent
                        || b.state == ReaderState::Returned && b.eof && b.closed && b.terminal)
            })
    }
    pub(super) fn seal_key(
        &self,
        reserved: &mut crate::vault_crypto::ReservedAppleDistributionKey,
        key: &crate::vault_crypto::VaultKey,
        allowance: usize,
        output: &KeyOutputMetadata,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if !self.returned_matches(output) {
            return Err(Error::Authentication);
        }
        let b = self.backing.try_lock().map_err(|_| Error::Authentication)?;
        if b.drained || !b.body_complete(output) || self.failed.load(Ordering::SeqCst) {
            return Err(Error::Authentication);
        }
        b.fields
            .as_ref()
            .ok_or(Error::Authentication)?
            .seal_new(reserved, key, allowance)
    }
    pub(super) fn matches_readback(
        &self,
        record: &crate::vault_crypto::AuthenticatedRecord,
        output: &KeyOutputMetadata,
    ) -> bool {
        self.returned_matches(output)
            && self.backing.try_lock().is_ok_and(|b| {
                !b.drained
                    && b.body_complete(output)
                    && b.fields
                        .as_ref()
                        .is_some_and(|fields| fields.matches_authenticated_readback(record))
            })
    }
    pub(super) fn drain_saved(&self, output: &KeyOutputMetadata) -> bool {
        if !self.returned_matches(output) {
            return false;
        }
        self.drain(false)
    }
    pub(super) fn drain_never_generated(&self) -> bool {
        if !self.no_body_returned() {
            return false;
        }
        self.drain(true)
    }
    fn drain(&self, never_generated: bool) -> bool {
        if self.failed.load(Ordering::SeqCst) {
            return false;
        }
        let Ok(mut b) = self.backing.try_lock() else {
            return false;
        };
        if b.drained {
            return false;
        }
        if never_generated
            && (b.used != 0 || b.output.is_some() || b.fields.is_some() || b.ack_entered)
        {
            return false;
        }
        // The sole parent calls this only at its actual all-jobs/Asset-close
        // cut. Fields owns its own zeroization; no CSR is published here.
        b.fields = None;
        b.body.zeroize();
        b.json.zeroize();
        b.drained = true;
        true
    }
}

impl Backing {
    fn body_complete(&self, expected: &KeyOutputMetadata) -> bool {
        self.output.as_ref() == Some(expected)
            && self.fields.is_some()
            && self.used == HEADER + expected.frame_bytes as usize
    }
    fn copy_body(&mut self, bytes: &[u8]) -> Result<(usize, bool), BridgeError> {
        let expected = self.output.as_ref().ok_or_else(invalid)?;
        if self.state != ReaderState::Reading
            || self.terminal
            || self.eof
            || self.drained
            || self.fields.is_some()
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
        let raw = &self.body[HEADER..end];
        if hex(&Sha256::digest(raw)) != expected.frame_sha256 {
            return Err(invalid());
        }
        let fields = AppleDistributionKeyFields::from_private_frame(raw).map_err(|_| invalid())?;
        let metadata = fields.metadata();
        if hex(&metadata.csr_sha256) != expected.csr_sha256
            || hex(&metadata.public_key_sha256) != expected.public_key_sha256
        {
            return Err(invalid());
        }
        self.fields = Some(fields);
        Ok((count, true))
    }
    fn finish(&mut self) -> bool {
        self.eof = true;
        self.terminal
            && self.json.is_empty()
            && match &self.output {
                Some(output) => self.body_complete(output),
                None => self.used == 0 && self.fields.is_none() && !self.ack_entered,
            }
    }
}

/// Dispatched from the original read_output ONLY for key-prepare. The same
/// Pipe/Guard/ReadEnd/queue are retained. A key event is withheld from the writer
/// until all its exact private body is captured; no ACK can race the body.
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
                                    || b.json.len() == wire::FRAME_LIMIT
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
                                if let wire::EventData::Key(wire::KeyEvent::Output(output)) =
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
                    // Continue bounded original drain, never log key bytes.
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

#[cfg(test)]
mod tests {
    use super::*;
    const REQUEST: &[u8] = b"{\"synthetic\":true}\n";
    const CSR: &[u8] =
        b"-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n";

    fn frame() -> (KeyOutputMetadata, Vec<u8>) {
        // Empty ASN.1 sequences, deliberately NOT private keys, SPKI or signed
        // CSRs. Only this storage framing/custody DATA is under test.
        let mut raw = b"MRK-APPLE-DISTRIBUTION-KEY/1\n".to_vec();
        for size in [2, CSR.len(), 2] {
            raw.extend((size as u32).to_be_bytes());
        }
        raw.extend([0x30, 0]);
        raw.extend(CSR);
        raw.extend([0x30, 0]);
        let output = KeyOutputMetadata {
            frame_bytes: raw.len() as u32,
            frame_sha256: hex(&Sha256::digest(&raw)),
            csr_sha256: hex(&Sha256::digest(CSR)),
            public_key_sha256: hex(&Sha256::digest([0x30, 0])),
        };
        let mut transfer = MAGIC.to_vec();
        transfer.extend(output.frame_bytes.to_be_bytes());
        transfer.extend(Sha256::digest(REQUEST));
        transfer.extend(Sha256::digest(&raw));
        transfer.extend(raw);
        (output, transfer)
    }
    fn reading() -> Arc<ReceiveBook> {
        let book = ReceiveBook::reserved().unwrap();
        book.bind_request(REQUEST).unwrap();
        // No pipe/EOF/close or native join is claimed; all those remain false.
        book.backing.lock().unwrap().state = ReaderState::Reading;
        book
    }
    #[test]
    fn complete_body_allows_only_one_custody_ack_not_eof_or_save_or_drain() {
        let (output, transfer) = frame();
        let book = reading();
        book.begin(&output).unwrap();
        for byte in &transfer[..transfer.len() - 1] {
            assert!(!book.copy_body(&[*byte]).unwrap().1);
            assert!(!book.custody_matches(&output));
        }
        assert!(book.begin_ack(&output).is_err());
        assert_eq!(
            book.copy_body(&transfer[transfer.len() - 1..]).unwrap(),
            (1, true)
        );
        assert!(book.custody_matches(&output));
        book.begin_ack(&output).unwrap();
        assert!(book.begin_ack(&output).is_err());
        assert!(!book.returned_matches(&output));
        assert!(book.end_ack(&output, true));
        assert!(!book.returned_matches(&output));
        assert!(!book.no_body_returned() && !book.drain_never_generated());
        let held = book.backing.lock().unwrap();
        assert_eq!(&held.body[..held.used], transfer.as_slice());
        assert!(!held.eof && !held.closed && !held.terminal && !held.drained);
    }
    #[test]
    fn missing_or_partial_body_cannot_be_acknowledged_or_relabelled_empty() {
        let (output, transfer) = frame();
        for cut in [0, MAGIC.len(), HEADER, transfer.len() - 1] {
            let book = reading();
            book.begin(&output).unwrap();
            if cut > 0 {
                assert!(!book.copy_body(&transfer[..cut]).unwrap().1);
            }
            assert!(book.begin_ack(&output).is_err());
            assert!(!book.no_body_returned());
            assert!(!book.drain_never_generated());
            assert!(!book.returned_matches(&output));
        }
    }
    #[test]
    fn request_length_hash_and_ambiguous_second_transfer_refuse_before_custody() {
        let (output, transfer) = frame();
        for index in [
            0,
            MAGIC.len(),
            MAGIC.len() + 4,
            MAGIC.len() + 4 + 32,
            transfer.len() - 1,
        ] {
            let book = reading();
            book.begin(&output).unwrap();
            let mut bad = transfer.clone();
            bad[index] ^= 1;
            assert!(book.copy_body(&bad).is_err());
            assert!(!book.custody_matches(&output) && !book.returned_matches(&output));
        }
        let book = reading();
        book.begin(&output).unwrap();
        book.copy_body(&transfer).unwrap();
        assert!(book.begin(&output).is_err());
        let mut changed = output.clone();
        changed.csr_sha256 = "0".repeat(64);
        assert!(book.begin_ack(&changed).is_err());
    }
    #[test]
    fn lost_custody_ack_is_absorbing_and_preserves_original_body() {
        let (output, transfer) = frame();
        let book = reading();
        book.begin(&output).unwrap();
        book.copy_body(&transfer).unwrap();
        book.begin_ack(&output).unwrap();
        assert!(!book.end_ack(&output, false));
        assert!(!book.end_ack(&output, true));
        assert!(!book.custody_matches(&output) && !book.returned_matches(&output));
        assert!(!book.drain_never_generated());
        let held = book.backing.lock().unwrap();
        assert_eq!(&held.body[..held.used], transfer.as_slice());
        assert!(held.fields.is_some() && !held.drained);
    }
}
