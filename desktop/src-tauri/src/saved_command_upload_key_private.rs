//! Private binary backing on the SAME original stdout reader. This file is a
//! child of the closed GenerateUploadKey facet; no public decoder sees bytes.
use super::*;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[path = "saved_command_upload_key_cancellation.rs"]
pub(super) mod cancellation;

pub(super) struct ReceiveBook {
    pub(super) backing: AsyncMutex<Backing>,
    request: Mutex<Option<[u8; 32]>>,
    pub(super) ready: AtomicBool,
    pub(super) wake: Notify,
    pub(super) complete: AtomicBool,
    pub(super) joined: AtomicBool,
    pub(super) failed: AtomicBool,
}
pub(super) struct Backing {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    pub(super) length: usize,
    pub(super) target: usize,
    pub(super) header: Option<wire::EndHeader>,
    pub(super) eof: bool,
}
impl ReceiveBook {
    pub(super) fn reserved() -> Result<Arc<Self>, BridgeError> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(wire::PRIVATE_BACKING_LIMIT)
            .map_err(|_| wire::unavailable())?;
        if bytes.capacity() != wire::PRIVATE_BACKING_LIMIT {
            return Err(wire::unavailable());
        }
        bytes.resize(wire::PRIVATE_BACKING_LIMIT, 0);
        Ok(Arc::new(Self {
            backing: AsyncMutex::new(Backing {
                bytes,
                length: 0,
                target: wire::READY_LENGTH,
                header: None,
                eof: false,
            }),
            request: Mutex::new(None),
            ready: AtomicBool::new(false),
            wake: Notify::new(),
            complete: AtomicBool::new(false),
            joined: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }))
    }
    pub(super) fn bind_request(&self, request: &[u8]) -> Result<(), BridgeError> {
        if request.is_empty()
            || request.len() > wire::REQUEST_LIMIT
            || !request.ends_with(b"\n")
            || self.ready.load(Ordering::SeqCst)
            || self.failed.load(Ordering::SeqCst)
        {
            return Err(wire::invalid());
        }
        let mut digest = self.request.lock().map_err(|_| wire::invalid())?;
        if digest.is_some() {
            return Err(wire::invalid());
        }
        *digest = Some(Sha256::digest(request).into());
        Ok(())
    }
    pub(super) fn digest(&self) -> Result<[u8; 32], BridgeError> {
        self.request
            .lock()
            .map_err(|_| wire::invalid())?
            .ok_or_else(wire::invalid)
    }
    pub(super) fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.wake.notify_waiters();
    }
    pub(super) fn fixed_bytes() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(wire::PRIVATE_BACKING_LIMIT)?
            .checked_add(4 * std::mem::size_of::<usize>())
    }
}

/// Native candidate stays in this original Session, not a Vec/path/DTO passed
/// to the vault. Only native retirement below can create this handle.
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
pub(crate) struct GeneratedUploadCandidate {
    original: std::sync::Weak<Session>,
    context: wire::UploadKeyContext,
    book: Arc<ReceiveBook>,
    secrets: Arc<crate::asset_commands::UploadKeySecrets>,
    seal_attempted: bool,
    sealed_revision: Option<crate::vault_format::Revision>,
    authenticated: bool,
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
impl GeneratedUploadCandidate {
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(super) fn from_joined(original: &Arc<Session>) -> Result<Self, BridgeError> {
        let state = &original.upload_key;
        let intent = state.intent.as_ref().ok_or_else(wire::invalid)?;
        let book = state.receive.as_ref().ok_or_else(wire::invalid)?;
        if !original_joined(original)
            || !book.joined.load(Ordering::SeqCst)
            || !book.complete.load(Ordering::SeqCst)
            || book.failed.load(Ordering::SeqCst)
            || original.resource_unknown.load(Ordering::SeqCst)
            || state.invalid.load(Ordering::SeqCst)
        {
            return Err(wire::invalid());
        }
        let backing = book.backing.try_lock().map_err(|_| wire::invalid())?;
        let header = backing.header.ok_or_else(wire::invalid)?;
        if !backing.eof || header.status != wire::CoreStatus::Ok {
            return Err(wire::invalid());
        }
        let start = wire::READY_LENGTH + wire::END_HEADER_LENGTH;
        if !wire::generated_container(
            &backing.bytes[start..start + header.jks],
            &backing.bytes[start + header.jks..start + header.jks + header.certificate],
        ) {
            return Err(wire::invalid());
        }
        Ok(Self {
            original: Arc::downgrade(original),
            context: intent.preparation.context.clone(),
            book: book.clone(),
            secrets: intent.gate()?.secrets().clone(),
            seal_attempted: false,
            sealed_revision: None,
            authenticated: false,
        })
    }
    fn current(&self) -> bool {
        !self.book.failed.load(Ordering::SeqCst)
            && self.book.joined.load(Ordering::SeqCst)
            && self.original.upgrade().is_some_and(|o| {
                original_joined(&o)
                    && !o.resource_unknown.load(Ordering::SeqCst)
                    && !o.upload_key.invalid.load(Ordering::SeqCst)
                    && !o.upload_key.disposed.load(Ordering::SeqCst)
                    && Instant::now() < o.clocks.work
            })
    }
    pub(crate) fn seal_new(
        &mut self,
        key: &crate::vault_crypto::VaultKey,
        record: crate::vault_format::Id,
        allowance: usize,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        if self.seal_attempted
            || !self.current()
            || key.identity() != self.context.vault
            || record != self.context.record
        {
            return Err(Error::Authentication);
        }
        self.seal_attempted = true; // A failed/unknown seal never starts a replacement attempt.
        let backing = self
            .book
            .backing
            .try_lock()
            .map_err(|_| Error::Authentication)?;
        let header = backing.header.ok_or(Error::Format)?;
        let start = wire::READY_LENGTH + wire::END_HEADER_LENGTH;
        let sealed = self.secrets.seal_new_fields(
            key,
            record,
            &backing.bytes[start..start + header.jks],
            allowance,
        )?;
        self.sealed_revision = Some(sealed.revision());
        if !self.current() {
            return Err(Error::Authentication);
        }
        Ok(sealed)
    }
    pub(crate) fn matches_authenticated_readback(
        &mut self,
        record: &crate::vault_crypto::AuthenticatedRecord,
    ) -> bool {
        if !self.current()
            || !self.seal_attempted
            || self.sealed_revision != Some(record.revision)
            || record.record != self.context.record
            || !self.secrets.matches_fields(record)
        {
            return false;
        }
        let Ok(backing) = self.book.backing.try_lock() else {
            return false;
        };
        let Some(header) = backing.header else {
            return false;
        };
        let start = wire::READY_LENGTH + wire::END_HEADER_LENGTH;
        let same = record
            .file
            .as_ref()
            .is_some_and(|file| file.bytes() == &backing.bytes[start..start + header.jks]);
        self.authenticated = same;
        same
    }
    /// Public certificate DATA is bound to the fully authenticated saved
    /// record by the original vault parent. Never configured expected policy.
    pub(crate) fn observed_certificate_sha256(&self) -> Option<[u8; 32]> {
        if !self.authenticated || !self.current() {
            return None;
        }
        let backing = self.book.backing.try_lock().ok()?;
        let header = backing.header?;
        let start = wire::READY_LENGTH + wire::END_HEADER_LENGTH + header.jks;
        Some(Sha256::digest(&backing.bytes[start..start + header.certificate]).into())
    }
}

pub(super) async fn read<T: AsyncRead + Unpin + OriginalClose>(
    inner: Arc<Inner>,
    owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>,
    mut guard: Guard,
) -> ReadEnd {
    let Some(book) = owner.upload_key.receive.clone() else {
        inner.unknown(&owner);
        return ReadEnd {
            frames: 0,
            eof: false,
            closed: false,
            failed: true,
            decoder_settled: false,
        };
    };
    match pipe_state(&owner).await {
        Some(true) => {}
        other => {
            guard.complete = other.is_some();
            return ReadEnd {
                frames: 0,
                eof: false,
                closed: false,
                failed: other.is_none(),
                decoder_settled: false,
            };
        }
    }
    let mut pipe = slot.lock().await;
    // The SAME Session held this allocation before reader creation/GO. Reads
    // land directly in it, including partial/error/oversize/trailing bytes.
    let mut backing = book.backing.lock().await;
    let mut frames = 0usize;
    let mut failed = false;
    let mut eof = false;
    let mut discarded = 0usize;
    loop {
        let Some(reader) = pipe.io.as_mut() else {
            failed = true;
            break;
        };
        let at = backing.length;
        let target = backing.target;
        let range = if failed || at == target {
            wire::RESPONSE_LIMIT..wire::RESPONSE_LIMIT + 4096
        } else {
            at..target
        };
        match reader.read(&mut backing.bytes[range]).await {
            Ok(0) => {
                eof = true;
                backing.eof = true;
                if at != target || backing.header.is_none() {
                    failed = true;
                }
                break;
            }
            Ok(count) => {
                let old = owner
                    .output_bytes
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        Some(n.saturating_add(count))
                    })
                    .unwrap_or(usize::MAX);
                if failed || at == target || old.saturating_add(count) > wire::RESPONSE_LIMIT {
                    failed = true;
                    discarded = discarded.saturating_add(count);
                } else {
                    backing.length = at + count;
                    if backing.length == wire::READY_LENGTH {
                        let valid = book.digest().is_ok_and(|digest| {
                            wire::check_ready(
                                &backing.bytes[..wire::READY_LENGTH],
                                &owner.id,
                                &owner.generation,
                                &digest,
                            )
                        });
                        if valid
                            && enqueue_frame(
                                &inner,
                                &owner,
                                Frame::GenerateUploadKey(wire::Frame::Accepted),
                            )
                            .await
                        {
                            frames = 1;
                            backing.target = wire::READY_LENGTH + wire::END_HEADER_LENGTH;
                            book.ready.store(true, Ordering::SeqCst);
                            book.wake.notify_waiters();
                        } else {
                            failed = true;
                        }
                    } else if backing.header.is_none()
                        && backing.length == wire::READY_LENGTH + wire::END_HEADER_LENGTH
                    {
                        match wire::end_header(
                            &backing.bytes[wire::READY_LENGTH..backing.length],
                            &owner.id,
                            &owner.generation,
                        ) {
                            Ok(header) => {
                                backing.target = backing.length + header.jks + header.certificate;
                                backing.header = Some(header);
                            }
                            Err(_) => failed = true,
                        }
                    }
                    if backing.header.is_some() && backing.length == backing.target {
                        let header = backing.header.unwrap();
                        let start = wire::READY_LENGTH + wire::END_HEADER_LENGTH;
                        if header.status == wire::CoreStatus::Ok
                            && !wire::generated_container(
                                &backing.bytes[start..start + header.jks],
                                &backing.bytes[start + header.jks..backing.target],
                            )
                        {
                            failed = true;
                        }
                        if !failed
                            && enqueue_frame(
                                &inner,
                                &owner,
                                Frame::GenerateUploadKey(wire::Frame::Terminal(wire::Terminal {
                                    status: header.status,
                                })),
                            )
                            .await
                        {
                            frames = 2;
                            book.complete.store(true, Ordering::SeqCst);
                        } else {
                            failed = true;
                        }
                    }
                }
                if failed {
                    book.fail();
                    inner.stop(&owner, Reason::ProtocolError);
                    owner.resource_unknown.store(true, Ordering::SeqCst);
                    inner.unknown(&owner);
                }
                // Continue draining through the fixed private discard range;
                // no public frame/String is produced, even after an overrun.
                let _ = discarded;
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    let closed = close_original(&mut pipe);
    if failed || !closed || !eof || frames != 2 {
        book.fail();
        owner.resource_unknown.store(true, Ordering::SeqCst);
        inner.stop(&owner, Reason::ProtocolError);
        inner.unknown(&owner);
    }
    guard.complete = true;
    ReadEnd {
        frames,
        eof,
        closed,
        failed: failed || !closed || frames != 2,
        decoder_settled: !failed && frames == 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_first_read_backing_is_bounded_and_has_no_join_authority() {
        let book = ReceiveBook::reserved().unwrap();
        let bytes = book.backing.try_lock().unwrap();
        assert_eq!(bytes.bytes.capacity(), wire::PRIVATE_BACKING_LIMIT);
        assert_eq!(bytes.bytes.len(), wire::PRIVATE_BACKING_LIMIT);
        assert_eq!(bytes.target, wire::READY_LENGTH);
        assert!(bytes.bytes.iter().all(|byte| *byte == 0));
        assert!(!bytes.eof && bytes.header.is_none());
        assert!(!book.ready.load(Ordering::SeqCst));
        assert!(!book.complete.load(Ordering::SeqCst));
        assert!(!book.joined.load(Ordering::SeqCst));
        assert!(ReceiveBook::fixed_bytes().unwrap() >= wire::PRIVATE_BACKING_LIMIT);
        // The private overrun-drain range also fits this original allocation.
        assert!(wire::RESPONSE_LIMIT + 4096 <= bytes.bytes.len());
    }

    #[test]
    fn exact_request_digest_is_one_attempt_and_failure_does_not_reopen_it() {
        let book = ReceiveBook::reserved().unwrap();
        assert!(book.digest().is_err());
        assert!(book.bind_request(b"not-terminated").is_err());
        let request = b"{\"syntheticMetadata\":true}\n";
        book.bind_request(request).unwrap();
        let digest: [u8; 32] = Sha256::digest(request).into();
        assert_eq!(book.digest().unwrap(), digest);
        assert!(book.bind_request(request).is_err());
        book.fail();
        assert!(book.failed.load(Ordering::SeqCst));
        assert!(book.bind_request(b"{}\n").is_err());
        assert_eq!(book.digest().unwrap(), digest);
        assert!(!book.joined.load(Ordering::SeqCst));
    }
}
