//! Fixed NEW AppleP12 reservation on the SAME vault codec/key Arc.
//! Not a native certificate binding, save permit, assignment or replacement.
use super::*;
use std::sync::{Arc, Weak};

pub(crate) const P12_CRYPTO_BYTES: usize = 2 * 1024 * 1024;
const _: () = assert!(
    format::RECORD_OVERHEAD
        + format::DESCRIPTOR_LIMIT
        + 8
        + 80
        + commands::APPLE_P12_BYTES
        + CONTROL_BYTES
        <= P12_CRYPTO_BYTES
);

pub(crate) struct ReservedAppleP12 {
    key: Weak<VaultKey>,
    identity: Identity,
    record: Id,
    revision: Revision,
    attempted: bool,
}
impl ReservedAppleP12 {
    pub(crate) fn reserve(key: &Arc<VaultKey>, existing: &[Id]) -> Result<Self> {
        Self::reserve_with(key, existing, &mut OsEntropy)
    }
    fn reserve_with(
        key: &Arc<VaultKey>,
        existing: &[Id],
        entropy: &mut impl Entropy,
    ) -> Result<Self> {
        if existing.len() > format::DESCRIPTOR_COUNT {
            return Err(Error::Bounds);
        }
        let record = fresh_id(entropy)?;
        let revision = Revision::new(fresh_id(entropy)?, 1)?;
        if existing.contains(&record)
            || record == revision.random
            || [record, revision.random]
                .iter()
                .any(|id| [key.identity.vault, key.identity.generation].contains(id))
        {
            return Err(Error::Random);
        }
        Ok(Self {
            key: Arc::downgrade(key),
            identity: key.identity,
            record,
            revision,
            attempted: false,
        })
    }
    pub(crate) fn descriptor(&self) -> (Identity, Id, Revision) {
        (self.identity, self.record, self.revision)
    }
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
    pub(crate) fn attempted(&self) -> bool {
        self.attempted
    }
    fn same_key(&self, key: &VaultKey) -> bool {
        self.key.upgrade().is_some_and(|original| {
            std::ptr::eq(original.as_ref(), key) && key.identity == self.identity
        })
    }
    pub(crate) fn seal_p12(
        &mut self,
        key: &VaultKey,
        fields: &Fields,
        p12: Result<&[u8]>,
        allowance: usize,
    ) -> Result<SealedRecord> {
        if std::mem::replace(&mut self.attempted, true) {
            return Err(Error::Format);
        }
        let p12 = p12?;
        if !self.same_key(key)
            || fields.vault_kind() != commands::Kind::AppleP12
            || fields.vault_presence() != [true]
            || fields
                .borrow_value("password")
                .is_none_or(|p| p.len() != 64)
            || p12.is_empty()
            || p12.len() > commands::APPLE_P12_BYTES
            || allowance > P12_CRYPTO_BYTES
        {
            return Err(Error::Bounds);
        }
        let descriptor = Descriptor::new(commands::Kind::AppleP12, None, vec![true], true)?;
        key.seal_record_with_revision(
            self.record,
            None,
            &descriptor,
            fields,
            Some(p12),
            allowance,
            &mut OsEntropy,
            Some(self.revision),
        )
    }
    pub(crate) fn matches_record(&self, key: &VaultKey, record: &AuthenticatedRecord) -> bool {
        self.attempted
            && self.same_key(key)
            && record.record == self.record
            && record.revision == self.revision
            && record.descriptor.kind == commands::Kind::AppleP12
            && record.descriptor.label.is_none()
            && record.descriptor.has_file()
            && record.descriptor.presence() == [true]
            && record.fields.vault_kind() == commands::Kind::AppleP12
            && record.fields.vault_presence() == [true]
            && record.file.as_ref().is_some_and(|p12| {
                !p12.bytes().is_empty() && p12.bytes().len() <= commands::APPLE_P12_BYTES
            })
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    struct Fixed(u8);
    impl Entropy for Fixed {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<()> {
            self.0 += 1;
            bytes.fill(self.0);
            Ok(())
        }
    }
    fn key() -> Arc<VaultKey> {
        Arc::new(lifecycle_data_key(
            Identity::new(
                Id::from_bytes([61; 16]).unwrap(),
                Id::from_bytes([62; 16]).unwrap(),
            )
            .unwrap(),
        ))
    }
    #[test]
    fn p12_reserved_identity_cannot_be_recreated_or_corrected_after_failed_seal() {
        let key = key();
        let mut reserved = ReservedAppleP12::reserve_with(&key, &[], &mut Fixed(70)).unwrap();
        let (identity, record, revision) = reserved.descriptor();
        assert!(identity == key.identity() && revision.counter == 1 && record != revision.random);
        // Bad frame is consumed before platform/kind admission and allocation.
        let password = commands::AppleP12Password::generate().unwrap();
        assert!(password
            .seal_new(&mut reserved, &key, b"not-a-frame", P12_CRYPTO_BYTES)
            .is_err());
        assert!(reserved.attempted());
        assert!(password
            .seal_new(&mut reserved, &key, b"not-a-frame", P12_CRYPTO_BYTES)
            .is_err());
        assert!(reserved.descriptor() == (identity, record, revision));
        let mut collision = Fixed(60); // Record aliases existing vault identity.
        assert!(ReservedAppleP12::reserve_with(&key, &[], &mut collision).is_err());
    }
    #[cfg(all(target_os = "macos", target_pointer_width = "64"))]
    #[test]
    fn p12_reserved_cipher_requires_full_password_file_and_revision_readback() {
        let key = key();
        let foreign = self::key();
        let password = commands::AppleP12Password::generate().unwrap();
        let mut frame = b"MRK-APPLE-P12/1\n".to_vec();
        frame.extend(4u32.to_be_bytes());
        frame.extend([1; 64]);
        frame.extend(b"DATA");
        let mut reserved = ReservedAppleP12::reserve_with(&key, &[], &mut Fixed(80)).unwrap();
        let sealed = password
            .seal_new(&mut reserved, &key, &frame, P12_CRYPTO_BYTES)
            .unwrap();
        let opened = key
            .open_record(sealed.bytes().to_vec(), P12_CRYPTO_BYTES)
            .unwrap();
        assert!(reserved.matches_record(&key, &opened));
        assert!(!reserved.matches_record(&foreign, &opened));
        assert!(password.matches_authenticated_readback(&opened, &frame));
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert!(!password.matches_authenticated_readback(&opened, &frame));
        frame[last] ^= 1;
        let wrong_password = commands::AppleP12Password::generate().unwrap();
        assert!(!wrong_password.matches_authenticated_readback(&opened, &frame));
    }
}
