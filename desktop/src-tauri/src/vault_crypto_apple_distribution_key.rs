//! Fixed NEW-only identity for an encrypted pending Apple Distribution key.
//!
//! Reserving/sealing here is not a native grant, durable journal ACK, store
//! mutation, CSR release or certificate binding. The original Apple operation
//! owns those facts. This child cannot create/replace a P8, P12 or profile.
use super::*;
use std::sync::{Arc, Weak};

pub(crate) const KEY_CRYPTO_BYTES: usize = 1024 * 1024;
const _: () = assert!(
    format::RECORD_OVERHEAD + format::DESCRIPTOR_LIMIT + format::SCALAR_LIMIT + 8 + CONTROL_BYTES
        <= KEY_CRYPTO_BYTES
);

pub(crate) struct ReservedAppleDistributionKey {
    key: Weak<VaultKey>,
    identity: Identity,
    record: Id,
    revision: Revision,
    attempted: bool,
}

impl ReservedAppleDistributionKey {
    pub(crate) fn reserve(key: &Arc<VaultKey>, existing: &[Id]) -> Result<Self> {
        Self::reserve_with(key, existing, &mut OsEntropy)
    }

    fn reserve_with(
        key: &Arc<VaultKey>,
        existing: &[Id],
        random: &mut impl Entropy,
    ) -> Result<Self> {
        if existing.len() > format::DESCRIPTOR_COUNT {
            return Err(Error::Bounds);
        }
        let record = fresh_id(random)?;
        let revision = Revision::new(fresh_id(random)?, 1)?;
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

    /// Comparison DATA for the durable pre-generation intent. It cannot
    /// recreate this same-key token or authorize submitting a CSR.
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

    /// Fixed scalar-only child, called by the retained candidate's seal_new.
    /// Every attempt is consumed before validation. The original candidate and
    /// reservation remain retained on any error, never silently regenerated.
    pub(crate) fn seal_fields(
        &mut self,
        key: &VaultKey,
        fields: &Fields,
        allowance: usize,
    ) -> Result<SealedRecord> {
        if std::mem::replace(&mut self.attempted, true)
            || !self.same_key(key)
            || fields.vault_kind() != commands::Kind::AppleDistributionKey
            || fields.vault_presence() != [true; 3]
            || allowance > KEY_CRYPTO_BYTES
        {
            return Err(Error::Format);
        }
        let descriptor = Descriptor::new(
            commands::Kind::AppleDistributionKey,
            None,
            vec![true; 3],
            false,
        )?;
        key.seal_record_with_revision(
            self.record,
            None,
            &descriptor,
            fields,
            None,
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
            && record.descriptor.kind == commands::Kind::AppleDistributionKey
            && record.descriptor.label.is_none()
            && !record.descriptor.has_file()
            && record.descriptor.presence() == [true; 3]
            && record.file.is_none()
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use commands::{AppleDistributionKeyFields, Kind};

    const REQUEST: &str =
        "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n";
    struct Fixed(u8);
    impl Entropy for Fixed {
        fn fill(&mut self, output: &mut [u8]) -> Result<()> {
            self.0 = self.0.checked_add(1).ok_or(Error::Random)?;
            output.fill(self.0);
            Ok(())
        }
    }
    fn key() -> Arc<VaultKey> {
        let identity = Identity::new(
            Id::from_bytes([61; 16]).unwrap(),
            Id::from_bytes([62; 16]).unwrap(),
        )
        .unwrap();
        Arc::new(lifecycle_data_key(identity))
    }
    fn material() -> AppleDistributionKeyFields {
        // Deliberately not private keys/signed CSRs. These tests exercise the
        // actual AEAD/descriptor/scalar codec, never generation/native grants.
        let mut frame = b"MRK-APPLE-DISTRIBUTION-KEY/1\n".to_vec();
        for length in [2, REQUEST.len(), 2] {
            frame.extend((length as u32).to_be_bytes());
        }
        frame.extend([0x30, 0]);
        frame.extend(REQUEST.as_bytes());
        frame.extend([0x30, 0]);
        AppleDistributionKeyFields::from_private_frame(&frame).unwrap()
    }

    #[test]
    fn pending_key_reservation_is_original_and_one_attempt_even_on_refusal() {
        let owner = key();
        let foreign = key();
        let fields = material();
        let mut reserved =
            ReservedAppleDistributionKey::reserve_with(&owner, &[], &mut Fixed(70)).unwrap();
        let reference = reserved.descriptor();
        assert!(fields
            .seal_new(&mut reserved, &foreign, KEY_CRYPTO_BYTES)
            .is_err());
        assert!(reserved.attempted());
        assert!(fields
            .seal_new(&mut reserved, &owner, KEY_CRYPTO_BYTES)
            .is_err());
        assert!(reserved.descriptor() == reference);
        assert!(
            ReservedAppleDistributionKey::reserve_with(&owner, &[reference.1], &mut Fixed(70))
                .is_err()
        );
        assert!(ReservedAppleDistributionKey::reserve_with(&owner, &[], &mut Fixed(60)).is_err());
    }

    #[test]
    fn pending_key_loss_or_entropy_failure_cannot_recreate_a_reservation() {
        struct Failed;
        impl Entropy for Failed {
            fn fill(&mut self, _: &mut [u8]) -> Result<()> {
                Err(Error::Random)
            }
        }
        let owner = key();
        assert!(matches!(
            ReservedAppleDistributionKey::reserve_with(&owner, &[], &mut Failed),
            Err(Error::Random)
        ));
        let mut reserved =
            ReservedAppleDistributionKey::reserve_with(&owner, &[], &mut Fixed(80)).unwrap();
        drop(owner);
        assert!(material()
            .seal_new(&mut reserved, &key(), KEY_CRYPTO_BYTES)
            .is_err());
        assert!(reserved.attempted());
    }

    #[test]
    fn actual_pending_key_cipher_reopens_and_lists_without_scalar_disclosure() {
        let owner = key();
        let fields = material();
        let mut reserved =
            ReservedAppleDistributionKey::reserve_with(&owner, &[], &mut Fixed(70)).unwrap();
        let (_, record, revision) = reserved.descriptor();
        let sealed = fields
            .seal_new(&mut reserved, &owner, KEY_CRYPTO_BYTES)
            .unwrap();
        assert!(sealed.prefix.record == record && sealed.revision() == revision);
        // Listing reads only the original wrapped-key/descriptor prefix;
        // passing the complete private record is not that API's contract.
        let listed_end = 216 + sealed.prefix.descriptor_length + 16;
        let descriptor = owner
            .open_descriptor(&sealed.bytes()[..listed_end], KEY_CRYPTO_BYTES)
            .unwrap();
        assert!(descriptor.record == record && descriptor.revision == revision);
        assert!(descriptor.descriptor.kind == Kind::AppleDistributionKey);
        let public_descriptor = descriptor.descriptor.encode().unwrap();
        let text = std::str::from_utf8(&public_descriptor).unwrap();
        assert!(text.contains("apple-distribution-key"));
        assert!(
            !text.contains("MAA=") && !text.contains("csrPem") && !text.contains("PRIVATE KEY")
        );
        let opened = owner
            .open_record(sealed.bytes().to_vec(), KEY_CRYPTO_BYTES)
            .unwrap();
        assert!(
            reserved.matches_record(&owner, &opened)
                && fields.matches_authenticated_readback(&opened)
        );
        let foreign = key();
        assert!(!reserved.matches_record(&foreign, &opened));
        assert!(fields
            .seal_new(&mut reserved, &owner, KEY_CRYPTO_BYTES)
            .is_err());
    }

    #[test]
    fn actual_encrypted_backup_restores_pending_key_new_and_unassigned() {
        let owner = key();
        let fields = material();
        let mut reserved =
            ReservedAppleDistributionKey::reserve_with(&owner, &[], &mut Fixed(70)).unwrap();
        let sealed = fields
            .seal_new(&mut reserved, &owner, KEY_CRYPTO_BYTES)
            .unwrap();
        let original = owner
            .open_record(sealed.bytes().to_vec(), KEY_CRYPTO_BYTES)
            .unwrap();
        let exported = backup::export(
            &original.descriptor,
            &original.fields,
            None,
            KEY_CRYPTO_BYTES,
        )
        .unwrap();
        let imported = exported.deliver(|ciphertext, code| {
            assert!(!ciphertext
                .windows(REQUEST.len())
                .any(|row| row == REQUEST.as_bytes()));
            assert!(backup::RecoveryCode::parse(b"a-password-is-not-a-recovery-code").is_err());
            assert!(backup::import(
                ciphertext.to_vec(),
                backup::RecoveryCode::parse(code).unwrap(),
                0
            )
            .is_err());
            backup::import(
                ciphertext.to_vec(),
                backup::RecoveryCode::parse(code).unwrap(),
                KEY_CRYPTO_BYTES,
            )
            .unwrap()
        });
        drop(owner);
        let identity = Identity::new(
            Id::from_bytes([93; 16]).unwrap(),
            Id::from_bytes([94; 16]).unwrap(),
        )
        .unwrap();
        let other_vault = lifecycle_data_key(identity);
        let fresh = Id::from_bytes([92; 16]).unwrap();
        let resealed = other_vault
            .seal_record(
                fresh,
                None,
                &imported.descriptor,
                &imported.fields,
                None,
                KEY_CRYPTO_BYTES,
            )
            .unwrap();
        let restored = other_vault
            .open_record(resealed.bytes().to_vec(), KEY_CRYPTO_BYTES)
            .unwrap();
        assert!(
            restored.record == fresh
                && restored.record != original.record
                && restored.revision != original.revision
        );
        assert!(fields.matches_authenticated_readback(&restored));
        assert!(!reserved.matches_record(&other_vault, &restored));
        assert!(!Kind::AppleDistributionKey.enabled()); // No ordinary assess/Bind.
    }

    #[test]
    fn unsupported_newer_kind_preserves_input_and_old_descriptor_bytes() {
        let old = Descriptor::new(Kind::ProjectReadToken, None, vec![true], false).unwrap();
        let encoded = old.encode().unwrap();
        assert_eq!(encoded, b"{\"schemaVersion\":1,\"kind\":\"project-read-token\",\"label\":null,\"fieldPresence\":[true],\"filePresent\":false}");
        assert_eq!(
            Descriptor::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        let future = br#"{"schemaVersion":1,"kind":"future-signing-key","label":null,"fieldPresence":[true],"filePresent":false}"#.to_vec();
        let retained = future.clone();
        assert!(Descriptor::decode(&future).is_err());
        assert_eq!(future, retained); // No reset/deletion/rewrite API exists here.
    }
}
