//! One reserved NEW Apple provisioning-profile identity, not a Store action,
//! native lease, file writer, credential assessment or assignment.
//!
//! The reservation is made before the original provisioning journal is
//! committed. Sealing consumes it once, including every refused attempt. The
//! existing vault cipher/record codec supplies the authenticated bytes.
use super::*;
use std::sync::{Arc, Weak};

pub(crate) const PROFILE_BYTES: usize = 1024 * 1024;
pub(crate) const PROFILE_CRYPTO_BYTES: usize = 2 * 1024 * 1024;
const _: () = assert!(
    format::RECORD_OVERHEAD + format::DESCRIPTOR_LIMIT + 8 + 2 + PROFILE_BYTES + CONTROL_BYTES
        <= PROFILE_CRYPTO_BYTES
);

/// The complete future record identity belongs to this original key Arc.
/// Its public tuple is comparison DATA; it cannot recreate this token.
pub(crate) struct ReservedAppleProfile {
    key: Weak<VaultKey>,
    identity: Identity,
    record: Id,
    revision: Revision,
    attempted: bool,
}

impl ReservedAppleProfile {
    pub(crate) fn reserve(key: &Arc<VaultKey>, existing: &[Id]) -> Result<Self> {
        let record = key.new_record_id(existing)?;
        let revision = Revision::new(fresh_id(&mut OsEntropy)?, 1)?;
        if revision.random == record
            || [key.identity.vault, key.identity.generation].contains(&revision.random)
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

    /// Called only by the fixed native save permit, which owns the original
    /// validated profile receive backing. This is no arbitrary-kind/revision
    /// sealing API and does not turn syntax into native permission.
    pub(crate) fn seal_profile(
        &mut self,
        key: &VaultKey,
        profile: &[u8],
        allowance: usize,
    ) -> Result<SealedRecord> {
        if std::mem::replace(&mut self.attempted, true) {
            return Err(Error::Format);
        }
        if !self.key.upgrade().is_some_and(|original| {
            std::ptr::eq(original.as_ref(), key) && original.identity == self.identity
        }) || profile.is_empty()
            || profile.len() > PROFILE_BYTES
            || allowance > PROFILE_CRYPTO_BYTES
        {
            return Err(Error::Bounds);
        }
        let descriptor = Descriptor::new(commands::Kind::AppleProfile, None, vec![], true)?;
        let fields = commands::own_fields(commands::Kind::AppleProfile, &serde_json::json!({}))
            .map_err(|_| Error::Format)?;
        // The parent-private seam is the SAME record codec. Only this fixed
        // child selects an already reserved NEW revision; old callers retain
        // their existing automatic revision generation unchanged.
        key.seal_record_with_revision(
            self.record,
            None,
            &descriptor,
            &fields,
            Some(profile),
            allowance,
            &mut OsEntropy,
            Some(self.revision),
        )
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn key() -> Arc<VaultKey> {
        let identity = Identity::new(
            Id::from_bytes([71; 16]).unwrap(),
            Id::from_bytes([72; 16]).unwrap(),
        )
        .unwrap();
        Arc::new(lifecycle_data_key(identity))
    }

    #[test]
    fn profile_reservation_binds_original_key_and_burns_a_refused_attempt() {
        let first = key();
        let foreign = key(); // Same public identity is not the original key.
        let mut reserved = ReservedAppleProfile::reserve(&first, &[]).unwrap();
        let expected = reserved.descriptor();
        assert!(expected.0 == first.identity());
        assert_eq!(expected.2.counter, 1);
        assert!(reserved
            .seal_profile(
                foreign.as_ref(),
                b"public-data-not-a-profile",
                PROFILE_CRYPTO_BYTES
            )
            .is_err());
        assert!(reserved.attempted());
        assert!(reserved
            .seal_profile(
                first.as_ref(),
                b"public-data-not-a-profile",
                PROFILE_CRYPTO_BYTES
            )
            .is_err());
        assert!(reserved.descriptor() == expected);
    }

    #[test]
    fn profile_reservation_does_not_retain_or_recreate_a_lost_key() {
        let first = key();
        let mut reserved = ReservedAppleProfile::reserve(&first, &[]).unwrap();
        drop(first);
        let replacement = key();
        assert!(reserved
            .seal_profile(replacement.as_ref(), b"public-data", PROFILE_CRYPTO_BYTES)
            .is_err());
        assert!(reserved.attempted());
    }

    #[cfg(all(target_os = "macos", target_pointer_width = "64"))]
    #[test]
    fn profile_cipher_uses_the_reserved_revision_and_full_authenticated_bytes() {
        // Codec DATA only: these bytes are deliberately not a CMS profile.
        let key = key();
        let mut reserved = ReservedAppleProfile::reserve(&key, &[]).unwrap();
        let (_, record, revision) = reserved.descriptor();
        let sealed = reserved
            .seal_profile(
                key.as_ref(),
                b"fixed-profile-codec-data",
                PROFILE_CRYPTO_BYTES,
            )
            .unwrap();
        assert!(sealed.prefix.record == record);
        assert!(sealed.revision() == revision);
        let opened = key
            .open_record(sealed.bytes().to_vec(), PROFILE_CRYPTO_BYTES)
            .unwrap();
        assert!(opened.record == record);
        assert!(opened.revision == revision);
        assert!(opened.descriptor.kind == commands::Kind::AppleProfile);
        assert_eq!(opened.fields.into_value(), serde_json::json!({}));
        assert_eq!(opened.file.unwrap().bytes(), b"fixed-profile-codec-data");
        assert!(reserved
            .seal_profile(key.as_ref(), b"another-profile", PROFILE_CRYPTO_BYTES)
            .is_err());
    }
}
