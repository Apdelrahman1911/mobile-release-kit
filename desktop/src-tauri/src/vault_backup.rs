//! Independently recoverable single-record backups, not vault/keychain copies.
//!
//! The recovery CODE is a fresh uniformly random 256-bit encryption key, not a
//! password. There is deliberately no password-to-key conversion. An approved
//! private native destination owns code delivery; neither it nor plaintext has
//! Debug/Clone/serde/public-response support here. This codec does no filesystem
//! IO and grants no authorization, producer finality, import or assignment.
use super::{capacity, cipher, decode_payload, nonce, random_key, Entropy, Error,
    OsEntropy, Result, ScalarCount, SliceWriter};
use crate::{asset_commands::Fields, asset_source, vault_format as format};
use chacha20poly1305::{AeadInOut, Tag, XNonce};
use std::ops::Range;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"MRKBKP01";
const VERSION: u16 = 1;
const SUITE: u16 = 1; // XChaCha20-Poly1305, directly keyed by a random recovery code.
const DOMAIN: &[u8] = b"dev.mobile-release-kit.desktop/portable-credential-backup/v1\0";
const CODE_PREFIX: &[u8] = b"mrk-recovery-v1-";
const CODE_BYTES: usize = CODE_PREFIX.len() + 64;
const HEADER_BYTES: usize = 48;
const TAG_BYTES: usize = 16;
const PLAIN_LIMIT: usize = 4 + format::DESCRIPTOR_LIMIT + format::PAYLOAD_LIMIT;
pub(crate) const BACKUP_LIMIT: usize = HEADER_BYTES + PLAIN_LIMIT + TAG_BYTES;

/// Private output custody. The owner must choose separate destinations before
/// creating a backup; this object cannot be sent as a normal command response.
pub(crate) struct ExportedBackup {
    encrypted: Vec<u8>,
    recovery: RecoveryCode,
}
impl ExportedBackup {
    #[cfg(test)]
    pub(crate) fn encrypted(&self) -> &[u8] { &self.encrypted }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.encrypted.capacity().checked_add(std::mem::size_of::<Self>())
    }
    /// Sole production export seam: borrow this SAME retained private output
    /// into the concrete original two-destination owner as one operation. No
    /// getter, callback or independently writable output is made available.
    /// Return is not delivery; the native parent still owes current-reference
    /// checks and original child/coordinator joins before publication/disposal.
    #[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn publish_to(&self, destination: &mut crate::asset_source::BackupDestinations,
        owner: &std::sync::Arc<crate::asset_session::OriginalWork>) -> std::result::Result<(), crate::asset_commands::Reason> {
        let code = self.recovery.encoded();
        destination.publish_pair(&self.encrypted, &code[..], owner)
    }
    /// Synthetic codec fixture extraction only. Production output remains
    /// opaque until a concrete original private sink is implemented/reviewed.
    /// In particular a callback result is never durable delivery evidence.
    #[cfg(test)]
    pub(crate) fn deliver<R>(self, destination: impl FnOnce(&[u8], &[u8]) -> R) -> R {
        let code = self.recovery.encoded();
        destination(&self.encrypted, &code[..])
    }
}

/// A parsed recovery code is useful only for decryption. Export always creates
/// its own new key, even if a caller already holds a valid code.
pub(crate) struct RecoveryCode(Zeroizing<[u8; 32]>);
impl RecoveryCode {
    pub(crate) fn parse(code: &[u8]) -> Result<Self> {
        if code.len() != CODE_BYTES || !code.starts_with(CODE_PREFIX) { return Err(Error::Format); }
        let mut key = Zeroizing::new([0; 32]);
        fn digit(byte: u8) -> Result<u8> {
            match byte { b'0'..=b'9' => Ok(byte - b'0'), b'a'..=b'f' => Ok(byte - b'a' + 10), _ => Err(Error::Format) }
        }
        for (index, pair) in code[CODE_PREFIX.len()..].chunks_exact(2).enumerate() {
            key[index] = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        if key.iter().all(|byte| *byte == 0) { return Err(Error::Format); }
        Ok(Self(key))
    }
    fn encoded(&self) -> Zeroizing<[u8; CODE_BYTES]> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut code = Zeroizing::new([0; CODE_BYTES]);
        code[..CODE_PREFIX.len()].copy_from_slice(CODE_PREFIX);
        for (index, byte) in self.0.iter().copied().enumerate() {
            code[CODE_PREFIX.len() + index * 2] = DIGITS[(byte >> 4) as usize];
            code[CODE_PREFIX.len() + index * 2 + 1] = DIGITS[(byte & 15) as usize];
        }
        code
    }
}

/// Authenticated restored DATA, never a persisted source, old record id or
/// previous approval. The existing vault owner must create a NEW record and
/// explicitly assess/bind it. No saved authorization crosses this format.
pub(crate) struct ImportedBackup {
    pub(crate) descriptor: format::Descriptor,
    pub(crate) fields: Fields,
    plaintext: Zeroizing<Vec<u8>>,
    file: Option<Range<usize>>,
}
impl ImportedBackup {
    pub(crate) fn file(&self) -> Option<&[u8]> { self.file.as_ref().map(|range| &self.plaintext[range.clone()]) }
    /// Compare the complete authenticated NEW readback to this SAME restored
    /// input, without serializing or copying any private scalar/file. Record
    /// and fresh revision identity remain the native import owner's checks.
    pub(crate) fn matches_authenticated_readback(&self, record: &super::AuthenticatedRecord) -> bool {
        let expected = &self.descriptor;
        let actual = &record.descriptor;
        expected.kind == actual.kind && expected.label == actual.label
            && expected.presence() == actual.presence() && expected.has_file() == actual.has_file()
            && self.fields.vault_kind() == expected.kind && record.fields.vault_kind() == expected.kind
            && crate::asset_commands::field_names(expected.kind).iter().all(|name|
                self.fields.borrow_value(name) == record.fields.borrow_value(name))
            && self.file() == record.file.as_ref().map(super::StoredBytes::bytes)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.plaintext.capacity().checked_add(self.descriptor.retained_bytes().ok()?)?
            .checked_add(self.fields.retained_bytes()?)?.checked_add(std::mem::size_of::<Self>())
    }
}

fn aad(header: &[u8]) -> Result<[u8; DOMAIN.len() + HEADER_BYTES]> {
    if header.len() != HEADER_BYTES { return Err(Error::Format); }
    let mut aad = [0; DOMAIN.len() + HEADER_BYTES];
    aad[..DOMAIN.len()].copy_from_slice(DOMAIN);
    aad[DOMAIN.len()..].copy_from_slice(header);
    Ok(aad)
}
fn allocate(length: usize, already_owned: usize, allowance: usize) -> Result<Zeroizing<Vec<u8>>> {
    capacity(length.checked_add(already_owned).ok_or(Error::Bounds)?, allowance)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length).map_err(|_| Error::Allocation)?;
    capacity(bytes.capacity().checked_add(already_owned).ok_or(Error::Bounds)?, allowance)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

/// Call only after the original owner has authenticated/rechecked the selected
/// full stored payload and admitted export. `allowance` is the owner's free
/// working allocation, excluding the borrowed payload/Fields/descriptor.
pub(crate) fn export(descriptor: &format::Descriptor, fields: &Fields, file: Option<&[u8]>, allowance: usize)
    -> Result<ExportedBackup> {
    export_with(descriptor, fields, file, allowance, &mut OsEntropy)
}
fn export_with(descriptor: &format::Descriptor, fields: &Fields, file: Option<&[u8]>, allowance: usize,
    random: &mut impl Entropy) -> Result<ExportedBackup> {
    capacity(0, allowance)?;
    if descriptor.kind != fields.vault_kind() || descriptor.presence() != fields.vault_presence()
        || descriptor.has_file() != file.is_some() { return Err(Error::Format); }
    let file_length = file.map_or(0, <[u8]>::len);
    match (descriptor.kind.file(), file) {
        (Some(kind), Some(_)) if file_length <= asset_source::material_limit(kind) => {},
        (None, None) => {}, _ => return Err(Error::Bounds),
    }
    let mut count = ScalarCount(0);
    fields.write_vault_scalars(&mut count).map_err(|_| Error::Bounds)?;
    let scalars = count.0;
    let descriptor_bytes = Zeroizing::new(descriptor.encode()?);
    let plaintext_length = 4usize.checked_add(descriptor_bytes.len()).and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(scalars)).and_then(|n| n.checked_add(file_length))
        .filter(|n| *n <= PLAIN_LIMIT).ok_or(Error::Bounds)?;
    let length = HEADER_BYTES.checked_add(plaintext_length).and_then(|n| n.checked_add(TAG_BYTES)).ok_or(Error::Bounds)?;
    let mut bytes = allocate(length, descriptor_bytes.capacity(), allowance)?;
    let recovery = RecoveryCode(random_key(random)?);
    let nonce = nonce(random)?;
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&SUITE.to_le_bytes());
    bytes[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&(plaintext_length as u64).to_le_bytes());
    bytes[24..48].copy_from_slice(&nonce);
    let descriptor_end = HEADER_BYTES + 4 + descriptor_bytes.len();
    bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&(descriptor_bytes.len() as u32).to_le_bytes());
    bytes[HEADER_BYTES + 4..descriptor_end].copy_from_slice(&descriptor_bytes);
    bytes[descriptor_end..descriptor_end + 4].copy_from_slice(&(scalars as u32).to_le_bytes());
    bytes[descriptor_end + 4..descriptor_end + 8].copy_from_slice(&(file_length as u32).to_le_bytes());
    let scalar_start = descriptor_end + 8;
    let file_start = scalar_start + scalars;
    let mut writer = SliceWriter { bytes: &mut bytes[scalar_start..file_start], written: 0 };
    fields.write_vault_scalars(&mut writer).map_err(|_| Error::Format)?;
    if writer.written != scalars { return Err(Error::Format); }
    let tag_start = HEADER_BYTES + plaintext_length;
    if let Some(file) = file { bytes[file_start..tag_start].copy_from_slice(file); }
    let authenticated = aad(&bytes[..HEADER_BYTES])?;
    let nonce = XNonce::try_from(nonce.as_slice()).map_err(|_| Error::Format)?;
    let tag = cipher(&recovery.0[..])?.encrypt_inout_detached(&nonce, &authenticated,
        (&mut bytes[HEADER_BYTES..tag_start]).into()).map_err(|_| Error::Authentication)?;
    bytes[tag_start..].copy_from_slice(tag.as_slice());
    Ok(ExportedBackup { encrypted: std::mem::take(&mut *bytes), recovery })
}

/// Takes ownership of bounded ciphertext, authenticates the ENTIRE envelope
/// before any payload/descriptor parsing, and keeps decrypted backing private.
/// A bad code and a modified payload share the same Authentication error.
pub(crate) fn import(encrypted: Vec<u8>, recovery: RecoveryCode, allowance: usize) -> Result<ImportedBackup> {
    let mut bytes = Zeroizing::new(encrypted);
    capacity(bytes.capacity(), allowance)?;
    if !(HEADER_BYTES + 4 + 8 + TAG_BYTES..=BACKUP_LIMIT).contains(&bytes.len()) { return Err(Error::Bounds); }
    if &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_le_bytes() || bytes[10..12] != SUITE.to_le_bytes()
        || bytes[12..16] != (HEADER_BYTES as u32).to_le_bytes() { return Err(Error::Format); }
    let plaintext_length = u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| Error::Format)?);
    let plaintext_length = usize::try_from(plaintext_length).map_err(|_| Error::Bounds)?;
    if plaintext_length > PLAIN_LIMIT || plaintext_length.checked_add(HEADER_BYTES + TAG_BYTES) != Some(bytes.len()) {
        return Err(Error::Bounds);
    }
    let tag_start = HEADER_BYTES + plaintext_length;
    let authenticated = aad(&bytes[..HEADER_BYTES])?;
    let nonce = XNonce::try_from(&bytes[24..48]).map_err(|_| Error::Format)?;
    let tag = Tag::try_from(&bytes[tag_start..]).map_err(|_| Error::Format)?;
    cipher(&recovery.0[..])?.decrypt_inout_detached(&nonce, &authenticated,
        (&mut bytes[HEADER_BYTES..tag_start]).into(), &tag).map_err(|_| Error::Authentication)?;
    // No parsing above this point depends on unauthenticated plaintext.
    let descriptor_length = u32::from_le_bytes(bytes[HEADER_BYTES..HEADER_BYTES + 4].try_into().map_err(|_| Error::Format)?) as usize;
    if descriptor_length == 0 || descriptor_length > format::DESCRIPTOR_LIMIT { return Err(Error::Bounds); }
    let payload_start = (HEADER_BYTES + 4).checked_add(descriptor_length).filter(|n| *n <= tag_start).ok_or(Error::Bounds)?;
    let descriptor = format::Descriptor::decode(&bytes[HEADER_BYTES + 4..payload_start])?;
    let (fields, file) = decode_payload(&descriptor, &bytes[payload_start..tag_start])?;
    let file = file.map(|range| range.start + payload_start..range.end + payload_start);
    let restored = ImportedBackup { descriptor, fields, plaintext: bytes, file };
    capacity(restored.retained_bytes().ok_or(Error::Bounds)?, allowance)?;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_commands::{self as commands, Kind};
    const ALLOWANCE: usize = format::WORKING_BYTES;
    struct Fixed { call: u8, fail: Option<u8> }
    impl Entropy for Fixed {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<()> {
            self.call += 1;
            if self.fail == Some(self.call) { return Err(Error::Random); }
            bytes.fill(self.call); Ok(())
        }
    }
    fn material() -> (format::Descriptor, Fields) {
        (format::Descriptor::new(Kind::AndroidKeystore, Some("Synthetic upload key".into()), vec![true; 3], true).unwrap(),
         commands::own_fields(Kind::AndroidKeystore, &serde_json::json!({
             "storePassword":"synthetic-store", "keyAlias":"synthetic-upload", "keyPassword":"synthetic-key"
         })).ok().unwrap())
    }
    fn backup() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        let (descriptor, fields) = material();
        let backup = export_with(&descriptor, &fields, Some(b"synthetic-not-a-real-key"), ALLOWANCE,
            &mut Fixed { call: 17, fail: None }).unwrap();
        backup.deliver(|bytes, code| (bytes.to_vec(), Zeroizing::new(code.to_vec())))
    }
    #[test]
    fn restore_needs_only_backup_and_code_not_original_vault_or_keychain() {
        let (bytes, code) = backup();
        for value in [b"synthetic-store".as_slice(), b"synthetic-key", b"synthetic-not-a-real-key", code.as_slice()] {
            assert!(!bytes.windows(value.len()).any(|window| window == value));
        }
        let restored = import(bytes, RecoveryCode::parse(&code).unwrap(), ALLOWANCE).unwrap();
        assert!(restored.descriptor.kind == Kind::AndroidKeystore);
        assert_eq!(restored.fields.borrow_value("keyAlias"), Some("synthetic-upload"));
        assert_eq!(restored.file(), Some(b"synthetic-not-a-real-key".as_slice()));
    }
    #[test]
    fn wrong_code_nonce_or_ciphertext_never_returns_plaintext() {
        let (bytes, code) = backup();
        let mut wrong = code.to_vec(); let last = wrong.len() - 1; wrong[last] = if wrong[last] == b'a' { b'b' } else { b'a' };
        assert!(matches!(import(bytes.clone(), RecoveryCode::parse(&wrong).unwrap(), ALLOWANCE), Err(Error::Authentication)));
        for at in [24, 47, HEADER_BYTES, bytes.len() / 2, bytes.len() - 1] {
            let mut changed = bytes.clone(); changed[at] ^= 1;
            assert!(matches!(import(changed, RecoveryCode::parse(&code).unwrap(), ALLOWANCE), Err(Error::Authentication)));
        }
    }
    #[test]
    fn header_truncation_wrong_suite_trailing_data_and_bounds_fail_closed() {
        let (bytes, code) = backup();
        for at in [0, 7, 8, 10, 12, 16, 23] {
            let mut changed = bytes.clone(); changed[at] ^= 1;
            assert!(import(changed, RecoveryCode::parse(&code).unwrap(), ALLOWANCE).is_err());
        }
        for length in [0, 7, HEADER_BYTES - 1, HEADER_BYTES, bytes.len() - 1] {
            assert!(import(bytes[..length].to_vec(), RecoveryCode::parse(&code).unwrap(), ALLOWANCE).is_err());
        }
        let mut appended = bytes.clone(); appended.push(0);
        assert!(import(appended, RecoveryCode::parse(&code).unwrap(), ALLOWANCE).is_err());
        assert!(matches!(import(bytes, RecoveryCode::parse(&code).unwrap(), 0), Err(Error::Bounds)));
        let mut advertised = backup().0; advertised[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(import(advertised, RecoveryCode::parse(&code).unwrap(), ALLOWANCE), Err(Error::Bounds)));
    }
    #[test]
    fn recovery_code_is_fixed_random_key_not_password_or_passphrase() {
        for code in [b"a memorable password".as_slice(), b"", b"mrk-recovery-v1-0000", b"MRK-RECOVERY-V1-"] {
            assert!(RecoveryCode::parse(code).is_err());
        }
        let mut zero = CODE_PREFIX.to_vec(); zero.extend_from_slice(&[b'0'; 64]);
        assert!(RecoveryCode::parse(&zero).is_err());
        let (_, mut valid) = backup(); valid[CODE_PREFIX.len()] = b'G';
        assert!(RecoveryCode::parse(&valid).is_err());
    }
    #[test]
    fn each_export_uses_new_random_key_and_nonce_and_rng_failure_is_not_fallback() {
        let (descriptor, fields) = material();
        let mut random = Fixed { call: 1, fail: None };
        let one = export_with(&descriptor, &fields, Some(b"synthetic"), ALLOWANCE, &mut random).unwrap();
        let two = export_with(&descriptor, &fields, Some(b"synthetic"), ALLOWANCE, &mut random).unwrap();
        assert_ne!(one.encrypted(), two.encrypted());
        assert_ne!(one.recovery.encoded().as_slice(), two.recovery.encoded().as_slice());
        assert_ne!(&one.encrypted()[24..48], &two.encrypted()[24..48]);
        for call in [1, 2] {
            assert!(matches!(export_with(&descriptor, &fields, Some(b"synthetic"), ALLOWANCE,
                &mut Fixed { call: 0, fail: Some(call) }), Err(Error::Random)));
        }
        assert!(matches!(export_with(&descriptor, &fields, Some(b"synthetic"), 0,
            &mut Fixed { call: 0, fail: None }), Err(Error::Bounds)));
    }
    #[test]
    fn four_field_current_contact_kind_restores_and_reseals_in_a_new_vault_record() {
        // Synthetic scalar fixture only, no actual contact/account or signing
        // key. Exercise the REAL enabled-kind field codec, not a shadow parser.
        let descriptor = format::Descriptor::new(Kind::AppleReviewContact, None, vec![true; 4], false).unwrap();
        let fields = commands::own_fields(Kind::AppleReviewContact, &serde_json::json!({
            "contactFirstName":"Synthetic", "contactLastName":"Fixture",
            "contactEmail":"fixture@example.invalid", "contactPhone":"+12025550123"
        })).ok().unwrap();
        let backup = export_with(&descriptor, &fields, None, ALLOWANCE, &mut Fixed { call: 10, fail: None }).unwrap();
        let restored = backup.deliver(|bytes, code| import(bytes.to_vec(), RecoveryCode::parse(code).unwrap(), ALLOWANCE)).unwrap();
        assert_eq!(restored.fields.borrow_value("contactPhone"), Some("+12025550123"));
        let id = |byte| format::Id::from_bytes([byte; 16]).unwrap();
        let identity = format::Identity::new(id(40), id(41)).unwrap();
        let key = super::super::lifecycle_data_key(identity);
        let sealed = key.seal_record_with(id(42), None, &restored.descriptor, &restored.fields, restored.file(), ALLOWANCE,
            &mut Fixed { call: 50, fail: None }).unwrap();
        assert_eq!(sealed.revision().counter, 1);
        let opened = key.open_record(sealed.bytes().to_vec(), ALLOWANCE).unwrap();
        assert!(opened.record == id(42));
        assert_eq!(opened.fields.borrow_value("contactEmail"), Some("fixture@example.invalid"));
        assert!(opened.file.is_none());
        assert!(restored.matches_authenticated_readback(&opened));
    }
    #[test]
    fn complete_new_readback_matches_every_descriptor_scalar_and_file() {
        let (bytes, code) = backup();
        let restored = import(bytes, RecoveryCode::parse(&code).unwrap(), ALLOWANCE).unwrap();
        let id = |byte| format::Id::from_bytes([byte; 16]).unwrap();
        let key = super::super::lifecycle_data_key(format::Identity::new(id(40), id(41)).unwrap());
        let seal_open = |descriptor: &format::Descriptor, fields: &Fields, file: Option<&[u8]>| {
            let sealed = key.seal_record_with(id(42), None, descriptor, fields, file, ALLOWANCE,
                &mut Fixed { call: 50, fail: None }).unwrap();
            key.open_record(sealed.bytes().to_vec(), ALLOWANCE).unwrap()
        };
        let opened = seal_open(&restored.descriptor, &restored.fields, restored.file());
        assert!(restored.matches_authenticated_readback(&opened));
        for name in commands::field_names(Kind::AndroidKeystore) {
            let mut values = serde_json::json!({"storePassword":"synthetic-store",
                "keyAlias":"synthetic-upload", "keyPassword":"synthetic-key"});
            values[*name] = serde_json::json!("different-synthetic-value");
            let changed = commands::own_fields(Kind::AndroidKeystore, &values).ok().unwrap();
            let opened = seal_open(&restored.descriptor, &changed, restored.file());
            assert!(!restored.matches_authenticated_readback(&opened));
        }
        let changed_label = format::Descriptor::new(Kind::AndroidKeystore,
            Some("Different synthetic label".into()), vec![true; 3], true).unwrap();
        assert!(!restored.matches_authenticated_readback(&seal_open(&changed_label, &restored.fields, restored.file())));
        assert!(!restored.matches_authenticated_readback(&seal_open(&restored.descriptor,
            &restored.fields, Some(b"different-synthetic-file"))));
        let changed_presence = format::Descriptor::new(Kind::AndroidKeystore,
            restored.descriptor.label.clone(), vec![true, false, true], true).unwrap();
        let absent_alias = commands::own_fields(Kind::AndroidKeystore, &serde_json::json!({
            "storePassword":"synthetic-store", "keyAlias":null, "keyPassword":"synthetic-key"
        })).ok().unwrap();
        assert!(!restored.matches_authenticated_readback(&seal_open(&changed_presence, &absent_alias, restored.file())));
    }
    #[test]
    fn descriptor_success_does_not_authenticate_persisted_backup_payload() {
        let (bytes, code) = backup();
        let restored = import(bytes, RecoveryCode::parse(&code).unwrap(), ALLOWANCE).unwrap();
        let id = |byte| format::Id::from_bytes([byte; 16]).unwrap();
        let key = super::super::lifecycle_data_key(format::Identity::new(id(40), id(41)).unwrap());
        let sealed = key.seal_record_with(id(42), None, &restored.descriptor, &restored.fields,
            restored.file(), ALLOWANCE, &mut Fixed { call: 50, fail: None }).unwrap();
        let descriptor_end = 216 + sealed.prefix.descriptor_length + 16;
        let mut changed = sealed.bytes().to_vec();
        let last = changed.len() - 1; changed[last] ^= 1;
        assert!(key.open_descriptor(&changed[..descriptor_end], ALLOWANCE).is_ok());
        assert!(matches!(key.open_record(changed, ALLOWANCE), Err(Error::Authentication)));
    }
}
