//! Fixed private scalars for one explicitly reserved Android upload key.
//!
//! This child of asset_commands constructs the existing zeroizing Fields, not
//! a new credential format. It grants no generation, tool, file or vault access.
//! The original generation owner calls generate only after its durable intent.
use super::{Fields, Kind};
use crate::{vault_crypto as crypto, vault_format as format};
use zeroize::Zeroizing;

pub(crate) const ALIAS: &str = "upload";
pub(crate) const PASSWORD_CHARACTERS: usize = 64;
const RANDOM_BYTES: usize = 32;

/// No Clone/Debug/serde/raw getter. The same fields are borrowed by the original
/// private writer and vault seal; their existing Drop zeroizes owned strings.
pub(crate) struct UploadKeySecrets {
    fields: Fields,
}

trait Entropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crypto::Error>;
}
struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crypto::Error> {
        getrandom::fill(bytes).map_err(|_| crypto::Error::Random)
    }
}

fn hexadecimal(bytes: &[u8]) -> Result<Zeroizing<String>, crypto::Error> {
    if bytes.len() != RANDOM_BYTES {
        return Err(crypto::Error::Bounds);
    }
    let mut text = Zeroizing::new(String::new());
    text.try_reserve_exact(PASSWORD_CHARACTERS)
        .map_err(|_| crypto::Error::Allocation)?;
    if text.capacity() != PASSWORD_CHARACTERS {
        return Err(crypto::Error::Bounds);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(text)
}

impl UploadKeySecrets {
    pub(crate) fn generate() -> Result<Self, crypto::Error> {
        Self::generate_with(&mut OsEntropy)
    }

    fn generate_with(random: &mut impl Entropy) -> Result<Self, crypto::Error> {
        // Keep the initial, partially filled and error-path entropy buffers
        // zeroizing. There is no user-password mode, fixed seed or retry loop.
        let mut bytes = Zeroizing::new([0u8; RANDOM_BYTES * 2]);
        random.fill(&mut bytes[..])?;
        let (store, key) = bytes.split_at(RANDOM_BYTES);
        if store.iter().all(|byte| *byte == 0) || key.iter().all(|byte| *byte == 0) || store == key
        {
            return Err(crypto::Error::Random);
        }
        let mut store = hexadecimal(store)?;
        let mut key = hexadecimal(key)?;
        let mut alias = Zeroizing::new(String::new());
        alias
            .try_reserve_exact(ALIAS.len())
            .map_err(|_| crypto::Error::Allocation)?;
        if alias.capacity() != ALIAS.len() {
            return Err(crypto::Error::Bounds);
        }
        alias.push_str(ALIAS);
        let mut values = Vec::new();
        values
            .try_reserve_exact(3)
            .map_err(|_| crypto::Error::Allocation)?;
        if values.capacity() != 3 {
            return Err(crypto::Error::Bounds);
        }
        values.push(Some(std::mem::take(&mut *store)));
        values.push(Some(std::mem::take(&mut *alias)));
        values.push(Some(std::mem::take(&mut *key)));
        Ok(Self {
            fields: Fields {
                kind: Kind::AndroidKeystore,
                values,
            },
        })
    }

    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.fields.retained_bytes()?)
    }

    /// Only the fixed native writer can receive the private segments. That
    /// writer takes the SAME one-use original GO, retains its zeroizing frame
    /// before sending, and never sends these fields to public JSON/status.
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn write_to(
        &self,
        writer: &mut crate::saved_command_owner::PrivateUploadKeyInput,
        go: crate::asset_session::PreparedGenerationGo,
    ) -> Result<(), crate::error::BridgeError> {
        // These strings are created only by generate_with above. No scalar is
        // returned, cloned into a Value or placed in the parent's environment.
        let store = self.fields.borrow_value("storePassword");
        let key = self.fields.borrow_value("keyPassword");
        match (store, key) {
            (Some(store), Some(key))
                if store.len() == PASSWORD_CHARACTERS && key.len() == PASSWORD_CHARACTERS =>
            {
                writer.passwords(go, store.as_bytes(), key.as_bytes())
            }
            _ => Err(crate::error::BridgeError::protocol()),
        }
    }

    /// The native candidate, not this cryptographic helper, proves the fixed
    /// generated JKS/current tool and enforces its once-only seal transition.
    /// This always seals a NEW Android record; there is no replacement arm.
    pub(crate) fn seal_new_fields(
        &self,
        key: &crypto::VaultKey,
        record: format::Id,
        jks: &[u8],
        allowance: usize,
    ) -> Result<crypto::SealedRecord, crypto::Error> {
        let descriptor = format::Descriptor::new(Kind::AndroidKeystore, None, vec![true; 3], true)?;
        key.seal_record(
            record,
            None,
            &descriptor,
            &self.fields,
            Some(jks),
            allowance,
        )
    }

    /// Private equality only. The actual native candidate additionally matches
    /// its exact generated JKS and sealed full random record revision; callers
    /// must authenticate this record using the same original current VaultKey.
    pub(crate) fn matches_fields(&self, record: &crypto::AuthenticatedRecord) -> bool {
        record.descriptor.kind == Kind::AndroidKeystore
            && record.descriptor.has_file()
            && record.descriptor.presence() == [true; 3]
            && record.fields.vault_kind() == Kind::AndroidKeystore
            && ["storePassword", "keyAlias", "keyPassword"]
                .into_iter()
                .all(|name| {
                    record.fields.borrow_value(name).is_some()
                        && record.fields.borrow_value(name) == self.fields.borrow_value(name)
                })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureEntropy {
        fail: bool,
        same: bool,
        calls: usize,
    }
    impl Entropy for FixtureEntropy {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crypto::Error> {
            self.calls += 1;
            assert_eq!(bytes.len(), 64);
            bytes[..32].fill(11);
            if self.fail {
                return Err(crypto::Error::Random);
            }
            bytes[32..].fill(if self.same { 11 } else { 12 });
            Ok(())
        }
    }
    fn fixture() -> UploadKeySecrets {
        UploadKeySecrets::generate_with(&mut FixtureEntropy {
            fail: false,
            same: false,
            calls: 0,
        })
        .ok()
        .unwrap()
    }
    fn id(byte: u8) -> format::Id {
        format::Id::from_bytes([byte; 16]).unwrap()
    }

    #[test]
    fn fixed_fields_use_two_independent_full_length_synthetic_entropy_segments() {
        let secrets = fixture();
        assert_eq!(secrets.fields.vault_kind(), Kind::AndroidKeystore);
        assert_eq!(secrets.fields.borrow_value("keyAlias"), Some(ALIAS));
        assert_eq!(
            secrets.fields.borrow_value("storePassword"),
            Some("0b".repeat(32).as_str())
        );
        assert_eq!(
            secrets.fields.borrow_value("keyPassword"),
            Some("0c".repeat(32).as_str())
        );
        assert_eq!(secrets.fields.vault_presence(), vec![true; 3]);
        assert_eq!(
            secrets.fields.byte_count(),
            PASSWORD_CHARACTERS * 2 + ALIAS.len()
        );
        assert!(secrets.retained_bytes().is_some_and(|bytes| bytes < 1024));
    }

    #[test]
    fn random_failure_or_repeated_segments_return_no_fields_and_never_retry() {
        for (fail, same) in [(true, false), (false, true)] {
            let mut random = FixtureEntropy {
                fail,
                same,
                calls: 0,
            };
            assert!(matches!(
                UploadKeySecrets::generate_with(&mut random),
                Err(crypto::Error::Random)
            ));
            assert_eq!(random.calls, 1);
        }
    }

    #[test]
    fn existing_cipher_roundtrip_checks_actual_full_fields_not_descriptor_presence() {
        // Synthetic arbitrary file DATA, NOT a generated/valid JKS or a native
        // keytool receipt. This tests the real vault codec + private equality.
        let identity = format::Identity::new(id(1), id(2)).unwrap();
        let key = crypto::lifecycle_data_key(identity);
        let secrets = fixture();
        let synthetic_file = vec![0x5a; 64 * 1024]; // The generated protocol's maximum JKS size, not a JKS.
        let allowance = 1024 * 1024; // Parent's fixed, source-derived crypto workspace.
        let sealed = secrets
            .seal_new_fields(&key, id(3), &synthetic_file, allowance)
            .unwrap();
        assert_eq!(sealed.revision().counter, 1);
        assert!(sealed.bytes().len() + crypto::CONTROL_BYTES <= allowance);
        let mut opened = key.open_record(sealed.bytes().to_vec(), allowance).unwrap();
        assert!(secrets.matches_fields(&opened));
        assert_eq!(opened.file.as_ref().unwrap().bytes(), synthetic_file);
        opened.fields.values[0] = Some("different-synthetic-password".into());
        assert!(!secrets.matches_fields(&opened));
    }
}
