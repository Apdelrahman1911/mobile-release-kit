//! Fixed password/private-output codec for one original P12 packaging attempt.
//! No native binding, trust, assignment, store writer or public byte getter.
use super::{Fields, Kind};
use crate::vault_crypto as crypto;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const MAGIC: &[u8] = b"MRK-APPLE-P12/1\n";
pub(crate) const PASSWORD_BYTES: usize = 64;
pub(crate) const P12_BYTES: usize = 1024 * 1024;
pub(crate) const HEADER_BYTES: usize = MAGIC.len() + 4 + 64;
pub(crate) const PRIVATE_FRAME_BYTES: usize = HEADER_BYTES + P12_BYTES;
pub(crate) const PASSWORD_BACKING_BYTES: usize = std::mem::size_of::<AppleP12Password>()
    + std::mem::size_of::<Option<String>>()
    + PASSWORD_BYTES;

/// Comparison DATA only. The parent separately requires its genuine same-key
/// certificate-policy binding, original raw receiver and all native joins.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppleP12OutputMetadata {
    pub(crate) frame_bytes: usize,
    pub(crate) frame_sha256: [u8; 32],
    pub(crate) p12_bytes: usize,
    pub(crate) p12_sha256: [u8; 32],
    pub(crate) leaf_sha256: [u8; 32],
    pub(crate) spki_sha256: [u8; 32],
}

fn private_body(frame: &[u8]) -> Result<&[u8], crypto::Error> {
    if frame.len() <= HEADER_BYTES || frame.len() > PRIVATE_FRAME_BYTES || !frame.starts_with(MAGIC)
    {
        return Err(crypto::Error::Bounds);
    }
    let length = u32::from_be_bytes(
        frame[MAGIC.len()..MAGIC.len() + 4]
            .try_into()
            .map_err(|_| crypto::Error::Format)?,
    ) as usize;
    if length == 0 || length > P12_BYTES || HEADER_BYTES.checked_add(length) != Some(frame.len()) {
        return Err(crypto::Error::Format);
    }
    Ok(&frame[HEADER_BYTES..])
}

pub(crate) fn output_metadata(frame: &[u8]) -> Result<AppleP12OutputMetadata, crypto::Error> {
    let body = private_body(frame)?;
    let hashes = MAGIC.len() + 4;
    Ok(AppleP12OutputMetadata {
        frame_bytes: frame.len(),
        frame_sha256: Sha256::digest(frame).into(),
        p12_bytes: body.len(),
        p12_sha256: Sha256::digest(body).into(),
        leaf_sha256: frame[hashes..hashes + 32]
            .try_into()
            .map_err(|_| crypto::Error::Format)?,
        spki_sha256: frame[hashes + 32..HEADER_BYTES]
            .try_into()
            .map_err(|_| crypto::Error::Format)?,
    })
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

/// Original existing zeroizing Fields, no Clone/Debug/serde/password getter.
/// The destination retains this same object through writer/save/unknown paths.
pub(crate) struct AppleP12Password {
    fields: Fields,
}
impl AppleP12Password {
    pub(crate) fn generate() -> Result<Self, crypto::Error> {
        Self::generate_with(&mut OsEntropy)
    }
    fn generate_with(random: &mut impl Entropy) -> Result<Self, crypto::Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        random.fill(&mut entropy[..])?; // One attempt, never a fallback/retry.
        if entropy.iter().all(|byte| *byte == 0) {
            return Err(crypto::Error::Random);
        }
        let mut text = Zeroizing::new(String::new());
        text.try_reserve_exact(PASSWORD_BYTES)
            .map_err(|_| crypto::Error::Allocation)?;
        if text.capacity() != PASSWORD_BYTES {
            return Err(crypto::Error::Bounds);
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in entropy.iter() {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(1)
            .map_err(|_| crypto::Error::Allocation)?;
        if values.capacity() != 1 {
            return Err(crypto::Error::Bounds);
        }
        values.push(Some(std::mem::take(&mut *text)));
        Ok(Self {
            fields: Fields {
                kind: Kind::AppleP12,
                values,
            },
        })
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.fields.retained_bytes()?)
    }

    /// Fixed native material child only; no FnOnce, raw getter or serde copy.
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn write_to(
        &self,
        writer: &mut crate::saved_command_owner::PrivateAppleP12Input,
    ) -> Result<(), crate::error::BridgeError> {
        let password = self
            .fields
            .borrow_value("password")
            .filter(|value| value.len() == PASSWORD_BYTES)
            .ok_or_else(crate::error::BridgeError::protocol)?;
        writer.password(self, password.as_bytes())
    }

    /// Cryptographic DATA only. The real native P12SavePermit lends the SAME
    /// original private frame after joined producer/policy/source validation.
    pub(crate) fn seal_new(
        &self,
        reserved: &mut crypto::ReservedAppleP12,
        key: &crypto::VaultKey,
        frame: &[u8],
        allowance: usize,
    ) -> Result<crypto::SealedRecord, crypto::Error> {
        // Reservation burns even on bad framing: do not permit a second seal
        // by correcting a failed/private output argument after an attempt.
        reserved.seal_p12(key, &self.fields, private_body(frame), allowance)
    }
    pub(crate) fn matches_authenticated_readback(
        &self,
        record: &crypto::AuthenticatedRecord,
        frame: &[u8],
    ) -> bool {
        record.descriptor.kind == Kind::AppleP12
            && record.descriptor.label.is_none()
            && record.descriptor.has_file()
            && record.descriptor.presence() == [true]
            && record.fields.vault_kind() == Kind::AppleP12
            && record.fields.vault_presence() == [true]
            && self.fields.borrow_value("password").is_some()
            && self.fields.borrow_value("password") == record.fields.borrow_value("password")
            && private_body(frame).is_ok_and(|body| {
                record
                    .file
                    .as_ref()
                    .is_some_and(|file| file.bytes() == body)
            })
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    struct Fixed {
        calls: usize,
        fail: bool,
        zero: bool,
    }
    impl Entropy for Fixed {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crypto::Error> {
            self.calls += 1;
            assert_eq!(bytes.len(), 32);
            bytes.fill(if self.zero { 0 } else { 19 });
            if self.fail {
                Err(crypto::Error::Random)
            } else {
                Ok(())
            }
        }
    }
    fn frame() -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(4u32.to_be_bytes());
        out.extend([23; 32]);
        out.extend([24; 32]);
        out.extend(b"DATA"); // Not a PKCS12 or a native certificate receipt.
        out
    }
    #[test]
    fn p12_password_is_one_fixed_entropy_attempt_in_existing_private_fields() {
        let mut random = Fixed {
            calls: 0,
            fail: false,
            zero: false,
        };
        let password = AppleP12Password::generate_with(&mut random).unwrap();
        assert_eq!(random.calls, 1);
        assert!(password.fields.vault_kind() == Kind::AppleP12);
        assert!(password
            .fields
            .borrow_value("password")
            .is_some_and(|text| text == "13".repeat(32)));
        assert_eq!(password.retained_bytes(), Some(PASSWORD_BACKING_BYTES));
        for (fail, zero) in [(true, false), (false, true)] {
            let mut random = Fixed {
                calls: 0,
                fail,
                zero,
            };
            assert!(AppleP12Password::generate_with(&mut random).is_err());
            assert_eq!(random.calls, 1);
        }
    }
    #[test]
    fn p12_private_output_is_borrowed_and_strict_before_any_copy() {
        let original = frame();
        let body = private_body(&original).unwrap();
        assert_eq!(body.as_ptr(), original[HEADER_BYTES..].as_ptr());
        let metadata = output_metadata(&original).unwrap();
        assert_eq!(metadata.p12_bytes, 4);
        assert_eq!(metadata.leaf_sha256, [23; 32]);
        assert_eq!(metadata.spki_sha256, [24; 32]);
        assert_eq!(
            metadata.p12_sha256,
            <[u8; 32]>::from(Sha256::digest(b"DATA"))
        );
        for cut in [0, MAGIC.len(), HEADER_BYTES, original.len() - 1] {
            assert!(output_metadata(&original[..cut]).is_err());
        }
        let mut bad = original.clone();
        bad.extend(b"trailing");
        assert!(output_metadata(&bad).is_err());
        bad[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(output_metadata(&bad).is_err());
        assert_eq!(original, frame());
    }
}
