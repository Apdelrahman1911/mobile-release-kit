//! Private scalar backing for the fixed local Apple Distribution key producer.
//!
//! This is storage/encoding DATA, not key generation, native validation, a
//! credential assessment, a CSR export capability or a renderer input format.
//! The SAME Apple owner retains the original private receive before calling
//! this bounded decoder. Its NEW/save/readback and durable journal ACK must
//! succeed before a separate native handoff can disclose the public CSR.
use super::{AssetError, Fields, Kind, Reason};
use crate::vault_crypto as crypto;
use der_07::pem::{Base64Decoder, Base64Encoder, Decoder, LineEnding};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const MAGIC: &[u8] = b"MRK-APPLE-DISTRIBUTION-KEY/1\n";
pub(crate) const KEY_DER_LIMIT: usize = 3 * 1024;
pub(crate) const CSR_PEM_LIMIT: usize = 4096;
pub(crate) const SPKI_DER_LIMIT: usize = 1024;
const KEY_TEXT_LIMIT: usize = 4 * ((KEY_DER_LIMIT + 2) / 3);
const SPKI_TEXT_LIMIT: usize = 4 * ((SPKI_DER_LIMIT + 2) / 3);
const CSR_DER_LIMIT: usize = 3 * 1024;
pub(crate) const PRIVATE_FRAME_LIMIT: usize =
    MAGIC.len() + 12 + KEY_DER_LIMIT + CSR_PEM_LIMIT + SPKI_DER_LIMIT;
const FIELD_NAMES: [&str; 3] = ["privateKeyPkcs8Base64", "csrPem", "publicKeySpkiBase64"];
const CELLS: usize = 3 * std::mem::size_of::<Option<String>>();
const FIELD_BACKING_LIMIT: usize = KEY_TEXT_LIMIT + CSR_PEM_LIMIT + SPKI_TEXT_LIMIT + CELLS;
// Original raw receive + all resulting scalar backing + the largest live
// decode/re-encode scratch + fixed wrapper. An original native census also
// charges the enclosing receiver and its actual allocation capacity. This is
// not a process/RSS bound or a claim that OpenSSL/Ruby heaps were erased.
pub(crate) const CONSTRUCTION_BYTES: usize = PRIVATE_FRAME_LIMIT
    + FIELD_BACKING_LIMIT
    + KEY_DER_LIMIT
    + 2 * KEY_TEXT_LIMIT
    + 2 * CSR_PEM_LIMIT
    + std::mem::size_of::<AppleDistributionKeyFields>();

/// Only nonsecret comparisons. A digest is not key custody or an assessment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppleDistributionKeyMetadata {
    pub(crate) csr_sha256: [u8; 32],
    pub(crate) public_key_sha256: [u8; 32],
}

/// No Clone/Debug/serde, raw scalar getter or public-CSR accessor. The original
/// Fields Drop zeroizes each owned scalar on every success/error retirement.
pub(crate) struct AppleDistributionKeyFields {
    fields: Fields,
    metadata: AppleDistributionKeyMetadata,
}

fn bytes(length: usize, maximum: usize) -> Result<Zeroizing<Vec<u8>>, crypto::Error> {
    if length == 0 || length > maximum {
        return Err(crypto::Error::Bounds);
    }
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(length)
        .map_err(|_| crypto::Error::Allocation)?;
    if out.capacity() > maximum {
        return Err(crypto::Error::Bounds);
    }
    out.resize(length, 0);
    Ok(out)
}

fn text(value: &str, maximum: usize) -> Result<Zeroizing<String>, crypto::Error> {
    if value.is_empty() || value.len() > maximum {
        return Err(crypto::Error::Bounds);
    }
    let mut out = Zeroizing::new(String::new());
    out.try_reserve_exact(value.len())
        .map_err(|_| crypto::Error::Allocation)?;
    if out.capacity() > maximum {
        return Err(crypto::Error::Bounds);
    }
    out.push_str(value);
    Ok(out)
}

fn base64(raw: &[u8], maximum: usize) -> Result<Zeroizing<String>, crypto::Error> {
    if raw.is_empty() || raw.len() > maximum {
        return Err(crypto::Error::Bounds);
    }
    let length = raw
        .len()
        .checked_add(2)
        .and_then(|n| (n / 3).checked_mul(4))
        .ok_or(crypto::Error::Bounds)?;
    let maximum = 4 * ((maximum + 2) / 3);
    let mut buffer = bytes(length, maximum)?;
    // Reuse the maintained constant-time Base64 implementation already
    // reexported by our pinned DER/PEM dependency; no new codec/dependency.
    let mut encoder = Base64Encoder::new(&mut buffer).map_err(|_| crypto::Error::Format)?;
    encoder.encode(raw).map_err(|_| crypto::Error::Format)?;
    let encoded = encoder.finish().map_err(|_| crypto::Error::Format)?;
    if encoded.len() != length {
        return Err(crypto::Error::Format);
    }
    text(encoded, maximum)
}

fn decoded_base64(value: &str, maximum: usize) -> Result<Zeroizing<Vec<u8>>, crypto::Error> {
    if !value.is_ascii() || value.is_empty() || value.len() > 4 * ((maximum + 2) / 3) {
        return Err(crypto::Error::Bounds);
    }
    let mut decoder = Base64Decoder::new(value.as_bytes()).map_err(|_| crypto::Error::Format)?;
    let mut out = bytes(decoder.remaining_len(), maximum)?;
    decoder
        .decode(&mut out)
        .map_err(|_| crypto::Error::Format)?;
    if !decoder.is_finished() || base64(&out, maximum)?.as_str() != value {
        return Err(crypto::Error::Format);
    }
    Ok(out)
}

fn csr(value: &str) -> Result<(), crypto::Error> {
    if !value.is_ascii()
        || value.len() > CSR_PEM_LIMIT
        || !value.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n")
        || !value.ends_with("-----END CERTIFICATE REQUEST-----\n")
    {
        return Err(crypto::Error::Format);
    }
    let mut decoder = Decoder::new(value.as_bytes()).map_err(|_| crypto::Error::Format)?;
    if decoder.type_label() != "CERTIFICATE REQUEST" {
        return Err(crypto::Error::Format);
    }
    let mut der = bytes(decoder.remaining_len(), CSR_DER_LIMIT)?;
    decoder
        .decode(&mut der)
        .map_err(|_| crypto::Error::Format)?;
    if !decoder.is_finished() {
        return Err(crypto::Error::Format);
    }
    let length = der_07::pem::encoded_len("CERTIFICATE REQUEST", LineEnding::LF, &der)
        .map_err(|_| crypto::Error::Format)?;
    let mut encoded = bytes(length, CSR_PEM_LIMIT)?;
    if der_07::pem::encode("CERTIFICATE REQUEST", LineEnding::LF, &der, &mut encoded)
        .map_err(|_| crypto::Error::Format)?
        != value
    {
        return Err(crypto::Error::Format);
    }
    // Canonical PEM only. Signature/RSA/SPKI equality is checked by the actual
    // bundled producer, and checked again by a native reuse operation after a
    // restore. Decoding this storage record cannot grant certificate issuance.
    Ok(())
}

fn scalar_fields(mut values: [Zeroizing<String>; 3]) -> Result<Fields, crypto::Error> {
    let mut fields = Fields {
        kind: Kind::AppleDistributionKey,
        values: Vec::new(),
    };
    fields
        .values
        .try_reserve_exact(3)
        .map_err(|_| crypto::Error::Allocation)?;
    if fields.values.capacity() != 3 {
        return Err(crypto::Error::Bounds);
    }
    for value in &mut values {
        fields.values.push(Some(std::mem::take(&mut **value)));
    }
    if fields
        .retained_bytes()
        .is_none_or(|n| n > FIELD_BACKING_LIMIT)
    {
        return Err(crypto::Error::Bounds);
    }
    Ok(fields)
}

impl AppleDistributionKeyFields {
    /// Borrow original private output. Never consumes it, including malformed
    /// lengths, allocation failure or a later native save/journal interruption.
    pub(crate) fn from_private_frame(frame: &[u8]) -> Result<Self, crypto::Error> {
        let header = MAGIC.len() + 12;
        if frame.len() <= header || frame.len() > PRIVATE_FRAME_LIMIT || !frame.starts_with(MAGIC) {
            return Err(crypto::Error::Bounds);
        }
        let length = |index: usize| -> Result<usize, crypto::Error> {
            let begin = MAGIC.len() + index * 4;
            Ok(u32::from_be_bytes(
                frame[begin..begin + 4]
                    .try_into()
                    .map_err(|_| crypto::Error::Format)?,
            ) as usize)
        };
        let lengths = [length(0)?, length(1)?, length(2)?];
        if lengths
            .iter()
            .zip([KEY_DER_LIMIT, CSR_PEM_LIMIT, SPKI_DER_LIMIT])
            .any(|(length, maximum)| *length == 0 || *length > maximum)
        {
            return Err(crypto::Error::Bounds);
        }
        let key_end = header
            .checked_add(lengths[0])
            .ok_or(crypto::Error::Bounds)?;
        let csr_end = key_end
            .checked_add(lengths[1])
            .ok_or(crypto::Error::Bounds)?;
        if csr_end.checked_add(lengths[2]) != Some(frame.len()) {
            return Err(crypto::Error::Format);
        }
        let private = &frame[header..key_end];
        let request =
            std::str::from_utf8(&frame[key_end..csr_end]).map_err(|_| crypto::Error::Format)?;
        let public = &frame[csr_end..];
        csr(request)?;
        let fields = scalar_fields([
            base64(private, KEY_DER_LIMIT)?,
            text(request, CSR_PEM_LIMIT)?,
            base64(public, SPKI_DER_LIMIT)?,
        ])?;
        Ok(Self {
            fields,
            metadata: AppleDistributionKeyMetadata {
                csr_sha256: Sha256::digest(request.as_bytes()).into(),
                public_key_sha256: Sha256::digest(public).into(),
            },
        })
    }

    fn from_storage(value: &Value) -> Result<Self, crypto::Error> {
        let object = value
            .as_object()
            .filter(|o| o.len() == 3 && FIELD_NAMES.iter().all(|name| o.contains_key(*name)))
            .ok_or(crypto::Error::Format)?;
        let get = |name: &str| object[name].as_str().ok_or(crypto::Error::Format);
        let private = get(FIELD_NAMES[0])?;
        let request = get(FIELD_NAMES[1])?;
        let public = get(FIELD_NAMES[2])?;
        // Bounds are checked before any private decoding/allocation. Null,
        // duplicate, unknown and missing keys are also rejected by ScalarSeed.
        if private.len() > KEY_TEXT_LIMIT
            || request.len() > CSR_PEM_LIMIT
            || public.len() > SPKI_TEXT_LIMIT
        {
            return Err(crypto::Error::Bounds);
        }
        drop(decoded_base64(private, KEY_DER_LIMIT)?);
        csr(request)?;
        let public_der = decoded_base64(public, SPKI_DER_LIMIT)?;
        let fields = scalar_fields([
            text(private, KEY_TEXT_LIMIT)?,
            text(request, CSR_PEM_LIMIT)?,
            text(public, SPKI_TEXT_LIMIT)?,
        ])?;
        Ok(Self {
            fields,
            metadata: AppleDistributionKeyMetadata {
                csr_sha256: Sha256::digest(request.as_bytes()).into(),
                public_key_sha256: Sha256::digest(&public_der).into(),
            },
        })
    }

    pub(crate) fn metadata(&self) -> AppleDistributionKeyMetadata {
        self.metadata
    }

    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.fields
            .retained_bytes()?
            .checked_add(std::mem::size_of::<Self>())
    }

    pub(crate) fn matches_authenticated_readback(
        &self,
        record: &crypto::AuthenticatedRecord,
    ) -> bool {
        record.descriptor.kind == Kind::AppleDistributionKey
            && record.descriptor.label.is_none()
            && !record.descriptor.has_file()
            && record.descriptor.presence() == [true; 3]
            && record.file.is_none()
            && record.fields.vault_kind() == Kind::AppleDistributionKey
            && FIELD_NAMES.iter().all(|name| {
                record.fields.borrow_value(name).is_some()
                    && record.fields.borrow_value(name) == self.fields.borrow_value(name)
            })
    }

    /// Only the typed NEW reservation can select this fixed record/revision.
    /// This helper produces encrypted bytes, not a native save receipt.
    pub(crate) fn seal_new(
        &self,
        reserved: &mut crypto::ReservedAppleDistributionKey,
        key: &crypto::VaultKey,
        allowance: usize,
    ) -> Result<crypto::SealedRecord, crypto::Error> {
        reserved.seal_fields(key, &self.fields, allowance)
    }
}

/// Authenticated vault/backup decoding ONLY. The ordinary kind parser and
/// validate_fields/own_fields deliberately remain closed to this new kind.
pub(super) fn stored_fields(value: &Value) -> Result<Fields, AssetError> {
    AppleDistributionKeyFields::from_storage(value)
        .map(|value| value.fields)
        .map_err(|error| {
            AssetError::new(match error {
                crypto::Error::Allocation | crypto::Error::Bounds => Reason::Capacity,
                _ => Reason::UnsupportedFormat,
            })
        })
}

/// Compare the fixed verifier's PUBLIC result with the actual stored scalars.
/// Does not verify RSA/CSR/signature or manufacture a native current-key loan.
pub(crate) fn public_parts_match(fields: &Fields, request: &[u8], public: &[u8]) -> bool {
    fields.vault_kind() == Kind::AppleDistributionKey
        && request.len() <= CSR_PEM_LIMIT
        && !request.is_empty()
        && fields
            .borrow_value("csrPem")
            .is_some_and(|saved| saved.as_bytes() == request)
        && base64(public, SPKI_DER_LIMIT).is_ok_and(|encoded| {
            fields.borrow_value("publicKeySpkiBase64") == Some(encoded.as_str())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REQUEST: &str =
        "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n";
    fn frame(private: &[u8], public: &[u8]) -> Vec<u8> {
        // Deliberately NOT keys or signed CSRs. These tests qualify only fixed
        // private framing/codec DATA; no OpenSSL generation or native receipts.
        let mut value = MAGIC.to_vec();
        for size in [private.len(), REQUEST.len(), public.len()] {
            value.extend((size as u32).to_be_bytes());
        }
        value.extend(private);
        value.extend(REQUEST.as_bytes());
        value.extend(public);
        value
    }
    fn storage() -> Value {
        json!({
            "privateKeyPkcs8Base64":"MAA=", "csrPem":REQUEST, "publicKeySpkiBase64":"MAA=",
        })
    }

    #[test]
    fn pending_key_storage_is_not_manual_credential_admission() {
        assert!(!Kind::AppleDistributionKey.enabled());
        assert!(Kind::AppleDistributionKey.file().is_none());
        assert!(super::super::kind(&json!("apple-distribution-key")).is_err());
        assert!(super::super::own_fields(Kind::AppleDistributionKey, &storage()).is_err());
        assert!(stored_fields(&storage()).is_ok());
    }

    #[test]
    fn frame_borrows_and_bounds_before_scalar_allocation() {
        let original = frame(&[0x30, 0], &[0x30, 0]);
        let fields = AppleDistributionKeyFields::from_private_frame(&original).unwrap();
        assert!(
            fields.retained_bytes().unwrap()
                <= FIELD_BACKING_LIMIT + std::mem::size_of::<AppleDistributionKeyFields>()
        );
        assert!(CONSTRUCTION_BYTES > fields.retained_bytes().unwrap() + PRIVATE_FRAME_LIMIT);
        assert_eq!(
            fields.metadata().csr_sha256,
            <[u8; 32]>::from(Sha256::digest(REQUEST.as_bytes()))
        );
        for which in 0..3 {
            let mut bad = original.clone();
            let start = MAGIC.len() + which * 4;
            bad[start..start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(AppleDistributionKeyFields::from_private_frame(&bad).is_err());
            assert_eq!(bad[start..start + 4], u32::MAX.to_be_bytes());
        }
        for cut in [0, MAGIC.len(), MAGIC.len() + 11, original.len() - 1] {
            assert!(AppleDistributionKeyFields::from_private_frame(&original[..cut]).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(AppleDistributionKeyFields::from_private_frame(&trailing).is_err());
        assert_eq!(original, frame(&[0x30, 0], &[0x30, 0]));
    }

    #[test]
    fn restored_fields_require_exact_canonical_bounded_values() {
        for (name, value) in [
            ("privateKeyPkcs8Base64", json!("MAB=")),
            ("publicKeySpkiBase64", json!("MAA=\n")),
            ("privateKeyPkcs8Base64", json!("AA==".repeat(1025))),
            ("privateKeyPkcs8Base64", Value::Null),
            ("csrPem", json!(REQUEST.replace('\n', "\r\n"))),
            ("csrPem", json!(format!("preamble\n{REQUEST}"))),
            ("csrPem", json!(format!("{REQUEST}{REQUEST}"))),
        ] {
            let mut data = storage();
            data[name] = value;
            assert!(stored_fields(&data).is_err(), "closed field: {name}");
        }
        let mut extra = storage();
        extra["password"] = json!("must-not-be-admitted");
        assert!(stored_fields(&extra).is_err());
        let mut missing = storage();
        missing.as_object_mut().unwrap().remove("csrPem");
        assert!(stored_fields(&missing).is_err());
    }

    #[test]
    fn full_scalar_readback_comparison_is_not_hash_only() {
        let expected =
            AppleDistributionKeyFields::from_private_frame(&frame(&[0x30, 0], &[0x30, 0])).unwrap();
        let record = |fields| crypto::AuthenticatedRecord {
            record: crate::vault_format::Id::from_bytes([1; 16]).unwrap(),
            revision: crate::vault_format::Revision::new(
                crate::vault_format::Id::from_bytes([2; 16]).unwrap(),
                1,
            )
            .unwrap(),
            descriptor: crate::vault_format::Descriptor::new(
                Kind::AppleDistributionKey,
                None,
                vec![true; 3],
                false,
            )
            .unwrap(),
            fields,
            file: None,
        };
        assert!(expected.matches_authenticated_readback(&record(
            stored_fields(&storage()).unwrap_or_else(|_| panic!("fixed fields"))
        )));
        let mut different = storage();
        different["privateKeyPkcs8Base64"] = json!("MAE=");
        assert!(!expected.matches_authenticated_readback(&record(
            stored_fields(&different).unwrap_or_else(|_| panic!("fixed fields"))
        )));
        let fields = stored_fields(&storage()).unwrap_or_else(|_| panic!("fixed fields"));
        assert!(public_parts_match(&fields, REQUEST.as_bytes(), &[0x30, 0]));
        assert!(!public_parts_match(&fields, REQUEST.as_bytes(), &[0x30, 1]));
        assert!(!public_parts_match(
            &fields,
            b"different-public-csr",
            &[0x30, 0]
        ));
    }
}
