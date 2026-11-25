//! Bounded, UNTRUSTED certificate facts for a future native provisioning owner.
//!
//! This is a child of the existing credential_apple parser, not another trust
//! engine. RustCrypto owns DER/X.509 decoding; its original borrowed preflight
//! bounds allocations/work before owned decoding. No path, process, keychain,
//! clock read, private key, account, network or Security.framework call occurs.
//!
//! A syntactically suitable leaf, matching public SPKI and codeSigning EKU do
//! NOT establish a signature, Apple issuance, iOS distribution purpose, current
//! private-key custody or assignment. Even a deliberately fake signature can
//! produce this candidate. Comparison inputs are not authenticated here.
//! The private borrow-bound result has no readiness/binding conversion and no
//! Debug/Clone/Serde. See docs/apple-provisioning-certificate.md for the missing
//! original native trust/loan interface. Existing profile/Developer-ID purposes
//! cannot supply it. In particular, no Apple-purpose OIDs are guessed here.

use super::{poll, preflight, Failure};
use cms::cert::x509::{
    certificate::Version,
    ext::{
        pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        Extension,
    },
    Certificate,
};
use der_07::{
    asn1::{ObjectIdentifier, PrintableStringRef, Utf8StringRef},
    Decode, Encode, Tagged,
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const CERTIFICATE_BYTES: usize = 64 * 1024;
const CERTIFICATE_NODES: usize = 2048;
const EXTENSIONS: usize = 32;
const EXTENSION_BYTES: usize = 4096;
const EXTENSION_TOTAL_BYTES: usize = 16 * 1024;
const EXTENSION_NODES: usize = 128;
const SPKI_BYTES: usize = 16 * 1024;
const PUBLIC_KEY_BYTES: usize = 8192;
const SIGNATURE_BYTES: usize = 8192;

#[path = "apple_distribution_certificate_policy.rs"]
mod distribution_policy;
pub(crate) use distribution_policy::inspect_distribution_certificate_candidate;

#[derive(Clone, Copy)]
enum Purpose {
    ProfileScopedComparison,
    UnifiedDistributionComparison,
}

// Standard X.509 syntax identifiers, NOT an Apple distribution-purpose policy.
const TEAM_OU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

// The parent's maintained-decoder cell-size checks cover all reachable X.509
// vectors. Use a substantially smaller node ceiling than its CMS lane, plus
// bounded certificate/SPKI re-encodings and one known extension at a time.
const _: () = assert!(std::mem::size_of::<Certificate>() <= super::OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<ObjectIdentifier>() <= super::OWNED_CELL_LIMIT);
const _: () = assert!(
    4 * (CERTIFICATE_NODES + EXTENSION_NODES) * super::OWNED_CELL_LIMIT
        + 6 * CERTIFICATE_BYTES
        + SPKI_BYTES
        < 10 * 1024 * 1024
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateCandidateFailure {
    Interrupted,
    MaterialLimit,
    ParserLimit,
    Malformed,
    UnsupportedVariant,
    InvalidComparison,
    TeamMismatch,
    PublicKeyMismatch,
    NotCurrentAtComparison,
    SigningFactsMismatch,
}

/// Native-only DATA borrowing the exact input snapshot. These hashes/claims
/// are comparisons, never portable proof of trust, freshness or key custody.
pub(crate) struct UntrustedCertificateCandidate<'a> {
    captured_der: &'a [u8],
    certificate_sha256: [u8; 32],
    spki_sha256: [u8; 32],
    compared_team: [u8; 10],
    compared_at: SystemTime,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

impl UntrustedCertificateCandidate<'_> {
    pub(crate) fn captured_der(&self) -> &[u8] {
        self.captured_der
    }
    pub(crate) fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }
    pub(crate) fn spki_sha256(&self) -> &[u8; 32] {
        &self.spki_sha256
    }
    pub(crate) fn compared_team(&self) -> &[u8; 10] {
        &self.compared_team
    }
    pub(crate) fn compared_at(&self) -> SystemTime {
        self.compared_at
    }
    pub(crate) fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }
    pub(crate) fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }
}

fn mapped(error: Failure) -> CertificateCandidateFailure {
    match error {
        Failure::Interrupted => CertificateCandidateFailure::Interrupted,
        Failure::Limit(_) => CertificateCandidateFailure::ParserLimit,
        Failure::Malformed => CertificateCandidateFailure::Malformed,
        Failure::UnsupportedVariant => CertificateCandidateFailure::UnsupportedVariant,
    }
}

fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<(), CertificateCandidateFailure> {
    poll(stop).map_err(mapped)
}

fn admitted_der(
    bytes: &[u8],
    nodes: usize,
    stop: &mut dyn FnMut() -> bool,
) -> Result<(), CertificateCandidateFailure> {
    let (_, budget) = preflight(bytes, stop).map_err(mapped)?;
    if budget.nodes > nodes {
        return Err(CertificateCandidateFailure::ParserLimit);
    }
    Ok(())
}

fn decode_extension<'a, T: Decode<'a>>(
    bytes: &'a [u8],
    stop: &mut dyn FnMut() -> bool,
) -> Result<T, CertificateCandidateFailure> {
    // The original OUTER walk treats extnValue OCTET STRINGs as opaque. Never
    // pass their hidden DER to an owned decoder without separate admission.
    if bytes.len() > EXTENSION_BYTES {
        return Err(CertificateCandidateFailure::MaterialLimit);
    }
    admitted_der(bytes, EXTENSION_NODES, stop)?;
    checkpoint(stop)?;
    let decoded = T::from_der(bytes);
    checkpoint(stop)?;
    decoded.map_err(|_| CertificateCandidateFailure::Malformed)
}

fn signing_facts(
    extensions: Option<&[Extension]>,
    stop: &mut dyn FnMut() -> bool,
) -> Result<(), CertificateCandidateFailure> {
    use CertificateCandidateFailure as E;
    let extensions = extensions.ok_or(E::SigningFactsMismatch)?;
    if extensions.len() > EXTENSIONS {
        return Err(E::ParserLimit);
    }
    let mut total = 0usize;
    for (index, extension) in extensions.iter().enumerate() {
        checkpoint(stop)?;
        let size = extension.extn_value.as_bytes().len();
        total = total.checked_add(size).ok_or(E::MaterialLimit)?;
        if size > EXTENSION_BYTES || total > EXTENSION_TOTAL_BYTES {
            return Err(E::MaterialLimit);
        }
        if extensions[..index]
            .iter()
            .any(|earlier| earlier.extn_id == extension.extn_id)
        {
            return Err(E::Malformed);
        }
        if extension.critical
            && ![BASIC_CONSTRAINTS, KEY_USAGE, EXTENDED_KEY_USAGE].contains(&extension.extn_id)
        {
            return Err(E::UnsupportedVariant);
        }
    }
    let (mut basic, mut key, mut extended) = (false, false, false);
    for extension in extensions {
        checkpoint(stop)?;
        let bytes = extension.extn_value.as_bytes();
        match extension.extn_id {
            BASIC_CONSTRAINTS => {
                let value: BasicConstraints = decode_extension(bytes, stop)?;
                if value.ca || value.path_len_constraint.is_some() {
                    return Err(E::SigningFactsMismatch);
                }
                basic = true;
            }
            KEY_USAGE => {
                let value: KeyUsage = decode_extension(bytes, stop)?;
                if !value.digital_signature() || value.key_cert_sign() || value.crl_sign() {
                    return Err(E::SigningFactsMismatch);
                }
                key = true;
            }
            EXTENDED_KEY_USAGE => {
                let value: ExtendedKeyUsage = decode_extension(bytes, stop)?;
                if value.0.as_slice() != [CODE_SIGNING] {
                    return Err(E::SigningFactsMismatch);
                }
                extended = true;
            }
            _ => {
                // Bounded unknown NON-critical extension contents stay opaque;
                // they are not decoded, interpreted, authenticated or ignored
                // by a trust policy here. The later native owner sees full DER.
            }
        }
    }
    if !basic || !key || !extended {
        return Err(E::SigningFactsMismatch);
    }
    Ok(())
}

fn team_matches(
    certificate: &Certificate,
    expected: &[u8; 10],
    stop: &mut dyn FnMut() -> bool,
) -> Result<(), CertificateCandidateFailure> {
    use CertificateCandidateFailure as E;
    let mut seen = false;
    for name in &certificate.tbs_certificate.subject.0 {
        for attribute in name.0.iter() {
            checkpoint(stop)?;
            if attribute.oid != TEAM_OU {
                continue;
            }
            if seen {
                return Err(E::TeamMismatch);
            }
            seen = true;
            // No formatted subject/CN substring, trimming, case folding, BMP
            // guess or alternate identity source is accepted for the team OU.
            match attribute.value.tag() {
                der_07::Tag::Utf8String => {
                    attribute
                        .value
                        .decode_as::<Utf8StringRef<'_>>()
                        .map_err(|_| E::Malformed)?;
                }
                der_07::Tag::PrintableString => {
                    attribute
                        .value
                        .decode_as::<PrintableStringRef<'_>>()
                        .map_err(|_| E::Malformed)?;
                }
                _ => return Err(E::UnsupportedVariant),
            }
            if attribute.value.value() != expected {
                return Err(E::TeamMismatch);
            }
        }
    }
    if !seen {
        return Err(E::TeamMismatch);
    }
    Ok(())
}

fn hash(
    bytes: &[u8],
    stop: &mut dyn FnMut() -> bool,
) -> Result<[u8; 32], CertificateCandidateFailure> {
    let mut state = Sha256::new();
    for chunk in bytes.chunks(4096) {
        checkpoint(stop)?;
        state.update(chunk);
    }
    checkpoint(stop)?;
    Ok(state.finalize().into())
}

fn inspect_inner<'a>(
    captured_der: &'a [u8],
    expected_team: &[u8; 10],
    expected_spki_sha256: &[u8; 32],
    at: SystemTime,
    purpose: Purpose,
    stop: &mut dyn FnMut() -> bool,
) -> Result<UntrustedCertificateCandidate<'a>, CertificateCandidateFailure> {
    use CertificateCandidateFailure as E;
    if captured_der.len() > CERTIFICATE_BYTES {
        return Err(E::MaterialLimit);
    }
    if !expected_team
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(E::InvalidComparison);
    }
    let comparison = at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| E::InvalidComparison)?;
    admitted_der(captured_der, CERTIFICATE_NODES, stop)?;
    checkpoint(stop)?;
    let decoded = Certificate::from_der(captured_der);
    checkpoint(stop)?;
    let certificate = decoded.map_err(|_| E::Malformed)?;
    let tbs = &certificate.tbs_certificate;
    if tbs.version != Version::V3
        || tbs.issuer_unique_id.is_some()
        || tbs.subject_unique_id.is_some()
    {
        return Err(E::UnsupportedVariant);
    }
    if tbs.signature != certificate.signature_algorithm {
        return Err(E::Malformed);
    }
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or(E::UnsupportedVariant)?;
    if signature.is_empty() {
        return Err(E::Malformed);
    }
    if signature.len() > SIGNATURE_BYTES {
        return Err(E::MaterialLimit);
    }
    // This checks encoding agreement only, NOT the signature or algorithm's
    // cryptographic acceptability. The typed DER roundtrip ensures the encoded
    // SPKI below belongs exactly to this input, without hand-parsing offsets.
    let size = usize::try_from(certificate.encoded_len().map_err(|_| E::Malformed)?)
        .map_err(|_| E::MaterialLimit)?;
    if size != captured_der.len() {
        return Err(E::Malformed);
    }
    checkpoint(stop)?;
    let encoded = certificate.to_der();
    checkpoint(stop)?;
    let encoded = encoded.map_err(|_| E::Malformed)?;
    if encoded != captured_der {
        return Err(E::Malformed);
    }
    drop(encoded);
    team_matches(&certificate, expected_team, stop)?;
    let before = tbs.validity.not_before.to_unix_duration();
    let after = tbs.validity.not_after.to_unix_duration();
    if before >= after {
        return Err(E::Malformed);
    }
    // Match the provisioning planner's conservative [notBefore, notAfter)
    // convention. Preserve fractional comparison seconds, never round down an
    // expired input or silently obtain a new wall-clock reading.
    if comparison < before || comparison >= after {
        return Err(E::NotCurrentAtComparison);
    }
    match purpose {
        Purpose::ProfileScopedComparison => signing_facts(tbs.extensions.as_deref(), stop)?,
        Purpose::UnifiedDistributionComparison => distribution_policy::signing_facts(&certificate, stop)?,
    }
    let spki = &tbs.subject_public_key_info;
    let public_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(E::UnsupportedVariant)?;
    if public_key.is_empty() {
        return Err(E::Malformed);
    }
    if public_key.len() > PUBLIC_KEY_BYTES {
        return Err(E::MaterialLimit);
    }
    let size = usize::try_from(spki.encoded_len().map_err(|_| E::Malformed)?)
        .map_err(|_| E::MaterialLimit)?;
    if size > SPKI_BYTES {
        return Err(E::MaterialLimit);
    }
    checkpoint(stop)?;
    let encoded_spki = spki.to_der();
    checkpoint(stop)?;
    let encoded_spki = encoded_spki.map_err(|_| E::Malformed)?;
    // Full SubjectPublicKeyInfo DER: AlgorithmIdentifier + all parameters +
    // the BIT STRING. Never compare only RSA modulus/EC point/PEM formatting.
    // Algorithm-specific BIT contents stay opaque; no further owned decoding
    // occurs here and their syntax/strength are not vouched for by this hash.
    let spki_sha256 = hash(&encoded_spki, stop)?;
    drop(encoded_spki);
    if &spki_sha256 != expected_spki_sha256 {
        return Err(E::PublicKeyMismatch);
    }
    let certificate_sha256 = hash(captured_der, stop)?;
    Ok(UntrustedCertificateCandidate {
        captured_der,
        certificate_sha256,
        spki_sha256,
        compared_team: *expected_team,
        compared_at: at,
        not_before_unix_seconds: before.as_secs(),
        not_after_unix_seconds: after.as_secs(),
    })
}

/// Inspect the existing captured PUBLIC leaf without creating native authority.
/// STOP wins even over a refusal at the last check; a later trust borrower must
/// independently obtain its original owner/lease, current time and settlement.
pub(crate) fn inspect_certificate_candidate<'a>(
    captured_der: &'a [u8],
    expected_team: &[u8; 10],
    expected_spki_sha256: &[u8; 32],
    at: SystemTime,
    stop: &mut dyn FnMut() -> bool,
) -> Result<UntrustedCertificateCandidate<'a>, CertificateCandidateFailure> {
    checkpoint(stop)?;
    let result = inspect_inner(captured_der, expected_team, expected_spki_sha256, at,
        Purpose::ProfileScopedComparison, stop);
    checkpoint(stop)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use cms::cert::x509::{
        attr::AttributeTypeAndValue,
        ext::pkix::KeyUsages,
        name::{Name, RdnSequence, RelativeDistinguishedName},
        serial_number::SerialNumber,
        spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
        time::{Time, Validity},
        TbsCertificate,
    };
    use der_07::{
        asn1::{BitString, OctetString, UtcTime},
        Any, Tag,
    };
    use std::{str::FromStr, time::Duration};

    const TEAM: [u8; 10] = *b"ABCDE12345";
    const BEFORE: u64 = 1_700_000_000;
    const AFTER: u64 = 1_900_000_000;
    const AT: u64 = 1_800_000_000;
    const OTHER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.5.6");
    type E = CertificateCandidateFailure;

    fn when(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn extension(oid: ObjectIdentifier, bytes: Vec<u8>) -> Extension {
        Extension {
            extn_id: oid,
            critical: true,
            extn_value: OctetString::new(bytes).unwrap(),
        }
    }

    pub(super) fn fixture() -> Certificate {
        let signature = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Any::null()),
        };
        // Maintained-library encodings only. NO keypair generation/signing,
        // valid chain, Apple issuer, native call or trust-positive fixture.
        Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[1]).unwrap(),
                signature: signature.clone(),
                issuer: Name::from_str("CN=UNTRUSTED SYNTHETIC TEST ISSUER").unwrap(),
                validity: Validity {
                    not_before: Time::UtcTime(
                        UtcTime::from_unix_duration(Duration::from_secs(BEFORE)).unwrap(),
                    ),
                    not_after: Time::UtcTime(
                        UtcTime::from_unix_duration(Duration::from_secs(AFTER)).unwrap(),
                    ),
                },
                subject: Name::from_str("CN=NOT A REAL SIGNER,OU=ABCDE12345").unwrap(),
                subject_public_key_info: SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                        parameters: Some(Any::null()),
                    },
                    subject_public_key: BitString::from_bytes(b"NOT-A-REAL-PUBLIC-KEY").unwrap(),
                },
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(vec![
                    extension(
                        BASIC_CONSTRAINTS,
                        BasicConstraints {
                            ca: false,
                            path_len_constraint: None,
                        }
                        .to_der()
                        .unwrap(),
                    ),
                    extension(
                        KEY_USAGE,
                        KeyUsage(KeyUsages::DigitalSignature.into())
                            .to_der()
                            .unwrap(),
                    ),
                    extension(
                        EXTENDED_KEY_USAGE,
                        ExtendedKeyUsage(vec![CODE_SIGNING]).to_der().unwrap(),
                    ),
                ]),
            },
            signature_algorithm: signature,
            signature: BitString::from_bytes(b"FAKE-NOT-A-CRYPTOGRAPHIC-SIGNATURE").unwrap(),
        }
    }

    pub(super) fn inputs(certificate: &Certificate) -> (Vec<u8>, [u8; 32]) {
        (
            certificate.to_der().unwrap(),
            Sha256::digest(
                certificate
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap(),
            )
            .into(),
        )
    }

    fn evaluate(certificate: &Certificate) -> Result<(), E> {
        let (der, spki) = inputs(certificate);
        inspect_certificate_candidate(&der, &TEAM, &spki, when(AT), &mut || false).map(|_| ())
    }

    fn replace_extension(certificate: &mut Certificate, oid: ObjectIdentifier, bytes: Vec<u8>) {
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry.extn_id == oid)
            .unwrap()
            .extn_value = OctetString::new(bytes).unwrap();
    }

    #[test]
    fn fake_signature_produces_only_borrow_bound_untrusted_comparison_facts() {
        let (der, spki) = inputs(&fixture());
        let candidate =
            inspect_certificate_candidate(&der, &TEAM, &spki, when(AT), &mut || false).unwrap();
        assert_eq!(candidate.captured_der().as_ptr(), der.as_ptr());
        assert_eq!(candidate.captured_der(), der);
        assert_eq!(
            candidate.certificate_sha256(),
            &<[u8; 32]>::from(Sha256::digest(&der))
        );
        assert_eq!(candidate.spki_sha256(), &spki);
        assert_eq!(candidate.compared_team(), &TEAM);
        assert_eq!(candidate.compared_at(), when(AT));
        assert_eq!(candidate.not_before_unix_seconds(), BEFORE);
        assert_eq!(candidate.not_after_unix_seconds(), AFTER);
        // Deliberately no is_trusted/is_distribution/assign/CertificateBinding
        // API. This result and its synthetic signature cannot authorize use.
    }

    #[test]
    fn exact_spki_includes_algorithm_parameters_and_key_bits() {
        let base = fixture();
        let (_, expected) = inputs(&base);
        let mut changed = vec![];
        let mut certificate = base.clone();
        certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = None;
        changed.push(certificate);
        let mut certificate = base.clone();
        certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid = OTHER;
        changed.push(certificate);
        let mut certificate = base;
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(b"OTHER FAKE KEY").unwrap();
        changed.push(certificate);
        for certificate in changed {
            let (der, actual) = inputs(&certificate);
            assert_ne!(actual, expected);
            assert_eq!(
                inspect_certificate_candidate(&der, &TEAM, &expected, when(AT), &mut || false)
                    .err(),
                Some(E::PublicKeyMismatch)
            );
        }
    }

    #[test]
    fn exact_der_hash_changes_even_when_same_public_key_is_reissued() {
        let base = fixture();
        let (old_der, expected) = inputs(&base);
        let mut reissued = base;
        reissued.tbs_certificate.serial_number = SerialNumber::new(&[2]).unwrap();
        let (der, _) = inputs(&reissued);
        let candidate =
            inspect_certificate_candidate(&der, &TEAM, &expected, when(AT), &mut || false).unwrap();
        assert_ne!(
            candidate.certificate_sha256(),
            &<[u8; 32]>::from(Sha256::digest(old_der))
        );
        assert_eq!(candidate.spki_sha256(), &expected);
    }

    #[test]
    fn team_requires_single_exact_typed_ou_not_common_name_or_substring() {
        for subject in [
            "CN=OU=ABCDE12345",
            "CN=NOT A REAL SIGNER,OU=ZZZZZ12345",
            "CN=NOT A REAL SIGNER,OU=ABCDE12345,OU=ABCDE12345",
            "CN=NOT A REAL SIGNER,OU=abcde12345",
            "CN=NOT A REAL SIGNER,OU=PREFIXABCDE12345",
        ] {
            let mut certificate = fixture();
            certificate.tbs_certificate.subject = Name::from_str(subject).unwrap();
            assert_eq!(evaluate(&certificate), Err(E::TeamMismatch));
        }
        let mut certificate = fixture();
        certificate.tbs_certificate.subject = RdnSequence(vec![
            RelativeDistinguishedName::try_from(vec![AttributeTypeAndValue {
                oid: TEAM_OU,
                value: Any::new(Tag::Ia5String, TEAM.to_vec()).unwrap(),
            }])
            .unwrap(),
        ]);
        assert_eq!(evaluate(&certificate), Err(E::UnsupportedVariant));
    }

    #[test]
    fn both_utf8_and_printable_exact_team_values_are_supported_syntax() {
        for tag in [Tag::Utf8String, Tag::PrintableString] {
            let mut certificate = fixture();
            certificate.tbs_certificate.subject = RdnSequence(vec![
                RelativeDistinguishedName::try_from(vec![AttributeTypeAndValue {
                    oid: TEAM_OU,
                    value: Any::new(tag, TEAM.to_vec()).unwrap(),
                }])
                .unwrap(),
            ]);
            assert_eq!(evaluate(&certificate), Ok(()));
        }
    }

    #[test]
    fn supplied_time_is_half_open_without_rounding_or_clock_refresh() {
        let (der, spki) = inputs(&fixture());
        for (time, valid) in [
            (when(BEFORE) - Duration::from_nanos(1), false),
            (when(BEFORE), true),
            (when(AFTER) - Duration::from_nanos(1), true),
            (when(AFTER), false),
            (when(AFTER) + Duration::from_nanos(1), false),
        ] {
            let result = inspect_certificate_candidate(&der, &TEAM, &spki, time, &mut || false);
            if valid {
                assert_eq!(result.unwrap().compared_at(), time);
            } else {
                assert_eq!(result.err(), Some(E::NotCurrentAtComparison));
            }
        }
        assert_eq!(
            inspect_certificate_candidate(
                &der,
                &TEAM,
                &spki,
                UNIX_EPOCH - Duration::from_secs(1),
                &mut || false
            )
            .err(),
            Some(E::InvalidComparison)
        );
        assert_eq!(
            inspect_certificate_candidate(&der, b"bad-input!", &spki, when(AT), &mut || false)
                .err(),
            Some(E::InvalidComparison)
        );
    }

    #[test]
    fn reversed_or_empty_validity_is_malformed_not_an_expired_identity() {
        for reverse in [false, true] {
            let mut certificate = fixture();
            if reverse {
                std::mem::swap(
                    &mut certificate.tbs_certificate.validity.not_before,
                    &mut certificate.tbs_certificate.validity.not_after,
                );
            } else {
                certificate.tbs_certificate.validity.not_after =
                    certificate.tbs_certificate.validity.not_before;
            }
            assert_eq!(evaluate(&certificate), Err(E::Malformed));
        }
    }

    #[test]
    fn ca_or_ca_signing_and_missing_code_signing_facts_refuse() {
        for value in [
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
            BasicConstraints {
                ca: false,
                path_len_constraint: Some(0),
            },
        ] {
            let mut certificate = fixture();
            replace_extension(&mut certificate, BASIC_CONSTRAINTS, value.to_der().unwrap());
            assert_eq!(evaluate(&certificate), Err(E::SigningFactsMismatch));
        }
        for value in [
            KeyUsages::KeyCertSign.into(),
            KeyUsages::DigitalSignature | KeyUsages::KeyCertSign,
            KeyUsages::DigitalSignature | KeyUsages::CRLSign,
        ] {
            let mut certificate = fixture();
            replace_extension(
                &mut certificate,
                KEY_USAGE,
                KeyUsage(value).to_der().unwrap(),
            );
            assert_eq!(evaluate(&certificate), Err(E::SigningFactsMismatch));
        }
        for purposes in [
            vec![],
            vec![OTHER],
            vec![CODE_SIGNING, OTHER],
            vec![CODE_SIGNING, CODE_SIGNING],
        ] {
            let mut certificate = fixture();
            replace_extension(
                &mut certificate,
                EXTENDED_KEY_USAGE,
                ExtendedKeyUsage(purposes).to_der().unwrap(),
            );
            assert_eq!(evaluate(&certificate), Err(E::SigningFactsMismatch));
        }
        for oid in [BASIC_CONSTRAINTS, KEY_USAGE, EXTENDED_KEY_USAGE] {
            let mut certificate = fixture();
            certificate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|entry| entry.extn_id != oid);
            assert_eq!(evaluate(&certificate), Err(E::SigningFactsMismatch));
        }
    }

    #[test]
    fn duplicate_extensions_including_unknown_noncritical_are_malformed() {
        for oid in [KEY_USAGE, OTHER] {
            let mut certificate = fixture();
            let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
            let mut duplicate = extensions
                .iter()
                .find(|entry| entry.extn_id == oid)
                .cloned()
                .unwrap_or_else(|| {
                    let mut extension = extension(OTHER, Any::null().to_der().unwrap());
                    extension.critical = false;
                    extensions.push(extension.clone());
                    extension
                });
            duplicate.critical = false;
            extensions.push(duplicate);
            assert_eq!(evaluate(&certificate), Err(E::Malformed));
        }
    }

    #[test]
    fn unknown_critical_never_borrows_code_signing_or_subject_authority() {
        let mut certificate = fixture();
        certificate.tbs_certificate.subject =
            Name::from_str("CN=Apple Distribution SYNTHETIC NOT TRUSTED,OU=ABCDE12345").unwrap();
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extension(OTHER, Any::null().to_der().unwrap()));
        assert_eq!(evaluate(&certificate), Err(E::UnsupportedVariant));
        // Opaque non-critical extensions may survive as DATA, but are not
        // decoded/trusted. In particular no iOS purpose is inferred from them.
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .last_mut()
            .unwrap()
            .critical = false;
        assert_eq!(evaluate(&certificate), Ok(()));
    }

    #[test]
    fn known_extension_hidden_der_is_admitted_before_owned_decoder() {
        let mut certificate = fixture();
        // A valid generic DER tree hidden in extnValue exceeds the stricter
        // inner node cap. Typed EKU decoding would instead call it malformed.
        let child = Any::new(Tag::Sequence, vec![OTHER.to_der().unwrap(); 4].concat())
            .unwrap()
            .to_der()
            .unwrap();
        let hidden = Any::new(Tag::Sequence, vec![child; 32].concat())
            .unwrap()
            .to_der()
            .unwrap();
        assert!(hidden.len() < EXTENSION_BYTES);
        replace_extension(&mut certificate, EXTENDED_KEY_USAGE, hidden);
        assert_eq!(evaluate(&certificate), Err(E::ParserLimit));
        replace_extension(&mut certificate, EXTENDED_KEY_USAGE, vec![0x30, 0x80, 0, 0]);
        assert_eq!(evaluate(&certificate), Err(E::Malformed));
    }

    #[test]
    fn outer_node_limit_precedes_owned_certificate_decode() {
        let mut certificate = fixture();
        let attributes = (0..16)
            .map(|index| AttributeTypeAndValue {
                oid: ObjectIdentifier::new_unwrap("2.5.4.3"),
                value: Any::new(
                    Tag::Utf8String,
                    format!("synthetic-{index:02}").into_bytes(),
                )
                .unwrap(),
            })
            .collect::<Vec<_>>();
        certificate.tbs_certificate.subject =
            RdnSequence(vec![
                RelativeDistinguishedName::try_from(attributes).unwrap();
                48
            ]);
        let (der, spki) = inputs(&certificate);
        assert!(der.len() < CERTIFICATE_BYTES);
        assert_eq!(
            inspect_certificate_candidate(&der, &TEAM, &spki, when(AT), &mut || false).err(),
            Some(E::ParserLimit)
        );
    }

    #[test]
    fn extension_and_public_key_material_limits_are_small_and_exact() {
        let mut certificate = fixture();
        let mut extra = extension(OTHER, vec![0; EXTENSION_BYTES + 1]);
        extra.critical = false;
        certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(extra);
        assert_eq!(evaluate(&certificate), Err(E::MaterialLimit));
        let mut certificate = fixture();
        for index in 0..5 {
            let mut extra = extension(
                ObjectIdentifier::new(&format!("1.2.3.4.{index}")).unwrap(),
                vec![0; 3500],
            );
            extra.critical = false;
            certificate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(extra);
        }
        assert_eq!(evaluate(&certificate), Err(E::MaterialLimit));
        let mut certificate = fixture();
        for index in 0..30 {
            let mut extra = extension(
                ObjectIdentifier::new(&format!("1.2.3.4.{index}")).unwrap(),
                Any::null().to_der().unwrap(),
            );
            extra.critical = false;
            certificate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(extra);
        }
        assert_eq!(evaluate(&certificate), Err(E::ParserLimit));
        let mut certificate = fixture();
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(&vec![1; PUBLIC_KEY_BYTES + 1]).unwrap();
        assert_eq!(evaluate(&certificate), Err(E::MaterialLimit));
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(&vec![1; PUBLIC_KEY_BYTES]).unwrap();
        certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters =
            Some(Any::new(Tag::OctetString, vec![1; SPKI_BYTES - PUBLIC_KEY_BYTES]).unwrap());
        assert_eq!(evaluate(&certificate), Err(E::MaterialLimit));
    }

    #[test]
    fn unsupported_version_unique_id_or_unaligned_key_never_falls_back() {
        let mut certificate = fixture();
        certificate.tbs_certificate.version = Version::V1;
        assert_eq!(evaluate(&certificate), Err(E::UnsupportedVariant));
        let mut certificate = fixture();
        certificate.tbs_certificate.subject_unique_id =
            Some(BitString::from_bytes(b"synthetic").unwrap());
        assert_eq!(evaluate(&certificate), Err(E::UnsupportedVariant));
        let mut certificate = fixture();
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::new(1, vec![0x80]).unwrap();
        assert_eq!(evaluate(&certificate), Err(E::UnsupportedVariant));
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(&[]).unwrap();
        assert_eq!(evaluate(&certificate), Err(E::Malformed));
    }

    #[test]
    fn signature_encoding_and_algorithm_agreement_are_not_signature_verification() {
        let mut certificate = fixture();
        certificate.signature_algorithm.oid = OTHER;
        assert_eq!(evaluate(&certificate), Err(E::Malformed));
        let mut certificate = fixture();
        certificate.signature = BitString::from_bytes(&[]).unwrap();
        assert_eq!(evaluate(&certificate), Err(E::Malformed));
        certificate.signature = BitString::new(1, vec![0x80]).unwrap();
        assert_eq!(evaluate(&certificate), Err(E::UnsupportedVariant));
        certificate.signature = BitString::from_bytes(&vec![1; SIGNATURE_BYTES + 1]).unwrap();
        assert_eq!(evaluate(&certificate), Err(E::MaterialLimit));
        certificate.signature = BitString::from_bytes(b"ANOTHER OBVIOUS FAKE SIGNATURE").unwrap();
        assert_eq!(evaluate(&certificate), Ok(()));
    }

    #[test]
    fn malformed_truncated_concatenated_and_oversize_inputs_refuse_without_projection() {
        let (der, spki) = inputs(&fixture());
        for bad in [
            vec![],
            b"not DER".to_vec(),
            der[..der.len() - 1].to_vec(),
            [der.as_slice(), der.as_slice()].concat(),
        ] {
            assert_eq!(
                inspect_certificate_candidate(&bad, &TEAM, &spki, when(AT), &mut || false).err(),
                Some(E::Malformed)
            );
        }
        assert_eq!(
            inspect_certificate_candidate(
                &vec![0; CERTIFICATE_BYTES + 1],
                &TEAM,
                &spki,
                when(AT),
                &mut || false
            )
            .err(),
            Some(E::MaterialLimit)
        );
    }

    #[test]
    fn every_stop_checkpoint_vetoes_even_a_last_candidate_or_refusal() {
        let (der, spki) = inputs(&fixture());
        let mut count = 0;
        assert!(
            inspect_certificate_candidate(&der, &TEAM, &spki, when(AT), &mut || {
                count += 1;
                false
            })
            .is_ok()
        );
        assert!(count > 10);
        for target in 1..=count {
            let mut calls = 0;
            let result = inspect_certificate_candidate(&der, &TEAM, &spki, when(AT), &mut || {
                calls += 1;
                calls >= target
            });
            assert_eq!(result.err(), Some(E::Interrupted));
        }
        let mut calls = 0;
        let result =
            inspect_certificate_candidate(&der, b"bad-input!", &spki, when(AT), &mut || {
                calls += 1;
                calls >= 2
            });
        assert_eq!(result.err(), Some(E::Interrupted));
    }
}
