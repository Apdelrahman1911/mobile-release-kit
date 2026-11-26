//! Additional UNTRUSTED syntax/purpose admission for the certificate-only lane.
//! Same maintained decoder, borrowed preflight and fixed comparison clock as the
//! old profile-scoped candidate. This never verifies signatures, chain, private
//! possession, revocation, ASC association or native ownership by itself.
//!
//! Apple WWDR CPS 3.0 (2026-03-23) §4.11.24 specifies both critical submission
//! markers for unified Apple Distribution. Canonical DER NULL is our supported
//! encoding subset (also accepted by the pinned Security marker matcher), not
//! an assertion that the CPS mandates every encoding detail.
use super::*;

const IPHONE_SUBMISSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.1.4");
const MAC_SUBMISSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.1.7");
const CLOUD_MANAGED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113635.100.6.1.32");
const RSA_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA2_RSA: [ObjectIdentifier; 3] = [
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
];

pub(super) fn signing_facts(
    certificate: &Certificate,
    stop: &mut dyn FnMut() -> bool,
) -> Result<(), CertificateCandidateFailure> {
    use CertificateCandidateFailure as E;
    let tbs = &certificate.tbs_certificate;
    // Algorithm-specific key syntax/strength is checked separately by the
    // original fixed stored-key verifier and leaf helper; full SPKI equality is
    // mandatory. No new private-key or RSA decoder lives in this parser.
    if !SHA2_RSA.contains(&certificate.signature_algorithm.oid)
        || certificate.signature_algorithm.parameters != Some(der_07::Any::null())
        || tbs.subject_public_key_info.algorithm.oid != RSA_KEY
        || tbs.subject_public_key_info.algorithm.parameters != Some(der_07::Any::null())
    {
        return Err(E::UnsupportedVariant);
    }
    let extensions = tbs.extensions.as_deref().ok_or(E::SigningFactsMismatch)?;
    if extensions.len() > EXTENSIONS {
        return Err(E::ParserLimit);
    }
    let required = [
        BASIC_CONSTRAINTS,
        KEY_USAGE,
        EXTENDED_KEY_USAGE,
        IPHONE_SUBMISSION,
        MAC_SUBMISSION,
    ];
    let mut seen = [false; 5];
    let mut total = 0usize;
    for (index, extension) in extensions.iter().enumerate() {
        checkpoint(stop)?;
        let bytes = extension.extn_value.as_bytes();
        total = total.checked_add(bytes.len()).ok_or(E::MaterialLimit)?;
        if bytes.len() > EXTENSION_BYTES || total > EXTENSION_TOTAL_BYTES {
            return Err(E::MaterialLimit);
        }
        if extensions[..index]
            .iter()
            .any(|prior| prior.extn_id == extension.extn_id)
        {
            return Err(E::Malformed);
        }
        if extension.extn_id == CLOUD_MANAGED {
            return Err(E::UnsupportedVariant);
        }
        let Some(position) = required.iter().position(|oid| *oid == extension.extn_id) else {
            if extension.critical {
                return Err(E::UnsupportedVariant);
            }
            continue; // Bounded noncritical contents are not a trust assertion.
        };
        if !extension.critical {
            return Err(E::SigningFactsMismatch);
        }
        match extension.extn_id {
            BASIC_CONSTRAINTS => {
                let value: BasicConstraints = decode_extension(bytes, stop)?;
                if value.ca || value.path_len_constraint.is_some() || bytes != b"\x30\x00" {
                    return Err(E::SigningFactsMismatch);
                }
            }
            KEY_USAGE => {
                let value: KeyUsage = decode_extension(bytes, stop)?;
                if !value.digital_signature() || bytes != b"\x03\x02\x07\x80" {
                    return Err(E::SigningFactsMismatch);
                }
            }
            EXTENDED_KEY_USAGE => {
                let value: ExtendedKeyUsage = decode_extension(bytes, stop)?;
                if value.0.as_slice() != [CODE_SIGNING]
                    || bytes != b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x03"
                {
                    return Err(E::SigningFactsMismatch);
                }
            }
            IPHONE_SUBMISSION | MAC_SUBMISSION => {
                // Exact canonical payload, not presence-only/opaque extension
                // waiver. Unknown or trailing bytes never reach the callback.
                if bytes != b"\x05\x00" {
                    return Err(E::UnsupportedVariant);
                }
            }
            _ => return Err(E::UnsupportedVariant),
        }
        seen[position] = true;
    }
    if seen != [true; 5] {
        return Err(E::SigningFactsMismatch);
    }
    checkpoint(stop)
}

pub(crate) fn inspect_distribution_certificate_candidate<'a>(
    captured_der: &'a [u8],
    expected_team: &[u8; 10],
    expected_spki_sha256: &[u8; 32],
    at: SystemTime,
    stop: &mut dyn FnMut() -> bool,
) -> Result<UntrustedCertificateCandidate<'a>, CertificateCandidateFailure> {
    checkpoint(stop)?;
    let result = inspect_inner(
        captured_der,
        expected_team,
        expected_spki_sha256,
        at,
        Purpose::UnifiedDistributionComparison,
        stop,
    );
    checkpoint(stop)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use der_07::asn1::OctetString;
    use std::time::Duration;

    fn fixture() -> Certificate {
        let mut value = super::super::tests::fixture();
        let extensions = value.tbs_certificate.extensions.as_mut().unwrap();
        for oid in [IPHONE_SUBMISSION, MAC_SUBMISSION] {
            extensions.push(Extension {
                extn_id: oid,
                critical: true,
                extn_value: OctetString::new(b"\x05\x00").unwrap(),
            });
        }
        value
    }
    fn admitted(value: &Certificate) -> Result<(), CertificateCandidateFailure> {
        let (der, spki) = super::super::tests::inputs(value);
        inspect_distribution_certificate_candidate(
            &der,
            b"ABCDE12345",
            &spki,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            &mut || false,
        )
        .map(|_| ())
    }
    #[test]
    fn unified_markers_are_untrusted_new_lane_only_and_old_scope_stays_closed() {
        let value = fixture();
        assert_eq!(admitted(&value), Ok(())); // Existing intentionally FAKE signature.
        let (der, spki) = super::super::tests::inputs(&value);
        assert_eq!(
            inspect_certificate_candidate(
                &der,
                b"ABCDE12345",
                &spki,
                UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                &mut || false
            )
            .err(),
            Some(CertificateCandidateFailure::UnsupportedVariant)
        );
        assert!(admitted(&super::super::tests::fixture()).is_err());
    }
    #[test]
    fn every_required_critical_marker_payload_is_closed_and_duplicates_refuse() {
        for oid in [
            BASIC_CONSTRAINTS,
            KEY_USAGE,
            EXTENDED_KEY_USAGE,
            IPHONE_SUBMISSION,
            MAC_SUBMISSION,
        ] {
            let mut value = fixture();
            value
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|item| item.extn_id == oid)
                .unwrap()
                .critical = false;
            assert!(admitted(&value).is_err());
        }
        for bytes in [b"\x05\x01\x00".as_slice(), b"\x05\x00\x00", b"\x30\x00"] {
            let mut value = fixture();
            value
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|item| item.extn_id == IPHONE_SUBMISSION)
                .unwrap()
                .extn_value = OctetString::new(bytes).unwrap();
            assert!(admitted(&value).is_err());
        }
        let mut value = fixture();
        let duplicate = value.tbs_certificate.extensions.as_ref().unwrap()[3].clone();
        value
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            admitted(&value),
            Err(CertificateCandidateFailure::Malformed)
        );
    }
    #[test]
    fn unknown_critical_cloud_and_non_sha2_rsa_are_not_admitted() {
        for (oid, critical) in [
            (ObjectIdentifier::new_unwrap("1.2.3.4.999"), true),
            (CLOUD_MANAGED, false),
        ] {
            let mut value = fixture();
            value
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(Extension {
                    extn_id: oid,
                    critical,
                    extn_value: OctetString::new(b"\x05\x00").unwrap(),
                });
            assert_eq!(
                admitted(&value),
                Err(CertificateCandidateFailure::UnsupportedVariant)
            );
        }
        let mut value = fixture();
        value.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
        value.tbs_certificate.signature = value.signature_algorithm.clone();
        assert_eq!(
            admitted(&value),
            Err(CertificateCandidateFailure::UnsupportedVariant)
        );
    }
    #[test]
    fn same_original_stop_comparison_and_allocation_limits_remain_in_force() {
        let (der, spki) = super::super::tests::inputs(&fixture());
        let at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(
            inspect_distribution_certificate_candidate(&der, b"ABCDE12345", &spki, at, &mut || {
                true
            })
            .err(),
            Some(CertificateCandidateFailure::Interrupted)
        );
        assert_eq!(
            inspect_distribution_certificate_candidate(
                &der,
                b"ABCDE12345",
                &[0; 32],
                at,
                &mut || false
            )
            .err(),
            Some(CertificateCandidateFailure::PublicKeyMismatch)
        );
        assert_eq!(
            inspect_distribution_certificate_candidate(
                &vec![0; CERTIFICATE_BYTES + 1],
                b"ABCDE12345",
                &spki,
                at,
                &mut || false
            )
            .err(),
            Some(CertificateCandidateFailure::MaterialLimit)
        );
    }
}
