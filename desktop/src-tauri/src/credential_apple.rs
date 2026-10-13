//! Mechanical Apple-file envelopes, never password or Apple trust validation.
//!
//! The original native owner supplies captured bytes and the nonrenewable STOP
//! closure. No pathname, password, process, keychain, decoded private material,
//! certificate subject or embedded-profile claim is returned from this module.
//! RustCrypto owns ASN.1 decoding; the borrowed walk is allocation/work admission
//! before those owned decoders, not a second tag/length or schema parser.
//!
//! This mechanical subset does not support ANY primitive context-specific field
//! outside opaque OCTET/BIT payloads. That includes otherwise valid CMS subject
//! key identifier SIDs, X.509 unique IDs, and arbitrary primitive-context ANY
//! parameters/attributes. They are unavailable/unsupported, never declared
//! malformed. Common data-authSafe PFX and issuer-and-serial CMS are unaffected.
use super::{poll, CmsEncoding, Failure, FileObservation, Limit, Observation, Observed,
    Pkcs12AuthSafe, Pkcs8Encoding, Pkcs8Algorithm, Pkcs8Curve, UnavailableReason, DEPTH_LIMIT, NODE_LIMIT};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use der_07::{asn1::{AnyRef, ObjectIdentifier, OctetStringRef}, Decode, Reader, SliceReader, Tag, Tagged};
use pkcs12::pfx::Pfx;

const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const SIBLING_LIMIT: usize = 64;
const COMPARISON_LIMIT: usize = 200_000;
const COMPARED_WORK_LIMIT: usize = 256 * 1024 * 1024;

// Full SignedData expands certificate/CRL/attribute vectors and its CHOICE
// comparisons may encode two temporary values. Keep that lane explicitly
// smaller than the ordinary 32MiB PFX data lane; no truncation/fake observation.
const SIGNED_INPUT_LIMIT: usize = 4 * 1024 * 1024;
const OWNED_NODE_LIMIT: usize = 16_384;
const OWNED_CELL_LIMIT: usize = 1024;
// Vec growth for a nonzero-sized cell <=1024 is bounded by four cells per
// admitted element (including the minimum capacity of four). SignedData's
// reachable element types are checked below. Bytes, outer ANY and sort copies
// are separate rows; all remain below the existing 96MiB scratch allowance.
const SIGNED_SCRATCH_LIMIT: usize = 4 * OWNED_NODE_LIMIT * OWNED_CELL_LIMIT
    + 5 * SIGNED_INPUT_LIMIT + 1024 * 1024;
const _: () = assert!(SIGNED_SCRATCH_LIMIT < 96 * 1024 * 1024);
const _: () = assert!(std::mem::size_of::<cms::cert::CertificateChoices>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::revocation::RevocationInfoChoice>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::signed_data::SignerInfo>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::cert::x509::spki::AlgorithmIdentifierOwned>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::cert::x509::crl::RevokedCert>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::cert::x509::name::RelativeDistinguishedName>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::cert::x509::attr::Attribute>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::cert::x509::attr::AttributeTypeAndValue>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<cms::cert::x509::ext::Extension>() <= OWNED_CELL_LIMIT);
const _: () = assert!(std::mem::size_of::<der_07::Any>() <= OWNED_CELL_LIMIT);

#[derive(Default)]
struct Budget { nodes: usize, comparisons: usize, compared_work: usize }
impl Budget {
    fn enter(&mut self, depth: usize) -> Result<(), Failure> {
        if depth > DEPTH_LIMIT { return Err(Failure::Limit(Limit::Depth)); }
        self.nodes = self.nodes.checked_add(1).filter(|n| *n <= NODE_LIMIT)
            .ok_or(Failure::Limit(Limit::Nodes))?;
        Ok(())
    }
    fn set(&mut self, children: usize, largest: usize) -> Result<(), Failure> {
        // der0.7 SetOfVec insertion-sort + adjacent duplicate/order checks.
        // Treat every constructed context-specific value as a potential
        // implicit SET. EXPLICIT wrappers have one child and charge no sort.
        let pairs = children.checked_mul(children.saturating_sub(1)).map(|n| n / 2)
            .and_then(|n| n.checked_add(children.saturating_sub(1)))
            .ok_or(Failure::Limit(Limit::Asn1Work))?;
        self.comparisons = self.comparisons.checked_add(pairs).filter(|n| *n <= COMPARISON_LIMIT)
            .ok_or(Failure::Limit(Limit::Asn1Work))?;
        // Two child encodings, their length walks and comparisons, with extra
        // header/value traversal allowance at every admitted nesting level.
        let work = pairs.checked_mul(largest).and_then(|n| n.checked_mul(8 * (DEPTH_LIMIT + 1)))
            .ok_or(Failure::Limit(Limit::Asn1Work))?;
        self.compared_work = self.compared_work.checked_add(work).filter(|n| *n <= COMPARED_WORK_LIMIT)
            .ok_or(Failure::Limit(Limit::Asn1Work))?;
        Ok(())
    }
}

fn walk(value: AnyRef<'_>, depth: usize, budget: &mut Budget, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
    poll(stop)?; budget.enter(depth)?;
    // der0.7's IMPLICIT field decoder can decode its owned inner value BEFORE
    // rejecting the wrong constructed bit. Treating such bodies as opaque
    // would hide lengths/nodes/sets from admission. Refuse the whole primitive
    // context-specific subset rather than guessing its typed schema or letting
    // an owned decoder perform unaccounted work before a late format refusal.
    if value.tag().is_context_specific() && !value.tag().is_constructed() {
        return Err(Failure::UnsupportedVariant);
    }
    if value.tag().is_constructed() {
        let mut reader = SliceReader::new(value.value()).map_err(|_| Failure::Malformed)?;
        let (mut children, mut largest) = (0usize, 0usize);
        while !reader.is_finished() {
            poll(stop)?;
            children += 1;
            if children > SIBLING_LIMIT { return Err(Failure::Limit(Limit::Nodes)); }
            // Library tlv_bytes/read_slice prove containment BEFORE ANY owned
            // read_vec can allocate the advertised length. No wire arithmetic.
            let bytes = reader.tlv_bytes().map_err(|_| Failure::Malformed)?;
            let child = AnyRef::from_der(bytes).map_err(|_| Failure::Malformed)?;
            largest = largest.max(bytes.len());
            walk(child, depth + 1, budget, stop)?;
        }
        reader.finish(()).map_err(|_| Failure::Malformed)?;
        if value.tag() == Tag::Set || value.tag().is_context_specific() { budget.set(children, largest)?; }
    }
    // Universal primitive OCTET/BIT STRINGs stay opaque. This typed path never
    // parses their private contents later. Primitive context-specific fields,
    // unlike those universal payloads, have already been refused above.
    poll(stop)
}

fn preflight<'a>(bytes: &'a [u8], stop: &mut dyn FnMut() -> bool) -> Result<(AnyRef<'a>, Budget), Failure> {
    poll(stop)?;
    let outer = AnyRef::from_der(bytes).map_err(|_| Failure::Malformed)?;
    let mut budget = Budget::default();
    walk(outer, 1, &mut budget, stop)?;
    Ok((outer, budget))
}

fn signed_admission(bytes: usize, nodes: usize) -> Result<(), Failure> {
    if bytes > SIGNED_INPUT_LIMIT || nodes > OWNED_NODE_LIMIT { Err(Failure::Limit(Limit::Asn1Work)) } else { Ok(()) }
}

fn signed(content: &der_07::Any, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
    poll(stop)?;
    // This original content was completely traversed before the outer owned
    // decode. decode_as uses its borrowed body; no second full DER encoding.
    let decoded = content.decode_as::<SignedData>();
    poll(stop)?;
    let decoded = decoded.map_err(|_| Failure::Malformed)?;
    // RFC5652's eContent is an OCTET STRING. cms0.2 deliberately represents it
    // with Any, so apply that one public schema constraint through the library.
    if let Some(value) = &decoded.encap_content_info.econtent {
        value.decode_as::<OctetStringRef<'_>>().map_err(|_| Failure::Malformed)?;
    }
    drop(decoded); // Not secure erasure; none of this material is projected.
    poll(stop)
}

pub(super) fn pfx(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileObservation, Failure> {
    // A format hint only; every admitted tag/length/schema is decoded by DER.
    if bytes.first() != Some(&0x30) { return Ok(FileObservation::unavailable(UnavailableReason::UnsupportedFormat)); }
    let (outer, budget) = preflight(bytes, stop)?;
    if outer.tag() != Tag::Sequence { return Err(Failure::Malformed); }
    let mut version_reader = SliceReader::new(outer.value()).map_err(|_| Failure::Malformed)?;
    let version = u8::decode(&mut version_reader).map_err(|_| Failure::Malformed)?;
    if version != 3 { return Err(Failure::UnsupportedVariant); }
    poll(stop)?;
    let decoded = Pfx::from_der(bytes);
    poll(stop)?;
    let decoded = decoded.map_err(|_| Failure::Malformed)?;
    let auth_safe = if decoded.auth_safe.content_type == DATA {
        decoded.auth_safe.content.decode_as::<OctetStringRef<'_>>().map_err(|_| Failure::Malformed)?;
        Pkcs12AuthSafe::Data
    } else if decoded.auth_safe.content_type == SIGNED_DATA {
        signed_admission(bytes.len(), budget.nodes)?;
        signed(&decoded.auth_safe.content, stop)?;
        Pkcs12AuthSafe::SignedData
    } else { return Err(Failure::UnsupportedVariant); };
    drop(decoded);
    poll(stop)?;
    Ok(FileObservation(Observation::Observed { data: Observed::Pkcs12 {
        byte_count: bytes.len() as u64, version: 3, auth_safe,
    } }))
}

pub(super) fn profile(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileObservation, Failure> {
    if bytes.first() != Some(&0x30) { return Ok(FileObservation::unavailable(UnavailableReason::UnsupportedFormat)); }
    let (_, budget) = preflight(bytes, stop)?;
    signed_admission(bytes.len(), budget.nodes)?;
    poll(stop)?;
    let decoded = ContentInfo::from_der(bytes);
    poll(stop)?;
    let decoded = decoded.map_err(|_| Failure::Malformed)?;
    if decoded.content_type != SIGNED_DATA { return Err(Failure::UnsupportedVariant); }
    signed(&decoded.content, stop)?;
    drop(decoded);
    poll(stop)?;
    Ok(FileObservation(Observation::Observed { data: Observed::CmsSignedData {
        byte_count: bytes.len() as u64, encoding: CmsEncoding::Der,
    } }))
}


const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

// No PEM preamble, extra block or trailing data is accepted. The maintained
// decoder owns complete boundary/base64 syntax; only the original leading
// boundary is admitted here, so its optional preamble feature is never used.
// The owned DER allocation below is zeroized. The maintained decoder also uses
// small internal stack/block temporaries without a zeroize API; this is not a
// promise of complete stack/register/process erasure.
fn p8_pem(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<zeroize::Zeroizing<Vec<u8>>, Failure> {
    poll(stop)?;
    if !bytes.starts_with(b"-----BEGIN ") { return Err(Failure::UnsupportedVariant); }
    let decoder = der_07::pem::Decoder::new(bytes);
    poll(stop)?;
    let mut decoder = decoder.map_err(|_| Failure::Malformed)?;
    if decoder.type_label() != "PRIVATE KEY" { return Err(Failure::UnsupportedVariant); }
    let size = decoder.remaining_len();
    if size == 0 { return Err(Failure::Malformed); }
    if size > super::JSON_LIMIT || size > bytes.len() { return Err(Failure::Limit(Limit::Allocation)); }

    // Allocate the owned DER buffer once before filling it. Zeroizing owns
    // the whole allocation on success, refusal, allocation error and every STOP.
    // No growth, cloning or retained normalized copy follows this admission.
    let mut decoded = zeroize::Zeroizing::new(Vec::<u8>::new());
    decoded.try_reserve_exact(size).map_err(|_| Failure::Limit(Limit::Allocation))?;
    if decoded.capacity() > size { return Err(Failure::Limit(Limit::Allocation)); }
    poll(stop)?;
    decoded.resize(size, 0);
    for chunk in decoded.chunks_mut(super::STOP_STRIDE) {
        poll(stop)?;
        let result = decoder.decode(chunk);
        poll(stop)?;
        result.map_err(|_| Failure::Malformed)?;
    }
    if !decoder.is_finished() { return Err(Failure::Malformed); }
    poll(stop)?;
    Ok(decoded)
}

// Borrowed version-0 PrivateKeyInfo only. The private OCTET STRING is nonempty
// but opaque: this does not parse an EC scalar, derive a public key, decrypt,
// sign, identify an account or validate Apple's authority.
fn p8_envelope(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<(Pkcs8Algorithm, Option<Pkcs8Curve>), Failure> {
    let (outer, _) = preflight(bytes, stop)?;
    if outer.tag() != Tag::Sequence { return Err(Failure::Malformed); }
    let mut reader = SliceReader::new(outer.value()).map_err(|_| Failure::Malformed)?;
    let version = u8::decode(&mut reader).map_err(|_| Failure::Malformed)?;
    if version != 0 { return Err(Failure::UnsupportedVariant); }
    poll(stop)?;
    let identifier = AnyRef::decode(&mut reader).map_err(|_| Failure::Malformed)?;
    if identifier.tag() != Tag::Sequence { return Err(Failure::Malformed); }
    let mut algorithm_reader = SliceReader::new(identifier.value()).map_err(|_| Failure::Malformed)?;
    let oid = ObjectIdentifier::decode(&mut algorithm_reader).map_err(|_| Failure::Malformed)?;
    let parameters = if algorithm_reader.is_finished() { None }
        else { Some(AnyRef::decode(&mut algorithm_reader).map_err(|_| Failure::Malformed)?) };
    algorithm_reader.finish(()).map_err(|_| Failure::Malformed)?;
    poll(stop)?;
    let private = OctetStringRef::decode(&mut reader).map_err(|_| Failure::Malformed)?;
    if private.as_bytes().is_empty() { return Err(Failure::Malformed); }
    if !reader.is_finished() { return Err(Failure::UnsupportedVariant); } // No attributes/public-key extension.
    reader.finish(()).map_err(|_| Failure::Malformed)?;
    let result = if oid == EC_PUBLIC_KEY {
        let parameters = parameters.ok_or(Failure::UnsupportedVariant)?;
        if parameters.tag() != Tag::ObjectIdentifier { return Err(Failure::UnsupportedVariant); } // No explicit EC params.
        let curve = parameters.decode_as::<ObjectIdentifier>().map_err(|_| Failure::Malformed)?;
        (Pkcs8Algorithm::Ec, Some(if curve == PRIME256V1 { Pkcs8Curve::P256 } else { Pkcs8Curve::Other }))
    } else {
        // No arbitrary OID or parameter value leaves this module. Recognized
        // non-EC algorithms remain fixed identifiers for the core to reject.
        (if oid == RSA_ENCRYPTION { Pkcs8Algorithm::Rsa } else { Pkcs8Algorithm::Other }, None)
    };
    poll(stop)?;
    Ok(result)
}

pub(super) fn p8(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileObservation, Failure> {
    poll(stop)?;
    let (encoding, (algorithm, curve)) = if bytes.first() == Some(&0x30) {
        (Pkcs8Encoding::Der, p8_envelope(bytes, stop)?)
    } else if bytes.starts_with(b"-----BEGIN ") {
        let decoded = p8_pem(bytes, stop)?;
        (Pkcs8Encoding::Pem, p8_envelope(&decoded, stop)?)
        // The one decoded allocation is zeroized/dropped here, including on ?.
    } else { return Ok(FileObservation::unavailable(UnavailableReason::UnsupportedFormat)); };
    poll(stop)?;
    Ok(FileObservation(Observation::Observed { data: Observed::Pkcs8 {
        byte_count: bytes.len() as u64, encoding, algorithm, curve,
    } }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{inspect, FileKind};
    use cms::{content_info::CmsVersion, signed_data::{EncapsulatedContentInfo, SignerInfos}};
    use der_07::{Any, Encode};
    use serde_json::{json, Value};

    const CANARY: &[u8] = b"private-envelope-only-canary";
    fn tlv(tag: Tag, value: &[u8]) -> Vec<u8> { Any::new(tag, value.to_vec()).unwrap().to_der().unwrap() }
    fn signed_body(value: &[u8]) -> Any {
        Any::encode_from(&SignedData { version: CmsVersion::V1, digest_algorithms: Default::default(),
            encap_content_info: EncapsulatedContentInfo { econtent_type: DATA,
                econtent: Some(Any::new(Tag::OctetString, value.to_vec()).unwrap()) },
            certificates: None, crls: None, signer_infos: SignerInfos(Default::default()),
        }).unwrap()
    }
    fn signed_with_optional_field(field: &[u8]) -> Any {
        let value = signed_body(CANARY);
        let mut reader = SliceReader::new(value.value()).unwrap();
        let mut body = Vec::new();
        for _ in 0..3 { body.extend_from_slice(reader.tlv_bytes().unwrap()); }
        body.extend_from_slice(field); // Before signerInfos: certificates/CRLs.
        body.extend_from_slice(reader.read_slice(reader.remaining_len()).unwrap());
        Any::new(Tag::Sequence, body).unwrap()
    }
    fn pfx_fixture(content_type: ObjectIdentifier, content: Any) -> Vec<u8> {
        Pfx { version: pkcs12::pfx::Version::V3, auth_safe: ContentInfo { content_type, content }, mac_data: None }.to_der().unwrap()
    }
    fn profile_fixture(content_type: ObjectIdentifier, content: Any) -> Vec<u8> { ContentInfo { content_type, content }.to_der().unwrap() }
    fn data_pfx() -> Vec<u8> { pfx_fixture(DATA, Any::new(Tag::OctetString, CANARY.to_vec()).unwrap()) }
    fn signed_pfx() -> Vec<u8> { pfx_fixture(SIGNED_DATA, signed_body(CANARY)) }
    fn profile() -> Vec<u8> { profile_fixture(SIGNED_DATA, signed_body(CANARY)) }
    fn wire(kind: FileKind, bytes: &[u8]) -> Value { serde_json::to_value(inspect(kind, bytes, &mut || false).ok().unwrap()).unwrap() }


    fn p8_fixture(algorithm: ObjectIdentifier, parameters: Option<Any>, version: u8, private: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut identifier = algorithm.to_der().unwrap();
        if let Some(parameters) = parameters { identifier.extend_from_slice(&parameters.to_der().unwrap()); }
        let mut fields = version.to_der().unwrap();
        fields.extend_from_slice(&tlv(Tag::Sequence, &identifier));
        fields.extend_from_slice(&tlv(Tag::OctetString, private));
        fields.extend_from_slice(tail);
        tlv(Tag::Sequence, &fields)
    }
    fn p8_curve(oid: ObjectIdentifier) -> Option<Any> { Some(Any::encode_from(&oid).unwrap()) }
    fn p8_der() -> Vec<u8> { p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 0, CANARY, &[]) }
    fn p8_text(label: &str, bytes: &[u8]) -> Vec<u8> {
        der_07::pem::encode_string(label, der_07::pem::LineEnding::LF, bytes).unwrap().into_bytes()
    }

    #[test]
    fn p8_der_and_pem_publish_only_envelope_identifiers_not_key_validity() {
        let der = p8_der(); let pem = p8_text("PRIVATE KEY", &der);
        for (encoding, bytes) in [("der", der), ("pem", pem)] {
            let result = wire(FileKind::AscP8, &bytes);
            assert_eq!(result, json!({"status":"observed","format":"pkcs8","byteCount":bytes.len(),
                "encoding":encoding,"algorithm":"ec","curve":"p256"}));
            assert!(!result.to_string().contains(std::str::from_utf8(CANARY).unwrap()));
        }
        // Not even an inner EC key: a nonempty opaque payload is deliberately
        // enough for this narrow observation. No signing/key-validity claim.
        let bytes = p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 0, &[0xff, 0], &[]);
        assert_eq!(wire(FileKind::AscP8, &bytes)["status"], "observed");
        let pem = String::from_utf8(p8_text("PRIVATE KEY", &p8_der())).unwrap();
        assert_eq!(wire(FileKind::AscP8, pem.replace('\n', "\r\n").as_bytes())["encoding"], "pem");
    }
    #[test]
    fn p8_other_algorithms_and_curves_are_fixed_nonsecret_core_rejection_facts() {
        for (oid, parameters, algorithm, curve) in [
            (RSA_ENCRYPTION, Some(Any::null()), "rsa", Value::Null),
            (ObjectIdentifier::new_unwrap("1.3.101.112"), None, "other", Value::Null),
            (EC_PUBLIC_KEY, p8_curve(ObjectIdentifier::new_unwrap("1.3.132.0.34")), "ec", json!("other")),
        ] {
            let bytes = p8_fixture(oid, parameters, 0, CANARY, &[]);
            assert_eq!(wire(FileKind::AscP8, &bytes), json!({"status":"observed","format":"pkcs8","byteCount":bytes.len(),
                "encoding":"der","algorithm":algorithm,"curve":curve}));
        }
    }
    #[test]
    fn p8_never_accepts_encryption_sec1_extensions_or_explicit_ec_parameters() {
        for label in ["ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY", "PUBLIC KEY"] {
            assert_eq!(wire(FileKind::AscP8, &p8_text(label, &p8_der())),
                json!({"status":"unavailable","reason":"unsupported-variant"}));
        }
        let attributes = tlv(Tag::ContextSpecific { constructed: true, number: der_07::TagNumber::N0 }, &[]);
        for bytes in [
            p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 1, CANARY, &[]),
            p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 0, CANARY, &attributes),
            p8_fixture(EC_PUBLIC_KEY, Some(Any::new(Tag::Sequence, Vec::new()).unwrap()), 0, CANARY, &[]),
            p8_fixture(EC_PUBLIC_KEY, Some(Any::null()), 0, CANARY, &[]),
            p8_fixture(EC_PUBLIC_KEY, None, 0, CANARY, &[]),
        ] {
            assert_eq!(wire(FileKind::AscP8, &bytes), json!({"status":"unavailable","reason":"unsupported-variant"}));
        }
        let mut sec1 = 1u8.to_der().unwrap(); sec1.extend_from_slice(&tlv(Tag::OctetString, CANARY));
        assert_eq!(wire(FileKind::AscP8, &tlv(Tag::Sequence, &sec1))["status"], "unavailable");
        let mut encrypted = tlv(Tag::Sequence, &RSA_ENCRYPTION.to_der().unwrap());
        encrypted.extend_from_slice(&tlv(Tag::OctetString, CANARY));
        assert_ne!(wire(FileKind::AscP8, &tlv(Tag::Sequence, &encrypted))["status"], "observed");
    }
    #[test]
    fn p8_requires_complete_canonical_framing_and_nonempty_private_octets() {
        let der = p8_der();
        for end in 0..der.len() { assert_ne!(wire(FileKind::AscP8, &der[..end])["status"], "observed"); }
        let mut trailing = der.clone(); trailing.extend_from_slice(&[5, 0]);
        assert_eq!(wire(FileKind::AscP8, &trailing), json!({"status":"rejected","reason":"malformed-container"}));
        assert!(der[1] < 128);
        let mut noncanonical = vec![0x30, 0x81, der[1]]; noncanonical.extend_from_slice(&der[2..]);
        assert_eq!(wire(FileKind::AscP8, &noncanonical), json!({"status":"rejected","reason":"malformed-container"}));
        let empty = p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 0, &[], &[]);
        assert_eq!(wire(FileKind::AscP8, &empty), json!({"status":"rejected","reason":"malformed-container"}));
        let bad_oid = p8_fixture(EC_PUBLIC_KEY, Some(Any::new(Tag::ObjectIdentifier, vec![0x80]).unwrap()), 0, CANARY, &[]);
        assert_eq!(wire(FileKind::AscP8, &bad_oid), json!({"status":"rejected","reason":"malformed-container"}));
        let pem = p8_text("PRIVATE KEY", &der);
        for bytes in [
            [b"preamble\n".as_slice(), &pem].concat(), [pem.as_slice(), b"trailing"].concat(),
            [pem.as_slice(), pem.as_slice()].concat(),
            b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\nMA==\n-----END PUBLIC KEY-----\n".to_vec(),
        ] {
            let result = wire(FileKind::AscP8, &bytes);
            assert_ne!(result["status"], "observed");
            assert!(!result.to_string().contains(std::str::from_utf8(CANARY).unwrap()));
        }
    }
    #[test]
    fn p8_preserves_material_and_existing_der_work_limits() {
        assert_eq!(wire(FileKind::AscP8, &vec![0; super::super::JSON_LIMIT + 1]),
            json!({"status":"unavailable","reason":"material-limit"}));
        let mut deep = tlv(Tag::Null, &[]);
        for _ in 0..DEPTH_LIMIT { deep = tlv(Tag::Sequence, &deep); }
        let too_many = tlv(Tag::Sequence, &[5u8, 0].repeat(SIBLING_LIMIT + 1));
        let large_set = tlv(Tag::Set, &tlv(Tag::OctetString, &[0; 4096]).repeat(64));
        for parameter in [deep, too_many, large_set] {
            let bytes = p8_fixture(ObjectIdentifier::new_unwrap("1.2.3.4"), Some(Any::from_der(&parameter).unwrap()), 0, CANARY, &[]);
            assert_eq!(wire(FileKind::AscP8, &bytes), json!({"status":"unavailable","reason":"parser-limit"}));
        }
    }
    #[test]
    fn p8_stop_at_every_original_checkpoint_prevents_success_and_refusal() {
        // Multiple PEM chunks make mid-decode STOP meaningful. These are inert
        // canaries, never an actual key or an allocation/OOM experiment.
        let large = p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 0, &CANARY.repeat(400), &[]);
        for bytes in [p8_der(), p8_text("PRIVATE KEY", &large),
            p8_fixture(EC_PUBLIC_KEY, p8_curve(PRIME256V1), 1, CANARY, &[]),
            p8_text("ENCRYPTED PRIVATE KEY", &p8_der()), b"preamble\n".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n".to_vec(),
            vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]] {
            let mut count = 0;
            assert!(inspect(FileKind::AscP8, &bytes, &mut || { count += 1; false }).is_ok());
            for cutoff in 1..=count {
                let mut calls = 0;
                assert!(inspect(FileKind::AscP8, &bytes, &mut || { calls += 1; calls >= cutoff }).is_err());
            }
        }
    }

    #[test]
    fn both_pfx_forms_and_cms_publish_only_mechanical_envelope_facts() {
        for (bytes, auth_safe) in [(data_pfx(), "data"), (signed_pfx(), "signed-data")] {
            let result = wire(FileKind::AppleP12, &bytes);
            assert_eq!(result, json!({"status":"observed","format":"pkcs12","byteCount":bytes.len(),"version":3,"authSafe":auth_safe}));
            assert!(!result.to_string().contains(std::str::from_utf8(CANARY).unwrap()));
        }
        let bytes = profile();
        assert_eq!(wire(FileKind::AppleProfile, &bytes), json!({"status":"observed","format":"cms-signed-data","byteCount":bytes.len(),"encoding":"der"}));
        // These deliberately signature-less synthetic envelopes are format
        // fixtures only. None is an Apple profile/P12 signing-validity fixture.
    }
    #[test]
    fn signed_oid_alone_and_embedded_plist_are_not_signed_data_shapes() {
        for content in [Any::new(Tag::OctetString, b"<plist/>".to_vec()).unwrap(), Any::new(Tag::Sequence, Vec::new()).unwrap()] {
            for (kind, bytes) in [(FileKind::AppleProfile, profile_fixture(SIGNED_DATA, content.clone())),
                (FileKind::AppleP12, pfx_fixture(SIGNED_DATA, content))] {
                assert_eq!(wire(kind, &bytes), json!({"status":"rejected","reason":"malformed-container"}));
            }
        }
        let not_octets = signed_body(CANARY).decode_as::<SignedData>().unwrap();
        let mut wrong_econtent = not_octets;
        wrong_econtent.encap_content_info.econtent = Some(Any::new(Tag::Sequence, Vec::new()).unwrap());
        assert_eq!(wire(FileKind::AppleProfile, &profile_fixture(SIGNED_DATA, Any::encode_from(&wrong_econtent).unwrap())),
            json!({"status":"rejected","reason":"malformed-container"}));
        assert_eq!(wire(FileKind::AppleProfile, b"<?xml version='1.0'?><plist/>"), json!({"status":"unavailable","reason":"unsupported-format"}));
    }
    #[test]
    fn version_content_type_and_container_framing_are_not_guessed() {
        let bytes = data_pfx();
        let any = AnyRef::from_der(&bytes).unwrap();
        let mut reader = SliceReader::new(any.value()).unwrap();
        let _ = u8::decode(&mut reader).unwrap();
        let suffix = reader.read_slice(reader.remaining_len()).unwrap();
        let mut changed = 2u8.to_der().unwrap(); changed.extend_from_slice(suffix);
        assert_eq!(wire(FileKind::AppleP12, &tlv(Tag::Sequence, &changed)), json!({"status":"unavailable","reason":"unsupported-variant"}));
        let unknown_oid_pfx = pfx_fixture(ObjectIdentifier::new_unwrap("1.2.3.4"), Any::null());
        assert!(Pfx::from_der(&unknown_oid_pfx).is_ok());
        for (kind, wrong) in [(FileKind::AppleP12, unknown_oid_pfx),
            (FileKind::AppleProfile, profile_fixture(DATA, Any::new(Tag::OctetString, CANARY.to_vec()).unwrap()))] {
            assert_eq!(wire(kind, &wrong), json!({"status":"unavailable","reason":"unsupported-variant"}));
        }
        for (kind, valid) in [(FileKind::AppleP12, bytes), (FileKind::AppleProfile, profile())] {
            for end in 1..valid.len() { assert_ne!(wire(kind, &valid[..end])["status"], "observed"); }
            let mut trailing = valid.clone(); trailing.extend_from_slice(&[5, 0]);
            assert_eq!(wire(kind, &trailing), json!({"status":"rejected","reason":"malformed-container"}));
            assert!(valid[1] < 128);
            let mut noncanonical = vec![0x30, 0x81, valid[1]]; noncanonical.extend_from_slice(&valid[2..]);
            assert_eq!(wire(kind, &noncanonical), json!({"status":"rejected","reason":"malformed-container"}));
        }
    }
    #[test]
    fn advertised_or_indefinite_lengths_refuse_before_owned_decoding() {
        for bytes in [vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff], vec![0x30, 0x80, 0, 0],
            vec![0x30, 6, 4, 0x84, 0x7f, 0xff, 0xff, 0xff], vec![0x30, 3, 4, 0x81, 0xff]] {
            assert!(matches!(preflight(&bytes, &mut || false), Err(Failure::Malformed)));
            for kind in [FileKind::AppleP12, FileKind::AppleProfile, FileKind::AscP8] {
                assert_eq!(wire(kind, &bytes), json!({"status":"rejected","reason":"malformed-container"}));
            }
        }
        // Private opaque data is not recursively mistaken for another ASN.1
        // document, and is not decrypted merely to give a format observation.
        let opaque = pfx_fixture(DATA, Any::new(Tag::OctetString, vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]).unwrap());
        assert_eq!(wire(FileKind::AppleP12, &opaque)["status"], "observed");
    }
    #[test]
    fn wrong_bit_implicit_lengths_refuse_before_any_owned_decoder() {
        let primitive = Tag::ContextSpecific { constructed: false, number: der_07::TagNumber::N0 };
        let other = Tag::ContextSpecific { constructed: true, number: der_07::TagNumber::N3 };
        // The large advertisement is presented ONLY to the borrowed admission
        // function; never run an owned allocation/OOM experiment. The separate
        // full-envelope regression below advertises only8192 bytes, so even a
        // regressed guard cannot demand a dangerous allocation in this test.
        for (length, full_inspect) in [(&[4, 0x84, 8, 0, 0, 0][..], false), (&[4, 0x82, 0x20, 0][..], true)] {
            let mut body = ObjectIdentifier::new_unwrap("1.2.3").to_der().unwrap();
            body.extend_from_slice(length); // Missing ANY value, hidden in primitive certificates.
            let field = tlv(primitive, &tlv(other, &tlv(Tag::Sequence, &body)));
            for (kind, bytes) in [(FileKind::AppleProfile, profile_fixture(SIGNED_DATA, signed_with_optional_field(&field))),
                (FileKind::AppleP12, pfx_fixture(SIGNED_DATA, signed_with_optional_field(&field)))] {
                assert!(matches!(preflight(&bytes, &mut || false), Err(Failure::UnsupportedVariant)));
                if full_inspect { assert_eq!(wire(kind, &bytes), json!({"status":"unavailable","reason":"unsupported-variant"})); }
            }
        }
    }
    #[test]
    fn primitive_implicit_wrappers_cannot_hide_node_or_set_work() {
        let leaves = [5u8, 0].repeat(SIBLING_LIMIT);
        let branch = tlv(Tag::Sequence, &tlv(Tag::Sequence, &leaves).repeat(64));
        let hidden_nodes = tlv(Tag::Sequence, &branch.repeat(5));
        let hidden_siblings = [5u8, 0].repeat(SIBLING_LIMIT + 1);
        let hidden_set = tlv(Tag::Set, &tlv(Tag::OctetString, &[0; 4096]).repeat(64));
        for body in [&hidden_nodes, &hidden_siblings, &hidden_set] {
            for number in [der_07::TagNumber::N0, der_07::TagNumber::N1] {
                let field = tlv(Tag::ContextSpecific { constructed: false, number }, body);
                let bytes = profile_fixture(SIGNED_DATA, signed_with_optional_field(&field));
                assert!(matches!(preflight(&bytes, &mut || false), Err(Failure::UnsupportedVariant)));
            }
        }
    }
    #[test]
    fn legitimate_primitive_context_fields_are_unsupported_not_malformed() {
        use cms::{cert::x509::ext::pkix::SubjectKeyIdentifier, signed_data::SignerIdentifier};
        use der_07::{asn1::{BitStringRef, ContextSpecific, OctetString}, TagMode, TagNumber};
        let ski = SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(OctetString::new(CANARY).unwrap()));
        let ski_bytes = ski.to_der().unwrap();
        assert!(SignerIdentifier::from_der(&ski_bytes).is_ok()); // Valid library-produced CHOICE.
        let mut fields = vec![ski_bytes];
        for number in [TagNumber::N1, TagNumber::N2] {
            // The real X.509 issuer/subjectUniqueID implicit BIT STRING forms.
            fields.push(ContextSpecific { tag_number: number, tag_mode: TagMode::Implicit,
                value: BitStringRef::from_bytes(CANARY).unwrap() }.to_der().unwrap());
        }
        // Arbitrary primitive-context ANY parameters/attributes are unsupported
        // too; the policy is deliberately not limited to the named examples.
        fields.push(tlv(Tag::ContextSpecific { constructed: false, number: TagNumber::N3 }, CANARY));
        for field in fields {
            assert!(matches!(preflight(&field, &mut || false), Err(Failure::UnsupportedVariant)));
            let bytes = profile_fixture(SIGNED_DATA, Any::new(Tag::Sequence, field.clone()).unwrap());
            assert_eq!(wire(FileKind::AppleProfile, &bytes), json!({"status":"unavailable","reason":"unsupported-variant"}));
            // The same bytes inside a universal data OCTET are private opaque
            // payload, not a context field traversed by these typed decoders.
            let opaque = pfx_fixture(DATA, Any::new(Tag::OctetString, field).unwrap());
            assert_eq!(wire(FileKind::AppleP12, &opaque)["status"], "observed");
        }
    }
    #[test]
    fn depth_nodes_siblings_and_implicit_set_work_are_admitted_before_decode() {
        let mut nested = tlv(Tag::Null, &[]);
        for _ in 1..DEPTH_LIMIT { nested = tlv(Tag::Sequence, &nested); }
        assert!(preflight(&nested, &mut || false).is_ok());
        assert!(matches!(preflight(&tlv(Tag::Sequence, &nested), &mut || false), Err(Failure::Limit(Limit::Depth))));
        let leaves = [5u8, 0].repeat(SIBLING_LIMIT);
        assert!(preflight(&tlv(Tag::Sequence, &leaves), &mut || false).is_ok());
        assert!(matches!(preflight(&tlv(Tag::Sequence, &[5u8, 0].repeat(SIBLING_LIMIT + 1)), &mut || false), Err(Failure::Limit(Limit::Nodes))));
        let branch = tlv(Tag::Sequence, &tlv(Tag::Sequence, &leaves).repeat(64));
        assert!(preflight(&tlv(Tag::Sequence, &branch.repeat(4)), &mut || false).is_ok());
        assert!(matches!(preflight(&tlv(Tag::Sequence, &branch.repeat(5)), &mut || false), Err(Failure::Limit(Limit::Nodes))));
        let large = tlv(Tag::OctetString, &[0; 4096]).repeat(64);
        assert!(preflight(&tlv(Tag::Sequence, &large), &mut || false).is_ok());
        for tag in [Tag::Set, Tag::ContextSpecific { constructed: true, number: der_07::TagNumber::N0 }] {
            assert!(matches!(preflight(&tlv(tag, &large), &mut || false), Err(Failure::Limit(Limit::Asn1Work))));
        }
    }
    #[test]
    fn signed_expansion_limit_is_explicit_without_reducing_ordinary_pfx_data() {
        assert!(signed_admission(SIGNED_INPUT_LIMIT, OWNED_NODE_LIMIT).is_ok());
        assert!(matches!(signed_admission(SIGNED_INPUT_LIMIT + 1, 1), Err(Failure::Limit(Limit::Asn1Work))));
        assert!(matches!(signed_admission(1, OWNED_NODE_LIMIT + 1), Err(Failure::Limit(Limit::Asn1Work))));
        let material = vec![0; SIGNED_INPUT_LIMIT];
        let data = pfx_fixture(DATA, Any::new(Tag::OctetString, material.clone()).unwrap());
        assert_eq!(wire(FileKind::AppleP12, &data)["status"], "observed");
        let signed = pfx_fixture(SIGNED_DATA, signed_body(&material));
        assert_eq!(wire(FileKind::AppleP12, &signed), json!({"status":"unavailable","reason":"parser-limit"}));
        assert_eq!(wire(FileKind::AppleProfile, &profile_fixture(SIGNED_DATA, signed_body(&material))),
            json!({"status":"unavailable","reason":"material-limit"}));
    }
    #[test]
    fn stop_at_each_original_checkpoint_prevents_both_success_and_refusal() {
        for (kind, bytes) in [(FileKind::AppleP12, data_pfx()), (FileKind::AppleP12, signed_pfx()),
            (FileKind::AppleProfile, profile()), (FileKind::AppleProfile, b"<plist/>".to_vec()),
            (FileKind::AppleProfile, profile_fixture(SIGNED_DATA, signed_with_optional_field(&tlv(
                Tag::ContextSpecific { constructed: false, number: der_07::TagNumber::N0 }, CANARY)))),
            (FileKind::AppleP12, vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff])] {
            let mut count = 0;
            assert!(inspect(kind, &bytes, &mut || { count += 1; false }).is_ok());
            for cutoff in 1..=count {
                let mut calls = 0;
                assert!(inspect(kind, &bytes, &mut || { calls += 1; calls >= cutoff }).is_err());
            }
        }
    }
}
