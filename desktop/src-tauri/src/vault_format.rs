//! Bounded v1 vault framing, not authentication or filesystem authority.
//!
//! Parsing a header/record here only checks its closed wire shape. The private
//! crypto owner must authenticate it before using a descriptor or payload, and
//! the store must independently bind the original directory/leaf. No path,
//! credential, parser approval or previously granted assignment is serialized.
use crate::asset_commands::{self as commands, Kind};
use serde::Deserialize;

pub(crate) const RESERVATION_BYTES: usize = 48;
pub(crate) const HEADER_PREFIX_BYTES: usize = 64;
pub(crate) const HEADER_BYTES: usize = 104;
pub(crate) const RECORD_PREFIX_BYTES: usize = 168;
pub(crate) const RECORD_OVERHEAD: usize = 248;
pub(crate) const INTENT_PREFIX_BYTES: usize = 160;
pub(crate) const INTENT_BYTES: usize = 200;
pub(crate) const DESCRIPTOR_LIMIT: usize = 4096;
pub(crate) const SCALAR_LIMIT: usize = 128 * 1024;
pub(crate) const FILE_LIMIT: usize = 32 * 1024 * 1024;
pub(crate) const PAYLOAD_LIMIT: usize = 8 + SCALAR_LIMIT + FILE_LIMIT;
pub(crate) const RECORD_LIMIT: usize = RECORD_OVERHEAD + DESCRIPTOR_LIMIT + PAYLOAD_LIMIT;
pub(crate) const DOMAIN: &[u8] = b"dev.mobile-release-kit.desktop/vault/v1\0";
pub(crate) const RESERVATION_NAME: &str = "initialization-reservation";
pub(crate) const HEADER_NAME: &str = "vault-header";
pub(crate) const LOCK_NAME: &str = "vault-lock";
pub(crate) const INTENT_NAME: &str = ".mutation-intent";

const RESERVATION_MAGIC: &[u8; 8] = b"MRKVRS01";
const HEADER_MAGIC: &[u8; 8] = b"MRKVHD01";
const RECORD_MAGIC: &[u8; 8] = b"MRKVRC01";
const INTENT_MAGIC: &[u8; 8] = b"MRKVIN01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Shape, Identity, Bounds, Allocation }
type Result<T> = std::result::Result<T, Error>;

/// A nonzero syntactic ID. It does not attest a key, vault, record or provider.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Id([u8; 16]);
impl Id {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Result<Self> {
        if bytes == [0; 16] { Err(Error::Identity) } else { Ok(Self(bytes)) }
    }
    pub(crate) fn bytes(&self) -> &[u8; 16] { &self.0 }
    pub(crate) fn token(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(32);
        for byte in self.0 { value.push(char::from(HEX[usize::from(byte >> 4)])); value.push(char::from(HEX[usize::from(byte & 15)])); }
        value
    }
    pub(crate) fn from_token(value: &str) -> Result<Self> {
        fn digit(value: u8) -> Result<u8> {
            match value { b'0'..=b'9' => Ok(value - b'0'), b'a'..=b'f' => Ok(value - b'a' + 10), _ => Err(Error::Shape) }
        }
        if value.len() != 32 { return Err(Error::Shape); }
        let mut bytes = [0; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Self::from_bytes(bytes)
    }
    pub(crate) fn record_name(&self) -> String { format!("record-{}", self.token()) }
    pub(crate) fn candidate_name(&self) -> String { format!(".candidate-{}", self.token()) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Identity { pub(crate) vault: Id, pub(crate) generation: Id }
impl Identity {
    pub(crate) fn new(vault: Id, generation: Id) -> Result<Self> {
        if vault == generation { return Err(Error::Identity); }
        Ok(Self { vault, generation })
    }
    pub(crate) fn reservation(self) -> [u8; RESERVATION_BYTES] {
        let mut out = [0; RESERVATION_BYTES];
        out[..8].copy_from_slice(RESERVATION_MAGIC);
        put16(&mut out, 8, 1); put16(&mut out, 10, 1); put16(&mut out, 12, 1);
        out[16..32].copy_from_slice(self.vault.bytes());
        out[32..48].copy_from_slice(self.generation.bytes());
        out
    }
    pub(crate) fn parse_reservation(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RESERVATION_BYTES || bytes.get(..8) != Some(RESERVATION_MAGIC.as_slice()) { return Err(Error::Shape); }
        identity_prefix(bytes)
    }
    pub(crate) fn header_prefix(self) -> [u8; HEADER_PREFIX_BYTES] {
        let mut out = [0; HEADER_PREFIX_BYTES];
        out[..RESERVATION_BYTES].copy_from_slice(&self.reservation());
        out[..8].copy_from_slice(HEADER_MAGIC);
        out
    }
}

/// A structural header view only. Authentication is deliberately absent here.
pub(crate) struct Header<'a> { bytes: &'a [u8], pub(crate) identity: Identity }
impl<'a> Header<'a> {
    pub(crate) fn parse(bytes: &'a [u8], reservation: Identity) -> Result<Self> {
        if bytes.len() != HEADER_BYTES || bytes.get(..8) != Some(HEADER_MAGIC.as_slice()) || bytes[48..64] != [0; 16] {
            return Err(Error::Shape);
        }
        let identity = identity_prefix(bytes)?;
        if identity != reservation { return Err(Error::Identity); }
        Ok(Self { bytes, identity })
    }
    pub(crate) fn prefix(&self) -> &[u8] { &self.bytes[..HEADER_PREFIX_BYTES] }
    pub(crate) fn nonce(&self) -> &[u8] { &self.bytes[64..88] }
    pub(crate) fn tag(&self) -> &[u8] { &self.bytes[88..104] }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Revision { pub(crate) random: Id, pub(crate) counter: u32 }
impl Revision {
    pub(crate) fn new(random: Id, counter: u32) -> Result<Self> {
        if counter == 0 { Err(Error::Identity) } else { Ok(Self { random, counter }) }
    }
    fn follows(self, previous: Self) -> bool {
        self.random != previous.random && previous.counter.checked_add(1) == Some(self.counter)
    }
}

pub(crate) struct RecordPrefix {
    bytes: [u8; RECORD_PREFIX_BYTES],
    pub(crate) identity: Identity, pub(crate) record: Id, pub(crate) revision: Revision,
    pub(crate) descriptor_length: usize, pub(crate) payload_length: usize,
}
impl RecordPrefix {
    pub(crate) fn new(identity: Identity, record: Id, revision: Revision, descriptor_length: usize,
        payload_length: usize, nonces: [[u8; 24]; 3]) -> Result<Self> {
        let mut bytes = [0; RECORD_PREFIX_BYTES];
        bytes[..8].copy_from_slice(RECORD_MAGIC); put16(&mut bytes, 8, 1); put16(&mut bytes, 10, 1);
        bytes[16..32].copy_from_slice(identity.vault.bytes()); bytes[32..48].copy_from_slice(identity.generation.bytes());
        bytes[48..64].copy_from_slice(record.bytes()); bytes[64..80].copy_from_slice(revision.random.bytes());
        put32(&mut bytes, 80, revision.counter);
        put32(&mut bytes, 84, u32::try_from(descriptor_length).map_err(|_| Error::Bounds)?);
        put64(&mut bytes, 88, u64::try_from(payload_length).map_err(|_| Error::Bounds)?);
        for (slot, nonce) in bytes[96..].chunks_exact_mut(24).zip(nonces) { slot.copy_from_slice(&nonce); }
        Self::parse(&bytes, identity)
    }
    pub(crate) fn parse(bytes: &[u8], identity: Identity) -> Result<Self> {
        if bytes.len() != RECORD_PREFIX_BYTES || bytes.get(..8) != Some(RECORD_MAGIC.as_slice())
            || read16(bytes, 8)? != 1 || read16(bytes, 10)? != 1 || read32(bytes, 12)? != 0 { return Err(Error::Shape); }
        let actual = Identity::new(id_at(bytes, 16)?, id_at(bytes, 32)?)?;
        if actual != identity { return Err(Error::Identity); }
        let record = id_at(bytes, 48)?; let revision = Revision::new(id_at(bytes, 64)?, read32(bytes, 80)?)?;
        if record == identity.vault || record == identity.generation || revision.random == record
            || revision.random == identity.vault || revision.random == identity.generation { return Err(Error::Identity); }
        let descriptor_length = usize::try_from(read32(bytes, 84)?).map_err(|_| Error::Bounds)?;
        let payload_length = usize::try_from(read64(bytes, 88)?).map_err(|_| Error::Bounds)?;
        if !(1..=DESCRIPTOR_LIMIT).contains(&descriptor_length) || !(8..=PAYLOAD_LIMIT).contains(&payload_length) {
            return Err(Error::Bounds);
        }
        if bytes[96..120] == bytes[120..144] || bytes[96..120] == bytes[144..168] || bytes[120..144] == bytes[144..168] {
            return Err(Error::Identity);
        }
        Ok(Self { bytes: bytes.try_into().map_err(|_| Error::Shape)?, identity, record, revision, descriptor_length, payload_length })
    }
    pub(crate) fn bytes(&self) -> &[u8; RECORD_PREFIX_BYTES] { &self.bytes }
    pub(crate) fn nonce(&self, role: RecordRole) -> &[u8] {
        let start = match role { RecordRole::Wrap => 96, RecordRole::Descriptor => 120, RecordRole::Payload => 144 };
        &self.bytes[start..start + 24]
    }
    pub(crate) fn total_length(&self) -> Result<usize> {
        RECORD_OVERHEAD.checked_add(self.descriptor_length).and_then(|n| n.checked_add(self.payload_length)).ok_or(Error::Bounds)
    }
    pub(crate) fn split<'a>(&self, bytes: &'a [u8]) -> Result<RecordSections<'a>> {
        if bytes.len() != self.total_length()? || bytes.get(..RECORD_PREFIX_BYTES) != Some(self.bytes.as_slice()) { return Err(Error::Shape); }
        let descriptor_end = 216 + self.descriptor_length;
        let payload_start = descriptor_end + 16;
        let payload_end = payload_start + self.payload_length;
        Ok(RecordSections { wrapped_key: &bytes[168..200], wrap_tag: &bytes[200..216],
            descriptor: &bytes[216..descriptor_end], descriptor_tag: &bytes[descriptor_end..payload_start],
            payload: &bytes[payload_start..payload_end], payload_tag: &bytes[payload_end..] })
    }
}
pub(crate) struct RecordSections<'a> {
    pub(crate) wrapped_key: &'a [u8], pub(crate) wrap_tag: &'a [u8],
    pub(crate) descriptor: &'a [u8], pub(crate) descriptor_tag: &'a [u8],
    pub(crate) payload: &'a [u8], pub(crate) payload_tag: &'a [u8],
}
#[derive(Clone, Copy)]
pub(crate) enum RecordRole { Wrap, Descriptor, Payload }
impl RecordRole {
    pub(crate) fn aad_role(self) -> &'static [u8] {
        match self { Self::Wrap => b"wrap\0", Self::Descriptor => b"descriptor\0", Self::Payload => b"payload\0" }
    }
}

/// Descriptor DATA is decoded only by the authenticated crypto path. Keeping
/// this decoder private to the crate does not by itself authenticate its input.
pub(crate) struct Descriptor { pub(crate) kind: Kind, pub(crate) label: Option<String>, field_presence: Vec<bool>, file_present: bool }
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DescriptorWire {
    schema_version: u8, kind: String,
    // deserialize_with (without default) requires the key even for JSON null.
    #[serde(deserialize_with = "decode_label")]
    label: Option<String>,
    field_presence: Vec<bool>, file_present: bool,
}
fn decode_label<'de, D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(decoder)
}
pub(crate) fn valid_label(value: Option<&str>) -> bool {
    value.is_none_or(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
}
impl Descriptor {
    pub(crate) fn new(kind: Kind, label: Option<String>, field_presence: Vec<bool>, file_present: bool) -> Result<Self> {
        if !kind.enabled() || !valid_label(label.as_deref()) || field_presence.len() != commands::field_names(kind).len()
            || file_present != kind.file().is_some() { return Err(Error::Shape); }
        Ok(Self { kind, label, field_presence, file_present })
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > DESCRIPTOR_LIMIT { return Err(Error::Bounds); }
        // Primitive-only typed fields reject extra depth, floats, duplicate
        // fields (including escaped spelling), unknown keys and trailing data.
        let wire: DescriptorWire = serde_json::from_slice(bytes).map_err(|_| Error::Shape)?;
        if wire.schema_version != 1 { return Err(Error::Shape); }
        let kind = commands::kind(&serde_json::Value::String(wire.kind)).map_err(|_| Error::Shape)?;
        Self::new(kind, wire.label, wire.field_presence, wire.file_present)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        // An explicit struct preserves the one fixed serialization key order.
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> { schema_version: u8, kind: &'a str, label: Option<&'a str>, field_presence: &'a [bool], file_present: bool }
        let out = serde_json::to_vec(&Wire { schema_version: 1, kind: self.kind.name(), label: self.label.as_deref(),
            field_presence: &self.field_presence, file_present: self.file_present }).map_err(|_| Error::Shape)?;
        if out.len() > DESCRIPTOR_LIMIT { return Err(Error::Bounds); } Ok(out)
    }
    pub(crate) fn presence(&self) -> &[bool] { &self.field_presence }
    pub(crate) fn has_file(&self) -> bool { self.file_present }
    pub(crate) fn retained_bytes(&self) -> Result<usize> {
        std::mem::size_of::<Self>().checked_add(self.label.as_ref().map_or(0, String::capacity))
            .and_then(|n| n.checked_add(self.field_presence.capacity())).ok_or(Error::Bounds)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mutation { New, Replace, Delete }
impl Mutation {
    fn code(self) -> u8 { match self { Self::New => 1, Self::Replace => 2, Self::Delete => 3 } }
}
pub(crate) struct IntentPrefix {
    bytes: [u8; INTENT_PREFIX_BYTES],
    pub(crate) identity: Identity, pub(crate) operation: Mutation, pub(crate) fence: Id, pub(crate) record: Id,
    pub(crate) expected: Option<Revision>, pub(crate) proposed: Option<Revision>,
    pub(crate) candidate_digest: [u8; 32], pub(crate) candidate_length: usize,
}
impl IntentPrefix {
    pub(crate) fn new(identity: Identity, operation: Mutation, fence: Id, record: Id, expected: Option<Revision>,
        proposed: Option<Revision>, candidate_digest: [u8; 32], candidate_length: usize) -> Result<Self> {
        let mut bytes = [0; INTENT_PREFIX_BYTES];
        bytes[..8].copy_from_slice(INTENT_MAGIC); put16(&mut bytes, 8, 1); bytes[10] = operation.code();
        bytes[16..32].copy_from_slice(identity.vault.bytes()); bytes[32..48].copy_from_slice(identity.generation.bytes());
        bytes[48..64].copy_from_slice(fence.bytes()); bytes[64..80].copy_from_slice(record.bytes());
        if let Some(value) = expected { bytes[80..96].copy_from_slice(value.random.bytes()); put32(&mut bytes, 96, value.counter); }
        if let Some(value) = proposed { bytes[100..116].copy_from_slice(value.random.bytes()); put32(&mut bytes, 116, value.counter); }
        bytes[120..152].copy_from_slice(&candidate_digest); put64(&mut bytes, 152, u64::try_from(candidate_length).map_err(|_| Error::Bounds)?);
        Self::parse(&bytes, identity)
    }
    pub(crate) fn parse(bytes: &[u8], identity: Identity) -> Result<Self> {
        if bytes.len() != INTENT_PREFIX_BYTES || bytes.get(..8) != Some(INTENT_MAGIC.as_slice())
            || read16(bytes, 8)? != 1 || bytes[11..16] != [0; 5] { return Err(Error::Shape); }
        let actual = Identity::new(id_at(bytes, 16)?, id_at(bytes, 32)?)?;
        if identity != actual { return Err(Error::Identity); }
        let operation = match bytes[10] { 1 => Mutation::New, 2 => Mutation::Replace, 3 => Mutation::Delete, _ => return Err(Error::Shape) };
        let fence = id_at(bytes, 48)?; let record = id_at(bytes, 64)?;
        if fence == record || [fence, record].iter().any(|id| *id == identity.vault || *id == identity.generation) { return Err(Error::Identity); }
        let expected = optional_revision(bytes, 80, 96)?; let proposed = optional_revision(bytes, 100, 116)?;
        for revision in expected.iter().chain(proposed.iter()) {
            if [identity.vault, identity.generation, fence, record].contains(&revision.random) { return Err(Error::Identity); }
        }
        let candidate_digest: [u8; 32] = bytes[120..152].try_into().map_err(|_| Error::Shape)?;
        let candidate_length = usize::try_from(read64(bytes, 152)?).map_err(|_| Error::Bounds)?;
        let shape = match operation {
            Mutation::New => expected.is_none() && proposed.is_some_and(|p| p.counter == 1),
            Mutation::Replace => expected.zip(proposed).is_some_and(|(e, p)| p.follows(e)),
            Mutation::Delete => expected.is_some() && proposed.is_none(),
        };
        if !shape { return Err(Error::Identity); }
        if operation == Mutation::Delete {
            if candidate_digest != [0; 32] || candidate_length != 0 { return Err(Error::Shape); }
        } else if !(RECORD_OVERHEAD + 9..=RECORD_LIMIT).contains(&candidate_length) { return Err(Error::Bounds); }
        Ok(Self { bytes: bytes.try_into().map_err(|_| Error::Shape)?, identity, operation, fence, record,
            expected, proposed, candidate_digest, candidate_length })
    }
    pub(crate) fn bytes(&self) -> &[u8; INTENT_PREFIX_BYTES] { &self.bytes }
    pub(crate) fn parse_frame<'a>(bytes: &'a [u8], identity: Identity) -> Result<(Self, &'a [u8], &'a [u8])> {
        if bytes.len() != INTENT_BYTES { return Err(Error::Shape); }
        Ok((Self::parse(&bytes[..INTENT_PREFIX_BYTES], identity)?, &bytes[160..184], &bytes[184..200]))
    }
}

fn identity_prefix(bytes: &[u8]) -> Result<Identity> {
    if read16(bytes, 8)? != 1 || read16(bytes, 10)? != 1 || read16(bytes, 12)? != 1 || read16(bytes, 14)? != 0 { return Err(Error::Shape); }
    Identity::new(id_at(bytes, 16)?, id_at(bytes, 32)?)
}
fn optional_revision(bytes: &[u8], offset: usize, counter: usize) -> Result<Option<Revision>> {
    let id: [u8; 16] = range(bytes, offset, 16)?.try_into().map_err(|_| Error::Shape)?;
    let counter = read32(bytes, counter)?;
    if id == [0; 16] && counter == 0 { Ok(None) } else { Revision::new(Id::from_bytes(id)?, counter).map(Some) }
}
fn range(bytes: &[u8], at: usize, count: usize) -> Result<&[u8]> {
    bytes.get(at..at.checked_add(count).ok_or(Error::Bounds)?).ok_or(Error::Shape)
}
fn id_at(bytes: &[u8], offset: usize) -> Result<Id> { Id::from_bytes(range(bytes, offset, 16)?.try_into().map_err(|_| Error::Shape)?) }
fn read16(bytes: &[u8], offset: usize) -> Result<u16> { Ok(u16::from_le_bytes(range(bytes, offset, 2)?.try_into().map_err(|_| Error::Shape)?)) }
fn read32(bytes: &[u8], offset: usize) -> Result<u32> { Ok(u32::from_le_bytes(range(bytes, offset, 4)?.try_into().map_err(|_| Error::Shape)?)) }
fn read64(bytes: &[u8], offset: usize) -> Result<u64> { Ok(u64::from_le_bytes(range(bytes, offset, 8)?.try_into().map_err(|_| Error::Shape)?)) }
fn put16(bytes: &mut [u8], offset: usize, value: u16) { bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes()); }
fn put32(bytes: &mut [u8], offset: usize, value: u32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
fn put64(bytes: &mut [u8], offset: usize, value: u64) { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }

#[cfg(test)]
mod tests {
    use super::*;
    fn id(byte: u8) -> Id { Id::from_bytes([byte; 16]).unwrap() }
    fn identity() -> Identity { Identity::new(id(1), id(2)).unwrap() }
    fn revision(byte: u8, counter: u32) -> Revision { Revision::new(id(byte), counter).unwrap() }
    fn record() -> RecordPrefix { RecordPrefix::new(identity(), id(3), revision(4, 1), 100, 12, [[5; 24], [6; 24], [7; 24]]).unwrap() }

    #[test]
    fn identity_header_and_namespace_are_closed_but_not_authentication() {
        let current = identity(); let reservation = current.reservation();
        assert_eq!(reservation.len(), 48); assert!(Identity::parse_reservation(&reservation) == Ok(current));
        let mut header = [0; HEADER_BYTES]; header[..64].copy_from_slice(&current.header_prefix());
        assert!(Header::parse(&header, current).is_ok()); // A zero tag is only syntactically accepted; crypto must reject it.
        for offset in [0, 8, 10, 12, 14, 48, 63] {
            let mut wrong = header; wrong[offset] ^= 2; assert!(Header::parse(&wrong, current).is_err());
        }
        let other = Identity::new(id(8), id(9)).unwrap(); assert!(Header::parse(&header, other).is_err());
        for length in [0, 47, 49, 103, 105] {
            assert!(Identity::parse_reservation(&vec![0; length]).is_err());
            assert!(Header::parse(&vec![0; length], current).is_err());
        }
        assert!(Id::from_token("00000000000000000000000000000000").is_err());
        assert!(Id::from_token("ABCDEFABCDEFABCDEFABCDEFABCDEFABCD").is_err());
        assert!(Id::from_token(&id(0x8f).token()) == Ok(id(0x8f)));
        assert_eq!(id(3).record_name(), "record-03030303030303030303030303030303");
        assert_eq!(id(4).candidate_name(), ".candidate-04040404040404040404040404040404");
    }

    #[test]
    fn record_lengths_sections_revisions_and_nonce_roles_are_exact() {
        let prefix = record(); assert_eq!(prefix.total_length().unwrap(), 360);
        let mut bytes = vec![0; 360]; bytes[..168].copy_from_slice(prefix.bytes());
        let sections = prefix.split(&bytes).unwrap();
        assert_eq!([sections.wrapped_key.len(), sections.wrap_tag.len(), sections.descriptor.len(), sections.descriptor_tag.len(),
            sections.payload.len(), sections.payload_tag.len()], [32, 16, 100, 16, 12, 16]);
        for offset in [0, 8, 10, 12, 16, 32, 48, 64, 80] {
            let mut wrong = *prefix.bytes();
            match offset { 48 => wrong[48..64].fill(0), 64 => wrong[64..80].fill(0), 80 => wrong[80..84].fill(0), _ => wrong[offset] ^= 2 }
            assert!(RecordPrefix::parse(&wrong, identity()).is_err());
        }
        for (d, p) in [(0, 8), (4097, 8), (1, 7), (1, PAYLOAD_LIMIT + 1), (usize::MAX, 8), (1, usize::MAX)] {
            assert!(RecordPrefix::new(identity(), id(3), revision(4, 1), d, p, [[5; 24], [6; 24], [7; 24]]).is_err());
        }
        assert!(RecordPrefix::new(identity(), id(3), revision(4, 1), 1, 8, [[5; 24]; 3]).is_err());
        assert!(prefix.split(&bytes[..359]).is_err()); bytes.push(0); assert!(prefix.split(&bytes).is_err());
        let mut overflow = *prefix.bytes(); overflow[88..96].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(RecordPrefix::parse(&overflow, identity()).is_err());
        assert_eq!(prefix.nonce(RecordRole::Wrap), &[5; 24]); assert_eq!(prefix.nonce(RecordRole::Descriptor), &[6; 24]);
        assert_eq!(prefix.nonce(RecordRole::Payload), &[7; 24]);
    }

    #[test]
    fn descriptor_requires_every_exact_typed_key_and_current_kind_presence() {
        for kind in [Kind::AndroidKeystore, Kind::AndroidFirebase, Kind::IosFirebase, Kind::AscP8, Kind::GoogleWif, Kind::ProjectReadToken,
            Kind::AppleReviewContact, Kind::AppleReviewDemoAccount] {
            let original = Descriptor::new(kind, Some("Personal development".into()), vec![false; commands::field_names(kind).len()], kind.file().is_some()).unwrap();
            let raw = original.encode().unwrap(); let decoded = Descriptor::decode(&raw).unwrap();
            assert!(decoded.kind == kind); assert_eq!(decoded.label.as_deref(), Some("Personal development"));
            assert_eq!(decoded.presence(), original.presence()); assert_eq!(decoded.has_file(), kind.file().is_some());
        }
        let good = r#"{"schemaVersion":1,"kind":"ios-firebase","label":null,"fieldPresence":[],"filePresent":true}"#;
        assert!(Descriptor::decode(good.as_bytes()).is_ok());
        for wrong in [good.replace("\"label\":null,", ""), good.replace("\"label\":null", "\"label\":null,\"label\":null"),
            good.replace("\"label\":null", "\"label\":null,\"labe\\u006c\":null"), good.replace("\"label\":null", "\"label\":[]"),
            good.replace("\"label\":null", "\"label\":\"\""), good.replace("\"label\":null", "\"label\":\"bad\\nlabel\""),
            good.replace("\"fieldPresence\":[]", "\"fieldPresence\":[false]"), good.replace("true", "1"),
            good.replace("true", "false"), good.replace(":1,", ":1.0,"), good.replace("ios-firebase", "apple-p12"),
            good.replace("ios-firebase", "unknown"), good.replace("null", "{\"x\":{\"y\":0}}"),
            good.replace("true}", "true,\"approval\":true}"), format!("{good} true")] {
            assert!(Descriptor::decode(wrong.as_bytes()).is_err(), "descriptor shape accepted");
        }
        assert!(valid_label(Some("Development 🔐"))); assert!(!valid_label(Some(&"é".repeat(65))));
        assert!(!valid_label(Some("\0"))); assert!(!valid_label(Some("\u{0085}")));
    }

    #[test]
    fn asc_descriptor_has_exact_two_presence_cells_and_no_persisted_approval() {
        for presence in [vec![false, false], vec![true, false], vec![false, true], vec![true, true]] {
            let descriptor = Descriptor::new(Kind::AscP8, None, presence.clone(), true).unwrap();
            let encoded = descriptor.encode().unwrap();
            let decoded = Descriptor::decode(&encoded).unwrap();
            assert!(decoded.kind == Kind::AscP8 && decoded.has_file());
            assert_eq!(decoded.presence(), presence);
            let wire: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(wire, serde_json::json!({"schemaVersion":1,"kind":"asc-p8","label":null,
                "fieldPresence":presence,"filePresent":true}));
        }
        for presence in [vec![], vec![true], vec![true, true, false]] {
            assert!(Descriptor::new(Kind::AscP8, None, presence, true).is_err());
        }
        assert!(Descriptor::new(Kind::AscP8, None, vec![true, true], false).is_err());
        let good = r#"{"schemaVersion":1,"kind":"asc-p8","label":null,"fieldPresence":[true,false],"filePresent":true}"#;
        for wrong in [
            good.replace(r#""fieldPresence":[true,false],"#, ""),
            good.replace(r#""fieldPresence":[true,false]"#, r#""fieldPresence":[true]"#),
            good.replace(r#""fieldPresence":[true,false]"#, r#""fieldPresence":[true,false,true]"#),
            good.replace(r#""fieldPresence":[true,false]"#, r#""fieldPresence":[1,null]"#),
            good.replace(r#""kind":"asc-p8""#, r#""kind":"asc-p8","ki\u006ed":"asc-p8""#),
            good.replace(r#""filePresent":true"#, r#""filePresent":true,"filePresent":true"#),
            good.replace(r#""filePresent":true"#, r#""filePresent":false"#),
            good.replace(r#""filePresent":true"#, r#""filePresent":true,"approval":{"algorithm":"ec","curve":"p256"}"#),
        ] { assert!(Descriptor::decode(wrong.as_bytes()).is_err()); }
    }


    #[test]
    fn private_review_descriptors_keep_exact_presence_without_files_values_or_approval() {
        for (kind, count) in [(Kind::AppleReviewContact, 4), (Kind::AppleReviewDemoAccount, 2), (Kind::AppleOperationCommitment, 2)] {
            for presence in [vec![false; count], vec![true; count]] {
                let descriptor = Descriptor::new(kind, None, presence.clone(), false).unwrap();
                let encoded = descriptor.encode().unwrap();
                let decoded = Descriptor::decode(&encoded).unwrap();
                assert!(decoded.kind == kind && !decoded.has_file());
                assert_eq!(decoded.presence(), presence);
                let wire: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
                assert_eq!(wire, serde_json::json!({"schemaVersion":1,"kind":kind.name(),"label":null,
                    "fieldPresence":presence,"filePresent":false}));
                let mut wrong_kind = wire.clone(); wrong_kind["kind"] = serde_json::json!("unknown-future-private-kind");
                assert!(Descriptor::decode(&serde_json::to_vec(&wrong_kind).unwrap()).is_err());
                let mut value = wire.clone(); value["fields"] = serde_json::json!({"password":"private-canary"});
                assert!(Descriptor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
                let mut approval = wire.clone(); approval["approval"] = serde_json::json!(true);
                assert!(Descriptor::decode(&serde_json::to_vec(&approval).unwrap()).is_err());
            }
            for cells in [0, count - 1, count + 1] {
                assert!(Descriptor::new(kind, None, vec![true; cells], false).is_err());
            }
            assert!(Descriptor::new(kind, None, vec![true; count], true).is_err());
        }
    }

    #[test]
    fn mutation_fence_has_exact_new_replace_delete_and_zero_absence_rules() {
        let cases = [(Mutation::New, None, Some(revision(5, 1)), [7; 32], 360),
            (Mutation::Replace, Some(revision(4, 1)), Some(revision(5, 2)), [7; 32], 360),
            (Mutation::Delete, Some(revision(4, 1)), None, [0; 32], 0)];
        for (operation, expected, proposed, digest, length) in cases {
            let original = IntentPrefix::new(identity(), operation, id(8), id(3), expected, proposed, digest, length).unwrap();
            let mut frame = [0; INTENT_BYTES]; frame[..160].copy_from_slice(original.bytes());
            let (decoded, nonce, tag) = IntentPrefix::parse_frame(&frame, identity()).unwrap();
            assert!(decoded.operation == operation && decoded.expected == expected && decoded.proposed == proposed);
            assert_eq!((decoded.candidate_digest, decoded.candidate_length, nonce.len(), tag.len()), (digest, length, 24, 16));
            for offset in [0, 8, 10, 11, 12, 15, 16, 32] {
                let mut wrong = frame; wrong[offset] ^= 0xff; assert!(IntentPrefix::parse_frame(&wrong, identity()).is_err());
            }
            assert!(IntentPrefix::parse_frame(&frame[..199], identity()).is_err());
            assert!(IntentPrefix::parse_frame(&[0; 201], identity()).is_err());
        }
        for (operation, expected, proposed, digest, length) in [
            (Mutation::New, Some(revision(4, 1)), Some(revision(5, 1)), [7; 32], 360),
            (Mutation::New, None, Some(revision(5, 2)), [7; 32], 360),
            (Mutation::Replace, Some(revision(4, 1)), Some(revision(4, 2)), [7; 32], 360),
            (Mutation::Replace, Some(revision(4, 1)), Some(revision(5, 3)), [7; 32], 360),
            (Mutation::Replace, Some(revision(4, u32::MAX)), Some(revision(5, 1)), [7; 32], 360),
            (Mutation::Delete, Some(revision(4, 1)), Some(revision(5, 2)), [0; 32], 0),
            (Mutation::Delete, Some(revision(4, 1)), None, [7; 32], 0),
            (Mutation::Delete, Some(revision(4, 1)), None, [0; 32], 360),
        ] { assert!(IntentPrefix::new(identity(), operation, id(8), id(3), expected, proposed, digest, length).is_err()); }
    }
}
