//! Private v1 authenticated storage codec. No filesystem, IPC, provider prompt,
//! signing, parser approval or task lifetime is created here. The document
//! supplies the original operation and actual memory allowance. Authentication
//! alone is not native original/finality authority.
use crate::{asset_commands::{self as commands, Fields}, asset_source,
    vault_format::{self as format, Descriptor, Id, Identity, IntentPrefix, Mutation, RecordPrefix, RecordRole, Revision}};
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use serde::{de::{self, DeserializeSeed, MapAccess, Visitor}, Deserialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{fmt, io::{self, Write}, ops::Range};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Format, Authentication, Random, Bounds, Allocation }
type Result<T> = std::result::Result<T, Error>;
impl From<format::Error> for Error {
    fn from(error: format::Error) -> Self {
        match error { format::Error::Bounds => Self::Bounds, format::Error::Allocation => Self::Allocation, _ => Self::Format }
    }
}

// Bounded scalar/descriptor, serde scratch, cipher state and fixed cells. The
// record buffer is charged separately at ACTUAL capacity. This conservative
// source-informed allowance is not an allocator/RSS or total erasure guarantee.
pub(crate) const CONTROL_BYTES: usize = 512 * 1024;
const AAD_BYTES: usize = format::DOMAIN.len() + format::RECORD_PREFIX_BYTES + 11;
fn capacity(owned: usize, allowance: usize) -> Result<()> {
    if allowance > crate::vault_store::WORKING_BYTES
        || owned.checked_add(CONTROL_BYTES).is_none_or(|value| value > allowance) { Err(Error::Bounds) } else { Ok(()) }
}
fn buffer(length: usize, allowance: usize) -> Result<Zeroizing<Vec<u8>>> {
    capacity(length, allowance)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length).map_err(|_| Error::Allocation)?;
    capacity(bytes.capacity(), allowance)?;
    bytes.resize(length, 0); Ok(bytes)
}
trait Entropy { fn fill(&mut self, output: &mut [u8]) -> Result<()>; }
struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<()> { getrandom::fill(output).map_err(|_| Error::Random) }
}
fn fresh_id(random: &mut impl Entropy) -> Result<Id> {
    let mut bytes = [0; 16]; random.fill(&mut bytes)?;
    Id::from_bytes(bytes).map_err(|_| Error::Random)
}
fn random_key(random: &mut impl Entropy) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]); random.fill(&mut key[..])?;
    if key.iter().all(|byte| *byte == 0) { return Err(Error::Random); } Ok(key)
}
fn nonce(random: &mut impl Entropy) -> Result<[u8; 24]> {
    let mut nonce = [0; 24]; random.fill(&mut nonce)?; Ok(nonce)
}
fn new_identity_with(random: &mut impl Entropy) -> Result<Identity> {
    Identity::new(fresh_id(random)?, fresh_id(random)?).map_err(|_| Error::Random)
}
pub(crate) fn new_identity() -> Result<Identity> { new_identity_with(&mut OsEntropy) }

struct Aad { bytes: [u8; AAD_BYTES], length: usize }
impl Aad {
    fn new(prefix: &[u8], role: &[u8]) -> Result<Self> {
        if !matches!((prefix.len(), role), (64, b"header\0") | (160, b"intent\0")
            | (168, b"wrap\0") | (168, b"descriptor\0") | (168, b"payload\0")) { return Err(Error::Format); }
        let mut result = Self { bytes: [0; AAD_BYTES], length: 0 };
        for part in [format::DOMAIN, prefix, role] {
            let end = result.length.checked_add(part.len()).filter(|end| *end <= AAD_BYTES).ok_or(Error::Bounds)?;
            result.bytes[result.length..end].copy_from_slice(part); result.length = end;
        }
        Ok(result)
    }
    fn bytes(&self) -> &[u8] { &self.bytes[..self.length] }
}
fn seal(cipher: &XChaCha20Poly1305, nonce: &[u8], prefix: &[u8], role: &[u8], bytes: &mut [u8]) -> Result<[u8; 16]> {
    let nonce = XNonce::try_from(nonce).map_err(|_| Error::Format)?; let aad = Aad::new(prefix, role)?;
    let tag = cipher.encrypt_inout_detached(&nonce, aad.bytes(), bytes.into()).map_err(|_| Error::Authentication)?;
    Ok(tag.into())
}
fn open(cipher: &XChaCha20Poly1305, nonce: &[u8], prefix: &[u8], role: &[u8], bytes: &mut [u8], tag: &[u8]) -> Result<()> {
    let nonce = XNonce::try_from(nonce).map_err(|_| Error::Format)?;
    let tag = Tag::try_from(tag).map_err(|_| Error::Format)?; let aad = Aad::new(prefix, role)?;
    cipher.decrypt_inout_detached(&nonce, aad.bytes(), bytes.into(), &tag).map_err(|_| Error::Authentication)
}
fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    // This borrows the32-byte source; the cipher's own key and temporary
    // stream/MAC states use the sealed zeroization feature set.
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Format)
}
fn make_header(identity: Identity, key: &[u8; 32], nonce: [u8; 24]) -> Result<[u8; format::HEADER_BYTES]> {
    let prefix = identity.header_prefix(); let mut bytes = [0; format::HEADER_BYTES];
    bytes[..64].copy_from_slice(&prefix); bytes[64..88].copy_from_slice(&nonce);
    bytes[88..].copy_from_slice(&seal(&cipher(key)?, &nonce, &prefix, b"header\0", &mut [])?); Ok(bytes)
}

/// Proposed key for ONE explicit initialization. It creates no provider item
/// or durable state. A retrieved candidate must later authenticate this exact
/// header before the document may publish any usable lease.
pub(crate) struct InitializationKey { bytes: Zeroizing<[u8; 32]>, header: [u8; format::HEADER_BYTES] }
impl InitializationKey {
    pub(crate) fn generate(identity: Identity) -> Result<Self> { Self::generate_with(identity, &mut OsEntropy) }
    fn generate_with(identity: Identity, random: &mut impl Entropy) -> Result<Self> {
        let bytes = random_key(random)?; let header = make_header(identity, &bytes, nonce(random)?)?;
        Ok(Self { bytes, header })
    }
    pub(crate) fn header(&self) -> &[u8; format::HEADER_BYTES] { &self.header }
    pub(crate) fn retained_bytes(&self) -> usize { std::mem::size_of::<Self>() }
    /// The checked SDK encrypts synchronously inside this consuming callback.
    /// Original key storage stays charged until callback return and erasure.
    pub(crate) fn consume_for_transport<R>(self, encrypt: impl FnOnce(&[u8; 32]) -> R) -> ([u8; format::HEADER_BYTES], R) {
        (self.header, encrypt(&self.bytes))
    }
}

/// Authenticated cipher ownership, NOT document permission/native finality.
/// No raw getter, Clone, Debug, serde or renderer key surface. The document must
/// charge this actual retained lease before refunding the original transport.
pub(crate) struct VaultKey { cipher: XChaCha20Poly1305, identity: Identity, header_nonce: [u8; 24] }
#[cfg(all(test, debug_assertions))]
pub(crate) fn lifecycle_data_key(identity: Identity) -> VaultKey {
    // Inert codec/lifecycle DATA only. This is no provider/document/native
    // admission, never compiled into an installed production application.
    let header = make_header(identity, &[73; 32], [74; 24]).expect("fixed test header");
    VaultKey::authenticate(&[73; 32], identity, &header).expect("fixed test authentication")
}
impl VaultKey {
    pub(crate) fn authenticate_candidate(candidate: secret_service::checked_lookup::WrappingKeyCandidate,
        identity: Identity, bytes: &[u8; format::HEADER_BYTES]) -> Result<Self> {
        candidate.consume(|key| Self::authenticate(key, identity, bytes))
    }
    fn authenticate(key: &[u8; 32], identity: Identity, bytes: &[u8; format::HEADER_BYTES]) -> Result<Self> {
        let header = format::Header::parse(bytes, identity)?; let cipher = cipher(key)?;
        open(&cipher, header.nonce(), header.prefix(), b"header\0", &mut [], header.tag())?;
        Ok(Self { cipher, identity, header_nonce: header.nonce().try_into().map_err(|_| Error::Format)? })
    }
    pub(crate) fn identity(&self) -> Identity { self.identity }
    pub(crate) fn retained_bytes(&self) -> usize { std::mem::size_of::<Self>() }
    pub(crate) fn new_record_id(&self, existing: &[Id]) -> Result<Id> {
        if existing.len() > crate::vault_store::DESCRIPTOR_COUNT { return Err(Error::Bounds); }
        let id = fresh_id(&mut OsEntropy)?;
        if existing.contains(&id) || [self.identity.vault, self.identity.generation].contains(&id) { return Err(Error::Random); } Ok(id)
    }
    pub(crate) fn seal_record(&self, record: Id, previous: Option<Revision>, descriptor: &Descriptor,
        fields: &Fields, file: Option<&[u8]>, allowance: usize) -> Result<SealedRecord> {
        self.seal_record_with(record, previous, descriptor, fields, file, allowance, &mut OsEntropy)
    }
    fn seal_record_with(&self, record: Id, previous: Option<Revision>, descriptor: &Descriptor,
        fields: &Fields, file: Option<&[u8]>, allowance: usize, random: &mut impl Entropy) -> Result<SealedRecord> {
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
        let payload_length = 8usize.checked_add(scalars).and_then(|value| value.checked_add(file_length)).ok_or(Error::Bounds)?;
        let descriptor_bytes = Zeroizing::new(descriptor.encode()?);
        let counter = previous.map_or(Some(1), |previous| previous.counter.checked_add(1)).ok_or(Error::Bounds)?;
        let revision = Revision::new(fresh_id(random)?, counter)?;
        if previous.is_some_and(|previous| previous.random == revision.random) { return Err(Error::Random); }
        let data_key = random_key(random)?; let nonces = [nonce(random)?, nonce(random)?, nonce(random)?];
        if nonces[0] == self.header_nonce { return Err(Error::Random); }
        let prefix = RecordPrefix::new(self.identity, record, revision, descriptor_bytes.len(), payload_length, nonces)?;
        let mut bytes = buffer(prefix.total_length()?, allowance)?;
        bytes[..168].copy_from_slice(prefix.bytes()); bytes[168..200].copy_from_slice(&data_key[..]);
        let descriptor_end = 216 + descriptor_bytes.len(); let payload_start = descriptor_end + 16;
        let payload_end = payload_start + payload_length;
        bytes[216..descriptor_end].copy_from_slice(&descriptor_bytes);
        bytes[payload_start..payload_start + 4].copy_from_slice(&u32::try_from(scalars).map_err(|_| Error::Bounds)?.to_le_bytes());
        bytes[payload_start + 4..payload_start + 8].copy_from_slice(&u32::try_from(file_length).map_err(|_| Error::Bounds)?.to_le_bytes());
        let scalar_start = payload_start + 8; let file_start = scalar_start + scalars;
        let mut scalar_writer = SliceWriter { bytes: &mut bytes[scalar_start..file_start], written: 0 };
        fields.write_vault_scalars(&mut scalar_writer).map_err(|_| Error::Format)?;
        if scalar_writer.written != scalars { return Err(Error::Format); }
        if let Some(file) = file { bytes[file_start..payload_end].copy_from_slice(file); }
        let data_cipher = cipher(&data_key[..])?;
        let wrapped = seal(&self.cipher, prefix.nonce(RecordRole::Wrap), prefix.bytes(), b"wrap\0", &mut bytes[168..200])?;
        bytes[200..216].copy_from_slice(&wrapped);
        let tag = seal(&data_cipher, prefix.nonce(RecordRole::Descriptor), prefix.bytes(), b"descriptor\0", &mut bytes[216..descriptor_end])?;
        bytes[descriptor_end..payload_start].copy_from_slice(&tag);
        let tag = seal(&data_cipher, prefix.nonce(RecordRole::Payload), prefix.bytes(), b"payload\0", &mut bytes[payload_start..payload_end])?;
        bytes[payload_end..].copy_from_slice(&tag);
        // Only after all sections are ciphertext can this become ordinary
        // storage backing. Every earlier exit zeroizes the owned buffer.
        Ok(SealedRecord { prefix, bytes: std::mem::take(&mut *bytes) })
    }
    pub(crate) fn seal_intent(&self, operation: Mutation, record: Id, expected: Option<Revision>, candidate: Option<&SealedRecord>)
        -> Result<[u8; format::INTENT_BYTES]> {
        self.seal_intent_with(operation, record, expected, candidate, &mut OsEntropy)
    }
    fn seal_intent_with(&self, operation: Mutation, record: Id, expected: Option<Revision>, candidate: Option<&SealedRecord>, random: &mut impl Entropy)
        -> Result<[u8; format::INTENT_BYTES]> {
        if (operation == Mutation::Delete) != candidate.is_none() { return Err(Error::Format); }
        let (proposed, digest, length) = if let Some(candidate) = candidate {
            if candidate.prefix.identity != self.identity || candidate.prefix.record != record { return Err(Error::Format); }
            (Some(candidate.prefix.revision), Sha256::digest(&candidate.bytes).into(), candidate.bytes.len())
        } else { (None, [0; 32], 0) };
        let prefix = IntentPrefix::new(self.identity, operation, fresh_id(random)?, record, expected, proposed, digest, length)?;
        let nonce = nonce(random)?;
        if nonce == self.header_nonce || candidate.is_some_and(|candidate| candidate.prefix.nonce(RecordRole::Wrap) == nonce) {
            return Err(Error::Random);
        }
        let mut bytes = [0; format::INTENT_BYTES]; bytes[..160].copy_from_slice(prefix.bytes()); bytes[160..184].copy_from_slice(&nonce);
        bytes[184..].copy_from_slice(&seal(&self.cipher, &nonce, prefix.bytes(), b"intent\0", &mut [])?); Ok(bytes)
    }
    pub(crate) fn authenticate_intent(&self, bytes: &[u8; format::INTENT_BYTES]) -> Result<IntentPrefix> {
        let (prefix, nonce, tag) = IntentPrefix::parse_frame(bytes, self.identity)?;
        open(&self.cipher, nonce, prefix.bytes(), b"intent\0", &mut [], tag)?; Ok(prefix)
    }
    fn prefix_key(&self, bytes: &[u8]) -> Result<(RecordPrefix, XChaCha20Poly1305)> {
        let prefix = RecordPrefix::parse(bytes.get(..168).ok_or(Error::Format)?, self.identity)?;
        let mut data_key = Zeroizing::new([0; 32]); data_key.copy_from_slice(bytes.get(168..200).ok_or(Error::Format)?);
        open(&self.cipher, prefix.nonce(RecordRole::Wrap), prefix.bytes(), b"wrap\0", &mut data_key[..], bytes.get(200..216).ok_or(Error::Format)?)?;
        let cipher = cipher(&data_key[..])?; Ok((prefix, cipher))
    }
    /// Listing deliberately authenticates only wrapped key + descriptor. The
    /// result contains no payload or persisted parser/approval object.
    pub(crate) fn open_descriptor(&self, bytes: &[u8], allowance: usize) -> Result<AuthenticatedDescriptor> {
        capacity(bytes.len(), allowance)?;
        let (prefix, data_cipher) = self.prefix_key(bytes)?;
        let descriptor_end = 216 + prefix.descriptor_length;
        if bytes.len() != descriptor_end + 16 { return Err(Error::Format); }
        let mut descriptor = buffer(prefix.descriptor_length, allowance)?;
        descriptor.copy_from_slice(&bytes[216..descriptor_end]);
        open(&data_cipher, prefix.nonce(RecordRole::Descriptor), prefix.bytes(), b"descriptor\0", &mut descriptor, &bytes[descriptor_end..])?;
        Ok(AuthenticatedDescriptor { record: prefix.record, revision: prefix.revision, descriptor: Descriptor::decode(&descriptor)? })
    }
    /// Transfer complete ciphertext backing rather than clone a32MiB payload.
    /// Only the authenticated file slice becomes stored material; it is never a
    /// CapturedSource, saved approval or pathname reopen capability.
    pub(crate) fn open_record(&self, bytes: Vec<u8>, allowance: usize) -> Result<AuthenticatedRecord> {
        let mut bytes = Zeroizing::new(bytes); capacity(bytes.capacity(), allowance)?;
        let (prefix, data_cipher) = self.prefix_key(&bytes)?;
        prefix.split(&bytes)?; // Exact total length before plaintext use.
        let descriptor_end = 216 + prefix.descriptor_length; let payload_start = descriptor_end + 16;
        let payload_end = payload_start + prefix.payload_length;
        let descriptor_tag: [u8; 16] = bytes[descriptor_end..payload_start].try_into().map_err(|_| Error::Format)?;
        open(&data_cipher, prefix.nonce(RecordRole::Descriptor), prefix.bytes(), b"descriptor\0", &mut bytes[216..descriptor_end], &descriptor_tag)?;
        let descriptor = Descriptor::decode(&bytes[216..descriptor_end])?;
        let payload_tag: [u8; 16] = bytes[payload_end..].try_into().map_err(|_| Error::Format)?;
        open(&data_cipher, prefix.nonce(RecordRole::Payload), prefix.bytes(), b"payload\0", &mut bytes[payload_start..payload_end], &payload_tag)?;
        let (fields, file) = decode_payload(&descriptor, &bytes[payload_start..payload_end])?;
        let file = file.map(|range| range.start + payload_start..range.end + payload_start);
        let stored = if let Some(range) = file {
            bytes[..range.start].zeroize(); bytes[range.end..].zeroize();
            Some(StoredBytes { bytes, file: range })
        } else { None }; // Entire scalar-only backing is wiped at return.
        Ok(AuthenticatedRecord { record: prefix.record, revision: prefix.revision, descriptor, fields, file: stored })
    }
}

pub(crate) struct SealedRecord { prefix: RecordPrefix, bytes: Vec<u8> }
impl SealedRecord {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn revision(&self) -> Revision { self.prefix.revision }
    pub(crate) fn retained_bytes(&self) -> Result<usize> { self.bytes.capacity().checked_add(std::mem::size_of::<Self>()).ok_or(Error::Bounds) }
}
pub(crate) struct AuthenticatedDescriptor { pub(crate) record: Id, pub(crate) revision: Revision, pub(crate) descriptor: Descriptor }
pub(crate) struct StoredBytes { bytes: Zeroizing<Vec<u8>>, file: Range<usize> }
impl StoredBytes {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes[self.file.clone()] }
    pub(crate) fn retained_bytes(&self) -> Result<usize> { self.bytes.capacity().checked_add(std::mem::size_of::<Self>()).ok_or(Error::Bounds) }
}
pub(crate) struct AuthenticatedRecord {
    pub(crate) record: Id, pub(crate) revision: Revision, pub(crate) descriptor: Descriptor,
    pub(crate) fields: Fields, pub(crate) file: Option<StoredBytes>,
}

struct ScalarCount(usize);
impl Write for ScalarCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).filter(|length| *length <= format::SCALAR_LIMIT)
            .ok_or_else(|| io::Error::other("vault scalar bound"))?; Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
struct SliceWriter<'a> { bytes: &'a mut [u8], written: usize }
impl Write for SliceWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self.written.checked_add(bytes.len()).filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| io::Error::other("vault scalar bound"))?;
        self.bytes[self.written..end].copy_from_slice(bytes); self.written = end; Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
struct PrivateText(Zeroizing<String>);
impl<'de> Deserialize<'de> for PrivateText {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct Text;
        impl<'de> Visitor<'de> for Text {
            type Value = PrivateText;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str("a scalar string") }
            fn visit_str<E: de::Error>(self, text: &str) -> std::result::Result<Self::Value, E> {
                Ok(PrivateText(Zeroizing::new(text.to_owned())))
            }
            fn visit_string<E: de::Error>(self, text: String) -> std::result::Result<Self::Value, E> {
                Ok(PrivateText(Zeroizing::new(text)))
            }
        }
        decoder.deserialize_string(Text)
    }
}
struct PrivateScalars(Value);
impl Drop for PrivateScalars {
    fn drop(&mut self) {
        // Only our closed one-level string/null map can inhabit this wrapper.
        if let Value::Object(object) = &mut self.0 {
            for value in object.values_mut() { if let Value::String(value) = value { value.zeroize(); } }
        }
    }
}
struct ScalarSeed { kind: commands::Kind }
impl<'de> DeserializeSeed<'de> for ScalarSeed {
    type Value = PrivateScalars;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> std::result::Result<Self::Value, D::Error> {
        impl<'de> Visitor<'de> for ScalarSeed {
            type Value = PrivateScalars;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str("the exact scalar field object") }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<Self::Value, M::Error> {
                let names = commands::field_names(self.kind);
                // The current closed kinds have at most four scalar fields. A
                // future larger layout must refuse, never index past this bound.
                let mut seen = [false; 4];
                let Some(seen) = seen.get_mut(..names.len()) else {
                    return Err(de::Error::custom("unsupported scalar field count"));
                };
                let mut object = PrivateScalars(Value::Object(Map::new()));
                while let Some(key) = map.next_key::<PrivateText>()? {
                    let index = names.iter().position(|name| *name == key.0.as_str())
                        .filter(|index| !seen[*index]).ok_or_else(|| de::Error::custom("unknown or repeated scalar key"))?;
                    seen[index] = true;
                    let value = map.next_value::<Option<PrivateText>>()?;
                    let value = match value { Some(mut text) => Value::String(std::mem::take(&mut *text.0)), None => Value::Null };
                    if let Value::Object(object) = &mut object.0 { object.insert(names[index].to_owned(), value); }
                }
                if seen.contains(&false) { return Err(de::Error::custom("missing scalar key")); }
                Ok(object)
            }
        }
        decoder.deserialize_map(self)
    }
}
fn decode_payload(descriptor: &Descriptor, payload: &[u8]) -> Result<(Fields, Option<Range<usize>>)> {
    if payload.len() < 8 || payload.len() > format::PAYLOAD_LIMIT { return Err(Error::Bounds); }
    let scalar_length = u32::from_le_bytes(payload[..4].try_into().map_err(|_| Error::Format)?) as usize;
    let file_length = u32::from_le_bytes(payload[4..8].try_into().map_err(|_| Error::Format)?) as usize;
    if scalar_length > format::SCALAR_LIMIT { return Err(Error::Bounds); }
    let scalar_end = 8usize.checked_add(scalar_length).ok_or(Error::Bounds)?;
    let end = scalar_end.checked_add(file_length).ok_or(Error::Bounds)?;
    if end != payload.len() { return Err(Error::Format); }
    let file = match descriptor.kind.file() {
        Some(kind) if descriptor.has_file() && file_length <= asset_source::material_limit(kind) => Some(scalar_end..end),
        None if !descriptor.has_file() && file_length == 0 => None,
        _ => return Err(Error::Bounds),
    };
    // Generic Value parsing would erase duplicate keys. This seed rejects them,
    // unknown keys/depth/types before the existing scalar semantics run.
    let mut decoder = serde_json::Deserializer::from_slice(&payload[8..scalar_end]);
    let values = ScalarSeed { kind: descriptor.kind }.deserialize(&mut decoder).map_err(|_| Error::Format)?;
    decoder.end().map_err(|_| Error::Format)?;
    commands::validate_fields(descriptor.kind, &values.0).map_err(|_| Error::Format)?;
    let fields = commands::own_fields(descriptor.kind, &values.0).map_err(|_| Error::Format)?;
    if fields.vault_presence() != descriptor.presence() { return Err(Error::Format); }
    Ok((fields, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    const ALLOWANCE: usize = crate::vault_store::WORKING_BYTES;
    fn id(byte: u8) -> Id { Id::from_bytes([byte; 16]).unwrap() }
    fn identity() -> Identity { Identity::new(id(1), id(2)).unwrap() }
    fn key() -> VaultKey { VaultKey::authenticate(&[9; 32], identity(), &make_header(identity(), &[9; 32], [5; 24]).unwrap()).unwrap() }
    struct Fixed { call: u8, fail: Option<u8>, repeat: Option<u8> }
    impl Fixed { fn at(call: u8) -> Self { Self { call, fail: None, repeat: None } } }
    impl Entropy for Fixed {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<()> {
            self.call += 1;
            if self.fail == Some(self.call) { return Err(Error::Random); }
            bytes.fill(self.repeat.unwrap_or(self.call)); Ok(())
        }
    }
    fn descriptor() -> Descriptor { Descriptor::new(commands::Kind::ProjectReadToken, Some("Development".into()), vec![true], false).unwrap() }
    fn fields() -> Fields {
        commands::own_fields(commands::Kind::ProjectReadToken, &serde_json::json!({"token":"synthetic-test-value"}))
            .unwrap_or_else(|_| panic!("fixed scalar DATA"))
    }
    fn record(key: &VaultKey) -> SealedRecord {
        key.seal_record_with(id(3), None, &descriptor(), &fields(), None, ALLOWANCE, &mut Fixed::at(20)).unwrap()
    }
    fn payload(scalars: &[u8], file: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new(); bytes.extend_from_slice(&(scalars.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(file.len() as u32).to_le_bytes()); bytes.extend_from_slice(scalars); bytes.extend_from_slice(file); bytes
    }

    #[test]
    fn published_xchacha_vector_matches_selected_detached_api() {
        // Fixed published DATA copied from the authenticated upstream archive;
        // expected output was not generated by this implementation.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Vector { source: String, archive_sha256: String, key: [u8; 32], nonce: [u8; 24],
            aad: Vec<u8>, plaintext: Vec<u8>, ciphertext: Vec<u8>, tag: [u8; 16] }
        let vector: Vector = serde_json::from_str(include_str!("../tests/data/vault-xchacha-a1.json")).unwrap();
        assert!(vector.source.contains("appendix A.1") && vector.archive_sha256.len() == 64);
        let cipher = cipher(&vector.key).unwrap(); let nonce = XNonce::try_from(vector.nonce.as_slice()).unwrap();
        let mut bytes = vector.plaintext.clone();
        let tag = cipher.encrypt_inout_detached(&nonce, &vector.aad, bytes.as_mut_slice().into()).unwrap();
        assert_eq!(bytes, vector.ciphertext); assert_eq!(tag.as_slice(), vector.tag);
        cipher.decrypt_inout_detached(&nonce, &vector.aad, bytes.as_mut_slice().into(), &tag).unwrap();
        assert_eq!(bytes, vector.plaintext);
    }

    #[test]
    fn header_requires_the_exact_identity_key_nonce_and_tag() {
        let original = make_header(identity(), &[9; 32], [5; 24]).unwrap();
        assert!(VaultKey::authenticate(&[9; 32], identity(), &original).is_ok());
        assert!(VaultKey::authenticate(&[8; 32], identity(), &original).is_err());
        assert!(VaultKey::authenticate(&[9; 32], Identity::new(id(7), id(8)).unwrap(), &original).is_err());
        for offset in [0, 8, 10, 12, 14, 16, 32, 48, 63, 64, 87, 88, 103] {
            let mut changed = original; changed[offset] ^= 1;
            assert!(VaultKey::authenticate(&[9; 32], identity(), &changed).is_err());
        }
        let proposed = InitializationKey::generate_with(identity(), &mut Fixed::at(40)).unwrap();
        let expected = *proposed.header();
        let (header, adopted) = proposed.consume_for_transport(|bytes| VaultKey::authenticate(bytes, identity(), &expected));
        assert_eq!(header, expected); assert!(adopted.is_ok());
    }

    #[test]
    fn listing_checks_only_descriptor_and_full_open_checks_every_section() {
        let key = key(); let sealed = record(&key);
        let descriptor_end = 216 + sealed.prefix.descriptor_length;
        let partial_end = descriptor_end + 16;
        let listed = key.open_descriptor(&sealed.bytes[..partial_end], ALLOWANCE).unwrap();
        assert!(listed.record == id(3) && listed.revision == sealed.revision());
        assert_eq!(listed.descriptor.label.as_deref(), Some("Development"));
        let opened = key.open_record(sealed.bytes.clone(), ALLOWANCE).unwrap();
        assert!(opened.file.is_none()); assert!(opened.record == id(3));
        assert_eq!(opened.fields.into_value(), fields().into_value());
        assert!(!sealed.bytes.windows(b"synthetic-test-value".len()).any(|part| part == b"synthetic-test-value"));
        for offset in [0, 8, 12, 16, 32, 48, 64, 80, 84, 88, 96, 120, 144, 168, 200, 216, descriptor_end, partial_end, sealed.bytes.len() - 1] {
            let mut changed = sealed.bytes.clone(); changed[offset] ^= 1;
            if offset >= partial_end { assert!(key.open_descriptor(&changed[..partial_end], ALLOWANCE).is_ok()); }
            else { assert!(key.open_descriptor(&changed[..partial_end], ALLOWANCE).is_err()); }
            assert!(key.open_record(changed, ALLOWANCE).is_err());
        }
        for length in [0, 167, 215, partial_end - 1, sealed.bytes.len() - 1] {
            assert!(key.open_record(sealed.bytes[..length].to_vec(), ALLOWANCE).is_err());
        }
        let mut trailing = sealed.bytes.clone(); trailing.push(0);
        assert!(key.open_record(trailing, ALLOWANCE).is_err());
    }

    #[test]
    fn authenticated_payload_uses_exact_shared_scalar_and_file_semantics() {
        let descriptor = descriptor();
        let (decoded, file) = decode_payload(&descriptor, &payload(br#"{"token":"test"}"#, &[])).unwrap();
        assert_eq!(decoded.into_value(), serde_json::json!({"token":"test"})); assert!(file.is_none());
        for invalid in [br#"{}"#.as_slice(), br#"{"token":"a","token":"b"}"#,
            br#"{"token":"a","to\u006ben":"b"}"#, br#"{"token":"a","extra":null}"#,
            br#"{"token":[]}"#, br#"{"token":{}}"#, br#"{"token":true}"#, br#"{"token":1}"#,
            br#"{"token":null}"#, br#"{"token":"a"} {}"#, b"[null]", b"\xff"] {
            assert!(decode_payload(&descriptor, &payload(invalid, &[])).is_err());
        }
        assert!(decode_payload(&descriptor, &payload(br#"{"token":"a"}"#, b"unexpected-file")).is_err());
        let oversized = serde_json::to_vec(&serde_json::json!({"token":"x".repeat(4097)})).unwrap();
        assert!(decode_payload(&descriptor, &payload(&oversized, &[])).is_err());
        let nullable = Descriptor::new(commands::Kind::ProjectReadToken, None, vec![false], false).unwrap();
        assert!(decode_payload(&nullable, &payload(br#"{"token":null}"#, &[])).is_ok());
        let mut length = payload(br#"{"token":"a"}"#, &[]); length[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_payload(&descriptor, &length).is_err());
        for kind in [commands::Kind::AndroidFirebase, commands::Kind::IosFirebase] {
            let descriptor = Descriptor::new(kind, None, vec![], true).unwrap();
            let fields = commands::own_fields(kind, &serde_json::json!({})).unwrap_or_else(|_| panic!("fixed fields"));
            let sealed = key().seal_record_with(id(3), None, &descriptor, &fields, Some(b"synthetic-file"), ALLOWANCE, &mut Fixed::at(20)).unwrap();
            let opened = key().open_record(sealed.bytes, ALLOWANCE).unwrap();
            assert!(opened.descriptor.kind == kind);
            assert_eq!(opened.file.as_ref().unwrap().bytes(), b"synthetic-file");
            assert!(opened.file.unwrap().retained_bytes().unwrap() > b"synthetic-file".len());
        }
    }


    #[test]
    fn private_review_authenticated_payloads_preserve_four_and_two_scalar_fields_without_files() {
        let key = key();
        for (kind, values) in [
            (commands::Kind::AppleReviewContact, serde_json::json!({
                "firstName":"  ORIGINAL_FIRST_CANARY  ", "lastName":null,
                "email":"not-an-email", "phone":"ORIGINAL_PHONE_CANARY\0é",
            })),
            (commands::Kind::AppleReviewDemoAccount, serde_json::json!({
                "username":" ORIGINAL_DEMO_CANARY ", "password":"ORIGINAL_PASSWORD_CANARY\0é",
            })),
            (commands::Kind::AppleOperationCommitment, serde_json::json!({
                "keyBase64":" ORIGINAL_KEY_CANARY ", "keyVersion":"ORIGINAL_VERSION_CANARY\0é",
            })),
        ] {
            // The codec preserves supplied values. Authentication is not core
            // syntax, contact reachability, demo login, recovery match or saved approval.
            let fields = commands::own_fields(kind, &values).ok().unwrap();
            let presence = fields.vault_presence();
            assert_eq!(presence.len(), commands::field_names(kind).len());
            let descriptor = Descriptor::new(kind, None, presence.clone(), false).unwrap();
            let sealed = key.seal_record_with(id(3), None, &descriptor, &fields, None, ALLOWANCE, &mut Fixed::at(20)).unwrap();
            let revision = sealed.revision();
            let listed = key.open_descriptor(&sealed.bytes[..216 + sealed.prefix.descriptor_length + 16], ALLOWANCE).unwrap();
            assert!(listed.descriptor.kind == kind && listed.revision == revision);
            assert_eq!(listed.descriptor.presence(), presence);
            let opened = key.open_record(sealed.bytes, ALLOWANCE).unwrap();
            assert!(opened.descriptor.kind == kind && opened.record == id(3) && opened.revision == revision);
            assert!(opened.file.is_none());
            assert_eq!(opened.fields.into_value(), values);

            let nulls: Map<String, Value> = commands::field_names(kind).iter().map(|name| ((*name).into(), Value::Null)).collect();
            let nulls = Value::Object(nulls);
            let missing = Descriptor::new(kind, None, vec![false; presence.len()], false).unwrap();
            let (decoded, file) = decode_payload(&missing, &payload(&serde_json::to_vec(&nulls).unwrap(), &[])).unwrap();
            assert_eq!(decoded.into_value(), nulls); assert!(file.is_none());
        }
    }

    #[test]
    fn private_review_payload_decoder_refuses_inexact_maps_presence_and_oversized_values() {
        for (kind, values, escaped_last_key) in [
            (commands::Kind::AppleReviewContact, serde_json::json!({
                "firstName":"fictional", "lastName":"contact", "email":"reviewer@example.test", "phone":"fictional-phone",
            }), r"pho\u006ee"),
            (commands::Kind::AppleReviewDemoAccount, serde_json::json!({
                "username":"fictional-demo", "password":"fictional-password",
            }), r"passw\u006frd"),
            (commands::Kind::AppleOperationCommitment, serde_json::json!({
                "keyBase64":"fictional-supplied-key", "keyVersion":"retained-v1",
            }), r"keyVersi\u006fn"),
        ] {
            let names = commands::field_names(kind);
            let descriptor = Descriptor::new(kind, None, vec![true; names.len()], false).unwrap();
            let raw = serde_json::to_vec(&values).unwrap();
            assert!(decode_payload(&descriptor, &payload(&raw, &[])).is_ok());
            assert!(decode_payload(&descriptor, &payload(&raw, b"unexpected-file")).is_err());
            for name in names {
                let mut missing = values.clone(); missing.as_object_mut().unwrap().remove(*name);
                assert!(decode_payload(&descriptor, &payload(&serde_json::to_vec(&missing).unwrap(), &[])).is_err());
                for bad in [Value::Null, serde_json::json!({"nested":"private-canary"}), serde_json::json!("é".repeat(2049))] {
                    let mut wrong = values.clone(); wrong[*name] = bad;
                    assert!(decode_payload(&descriptor, &payload(&serde_json::to_vec(&wrong).unwrap(), &[])).is_err());
                }
            }
            let text = serde_json::to_string(&values).unwrap();
            for repeated in [*names.last().unwrap(), escaped_last_key] {
                let duplicate = format!("{},\"{}\":\"repeated\"}}", &text[..text.len() - 1], repeated);
                assert!(decode_payload(&descriptor, &payload(duplicate.as_bytes(), &[])).is_err());
            }
            let mut extra = values.clone(); extra["file"] = Value::Null;
            assert!(decode_payload(&descriptor, &payload(&serde_json::to_vec(&extra).unwrap(), &[])).is_err());
            assert!(decode_payload(&descriptor, &payload(b"{}", &[])).is_err());
            assert!(decode_payload(&descriptor, &payload(format!("{text} {{}}").as_bytes(), &[])).is_err());
        }
    }

    fn asc_file() -> Vec<u8> {
        use der_07::{asn1::ObjectIdentifier, Any, Encode, Tag};
        // Deliberately not an EC scalar. Authentication/envelope recognition
        // must never be presented as mathematical key or account validation.
        let mut identifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1").to_der().unwrap();
        identifier.extend_from_slice(&ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7").to_der().unwrap());
        let mut fields = 0u8.to_der().unwrap();
        fields.extend_from_slice(&Any::new(Tag::Sequence, identifier).unwrap().to_der().unwrap());
        fields.extend_from_slice(&Any::new(Tag::OctetString, b"PRIVATE_P8_PAYLOAD_CANARY".to_vec()).unwrap().to_der().unwrap());
        Any::new(Tag::Sequence, fields).unwrap().to_der().unwrap()
    }

    #[test]
    fn asc_authenticated_round_trip_retains_original_bytes_and_requires_fresh_observation() {
        use crate::credential_format::{inspect, FileKind};
        let key = key(); let der = asc_file();
        let pem = der_07::pem::encode_string("PRIVATE KEY", der_07::pem::LineEnding::CRLF, &der).unwrap().into_bytes();
        // Raw companion spelling is preserved. Core semantics, not this codec,
        // decide that whitespace/NUL/non-identifier values are unusable.
        let values = serde_json::json!({"keyId":" RAW_ASC_KEY_CANARY\0é ", "issuerId":"MixedCase-ASC-ISSUER-CANARY\n"});
        let fields = commands::own_fields(commands::Kind::AscP8, &values).ok().unwrap();
        let descriptor = Descriptor::new(commands::Kind::AscP8, None, vec![true, true], true).unwrap();
        for (encoding, file) in [("der", der), ("pem", pem)] {
            let sealed = key.seal_record_with(id(3), None, &descriptor, &fields, Some(&file), ALLOWANCE, &mut Fixed::at(20)).unwrap();
            let original_revision = sealed.revision();
            let listed = key.open_descriptor(&sealed.bytes[..216 + sealed.prefix.descriptor_length + 16], ALLOWANCE).unwrap();
            assert!(listed.descriptor.kind == commands::Kind::AscP8 && listed.revision == original_revision);
            assert_eq!(listed.descriptor.presence(), &[true, true]);
            let opened = key.open_record(sealed.bytes, ALLOWANCE).unwrap();
            assert!(opened.record == id(3) && opened.revision == original_revision);
            let stored = opened.file.as_ref().unwrap();
            assert_eq!(stored.bytes(), file);
            let observed = inspect(FileKind::AscP8, stored.bytes(), &mut || false).ok().unwrap();
            assert_eq!(serde_json::to_value(observed).unwrap(), serde_json::json!({
                "status":"observed","byteCount":file.len(),"format":"pkcs8","encoding":encoding,"algorithm":"ec","curve":"p256"}));
            assert!(inspect(FileKind::AscP8, stored.bytes(), &mut || true).is_err());
            assert_eq!(opened.fields.into_value(), values);

            let replacement = key.seal_record_with(id(3), Some(original_revision), &descriptor, &fields, Some(&file), ALLOWANCE, &mut Fixed::at(40)).unwrap();
            let opened = key.open_record(replacement.bytes, ALLOWANCE).unwrap();
            assert_eq!(opened.revision.counter, 2);
            assert!(opened.revision != original_revision && opened.revision.random != original_revision.random);
            assert_eq!(opened.file.as_ref().unwrap().bytes(), file);
        }
        let missing = serde_json::json!({"keyId":null,"issuerId":null});
        let fields = commands::own_fields(commands::Kind::AscP8, &missing).ok().unwrap();
        let descriptor = Descriptor::new(commands::Kind::AscP8, None, vec![false, false], true).unwrap();
        let malformed = b"not-a-private-key-envelope";
        let sealed = key.seal_record_with(id(3), None, &descriptor, &fields, Some(malformed), ALLOWANCE, &mut Fixed::at(20)).unwrap();
        let opened = key.open_record(sealed.bytes, ALLOWANCE).unwrap();
        assert_eq!(opened.fields.into_value(), missing);
        let observation = inspect(FileKind::AscP8, opened.file.as_ref().unwrap().bytes(), &mut || false).ok().unwrap();
        assert_ne!(serde_json::to_value(observation).unwrap()["status"], "observed",
            "authenticated storage never persists parser approval");
    }

    #[test]
    fn asc_payload_refuses_wrong_kind_presence_duplicate_companions_and_over_cap_before_entropy() {
        let key = key(); let kind = commands::Kind::AscP8; let file = asc_file();
        let descriptor = Descriptor::new(kind, None, vec![true, true], true).unwrap();
        let values = serde_json::json!({"keyId":"A1B2C3D4E5","issuerId":"00112233-4455-6677-8899-AABBCCDDEEFF"});
        let fields = commands::own_fields(kind, &values).ok().unwrap();
        for invalid in [
            br#"{"keyId":"a"}"#.as_slice(), br#"{"keyId":"a","issuerId":"b","keyId":"a"}"#,
            br#"{"keyId":"a","issuerId":"b","key\u0049d":"a"}"#,
            br#"{"keyId":"a","issuerId":"b","extra":null}"#, br#"{"keyId":"a","issuerId":[]}"#,
            br#"{"keyId":null,"issuerId":"b"}"#, br#"{"keyId":"a","issuerId":"b"} {}"#,
        ] { assert!(decode_payload(&descriptor, &payload(invalid, &file)).is_err()); }
        for oversized in ["x".repeat(4097), "é".repeat(2049)] {
            let raw = serde_json::to_vec(&serde_json::json!({"keyId":oversized,"issuerId":"b"})).unwrap();
            assert!(decode_payload(&descriptor, &payload(&raw, &file)).is_err());
        }
        let nullable = Descriptor::new(kind, None, vec![false, true], true).unwrap();
        assert!(decode_payload(&nullable, &payload(br#"{"keyId":null,"issuerId":"b"}"#, &file)).is_ok());
        let wrong_kind = super::tests::fields();
        for (descriptor, fields, source) in [
            (&descriptor, &wrong_kind, Some(file.as_slice())),
            (&nullable, &fields, Some(file.as_slice())),
            (&descriptor, &fields, None),
        ] {
            let mut random = Fixed::at(20);
            assert!(key.seal_record_with(id(3), None, descriptor, fields, source, ALLOWANCE, &mut random).is_err());
            assert_eq!(random.call, 20);
        }
        let limit = asset_source::material_limit(crate::credential_format::FileKind::AscP8);
        assert_eq!(limit, 4 * 1024 * 1024);
        let over = vec![b'x'; limit + 1];
        let mut random = Fixed::at(20);
        assert!(key.seal_record_with(id(3), None, &descriptor, &fields, Some(&over), ALLOWANCE, &mut random).is_err());
        assert_eq!(random.call, 20);
        assert!(decode_payload(&descriptor, &payload(&serde_json::to_vec(&values).unwrap(), &over)).is_err());
        let sealed = key.seal_record_with(id(3), None, &descriptor, &fields, Some(&over[..limit]), ALLOWANCE, &mut random).unwrap();
        let opened = key.open_record(sealed.bytes, ALLOWANCE).unwrap();
        assert_eq!(opened.file.as_ref().unwrap().bytes(), &over[..limit]);
    }

    #[test]
    fn random_refusal_collision_and_capacity_never_return_an_output() {
        for failed in 21..=22 {
            let mut random = Fixed::at(20); random.fail = Some(failed);
            assert!(InitializationKey::generate_with(identity(), &mut random).is_err()); assert_eq!(random.call, failed);
        }
        for failed in 21..=25 {
            let mut random = Fixed::at(20); random.fail = Some(failed);
            assert!(key().seal_record_with(id(3), None, &descriptor(), &fields(), None, ALLOWANCE, &mut random).is_err());
            assert_eq!(random.call, failed);
        }
        for repeated in [0, 1, 5, 7] {
            let mut random = Fixed::at(20); random.repeat = Some(repeated);
            assert!(new_identity_with(&mut random).is_err());
            assert!(key().seal_record_with(id(3), None, &descriptor(), &fields(), None, ALLOWANCE, &mut random).is_err());
        }
        let mut random = Fixed::at(20);
        assert!(key().seal_record_with(id(3), None, &descriptor(), &fields(), None, 0, &mut random).is_err());
        assert_eq!(random.call, 20); // refuse before RNG/allocation with no allowance
        let mut bytes = record(&key()).bytes; let original_length = bytes.len(); bytes.reserve(8192);
        assert!(bytes.capacity() > original_length);
        assert!(key().open_record(bytes, CONTROL_BYTES + original_length).is_err());
        assert!(capacity(usize::MAX, ALLOWANCE).is_err());
        assert!(capacity(0, ALLOWANCE + 1).is_err());
    }

    #[test]
    fn intent_authenticates_exact_candidate_revisions_and_operation_without_replay() {
        let key = key(); let first = record(&key);
        let intent = key.seal_intent_with(Mutation::New, id(3), None, Some(&first), &mut Fixed::at(40)).unwrap();
        let checked = key.authenticate_intent(&intent).unwrap();
        assert!(checked.expected.is_none() && checked.proposed == Some(first.revision()));
        assert_eq!(checked.candidate_length, first.bytes.len());
        let digest: [u8; 32] = Sha256::digest(&first.bytes).into(); assert_eq!(checked.candidate_digest, digest);
        for offset in [0, 8, 10, 11, 12, 16, 32, 48, 64, 80, 96, 100, 116, 120, 152, 160, 184, 199] {
            let mut changed = intent; changed[offset] ^= 1; assert!(key.authenticate_intent(&changed).is_err());
        }
        let next = key.seal_record_with(id(3), Some(first.revision()), &descriptor(), &fields(), None, ALLOWANCE, &mut Fixed::at(30)).unwrap();
        let replaced = key.seal_intent_with(Mutation::Replace, id(3), Some(first.revision()), Some(&next), &mut Fixed::at(50)).unwrap();
        let checked = key.authenticate_intent(&replaced).unwrap();
        assert!(checked.expected == Some(first.revision()) && checked.proposed == Some(next.revision()));
        assert_eq!(next.revision().counter, 2);
        assert!(key.seal_intent_with(Mutation::Replace, id(3), None, Some(&next), &mut Fixed::at(50)).is_err());
        assert!(key.seal_intent_with(Mutation::New, id(3), Some(first.revision()), Some(&first), &mut Fixed::at(50)).is_err());
        assert!(key.seal_intent_with(Mutation::New, id(4), None, Some(&first), &mut Fixed::at(50)).is_err());
        let deleted = key.seal_intent_with(Mutation::Delete, id(3), Some(first.revision()), None, &mut Fixed::at(60)).unwrap();
        let checked = key.authenticate_intent(&deleted).unwrap();
        assert!(checked.proposed.is_none()); assert_eq!(checked.candidate_length, 0); assert_eq!(checked.candidate_digest, [0; 32]);
        let exhausted = Revision::new(id(7), u32::MAX).unwrap();
        assert!(key.seal_record_with(id(3), Some(exhausted), &descriptor(), &fields(), None, ALLOWANCE, &mut Fixed::at(30)).is_err());
        for failed in 71..=72 {
            let mut random = Fixed::at(70); random.fail = Some(failed);
            assert!(key.seal_intent_with(Mutation::New, id(3), None, Some(&first), &mut random).is_err()); assert_eq!(random.call, failed);
        }
    }

    #[test]
    fn section_aad_is_domain_full_prefix_and_role_not_an_ambiguous_concatenation() {
        let key = key(); let record = record(&key);
        let prefix = record.prefix.bytes(); let nonce = record.prefix.nonce(RecordRole::Wrap);
        let wrap = Aad::new(prefix, b"wrap\0").unwrap();
        assert!(wrap.bytes().starts_with(format::DOMAIN));
        assert_eq!(&wrap.bytes()[format::DOMAIN.len()..format::DOMAIN.len() + 168], prefix);
        assert!(wrap.bytes().ends_with(b"wrap\0"));
        assert!(Aad::new(&prefix[..160], b"wrap\0").is_err());
        let mut bytes = b"role-bound-synthetic-data".to_vec();
        let tag = seal(&key.cipher, nonce, prefix, b"wrap\0", &mut bytes).unwrap();
        for role in [b"descriptor\0".as_slice(), b"payload\0"] {
            let mut changed = bytes.clone(); assert!(open(&key.cipher, nonce, prefix, role, &mut changed, &tag).is_err());
        }
        open(&key.cipher, nonce, prefix, b"wrap\0", &mut bytes, &tag).unwrap();
        assert_eq!(bytes, b"role-bound-synthetic-data");
    }
}
