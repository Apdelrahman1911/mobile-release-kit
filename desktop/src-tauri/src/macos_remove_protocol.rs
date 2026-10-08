//! The outer removal request, four fixed frames and transcript are DATA only.
//!
//! This module does not read a clock, generate a nonce, open a channel, select
//! code, confirm a user action or create Completion/QuitReady/EX authority.
//! Its caller must retain the actual current source, peer, original clock and
//! private owner results. Matching bytes cannot substitute for any of them.
//! In particular, FramesExchanged does not prove a send, confirmation, Prepare,
//! ordinary Quit, peer exit, native close or permission to remove anything.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use serde::{de::{value::MapAccessDeserializer, MapAccess, Visitor}, Deserialize, Deserializer, Serialize};
pub use crate::macos_build_profile::MacBuildTarget as TargetData;

pub const FRAME_BODY_LIMIT: usize = 4096;
pub const PREFIX_BYTES: usize = 4;
pub const FRAME_LIMIT: usize = PREFIX_BYTES + FRAME_BODY_LIMIT;
pub const FRAME_COUNT: usize = 4;
pub const WORK_NS: u64 = 110_000_000_000;
pub const HARD_NS: u64 = 120_000_000_000;
pub const PURPOSE: &str = "mrk-macos-remove-producer-v1";
pub const REQUEST_LIMIT: usize = 32768;
pub const DESCRIPTOR_LIMIT: usize = 16384;
pub const SIGNATURE_LIMIT: usize = 512;
pub const REQUEST_PURPOSE: &str = "mrk-macos-remove-request-v1";
const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataError {
    Limit, Shape, Binding, Clock, WorkExpired, HardExpired,
    Direction, Order, Nonce, Aborted,
}
pub type DataResult<T> = std::result::Result<T, DataError>;
fn require(ok: bool, error: DataError) -> DataResult<()> {
    if ok { Ok(()) } else { Err(error) }
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

/// Raw CLOCK_MONOTONIC nanosecond comparison DATA, not native ParentCutoff.
/// These are the already captured original endpoints, never receipt-relative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentClockData { start: u64, work: u64, hard: u64 }
impl ParentClockData {
    pub fn new_data(start: u64, work: u64, hard: u64) -> DataResult<Self> {
        require(start != 0 && start.checked_add(WORK_NS) == Some(work)
            && start.checked_add(HARD_NS) == Some(hard), DataError::Clock)?;
        Ok(Self { start, work, hard })
    }
    pub fn start_data(self) -> u64 { self.start }
    pub fn work_data(self) -> u64 { self.work }
    pub fn hard_data(self) -> u64 { self.hard }
    fn sample_data(self, last: u64, now: u64, work: bool) -> DataResult<u64> {
        require(last >= self.start && now >= last, DataError::Clock)?;
        require(now < self.hard, DataError::HardExpired)?;
        require(!work || now < self.work, DataError::WorkExpired)?;
        Ok(now)
    }
    pub fn work_sample_data(self, last: u64, now: u64) -> DataResult<u64> {
        self.sample_data(last, now, true)
    }
    /// Comparison for the caller's original settlement only. This cannot
    /// revive a refused transcript or authorize a late successful frame.
    pub fn settlement_sample_data(self, last: u64, now: u64) -> DataResult<u64> {
        self.sample_data(last, now, false)
    }
}

/// Independently supplied expected values. No field establishes its origin.
#[derive(Clone, Copy)]
pub struct BindingInputData<'a> {
    pub request_id: &'a str, pub root_nonce: &'a str,
    pub source_commit: &'a str, pub release: &'a str, pub target: TargetData,
    pub remove_producer_sha256: &'a str, pub installed_producer_sha256: &'a str,
    pub installed_inventory_sha256: &'a str, pub protocol_sha256: &'a str,
    pub start: u64, pub work: u64, pub hard: u64,
}
fn validate_binding_data(value: BindingInputData<'_>) -> DataResult<()> {
    require(hex(value.request_id, 32) && hex(value.root_nonce, 32)
        && value.request_id != value.root_nonce, DataError::Binding)?;
    require(hex(value.source_commit, 40)
        && [value.remove_producer_sha256, value.installed_producer_sha256,
            value.installed_inventory_sha256, value.protocol_sha256]
            .iter().all(|value| hex(value, 64)), DataError::Binding)?;
    let prefix = value.target.release_prefix();
    require(value.release.len() > prefix.len() && value.release.len() <= 128
        && value.release.starts_with(prefix)
        && value.release.bytes().all(|b| b.is_ascii_lowercase()
            || b.is_ascii_digit() || b"-_.".contains(&b))
        && value.release.as_bytes().last().is_some_and(|b|
            b.is_ascii_lowercase() || b.is_ascii_digit()), DataError::Binding)?;
    ParentClockData::new_data(value.start, value.work, value.hard)?;
    Ok(())
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingWire {
    request_id: String, root_nonce: String, source_commit: String,
    release: String, target: String,
    remove_producer_sha256: String, installed_producer_sha256: String,
    installed_inventory_sha256: String, protocol_sha256: String,
    start: u64, work: u64, hard: u64,
}

/// Immutable validated DATA, deliberately not Deserialize. Public constructors
/// cannot mint the separate native source-purpose or ParentCutoff proofs.
#[derive(Clone, PartialEq, Eq)]
pub struct BindingData { wire: BindingWire, target: TargetData }
impl BindingData {
    pub fn new_data(value: BindingInputData<'_>) -> DataResult<Self> {
        // Refuse oversized input before allocating its owned strings.
        validate_binding_data(value)?;
        Ok(Self { target: value.target, wire: BindingWire {
            request_id: value.request_id.into(), root_nonce: value.root_nonce.into(),
            source_commit: value.source_commit.into(), release: value.release.into(),
            target: value.target.target().into(),
            remove_producer_sha256: value.remove_producer_sha256.into(),
            installed_producer_sha256: value.installed_producer_sha256.into(),
            installed_inventory_sha256: value.installed_inventory_sha256.into(),
            protocol_sha256: value.protocol_sha256.into(),
            start: value.start, work: value.work, hard: value.hard,
        } })
    }
    fn from_wire_data(wire: BindingWire) -> DataResult<Self> {
        let target = match wire.target.as_str() {
            "aarch64-apple-darwin" => TargetData::Arm64,
            "x86_64-apple-darwin" => TargetData::Intel,
            _ => return Err(DataError::Binding),
        };
        let value = Self { wire, target };
        validate_binding_data(value.fields_data())?;
        Ok(value)
    }
    pub fn fields_data(&self) -> BindingInputData<'_> {
        BindingInputData {
            request_id: &self.wire.request_id, root_nonce: &self.wire.root_nonce,
            source_commit: &self.wire.source_commit, release: &self.wire.release,
            target: self.target, remove_producer_sha256: &self.wire.remove_producer_sha256,
            installed_producer_sha256: &self.wire.installed_producer_sha256,
            installed_inventory_sha256: &self.wire.installed_inventory_sha256,
            protocol_sha256: &self.wire.protocol_sha256,
            start: self.wire.start, work: self.wire.work, hard: self.wire.hard,
        }
    }
    pub fn clock_data(&self) -> ParentClockData {
        ParentClockData { start: self.wire.start, work: self.wire.work, hard: self.wire.hard }
    }
    fn heap_bytes_data(&self) -> Option<usize> {
        [&self.wire.request_id, &self.wire.root_nonce, &self.wire.source_commit,
            &self.wire.release, &self.wire.target, &self.wire.remove_producer_sha256,
            &self.wire.installed_producer_sha256, &self.wire.installed_inventory_sha256,
            &self.wire.protocol_sha256]
            .iter().try_fold(0usize, |sum, value| sum.checked_add(value.capacity()))
    }
    /// Actual retained Rust storage, not allocator/RSS or the caller's whole
    /// native/task/frame reservation. Overlapping copies must each be charged.
    pub fn owned_bytes_data(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.heap_bytes_data()?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FrameKindData { Challenge, Confirmed, Prepared, QuitAcknowledged }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PreparationData { NeverRegistered, UnregisteredNow }

// Use the existing closed-object visitor pattern rather than materializing an
// arbitrary JSON Value tree. The root and binding must be objects, derived
// visitors reject duplicate/unknown fields, and every leaf has an exact type.
// Missing optional fields differ from explicit null, which is always refused.
fn binding_object<'de, D: Deserializer<'de>>(decoder: D) -> Result<BindingWire, D::Error> {
    struct Object;
    impl<'de> Visitor<'de> for Object {
        type Value = BindingWire;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("fixed removal binding object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<BindingWire, A::Error> {
            BindingWire::deserialize(MapAccessDeserializer::new(map))
        }
    }
    decoder.deserialize_map(Object)
}
fn present_nonce<'de, D: Deserializer<'de>>(decoder: D) -> Result<Option<String>, D::Error> {
    String::deserialize(decoder).map(Some)
}
fn present_preparation<'de, D: Deserializer<'de>>(decoder: D) -> Result<Option<PreparationData>, D::Error> {
    PreparationData::deserialize(decoder).map(Some)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameWire {
    schema_version: u32, purpose: String, frame: FrameKindData,
    #[serde(deserialize_with = "binding_object")]
    binding: BindingWire,
    #[serde(default, deserialize_with = "present_nonce")]
    app_nonce: Option<String>,
    #[serde(default, deserialize_with = "present_preparation")]
    preparation: Option<PreparationData>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameEncoding<'a> {
    schema_version: u32, purpose: &'static str, frame: FrameKindData,
    binding: &'a BindingWire,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preparation: Option<PreparationData>,
}

/// One fully framed message. No serde constructor can bypass the byte limit.
#[derive(Clone, PartialEq, Eq)]
pub struct FrameData {
    binding: BindingData, kind: FrameKindData,
    app_nonce: Option<String>, preparation: Option<PreparationData>,
}
impl FrameData {
    fn new_data(binding: &BindingData, kind: FrameKindData, nonce: Option<&str>,
        preparation: Option<PreparationData>) -> DataResult<Self> {
        if let Some(nonce) = nonce { check_app_nonce_data(binding, nonce)?; }
        let frame = Self { binding: binding.clone(), kind,
            app_nonce: nonce.map(str::to_owned), preparation };
        frame.validate_data()?;
        Ok(frame)
    }
    pub fn challenge_data(binding: &BindingData) -> DataResult<Self> {
        Self::new_data(binding, FrameKindData::Challenge, None, None)
    }
    pub fn confirmed_data(binding: &BindingData, app_nonce: &str) -> DataResult<Self> {
        Self::new_data(binding, FrameKindData::Confirmed, Some(app_nonce), None)
    }
    pub fn prepared_data(binding: &BindingData, app_nonce: &str, preparation: PreparationData) -> DataResult<Self> {
        Self::new_data(binding, FrameKindData::Prepared, Some(app_nonce), Some(preparation))
    }
    pub fn quit_acknowledged_data(binding: &BindingData, app_nonce: &str) -> DataResult<Self> {
        Self::new_data(binding, FrameKindData::QuitAcknowledged, Some(app_nonce), None)
    }
    fn validate_data(&self) -> DataResult<()> {
        validate_binding_data(self.binding.fields_data())?;
        require(self.binding.wire.target == self.binding.target.target(), DataError::Binding)?;
        require(self.app_nonce.is_some() == (self.kind != FrameKindData::Challenge)
            && self.preparation.is_some() == (self.kind == FrameKindData::Prepared), DataError::Shape)?;
        if let Some(nonce) = &self.app_nonce { check_app_nonce_data(&self.binding, nonce)?; }
        Ok(())
    }
    pub fn binding_data(&self) -> &BindingData { &self.binding }
    pub fn kind_data(&self) -> FrameKindData { self.kind }
    pub fn app_nonce_data(&self) -> Option<&str> { self.app_nonce.as_deref() }
    pub fn preparation_data(&self) -> Option<PreparationData> { self.preparation }
    pub fn parse_framed_data(bytes: &[u8]) -> DataResult<Self> {
        require(bytes.len() >= PREFIX_BYTES, DataError::Limit)?;
        let length = frame_body_length_data(&bytes[..PREFIX_BYTES])?;
        require(bytes.len() == PREFIX_BYTES + length, DataError::Limit)?;
        let body = &bytes[PREFIX_BYTES..];
        require(std::str::from_utf8(body).is_ok()
            && body.iter().copied().find(|b| !b" \t\r\n".contains(b)) == Some(b'{'), DataError::Shape)?;
        let wire: FrameWire = serde_json::from_slice(body).map_err(|_| DataError::Shape)?;
        require(wire.schema_version == SCHEMA_VERSION && wire.purpose == PURPOSE, DataError::Binding)?;
        let frame = Self { binding: BindingData::from_wire_data(wire.binding)?,
            kind: wire.frame, app_nonce: wire.app_nonce, preparation: wire.preparation };
        frame.validate_data()?;
        Ok(frame)
    }
    /// Writes only to the caller's fixed buffer; no allocation or transport is
    /// hidden here. A failure leaves the entire buffer cleared, never publishable.
    pub fn encode_framed_data(&self, output: &mut [u8; FRAME_LIMIT]) -> DataResult<usize> {
        output.fill(0);
        self.validate_data()?;
        let wire = FrameEncoding { schema_version: SCHEMA_VERSION, purpose: PURPOSE,
            frame: self.kind, binding: &self.binding.wire,
            app_nonce: self.app_nonce.as_deref(), preparation: self.preparation };
        let mut writer = BodyWriter { bytes: &mut output[PREFIX_BYTES..], used: 0 };
        let result = serde_json::to_writer(&mut writer, &wire);
        let used = writer.used;
        drop(writer);
        if result.is_err() || used == 0 || used > FRAME_BODY_LIMIT {
            output.fill(0); return Err(DataError::Limit);
        }
        let length = u32::try_from(used).map_err(|_| DataError::Limit)?;
        output[..PREFIX_BYTES].copy_from_slice(&length.to_be_bytes());
        Ok(PREFIX_BYTES + used)
    }
    pub fn owned_bytes_data(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.binding.heap_bytes_data()?)?
            .checked_add(self.app_nonce.as_ref().map_or(0, String::capacity))
    }
}
fn check_app_nonce_data(binding: &BindingData, nonce: &str) -> DataResult<()> {
    require(hex(nonce, 32) && nonce != binding.wire.request_id
        && nonce != binding.wire.root_nonce, DataError::Nonce)
}
/// Admit the fixed four-byte big-endian prefix before the caller reads a body.
/// This is a size check, not permission to allocate a new channel or retry.
pub fn frame_body_length_data(prefix: &[u8]) -> DataResult<usize> {
    require(prefix.len() == PREFIX_BYTES, DataError::Limit)?;
    let word: [u8; PREFIX_BYTES] = prefix.try_into().map_err(|_| DataError::Limit)?;
    let length = usize::try_from(u32::from_be_bytes(word)).map_err(|_| DataError::Limit)?;
    require(length > 0 && length <= FRAME_BODY_LIMIT, DataError::Limit)?;
    Ok(length)
}
struct BodyWriter<'a> { bytes: &'a mut [u8], used: usize }
impl Write for BodyWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.bytes.len().saturating_sub(self.used) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "fixed removal frame limit"));
        }
        self.bytes[self.used..self.used + bytes.len()].copy_from_slice(bytes);
        self.used += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

// The outer request is not a fifth channel frame or a signed descriptor. Its
// two encoded leaves preserve the original signed bytes without interpreting
// them. In particular, the binding and raw pair still need independent source,
// signature, current-peer and original-clock admission by the enclosing owner.
fn valid_request_lengths_data(descriptor: usize, signature: usize) -> DataResult<()> {
    require(descriptor > 0 && descriptor <= DESCRIPTOR_LIMIT
        && signature <= SIGNATURE_LIMIT && matches!(signature, 256 | 384 | 512), DataError::Limit)
}
fn request_base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62), b'/' => Some(63), _ => None,
    }
}
fn decode_request_base64_data(text: &str, signature: bool) -> DataResult<Vec<u8>> {
    let raw_limit = if signature { SIGNATURE_LIMIT } else { DESCRIPTOR_LIMIT };
    let encoded_limit = (raw_limit + 2) / 3 * 4; // Fixed 684 or 21,848.
    let bytes = text.as_bytes();
    // Check both encoded and decoded limits before allocating decoded storage.
    // The maximum encoded size alone is insufficient: 16,384 and 16,386 raw
    // bytes, for example, have the same padded base64 length.
    require(!bytes.is_empty() && bytes.len() <= encoded_limit && bytes.len() % 4 == 0,
        DataError::Limit)?;
    let padding = if bytes.ends_with(b"==") { 2 } else if bytes.ends_with(b"=") { 1 } else { 0 };
    let used = bytes.len() - padding;
    let decoded = bytes.len() / 4 * 3 - padding;
    require(decoded > 0 && decoded <= raw_limit
        && (!signature || matches!(decoded, 256 | 384 | 512)), DataError::Limit)?;
    require(bytes[..used].iter().all(|byte| request_base64_value(*byte).is_some()), DataError::Shape)?;
    // Only the last quartet may contain padding. Reject nonzero unused bits,
    // rather than accepting multiple encodings for the same original bytes.
    let tail = request_base64_value(bytes[used - 1]).ok_or(DataError::Shape)?;
    require((padding != 2 || tail & 15 == 0) && (padding != 1 || tail & 3 == 0), DataError::Shape)?;
    let mut output = Vec::new();
    output.try_reserve_exact(decoded).map_err(|_| DataError::Limit)?;
    for quartet in bytes.chunks_exact(4) {
        let a = request_base64_value(quartet[0]).ok_or(DataError::Shape)?;
        let b = request_base64_value(quartet[1]).ok_or(DataError::Shape)?;
        output.push((a << 2) | (b >> 4));
        if quartet[2] != b'=' {
            let c = request_base64_value(quartet[2]).ok_or(DataError::Shape)?;
            output.push((b << 4) | (c >> 2));
            if quartet[3] != b'=' {
                let d = request_base64_value(quartet[3]).ok_or(DataError::Shape)?;
                output.push((c << 6) | d);
            }
        }
    }
    require(output.len() == decoded, DataError::Shape)?;
    Ok(output)
}
struct RequestBase64 { signature: bool }
impl<'de> Visitor<'de> for RequestBase64 {
    type Value = Vec<u8>;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded canonical removal-request base64 string")
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Vec<u8>, E> {
        decode_request_base64_data(text, self.signature)
            .map_err(|_| E::custom("invalid bounded removal-request base64"))
    }
}
fn request_descriptor<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decoder.deserialize_str(RequestBase64 { signature: false })
}
fn request_signature<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decoder.deserialize_str(RequestBase64 { signature: true })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestWire {
    schema_version: u32, purpose: String,
    #[serde(deserialize_with = "binding_object")]
    binding: BindingWire,
    #[serde(deserialize_with = "request_descriptor")]
    remove_descriptor: Vec<u8>,
    #[serde(deserialize_with = "request_signature")]
    remove_signature: Vec<u8>,
}
fn write_request_base64_data(writer: &mut BodyWriter<'_>, bytes: &[u8]) -> DataResult<()> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        let quartet = [ALPHABET[usize::from(a >> 2)], ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))],
            if part.len() > 1 { ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))] } else { b'=' },
            if part.len() > 2 { ALPHABET[usize::from(c & 63)] } else { b'=' }];
        writer.write_all(&quartet).map_err(|_| DataError::Limit)?;
    }
    Ok(())
}

/// Immutable outer request DATA. No public Deserialize/Serialize constructor,
/// signature verifier, path selector or native capability is provided here.
pub struct RequestData {
    binding: BindingData, remove_descriptor: Vec<u8>, remove_signature: Vec<u8>,
}
impl RequestData {
    pub fn new_data(binding: &BindingData, remove_descriptor: &[u8], remove_signature: &[u8]) -> DataResult<Self> {
        valid_request_lengths_data(remove_descriptor.len(), remove_signature.len())?;
        validate_binding_data(binding.fields_data())?;
        require(binding.wire.target == binding.target.target(), DataError::Binding)?;
        let mut descriptor = Vec::new();
        descriptor.try_reserve_exact(remove_descriptor.len()).map_err(|_| DataError::Limit)?;
        descriptor.extend_from_slice(remove_descriptor);
        let mut signature = Vec::new();
        signature.try_reserve_exact(remove_signature.len()).map_err(|_| DataError::Limit)?;
        signature.extend_from_slice(remove_signature);
        Ok(Self { binding: binding.clone(), remove_descriptor: descriptor, remove_signature: signature })
    }
    pub fn parse_data(bytes: &[u8]) -> DataResult<Self> {
        require(!bytes.is_empty() && bytes.len() <= REQUEST_LIMIT, DataError::Limit)?;
        require(std::str::from_utf8(bytes).is_ok()
            && bytes.iter().copied().find(|byte| !b" \t\r\n".contains(byte)) == Some(b'{'), DataError::Shape)?;
        // The private string visitors decode directly into the retained Vecs;
        // they never own a second base64 String. serde's escaped-string scratch
        // and the caller's original JSON remain separate bounded parse storage.
        let wire: RequestWire = serde_json::from_slice(bytes).map_err(|_| DataError::Shape)?;
        require(wire.schema_version == SCHEMA_VERSION && wire.purpose == REQUEST_PURPOSE, DataError::Binding)?;
        let request = Self { binding: BindingData::from_wire_data(wire.binding)?,
            remove_descriptor: wire.remove_descriptor, remove_signature: wire.remove_signature };
        request.validate_data()?;
        Ok(request)
    }
    fn validate_data(&self) -> DataResult<()> {
        validate_binding_data(self.binding.fields_data())?;
        require(self.binding.wire.target == self.binding.target.target(), DataError::Binding)?;
        valid_request_lengths_data(self.remove_descriptor.len(), self.remove_signature.len())
    }
    pub fn binding_data(&self) -> &BindingData { &self.binding }
    pub fn remove_descriptor_data(&self) -> &[u8] { &self.remove_descriptor }
    pub fn remove_signature_data(&self) -> &[u8] { &self.remove_signature }
    /// Serialize exactly the five fields into the caller's fixed buffer. The
    /// base64 encoder uses one four-byte quartet, not an encoded heap copy.
    /// Every error leaves the entire buffer zeroed and unpublishable.
    pub fn encode_data(&self, output: &mut [u8; REQUEST_LIMIT]) -> DataResult<usize> {
        output.fill(0);
        let result = (|| {
            self.validate_data()?;
            let mut writer = BodyWriter { bytes: output, used: 0 };
            writer.write_all(b"{\"schemaVersion\":").map_err(|_| DataError::Limit)?;
            serde_json::to_writer(&mut writer, &SCHEMA_VERSION).map_err(|_| DataError::Limit)?;
            writer.write_all(b",\"purpose\":").map_err(|_| DataError::Limit)?;
            serde_json::to_writer(&mut writer, REQUEST_PURPOSE).map_err(|_| DataError::Limit)?;
            writer.write_all(b",\"binding\":").map_err(|_| DataError::Limit)?;
            serde_json::to_writer(&mut writer, &self.binding.wire).map_err(|_| DataError::Limit)?;
            writer.write_all(b",\"removeDescriptor\":\"").map_err(|_| DataError::Limit)?;
            write_request_base64_data(&mut writer, &self.remove_descriptor)?;
            writer.write_all(b"\",\"removeSignature\":\"").map_err(|_| DataError::Limit)?;
            write_request_base64_data(&mut writer, &self.remove_signature)?;
            writer.write_all(b"\"}").map_err(|_| DataError::Limit)?;
            require(writer.used > 0 && writer.used <= REQUEST_LIMIT, DataError::Limit)?;
            Ok(writer.used)
        })();
        if result.is_err() { output.fill(0); }
        result
    }
    /// Actual retained Rust storage only. Count the original JSON, caller raw
    /// pair/binding, fixed output, serde working storage and any simultaneous
    /// request/frame/transcript/native objects separately in the owner budget.
    pub fn owned_bytes_data(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.binding.heap_bytes_data()?)?
            .checked_add(self.remove_descriptor.capacity())?
            .checked_add(self.remove_signature.capacity())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleData { Parent, App }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionData { Send, Receive }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressData {
    AwaitChallenge, AwaitConfirmed, AwaitPrepared, AwaitQuitAcknowledged,
    FramesExchanged, Refused,
}
/// Exactly one transcript. It is not Clone, serializable or resettable. The
/// caller supplies actual samples and must independently prove every effect,
/// current confirmation/Completion, live peer, join and consuming close.
pub struct TranscriptData {
    role: RoleData, binding: BindingData, progress: ProgressData, last: u64,
    app_nonce: Option<String>, preparation: Option<PreparationData>, first: Option<DataError>,
}
impl TranscriptData {
    pub fn new_data(role: RoleData, binding: BindingData) -> Self {
        Self { role, last: binding.wire.start, binding,
            progress: ProgressData::AwaitChallenge, app_nonce: None, preparation: None, first: None }
    }
    pub fn binding_data(&self) -> &BindingData { &self.binding }
    pub fn progress_data(&self) -> ProgressData { self.progress }
    pub fn first_error_data(&self) -> Option<DataError> { self.first }
    pub fn app_nonce_data(&self) -> Option<&str> { self.app_nonce.as_deref() }
    pub fn preparation_data(&self) -> Option<PreparationData> { self.preparation }
    pub fn last_sample_data(&self) -> u64 { self.last }
    pub fn owned_bytes_data(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.binding.heap_bytes_data()?)?
            .checked_add(self.app_nonce.as_ref().map_or(0, String::capacity))
    }
    fn refuse_data(&mut self, error: DataError) -> DataError {
        let first = *self.first.get_or_insert(error);
        self.progress = ProgressData::Refused;
        first
    }
    pub fn abort_data(&mut self) -> DataError { self.refuse_data(DataError::Aborted) }
    /// Validate bytes/direction/order only. Returned FrameData cannot authorize
    /// Send, Prepared or Quit: the caller's private originals are still required.
    /// Any malformed, stale, late or out-of-order input irreversibly refuses this
    /// transcript. No second connection or attempt is constructed by this API.
    pub fn advance_data(&mut self, action: ActionData, bytes: &[u8], now: u64) -> DataResult<FrameData> {
        if let Some(error) = self.first { return Err(error); }
        match self.advance_inner_data(action, bytes, now) {
            Ok(frame) => Ok(frame),
            Err(error) => Err(self.refuse_data(error)),
        }
    }
    fn advance_inner_data(&mut self, action: ActionData, bytes: &[u8], now: u64) -> DataResult<FrameData> {
        let sample = self.binding.clock_data().work_sample_data(self.last, now);
        // Retain the supplied late sample as DATA, but never regress it.
        // Its actual clock provenance remains the caller's responsibility.
        if now >= self.last { self.last = now; }
        sample?;
        let frame = FrameData::parse_framed_data(bytes)?;
        require(frame.binding == self.binding, DataError::Binding)?;
        let expected = match self.progress {
            ProgressData::AwaitChallenge => FrameKindData::Challenge,
            ProgressData::AwaitConfirmed => FrameKindData::Confirmed,
            ProgressData::AwaitPrepared => FrameKindData::Prepared,
            ProgressData::AwaitQuitAcknowledged => FrameKindData::QuitAcknowledged,
            ProgressData::FramesExchanged | ProgressData::Refused => return Err(DataError::Order),
        };
        require(frame.kind == expected, DataError::Order)?;
        let parent_sends = matches!(expected, FrameKindData::Challenge | FrameKindData::QuitAcknowledged);
        let expected_action = if parent_sends == (self.role == RoleData::Parent) {
            ActionData::Send
        } else { ActionData::Receive };
        require(action == expected_action, DataError::Direction)?;
        if matches!(expected, FrameKindData::Prepared | FrameKindData::QuitAcknowledged) {
            require(frame.app_nonce == self.app_nonce, DataError::Nonce)?;
        }
        self.progress = match expected {
            FrameKindData::Challenge => ProgressData::AwaitConfirmed,
            FrameKindData::Confirmed => {
                self.app_nonce = frame.app_nonce.clone();
                ProgressData::AwaitPrepared
            }
            FrameKindData::Prepared => {
                self.preparation = frame.preparation;
                ProgressData::AwaitQuitAcknowledged
            }
            FrameKindData::QuitAcknowledged => ProgressData::FramesExchanged,
        };
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const START: u64 = 9_007_199_254_740_993; // Raw u64, not a JS/Instant cast.
    fn binding(target: TargetData) -> BindingData {
        BindingData::new_data(BindingInputData {
            request_id: &"1".repeat(32), root_nonce: &"2".repeat(32),
            source_commit: &"3".repeat(40), release: match target {
                TargetData::Arm64 => "macos26-arm64-remove-01",
                TargetData::Intel => "macos26-x86_64-remove-01",
            }, target, remove_producer_sha256: &"4".repeat(64),
            installed_producer_sha256: &"5".repeat(64), installed_inventory_sha256: &"6".repeat(64),
            protocol_sha256: &"7".repeat(64), start: START, work: START + WORK_NS, hard: START + HARD_NS,
        }).unwrap()
    }
    fn frames(binding: &BindingData, branch: PreparationData) -> [FrameData; FRAME_COUNT] {
        let app = "8".repeat(32);
        [FrameData::challenge_data(binding).unwrap(), FrameData::confirmed_data(binding, &app).unwrap(),
            FrameData::prepared_data(binding, &app, branch).unwrap(),
            FrameData::quit_acknowledged_data(binding, &app).unwrap()]
    }
    fn bytes(frame: &FrameData) -> Vec<u8> {
        let mut output = [0; FRAME_LIMIT];
        let used = frame.encode_framed_data(&mut output).unwrap();
        assert!(output[used..].iter().all(|b| *b == 0));
        output[..used].to_vec()
    }
    fn body(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(bytes); out
    }
    fn value(frame: &FrameData) -> Value { serde_json::from_slice(&bytes(frame)[PREFIX_BYTES..]).unwrap() }
    fn encoded(value: &Value) -> Vec<u8> { body(&serde_json::to_vec(value).unwrap()) }
    fn action(role: RoleData, index: usize) -> ActionData {
        if matches!(index, 0 | 3) == (role == RoleData::Parent) { ActionData::Send }
        else { ActionData::Receive }
    }
    fn advance_prefix(state: &mut TranscriptData, frames: &[FrameData; 4], role: RoleData, count: usize) {
        for (i, frame) in frames.iter().enumerate().take(count) {
            state.advance_data(action(role, i), &bytes(frame), START + i as u64).unwrap();
        }
    }

    fn request_bytes(request: &RequestData) -> Vec<u8> {
        let mut output = [255; REQUEST_LIMIT];
        let used = request.encode_data(&mut output).unwrap();
        assert!(output[used..].iter().all(|byte| *byte == 0));
        output[..used].to_vec()
    }
    fn request_value(request: &RequestData) -> Value {
        serde_json::from_slice(&request_bytes(request)).unwrap()
    }
    fn parse_request_value(value: &Value) -> DataResult<RequestData> {
        RequestData::parse_data(&serde_json::to_vec(value).unwrap())
    }
    fn raw_base64(bytes: &[u8]) -> String {
        let mut output = [0; REQUEST_LIMIT];
        let mut writer = BodyWriter { bytes: &mut output, used: 0 };
        write_request_base64_data(&mut writer, bytes).unwrap();
        let used = writer.used;
        drop(writer);
        String::from_utf8(output[..used].to_vec()).unwrap()
    }

    #[test]
    fn four_frames_bind_both_targets_roles_and_preparation_labels_as_data_only() {
        for target in [TargetData::Arm64, TargetData::Intel] {
            for branch in [PreparationData::NeverRegistered, PreparationData::UnregisteredNow] {
                let expected = binding(target);
                let frames = frames(&expected, branch);
                for role in [RoleData::Parent, RoleData::App] {
                    let mut state = TranscriptData::new_data(role, expected.clone());
                    for (index, frame) in frames.iter().enumerate() {
                        let encoded = bytes(frame);
                        assert_eq!(frame_body_length_data(&encoded[..4]).unwrap(), encoded.len() - 4);
                        let parsed = state.advance_data(action(role, index), &encoded, START + index as u64).unwrap();
                        assert!(parsed == *frame);
                        assert!(parsed.binding_data() == &expected);
                        assert_eq!(parsed.binding_data().fields_data().target, target);
                    }
                    assert_eq!(state.progress_data(), ProgressData::FramesExchanged);
                    assert_eq!(state.preparation_data(), Some(branch));
                    assert_eq!(state.app_nonce_data(), Some("88888888888888888888888888888888"));
                    assert_eq!(state.first_error_data(), None);
                    // Only syntax/order is complete. No native/private result
                    // or exit/close/removal authority is represented by it.
                    assert_eq!(state.advance_data(action(role, 0), &bytes(&frames[0]), START + 4).err(), Some(DataError::Order));
                    assert_eq!(state.progress_data(), ProgressData::Refused);
                }
            }
        }

        // Outer requests preserve both exact raw originals, not a normalized
        // descriptor JSON or a hash substituted for a detached signature.
        for target in [TargetData::Arm64, TargetData::Intel] {
            for descriptor_length in [1, 2, 3, 4, DESCRIPTOR_LIMIT] {
                let descriptor: Vec<u8> = (0..descriptor_length).map(|i| (i % 256) as u8).collect();
                for signature_length in [256, 384, 512] {
                    let signature: Vec<u8> = (0..signature_length).map(|i| 255 - (i % 256) as u8).collect();
                    let expected = binding(target);
                    let request = RequestData::new_data(&expected, &descriptor, &signature).unwrap();
                    let encoded = request_bytes(&request);
                    assert!(encoded.len() < REQUEST_LIMIT);
                    let parsed = RequestData::parse_data(&encoded).unwrap();
                    assert!(parsed.binding_data() == &expected);
                    assert_eq!(parsed.remove_descriptor_data(), descriptor.as_slice());
                    assert_eq!(parsed.remove_signature_data(), signature.as_slice());
                    assert_eq!(parsed.binding_data().clock_data().start_data(), START);
                    assert_eq!(request_bytes(&parsed), encoded);
                    let wire: Value = serde_json::from_slice(&encoded).unwrap();
                    assert_eq!(wire.as_object().unwrap().len(), 5);
                    assert_eq!(wire["schemaVersion"], json!(1));
                    assert_eq!(wire["purpose"], json!(REQUEST_PURPOSE));
                    assert_eq!(wire["removeDescriptor"], json!(raw_base64(&descriptor)));
                    assert_eq!(wire["removeSignature"], json!(raw_base64(&signature)));
                }
            }
        }
    }

    #[test]
    fn closed_json_types_duplicates_and_exact_framing_refuse_without_a_second_message() {
        let expected = binding(TargetData::Arm64);
        let frames = frames(&expected, PreparationData::NeverRegistered);
        for frame in &frames {
            let original = value(frame);
            for key in ["schemaVersion", "purpose", "frame", "binding"] {
                let mut bad = original.clone(); bad.as_object_mut().unwrap().remove(key);
                assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err(), "{key}");
            }
            for key in original["binding"].as_object().unwrap().keys() {
                let mut bad = original.clone(); bad["binding"].as_object_mut().unwrap().remove(key);
                assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err(), "{key}");
            }
            for key in ["appNonce", "preparation"] {
                let mut bad = original.clone(); bad[key] = Value::Null;
                assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err(), "explicit null {key}");
            }
            for nested in [false, true] {
                let mut bad = original.clone();
                if nested { bad["binding"]["allow"] = json!(true); } else { bad["allow"] = json!(true); }
                assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
            }
        }
        let original = value(&frames[0]);
        for replacement in [json!(true), json!(1.0), json!("1"), Value::Null, json!(2)] {
            let mut bad = original.clone(); bad["schemaVersion"] = replacement;
            assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        }
        for key in ["start", "work", "hard"] {
            for replacement in [json!(-1), json!(1.0), json!("1"), json!(true), Value::Null] {
                let mut bad = original.clone(); bad["binding"][key] = replacement;
                assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
            }
        }
        for (key, replacement) in [("purpose", json!("mrk-macos-install-producer-v2")),
            ("frame", json!("retry")), ("binding", json!([])), ("appNonce", json!("8".repeat(32))),
            ("preparation", json!("never-registered"))] {
            let mut bad = original.clone(); bad[key] = replacement;
            assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        }
        let mut bad = value(&frames[2]); bad["preparation"] = json!("not-found");
        assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        let mut bad = value(&frames[1]); bad.as_object_mut().unwrap().remove("appNonce");
        assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        let mut bad = value(&frames[2]); bad.as_object_mut().unwrap().remove("preparation");
        assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        let raw = String::from_utf8(bytes(&frames[0])[4..].to_vec()).unwrap();
        for duplicate in [raw.replacen('{', "{\"schemaVersion\":1,", 1),
            raw.replacen('{', "{\"schema\\u0056ersion\":1,", 1),
            raw.replacen("\"binding\":{", &format!("\"binding\":{{\"requestId\":\"{}\",", "1".repeat(32)), 1)] {
            assert!(FrameData::parse_framed_data(&body(duplicate.as_bytes())).is_err());
        }
        let array = json!([1, PURPOSE, "challenge", original["binding"].clone(), null, null]);
        assert!(FrameData::parse_framed_data(&encoded(&array)).is_err());
        let binding_order = ["requestId", "rootNonce", "sourceCommit", "release", "target", "removeProducerSha256",
            "installedProducerSha256", "installedInventorySha256", "protocolSha256", "start", "work", "hard"];
        let mut bad = original.clone();
        bad["binding"] = Value::Array(binding_order.iter().map(|key| original["binding"][*key].clone()).collect());
        assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        let valid = bytes(&frames[0]);
        for length in 0..PREFIX_BYTES { assert!(FrameData::parse_framed_data(&valid[..length]).is_err()); }
        for prefix in [0u32, 4097, u32::MAX] {
            assert_eq!(frame_body_length_data(&prefix.to_be_bytes()), Err(DataError::Limit));
        }
        assert_eq!(frame_body_length_data(&[0, 0, 16]), Err(DataError::Limit));
        assert_eq!(frame_body_length_data(&[0, 0, 16, 0, 0]), Err(DataError::Limit));
        assert!(FrameData::parse_framed_data(&valid[..valid.len() - 1]).is_err());
        let mut extra = valid.clone(); extra.push(b' ');
        assert!(FrameData::parse_framed_data(&extra).is_err());
        let mut little = valid.clone(); little[..4].reverse();
        assert!(FrameData::parse_framed_data(&little).is_err());
        let mut padded = valid[4..].to_vec(); padded.resize(FRAME_BODY_LIMIT, b' ');
        assert!(FrameData::parse_framed_data(&body(&padded)).is_ok());
        padded.push(b' ');
        assert_eq!(FrameData::parse_framed_data(&body(&padded)).err(), Some(DataError::Limit));
        let mut invalid_utf8 = valid[4..].to_vec(); invalid_utf8[1] = 255;
        assert!(FrameData::parse_framed_data(&body(&invalid_utf8)).is_err());
        assert!(FrameData::parse_framed_data(&body(format!("{raw}{{}}").as_bytes())).is_err());
        let mut state = TranscriptData::new_data(RoleData::Parent, expected);
        assert_eq!(state.advance_data(ActionData::Send, &extra, START).err(), Some(DataError::Limit));
        assert_eq!(state.advance_data(ActionData::Send, &valid, START).err(), Some(DataError::Limit));
        assert_eq!(state.progress_data(), ProgressData::Refused);

        let request = RequestData::new_data(&binding(TargetData::Arm64), b"f", &[0; 256]).unwrap();
        let request_original = request_value(&request);
        let request_raw = String::from_utf8(request_bytes(&request)).unwrap();
        for key in ["schemaVersion", "purpose", "binding", "removeDescriptor", "removeSignature"] {
            let mut bad = request_original.clone(); bad.as_object_mut().unwrap().remove(key);
            assert!(parse_request_value(&bad).is_err(), "request missing {key}");
            let mut bad = request_original.clone(); bad[key] = Value::Null;
            assert!(parse_request_value(&bad).is_err(), "request null {key}");
            let duplicate = request_raw.replacen('{', &format!("{{\"{key}\":{},", request_original[key]), 1);
            assert!(RequestData::parse_data(duplicate.as_bytes()).is_err(), "request duplicate {key}");
        }
        for key in request_original["binding"].as_object().unwrap().keys() {
            let mut bad = request_original.clone(); bad["binding"].as_object_mut().unwrap().remove(key);
            assert!(parse_request_value(&bad).is_err(), "request binding missing {key}");
            let duplicate = request_raw.replacen("\"binding\":{",
                &format!("\"binding\":{{\"{key}\":{},", request_original["binding"][key]), 1);
            assert!(RequestData::parse_data(duplicate.as_bytes()).is_err(), "request binding duplicate {key}");
        }
        let escaped_duplicate = request_raw.replacen('{', r#"{"schema\u0056ersion":1,"#, 1);
        assert!(RequestData::parse_data(escaped_duplicate.as_bytes()).is_err());
        for nested in [false, true] {
            let mut bad = request_original.clone();
            if nested { bad["binding"]["allow"] = json!(true); } else { bad["allow"] = json!(true); }
            assert!(parse_request_value(&bad).is_err());
        }
        for replacement in [json!(true), json!(1.0), json!("1"), json!(-1), json!(2)] {
            let mut bad = request_original.clone(); bad["schemaVersion"] = replacement;
            assert!(parse_request_value(&bad).is_err());
        }
        for replacement in [json!(true), json!(1), json!([]), json!({}), json!(PURPOSE), json!("")] {
            let mut bad = request_original.clone(); bad["purpose"] = replacement;
            assert!(parse_request_value(&bad).is_err());
        }
        for key in ["removeDescriptor", "removeSignature"] {
            for replacement in [json!(true), json!(1), json!([]), json!({}), json!("")] {
                let mut bad = request_original.clone(); bad[key] = replacement;
                assert!(parse_request_value(&bad).is_err());
            }
        }
        for bad_root in [json!([]), json!([1, REQUEST_PURPOSE, request_original["binding"].clone(), "Zg==", "AAAA"]),
            Value::Null, json!(true), json!("object"), json!({})] {
            assert!(parse_request_value(&bad_root).is_err());
        }
        let binding_order = ["requestId", "rootNonce", "sourceCommit", "release", "target", "removeProducerSha256",
            "installedProducerSha256", "installedInventorySha256", "protocolSha256", "start", "work", "hard"];
        for bad_binding in [json!([]), json!([1]), json!(true), json!("binding"), json!({}),
            Value::Array(binding_order.iter().map(|key| request_original["binding"][*key].clone()).collect())] {
            let mut bad = request_original.clone(); bad["binding"] = bad_binding;
            assert!(parse_request_value(&bad).is_err());
        }
        for invalid in ["", "Zg", "Zg=", "Zg===", "Zg====", " Zg==", "Zg== ", "Zg==\n", "Zg\t==",
            "Zg=-", "Zg__", "Zg=Z", "Z=g=", "=g==", "Zh==", "Zm9=", "Zg==AAAA", "----", "____",
            "Zg==\0", "Zg==\u{a0}", "éAAA"] {
            let mut bad = request_original.clone(); bad["removeDescriptor"] = json!(invalid);
            assert!(parse_request_value(&bad).is_err(), "request canonical base64 {invalid:?}");
        }
        let signature_text = request_original["removeSignature"].as_str().unwrap();
        assert!(signature_text.ends_with("AA=="));
        let noncanonical = format!("{}AB==", &signature_text[..signature_text.len() - 4]);
        let mut bad = request_original.clone(); bad["removeSignature"] = json!(noncanonical);
        assert!(parse_request_value(&bad).is_err());
        // JSON escapes do not relax base64 grammar or change the original bytes.
        let escaped = request_raw.replacen("\"Zg==\"", r#""Zg\u003d\u003d""#, 1);
        assert_eq!(RequestData::parse_data(escaped.as_bytes()).unwrap().remove_descriptor_data(), b"f");
        assert!(RequestData::parse_data(format!("{request_raw}{{}}").as_bytes()).is_err());
        let mut invalid_utf8 = request_raw.into_bytes(); invalid_utf8[1] = 255;
        assert!(RequestData::parse_data(&invalid_utf8).is_err());
    }

    #[test]
    fn current_binding_direction_order_and_fresh_nonce_data_cannot_be_replayed() {
        let expected = binding(TargetData::Arm64);
        let frames = frames(&expected, PreparationData::UnregisteredNow);
        let original = value(&frames[0]);
        for (key, replacement) in [("requestId", "a".repeat(32)), ("rootNonce", "b".repeat(32)),
            ("sourceCommit", "c".repeat(40)), ("release", "macos26-arm64-other-02".into()),
            ("removeProducerSha256", "d".repeat(64)), ("installedProducerSha256", "e".repeat(64)),
            ("installedInventorySha256", "f".repeat(64)), ("protocolSha256", "9".repeat(64))] {
            let mut changed = original.clone(); changed["binding"][key] = json!(replacement);
            assert!(FrameData::parse_framed_data(&encoded(&changed)).is_ok());
            let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
            assert_eq!(state.advance_data(ActionData::Send, &encoded(&changed), START).err(), Some(DataError::Binding));
            assert_eq!(state.advance_data(ActionData::Send, &bytes(&frames[0]), START).err(), Some(DataError::Binding));
        }
        let mut shifted = original.clone();
        for key in ["start", "work", "hard"] { shifted["binding"][key] = json!(original["binding"][key].as_u64().unwrap() + 1); }
        assert!(FrameData::parse_framed_data(&encoded(&shifted)).is_ok());
        for foreign in [encoded(&shifted), bytes(&FrameData::challenge_data(&binding(TargetData::Intel)).unwrap())] {
            let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
            assert_eq!(state.advance_data(ActionData::Send, &foreign, START + 1).err(), Some(DataError::Binding));
        }
        for role in [RoleData::Parent, RoleData::App] {
            for index in 0..FRAME_COUNT {
                let mut wrong_direction = TranscriptData::new_data(role, expected.clone());
                advance_prefix(&mut wrong_direction, &frames, role, index);
                let opposite = if action(role, index) == ActionData::Send { ActionData::Receive } else { ActionData::Send };
                assert_eq!(wrong_direction.advance_data(opposite, &bytes(&frames[index]), START + 10).err(), Some(DataError::Direction));
                assert_eq!(wrong_direction.abort_data(), DataError::Direction);
                let mut wrong_order = TranscriptData::new_data(role, expected.clone());
                advance_prefix(&mut wrong_order, &frames, role, index);
                assert_eq!(wrong_order.advance_data(action(role, index), &bytes(&frames[(index + 1) % 4]), START + 10).err(), Some(DataError::Order));
                assert_eq!(wrong_order.advance_data(action(role, index), &bytes(&frames[index]), START + 10).err(), Some(DataError::Order));
            }
        }
        for index in [2, 3] {
            let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
            advance_prefix(&mut state, &frames, RoleData::Parent, index);
            let mut bad = value(&frames[index]); bad["appNonce"] = json!("a".repeat(32));
            assert_eq!(state.advance_data(action(RoleData::Parent, index), &encoded(&bad), START + 10).err(), Some(DataError::Nonce));
            assert_eq!(state.app_nonce_data(), Some("88888888888888888888888888888888"));
            assert_eq!(state.advance_data(action(RoleData::Parent, index), &bytes(&frames[index]), START + 10).err(), Some(DataError::Nonce));
        }
        let mut duplicate = TranscriptData::new_data(RoleData::Parent, expected.clone());
        advance_prefix(&mut duplicate, &frames, RoleData::Parent, 2);
        assert_eq!(duplicate.advance_data(ActionData::Receive, &bytes(&frames[1]), START + 2).err(), Some(DataError::Order));
        for nonce in ["0".repeat(32), "A".repeat(32), "8".repeat(31), "8".repeat(33),
            expected.fields_data().request_id.into(), expected.fields_data().root_nonce.into()] {
            assert_eq!(FrameData::confirmed_data(&expected, &nonce).err(), Some(DataError::Nonce));
        }
        for key in ["requestId", "rootNonce", "sourceCommit", "removeProducerSha256", "installedProducerSha256",
            "installedInventorySha256", "protocolSha256"] {
            for bad_value in ["0".repeat(original["binding"][key].as_str().unwrap().len()), "A".repeat(32), String::new()] {
                let mut bad = original.clone(); bad["binding"][key] = json!(bad_value);
                assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
            }
        }
        for (key, bad_value) in [("rootNonce", "1".repeat(32)), ("target", "x86_64-unknown-linux-gnu".into()),
            ("release", "macos26-x86_64-other-01".into()), ("release", "macos26-arm64-".into()),
            ("release", "macos26-arm64-trailing-".into()), ("release", "macos26-arm64-../x".into())] {
            let mut bad = original.clone(); bad["binding"][key] = json!(bad_value);
            assert!(FrameData::parse_framed_data(&encoded(&bad)).is_err());
        }

        let request = RequestData::new_data(&expected, b"raw descriptor", &[1; 256]).unwrap();
        let request_original = request_value(&request);
        for (key, replacement) in [("requestId", "a".repeat(32)), ("rootNonce", "b".repeat(32)),
            ("sourceCommit", "c".repeat(40)), ("release", "macos26-arm64-other-02".into()),
            ("removeProducerSha256", "d".repeat(64)), ("installedProducerSha256", "e".repeat(64)),
            ("installedInventorySha256", "f".repeat(64)), ("protocolSha256", "9".repeat(64))] {
            let mut changed = request_original.clone(); changed["binding"][key] = json!(replacement);
            let parsed = parse_request_value(&changed).unwrap();
            assert!(parsed.binding_data() != &expected);
            let challenge = FrameData::challenge_data(parsed.binding_data()).unwrap();
            let mut current = TranscriptData::new_data(RoleData::App, expected.clone());
            assert_eq!(current.advance_data(ActionData::Receive, &bytes(&challenge), START).err(), Some(DataError::Binding));
        }
        let other = RequestData::new_data(&binding(TargetData::Intel), b"raw descriptor", &[1; 256]).unwrap();
        let parsed = RequestData::parse_data(&request_bytes(&other)).unwrap();
        assert!(parsed.binding_data() != &expected);
        for (key, replacement) in [("rootNonce", "1".repeat(32)), ("requestId", "0".repeat(32)),
            ("sourceCommit", "C".repeat(40)), ("target", "x86_64-unknown-linux-gnu".into()),
            ("release", "macos26-x86_64-other-01".into())] {
            let mut bad = request_original.clone(); bad["binding"][key] = json!(replacement);
            assert!(parse_request_value(&bad).is_err());
        }
        // Syntax cannot authenticate a raw pair against the binding's digest.
        // Both owners must verify these exact returned originals independently.
        for key in ["removeDescriptor", "removeSignature"] {
            let replacement = if key == "removeDescriptor" { raw_base64(b"different raw original") }
                else { raw_base64(&[2; 256]) };
            let mut changed = request_original.clone(); changed[key] = json!(replacement);
            let parsed = parse_request_value(&changed).unwrap();
            assert!(parsed.binding_data() == &expected);
            if key == "removeDescriptor" { assert_ne!(parsed.remove_descriptor_data(), request.remove_descriptor_data()); }
            else { assert_ne!(parsed.remove_signature_data(), request.remove_signature_data()); }
        }
    }

    #[test]
    fn original_raw_endpoints_equality_regression_and_first_refusal_never_renew() {
        let expected = binding(TargetData::Arm64);
        let clock = expected.clock_data();
        assert_eq!(clock.start_data(), START);
        assert_eq!(clock.work_data(), START + WORK_NS);
        assert_eq!(clock.hard_data(), START + HARD_NS);
        for (start, work, hard) in [(0, WORK_NS, HARD_NS), (START, START + WORK_NS - 1, START + HARD_NS),
            (START, START + WORK_NS + 1, START + HARD_NS), (START, START + WORK_NS, START + HARD_NS - 1),
            (START, START + WORK_NS, START + HARD_NS + 1), (u64::MAX, 1, 2)] {
            assert_eq!(ParentClockData::new_data(start, work, hard), Err(DataError::Clock));
        }
        let edge = ParentClockData::new_data(u64::MAX - HARD_NS, u64::MAX - (HARD_NS - WORK_NS), u64::MAX).unwrap();
        assert!(edge.work_sample_data(edge.start_data(), edge.work_data() - 1).is_ok());
        assert_eq!(edge.settlement_sample_data(edge.start_data(), u64::MAX), Err(DataError::HardExpired));
        let frames = frames(&expected, PreparationData::NeverRegistered);
        for index in 0..FRAME_COUNT {
            for (now, error) in [(clock.work_data(), DataError::WorkExpired),
                (clock.work_data() + 1, DataError::WorkExpired), (clock.hard_data(), DataError::HardExpired)] {
                let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
                advance_prefix(&mut state, &frames, RoleData::Parent, index);
                assert_eq!(state.advance_data(action(RoleData::Parent, index), &bytes(&frames[index]), now).err(), Some(error));
                assert_eq!(state.last_sample_data(), now);
                assert_eq!(state.advance_data(action(RoleData::Parent, index), &bytes(&frames[index]), START + 10).err(), Some(error));
                assert_eq!(state.first_error_data(), Some(error));
                assert_eq!(state.progress_data(), ProgressData::Refused);
            }
        }
        let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
        state.advance_data(ActionData::Send, &bytes(&frames[0]), START + 2).unwrap();
        assert_eq!(state.advance_data(ActionData::Receive, &bytes(&frames[1]), START + 1).err(), Some(DataError::Clock));
        assert_eq!(state.last_sample_data(), START + 2);
        assert_eq!(state.abort_data(), DataError::Clock);
        for now in [0, START - 1] {
            let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
            assert_eq!(state.advance_data(ActionData::Send, &bytes(&frames[0]), now).err(), Some(DataError::Clock));
        }
        assert!(clock.settlement_sample_data(START, clock.work_data()).is_ok());
        assert!(clock.settlement_sample_data(clock.work_data(), clock.hard_data() - 1).is_ok());
        assert_eq!(clock.settlement_sample_data(clock.work_data(), clock.hard_data()), Err(DataError::HardExpired));
        assert_eq!(clock.settlement_sample_data(START + 2, START + 1), Err(DataError::Clock));
        // Reading settlement DATA did not clear or advance the failed attempt.
        assert_eq!(state.first_error_data(), Some(DataError::Clock));
        let mut equal = TranscriptData::new_data(RoleData::Parent, expected);
        for (index, frame) in frames.iter().enumerate() {
            equal.advance_data(action(RoleData::Parent, index), &bytes(frame), START).unwrap();
        }
        assert_eq!(equal.progress_data(), ProgressData::FramesExchanged);

        let request_binding = binding(TargetData::Arm64);
        let request = RequestData::new_data(&request_binding, b"raw", &[1; 384]).unwrap();
        let request_original = request_value(&request);
        let parsed = RequestData::parse_data(&request_bytes(&request)).unwrap();
        assert_eq!(parsed.binding_data().clock_data(), request_binding.clock_data());
        assert_eq!(parsed.binding_data().fields_data().start, START);
        for key in ["start", "work", "hard"] {
            for replacement in [json!(-1), json!(1.0), json!("1"), json!(true), Value::Null] {
                let mut bad = request_original.clone(); bad["binding"][key] = replacement;
                assert!(parse_request_value(&bad).is_err());
            }
            let mut bad = request_original.clone();
            bad["binding"][key] = json!(request_original["binding"][key].as_u64().unwrap() + 1);
            assert!(parse_request_value(&bad).is_err());
        }
        let mut shifted = request_original.clone();
        for key in ["start", "work", "hard"] {
            shifted["binding"][key] = json!(request_original["binding"][key].as_u64().unwrap() + 1);
        }
        let shifted = parse_request_value(&shifted).unwrap();
        assert_eq!(shifted.binding_data().fields_data().start, START + 1);
        assert!(shifted.binding_data() != &request_binding);
        // Parsing is not a new endpoint, native cutoff, or renewed transcript.
        let challenge = FrameData::challenge_data(parsed.binding_data()).unwrap();
        let mut late = TranscriptData::new_data(RoleData::App, request_binding);
        assert_eq!(late.advance_data(ActionData::Receive, &bytes(&challenge), START + WORK_NS).err(), Some(DataError::WorkExpired));
        assert!(RequestData::parse_data(&request_bytes(&request)).is_ok());
        assert_eq!(late.first_error_data(), Some(DataError::WorkExpired));
        assert_eq!(late.progress_data(), ProgressData::Refused);
    }

    #[test]
    fn fixed_encoding_capacity_and_retained_storage_count_real_copies() {
        let expected = binding(TargetData::Arm64);
        let frames = frames(&expected, PreparationData::UnregisteredNow);
        let mut output = [255; FRAME_LIMIT];
        let used = frames[2].encode_framed_data(&mut output).unwrap();
        assert!(used <= FRAME_LIMIT);
        assert!(FrameData::parse_framed_data(&output[..used]).unwrap() == frames[2]);
        assert!(output[used..].iter().all(|b| *b == 0));
        let mut backing = [0; FRAME_BODY_LIMIT];
        let mut writer = BodyWriter { bytes: &mut backing, used: 0 };
        writer.write_all(&[7; FRAME_BODY_LIMIT]).unwrap();
        assert_eq!(writer.used, FRAME_BODY_LIMIT);
        assert!(writer.write_all(&[8]).is_err());
        assert_eq!(writer.used, FRAME_BODY_LIMIT);
        drop(writer);
        assert!(backing.iter().all(|b| *b == 7));
        let mut malformed = frames[0].clone(); malformed.app_nonce = Some("8".repeat(32));
        output.fill(255);
        assert_eq!(malformed.encode_framed_data(&mut output), Err(DataError::Shape));
        assert!(output.iter().all(|b| *b == 0));
        let too_long = format!("macos26-arm64-{}", "a".repeat(129));
        let mut fields = expected.fields_data(); fields.release = &too_long;
        assert_eq!(BindingData::new_data(fields).err(), Some(DataError::Binding));
        let heap = expected.heap_bytes_data().unwrap();
        assert_eq!(expected.owned_bytes_data(), Some(std::mem::size_of::<BindingData>() + heap));
        let mut state = TranscriptData::new_data(RoleData::Parent, expected.clone());
        assert_eq!(state.owned_bytes_data(), Some(std::mem::size_of::<TranscriptData>() + heap));
        advance_prefix(&mut state, &frames, RoleData::Parent, 2);
        let nonce_capacity = state.app_nonce.as_ref().unwrap().capacity();
        assert_eq!(state.owned_bytes_data(), Some(std::mem::size_of::<TranscriptData>() + heap + nonce_capacity));
        assert_eq!(frames[2].owned_bytes_data(), Some(std::mem::size_of::<FrameData>()
            + frames[2].binding.heap_bytes_data().unwrap() + frames[2].app_nonce.as_ref().unwrap().capacity()));
        // Caller frame buffers, simultaneous FrameData and native/task/Completion
        // originals are separate retained objects, not hidden zero-byte credit.
        assert!(state.owned_bytes_data().unwrap().checked_add(frames[2].owned_bytes_data().unwrap())
            .and_then(|n| n.checked_add(FRAME_LIMIT)).is_some());
        assert_eq!(state.abort_data(), DataError::Aborted);
        assert_eq!(state.advance_data(ActionData::Receive, &bytes(&frames[2]), START + 2).err(), Some(DataError::Aborted));

        assert_eq!(REQUEST_LIMIT, 32768);
        assert_eq!(DESCRIPTOR_LIMIT, 16384);
        assert_eq!(SIGNATURE_LIMIT, 512);
        for (raw, encoded) in [(b"f".as_slice(), "Zg=="), (b"fo".as_slice(), "Zm8="),
            (b"foo".as_slice(), "Zm9v"), (b"foob".as_slice(), "Zm9vYg=="),
            (b"fooba".as_slice(), "Zm9vYmE="), (b"foobar".as_slice(), "Zm9vYmFy"),
            (b"\xfb\xff".as_slice(), "+/8="), (b"\xff\xff\xff".as_slice(), "////")] {
            assert_eq!(raw_base64(raw), encoded);
            assert_eq!(decode_request_base64_data(encoded, false).unwrap().as_slice(), raw);
        }
        for descriptor in [Vec::new(), vec![0; DESCRIPTOR_LIMIT + 1]] {
            assert_eq!(RequestData::new_data(&expected, &descriptor, &[0; 256]).err(), Some(DataError::Limit));
        }
        for length in [0, 255, 257, 383, 385, 511, 513] {
            assert_eq!(RequestData::new_data(&expected, b"d", &vec![0; length]).err(), Some(DataError::Limit));
        }
        let request = RequestData::new_data(&expected, b"raw", &[1; 512]).unwrap();
        let request_original = request_value(&request);
        for length in [DESCRIPTOR_LIMIT + 1, DESCRIPTOR_LIMIT + 2, DESCRIPTOR_LIMIT + 3] {
            let mut bad = request_original.clone(); bad["removeDescriptor"] = json!(raw_base64(&vec![0; length]));
            assert!(parse_request_value(&bad).is_err());
        }
        for length in [255, 257, 383, 385, 511, 513, 514] {
            let mut bad = request_original.clone(); bad["removeSignature"] = json!(raw_base64(&vec![0; length]));
            assert!(parse_request_value(&bad).is_err());
        }
        let mut exact = request_bytes(&request); exact.resize(REQUEST_LIMIT, b' ');
        assert!(RequestData::parse_data(&exact).is_ok());
        exact.push(b' ');
        assert_eq!(RequestData::parse_data(&exact).err(), Some(DataError::Limit));
        assert_eq!(RequestData::parse_data(&[]).err(), Some(DataError::Limit));
        for mutation in 0..4 {
            let mut malformed = RequestData::new_data(&expected, b"raw", &[1; 256]).unwrap();
            match mutation {
                0 => malformed.remove_descriptor.clear(),
                1 => malformed.remove_descriptor.resize(DESCRIPTOR_LIMIT + 1, 1),
                2 => { malformed.remove_signature.pop(); },
                _ => malformed.binding.wire.target = "x86_64-unknown-linux-gnu".into(),
            }
            let mut request_output = [255; REQUEST_LIMIT];
            assert!(malformed.encode_data(&mut request_output).is_err());
            assert!(request_output.iter().all(|byte| *byte == 0));
        }
        let mut small = [0; 3];
        let mut writer = BodyWriter { bytes: &mut small, used: 0 };
        assert_eq!(write_request_base64_data(&mut writer, b"f"), Err(DataError::Limit));
        assert_eq!(writer.used, 0);
        let mut retained = RequestData::new_data(&expected, b"raw", &[1; 256]).unwrap();
        let original_count = retained.owned_bytes_data().unwrap();
        let descriptor_spare = retained.remove_descriptor.capacity() + 7;
        let signature_spare = retained.remove_signature.capacity() + 7;
        let release_spare = retained.binding.wire.release.capacity() + 7;
        retained.remove_descriptor.reserve_exact(descriptor_spare);
        retained.remove_signature.reserve_exact(signature_spare);
        retained.binding.wire.release.reserve_exact(release_spare);
        assert!(retained.owned_bytes_data().unwrap() > original_count);
        assert_eq!(retained.owned_bytes_data(), Some(std::mem::size_of::<RequestData>()
            + retained.binding.heap_bytes_data().unwrap()
            + retained.remove_descriptor.capacity() + retained.remove_signature.capacity()));
        let reparsed = RequestData::parse_data(&request_bytes(&retained)).unwrap();
        assert_eq!(reparsed.owned_bytes_data(), Some(std::mem::size_of::<RequestData>()
            + reparsed.binding.heap_bytes_data().unwrap()
            + reparsed.remove_descriptor.capacity() + reparsed.remove_signature.capacity()));
        // These are two retained requests, not one shared byte count. Caller
        // JSON/raw input, output and serde scratch are separate working memory.
        assert!(retained.owned_bytes_data().unwrap().checked_add(reparsed.owned_bytes_data().unwrap())
            .and_then(|count| count.checked_add(expected.owned_bytes_data().unwrap()))
            .and_then(|count| count.checked_add(REQUEST_LIMIT)).is_some());
    }
}
