//! Private mechanical observations over an already-captured native snapshot.
//!
//! No path/suffix, file IO, policy, password, identity match or native validation
//! lives here. JKS is header-only; JSON is a complete bounded document, not just
//! a search for a matching client. The native owner supplies STOP/deadline and
//! must independently establish capture/close custody. No result grants use.
//!
//! R5 requires serde_json 1.0.145 from_slice with its default recursion guard,
//! without arbitrary_precision/float_roundtrip. Native enablement still requires
//! the separately reviewed effective feature/stdlib/native evidence. The lexical
//! pass bounds serde's otherwise-private string scratch before decoding. Parser
//! arenas and all partial projections end before this module returns; dropping
//! memory is not a secure-erasure guarantee.
use std::{fmt, io, mem};
use serde::{de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor}, Serialize};

const JKS_LIMIT: usize = 32 * 1024 * 1024;
const JSON_LIMIT: usize = 4 * 1024 * 1024;
const QUOTED_LIMIT: usize = 8192; // Includes both encoded quote bytes.
const ATOM_LIMIT: usize = 128;
const EXPONENT_LIMIT: u16 = 128;
const STOP_STRIDE: usize = 4096;
const DEPTH_LIMIT: usize = 32;
const NODE_LIMIT: usize = 20_000; // Keys are nodes too.
const KEY_BYTES_LIMIT: usize = 4 * 1024 * 1024;
const COMPARISON_LIMIT: usize = 200_000;
const COMPARED_BYTES_LIMIT: usize = 16 * 1024 * 1024;
const CLIENT_LIMIT: usize = 256;
const PACKAGE_LIMIT: usize = 1024;
const OBSERVATION_LIMIT: usize = 64 * 1024;
const OBSERVATION_NODES: usize = 4096;
const OBSERVATION_DEPTH: usize = 8;
const NO_KEY: u32 = u32::MAX;
const PARSE_ERROR: &str = "credential document refused";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileKind { AndroidKeystore, AndroidFirebase }

pub(crate) struct Interrupted;

// These DTOs are native-only and deliberately have no Debug, Deserialize or
// Clone implementation. The wrapper prevents construction from renderer data.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct FileObservation(Observation);

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Observation {
    Unavailable { reason: UnavailableReason },
    Rejected { reason: RejectedReason },
    Observed { #[serde(flatten)] data: Observed },
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum UnavailableReason { UnsupportedFormat, UnsupportedVariant, MaterialLimit, ParserLimit }

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum RejectedReason { EmptyFile, MalformedContainer }

#[derive(Serialize)]
#[serde(tag = "format")]
enum Observed {
    #[serde(rename = "jks")]
    Jks { #[serde(rename = "byteCount")] byte_count: u64, version: u8 },
    #[serde(rename = "firebase-json")]
    FirebaseJson { #[serde(rename = "byteCount")] byte_count: u64, document: AndroidProjection },
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum AndroidRoot { Object, Other }

#[derive(Serialize)]
struct AndroidProjection { root: AndroidRoot, clients: Option<Vec<Option<AndroidClient>>> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AndroidClient { client_info: Option<ClientInfo> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientInfo { android_client_info: Option<AndroidClientInfo> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AndroidClientInfo { package_name: Option<String> }

// The only returned recursive-looking shape is actually six fixed levels and
// at most seven value/key nodes per client. Strings' requested capacities are
// charged by the serialized budget; the one client vector is reserved once.
const _: () = assert!(6 <= OBSERVATION_DEPTH && 13 + 7 * CLIENT_LIMIT <= OBSERVATION_NODES);
const _: () = assert!(CLIENT_LIMIT * mem::size_of::<Option<AndroidClient>>() + OBSERVATION_LIMIT < 1024 * 1024);

impl FileObservation {
    pub(crate) fn is_observed(&self) -> bool { matches!(&self.0, Observation::Observed { .. }) }
    fn unavailable(reason: UnavailableReason) -> Self { Self(Observation::Unavailable { reason }) }
    fn rejected(reason: RejectedReason) -> Self { Self(Observation::Rejected { reason }) }
}

/// STOP is checked before admission, throughout bounded parser work and before
/// return, including refusal paths. Interruption is never a format observation.
pub(crate) fn inspect(
    kind: FileKind, bytes: &[u8], stop: &mut dyn FnMut() -> bool,
) -> Result<FileObservation, Interrupted> {
    if stop() { return Err(Interrupted); }
    let maximum = match kind { FileKind::AndroidKeystore => JKS_LIMIT, FileKind::AndroidFirebase => JSON_LIMIT };
    let observation = if bytes.len() > maximum {
        FileObservation::unavailable(UnavailableReason::MaterialLimit)
    } else if bytes.is_empty() {
        FileObservation::rejected(RejectedReason::EmptyFile)
    } else {
        match kind {
            FileKind::AndroidKeystore => jks(bytes),
            FileKind::AndroidFirebase => match firebase_json(bytes, stop) {
                Ok(observation) => observation,
                Err(Failure::Interrupted) => return Err(Interrupted),
                Err(Failure::Limit(_)) => FileObservation::unavailable(UnavailableReason::ParserLimit),
                Err(Failure::Malformed) => FileObservation::rejected(RejectedReason::MalformedContainer),
            },
        }
    };
    if stop() { Err(Interrupted) } else { Ok(observation) }
}

fn jks(bytes: &[u8]) -> FileObservation {
    if bytes.len() < 12 { return FileObservation::rejected(RejectedReason::MalformedContainer); }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != 0xfeed_feed { return FileObservation::unavailable(UnavailableReason::UnsupportedFormat); }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let entries = i32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if entries < 0 { return FileObservation::rejected(RejectedReason::MalformedContainer); }
    if !matches!(version, 1 | 2) { return FileObservation::unavailable(UnavailableReason::UnsupportedVariant); }
    // Never allocate/walk entries or interpret the opaque remainder/digest.
    FileObservation(Observation::Observed { data: Observed::Jks { byte_count: bytes.len() as u64, version: version as u8 } })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Limit { Lexical, Number, Depth, Nodes, KeyStorage, KeyComparison, Projection, Allocation }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure { Interrupted, Limit(Limit), Malformed }

fn poll(stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
    if stop() { Err(Failure::Interrupted) } else { Ok(()) }
}

fn exponent_quota(atom: &[u8]) -> Result<(), Failure> {
    if !matches!(atom.first(), Some(b'-' | b'0'..=b'9')) { return Ok(()); }
    let Some(index) = atom.iter().position(|byte| matches!(*byte, b'e' | b'E')) else { return Ok(()); };
    let mut exponent = &atom[index + 1..];
    if matches!(exponent.first(), Some(b'+' | b'-')) { exponent = &exponent[1..]; }
    // Do not label a malformed exponent suffix as numeric overflow.
    if exponent.is_empty() || !exponent.iter().all(u8::is_ascii_digit) { return Ok(()); }
    let mut magnitude = 0u16;
    for digit in exponent {
        magnitude = magnitude.checked_mul(10).and_then(|value| value.checked_add(u16::from(*digit - b'0')))
            .ok_or(Failure::Limit(Limit::Number))?;
        if magnitude > EXPONENT_LIMIT { return Err(Failure::Limit(Limit::Number)); }
    }
    Ok(())
}

/// Quotas only, not a JSON decoder. All syntax/UTF-8/escape decisions remain in
/// serde. Whitespace/punctuation delimit outside atoms; escaped quotes do not.
fn lexical_quota(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
    let mut quoted = false;
    let mut escaped = false;
    let mut quoted_len = 0usize;
    let mut atom_start = None;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if offset % STOP_STRIDE == 0 { poll(stop)?; }
        if quoted {
            if quoted_len == QUOTED_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
            quoted_len += 1;
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else if matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}' | b'[' | b']' | b',' | b':' | b'"') {
            if let Some(start) = atom_start.take() { exponent_quota(&bytes[start..offset])?; }
            if byte == b'"' { quoted = true; quoted_len = 1; }
        } else {
            let start = *atom_start.get_or_insert(offset);
            if offset - start >= ATOM_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
        }
    }
    if let Some(start) = atom_start { exponent_quota(&bytes[start..])?; }
    poll(stop)
}

// One append-only arena, fixed 16-byte links, one head per source depth. Map
// completion does not reclaim arena space; siblings only reset their own head.
#[derive(Clone, Copy)]
struct KeySlot { start: u32, length: u32, next: u32, _reserved: u32 }
const _: () = assert!(mem::size_of::<KeySlot>() == 16);
const _: () = assert!(KEY_BYTES_LIMIT + NODE_LIMIT * 16 + 64 * 1024 + 1024 * 1024 <= 6 * 1024 * 1024);

fn reserved<T>(capacity: usize) -> Result<Vec<T>, Failure> {
    let mut value = Vec::new();
    value.try_reserve_exact(capacity).map_err(|_| Failure::Limit(Limit::Allocation))?;
    if value.capacity() > capacity { return Err(Failure::Limit(Limit::Allocation)); }
    Ok(value)
}

// Start with the complete smallest observation, not just string contents. Each
// change replaces an already-charged slot before allocating/storing its value.
// A package slot initially charges the smaller possible encoding ("", not null)
// so temporary null placeholders cannot falsely refuse an exact-limit result.
// Counts include keys, commas, quotes, escapes and byteCount.
struct ProjectionBudget { bytes: usize, nodes: usize }
impl ProjectionBudget {
    fn new(byte_count: usize) -> Self {
        const BASE: &str = r#"{"status":"observed","byteCount":0,"format":"firebase-json","document":{"root":"other","clients":null}}"#;
        let mut digits = 1;
        let mut remaining = byte_count;
        while remaining >= 10 { digits += 1; remaining /= 10; }
        Self { bytes: BASE.len() - 1 + digits, nodes: 13 }
    }
    fn replace_bytes(&mut self, old: usize, new: usize) -> Result<(), Failure> {
        let bytes = self.bytes.checked_sub(old).and_then(|value| value.checked_add(new))
            .filter(|value| *value <= OBSERVATION_LIMIT).ok_or(Failure::Limit(Limit::Projection))?;
        self.bytes = bytes;
        Ok(())
    }
    fn add_nodes(&mut self, extra: usize, depth: usize, container: bool) -> Result<(), Failure> {
        if depth > OBSERVATION_DEPTH || (container && depth >= OBSERVATION_DEPTH) {
            return Err(Failure::Limit(Limit::Projection));
        }
        self.nodes = self.nodes.checked_add(extra).filter(|value| *value <= OBSERVATION_NODES)
            .ok_or(Failure::Limit(Limit::Projection))?;
        Ok(())
    }
    fn client(&mut self, index: usize) -> Result<(), Failure> {
        if index >= CLIENT_LIMIT { return Err(Failure::Limit(Limit::Projection)); }
        self.add_nodes(1, 3, false)?;
        self.replace_bytes(0, 4 + usize::from(index != 0))
    }
    fn object(&mut self, focus: Focus) -> Result<(), Failure> {
        let (template, depth) = match focus {
            Focus::Root => return self.replace_bytes("other".len(), "object".len()),
            Focus::Client(_) => (r#"{"clientInfo":null}"#, 3),
            Focus::ClientInfo => (r#"{"androidClientInfo":null}"#, 4),
            Focus::AndroidClientInfo => (r#"{"packageName":""}"#, 5),
            _ => return Ok(()),
        };
        self.add_nodes(0, depth, true)?;
        self.add_nodes(2, depth + 1, false)?;
        self.replace_bytes(4, template.len())
    }
    fn package(&mut self, value: &str) -> Result<(), Failure> {
        if value.len() > PACKAGE_LIMIT { return Err(Failure::Limit(Limit::Projection)); }
        let mut encoded = 2usize;
        for byte in value.bytes() {
            let size = match byte {
                b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
                0..=0x1f => 6,
                _ => 1,
            };
            encoded = encoded.checked_add(size).ok_or(Failure::Limit(Limit::Projection))?;
        }
        self.add_nodes(0, 6, false)?;
        self.replace_bytes(2, encoded)
    }
}

struct ParseState<'stop> {
    stop: &'stop mut dyn FnMut() -> bool,
    failure: Option<Failure>,
    nodes: usize,
    keys: Vec<u8>,
    slots: Vec<KeySlot>,
    heads: [u32; DEPTH_LIMIT + 1],
    comparisons: usize,
    compared_bytes: usize,
    projection: ProjectionBudget,
}

impl<'stop> ParseState<'stop> {
    fn new(byte_count: usize, stop: &'stop mut dyn FnMut() -> bool) -> Result<Self, Failure> {
        poll(stop)?;
        let keys = reserved(byte_count.min(KEY_BYTES_LIMIT))?;
        poll(stop)?;
        let slots = reserved(NODE_LIMIT)?;
        poll(stop)?;
        Ok(Self { stop, failure: None, nodes: 0, keys, slots, heads: [NO_KEY; DEPTH_LIMIT + 1],
            comparisons: 0, compared_bytes: 0, projection: ProjectionBudget::new(byte_count) })
    }
    fn refuse<E: de::Error>(&mut self, failure: Failure) -> E {
        if self.failure.is_none() { self.failure = Some(failure); }
        E::custom(PARSE_ERROR) // Never reflect serde, bytes, property names or offsets.
    }
    fn checkpoint<E: de::Error>(&mut self) -> Result<(), E> {
        poll(self.stop).map_err(|failure| self.refuse(failure))
    }
    fn node<E: de::Error>(&mut self, depth: usize) -> Result<(), E> {
        self.checkpoint::<E>()?;
        if depth > DEPTH_LIMIT { return Err(self.refuse(Failure::Limit(Limit::Depth))); }
        if self.nodes >= NODE_LIMIT { return Err(self.refuse(Failure::Limit(Limit::Nodes))); }
        self.nodes += 1;
        Ok(())
    }
    fn container<E: de::Error>(&mut self, depth: usize) -> Result<(), E> {
        self.checkpoint::<E>()?;
        if depth >= DEPTH_LIMIT { return Err(self.refuse(Failure::Limit(Limit::Depth))); }
        Ok(())
    }
    fn key<E: de::Error>(&mut self, depth: usize, value: &str) -> Result<Key, E> {
        self.checkpoint::<E>()?;
        if self.slots.len() >= NODE_LIMIT || self.slots.len() >= self.slots.capacity()
            || value.len() > KEY_BYTES_LIMIT.saturating_sub(self.keys.len())
            || value.len() > self.keys.capacity().saturating_sub(self.keys.len()) {
            return Err(self.refuse(Failure::Limit(Limit::KeyStorage)));
        }
        let mut next = self.heads[depth];
        while next != NO_KEY {
            self.checkpoint::<E>()?;
            let previous = self.slots[next as usize];
            // Charge the longer length even for unequal-length keys. Each step
            // is one candidate key comparison; content comparisons are chunked.
            let charge = (previous.length as usize).max(value.len());
            if self.comparisons >= COMPARISON_LIMIT
                || charge > COMPARED_BYTES_LIMIT.saturating_sub(self.compared_bytes) {
                return Err(self.refuse(Failure::Limit(Limit::KeyComparison)));
            }
            self.comparisons += 1;
            self.compared_bytes += charge;
            let mut equal = previous.length as usize == value.len();
            if equal {
                for offset in (0..value.len()).step_by(STOP_STRIDE) {
                    self.checkpoint::<E>()?;
                    let end = value.len().min(offset + STOP_STRIDE);
                    let start = previous.start as usize;
                    if self.keys[start + offset..start + end] != value.as_bytes()[offset..end] {
                        equal = false;
                        break;
                    }
                }
            }
            if equal { return Err(self.refuse(Failure::Malformed)); }
            next = previous.next;
        }
        self.checkpoint::<E>()?;
        let index = self.slots.len() as u32;
        let slot = KeySlot { start: self.keys.len() as u32, length: value.len() as u32,
            next: self.heads[depth], _reserved: 0 };
        // Both buffers were fallibly preallocated; neither append may grow.
        self.keys.extend_from_slice(value.as_bytes());
        self.slots.push(slot);
        self.heads[depth] = index;
        self.checkpoint::<E>()?;
        Ok(match value {
            "client" => Key::Client, "client_info" => Key::ClientInfo,
            "android_client_info" => Key::AndroidClientInfo, "package_name" => Key::PackageName,
            _ => Key::Other,
        })
    }
}

#[derive(Clone, Copy)]
enum Key { Client, ClientInfo, AndroidClientInfo, PackageName, Other }

#[derive(Clone, Copy)]
enum Focus { Root, Clients, Client(usize), ClientInfo, AndroidClientInfo, PackageName, Ignore }

enum Piece {
    None, Root(AndroidProjection), Clients(Vec<Option<AndroidClient>>), Client(AndroidClient),
    ClientInfo(ClientInfo), AndroidClientInfo(AndroidClientInfo), PackageName(String),
}
impl Piece {
    fn absent(focus: Focus) -> Self {
        match focus { Focus::Root => Self::Root(AndroidProjection { root: AndroidRoot::Other, clients: None }), _ => Self::None }
    }
}

struct KeySeed<'a, 'stop> { state: &'a mut ParseState<'stop>, depth: usize }
impl<'de> DeserializeSeed<'de> for KeySeed<'_, '_> {
    type Value = Key;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Key, D::Error> {
        self.state.node::<D::Error>(self.depth + 1)?;
        deserializer.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for KeySeed<'_, '_> {
    type Value = Key;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("a bounded JSON object key") }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Key, E> { self.state.key::<E>(self.depth, value) }
}

struct Seed<'a, 'stop> { state: &'a mut ParseState<'stop>, depth: usize, focus: Focus }
impl<'de> DeserializeSeed<'de> for Seed<'_, '_> {
    type Value = Piece;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Piece, D::Error> {
        self.state.node::<D::Error>(self.depth)?;
        if let Focus::Client(index) = self.focus {
            self.state.projection.client(index).map_err(|failure| self.state.refuse::<D::Error>(failure))?;
        }
        deserializer.deserialize_any(self)
    }
}
impl Seed<'_, '_> {
    fn scalar<E: de::Error>(self) -> Result<Piece, E> {
        self.state.checkpoint::<E>()?;
        Ok(Piece::absent(self.focus))
    }
}
impl<'de> Visitor<'de> for Seed<'_, '_> {
    type Value = Piece;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("a bounded JSON value") }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Piece, E> { self.scalar::<E>() }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Piece, E> { self.scalar::<E>() }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Piece, E> { self.scalar::<E>() }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Piece, E> {
        if !value.is_finite() { return Err(self.state.refuse(Failure::Limit(Limit::Number))); }
        self.scalar::<E>()
    }
    fn visit_unit<E: de::Error>(self) -> Result<Piece, E> { self.scalar::<E>() }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Piece, E> {
        self.state.checkpoint::<E>()?;
        if !matches!(self.focus, Focus::PackageName) { return Ok(Piece::absent(self.focus)); }
        self.state.projection.package(value).map_err(|failure| self.state.refuse::<E>(failure))?;
        let mut name = String::new();
        name.try_reserve_exact(value.len()).map_err(|_| self.state.refuse::<E>(Failure::Limit(Limit::Allocation)))?;
        if name.capacity() > value.len() { return Err(self.state.refuse(Failure::Limit(Limit::Allocation))); }
        name.push_str(value);
        self.state.checkpoint::<E>()?;
        Ok(Piece::PackageName(name))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Piece, A::Error> {
        self.state.container::<A::Error>(self.depth)?;
        if matches!(self.focus, Focus::Clients) {
            self.state.projection.add_nodes(0, 2, true).map_err(|failure| self.state.refuse::<A::Error>(failure))?;
            self.state.projection.replace_bytes(4, 2).map_err(|failure| self.state.refuse::<A::Error>(failure))?;
            let mut clients = reserved(CLIENT_LIMIT).map_err(|failure| self.state.refuse::<A::Error>(failure))?;
            loop {
                self.state.checkpoint::<A::Error>()?;
                let Some(piece) = seq.next_element_seed(Seed { state: self.state, depth: self.depth + 1,
                    focus: Focus::Client(clients.len()) })? else { break; };
                let client = match piece { Piece::Client(client) => Some(client), Piece::None => None,
                    _ => return Err(self.state.refuse(Failure::Limit(Limit::Projection))) };
                if clients.len() >= clients.capacity() { return Err(self.state.refuse(Failure::Limit(Limit::Allocation))); }
                self.state.checkpoint::<A::Error>()?;
                clients.push(client);
            }
            Ok(Piece::Clients(clients))
        } else {
            // Wrong-type and ignored branches still visit every value/key.
            loop {
                self.state.checkpoint::<A::Error>()?;
                if seq.next_element_seed(Seed { state: self.state, depth: self.depth + 1, focus: Focus::Ignore })?.is_none() { break; }
            }
            Ok(Piece::absent(self.focus))
        }
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Piece, A::Error> {
        self.state.container::<A::Error>(self.depth)?;
        self.state.heads[self.depth] = NO_KEY;
        self.state.projection.object(self.focus).map_err(|failure| self.state.refuse::<A::Error>(failure))?;
        let mut piece = match self.focus {
            Focus::Root => Piece::Root(AndroidProjection { root: AndroidRoot::Object, clients: None }),
            Focus::Client(_) => Piece::Client(AndroidClient { client_info: None }),
            Focus::ClientInfo => Piece::ClientInfo(ClientInfo { android_client_info: None }),
            Focus::AndroidClientInfo => Piece::AndroidClientInfo(AndroidClientInfo { package_name: None }),
            _ => Piece::None,
        };
        loop {
            self.state.checkpoint::<A::Error>()?;
            let Some(key) = map.next_key_seed(KeySeed { state: self.state, depth: self.depth })? else { break; };
            let focus = match (self.focus, key) {
                (Focus::Root, Key::Client) => Focus::Clients,
                (Focus::Client(_), Key::ClientInfo) => Focus::ClientInfo,
                (Focus::ClientInfo, Key::AndroidClientInfo) => Focus::AndroidClientInfo,
                (Focus::AndroidClientInfo, Key::PackageName) => Focus::PackageName,
                _ => Focus::Ignore,
            };
            let child = map.next_value_seed(Seed { state: self.state, depth: self.depth + 1, focus })?;
            match (&mut piece, child) {
                (Piece::Root(root), Piece::Clients(clients)) => root.clients = Some(clients),
                (Piece::Client(client), Piece::ClientInfo(info)) => client.client_info = Some(info),
                (Piece::ClientInfo(info), Piece::AndroidClientInfo(android)) => info.android_client_info = Some(android),
                (Piece::AndroidClientInfo(android), Piece::PackageName(name)) => android.package_name = Some(name),
                _ => {},
            }
        }
        if matches!(&piece, Piece::AndroidClientInfo(android) if android.package_name.is_none()) {
            self.state.projection.replace_bytes(2, 4).map_err(|failure| self.state.refuse::<A::Error>(failure))?;
        }
        Ok(piece)
    }
}

// No output buffer/tree: independently confirm the pre-allocation byte ledger
// against the actual pinned serializer. Writer errors are private fixed facts.
struct ObservationCounter<'a> { stop: &'a mut dyn FnMut() -> bool, used: usize, interrupted: bool }
impl io::Write for ObservationCounter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if (self.stop)() {
            self.interrupted = true;
            // write_all retries ErrorKind::Interrupted; STOP must instead end
            // this serialization once, with the typed flag carrying its cause.
            return Err(io::Error::new(io::ErrorKind::InvalidData, PARSE_ERROR));
        }
        if bytes.len() > OBSERVATION_LIMIT.saturating_sub(self.used) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, PARSE_ERROR));
        }
        self.used += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn firebase_json(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileObservation, Failure> {
    lexical_quota(bytes, stop)?;
    let (document, projected_bytes) = {
        let mut state = ParseState::new(bytes.len(), stop)?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let piece = Seed { state: &mut state, depth: 0, focus: Focus::Root }.deserialize(&mut decoder)
            .map_err(|_| state.failure.unwrap_or(Failure::Malformed))?;
        poll(state.stop)?;
        decoder.end().map_err(|_| Failure::Malformed)?;
        poll(state.stop)?;
        let Piece::Root(document) = piece else { return Err(Failure::Limit(Limit::Projection)); };
        (document, state.projection.bytes)
    }; // Decoder scratch, keys, links and frame heads are released here.
    let observation = FileObservation(Observation::Observed { data: Observed::FirebaseJson {
        byte_count: bytes.len() as u64, document,
    } });
    let mut counter = ObservationCounter { stop, used: 0, interrupted: false };
    if serde_json::to_writer(&mut counter, &observation).is_err() {
        return Err(if counter.interrupted { Failure::Interrupted } else { Failure::Limit(Limit::Projection) });
    }
    if counter.used != projected_bytes { return Err(Failure::Limit(Limit::Projection)); }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    // Authored for separately admitted pure checks; synthetic memory only. No
    // path, file, native parser, process, service, original material or policy.
    use super::*;
    use serde_json::{json, Value};

    fn wire(kind: FileKind, bytes: &[u8]) -> Value {
        let result = match inspect(kind, bytes, &mut || false) {
            Ok(result) => result, Err(_) => panic!("unexpected synthetic interruption"),
        };
        serde_json::to_value(result).unwrap_or_else(|_| panic!("synthetic observation serialization failed"))
    }
    fn json_wire(bytes: &[u8]) -> Value { wire(FileKind::AndroidFirebase, bytes) }
    fn refusal(bytes: &[u8], status: &str, reason: &str) { assert_eq!(json_wire(bytes), json!({"status":status,"reason":reason})); }
    fn source(value: Value) -> Vec<u8> { serde_json::to_vec(&value).unwrap_or_else(|_| panic!("synthetic source serialization failed")) }
    fn header(version: u32, entries: i32) -> Vec<u8> {
        let mut bytes = vec![0xfe, 0xed, 0xfe, 0xed];
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&entries.to_be_bytes());
        bytes
    }
    fn client(name: Value) -> Value { json!({"client_info":{"android_client_info":{"package_name":name}}}) }
    fn projected(name: Value) -> Value { json!({"clientInfo":{"androidClientInfo":{"packageName":name}}}) }
    fn is_observed(kind: FileKind, bytes: &[u8]) -> bool {
        match inspect(kind, bytes, &mut || false) { Ok(value) => value.is_observed(), Err(_) => false }
    }

    #[test]
    fn jks_is_exactly_header_only_and_does_not_walk_entry_count() {
        for version in [1, 2] {
            for entries in [0, i32::MAX] {
                let mut bytes = header(version, entries);
                bytes.extend_from_slice(&[0xff, 0, 0x80, 0xfe]); // Deliberately opaque, not valid entries/digest.
                assert_eq!(wire(FileKind::AndroidKeystore, &bytes), json!({
                    "status":"observed","byteCount":16,"format":"jks","version":version,
                }));
            }
        }
    }

    #[test]
    fn jks_refusals_distinguish_empty_truncation_variant_and_format() {
        assert_eq!(wire(FileKind::AndroidKeystore, b""), json!({"status":"rejected","reason":"empty-file"}));
        let bytes = header(1, 0);
        for length in 1..12 {
            assert_eq!(wire(FileKind::AndroidKeystore, &bytes[..length]), json!({"status":"rejected","reason":"malformed-container"}));
        }
        assert_eq!(wire(FileKind::AndroidKeystore, &header(2, -1)), json!({"status":"rejected","reason":"malformed-container"}));
        assert_eq!(wire(FileKind::AndroidKeystore, &header(3, 0)), json!({"status":"unavailable","reason":"unsupported-variant"}));
        assert_eq!(wire(FileKind::AndroidKeystore, &[0; 12]), json!({"status":"unavailable","reason":"unsupported-format"}));
    }

    #[test]
    fn material_limits_are_inclusive_and_enforced_without_native_custody() {
        let mut bytes = vec![0; JKS_LIMIT + 1];
        bytes[..12].copy_from_slice(&header(1, 0));
        assert!(is_observed(FileKind::AndroidKeystore, &bytes[..JKS_LIMIT]));
        assert_eq!(wire(FileKind::AndroidKeystore, &bytes), json!({"status":"unavailable","reason":"material-limit"}));
        drop(bytes);
        let mut bytes = vec![b' '; JSON_LIMIT + 1];
        bytes[..4].copy_from_slice(b"null");
        assert!(is_observed(FileKind::AndroidFirebase, &bytes[..JSON_LIMIT]));
        refusal(&bytes, "unavailable", "material-limit");
    }

    #[test]
    fn root_and_wrong_client_types_are_observations_not_policy_failures() {
        for bytes in [b"null".as_slice(), b"true", b"false", b"12", b"-0.25", br#""text""#, b"[]", br#"[{"client":[]}]"#] {
            assert_eq!(json_wire(bytes)["document"], json!({"root":"other","clients":null}));
        }
        for bytes in [b"{}".as_slice(), br#"{"client":null}"#, br#"{"client":{}}"#, br#"{"client":false}"#] {
            assert_eq!(json_wire(bytes)["document"], json!({"root":"object","clients":null}));
        }
        assert_eq!(json_wire(br#"{"client":[]}"#)["document"], json!({"root":"object","clients":[]}));
    }

    #[test]
    fn every_client_and_every_missing_or_wrong_type_slot_survives_in_order() {
        let bytes = source(json!({"client":[
            1, null, [], {}, {"client_info":null}, {"client_info":[]}, {"client_info":{}},
            {"client_info":{"android_client_info":false}}, {"client_info":{"android_client_info":{}}},
            client(json!([])), client(json!("")), client(json!(" org.Exact ")), client(json!("org.Exact")), client(json!("org.Exact")),
        ]}));
        assert_eq!(json_wire(&bytes), json!({"status":"observed","byteCount":bytes.len(),"format":"firebase-json",
            "document":{"root":"object","clients":[
                null, null, null, {"clientInfo":null}, {"clientInfo":null}, {"clientInfo":null},
                {"clientInfo":{"androidClientInfo":null}}, {"clientInfo":{"androidClientInfo":null}},
                projected(Value::Null), projected(Value::Null), projected(json!("")), projected(json!(" org.Exact ")),
                projected(json!("org.Exact")), projected(json!("org.Exact")),
            ]}}));
    }

    #[test]
    fn decoded_duplicates_are_rejected_even_in_discarded_or_wrong_type_branches() {
        for bytes in [
            br#"{"a":0,"a":1}"#.as_slice(), br#"{"a":0,"\u0061":1}"#,
            br#"{"ignored":{"a":0,"a":1}}"#, br#"{"client":{"a":0,"a":1}}"#,
            br#"[{"a":0,"a":1}]"#,
            br#"{"client":[{"client_info":{"android_client_info":{"package_name":{"x":0,"x":1}}}}]}"#,
            "{\"\\ud83d\\ude00\":0,\"😀\":1}".as_bytes(),
        ] { refusal(bytes, "rejected", "malformed-container"); }
        assert!(is_observed(FileKind::AndroidFirebase, br#"{"a":{"same":1},"b":{"same":2}}"#));
        assert!(is_observed(FileKind::AndroidFirebase, br#"[{"same":1},{"same":2}]"#));
    }

    #[test]
    fn supported_json_syntax_utf8_escapes_and_end_are_not_skipped() {
        for bytes in [
            b" ".as_slice(), b"{", b"{}{}", b"{} trailing", b"/*comment*/{}", b"{}//comment", b"\xef\xbb\xbf{}",
            b"[0,]", br#"{"a":0,}"#, br#"{"a" 0}"#, b"[0 1]", b"NaN", b"Infinity", b"+1", b"01", b"-01",
            b"1e", b"1e+", b"1.", br#""\q""#, br#""\ud800""#, br#""\udc00""#, b"\xff", b"\"\xff\"", b"\"\n\"",
        ] { refusal(bytes, "rejected", "malformed-container"); }
        refusal(b"", "rejected", "empty-file");
        assert!(is_observed(FileKind::AndroidFirebase, b" \r\n\t{}\t \n"));
        assert!(is_observed(FileKind::AndroidFirebase, br#"{"ignored":"a\\\"b","client":[]}"#));
    }

    #[test]
    fn lexical_quotas_precede_string_scratch_and_are_inclusive() {
        let quoted = format!("\"{}\"", "x".repeat(QUOTED_LIMIT - 2));
        assert!(is_observed(FileKind::AndroidFirebase, quoted.as_bytes()));
        refusal(format!("\"{}\"", "x".repeat(QUOTED_LIMIT - 1)).as_bytes(), "unavailable", "parser-limit");
        let escaped = format!("\"{}\"", "\\n".repeat((QUOTED_LIMIT - 2) / 2));
        assert!(is_observed(FileKind::AndroidFirebase, escaped.as_bytes()));
        refusal(format!("\"{}\"", "\\n".repeat(QUOTED_LIMIT / 2)).as_bytes(), "unavailable", "parser-limit");
        let key = format!("{{\"{}\":0}}", "k".repeat(QUOTED_LIMIT - 2));
        assert!(is_observed(FileKind::AndroidFirebase, key.as_bytes()));
        assert!(matches!(lexical_quota(&vec![b'x'; ATOM_LIMIT + 1], &mut || false), Err(Failure::Limit(Limit::Lexical))));
    }

    #[test]
    fn number_quotas_distinguish_subset_limits_from_malformed_suffixes() {
        for bytes in [b"1e128".as_slice(), b"1e-128", b"-0.1E+000128", b"1e000000", br#""1e9999""#] {
            assert!(is_observed(FileKind::AndroidFirebase, bytes));
        }
        assert!(is_observed(FileKind::AndroidFirebase, "9".repeat(ATOM_LIMIT).as_bytes()));
        for bytes in [b"1e129".as_slice(), b"1e-129", b"1e99999999999999"] { refusal(bytes, "unavailable", "parser-limit"); }
        refusal("9".repeat(ATOM_LIMIT + 1).as_bytes(), "unavailable", "parser-limit");
        for bytes in [b"1e129x".as_slice(), b"1ee129", b"x1e129"] { refusal(bytes, "rejected", "malformed-container"); }
    }

    #[test]
    fn source_depth_counts_root_zero_and_refuses_a_container_at_thirty_two() {
        let deep = format!("{}0{}", "[".repeat(DEPTH_LIMIT), "]".repeat(DEPTH_LIMIT));
        assert!(is_observed(FileKind::AndroidFirebase, deep.as_bytes()));
        let empty_at_limit = format!("{}[]{}", "[".repeat(DEPTH_LIMIT), "]".repeat(DEPTH_LIMIT));
        refusal(empty_at_limit.as_bytes(), "unavailable", "parser-limit");
        let ignored = format!("{{\"ignored\":{}0{}}}", "[".repeat(DEPTH_LIMIT), "]".repeat(DEPTH_LIMIT));
        refusal(ignored.as_bytes(), "unavailable", "parser-limit");
    }

    #[test]
    fn source_node_budget_counts_keys_before_storage_without_a_value_tree() {
        // 1 array + 6666 * (object + key + scalar) + one scalar = 20,000.
        let mut bytes = String::from("[");
        for _ in 0..6666 { bytes.push_str(r#"{"k":0},"#); }
        bytes.push_str("0]");
        assert!(is_observed(FileKind::AndroidFirebase, bytes.as_bytes()));
        bytes.pop();
        bytes.push_str(",0]");
        refusal(bytes.as_bytes(), "unavailable", "parser-limit");
    }

    fn key_object(count: usize, length: usize) -> Vec<u8> {
        let mut text = String::from("{");
        for index in 0..count {
            if index != 0 { text.push(','); }
            text.push('"');
            text.push_str(&"k".repeat(length - 3));
            text.push_str(&format!("{index:03}"));
            text.push_str("\":0");
        }
        text.push('}');
        text.into_bytes()
    }

    #[test]
    fn duplicate_work_has_both_step_and_worst_case_byte_limits() {
        // 632*631/2 = 199,396 comparisons; 633*632/2 = 200,028.
        assert!(is_observed(FileKind::AndroidFirebase, &key_object(632, 4)));
        refusal(&key_object(633, 4), "unavailable", "parser-limit");
        // 64 keys * 63/2 * 8190 < 16 MiB; adding the 65th crosses it.
        assert!(is_observed(FileKind::AndroidFirebase, &key_object(64, QUOTED_LIMIT - 2)));
        refusal(&key_object(65, QUOTED_LIMIT - 2), "unavailable", "parser-limit");
    }

    #[test]
    fn clients_and_utf8_package_limits_never_filter_or_truncate_to_fit() {
        let bytes = source(json!({"client":vec![Value::Null; CLIENT_LIMIT]}));
        assert_eq!(json_wire(&bytes)["document"]["clients"].as_array().map(Vec::len), Some(CLIENT_LIMIT));
        refusal(&source(json!({"client":vec![Value::Null; CLIENT_LIMIT + 1]})), "unavailable", "parser-limit");
        for name in ["x".repeat(PACKAGE_LIMIT), "🦀".repeat(PACKAGE_LIMIT / 4)] {
            let bytes = source(json!({"client":[client(json!(name))]}));
            assert!(is_observed(FileKind::AndroidFirebase, &bytes));
        }
        refusal(&source(json!({"client":[client(json!("x".repeat(PACKAGE_LIMIT + 1)))]})), "unavailable", "parser-limit");
        // Many short decoded names still exceed the serialized observation cap
        // once all control-character escapes are charged before allocation.
        refusal(&source(json!({"client":(0..11).map(|_| client(json!("\0".repeat(1024)))).collect::<Vec<_>>()})), "unavailable", "parser-limit");
    }

    #[test]
    fn complete_observation_byte_limit_is_exact_and_includes_envelope_and_escaping() {
        let mut names: Vec<String> = (0..60).map(|_| "x".repeat(PACKAGE_LIMIT)).collect();
        names.push(String::new());
        names.push(String::new()); // Last empty package tests the smallest leaf reservation.
        let make_source = |names: &[String]| source(json!({"client":names.iter().map(|name| client(json!(name))).collect::<Vec<_>>()}));
        let bytes = make_source(&names);
        let baseline = source(json_wire(&bytes)).len();
        assert!(baseline < OBSERVATION_LIMIT && OBSERVATION_LIMIT - baseline <= PACKAGE_LIMIT);
        names[60] = "x".repeat(OBSERVATION_LIMIT - baseline);
        let exact = make_source(&names);
        let observation = json_wire(&exact);
        assert_eq!(observation["status"], "observed");
        assert_eq!(source(observation).len(), OBSERVATION_LIMIT);
        names[60].push('x');
        refusal(&make_source(&names), "unavailable", "parser-limit");
        let escaped = source(json!({"client":[client(json!("\0\u{1}\n\r\t\u{8}\u{c}\\\"/é🦀"))]}));
        assert!(is_observed(FileKind::AndroidFirebase, &escaped));
    }

    #[test]
    fn projection_node_depth_and_fixed_storage_guards_are_independent() {
        let mut budget = ProjectionBudget::new(1);
        assert!(matches!(budget.add_nodes(OBSERVATION_NODES, 0, false), Err(Failure::Limit(Limit::Projection))));
        assert!(matches!(budget.add_nodes(0, OBSERVATION_DEPTH, true), Err(Failure::Limit(Limit::Projection))));
        assert!(budget.add_nodes(0, OBSERVATION_DEPTH, false).is_ok());
        let mut stop = || false;
        let mut state = ParseState::new(1, &mut stop).unwrap_or_else(|_| panic!("synthetic reserve failed"));
        assert_eq!(mem::size_of::<KeySlot>(), 16);
        assert_eq!(state.keys.capacity(), 1);
        assert_eq!(state.slots.capacity(), NODE_LIMIT);
        assert!(state.key::<serde_json::Error>(0, "aa").is_err());
        assert!(matches!(state.failure, Some(Failure::Limit(Limit::KeyStorage))));
        assert!(state.keys.is_empty() && state.slots.is_empty());
    }

    #[test]
    fn every_success_checkpoint_can_interrupt_without_becoming_a_format_fact() {
        let bytes = source(json!({"ignored":"a".repeat(STOP_STRIDE + 1),"client":[client(json!("org.synthetic")),null]}));
        let mut checkpoints = 0usize;
        assert!(inspect(FileKind::AndroidFirebase, &bytes, &mut || { checkpoints += 1; false }).is_ok());
        assert!(checkpoints > 10);
        for cancel_at in 1..=checkpoints {
            let mut calls = 0usize;
            assert!(inspect(FileKind::AndroidFirebase, &bytes, &mut || { calls += 1; calls >= cancel_at }).is_err(),
                "checkpoint {cancel_at} must not publish an observation");
        }
    }

    #[test]
    fn cancellation_wins_at_final_refusal_boundary_too() {
        for (kind, bytes) in [(FileKind::AndroidKeystore, header(1, 0)), (FileKind::AndroidKeystore, header(3, 0)),
            (FileKind::AndroidFirebase, b"{".to_vec()), (FileKind::AndroidFirebase, b"1e129".to_vec())] {
            let mut checkpoints = 0usize;
            assert!(inspect(kind, &bytes, &mut || { checkpoints += 1; false }).is_ok());
            let mut calls = 0usize;
            assert!(inspect(kind, &bytes, &mut || { calls += 1; calls >= checkpoints }).is_err());
        }
        let mut calls = 0;
        assert!(matches!(lexical_quota(&vec![b' '; 3 * STOP_STRIDE], &mut || { calls += 1; calls >= 3 }), Err(Failure::Interrupted)));
        assert_eq!(calls, 3);
    }

    #[test]
    fn ignored_secret_canaries_and_parser_details_do_not_escape_observations() {
        const CANARY: &str = "fictional-private-parser-canary";
        let bytes = source(json!({CANARY:{"ignored":[1,2,{"value":CANARY}]},"client":[]}));
        let result = source(json_wire(&bytes));
        assert!(!String::from_utf8_lossy(&result).contains(CANARY));
        let malformed = format!("{{\"{CANARY}\":0,\"{CANARY}\":1}}");
        assert_eq!(json_wire(malformed.as_bytes()), json!({"status":"rejected","reason":"malformed-container"}));
        assert_eq!(json_wire(b"1e99999"), json!({"status":"unavailable","reason":"parser-limit"}));
    }
}
