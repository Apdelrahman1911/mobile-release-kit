//! XML-only mechanical plist facts over the original captured slice.
//!
//! quick-xml 0.42.0 owns XML tokenization. The finite guard owns plist framing,
//! quotas and normalized duplicate keys; plist 1.10.1 validates each complete
//! original scalar span, never an unrestricted Value or fabricated XML. In
//! particular its private buffer cannot accumulate across the whole document.
//! No observation is returned until the whole document and tail are consumed.
use std::{io::{self, BufRead, Read}, mem};
use plist::stream::{Event as PlistEvent, XmlReader};
use quick_xml::{events::{attributes::{Attribute, Attributes}, BytesStart, Event}, Reader};

use super::{poll, reserved, Failure, FileObservation, IosProjection, IosRoot, KeySlot,
    Limit, Observation, ObservationCounter, Observed, PlistEncoding,
    COMPARISON_LIMIT, COMPARED_BYTES_LIMIT, DEPTH_LIMIT, KEY_BYTES_LIMIT, NODE_LIMIT,
    NO_KEY, OBSERVATION_DEPTH, OBSERVATION_LIMIT, OBSERVATION_NODES, STOP_STRIDE};

const EVENT_LIMIT: usize = 8192;
const SCALAR_SPAN_LIMIT: usize = 8192;
const SCALAR_LIMIT: usize = 8192;
const MARKUP_LIMIT: usize = 512;
const REFERENCE_LIMIT: usize = 32;
const NUMBER_DATE_LIMIT: usize = 128;
const KEY_LIMIT: usize = 1024;
const BUNDLE_LIMIT: usize = 1024;
const EVENT_COUNT: usize = 100_000;
const PLIST_OBSERVATION_LIMIT: usize = 8192;
const APPLE_DOCTYPE: &str = "plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"";
const APPLE_DOCTYPE_SINGLE: &str = "plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'";

// The 512KiB allowance covers both readers' bounded name/error/scratch buffers,
// scalar/EOL/data copies, fixed stacks and the one small retained projection.
// Native qualification must independently join the actual target allocations.
const _: () = assert!(KEY_BYTES_LIMIT + NODE_LIMIT * 16 + 512 * 1024 < 6 * 1024 * 1024);
const _: () = assert!(6 * BUNDLE_LIMIT + 256 < PLIST_OBSERVATION_LIMIT
    && PLIST_OBSERVATION_LIMIT <= OBSERVATION_LIMIT);
const _: () = assert!(17 <= OBSERVATION_NODES && 3 <= OBSERVATION_DEPTH);

/// No IO. STOP is not io::ErrorKind::Interrupted: both selected readers retry
/// that error. The fixed Other error ends the call; the private latch preserves
/// its real cause. Exposed bytes are bounded BEFORE library vector extension.
struct SliceSource<'bytes, 'stop> {
    bytes: &'bytes [u8], stop: &'stop mut dyn FnMut() -> bool,
    position: usize, exposed: usize, end: usize, failure: Option<Failure>,
}
impl<'bytes, 'stop> SliceSource<'bytes, 'stop> {
    fn new(bytes: &'bytes [u8], stop: &'stop mut dyn FnMut() -> bool) -> Self {
        Self { bytes, stop, position: 0, exposed: 0, end: bytes.len(), failure: None }
    }
    fn event(&mut self, scalar_start: Option<usize>) -> Result<(), Failure> {
        poll(self.stop)?;
        self.end = self.position.checked_add(EVENT_LIMIT)
            .ok_or(Failure::Limit(Limit::Lexical))?.min(self.bytes.len());
        if let Some(start) = scalar_start {
            self.end = self.end.min(start.checked_add(SCALAR_SPAN_LIMIT)
                .ok_or(Failure::Limit(Limit::Lexical))?);
        }
        if self.end < self.position { return Err(Failure::Limit(Limit::Lexical)); }
        // quick-xml can carry its already-peeked '<' into the next event and
        // consume it before another fill_buf. Preserve that unconsumed grant,
        // narrowed to the new limit; never fabricate a fresh byte allowance.
        self.exposed = self.exposed.min(self.end - self.position);
        Ok(())
    }
    fn failed(&mut self, failure: Failure) -> io::Error {
        if self.failure.is_none() || failure == Failure::Interrupted { self.failure = Some(failure); }
        io::Error::from(io::ErrorKind::Other)
    }
    fn result(&mut self) -> Result<(), Failure> {
        poll(self.stop)?;
        self.failure.map_or(Ok(()), Err)
    }
}
impl BufRead for SliceSource<'_, '_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if (self.stop)() { return Err(self.failed(Failure::Interrupted)); }
        if let Some(failure) = self.failure { return Err(self.failed(failure)); }
        if self.position == self.bytes.len() { self.exposed = 0; return Ok(&[]); }
        if self.position >= self.end { return Err(self.failed(Failure::Limit(Limit::Lexical))); }
        self.exposed = (self.end - self.position).min(STOP_STRIDE);
        Ok(&self.bytes[self.position..self.position + self.exposed])
    }
    fn consume(&mut self, amount: usize) {
        if amount > self.exposed {
            let _ = self.failed(Failure::Limit(Limit::Lexical));
            return;
        }
        self.position += amount;
        self.exposed -= amount;
    }
}
impl Read for SliceSource<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let input = self.fill_buf()?;
        let count = input.len().min(output.len());
        output[..count].copy_from_slice(&input[..count]);
        self.consume(count);
        Ok(count)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag { Plist, Dictionary, Array, Key, String, Integer, Real, Date, Data, True, False }
impl Tag {
    fn named(name: &str) -> Result<Self, Failure> {
        match name {
            "plist" => Ok(Self::Plist), "dict" => Ok(Self::Dictionary), "array" => Ok(Self::Array),
            "key" => Ok(Self::Key), "string" => Ok(Self::String), "integer" => Ok(Self::Integer),
            "real" => Ok(Self::Real), "date" => Ok(Self::Date), "data" => Ok(Self::Data),
            "true" => Ok(Self::True), "false" => Ok(Self::False), _ => Err(Failure::Malformed),
        }
    }
    fn scalar(self) -> bool { !matches!(self, Self::Plist | Self::Dictionary | Self::Array) }
}

#[derive(Clone, Copy)]
struct Frame {
    tag: Tag, start: usize, head: u32, wants_key: bool,
    value_seen: bool, bundle_next: bool, capture_bundle: bool,
}
impl Frame {
    const EMPTY: Self = Self { tag: Tag::Plist, start: 0, head: NO_KEY, wants_key: true,
        value_seen: false, bundle_next: false, capture_bundle: false };
}
const _: () = assert!(mem::size_of::<Frame>() * (DEPTH_LIMIT + 1) < 4096);

struct Guard {
    stack: [Frame; DEPTH_LIMIT + 1], depth: usize, nodes: usize,
    keys: Vec<u8>, slots: Vec<KeySlot>, comparisons: usize, compared_bytes: usize,
    scalar: Vec<u8>, bundle_id: Option<String>, root_dictionary: bool,
    may_declare: bool, doctype_seen: bool, root_seen: bool, root_closed: bool,
}
impl Guard {
    fn new(byte_count: usize, stop: &mut dyn FnMut() -> bool) -> Result<Self, Failure> {
        poll(stop)?;
        let keys = reserved(byte_count.min(KEY_BYTES_LIMIT))?;
        poll(stop)?;
        let slots = reserved(NODE_LIMIT)?;
        poll(stop)?;
        let scalar = reserved(SCALAR_LIMIT)?;
        poll(stop)?;
        Ok(Self { stack: [Frame::EMPTY; DEPTH_LIMIT + 1], depth: 0, nodes: 0,
            keys, slots, comparisons: 0, compared_bytes: 0, scalar, bundle_id: None,
            root_dictionary: false, may_declare: true, doctype_seen: false,
            root_seen: false, root_closed: false })
    }
    fn current(&self) -> Option<Frame> { self.depth.checked_sub(1).map(|index| self.stack[index]) }
    fn scalar_start(&self) -> Option<usize> { self.current().filter(|frame| frame.tag.scalar()).map(|frame| frame.start) }
    fn start(&mut self, tag: Tag, offset: usize, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        poll(stop)?;
        self.may_declare = false;
        if tag == Tag::Plist {
            if self.depth != 0 || self.root_seen { return Err(Failure::Malformed); }
            self.root_seen = true;
            self.stack[0] = Frame::EMPTY;
            self.depth = 1;
            return Ok(());
        }
        let parent_index = self.depth.checked_sub(1).ok_or(Failure::Malformed)?;
        let parent = self.stack[parent_index];
        if parent.tag.scalar() { return Err(Failure::Malformed); }
        if self.depth > DEPTH_LIMIT { return Err(Failure::Limit(Limit::Depth)); }
        if self.nodes >= NODE_LIMIT { return Err(Failure::Limit(Limit::Nodes)); }
        self.nodes += 1;
        let capture_bundle = if tag == Tag::Key {
            if parent.tag != Tag::Dictionary || !parent.wants_key { return Err(Failure::Malformed); }
            false
        } else {
            match parent.tag {
                Tag::Plist => {
                    if parent.value_seen { return Err(Failure::Malformed); }
                    self.stack[parent_index].value_seen = true;
                    self.root_dictionary = tag == Tag::Dictionary;
                    false
                }
                Tag::Dictionary => {
                    if parent.wants_key { return Err(Failure::Malformed); }
                    self.stack[parent_index].wants_key = true;
                    self.stack[parent_index].bundle_next = false;
                    parent.bundle_next
                }
                Tag::Array => false,
                _ => return Err(Failure::Malformed),
            }
        };
        self.stack[self.depth] = Frame { tag, start: offset, capture_bundle, ..Frame::EMPTY };
        self.depth += 1;
        if tag.scalar() { self.scalar.clear(); }
        Ok(())
    }
    fn text(&mut self, text: &str, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        poll(stop)?;
        let Some(frame) = self.current().filter(|frame| frame.tag.scalar()) else {
            for chunk in text.as_bytes().chunks(STOP_STRIDE) {
                poll(stop)?;
                if !chunk.iter().copied().all(xml_space) { return Err(Failure::Malformed); }
            }
            if self.depth == 0 && !text.is_empty() { self.may_declare = false; }
            return Ok(());
        };
        if matches!(frame.tag, Tag::True | Tag::False) && !text.is_empty() { return Err(Failure::Malformed); }
        let (maximum, failure) = if matches!(frame.tag, Tag::Integer | Tag::Real | Tag::Date) {
            (NUMBER_DATE_LIMIT, Limit::Number)
        } else if frame.tag == Tag::Key { (KEY_LIMIT, Limit::KeyStorage) }
        else if frame.tag == Tag::String && frame.capture_bundle { (BUNDLE_LIMIT, Limit::Projection) }
        else { (SCALAR_LIMIT, Limit::Lexical) };
        if text.len() > maximum.saturating_sub(self.scalar.len()) { return Err(Failure::Limit(failure)); }
        for chunk in text.as_bytes().chunks(STOP_STRIDE) {
            poll(stop)?;
            self.scalar.extend_from_slice(chunk);
        }
        Ok(())
    }
    fn key(&mut self, parent: usize, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        let length = self.scalar.len();
        if length > self.keys.capacity().saturating_sub(self.keys.len()) || self.slots.len() >= NODE_LIMIT {
            return Err(Failure::Limit(Limit::KeyStorage));
        }
        let mut link = self.stack[parent].head;
        while link != NO_KEY {
            poll(stop)?;
            if self.comparisons >= COMPARISON_LIMIT { return Err(Failure::Limit(Limit::KeyComparison)); }
            self.comparisons += 1;
            let previous = self.slots[link as usize];
            if previous.length as usize == length {
                if length > COMPARED_BYTES_LIMIT.saturating_sub(self.compared_bytes) {
                    return Err(Failure::Limit(Limit::KeyComparison));
                }
                self.compared_bytes += length;
                let start = previous.start as usize;
                if self.keys[start..start + length] == self.scalar { return Err(Failure::Malformed); }
            }
            link = previous.next;
        }
        poll(stop)?;
        let start = self.keys.len();
        self.keys.extend_from_slice(&self.scalar);
        self.slots.push(KeySlot { start: start as u32, length: length as u32,
            next: self.stack[parent].head, _reserved: 0 });
        self.stack[parent].head = (self.slots.len() - 1) as u32;
        self.stack[parent].wants_key = false;
        self.stack[parent].bundle_next = parent == 1 && self.scalar == b"BUNDLE_ID";
        Ok(())
    }
    fn finish(&mut self, tag: Tag, end: usize, bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
        poll(stop)?;
        let frame = self.current().ok_or(Failure::Malformed)?;
        if frame.tag != tag { return Err(Failure::Malformed); }
        if tag.scalar() {
            let span = bytes.get(frame.start..end).ok_or(Failure::Malformed)?;
            if span.len() > SCALAR_SPAN_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
            if tag == Tag::Integer && self.scalar.starts_with(b"0x0x") { return Err(Failure::Malformed); }
            scalar_value(tag, span, stop)?;
            if tag == Tag::Key {
                let parent = self.depth.checked_sub(2).ok_or(Failure::Malformed)?;
                self.key(parent, stop)?;
            } else if tag == Tag::String && frame.capture_bundle {
                let text = std::str::from_utf8(&self.scalar).map_err(|_| Failure::Malformed)?;
                let mut copy = String::new();
                copy.try_reserve_exact(text.len()).map_err(|_| Failure::Limit(Limit::Allocation))?;
                if copy.capacity() > text.len() { return Err(Failure::Limit(Limit::Allocation)); }
                copy.push_str(text);
                self.bundle_id = Some(copy);
            }
            self.scalar.clear();
        } else if tag == Tag::Dictionary && !frame.wants_key { return Err(Failure::Malformed); }
        else if tag == Tag::Plist {
            if !frame.value_seen || self.depth != 1 { return Err(Failure::Malformed); }
            self.root_closed = true;
        }
        self.depth -= 1;
        poll(stop)
    }
}

fn xml_space(byte: u8) -> bool { matches!(byte, b' ' | b'\t' | b'\r' | b'\n') }
fn legal_char(ch: char) -> bool {
    matches!(ch, '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
fn legal_text(text: &str, character_data: bool, stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
    poll(stop)?;
    let mut next = STOP_STRIDE;
    let mut brackets = 0;
    for (offset, ch) in text.char_indices() {
        if offset >= next { poll(stop)?; next = offset + STOP_STRIDE; }
        if !legal_char(ch) || (character_data && ch == '>' && brackets == 2) { return Err(Failure::Malformed); }
        brackets = if ch == ']' { (brackets + 1).min(2) } else { 0 };
    }
    poll(stop)
}

fn attributes(tag: Tag, start: &BytesStart<'_>) -> Result<(), Failure> {
    let mut attrs = start.attributes();
    attrs.with_checks(true);
    if tag == Tag::Plist {
        let first = attrs.next().ok_or(Failure::Malformed)?.map_err(|_| Failure::Malformed)?;
        if first.key.as_ref() != "version" { return Err(Failure::Malformed); }
        if first.value.as_ref() != "1.0" { return Err(Failure::UnsupportedVariant); }
    }
    if attrs.next().is_some() { return Err(Failure::Malformed); }
    Ok(())
}

fn separated_attribute(text: &str, attr: &Attribute<'_>) -> Result<(), Failure> {
    // Attributes validates quotes and duplicate names, but 0.42.0 accepts
    // adjacent quoted attributes without XML's required separating whitespace.
    // Its key is a borrowed slice of this very declaration. Check the preceding
    // original byte; no additional attribute tokenizer or rewritten XML.
    let key = attr.key.as_ref();
    let offset = key.as_ptr().addr().checked_sub(text.as_ptr().addr()).ok_or(Failure::Malformed)?;
    if offset == 0 || key.len() > text.len().saturating_sub(offset)
        || !text.as_bytes().get(offset - 1).is_some_and(|byte| xml_space(*byte)) {
        return Err(Failure::Malformed);
    }
    Ok(())
}

fn declaration(text: &str, wire_len: usize) -> Result<(), Failure> {
    if wire_len > MARKUP_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
    let mut attrs = Attributes::new(text, 3);
    attrs.with_checks(true);
    let first = attrs.next().ok_or(Failure::Malformed)?.map_err(|_| Failure::Malformed)?;
    separated_attribute(text, &first)?;
    if first.key.as_ref() != "version" { return Err(Failure::Malformed); }
    if first.value.as_ref() != "1.0" { return Err(Failure::UnsupportedVariant); }
    let mut encoding = false;
    let mut standalone = false;
    for index in 1..=3 {
        let Some(attr) = attrs.next() else { return Ok(()); };
        let attr = attr.map_err(|_| Failure::Malformed)?;
        if index == 3 { return Err(Failure::Malformed); }
        separated_attribute(text, &attr)?;
        match attr.key.as_ref() {
            "encoding" if !encoding && !standalone => {
                if !attr.value.eq_ignore_ascii_case("UTF-8") { return Err(Failure::UnsupportedVariant); }
                encoding = true;
            }
            "standalone" if !standalone => {
                if !matches!(attr.value.as_ref(), "yes" | "no") { return Err(Failure::Malformed); }
                standalone = true;
            }
            _ => return Err(Failure::Malformed),
        }
    }
    Err(Failure::Malformed)
}

fn scalar_value(tag: Tag, span: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<(), Failure> {
    poll(stop)?;
    let mut reader = XmlReader::new(SliceSource::new(span, stop));
    let first = reader.next();
    let typed = matches!((&first, tag),
        (Some(Ok(PlistEvent::String(_))), Tag::Key | Tag::String)
        | (Some(Ok(PlistEvent::Integer(_))), Tag::Integer)
        | (Some(Ok(PlistEvent::Real(_))), Tag::Real)
        | (Some(Ok(PlistEvent::Date(_))), Tag::Date)
        | (Some(Ok(PlistEvent::Data(_))), Tag::Data)
        | (Some(Ok(PlistEvent::Boolean(true))), Tag::True)
        | (Some(Ok(PlistEvent::Boolean(false))), Tag::False));
    drop(first); // No owned scalar survives to the next read or source event.
    let eof = typed && reader.next().is_none();
    let mut original = reader.into_inner();
    original.result()?;
    if !typed || !eof || original.position != span.len() { return Err(Failure::Malformed); }
    poll(original.stop)
}

fn document(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<IosProjection, Failure> {
    let mut guard = Guard::new(bytes.len(), stop)?;
    let mut scratch = reserved(EVENT_LIMIT)?;
    let mut reader = Reader::from_reader(SliceSource::new(bytes, stop));
    let config = reader.config_mut();
    config.allow_dangling_amp = false;
    config.allow_unmatched_ends = false;
    config.check_comments = true;
    config.check_end_names = true;
    config.expand_empty_elements = false;
    config.trim_text(false);
    for _ in 0..EVENT_COUNT {
        reader.get_mut().event(guard.scalar_start())?;
        scratch.clear();
        // read_event_into returns a borrow of scratch. Pin the original cursor
        // before reading instead of touching that borrowed buffer afterwards.
        // Only the first read removes a UTF-8 BOM; it is not part of the tag.
        let start = reader.get_ref().position;
        let start = if start == 0 && bytes.starts_with(b"\xef\xbb\xbf") { 3 } else { start };
        let event = reader.read_event_into(&mut scratch);
        reader.get_mut().result()?;
        let event = event.map_err(|_| Failure::Malformed)?;
        let end = reader.get_ref().position;
        let wire = bytes.get(start..end).ok_or(Failure::Malformed)?;
        let stop = &mut *reader.get_mut().stop;
        match event {
            Event::Start(ref element) | Event::Empty(ref element) => {
                if wire.len() > MARKUP_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
                let tag = Tag::named(element.name().as_ref())?;
                attributes(tag, element)?;
                guard.start(tag, start, stop)?;
                if matches!(event, Event::Empty(_)) { guard.finish(tag, end, bytes, stop)?; }
            }
            Event::End(element) => {
                if wire.len() > MARKUP_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
                guard.finish(Tag::named(element.name().as_ref())?, end, bytes, stop)?;
            }
            Event::Text(text) => {
                legal_text(text.as_ref(), true, stop)?;
                let normalized = text.xml10_content();
                guard.text(normalized.as_ref(), stop)?;
            }
            Event::GeneralRef(reference) => {
                if wire.len() > REFERENCE_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
                if guard.scalar_start().is_none() { return Err(Failure::Malformed); }
                if let Some(ch) = reference.resolve_char_ref().map_err(|_| Failure::Malformed)? {
                    if !legal_char(ch) { return Err(Failure::Malformed); }
                    let mut encoded = [0u8; 4];
                    guard.text(ch.encode_utf8(&mut encoded), stop)?;
                } else {
                    let text = quick_xml::escape::resolve_xml_entity(reference.as_ref()).ok_or(Failure::UnsupportedVariant)?;
                    guard.text(text, stop)?;
                }
            }
            Event::Comment(text) => {
                if wire.len() > MARKUP_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
                legal_text(text.as_ref(), false, stop)?;
                if guard.depth == 0 { guard.may_declare = false; }
            }
            Event::Decl(decl) => {
                if !guard.may_declare || guard.root_seen || guard.depth != 0 { return Err(Failure::Malformed); }
                declaration(decl.as_ref(), wire.len())?;
                guard.may_declare = false;
            }
            Event::DocType(text) => {
                if guard.doctype_seen || guard.root_seen || guard.depth != 0 { return Err(Failure::Malformed); }
                if wire.len() > MARKUP_LIMIT { return Err(Failure::Limit(Limit::Lexical)); }
                if !wire.starts_with(b"<!DOCTYPE") || !wire.get(9).is_some_and(|byte| xml_space(*byte))
                    || !matches!(text.as_ref().trim_end_matches(|ch: char| ch.is_ascii() && xml_space(ch as u8)), APPLE_DOCTYPE | APPLE_DOCTYPE_SINGLE) {
                    return Err(Failure::UnsupportedVariant);
                }
                guard.doctype_seen = true;
                guard.may_declare = false;
            }
            Event::CData(_) | Event::PI(_) => return Err(Failure::UnsupportedVariant),
            Event::Eof => {
                if !guard.root_seen || !guard.root_closed || guard.depth != 0 || end != bytes.len() { return Err(Failure::Malformed); }
                poll(stop)?;
                return Ok(IosProjection { root: if guard.root_dictionary { IosRoot::Dictionary } else { IosRoot::Other },
                    bundle_id: guard.bundle_id.take() });
            }
        }
        poll(stop)?;
    }
    Err(Failure::Limit(Limit::Nodes))
}

pub(super) fn inspect(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileObservation, Failure> {
    poll(stop)?;
    if bytes.starts_with(b"bplist") || [b"\xff\xfe".as_slice(), b"\xfe\xff", b"\x00\x00\xfe\xff"].iter().any(|bom| bytes.starts_with(bom)) {
        return Err(Failure::UnsupportedVariant);
    }
    let projection = document(bytes, stop)?; // All parser arenas/readers end here.
    let observation = FileObservation(Observation::Observed { data: Observed::FirebasePlist {
        byte_count: bytes.len() as u64, encoding: PlistEncoding::Xml, document: projection,
    } });
    let mut counter = ObservationCounter { stop, used: 0, interrupted: false };
    if serde_json::to_writer(&mut counter, &observation).is_err() {
        return Err(if counter.interrupted { Failure::Interrupted } else { Failure::Limit(Limit::Projection) });
    }
    if counter.used > PLIST_OBSERVATION_LIMIT { return Err(Failure::Limit(Limit::Projection)); }
    poll(counter.stop)?;
    Ok(observation)
}

#[cfg(test)]
#[path = "credential_plist_tests.rs"]
mod tests;
