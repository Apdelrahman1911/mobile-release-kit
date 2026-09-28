//! Closed diagnostic DATA. Private payloads have no Debug/Display/serialization.
//! This is not an output-admission, creator-attribution or cleanup capability.
use crate::ui_observer_diagnostic_data::Projection;
use std::io::{self, Write};

pub(crate) const PLAINTEXT_BYTES: usize = 688;
pub(crate) const CIPHERTEXT_BYTES: usize = 768;
pub(crate) const PUBLIC_BLOB_BYTES: usize = 795;
pub(crate) const LEAF_UNITS: usize = 255;
pub(crate) const FRAME_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Binding, JournalSnapshot, OutputMetadata, LeafBounds, AlreadyClaimed,
    Recipient, Clock, ProviderOpen, PublicImport, Encrypt, CipherLength,
}
impl Stage {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Binding => "binding", Self::JournalSnapshot => "journal-snapshot",
            Self::OutputMetadata => "output-metadata", Self::LeafBounds => "leaf-bounds",
            Self::AlreadyClaimed => "already-claimed", Self::Recipient => "recipient",
            Self::Clock => "clock", Self::ProviderOpen => "provider-open",
            Self::PublicImport => "public-import", Self::Encrypt => "encrypt",
            Self::CipherLength => "cipher-length",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Failure { pub(crate) stage: Stage, pub(crate) status: Option<i32> }
impl Failure {
    pub(crate) const fn data(stage: Stage) -> Self { Self { stage, status: None } }
    pub(crate) const fn native(stage: Stage, status: i32) -> Self { Self { stage, status: Some(status) } }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Binding {
    source: [u8; 20], tree: [u8; 20], run: u64, request: [u8; 32],
}
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N { return None; }
    let digit = |v| match v { b'0'..=b'9' => Some(v - b'0'), b'a'..=b'f' => Some(v - b'a' + 10), _ => None };
    let mut result = [0; N];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Some(result)
}
impl Binding {
    pub(crate) fn parse(source: &str, tree: &str, run: &str, request: &str) -> Option<Self> {
        if run.is_empty() || run.len() > 20 || run.starts_with('0') || !run.bytes().all(|b| b.is_ascii_digit()) { return None; }
        Some(Self { source: unhex(source)?, tree: unhex(tree)?, run: run.parse().ok()?, request: unhex(request)? })
    }
}
#[derive(Clone, Copy)]
pub(crate) struct PublicContext { binding: Binding, journal: Option<Projection> }

// Do not derive Debug/Clone/Copy: this buffer contains the original private leaf.
pub(crate) struct Capture {
    selected: bool, claimed: bool, ready: bool, failure: Option<Failure>,
    binding: Option<Binding>, journal: Option<Projection>, payload: [u8; PLAINTEXT_BYTES],
}
impl Default for Capture {
    fn default() -> Self {
        Self { selected: false, claimed: false, ready: false, failure: None,
            binding: None, journal: None, payload: [0; PLAINTEXT_BYTES] }
    }
}
impl Capture {
    pub(crate) fn journal_returned(&mut self, projection: Projection) {
        if self.journal.is_none() && !self.selected { self.journal = Some(projection); }
    }
    pub(crate) fn record_once(&mut self, binding: Option<Binding>, attributes: u32,
        output: Option<(u64, [u8; 16])>, entry_id: [u8; 16], leaf: &str) {
        if self.selected { return; }
        self.selected = true; self.binding = binding;
        let result = self.encode(binding, attributes, output, entry_id, leaf);
        match result { Ok(()) => self.ready = true, Err(failure) => self.failure = Some(failure) }
    }
    fn encode(&mut self, binding: Option<Binding>, attributes: u32,
        output: Option<(u64, [u8; 16])>, entry_id: [u8; 16], leaf: &str) -> Result<(), Failure> {
        let binding = binding.ok_or(Failure::data(Stage::Binding))?;
        if self.journal.is_none() { return Err(Failure::data(Stage::JournalSnapshot)); }
        let (volume, id) = output.ok_or(Failure::data(Stage::OutputMetadata))?;
        self.payload[..8].copy_from_slice(b"MRKODC1\0");
        self.payload[8..12].copy_from_slice(&[1, 0, 1, 1]); // ProjectDraft, position0, directory, attempt1.
        self.payload[12..16].copy_from_slice(&attributes.to_le_bytes());
        self.payload[16..36].copy_from_slice(&binding.source);
        self.payload[36..56].copy_from_slice(&binding.tree);
        self.payload[56..64].copy_from_slice(&binding.run.to_le_bytes());
        self.payload[64..96].copy_from_slice(&binding.request);
        self.payload[96..104].copy_from_slice(&volume.to_le_bytes());
        self.payload[104..120].copy_from_slice(&id);
        self.payload[120..136].copy_from_slice(&entry_id);
        let mut count = 0usize;
        for unit in leaf.encode_utf16() {
            if count == LEAF_UNITS { return Err(Failure::data(Stage::LeafBounds)); }
            let at = 138 + count * 2;
            self.payload[at..at + 2].copy_from_slice(&unit.to_le_bytes()); count += 1;
        }
        if count == 0 { return Err(Failure::data(Stage::LeafBounds)); }
        self.payload[136..138].copy_from_slice(&(count as u16).to_le_bytes());
        Ok(())
    }
    pub(crate) fn selected(&self) -> bool { self.selected }
    pub(crate) fn public_context(&self) -> Option<PublicContext> {
        self.binding.map(|binding| PublicContext { binding, journal: self.journal })
    }
    pub(crate) fn begin_seal(&mut self) -> Result<(), Failure> {
        if self.claimed { return Err(Failure::data(Stage::AlreadyClaimed)); }
        self.claimed = true;
        if !self.selected || !self.ready { return Err(self.failure.unwrap_or(Failure::data(Stage::Binding))); }
        Ok(())
    }
    // Only the retained CNG owner borrows this in production, never a formatter.
    pub(crate) fn private_buffer(&mut self) -> &mut [u8; PLAINTEXT_BYTES] { &mut self.payload }
}
pub(crate) enum Reply {
    Sealed { key_id: [u8; 32], ciphertext: [u8; CIPHERTEXT_BYTES] },
    Incomplete { key_id: Option<[u8; 32]>, failure: Failure },
}
fn hex(output: &mut impl Write, value: &[u8]) -> io::Result<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for value in value { output.write_all(&[DIGITS[(value >> 4) as usize], DIGITS[(value & 15) as usize]])?; }
    Ok(())
}
pub(crate) fn frame(context: PublicContext, reply: &Reply, bytes: &mut [u8; FRAME_BYTES]) -> Option<usize> {
    fn encode(context: PublicContext, reply: &Reply, output: &mut impl Write) -> io::Result<()> {
        let binding = context.binding;
        output.write_all(b"\nMRK_WINDOWS_UI_OUTPUT_ORIGIN_CAPSULE_V1={\"schema\":1,\"diagnosticOnly\":true,\"source\":\"")?;
        hex(output, &binding.source)?; output.write_all(b"\",\"tree\":\"")?; hex(output, &binding.tree)?;
        write!(output, "\",\"run\":\"{}\",\"attempt\":1,\"role\":\"project-draft\",\"request\":\"", binding.run)?;
        hex(output, &binding.request)?; output.write_all(b"\",\"keySha256\":")?;
        let key = match reply { Reply::Sealed { key_id, .. } => Some(key_id), Reply::Incomplete { key_id, .. } => key_id.as_ref() };
        match key { Some(key) => { output.write_all(b"\"")?; hex(output, key)?; output.write_all(b"\"")?; }, None => output.write_all(b"null")? }
        output.write_all(b",\"scheme\":\"RSA-6144-OAEP-SHA256-MGF1SHA256\",\"plaintextBytes\":688,\"ciphertextBytes\":768,\"inventoryComplete\":false,\"checkedJournalContext\":")?;
        match context.journal { Some(value) => value.write_json(output)?, None => output.write_all(b"null")? }
        match reply {
            Reply::Sealed { ciphertext, .. } => {
                output.write_all(b",\"status\":\"sealed\",\"ciphertextHex\":\"")?;
                hex(output, ciphertext)?; output.write_all(b"\"")?;
            }
            Reply::Incomplete { failure, .. } => {
                write!(output, ",\"status\":\"incomplete\",\"stage\":\"{}\",\"ntstatus\":", failure.stage.label())?;
                match failure.status { Some(status) => write!(output, "{}", status as u32)?, None => output.write_all(b"null")? }
            }
        }
        output.write_all(b"}\n")
    }
    if matches!(reply, Reply::Sealed { .. }) && context.journal.is_none() { return None; }
    let mut output = io::Cursor::new(bytes.as_mut_slice());
    encode(context, reply, &mut output).ok()?;
    usize::try_from(output.position()).ok().filter(|length| *length <= FRAME_BYTES)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase { Open, Import, Encrypt, Destroy, Close }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Step { Good, Refused(Failure), Unresolved }
pub(crate) fn seal_once(mut call: impl FnMut(Phase) -> Step) -> Step {
    let mut failure = None;
    for phase in [Phase::Open, Phase::Import, Phase::Encrypt] {
        match call(phase) {
            Step::Good => (), Step::Refused(value) => { failure = Some(value); break; },
            Step::Unresolved => return Step::Unresolved,
        }
    }
    // The original backend consumes only actually-owned handles. Unknown stops.
    for phase in [Phase::Destroy, Phase::Close] {
        match call(phase) {
            Step::Good => (), Step::Refused(value) => { if failure.is_none() { failure = Some(value); } },
            Step::Unresolved => return Step::Unresolved,
        }
    }
    failure.map_or(Step::Good, Step::Refused)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleState { Reserved, Acquiring, NoHandle, Owned, Closing, Closed, Unknown }
pub(crate) struct HandleOrder { state: HandleState }
impl HandleOrder {
    pub(crate) const fn new() -> Self { Self { state: HandleState::Reserved } }
    pub(crate) fn acquire_enter(&mut self) -> bool {
        if self.state != HandleState::Reserved { self.state = HandleState::Unknown; return false; }
        self.state = HandleState::Acquiring; true
    }
    pub(crate) fn acquire_return(&mut self, status: i32, present: bool) -> HandleState {
        self.state = if self.state != HandleState::Acquiring { HandleState::Unknown }
            else { match (status == 0, present) {
                (true, true) => HandleState::Owned, (false, false) => HandleState::NoHandle, _ => HandleState::Unknown } };
        self.state
    }
    pub(crate) fn close_enter(&mut self) -> Option<bool> {
        match self.state {
            HandleState::Reserved | HandleState::NoHandle | HandleState::Closed => Some(false),
            HandleState::Owned => { self.state = HandleState::Closing; Some(true) },
            _ => { self.state = HandleState::Unknown; None },
        }
    }
    pub(crate) fn close_return(&mut self, status: i32) -> bool {
        self.state = if self.state == HandleState::Closing && status == 0 { HandleState::Closed } else { HandleState::Unknown };
        self.state == HandleState::Closed
    }
    pub(crate) fn owned(&self) -> bool { self.state == HandleState::Owned }
    pub(crate) fn settled(&self) -> bool { matches!(self.state, HandleState::Reserved | HandleState::NoHandle | HandleState::Closed) }
}
pub(crate) fn public_blob_valid(blob: &[u8; PUBLIC_BLOB_BYTES]) -> bool {
    // Public format only, no RSA arithmetic or private material.
    let header = [0x3141_5352u32, 6144, 3, 768, 0, 0];
    header.iter().enumerate().all(|(index, value)| blob[index * 4..index * 4 + 4] == value.to_le_bytes())
        && blob[24..27] == [1, 0, 1] && blob[27] & 0x80 != 0 && blob[PUBLIC_BLOB_BYTES - 1] & 1 == 1
}
