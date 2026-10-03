//! Fixed prepare DATA for one authenticated native connection.
//! Authentication/native originals are supplied by the transport, never by this
//! codec. A zero payload sequence is not evidence that prepare never entered.
#![forbid(unsafe_code)]

pub const BYTES: usize = 64;
pub const MAX_RAW: u64 = (1_u64 << 61) - 1;
pub const CLEANUP_NS: u64 = 10_000_000_000;
const REQUEST_MAGIC: &[u8; 8] = b"MRKATP01";
const REPLY_MAGIC: &[u8; 8] = b"MRKATS01";
const NONCE_PREFIX: &[u8; 8] = b"MRKACTX1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role { Registration = 1, Catalog = 2, Start = 3 }
impl Role {
    pub fn decode(value: u8) -> Option<Self> {
        match value { 1 => Some(Self::Registration), 2 => Some(Self::Catalog),
            3 => Some(Self::Start), _ => None }
    }
    pub fn work_ns(self) -> u64 {
        match self { Self::Registration => 300_000_000_000,
            Self::Catalog => 60_000_000_000, Self::Start => 3_000_000_000_000 }
    }
    pub fn hard_ns(self) -> u64 { self.work_ns() + CLEANUP_NS }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds { pub role: Role, pub origin: u64, pub work: u64, pub hard: u64 }
impl Bounds {
    pub fn valid(self) -> bool {
        self.origin != 0 && self.hard <= MAX_RAW
            && self.origin.checked_add(self.role.work_ns()) == Some(self.work)
            && self.origin.checked_add(self.role.hard_ns()) == Some(self.hard)
    }
    pub fn work_admitted(self, now: u64) -> bool {
        self.valid() && now >= self.origin && now < self.work
    }
    pub fn cleanup(self, first: Option<u64>) -> Option<u64> {
        if !self.valid() { return None; }
        match first {
            None => Some(self.hard),
            Some(at) if at >= self.origin && at <= MAX_RAW =>
                at.checked_add(CLEANUP_NS).map(|end| end.min(self.hard)),
            _ => None,
        }
    }
    pub fn accepts_observation(self, first: Option<u64>, now: u64, last: u64) -> bool {
        self.valid() && now >= last && now >= self.origin && now <= MAX_RAW
            && first.is_none_or(|at| at >= self.origin && at <= now)
    }
}
fn wide(raw: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(raw[at..at + 8].try_into().expect("fixed prepared frame"))
}
fn put(raw: &mut [u8], at: usize, value: u64) {
    raw[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request { pub bounds: Bounds }
impl Request {
    pub fn encode(self) -> Option<[u8; BYTES]> {
        if !self.bounds.valid() { return None; }
        let mut raw = [0; BYTES]; raw[..8].copy_from_slice(REQUEST_MAGIC);
        for (at, value) in [(8, self.bounds.origin), (16, self.bounds.work), (24, self.bounds.hard)] {
            put(&mut raw, at, value);
        }
        raw[32] = self.bounds.role as u8; Some(raw)
    }
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != BYTES || &raw[..8] != REQUEST_MAGIC || raw[33..].iter().any(|v| *v != 0) {
            return None;
        }
        let bounds = Bounds { role: Role::decode(raw[32])?, origin: wide(raw, 8),
            work: wide(raw, 16), hard: wide(raw, 24) };
        bounds.valid().then_some(Self { bounds })
    }
}

/// Connection-local counter comparison DATA, never authentication or a
/// persisted globally unique name. Only the resident counter creates a nonce.
pub fn nonce_for_counter(counter: u64) -> Option<[u8; 16]> {
    if counter == 0 { return None; }
    let mut nonce = [0; 16]; nonce[..8].copy_from_slice(NONCE_PREFIX);
    nonce[8..].copy_from_slice(&counter.to_be_bytes()); Some(nonce)
}
pub fn nonce_valid(nonce: &[u8; 16]) -> bool {
    &nonce[..8] == NONCE_PREFIX && nonce[8..].iter().any(|v| *v != 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase { Pending = 1, Ready = 2, Busy = 3, Refused = 4, Unknown = 5 }
impl Phase {
    fn decode(value: u8) -> Option<Self> {
        match value { 1 => Some(Self::Pending), 2 => Some(Self::Ready),
            3 => Some(Self::Busy), 4 => Some(Self::Refused),
            5 => Some(Self::Unknown), _ => None }
    }
    pub fn no_entry(self) -> bool { matches!(self, Self::Busy | Self::Refused) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub phase: Phase, pub bounds: Bounds, pub nonce: [u8; 16],
    pub first: Option<u64>, pub unknown: bool,
}
impl Reply {
    pub fn valid(self) -> bool {
        self.bounds.valid() && nonce_valid(&self.nonce)
            && self.unknown == (self.phase == Phase::Unknown)
            && self.first.is_none_or(|at| at >= self.bounds.origin && at <= MAX_RAW)
            && self.bounds.cleanup(self.first).is_some()
    }
    pub fn encode(self) -> Option<[u8; BYTES]> {
        if !self.valid() { return None; }
        let mut raw = [0; BYTES]; raw[..8].copy_from_slice(REPLY_MAGIC);
        raw[8] = self.phase as u8; raw[9] = self.bounds.role as u8;
        raw[10] = u8::from(self.unknown); raw[16..32].copy_from_slice(&self.nonce);
        for (at, value) in [(32, self.bounds.origin), (40, self.bounds.work),
            (48, self.bounds.hard), (56, self.first.unwrap_or(0))] { put(&mut raw, at, value); }
        Some(raw)
    }
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != BYTES || &raw[..8] != REPLY_MAGIC || raw[10] > 1
            || raw[11..16].iter().any(|v| *v != 0) { return None; }
        let first = wide(raw, 56);
        let value = Self {
            phase: Phase::decode(raw[8])?,
            bounds: Bounds { role: Role::decode(raw[9])?, origin: wide(raw, 32),
                work: wide(raw, 40), hard: wide(raw, 48) },
            nonce: raw[16..32].try_into().ok()?,
            first: (first != 0).then_some(first), unknown: raw[10] != 0,
        };
        value.valid().then_some(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerCustody { PrepareNotEntered, DefiniteNoEntry, Ambiguous, Pending, Ready }

/// Original prepare call custody. The native wrapper must invoke enter_native
/// BEFORE FFI, and accept_authenticated ONLY after positive same-call return,
/// fixed code requirement, actual root peer EUID and checked original clock.
pub struct ClientAttempt {
    request: Request, state: PeerCustody, nonce: Option<[u8; 16]>,
    call_entered: bool, owner_possible: bool,
}
impl ClientAttempt {
    pub fn new(request: Request) -> Option<Self> {
        request.bounds.valid().then_some(Self { request, state: PeerCustody::PrepareNotEntered,
            nonce: None, call_entered: false, owner_possible: false })
    }
    pub fn request(&self) -> Request { self.request }
    pub fn state(&self) -> PeerCustody { self.state }
    pub fn nonce(&self) -> Option<[u8; 16]> { self.nonce }
    pub fn peer_nonentry_known(&self) -> bool {
        !self.call_entered && !self.owner_possible
            && matches!(self.state, PeerCustody::PrepareNotEntered | PeerCustody::DefiniteNoEntry)
    }
    pub fn enter_native(&mut self) -> bool {
        if self.call_entered || !matches!(self.state, PeerCustody::PrepareNotEntered | PeerCustody::Pending) {
            return false;
        }
        self.call_entered = true; self.state = PeerCustody::Ambiguous; true
    }
    pub fn lost_reply(&mut self) {
        if self.call_entered {
            self.call_entered = false; self.owner_possible = true;
            self.state = PeerCustody::Ambiguous;
        }
    }
    /// No retry follows lost/malformed reply. A remembered admitted nonce only
    /// permits cleanup Stop/Status on the same connection, never another prepare.
    pub fn accept_authenticated(&mut self, reply: Reply) -> bool {
        if !self.call_entered { return false; }
        self.call_entered = false;
        if !reply.valid() || reply.bounds != self.request.bounds
            || self.nonce.is_some_and(|nonce| nonce != reply.nonce)
            || self.owner_possible && reply.phase.no_entry()
        {
            self.owner_possible = true; self.state = PeerCustody::Ambiguous; return false;
        }
        self.nonce = Some(reply.nonce);
        self.state = match reply.phase {
            Phase::Pending => PeerCustody::Pending, Phase::Ready => PeerCustody::Ready,
            Phase::Busy | Phase::Refused => PeerCustody::DefiniteNoEntry,
            Phase::Unknown => PeerCustody::Ambiguous,
        };
        self.owner_possible |= !reply.phase.no_entry();
        true
    }
}

/// Exact Hello non-entry is independent of payload sequence or acknowledgment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloEntry { possible: bool }
impl HelloEntry {
    pub fn reserved() -> Self { Self { possible: false } }
    pub fn before_native_entry(&mut self) { self.possible = true; }
    pub fn never_entered(&self) -> bool { !self.possible }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bounds(role: Role) -> Bounds {
        let origin = 100;
        Bounds { role, origin, work: origin + role.work_ns(), hard: origin + role.hard_ns() }
    }
    fn reply(phase: Phase) -> Reply {
        Reply { phase, bounds: bounds(Role::Catalog), nonce: nonce_for_counter(1).unwrap(),
            first: None, unknown: phase == Phase::Unknown }
    }
    #[test]
    fn fixed_layout_role_and_reserved_bytes_cannot_alias() {
        for role in [Role::Registration, Role::Catalog, Role::Start] {
            let request = Request { bounds: bounds(role) };
            let raw = request.encode().unwrap();
            assert_eq!(Request::decode(&raw), Some(request));
            let mut changed = raw; changed[33] = 1; assert!(Request::decode(&changed).is_none());
            changed = raw; changed[32] = if role == Role::Catalog { 3 } else { 2 };
            assert!(Request::decode(&changed).is_none());
        }
        for phase in [Phase::Pending, Phase::Ready, Phase::Busy, Phase::Refused, Phase::Unknown] {
            let value = reply(phase); let raw = value.encode().unwrap();
            assert_eq!(Reply::decode(&raw), Some(value));
            let mut changed = raw; changed[15] = 1; assert!(Reply::decode(&changed).is_none());
            changed = raw; changed[10] ^= 1; assert!(Reply::decode(&changed).is_none());
        }
        assert!(Request::decode(&[0; BYTES - 1]).is_none());
        assert!(Reply::decode(&[0; BYTES + 1]).is_none());
    }
    #[test]
    fn zero_sequence_cannot_discharge_ambiguous_pending_or_ready_prepare() {
        let mut lost = ClientAttempt::new(Request { bounds: bounds(Role::Catalog) }).unwrap();
        assert!(lost.peer_nonentry_known()); assert!(lost.enter_native());
        assert!(!lost.peer_nonentry_known()); lost.lost_reply();
        assert!(!lost.peer_nonentry_known()); assert!(!lost.enter_native());
        for phase in [Phase::Pending, Phase::Ready] {
            let mut entered = ClientAttempt::new(Request { bounds: bounds(Role::Catalog) }).unwrap();
            assert!(entered.enter_native()); assert!(entered.accept_authenticated(reply(phase)));
            assert!(!entered.peer_nonentry_known()); assert_eq!(entered.nonce(), Some(reply(phase).nonce));
        }
    }
    #[test]
    fn only_first_noentry_is_credit_and_admitted_nonce_never_changes() {
        for phase in [Phase::Busy, Phase::Refused] {
            let mut first = ClientAttempt::new(Request { bounds: bounds(Role::Catalog) }).unwrap();
            assert!(first.enter_native()); assert!(first.accept_authenticated(reply(phase)));
            assert!(first.peer_nonentry_known()); assert!(!first.enter_native());
            let mut pending = ClientAttempt::new(Request { bounds: bounds(Role::Catalog) }).unwrap();
            assert!(pending.enter_native()); assert!(pending.accept_authenticated(reply(Phase::Pending)));
            assert!(pending.enter_native()); assert!(!pending.accept_authenticated(reply(phase)));
            assert!(!pending.peer_nonentry_known()); assert!(!pending.enter_native());
        }
        let mut pending = ClientAttempt::new(Request { bounds: bounds(Role::Catalog) }).unwrap();
        assert!(pending.enter_native()); assert!(pending.accept_authenticated(reply(Phase::Pending)));
        assert!(pending.enter_native());
        let mut changed = reply(Phase::Ready); changed.nonce = nonce_for_counter(2).unwrap();
        assert!(!pending.accept_authenticated(changed));
        assert_eq!(pending.nonce(), Some(reply(Phase::Pending).nonce));
    }
    #[test]
    fn original_bounds_failure_and_hello_entry_never_rebase() {
        let b = bounds(Role::Registration);
        assert_eq!(b.cleanup(Some(b.origin + 1)), Some(b.origin + 1 + CLEANUP_NS));
        assert!(!b.accepts_observation(Some(b.origin + 2), b.origin + 1, b.origin));
        assert!(!b.accepts_observation(None, b.origin, b.origin + 1));
        assert!(!b.work_admitted(b.work));
        let mut bad = b; bad.origin = MAX_RAW; assert!(!bad.valid());
        assert!(nonce_for_counter(0).is_none());
        assert!(nonce_valid(&nonce_for_counter(u64::MAX).unwrap()));
        assert!(!nonce_valid(&[1; 16]));
        let mut hello = HelloEntry::reserved(); assert!(hello.never_entered());
        hello.before_native_entry(); assert!(!hello.never_entered());
        // Reply loss does not provide an operation that resets possible entry.
        hello.before_native_entry(); assert!(!hello.never_entered());
    }
}
