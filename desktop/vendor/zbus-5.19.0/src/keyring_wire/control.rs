//! Source-derived fixed-control arithmetic for the private owned keyring route.
//!
//! This is not an allocator monitor, compiler authenticator, RSS limit or provider
//! qualification. The caller must retain the one-reader/one-RPC topology and the
//! exact source/configuration closure recorded in
//! asset-vault-owned-keyring-wire-control-census-advisory-01.md. That note is
//! advisory, not a measured-size result. These formulae have a separate shipping
//! qualification obligation even when their target/layout guards pass in release.
//!
//! Basis: rustc/std 1.98.0, commit 88d9e12ae178fab0fb5cc050a94da85685d449ea;
//! std hashbrown 0.17.1; async-broadcast 0.7.2; event-listener 5.4.2 (std intrusive,
//! no critical-section/portable-atomic/loom substitution); parking 2.2.1; Tokio
//! 1.48.0 (no loom/tokio_unstable/taskdump). Changed sources and the 1.88 MSRV
//! remain unqualified. Identity is bound by the reviewed verification carrier,
//! not by an environment sentinel or by sizeof checks in this module.
//!
//! Post-advisory tracing caveat: tracing 0.1.44 WithDispatch::poll only scopes
//! polling, not destruction. Dispatch::none() in tracing-core 0.1.36 uses a static
//! NoSubscriber and allocates nothing. Dispatch::new(NoSubscriber) ALSO registers
//! globally and may grow a registry Vec; two Arc handles would not bound that.
//! First-use callsite registration can invoke other registered subscribers even
//! under Dispatch::none(). Bounded-callsite/destruction isolation must therefore
//! be closed by source integration; this arithmetic does not certify it.

#![cfg(all(unix, feature = "tokio"))]

use std::{
    collections::VecDeque,
    mem::{align_of, size_of},
    num::NonZeroU64,
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize},
        Arc,
    },
    task::Waker,
};

const KIB: usize = 1024;
pub(crate) const FIXED_SDK_BYTES: usize = 16 * KIB;
pub(crate) const FUTURE_CONTROL_BYTES: usize =
    2 * super::FUTURE_BYTES + 7 * super::TRANSPORT_FUTURE_BYTES + super::FUTURE_BYTES;
const FUTURE_RESERVATION: usize = 32 * KIB;
const ROOT_LIMIT: usize = 6 * KIB;
const COLLECTION_LIMIT: usize = 4 * KIB;
const EVENT_LIMIT: usize = 4 * KIB;
const TOKIO_LIMIT: usize = 2 * KIB;
const LOCAL_ERROR_LIMIT: usize = KIB;
const CELL_ALIGN: usize = 128;

/// The layout of the actual type, not a pointer to its allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TypeLayout {
    pub size: usize,
    pub align: usize,
}

impl TypeLayout {
    pub(crate) const fn of<T>() -> Self {
        Self { size: size_of::<T>(), align: align_of::<T>() }
    }

    const fn fits(self, size: usize, align: usize) -> bool {
        self.align.is_power_of_two()
            && self.align <= align
            && self.size <= size
            && self.size % self.align == 0
    }
}

/// Supply layouts from the private modules that own these actual types.
///
/// The first six inputs are Arc POINTEES (including their Mutex where listed).
/// The next two are Box POINTEES. The attempt is charged inline once here.
/// Maps/queue entries include their full inline keys/values, not handles to them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LayoutInputs {
    pub retained_mutex: TypeLayout,
    pub connection_inner: TypeLayout,
    pub socket_status: TypeLayout,
    pub senders_mutex: TypeLayout,
    pub pending_mutex: TypeLayout,
    pub split_stream: TypeLayout,
    pub keyring_read: TypeLayout,
    pub keyring_write: TypeLayout,
    pub owned_attempt: TypeLayout,
    pub unfiltered_queue_entry: TypeLayout,
    pub reply_queue_entry: TypeLayout,
    pub sender_map_entry: TypeLayout,
    pub pending_map_entry: TypeLayout,
    pub drained_sender: TypeLayout,
    pub command: TypeLayout,
    /// Independently source-proved TOTAL simultaneous small-error heap backing.
    ///
    /// None fails closed. Some(n) is not itself a proof: the integrated source
    /// audit must bound all reachable error sets, including Custom/StringError
    /// boxes and strings, not just Arc<io::Error>. Normalizing after an arbitrary
    /// allocating decoder is not automatically a bound on its temporary errors.
    /// Separately accounted frame/header/SASL/MethodError payload rows must not
    /// be counted again here, or used to hide additional unbounded errors.
    pub local_error_backing_bytes: Option<usize>,
}

/// Conservative source/layout bounds, never allocator measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedCensus {
    pub roots_bytes: usize,
    pub collections_bytes: usize,
    pub events_bytes: usize,
    pub tokio_bytes: usize,
    pub channel_arc_bytes: usize,
    pub event_arc_bytes: usize,
    pub listener_box_bytes: usize,
    pub task_overhead_bytes: usize,
    pub registration_arc_bytes: usize,
}

impl FixedCensus {
    pub(crate) const fn total(self) -> usize {
        self.roots_bytes + self.collections_bytes + self.events_bytes + self.tokio_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CensusError {
    UnsupportedTarget,
    FutureReservation,
    UnqualifiedLocalErrorBacking,
    LocalErrorBacking,
    InvalidTypeLayout,
    ExternalLayoutWitness,
    RootControls,
    ChannelControls,
    CollectionControls,
    EventControls,
    TokioControls,
}

/// Target support only. Neither this nor a successful census qualifies a build.
pub(crate) const fn supported_target() -> bool {
    cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64",
        not(feature = "async-io"),
        not(tokio_unstable),
    ))
}

/// Apply to the actual original reader future, including subscriber wrappers.
pub(crate) const fn reader_layout_supported(reader: TypeLayout) -> bool {
    supported_target() && reader.fits(super::FUTURE_BYTES, CELL_ALIGN)
}

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

// Only used after the small-layout guards, or with bounded source constants.
const fn round(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

/// Upper bound for the frozen compiler's ordinary record layouts. Every field
/// is padded to the maximum field alignment, so reordering cannot evade the
/// bound. Explicit outer alignment pads the whole record, not every field.
const fn record(fields: &[TypeLayout], outer_align: usize) -> TypeLayout {
    let mut field_align = 1;
    let mut i = 0;
    while i < fields.len() {
        field_align = max(field_align, fields[i].align);
        i += 1;
    }
    let mut size = 0;
    i = 0;
    while i < fields.len() {
        size += round(fields[i].size, field_align);
        i += 1;
    }
    let align = max(field_align, outer_align);
    TypeLayout { size: round(size, align), align }
}

const fn payload(a: TypeLayout, b: TypeLayout) -> TypeLayout {
    let align = max(a.align, b.align);
    TypeLayout { size: round(max(a.size, b.size), align), align }
}

// Deliberately permits a full word tag: no enum/Option niche reliance.
const fn tagged(value: TypeLayout) -> TypeLayout {
    record(&[TypeLayout::of::<usize>(), value], 1)
}

// Retained std alloc/src/sync.rs:387-409: repr(C, align(2)) ArcInner has two
// AtomicUsize counts, then data; allocation extends and pads that layout.
const fn arc_bytes(data: TypeLayout) -> usize {
    let header = TypeLayout::of::<[AtomicUsize; 2]>();
    round(round(header.size, data.align) + data.size, max(header.align, data.align))
}

pub(crate) const fn arc_allocation_bytes(data: TypeLayout) -> Option<usize> {
    if !supported_target() || !data.fits(8 * KIB, CELL_ALIGN) {
        return None;
    }
    Some(arc_bytes(data))
}

// Retained std sync/poison/mutex.rs:227-230 and sys/pal/unix/futex.rs:19-22:
// AtomicU32 raw lock + worst-case AtomicBool poison + UnsafeCell<T>.
const fn std_mutex(data: TypeLayout) -> TypeLayout {
    record(&[TypeLayout::of::<AtomicU32>(), TypeLayout::of::<AtomicBool>(), data], 1)
}

const fn external_witnesses_match() -> bool {
    let word = TypeLayout::of::<usize>();
    word.size == 8 && word.align == 8
        && TypeLayout::of::<AtomicUsize>().fits(8, 8)
        && TypeLayout::of::<AtomicU32>().fits(4, 4)
        && TypeLayout::of::<AtomicBool>().fits(1, 1)
        && TypeLayout::of::<Arc<()>>().size == 8
        && TypeLayout::of::<Arc<()>>().align == 8
        && TypeLayout::of::<&()>().size == 8
        && TypeLayout::of::<&()>().align == 8
        && TypeLayout::of::<Option<NonNull<()>>>().fits(8, 8)
        && TypeLayout::of::<Option<NonZeroU64>>().fits(8, 8)
        && TypeLayout::of::<event_listener::Event>().size == 8
        && TypeLayout::of::<event_listener::Event>().align == 8
        && TypeLayout::of::<Waker>().fits(16, 8)
        && TypeLayout::of::<Option<Waker>>().fits(16, 8)
        && TypeLayout::of::<Arc<dyn Fn() + Send + Sync>>().fits(16, 8)
        && TypeLayout::of::<tokio::task::Id>().fits(8, 8)
        && TypeLayout::of::<Result<(), tokio::task::JoinError>>().fits(64, 8)
        // This contains a real intrusive listener, unlike EventListener's handle.
        // Its &Inner field differs from heap InnerListener's Arc<Inner> field;
        // equal pointer size/alignment above plus the source roster below is
        // the bound, not a claim that these are the identical specialization.
        && TypeLayout::of::<event_listener::__private::StackSlot<'static, ()>>().fits(64, 8)
        && TypeLayout::of::<VecDeque<(crate::Result<crate::Message>, usize)>>().fits(32, 8)
        && TypeLayout::of::<VecDeque<((crate::message::Sequence, crate::Result<crate::Message>), usize)>>().fits(32, 8)
}

// async-broadcast 0.7.2 lib.rs:179-200: queue, four usize counts, head_pos,
// three bools, two Event fields. The mutex/Arc are allocations, not Sender size.
const fn channel_arc(queue: TypeLayout) -> usize {
    let word = TypeLayout::of::<usize>();
    let flag = TypeLayout::of::<bool>();
    let event = TypeLayout::of::<event_listener::Event>();
    let inner = record(
        &[queue, word, word, word, word, TypeLayout::of::<u64>(), flag, flag, flag, event, event],
        1,
    );
    arc_bytes(std_mutex(inner))
}

// std's hashbrown 0.17.1 raw.rs:104-149,201-234,3272-3288. With entry size
// >=4, first insertion chooses four buckets (capacity3). Below Group::WIDTH
// no DELETED tags survive removal; <=one-entry reuse cannot force growth.
// x86_64 SSE2 Group::WIDTH=16. Global returns requested, not usable, length.
const fn four_bucket_map(entry: TypeLayout) -> usize {
    round(4 * entry.size, max(entry.align, 16)) + 4 + 16
}

const fn event_bounds() -> (usize, usize) {
    let word = TypeLayout::of::<usize>();
    // event-listener 5.4.2 intrusive.rs:33-48: three pointers, two counts.
    let list = record(&[word, word, word, word, word], 1);
    let inner = record(&[TypeLayout::of::<AtomicUsize>(), std_mutex(list)], 1);
    // lib.rs:1287-1294: Waker or parking2.2.1 Unparker (one Arc, lib.rs:238).
    let task = tagged(payload(TypeLayout::of::<Waker>(), TypeLayout::of::<Arc<()>>()));
    // lib.rs:1205-1227: Created, Notified {bool, ()}, Task, NotifiedTaken.
    let state = tagged(payload(task, TypeLayout::of::<bool>()));
    // intrusive.rs:401-421: UnsafeCell<Link>, PhantomPinned; State, prev, next.
    let listener = record(&[state, word, word], 1);
    // lib.rs:1053-1069: Arc<Inner> + Option<Listener>.
    let heap_listener = record(&[TypeLayout::of::<Arc<()>>(), tagged(listener)], 1);
    (arc_bytes(inner), heap_listener.size)
}

const fn tokio_bounds() -> (usize, usize) {
    let word = TypeLayout::of::<usize>();
    let pointer = TypeLayout::of::<Option<NonNull<()>>>();
    // Tokio1.48 core.rs:157-184: atomic State, queue_next, vtable, owner_id.
    let header = record(&[
        TypeLayout::of::<AtomicUsize>(), pointer, TypeLayout::of::<&()>(),
        TypeLayout::of::<Option<NonZeroU64>>(),
    ], 1);
    // core.rs:192-198 + task_hooks.rs:83: list pointers, waker, optional Arc Fn.
    let hook = tagged(TypeLayout::of::<Arc<dyn Fn() + Send + Sync>>());
    let trailer = record(&[pointer, pointer, TypeLayout::of::<Option<Waker>>(), hook], 1);
    // core.rs:139-154,209-215; scheduler/current_thread/mod.rs:449-459 and
    // scheduler/multi_thread/handle.rs:58-68 bind Arc<Handle>, not a new runtime.
    //
    // All metadata fields rounded separately to128 overbound their actual
    // alignments. One extra128 bounds output<=64/auto-boxed-pointer and payload
    // rounding above the separately charged original reader size. This covers
    // both inline and auto-boxed tasks, without counting reader bytes twice.
    let task = round(header.size, CELL_ALIGN)
        + round(TypeLayout::of::<Arc<()>>().size, CELL_ALIGN)
        + round(TypeLayout::of::<tokio::task::Id>().size, CELL_ALIGN)
        + round(word.size, CELL_ALIGN) + CELL_ALIGN
        + round(trailer.size, CELL_ALIGN);

    // scheduled_io.rs:101-122; linked_list.rs:19-28; loom/std/mutex.rs:3-6.
    // Waiters: intrusive head/tail + reader/writer wakers. ScheduledIo has
    // intrusive pointers, AtomicUsize, Mutex<Waiters>, explicit alignment128.
    let waiters = record(&[pointer, pointer, TypeLayout::of::<Option<Waker>>(),
        TypeLayout::of::<Option<Waker>>()], 1);
    let io = record(&[pointer, pointer, TypeLayout::of::<AtomicUsize>(), std_mutex(waiters)], CELL_ALIGN);
    (task, arc_bytes(io))
}

/// Calculate source-derived bounds; failure must refuse the bounded profile
/// before creating roots/tasks/I/O. Caller-supplied source obligations are NOT
/// authenticated here (notably error backing, topology and tracing isolation).
pub(crate) const fn fixed_census(input: LayoutInputs) -> Result<FixedCensus, CensusError> {
    if !supported_target() { return Err(CensusError::UnsupportedTarget); }
    if FUTURE_CONTROL_BYTES > FUTURE_RESERVATION {
        return Err(CensusError::FutureReservation);
    }
    let error_bound = match input.local_error_backing_bytes {
        Some(bytes) => bytes,
        None => return Err(CensusError::UnqualifiedLocalErrorBacking),
    };
    if error_bound > LOCAL_ERROR_LIMIT { return Err(CensusError::LocalErrorBacking); }
    if !external_witnesses_match() { return Err(CensusError::ExternalLayoutWitness); }

    let roots = [input.retained_mutex, input.connection_inner, input.socket_status,
        input.senders_mutex, input.pending_mutex, input.split_stream];
    let mut roots_bytes = 0;
    let mut i = 0;
    while i < roots.len() {
        if roots[i].size == 0 || !roots[i].fits(8 * KIB, CELL_ALIGN) {
            return Err(CensusError::InvalidTypeLayout);
        }
        roots_bytes += arc_bytes(roots[i]);
        i += 1;
    }
    let direct = [input.keyring_read, input.keyring_write, input.owned_attempt];
    i = 0;
    while i < direct.len() {
        if direct[i].size == 0 || !direct[i].fits(8 * KIB, CELL_ALIGN) {
            return Err(CensusError::InvalidTypeLayout);
        }
        roots_bytes += direct[i].size;
        i += 1;
    }
    // Charge the entire finite error envelope, not an unexplained remainder.
    roots_bytes += LOCAL_ERROR_LIMIT;
    if roots_bytes > ROOT_LIMIT { return Err(CensusError::RootControls); }

    if !input.unfiltered_queue_entry.fits(256, 16) || input.unfiltered_queue_entry.size == 0
        || !input.reply_queue_entry.fits(256, 16) || input.reply_queue_entry.size == 0
        || !input.sender_map_entry.fits(512, 16) || input.sender_map_entry.size < 4
        || !input.pending_map_entry.fits(32, 16) || input.pending_map_entry.size < 4
        || !input.drained_sender.fits(8, 8) || input.drained_sender.size != 8
        || !input.command.fits(64, 16) || input.command.size < 2
    {
        return Err(CensusError::InvalidTypeLayout);
    }
    let unfiltered_arc = channel_arc(
        TypeLayout::of::<VecDeque<(crate::Result<crate::Message>, usize)>>(),
    );
    let reply_arc = channel_arc(
        TypeLayout::of::<VecDeque<((crate::message::Sequence, crate::Result<crate::Message>), usize)>>(),
    );
    if unfiltered_arc > 256 || reply_arc > 256 { return Err(CensusError::ChannelControls); }
    // One unfiltered + at most two reply allocations (old reader Sender can
    // overlap staging the next RPC). Physical VecDeque capacity is exactly1
    // under retained std with_capacity/RawVec/Global, not inferred from its API.
    // fail_all's nonempty generic collect has min capacity4 for an 8-byte Sender.
    // Command Vec capacity4 and one-command read Vec do not overlap.
    let collections_bytes = unfiltered_arc + 2 * reply_arc
        + input.unfiltered_queue_entry.size + 2 * input.reply_queue_entry.size
        + four_bucket_map(input.sender_map_entry) + four_bucket_map(input.pending_map_entry)
        + 4 * input.drained_sender.size + 4 * input.command.size;
    if collections_bytes > COLLECTION_LIMIT { return Err(CensusError::CollectionControls); }

    let (event_arc_bytes, listener_box_bytes) = event_bounds();
    if event_arc_bytes > 256 || listener_box_bytes > 256 { return Err(CensusError::EventControls); }
    // Nine lazy Event owners plus one concurrent first-use CAS loser; three
    // intrusive listener boxes. notify() may allocate even without a listener.
    let events_bytes = 10 * event_arc_bytes + 3 * listener_box_bytes;
    if events_bytes > EVENT_LIMIT { return Err(CensusError::EventControls); }

    let (task_overhead_bytes, registration_arc_bytes) = tokio_bounds();
    if task_overhead_bytes > KIB || registration_arc_bytes > 256 {
        return Err(CensusError::TokioControls);
    }
    // Two registrations may overlap across into_std/from_std; include two
    // pending-release Arc bookkeeping slots, not the runtime's whole Vec/RSS.
    let tokio_bytes = task_overhead_bytes + 2 * registration_arc_bytes + 2 * size_of::<Arc<()>>();
    if tokio_bytes > TOKIO_LIMIT { return Err(CensusError::TokioControls); }
    Ok(FixedCensus {
        roots_bytes, collections_bytes, events_bytes, tokio_bytes,
        channel_arc_bytes: max(unfiltered_arc, reply_arc),
        event_arc_bytes, listener_box_bytes, task_overhead_bytes, registration_arc_bytes,
    })
}

/// Arithmetic regression checks shared by crate tests and the existing app
/// test-support bridge. The synthetic layouts are NOT measurements of P roots;
/// the integration must separately call fixed_census with real private types.
#[cfg(any(test, feature = "mrk-owned-test-support"))]
#[cfg_attr(test, test)]
pub(crate) fn formula_regressions() {
    let small = TypeLayout::of::<[usize; 16]>();
    let mut input = LayoutInputs {
        retained_mutex: small, connection_inner: small, socket_status: small,
        senders_mutex: small, pending_mutex: small, split_stream: small,
        keyring_read: TypeLayout::of::<usize>(), keyring_write: TypeLayout::of::<usize>(),
        owned_attempt: small,
        unfiltered_queue_entry: TypeLayout { size: 256, align: 8 },
        reply_queue_entry: TypeLayout { size: 256, align: 8 },
        sender_map_entry: TypeLayout { size: 512, align: 16 },
        pending_map_entry: TypeLayout { size: 32, align: 16 },
        drained_sender: TypeLayout::of::<usize>(),
        command: TypeLayout { size: 64, align: 8 },
        local_error_backing_bytes: None,
    };
    if !supported_target() {
        assert_eq!(fixed_census(input), Err(CensusError::UnsupportedTarget));
        assert!(!reader_layout_supported(small));
        return;
    }
    assert_eq!(FUTURE_CONTROL_BYTES, 31 * KIB);
    assert_eq!(ROOT_LIMIT + COLLECTION_LIMIT + EVENT_LIMIT + TOKIO_LIMIT, FIXED_SDK_BYTES);
    assert_eq!(FUTURE_RESERVATION + FIXED_SDK_BYTES + 16 * KIB, 64 * KIB);
    assert_eq!(fixed_census(input), Err(CensusError::UnqualifiedLocalErrorBacking));
    input.local_error_backing_bytes = Some(LOCAL_ERROR_LIMIT + 1);
    assert_eq!(fixed_census(input), Err(CensusError::LocalErrorBacking));
    input.local_error_backing_bytes = Some(LOCAL_ERROR_LIMIT);
    let census = fixed_census(input).expect("supported source-layout arithmetic");
    assert!(census.total() <= FIXED_SDK_BYTES);
    assert!(census.collections_bytes <= 4040);
    assert!(census.events_bytes <= 3328);
    assert!(census.tokio_bytes <= 1552);
    assert_eq!(four_bucket_map(input.sender_map_entry), 2068);
    assert_eq!(four_bucket_map(input.pending_map_entry), 148);
    assert_eq!(arc_allocation_bytes(TypeLayout { size: 128, align: 128 }), Some(256));
    assert_eq!(arc_allocation_bytes(TypeLayout { size: 8, align: 3 }), None);
    assert!(reader_layout_supported(TypeLayout { size: 8192, align: 128 }));
    assert!(!reader_layout_supported(TypeLayout { size: 8193, align: 1 }));
    assert!(!reader_layout_supported(TypeLayout { size: 8192, align: 256 }));
    input.sender_map_entry = TypeLayout { size: 528, align: 16 };
    assert_eq!(fixed_census(input), Err(CensusError::InvalidTypeLayout));
    input.sender_map_entry = TypeLayout { size: 512, align: 16 };
    input.connection_inner = TypeLayout { size: 8192, align: 8 };
    assert_eq!(fixed_census(input), Err(CensusError::RootControls));
}
