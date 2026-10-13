//! Ignored REAL-GNOME, SESSION-COLLECTION component fixture, not qualification.
//!
//! Run only after separate source/command review and fresh private-namespace
//! admission. The launcher must bind the pinned daemon/library closure at the
//! fixed paths below, reserve the same NONROOT outer/inner UID/GID, exclude host
//! sessions/network/activation, and impose output/FD/memory/outer time bounds.
//! No account, mount, package installation, login/unlock, persistent collection,
//! GUI, Python/core runtime or shared user data is created by this fixture.
//!
//! One sequential selector owns its bus/provider children, bootstrap attempt,
//! and actual app coordinator. Only closed Boolean/count outcomes are printed.
//! A missing internal join fails and retains its custody until the separately
//! owned enclosing namespace is retired; outer disposal is NEVER a native pass.

use super::*;
use crate::vault_keyring_linux::{LookupInput, NativeFixtureSnapshot, Problem, Step};
use ordered_stream::{OrderedStream, PollResult};
use secret_service::checked_lookup::{self as checked, test_support as fixture_sdk};
use std::{fs::{File, OpenOptions}, io::Write, os::unix::{fs::{MetadataExt, OpenOptionsExt},
    process::ExitStatusExt}, path::{Path, PathBuf}, process::{ExitStatus, Stdio}};
use tokio::{io::AsyncReadExt, process::{Child, Command}};
use zbus::{connection::{LocalSettlement, OwnedConnectionAttempt}, message::Type as MessageType,
    names::UniqueName, zvariant::{OwnedObjectPath, Signature, Type}, MatchRule, Message};

type Check<T> = Result<T, &'static str>;
const ROOT: &str = "/mrk-gnome-fixture";
const BUS_SOCKET: &str = "/mrk-gnome-fixture/run/bus";
const BUS_CONFIG: &str = "/mrk-gnome-fixture/bus.conf";
const BUS_BIN: &str = "/usr/bin/dbus-daemon";
const PROVIDER_BIN: &str = "/usr/bin/gnome-keyring-daemon";
const BUS: &str = "org.freedesktop.DBus";
const BUS_OBJECT: &str = "/org/freedesktop/DBus";
const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_OBJECT: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const VAULT: &str = "mrk-gnome-session-component-v1";
const SINGLE: &str = "single-generation-v1";
const DUPLICATE: &str = "duplicate-generation-v1";
const MISSING: &str = "absent-generation-v1";

#[derive(Clone, Copy)]
struct Observed<T> { value: T, end: Instant, at: Instant }
impl<T> Observed<T> {
    fn now(value: T, end: Instant) -> Self { Self { value, end, at: Instant::now() } }
    fn timely(&self) -> bool { self.at < self.end }
    // Readiness/snapshot callers may consume this. Original build, raw, local
    // settlement and child values instead stay retained even when they are late.
    fn timely_value(self) -> Check<T> { if self.timely() { Ok(self.value) } else { Err("fixture-deadline") } }
}
async fn before<T>(end: Instant, future: impl Future<Output = T>) -> Check<Observed<T>> {
    // Tokio can return an already-ready original on a poll after timeout_at's
    // endpoint. Preserve that result; Ready alone is NOT timely authority.
    tokio::time::timeout_at(tokio::time::Instant::from_std(end), future).await
        .map(|value| Observed::now(value, end)).map_err(|_| "fixture-deadline")
}

/// A selected successor is withheld for only one bounded wait at a time.
/// The caller re-enters the ordinary drive loop, including real owner-stream
/// processing. This is NOT a second backend loop or a native result producer.
pub(super) struct BoundaryGate {
    step: Step, reached: AtomicBool, changed: Notify,
}
impl BoundaryGate {
    fn new(step: Step) -> Arc<Self> {
        Arc::new(Self { step, reached: AtomicBool::new(false), changed: Notify::new() })
    }
}
pub(super) async fn hold_successor(owner: &Arc<OriginalWork>, step: Step) -> bool {
    let gate = owner.gnome_transport_gate.lock().ok().and_then(|gate| gate.clone());
    let Some(gate) = gate.filter(|gate| gate.step == step) else { return false; };
    if !gate.reached.swap(true, Ordering::SeqCst) { gate.changed.notify_one(); }
    if owner.interrupted() { return false; }
    // No document/book lock crosses the wait. The actual first WORK endpoint
    // and STOP notifier wake it; the next turn still owes ordinary admission.
    let end = owner.endpoint().unwrap_or_else(Instant::now);
    let tick = (Instant::now() + Duration::from_millis(10)).min(end);
    tokio::select! { _ = owner.wake.notified() => {},
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(tick)) => {} }
    true
}

// Fixed typed setup request. IV/ciphertext slices serialize as ay, not fixed
// Rust-array structures. No generic Value map or user-controlled properties.
struct Attributes(&'static str);
impl Type for Attributes { const SIGNATURE: &'static Signature = &Signature::static_dict(&Signature::Str, &Signature::Str); }
impl Serialize for Attributes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(4))?;
        for (key, value) in [("application", "dev.mobile-release-kit.desktop"), ("purpose", "vault-wrapping-key-v1"),
            ("vault-id", VAULT), ("generation-id", self.0)] { map.serialize_entry(key, value)?; }
        map.end()
    }
}
struct Properties(Attributes);
impl Type for Properties { const SIGNATURE: &'static Signature = &Signature::static_dict(&Signature::Str, &Signature::Variant); }
impl Serialize for Properties {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        use zbus::zvariant::as_value::Serialize as Variant;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("org.freedesktop.Secret.Item.Label", &Variant(&"MRK public transport canary"))?;
        map.serialize_entry("org.freedesktop.Secret.Item.Attributes", &Variant(&self.0))?;
        map.end()
    }
}
struct CreateItem {
    generation: &'static str, session: OwnedObjectPath, iv: [u8; 16], ciphertext: [u8; 48],
}
impl Type for CreateItem {
    const SIGNATURE: &'static Signature =
        <(Properties, (OwnedObjectPath, Vec<u8>, Vec<u8>, String), bool)>::SIGNATURE;
}

impl Serialize for CreateItem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (Properties(Attributes(self.generation)),
            (&self.session, &self.iv[..], &self.ciphertext[..], "application/octet-stream"), false).serialize(serializer)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupCall { Other, Open, Close, Remove }
struct PendingSetupCall { kind: SetupCall, polled: bool, end: Instant, cleanup: bool }
struct Bootstrap {
    attempt: OwnedConnectionAttempt, build_pending: bool, build_polled: bool,
    build_result: Option<Observed<zbus::Result<()>>>, late: bool,
    call: Option<PendingSetupCall>, raw: Option<zbus::Result<Message>>, raw_reconciled: bool,
    raw_observed: Option<Observed<()>>, raw_reconciled_at: Option<Observed<()>>,
    owner: Option<UniqueName<'static>>, owner_changed: bool, stream_failed: bool,
    subscribed: bool, removed: bool, session: Option<OwnedObjectPath>, session_possible: bool, close_polled: bool,
    opens: u8, closes: u8, work_end: Instant, first_stop: Option<Instant>,
    stream_released: bool, local: Option<Observed<LocalSettlement>>,
}
impl Bootstrap {
    fn new() -> Check<Self> {
        Ok(Self { attempt: OwnedConnectionAttempt::keyring_unix(PathBuf::from(BUS_SOCKET)).map_err(|_| "setup-constructor")?,
            build_pending: true, build_polled: false, build_result: None, late: false,
            call: None, raw: None, raw_reconciled: true, raw_observed: None, raw_reconciled_at: None,
            owner: None, owner_changed: false, stream_failed: false,
            subscribed: false, removed: false, session: None, session_possible: false, close_polled: false, opens: 0, closes: 0,
            work_end: Instant::now() + WORK, first_stop: None, stream_released: false, local: None })
    }
    fn fail_at(&mut self, at: Instant) { self.first_stop.get_or_insert(at.min(self.work_end)); }
    fn observe<T>(&mut self, value: T, end: Instant) -> Observed<T> {
        let observed = Observed::now(value, end);
        if !observed.timely() { self.late = true; self.fail_at(end); }
        observed
    }
    fn timely_wait<T>(&mut self, result: &Check<Observed<T>>, end: Instant) -> bool {
        let timely = result.as_ref().is_ok_and(|observed| observed.end == end && observed.timely());
        if !timely { self.late = true; self.fail_at(end); }
        timely
    }
    fn reconcile_raw(&mut self) {
        self.raw_reconciled = true;
        if let Some(observed) = self.raw_observed {
            let reconciled = self.observe((), observed.end);
            self.raw_reconciled_at.get_or_insert(reconciled);
        }
    }
    fn local_finality(&self) -> bool {
        !self.late && self.local.is_some_and(|local| local.timely() && local.value.clean())
            && self.stream_released && !self.build_pending && self.call.is_none() && self.raw.is_none()
    }
    fn finality(&self) -> bool {
        self.local_finality() && !self.session_possible && self.opens == self.closes && (!self.subscribed || self.removed)
    }
    fn body(&self) -> Check<zbus::message::Body> {
        self.raw.as_ref().and_then(|raw| raw.as_ref().ok()).map(Message::body).ok_or("setup-raw-reply")
    }
    fn owner(&self) -> Check<UniqueName<'static>> { self.owner.clone().ok_or("setup-owner-absent") }
    fn event(&mut self, message: &Message) {
        let header = message.header();
        if header.message_type() != MessageType::Signal
            || header.sender().map(|name| name.as_str()) != Some(BUS)
            || header.member().map(|name| name.as_str()) != Some("NameOwnerChanged") { return; }
        match checked::decode_owner_changed(&message.body()) {
            Ok((None, Some(new))) if self.owner.is_none() => match UniqueName::try_from(new.to_owned()) {
                Ok(owner) => self.owner = Some(owner), Err(_) => self.owner_changed = true,
            },
            _ => self.owner_changed = true,
        }
    }
    fn poll_stream(&mut self, cx: &mut TaskContext<'_>, before: Option<&zbus::message::Sequence>) -> bool {
        match Pin::new(&mut self.attempt).poll_next_before(cx, before) {
            Poll::Pending => false,
            Poll::Ready(PollResult::NoneBefore) => before.is_some(),
            Poll::Ready(PollResult::Item { data: Ok(message), .. }) => {
                self.event(&message); cx.waker().wake_by_ref(); false
            },
            Poll::Ready(PollResult::Item { data: Err(_), .. } | PollResult::Terminated) => {
                self.stream_failed = true; true
            },
        }
    }
    fn poll_call(&mut self, cx: &mut TaskContext<'_>) {
        let Some(call) = self.call.as_mut() else { return; };
        if !call.polled && (Instant::now() >= call.end || !call.cleanup
            && (self.first_stop.is_some() || self.owner_changed || self.stream_failed)) {
            let at = Instant::now().min(call.end);
            if self.attempt.refuse_unpolled_call().is_ok() {
                self.call = None; self.raw = Some(Err(zbus::Error::InvalidReply)); self.raw_reconciled = true;
            }
            self.fail_at(at); cx.waker().wake_by_ref(); return;
        }
        if !call.polled {
            if call.kind == SetupCall::Open { self.session_possible = true; self.opens += 1; }
            if call.kind == SetupCall::Close { self.close_polled = true; }
        }
        call.polled = true;
        let kind = call.kind; let end = call.end;
        if let Poll::Ready(raw) = self.attempt.poll_raw_call(cx) {
            self.call = None; self.raw = Some(raw); self.raw_reconciled = false;
            self.raw_observed = Some(self.observe((), end));
            // Retain every trustworthy OpenSession path BEFORE a later owner,
            // deadline, derivation or CreateItem failure. Even cleanup observes
            // a late original; it does not pretend the session never existed.
            if kind == SetupCall::Open {
                if let (Ok(owner), Ok(body)) = (self.owner(), self.body()) {
                    if let Ok((_, path)) = checked::decode_open_session(&body, &owner) {
                        if let Ok(path) = OwnedObjectPath::try_from(path.to_owned()) { self.session = Some(path); }
                    }
                }
            }
            cx.waker().wake_by_ref();
        }
    }
    async fn build(&mut self) -> Check<()> {
        let result = before(self.work_end, std::future::poll_fn(|cx| {
            if !self.build_polled && Instant::now() >= self.work_end {
                if self.attempt.refuse_unpolled_build().is_ok() { self.build_pending = false; }
                return Poll::Ready(());
            }
            self.build_polled = true;
            if let Poll::Ready(result) = self.attempt.poll_build(cx) {
                self.build_pending = false;
                self.build_result = Some(self.observe(result, self.work_end));
                Poll::Ready(())
            } else { Poll::Pending }
        })).await;
        if self.timely_wait(&result, self.work_end) && !self.late
            && self.build_result.as_ref().is_some_and(|result| result.timely() && result.value.is_ok()) { Ok(()) }
        else { self.fail_at(Instant::now()); Err("setup-build") }
    }
    async fn call(&mut self, kind: SetupCall, end: Instant, cleanup: bool,
        start: impl FnOnce(&mut OwnedConnectionAttempt) -> zbus::Result<()>) -> Check<()> {
        if self.call.is_some() || !self.raw_reconciled || self.build_pending || self.local.is_some() || Instant::now() >= end
            || !cleanup && (self.first_stop.is_some() || self.owner_changed || self.stream_failed) { return Err("setup-call-admission"); }
        if start(&mut self.attempt).is_err() { self.fail_at(Instant::now()); return Err("setup-call-stage"); }
        self.raw = None; self.raw_observed = None; self.raw_reconciled_at = None;
        self.call = Some(PendingSetupCall { kind, polled: false, end, cleanup });
        let result = before(end, std::future::poll_fn(|cx| {
            let boundary = self.raw.as_ref().and_then(|raw| match raw {
                Ok(message) | Err(zbus::Error::MethodError(_, _, message)) => Some(message.recv_position()), _ => None,
            });
            let reconciled = self.poll_stream(cx, boundary.as_ref());
            if self.call.is_some() { self.poll_call(cx); return Poll::Pending; }
            if boundary.is_none() || reconciled { self.reconcile_raw(); Poll::Ready(()) } else { Poll::Pending }
        })).await;
        if !self.timely_wait(&result, end) || self.stream_failed || self.raw.as_ref().is_none_or(Result::is_err)
            || !cleanup && self.owner_changed {
            self.fail_at(if result.is_err() { end } else { Instant::now() }); Err("setup-call-failed")
        } else { Ok(()) }
    }
    async fn subscribe(&mut self) -> Check<()> {
        let rule = owner_rule()?;
        self.subscribed = true; // Conservative debt even on a pre-poll refusal.
        self.call(SetupCall::Other, self.work_end, false, |attempt| bus_call(attempt, "AddMatch", rule))
            .await.map_err(|_| "setup-add-match-call")?;
        checked::check_empty_bus_reply(&self.body()?).map_err(|_| "setup-add-match")
    }
    async fn authenticate_provider(&mut self, pid: u32, uid: u32) -> Check<()> {
        let event = before(self.work_end, std::future::poll_fn(|cx| {
            self.poll_stream(cx, None);
            if self.owner_changed || self.stream_failed { return Poll::Ready(Err("setup-owner-event")); }
            if self.owner.is_some() { Poll::Ready(Ok(())) } else { Poll::Pending }
        })).await;
        if !self.timely_wait(&event, self.work_end) { return Err("setup-owner-deadline"); }
        event?.value?;
        self.call(SetupCall::Other, self.work_end, false, |attempt| bus_call(attempt, "GetNameOwner", SERVICE))
            .await.map_err(|_| "setup-name-owner-call")?;
        if checked::decode_name_owner(&self.body()?).map_err(|_| "setup-name-owner")? != self.owner()?.as_str() {
            return Err("setup-owner-mismatch");
        }
        for (member, expected) in [("GetConnectionUnixUser", uid), ("GetConnectionUnixProcessID", pid)] {
            let owner = self.owner()?.as_str().to_owned();
            self.call(SetupCall::Other, self.work_end, false, |attempt| bus_call(attempt, member, owner))
                .await.map_err(|_| if member == "GetConnectionUnixUser" { "setup-owner-uid-call" } else { "setup-owner-pid-call" })?;
            if fixture_sdk::decode_bus_identity(&self.body()?).map_err(|_| "setup-provider-identity")? != expected {
                return Err("setup-provider-correspondence");
            }
        }
        Ok(())
    }
    async fn session_collection(&mut self) -> Check<OwnedObjectPath> {
        let owner = self.owner()?;
        self.call(SetupCall::Other, self.work_end, false, |attempt| attempt.start_raw_call(
            owner.as_str().to_owned().try_into()?, SERVICE_OBJECT.try_into()?, SERVICE_INTERFACE.try_into()?,
            "ReadAlias".try_into()?, "session")).await.map_err(|_| "setup-session-alias-call")?;
        let body = self.body()?;
        let collection = OwnedObjectPath::try_from(fixture_sdk::decode_session_alias(&body, &owner)
            .map_err(|_| "setup-session-alias")?.to_owned()).map_err(|_| "setup-session-alias")?;
        drop(body);
        self.call(SetupCall::Other, self.work_end, false, |attempt| attempt.start_raw_call(
            owner.as_str().to_owned().try_into()?, collection.clone(), "org.freedesktop.DBus.Properties".try_into()?,
            "Get".try_into()?, (COLLECTION_INTERFACE, "Locked"))).await.map_err(|_| "setup-collection-locked-call")?;
        if checked::decode_locked(&self.body()?, &owner).map_err(|_| "setup-collection-locked")? { return Err("setup-collection-locked"); }
        Ok(collection)
    }
    async fn seed(&mut self, collection: &OwnedObjectPath, generation: &'static str) -> Check<OwnedObjectPath> {
        if self.session_possible || self.session.is_some() { return Err("setup-session-already-held"); }
        let owner = self.owner()?;
        let exchange = checked::CheckedDhExchange::generate().map_err(|_| "setup-exchange")?;
        self.call(SetupCall::Open, self.work_end, false,
            |attempt| checked::start_owned_open_session(attempt, &owner, exchange.public_key()))
            .await.map_err(|_| "setup-encrypted-open-call")?;
        let body = self.body()?;
        let (peer, _) = checked::decode_open_session(&body, &owner).map_err(|_| "setup-open-session")?;
        let key = exchange.derive(peer).map_err(|_| "setup-provider-key")?;
        drop(body);
        let (iv, ciphertext) = fixture_sdk::encrypt_native_canary(key).map_err(|_| "setup-canary-encryption")?;
        let request = CreateItem { generation, session: self.session.clone().ok_or("setup-open-path")?, iv, ciphertext };
        self.call(SetupCall::Other, self.work_end, false, |attempt| attempt.start_raw_call(
            owner.as_str().to_owned().try_into()?, collection.clone(), COLLECTION_INTERFACE.try_into()?, "CreateItem".try_into()?, request))
            .await.map_err(|_| "setup-create-item-call")?;
        let body = self.body()?;
        let item = OwnedObjectPath::try_from(fixture_sdk::decode_created_item(&body, &owner)
            .map_err(|_| "setup-create-item")?.to_owned()).map_err(|_| "setup-create-item")?;
        drop(body);
        self.close_session(self.work_end).await?;
        Ok(item)
    }
    async fn close_session(&mut self, end: Instant) -> Check<()> {
        let owner = self.owner()?; let session = self.session.clone().ok_or("setup-close-path")?;
        self.call(SetupCall::Close, end, true,
            |attempt| checked::start_owned_close_session(attempt, &owner, &session)).await.map_err(|_| "setup-close-call")?;
        checked::check_empty_owner_reply(&self.body()?, &owner).map_err(|_| "setup-close-reply")?;
        self.closes += 1; self.session = None; self.session_possible = false; self.close_polled = false; Ok(())
    }
    async fn finish(&mut self) -> bool {
        if self.local.is_some() { return self.finality(); }
        self.fail_at(Instant::now());
        let end = self.first_stop.unwrap_or(self.work_end) + CLEANUP;
        if !self.build_pending && self.call.is_none() && !self.raw_reconciled {
            let middle = Instant::now() + end.saturating_duration_since(Instant::now()) / 2;
            let reconciled = before(middle, std::future::poll_fn(|cx| {
                let boundary = self.raw.as_ref().and_then(|raw| match raw {
                    Ok(message) | Err(zbus::Error::MethodError(_, _, message)) => Some(message.recv_position()), _ => None,
                });
                if boundary.is_none() || self.poll_stream(cx, boundary.as_ref()) {
                    self.reconcile_raw(); Poll::Ready(())
                } else { Poll::Pending }
            })).await;
            self.timely_wait(&reconciled, middle);
        }
        if !self.build_pending && self.call.is_none() && self.raw_reconciled && !self.close_polled
            && self.session.is_some() && Instant::now() < end {
            let middle = Instant::now() + end.saturating_duration_since(Instant::now()) / 2;
            let _ = self.close_session(middle).await;
        }
        if self.subscribed && !self.removed && !self.build_pending && self.call.is_none() && self.raw_reconciled && Instant::now() < end {
            if let Ok(rule) = owner_rule() {
                let middle = Instant::now() + end.saturating_duration_since(Instant::now()) / 2;
                if self.call(SetupCall::Remove, middle, true,
                    |attempt| bus_call(attempt, "RemoveMatch", rule)).await.is_ok()
                    && self.body().is_ok_and(|body| checked::check_empty_bus_reply(&body).is_ok()) { self.removed = true; }
            }
        }
        // On a cutoff the ORIGINAL build/raw call still resides in attempt.
        // Poll its local shutdown independently to interrupt IO, then consume
        // those originals and all raw holdings before releasing the stream.
        let settled = before(end, std::future::poll_fn(|cx| {
            if self.build_pending {
                if !self.build_polled {
                    if self.attempt.refuse_unpolled_build().is_ok() { self.build_pending = false; }
                } else if let Poll::Ready(result) = self.attempt.poll_build(cx) {
                    self.build_pending = false;
                    self.build_result = Some(self.observe(result, self.work_end));
                }
            }
            if self.call.is_some() { self.poll_call(cx); }
            if !self.build_pending && self.call.is_none() && !self.stream_released {
                // Teardown is explicit failed-result reconciliation, not a
                // successful remote semantic receipt inferred from shutdown.
                self.raw = None;
                if self.attempt.release_stream().is_ok() { self.stream_released = true; }
            }
            if let Poll::Ready(local) = self.attempt.poll_local_shutdown(cx) {
                self.local = Some(self.observe(local, end)); Poll::Ready(())
            } else { Poll::Pending }
        })).await;
        self.timely_wait(&settled, end);
        self.finality()
    }
}

fn owner_rule() -> Check<MatchRule<'static>> {
    Ok(MatchRule::builder().msg_type(MessageType::Signal).sender(BUS).map_err(|_| "setup-rule")?
        .interface(BUS).map_err(|_| "setup-rule")?.path(BUS_OBJECT).map_err(|_| "setup-rule")?
        .member("NameOwnerChanged").map_err(|_| "setup-rule")?.arg(0, SERVICE).map_err(|_| "setup-rule")?.build())
}
fn bus_call<B: Serialize + zbus::zvariant::DynamicType + Send + Sync + 'static>(
    attempt: &mut OwnedConnectionAttempt, member: &'static str, body: B) -> zbus::Result<()> {
    attempt.start_raw_call(BUS.try_into()?, BUS_OBJECT.try_into()?, BUS.try_into()?, member.try_into()?, body)
}

#[derive(Clone, Copy)]
enum Case { Existing, Missing, Duplicate, Stop, Deadline, OwnerLoss, FreshAbsent }
impl Case {
    fn name(self) -> &'static str { match self { Self::Existing => "existing", Self::Missing => "missing", Self::Duplicate => "duplicate",
        Self::Stop => "stop-after-secret", Self::Deadline => "deadline-after-secret", Self::OwnerLoss => "owner-loss", Self::FreshAbsent => "fresh-session-absent" } }
    fn generation(self) -> &'static str { match self { Self::Missing => MISSING, Self::Duplicate => DUPLICATE, _ => SINGLE } }
    fn gate(self) -> Option<Step> { match self { Self::Stop | Self::Deadline => Some(Step::CloseSession), Self::OwnerLoss => Some(Step::GetSecret), _ => None } }
}
struct LookupRun {
    document: DocumentBinding, owner: Arc<OriginalWork>, work_end: Instant,
    gate: Option<Arc<BoundaryGate>>, result: Arc<Mutex<Option<LookupOutcome>>>,
    expected_owner: String, go: Option<oneshot::Sender<()>>, settled_at: Mutex<Option<Instant>>,
}
struct LookupOutcome {
    result: Result<(), Problem>, snapshot: NativeFixtureSnapshot,
    work_end: Option<Instant>, cleanup_end: Option<Instant>, returned_at: Instant,
}
impl LookupRun {
    fn install(case: Case, provider: &UniqueName<'_>, collection: &OwnedObjectPath) -> Check<Self> {
        let input = LookupInput::new(Path::new(BUS_SOCKET), collection.as_str(), VAULT, case.generation()).map_err(|_| "lookup-input")?;
        let document = DocumentBinding::new(Arc::new(DesktopBridge::new(PathBuf::from(ROOT).join("no-core-runtime"))));
        let mut state = document.lock();
        // Explicitly HEADLESS test document events, not fabricated native
        // window/hook evidence or installed-profile qualification.
        state.lifetime.navigation(true); state.lifetime.started(true);
        state.lifetime.crash_hook_installed(); state.lifetime.finished(true);
        let owner = OriginalWork::new(1, false, Arc::downgrade(&document.inner));
        let work_end = owner.endpoint().ok_or("lookup-original-clock")?;
        let mut slot = Slot::new(owner.clone(), Operation::Prepare, None, None, None);
        slot.phase = Phase::Assessing; state.slot = Some(slot);
        let gate = case.gate().map(BoundaryGate::new);
        *owner.gnome_transport_gate.lock().map_err(|_| "lookup-gate-lock")? = gate.clone();
        let result = Arc::new(Mutex::new(None));
        let (go, enter) = oneshot::channel();
        let worker = owner.clone(); let original_document = document.clone(); let output = result.clone();
        let expected_owner = provider.as_str().to_owned(); let original_provider = expected_owner.clone();
        let end = CoordinatorEnd(owner.clone()); // Exists BEFORE spawn/GO.
        let mut book = owner.coordinator.lock().map_err(|_| "lookup-coordinator-lock")?;
        book.receipt = JoinReceipt::Pending;
        book.handle = Some(tokio::spawn(async move {
            let _end = end;
            if enter.await.is_err() { worker.stop(); return; }
            let actual = original_document.drive_keyring_lookup(&worker, input).await;
            let snapshot = worker.keyring.lock().ok().map(|book| book.native_fixture_snapshot(&original_provider));
            let work_end = worker.endpoint();
            let cleanup_end = original_document.lock().slot.as_ref().filter(|slot| Arc::ptr_eq(&slot.owner, &worker))
                .and_then(|slot| slot.cleanup_end);
            if let (Some(snapshot), Ok(mut output)) = (snapshot, output.lock()) {
                *output = Some(LookupOutcome { result: actual, snapshot, work_end, cleanup_end, returned_at: Instant::now() });
            };
        }));
        // Same original CoordinatorBook, real Pending HANDLE and exact slot
        // already installed. Both custody locks are released before GO.
        drop(book); drop(state);
        Ok(Self { document, owner, work_end, gate, result, expected_owner, go: Some(go), settled_at: Mutex::new(None) })
    }
    fn start(&mut self) -> Check<()> {
        // The enclosing Fixture now retains this complete LookupRun even if
        // GO publication fails; its original coordinator must still be joined.
        self.go.take().ok_or("lookup-go-absent")?.send(()).map_err(|_| "lookup-go")
    }
    async fn boundary(&self) -> Check<NativeFixtureSnapshot> {
        let gate = self.gate.as_ref().ok_or("lookup-no-boundary")?;
        before(self.work_end, async {
            loop {
                if gate.reached.load(Ordering::SeqCst) { break; }
                if self.owner.ended.load(Ordering::SeqCst) { return Err("lookup-ended-before-boundary"); }
                tokio::select! { _ = gate.changed.notified() => {}, _ = self.owner.wake.notified() => {} }
            }
            self.owner.keyring.lock().map(|book| book.native_fixture_snapshot(&self.expected_owner)).map_err(|_| "lookup-boundary-lock")
        }).await.and_then(Observed::timely_value)?
    }
    fn stop(&self) -> Check<Instant> {
        let mut state = self.document.lock();
        let slot = state.slot.as_mut().filter(|slot| Arc::ptr_eq(&slot.owner, &self.owner)).ok_or("lookup-stop-slot")?;
        let at = Instant::now(); slot.stop(Reason::UserCancelled, at);
        let first = slot.cleanup_end.ok_or("lookup-stop-clock")?;
        // Repeated cancellation must preserve BOTH original first clocks.
        slot.stop(Reason::UserCancelled, Instant::now());
        if slot.cleanup_end != Some(first) || self.owner.endpoint() != Some(self.work_end)
            || first != at.min(self.work_end) + CLEANUP { return Err("lookup-renewed-clock"); }
        Ok(first)
    }
    async fn settle(&self, end: Instant) -> bool {
        self.document.reconcile();
        if self.record_settlement() {
            return self.settled_at.lock().ok().is_some_and(|at| at.is_some_and(|at| at < end));
        }
        before(end, async {
            loop {
                self.document.reconcile();
                if self.record_settlement() { return true; }
                tokio::select! { _ = self.owner.wake.notified() => {},
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {} }
            }
        }).await.and_then(Observed::timely_value).unwrap_or(false)
    }
    fn record_settlement(&self) -> bool {
        if !self.owner.resources_settled() { return false; }
        let Ok(mut at) = self.settled_at.lock() else { return false; };
        at.get_or_insert_with(Instant::now); true
    }
    fn verify(&self, case: Case, stop_end: Option<Instant>) -> Check<()> {
        let output = self.result.lock().map_err(|_| "lookup-result-lock")?;
        let outcome = output.as_ref().ok_or("lookup-result-absent")?;
        let result = &outcome.result; let snapshot = &outcome.snapshot;
        println!("MRK_GNOME_SESSION observation={} result={:?} owner_matches={} first_polls={:?} local_reader={:?} local_clean={} candidate_present={} settled_canary={} session_unknown={}",
            case.name(), result, snapshot.owner_matches, snapshot.first_polls, snapshot.local.map(|local| local.reader),
            snapshot.local.is_some_and(LocalSettlement::clean), snapshot.candidate_present, snapshot.settled_canary, snapshot.session_unknown);
        let joined = self.owner.coordinator.lock().map_err(|_| "lookup-join-lock")?;
        let normally_joined = joined.receipt == JoinReceipt::Returned && joined.handle.is_none();
        drop(joined);
        if !normally_joined || !self.owner.resources_settled()
            || !snapshot.resources_settled || !snapshot.charged || !snapshot.owner_matches
            || !snapshot.local.is_some_and(LocalSettlement::clean) { return Err("lookup-original-settlement"); }
        let state = self.document.lock(); let slot = state.slot.as_ref().ok_or("lookup-final-slot")?;
        if !state.records.is_empty() || !state.assignments.is_empty() || slot.staged.is_some() || slot.preview.is_some()
            || slot.candidate.is_some() || snapshot.problem != result.as_ref().err().copied()
            || snapshot.problem_at != self.owner.keyring.lock().map_err(|_| "lookup-final-book")?.problem_at() {
            return Err("lookup-late-authority");
        }
        let final_end = outcome.cleanup_end.unwrap_or(self.work_end);
        if outcome.work_end != Some(self.work_end) || outcome.cleanup_end != slot.cleanup_end
            || result.is_err() && slot.cleanup_end.is_none() || outcome.returned_at >= final_end
            || !self.settled_at.lock().map_err(|_| "lookup-settlement-clock")?.is_some_and(|at| at < final_end)
            || !matches!(case, Case::OwnerLoss) && state.unknown {
            return Err("lookup-final-clock");
        }
        if matches!(case, Case::Missing | Case::Duplicate | Case::OwnerLoss | Case::FreshAbsent)
            && slot.cleanup_end != snapshot.problem_at.map(|at| first_cleanup_end(at, Some(self.work_end), None)) {
            return Err("lookup-first-failure-clock");
        }
        let absent = matches!(case, Case::Missing | Case::Duplicate | Case::FreshAbsent);
        let expected = if absent { [1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1] }
            else if matches!(case, Case::OwnerLoss) { [1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1] }
            else { [1; 11] };
        if snapshot.first_polls != expected { return Err("lookup-first-poll-counts"); }
        let valid = match case {
            Case::Existing => result.is_ok() && snapshot.settled_canary && snapshot.candidate_present && snapshot.session_closed,
            Case::Missing | Case::FreshAbsent => *result == Err(Problem::MissingKey),
            Case::Duplicate => *result == Err(Problem::InvalidReply),
            Case::Stop => *result == Err(Problem::Interrupted) && slot.cleanup_end == stop_end
                && slot.reason == Reason::UserCancelled && snapshot.session_closed,
            Case::Deadline => *result == Err(Problem::Interrupted) && slot.cleanup_end == Some(self.work_end + CLEANUP)
                && slot.reason == Reason::Deadline && snapshot.session_closed && Instant::now() >= self.work_end,
            Case::OwnerLoss => *result == Err(Problem::OwnerChanged) && snapshot.session_unknown,
        };
        if !valid || !snapshot.subscription_removed || !matches!(case, Case::Existing) && (snapshot.candidate_present || snapshot.settled_canary) {
            return Err("lookup-unexpected-outcome");
        }
        // No raw keys, item paths, private bus names or daemon output.
        println!("MRK_GNOME_SESSION case={} verified=true original_join=true storage_disposed=true first_polls={:?} remote_session_unknown={}",
            case.name(), snapshot.first_polls, snapshot.session_unknown);
        Ok(())
    }
}

struct OwnedChild { child: Child, stop: Option<(bool, Instant)> }
#[derive(Clone, Copy)]
struct ChildExit { status: ExitStatus, stop_ok: bool, observed: Observed<()> }
impl ChildExit {
    fn from_wait(waited: Observed<std::io::Result<ExitStatus>>, stop_ok: bool) -> Check<Self> {
        let Observed { value, end, at } = waited;
        value.map(|status| Self { status, stop_ok, observed: Observed { value: (), end, at } })
            .map_err(|_| "fixture-child-wait-unknown")
    }
    fn accepted(&self) -> bool { self.stop_ok && self.observed.timely() }
}
struct Fixture {
    root: File, uid: u32, bus: Option<OwnedChild>, bus_stdout: Option<tokio::process::ChildStdout>,
    provider: Option<OwnedChild>, setup: Option<Bootstrap>, lookup: Option<LookupRun>,
    child_exits: Vec<ChildExit>, cleanup_failed: bool,
}
fn private_file(path: &str) -> Check<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|_| "fixture-exclusive-file")
}
fn child_command(program: &str, error_path: &str) -> Check<Command> {
    let mut command = Command::new(program);
    command.env_clear().current_dir(ROOT).stdin(Stdio::null()).stdout(Stdio::null())
        .stderr(Stdio::from(private_file(error_path)?))
        .env("HOME", "/mrk-gnome-fixture/home")
        .env("XDG_RUNTIME_DIR", "/mrk-gnome-fixture/run")
        .env("XDG_DATA_HOME", "/mrk-gnome-fixture/data")
        .env("XDG_CONFIG_HOME", "/mrk-gnome-fixture/config")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/mrk-gnome-fixture/run/bus")
        .env("LANG", "C").env("LC_ALL", "C");
    Ok(command)
}
impl Fixture {
    fn new() -> Check<Self> {
        let uid = rustix::process::geteuid().as_raw(); let gid = rustix::process::getegid().as_raw();
        if uid == 0 || gid == 0 || rustix::process::getuid().as_raw() != uid || rustix::process::getgid().as_raw() != gid {
            return Err("fixture-nonroot-account-required");
        }
        let root = File::open(ROOT).map_err(|_| "fixture-root-absent")?;
        for path in [ROOT, "/mrk-gnome-fixture/home", "/mrk-gnome-fixture/run", "/mrk-gnome-fixture/data",
            "/mrk-gnome-fixture/config", "/mrk-gnome-fixture/control-1", "/mrk-gnome-fixture/control-2"] {
            let metadata = std::fs::symlink_metadata(path).map_err(|_| "fixture-private-layout")?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.gid() != gid || metadata.mode() & 0o7777 != 0o700 {
                return Err("fixture-private-layout");
            }
        }
        let held = root.metadata().map_err(|_| "fixture-root-metadata")?;
        let named = std::fs::symlink_metadata(ROOT).map_err(|_| "fixture-root-metadata")?;
        if held.dev() != named.dev() || held.ino() != named.ino() { return Err("fixture-root-changed"); }
        Ok(Self { root, uid, bus: None, bus_stdout: None, provider: None, setup: None, lookup: None,
            child_exits: Vec::with_capacity(3), cleanup_failed: false })
    }
    async fn start_bus(&mut self) -> Check<()> {
        let config = format!("<busconfig><type>session</type><listen>unix:path={BUS_SOCKET}</listen><auth>EXTERNAL</auth>\
            <policy context=\"default\"><deny user=\"*\"/><allow user=\"{}\"/>\
            <allow own=\"org.freedesktop.secrets\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy>\
            <limit name=\"max_message_size\">65536</limit><limit name=\"max_received_unix_fds\">0</limit>\
            <limit name=\"max_completed_connections\">8</limit><limit name=\"max_connections_per_user\">8</limit></busconfig>\n", self.uid);
        let mut file = private_file(BUS_CONFIG)?;
        file.write_all(config.as_bytes()).map_err(|_| "fixture-bus-config")?;
        file.sync_all().map_err(|_| "fixture-bus-config")?; drop(file);
        let mut command = child_command(BUS_BIN, "/mrk-gnome-fixture/bus.stderr")?;
        command.args(["--nofork", "--config-file=/mrk-gnome-fixture/bus.conf", "--print-address=1"]).stdout(Stdio::piped());
        self.bus = Some(OwnedChild { child: command.spawn().map_err(|_| "fixture-bus-spawn")?, stop: None });
        drop(command);
        self.bus_stdout = self.bus.as_mut().and_then(|owner| owner.child.stdout.take());
        let reader = self.bus_stdout.as_mut().ok_or("fixture-bus-readiness-custody")?;
        let line = before(Instant::now() + WORK, async {
            let mut line = Vec::with_capacity(256);
            for _ in 0..256 {
                let byte = reader.read_u8().await.map_err(|_| "fixture-bus-readiness")?;
                if byte == b'\n' { return Ok(line); }
                line.push(byte);
            }
            Err("fixture-bus-readiness-bound")
        }).await.and_then(Observed::timely_value)??;
        self.bus_stdout = None; // Sole bounded reader/FD closed, no background task.
        let prefix = format!("unix:path={BUS_SOCKET},guid=");
        if !line.starts_with(prefix.as_bytes()) || line.len() != prefix.len() + 32
            || !line[prefix.len()..].iter().all(u8::is_ascii_hexdigit) { return Err("fixture-bus-address"); }
        Ok(())
    }
    async fn bootstrap(&mut self, fresh: bool) -> Check<(UniqueName<'static>, OwnedObjectPath)> {
        if self.setup.is_some() { return Err("fixture-old-setup-retained"); }
        self.setup = Some(Bootstrap::new()?);
        let setup = self.setup.as_mut().ok_or("fixture-setup-slot")?;
        setup.build().await?; setup.subscribe().await?;
        let (control, error) = if fresh { ("--control-directory=/mrk-gnome-fixture/control-2", "/mrk-gnome-fixture/provider-2.stderr") }
            else { ("--control-directory=/mrk-gnome-fixture/control-1", "/mrk-gnome-fixture/provider-1.stderr") };
        let mut command = child_command(PROVIDER_BIN, error)?;
        command.args(["--foreground", "--components=secrets", control]);
        if self.provider.is_some() { return Err("fixture-old-provider-retained"); }
        self.provider = Some(OwnedChild { child: command.spawn().map_err(|_| "fixture-provider-spawn")?, stop: None });
        drop(command);
        let pid = self.provider.as_ref().and_then(|owner| owner.child.id()).ok_or("fixture-provider-original-pid")?;
        setup.authenticate_provider(pid, self.uid).await?;
        let owner = setup.owner()?; let collection = setup.session_collection().await?;
        if !fresh {
            let single = setup.seed(&collection, SINGLE).await?;
            let duplicate_a = setup.seed(&collection, DUPLICATE).await?;
            let duplicate_b = setup.seed(&collection, DUPLICATE).await?;
            if duplicate_a == duplicate_b || single == duplicate_a || single == duplicate_b { return Err("fixture-distinct-items"); }
        }
        if !setup.finish().await { return Err("fixture-setup-finality"); }
        println!("MRK_GNOME_SESSION bootstrap={} verified=true encrypted_opens={} explicit_closes={} local_join=true provider_child_matches=true",
            if fresh { "fresh" } else { "seed" }, setup.opens, setup.closes);
        self.setup = None; // Only after the actual consumed local settlement.
        Ok((owner, collection))
    }
    async fn case(&mut self, case: Case, owner: &UniqueName<'_>, collection: &OwnedObjectPath) -> Check<()> {
        if self.lookup.is_some() { return Err("fixture-old-lookup-retained"); }
        self.lookup = Some(LookupRun::install(case, owner, collection)?);
        self.lookup.as_mut().ok_or("fixture-lookup-slot")?.start()?;
        let run = self.lookup.as_ref().ok_or("fixture-lookup-slot")?;
        let mut stop_end = None;
        if case.gate().is_some() {
            let boundary = run.boundary().await?;
            if !boundary.owner_matches || !boundary.charged || boundary.resources_settled || boundary.problem.is_some()
                || boundary.settled_canary || boundary.first_polls[8..] != [0, 0, 0]
                || run.owner.endpoint() != Some(run.work_end) { return Err("fixture-boundary-state"); }
            if matches!(case, Case::OwnerLoss) {
                if boundary.candidate_present || boundary.first_polls[6..8] != [1, 0] { return Err("fixture-open-boundary"); }
                let exit = stop_child(&mut self.provider).await?; self.child_exits.push(exit);
                if !exit.stop_ok { return Err("fixture-provider-stop-error"); }
                if !exit.accepted() { return Err("fixture-provider-stop-late"); }
                // Do not release GetSecret: the SAME driver keeps processing
                // its real owner stream until loss selects ordinary cleanup.
            } else {
                if !boundary.candidate_present || boundary.first_polls[6..8] != [1, 1] { return Err("fixture-secret-boundary"); }
                if matches!(case, Case::Stop) { stop_end = Some(run.stop()?); }
                // Deadline deliberately waits the actual original ten seconds.
            }
        }
        if !run.settle(run.work_end + CLEANUP).await { return Err("fixture-lookup-unsettled"); }
        run.verify(case, stop_end)?;
        self.lookup = None;
        Ok(())
    }
    async fn run(&mut self) -> Check<()> {
        self.start_bus().await?;
        let (owner, collection) = self.bootstrap(false).await?;
        for case in [Case::Existing, Case::Missing, Case::Duplicate, Case::Stop, Case::Deadline, Case::OwnerLoss] {
            self.case(case, &owner, &collection).await?;
        }
        // The loss case consumed the OLD retained Child and every old lookup
        // original before a replacement is launched. Fresh bootstrap separately
        // authenticates the new owner/Child; no old provider witness is reused.
        let (fresh_owner, fresh_collection) = self.bootstrap(true).await?;
        if fresh_owner == owner { return Err("fixture-reused-owner"); }
        self.case(Case::FreshAbsent, &fresh_owner, &fresh_collection).await
    }
    async fn finish(&mut self) -> bool {
        let mut clean = true;
        if let Some(run) = self.lookup.as_ref() {
            if !run.owner.resources_settled() { let _ = run.stop(); }
            // Never renew an old product endpoint to get a clean receipt.
            if !run.settle(run.work_end + CLEANUP).await { clean = false; }
            if run.owner.resources_settled() { self.lookup = None; }
        }
        if let Some(setup) = self.setup.as_mut() {
            let remote_and_local = setup.finish().await;
            println!("MRK_GNOME_SESSION bootstrap_final local_settled={} local_clean={} local_timely={} deadline_failed={} remote_complete={} opens={} closes={} session_unknown={} subscription_removed={}",
                setup.local.is_some(), setup.local.is_some_and(|local| local.value.clean()),
                setup.local.is_some_and(|local| local.timely()), setup.late, remote_and_local,
                setup.opens, setup.closes, setup.session_possible, setup.removed);
            // Failed/uncertain REMOTE setup already refused run(). It cannot
            // become success, but it is distinct from missing LOCAL originals.
            if !setup.local_finality() { clean = false; }
            if setup.local.is_some() { self.setup = None; }
        }
        self.bus_stdout = None;
        for child in [&mut self.provider, &mut self.bus] {
            if child.is_some() {
                match stop_child(child).await { Ok(exit) => { self.child_exits.push(exit); clean &= exit.accepted(); }, Err(_) => clean = false }
            }
        }
        // Receipt is about original statuses, not a promised graceful daemon
        // flush. No fixture path/log is removed while any original is unknown.
        for (ordinal, exit) in self.child_exits.iter().enumerate() {
            println!("MRK_GNOME_SESSION child={} code={:?} signal={:?} stop_ok={} original_wait=true timely={}",
                ordinal, exit.status.code(), exit.status.signal(), exit.stop_ok, exit.observed.timely());
        }
        let held = self.root.metadata().ok(); let named = std::fs::symlink_metadata(ROOT).ok();
        clean &= self.child_exits.iter().all(ChildExit::accepted)
            && self.lookup.is_none() && self.setup.is_none() && self.provider.is_none() && self.bus.is_none()
            && held.zip(named).is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino());
        self.cleanup_failed |= !clean;
        !self.cleanup_failed
    }
}

async fn stop_child(slot: &mut Option<OwnedChild>) -> Check<ChildExit> {
    let owner = slot.as_mut().ok_or("fixture-child-absent")?;
    // Ordinary retained Child API, never a PID/name search or a foreign wait.
    // No consuming status poll preceded this one stop request.
    if owner.stop.is_none() {
        let end = Instant::now() + CLEANUP;
        owner.stop = Some((owner.child.start_kill().is_ok(), end));
    }
    let (stop_ok, end) = owner.stop.ok_or("fixture-child-stop-clock")?;
    let waited = before(end, owner.child.wait()).await.map_err(|_| "fixture-child-wait-unknown")?;
    let exit = ChildExit::from_wait(waited, stop_ok)?;
    // A late known exit still consumes this exact original. Its status and
    // unchanged first-end classification travel together to EVERY consumer.
    *slot = None;
    Ok(exit)
}

#[test]
fn gnome_transport_fixed_setup_contract_data() {
    fixture_sdk::assert_native_canary_helpers(); fixture_sdk::assert_setup_decoders();
    let request = CreateItem { generation: SINGLE, session: OwnedObjectPath::try_from("/session").unwrap(),
        iv: [0x27; 16], ciphertext: [0; 48] };
    let message = Message::method_call("/collection", "CreateItem").unwrap().build(&request).unwrap();
    assert_eq!(message.body().signature().to_string_no_parens(), "a{sv}(oayays)b");
    assert_eq!(WORK, Duration::from_secs(10)); assert_eq!(CLEANUP, Duration::from_secs(2));
    assert_ne!(SINGLE, DUPLICATE); assert_ne!(SINGLE, MISSING); assert_ne!(DUPLICATE, MISSING);
    assert!(!NATIVE_QUALIFIED);

    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    runtime.block_on(async {
        let end = Instant::now() - Duration::from_secs(1);
        assert!(!Observed { value: (), end, at: end }.timely());
        let waited = before(end, std::future::ready(Ok(ExitStatus::from_raw(7 << 8)))).await.unwrap();
        let exit = ChildExit::from_wait(waited, true).unwrap();
        assert_eq!(exit.status.code(), Some(7));
        assert_eq!(exit.observed.end, end); assert!(exit.observed.at >= end);
        for _ in 0..2 {
            assert!(!exit.accepted()); assert_eq!(exit.status.code(), Some(7));
            assert_eq!(exit.observed.end, end);
        }

        // No build/RPC is first-polled: the real SDK consumes its unpolled
        // startup and returns genuine NotStarted local settlement without IO.
        // Even that already-ready original must stay late on repeated finish.
        let mut setup = Bootstrap::new().unwrap();
        setup.work_end = end - CLEANUP;
        assert!(!setup.finish().await);
        let local = setup.local.expect("known late original settlement is retained");
        assert!(local.value.clean());
        assert_eq!(local.value.reader, zbus::connection::ReaderOutcome::NotStarted);
        assert_eq!(local.end, end); assert!(local.at >= end); assert!(!local.timely());
        assert!(!setup.build_polled); assert!(!setup.build_pending); assert!(setup.build_result.is_none());
        assert!(setup.late); assert_eq!(setup.first_stop, Some(end - CLEANUP));
        for _ in 0..2 {
            assert!(!setup.finish().await); assert!(!setup.local_finality());
            let retained = setup.local.unwrap();
            assert_eq!(retained.value, local.value); assert_eq!(retained.at, local.at); assert_eq!(retained.end, end);
            assert!(setup.late); assert_eq!(setup.first_stop, Some(end - CLEANUP));
        }
    });
}

#[test]
#[ignore = "requires freshly admitted pinned private nonroot GNOME namespace; session transport only"]
fn real_gnome_session_transport_originals() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("fixture runtime creation");
    let mut fixture = match Fixture::new() {
        Ok(fixture) => fixture, Err(reason) => panic!("GNOME fixture refused before creation: {reason}"),
    };
    // Keep the entire original fixture OUTSIDE the unwind boundary. A panic
    // does not drop the bus/provider/SDK/coordinator before independent cleanup.
    // Opaque panic payloads are never formatted into native diagnostics.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(fixture.run())))
        .unwrap_or(Err("fixture-body-panicked"));
    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(fixture.finish())))
        .unwrap_or(false);
    if !cleanup {
        // Retain at most this one bounded failed fixture until original outer
        // domain disposal. Dropping a Tokio handle must not masquerade as join.
        std::mem::forget(fixture);
        std::mem::forget(runtime);
    }
    assert!(cleanup, "GNOME fixture cleanup untimely or unconfirmed; retained state requires enclosing-domain disposal");
    assert!(result.is_ok(), "GNOME session transport refused: {}", result.err().unwrap_or("unknown"));
    println!("MRK_GNOME_SESSION batch=7 verified=true persistent=false installed_provider=false gui=false");
}
