//! Fixed keyring transport/profile phase, owned by asset_session::OriginalWork.
//!
//! No renderer/session command calls this phase. Endpoint/provider qualification,
//! and native qualification remain OFF. Only this private entry selects the
//! closed bounded wire profile; the legacy SDK fixtures are separate. Local
//! finality requires the maintained SDK's consumed original task/resource result;
//! a lookup, RemoveMatch or coordinator return alone is never a task join.

use std::{os::unix::ffi::OsStrExt, path::{Component, Path, PathBuf}, pin::Pin,
    sync::Arc, task::{Context, Poll}, time::Instant};
#[cfg(test)]
use std::future::Future;
use ordered_stream::{OrderedStream, PollResult};
use secret_service::checked_lookup;
use provider_files::Originals as ProviderOriginals;
use zbus::{connection::{LocalSettlement, OwnedConnectionAttempt},
    message::{Sequence, Type}, names::UniqueName, zvariant::OwnedObjectPath,
    MatchRule, Message};

const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const SERVICE: &str = "org.freedesktop.secrets";
const MANAGER: &str = "org.freedesktop.systemd1";
const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    InvalidInput, Unavailable, InvalidReply, IdentityMismatch, OwnerChanged,
    StreamFailed, Interrupted, CleanupUnknown, Capacity, MissingKey, Locked, Crypto,
    UnsupportedProvider, Denied,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    AddMatch, GetNameOwner, SearchItems, Attributes, Locked, OpenSession, GetSecret, CloseSession, RemoveMatch,
    AddManagerMatch, GetManagerOwner, ProviderUser, ProviderPid, GetUnit, UnitProperty(checked_lookup::UnitProperty),
    LoginAlias, SessionAlias, CollectionLocked, AddPromptMatch, Unlock, Prompt, Dismiss, CreateItem,
    RemovePromptMatch, RemoveManagerMatch,
}
impl Step { pub(crate) fn cleanup(self) -> bool {
    matches!(self, Self::CloseSession | Self::RemoveMatch | Self::Dismiss | Self::RemovePromptMatch | Self::RemoveManagerMatch)
} }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderStep { Acquire, Bind, Recheck, Release }
pub(crate) enum Next {
    Admit(Step), FirstPoll, AdmitShutdown, FirstPollShutdown, Settled,
    ProviderAcquire, ProviderBind, ProviderRecheck, ProviderRelease,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Unstarted, Connecting, Admit(Step), Calling(Step), Native(ProviderStep), AwaitPrompt, Holding }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registration { Unsent, Possible, Registered, Removed, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteSession { Unopened, Possible, Known, Closing, Closed, Unknown }

struct Query {
    collection: OwnedObjectPath, vault_id: Box<str>, generation_id: Box<str>,
}

enum Purpose { Legacy, Unlock(crate::vault_format::Identity), Initialize(crate::vault_format::Identity, crate::vault_crypto::InitializationKey) }

/// Private operation-local profile conjunction, never a caller tuple/Boolean.
/// It is minted only after original native binding plus exact owner/UID/PID,
/// unit policy and login-versus-session reconciliation. This is profile/change
/// detection under the trusted OS/current-user-session boundary, not hostile
/// same-UID protection or cryptographic/atomic live-executable attestation.
struct AdmittedProvider;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CredentialRound { Initial, Bound, Final }
impl CredentialRound {
    fn bit(self) -> u8 { match self { Self::Initial => 1, Self::Bound => 2, Self::Final => 4 } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Creation { Unsent, Possible, Known, Unknown }
#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeProgress { Ready(ProviderStep), Entered(ProviderStep), Returned(ProviderStep, Result<(), Problem>), Joined(ProviderStep) }

enum CompletionFact { Dismissed, Unlocked, Created(Arc<OwnedObjectPath>), Invalid }
struct PromptOriginal {
    path: Arc<OwnedObjectPath>, role: checked_lookup::PromptRole,
    invoked: bool, method_returned: bool, dismiss_entered: bool, dismiss_returned: bool,
    completion: Option<CompletionFact>, position: Option<Sequence>, reconciled: bool, unknown: bool,
}
impl PromptOriginal {
    fn complete(&self) -> bool { self.completion.is_some() && self.reconciled && !self.unknown }
}

struct Profile {
    identity: crate::vault_format::Identity, initialize: bool,
    proposal: Option<crate::vault_crypto::InitializationKey>, encrypted: Option<([u8; 16], [u8; 48])>,
    uid: u32, endpoint: Option<PathBuf>, dispatch_end: Instant, control_argument: Box<str>,
    native: ProviderOriginals, native_progress: NativeProgress, sdk_constructed: bool, native_acquired: bool, native_bound: bool,
    native_rechecked: bool, native_released: bool,
    manager: Option<Arc<UniqueName<'static>>>, manager_rule: Arc<MatchRule<'static>>, manager_registration: Registration,
    unit: Option<Arc<OwnedObjectPath>>, pid: Option<u32>, round: CredentialRound,
    user_rounds: u8, process_rounds: u8, policy: u16, prompt_end: Option<Instant>,
    admitted: Option<AdmittedProvider>, login_checked: bool, session_checked: bool,
    prompt_rule: Option<Arc<MatchRule<'static>>>, prompt_registration: Registration, after_prompt_match: Option<Step>,
    prompts: [Option<PromptOriginal>; 2], current_prompt: Option<usize>, unlock_target: Option<Arc<OwnedObjectPath>>,
    unlock_attempted: bool, target_locked: bool, absence_proved: bool,
    creation: Creation, created_item: Option<Arc<OwnedObjectPath>>,
}
impl Profile {
    fn new(endpoint: PathBuf, purpose: Purpose, dispatch_end: Instant) -> Result<Self, Problem> {
        Self::for_uid(endpoint, purpose, dispatch_end, rustix::process::geteuid().as_raw())
    }
    fn for_uid(endpoint: PathBuf, purpose: Purpose, dispatch_end: Instant, uid: u32) -> Result<Self, Problem> {
        let (identity, proposal) = match purpose {
            Purpose::Unlock(identity) => (identity, None),
            Purpose::Initialize(identity, proposal) => (identity, Some(proposal)),
            Purpose::Legacy => return Err(Problem::InvalidInput),
        };
        if uid == 0 || endpoint != PathBuf::from(format!("/run/user/{uid}/bus")) { return Err(Problem::UnsupportedProvider); }
        let manager_rule = MatchRule::builder().msg_type(Type::Signal).sender(BUS).map_err(|_| Problem::InvalidInput)?
            .interface(BUS).map_err(|_| Problem::InvalidInput)?.path(BUS_PATH).map_err(|_| Problem::InvalidInput)?
            .member("NameOwnerChanged").map_err(|_| Problem::InvalidInput)?.arg(0, MANAGER).map_err(|_| Problem::InvalidInput)?.build();
        Ok(Self { identity, initialize: proposal.is_some(), proposal, encrypted: None, uid,
            endpoint: Some(endpoint), dispatch_end, control_argument: format!("--control-directory=/run/user/{uid}/keyring").into(),
            native: ProviderOriginals::new(), native_progress: NativeProgress::Ready(ProviderStep::Acquire), sdk_constructed: false,
            native_acquired: false, native_bound: false, native_rechecked: false, native_released: false,
            manager: None, manager_rule: Arc::new(manager_rule), manager_registration: Registration::Unsent,
            unit: None, pid: None, round: CredentialRound::Initial, user_rounds: 0, process_rounds: 0, policy: 0, prompt_end: None, admitted: None, login_checked: false, session_checked: false,
            prompt_rule: None, prompt_registration: Registration::Unsent, after_prompt_match: None,
            prompts: std::array::from_fn(|_| None), current_prompt: None, unlock_target: None,
            unlock_attempted: false, target_locked: false, absence_proved: false, creation: Creation::Unsent, created_item: None })
    }
    fn all_prompts_settled(&self) -> bool { self.prompts.iter().flatten().all(PromptOriginal::complete) }
    fn remote_unknown(&self) -> bool {
        self.manager_registration == Registration::Unknown || self.prompt_registration == Registration::Unknown
            || self.prompts.iter().flatten().any(|prompt| prompt.unknown || !prompt.complete())
            || matches!(self.creation, Creation::Possible | Creation::Unknown)
    }
    fn profile_conjunction(&self) -> bool {
        self.native_acquired && self.native_bound && self.native_progress == NativeProgress::Joined(ProviderStep::Bind)
            && self.native.acquired_and_bound() && self.sdk_constructed && self.pid.is_some_and(|pid| pid != 0)
            && self.user_rounds == 3 && self.process_rounds == 3 && self.round == CredentialRound::Bound
            && self.manager.is_some() && self.manager_registration == Registration::Registered
            && self.unit.is_some() && self.policy == (1 << 10) - 1 && self.login_checked && self.session_checked
    }
    fn current(&self) -> Result<&PromptOriginal, Problem> {
        self.current_prompt.and_then(|index| self.prompts.get(index)).and_then(Option::as_ref)
            .ok_or(Problem::CleanupUnknown)
    }
    fn current_mut(&mut self) -> Result<&mut PromptOriginal, Problem> {
        self.current_prompt.and_then(|index| self.prompts.get_mut(index)).and_then(Option::as_mut)
            .ok_or(Problem::CleanupUnknown)
    }
    fn retain_prompt(&mut self, path: &str, role: checked_lookup::PromptRole) -> Result<(), Problem> {
        if path == "/" { return Ok(()); }
        let index = match role { checked_lookup::PromptRole::Unlock => 0, checked_lookup::PromptRole::Create => 1 };
        if self.prompts[index].is_some() || self.prompts.iter().flatten().any(|prompt| prompt.path.as_str() == path) {
            return Err(Problem::InvalidReply);
        }
        let path = Arc::new(OwnedObjectPath::try_from(path.to_owned()).map_err(|_| Problem::InvalidReply)?);
        // Custody is established BEFORE STOP, reconciliation or tuple-semantic
        // checks can refuse successor work. No Prompt call is implied here.
        self.prompts[index] = Some(PromptOriginal { path, role, invoked: false, method_returned: false,
            dismiss_entered: false, dismiss_returned: false, completion: None, position: None,
            reconciled: false, unknown: false });
        self.current_prompt = Some(index);
        Ok(())
    }
}
impl Query {
    fn attributes(&self) -> [(&str, &str); 4] {
        [("application", "dev.mobile-release-kit.desktop"), ("purpose", "vault-wrapping-key-v1"),
            ("vault-id", &self.vault_id), ("generation-id", &self.generation_id)]
    }
}

/// Mechanical bounded backend input only, NOT endpoint/peer/provider admission.
/// A later reviewed profile must supply these reserved identities; no persistent
/// ID encoding or durable reservation is invented here.
pub(crate) struct LookupInput { endpoint: PathBuf, query: Arc<Query>, rule: Arc<MatchRule<'static>>, purpose: Purpose }
impl LookupInput {
    pub(crate) fn new(endpoint: &Path, collection: &str, vault_id: &str, generation_id: &str) -> Result<Self, Problem> {
        let bytes = endpoint.as_os_str().as_bytes();
        if !endpoint.is_absolute() || bytes.is_empty() || bytes.len() > 107 || bytes.contains(&0)
            || endpoint.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            || collection == "/" || collection.len() > 512
            || [vault_id, generation_id].iter().any(|value| value.is_empty() || value.len() > 256 || value.contains('\0'))
        { return Err(Problem::InvalidInput); }
        let collection = OwnedObjectPath::try_from(collection.to_owned()).map_err(|_| Problem::InvalidInput)?;
        let rule = MatchRule::builder().msg_type(Type::Signal).sender(BUS).map_err(|_| Problem::InvalidInput)?
            .interface(BUS).map_err(|_| Problem::InvalidInput)?.path(BUS_PATH).map_err(|_| Problem::InvalidInput)?
            .member("NameOwnerChanged").map_err(|_| Problem::InvalidInput)?.arg(0, SERVICE).map_err(|_| Problem::InvalidInput)?.build();
        Ok(Self { endpoint: endpoint.to_path_buf(),
            query: Arc::new(Query { collection, vault_id: vault_id.into(), generation_id: generation_id.into() }),
            rule: Arc::new(rule), purpose: Purpose::Legacy })
    }

    pub(crate) fn unlock(identity: crate::vault_format::Identity) -> Result<Self, Problem> {
        Self::persistent(identity, Purpose::Unlock(identity))
    }
    pub(crate) fn initialize(admission: crate::asset_session::KeyringInitializationAdmission,
        proposal: crate::vault_crypto::InitializationKey) -> Result<Self, Problem> {
        let identity = admission.into_identity();
        crate::vault_format::Header::parse(proposal.header(), identity).map_err(|_| Problem::IdentityMismatch)?;
        Self::persistent(identity, Purpose::Initialize(identity, proposal))
    }
    fn persistent(identity: crate::vault_format::Identity, purpose: Purpose) -> Result<Self, Problem> {
        crate::vault_format::Identity::new(identity.vault, identity.generation).map_err(|_| Problem::InvalidInput)?;
        let uid = rustix::process::geteuid().as_raw();
        if uid == 0 { return Err(Problem::UnsupportedProvider); }
        let endpoint = PathBuf::from(format!("/run/user/{uid}/bus"));
        let mut input = Self::new(&endpoint, LOGIN_COLLECTION, &identity.vault.token(), &identity.generation.token())?;
        input.purpose = purpose;
        Ok(input)
    }
}

#[cfg(test)]
type ConnectFuture = Pin<Box<dyn Future<Output = zbus::Result<()>> + Send>>;
#[cfg(test)]
type RpcFuture = Pin<Box<dyn Future<Output = zbus::Result<Message>> + Send>>;
enum ConnectOriginal { Native, #[cfg(test)] Data(ConnectFuture) }
enum RpcOriginal { Native, #[cfg(test)] Data(RpcFuture) }
enum Pending {
    Connect { future: ConnectOriginal, polled: bool, dispatch_end: Instant },
    Rpc { future: RpcOriginal, polled: bool, dispatch_end: Instant },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shutdown { Unrequested, Staged(Instant), Entered, Settled, Refused }

// Retain non-owning error facts after the actual raw error has been reconciled.
// In particular, a MethodError's Message may own received descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorClass { Io(std::io::ErrorKind, Option<i32>), Remote, Handshake, Protocol, Other }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemovalReply { Confirmed, Failed(ErrorClass) }
fn error_class(error: &zbus::Error) -> ErrorClass {
    match error {
        zbus::Error::InputOutput(error) | zbus::Error::Connection(error, _) => ErrorClass::Io(error.kind(), error.raw_os_error()),
        zbus::Error::MethodError(..) => ErrorClass::Remote,
        zbus::Error::Handshake(_) => ErrorClass::Handshake,
        zbus::Error::InvalidReply | zbus::Error::InvalidField | zbus::Error::ExcessData
            | zbus::Error::MissingField | zbus::Error::InvalidSerial | zbus::Error::Variant(_)
            | zbus::Error::Names(_) => ErrorClass::Protocol,
        _ => ErrorClass::Other,
    }
}

pub(crate) enum Observation { Absent, Candidate(Arc<OwnedObjectPath>) }

pub(crate) struct LookupBook {
    entered: bool, constructor_refused: bool, cleanup_failed_seen: bool, charge: Option<crate::asset_session::KeyringMemoryAdmission>,
    phase: Phase, attempt: Option<OwnedConnectionAttempt>,
    stream_ended: bool, pending: Option<Pending>, first_poll_ready: bool, connect_failure: Option<zbus::Error>,
    raw: Option<zbus::Result<Message>>, raw_pending: bool, removal_reply: Option<RemovalReply>,
    call_end: Option<Instant>, call_outer_end: Option<Instant>, cleanup_cutoff_seen: bool,
    session: RemoteSession, session_path: Option<Arc<OwnedObjectPath>>,
    exchange: Option<checked_lookup::CheckedDhExchange>, session_key: Option<checked_lookup::CheckedSessionKey>,
    key_candidate: Option<checked_lookup::WrappingKeyCandidate>, close_error: Option<ErrorClass>,
    owner: Option<Arc<UniqueName<'static>>>, query: Option<Arc<Query>>, rule: Option<Arc<MatchRule<'static>>>,
    candidate: Option<Arc<OwnedObjectPath>>, observation: Option<Observation>,
    profile: Option<Profile>,
    problem: Option<Problem>, problem_at: Option<Instant>, registration: Registration,
    shutdown: Shutdown, shutdown_ready: bool, local_settlement: Option<LocalSettlement>,
    build_error: Option<ErrorClass>, raw_error: Option<ErrorClass>, cleanup_error: Option<ErrorClass>,
    #[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
    fixture_first_polls: [u8; 11],
}
// App share of the SAME 64KiB whole-attempt control row. The document adds
// its fixed owner/slot/source cells and asserts the combined share <=16KiB.
// Query/path/string heap backing belongs to the separate 32KiB input-copy row.
pub(crate) const LOOKUP_CONTROL_BYTES: usize = std::mem::size_of::<LookupBook>()
    + std::mem::size_of::<LookupInput>() + std::mem::size_of::<Query>() + std::mem::size_of::<Pending>()
    + 3 * std::mem::size_of::<MatchRule<'static>>() + 2 * std::mem::size_of::<UniqueName<'static>>()
    + 8 * std::mem::size_of::<OwnedObjectPath>() + 64 * std::mem::size_of::<usize>();

impl LookupBook {
    pub(crate) fn new() -> Self {
        Self { entered: false, constructor_refused: false, cleanup_failed_seen: false, charge: None, phase: Phase::Unstarted, attempt: None,
            stream_ended: false, pending: None, first_poll_ready: false, connect_failure: None, raw: None, raw_pending: false, removal_reply: None,
            call_end: None, call_outer_end: None, cleanup_cutoff_seen: false, session: RemoteSession::Unopened, session_path: None,
            exchange: None, session_key: None, key_candidate: None, close_error: None,
            owner: None, query: None, rule: None, candidate: None, observation: None, profile: None,
            problem: None, problem_at: None, registration: Registration::Unsent,
            shutdown: Shutdown::Unrequested, shutdown_ready: false, local_settlement: None,
            build_error: None, raw_error: None, cleanup_error: None,
            #[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
            fixture_first_polls: [0; 11],
        }
    }
    pub(crate) fn resources_settled(&self) -> bool {
        self.sdk_resources_settled()
            && self.profile.as_ref().is_none_or(|profile| profile.native_released && profile.native.settled())
    }
    fn sdk_resources_settled(&self) -> bool {
        !self.entered || ((self.constructor_refused && self.attempt.is_none()
            || self.profile.as_ref().is_some_and(|profile| !profile.sdk_constructed) && self.attempt.is_none()
            || self.shutdown == Shutdown::Settled && self.local_settlement.is_some())
            && self.pending.is_none() && !self.raw_pending && self.raw.is_none() && self.connect_failure.is_none())
    }
    pub(crate) fn memory_held(&self) -> bool { self.charge.is_some() }
    pub(crate) fn allocations_released(&self) -> bool {
        self.charge.is_none() && self.attempt.is_none() && self.pending.is_none() && self.raw.is_none()
            && self.connect_failure.is_none() && self.query.is_none() && self.rule.is_none()
            && self.owner.is_none() && self.candidate.is_none() && self.observation.is_none()
            && self.session_path.is_none() && self.exchange.is_none() && self.session_key.is_none() && self.key_candidate.is_none()
            && self.profile.is_none()
    }
    pub(crate) fn can_begin(&self) -> bool {
        !self.entered && self.phase == Phase::Unstarted && self.problem.is_none() && self.allocations_released()
            && self.shutdown == Shutdown::Unrequested && self.local_settlement.is_none()
    }
    // Called only by the original document's reconciliation after coordinator,
    // child/source and retirement joins/disposal. SDK settlement alone does not
    // refund: even its settled attempt and the query/rule/observation still own
    // backing. Retain the charge if any destructor fails, and all terminal facts
    // after success. This is never a fresh, retryable LookupBook.
    pub(crate) fn dispose_settled_storage(&mut self) -> bool {
        if !self.memory_held() || !self.resources_settled() { return false; }
        self.cleanup_failed_seen |= self.attempt.as_ref().is_some_and(OwnedConnectionAttempt::cleanup_failed);
        drop((self.attempt.take(), self.query.take(), self.rule.take(), self.owner.take(),
            self.candidate.take(), self.observation.take(), self.session_path.take(),
            self.exchange.take(), self.session_key.take(), self.key_candidate.take(), self.profile.take()));
        self.charge.take(); // Exactly once, AFTER actual charged holding disposal.
        true
    }
    pub(crate) fn started(&self) -> bool { self.entered }
    pub(crate) fn problem(&self) -> Option<Problem> { self.problem }
    pub(crate) fn problem_at(&self) -> Option<Instant> { self.problem_at }
    pub(crate) fn cleanup_unknown(&self) -> bool {
        self.local_cleanup_unknown() || self.registration == Registration::Unknown || self.session == RemoteSession::Unknown
            || self.profile.as_ref().is_some_and(Profile::remote_unknown)
    }
    // A failed remote Close/removal is permanent failed operation evidence,
    // not loss of this coordinator's ability to settle its remaining originals.
    // Existing local/poison/document Unknown gates remain unchanged.
    pub(crate) fn local_cleanup_unknown(&self) -> bool {
        self.cleanup_failed_seen || self.local_settlement.is_some_and(|result| !result.clean())
            || self.attempt.as_ref().is_some_and(OwnedConnectionAttempt::cleanup_failed)
            || self.profile.as_ref().is_some_and(|profile| profile.native.unknown())
    }
    pub(crate) fn document_cleanup_unknown(&self) -> bool {
        // Defer only remote semantic uncertainty until independent LOCAL
        // originals have settled. Never defer actual custody/poison failures.
        self.local_cleanup_unknown() || self.resources_settled() && self.cleanup_unknown()
    }
    pub(crate) fn observation(&self) -> Option<&Observation> {
        if self.problem.is_none() { self.observation.as_ref() } else { None }
    }
    fn fail(&mut self, problem: Problem) {
        self.fail_at(problem, Instant::now());
    }
    fn fail_at(&mut self, problem: Problem, at: Instant) {
        if self.problem.is_none() { self.problem = Some(problem); self.problem_at = Some(at); }
        // No late success can recreate authority after STOP, failure or cutoff.
        // These owned buffers zeroize; the original raw result remains retained.
        self.exchange = None; self.session_key = None; self.key_candidate = None;
        if let Some(profile) = self.profile.as_mut() { profile.proposal = None; profile.encrypted = None; }
    }
    pub(crate) fn interrupt(&mut self) { self.fail(Problem::Interrupted); }

    // This remains private readiness evidence, never document/publication authority.
    fn key_ready(&self) -> bool {
        self.problem.is_none() && self.key_candidate.is_some() && self.session == RemoteSession::Closed
            && self.registration == Registration::Removed && self.resources_settled()
            && !self.cleanup_unknown() && self.local_settlement.is_some_and(|result| result.clean())
            && self.profile.as_ref().is_none_or(|profile| profile.admitted.is_some() && profile.native_rechecked
                && profile.native_released && profile.all_prompts_settled() && profile.round == CredentialRound::Final
                && profile.user_rounds == 7 && profile.process_rounds == 7 && profile.manager_registration == Registration::Removed
                && matches!(profile.prompt_registration, Registration::Unsent | Registration::Removed))
    }

    pub(crate) fn consume_settled_key<R>(&mut self,
        authenticate: impl FnOnce(checked_lookup::WrappingKeyCandidate) -> R) -> Result<R, Problem> {
        if !self.key_ready() || self.charge.is_none() { return Err(self.problem.unwrap_or(Problem::CleanupUnknown)); }
        self.consume_charged_candidate(authenticate)
    }
    // Private ownership-only half of the public-to-OriginalWork settled seam.
    // Its sole production caller above first proves key_ready. Kept separate
    // for DATA charge/one-shot tests, which must not forge a native settlement.
    fn consume_charged_candidate<R>(&mut self,
        authenticate: impl FnOnce(checked_lookup::WrappingKeyCandidate) -> R) -> Result<R, Problem> {
        if self.charge.is_none() { return Err(Problem::CleanupUnknown); }
        let candidate = self.key_candidate.take().ok_or(Problem::CleanupUnknown)?;
        // Charge is deliberately NOT returned. Product authenticates/counts the
        // retained opaque key inside this same OriginalWork before disposal.
        Ok(authenticate(candidate))
    }
    pub(crate) fn creation_possible(&self) -> bool {
        self.profile.as_ref().is_some_and(|profile| profile.creation != Creation::Unsent)
    }

    // Fallible RNG/crypto preparation belongs to this SAME charged coordinator,
    // outside the document mutex. It cannot dispatch or grant the later RPC.
    pub(crate) fn prepare_exchange(&mut self) -> Result<(), Problem> {
        if !self.expected(Step::OpenSession) || self.problem.is_some() || self.shutdown != Shutdown::Unrequested
            || self.exchange.is_some() || self.session != RemoteSession::Unopened { return Err(Problem::CleanupUnknown); }
        match checked_lookup::CheckedDhExchange::generate() {
            Ok(exchange) => { self.exchange = Some(exchange); Ok(()) }
            Err(_) => { self.fail(Problem::Crypto); Err(Problem::Crypto) }
        }
    }

    pub(crate) fn begin(&mut self, input: LookupInput, dispatch_end: Instant,
        charge: crate::asset_session::KeyringMemoryAdmission) -> Result<(), Problem> {
        self.begin_constructed(input, dispatch_end, charge, OwnedConnectionAttempt::keyring_unix)
    }
    fn claim(&mut self, charge: crate::asset_session::KeyringMemoryAdmission) -> Result<(), Problem> {
        // Reject duplicates BEFORE allocating even an unpolled SDK constructor.
        if !self.can_begin() { return Err(Problem::CleanupUnknown); }
        // Permanent before construction/first poll. No cancellation, error,
        // coordinator return or eventual refund restores one-shot entry.
        self.entered = true; self.charge = Some(charge); Ok(())
    }
    fn begin_constructed(&mut self, input: LookupInput, dispatch_end: Instant,
        charge: crate::asset_session::KeyringMemoryAdmission,
        make: impl FnOnce(PathBuf) -> zbus::Result<OwnedConnectionAttempt>) -> Result<(), Problem> {
        self.claim(charge)?;
        let LookupInput { endpoint, query, rule, purpose } = input;
        self.query = Some(query); self.rule = Some(rule);
        if !matches!(purpose, Purpose::Legacy) {
            match Profile::new(endpoint, purpose, dispatch_end) {
                Ok(profile) => { self.profile = Some(profile); self.phase = Phase::Native(ProviderStep::Acquire); return Ok(()); },
                Err(problem) => {
                    self.constructor_refused = true; self.phase = Phase::Holding; self.fail(problem); return Err(problem);
                }
            }
        }
        self.construct_attempt(endpoint, dispatch_end, make)
    }
    fn construct_attempt(&mut self, endpoint: PathBuf, dispatch_end: Instant,
        make: impl FnOnce(PathBuf) -> zbus::Result<OwnedConnectionAttempt>) -> Result<(), Problem> {
        match make(endpoint) {
            Ok(attempt) => {
                self.attempt = Some(attempt); self.phase = Phase::Connecting;
                self.pending = Some(Pending::Connect { future: ConnectOriginal::Native, polled: false, dispatch_end });
                Ok(())
            }
            Err(error) => {
                // No SDK attempt/task ever existed on THIS constructor refusal.
                // This is distinct from a failed original build future, whose
                // attempt and true shutdown/join roster remain mandatory.
                self.build_error = Some(error_class(&error)); drop(error);
                self.constructor_refused = true; self.phase = Phase::Holding;
                self.fail(Problem::Unavailable); Err(Problem::Unavailable)
            }
        }
    }

    pub(crate) fn provider_step_ready(&self, step: ProviderStep) -> bool {
        let Some(profile) = self.profile.as_ref() else { return false; };
        self.phase == Phase::Native(step) && profile.native_progress == NativeProgress::Ready(step)
            && self.charge.is_some() && self.pending.is_none() && !self.raw_pending
            && match step {
                ProviderStep::Acquire => !profile.sdk_constructed && !profile.native_acquired && self.attempt.is_none(),
                ProviderStep::Bind => profile.native_acquired && !profile.native_bound && profile.pid.is_some()
                    && self.attempt.is_some() && self.shutdown == Shutdown::Unrequested,
                ProviderStep::Recheck => profile.native_bound && profile.admitted.is_some() && !profile.native_rechecked
                    && self.key_candidate.is_some() && self.shutdown == Shutdown::Unrequested,
                ProviderStep::Release => !profile.native_released && self.sdk_resources_settled(),
            }
    }
    fn run_provider(&mut self, step: ProviderStep, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
        if !self.provider_step_ready(step) { return Err(Problem::CleanupUnknown); }
        let previous_problem = self.problem;
        let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
        profile.native_progress = NativeProgress::Entered(step);
        let result = if step != ProviderStep::Release && previous_problem.is_some() {
            Err(previous_problem.unwrap_or(Problem::Interrupted))
        } else { match step {
            ProviderStep::Acquire => profile.native.acquire(profile.uid, stop),
            ProviderStep::Bind => match profile.pid {
                Some(pid) => profile.native.bind(profile.uid, pid, stop), None => Err(Problem::CleanupUnknown),
            },
            ProviderStep::Recheck => profile.native.recheck(profile.uid, stop),
            ProviderStep::Release => profile.native.release(stop),
        } };
        // This is the actual synchronous method return, not the native child's
        // join. A panic leaves Entered/poisoned originals, never fabricated facts.
        profile.native_progress = NativeProgress::Returned(step, result);
        if let Err(problem) = result { self.fail(problem); }
        result
    }
    pub(crate) fn prepare_provider(&mut self, stop: &mut impl FnMut() -> bool) -> Result<(), Problem> {
        self.run_provider(ProviderStep::Acquire, stop)
    }
    pub(crate) fn bind_provider(&mut self, stop: &mut impl FnMut() -> bool) -> Result<(), Problem> {
        self.run_provider(ProviderStep::Bind, stop)
    }
    pub(crate) fn recheck_provider(&mut self, stop: &mut impl FnMut() -> bool) -> Result<(), Problem> {
        self.run_provider(ProviderStep::Recheck, stop)
    }
    pub(crate) fn release_provider(&mut self, cleanup_expired: &mut impl FnMut() -> bool) -> Result<(), Problem> {
        self.run_provider(ProviderStep::Release, cleanup_expired)
    }
    pub(crate) fn provider_child_joined(&mut self, step: ProviderStep, result: Result<(), Problem>) -> Result<(), Problem> {
        let Some(profile) = self.profile.as_mut() else { self.fail(Problem::CleanupUnknown); return Err(Problem::CleanupUnknown); };
        if self.phase != Phase::Native(step) || profile.native_progress != NativeProgress::Returned(step, result) {
            self.fail(Problem::CleanupUnknown); return Err(Problem::CleanupUnknown);
        }
        // Product calls this only after consuming the ORIGINAL ChildJob join.
        // Record these facts even if STOP/document freshness already forbids
        // successor work. Native cleanup finality is not a GUI-liveness test.
        profile.native_progress = NativeProgress::Joined(step);
        match step {
            ProviderStep::Acquire => profile.native_acquired = result.is_ok(),
            ProviderStep::Bind => profile.native_bound = result.is_ok(),
            ProviderStep::Recheck => profile.native_rechecked = result.is_ok(),
            ProviderStep::Release => profile.native_released = true,
        }
        if let Err(problem) = result { self.fail(problem); }
        if step == ProviderStep::Release { self.phase = Phase::Holding; return result; }
        if let Some(problem) = self.problem { self.cleanup_or_hold(); return Err(problem); }
        let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
        match step {
            ProviderStep::Acquire => {
                let Some(endpoint) = profile.endpoint.take() else {
                    self.fail(Problem::CleanupUnknown); self.cleanup_or_hold(); return Err(Problem::CleanupUnknown);
                };
                let dispatch_end = profile.dispatch_end;
                profile.sdk_constructed = true;
                self.construct_attempt(endpoint, dispatch_end, OwnedConnectionAttempt::keyring_unix)
            }
            ProviderStep::Bind | ProviderStep::Recheck => {
                profile.round = if step == ProviderStep::Bind { CredentialRound::Bound } else { CredentialRound::Final };
                self.phase = Phase::Admit(Step::ProviderUser); Ok(())
            }
            ProviderStep::Release => Err(Problem::CleanupUnknown),
        }
    }
    #[cfg(test)]
    fn begin_with(&mut self, query: Arc<Query>, rule: Arc<MatchRule<'static>>, dispatch_end: Instant, future: ConnectFuture) -> Result<(), Problem> {
        self.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap())?;
        self.query = Some(query); self.rule = Some(rule); self.phase = Phase::Connecting;
        self.pending = Some(Pending::Connect { future: ConnectOriginal::Data(future), polled: false, dispatch_end });
        Ok(())
    }
    pub(crate) fn current_step(&self) -> Option<Step> {
        match self.phase { Phase::Calling(step) => Some(step), _ => None }
    }
    pub(crate) fn expected(&self, step: Step) -> bool {
        self.phase == Phase::Admit(step) && self.pending.is_none() && !self.raw_pending
    }
    pub(crate) fn admit(&mut self, step: Step, dispatch_end: Instant) -> Result<(), Problem> {
        self.admit_original(step, dispatch_end, Self::rpc)
    }
    // Single actual dispatch-registration seam. Tests inject a DATA future here,
    // not an alternate lifecycle model, fake connection or native-test bypass.
    #[cfg(test)]
    fn admit_with(&mut self, step: Step, dispatch_end: Instant, make: impl FnOnce(&Self, Step) -> Result<RpcFuture, Problem>) -> Result<(), Problem> {
        self.admit_original(step, dispatch_end, |book, step| make(book, step).map(RpcOriginal::Data))
    }
    fn admit_original(&mut self, step: Step, dispatch_end: Instant, make: impl FnOnce(&mut Self, Step) -> Result<RpcOriginal, Problem>) -> Result<(), Problem> {
        if !self.expected(step) || (!step.cleanup() && self.problem.is_some()) || self.cleanup_cutoff_seen
            || self.shutdown != Shutdown::Unrequested {
            return Err(self.problem.unwrap_or(Problem::CleanupUnknown));
        }
        if step == Step::RemoveMatch && !matches!(self.registration, Registration::Possible | Registration::Registered)
            || step == Step::CloseSession && (self.session != RemoteSession::Known || self.session_path.is_none()) {
            return Err(Problem::CleanupUnknown);
        }
        if let Some(profile) = self.profile.as_mut() {
            // admit() is reached only AFTER the original document's fresh gate.
            // A raw profile tuple, a nominal PID/path, or caller Boolean cannot
            // manufacture this private conjunction. Its first use is still
            // followed by the ordinary final stream/first-poll document gate.
            if profile.admitted.is_none() && matches!(step, Step::CollectionLocked | Step::SearchItems) {
                if !profile.profile_conjunction() || self.owner.is_none()
                    || self.registration != Registration::Registered || self.charge.is_none() {
                    return Err(Problem::UnsupportedProvider);
                }
                let query = self.query.as_ref().ok_or(Problem::CleanupUnknown)?;
                if crate::vault_format::Id::from_token(&query.vault_id).ok() != Some(profile.identity.vault)
                    || crate::vault_format::Id::from_token(&query.generation_id).ok() != Some(profile.identity.generation) {
                    return Err(Problem::IdentityMismatch);
                }
                profile.admitted = Some(AdmittedProvider);
            }
            let allowed = match step {
                Step::AddManagerMatch => profile.manager_registration == Registration::Unsent,
                Step::RemoveManagerMatch => matches!(profile.manager_registration, Registration::Possible | Registration::Registered),
                Step::AddPromptMatch => profile.prompt_registration == Registration::Unsent
                    && profile.prompt_rule.is_some() && profile.after_prompt_match.is_some(),
                Step::RemovePromptMatch => matches!(profile.prompt_registration, Registration::Possible | Registration::Registered),
                Step::Unlock => profile.admitted.is_some() && !profile.unlock_attempted && profile.unlock_target.is_some()
                    && profile.prompt_registration == Registration::Registered,
                Step::CreateItem => profile.admitted.is_some() && profile.initialize && profile.absence_proved
                    && profile.creation == Creation::Unsent && profile.encrypted.is_some() && profile.proposal.is_none()
                    && self.session == RemoteSession::Known && self.session_key.is_some()
                    && profile.prompt_registration == Registration::Registered,
                Step::Prompt => profile.current().is_ok_and(|prompt| !prompt.invoked && !prompt.unknown && prompt.completion.is_none()),
                Step::Dismiss => profile.current().is_ok_and(|prompt| !prompt.dismiss_entered && !prompt.complete()),
                _ => true,
            };
            if !allowed { return Err(Problem::CleanupUnknown); }
        } else if matches!(step, Step::AddManagerMatch | Step::GetManagerOwner | Step::ProviderUser | Step::ProviderPid
            | Step::GetUnit | Step::UnitProperty(_) | Step::LoginAlias | Step::SessionAlias | Step::CollectionLocked
            | Step::AddPromptMatch | Step::Unlock | Step::Prompt | Step::Dismiss | Step::CreateItem
            | Step::RemovePromptMatch | Step::RemoveManagerMatch) {
            return Err(Problem::InvalidInput);
        }
        // A remote cleanup must leave time for independent original local stop.
        // Latch ONCE; retain through Pending and raw reconciliation, never renew.
        let outer_end = dispatch_end;
        let mut dispatch_end = if step.cleanup() { cleanup_progress_end(Instant::now(), outer_end) } else { outer_end };
        if step == Step::Dismiss {
            if let Some(end) = self.profile.as_ref().and_then(|profile| profile.prompt_end) { dispatch_end = dispatch_end.min(end); }
        }
        let future = make(self, step)?;
        // A preceding raw result stays retained through reconciliation and the
        // final stream/document gate, then this one successor replaces it.
        if let Some(Err(error)) = self.raw.as_ref() { self.raw_error.get_or_insert_with(|| error_class(error)); }
        self.raw = None; self.phase = Phase::Calling(step); self.call_end = Some(dispatch_end);
        self.call_outer_end = step.cleanup().then_some(outer_end);
        self.pending = Some(Pending::Rpc { future, polled: false, dispatch_end });
        Ok(())
    }
    fn rpc(&mut self, step: Step) -> Result<RpcOriginal, Problem> {
        let attempt = self.attempt.as_mut().ok_or(Problem::CleanupUnknown)?;
        match step {
            Step::AddMatch | Step::RemoveMatch | Step::AddManagerMatch | Step::RemoveManagerMatch
                | Step::AddPromptMatch | Step::RemovePromptMatch => {
                let rule = match step {
                    Step::AddMatch | Step::RemoveMatch => self.rule.as_ref(),
                    Step::AddManagerMatch | Step::RemoveManagerMatch => self.profile.as_ref().map(|profile| &profile.manager_rule),
                    _ => self.profile.as_ref().and_then(|profile| profile.prompt_rule.as_ref()),
                }.ok_or(Problem::CleanupUnknown)?;
                let method = if matches!(step, Step::AddMatch | Step::AddManagerMatch | Step::AddPromptMatch) { "AddMatch" } else { "RemoveMatch" };
                attempt.start_raw_call(BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                    BUS_PATH.try_into().map_err(|_| Problem::InvalidInput)?, BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                    method.try_into().map_err(|_| Problem::InvalidInput)?, rule.as_ref().clone())
            }
            Step::GetNameOwner | Step::GetManagerOwner => attempt.start_raw_call(BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                BUS_PATH.try_into().map_err(|_| Problem::InvalidInput)?, BUS.try_into().map_err(|_| Problem::InvalidInput)?,
                "GetNameOwner".try_into().map_err(|_| Problem::InvalidInput)?, if step == Step::GetNameOwner { SERVICE } else { MANAGER }),
            Step::ProviderUser | Step::ProviderPid => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let kind = if step == Step::ProviderUser { checked_lookup::BusIdentity::User } else { checked_lookup::BusIdentity::Process };
                checked_lookup::start_owned_bus_identity(attempt, owner.as_ref(), kind)
            }
            Step::GetUnit => {
                let profile = self.profile.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_get_unit_by_pid(attempt,
                    profile.manager.as_ref().ok_or(Problem::CleanupUnknown)?.as_ref(), profile.pid.ok_or(Problem::CleanupUnknown)?)
            }
            Step::UnitProperty(property) => {
                let profile = self.profile.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_unit_property(attempt,
                    profile.manager.as_ref().ok_or(Problem::CleanupUnknown)?.as_ref(),
                    profile.unit.as_ref().ok_or(Problem::CleanupUnknown)?.as_ref(), property)
            }
            Step::LoginAlias | Step::SessionAlias => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let alias = if step == Step::LoginAlias { checked_lookup::CollectionAlias::Login } else { checked_lookup::CollectionAlias::Session };
                checked_lookup::start_owned_read_alias(attempt, owner.as_ref(), alias)
            }
            Step::SearchItems => {
                let owner = self.owner.clone().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.clone().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_search_items(attempt, owner.as_ref(), &query.collection, &query.attributes())
            }
            Step::Attributes => {
                let owner = self.owner.clone().ok_or(Problem::CleanupUnknown)?;
                let item = self.candidate.clone().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_attributes(attempt, owner.as_ref(), item.as_ref())
            }
            Step::Locked => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let item = self.candidate.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_locked(attempt, owner.as_ref(), item.as_ref())
            }
            Step::CollectionLocked => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_collection_locked(attempt, owner.as_ref(), &query.collection)
            }
            Step::Unlock => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let target = self.profile.as_ref().and_then(|profile| profile.unlock_target.as_ref()).ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_unlock(attempt, owner.as_ref(), target.as_ref())
            }
            Step::Prompt | Step::Dismiss => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let prompt = self.profile.as_ref().ok_or(Problem::CleanupUnknown)?.current()?;
                if step == Step::Prompt { checked_lookup::start_owned_prompt(attempt, owner.as_ref(), prompt.path.as_ref()) }
                else { checked_lookup::start_owned_dismiss(attempt, owner.as_ref(), prompt.path.as_ref()) }
            }
            Step::CreateItem => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.as_ref().ok_or(Problem::CleanupUnknown)?;
                let session = self.session_path.as_ref().ok_or(Problem::CleanupUnknown)?;
                let (iv, ciphertext) = self.profile.as_ref().and_then(|profile| profile.encrypted.as_ref()).ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_create_item(attempt, owner.as_ref(), &query.collection,
                    &query.attributes(), session.as_ref(), iv, ciphertext)
            }
            Step::OpenSession => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let exchange = self.exchange.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_open_session(attempt, owner.as_ref(), exchange.public_key())
            }
            Step::GetSecret => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let item = self.candidate.as_ref().ok_or(Problem::CleanupUnknown)?;
                let session = self.session_path.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_get_secret(attempt, owner.as_ref(), item.as_ref(), session.as_ref())
            }
            Step::CloseSession => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let session = self.session_path.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::start_owned_close_session(attempt, owner.as_ref(), session.as_ref())
            }
        }.map_err(|_| Problem::Unavailable)?;
        Ok(RpcOriginal::Native)
    }
    fn cleanup_or_hold(&mut self) {
        if self.sdk_resources_settled() && self.profile.as_ref().is_some_and(|profile| !profile.native_released) {
            // Even a failed/never-entered Acquire owes its one release child.
            // A running/returned-but-unjoined child cannot be replaced here.
            self.stage_native_release();
            return;
        }
        if self.shutdown != Shutdown::Unrequested {
            self.abandon_remote_session();
            self.abandon_profile_remote();
            if matches!(self.registration, Registration::Possible | Registration::Registered) {
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
            }
            self.phase = Phase::Holding;
            return;
        }
        if self.cleanup_cutoff_seen {
            self.abandon_remote_session(); self.abandon_profile_remote();
            self.phase = Phase::Holding; return;
        }
        if let Some(profile) = self.profile.as_mut() {
            for (index, prompt) in profile.prompts.iter().enumerate().filter_map(|(i, prompt)| prompt.as_ref().map(|p| (i, p))) {
                if prompt.complete() || prompt.unknown { continue; }
                profile.current_prompt = Some(index);
                // A received completion must get its original ordering turn,
                // not an unnecessary Dismiss based on a stale empty snapshot.
                self.phase = if prompt.completion.is_some() || prompt.dismiss_returned {
                    Phase::AwaitPrompt
                } else if !prompt.dismiss_entered { Phase::Admit(Step::Dismiss) }
                else { Phase::AwaitPrompt };
                return;
            }
        }
        self.phase = if self.session == RemoteSession::Known {
            Phase::Admit(Step::CloseSession)
        } else if self.profile.as_ref().is_some_and(|profile| matches!(profile.prompt_registration, Registration::Possible | Registration::Registered)) {
            Phase::Admit(Step::RemovePromptMatch)
        } else if self.profile.as_ref().is_some_and(|profile| matches!(profile.manager_registration, Registration::Possible | Registration::Registered)) {
            Phase::Admit(Step::RemoveManagerMatch)
        } else if matches!(self.registration, Registration::Possible | Registration::Registered) {
            Phase::Admit(Step::RemoveMatch)
        } else { Phase::Holding };
    }
    fn stage_native(&mut self, step: ProviderStep) -> Result<(), Problem> {
        let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
        let predecessor = match step { ProviderStep::Bind => ProviderStep::Acquire,
            ProviderStep::Recheck => ProviderStep::Bind, _ => return Err(Problem::CleanupUnknown) };
        if profile.native_progress != NativeProgress::Joined(predecessor) { return Err(Problem::CleanupUnknown); }
        profile.native_progress = NativeProgress::Ready(step); self.phase = Phase::Native(step);
        Ok(())
    }
    fn stage_native_release(&mut self) {
        let Some(profile) = self.profile.as_mut() else { return; };
        if profile.native_released || matches!(profile.native_progress, NativeProgress::Entered(_) | NativeProgress::Returned(_, _)) { return; }
        profile.native_progress = NativeProgress::Ready(ProviderStep::Release);
        self.phase = Phase::Native(ProviderStep::Release);
    }
    fn prompt_match_then(&mut self, step: Step) -> Result<(), Problem> {
        if !matches!(step, Step::Unlock | Step::CreateItem) { return Err(Problem::CleanupUnknown); }
        let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
        let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
        if profile.admitted.is_none() { return Err(Problem::UnsupportedProvider); }
        match profile.prompt_registration {
            Registration::Registered => self.phase = Phase::Admit(step),
            Registration::Unsent if profile.prompt_rule.is_none() && profile.after_prompt_match.is_none() => {
                // Broad only across this ONE retained unique owner and exact
                // signal/interface; the borrowed decoder binds each path/role.
                let rule = MatchRule::builder().msg_type(Type::Signal)
                    .sender(owner.as_str().to_owned()).map_err(|_| Problem::InvalidInput)?
                    .interface("org.freedesktop.Secret.Prompt").map_err(|_| Problem::InvalidInput)?
                    .member("Completed").map_err(|_| Problem::InvalidInput)?.build();
                profile.prompt_rule = Some(Arc::new(rule)); profile.after_prompt_match = Some(step);
                self.phase = Phase::Admit(Step::AddPromptMatch);
            }
            _ => return Err(Problem::CleanupUnknown),
        }
        Ok(())
    }
    fn abandon_profile_remote(&mut self) {
        let Some(profile) = self.profile.as_mut() else { return; };
        let mut unknown = false;
        for registration in [&mut profile.manager_registration, &mut profile.prompt_registration] {
            if matches!(*registration, Registration::Possible | Registration::Registered) {
                *registration = Registration::Unknown; unknown = true;
            }
        }
        for prompt in profile.prompts.iter_mut().flatten() {
            if !prompt.complete() { prompt.unknown = true; unknown = true; }
        }
        if profile.creation == Creation::Possible { profile.creation = Creation::Unknown; unknown = true; }
        if unknown { self.fail(Problem::CleanupUnknown); }
    }
    fn abandon_remote_session(&mut self) {
        if matches!(self.session, RemoteSession::Possible | RemoteSession::Known | RemoteSession::Closing) {
            self.session = RemoteSession::Unknown;
            self.fail(Problem::CleanupUnknown);
        }
    }
    pub(crate) fn admission_refused(&mut self, step: Step, problem: Problem) {
        self.fail(problem);
        if !self.expected(step) { return; }
        self.refused_remote_cleanup(step);
        self.cleanup_or_hold();
    }
    fn refused_remote_cleanup(&mut self, step: Step) {
        match step {
            Step::CloseSession => self.session = RemoteSession::Unknown,
            Step::RemoveMatch => self.registration = Registration::Unknown,
            Step::RemovePromptMatch => if let Some(profile) = self.profile.as_mut() { profile.prompt_registration = Registration::Unknown; },
            Step::RemoveManagerMatch => if let Some(profile) = self.profile.as_mut() { profile.manager_registration = Registration::Unknown; },
            Step::Dismiss => if let Some(profile) = self.profile.as_mut() {
                if let Ok(prompt) = profile.current_mut() { prompt.unknown = true; }
            },
            _ => {}
        }
    }

    pub(crate) fn expected_shutdown(&self) -> bool {
        self.attempt.is_some() && self.shutdown == Shutdown::Unrequested && !self.never_polled()
            && self.local_shutdown_due(Instant::now())
    }
    // A later STOP can replace WORK with an earlier, immutable cleanup end.
    // Contract this SAME call's progress clock once against that real original
    // stop time, not the observation tick. A fresh call admitted after STOP
    // already has the smaller endpoint and retains its admission midpoint.
    pub(crate) fn constrain_cleanup_endpoint(&mut self, stop_at: Instant, outer_end: Instant) {
        if let Some(profile) = self.profile.as_mut() {
            if profile.prompts.iter().flatten().any(|prompt| !prompt.complete()) {
                let cutoff = cleanup_progress_end(stop_at, outer_end);
                profile.prompt_end = Some(profile.prompt_end.map_or(cutoff, |old| old.min(cutoff)));
            }
        }
        if !matches!(self.phase, Phase::Calling(step) if step.cleanup())
            || !self.call_outer_end.is_some_and(|old| outer_end < old) { return; }
        self.call_outer_end = Some(outer_end);
        let cutoff = cleanup_progress_end(stop_at, outer_end);
        if let Some(end) = self.call_end.as_mut() { *end = (*end).min(cutoff); }
        if let Some(Pending::Rpc { dispatch_end, .. }) = self.pending.as_mut() {
            *dispatch_end = (*dispatch_end).min(cutoff);
        }
        // No poll/drop, raw reconciliation, failure-clock change or new grant.
    }
    fn local_shutdown_due(&self, now: Instant) -> bool {
        let unfinished = self.pending.is_some() || self.raw_pending;
        let stalled = match self.phase {
            Phase::Calling(step) if step.cleanup() => unfinished && self.call_end.is_some_and(|end| now >= end),
            Phase::AwaitPrompt => self.problem.is_some() && self.profile.as_ref()
                .and_then(|profile| profile.prompt_end).is_some_and(|end| now >= end),
            _ => unfinished && self.problem.is_some(),
        };
        self.cleanup_cutoff_seen || stalled || self.phase == Phase::Holding
    }
    pub(crate) fn admit_shutdown(&mut self, dispatch_end: Instant) -> Result<(), Problem> {
        if !self.expected_shutdown() {
            self.commit_removal_reply();
            return Err(Problem::CleanupUnknown);
        }
        self.shutdown = Shutdown::Staged(dispatch_end);
        Ok(()) // No native cleanup is first-polled under the document mutex.
    }
    pub(crate) fn shutdown_admission_refused(&mut self, problem: Problem) {
        // Failed removal is deferred only through this local-stop admission,
        // never hidden after denial, expiry or an impossible ownership state.
        self.commit_removal_reply();
        if matches!(self.shutdown, Shutdown::Unrequested | Shutdown::Staged(_)) {
            self.shutdown = Shutdown::Refused;
            self.shutdown_ready = false;
            self.fail(problem);
        }
    }
    pub(crate) fn shutdown_waiting_first_poll(&self) -> bool {
        self.shutdown_ready && matches!(self.shutdown, Shutdown::Staged(_))
    }
    pub(crate) fn first_poll_shutdown(&mut self, cx: &mut Context<'_>,
        admission: Result<crate::asset_session::KeyringShutdownAdmission, Problem>) {
        if !std::mem::take(&mut self.shutdown_ready) {
            self.shutdown_admission_refused(Problem::CleanupUnknown);
            self.fail(Problem::CleanupUnknown); return;
        }
        let Shutdown::Staged(original_end) = self.shutdown else {
            self.shutdown_admission_refused(Problem::CleanupUnknown);
            self.fail(Problem::CleanupUnknown); return;
        };
        let end = match admission {
            Ok(admission) => original_end.min(admission.into_endpoint()),
            Err(problem) => { self.shutdown_admission_refused(problem); return; }
        };
        if Instant::now() >= end { self.shutdown_admission_refused(Problem::CleanupUnknown); return; }
        if self.attempt.is_none() { self.shutdown_admission_refused(Problem::CleanupUnknown); return; }
        self.commit_removal_reply();
        self.shutdown = Shutdown::Entered;
        self.abandon_remote_session();
        self.abandon_profile_remote();
        #[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
        { self.fixture_first_polls[10] = self.fixture_first_polls[10].saturating_add(1); }
        self.poll_shutdown(cx);
        cx.waker().wake_by_ref();
    }
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) {
        if self.shutdown != Shutdown::Entered { return; }
        self.commit_removal_reply();
        if self.pending.is_none() && !self.raw_pending {
            // No original Message escapes this book. Retain non-owning error
            // facts, then consume raw/MethodError and handshake FD holdings.
            if let Some(error) = self.connect_failure.take() { self.build_error.get_or_insert_with(|| error_class(&error)); }
            if let Some(Err(error)) = self.raw.take() { self.raw_error.get_or_insert_with(|| error_class(&error)); }
            if self.attempt.as_mut().is_none_or(|attempt| attempt.release_stream().is_err()) {
                self.fail(Problem::CleanupUnknown);
            }
        }
        let Some(attempt) = self.attempt.as_mut() else { self.fail(Problem::CleanupUnknown); return; };
        let result = attempt.poll_local_shutdown(cx);
        let failed = attempt.cleanup_failed();
        if failed { self.cleanup_failed_seen = true; self.fail(Problem::CleanupUnknown); }
        if let Poll::Ready(result) = result {
            self.local_settlement = Some(result);
            self.shutdown = Shutdown::Settled;
            self.abandon_remote_session();
            self.abandon_profile_remote();
            if !result.clean() { self.fail(Problem::CleanupUnknown); }
            if matches!(self.registration, Registration::Possible | Registration::Registered) {
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
            }
        }
    }

    /// One coordinator polls BOTH originals, bounded to one stream item and one
    /// future poll per turn. No observer owns/takes these holdings. A failed or
    /// poisoned coordinator retains Unknown holdings; it cannot keep driving.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Next> {
        let boundary = self.reconciliation_boundary();
        let turn = if self.removal_reply.is_some() {
            // This terminal raw result already consumed the original stream's
            // ordering evidence. Own shutdown must not sample a new EOF/error
            // and retroactively replace that result. Custody is still retained.
            StreamTurn::Reconciled
        } else { match self.attempt.as_mut() {
            Some(attempt) if !self.stream_ended => stream_turn_observing(attempt, cx, boundary.as_ref(), |message| {
                observe_message(self.profile.as_mut(), self.owner.as_ref().map(|owner| owner.as_ref()), message)
            }),
            None if matches!(self.phase, Phase::Native(_)) => StreamTurn::Idle,
            _ => StreamTurn::Ended,
        } };
        self.advance(cx, turn)
    }
    fn reconciliation_boundary(&self) -> Option<Sequence> {
        let raw = if self.raw_pending { self.raw.as_ref().and_then(raw_message).map(Message::recv_position) } else { None };
        self.profile.as_ref().into_iter().flat_map(|profile| profile.prompts.iter().flatten())
            .filter(|prompt| !prompt.reconciled).filter_map(|prompt| prompt.position).chain(raw).max()
    }

    fn never_polled(&self) -> bool {
        matches!(self.pending.as_ref(), Some(Pending::Connect { polled: false, .. } | Pending::Rpc { polled: false, .. }))
    }
    fn refuse_unpolled_pending(&mut self) -> Result<(), Problem> {
        match self.pending.as_ref() {
            Some(Pending::Connect { future: ConnectOriginal::Native, polled: false, .. }) =>
                self.attempt.as_mut().ok_or(Problem::CleanupUnknown)?.refuse_unpolled_build().map_err(|_| Problem::CleanupUnknown),
            Some(Pending::Rpc { future: RpcOriginal::Native, polled: false, .. }) =>
                self.attempt.as_mut().ok_or(Problem::CleanupUnknown)?.refuse_unpolled_call().map_err(|_| Problem::CleanupUnknown),
            #[cfg(test)]
            Some(Pending::Connect { future: ConnectOriginal::Data(_), polled: false, .. }
                | Pending::Rpc { future: RpcOriginal::Data(_), polled: false, .. }) => Ok(()),
            _ => Err(Problem::CleanupUnknown),
        }
    }
    /// Consume only this turn's readiness AFTER the final actual document gate.
    /// No stream poll, await, setup or lock acquisition may intervene between
    /// that gate's release and this method. The document-locked final admission
    /// is the local linearization point, not an instantaneous cancellation claim.
    pub(crate) fn first_poll(&mut self, cx: &mut Context<'_>, current_gate: Result<Instant, Problem>) {
        if !std::mem::take(&mut self.first_poll_ready) || !self.never_polled() {
            self.fail(Problem::CleanupUnknown);
            return; // Never poll without private, one-use stream readiness.
        }
        let refusal = if self.shutdown != Shutdown::Unrequested {
            Some(Problem::CleanupUnknown)
        } else { match self.pending.as_mut() {
            Some(Pending::Connect { dispatch_end, .. } | Pending::Rpc { dispatch_end, .. }) => match current_gate {
                Err(problem) => Some(problem),
                Ok(current_end) => {
                    *dispatch_end = (*dispatch_end).min(current_end);
                    if matches!(self.phase, Phase::Calling(_)) { self.call_end = Some(*dispatch_end); }
                    (Instant::now() >= *dispatch_end).then_some(if matches!(self.phase, Phase::Calling(step) if step.cleanup()) {
                        Problem::CleanupUnknown
                    } else { Problem::Interrupted })
                }
            },
            None => Some(Problem::CleanupUnknown),
        } };
        if let Some(problem) = refusal {
            self.fail(problem);
            if let Phase::Calling(step) = self.phase { self.refused_remote_cleanup(step); }
            if self.refuse_unpolled_pending().is_ok() { self.pending = None; }
            else { self.fail(Problem::CleanupUnknown); }
            self.cleanup_or_hold(); cx.waker().wake_by_ref(); return;
        }
        #[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
        if self.attempt.is_some() {
            let index = match self.pending.as_ref() {
                Some(Pending::Connect { future: ConnectOriginal::Native, .. }) => Some(0),
                Some(Pending::Rpc { future: RpcOriginal::Native, .. }) => self.current_step().and_then(fixture_step_index),
                _ => None,
            };
            if let Some(index) = index {
                self.fixture_first_polls[index] = self.fixture_first_polls[index].saturating_add(1);
            }
        }
        self.poll_pending(cx);
    }

    // Kept separate only to drive this exact state machine with synthetic DATA
    // streams in unit tests. Production always supplies the original stream's
    // real recv_position boundary above, never a caller ordering receipt.
    fn advance(&mut self, cx: &mut Context<'_>, turn: StreamTurn) -> Poll<Next> {
        self.first_poll_ready = false; // Readiness cannot survive another stream turn.
        self.shutdown_ready = false;
        // Production no longer samples here after terminal reconciliation.
        // Exclude stale DATA turns at this same state-machine boundary too.
        let turn = if self.removal_reply.is_some() { StreamTurn::Reconciled } else { turn };
        let reconciling = self.raw_pending;
        let has_boundary = reconciling && self.raw.as_ref().and_then(raw_message).is_some();
        match turn {
            StreamTurn::Observed(Some(problem)) => self.fail(problem),
            StreamTurn::Failed => self.fail(Problem::StreamFailed),
            StreamTurn::Ended if self.entered && self.phase != Phase::Connecting && self.registration != Registration::Removed
                && (self.attempt.is_some() || self.profile.is_none()) => {
                self.stream_ended = true; self.fail(Problem::StreamFailed);
            }
            _ => {}
        }
        if matches!(turn, StreamTurn::Drained) {
            if let Some(boundary) = self.reconciliation_boundary() {
                if let Some(profile) = self.profile.as_mut() {
                    for prompt in profile.prompts.iter_mut().flatten() {
                        if prompt.position.is_some_and(|position| position <= boundary) && prompt.completion.is_some() {
                            prompt.reconciled = true;
                        }
                    }
                }
            }
        }
        if matches!(self.phase, Phase::Calling(step) if step.cleanup())
            && (self.pending.is_some() || self.raw_pending)
        {
            if let Some(end) = self.call_end.filter(|end| Instant::now() >= *end) {
                // Detection may be late; it cannot move the already-latched
                // cleanup progress cutoff or recreate key authority.
                self.cleanup_cutoff_seen = true;
                self.fail_at(Problem::CleanupUnknown, end);
            }
        }
        if self.phase == Phase::AwaitPrompt {
            let profile = self.profile.as_ref();
            let end = if self.problem.is_some() { profile.and_then(|profile| profile.prompt_end) }
                else { profile.map(|profile| profile.dispatch_end) };
            if let Some(end) = end.filter(|end| Instant::now() >= *end) {
                if self.profile.as_ref().is_some_and(|profile| !profile.all_prompts_settled()) {
                    if self.problem.is_some() { self.cleanup_cutoff_seen = true; self.fail_at(Problem::CleanupUnknown, end); }
                    else { self.fail_at(Problem::Interrupted, end); }
                }
            }
        }

        // A never-polled future has dispatched nothing. After ONE native poll
        // its original is retained through STOP, owner/stream/observer loss.
        let skip_unpolled = self.problem.is_some() && (matches!(self.pending.as_ref(), Some(Pending::Connect { polled: false, .. }))
            || (matches!(self.pending.as_ref(), Some(Pending::Rpc { polled: false, .. }))
                && matches!(self.phase, Phase::Calling(step) if !step.cleanup())));
        if skip_unpolled {
            if self.refuse_unpolled_pending().is_ok() { self.pending = None; }
            else { self.fail(Problem::CleanupUnknown); }
            self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
        }
        // Consume the actual raw boundary BEFORE even staging local shutdown.
        // In particular, never discard a genuine RemoveMatch NoneBefore turn
        // and let shutdown's own reader error substitute for it on a later poll.
        if reconciling {
            if !has_boundary || matches!(turn, StreamTurn::Failed | StreamTurn::Ended) {
                self.finish_reply(false); cx.waker().wake_by_ref();
            } else if matches!(turn, StreamTurn::Drained) {
                self.finish_reply(true); cx.waker().wake_by_ref();
            }
        }
        self.poll_shutdown(cx); // Already-entered cleanup is never gated anew.
        if self.phase == Phase::AwaitPrompt && self.pending.is_none() && !self.raw_pending {
            if self.problem.is_some() {
                if matches!(turn, StreamTurn::Failed | StreamTurn::Ended) { self.abandon_profile_remote(); }
                self.cleanup_or_hold();
            } else if let Err(problem) = self.progress_prompt() { self.fail(problem); self.cleanup_or_hold(); }
        }
        if self.sdk_resources_settled() && self.profile.as_ref().is_some_and(|profile| !profile.native_released
            && (profile.sdk_constructed || self.problem.is_some())) {
            self.stage_native_release();
        }
        if matches!(self.phase, Phase::Native(step) if step != ProviderStep::Release) && self.problem.is_some()
            && self.profile.as_ref().is_some_and(|profile| matches!(profile.native_progress, NativeProgress::Ready(_))) {
            self.cleanup_or_hold();
        }
        if self.resources_settled() && self.entered { return Poll::Ready(Next::Settled); }
        if let Phase::Native(step) = self.phase {
            if self.provider_step_ready(step) && (matches!(turn, StreamTurn::Idle)
                || step == ProviderStep::Release && self.sdk_resources_settled()) {
                return Poll::Ready(match step {
                    ProviderStep::Acquire => Next::ProviderAcquire, ProviderStep::Bind => Next::ProviderBind,
                    ProviderStep::Recheck => Next::ProviderRecheck, ProviderStep::Release => Next::ProviderRelease,
                });
            }
        }
        if matches!(self.shutdown, Shutdown::Staged(_)) {
            // Drive a retained original before the FINAL gate, never after it
            // and before the first shutdown poll. A stalled RPC cannot prevent
            // this independent local shutdown admission.
            if !self.never_polled() && self.poll_pending(cx) {
                // A newly returned original has not had its own boundary
                // sampled yet. Give it one next bounded stream turn before the
                // final gate; a still-Pending original never blocks shutdown.
                cx.waker().wake_by_ref(); return Poll::Pending;
            }
            self.shutdown_ready = true;
            return Poll::Ready(Next::FirstPollShutdown);
        }
        if self.expected_shutdown() { return Poll::Ready(Next::AdmitShutdown); }
        if matches!(self.pending.as_ref(), Some(Pending::Rpc { polled: false, .. }))
            && !(matches!(turn, StreamTurn::Idle)
                || (matches!(self.phase, Phase::Calling(step) if step.cleanup()) && matches!(turn, StreamTurn::Failed | StreamTurn::Ended)))
        {
            // A message that arrived after serialized admission may have another
            // owner event behind it. Finish the bounded nonblocking drain before
            // FIRST dispatch; already-polled originals below are always driven.
            if matches!(turn, StreamTurn::Observed(_)) { cx.waker().wake_by_ref(); }
            return Poll::Pending;
        }

        if self.never_polled() {
            // Stream work is finished. The caller now takes document -> book,
            // checks the actual current slot/cutoff, releases the document and
            // invokes first_poll immediately, with NO intervening stream work.
            self.first_poll_ready = true;
            return Poll::Ready(Next::FirstPoll);
        }
        if self.poll_pending(cx) { return Poll::Pending; }
        if reconciling && !self.raw_pending { return Poll::Pending; }

        if matches!(turn, StreamTurn::Observed(_)) { cx.waker().wake_by_ref(); }
        if let Phase::Admit(step) = self.phase {
            if self.shutdown != Shutdown::Unrequested {
                self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
            }
            if !step.cleanup() && self.problem.is_some() {
                self.cleanup_or_hold(); cx.waker().wake_by_ref(); return Poll::Pending;
            }
            // Idle here is a FINAL nonblocking drain, not an ordering receipt.
            // The caller now checks the real document/slot/stop before admit().
            if matches!(turn, StreamTurn::Idle) || (step.cleanup() && matches!(turn, StreamTurn::Failed | StreamTurn::Ended)) {
                return Poll::Ready(Next::Admit(step));
            }
        }
        // A nonterminal stream is pumped even in Holding. Only the consumed
        // maintained join/disposal result, never Holding or reconciliation
        // itself, can complete a book.
        Poll::Pending
    }

    // Called either with consumed final admission or an already-polled original.
    // In the latter case STOP/Unknown/cutoff never causes re-adoption/cancellation.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> bool {
        match self.pending.as_mut() {
            Some(Pending::Connect { future, polled, .. }) => { *polled = true;
                let result = match future {
                    ConnectOriginal::Native => match self.attempt.as_mut() {
                        Some(attempt) => attempt.poll_build(cx),
                        None => Poll::Ready(Err(zbus::Error::InvalidField)),
                    },
                    #[cfg(test)]
                    ConnectOriginal::Data(future) => future.as_mut().poll(cx),
                };
                match result {
                Poll::Pending => {},
                Poll::Ready(Ok(())) => {
                    // Connection/stream/task never leave the retained SDK
                    // attempt, including an original failed startup.
                    self.pending = None;
                    self.phase = if self.problem.is_none() { Phase::Admit(Step::AddMatch) } else { Phase::Holding };
                    cx.waker().wake_by_ref(); return true;
                }
                Poll::Ready(Err(error)) => {
                    self.connect_failure = Some(error); self.pending = None;
                    self.fail(Problem::Unavailable); self.phase = Phase::Holding;
                    return true; // This result alone is not the original reader join.
                }
            } },
            Some(Pending::Rpc { future, polled, .. }) => {
                if !*polled {
                    match self.phase {
                        Phase::Calling(Step::AddMatch) => self.registration = Registration::Possible,
                        Phase::Calling(Step::OpenSession) => self.session = RemoteSession::Possible,
                        Phase::Calling(Step::CloseSession) => self.session = RemoteSession::Closing,
                        Phase::Calling(Step::AddManagerMatch) => if let Some(profile) = self.profile.as_mut() { profile.manager_registration = Registration::Possible; },
                        Phase::Calling(Step::AddPromptMatch) => if let Some(profile) = self.profile.as_mut() { profile.prompt_registration = Registration::Possible; },
                        Phase::Calling(Step::Unlock) => if let Some(profile) = self.profile.as_mut() { profile.unlock_attempted = true; },
                        Phase::Calling(Step::CreateItem) => if let Some(profile) = self.profile.as_mut() {
                            profile.creation = Creation::Possible; profile.encrypted = None;
                        },
                        Phase::Calling(Step::Prompt | Step::Dismiss) => if let Some(profile) = self.profile.as_mut() {
                            if let Ok(prompt) = profile.current_mut() {
                                if self.phase == Phase::Calling(Step::Prompt) { prompt.invoked = true; }
                                else { prompt.dismiss_entered = true; }
                            }
                        },
                        _ => {}
                    }
                }
                *polled = true;
                let result = match future {
                    RpcOriginal::Native => match self.attempt.as_mut() {
                        Some(attempt) => attempt.poll_raw_call(cx),
                        None => Poll::Ready(Err(zbus::Error::InvalidField)),
                    },
                    #[cfg(test)]
                    RpcOriginal::Data(future) => future.as_mut().poll(cx),
                };
                if let Poll::Ready(result) = result {
                    // Failure is known now, not at a later observer/drain tick.
                    // The raw result is nevertheless retained and reconciled.
                    if result.is_err() { self.fail(Problem::Unavailable); }
                    self.raw = Some(result); self.raw_pending = true; self.pending = None;
                    cx.waker().wake_by_ref(); return true;
                }
            }
            None => {}
        }
        false
    }

    fn finish_reply(&mut self, reconciled: bool) {
        self.raw_pending = false;
        let Phase::Calling(step) = self.phase else { self.fail(Problem::CleanupUnknown); self.phase = Phase::Holding; return; };
        let result = self.decode_reply(step, reconciled);
        if step == Step::CloseSession {
            if result.is_ok() { self.session = RemoteSession::Closed; }
            else {
                self.session = RemoteSession::Unknown;
                self.close_error = Some(match self.raw.as_ref() {
                    Some(Err(error)) => error_class(error), _ => ErrorClass::Protocol,
                });
                self.fail(Problem::CleanupUnknown);
            }
            // Session.Close is NOT the final bus removal. Its raw Message is
            // retained through this reconciliation and successor admission.
            self.cleanup_or_hold(); return;
        }
        if step == Step::RemoveMatch {
            self.removal_reply = Some(if result.is_ok() {
                RemovalReply::Confirmed
            } else {
                let error = match self.raw.as_ref() {
                    Some(Err(error)) => error_class(error),
                    _ => ErrorClass::Protocol,
                };
                // Latch failure NOW, before another admission or observer tick.
                // The prior raw Err clock, if any, remains authoritative.
                self.fail(Problem::CleanupUnknown);
                RemovalReply::Failed(error)
            });
            // No successor can replace this final raw slot. Its owning Message
            // and private stream stay retained until admitted local disposal.
            // Defer only semantic Unknown while staging the local stop; prior
            // document/slot Unknown still forbids admission, unchanged.
            if matches!(self.shutdown, Shutdown::Entered | Shutdown::Settled | Shutdown::Refused) {
                self.commit_removal_reply();
            }
            self.phase = Phase::Holding; return;
        }
        if matches!(step, Step::RemovePromptMatch | Step::RemoveManagerMatch) {
            if let Some(profile) = self.profile.as_mut() {
                let registration = if step == Step::RemovePromptMatch { &mut profile.prompt_registration }
                    else { &mut profile.manager_registration };
                *registration = if result.is_ok() { Registration::Removed } else { Registration::Unknown };
            }
            if result.is_err() { self.fail(Problem::CleanupUnknown); }
            self.cleanup_or_hold(); return;
        }
        if let Err(problem) = result { self.fail(problem); }
        if step == Step::OpenSession && self.session == RemoteSession::Possible {
            // A dispatched malformed/error reply supplies no trustworthy path.
            self.session = RemoteSession::Unknown; self.fail(Problem::CleanupUnknown);
        }
        if let Some(profile) = self.profile.as_mut() {
            if step == Step::CreateItem && result.is_err() && profile.creation == Creation::Possible {
                profile.creation = Creation::Unknown;
            }
            if step == Step::Dismiss && result.is_err() {
                if let Ok(prompt) = profile.current_mut() { prompt.unknown = true; }
            }
        }
        if self.problem.is_some() { self.cleanup_or_hold(); return; }
        if let Err(problem) = self.progress_reply(step) { self.fail(problem); self.cleanup_or_hold(); }
    }
    fn progress_reply(&mut self, step: Step) -> Result<(), Problem> {
        match step {
            Step::AddMatch => self.phase = Phase::Admit(if self.profile.is_some() { Step::AddManagerMatch } else { Step::GetNameOwner }),
            Step::AddManagerMatch => self.phase = Phase::Admit(Step::GetNameOwner),
            Step::GetNameOwner => self.phase = Phase::Admit(if self.profile.is_some() { Step::GetManagerOwner } else { Step::SearchItems }),
            Step::GetManagerOwner => self.phase = Phase::Admit(Step::ProviderUser),
            Step::ProviderUser => self.phase = Phase::Admit(Step::ProviderPid),
            Step::ProviderPid => match self.profile.as_ref().ok_or(Problem::CleanupUnknown)?.round {
                CredentialRound::Initial => self.stage_native(ProviderStep::Bind)?,
                CredentialRound::Bound => self.phase = Phase::Admit(Step::GetUnit),
                CredentialRound::Final => {
                    let profile = self.profile.as_ref().ok_or(Problem::CleanupUnknown)?;
                    if !profile.native_rechecked || profile.user_rounds != 7 || profile.process_rounds != 7 {
                        return Err(Problem::UnsupportedProvider);
                    }
                    self.phase = Phase::Admit(Step::CloseSession);
                }
            },
            Step::GetUnit => self.phase = Phase::Admit(Step::UnitProperty(checked_lookup::UnitProperty::Id)),
            Step::UnitProperty(property) => self.phase = Phase::Admit(property.next().map(Step::UnitProperty).unwrap_or(Step::LoginAlias)),
            Step::LoginAlias => self.phase = Phase::Admit(Step::SessionAlias),
            Step::SessionAlias => self.phase = Phase::Admit(if self.profile.as_ref().ok_or(Problem::CleanupUnknown)?.initialize {
                Step::CollectionLocked
            } else { Step::SearchItems }),
            Step::SearchItems => {
                if self.candidate.is_some() { self.phase = Phase::Admit(Step::Attributes); }
                else if self.profile.as_ref().is_some_and(|profile| profile.initialize && profile.absence_proved && profile.creation == Creation::Unsent) {
                    self.phase = Phase::Admit(Step::OpenSession);
                } else { return Err(Problem::MissingKey); }
            }
            Step::Attributes => self.phase = Phase::Admit(Step::Locked),
            Step::Locked | Step::CollectionLocked => {
                if self.profile.as_ref().is_some_and(|profile| profile.target_locked) {
                    let target = if step == Step::CollectionLocked {
                        Arc::new(self.query.as_ref().ok_or(Problem::CleanupUnknown)?.collection.clone())
                    } else { self.candidate.clone().ok_or(Problem::CleanupUnknown)? };
                    let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                    if profile.unlock_attempted { return Err(Problem::Locked); }
                    profile.unlock_target = Some(target);
                    self.prompt_match_then(Step::Unlock)?;
                } else { self.phase = Phase::Admit(if step == Step::CollectionLocked { Step::SearchItems }
                    else if self.session == RemoteSession::Known { Step::GetSecret } else { Step::OpenSession }); }
            }
            Step::AddPromptMatch => {
                let step = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?.after_prompt_match.take().ok_or(Problem::CleanupUnknown)?;
                self.phase = Phase::Admit(step);
            }
            Step::Unlock | Step::CreateItem => {
                if self.profile.as_ref().ok_or(Problem::CleanupUnknown)?.current_prompt.is_some() {
                    self.phase = Phase::Admit(Step::Prompt);
                } else if step == Step::CreateItem { self.phase = Phase::Admit(Step::SearchItems); }
                else { self.phase = Phase::Admit(self.unlock_recheck_step()?); }
            }
            Step::Prompt | Step::Dismiss => self.phase = Phase::AwaitPrompt,
            Step::OpenSession => {
                if self.profile.as_ref().is_some_and(|profile| profile.initialize) { self.prompt_match_then(Step::CreateItem)?; }
                else { self.phase = Phase::Admit(Step::GetSecret); }
            }
            Step::GetSecret => {
                if self.profile.is_some() { self.stage_native(ProviderStep::Recheck)?; }
                else { self.phase = Phase::Admit(Step::CloseSession); }
            }
            Step::CloseSession | Step::RemoveMatch | Step::RemovePromptMatch | Step::RemoveManagerMatch => return Err(Problem::CleanupUnknown),
        }
        Ok(())
    }
    fn unlock_recheck_step(&self) -> Result<Step, Problem> {
        let profile = self.profile.as_ref().ok_or(Problem::CleanupUnknown)?;
        Ok(if profile.initialize { Step::CollectionLocked } else { Step::Locked })
    }
    fn progress_prompt(&mut self) -> Result<(), Problem> {
        let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
        let prompt = profile.current()?;
        if !prompt.complete() { return Ok(()); }
        if self.problem.is_some() { self.cleanup_or_hold(); return Ok(()); }
        if !prompt.invoked || !prompt.method_returned { return Ok(()); }
        let next = match prompt.completion.as_ref().ok_or(Problem::CleanupUnknown)? {
            CompletionFact::Dismissed => return Err(Problem::Denied),
            CompletionFact::Invalid => return Err(Problem::InvalidReply),
            CompletionFact::Unlocked => if profile.initialize { Step::CollectionLocked } else { Step::Locked },
            CompletionFact::Created(path) => {
                if profile.creation != Creation::Known || profile.created_item.as_ref().is_none_or(|item| item.as_str() != path.as_str()) {
                    return Err(Problem::InvalidReply);
                }
                Step::SearchItems
            }
        };
        profile.current_prompt = None;
        self.phase = Phase::Admit(next);
        Ok(())
    }
    fn commit_removal_reply(&mut self) {
        match self.removal_reply {
            Some(RemovalReply::Confirmed) => self.registration = Registration::Removed,
            Some(RemovalReply::Failed(error)) => {
                self.cleanup_error = Some(error);
                self.registration = Registration::Unknown;
                self.fail(Problem::CleanupUnknown);
            }
            None => {}
        }
    }
    fn decode_reply(&mut self, step: Step, reconciled: bool) -> Result<(), Problem> {
        let result = self.raw.as_ref().ok_or(Problem::CleanupUnknown)?;
        // Retain the original MethodError Message through the exact same stream
        // gate as success. Never FDO-convert/format it or invent a sequence.
        let message = result.as_ref().map_err(|_| Problem::Unavailable)?;
        let body = message.body();
        if step == Step::OpenSession {
            let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
            let (peer, path) = checked_lookup::decode_open_session(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
            // Retain owner-validated cleanup custody before STOP/DH refusal.
            self.session_path = Some(Arc::new(OwnedObjectPath::try_from(path.to_owned()).map_err(|_| Problem::InvalidReply)?));
            self.session = RemoteSession::Known;
            if !reconciled { return Err(Problem::StreamFailed); }
            if let Some(problem) = self.problem { return Err(problem); }
            if self.shutdown != Shutdown::Unrequested { return Err(Problem::CleanupUnknown); }
            let exchange = self.exchange.take().ok_or(Problem::CleanupUnknown)?;
            let key = exchange.derive(peer).map_err(|_| Problem::Crypto)?;
            if let Some(profile) = self.profile.as_mut().filter(|profile| profile.initialize) {
                if profile.admitted.is_none() || !profile.absence_proved || profile.creation != Creation::Unsent || profile.encrypted.is_some() {
                    return Err(Problem::CleanupUnknown);
                }
                let proposal = profile.proposal.take().ok_or(Problem::CleanupUnknown)?;
                // Proposal bytes never become a lease. This single consuming
                // synchronous call returns the SAME transport key, to be used
                // only by the later ACTUAL GetSecret readback.
                let (_, encrypted) = proposal.consume_for_transport(|wrapping| key.encrypt_wrapping_key(wrapping));
                let (key, iv, ciphertext) = encrypted.map_err(|_| Problem::Crypto)?;
                profile.encrypted = Some((iv, ciphertext)); self.session_key = Some(key);
            } else { self.session_key = Some(key); }
            return Ok(());
        }
        if matches!(step, Step::Unlock | Step::CreateItem) {
            let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
            let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
            if step == Step::Unlock {
                let (target, prompt) = checked_lookup::decode_unlock(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
                profile.retain_prompt(prompt, checked_lookup::PromptRole::Unlock)?;
                let expected = profile.unlock_target.as_ref().ok_or(Problem::CleanupUnknown)?;
                if !(target == Some(expected.as_str()) && prompt == "/" || target.is_none() && prompt != "/") {
                    return Err(Problem::InvalidReply);
                }
            } else {
                let (item, prompt) = checked_lookup::decode_created_item(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
                profile.retain_prompt(prompt, checked_lookup::PromptRole::Create)?;
                if item != "/" {
                    profile.created_item = Some(Arc::new(OwnedObjectPath::try_from(item.to_owned()).map_err(|_| Problem::InvalidReply)?));
                }
                if item != "/" && prompt == "/" { profile.creation = Creation::Known; }
                else if !(item == "/" && prompt != "/") { profile.creation = Creation::Unknown; return Err(Problem::InvalidReply); }
            }
            if !reconciled { return Err(Problem::StreamFailed); }
            if let Some(problem) = self.problem { return Err(problem); }
            if self.shutdown != Shutdown::Unrequested { return Err(Problem::CleanupUnknown); }
            return Ok(());
        }
        if matches!(step, Step::Prompt | Step::Dismiss) {
            let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
            checked_lookup::check_empty_owner_reply(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
            let prompt = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?.current_mut()?;
            if step == Step::Prompt { prompt.method_returned = true; } else { prompt.dismiss_returned = true; }
            // These are actual method facts only. They NEVER set completion.
            if !reconciled { return Err(Problem::StreamFailed); }
            return Ok(());
        }
        if !reconciled { return Err(Problem::StreamFailed); }
        match step {
            Step::AddMatch => {
                checked_lookup::check_empty_bus_reply(&body).map_err(|_| Problem::InvalidReply)?;
                self.registration = Registration::Registered;
            }
            Step::AddManagerMatch | Step::AddPromptMatch => {
                checked_lookup::check_empty_bus_reply(&body).map_err(|_| Problem::InvalidReply)?;
                let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                if step == Step::AddManagerMatch { profile.manager_registration = Registration::Registered; }
                else { profile.prompt_registration = Registration::Registered; }
            }
            Step::RemoveMatch | Step::RemoveManagerMatch | Step::RemovePromptMatch => {
                checked_lookup::check_empty_bus_reply(&body).map_err(|_| Problem::InvalidReply)?;
            }
            Step::CloseSession => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::check_empty_owner_reply(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
            }
            _ if self.problem.is_some() => return Err(self.problem.unwrap_or(Problem::CleanupUnknown)),
            Step::GetNameOwner => {
                if self.owner.is_some() { return Err(Problem::CleanupUnknown); }
                let name = checked_lookup::decode_name_owner(&body).map_err(|_| Problem::InvalidReply)?;
                self.owner = Some(Arc::new(UniqueName::try_from(name.to_owned()).map_err(|_| Problem::InvalidReply)?));
            }
            Step::GetManagerOwner => {
                let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                if profile.manager.is_some() { return Err(Problem::CleanupUnknown); }
                let name = checked_lookup::decode_name_owner(&body).map_err(|_| Problem::InvalidReply)?;
                profile.manager = Some(Arc::new(UniqueName::try_from(name.to_owned()).map_err(|_| Problem::InvalidReply)?));
            }
            Step::ProviderUser | Step::ProviderPid => {
                let value = checked_lookup::decode_bus_identity(&body).map_err(|_| Problem::InvalidReply)?;
                let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                let bit = profile.round.bit();
                if step == Step::ProviderUser {
                    if profile.user_rounds & bit != 0 { return Err(Problem::CleanupUnknown); }
                    if value != profile.uid { return Err(Problem::UnsupportedProvider); }
                    profile.user_rounds |= bit;
                } else {
                    if profile.process_rounds & bit != 0 || profile.user_rounds & bit == 0 { return Err(Problem::CleanupUnknown); }
                    if value == 0 || value > i32::MAX as u32 { return Err(Problem::UnsupportedProvider); }
                    if profile.round == CredentialRound::Initial {
                        if profile.pid.replace(value).is_some() { return Err(Problem::CleanupUnknown); }
                    } else if profile.pid != Some(value) { return Err(Problem::UnsupportedProvider); }
                    profile.process_rounds |= bit;
                }
            }
            Step::GetUnit => {
                let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                if profile.unit.is_some() { return Err(Problem::CleanupUnknown); }
                let manager = profile.manager.as_ref().ok_or(Problem::CleanupUnknown)?;
                let path = checked_lookup::decode_unit_path(&body, manager.as_ref()).map_err(|_| Problem::UnsupportedProvider)?;
                profile.unit = Some(Arc::new(OwnedObjectPath::try_from(path.to_owned()).map_err(|_| Problem::InvalidReply)?));
            }
            Step::UnitProperty(property) => {
                let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                let bit = 1u16 << property as u32;
                if profile.policy & bit != 0 { return Err(Problem::CleanupUnknown); }
                checked_lookup::check_gnome_unit_property(&body, profile.manager.as_ref().ok_or(Problem::CleanupUnknown)?.as_ref(),
                    property, profile.pid.ok_or(Problem::CleanupUnknown)?, &profile.control_argument).map_err(|_| Problem::UnsupportedProvider)?;
                profile.policy |= bit;
            }
            Step::LoginAlias | Step::SessionAlias => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let path = checked_lookup::decode_read_alias(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
                if path == "/" { return Err(Problem::UnsupportedProvider); }
                let profile = self.profile.as_mut().ok_or(Problem::CleanupUnknown)?;
                if step == Step::LoginAlias {
                    if profile.login_checked { return Err(Problem::CleanupUnknown); }
                    let query = self.query.as_mut().and_then(Arc::get_mut).ok_or(Problem::CleanupUnknown)?;
                    query.collection = OwnedObjectPath::try_from(path.to_owned()).map_err(|_| Problem::InvalidReply)?;
                    profile.login_checked = true;
                } else {
                    if !profile.login_checked || profile.session_checked { return Err(Problem::CleanupUnknown); }
                    if self.query.as_ref().ok_or(Problem::CleanupUnknown)?.collection.as_str() == path { return Err(Problem::UnsupportedProvider); }
                    profile.session_checked = true;
                }
            }
            Step::SearchItems => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let path = checked_lookup::decode_item_path(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
                if let Some(profile) = self.profile.as_mut().filter(|profile| profile.initialize) {
                    match profile.creation {
                        Creation::Unsent => {
                            if profile.absence_proved { return Err(Problem::CleanupUnknown); }
                            if path.is_some() { return Err(Problem::IdentityMismatch); }
                            profile.absence_proved = true; self.observation = Some(Observation::Absent);
                        }
                        Creation::Known => {
                            let item = profile.created_item.as_ref().ok_or(Problem::CleanupUnknown)?;
                            if path != Some(item.as_str()) { return Err(Problem::IdentityMismatch); }
                            self.candidate = Some(item.clone());
                        }
                        _ => return Err(Problem::CleanupUnknown),
                    }
                } else { match path {
                    Some(path) => self.candidate = Some(Arc::new(OwnedObjectPath::try_from(path.to_owned()).map_err(|_| Problem::InvalidReply)?)),
                    None => { self.observation = Some(Observation::Absent); return Err(Problem::MissingKey); }
                } }
            }
            Step::Attributes => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let query = self.query.as_ref().ok_or(Problem::CleanupUnknown)?;
                checked_lookup::check_attributes(&body, owner.as_ref(), &query.attributes()).map_err(|_| Problem::IdentityMismatch)?;
                self.observation = Some(Observation::Candidate(self.candidate.clone().ok_or(Problem::CleanupUnknown)?));
            }
            Step::Locked | Step::CollectionLocked => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let locked = checked_lookup::decode_locked(&body, owner.as_ref()).map_err(|_| Problem::InvalidReply)?;
                if let Some(profile) = self.profile.as_mut() {
                    profile.target_locked = locked;
                    if locked && (profile.unlock_attempted || profile.initialize && profile.creation != Creation::Unsent) { return Err(Problem::Locked); }
                } else if locked { return Err(Problem::Locked); } // Legacy fixtures never follow prompts.
            }
            Step::GetSecret => {
                let owner = self.owner.as_ref().ok_or(Problem::CleanupUnknown)?;
                let session = self.session_path.as_ref().ok_or(Problem::CleanupUnknown)?;
                let (iv, ciphertext) = checked_lookup::decode_get_secret(&body, owner.as_ref(), session.as_ref()).map_err(|_| Problem::InvalidReply)?;
                let key = self.session_key.take().ok_or(Problem::CleanupUnknown)?;
                self.key_candidate = Some(key.decrypt_wrapping_key(iv, ciphertext).map_err(|_| Problem::Crypto)?);
            }
            Step::OpenSession | Step::Unlock | Step::CreateItem | Step::Prompt | Step::Dismiss => return Err(Problem::CleanupUnknown),
        }
        Ok(())
    }

}

#[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
fn fixture_step_index(step: Step) -> Option<usize> {
    Some(match step { Step::AddMatch => 1, Step::GetNameOwner => 2, Step::SearchItems => 3,
        Step::Attributes => 4, Step::Locked => 5, Step::OpenSession => 6, Step::GetSecret => 7,
        Step::CloseSession => 8, Step::RemoveMatch => 9, _ => return None })
}

/// Closed nonsecret component observations, never a provider/persistence grant.
#[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeFixtureSnapshot {
    pub(crate) first_polls: [u8; 11],
    pub(crate) owner_matches: bool,
    pub(crate) candidate_present: bool,
    pub(crate) settled_canary: bool,
    pub(crate) session_closed: bool,
    pub(crate) session_unknown: bool,
    pub(crate) subscription_removed: bool,
    pub(crate) local: Option<LocalSettlement>,
    pub(crate) resources_settled: bool,
    pub(crate) charged: bool,
    pub(crate) problem: Option<Problem>,
    pub(crate) problem_at: Option<Instant>,
}
#[cfg(all(test, debug_assertions, not(feature = "desktop-shell")))]
impl LookupBook {
    pub(crate) fn native_fixture_snapshot(&self, expected_owner: &str) -> NativeFixtureSnapshot {
        NativeFixtureSnapshot { first_polls: self.fixture_first_polls,
            owner_matches: self.owner.as_ref().is_some_and(|owner| owner.as_str() == expected_owner),
            candidate_present: self.key_candidate.is_some(),
            settled_canary: self.key_ready() && self.key_candidate.as_ref()
                .is_some_and(checked_lookup::test_support::is_native_canary),
            session_closed: self.session == RemoteSession::Closed,
            session_unknown: self.session == RemoteSession::Unknown,
            subscription_removed: self.registration == Registration::Removed,
            local: self.local_settlement, resources_settled: self.resources_settled(),
            charged: self.memory_held(), problem: self.problem, problem_at: self.problem_at }
    }
}

fn cleanup_progress_end(now: Instant, outer_end: Instant) -> Instant {
    outer_end.checked_duration_since(now).map_or(outer_end, |remaining| now + remaining / 2)
}

fn raw_message(result: &zbus::Result<Message>) -> Option<&Message> {
    match result { Ok(message) | Err(zbus::Error::MethodError(_, _, message)) => Some(message), _ => None }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamTurn { Idle, Pending, Observed(Option<Problem>), Drained, Failed, Ended, Reconciled }

fn stream_turn<S>(stream: &mut S, cx: &mut Context<'_>, before: Option<&S::Ordering>) -> StreamTurn
where S: OrderedStream<Data = zbus::Result<Message>> + Unpin {
    stream_turn_observing(stream, cx, before, |message| observe_message(None, None, message))
}
fn stream_turn_observing<S>(stream: &mut S, cx: &mut Context<'_>, before: Option<&S::Ordering>,
    observe: impl FnOnce(&Message) -> Option<Problem>) -> StreamTurn
where S: OrderedStream<Data = zbus::Result<Message>> + Unpin {
    match Pin::new(stream).poll_next_before(cx, before) {
        Poll::Pending if before.is_none() => StreamTurn::Idle,
        Poll::Pending => StreamTurn::Pending,
        Poll::Ready(PollResult::NoneBefore) if before.is_some() => StreamTurn::Drained,
        Poll::Ready(PollResult::NoneBefore) => StreamTurn::Failed,
        Poll::Ready(PollResult::Terminated) => StreamTurn::Ended,
        Poll::Ready(PollResult::Item { data: Err(_), .. }) => StreamTurn::Failed,
        Poll::Ready(PollResult::Item { data: Ok(message), .. }) => {
            // Do NOT discard Item merely because its ordering is >= before:
            // an already-observed later owner change refuses progression too.
            StreamTurn::Observed(observe(&message))
        }
    }
}
fn observe_message(profile: Option<&mut Profile>, owner: Option<&UniqueName<'_>>, message: &Message) -> Option<Problem> {
    let header = message.header();
    if header.message_type() == Type::Signal && header.sender().map(|name| name.as_str()) == Some(BUS)
        && header.member().map(|name| name.as_str()) == Some("NameOwnerChanged") {
        return Some(if checked_lookup::decode_owner_changed(&message.body()).is_ok()
            || profile.is_some() && checked_lookup::decode_manager_changed(&message.body()).is_ok() {
            Problem::OwnerChanged
        } else { Problem::InvalidReply });
    }
    let (Some(profile), Some(owner)) = (profile, owner) else { return None; };
    if header.message_type() != Type::Signal || header.sender().map(|name| name.as_str()) != Some(owner.as_str())
        || header.interface().map(|name| name.as_str()) != Some("org.freedesktop.Secret.Prompt")
        || header.member().map(|name| name.as_str()) != Some("Completed") { return None; }
    let Some(index) = profile.prompts.iter().position(|prompt| prompt.as_ref()
        .is_some_and(|prompt| Some(prompt.path.as_str()) == header.path().map(|path| path.as_str()))) else { return None; };
    let prompt = profile.prompts[index].as_ref()?;
    // Foreign/earlier/duplicate signals cannot settle a later prompt. Keep
    // original complete facts on duplication; never replace their sequence.
    if prompt.completion.is_some() || !prompt.invoked && !prompt.dismiss_entered { return Some(Problem::InvalidReply); }
    let role = prompt.role;
    let body = message.body();
    let completion = checked_lookup::decode_prompt_completed(&body, owner, prompt.path.as_ref(), role);
    let (fact, problem) = match completion {
        Ok(checked_lookup::PromptCompletion::Dismissed) => {
            if role == checked_lookup::PromptRole::Create && profile.creation == Creation::Possible { profile.creation = Creation::Unknown; }
            (CompletionFact::Dismissed, Some(Problem::Denied))
        }
        Ok(checked_lookup::PromptCompletion::Unlocked(path)) => {
            if path.is_some() && path == profile.unlock_target.as_ref().map(|target| target.as_str()) {
                (CompletionFact::Unlocked, None)
            } else { (CompletionFact::Invalid, Some(Problem::InvalidReply)) }
        }
        Ok(checked_lookup::PromptCompletion::Created(path)) => {
            if path == "/" || !profile.initialize || !matches!(profile.creation, Creation::Possible | Creation::Unknown) {
                (CompletionFact::Invalid, Some(Problem::InvalidReply))
            } else {
                let Ok(path) = OwnedObjectPath::try_from(path.to_owned()) else { return Some(Problem::InvalidReply); };
                let path = Arc::new(path); profile.created_item = Some(path.clone()); profile.creation = Creation::Known;
                (CompletionFact::Created(path), None)
            }
        }
        Err(_) => {
            if let Some(prompt) = profile.prompts[index].as_mut() { prompt.unknown = true; }
            return Some(Problem::InvalidReply);
        }
    };
    if let Some(prompt) = profile.prompts[index].as_mut() {
        prompt.completion = Some(fact); prompt.position = Some(message.recv_position()); prompt.reconciled = false;
    }
    // Only bounded facts and this ACTUAL sequence survive the turn, never a
    // second retained Message/FD slot or a caller-supplied ordering number.
    problem
}

// Fixed data/handle cells inside LookupBook, not a second owner or task. Only
// its registered OriginalWork native child may call these synchronous methods.
mod provider_files {
    use super::Problem;
    use std::{mem::ManuallyDrop, os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd}};
    use rustix::{fs::{self, AtFlags, FileType, Mode, OFlags, Stat}, io, process};
    use sha2::{Digest, Sha256};

    const SLOTS: usize = 16;
    const BLOCK: usize = 4096;
    const DAEMON: usize = 3;
    const PROC: usize = 12;
    const PROCESS: usize = 13;
    const PIDFD: usize = 14;
    const EXE: usize = 15;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State { Vacant, Reserved, Entered, Held, NoHandle, Closing, Closed, Unknown }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Fingerprint {
        dev: u64, ino: u64, mode: u32, uid: u32, gid: u32, links: u64, bytes: i64,
        modified: (i64, i64), changed: (i64, i64),
    }
    impl Fingerprint {
        fn of(stat: &Stat) -> Result<Self, Problem> {
            let modified = i64::try_from(stat.st_mtime_nsec).map_err(|_| Problem::UnsupportedProvider)?;
            let changed = i64::try_from(stat.st_ctime_nsec).map_err(|_| Problem::UnsupportedProvider)?;
            if !(0..1_000_000_000).contains(&modified) || !(0..1_000_000_000).contains(&changed) {
                return Err(Problem::UnsupportedProvider);
            }
            Ok(Self { dev: stat.st_dev, ino: stat.st_ino, mode: stat.st_mode, uid: stat.st_uid,
                gid: stat.st_gid, links: stat.st_nlink, bytes: stat.st_size,
                modified: (stat.st_mtime, modified), changed: (stat.st_ctime, changed) })
        }
        fn same_directory(self, other: Self) -> bool {
            (self.dev, self.ino, self.mode, self.uid, self.gid) == (other.dev, other.ino, other.mode, other.uid, other.gid)
        }
        fn directory(self, uid: u32, private: bool) -> bool {
            FileType::from_raw_mode(self.mode) == FileType::Directory && self.uid == uid
                && if private { self.mode & 0o7777 == 0o700 } else { self.mode & 0o022 == 0 }
        }
        fn packaged_file(self, bytes: u64) -> bool {
            FileType::from_raw_mode(self.mode) == FileType::RegularFile && self.uid == 0
                && self.mode & 0o022 == 0 && self.bytes >= 0 && self.bytes as u64 == bytes && self.links != 0
        }
    }
    struct Slot {
        fd: Option<ManuallyDrop<OwnedFd>>, state: State, parent: Option<usize>, name: Box<str>,
        fingerprint: Option<Fingerprint>,
    }
    pub(super) struct Originals {
        slots: [Slot; SLOTS], bus: Option<Fingerprint>, acquired: bool, bound: bool,
        rechecked: bool, release_entered: bool,
    }
    fn checkpoint(stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
        if stop() { Err(Problem::Interrupted) } else { Ok(()) }
    }
    fn require(value: bool) -> Result<(), Problem> {
        if value { Ok(()) } else { Err(Problem::UnsupportedProvider) }
    }
    fn native(_: io::Errno) -> Problem { Problem::UnsupportedProvider }
    impl Originals {
        pub(super) fn new() -> Self {
            Self { slots: std::array::from_fn(|_| Slot { fd: None, state: State::Vacant,
                parent: None, name: "".into(), fingerprint: None }), bus: None,
                acquired: false, bound: false, rechecked: false, release_entered: false }
        }
        pub(super) fn acquired_and_bound(&self) -> bool {
            self.acquired && self.bound && !self.release_entered
                && self.slots.iter().all(|slot| slot.state == State::Held && slot.fd.is_some())
                && self.slots.iter().enumerate().all(|(index, slot)| matches!(index, PIDFD | EXE) || slot.fingerprint.is_some())
        }
        pub(super) fn settled(&self) -> bool {
            self.slots.iter().all(|slot| slot.fd.is_none()
                && matches!(slot.state, State::Vacant | State::NoHandle | State::Closed))
        }
        pub(super) fn unknown(&self) -> bool {
            self.slots.iter().any(|slot| matches!(slot.state, State::Entered | State::Closing | State::Unknown))
                || self.release_entered && !self.settled()
        }
        fn fd(&self, index: usize) -> Result<BorrowedFd<'_>, Problem> {
            self.slots.get(index).filter(|slot| slot.state == State::Held)
                .and_then(|slot| slot.fd.as_ref()).map(|fd| fd.as_fd()).ok_or(Problem::CleanupUnknown)
        }
        fn arm(&mut self, index: usize, parent: Option<usize>, name: &str) -> Result<(), Problem> {
            if name.is_empty() || name.len() > 255 || name.contains('\0')
                || name.contains('/') && !(index == 0 && name == "/" && parent.is_none()) {
                return Err(Problem::InvalidInput);
            }
            if let Some(parent) = parent { self.fd(parent)?; }
            let slot = self.slots.get_mut(index).ok_or(Problem::Capacity)?;
            if slot.state != State::Vacant || slot.fd.is_some() { return Err(Problem::CleanupUnknown); }
            slot.name = name.into(); slot.parent = parent; slot.state = State::Reserved;
            Ok(())
        }
        fn open_armed(&mut self, index: usize, flags: OFlags, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            if self.slots.get(index).is_none_or(|slot| slot.state != State::Reserved || slot.fd.is_some()) {
                return Err(Problem::CleanupUnknown);
            }
            self.slots[index].state = State::Entered;
            let slot = &self.slots[index];
            let returned = match slot.parent {
                Some(parent) => self.fd(parent).and_then(|fd| fs::openat(fd, slot.name.as_ref(), flags, Mode::empty()).map_err(native)),
                None if index == 0 && slot.name.as_ref() == "/" => fs::open("/", flags, Mode::empty()).map_err(native),
                None => Err(Problem::CleanupUnknown),
            };
            match returned {
                Ok(fd) => { self.slots[index].fd = Some(ManuallyDrop::new(fd)); self.slots[index].state = State::Held; },
                Err(problem) => { self.slots[index].state = State::NoHandle; return Err(problem); },
            }
            checkpoint(stop) // Returned fd is already retained, even after STOP.
        }
        fn held(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<Fingerprint, Problem> {
            checkpoint(stop)?;
            let result = fs::fstat(self.fd(index)?).map_err(native);
            checkpoint(stop)?;
            Fingerprint::of(&result?)
        }
        fn named(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<Fingerprint, Problem> {
            checkpoint(stop)?;
            let slot = self.slots.get(index).ok_or(Problem::CleanupUnknown)?;
            let result = match slot.parent {
                Some(parent) => fs::statat(self.fd(parent)?, slot.name.as_ref(), AtFlags::SYMLINK_NOFOLLOW),
                None if index == 0 => fs::stat("/"),
                None => return Err(Problem::CleanupUnknown),
            }.map_err(native);
            checkpoint(stop)?;
            Fingerprint::of(&result?)
        }
        fn directory(&mut self, index: usize, parent: Option<usize>, name: &str, uid: u32,
            private: bool, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            self.arm(index, parent, name)?;
            let before = self.named(index, stop)?;
            require(before.directory(uid, private))?;
            self.open_armed(index, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, stop)?;
            let held = self.held(index, stop)?;
            require(before.same_directory(held) && before.same_directory(self.named(index, stop)?))?;
            self.slots[index].fingerprint = Some(held);
            Ok(())
        }
        fn file(&mut self, index: usize, parent: usize, name: &str, bytes: u64, digest: [u8; 32],
            scratch: &mut [u8; BLOCK], stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            self.arm(index, Some(parent), name)?;
            let before = self.named(index, stop)?;
            require(before.packaged_file(bytes))?;
            self.open_armed(index, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, stop)?;
            require(self.held(index, stop)? == before)?;
            let mut hash = Sha256::new(); let mut remaining = bytes;
            while remaining != 0 {
                checkpoint(stop)?;
                let count = io::read(self.fd(index)?, &mut scratch[..remaining.min(BLOCK as u64) as usize]).map_err(native);
                checkpoint(stop)?;
                let count = count?;
                require(count != 0 && count as u64 <= remaining)?;
                hash.update(&scratch[..count]); remaining -= count as u64;
            }
            checkpoint(stop)?;
            let eof = io::read(self.fd(index)?, &mut scratch[..1]).map_err(native);
            checkpoint(stop)?;
            require(eof? == 0 && <[u8; 32]>::from(hash.finalize()) == digest)?;
            require(self.held(index, stop)? == before && self.named(index, stop)? == before)?;
            self.slots[index].fingerprint = Some(before);
            Ok(())
        }
        fn bus(&self, uid: u32, stop: &mut dyn FnMut() -> bool) -> Result<Fingerprint, Problem> {
            checkpoint(stop)?;
            let stat = fs::statat(self.fd(11)?, "bus", AtFlags::SYMLINK_NOFOLLOW).map_err(native);
            checkpoint(stop)?;
            let value = Fingerprint::of(&stat?)?;
            require(value.uid == uid && FileType::from_raw_mode(value.mode) == FileType::Socket)?;
            Ok(value)
        }
        pub(super) fn acquire(&mut self, uid: u32, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            if self.acquired || self.release_entered || self.slots.iter().any(|slot| slot.state != State::Vacant) {
                return Err(Problem::CleanupUnknown);
            }
            let real_uid = process::getuid().as_raw(); let effective_uid = process::geteuid().as_raw();
            let real_gid = process::getgid().as_raw(); let effective_gid = process::getegid().as_raw();
            checkpoint(stop)?;
            require(uid != 0 && uid == real_uid && uid == effective_uid && real_gid == effective_gid)?;
            self.directory(0, None, "/", 0, false, stop)?;
            self.directory(1, Some(0), "usr", 0, false, stop)?;
            self.directory(2, Some(1), "bin", 0, false, stop)?;
            // The only hash scratch: no SDK/wire attempt exists in Acquire.
            let mut scratch = [0u8; BLOCK];
            self.file(3, 2, "gnome-keyring-daemon", 988488,
                [0xb7,0xb2,0x84,0x30,0x5f,0x8a,0x4c,0x4f,0x5c,0x5a,0x10,0x00,0xee,0x93,0xe2,0x2f,0x3d,0x7d,0xf4,0x92,0x5d,0xbf,0x2a,0x8f,0x3f,0x76,0x8a,0x66,0xb1,0x62,0x88,0x4d],
                &mut scratch, stop)?;
            self.directory(4, Some(1), "lib", 0, false, stop)?;
            self.directory(5, Some(4), "systemd", 0, false, stop)?;
            self.directory(6, Some(5), "user", 0, false, stop)?;
            self.file(7, 6, "gnome-keyring-daemon.service", 338,
                [0x00,0xfd,0x9d,0xc4,0x12,0xbe,0xf3,0xf3,0x1e,0x4c,0x45,0xd5,0x1e,0x5b,0x85,0xed,0x2b,0xc3,0x86,0x10,0x56,0xf3,0xd1,0x81,0xac,0x18,0xf2,0x66,0xf0,0x0d,0xa3,0x5d],
                &mut scratch, stop)?;
            self.file(8, 6, "gnome-keyring-daemon.socket", 157,
                [0xdc,0x52,0x50,0x51,0xed,0x16,0x13,0xed,0xb1,0x3f,0xd8,0x4c,0x63,0xdd,0x9d,0xb6,0x01,0x69,0x0e,0xa9,0xbc,0x3e,0x54,0x7f,0x0d,0x13,0xfb,0x2f,0x93,0xbd,0x44,0xfb],
                &mut scratch, stop)?;
            self.directory(9, Some(0), "run", 0, false, stop)?;
            self.directory(10, Some(9), "user", 0, false, stop)?;
            self.directory(11, Some(10), &uid.to_string(), uid, true, stop)?;
            self.bus = Some(self.bus(uid, stop)?);
            self.recheck_package(uid, stop)?;
            self.acquired = true;
            Ok(())
        }
        fn original(&self, index: usize) -> Result<Fingerprint, Problem> {
            self.slots.get(index).and_then(|slot| slot.fingerprint).ok_or(Problem::CleanupUnknown)
        }
        fn recheck_named(&self, index: usize, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            let expected = self.original(index)?;
            let held = self.held(index, stop)?;
            let named = self.named(index, stop)?;
            require(if FileType::from_raw_mode(expected.mode) == FileType::Directory {
                expected.same_directory(held) && expected.same_directory(named)
            } else { held == expected && named == expected })
        }
        fn recheck_package(&self, uid: u32, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            for index in 0..12 { self.recheck_named(index, stop)?; }
            require(self.bus == Some(self.bus(uid, stop)?))
        }
        fn procfs(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            let stat = fs::fstatfs(self.fd(PROC)?).map_err(native);
            checkpoint(stop)?;
            require(stat?.f_type as u64 == 0x9fa0)
        }
        fn alive(&self, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            let fd = self.fd(PIDFD)?;
            let mut descriptors = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)];
            // One borrowed original pidfd; timeout0 neither waits nor transfers ownership.
            let returned = nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::ZERO);
            checkpoint(stop)?;
            require(returned == Ok(0) && descriptors[0].revents() == Some(nix::poll::PollFlags::empty()))
        }
        fn current_image(&self, stop: &mut dyn FnMut() -> bool) -> Result<Fingerprint, Problem> {
            checkpoint(stop)?;
            // The ONLY deliberate magic-link follow: trusted original procfs,
            // retained numeric procdir and exactly its kernel-generated exe.
            let stat = fs::statat(self.fd(PROCESS)?, "exe", AtFlags::empty()).map_err(native);
            checkpoint(stop)?;
            Fingerprint::of(&stat?)
        }
        fn recheck_image(&self, uid: u32, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            self.alive(stop)?;
            self.procfs(stop)?;
            self.recheck_named(PROC, stop)?;
            self.recheck_named(PROCESS, stop)?;
            require(self.original(PROCESS)?.directory(uid, false))?;
            self.recheck_named(DAEMON, stop)?;
            let expected = self.original(DAEMON)?;
            require(self.held(EXE, stop)? == expected && self.current_image(stop)? == expected)?;
            self.alive(stop)
        }
        pub(super) fn bind(&mut self, uid: u32, pid: u32, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            if !self.acquired || self.bound || self.release_entered { return Err(Problem::CleanupUnknown); }
            require(pid != 0 && pid <= i32::MAX as u32)?;
            self.directory(PROC, Some(0), "proc", 0, false, stop)?;
            self.procfs(stop)?;
            self.arm(PIDFD, None, "pidfd")?;
            checkpoint(stop)?;
            let pid_value = process::Pid::from_raw(pid as i32).ok_or(Problem::UnsupportedProvider)?;
            self.slots[PIDFD].state = State::Entered;
            let returned = process::pidfd_open(pid_value, process::PidfdFlags::empty());
            match returned {
                Ok(fd) => { self.slots[PIDFD].fd = Some(ManuallyDrop::new(fd)); self.slots[PIDFD].state = State::Held; },
                Err(error) => { self.slots[PIDFD].state = State::NoHandle; return Err(native(error)); },
            }
            checkpoint(stop)?;
            self.alive(stop)?;
            self.directory(PROCESS, Some(PROC), &pid.to_string(), uid, false, stop)?;
            self.arm(EXE, Some(PROCESS), "exe")?;
            self.open_armed(EXE, OFlags::PATH | OFlags::CLOEXEC, stop)?;
            require(self.held(EXE, stop)? == self.original(DAEMON)?)?;
            self.recheck_package(uid, stop)?;
            self.recheck_image(uid, stop)?;
            // This pidfd pins only the process ACTUALLY acquired above. It does
            // not authenticate an earlier bus numeric incarnation or prevent
            // exec. The caller repeats original bus PID/owner reconciliation.
            self.bound = true;
            Ok(())
        }
        pub(super) fn recheck(&mut self, uid: u32, stop: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            checkpoint(stop)?;
            if !self.acquired || !self.bound || self.rechecked || self.release_entered { return Err(Problem::CleanupUnknown); }
            self.alive(stop)?;
            self.recheck_package(uid, stop)?;
            self.recheck_image(uid, stop)?;
            self.rechecked = true;
            Ok(())
        }
        pub(super) fn release(&mut self, expired: &mut dyn FnMut() -> bool) -> Result<(), Problem> {
            if self.release_entered { return Err(Problem::CleanupUnknown); }
            self.release_entered = true;
            let mut failed = false;
            for index in (0..SLOTS).rev() {
                let slot = &mut self.slots[index];
                match slot.state {
                    State::Vacant | State::NoHandle | State::Closed => continue,
                    State::Reserved if slot.fd.is_none() => { slot.state = State::NoHandle; continue; },
                    State::Held if slot.fd.is_some() => {},
                    _ => { slot.state = State::Unknown; failed = true; continue; },
                }
                if expired() { return Err(Problem::CleanupUnknown); }
                slot.state = State::Closing;
                let fd = slot.fd.take().ok_or(Problem::CleanupUnknown)?;
                // One consuming close attempt. Error/EINTR is permanent unknown;
                // never retry a numeric fd that the kernel may already reuse.
                let returned = nix::unistd::close(ManuallyDrop::into_inner(fd));
                match returned {
                    Ok(()) => slot.state = State::Closed,
                    Err(_) => { slot.state = State::Unknown; failed = true; },
                }
                // The actual return is recorded even after cutoff. Independent
                // next originals still require their own same-endpoint check.
            }
            if failed || !self.settled() { Err(Problem::CleanupUnknown) } else { Ok(()) }
        }
    }
}

#[cfg(test)]
impl LookupBook {
    pub(crate) fn constructor_refusal_data() -> Self {
        // Actual constructor-refusal bookkeeping, with no SDK/native original.
        let input = LookupInput::new(Path::new("/inert/not-opened"), "/collection", "data-vault", "data-generation").unwrap();
        let mut book = Self::new();
        assert_eq!(book.begin_constructed(input, Instant::now(),
            crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap(),
            |_| Err(zbus::Error::InvalidReply)), Err(Problem::Unavailable));
        book
    }
    // Actual-driver DATA seam for the real DocumentState/OriginalWork gate
    // regression. No Connection, stream, task or native receipt is fabricated.
    pub(crate) fn cleanup_data(dispatch_end: Instant, future: impl Future<Output = zbus::Result<Message>> + Send + 'static) -> Self {
        Self::cleanup_step_data(Step::RemoveMatch, dispatch_end, future)
    }
    pub(crate) fn cleanup_step_data(step: Step, dispatch_end: Instant,
        future: impl Future<Output = zbus::Result<Message>> + Send + 'static) -> Self {
        assert!(step.cleanup());
        let mut book = Self::new();
        book.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        book.phase = Phase::Admit(step); book.registration = Registration::Registered;
        if step == Step::CloseSession {
            book.session = RemoteSession::Known;
            book.session_path = Some(Arc::new(OwnedObjectPath::try_from("/session".to_owned()).unwrap()));
            book.owner = Some(Arc::new(UniqueName::try_from(":1.23".to_owned()).unwrap()));
        }
        book.admit_with(step, dispatch_end, |_, _| Ok(Box::pin(future))).unwrap();
        book
    }
    pub(crate) fn cleanup_progress_data(&self, at: Instant) -> (Option<Instant>, bool, bool, bool) {
        (self.call_end, self.local_shutdown_due(at), self.pending.is_some(), self.raw_pending)
    }
    pub(crate) fn idle_data_turn(&mut self, cx: &mut Context<'_>) -> Poll<Next> {
        self.advance(cx, StreamTurn::Idle)
    }
    pub(crate) fn shutdown_gate_data(dispatch_end: Instant) -> Self {
        // Only exercises the real document/one-use admission logic. There is
        // NO native attempt, task, connection or finality result in this book.
        let mut book = Self::new();
        book.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        book.phase = Phase::Calling(Step::RemoveMatch);
        book.registration = Registration::Registered;
        book.raw = Some(Err(zbus::Error::InvalidReply)); book.raw_pending = true;
        book.shutdown = Shutdown::Staged(dispatch_end);
        book.finish_reply(false); // Real terminal failure, not a caller receipt.
        book
    }
}

#[cfg(test)]
mod bounded_wire_tests {
    use zbus::connection::owned_test_support;

    #[test]
    fn bounded_frames_refuse_before_allocation() { owned_test_support::bounded_wire_frames(); }
    #[test]
    fn bounded_headers_refuse_before_generic_decode() { owned_test_support::bounded_wire_headers(); }
    #[test]
    fn bounded_serializer_and_control_census() { owned_test_support::bounded_wire_capacity(); }
    #[test]
    fn bounded_authentication_and_hello() { owned_test_support::bounded_wire_authentication(); }
    #[test]
    fn errors_complete_only_original_registrations() { owned_test_support::bounded_wire_error_registration(); }
    #[test]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    fn bounded_unix_original_rights_disposal() { owned_test_support::bounded_wire_original_rights_disposal(); }
}

#[cfg(test)]
mod original_finality_tests {
    use std::{future::Future, time::Duration};
    use zbus::connection::owned_test_support;

    async fn finite(check: impl Future<Output = ()>) {
        // Expiration is a test FAILURE, never evidence of task termination.
        tokio::time::timeout(Duration::from_secs(10), check).await
            .expect("owned SDK fixture did not consume its original work");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owned_task_join_outcomes() {
        finite(owned_test_support::original_task_join_outcomes()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_startup_error_roster() {
        finite(owned_test_support::original_startup_error_roster()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_startup_survives_observer_loss() {
        finite(owned_test_support::original_startup_survives_observer_loss()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_full_queue_reader_shutdown() {
        finite(owned_test_support::original_full_queue_reader_shutdown()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_raw_call_survives_observer_loss() {
        finite(owned_test_support::original_raw_call_survives_observer_loss()).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn owned_writer_close_failure() {
        finite(owned_test_support::original_writer_close_failure()).await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    async fn owned_unix_pending_authentication_shutdown() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::PathBuf::from(std::env::var_os("MRK_OWNED_UNIX_FIXTURE_ROOT")
            .expect("the native test owner must supply a private fixture directory"));
        assert!(root.is_absolute());
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        // The admitted owner validates ancestor/identity/ownership and cleans
        // ONLY this newly created pathname. No default or host bus fallback.
        finite(owned_test_support::unix_pending_authentication_shutdown(root.join("owned-startup.sock"))).await;
    }
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    async fn owned_keyring_peer_uid_before_authentication() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::PathBuf::from(std::env::var_os("MRK_OWNED_UNIX_FIXTURE_ROOT")
            .expect("the native test owner must supply a private fixture directory"));
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert!(root.is_absolute() && metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        finite(owned_test_support::keyring_unix_peer_uid_before_authentication(root.join("keyring-peer.sock"))).await;
    }
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires separately reviewed isolated Unix fixture admission"]
    async fn owned_unix_pending_write_and_received_fd_shutdown() {
        // LEGACY profile: the 8MiB write/received-FD fixture is deliberately
        // separate and is NOT evidence for the 64KiB/zero-FD Keyring profile.
        finite(owned_test_support::unix_pending_write_and_received_fd_shutdown()).await;
    }
}

#[cfg(test)]
mod tests {
    // DATA-only: no bus/socket/file/provider/task is opened or launched. Test
    // Message positions are zero; integer ordered fixtures prove this helper's
    // logic, NOT real connection ordering, transport capacity or native finality.
    use super::*;
    use std::{collections::VecDeque, sync::atomic::{AtomicBool, AtomicUsize, Ordering}, task::Waker};

    enum DataTurn { Item(u64, zbus::Result<Message>), Idle, Drained, Ended }
    struct DataStream(VecDeque<DataTurn>);
    impl OrderedStream for DataStream {
        type Ordering = u64;
        type Data = zbus::Result<Message>;
        fn poll_next_before(mut self: Pin<&mut Self>, _: &mut Context<'_>, _: Option<&u64>) -> Poll<PollResult<u64, Self::Data>> {
            match self.0.pop_front().unwrap_or(DataTurn::Idle) {
                DataTurn::Item(ordering, data) => Poll::Ready(PollResult::Item { ordering, data }),
                DataTurn::Idle => Poll::Pending,
                DataTurn::Drained => Poll::Ready(PollResult::NoneBefore),
                DataTurn::Ended => Poll::Ready(PollResult::Terminated),
            }
        }
    }
    fn data_deadline() -> Instant { Instant::now() + std::time::Duration::from_secs(60) }
    fn input() -> LookupInput {
        LookupInput::new(Path::new("/synthetic/never-opened/bus"), "/collection", "reserved-vault", "reserved-generation").unwrap()
    }
    fn data_book() -> LookupBook {
        // Seed only inert pre-call state. There is deliberately no Connection;
        // all RPCs below enter through the real admit_with dispatch seam.
        let input = input(); let mut book = LookupBook::new();
        book.claim(crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap()).unwrap();
        book.query = Some(input.query); book.rule = Some(input.rule);
        book.phase = Phase::Admit(Step::AddMatch); book
    }
    fn reply<T: serde::Serialize + zbus::zvariant::DynamicType>(sender: &'static str, data: &T) -> Message {
        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
        Message::method_return(&call.header()).unwrap().sender(sender).unwrap().build(data).unwrap()
    }
    fn owner_event() -> Message {
        Message::signal(BUS_PATH, BUS, "NameOwnerChanged").unwrap().sender(BUS).unwrap()
            .build(&(SERVICE, ":1.23", ":1.24")).unwrap()
    }
    fn tick(book: &mut LookupBook, turn: DataTurn) -> Poll<Step> {
        let mut stream = DataStream(VecDeque::from([turn]));
        let mut cx = Context::from_waker(Waker::noop());
        let before = book.reconciliation_boundary().is_some().then_some(10u64);
        let observed = stream_turn_observing(&mut stream, &mut cx, before.as_ref(), |message| {
            observe_message(book.profile.as_mut(), book.owner.as_ref().map(|owner| owner.as_ref()), message)
        });
        match book.advance(&mut cx, observed) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Next::Admit(step)) => Poll::Ready(step),
            Poll::Ready(Next::FirstPoll) => {
                // Lower-level DATA tests have no document. Actual slot/STOP
                // admission between these phases is tested in asset_session.
                book.first_poll(&mut cx, Ok(data_deadline()));
                Poll::Pending
            }
            Poll::Ready(Next::AdmitShutdown | Next::FirstPollShutdown | Next::Settled
                | Next::ProviderAcquire | Next::ProviderBind | Next::ProviderRecheck | Next::ProviderRelease) =>
                panic!("DATA RPCs cannot manufacture a maintained SDK finality receipt"),
        }
    }
    fn call(book: &mut LookupBook, step: Step, result: zbus::Result<Message>, registered: &mut Vec<Step>) {
        assert_eq!(tick(book, DataTurn::Idle), Poll::Ready(step));
        book.admit_with(step, data_deadline(), |_, actual| { registered.push(actual); Ok(Box::pin(std::future::ready(result))) }).unwrap();
        assert!(tick(book, DataTurn::Idle).is_pending()); // original returned, raw retained
        assert!(book.raw_pending);
        assert!(tick(book, DataTurn::Drained).is_pending()); // actual state-machine reconciliation
        assert!(!book.raw_pending);
        // These lower-level DATA books have no native shutdown to admit. Apply
        // only the production semantic result; no SDK settlement is invented.
        if step == Step::RemoveMatch { book.commit_removal_reply(); }
    }
    fn select_owner(book: &mut LookupBook, registered: &mut Vec<Step>) {
        call(book, Step::AddMatch, Ok(reply(BUS, &())), registered);
        call(book, Step::GetNameOwner, Ok(reply(BUS, &":1.23")), registered);
        assert_eq!(book.owner.as_ref().unwrap().as_str(), ":1.23");
    }
    fn select_item(book: &mut LookupBook, registered: &mut Vec<Step>) {
        select_owner(book, registered);
        let paths = [zbus::zvariant::ObjectPath::try_from("/one").unwrap()];
        call(book, Step::SearchItems, Ok(reply(":1.23", &&paths[..])), registered);
        let attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
        let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes)); drop(attributes);
        call(book, Step::Attributes, Ok(message), registered);
    }
    fn open_reply(sender: &'static str, peer: &[u8], path: &str) -> Message {
        reply(sender, &(zbus::zvariant::as_value::Serialize(&peer), zbus::zvariant::ObjectPath::try_from(path).unwrap()))
    }
    fn secret_reply(iv: &[u8; 16], ciphertext: &[u8; 48]) -> Message {
        reply(":1.23", &((zbus::zvariant::ObjectPath::try_from("/session").unwrap(), &iv[..], &ciphertext[..], "application/octet-stream"),))
    }
    fn prepared_open() -> (LookupBook, Vec<Step>, [u8; 1], [u8; 16], [u8; 48]) {
        let mut book = data_book(); let mut registered = Vec::new();
        select_item(&mut book, &mut registered);
        call(&mut book, Step::Locked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&false))), &mut registered);
        let (exchange, peer, iv, ciphertext) = checked_lookup::test_support::exchange_and_secret().unwrap();
        book.exchange = Some(exchange); // Real deterministic library helper, no fabricated key candidate.
        (book, registered, peer, iv, ciphertext)
    }
    fn retrieved_key() -> (LookupBook, Vec<Step>) {
        let (mut book, mut registered, peer, iv, ciphertext) = prepared_open();
        call(&mut book, Step::OpenSession, Ok(open_reply(":1.23", &peer, "/session")), &mut registered);
        call(&mut book, Step::GetSecret, Ok(secret_reply(&iv, &ciphertext)), &mut registered);
        assert!(book.key_candidate.is_some() && !book.key_ready());
        (book, registered)
    }
    #[test]
    fn sdk_checked_retrieval_crypto_contract() { checked_lookup::test_support::assert_crypto_helpers(); }
    #[test]
    fn sdk_checked_retrieval_wire_contract() { checked_lookup::test_support::assert_facade_helpers(); }
    #[test]
    fn lookup_charge_precedes_constructor_and_is_refunded_only_after_disposal() {
        let mut book = LookupBook::new(); let value = input();
        let query = Arc::downgrade(&value.query); let rule = Arc::downgrade(&value.rule);
        let charge = crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap();
        let calls = std::cell::Cell::new(0);
        assert_eq!(book.begin_constructed(value, data_deadline(), charge, |_| {
            calls.set(calls.get() + 1); Err(zbus::Error::InvalidReply)
        }), Err(Problem::Unavailable));
        assert_eq!(calls.get(), 1); assert!(book.started() && book.memory_held());
        assert!(book.resources_settled() && !book.allocations_released()); // no attempt was constructed
        assert!(query.upgrade().is_some() && rule.upgrade().is_some());
        let failed_at = book.problem_at(); book.interrupt();
        assert!(book.memory_held() && book.started());
        assert_eq!(book.begin_constructed(input(), data_deadline(),
            crate::asset_session::KeyringMemoryAdmission::data(0, 0).unwrap(),
            |_| panic!("duplicate entry reached SDK construction")), Err(Problem::CleanupUnknown));
        assert!(book.dispose_settled_storage());
        assert!(!book.memory_held() && book.allocations_released() && book.started() && !book.can_begin());
        assert!(query.upgrade().is_none() && rule.upgrade().is_none());
        assert_eq!(book.problem(), Some(Problem::Unavailable)); assert_eq!(book.problem_at(), failed_at);
        assert!(!book.dispose_settled_storage()); // no second refund
    }
    #[test]
    fn lookup_charge_is_not_refunded_by_stop_raw_or_unjoined_original() {
        let value = input(); let mut book = LookupBook::new();
        book.begin_with(value.query, value.rule, data_deadline(), Box::pin(std::future::pending())).unwrap();
        book.interrupt(); assert!(book.memory_held() && !book.dispose_settled_storage());
        assert!(book.pending.is_some() && book.started());
        let mut raw = LookupBook::shutdown_gate_data(data_deadline());
        assert!(raw.memory_held() && raw.raw.is_some());
        assert!(!raw.dispose_settled_storage() && raw.memory_held());
        assert!(raw.raw.is_some() && raw.started());
    }
    #[test]
    fn lookup_driver_runs_fixed_retrieval_or_missing_key_and_cleanup() {
        for candidate in [false, true] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let path = zbus::zvariant::ObjectPath::try_from("/one").unwrap();
            let paths = [path];
            let selected = if candidate { &paths[..] } else { &paths[..0] };
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &selected)), &mut registered);
            if candidate {
                let attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
                let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes));
                drop(attributes);
                call(&mut book, Step::Attributes, Ok(message), &mut registered);
                assert!(matches!(book.observation(), Some(Observation::Candidate(path)) if path.as_str() == "/one"));
                call(&mut book, Step::Locked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&false))), &mut registered);
                let (exchange, peer, iv, ciphertext) = checked_lookup::test_support::exchange_and_secret().unwrap();
                book.exchange = Some(exchange);
                call(&mut book, Step::OpenSession, Ok(open_reply(":1.23", &peer, "/session")), &mut registered);
                assert_eq!(book.session, RemoteSession::Known);
                call(&mut book, Step::GetSecret, Ok(secret_reply(&iv, &ciphertext)), &mut registered);
                assert!(book.key_candidate.is_some() && !book.key_ready());
                call(&mut book, Step::CloseSession, Ok(reply(":1.23", &())), &mut registered);
                assert_eq!(book.session, RemoteSession::Closed);
                assert!(book.removal_reply.is_none());
            } else { assert_eq!(book.problem(), Some(Problem::MissingKey)); assert!(book.key_candidate.is_none()); }
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            let expected = if candidate { vec![Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes,
                Step::Locked, Step::OpenSession, Step::GetSecret, Step::CloseSession, Step::RemoveMatch] }
                else { vec![Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::RemoveMatch] };
            assert_eq!(registered, expected);
            assert_eq!(book.registration, Registration::Removed);
            assert_eq!(book.phase, Phase::Holding);
            assert_eq!(book.problem(), if candidate { None } else { Some(Problem::MissingKey) });
            assert!(!book.key_ready()); // No actual SDK finality/document grant in these DATA books.
            assert!(!book.resources_settled()); // successful RPC/removal is not SDK joins
            let mut extra = 0;
            assert!(book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| { extra += 1; Ok(Box::pin(std::future::pending())) }).is_err());
            assert_eq!(extra, 0);
        }
    }
    #[test]
    fn locked_existing_key_never_opens_or_prompts() {
        let mut book = data_book(); let mut registered = Vec::new(); select_item(&mut book, &mut registered);
        call(&mut book, Step::Locked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&true))), &mut registered);
        assert_eq!(book.problem(), Some(Problem::Locked));
        assert_eq!(book.session, RemoteSession::Unopened);
        assert!(book.exchange.is_none() && book.key_candidate.is_none());
        call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
        assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes, Step::Locked, Step::RemoveMatch]);
    }
    #[test]
    fn original_open_path_survives_invalid_crypto_or_cancellation() {
        for cancelled in [false, true] {
            let (mut book, mut registered, peer, _, _) = prepared_open();
            let message = open_reply(":1.23", if cancelled { &peer[..] } else { &[] }, "/session");
            book.admit_with(Step::OpenSession, data_deadline(), |_, step| { registered.push(step); Ok(Box::pin(std::future::ready(Ok(message)))) }).unwrap();
            assert_eq!(book.session, RemoteSession::Unopened);
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert_eq!(book.session, RemoteSession::Possible); // FIRST poll, not constructor or decoder.
            if cancelled { book.interrupt(); }
            assert!(tick(&mut book, DataTurn::Drained).is_pending());
            assert_eq!(book.problem(), Some(if cancelled { Problem::Interrupted } else { Problem::Crypto }));
            assert_eq!(book.session, RemoteSession::Known);
            assert_eq!(book.session_path.as_ref().unwrap().as_str(), "/session");
            assert!(book.exchange.is_none() && book.session_key.is_none() && book.key_candidate.is_none());
            call(&mut book, Step::CloseSession, Ok(reply(":1.23", &())), &mut registered);
            assert!(book.removal_reply.is_none());
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert!(!registered.contains(&Step::GetSecret));
            assert_eq!(book.session, RemoteSession::Closed);
        }
    }
    #[test]
    fn untrusted_open_session_paths_never_authorize_cleanup() {
        for (sender, path) in [(":1.24", "/session"), (":1.23", "/")] {
            let (mut book, mut registered, peer, _, _) = prepared_open();
            call(&mut book, Step::OpenSession, Ok(open_reply(sender, &peer, path)), &mut registered);
            assert_eq!(book.session, RemoteSession::Unknown);
            assert!(book.session_path.is_none() && book.cleanup_unknown());
            assert!(!book.document_cleanup_unknown()); // Remaining local originals are still owned.
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert!(!registered.contains(&Step::CloseSession) && !registered.contains(&Step::GetSecret));
        }
    }
    #[test]
    fn close_errors_and_refusals_still_allow_independent_removal() {
        for refusal in 0..3 {
            let (mut book, mut registered) = retrieved_key();
            if refusal == 0 {
                book.admission_refused(Step::CloseSession, Problem::CleanupUnknown);
            } else {
                let result = if refusal == 1 { Ok(reply(":1.23", &0u32)) } else { Err(zbus::Error::InvalidReply) };
                call(&mut book, Step::CloseSession, result, &mut registered);
            }
            assert_eq!(book.session, RemoteSession::Unknown);
            assert!(book.problem_at().is_some() && book.key_candidate.is_none());
            assert!(book.cleanup_unknown() && !book.document_cleanup_unknown() && book.removal_reply.is_none());
            assert!(book.expected(Step::RemoveMatch) && !book.expected_shutdown());
            let first_failure = book.problem_at();
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert_eq!(book.registration, Registration::Removed);
            assert_eq!(book.problem_at(), first_failure);
            assert!(!book.resources_settled() && book.memory_held() && !book.key_ready());
            let mut retries = 0;
            assert!(book.admit_with(Step::CloseSession, data_deadline(), |_, _| { retries += 1; Ok(Box::pin(std::future::pending())) }).is_err());
            assert_eq!(retries, 0);
        }
    }
    #[test]
    fn cleanup_midpoint_and_pending_original_do_not_renew_or_restore_key() {
        use std::time::Duration;
        let now = Instant::now(); let end = now + Duration::from_secs(2);
        assert_eq!(cleanup_progress_end(now, end), now + Duration::from_secs(1));
        assert_eq!(cleanup_progress_end(end, end), end);
        assert_eq!(cleanup_progress_end(end + Duration::from_millis(1), end), end);

        let (mut book, _) = retrieved_key();
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        let outer_end = data_deadline();
        book.admit_with(Step::CloseSession, outer_end, |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(":1.23", &())), false))).unwrap();
        let cutoff = book.call_end.unwrap();
        assert!(cutoff < outer_end);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(book.session, RemoteSession::Closing);
        book.interrupt(); let first_failure = book.problem_at();
        assert!(!book.local_shutdown_due(Instant::now())); // Old failure does not preempt eligible cleanup.
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(book.call_end, Some(cutoff));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let expired = Instant::now() - Duration::from_millis(1);
        book.call_end = Some(expired); // DATA clock input to the ACTUAL driver, no sleep or new lease.
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(book.cleanup_cutoff_seen && book.local_shutdown_due(Instant::now()));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(book.key_candidate.is_none());
        ready.store(true, Ordering::SeqCst);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(drops.load(Ordering::SeqCst), 1); // Only its actual Ready consumed the original.
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        assert_eq!(book.problem_at(), first_failure);
        assert_eq!(book.call_end, Some(expired));
        let mut successors = 0;
        assert!(book.admit_with(Step::RemoveMatch, outer_end, |_, _| { successors += 1; Ok(Box::pin(std::future::pending())) }).is_err());
        assert_eq!(successors, 0);
        assert!(!book.key_ready() && !book.resources_settled() && book.memory_held());
        // DATA cannot manufacture the required original SDK local shutdown.
    }
    #[test]
    fn late_open_after_local_shutdown_never_reopens_remote_cleanup() {
        let (mut book, _, peer, _, _) = prepared_open();
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        let message = open_reply(":1.23", &peer, "/session");
        book.admit_with(Step::OpenSession, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(message), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(book.session, RemoteSession::Possible);
        book.interrupt();
        book.shutdown = Shutdown::Entered; // Predicate input, NOT a native receipt/settlement.
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        ready.store(true, Ordering::SeqCst);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(book.session_path.as_ref().unwrap().as_str(), "/session");
        assert_eq!(book.session, RemoteSession::Unknown);
        assert!(!book.expected(Step::CloseSession) && !book.expected(Step::GetSecret));
        assert!(book.exchange.is_none() && book.session_key.is_none() && book.key_candidate.is_none());
        assert!(!book.resources_settled() && book.memory_held());
    }
    #[test]
    fn lookup_refusal_never_registers_an_attribute_fanout_or_replacement_owner() {
        for paths in [vec!["/"], vec!["/one", "/two"]] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let paths: Vec<_> = paths.into_iter().map(|path| zbus::zvariant::ObjectPath::try_from(path).unwrap()).collect();
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &paths)), &mut registered);
            assert_eq!(book.problem(), Some(Problem::InvalidReply));
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::RemoveMatch]);
            assert!(book.observation().is_none());
            assert_eq!(book.owner.as_ref().unwrap().as_str(), ":1.23");
        }
        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let path = [zbus::zvariant::ObjectPath::try_from("/one").unwrap()];
        call(&mut book, Step::SearchItems, Ok(reply(":1.23", &&path[..])), &mut registered);
        let mut attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
        attributes.insert("vault-id", "another-vault");
        let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes)); drop(attributes);
        call(&mut book, Step::Attributes, Ok(message), &mut registered);
        assert_eq!(book.problem(), Some(Problem::IdentityMismatch));
        assert!(book.observation().is_none());
        call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
        assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes, Step::RemoveMatch]);
    }
    #[test]
    fn earlier_and_already_observed_later_owner_events_refuse_the_same_original_result() {
        for ordering in [2u64, 20] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let paths = [zbus::zvariant::ObjectPath::try_from("/one").unwrap()];
            let message = reply(":1.23", &&paths[..]);
            book.admit_with(Step::SearchItems, data_deadline(), |_, step| { registered.push(step); Ok(Box::pin(std::future::ready(Ok(message)))) }).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert!(tick(&mut book, DataTurn::Item(ordering, Ok(owner_event()))).is_pending());
            assert_eq!(book.problem(), Some(Problem::OwnerChanged));
            assert!(book.raw_pending); // an Item is not the NoneBefore receipt
            assert!(tick(&mut book, DataTurn::Drained).is_pending());
            assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert_eq!(registered, [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::RemoveMatch]);
            assert!(book.observation().is_none() && !book.resources_settled());
        }
    }
    #[test]
    fn raw_method_errors_require_drain_and_stream_failures_never_supply_it() {
        for failure in [DataTurn::Item(12, Err(zbus::Error::InvalidReply)), DataTurn::Ended, DataTurn::Drained] {
            let mut book = data_book(); let mut registered = Vec::new();
            select_owner(&mut book, &mut registered);
            let call_message = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
            let message = Message::error(&call_message.header(), "org.example.Refused").unwrap().sender(":1.23").unwrap().build(&"detail").unwrap();
            let bytes = message.data().bytes().as_ptr();
            let original = zbus::Error::MethodError("org.example.Refused".try_into().unwrap(), None, message);
            book.admit_with(Step::SearchItems, data_deadline(), |_, _| Ok(Box::pin(std::future::ready(Err(original))))).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert_eq!(book.problem(), Some(Problem::Unavailable)); // Latched at the actual raw Err, before drain.
            let original_failure_at = book.problem_at().unwrap();
            assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
            assert!(tick(&mut book, DataTurn::Idle).is_pending()); // Pending with boundary is not drained
            assert!(book.raw_pending);
            assert!(tick(&mut book, failure).is_pending());
            assert!(!book.raw_pending);
            assert!(book.problem().is_some());
            assert_eq!(book.problem_at(), Some(original_failure_at));
            assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
            assert!(matches!(book.raw, Some(Err(zbus::Error::MethodError(_, _, _)))));
        }
        let mut stream = DataStream(VecDeque::from([DataTurn::Drained]));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(stream_turn(&mut stream, &mut cx, None), StreamTurn::Failed);
    }

    #[test]
    fn terminal_removal_reconciliation_precedes_shutdown_and_closes_stream_sampling() {
        #[derive(Clone, Copy)]
        enum ReplyKind { Valid, Malformed, MethodError }
        fn removal(result: zbus::Result<Message>) -> LookupBook {
            let mut book = data_book();
            book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
            book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(Box::pin(std::future::ready(result)))).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert!(book.raw_pending && book.removal_reply.is_none());
            book
        }
        let mut cx = Context::from_waker(Waker::noop());
        for kind in [ReplyKind::Valid, ReplyKind::Malformed, ReplyKind::MethodError] {
            for staged in [false, true] {
                let raw = match kind {
                    ReplyKind::Valid => Ok(reply(BUS, &())),
                    ReplyKind::Malformed => Ok(reply(BUS, &"not an empty reply")),
                    ReplyKind::MethodError => {
                        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
                        let message = Message::error(&call.header(), "org.example.Refused").unwrap()
                            .sender(BUS).unwrap().build(&"detail").unwrap();
                        Err(zbus::Error::MethodError("org.example.Refused".try_into().unwrap(), None, message))
                    }
                };
                let bytes = raw_message(&raw).unwrap().data().bytes().as_ptr();
                let mut book = removal(raw);
                let raw_failure_at = book.problem_at();
                assert_eq!(raw_failure_at.is_some(), matches!(kind, ReplyKind::MethodError));
                // Neither an earlier Item nor Pending proves this raw boundary.
                for turn in [StreamTurn::Observed(None), StreamTurn::Pending] {
                    assert!(book.advance(&mut cx, turn).is_pending());
                    assert!(book.raw_pending && book.removal_reply.is_none());
                }
                let end = data_deadline();
                if staged { book.shutdown = Shutdown::Staged(end); }
                let next = book.advance(&mut cx, StreamTurn::Drained);
                if staged { assert!(matches!(next, Poll::Ready(Next::FirstPollShutdown))); }
                else { assert!(next.is_pending()); }
                assert!(!book.raw_pending);
                let expected = match kind {
                    ReplyKind::Valid => RemovalReply::Confirmed,
                    ReplyKind::Malformed => RemovalReply::Failed(ErrorClass::Protocol),
                    ReplyKind::MethodError => RemovalReply::Failed(ErrorClass::Remote),
                };
                assert_eq!(book.removal_reply, Some(expected));
                assert_eq!(book.registration, Registration::Registered); // Not a local-stop receipt.
                let problem = book.problem(); let problem_at = book.problem_at();
                assert_eq!(problem.is_none(), matches!(kind, ReplyKind::Valid));
                if raw_failure_at.is_some() { assert_eq!(problem_at, raw_failure_at); }
                assert!(!book.cleanup_unknown()); // Only this bounded stop admission is pending.
                // A reader awakened by own shutdown may produce either turn.
                // Terminal reconciliation cannot be replaced by that later error.
                for stale in [StreamTurn::Failed, StreamTurn::Ended] {
                    let _ = book.advance(&mut cx, stale);
                    assert_eq!(book.removal_reply, Some(expected));
                    assert_eq!(book.problem(), problem); assert_eq!(book.problem_at(), problem_at);
                }
                // The real poll entry must skip sampling too, not only advance.
                // This DATA book has no stream: sampling it would yield Ended.
                let _ = book.poll(&mut cx);
                assert_eq!(book.problem(), problem); assert_eq!(book.problem_at(), problem_at);
                if staged { assert_eq!(book.shutdown, Shutdown::Staged(end)); }
                assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
                book.shutdown_admission_refused(Problem::Interrupted);
                assert_eq!(book.registration, if matches!(kind, ReplyKind::Valid) { Registration::Removed } else { Registration::Unknown });
                assert_eq!(book.cleanup_unknown(), !matches!(kind, ReplyKind::Valid));
                if problem_at.is_some() { assert_eq!(book.problem_at(), problem_at); }
                assert_eq!(raw_message(book.raw.as_ref().unwrap()).unwrap().data().bytes().as_ptr(), bytes);
                assert!(!book.resources_settled());
            }
        }
        for turn in [StreamTurn::Failed, StreamTurn::Ended] {
            let mut book = removal(Ok(reply(BUS, &())));
            book.shutdown = Shutdown::Staged(data_deadline());
            assert!(matches!(book.advance(&mut cx, turn), Poll::Ready(Next::FirstPollShutdown)));
            assert_eq!(book.removal_reply, Some(RemovalReply::Failed(ErrorClass::Protocol)));
            let problem_at = book.problem_at();
            book.shutdown_admission_refused(Problem::CleanupUnknown);
            assert!(book.cleanup_unknown() && !book.resources_settled());
            assert_eq!(book.problem_at(), problem_at); // Missing drain is NEVER Confirmed.
        }

        // If an entered original returns while shutdown is staged, its new raw
        // boundary gets one following turn. A still-stalled RPC does not block
        // the independent local-stop gate, nor is its original dropped.
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let mut book = data_book(); book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
        book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        book.interrupt(); let problem_at = book.problem_at();
        let end = data_deadline(); book.shutdown = Shutdown::Staged(end);
        assert!(matches!(book.advance(&mut cx, StreamTurn::Pending), Poll::Ready(Next::FirstPollShutdown)));
        assert_eq!(polls.load(Ordering::SeqCst), 2); assert_eq!(drops.load(Ordering::SeqCst), 0);
        ready.store(true, Ordering::SeqCst);
        assert!(book.advance(&mut cx, StreamTurn::Idle).is_pending());
        assert!(book.raw_pending && !book.shutdown_waiting_first_poll());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(matches!(book.advance(&mut cx, StreamTurn::Drained), Poll::Ready(Next::FirstPollShutdown)));
        assert_eq!(book.removal_reply, Some(RemovalReply::Confirmed));
        assert_eq!(book.shutdown, Shutdown::Staged(end)); assert_eq!(book.problem_at(), problem_at);
        assert!(book.raw.is_some() && !book.resources_settled());

        // All invalid consumers commit failed removal, even if no document
        // grant can be obtained. The real token's denial/expiry/absent-attempt
        // consumption is additionally covered by the asset_session gate test.
        for invalid in 0..3 {
            let mut book = LookupBook::shutdown_gate_data(data_deadline());
            let problem_at = book.problem_at();
            match invalid {
                0 => book.first_poll_shutdown(&mut cx, Err(Problem::CleanupUnknown)), // Missing readiness.
                1 => {
                    book.shutdown = Shutdown::Unrequested; book.shutdown_ready = true;
                    book.first_poll_shutdown(&mut cx, Err(Problem::CleanupUnknown)); // Wrong stage.
                }
                _ => {
                    book.shutdown = Shutdown::Unrequested;
                    assert!(book.admit_shutdown(data_deadline()).is_err()); // Impossible attempt.
                }
            }
            assert!(book.cleanup_unknown() && !book.resources_settled());
            assert_eq!(book.problem_at(), problem_at); assert!(book.raw.is_some());
        }
    }

    struct HeldCall {
        polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize>, ready: Arc<AtomicBool>,
        panic_on_poll: bool, result: Option<zbus::Result<Message>>,
    }
    impl Future for HeldCall {
        type Output = zbus::Result<Message>;
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic_on_poll, "synthetic original poll failure");
            if self.ready.load(Ordering::SeqCst) { Poll::Ready(self.result.take().unwrap()) } else { Poll::Pending }
        }
    }
    impl Drop for HeldCall { fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); } }
    fn held(polls: &Arc<AtomicUsize>, drops: &Arc<AtomicUsize>, ready: &Arc<AtomicBool>, result: zbus::Result<Message>, panic_on_poll: bool) -> RpcFuture {
        Box::pin(HeldCall { polls: polls.clone(), drops: drops.clone(), ready: ready.clone(), result: Some(result), panic_on_poll })
    }
    #[test]
    fn startup_owner_loss_and_stop_retain_original_calls_and_cleanup_errors() {
        let mut book = data_book();
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::AddMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(tick(&mut book, DataTurn::Item(2, Ok(owner_event()))).is_pending());
        book.interrupt();
        let original_failure_at = book.problem_at();
        let observer = std::future::poll_fn(|cx| book.poll(cx)); drop(observer);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 3);
        assert_eq!(book.problem(), Some(Problem::OwnerChanged));
        ready.store(true, Ordering::SeqCst);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        assert!(book.owner.is_none()); // startup cannot infer/re-resolve a baseline
        assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
        book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(Box::pin(std::future::ready(Err(zbus::Error::InvalidReply))))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(tick(&mut book, DataTurn::Idle).is_pending()); // transport error, no invented boundary
        book.commit_removal_reply(); // DATA has no local shutdown admission.
        assert!(book.cleanup_unknown());
        assert_eq!(book.phase, Phase::Holding);
        assert_eq!(book.problem(), Some(Problem::OwnerChanged));
        assert_eq!(book.problem_at(), original_failure_at);
        assert!(book.raw.is_some() && !book.resources_settled());
    }
    #[test]
    fn failed_build_and_coordinator_panic_never_reset_started_custody() {
        let input = input(); let mut book = LookupBook::new();
        book.begin_with(input.query, input.rule, data_deadline(), Box::pin(std::future::ready(Err(zbus::Error::InvalidReply)))).unwrap();
        assert!(book.started() && !book.resources_settled()); // before first build poll
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(book.poll(&mut cx), Poll::Ready(Next::FirstPoll)));
        book.first_poll(&mut cx, Ok(data_deadline()));
        assert!(book.connect_failure.is_some() && book.attempt.is_none());
        book.interrupt();
        assert_eq!(book.problem(), Some(Problem::Unavailable));
        assert!(!book.resources_settled());

        let mut book = data_book();
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::AddMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), true))).unwrap();
        let retained = std::sync::Mutex::new(book);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut book = retained.lock().unwrap(); let _ = tick(&mut book, DataTurn::Idle);
        }));
        assert!(failure.is_err() && retained.is_poisoned());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let book = match retained.lock() { Err(error) => error.into_inner(), Ok(_) => panic!("synthetic panic must poison its book") };
        assert!(book.pending.is_some() && !book.resources_settled());
        // No repoll or native-finality claim after the original coordinator failed.
    }
    #[test]
    fn predispatch_interruption_never_polls_a_new_provider_or_resets_finality() {
        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::SearchItems, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(":1.23", &())), false))).unwrap();
        book.interrupt(); assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1); // only a never-polled future
        assert!(book.raw.is_none());
        assert_eq!(book.phase, Phase::Admit(Step::RemoveMatch));
        assert!(!book.resources_settled());

        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        book.admit_with(Step::SearchItems, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(":1.23", &())), false))).unwrap();
        let unrelated = Message::signal("/other", "org.example.Other", "Changed").unwrap().sender(":1.9").unwrap().build(&()).unwrap();
        assert!(tick(&mut book, DataTurn::Item(1, Ok(unrelated))).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0); // another queued event must be drained before first send
        assert!(tick(&mut book, DataTurn::Item(2, Ok(owner_event()))).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(book.problem(), Some(Problem::OwnerChanged));
        assert!(book.raw.is_none() && !book.resources_settled());
    }
    #[test]
    fn cutoff_refuses_first_poll_but_never_drops_an_already_polled_original() {
        for step in [Step::AddMatch, Step::GetNameOwner, Step::SearchItems, Step::Attributes, Step::Locked,
            Step::OpenSession, Step::GetSecret, Step::CloseSession, Step::RemoveMatch] {
            let mut book = data_book(); book.phase = Phase::Admit(step);
            book.registration = if step == Step::AddMatch { Registration::Unsent } else { Registration::Registered };
            if step == Step::CloseSession {
                book.session = RemoteSession::Known;
                book.session_path = Some(Arc::new(OwnedObjectPath::try_from("/session".to_owned()).unwrap()));
            }
            let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
            book.admit_with(step, Instant::now(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(book.phase, if matches!(step, Step::RemoveMatch | Step::AddMatch) { Phase::Holding } else { Phase::Admit(Step::RemoveMatch) });
            assert!(!book.resources_settled());
        }
        let mut book = data_book(); book.phase = Phase::Admit(Step::RemoveMatch); book.registration = Registration::Registered;
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0)); let ready = Arc::new(AtomicBool::new(false));
        book.admit_with(Step::RemoveMatch, data_deadline(), |_, _| Ok(held(&polls, &drops, &ready, Ok(reply(BUS, &())), false))).unwrap();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        if let Some(Pending::Rpc { dispatch_end, .. }) = book.pending.as_mut() { *dispatch_end = Instant::now(); }
        book.interrupt();
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        ready.store(true, Ordering::SeqCst);
        assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        book.commit_removal_reply(); // DATA has no local shutdown admission.
        assert_eq!(book.registration, Registration::Removed); // late own removal, not overall success
        assert_eq!(book.problem(), Some(Problem::Interrupted));
        assert!(!book.resources_settled());
    }
    #[test]
    fn final_first_poll_requires_one_use_readiness_and_rechecks_effective_time() {
        let mut cx = Context::from_waker(Waker::noop());
        for readiness in [false, true] {
            let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(AtomicBool::new(false));
            let mut book = LookupBook::cleanup_data(data_deadline(), held(&polls, &drops, &ready, Ok(reply(BUS, &())), false));
            if readiness { assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll))); }
            // Even a grant obtained before this instant cannot authorize a poll
            // after its now-expired effective end. Without readiness, no grant
            // is consumed and the original future is kept, never polled.
            book.first_poll(&mut cx, Ok(Instant::now()));
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), if readiness { 1 } else { 0 });
            assert_eq!(book.problem(), Some(Problem::CleanupUnknown));
            assert!(!book.resources_settled());
        }
        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let mut book = LookupBook::cleanup_data(data_deadline(), held(&polls, &drops, &ready, Ok(reply(BUS, &())), false));
        assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll)));
        assert!(book.advance(&mut cx, StreamTurn::Observed(None)).is_pending());
        book.first_poll(&mut cx, Ok(data_deadline())); // Another stream turn invalidated readiness.
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let mut book = LookupBook::cleanup_data(data_deadline(), held(&polls, &drops, &ready, Ok(reply(BUS, &())), false));
        let shorter_end = Instant::now() + std::time::Duration::from_secs(30);
        assert!(matches!(book.idle_data_turn(&mut cx), Poll::Ready(Next::FirstPoll)));
        book.first_poll(&mut cx, Ok(shorter_end));
        assert!(matches!(book.pending, Some(Pending::Rpc { dispatch_end, .. }) if dispatch_end == shorter_end));
        book.first_poll(&mut cx, Ok(data_deadline())); // The one-use readiness is spent.
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(book.idle_data_turn(&mut cx).is_pending()); // Still drive this already-polled original.
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sdk_checked_persistent_provider_wire_contract() { checked_lookup::test_support::assert_provider_helpers(); }
    #[test]
    fn sdk_checked_initialization_crypto_contract() { checked_lookup::test_support::assert_initialization_helpers(); }

    fn profile_identity() -> crate::vault_format::Identity {
        crate::vault_format::Identity::new(crate::vault_format::Id::from_bytes([1; 16]).unwrap(),
            crate::vault_format::Id::from_bytes([2; 16]).unwrap()).unwrap()
    }
    fn profile_data_book(initialize: bool) -> (LookupBook, Vec<Step>) {
        let mut book = data_book(); let mut registered = Vec::new(); select_owner(&mut book, &mut registered);
        let identity = profile_identity();
        let query = book.query.as_mut().and_then(Arc::get_mut).unwrap();
        query.vault_id = identity.vault.token().into_boxed_str(); query.generation_id = identity.generation.token().into_boxed_str();
        let mut profile = Profile::for_uid(PathBuf::from("/run/user/1000/bus"), Purpose::Unlock(identity), data_deadline(), 1000).unwrap();
        // Only inert post-admission INPUT to the RPC/prompt DATA driver below.
        // There is no SDK/native original, fd, child join or publication here.
        // sdk_constructed prevents no-SDK finality; the native conjunction stays
        // false, and every test retains key_ready/resources_settled == false.
        profile.sdk_constructed = true; profile.initialize = initialize; profile.admitted = Some(AdmittedProvider);
        profile.manager = Some(Arc::new(UniqueName::try_from(":1.77".to_owned()).unwrap()));
        profile.manager_registration = Registration::Registered;
        book.profile = Some(profile);
        book.phase = Phase::Admit(if initialize { Step::CollectionLocked } else { Step::SearchItems });
        (book, registered)
    }
    fn profile_prompt_book(initialize: bool) -> (LookupBook, Vec<Step>) {
        let (mut book, mut registered) = profile_data_book(initialize);
        if initialize {
            call(&mut book, Step::CollectionLocked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&true))), &mut registered);
        } else {
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &vec![zbus::zvariant::ObjectPath::try_from("/one").unwrap()])), &mut registered);
            let attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
            let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes)); drop(attributes);
            call(&mut book, Step::Attributes, Ok(message), &mut registered);
            call(&mut book, Step::Locked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&true))), &mut registered);
        }
        call(&mut book, Step::AddPromptMatch, Ok(reply(BUS, &())), &mut registered);
        let reply = reply(":1.23", &(Vec::<zbus::zvariant::ObjectPath<'_>>::new(), zbus::zvariant::ObjectPath::try_from("/prompt").unwrap()));
        call(&mut book, Step::Unlock, Ok(reply), &mut registered);
        assert!(book.expected(Step::Prompt));
        (book, registered)
    }
    fn completion(path: &str, denied: bool, target: &str) -> Message {
        let paths = vec![zbus::zvariant::ObjectPath::try_from(target).unwrap()];
        Message::signal(path, "org.freedesktop.Secret.Prompt", "Completed").unwrap().sender(":1.23").unwrap()
            .build(&(denied, zbus::zvariant::as_value::Serialize(&paths))).unwrap()
    }

    #[test]
    fn persistent_prompt_reconciles_both_orderings_before_fresh_locked_recheck() {
        for completed_first in [false, true] {
            let (mut book, mut registered) = profile_prompt_book(false);
            let polls = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(AtomicBool::new(!completed_first));
            assert_eq!(tick(&mut book, DataTurn::Idle), Poll::Ready(Step::Prompt));
            book.admit_with(Step::Prompt, data_deadline(), |_, step| {
                registered.push(step); Ok(held(&polls, &drops, &ready, Ok(reply(":1.23", &())), false))
            }).unwrap();
            assert!(tick(&mut book, DataTurn::Idle).is_pending());
            assert!(book.profile.as_ref().unwrap().current().unwrap().invoked);
            if !completed_first { assert!(tick(&mut book, DataTurn::Drained).is_pending()); }
            let message = completion("/prompt", false, "/one"); let position = message.recv_position();
            assert!(tick(&mut book, DataTurn::Item(11, Ok(message))).is_pending());
            let prompt = book.profile.as_ref().unwrap().current().unwrap();
            assert_eq!(prompt.position, Some(position)); assert!(!prompt.reconciled && !prompt.complete());
            assert!(tick(&mut book, DataTurn::Drained).is_pending());
            if completed_first {
                assert!(!book.expected(Step::Locked)); assert!(book.pending.is_some());
                assert!(!book.profile.as_ref().unwrap().current().unwrap().method_returned);
                ready.store(true, Ordering::SeqCst);
                assert!(tick(&mut book, DataTurn::Idle).is_pending()); assert!(book.raw_pending);
                assert!(tick(&mut book, DataTurn::Drained).is_pending());
            }
            assert_eq!(tick(&mut book, DataTurn::Idle), Poll::Ready(Step::Locked));
            assert!(book.profile.as_ref().unwrap().prompts[0].as_ref().unwrap().complete());
            assert!(book.profile.as_ref().unwrap().current_prompt.is_none());
            call(&mut book, Step::Locked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&false))), &mut registered);
            assert!(book.expected(Step::OpenSession));
            assert_eq!(registered.iter().filter(|step| **step == Step::Unlock).count(), 1);
            assert_eq!(registered.iter().filter(|step| **step == Step::Prompt).count(), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(book.problem().is_none() && !book.key_ready() && !book.resources_settled() && book.memory_held());
        }
    }

    #[test]
    fn persistent_prompt_denial_and_dismiss_reply_never_become_completion() {
        for dismiss in [false, true] {
            let (mut book, mut registered) = profile_prompt_book(true);
            call(&mut book, Step::Prompt, Ok(reply(":1.23", &())), &mut registered);
            assert_eq!(book.phase, Phase::AwaitPrompt);
            if dismiss {
                book.interrupt(); let stop = book.problem_at().unwrap();
                let end = stop + std::time::Duration::from_secs(40); book.constrain_cleanup_endpoint(stop, end);
                assert_eq!(tick(&mut book, DataTurn::Idle), Poll::Ready(Step::Dismiss));
                call(&mut book, Step::Dismiss, Ok(reply(":1.23", &())), &mut registered);
                let prompt = book.profile.as_ref().unwrap().current().unwrap();
                assert!(prompt.dismiss_entered && prompt.dismiss_returned && !prompt.complete() && prompt.completion.is_none());
                assert_eq!(book.phase, Phase::AwaitPrompt); assert!(!book.expected(Step::RemovePromptMatch));
                let cutoff = book.profile.as_ref().unwrap().prompt_end.unwrap();
                book.constrain_cleanup_endpoint(stop, end + std::time::Duration::from_secs(1));
                assert_eq!(book.profile.as_ref().unwrap().prompt_end, Some(cutoff));
            }
            assert!(tick(&mut book, DataTurn::Item(11, Ok(completion("/prompt", true, "/collection")))).is_pending());
            assert!(!book.profile.as_ref().unwrap().current().unwrap().complete());
            assert!(tick(&mut book, DataTurn::Drained).is_pending());
            assert!(book.profile.as_ref().unwrap().prompts[0].as_ref().unwrap().complete());
            assert_eq!(book.problem(), Some(if dismiss { Problem::Interrupted } else { Problem::Denied }));
            assert_eq!(tick(&mut book, DataTurn::Idle), Poll::Ready(Step::RemovePromptMatch));
            call(&mut book, Step::RemovePromptMatch, Ok(reply(BUS, &())), &mut registered);
            call(&mut book, Step::RemoveManagerMatch, Ok(reply(BUS, &())), &mut registered);
            call(&mut book, Step::RemoveMatch, Ok(reply(BUS, &())), &mut registered);
            assert_eq!(&registered[registered.len() - 3..], &[Step::RemovePromptMatch, Step::RemoveManagerMatch, Step::RemoveMatch]);
            assert!(book.key_candidate.is_none() && !book.key_ready() && !book.resources_settled());
            assert!(!book.expected(Step::CreateItem));
        }
    }

    #[test]
    fn persistent_prompt_foreign_duplicate_and_owner_change_cannot_settle_successors() {
        let (mut book, mut registered) = profile_prompt_book(false);
        assert!(tick(&mut book, DataTurn::Item(7, Ok(completion("/foreign", false, "/one")))).is_pending());
        assert!(book.profile.as_ref().unwrap().current().unwrap().completion.is_none());
        assert!(book.problem().is_none());
        call(&mut book, Step::Prompt, Ok(reply(":1.23", &())), &mut registered);
        assert!(tick(&mut book, DataTurn::Item(11, Ok(completion("/prompt", false, "/one")))).is_pending());
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        let position = book.profile.as_ref().unwrap().prompts[0].as_ref().unwrap().position;
        assert!(tick(&mut book, DataTurn::Item(12, Ok(completion("/prompt", false, "/one")))).is_pending());
        assert_eq!(book.problem(), Some(Problem::InvalidReply));
        assert_eq!(book.profile.as_ref().unwrap().prompts[0].as_ref().unwrap().position, position);
        assert!(!book.expected(Step::Locked) && book.key_candidate.is_none());
        let (mut book, mut registered) = profile_prompt_book(false);
        call(&mut book, Step::Prompt, Ok(reply(":1.23", &())), &mut registered);
        assert!(tick(&mut book, DataTurn::Item(11, Ok(completion("/prompt", false, "/one")))).is_pending());
        let manager = Message::signal(BUS_PATH, BUS, "NameOwnerChanged").unwrap().sender(BUS).unwrap()
            .build(&(MANAGER, ":1.77", ":1.78")).unwrap();
        assert!(tick(&mut book, DataTurn::Item(12, Ok(manager))).is_pending());
        assert!(tick(&mut book, DataTurn::Drained).is_pending());
        assert_eq!(book.problem(), Some(Problem::OwnerChanged)); assert!(!book.expected(Step::Locked));
        assert!(!book.key_ready() && !book.resources_settled());
    }

    fn create_data_book() -> (LookupBook, Vec<Step>) {
        let (mut book, mut registered) = profile_data_book(true);
        // Post-encryption request INPUT only, not a generated key/native grant.
        // The separately tested checked crypto owner supplies a real transport
        // key here, but these DATA bytes can never publish an authenticated key.
        let (exchange, peer, iv, ciphertext) = checked_lookup::test_support::exchange_and_secret().unwrap();
        book.session_key = Some(exchange.derive(&peer).unwrap()); book.session = RemoteSession::Known;
        book.session_path = Some(Arc::new(OwnedObjectPath::try_from("/session".to_owned()).unwrap()));
        let profile = book.profile.as_mut().unwrap(); profile.absence_proved = true; profile.encrypted = Some((iv, ciphertext));
        book.prompt_match_then(Step::CreateItem).unwrap();
        call(&mut book, Step::AddPromptMatch, Ok(reply(BUS, &())), &mut registered);
        (book, registered)
    }
    fn created(sender: &'static str, item: &str, prompt: &str) -> Message {
        reply(sender, &(zbus::zvariant::ObjectPath::try_from(item).unwrap(), zbus::zvariant::ObjectPath::try_from(prompt).unwrap()))
    }

    #[test]
    fn persistent_create_first_poll_and_late_tuple_keep_debt_not_a_key_or_retry() {
        for (sender, item, prompt, cancel) in [(":1.23", "/created", "/", true), (":1.23", "/", "/create_prompt", true),
            (":1.23", "/created", "/create_prompt", false), (":1.24", "/", "/create_prompt", false)] {
            let (mut book, mut registered) = create_data_book();
            let message = created(sender, item, prompt);
            assert_eq!(tick(&mut book, DataTurn::Idle), Poll::Ready(Step::CreateItem));
            book.admit_with(Step::CreateItem, data_deadline(), |_, step| { registered.push(step); Ok(Box::pin(std::future::ready(Ok(message)))) }).unwrap();
            assert!(!book.creation_possible());
            assert!(tick(&mut book, DataTurn::Idle).is_pending()); assert!(book.creation_possible());
            assert!(book.profile.as_ref().unwrap().encrypted.is_none());
            if cancel { book.interrupt(); }
            assert!(tick(&mut book, DataTurn::Drained).is_pending());
            assert!(book.problem().is_some() && book.creation_possible() && book.raw.is_some());
            let profile = book.profile.as_ref().unwrap();
            assert_eq!(profile.prompts[1].is_some(), sender == ":1.23" && prompt != "/");
            if let Some(prompt) = profile.prompts[1].as_ref() { assert_eq!(prompt.path.as_str(), "/create_prompt"); assert!(!prompt.complete()); }
            if sender == ":1.23" && item != "/" { assert_eq!(profile.created_item.as_ref().unwrap().as_str(), item); }
            assert!(book.key_candidate.is_none() && book.session_key.is_none() && !book.key_ready() && book.memory_held());
            let mut retries = 0;
            assert!(book.admit_with(Step::CreateItem, data_deadline(), |_, _| { retries += 1; Ok(Box::pin(std::future::pending())) }).is_err());
            assert_eq!(retries, 0); assert!(!book.resources_settled());
        }
        let (mut book, _) = create_data_book();
        book.admit_with(Step::CreateItem, data_deadline(), |_, _| Ok(Box::pin(std::future::pending()))).unwrap();
        book.interrupt(); assert!(tick(&mut book, DataTurn::Idle).is_pending());
        assert!(!book.creation_possible()); // Reserved/staged is NOT first dispatch.
    }

    #[test]
    fn persistent_initialization_requires_absence_and_unique_created_item_readback() {
        for absent in [false, true] {
            let (mut book, mut registered) = profile_data_book(true);
            call(&mut book, Step::CollectionLocked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&false))), &mut registered);
            let paths = if absent { vec![] } else { vec![zbus::zvariant::ObjectPath::try_from("/existing").unwrap()] };
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &paths)), &mut registered);
            assert_eq!(book.profile.as_ref().unwrap().absence_proved, absent);
            assert_eq!(book.expected(Step::OpenSession), absent);
            assert!(!book.creation_possible() && book.key_candidate.is_none());
            if !absent { assert_eq!(book.problem(), Some(Problem::IdentityMismatch)); }
        }
        for returned in [vec!["/created"], vec!["/other"], vec!["/created", "/other"], vec![]] {
            let (mut book, mut registered) = create_data_book();
            call(&mut book, Step::CreateItem, Ok(created(":1.23", "/created", "/")), &mut registered);
            assert!(book.expected(Step::SearchItems) && book.creation_possible());
            let paths: Vec<_> = returned.iter().map(|path| zbus::zvariant::ObjectPath::try_from(*path).unwrap()).collect();
            call(&mut book, Step::SearchItems, Ok(reply(":1.23", &paths)), &mut registered);
            if returned == ["/created"] {
                let attributes: std::collections::HashMap<_, _> = book.query.as_ref().unwrap().attributes().into_iter().collect();
                let message = reply(":1.23", &zbus::zvariant::as_value::Serialize(&attributes)); drop(attributes);
                call(&mut book, Step::Attributes, Ok(message), &mut registered);
                call(&mut book, Step::Locked, Ok(reply(":1.23", &zbus::zvariant::as_value::Serialize(&false))), &mut registered);
                assert!(book.expected(Step::GetSecret)); // Generated/created is never a key lease.
            } else { assert!(book.problem().is_some() && !book.expected(Step::GetSecret)); }
            assert!(book.key_candidate.is_none() && !book.key_ready() && !book.resources_settled());
        }
    }

    #[test]
    fn persistent_profile_refuses_nominal_pid_unit_and_fabricated_native_flags() {
        let (mut book, _) = profile_data_book(false);
        let profile = book.profile.as_mut().unwrap(); profile.admitted = None;
        profile.native_acquired = true; profile.native_bound = true; profile.native_progress = NativeProgress::Joined(ProviderStep::Bind);
        profile.round = CredentialRound::Bound; profile.user_rounds = 3; profile.process_rounds = 3; profile.pid = Some(123);
        profile.unit = Some(Arc::new(OwnedObjectPath::try_from("/unit".to_owned()).unwrap()));
        profile.policy = (1 << 10) - 1; profile.login_checked = true; profile.session_checked = true;
        // These are deliberately forged DATA inputs to a NEGATIVE predicate.
        // The actual original native cells have no fds/binding, so no token,
        // call or SDK/native/publication finality can be obtained from them.
        assert!(!profile.profile_conjunction());
        let mut calls = 0;
        assert_eq!(book.admit_with(Step::SearchItems, data_deadline(), |_, _| { calls += 1; Ok(Box::pin(std::future::pending())) }), Err(Problem::UnsupportedProvider));
        assert_eq!(calls, 0); assert!(book.profile.as_ref().unwrap().admitted.is_none());
        assert!(!book.resources_settled() && !book.key_ready());
    }

    #[test]
    fn persistent_native_acquire_stop_keeps_return_separate_from_join_and_release() {
        let mut book = data_book();
        book.profile = Some(Profile::for_uid(PathBuf::from("/run/user/1000/bus"), Purpose::Unlock(profile_identity()), data_deadline(), 1000).unwrap());
        book.phase = Phase::Native(ProviderStep::Acquire);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(book.poll(&mut cx), Poll::Ready(Next::ProviderAcquire)));
        assert!(book.attempt.is_none() && !book.profile.as_ref().unwrap().sdk_constructed);
        let mut stopped = 0;
        // Refuse at the FIRST checkpoint: no OS credential/stat/open/read,
        // process, socket, provider or native close is executed in this test.
        assert_eq!(book.prepare_provider(&mut || { stopped += 1; true }), Err(Problem::Interrupted));
        assert_eq!(stopped, 1);
        assert!(book.profile.as_ref().unwrap().native_progress == NativeProgress::Returned(ProviderStep::Acquire, Err(Problem::Interrupted)));
        assert!(!book.resources_settled() && book.memory_held());
        assert_eq!(book.provider_child_joined(ProviderStep::Acquire, Err(Problem::Interrupted)), Err(Problem::Interrupted));
        assert!(book.profile.as_ref().unwrap().native_progress == NativeProgress::Ready(ProviderStep::Release));
        assert!(book.attempt.is_none() && !book.profile.as_ref().unwrap().native_acquired);
        assert!(book.provider_step_ready(ProviderStep::Release) && !book.resources_settled());
        assert_eq!(book.provider_child_joined(ProviderStep::Acquire, Err(Problem::Interrupted)), Err(Problem::CleanupUnknown));
        assert!(book.memory_held() && !book.key_ready());
    }

    #[test]
    fn persistent_consuming_candidate_keeps_charge_and_is_one_shot_without_forging_finality() {
        let (mut book, _) = retrieved_key(); let mut called = false;
        assert_eq!(book.consume_settled_key(|_| { called = true; }), Err(Problem::CleanupUnknown));
        assert!(!called && book.key_candidate.is_some() && book.memory_held());
        // Exercise the actual private ownership half only. No invented SDK
        // result or native child join is used to pass the public settled seam.
        let consumed = book.consume_charged_candidate(|candidate| candidate.consume(|key| key.iter().all(|byte| *byte == 0xa5))).unwrap();
        assert!(consumed && book.key_candidate.is_none() && book.memory_held());
        assert_eq!(book.consume_charged_candidate(|_| ()), Err(Problem::CleanupUnknown));
        assert!(!book.resources_settled() && !book.dispose_settled_storage() && book.memory_held());
        let (mut book, _) = retrieved_key();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), Problem> = book.consume_charged_candidate(|_| panic!("synthetic authentication panic"));
        }));
        assert!(unwind.is_err() && book.key_candidate.is_none() && book.memory_held() && !book.resources_settled());
    }

}
