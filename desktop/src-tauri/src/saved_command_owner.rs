//! Finite original-resource owner for exactly two saved-command domains.
//! Source extraction only: Android native/runtime/tool custody is NOT qualified.
//! The ordinary core retains C/A/W custody; native retains every original
//! startup, child, pipe, decoder, wait, driver, manager and final-join record.
use std::{future::{pending, Future}, pin::Pin, process::ExitStatus,
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context as TaskContext, Poll, Wake, Waker}, time::{Duration, Instant}};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::{Child, ChildStdin, ChildStdout, ChildStderr},
    sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot, watch}, task::JoinHandle};
#[cfg(any(all(unix, debug_assertions, feature = "development-runtime"),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
use {std::process::Stdio, tokio::process::Command};
use crate::{asset_source::RegisteredRoot, offline_preflight_protocol as wire, android_build_protocol as android_wire,
    error::BridgeError, runtime::{RuntimeConfig, VerifiedRuntime}, android_toolchain::AndroidToolchainProfile};
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
use crate::{android_toolchain::AndroidToolchainCustody,
    installed_runtime::{AdmissionFailure, AndroidDescriptorBudget, CloseOutcome, InstalledRuntimeCustody, OfflinePreflightRuntimeSlots}};

// Qualification is domain-local. No environment/GitHub/offline permit, parsed
// tool binding, hash, mode or host profile can qualify Android build custody.
const OFFLINE_NATIVE_QUALIFIED: bool = false;
const OFFLINE_RUNTIME_QUALIFIED: bool = false;
const ANDROID_NATIVE_QUALIFIED: bool = false;
const ANDROID_RUNTIME_QUALIFIED: bool = false;
const ANDROID_TOOLCHAIN_QUALIFIED: bool = false;
const INTENT: Duration = Duration::from_secs(300);
const OFFLINE_WORK: Duration = Duration::from_secs(1800);
const OFFLINE_HARD: Duration = Duration::from_secs(1810);
const ANDROID_WORK: Duration = Duration::from_secs(3000);
const ANDROID_HARD: Duration = Duration::from_secs(3010);
const SETTLEMENT: Duration = Duration::from_secs(10);
// This private closed sum is not a runner API. No operation descriptors,
// callbacks, extension traits, caller argv or caller deadlines enter the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SavedCommandDomain { OfflinePreflight, AndroidBuild }
impl SavedCommandDomain {
    fn unavailable(self) -> BridgeError { match self {
        Self::OfflinePreflight => BridgeError::new("offline_preflight_unavailable", "Saved offline checks are unavailable for this original document, host and runtime."),
        Self::AndroidBuild => BridgeError::new("android_build_unavailable", "Saved Android builds are unavailable for this original document, host, runtime and tool custody."),
    } }
    fn busy(self) -> BridgeError { match self {
        Self::OfflinePreflight => BridgeError::new("offline_preflight_busy", "Finish or cancel the original operation before reviewing saved offline checks."),
        Self::AndroidBuild => BridgeError::new("android_build_busy", "Finish or cancel the original operation before reviewing a saved Android build."),
    } }
    fn invalid_owner(self) -> BridgeError { match self {
        Self::OfflinePreflight => BridgeError::new("offline_preflight_owner", "This request does not identify an unused original saved offline-check intent."),
        Self::AndroidBuild => BridgeError::new("android_build_owner", "This request does not identify an unused original saved Android-build intent."),
    } }
    fn request_limit(self) -> usize { match self {
        Self::OfflinePreflight => wire::REQUEST_LIMIT, Self::AndroidBuild => android_wire::REQUEST_LIMIT,
    } }
    fn response_limit(self) -> usize { match self {
        Self::OfflinePreflight => wire::RESPONSE_LIMIT, Self::AndroidBuild => android_wire::RESPONSE_LIMIT,
    } }
    fn frame_limit(self) -> usize { match self { Self::OfflinePreflight => 2, Self::AndroidBuild => 8 } }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Context { OfflinePreflight(wire::Context), AndroidBuild(android_wire::Context) }
impl Context {
    fn domain(&self) -> SavedCommandDomain { match self {
        Self::OfflinePreflight(_) => SavedCommandDomain::OfflinePreflight, Self::AndroidBuild(_) => SavedCommandDomain::AndroidBuild,
    } }
    fn project_id(&self) -> &str { match self {
        Self::OfflinePreflight(c) => &c.project_id, Self::AndroidBuild(c) => &c.project_id,
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile { OfflinePreflight(wire::Profile), AndroidBuild(android_wire::Profile) }
impl Profile {
    fn current(domain: SavedCommandDomain) -> Option<Self> { match domain {
        SavedCommandDomain::OfflinePreflight => wire::Profile::current().map(Self::OfflinePreflight),
        SavedCommandDomain::AndroidBuild => android_wire::Profile::current().map(Self::AndroidBuild),
    } }
}
// Internal phase/outcome/reason vocabulary is DATA, not an Offline DTO reused
// as Android authority. Typed adapters convert by finite exhaustive matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { AwaitingConsent, Starting, Running, Stopping, Terminal, Unknown }
impl Phase {
    fn offline(self) -> wire::Phase { match self {
            Self::AwaitingConsent => wire::Phase::AwaitingConsent, Self::Starting => wire::Phase::Starting, Self::Running => wire::Phase::Running,
            Self::Stopping => wire::Phase::Stopping, Self::Terminal => wire::Phase::Terminal, Self::Unknown => wire::Phase::Unknown,
    } }
    fn android(self) -> android_wire::Phase { match self {
            Self::AwaitingConsent => android_wire::Phase::AwaitingConsent, Self::Starting => android_wire::Phase::Starting, Self::Running => android_wire::Phase::Running,
            Self::Stopping => android_wire::Phase::Stopping, Self::Terminal => android_wire::Phase::Terminal, Self::Unknown => android_wire::Phase::Unknown,
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome { Complete, Refused, Cancelled, TimedOut, Failed, Unknown }
impl Outcome {
    fn from_offline(value: wire::Outcome) -> Self { match value {
            wire::Outcome::Complete => Self::Complete, wire::Outcome::Refused => Self::Refused, wire::Outcome::Cancelled => Self::Cancelled,
            wire::Outcome::TimedOut => Self::TimedOut, wire::Outcome::Failed => Self::Failed, wire::Outcome::Unknown => Self::Unknown,
    } }
    fn from_android(value: android_wire::Outcome) -> Self { match value {
            android_wire::Outcome::Complete => Self::Complete, android_wire::Outcome::Refused => Self::Refused, android_wire::Outcome::Cancelled => Self::Cancelled,
            android_wire::Outcome::TimedOut => Self::TimedOut, android_wire::Outcome::Failed => Self::Failed, android_wire::Outcome::Unknown => Self::Unknown,
    } }
    fn offline(self) -> wire::Outcome { match self {
            Self::Complete => wire::Outcome::Complete, Self::Refused => wire::Outcome::Refused, Self::Cancelled => wire::Outcome::Cancelled,
            Self::TimedOut => wire::Outcome::TimedOut, Self::Failed => wire::Outcome::Failed, Self::Unknown => wire::Outcome::Unknown,
    } }
    fn android(self) -> android_wire::Outcome { match self {
            Self::Complete => android_wire::Outcome::Complete, Self::Refused => android_wire::Outcome::Refused, Self::Cancelled => android_wire::Outcome::Cancelled,
            Self::TimedOut => android_wire::Outcome::TimedOut, Self::Failed => android_wire::Outcome::Failed, Self::Unknown => android_wire::Outcome::Unknown,
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown,
    TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired, StaleIntent,
    SavedConfigMissing, SavedConfigInvalid, SavedConfigChanged, SavedConfigSensitive, SavedConfigUnsafe,
    SavedConfigTooLarge, SavedVersionMissing, SavedVersionInvalid, SavedVersionChanged, SavedVersionSensitive,
    SavedVersionUnsafe, SavedVersionTooLarge, PlatformDisabled, ModuleRequired, ToolchainUnavailable,
    ToolchainMismatch, ProjectAdmissionRefused, CommandFailed, CommandIncomplete, ArtifactMissing,
    ArtifactAmbiguous, ArtifactUnsafe, ArtifactChanged, InputLimit, ResultLimit,
    WorkRetained, CleanupUnknown,
}
impl Reason {
    fn from_offline(value: wire::Reason) -> Self { match value {
            wire::Reason::None => Self::None, wire::Reason::Cancelled => Self::Cancelled, wire::Reason::ContextChanged => Self::ContextChanged,
            wire::Reason::DocumentLost => Self::DocumentLost, wire::Reason::Shutdown => Self::Shutdown, wire::Reason::TimedOut => Self::TimedOut,
            wire::Reason::ProtocolError => Self::ProtocolError, wire::Reason::RuntimeUnavailable => Self::RuntimeUnavailable, wire::Reason::IntentExpired => Self::IntentExpired,
            wire::Reason::StaleIntent => Self::StaleIntent, wire::Reason::SavedConfigMissing => Self::SavedConfigMissing, wire::Reason::SavedConfigInvalid => Self::SavedConfigInvalid,
            wire::Reason::SavedConfigChanged => Self::SavedConfigChanged, wire::Reason::SavedConfigSensitive => Self::SavedConfigSensitive, wire::Reason::SavedConfigUnsafe => Self::SavedConfigUnsafe,
            wire::Reason::SavedConfigTooLarge => Self::SavedConfigTooLarge, wire::Reason::PlatformDisabled => Self::PlatformDisabled, wire::Reason::ProjectAdmissionRefused => Self::ProjectAdmissionRefused,
            wire::Reason::InputLimit => Self::InputLimit, wire::Reason::ResultLimit => Self::ResultLimit, wire::Reason::CommandIncomplete => Self::CommandIncomplete,
            wire::Reason::CleanupUnknown => Self::CleanupUnknown,
    } }
    fn from_android(value: android_wire::Reason) -> Self { match value {
            android_wire::Reason::None => Self::None, android_wire::Reason::Cancelled => Self::Cancelled, android_wire::Reason::ContextChanged => Self::ContextChanged,
            android_wire::Reason::DocumentLost => Self::DocumentLost, android_wire::Reason::Shutdown => Self::Shutdown, android_wire::Reason::TimedOut => Self::TimedOut,
            android_wire::Reason::ProtocolError => Self::ProtocolError, android_wire::Reason::RuntimeUnavailable => Self::RuntimeUnavailable, android_wire::Reason::IntentExpired => Self::IntentExpired,
            android_wire::Reason::StaleIntent => Self::StaleIntent, android_wire::Reason::SavedConfigMissing => Self::SavedConfigMissing, android_wire::Reason::SavedConfigInvalid => Self::SavedConfigInvalid,
            android_wire::Reason::SavedConfigChanged => Self::SavedConfigChanged, android_wire::Reason::SavedConfigSensitive => Self::SavedConfigSensitive, android_wire::Reason::SavedConfigUnsafe => Self::SavedConfigUnsafe,
            android_wire::Reason::SavedConfigTooLarge => Self::SavedConfigTooLarge, android_wire::Reason::SavedVersionMissing => Self::SavedVersionMissing, android_wire::Reason::SavedVersionInvalid => Self::SavedVersionInvalid,
            android_wire::Reason::SavedVersionChanged => Self::SavedVersionChanged, android_wire::Reason::SavedVersionSensitive => Self::SavedVersionSensitive, android_wire::Reason::SavedVersionUnsafe => Self::SavedVersionUnsafe,
            android_wire::Reason::SavedVersionTooLarge => Self::SavedVersionTooLarge, android_wire::Reason::PlatformDisabled => Self::PlatformDisabled, android_wire::Reason::ModuleRequired => Self::ModuleRequired,
            android_wire::Reason::ToolchainUnavailable => Self::ToolchainUnavailable, android_wire::Reason::ToolchainMismatch => Self::ToolchainMismatch, android_wire::Reason::ProjectAdmissionRefused => Self::ProjectAdmissionRefused,
            android_wire::Reason::CommandFailed => Self::CommandFailed, android_wire::Reason::CommandIncomplete => Self::CommandIncomplete, android_wire::Reason::ArtifactMissing => Self::ArtifactMissing,
            android_wire::Reason::ArtifactAmbiguous => Self::ArtifactAmbiguous, android_wire::Reason::ArtifactUnsafe => Self::ArtifactUnsafe, android_wire::Reason::ArtifactChanged => Self::ArtifactChanged,
            android_wire::Reason::InputLimit => Self::InputLimit, android_wire::Reason::ResultLimit => Self::ResultLimit, android_wire::Reason::WorkRetained => Self::WorkRetained,
            android_wire::Reason::CleanupUnknown => Self::CleanupUnknown,
    } }
    fn offline(self) -> Result<wire::Reason, BridgeError> {
        Ok(match self {
            Self::None => wire::Reason::None, Self::Cancelled => wire::Reason::Cancelled, Self::ContextChanged => wire::Reason::ContextChanged,
            Self::DocumentLost => wire::Reason::DocumentLost, Self::Shutdown => wire::Reason::Shutdown, Self::TimedOut => wire::Reason::TimedOut,
            Self::ProtocolError => wire::Reason::ProtocolError, Self::RuntimeUnavailable => wire::Reason::RuntimeUnavailable, Self::IntentExpired => wire::Reason::IntentExpired,
            Self::StaleIntent => wire::Reason::StaleIntent, Self::SavedConfigMissing => wire::Reason::SavedConfigMissing, Self::SavedConfigInvalid => wire::Reason::SavedConfigInvalid,
            Self::SavedConfigChanged => wire::Reason::SavedConfigChanged, Self::SavedConfigSensitive => wire::Reason::SavedConfigSensitive, Self::SavedConfigUnsafe => wire::Reason::SavedConfigUnsafe,
            Self::SavedConfigTooLarge => wire::Reason::SavedConfigTooLarge, Self::PlatformDisabled => wire::Reason::PlatformDisabled, Self::ProjectAdmissionRefused => wire::Reason::ProjectAdmissionRefused,
            Self::InputLimit => wire::Reason::InputLimit, Self::ResultLimit => wire::Reason::ResultLimit, Self::CommandIncomplete => wire::Reason::CommandIncomplete,
            Self::CleanupUnknown => wire::Reason::CleanupUnknown,
            Self::SavedVersionMissing | Self::SavedVersionInvalid | Self::SavedVersionChanged | Self::SavedVersionSensitive |
            Self::SavedVersionUnsafe | Self::SavedVersionTooLarge | Self::ModuleRequired | Self::ToolchainUnavailable |
            Self::ToolchainMismatch | Self::CommandFailed | Self::ArtifactMissing | Self::ArtifactAmbiguous |
            Self::ArtifactUnsafe | Self::ArtifactChanged | Self::WorkRetained => return Err(BridgeError::protocol()),
        })
    }
    fn android(self) -> android_wire::Reason { match self {
            Self::None => android_wire::Reason::None, Self::Cancelled => android_wire::Reason::Cancelled, Self::ContextChanged => android_wire::Reason::ContextChanged,
            Self::DocumentLost => android_wire::Reason::DocumentLost, Self::Shutdown => android_wire::Reason::Shutdown, Self::TimedOut => android_wire::Reason::TimedOut,
            Self::ProtocolError => android_wire::Reason::ProtocolError, Self::RuntimeUnavailable => android_wire::Reason::RuntimeUnavailable, Self::IntentExpired => android_wire::Reason::IntentExpired,
            Self::StaleIntent => android_wire::Reason::StaleIntent, Self::SavedConfigMissing => android_wire::Reason::SavedConfigMissing, Self::SavedConfigInvalid => android_wire::Reason::SavedConfigInvalid,
            Self::SavedConfigChanged => android_wire::Reason::SavedConfigChanged, Self::SavedConfigSensitive => android_wire::Reason::SavedConfigSensitive, Self::SavedConfigUnsafe => android_wire::Reason::SavedConfigUnsafe,
            Self::SavedConfigTooLarge => android_wire::Reason::SavedConfigTooLarge, Self::SavedVersionMissing => android_wire::Reason::SavedVersionMissing, Self::SavedVersionInvalid => android_wire::Reason::SavedVersionInvalid,
            Self::SavedVersionChanged => android_wire::Reason::SavedVersionChanged, Self::SavedVersionSensitive => android_wire::Reason::SavedVersionSensitive, Self::SavedVersionUnsafe => android_wire::Reason::SavedVersionUnsafe,
            Self::SavedVersionTooLarge => android_wire::Reason::SavedVersionTooLarge, Self::PlatformDisabled => android_wire::Reason::PlatformDisabled, Self::ModuleRequired => android_wire::Reason::ModuleRequired,
            Self::ToolchainUnavailable => android_wire::Reason::ToolchainUnavailable, Self::ToolchainMismatch => android_wire::Reason::ToolchainMismatch, Self::ProjectAdmissionRefused => android_wire::Reason::ProjectAdmissionRefused,
            Self::CommandFailed => android_wire::Reason::CommandFailed, Self::CommandIncomplete => android_wire::Reason::CommandIncomplete, Self::ArtifactMissing => android_wire::Reason::ArtifactMissing,
            Self::ArtifactAmbiguous => android_wire::Reason::ArtifactAmbiguous, Self::ArtifactUnsafe => android_wire::Reason::ArtifactUnsafe, Self::ArtifactChanged => android_wire::Reason::ArtifactChanged,
            Self::InputLimit => android_wire::Reason::InputLimit, Self::ResultLimit => android_wire::Reason::ResultLimit, Self::WorkRetained => android_wire::Reason::WorkRetained,
            Self::CleanupUnknown => android_wire::Reason::CleanupUnknown,
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified, ToolchainUnqualified }
impl Availability {
    fn from_offline(value: wire::Availability) -> Self { match value {
            wire::Availability::Available => Self::Available, wire::Availability::Busy => Self::Busy, wire::Availability::Shutdown => Self::Shutdown,
            wire::Availability::CleanupUnknown => Self::CleanupUnknown, wire::Availability::DocumentLost => Self::DocumentLost, wire::Availability::UnsupportedPlatform => Self::UnsupportedPlatform,
            wire::Availability::RuntimeUnqualified => Self::RuntimeUnqualified,
    } }
    fn from_android(value: android_wire::Availability) -> Self { match value {
            android_wire::Availability::Available => Self::Available, android_wire::Availability::Busy => Self::Busy, android_wire::Availability::Shutdown => Self::Shutdown,
            android_wire::Availability::CleanupUnknown => Self::CleanupUnknown, android_wire::Availability::DocumentLost => Self::DocumentLost, android_wire::Availability::UnsupportedPlatform => Self::UnsupportedPlatform,
            android_wire::Availability::RuntimeUnqualified => Self::RuntimeUnqualified, android_wire::Availability::ToolchainUnqualified => Self::ToolchainUnqualified,
    } }
    fn offline(self) -> Result<wire::Availability, BridgeError> {
        Ok(match self {
            Self::Available => wire::Availability::Available, Self::Busy => wire::Availability::Busy, Self::Shutdown => wire::Availability::Shutdown,
            Self::CleanupUnknown => wire::Availability::CleanupUnknown, Self::DocumentLost => wire::Availability::DocumentLost, Self::UnsupportedPlatform => wire::Availability::UnsupportedPlatform,
            Self::RuntimeUnqualified => wire::Availability::RuntimeUnqualified,
            Self::ToolchainUnqualified => return Err(BridgeError::protocol()),
        })
    }
    fn android(self) -> android_wire::Availability { match self {
            Self::Available => android_wire::Availability::Available, Self::Busy => android_wire::Availability::Busy, Self::Shutdown => android_wire::Availability::Shutdown,
            Self::CleanupUnknown => android_wire::Availability::CleanupUnknown, Self::DocumentLost => android_wire::Availability::DocumentLost, Self::UnsupportedPlatform => android_wire::Availability::UnsupportedPlatform,
            Self::RuntimeUnqualified => android_wire::Availability::RuntimeUnqualified, Self::ToolchainUnqualified => android_wire::Availability::ToolchainUnqualified,
    } }
}
#[derive(Clone)]
enum Terminal { OfflinePreflight(wire::Terminal), AndroidBuild(android_wire::Terminal) }
impl Terminal {
    fn outcome(&self) -> Outcome { match self {
        Self::OfflinePreflight(t) => Outcome::from_offline(t.outcome), Self::AndroidBuild(t) => Outcome::from_android(t.outcome),
    } }
    fn reason(&self) -> Reason { match self {
        Self::OfflinePreflight(t) => Reason::from_offline(t.reason), Self::AndroidBuild(t) => Reason::from_android(t.reason),
    } }
    fn settled(&self) -> bool { match self {
        Self::OfflinePreflight(t) => t.lifetime.settled(), Self::AndroidBuild(t) => t.settled(),
    } }
}
enum Frame { OfflinePreflight(wire::Frame), AndroidBuild(android_wire::Frame) }
struct Start { operation_id: String, owner_generation: String }
enum Status { OfflinePreflight(wire::Status), AndroidBuild(android_wire::Status) }
impl Status {
    fn offline(self) -> Result<wire::Status, BridgeError> { match self {
        Self::OfflinePreflight(status) => Ok(status), Self::AndroidBuild(_) => Err(BridgeError::protocol()),
    } }
    fn android(self) -> Result<android_wire::Status, BridgeError> { match self {
        Self::AndroidBuild(status) => Ok(status), Self::OfflinePreflight(_) => Err(BridgeError::protocol()),
    } }
}

#[derive(Clone, Copy)]
struct Clocks { admitted: Instant, work: Instant, finality: Instant }
impl Clocks {
    fn new(domain: SavedCommandDomain, admitted: Instant) -> Self {
        let (work, hard) = match domain { SavedCommandDomain::OfflinePreflight => (OFFLINE_WORK, OFFLINE_HARD),
            SavedCommandDomain::AndroidBuild => (ANDROID_WORK, ANDROID_HARD) };
        Self { admitted, work: admitted + work, finality: admitted + hard }
    }
    fn settlement(self, first_stop: Option<Instant>) -> Instant {
        first_stop.map_or(self.finality, |first| self.finality.min(first + SETTLEMENT))
    }
}
#[derive(Clone)]
pub(crate) struct SavedCommandOwner { inner: Arc<Inner> }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct InstalledObservation { control: Arc<crate::shell::installed_observation::commands::Control>, original: Option<Arc<Session>>, retired: bool, core_settled: bool }
struct Inner {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    observation: Mutex<Option<InstalledObservation>>,
    domain: SavedCommandDomain, runtime: RuntimeConfig, toolchain: Option<AndroidToolchainProfile>, registry: Mutex<Registry>, changes: watch::Sender<u32>, changed: Notify, poisoned: AtomicBool,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Mutex<Option<std::sync::Weak<offline_tests::hosted::Permit>>>,
}
struct Registry {
    revision: u32, exhausted: bool, disabled: bool, stopping: bool, document_lost: bool,
    capability: Availability, prepared: Option<Prepared>, active: Option<Active>, last: Option<RunProjection>,
}
struct Prepared { projection: RunProjection, expires: Instant, registration: u32, project: RegisteredRoot }
struct Active {
    owner: Arc<Session>, projection: RunProjection, first_stop: Option<Instant>, work_expired: bool,
    accepted: bool, terminal: bool, unknown: bool, final_join_seen: bool,
}
#[derive(Clone)]
struct RunProjection {
    operation_id: String, owner_generation: String, context: Context, phase: Phase, intent_usable: bool,
    outcome: Option<Outcome>, reason: Reason, result: Option<Terminal>, stage: Option<android_wire::Stage>,
}
impl RunProjection {
    // Copy only public DATA. A core terminal is not a native receipt, and even
    // known retained-work facts stay hidden until the original final Ready join.
    fn public(&self) -> Self {
        let terminal = self.phase == Phase::Terminal;
        let unknown = self.phase == Phase::Unknown;
        let mut p = self.clone();
        p.intent_usable = self.phase == Phase::AwaitingConsent && self.intent_usable;
        p.outcome = if unknown { Some(Outcome::Unknown) } else if terminal { self.outcome } else { None };
        p.reason = if unknown { Reason::CleanupUnknown } else { self.reason };
        p.result = if terminal {
            match &self.result {
                Some(t) if self.outcome == Some(Outcome::Complete) && t.outcome() == Outcome::Complete => Some(t.clone()),
                Some(Terminal::AndroidBuild(t)) if t.outcome != android_wire::Outcome::Complete
                    && t.outcome != android_wire::Outcome::Unknown && t.settled()
                    && t.disposition.artifacts != android_wire::ArtifactDisposition::RetainedLocalResult => self.result.clone(),
                _ => None,
            }
        } else { None };
        p
    }
    fn offline(self) -> Result<wire::Projection, BridgeError> {
        let Context::OfflinePreflight(context) = self.context else { return Err(BridgeError::protocol()); };
        if self.stage.is_some() { return Err(BridgeError::protocol()); }
        let result = match self.result {
            Some(Terminal::OfflinePreflight(t)) => t.result,
            None => None, Some(Terminal::AndroidBuild(_)) => return Err(BridgeError::protocol()),
        };
        Ok(wire::Projection { operation_id: self.operation_id, owner_generation: self.owner_generation, context,
            phase: self.phase.offline(), intent_usable: self.intent_usable, outcome: self.outcome.map(Outcome::offline),
            reason: self.reason.offline()?, result })
    }
    fn android(self) -> Result<android_wire::Projection, BridgeError> {
        let Context::AndroidBuild(context) = self.context else { return Err(BridgeError::protocol()); };
        let (result, activity, disposition) = match self.result {
            Some(Terminal::AndroidBuild(t)) => (t.result, Some(t.activity), Some(t.disposition)),
            None => (None, None, None), Some(Terminal::OfflinePreflight(_)) => return Err(BridgeError::protocol()),
        };
        Ok(android_wire::Projection { operation_id: self.operation_id, owner_generation: self.owner_generation, context,
            phase: self.phase.android(), intent_usable: self.intent_usable, outcome: self.outcome.map(Outcome::android),
            reason: self.reason.android(), stage: self.stage, result, activity, disposition })
    }
}
struct Session {
    domain: SavedCommandDomain, id: String, generation: String, context: Context, profile: Profile, clocks: Clocks,
    registration: u32, project: RegisteredRoot, request: AsyncMutex<Option<Vec<u8>>>,
    stop: watch::Sender<bool>, pipes: watch::Sender<Pipes>, frames: mpsc::Sender<Frame>, wake: Notify,
    native_audit_cutoff: watch::Sender<Instant>,
    output_bytes: AtomicUsize, resource_unknown: AtomicBool,
    driver_done: AtomicBool, driver_joined: AtomicBool, driver_failed: AtomicBool,
    watchdog_joined: AtomicBool, watchdog_failed: AtomicBool, manager_failed: AtomicBool,
    startup: Mutex<Startup>, resources: AsyncMutex<Resources>,
    input: Arc<AsyncMutex<Pipe<ChildStdin>>>, output: Arc<AsyncMutex<Pipe<ChildStdout>>>, error: Arc<AsyncMutex<Pipe<ChildStderr>>>,
    driver: AsyncMutex<Option<JoinHandle<()>>>, watchdog: Mutex<Option<JoinHandle<bool>>>,
    manager: AsyncMutex<Option<JoinHandle<()>>>, observer: AsyncMutex<Option<JoinHandle<bool>>>,
    driver_return: Mutex<Option<Result<(), tokio::task::JoinError>>>, manager_return: Mutex<Option<Result<(), tokio::task::JoinError>>>,
    observer_return: Mutex<Option<Result<bool, tokio::task::JoinError>>>, watchdog_return: Mutex<Option<Result<bool, tokio::task::JoinError>>>,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Option<Arc<offline_tests::hosted::Permit>>,
}
#[derive(Default)]
struct Startup { attempted: bool, returned: bool, failed: bool, child: Option<Child> }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pipes { Pending, Available, Absent }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Close { New, Attempted, Settled, Unknown }
struct Pipe<T> { io: Option<T>, close: Close }
impl<T> Default for Pipe<T> { fn default() -> Self { Self { io: None, close: Close::New } } }
#[derive(Default)]
struct Resources {
    inspection: Option<JoinHandle<Result<VerifiedRuntime, BridgeError>>>, inspection_joined: bool, inspection_failed: bool,
    inspection_started: bool, inspection_error: Option<tokio::task::JoinError>,
    acquisition: Option<JoinHandle<()>>, acquisition_joined: bool, acquisition_failed: bool,
    acquisition_started: bool, acquisition_error: Option<tokio::task::JoinError>,
    offline_selected: bool,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    offline_installed: Option<Arc<Mutex<OfflinePreflightRuntimeSlots>>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    offline_settlement: Option<JoinHandle<CloseOutcome>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    offline_return: Option<Result<CloseOutcome, tokio::task::JoinError>>,
    offline_started: bool, offline_joined: bool, offline_failed: bool,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    native: Option<Arc<Mutex<AndroidNativeBooks>>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    native_settlement: Option<JoinHandle<NativeSettlement>>,
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    native_return: Option<Result<NativeSettlement, tokio::task::JoinError>>,
    native_started: bool, native_joined: bool, native_failed: bool,
    child: Option<Child>, waited: Option<ExitStatus>, wait_failed: bool,
    writer: Option<JoinHandle<WriteEnd>>, stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
    write_end: Option<WriteEnd>, out_end: Option<ReadEnd>, err_end: Option<ReadEnd>,
    write_failed: bool, out_failed: bool, err_failed: bool, frames: Option<mpsc::Receiver<Frame>>,
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum NativePhase { New, Inspecting, Ready, Claimed, Refused, Settling, Settled, Unknown }
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct AndroidNativeBooks {
    runtime: InstalledRuntimeCustody, tools: AndroidToolchainCustody,
    phase: NativePhase, failure: Option<AdmissionFailure>, settlement_started: bool,
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[derive(Clone, Copy, Debug)]
struct NativeSettlement { originals_closed: bool, integrity: bool }
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl AndroidNativeBooks {
    fn new(profile: AndroidToolchainProfile, audit_cutoff: watch::Receiver<Instant>) -> Self {
        let budget = Arc::new(AndroidDescriptorBudget::new(audit_cutoff));
        Self { runtime: InstalledRuntimeCustody::new_android(budget.clone()), tools: AndroidToolchainCustody::new(profile, budget),
            phase: NativePhase::New, failure: None, settlement_started: false }
    }
    fn inspect_once(&mut self, end: Instant, stop: &watch::Receiver<bool>) -> Result<VerifiedRuntime, BridgeError> {
        if self.phase != NativePhase::New { return Err(BridgeError::cleanup_unknown()); }
        self.phase = NativePhase::Inspecting;
        let result = self.runtime.retain_android_once(end, stop).and_then(|_| self.tools.inspect_once(end, stop))
            .and_then(|_| self.runtime.android_data());
        match result {
            Ok(data) => { self.phase = NativePhase::Ready; Ok(data) },
            Err(failure) => { self.failure.get_or_insert(failure); self.phase = NativePhase::Refused;
                Err(SavedCommandDomain::AndroidBuild.unavailable()) },
        }
    }
    fn request_binding(&self, runtime: &VerifiedRuntime) -> Result<android_wire::ToolchainBinding, AdmissionFailure> {
        if self.phase != NativePhase::Ready || self.failure.is_some() || self.settlement_started { return Err(AdmissionFailure::TransferUnavailable); }
        let actual = self.runtime.android_data()?;
        if (actual.python, actual.bootstrap, actual.core, actual.cwd)
            != (runtime.python.clone(), runtime.bootstrap.clone(), runtime.core.clone(), runtime.cwd.clone()) {
            return Err(AdmissionFailure::IdentityChanged);
        }
        self.tools.binding_data()
    }
    fn check_before_spawn(&mut self, runtime: &VerifiedRuntime, end: Instant, stop: &watch::Receiver<bool>) -> Result<(), AdmissionFailure> {
        let _ = self.request_binding(runtime)?;
        let result = self.runtime.check_before_spawn(end, stop).and_then(|_| self.tools.check_before_spawn(end, stop));
        if let Err(failure) = result { self.failure.get_or_insert(failure); self.phase = NativePhase::Refused; }
        result
    }
    fn interrupted(&mut self) {
        self.phase = NativePhase::Unknown; self.failure.get_or_insert(AdmissionFailure::Interrupted);
        self.runtime.mark_interrupted(); self.tools.mark_interrupted();
    }
    fn settle(&mut self, used: bool, end: Instant) -> NativeSettlement {
        if self.settlement_started || self.phase == NativePhase::Claimed && !used {
            return NativeSettlement { originals_closed: false, integrity: false };
        }
        self.settlement_started = true; self.phase = NativePhase::Settling;
        let mut integrity = !used || self.failure.is_none();
        if used {
            // Both independent final passes are owed even after the first error.
            for result in [self.runtime.check_after_use(end), self.tools.check_after_use(end)] {
                if let Err(failure) = result { self.failure.get_or_insert(failure); integrity = false; }
            }
        }
        // Reverse acquisition order, independent one-attempt consuming closes.
        let tools = self.tools.settle_originals(); let runtime = self.runtime.settle_originals();
        let originals_closed = tools == CloseOutcome::Settled && runtime == CloseOutcome::Settled
            && self.tools.settled() && self.runtime.settled();
        self.phase = if originals_closed { NativePhase::Settled } else { NativePhase::Unknown };
        NativeSettlement { originals_closed, integrity }
    }
    fn settled(&self) -> bool { self.phase == NativePhase::Settled && self.runtime.settled() && self.tools.settled() }
}
fn original_session(r: &Registry, owner: &Session) -> bool {
    r.active.as_ref().is_some_and(|a| std::ptr::eq(Arc::as_ptr(&a.owner), owner)
        && a.owner.domain == owner.domain && a.owner.id == owner.id && a.owner.generation == owner.generation
        && a.owner.context == owner.context && a.owner.registration == owner.registration && a.owner.project == owner.project)
}
// Clock/identity veto only, never a substitute for original resource joins.
// In particular, a previously positive final task result cannot retire a now
// Unknown owner or release its exclusion after H/earlier F+10.
fn final_clock_clear(r: &Registry, owner: &Session, now: Instant) -> bool {
    original_session(r, owner) && !r.disabled && !r.exhausted && !owner.resource_unknown.load(Ordering::SeqCst)
        && r.active.as_ref().is_some_and(|a| !a.unknown && now < owner.clocks.settlement(a.first_stop))
}
fn native_worker_lost(book: &Resources, owner: &Session) {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if owner.domain == SavedCommandDomain::OfflinePreflight {
        if let Some(native) = &book.offline_installed {
            match native.lock() { Ok(mut slots) => slots.mark_interrupted(), Err(error) => error.into_inner().mark_interrupted() }
        }
        return;
    }
    if owner.domain != SavedCommandDomain::AndroidBuild { return; }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(native) = &book.native {
        // Called ONLY after the actual original worker's failed Ready return.
        match native.lock() { Ok(mut native) => native.interrupted(), Err(error) => error.into_inner().interrupted() }
    }
}
fn native_final(book: &Resources, domain: SavedCommandDomain) -> bool {
    if domain == SavedCommandDomain::OfflinePreflight { return offline_installed_final(book); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        book.native_started && book.native_joined && !book.native_failed && book.native_settlement.is_none()
            && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, integrity: true })))
            && book.native.as_ref().is_some_and(|native| native.lock().is_ok_and(|native| native.settled()))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    { let _ = book; false }
}

struct WriteEnd { sent: bool, closed: bool, failed: bool }
struct ReadEnd { frames: usize, eof: bool, closed: bool, failed: bool, decoder_settled: bool }
struct Admitted { status: Status, release: Option<oneshot::Sender<()>> }
fn nonce(domain: SavedCommandDomain) -> Result<String, BridgeError> {
    let mut bytes = [0u8; 16]; getrandom::fill(&mut bytes).map_err(|_| domain.unavailable())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes { value.push(HEX[usize::from(byte >> 4)] as char); value.push(HEX[usize::from(byte & 15)] as char); } Ok(value)
}
fn prepare_refusal(domain: SavedCommandDomain, reason: Availability) -> BridgeError {
    // Fixed refusal before any new intent allocation; never after commit.
    if reason == Availability::Busy { domain.busy() } else { domain.unavailable() }
}
fn refusal_reason(reason: Availability) -> Reason { match reason {
    Availability::CleanupUnknown => Reason::CleanupUnknown, Availability::Shutdown => Reason::Shutdown,
    Availability::DocumentLost => Reason::DocumentLost, Availability::Busy => Reason::StaleIntent,
    Availability::ToolchainUnqualified => Reason::ToolchainUnavailable,
    _ => Reason::RuntimeUnavailable,
} }
fn retire(mut projection: RunProjection, reason: Reason) -> RunProjection {
    projection.intent_usable = false; projection.reason = reason; projection.result = None;
    projection.phase = if reason == Reason::CleanupUnknown { Phase::Unknown } else { Phase::Terminal };
    projection.outcome = Some(match reason { Reason::CleanupUnknown => Outcome::Unknown,
        Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown => Outcome::Cancelled,
        Reason::TimedOut => Outcome::TimedOut, _ => Outcome::Refused });
    projection
}

impl SavedCommandOwner {
    pub(crate) fn offline_preflight(runtime: RuntimeConfig) -> Self { Self::new(runtime, SavedCommandDomain::OfflinePreflight) }
    pub(crate) fn android_build(runtime: RuntimeConfig, toolchain: Option<AndroidToolchainProfile>) -> Self {
        Self::new_selected(runtime, SavedCommandDomain::AndroidBuild, toolchain)
    }
    fn require_domain(&self, domain: SavedCommandDomain) -> Result<(), BridgeError> {
        if self.inner.domain == domain { Ok(()) } else { Err(self.inner.domain.invalid_owner()) }
    }
    pub(crate) fn prepare_offline(&self, input: wire::Prepare, registration: u32, project: RegisteredRoot,
        gate: wire::Availability) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::OfflinePreflight)?;
        self.prepare(Context::OfflinePreflight(input.context()), registration, project, Availability::from_offline(gate))?.offline()
    }
    pub(crate) fn start_offline(&self, input: wire::Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>,
        gate: wire::Availability) -> Result<crate::offline_preflight_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::OfflinePreflight)?;
        let admitted = self.start(Start { operation_id: input.operation_id, owner_generation: input.owner_generation },
            admitted_at, registered, Availability::from_offline(gate))?;
        Ok(crate::offline_preflight_owner::Admitted::new(admitted.status.offline()?, admitted.release))
    }
    pub(crate) fn status_offline(&self, gate: wire::Availability) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::OfflinePreflight)?;
        self.status(Availability::from_offline(gate))?.offline()
    }
    pub(crate) fn cancel_offline(&self, operation: &str, generation: &str, gate: wire::Availability) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::OfflinePreflight)?;
        self.cancel(operation, generation, Availability::from_offline(gate))?.offline()
    }
    pub(crate) fn prepare_android(&self, input: android_wire::Prepare, registration: u32, project: RegisteredRoot,
        gate: android_wire::Availability) -> Result<android_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        self.prepare(Context::AndroidBuild(input.context()), registration, project, Availability::from_android(gate))?.android()
    }
    pub(crate) fn start_android(&self, input: android_wire::Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>,
        gate: android_wire::Availability) -> Result<crate::android_build_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        let admitted = self.start(Start { operation_id: input.operation_id, owner_generation: input.owner_generation },
            admitted_at, registered, Availability::from_android(gate))?;
        Ok(crate::android_build_owner::Admitted::new(admitted.status.android()?, admitted.release))
    }
    pub(crate) fn status_android(&self, gate: android_wire::Availability) -> Result<android_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        self.status(Availability::from_android(gate))?.android()
    }
    pub(crate) fn cancel_android(&self, operation: &str, generation: &str, gate: android_wire::Availability) -> Result<android_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        self.cancel(operation, generation, Availability::from_android(gate))?.android()
    }
}

impl SavedCommandOwner {
    fn new(runtime: RuntimeConfig, domain: SavedCommandDomain) -> Self { Self::new_selected(runtime, domain, None) }
    fn new_selected(runtime: RuntimeConfig, domain: SavedCommandDomain, toolchain: Option<AndroidToolchainProfile>) -> Self {
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner {
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            observation: Mutex::new(None),
            domain, runtime, toolchain, registry: Mutex::new(Registry { revision: 0, exhausted: false,
            disabled: false, stopping: false, document_lost: false, capability: Availability::RuntimeUnqualified,
            prepared: None, active: None, last: None }), changes, changed: Notify::new(), poisoned: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: Mutex::new(None),
        }) }
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.inner.lock().stopping }
    pub(crate) fn disabled(&self) -> bool { let r = self.inner.lock(); r.disabled || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) }
    pub(crate) fn can_exit(&self) -> bool { self.reconcile(); let r = self.inner.lock();
        !self.inner.poisoned.load(Ordering::SeqCst) && r.active.is_none() && r.prepared.is_none() }
    pub(crate) fn busy(&self) -> bool { !self.can_exit() }
    pub(crate) fn ensure_idle(&self) -> Result<(), BridgeError> {
        if self.disabled() { Err(BridgeError::cleanup_unknown()) } else if self.stopping() { Err(BridgeError::shutdown()) }
        else if self.busy() { Err(self.inner.domain.busy()) } else { Ok(()) }
    }
    pub(crate) fn prepared_project(&self, operation: &str, generation: &str) -> Result<String, BridgeError> {
        self.inner.lock().prepared.as_ref().filter(|p| p.projection.operation_id == operation && p.projection.owner_generation == generation)
            .map(|p| p.projection.context.project_id().to_owned()).ok_or_else(|| self.inner.domain.invalid_owner())
    }
    /// DATA only under the actual DocumentBinding mutex and native registration
    /// lookup. No filesystem/tool/runtime inspection, child or cleanup task.
    fn prepare(&self, context: Context, registration: u32, project: RegisteredRoot, gate: Availability) -> Result<Status, BridgeError> {
        let prepared_at = Instant::now(); // Before this intent's entropy; never renewed by polling.
        if context.domain() != self.inner.domain { return Err(self.inner.domain.invalid_owner()); }
        self.reconcile(); let mut r = self.inner.lock();
        let reason = self.inner.availability(&r, gate);
        if reason != Availability::Available { return Err(prepare_refusal(self.inner.domain, reason)); }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(observation) = self.inner.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?.as_ref() {
            observation.control.claim(crate::shell::installed_observation::commands::Domain::Offline)?;
        }
        let id = nonce(self.inner.domain)?; let generation = nonce(self.inner.domain)?;
        if r.last.as_ref().is_some_and(|last| last.operation_id == id || last.owner_generation == generation) { return Err(self.inner.domain.unavailable()); }
        let projection = RunProjection { operation_id: id, owner_generation: generation, context,
            phase: Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: Reason::None, result: None, stage: None };
        r.prepared = Some(Prepared { projection, expires: prepared_at + INTENT, registration, project });
        self.inner.bump(&mut r);
        // After commit, only typed status or unknown/lost reply, never the three
        // fixed preallocation refusal codes used by the renderer controller.
        self.inner.snapshot_locked(&mut r, gate)
    }
    /// T is captured synchronously at DocumentBinding Start entry, before any
    /// await/entropy/runtime/acquisition. Consume matching consent FIRST.
    fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        let clocks = Clocks::new(self.inner.domain, admitted_at);
        let mut r = self.inner.lock();
        if !r.prepared.as_ref().is_some_and(|p| p.projection.operation_id == input.operation_id && p.projection.owner_generation == input.owner_generation) {
            return Err(self.inner.domain.invalid_owner()); // Foreign/replayed Start never stops another owner.
        }
        let prepared = r.prepared.take().ok_or_else(|| self.inner.domain.invalid_owner())?; // One use, before executor/runtime/effects.
        let mut refused = if Instant::now() >= prepared.expires { Some(Reason::IntentExpired) }
            else if registered.as_ref().is_none_or(|(generation, project)| *generation != prepared.registration || project != &prepared.project) { Some(Reason::StaleIntent) }
            else { None };
        let availability = self.inner.availability(&r, gate);
        if matches!(availability, Availability::CleanupUnknown | Availability::Shutdown | Availability::DocumentLost)
            || refused.is_none() && availability != Availability::Available { refused = Some(refusal_reason(availability)); }
        if refused.is_none() && Instant::now() >= clocks.work { refused = Some(Reason::TimedOut); }
        let executor = tokio::runtime::Handle::try_current().ok();
        let profile = Profile::current(self.inner.domain);
        if refused.is_none() && (executor.is_none() || profile.is_none()) { refused = Some(Reason::RuntimeUnavailable); }
        if let Some(reason) = refused {
            if reason == Reason::CleanupUnknown { r.disabled = true; }
            r.last = Some(retire(prepared.projection, reason)); self.inner.bump(&mut r);
            return Ok(Admitted { status: self.inner.snapshot_locked(&mut r, gate)?, release: None });
        }
        // A consumed intent already has a safe refusal tombstone if an internal
        // allocation/slot error prevents admission. It is never armed again.
        r.last = Some(retire(prepared.projection.clone(), Reason::StaleIntent));
        self.inner.bump(&mut r);
        let executor = executor.ok_or_else(|| self.inner.domain.unavailable())?;
        let profile = profile.ok_or_else(|| self.inner.domain.unavailable())?;
        let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
        let (native_audit_cutoff, audit_cutoff) = watch::channel(clocks.work);
        let (frames, receiver) = mpsc::channel(2);
        let context = prepared.projection.context;
        let projection = RunProjection { operation_id: input.operation_id.clone(), owner_generation: input.owner_generation.clone(),
            context: context.clone(), phase: Phase::Starting, intent_usable: false, outcome: None, reason: Reason::None, result: None, stage: None };
        let owner = Arc::new(Session { domain: self.inner.domain, id: input.operation_id, generation: input.owner_generation, context, profile, clocks,
            registration: prepared.registration, project: prepared.project, request: AsyncMutex::new(None), stop, pipes, frames, wake: Notify::new(), native_audit_cutoff,
            output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false), driver_done: AtomicBool::new(false),
            driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false), watchdog_joined: AtomicBool::new(false),
            watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false), startup: Mutex::new(Startup::default()),
            resources: AsyncMutex::new(Resources { frames: Some(receiver),
                offline_selected: self.inner.offline_installed_selected(),
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                offline_installed: self.inner.offline_installed_selected().then(|| Arc::new(Mutex::new(OfflinePreflightRuntimeSlots::new()))),
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                native: if self.inner.domain == SavedCommandDomain::AndroidBuild {
                    self.inner.toolchain.clone().map(|profile| Arc::new(Mutex::new(AndroidNativeBooks::new(profile, audit_cutoff))))
                } else { None },
                ..Resources::default() }),
            input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())), error: Arc::new(AsyncMutex::new(Pipe::default())),
            driver: AsyncMutex::new(None), watchdog: Mutex::new(None), manager: AsyncMutex::new(None), observer: AsyncMutex::new(None),
            driver_return: Mutex::new(None), manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: if self.inner.domain == SavedCommandDomain::OfflinePreflight {
                self.inner.fixture.lock().ok().and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade))
            } else { None },
        });
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture {
            if owner.domain != SavedCommandDomain::OfflinePreflight { return Err(self.inner.domain.unavailable()); }
            permit.bind(&owner)?;
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(observation) = self.inner.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?.as_mut() {
            if observation.original.is_some() { return Err(self.inner.domain.unavailable()); }
            observation.original = Some(owner.clone());
        }
        let (release, enter) = oneshot::channel();
        // Every new roster slot precedes publication/spawn. No hosted-fixture
        // alternate bootstrap, other-owner permission or caller-owned runner.
        let mut book = owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut driver = owner.driver.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut watchdog_slot = owner.watchdog.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut manager = owner.manager.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut observer = owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        r.active = Some(Active { owner: owner.clone(), projection, first_stop: None, work_expired: false,
            accepted: false, terminal: false, unknown: false, final_join_seen: false });
        *watchdog_slot = Some(executor.spawn(watchdog(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        book.writer = Some(executor.spawn(write_request(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        book.stdout = Some(executor.spawn(read_output(self.inner.clone(), owner.clone(), owner.output.clone(), false, Guard::new(&self.inner, &owner))));
        book.stderr = Some(executor.spawn(read_output(self.inner.clone(), owner.clone(), owner.error.clone(), true, Guard::new(&self.inner, &owner))));
        *driver = Some(executor.spawn(drive(self.inner.clone(), owner.clone(), enter, Guard::new(&self.inner, &owner))));
        *manager = Some(executor.spawn(manage(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        *observer = Some(executor.spawn(observe_final(self.inner.clone(), owner.clone(), Guard::new(&self.inner, &owner))));
        self.inner.bump(&mut r);
        let status = self.inner.snapshot_locked(&mut r, gate)?;
        drop(observer); drop(manager); drop(watchdog_slot); drop(driver); drop(book); drop(r);
        self.reconcile(); // Original final-handle completion waker, before GO.
        Ok(Admitted { status, release: Some(release) })
    }
    fn status(&self, gate: Availability) -> Result<Status, BridgeError> {
        self.reconcile(); self.inner.snapshot_locked(&mut self.inner.lock(), gate)
    }
    fn cancel(&self, operation: &str, generation: &str, gate: Availability) -> Result<Status, BridgeError> {
        let mut r = self.inner.lock();
        // Match before clock reconciliation: foreign DATA changes no owner.
        if r.prepared.as_ref().is_some_and(|p| p.projection.operation_id == operation && p.projection.owner_generation == generation) {
            self.inner.retire_prepared(&mut r, Reason::Cancelled);
        } else if let Some(a) = r.active.as_ref().filter(|a| a.owner.id == operation && a.owner.generation == generation) {
            let owner = a.owner.clone(); self.inner.stop_locked(&mut r, &owner, Reason::Cancelled, Instant::now());
        } else if !r.last.as_ref().is_some_and(|last| last.operation_id == operation && last.owner_generation == generation) { return Err(self.inner.domain.invalid_owner()); }
        drop(r); self.status(gate)
    }
    #[cfg(test)]
    pub(crate) fn observed_document_lost_for_test(&self) -> Option<bool> {
        // Original startup DATA only; no reconciliation, mutation or blocking.
        self.inner.registry.try_lock().ok().map(|registry| registry.document_lost)
    }
    pub(crate) fn document_lost(&self) {
        let mut r = self.inner.lock(); if r.document_lost { return; } r.document_lost = true;
        self.inner.retire_prepared(&mut r, Reason::DocumentLost);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::DocumentLost, Instant::now()); }
        self.inner.bump(&mut r);
    }
    pub(crate) fn context_changed(&self) {
        let mut r = self.inner.lock(); self.inner.retire_prepared(&mut r, Reason::ContextChanged);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::ContextChanged, Instant::now()); }
    }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool {
        let r = self.inner.lock(); r.active.as_ref().is_none_or(|a| a.owner.registration == registration)
            && r.prepared.as_ref().is_none_or(|p| p.registration == registration)
    }
    pub(crate) fn request_shutdown(&self) {
        let mut r = self.inner.lock(); r.stopping = true; self.inner.retire_prepared(&mut r, Reason::Shutdown);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::Shutdown, Instant::now()); }
        self.inner.bump(&mut r);
    }
    pub(crate) async fn shutdown(&self) -> Result<(), BridgeError> {
        self.request_shutdown();
        loop {
            if self.can_exit() { return Ok(()); }
            if self.disabled() { return Err(BridgeError::cleanup_unknown()); }
            tokio::select! { _ = self.inner.changed.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(25)) => {} }
        }
    }
    fn reconcile(&self) {
        let owner = { let mut r = self.inner.lock(); self.inner.expire_prepared(&mut r, Instant::now()); r.active.as_ref().map(|a| a.owner.clone()) };
        let Some(owner) = owner else { return; };
        let mut r = self.inner.lock(); self.inner.advance_locked(&mut r, &owner, Instant::now());
        let Some(active) = r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, &owner)) else { return; };
        if active.final_join_seen { return; }
        let mut watchdog_slot = match owner.watchdog.try_lock() {
            Ok(slot) => slot, Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(_)) => { self.inner.unknown_locked(&mut r, &owner); return; }
        };
        let Some(handle) = watchdog_slot.as_mut() else { self.inner.unknown_locked(&mut r, &owner); return; };
        let waker = Waker::from(Arc::new(FinalWake(Arc::downgrade(&self.inner))));
        let mut context = TaskContext::from_waker(&waker);
        let Poll::Ready(result) = Pin::new(handle).poll(&mut context) else { return; };
        if let Some(a) = r.active.as_mut() { a.final_join_seen = true; }
        let positive = matches!(&result, Ok(true)); let joined = result.is_ok();
        let recorded = record_join(&owner.watchdog_return, result);
        owner.watchdog_joined.store(joined && recorded, Ordering::SeqCst);
        owner.watchdog_failed.store(!joined || !recorded, Ordering::SeqCst);
        if positive && recorded {
            self.inner.advance_locked(&mut r, &owner, Instant::now());
            if !final_clock_clear(&r, &owner, Instant::now()) {
                // Keep both the actual Ready result and the same original
                // handle/owner. final_join_seen prevents re-polling that handle.
                owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown_locked(&mut r, &owner); return;
            }
            watchdog_slot.take();
            if let Some(mut active) = r.active.take() {
                if !Arc::ptr_eq(&active.owner, &owner) { r.active = Some(active); return; }
                active.projection.phase = if active.unknown { Phase::Unknown } else { Phase::Terminal };
                if active.projection.outcome.is_none() { set_failure_outcome(&mut active.projection); }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Ok(mut observation) = self.inner.observation.lock() {
                    if let Some(observation) = observation.as_mut().filter(|o| o.original.as_ref().is_some_and(|s| Arc::ptr_eq(s, &owner))) {
                        observation.retired = true;
                        observation.core_settled = active.accepted && active.terminal && active.projection.result.as_ref().is_some_and(Terminal::settled);
                    }
                }
                r.last = Some(active.projection.public()); self.inner.bump(&mut r);
            }
        } else {
            // Retain the original failed handle and its result; never re-poll it.
            owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown_locked(&mut r, &owner);
        }
    }
}
struct FinalWake(std::sync::Weak<Inner>);
impl Wake for FinalWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { if let Some(inner) = self.0.upgrade() { inner.changes.send_modify(|_| {}); inner.changed.notify_one(); } }
}
fn record_join<T>(slot: &Mutex<Option<Result<T, tokio::task::JoinError>>>, result: Result<T, tokio::task::JoinError>) -> bool {
    match slot.lock() { Ok(mut slot) if slot.is_none() => { *slot = Some(result); true }, _ => false }
}
fn set_failure_outcome(p: &mut RunProjection) {
    if p.reason == Reason::None {
        p.reason = match p.context.domain() { SavedCommandDomain::OfflinePreflight => Reason::CommandIncomplete,
            SavedCommandDomain::AndroidBuild => Reason::ProtocolError };
    }
    // Known retained work is not successful cancellation/disposal. Keep the
    // original first reason, but preserve the core's Failed disposition outcome.
    if let Some(Terminal::AndroidBuild(t)) = &p.result {
        if t.outcome == android_wire::Outcome::Failed && t.disposition.work == android_wire::WorkDisposition::RetainedWork {
            p.outcome = Some(Outcome::Failed); return;
        }
    }
    p.outcome = Some(match p.reason {
        Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown => Outcome::Cancelled,
        Reason::TimedOut => Outcome::TimedOut, Reason::RuntimeUnavailable | Reason::ToolchainUnavailable => Outcome::Refused, Reason::CleanupUnknown => Outcome::Unknown,
        _ => p.result.as_ref().filter(|t| t.reason() == p.reason && t.outcome() != Outcome::Complete).map_or(Outcome::Failed, Terminal::outcome),
    });
}
impl Inner {
    fn offline_installed_selected(&self) -> bool {
        let qualified = OFFLINE_NATIVE_QUALIFIED && OFFLINE_RUNTIME_QUALIFIED;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let qualified = qualified || self.observation.lock().is_ok_and(|o| o.is_some());
        self.domain == SavedCommandDomain::OfflinePreflight && qualified && self.runtime.offline_preflight_installed_profile_available()
    }
    fn qualified(&self) -> bool {
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if self.domain == SavedCommandDomain::OfflinePreflight && self.fixture.lock().ok().and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade))
            .is_some_and(|permit| permit.permits(self)) { return true; }
        match self.domain {
            SavedCommandDomain::OfflinePreflight => self.offline_installed_selected(),
            SavedCommandDomain::AndroidBuild => ANDROID_NATIVE_QUALIFIED && ANDROID_RUNTIME_QUALIFIED && ANDROID_TOOLCHAIN_QUALIFIED && self.toolchain.is_some(),
        }
    }
    fn lock(&self) -> MutexGuard<'_, Registry> {
        match self.registry.lock() { Ok(r) => r, Err(error) => { self.poisoned.store(true, Ordering::SeqCst); error.into_inner() } }
    }
    fn bump(&self, r: &mut Registry) {
        if r.exhausted { return; }
        match r.revision.checked_add(1).filter(|n| *n < u32::MAX) {
            Some(next) => r.revision = next,
            None => { r.exhausted = true; r.disabled = true;
                if let Some(prepared) = r.prepared.take() { r.last = Some(retire(prepared.projection, Reason::CleanupUnknown)); }
                if let Some(a) = &r.active { a.owner.stop.send_replace(true); a.owner.wake.notify_waiters(); }
            },
        }
        self.changes.send_replace(r.revision); self.changed.notify_waiters();
    }
    fn retire_prepared(&self, r: &mut Registry, reason: Reason) {
        if let Some(prepared) = r.prepared.take() {
            if reason == Reason::CleanupUnknown { r.disabled = true; }
            r.last = Some(retire(prepared.projection, reason)); self.bump(r);
        }
    }
    fn expire_prepared(&self, r: &mut Registry, now: Instant) {
        if r.prepared.as_ref().is_some_and(|p| now >= p.expires) { self.retire_prepared(r, Reason::IntentExpired); }
    }
    fn availability(&self, r: &Registry, gate: Availability) -> Availability {
        if r.disabled || r.exhausted || self.poisoned.load(Ordering::SeqCst) || gate == Availability::CleanupUnknown { Availability::CleanupUnknown }
        else if r.stopping || gate == Availability::Shutdown { Availability::Shutdown }
        // No original can have started on an unsupported backend. Its missing
        // editing/crash hook must not falsely lock unrelated passive services.
        // Actual retained owners and Unknown still take their original gates.
        else if r.active.is_none() && r.prepared.is_none()
            && (Profile::current(self.domain).is_none() || gate == Availability::UnsupportedPlatform) { Availability::UnsupportedPlatform }
        else if r.document_lost || gate == Availability::DocumentLost { Availability::DocumentLost }
        else if r.active.is_some() || r.prepared.is_some() || gate == Availability::Busy { Availability::Busy }
        else if !self.qualified() {
            match self.domain {
                SavedCommandDomain::OfflinePreflight => Availability::RuntimeUnqualified,
                SavedCommandDomain::AndroidBuild if !ANDROID_NATIVE_QUALIFIED || !ANDROID_RUNTIME_QUALIFIED => Availability::RuntimeUnqualified,
                SavedCommandDomain::AndroidBuild => Availability::ToolchainUnqualified,
            }
        } else { gate }
    }
    fn snapshot_locked(&self, r: &mut Registry, gate: Availability) -> Result<Status, BridgeError> {
        self.expire_prepared(r, Instant::now());
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.advance_locked(r, &owner, Instant::now()); }
        if r.exhausted || self.poisoned.load(Ordering::SeqCst) { return Err(BridgeError::cleanup_unknown()); }
        let reason = self.availability(r, gate);
        if reason != r.capability { r.capability = reason; self.bump(r); }
        if r.exhausted { return Err(BridgeError::cleanup_unknown()); }
        let operation = r.active.as_ref().map(|a| a.projection.public())
            .or_else(|| r.prepared.as_ref().map(|p| p.projection.clone())).or_else(|| r.last.clone());
        match self.domain {
            SavedCommandDomain::OfflinePreflight => {
                let status = wire::Status { schema_version: 1, status_revision: r.revision, availability: reason.offline()?,
                    operation: operation.map(RunProjection::offline).transpose()? };
                crate::edit_protocol::bounded(&status, wire::STATUS_LIMIT)?; Ok(Status::OfflinePreflight(status))
            }
            SavedCommandDomain::AndroidBuild => {
                let status = android_wire::Status { schema_version: 1, status_revision: r.revision, availability: reason.android(),
                    operation: operation.map(RunProjection::android).transpose()? };
                android_wire::status_bytes(&status)?; Ok(Status::AndroidBuild(status))
            }
        }
    }
    fn stop_locked(&self, r: &mut Registry, owner: &Session, reason: Reason, at: Instant) {
        let Some(active) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        let at = at.min(owner.clocks.work).max(owner.clocks.admitted); let mut changed = false;
        if active.first_stop.is_none() { active.first_stop = Some(at); changed = true; }
        if owner.domain == SavedCommandDomain::AndroidBuild {
            let end = owner.clocks.work.min(owner.clocks.settlement(active.first_stop));
            owner.native_audit_cutoff.send_if_modified(|current| {
                if end < *current { *current = end; true } else { false }
            });
        }
        if active.projection.reason == Reason::None && reason != Reason::None { active.projection.reason = reason; changed = true; }
        if !active.unknown && active.projection.phase != Phase::Stopping { active.projection.phase = Phase::Stopping; changed = true; }
        if active.projection.reason != Reason::None { set_failure_outcome(&mut active.projection); }
        let first_signal = owner.stop.send_if_modified(|stopped| { if *stopped { false } else { *stopped = true; true } });
        if changed || first_signal { owner.wake.notify_waiters(); } if changed { self.bump(r); }
    }
    fn unknown_locked(&self, r: &mut Registry, owner: &Session) {
        self.stop_locked(r, owner, Reason::CleanupUnknown, Instant::now());
        if let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) {
            if !a.unknown { a.unknown = true; a.projection.phase = Phase::Unknown; r.disabled = true; self.bump(r); }
        }
    }
    fn advance_locked(&self, r: &mut Registry, owner: &Session, now: Instant) {
        let Some(a) = r.active.as_ref().filter(|a| a.owner.id == owner.id) else { return; };
        if now >= owner.clocks.work && !a.work_expired {
            if let Some(a) = r.active.as_mut() { a.work_expired = true; }
            self.stop_locked(r, owner, Reason::TimedOut, owner.clocks.work);
        }
        let finality_due = r.active.as_ref().is_some_and(|a| !a.unknown && now >= owner.clocks.settlement(a.first_stop));
        if finality_due || self.poisoned.load(Ordering::SeqCst) || owner.resource_unknown.load(Ordering::SeqCst) { self.unknown_locked(r, owner); }
    }
    fn stop(&self, owner: &Session, reason: Reason) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.stop_locked(&mut r, owner, reason, Instant::now()); }
    fn unknown(&self, owner: &Session) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.unknown_locked(&mut r, owner); }
    fn endpoint(&self, owner: &Session) -> Option<Instant> {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now());
        let a = r.active.as_ref().filter(|a| a.owner.id == owner.id)?;
        if a.unknown { None } else if a.first_stop.is_some() { Some(owner.clocks.settlement(a.first_stop)) } else { Some(owner.clocks.work) }
    }
    fn accept(&self, owner: &Session, frame: Frame) { self.accept_at(owner, frame, Instant::now()); }
    fn accept_at(&self, owner: &Session, frame: Frame, now: Instant) {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, now);
        if owner.domain != self.domain || owner.context.domain() != owner.domain {
            owner.resource_unknown.store(true, Ordering::SeqCst);
            self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked(&mut r, owner); return;
        }
        // Only these two typed streams exist; crossing domains is a protocol
        // failure, never a reinterpretation of an Offline terminal as Android.
        enum Incoming { Accepted(Option<android_wire::Stage>), Progress(android_wire::Stage), Terminal(Terminal) }
        let incoming = match (owner.domain, frame) {
            (SavedCommandDomain::OfflinePreflight, Frame::OfflinePreflight(wire::Frame::Accepted)) => Incoming::Accepted(None),
            (SavedCommandDomain::OfflinePreflight, Frame::OfflinePreflight(wire::Frame::Terminal(t))) => Incoming::Terminal(Terminal::OfflinePreflight(t)),
            (SavedCommandDomain::AndroidBuild, Frame::AndroidBuild(android_wire::Frame::Accepted)) => Incoming::Accepted(Some(android_wire::Stage::Accepted)),
            (SavedCommandDomain::AndroidBuild, Frame::AndroidBuild(android_wire::Frame::Progress(stage))) => Incoming::Progress(stage),
            (SavedCommandDomain::AndroidBuild, Frame::AndroidBuild(android_wire::Frame::Terminal(t))) => Incoming::Terminal(Terminal::AndroidBuild(t)),
            (SavedCommandDomain::OfflinePreflight, Frame::AndroidBuild(_)) | (SavedCommandDomain::AndroidBuild, Frame::OfflinePreflight(_)) => {
                owner.resource_unknown.store(true, Ordering::SeqCst);
                self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked(&mut r, owner); return;
            }
        };
        let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        match incoming {
            Incoming::Accepted(stage) if !a.accepted && !a.terminal => {
                a.accepted = true; a.projection.stage = stage;
                if a.first_stop.is_none() && !a.unknown { a.projection.phase = Phase::Running; } self.bump(&mut r);
            }
            Incoming::Progress(stage) if a.accepted && !a.terminal
                && a.projection.stage.is_some_and(|previous| stage > previous) => {
                a.projection.stage = Some(stage); self.bump(&mut r);
            }
            Incoming::Terminal(terminal) if a.accepted && !a.terminal => {
                if let Terminal::AndroidBuild(t) = &terminal {
                    if a.projection.stage.is_none_or(|stage| t.activity.stage < stage) {
                        owner.resource_unknown.store(true, Ordering::SeqCst);
                        self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked(&mut r, owner); return;
                    }
                    a.projection.stage = Some(t.activity.stage);
                }
                a.terminal = true; let settled = terminal.settled() && terminal.outcome() != Outcome::Unknown; let reason = terminal.reason();
                if a.projection.reason == Reason::None { a.projection.outcome = Some(terminal.outcome()); }
                a.projection.result = Some(terminal); self.bump(&mut r);
                if reason == Reason::None {
                    // Complete policy FAIL/MISSING/nonzero rows are NOT F. This
                    // closes the already-finished core input, still provisional.
                    if let Some(a) = r.active.as_mut() { if !a.unknown { a.projection.phase = Phase::Stopping; } }
                    owner.stop.send_replace(true); owner.wake.notify_waiters(); self.bump(&mut r);
                } else { self.stop_locked(&mut r, owner, reason, now); }
                if !settled { owner.resource_unknown.store(true, Ordering::SeqCst); self.unknown_locked(&mut r, owner); }
            }
            _ => { owner.resource_unknown.store(true, Ordering::SeqCst); self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked(&mut r, owner); }
        }
        owner.wake.notify_waiters();
    }
}

struct Guard { inner: Arc<Inner>, owner: Arc<Session>, complete: bool }
impl Guard { fn new(inner: &Arc<Inner>, owner: &Arc<Session>) -> Self { Self { inner: inner.clone(), owner: owner.clone(), complete: false } } }
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.complete { self.owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown(&self.owner); }
    }
}
trait OriginalClose { fn original_close(self) -> Result<(), ()>; }
macro_rules! close_pipe {
    ($type:ty) => { impl OriginalClose for $type {
        fn original_close(self) -> Result<(), ()> {
            #[cfg(unix)] { let owned = self.into_owned_fd().map_err(|_| ())?; nix::unistd::close(owned).map_err(|_| ()) }
            #[cfg(not(unix))] { let _ = self; Err(()) }
        }
    } };
}
close_pipe!(ChildStdin); close_pipe!(ChildStdout); close_pipe!(ChildStderr);
fn close_original<T: OriginalClose>(pipe: &mut Pipe<T>) -> bool {
    if pipe.close == Close::Settled { return true; }
    if pipe.close != Close::New { return false; }
    pipe.close = Close::Attempted;
    match pipe.io.take().map(OriginalClose::original_close) {
        Some(Ok(())) => { pipe.close = Close::Settled; true },
        _ => { pipe.close = Close::Unknown; false },
    }
}
async fn pipe_state(owner: &Session) -> Option<bool> {
    let mut state = owner.pipes.subscribe();
    loop {
        let value = *state.borrow_and_update();
        match value { Pipes::Available => return Some(true), Pipes::Absent => return Some(false), Pipes::Pending => {} }
        if state.changed().await.is_err() { return None; }
    }
}
async fn write_request(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> WriteEnd {
    match pipe_state(&owner).await {
        Some(true) => {}, other => { guard.complete = other.is_some(); return WriteEnd { sent: false, closed: false, failed: other.is_none() }; }
    }
    let mut input = owner.input.lock().await;
    let mut request = owner.request.lock().await;
    let mut stop = owner.stop.subscribe();
    let mut sent = false; let mut failed = false;
    if !*stop.borrow() {
        match (input.io.as_mut(), request.as_ref()) {
            (Some(writer), Some(bytes)) if bytes.len() <= owner.domain.request_limit() => {
                let result = tokio::select! { biased;
                    _ = stop.changed() => None,
                    result = writer.write_all(bytes) => Some(result),
                };
                match result { Some(Ok(())) => sent = true, Some(Err(_)) => failed = true, None => {} }
            }
            _ => failed = true,
        }
    }
    request.take(); drop(request); // Retire only this original bounded input.
    if failed { inner.stop(&owner, Reason::ProtocolError); }
    if sent && !failed {
        // Hold this sole writer after the one complete request. Closing it is
        // STOP, not ordinary request framing or a renderer acknowledgment.
        while !*stop.borrow_and_update() { if stop.changed().await.is_err() { failed = true; break; } }
    }
    let closed = close_original(&mut input);
    if !closed { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
    guard.complete = true; WriteEnd { sent, closed, failed }
}
// Decoder state is original per stdout reader; it is never reconstructed from
// a terminal or from the public projection. This is DATA validation only.
enum OutputDecoder {
    OfflinePreflight { frames: usize, failed: bool },
    AndroidBuild(android_wire::FrameDecoder),
}
impl OutputDecoder {
    fn new(owner: &Session) -> Result<Self, BridgeError> {
        match (owner.domain, &owner.context) {
            (SavedCommandDomain::OfflinePreflight, Context::OfflinePreflight(_)) => Ok(Self::OfflinePreflight { frames: 0, failed: false }),
            (SavedCommandDomain::AndroidBuild, Context::AndroidBuild(context)) =>
                android_wire::FrameDecoder::new(&owner.id, &owner.generation, context).map(Self::AndroidBuild),
            _ => Err(BridgeError::protocol()),
        }
    }
    fn push(&mut self, bytes: &[u8], owner: &Session) -> Result<Frame, BridgeError> {
        match self {
            Self::OfflinePreflight { frames, failed } => {
                let result = match &owner.context {
                    Context::OfflinePreflight(context) if owner.domain == SavedCommandDomain::OfflinePreflight && !*failed && *frames < 2 =>
                        wire::decode(bytes, &owner.id, &owner.generation, context),
                    _ => Err(BridgeError::protocol()),
                };
                let result = result.and_then(|frame| {
                    if (*frames == 0 && matches!(&frame, wire::Frame::Accepted))
                        || (*frames == 1 && matches!(&frame, wire::Frame::Terminal(_))) { Ok(frame) }
                    else { Err(BridgeError::protocol()) }
                });
                match result {
                    Ok(frame) => { *frames += 1; Ok(Frame::OfflinePreflight(frame)) },
                    Err(error) => { *failed = true; Err(error) },
                }
            }
            Self::AndroidBuild(decoder) => decoder.push(bytes).map(Frame::AndroidBuild),
        }
    }
    fn finish(&mut self) -> bool { match self {
        Self::OfflinePreflight { frames, failed } => { if *frames != 2 { *failed = true; } !*failed },
        Self::AndroidBuild(decoder) => decoder.finish().is_ok() && decoder.settled(),
    } }
}
async fn enqueue_frame(inner: &Inner, owner: &Session, frame: Frame) -> bool {
    match owner.domain {
        // Preserve the original two-frame Offline transport behavior exactly.
        SavedCommandDomain::OfflinePreflight => owner.frames.try_send(frame).is_ok(),
        SavedCommandDomain::AndroidBuild => {
            // A valid seven-frame activity stream must not overflow a two-slot
            // queue just because multiple frames arrived in the same read. The
            // original reader backpressures without spawning a task or enlarging
            // the queue. At the original finality endpoint it rejects and drains.
            let sending = owner.frames.send(frame); tokio::pin!(sending);
            loop {
                let wake = owner.wake.notified(); let end = inner.endpoint(owner);
                if end.is_none() { return false; }
                tokio::select! { result = &mut sending => return result.is_ok(), _ = wake => {}, _ = clock_wait(end) => {} }
            }
        }
    }
}
async fn read_output<T: AsyncRead + Unpin + OriginalClose>(inner: Arc<Inner>, owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>, stderr: bool, mut guard: Guard) -> ReadEnd {
    match pipe_state(&owner).await {
        Some(true) => {}, other => { guard.complete = other.is_some(); return ReadEnd { frames: 0, eof: false, closed: false,
            failed: other.is_none(), decoder_settled: false }; }
    }
    let mut pipe = slot.lock().await; let mut buffer = [0u8; 4096]; let mut bytes = Vec::new();
    let mut frames = 0usize; let mut failed = false; let mut eof = false; let mut discard = false;
    let mut decoder = if stderr { None } else { OutputDecoder::new(&owner).ok() };
    let mut decoder_settled = false;
    if !stderr && decoder.is_none() { failed = true; discard = true; }
    loop {
        let Some(reader) = pipe.io.as_mut() else { failed = true; break; };
        match reader.read(&mut buffer).await {
            Ok(0) => {
                eof = true; if !bytes.is_empty() { failed = true; }
                if !stderr { decoder_settled = decoder.as_mut().is_some_and(OutputDecoder::finish); if !decoder_settled { failed = true; } }
                break;
            }
            Ok(n) => {
                // One aggregate allowance including both transport streams and
                // framing. Continue draining after refusal without retaining raw text.
                let previous = owner.output_bytes.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
                    |value| Some(value.saturating_add(n))).unwrap_or(usize::MAX);
                if previous.saturating_add(n) > owner.domain.response_limit() || stderr { failed = true; discard = true; bytes.clear(); }
                if discard { inner.stop(&owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); continue; }
                for byte in &buffer[..n] {
                    if discard { break; }
                    bytes.push(*byte);
                    if *byte == b'\n' {
                        frames += 1;
                        let frame = if frames <= owner.domain.frame_limit() {
                            match decoder.as_mut() { Some(decoder) => decoder.push(&bytes, &owner), None => Err(BridgeError::protocol()) }
                        } else { Err(BridgeError::protocol()) };
                        let delivered = match frame { Ok(frame) => enqueue_frame(&inner, &owner, frame).await, Err(_) => false };
                        if !delivered { failed = true; discard = true; inner.stop(&owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
                        bytes.clear();
                    }
                }
            }
            Err(_) => { failed = true; break; },
        }
    }
    let closed = close_original(&mut pipe);
    if failed || !closed || !eof { owner.resource_unknown.store(true, Ordering::SeqCst); inner.stop(&owner, Reason::ProtocolError); inner.unknown(&owner); }
    guard.complete = true; ReadEnd { frames, eof, closed, failed, decoder_settled }
}
async fn clock_wait(end: Option<Instant>) {
    match end { Some(end) => tokio::time::sleep_until(tokio::time::Instant::from_std(end)).await, None => pending::<()>().await }
}
async fn watchdog(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> bool {
    // Acyclic: watchdog -> final observer -> manager -> driver/original book.
    // Direct Ready waiting keeps both W/H and the original JoinHandle waker
    // alive even while the final observer itself is held before return.
    let mut observer = owner.observer.lock().await;
    let observed = if observer.is_none() { false } else {
        let result = join_with_clock(&mut observer, &inner, &owner).await;
        let positive = matches!(&result, Ok(true));
        let recorded = record_join(&owner.observer_return, result);
        positive && recorded
    };
    // Preserve the actual observer Ready result even when finality has since
    // become Unknown. Do not consume its original handle before this veto.
    let in_time = inner.endpoint(&owner).is_some();
    let positive = observed && in_time;
    if positive { observer.take(); }
    drop(observer);
    if !positive { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
    guard.complete = true; positive
}
async fn join_slot<T>(slot: &mut Option<JoinHandle<T>>) -> Result<T, tokio::task::JoinError> {
    match slot { Some(task) => task.await, None => pending().await }
}
async fn join_with_clock<T>(slot: &mut Option<JoinHandle<T>>, inner: &Inner, owner: &Session) -> Result<T, tokio::task::JoinError> {
    loop {
        let wake = owner.wake.notified(); let end = inner.endpoint(owner);
        tokio::select! { result = join_slot(slot) => return result, _ = wake => {}, _ = clock_wait(end) => {} }
    }
}
fn offline_installed_final(book: &Resources) -> bool {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        if !book.offline_selected {
            return book.offline_installed.is_none() && !book.offline_started && !book.offline_joined && !book.offline_failed
                && book.offline_settlement.is_none() && book.offline_return.is_none();
        }
        book.offline_started && book.offline_joined && !book.offline_failed && book.offline_settlement.is_none()
            && matches!(book.offline_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && book.offline_installed.as_ref().is_some_and(|native| native.try_lock().is_ok_and(|slots| slots.settled()))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    { !book.offline_selected && !book.offline_started && !book.offline_joined && !book.offline_failed }
}
fn offline_worker_returned(started: bool, joined: bool, failed: bool, handle: bool, error: bool) -> bool {
    if !started { !joined && !failed && !handle && !error }
    else if failed { !joined && handle && error }
    else { joined && !handle && !error }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn offline_consumers_returned(book: &Resources, startup: &Startup, no_child_effect: bool) -> bool {
    if !offline_worker_returned(book.inspection_started, book.inspection_joined, book.inspection_failed,
            book.inspection.is_some(), book.inspection_error.is_some())
        || !offline_worker_returned(book.acquisition_started, book.acquisition_joined, book.acquisition_failed,
            book.acquisition.is_some(), book.acquisition_error.is_some()) { return false; }
    let io_returned = book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
        && !book.write_failed && !book.out_failed && !book.err_failed
        && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some();
    if !io_returned || startup.child.is_some() { return false; }
    if !startup.attempted {
        return no_child_effect && !startup.returned && !startup.failed && book.child.is_none() && book.waited.is_none() && !book.wait_failed;
    }
    startup.returned && !startup.failed && book.inspection_joined && !book.inspection_failed
        && book.acquisition_joined && !book.acquisition_failed && book.child.is_some() && !book.wait_failed
        && book.waited.as_ref().is_some_and(ExitStatus::success)
        && book.write_end.as_ref().is_some_and(|e| e.sent && e.closed && !e.failed)
        && book.out_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.decoder_settled && e.frames == 2)
        && book.err_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.frames == 0)
}
fn offline_installed_closure_ready(r: &Registry, owner: &Session, claimed: bool, direct_returned: bool) -> bool {
    direct_returned && owner.domain == SavedCommandDomain::OfflinePreflight && original_session(r, owner)
        && (!claimed || r.active.as_ref().is_some_and(|a| a.accepted && a.terminal
            && matches!(a.projection.result.as_ref(), Some(Terminal::OfflinePreflight(t)) if t.lifetime.settled())))
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn offline_installed_claim_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    owner.domain == SavedCommandDomain::OfflinePreflight && inner.offline_installed_selected()
        && final_clock_clear(r, owner, now) && !inner.poisoned.load(Ordering::SeqCst)
        && !r.stopping && !r.document_lost && !*owner.stop.borrow() && now < owner.clocks.work
        && Profile::current(owner.domain) == Some(owner.profile)
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn transfer_offline_installed(book: &Resources, inner: &Inner, owner: &Session) -> Result<(), BridgeError> {
    if !book.offline_selected || !book.inspection_started || !book.inspection_joined || book.inspection_failed
        || book.inspection.is_some() || book.inspection_error.is_some() || book.acquisition_started
        || book.acquisition_joined || book.acquisition_failed || book.acquisition.is_some() || book.acquisition_error.is_some() {
        return Err(BridgeError::cleanup_unknown());
    }
    let native = book.offline_installed.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
    let mut slots = native.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !offline_installed_claim_clear(inner, &r, owner, now) { return Err(owner.domain.unavailable()); }
    slots.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn acquire_offline_installed(inner: &Inner, owner: &Session, native: &Arc<Mutex<OfflinePreflightRuntimeSlots>>) {
    if owner.domain != SavedCommandDomain::OfflinePreflight || !inner.offline_installed_selected() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let mut slots = match native.lock() { Ok(slots) => slots, Err(_) => { inner.unknown(owner); return; } };
    let capability = match slots.capability() { Ok(capability) => capability, Err(_) => { inner.unknown(owner); return; } };
    let stop = owner.stop.subscribe();
    let selected = match capability.prepare_once(owner.clocks.work, &stop) {
        Ok(selected) => selected, Err(_) => { inner.stop(owner, Reason::RuntimeUnavailable); return; }
    };
    let mut command = Command::new(&selected.python);
    command.args(["-I", "-S", "-B"]).arg(&selected.bootstrap).arg(&selected.core)
        .current_dir(&selected.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    let mut startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !offline_installed_claim_clear(inner, &r, owner, now) { return; }
    if startup.attempted || startup.returned || startup.failed || startup.child.is_some() || capability.claim_once().is_err() {
        owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown_locked(&mut r, owner); return;
    }
    startup.attempted = true;
    drop(r);
    match command.spawn() {
        Ok(child) => { startup.child = Some(child); startup.returned = true; },
        Err(_) => { startup.failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); drop(startup);
            inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner); },
    }
}
async fn settle_offline_installed(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    if owner.domain != SavedCommandDomain::OfflinePreflight { return; }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    { let _ = (book, inner, owner); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        let Some(native) = book.offline_installed.clone() else {
            if book.offline_selected { inner.unknown(owner); }
            return;
        };
        if !book.offline_started {
            let returned = (|| {
                let slots = match native.try_lock() {
                    Ok(slots) => slots, Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return false,
                };
                let startup = match owner.startup.try_lock() {
                    Ok(startup) => startup, Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return false,
                };
                let r = inner.lock();
                offline_installed_closure_ready(&r, owner, startup.attempted,
                    offline_consumers_returned(book, &startup, slots.no_child_effect()))
            })();
            if !book.offline_selected || !returned { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let hold = inner.observation.lock().ok().and_then(|o| o.as_ref().map(|o| o.control.clone()))
                .filter(|c| c.case == crate::shell::installed_observation::commands::Case::OfflineSettlement);
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let hold = hold.filter(|control| match installed_observation_facts(inner, owner, book, false, false) {
                Some(facts) => control.prepare_hold(facts), None => { control.unavailable_witness(); false },
            }); // Observer failure cannot prevent the original physical closes.
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let hold_end = {
                let r = inner.lock(); owner.clocks.settlement(r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, owner)).and_then(|a| a.first_stop))
            };
            let (release, enter) = oneshot::channel();
            book.offline_started = true;
            book.offline_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(control) = hold { let _ = control.hold_settlement(hold_end); }
                match native.lock() {
                    Ok(mut slots) => slots.settle_originals(),
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots.settle_originals() },
                }
            }));
            let _ = release.send(());
        }
        if !book.offline_joined && !book.offline_failed {
            if book.offline_settlement.is_none() { inner.unknown(owner); return; }
            let result = join_with_clock(&mut book.offline_settlement, inner, owner).await;
            let joined = result.is_ok();
            if book.offline_return.is_some() { book.offline_failed = true; }
            else { book.offline_return = Some(result); book.offline_joined = joined; book.offline_failed = !joined; }
            if joined { book.offline_settlement.take(); } else { native_worker_lost(book, owner); }
        }
        if !offline_installed_final(book) { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
    }
}

fn spawn_original(inner: &Inner, owner: &Session, runtime: VerifiedRuntime) {
    if owner.domain == SavedCommandDomain::AndroidBuild {
        inner.stop(owner, Reason::ToolchainUnavailable); return;
    }
    // This gate remains distinct from source inspection. No packaged fallback,
    // environment-selected neutral cwd or other owner's permit is accepted.
    if inner.domain != owner.domain || !inner.qualified() || Profile::current(owner.domain) != Some(owner.profile) {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    #[cfg(not(all(unix, debug_assertions, feature = "development-runtime")))]
    { let _ = runtime; inner.stop(owner, Reason::RuntimeUnavailable); }
    #[cfg(all(unix, debug_assertions, feature = "development-runtime"))]
    {
        inner.endpoint(owner);
        if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if let Some(permit) = &owner.fixture {
            // The independent offline permit can only check the fixed actual
            // resolver tuple. It cannot supply another bootstrap/argv/cwd.
            if owner.domain != SavedCommandDomain::OfflinePreflight || permit.prepare_spawn(owner, &runtime).is_err() {
                inner.stop(owner, Reason::RuntimeUnavailable); return;
            }
        }
        let mut command = Command::new(&runtime.python);
        command.args(["-I", "-S", "-B"]).arg(&runtime.bootstrap).arg(&runtime.core);
        command.current_dir(&runtime.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
        let mut startup = match owner.startup.lock() {
            Ok(startup) => startup, Err(error) => { drop(error.into_inner()); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
        };
        inner.endpoint(owner);
        if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
        startup.attempted = true; // Before the sole original acquisition effect.
        match command.spawn() {
            Ok(child) => { startup.child = Some(child); startup.returned = true; },
            Err(_) => {
                startup.failed = true; // std/Tokio do not report failed-acquisition pipe closes.
                owner.resource_unknown.store(true, Ordering::SeqCst); drop(startup);
                inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner);
            }
        }
    }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn spawn_android_original(inner: &Inner, owner: &Session, runtime: VerifiedRuntime, native: Option<Arc<Mutex<AndroidNativeBooks>>>) {
    if owner.domain != SavedCommandDomain::AndroidBuild || inner.domain != owner.domain || !inner.qualified()
        || Profile::current(owner.domain) != Some(owner.profile) { inner.stop(owner, Reason::ToolchainUnavailable); return; }
    let Some(native) = native else { inner.stop(owner, Reason::ToolchainUnavailable); return; };
    let mut native = match native.lock() { Ok(native) => native, Err(_) => { inner.unknown(owner); return; } };
    // All command DATA construction precedes native checks and the final claim.
    let mut command = Command::new(&runtime.python);
    command.args(["-I", "-S", "-B"]).arg(&runtime.bootstrap).arg(&runtime.core);
    command.current_dir(&runtime.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    if native.check_before_spawn(&runtime, owner.clocks.work, &owner.stop.subscribe()).is_err() {
        inner.stop(owner, Reason::ToolchainMismatch); return;
    }
    let mut startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
    let mut registry = inner.lock(); inner.advance_locked(&mut registry, owner, Instant::now());
    if !original_session(&registry, owner) || registry.disabled || registry.exhausted || registry.stopping || registry.document_lost
        || *owner.stop.borrow() || Instant::now() >= owner.clocks.work || startup.attempted || startup.returned || startup.failed
        || startup.child.is_some() || native.phase != NativePhase::Ready || native.failure.is_some() || native.settlement_started { return; }
    native.phase = NativePhase::Claimed;
    startup.attempted = true; // One final active-Session/STOP/W claim, before effect.
    drop(registry);
    match command.spawn() { // No await, IO, recheck, callback or other work after claim.
        Ok(child) => { startup.child = Some(child); startup.returned = true; },
        Err(_) => { startup.failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); drop(startup);
            inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner); },
    }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn native_consumers_returned(book: &Resources, startup: &Startup, inner: &Inner, owner: &Session) -> bool {
    // Failed flags alone are not a returned borrower: keep the actual failed
    // original handle AND its Ready JoinError. Never infer return from timeout.
    let inspection_returned = if book.inspection_failed {
        !book.inspection_joined && book.inspection.is_some() && book.inspection_error.is_some()
    } else { book.inspection.is_none() && book.inspection_error.is_none() };
    let acquisition_returned = if book.acquisition_failed {
        !book.acquisition_joined && book.acquisition.is_some() && book.acquisition_error.is_some()
    } else { book.acquisition.is_none() && book.acquisition_error.is_none() };
    if !inspection_returned || !acquisition_returned { return false; }
    if !startup.attempted { return !startup.returned && !startup.failed && startup.child.is_none() && book.child.is_none(); }
    if !startup.returned || startup.failed || !book.inspection_joined || book.inspection_failed
        || !book.acquisition_joined || book.acquisition_failed || book.wait_failed
        || book.waited.as_ref().is_none_or(|s| !s.success()) || startup.child.is_some() || book.writer.is_some()
        || book.stdout.is_some() || book.stderr.is_some() || book.write_failed || book.out_failed || book.err_failed { return false; }
    let io = book.write_end.as_ref().is_some_and(|e| e.sent && e.closed && !e.failed)
        && book.out_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.decoder_settled && (2..=8).contains(&e.frames))
        && book.err_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.frames == 0);
    let registry = inner.lock();
    io && original_session(&registry, owner) && registry.active.as_ref().is_some_and(|a| a.accepted && a.terminal
        && matches!(&a.projection.result, Some(Terminal::AndroidBuild(t)) if t.settled()))
}
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
async fn settle_native(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    if !book.native_started {
        let used = {
            let startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
            if !native_consumers_returned(book, &startup, inner, owner) { inner.unknown(owner); return; }
            startup.attempted
        };
        let Some(native) = book.native.clone() else { inner.unknown(owner); return; };
        // Each book operation ALSO reads this same original Session cutoff, so
        // an earlier F during the audit tightens the running borrow immediately.
        let end = *owner.native_audit_cutoff.borrow();
        let (release, enter) = oneshot::channel();
        book.native_started = true; // Pre-rostered slot claimed before worker creation/effects.
        book.native_settlement = Some(tokio::task::spawn_blocking(move || {
            if enter.blocking_recv().is_err() { return NativeSettlement { originals_closed: false, integrity: false }; }
            match native.lock() {
                Ok(mut native) => native.settle(used, end),
                Err(error) => { let mut native = error.into_inner(); native.interrupted(); native.settle(used, end) },
            }
        }));
        let _ = release.send(());
    }
    if !book.native_joined && !book.native_failed {
        let result = join_with_clock(&mut book.native_settlement, inner, owner).await;
        let positive = matches!(&result, Ok(NativeSettlement { originals_closed: true, integrity: true }));
        let joined = result.is_ok();
        if book.native_return.is_some() { book.native_failed = true; }
        else { book.native_return = Some(result); book.native_joined = joined; book.native_failed = !joined; }
        if joined { book.native_settlement.take(); }
        else { native_worker_lost(book, owner); }
        if !positive || book.native_failed { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
    }
}

async fn start_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    if owner.domain == SavedCommandDomain::AndroidBuild && (!inner.qualified() || inner.toolchain.is_none()) {
        inner.stop(owner, Reason::ToolchainUnavailable); return;
    }
    let mut book = owner.resources.lock().await;
    inner.endpoint(owner);
    if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
    let runtime = inner.runtime.clone(); let end = owner.clocks.work; let domain = owner.domain;
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let native = book.native.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let offline_installed = book.offline_installed.clone();
    let stop = owner.stop.subscribe();
    let (inspect_start, inspect_enter) = oneshot::channel();
    book.inspection_started = true;
    book.inspection = Some(tokio::task::spawn_blocking(move || {
        inspect_enter.blocking_recv().map_err(|_| domain.unavailable())?;
        match domain {
            SavedCommandDomain::OfflinePreflight => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(native) = offline_installed {
                    let mut slots = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    return runtime.resolve_offline_preflight_installed(&mut slots, end, &stop);
                }
                runtime.resolve_offline_preflight(end)
            },
            SavedCommandDomain::AndroidBuild => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                {
                    let native = native.ok_or_else(|| domain.unavailable())?;
                    let mut native = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    native.inspect_once(end, &stop)
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
                { let _ = stop; Err(domain.unavailable()) }
            }
        }
    }));
    let _ = inspect_start.send(()); // Original handle AND books registered before the first effect.
    let runtime = match join_with_clock(&mut book.inspection, inner, owner).await {
        Ok(result) => { book.inspection_joined = true; book.inspection.take(); match result {
            Ok(runtime) => runtime, Err(_) => { inner.stop(owner, if owner.domain == SavedCommandDomain::AndroidBuild {
                Reason::ToolchainUnavailable } else { Reason::RuntimeUnavailable }); return; }
        } },
        Err(error) => {
            book.inspection_failed = true; book.inspection_error = Some(error);
            native_worker_lost(&book, owner); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return;
        },
    };
    inner.endpoint(owner);
    if *owner.stop.borrow() || Instant::now() >= owner.clocks.work || !original_session(&inner.lock(), owner) { return; }
    let bytes = match (&owner.context, owner.profile) {
        (Context::OfflinePreflight(context), Profile::OfflinePreflight(profile)) =>
            wire::request(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd),
        (Context::AndroidBuild(context), Profile::AndroidBuild(profile)) => {
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            {
                let binding = book.native.as_ref().and_then(|native| native.lock().ok())
                    .and_then(|native| native.request_binding(&runtime).ok());
                match binding { Some(binding) => android_wire::request(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd, &binding),
                    None => Err(owner.domain.unavailable()) }
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
            { let _ = (context, profile); Err(owner.domain.unavailable()) }
        }
        _ => Err(BridgeError::protocol()),
    };
    match bytes { Ok(bytes) => *owner.request.lock().await = Some(bytes), Err(_) => { inner.stop(owner, Reason::ProtocolError); return; } }
    let acquisition_owner = owner.clone(); let acquisition_inner = inner.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let acquisition_native = book.native.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let offline_installed = book.offline_installed.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if offline_installed.is_some() && transfer_offline_installed(&book, inner, owner).is_err() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let (acquire_start, acquire_enter) = oneshot::channel();
    book.acquisition_started = true;
    book.acquisition = Some(tokio::task::spawn_blocking(move || {
        if acquire_enter.blocking_recv().is_ok() {
            match acquisition_owner.domain {
                SavedCommandDomain::OfflinePreflight => {
                    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    if let Some(native) = offline_installed {
                        drop(runtime);
                        acquire_offline_installed(&acquisition_inner, &acquisition_owner, &native); return;
                    }
                    spawn_original(&acquisition_inner, &acquisition_owner, runtime);
                },
                SavedCommandDomain::AndroidBuild => {
                    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                    spawn_android_original(&acquisition_inner, &acquisition_owner, runtime, acquisition_native);
                    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
                    acquisition_inner.stop(&acquisition_owner, Reason::ToolchainUnavailable);
                }
            }
        } else { acquisition_inner.stop(&acquisition_owner, Reason::Cancelled); }
    }));
    let _ = acquire_start.send(());
}
async fn drive(inner: Arc<Inner>, owner: Arc<Session>, enter: oneshot::Receiver<()>, mut guard: Guard) {
    if enter.await.is_err() { inner.stop(&owner, Reason::Cancelled); }
    else {
        start_original(&inner, &owner).await;
    }
    continue_original(&inner, &owner).await;
    guard.complete = true;
}
async fn wait_child(child: &mut Option<Child>) -> std::io::Result<ExitStatus> { match child { Some(child) => child.wait().await, None => pending().await } }
async fn next_frame(frames: &mut Option<mpsc::Receiver<Frame>>) -> Option<Frame> { match frames { Some(frames) => frames.recv().await, None => pending().await } }
fn drain(book: &mut Resources, inner: &Inner, owner: &Session) {
    if let Some(frames) = book.frames.as_mut() { while let Ok(frame) = frames.try_recv() { deliver_frame(inner, owner, frame); } }
}
fn deliver_frame(inner: &Inner, owner: &Session, frame: Frame) {
    inner.accept(owner, frame);
}
fn require_terminal(inner: &Inner, owner: &Session) {
    if !inner.lock().active.as_ref().is_some_and(|a| a.owner.id == owner.id && a.accepted && a.terminal) {
        inner.stop(owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
    }
}
enum Event { Wait(std::io::Result<ExitStatus>), Write(Result<WriteEnd, tokio::task::JoinError>),
    Out(Result<ReadEnd, tokio::task::JoinError>), Err(Result<ReadEnd, tokio::task::JoinError>), Frame(Option<Frame>), Wake }
fn observe_child_status(inner: &Inner, owner: &Session, status: &ExitStatus) {
    if !status.success() {
        // A terminal precedes the core's final stdio closes. Nonzero cannot
        // certify those later original child-side transport returns.
        inner.stop(owner, Reason::ProtocolError); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
    }
}
async fn continue_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    // Sole driver, or its already-registered surviving manager AFTER a lost
    // driver. Only original book cleanup: no new inspection/acquisition/IO task.
    let mut book = owner.resources.lock().await;
    if book.inspection.is_some() && !book.inspection_joined && !book.inspection_failed {
        match join_with_clock(&mut book.inspection, inner, owner).await {
            Ok(_) => { book.inspection_joined = true; book.inspection.take(); }, // Late runtime DATA never launches.
            Err(error) => { book.inspection_failed = true; book.inspection_error = Some(error); native_worker_lost(&book, owner);
                owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); },
        }
    }
    if book.acquisition.is_some() && !book.acquisition_joined && !book.acquisition_failed {
        match join_with_clock(&mut book.acquisition, inner, owner).await {
            Ok(()) => { book.acquisition_joined = true; book.acquisition.take(); },
            Err(error) => { book.acquisition_failed = true; book.acquisition_error = Some(error); native_worker_lost(&book, owner);
                owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); },
        }
    }
    let expected = {
        let mut startup = match owner.startup.lock() {
            Ok(startup) => startup, Err(error) => { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); error.into_inner() }
        };
        if book.child.is_none() { book.child = startup.child.take(); }
        else if startup.child.is_some() { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
        startup.returned || book.child.is_some()
    };
    let pipes = *owner.pipes.borrow();
    if pipes == Pipes::Pending {
        if let Some(child) = book.child.as_mut() {
            let mut input = owner.input.lock().await; let mut output = owner.output.lock().await; let mut error = owner.error.lock().await;
            if input.io.is_none() && input.close == Close::New { input.io = child.stdin.take(); }
            if output.io.is_none() && output.close == Close::New { output.io = child.stdout.take(); }
            if error.io.is_none() && error.close == Close::New { error.io = child.stderr.take(); }
            if input.io.is_none() || output.io.is_none() || error.io.is_none() || child.stdin.is_some() || child.stdout.is_some() || child.stderr.is_some() {
                owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner);
            }
            owner.pipes.send_replace(Pipes::Available);
        } else { owner.pipes.send_replace(Pipes::Absent); }
    }
    if book.write_failed { let mut pipe = owner.input.lock().await; let _ = close_original(&mut pipe); }
    if book.out_failed { let mut pipe = owner.output.lock().await; let _ = close_original(&mut pipe); }
    if book.err_failed { let mut pipe = owner.error.lock().await; let _ = close_original(&mut pipe); }
    let mut frames_open = book.frames.is_some();
    loop {
        let wake = owner.wake.notified(); let end = inner.endpoint(owner);
        let wait_pending = book.child.is_some() && book.waited.is_none() && !book.wait_failed;
        let write_pending = book.writer.is_some() && !book.write_failed;
        let out_pending = book.stdout.is_some() && !book.out_failed;
        let err_pending = book.stderr.is_some() && !book.err_failed;
        if !wait_pending && !write_pending && !out_pending && !err_pending { drain(&mut book, inner, owner); break; }
        let event = {
            let Resources { child, writer, stdout, stderr, frames, .. } = &mut *book;
            tokio::select! {
                result = wait_child(child), if wait_pending => Event::Wait(result),
                result = join_slot(writer), if write_pending => Event::Write(result),
                result = join_slot(stdout), if out_pending => Event::Out(result),
                result = join_slot(stderr), if err_pending => Event::Err(result),
                frame = next_frame(frames), if frames_open => Event::Frame(frame),
                _ = wake => Event::Wake, _ = clock_wait(end) => Event::Wake,
            }
        };
        match event {
            Event::Wait(Ok(status)) => {
                observe_child_status(inner, owner, &status);
                book.waited = Some(status);
            }
            Event::Wait(Err(_)) => { book.wait_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); },
            Event::Write(Ok(end)) => { book.writer.take(); book.write_end = Some(end); },
            Event::Out(Ok(end)) => { book.stdout.take(); book.out_end = Some(end); drain(&mut book, inner, owner); if expected { require_terminal(inner, owner); } },
            Event::Err(Ok(end)) => { book.stderr.take(); book.err_end = Some(end); },
            Event::Write(Err(_)) => { book.write_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); let mut p = owner.input.lock().await; let _ = close_original(&mut p); },
            Event::Out(Err(_)) => { book.out_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); let mut p = owner.output.lock().await; let _ = close_original(&mut p); },
            Event::Err(Err(_)) => { book.err_failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); let mut p = owner.error.lock().await; let _ = close_original(&mut p); },
            Event::Frame(Some(frame)) => deliver_frame(inner, owner, frame), Event::Frame(None) => frames_open = false, Event::Wake => {},
        }
    }
    if expected { require_terminal(inner, owner); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if owner.domain == SavedCommandDomain::AndroidBuild { settle_native(&mut book, inner, owner).await; }
    settle_offline_installed(&mut book, inner, owner).await;
    // No broad signal or PID discovery. EOF is cooperative STOP; an unreturned
    // original child stays retained at H, even if its terminal was once positive.
}
type Continuation = Pin<Box<dyn Future<Output = ()> + Send>>;
async fn continuation(slot: &mut Option<Continuation>) { match slot { Some(future) => future.await, None => pending().await } }
enum Monitor { Driver(Result<(), tokio::task::JoinError>), Continued, Wake }
async fn monitor_original(inner: &Arc<Inner>, owner: &Arc<Session>) {
    let mut driver = owner.driver.lock().await;
    let mut continuing: Option<Continuation> = None;
    loop {
        let wake = owner.wake.notified(); let end = inner.endpoint(owner);
        let driver_known = owner.driver_joined.load(Ordering::SeqCst) || owner.driver_failed.load(Ordering::SeqCst);
        if driver.is_none() && !driver_known { owner.driver_failed.store(true, Ordering::SeqCst); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); continue; }
        if owner.driver_failed.load(Ordering::SeqCst) && !owner.driver_done.load(Ordering::SeqCst) && continuing.is_none() {
            let inner = inner.clone(); let owner = owner.clone();
            continuing = Some(Box::pin(async move { continue_original(&inner, &owner).await }));
        }
        if driver_known && owner.driver_done.load(Ordering::SeqCst) && continuing.is_none() { break; }
        let is_continuing = continuing.is_some();
        let event = tokio::select! {
            result = join_slot(&mut driver), if !driver_known => Monitor::Driver(result),
            _ = continuation(&mut continuing), if is_continuing => Monitor::Continued,
            _ = wake => Monitor::Wake, _ = clock_wait(end) => Monitor::Wake,
        };
        match event {
            Monitor::Driver(result) => {
                let joined = result.is_ok(); let recorded = record_join(&owner.driver_return, result);
                if joined { owner.driver_done.store(true, Ordering::SeqCst); }
                if joined && recorded { driver.take(); owner.driver_joined.store(true, Ordering::SeqCst); }
                else { owner.driver_failed.store(true, Ordering::SeqCst); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
                owner.wake.notify_waiters();
            },
            Monitor::Continued => { continuing.take(); owner.driver_done.store(true, Ordering::SeqCst); owner.wake.notify_waiters(); }, Monitor::Wake => {},
        }
    }
}
async fn manage(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) { monitor_original(&inner, &owner).await; guard.complete = true; }
async fn observe_final(inner: Arc<Inner>, owner: Arc<Session>, mut guard: Guard) -> bool {
    let manager_joined = {
        let mut manager = owner.manager.lock().await;
        if manager.is_none() { false } else {
            let result = join_with_clock(&mut manager, &inner, &owner).await;
            let joined = result.is_ok(); let recorded = record_join(&owner.manager_return, result);
            if joined && recorded { manager.take(); }
            joined && recorded
        }
    };
    if !manager_joined {
        owner.manager_failed.store(true, Ordering::SeqCst); owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner);
        // Exceptional original-only custody. Never a new acquisition/reader,
        // repair of the lost receipt or successful result after manager loss.
        monitor_original(&inner, &owner).await;
    }
    let settled = {
        let book = owner.resources.lock().await;
        let startup = match owner.startup.lock() { Ok(s) => s, Err(e) => { owner.resource_unknown.store(true, Ordering::SeqCst); e.into_inner() } };
        let startup_settled = book.inspection.is_none() && book.acquisition.is_none() && !book.inspection_failed && !book.acquisition_failed
            && !startup.failed && (!startup.attempted || startup.returned && book.acquisition_joined);
        let io_joined = book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none() && !book.write_failed && !book.out_failed && !book.err_failed
            && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some();
        let io = if startup.returned {
            book.waited.is_some() && !book.wait_failed
                && book.write_end.as_ref().is_some_and(|r| r.closed)
                && book.out_end.as_ref().is_some_and(|r| r.closed && r.eof)
                && book.err_end.as_ref().is_some_and(|r| r.closed && r.eof)
        } else { book.child.is_none() && startup.child.is_none() };
        let protocol = if startup.returned {
            let r = inner.lock();
            r.active.as_ref().is_some_and(|a| a.owner.id == owner.id && a.accepted && a.terminal
                && a.projection.result.as_ref().is_some_and(Terminal::settled))
                && book.out_end.as_ref().is_some_and(|r| r.decoder_settled && !r.failed && match owner.domain {
                    SavedCommandDomain::OfflinePreflight => r.frames == 2,
                    SavedCommandDomain::AndroidBuild => (2..=8).contains(&r.frames),
                })
                && book.err_end.as_ref().is_some_and(|r| r.frames == 0 && !r.failed)
                && book.write_end.as_ref().is_some_and(|r| r.sent && !r.failed)
        } else { true };
        manager_joined && startup_settled && io_joined && io && protocol && native_final(&book, owner.domain)
            && owner.driver_joined.load(Ordering::SeqCst)
            && !owner.resource_unknown.load(Ordering::SeqCst)
    };
    if !settled { inner.unknown(&owner); }
    // Final observer owns no unjoined child/IO/acquisition at this point. Its
    // ORIGINAL handle remains with the watchdog until its actual Ready join.
    { let mut r = inner.lock(); inner.bump(&mut r); }
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    if let Some(permit) = &owner.fixture {
        if owner.domain == SavedCommandDomain::OfflinePreflight { permit.observer_return(&owner, settled).await; }
        else { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(&owner); }
    }
    guard.complete = true; settled
}

// Fixture bodies stay lexical children of the custody owner. Only the thin
// Offline adapter registers their ORIGINAL test names; no duplicate roster and
// no crate-visible Inner/Session fields are introduced for tests.
#[cfg(test)]
#[path = "offline_preflight_owner_tests.rs"]
pub(crate) mod offline_tests;
#[cfg(test)]
#[path = "saved_command_owner_tests.rs"]
mod tests;

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
impl SavedCommandOwner {
    pub(crate) fn admit_installed_observation(&self, token: crate::shell::installed_observation::commands::OfflineAdmission) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::OfflinePreflight || r.revision != 0 || r.active.is_some() || r.prepared.is_some() || r.last.is_some()
            || r.disabled || r.stopping || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || !self.inner.runtime.offline_preflight_installed_profile_available() { return Err(self.inner.domain.unavailable()); }
        let mut slot = self.inner.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        *slot = Some(InstalledObservation { control: token.consume()?, original: None, retired: false, core_settled: false }); Ok(())
    }
    pub(crate) fn installed_observation_snapshot(&self) -> Option<crate::shell::installed_observation::commands::Snapshot> {
        let (owner, retired, core_settled) = {
            let book = self.inner.observation.lock().ok()?; let book = book.as_ref()?;
            (book.original.as_ref()?.clone(), book.retired, book.core_settled)
        };
        let book = owner.resources.try_lock().ok()?;
        let facts = installed_observation_facts(&self.inner, &owner, &book, retired, core_settled)?;
        let r = self.inner.lock();
        let projection = r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, &owner)).map(|a| &a.projection)
            .or_else(|| r.last.as_ref().filter(|p| p.operation_id == owner.id && p.owner_generation == owner.generation))?;
        Some(crate::shell::installed_observation::commands::Snapshot { facts, terminal: serde_json::to_value(projection.public().offline().ok()?).ok()? })
    }
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn installed_observation_facts(inner: &Inner, owner: &Session, book: &Resources, retired: bool, final_core: bool)
    -> Option<crate::shell::installed_observation::commands::OriginalFacts> {
    use crate::shell::installed_observation::commands::OriginalFacts;
    if owner.domain != SavedCommandDomain::OfflinePreflight { return None; }
    let startup = owner.startup.try_lock().ok()?;
    let native = book.offline_installed.as_ref()?.try_lock().ok()?;
    let r = inner.lock();
    let active = r.active.as_ref().filter(|a| std::ptr::eq(Arc::as_ptr(&a.owner), owner));
    let no_child = !startup.attempted && !startup.returned && !startup.failed && startup.child.is_none()
        && !book.acquisition_started && book.acquisition.is_none() && book.child.is_none() && native.no_child_effect();
    Some(OriginalFacts {
        domain: "offline", id: owner.id.clone(), generation: owner.generation.clone(),
        inspection_joined: book.inspection_started && book.inspection_joined && !book.inspection_failed && book.inspection.is_none() && book.inspection_error.is_none(),
        acquisition_joined: book.acquisition_started && book.acquisition_joined && !book.acquisition_failed && book.acquisition.is_none() && book.acquisition_error.is_none(),
        attempted: startup.attempted, no_child,
        child_waited_success: startup.returned && !startup.failed && book.child.is_some() && !book.wait_failed && book.waited.as_ref().is_some_and(ExitStatus::success),
        stdin_closed: book.write_end.as_ref().is_some_and(|v| v.sent && v.closed && !v.failed),
        stdout_eof_closed: book.out_end.as_ref().is_some_and(|v| v.frames == 2 && v.eof && v.closed && !v.failed),
        stderr_eof_closed: book.err_end.as_ref().is_some_and(|v| v.frames == 0 && v.eof && v.closed && !v.failed),
        io_joined: book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none() && !book.write_failed && !book.out_failed && !book.err_failed
            && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some(),
        core_lifetime_settled: if retired { final_core } else { active.is_some_and(|a| a.accepted && a.terminal && a.projection.result.as_ref().is_some_and(Terminal::settled)) },
        runtime_ledger_settled: native.settled(),
        runtime_settlement_joined: book.offline_selected && book.offline_started && book.offline_joined && !book.offline_failed && book.offline_settlement.is_none()
            && matches!(book.offline_return.as_ref(), Some(Ok(CloseOutcome::Settled))),
        driver_joined: owner.driver_joined.load(Ordering::SeqCst) && matches!(owner.driver_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
        manager_joined: !owner.manager_failed.load(Ordering::SeqCst) && matches!(owner.manager_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
        observer_joined: matches!(owner.observer_return.try_lock().ok()?.as_ref(), Some(Ok(true))),
        watchdog_joined: owner.watchdog_joined.load(Ordering::SeqCst) && !owner.watchdog_failed.load(Ordering::SeqCst)
            && matches!(owner.watchdog_return.try_lock().ok()?.as_ref(), Some(Ok(true))),
        retired_before_cutoff: retired, active_retained: active.is_some(),
        resource_unknown: owner.resource_unknown.load(Ordering::SeqCst) || active.is_some_and(|a| a.unknown) || inner.poisoned.load(Ordering::SeqCst),
    })
}
