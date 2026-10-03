//! Finite original-resource owner for the declared saved-command domains.
//! Source extraction only: Android native/runtime/tool custody is NOT qualified.
//! The ordinary core retains C/A/W custody; native retains every original
//! startup, child, pipe, decoder, wait, driver, manager and final-join record.
use std::{future::{pending, Future}, pin::Pin, process::ExitStatus,
    sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context as TaskContext, Poll, Wake, Waker}, time::{Duration, Instant}};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, process::{Child, ChildStdin, ChildStdout, ChildStderr},
    sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot, watch}, task::JoinHandle};
#[cfg(any(all(unix, debug_assertions, feature = "development-runtime"),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_arch = "aarch64")))]
use {std::process::Stdio, tokio::process::Command};
use crate::{asset_source::RegisteredRoot, offline_preflight_protocol as wire, android_build_protocol as android_wire, project_recovery_protocol as recovery_wire, ios_archive_protocol as ios_wire,
    error::BridgeError, runtime::{RuntimeConfig, VerifiedRuntime}, android_toolchain::AndroidToolchainProfile, asset_session::IOSSigningMaterial};
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
use crate::{android_toolchain::AndroidToolchainCustody,
    installed_runtime::{AdmissionFailure, AndroidDescriptorBudget, CloseOutcome, InstalledRuntimeCustody}};
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
use crate::installed_runtime::{OfflinePreflightRuntimeSlots, ProjectRecoveryRuntimeSlots};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::{installed_runtime::{AdmissionFailure, CloseOutcome, IOSArchiveRuntimeSlots}, ios_toolchain::IOSXcodeSlots};

#[path = "saved_command_android_catalog.rs"]
mod android_catalog;
#[path = "saved_command_android_sources.rs"]
mod android_sources;
#[path = "saved_command_android_registration.rs"]
mod android_registration;
pub(crate) type AndroidRegistrationSnapshot = android_registration::Snapshot;
pub(crate) type AndroidRegistrationChecked = android_registration::Checked;
pub(crate) type AndroidRegistrationAdmitted = android_registration::Admitted;
pub(crate) type AndroidRegistrationFinalization = android_registration::Finalization;
pub(crate) type AndroidRegistrationCancelPublisher = android_registration::CancelPublisher;
pub(crate) use android_registration::{ControlSlot as AndroidRegistrationControl, Publisher as AndroidRegistrationPublisher, PublisherKind as AndroidRegistrationPublisherKind};
pub(crate) use android_registration::WorkGate as AndroidRegistrationWorkGate;
pub(crate) type AndroidServiceSnapshot = android_registration::service_setup::Snapshot;
pub(crate) type AndroidServiceChecked = android_registration::service_setup::Checked;
pub(crate) type AndroidServiceAdmitted = android_registration::service_setup::Admitted;
pub(crate) type AndroidServiceFinalization = android_registration::service_setup::Finalization;
#[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
pub(crate) use android_registration::service_setup::Dispatcher as AndroidServiceDispatcher;
pub(crate) type AndroidCatalogAdmitted = android_catalog::Admitted;
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
#[path = "saved_command_android_leased.rs"]
mod android_leased;
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
use android_leased::{AndroidNativeBooks,AndroidUseControl,AndroidCloseSlot,AndroidObservationSlot};
#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "macos-android-registration-helper"))]
enum AndroidNativeBooks {} // Uninhabited: helper graph has no app-tool owner fallback.

/// Private, non-Clone, consuming proof, constructible only in this original
/// owner's actual Start/Catalog join edges. No Boolean/ID/renderer factory.
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
pub(crate) struct AndroidOriginalJoins(AndroidJoinedOriginal);
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
enum AndroidJoinedOriginal {Start(Arc<Session>),Catalog(Arc<android_catalog::Operation>)}
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
impl AndroidOriginalJoins {
    pub(crate) fn accepts_original(self,identity:&crate::android_shared_lease_macos::OriginalUseIdentity)->bool{
        match self.0 {
            AndroidJoinedOriginal::Start(owner) => {
                owner.android_control.as_ref().is_some_and(|control|control.identity().same_original(identity))
                    && owner.driver_joined.load(Ordering::SeqCst) && !owner.driver_failed.load(Ordering::SeqCst)
                    && !owner.manager_failed.load(Ordering::SeqCst) && !owner.resource_unknown.load(Ordering::SeqCst)
                    && owner.driver_return.lock().is_ok_and(|returned|matches!(returned.as_ref(),Some(Ok(()))))
                    && owner.manager_return.lock().is_ok_and(|returned|matches!(returned.as_ref(),Some(Ok(()))))
            },
            AndroidJoinedOriginal::Catalog(original)=>original.join_witness_matches(identity),
        }
    }
}

// Qualification is domain-local. No environment/GitHub/offline permit, parsed
// tool binding, hash, mode or host profile can qualify Android build custody.
const ANDROID_NATIVE_QUALIFIED: bool = false;
const ANDROID_RUNTIME_QUALIFIED: bool = false;
const ANDROID_TOOLCHAIN_QUALIFIED: bool = false;
const RECOVERY_NATIVE_QUALIFIED: bool = false;
const RECOVERY_RUNTIME_QUALIFIED: bool = false;
const RECOVERY_WORK: Duration = Duration::from_secs(120);
const RECOVERY_HARD: Duration = Duration::from_secs(130);
// Signed account/material/export qualification is not inherited from an
// installed unsigned-archive observation or a successful format assessment.
const IOS_SIGNED_NATIVE_QUALIFIED: bool = false;
const IOS_RECOVERY_NATIVE_QUALIFIED: bool = false;
const IOS_WORK: Duration = Duration::from_secs(5400);
const IOS_HARD: Duration = Duration::from_secs(5410);
const IOS_SIGNED_CLEANUP: Duration = Duration::from_secs(5520);
const IOS_SIGNED_HARD: Duration = Duration::from_secs(5530);
const IOS_SIGNED_SETTLEMENT: Duration = Duration::from_secs(130);
const IOS_RECOVERY_WORK: Duration = Duration::from_secs(120);
const IOS_RECOVERY_CLEANUP: Duration = Duration::from_secs(240);
const IOS_RECOVERY_HARD: Duration = Duration::from_secs(250);
const INTENT: Duration = Duration::from_secs(300);
const OFFLINE_WORK: Duration = Duration::from_secs(1800);
const OFFLINE_HARD: Duration = Duration::from_secs(1810);
const ANDROID_WORK: Duration = Duration::from_secs(3000);
const ANDROID_HARD: Duration = Duration::from_secs(3010);
const SETTLEMENT: Duration = Duration::from_secs(10);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn publish_macos_returned_failure(
    returned: Option<crate::installed_runtime::AdmissionFailure>,
    original_first: impl FnOnce() -> Option<(crate::installed_runtime::AdmissionFailure, Instant)>,
    publish: &mut dyn FnMut(Option<(crate::installed_runtime::AdmissionFailure, Instant)>),
) {
    // Capture this original Err BEFORE querying its Book or borrowing its
    // owner's publication latch. Neither a later getter nor a join supplies F.
    let returned = returned.map(|failure| (failure, Instant::now()));
    let first = original_first();
    // The existing owner latch selects min(F). Publish BOTH facts: a later
    // Unknown must remain absorbing even when an earlier cause owns F.
    publish(first);
    if returned.is_some() { publish(returned); }
}

// This private closed sum is not a runner API. No operation descriptors,
// callbacks, extension traits, caller argv or caller deadlines enter the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SavedCommandDomain { OfflinePreflight, AndroidBuild, ProjectRecovery, IOSArchive }
impl SavedCommandDomain {
    fn unavailable(self) -> BridgeError { match self {
        Self::OfflinePreflight => BridgeError::new("offline_preflight_unavailable", "Saved offline checks are unavailable for this original document, host and runtime."),
        Self::AndroidBuild => BridgeError::new("android_build_unavailable", "Saved Android builds are unavailable for this original document, host, runtime and tool custody."),
        Self::ProjectRecovery => BridgeError::new("project_recovery_unavailable", "Project recovery is unavailable for this original document, platform and runtime."),
        Self::IOSArchive => crate::ios_archive_owner::unavailable(),
    } }
    fn busy(self) -> BridgeError { match self {
        Self::OfflinePreflight => BridgeError::new("offline_preflight_busy", "Finish or cancel the original operation before reviewing saved offline checks."),
        Self::AndroidBuild => BridgeError::new("android_build_busy", "Finish or cancel the original operation before reviewing a saved Android build."),
        Self::ProjectRecovery => BridgeError::new("project_recovery_busy", "Finish or cancel the original operation before reviewing project recovery."),
        Self::IOSArchive => BridgeError::new("ios_archive_busy", "Finish or cancel the original operation before reviewing a saved iOS archive."),
    } }
    fn invalid_owner(self) -> BridgeError { match self {
        Self::OfflinePreflight => BridgeError::new("offline_preflight_owner", "This request does not identify an unused original saved offline-check intent."),
        Self::AndroidBuild => BridgeError::new("android_build_owner", "This request does not identify an unused original saved Android-build intent."),
        Self::IOSArchive => BridgeError::new("ios_archive_owner", "This request does not identify an unused original iOS-archive intent."),
        Self::ProjectRecovery => BridgeError::new("project_recovery_owner", "This request does not identify an unused original project-recovery intent."),
    } }
    fn request_limit(self) -> usize { match self {
        Self::OfflinePreflight => wire::REQUEST_LIMIT, Self::AndroidBuild => android_wire::REQUEST_LIMIT, Self::ProjectRecovery => recovery_wire::REQUEST_LIMIT, Self::IOSArchive => ios_wire::REQUEST_LIMIT,
    } }
    fn response_limit(self) -> usize { match self {
        Self::OfflinePreflight => wire::RESPONSE_LIMIT, Self::AndroidBuild => android_wire::RESPONSE_LIMIT, Self::ProjectRecovery => recovery_wire::RESPONSE_LIMIT, Self::IOSArchive => ios_wire::RESPONSE_LIMIT,
    } }
    fn frame_limit(self) -> usize { match self { Self::OfflinePreflight => 2, Self::AndroidBuild => 8, Self::ProjectRecovery => 2, Self::IOSArchive => ios_wire::MAX_FRAMES } }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Context { OfflinePreflight(wire::Context), AndroidBuild(android_wire::Context), ProjectRecovery(recovery_wire::Context), IOSArchive(ios_wire::Context) }
impl Context {
    fn signed_ios(&self) -> bool { matches!(self, Self::IOSArchive(context) if context.signed()) }
    fn recovery_ios(&self) -> bool { matches!(self, Self::IOSArchive(context) if context.recovery()) }
    fn frame_limit(&self) -> usize { match self { Self::IOSArchive(context) => context.frame_limit(), _ => self.domain().frame_limit() } }
    fn domain(&self) -> SavedCommandDomain { match self {
        Self::OfflinePreflight(_) => SavedCommandDomain::OfflinePreflight, Self::AndroidBuild(_) => SavedCommandDomain::AndroidBuild, Self::ProjectRecovery(_) => SavedCommandDomain::ProjectRecovery, Self::IOSArchive(_) => SavedCommandDomain::IOSArchive,
    } }
    fn project_id(&self) -> &str { match self {
        Self::OfflinePreflight(c) => &c.project_id, Self::AndroidBuild(c) => &c.project_id, Self::ProjectRecovery(c) => &c.project_id, Self::IOSArchive(c) => &c.project_id,
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile { OfflinePreflight(wire::Profile), AndroidBuild(android_wire::Profile), ProjectRecovery(recovery_wire::Profile), IOSArchive(ios_wire::Profile) }
impl Profile {
    fn current(domain: SavedCommandDomain) -> Option<Self> { match domain {
        SavedCommandDomain::OfflinePreflight => wire::Profile::current().map(Self::OfflinePreflight),
        SavedCommandDomain::AndroidBuild => android_wire::Profile::current().map(Self::AndroidBuild),
        SavedCommandDomain::ProjectRecovery => recovery_wire::Profile::current().map(Self::ProjectRecovery),
        SavedCommandDomain::IOSArchive => ios_wire::Profile::current().map(Self::IOSArchive),
    } }
}
// Internal phase/outcome/reason vocabulary is DATA, not an Offline DTO reused
// as Android authority. Typed adapters convert by finite exhaustive matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { AwaitingConsent, Starting, Running, Stopping, Terminal, Unknown }
impl Phase {
    fn recovery(self) -> recovery_wire::Phase { match self {
        Self::AwaitingConsent => recovery_wire::Phase::AwaitingConsent,
        Self::Starting => recovery_wire::Phase::Starting,
        Self::Running => recovery_wire::Phase::Running,
        Self::Stopping => recovery_wire::Phase::Stopping,
        Self::Terminal => recovery_wire::Phase::Terminal,
        Self::Unknown => recovery_wire::Phase::Unknown,
    } }
    fn offline(self) -> wire::Phase { match self {
            Self::AwaitingConsent => wire::Phase::AwaitingConsent, Self::Starting => wire::Phase::Starting, Self::Running => wire::Phase::Running,
            Self::Stopping => wire::Phase::Stopping, Self::Terminal => wire::Phase::Terminal, Self::Unknown => wire::Phase::Unknown,
    } }
    fn android(self) -> android_wire::Phase { match self {
            Self::AwaitingConsent => android_wire::Phase::AwaitingConsent, Self::Starting => android_wire::Phase::Starting, Self::Running => android_wire::Phase::Running,
            Self::Stopping => android_wire::Phase::Stopping, Self::Terminal => android_wire::Phase::Terminal, Self::Unknown => android_wire::Phase::Unknown,
    } }
    fn ios(self) -> ios_wire::Phase { match self {
            Self::AwaitingConsent => ios_wire::Phase::AwaitingConsent, Self::Starting => ios_wire::Phase::Starting, Self::Running => ios_wire::Phase::Running,
            Self::Stopping => ios_wire::Phase::Stopping, Self::Terminal => ios_wire::Phase::Terminal, Self::Unknown => ios_wire::Phase::Unknown,
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome { Complete, Refused, Cancelled, TimedOut, Failed, Unknown }
impl Outcome {
    fn recovery(self) -> recovery_wire::Outcome { match self {
        Self::Complete => recovery_wire::Outcome::Complete,
        Self::Refused => recovery_wire::Outcome::Refused,
        Self::Cancelled => recovery_wire::Outcome::Cancelled,
        Self::TimedOut => recovery_wire::Outcome::TimedOut,
        Self::Failed => recovery_wire::Outcome::Failed,
        Self::Unknown => recovery_wire::Outcome::Unknown,
    } }
    fn from_recovery(value: recovery_wire::Outcome) -> Self { match value {
        recovery_wire::Outcome::Complete => Self::Complete,
        recovery_wire::Outcome::Refused => Self::Refused,
        recovery_wire::Outcome::Cancelled => Self::Cancelled,
        recovery_wire::Outcome::TimedOut => Self::TimedOut,
        recovery_wire::Outcome::Failed => Self::Failed,
        recovery_wire::Outcome::Unknown => Self::Unknown,
    } }
    fn from_offline(value: wire::Outcome) -> Self { match value {
            wire::Outcome::Complete => Self::Complete, wire::Outcome::Refused => Self::Refused, wire::Outcome::Cancelled => Self::Cancelled,
            wire::Outcome::TimedOut => Self::TimedOut, wire::Outcome::Failed => Self::Failed, wire::Outcome::Unknown => Self::Unknown,
    } }
    fn from_android(value: android_wire::Outcome) -> Self { match value {
            android_wire::Outcome::Complete => Self::Complete, android_wire::Outcome::Refused => Self::Refused, android_wire::Outcome::Cancelled => Self::Cancelled,
            android_wire::Outcome::TimedOut => Self::TimedOut, android_wire::Outcome::Failed => Self::Failed, android_wire::Outcome::Unknown => Self::Unknown,
    } }
    fn from_ios(value: ios_wire::Outcome) -> Self { match value {
            ios_wire::Outcome::Complete => Self::Complete, ios_wire::Outcome::Refused => Self::Refused, ios_wire::Outcome::Cancelled => Self::Cancelled,
            ios_wire::Outcome::TimedOut => Self::TimedOut, ios_wire::Outcome::Failed => Self::Failed, ios_wire::Outcome::Unknown => Self::Unknown,
    } }
    fn offline(self) -> wire::Outcome { match self {
            Self::Complete => wire::Outcome::Complete, Self::Refused => wire::Outcome::Refused, Self::Cancelled => wire::Outcome::Cancelled,
            Self::TimedOut => wire::Outcome::TimedOut, Self::Failed => wire::Outcome::Failed, Self::Unknown => wire::Outcome::Unknown,
    } }
    fn android(self) -> android_wire::Outcome { match self {
            Self::Complete => android_wire::Outcome::Complete, Self::Refused => android_wire::Outcome::Refused, Self::Cancelled => android_wire::Outcome::Cancelled,
            Self::TimedOut => android_wire::Outcome::TimedOut, Self::Failed => android_wire::Outcome::Failed, Self::Unknown => android_wire::Outcome::Unknown,
    } }
    fn ios(self) -> ios_wire::Outcome { match self {
            Self::Complete => ios_wire::Outcome::Complete, Self::Refused => ios_wire::Outcome::Refused, Self::Cancelled => ios_wire::Outcome::Cancelled,
            Self::TimedOut => ios_wire::Outcome::TimedOut, Self::Failed => ios_wire::Outcome::Failed, Self::Unknown => ios_wire::Outcome::Unknown,
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
    WorkRetained, CleanupUnknown, ContainerRequired, SchemeRequired, ContainerMissing, ArchiveValidationFailed, ProjectChanged, ReviewStale, ManualRequired, ProjectBusy, ProjectConflict, RecoveryIncomplete,
    SigningPolicyRequired, SigningInputMissing, SigningInputInvalid, SigningValidationFailed,
    AccountAdmissionRefused, ArtifactValidationFailed, SymbolsUploadNotRequested, RecoveryAttention,
}
impl Reason {
    fn recovery(self) -> Result<recovery_wire::Reason, BridgeError> { Ok(match self {
        Self::None => recovery_wire::Reason::None,
        Self::Cancelled => recovery_wire::Reason::Cancelled,
        Self::ContextChanged => recovery_wire::Reason::ContextChanged,
        Self::DocumentLost => recovery_wire::Reason::DocumentLost,
        Self::Shutdown => recovery_wire::Reason::Shutdown,
        Self::TimedOut => recovery_wire::Reason::TimedOut,
        Self::ProtocolError => recovery_wire::Reason::ProtocolError,
        Self::RuntimeUnavailable => recovery_wire::Reason::RuntimeUnavailable,
        Self::IntentExpired => recovery_wire::Reason::IntentExpired,
        Self::StaleIntent => recovery_wire::Reason::StaleIntent,
        Self::ProjectChanged => recovery_wire::Reason::ProjectChanged,
        Self::ReviewStale => recovery_wire::Reason::ReviewStale,
        Self::ManualRequired => recovery_wire::Reason::ManualRequired,
        Self::ProjectBusy => recovery_wire::Reason::ProjectBusy,
        Self::ProjectConflict => recovery_wire::Reason::ProjectConflict,
        Self::RecoveryIncomplete => recovery_wire::Reason::RecoveryIncomplete,
        Self::InputLimit => recovery_wire::Reason::InputLimit,
        Self::ResultLimit => recovery_wire::Reason::ResultLimit,
        Self::CleanupUnknown => recovery_wire::Reason::CleanupUnknown,
        _ => return Err(BridgeError::protocol()),
    }) }
    fn from_recovery(value: recovery_wire::Reason) -> Self { match value {
        recovery_wire::Reason::None => Self::None,
        recovery_wire::Reason::Cancelled => Self::Cancelled,
        recovery_wire::Reason::ContextChanged => Self::ContextChanged,
        recovery_wire::Reason::DocumentLost => Self::DocumentLost,
        recovery_wire::Reason::Shutdown => Self::Shutdown,
        recovery_wire::Reason::TimedOut => Self::TimedOut,
        recovery_wire::Reason::ProtocolError => Self::ProtocolError,
        recovery_wire::Reason::RuntimeUnavailable => Self::RuntimeUnavailable,
        recovery_wire::Reason::IntentExpired => Self::IntentExpired,
        recovery_wire::Reason::StaleIntent => Self::StaleIntent,
        recovery_wire::Reason::ProjectChanged => Self::ProjectChanged,
        recovery_wire::Reason::ReviewStale => Self::ReviewStale,
        recovery_wire::Reason::ManualRequired => Self::ManualRequired,
        recovery_wire::Reason::ProjectBusy => Self::ProjectBusy,
        recovery_wire::Reason::ProjectConflict => Self::ProjectConflict,
        recovery_wire::Reason::RecoveryIncomplete => Self::RecoveryIncomplete,
        recovery_wire::Reason::InputLimit => Self::InputLimit,
        recovery_wire::Reason::ResultLimit => Self::ResultLimit,
        recovery_wire::Reason::CleanupUnknown => Self::CleanupUnknown,
    } }
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
    fn from_ios(value: ios_wire::Reason) -> Self { match value {
        ios_wire::Reason::None => Self::None,
        ios_wire::Reason::Cancelled => Self::Cancelled,
        ios_wire::Reason::ContextChanged => Self::ContextChanged,
        ios_wire::Reason::DocumentLost => Self::DocumentLost,
        ios_wire::Reason::Shutdown => Self::Shutdown,
        ios_wire::Reason::TimedOut => Self::TimedOut,
        ios_wire::Reason::ProtocolError => Self::ProtocolError,
        ios_wire::Reason::RuntimeUnavailable => Self::RuntimeUnavailable,
        ios_wire::Reason::IntentExpired => Self::IntentExpired,
        ios_wire::Reason::StaleIntent => Self::StaleIntent,
        ios_wire::Reason::SavedConfigMissing => Self::SavedConfigMissing,
        ios_wire::Reason::SavedConfigInvalid => Self::SavedConfigInvalid,
        ios_wire::Reason::SavedConfigChanged => Self::SavedConfigChanged,
        ios_wire::Reason::SavedConfigSensitive => Self::SavedConfigSensitive,
        ios_wire::Reason::SavedConfigUnsafe => Self::SavedConfigUnsafe,
        ios_wire::Reason::SavedConfigTooLarge => Self::SavedConfigTooLarge,
        ios_wire::Reason::SavedVersionMissing => Self::SavedVersionMissing,
        ios_wire::Reason::SavedVersionInvalid => Self::SavedVersionInvalid,
        ios_wire::Reason::SavedVersionChanged => Self::SavedVersionChanged,
        ios_wire::Reason::SavedVersionSensitive => Self::SavedVersionSensitive,
        ios_wire::Reason::SavedVersionUnsafe => Self::SavedVersionUnsafe,
        ios_wire::Reason::SavedVersionTooLarge => Self::SavedVersionTooLarge,
        ios_wire::Reason::PlatformDisabled => Self::PlatformDisabled,
        ios_wire::Reason::ContainerRequired => Self::ContainerRequired,
        ios_wire::Reason::SchemeRequired => Self::SchemeRequired,
        ios_wire::Reason::ContainerMissing => Self::ContainerMissing,
        ios_wire::Reason::ToolchainUnavailable => Self::ToolchainUnavailable,
        ios_wire::Reason::ToolchainMismatch => Self::ToolchainMismatch,
        ios_wire::Reason::ProjectAdmissionRefused => Self::ProjectAdmissionRefused,
        ios_wire::Reason::CommandFailed => Self::CommandFailed,
        ios_wire::Reason::CommandIncomplete => Self::CommandIncomplete,
        ios_wire::Reason::ArtifactMissing => Self::ArtifactMissing,
        ios_wire::Reason::ArtifactUnsafe => Self::ArtifactUnsafe,
        ios_wire::Reason::ArtifactChanged => Self::ArtifactChanged,
        ios_wire::Reason::ArchiveValidationFailed => Self::ArchiveValidationFailed,
        ios_wire::Reason::SigningPolicyRequired => Self::SigningPolicyRequired,
        ios_wire::Reason::SigningInputMissing => Self::SigningInputMissing,
        ios_wire::Reason::SigningInputInvalid => Self::SigningInputInvalid,
        ios_wire::Reason::SigningValidationFailed => Self::SigningValidationFailed,
        ios_wire::Reason::AccountAdmissionRefused => Self::AccountAdmissionRefused,
        ios_wire::Reason::ArtifactValidationFailed => Self::ArtifactValidationFailed,
        ios_wire::Reason::SymbolsUploadNotRequested => Self::SymbolsUploadNotRequested,
        ios_wire::Reason::RecoveryAttention => Self::RecoveryAttention,
        ios_wire::Reason::InputLimit => Self::InputLimit,
        ios_wire::Reason::ResultLimit => Self::ResultLimit,
        ios_wire::Reason::WorkRetained => Self::WorkRetained,
        ios_wire::Reason::CleanupUnknown => Self::CleanupUnknown,
    } }
    fn ios(self) -> Result<ios_wire::Reason, BridgeError> { Ok(match self {
        Self::None => ios_wire::Reason::None,
        Self::Cancelled => ios_wire::Reason::Cancelled,
        Self::ContextChanged => ios_wire::Reason::ContextChanged,
        Self::DocumentLost => ios_wire::Reason::DocumentLost,
        Self::Shutdown => ios_wire::Reason::Shutdown,
        Self::TimedOut => ios_wire::Reason::TimedOut,
        Self::ProtocolError => ios_wire::Reason::ProtocolError,
        Self::RuntimeUnavailable => ios_wire::Reason::RuntimeUnavailable,
        Self::IntentExpired => ios_wire::Reason::IntentExpired,
        Self::StaleIntent => ios_wire::Reason::StaleIntent,
        Self::SavedConfigMissing => ios_wire::Reason::SavedConfigMissing,
        Self::SavedConfigInvalid => ios_wire::Reason::SavedConfigInvalid,
        Self::SavedConfigChanged => ios_wire::Reason::SavedConfigChanged,
        Self::SavedConfigSensitive => ios_wire::Reason::SavedConfigSensitive,
        Self::SavedConfigUnsafe => ios_wire::Reason::SavedConfigUnsafe,
        Self::SavedConfigTooLarge => ios_wire::Reason::SavedConfigTooLarge,
        Self::SavedVersionMissing => ios_wire::Reason::SavedVersionMissing,
        Self::SavedVersionInvalid => ios_wire::Reason::SavedVersionInvalid,
        Self::SavedVersionChanged => ios_wire::Reason::SavedVersionChanged,
        Self::SavedVersionSensitive => ios_wire::Reason::SavedVersionSensitive,
        Self::SavedVersionUnsafe => ios_wire::Reason::SavedVersionUnsafe,
        Self::SavedVersionTooLarge => ios_wire::Reason::SavedVersionTooLarge,
        Self::PlatformDisabled => ios_wire::Reason::PlatformDisabled,
        Self::ContainerRequired => ios_wire::Reason::ContainerRequired,
        Self::SchemeRequired => ios_wire::Reason::SchemeRequired,
        Self::ContainerMissing => ios_wire::Reason::ContainerMissing,
        Self::ToolchainUnavailable => ios_wire::Reason::ToolchainUnavailable,
        Self::ToolchainMismatch => ios_wire::Reason::ToolchainMismatch,
        Self::ProjectAdmissionRefused => ios_wire::Reason::ProjectAdmissionRefused,
        Self::CommandFailed => ios_wire::Reason::CommandFailed,
        Self::CommandIncomplete => ios_wire::Reason::CommandIncomplete,
        Self::ArtifactMissing => ios_wire::Reason::ArtifactMissing,
        Self::ArtifactUnsafe => ios_wire::Reason::ArtifactUnsafe,
        Self::ArtifactChanged => ios_wire::Reason::ArtifactChanged,
        Self::ArchiveValidationFailed => ios_wire::Reason::ArchiveValidationFailed,
        Self::SigningPolicyRequired => ios_wire::Reason::SigningPolicyRequired,
        Self::SigningInputMissing => ios_wire::Reason::SigningInputMissing,
        Self::SigningInputInvalid => ios_wire::Reason::SigningInputInvalid,
        Self::SigningValidationFailed => ios_wire::Reason::SigningValidationFailed,
        Self::AccountAdmissionRefused => ios_wire::Reason::AccountAdmissionRefused,
        Self::ArtifactValidationFailed => ios_wire::Reason::ArtifactValidationFailed,
        Self::SymbolsUploadNotRequested => ios_wire::Reason::SymbolsUploadNotRequested,
        Self::RecoveryAttention => ios_wire::Reason::RecoveryAttention,
        Self::InputLimit => ios_wire::Reason::InputLimit,
        Self::ResultLimit => ios_wire::Reason::ResultLimit,
        Self::WorkRetained => ios_wire::Reason::WorkRetained,
        Self::CleanupUnknown => ios_wire::Reason::CleanupUnknown,
        Self::ModuleRequired | Self::ArtifactAmbiguous | Self::ProjectChanged | Self::ReviewStale |
        Self::ManualRequired | Self::ProjectBusy | Self::ProjectConflict | Self::RecoveryIncomplete => return Err(BridgeError::protocol()),
    }) }
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
            Self::ProjectChanged | Self::ReviewStale | Self::ManualRequired | Self::ProjectBusy | Self::ProjectConflict | Self::RecoveryIncomplete | Self::ArtifactUnsafe | Self::ArtifactChanged | Self::WorkRetained | Self::ContainerRequired | Self::SchemeRequired
            | Self::ContainerMissing | Self::ArchiveValidationFailed | Self::SigningPolicyRequired | Self::SigningInputMissing
            | Self::SigningInputInvalid | Self::SigningValidationFailed | Self::AccountAdmissionRefused
            | Self::ArtifactValidationFailed | Self::SymbolsUploadNotRequested | Self::RecoveryAttention => return Err(BridgeError::protocol()),
        })
    }
    fn android(self) -> Result<android_wire::Reason, BridgeError> { Ok(match self {
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
        Self::ProjectChanged | Self::ReviewStale | Self::ManualRequired | Self::ProjectBusy | Self::ProjectConflict | Self::RecoveryIncomplete | Self::ContainerRequired | Self::SchemeRequired | Self::ContainerMissing | Self::ArchiveValidationFailed
        | Self::SigningPolicyRequired | Self::SigningInputMissing | Self::SigningInputInvalid | Self::SigningValidationFailed
        | Self::AccountAdmissionRefused | Self::ArtifactValidationFailed | Self::SymbolsUploadNotRequested | Self::RecoveryAttention => return Err(BridgeError::protocol()),
    }) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified, ToolchainUnqualified }
impl Availability {
    fn recovery(self) -> Result<recovery_wire::Availability, BridgeError> { Ok(match self {
        Self::Available => recovery_wire::Availability::Available,
        Self::Busy => recovery_wire::Availability::Busy,
        Self::Shutdown => recovery_wire::Availability::Shutdown,
        Self::CleanupUnknown => recovery_wire::Availability::CleanupUnknown,
        Self::DocumentLost => recovery_wire::Availability::DocumentLost,
        Self::UnsupportedPlatform => recovery_wire::Availability::UnsupportedPlatform,
        Self::RuntimeUnqualified => recovery_wire::Availability::RuntimeUnqualified,
        _ => return Err(BridgeError::protocol()),
    }) }
    fn from_recovery(value: recovery_wire::Availability) -> Self { match value {
        recovery_wire::Availability::Available => Self::Available,
        recovery_wire::Availability::Busy => Self::Busy,
        recovery_wire::Availability::Shutdown => Self::Shutdown,
        recovery_wire::Availability::CleanupUnknown => Self::CleanupUnknown,
        recovery_wire::Availability::DocumentLost => Self::DocumentLost,
        recovery_wire::Availability::UnsupportedPlatform => Self::UnsupportedPlatform,
        recovery_wire::Availability::RuntimeUnqualified => Self::RuntimeUnqualified,
    } }
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
    fn from_ios(value: ios_wire::Availability) -> Self { match value {
            ios_wire::Availability::Available => Self::Available, ios_wire::Availability::Busy => Self::Busy, ios_wire::Availability::Shutdown => Self::Shutdown,
            ios_wire::Availability::CleanupUnknown => Self::CleanupUnknown, ios_wire::Availability::DocumentLost => Self::DocumentLost, ios_wire::Availability::UnsupportedPlatform => Self::UnsupportedPlatform,
            ios_wire::Availability::RuntimeUnqualified => Self::RuntimeUnqualified, ios_wire::Availability::ToolchainUnqualified => Self::ToolchainUnqualified,
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
    fn ios(self) -> ios_wire::Availability { match self {
            Self::Available => ios_wire::Availability::Available, Self::Busy => ios_wire::Availability::Busy, Self::Shutdown => ios_wire::Availability::Shutdown,
            Self::CleanupUnknown => ios_wire::Availability::CleanupUnknown, Self::DocumentLost => ios_wire::Availability::DocumentLost, Self::UnsupportedPlatform => ios_wire::Availability::UnsupportedPlatform,
            Self::RuntimeUnqualified => ios_wire::Availability::RuntimeUnqualified, Self::ToolchainUnqualified => ios_wire::Availability::ToolchainUnqualified,
    } }
}
#[derive(Clone)]
enum Terminal { OfflinePreflight(wire::Terminal), AndroidBuild(android_wire::Terminal), ProjectRecovery(recovery_wire::Terminal), IOSArchive(ios_wire::Terminal) }
impl Terminal {
    fn outcome(&self) -> Outcome { match self {
        Self::OfflinePreflight(t) => Outcome::from_offline(t.outcome), Self::AndroidBuild(t) => Outcome::from_android(t.outcome),
        Self::ProjectRecovery(t) => Outcome::from_recovery(t.outcome), Self::IOSArchive(t) => Outcome::from_ios(t.outcome),
    } }
    fn reason(&self) -> Reason { match self {
        Self::OfflinePreflight(t) => Reason::from_offline(t.reason), Self::AndroidBuild(t) => Reason::from_android(t.reason),
        Self::ProjectRecovery(t) => Reason::from_recovery(t.reason), Self::IOSArchive(t) => Reason::from_ios(t.reason),
    } }
    fn settled(&self) -> bool { match self {
        Self::OfflinePreflight(t) => t.lifetime.settled(), Self::AndroidBuild(t) => t.settled(),
        Self::ProjectRecovery(t) => t.settled(), Self::IOSArchive(t) => t.settled(),
    } }
}
enum Frame { OfflinePreflight(wire::Frame), AndroidBuild(android_wire::Frame), ProjectRecovery(recovery_wire::Frame), IOSArchive(ios_wire::Frame) }
struct Start { operation_id: String, owner_generation: String }
enum Status { OfflinePreflight(wire::Status), AndroidBuild(android_wire::Status), ProjectRecovery(recovery_wire::Status), IOSArchive(ios_wire::Status) }
impl Status {
    fn recovery(self) -> Result<recovery_wire::Status, BridgeError> { match self {
        Self::ProjectRecovery(status) => Ok(status), _ => Err(BridgeError::protocol()),
    } }
    fn offline(self) -> Result<wire::Status, BridgeError> { match self {
        Self::OfflinePreflight(status) => Ok(status), Self::AndroidBuild(_) | Self::ProjectRecovery(_) | Self::IOSArchive(_) => Err(BridgeError::protocol()),
    } }
    fn android(self) -> Result<android_wire::Status, BridgeError> { match self {
        Self::AndroidBuild(status) => Ok(status), Self::OfflinePreflight(_) | Self::ProjectRecovery(_) | Self::IOSArchive(_) => Err(BridgeError::protocol()),
    } }
    fn ios(self) -> Result<ios_wire::Status, BridgeError> { match self {
        Self::IOSArchive(status) => Ok(status), Self::OfflinePreflight(_) | Self::AndroidBuild(_) | Self::ProjectRecovery(_) => Err(BridgeError::protocol()),
    } }
}

#[derive(Clone, Copy)]
struct Clocks { admitted: Instant, work: Instant, finality: Instant, cleanup: Instant, signed: bool, recovery: bool }
impl Clocks {
    fn new(domain: SavedCommandDomain, admitted: Instant) -> Self {
        let (work, hard) = match domain { SavedCommandDomain::OfflinePreflight => (OFFLINE_WORK, OFFLINE_HARD),
            SavedCommandDomain::AndroidBuild => (ANDROID_WORK, ANDROID_HARD), SavedCommandDomain::IOSArchive => (IOS_WORK, IOS_HARD), SavedCommandDomain::ProjectRecovery => (RECOVERY_WORK, RECOVERY_HARD) };
        Self { admitted, work: admitted + work, finality: admitted + hard, cleanup: admitted + hard, signed: false, recovery: false }
    }
    fn for_context(context: &Context, admitted: Instant) -> Self {
        let mut clocks = Self::new(context.domain(), admitted);
        if context.signed_ios() {
            clocks.cleanup = admitted + IOS_SIGNED_CLEANUP;
            clocks.finality = admitted + IOS_SIGNED_HARD;
            clocks.signed = true;
        } else if context.recovery_ios() {
            clocks.work = admitted + IOS_RECOVERY_WORK;
            clocks.cleanup = admitted + IOS_RECOVERY_CLEANUP;
            clocks.finality = admitted + IOS_RECOVERY_HARD;
            clocks.recovery = true;
        }
        clocks
    }
    fn settlement(self, first_stop: Option<Instant>) -> Instant {
        first_stop.map_or(self.finality, |first| self.finality.min(first + if self.signed || self.recovery { IOS_SIGNED_SETTLEMENT } else { SETTLEMENT }))
    }
    fn cleanup_end(self, first_stop: Option<Instant>) -> Instant {
        first_stop.map_or(self.cleanup, |first| self.cleanup.min(first + if self.signed || self.recovery { Duration::from_secs(120) } else { SETTLEMENT }))
    }
    fn audit_end(self, first_stop: Option<Instant>) -> Instant {
        if self.signed || self.recovery { self.settlement(first_stop) } else { self.work.min(self.settlement(first_stop)) }
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
    fn installed_ios(admitted: Instant) -> Self {
        // Only the sealed original Mac observation admits this shorter clock.
        // It is selected at Start, before Session/watch publication, never by
        // the renderer, the environment, a subphase, or a later observation.
        let work = IOS_WORK.min(Duration::from_secs(300));
        let hard = IOS_HARD.min(work + SETTLEMENT);
        Self { admitted, work: admitted + work, finality: admitted + hard, cleanup: admitted + hard, signed: false, recovery: false }
    }
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
    fn installed_ios_signed(admitted: Instant) -> Self {
        // The same original signed observation selects all three clocks once
        // at Start. Existing F+120/F+130 tightening still cannot renew them.
        Self { admitted, work: admitted + IOS_WORK.min(Duration::from_secs(120)),
            finality: admitted + IOS_SIGNED_HARD.min(Duration::from_secs(250)),
            cleanup: admitted + IOS_SIGNED_CLEANUP.min(Duration::from_secs(240)), signed: true, recovery: false }
    }
}
#[derive(Clone)]
pub(crate) struct SavedCommandOwner { inner: Arc<Inner> }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct InstalledObservation { control: Arc<crate::shell::installed_observation::commands::Control>, original: Option<Arc<Session>>, retired: bool, core_settled: bool, android_lifetime: Option<android_wire::Lifetime> }
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
struct InstalledIOSObservation {
    control: Arc<crate::shell::installed_observation::ios::Control>, original: Option<Arc<Session>>,
    retired: bool, core_settled: bool, terminal: Option<ios_wire::Terminal>,
}
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
#[path = "saved_command_recovery_observation.rs"]
mod recovery_observation;
struct Inner {
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    observation: Mutex<Option<InstalledObservation>>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    observation_identity: Arc<()>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
    recovery_observation: Mutex<Option<recovery_observation::Observation>>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
    ios_observation: Mutex<Option<InstalledIOSObservation>>,
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
    ios_observation_identity: Arc<()>,
    android_original_owner: bool, android_document: Mutex<Option<std::sync::Weak<()>>>,
    android_registration_control: Arc<android_registration::ControlSlot>,
    #[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
    android_service_dispatcher:std::sync::OnceLock<Arc<AndroidServiceDispatcher>>,
    domain: SavedCommandDomain, runtime: RuntimeConfig, toolchain: Option<AndroidToolchainProfile>, registry: Mutex<Registry>, changes: watch::Sender<u32>, changed: Notify, poisoned: AtomicBool,
    #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
        any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    fixture: Mutex<Option<std::sync::Weak<offline_tests::hosted::Permit>>>,
}
struct Registry {
    revision: u32, exhausted: bool, disabled: bool, stopping: bool, document_lost: bool,
    capability: Availability, prepared: Option<Prepared>, active: Option<Active>, last: Option<RunProjection>, recovery_review: Option<RecoveryReview>,
    recovery: Option<Arc<IOSRecoveryObservation>>, android_catalog: android_catalog::Catalog, android_sources: android_sources::Sources,
    android_registration: android_registration::Registration,
}
struct Prepared { projection: RunProjection, expires: Instant, registration: u32, project: RegisteredRoot, recovery_stamp: Option<String>,
    material: Option<Arc<IOSSigningMaterial>>, recovery: Option<Arc<IOSRecoveryObservation>>,
    android_selection: Option<Arc<android_catalog::Selection>> }
struct RecoveryReview { context: recovery_wire::Context, observation: recovery_wire::Observation, stamp: String, expires: Instant, registration: u32, project: RegisteredRoot }
struct Active {
    owner: Arc<Session>, projection: RunProjection, first_stop: Option<Instant>, work_expired: bool,
    accepted: bool, terminal: bool, unknown: bool, final_join_seen: bool, context_invalidated: bool,
}
/// Issued only by reconcile after the actual positive original final join.
/// The renderer's session string is a comparison, not an admission capability.
/// Retain the original Session and its consumed Ready result, not a report
/// detached from the operation which produced and finalized it.
struct IOSRecoveryObservation { original: Arc<Session>, terminal: ios_wire::Terminal }
impl IOSRecoveryObservation {
    fn matches(&self, context: &Context, registration: u32, project: &RegisteredRoot) -> bool {
        let Context::IOSArchive(context) = context else { return false; };
        let Context::IOSArchive(inspected) = &self.original.context else { return false; };
        if !context.recovery() || !inspected.recovery() || self.original.registration != registration || &self.original.project != project
            || inspected.project_id != context.project_id || self.terminal.context != *inspected || !self.terminal.settled()
            || !inspected.recovery.as_ref().is_some_and(|r| r.action == ios_wire::RecoveryAction::Inspect)
            || !self.original.watchdog_joined.load(Ordering::SeqCst) || self.original.watchdog_failed.load(Ordering::SeqCst)
            || self.original.resource_unknown.load(Ordering::SeqCst) || !self.original.material_retired.load(Ordering::SeqCst)
            || !self.original.watchdog_return.lock().is_ok_and(|r| matches!(r.as_ref(), Some(Ok(true)))) { return false; }
        let Some(intent) = &context.recovery else { return false; };
        let Some(report) = &self.terminal.report else { return false; };
        let row = match intent.action { ios_wire::RecoveryAction::Account => report.account.as_ref(),
            ios_wire::RecoveryAction::Project => report.project.as_ref(), ios_wire::RecoveryAction::Inspect => return false };
        row.is_some_and(|row| row.session.is_some() && row.session == intent.session && row.next == ios_wire::RecoveryNext::Ordinary
            && matches!(row.status, ios_wire::RecoveryState::Pending | ios_wire::RecoveryState::CleanupOnly))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage { AndroidBuild(android_wire::Stage), IOSArchive(ios_wire::Stage) }
impl Stage {
    fn after(self, previous: Self) -> bool { match (self, previous) {
        (Self::AndroidBuild(a), Self::AndroidBuild(b)) => a > b, (Self::IOSArchive(a), Self::IOSArchive(b)) => a > b, _ => false,
    } }
    fn at_or_after(self, previous: Self) -> bool { self == previous || self.after(previous) }
}
#[derive(Clone)]
struct RunProjection {
    operation_id: String, owner_generation: String, context: Context, phase: Phase, intent_usable: bool,
    outcome: Option<Outcome>, reason: Reason, result: Option<Terminal>, stage: Option<Stage>,
}
impl RunProjection {
    fn recovery(self) -> Result<recovery_wire::Projection, BridgeError> {
        let Context::ProjectRecovery(context) = self.context else { return Err(BridgeError::protocol()); };
        if self.stage.is_some() { return Err(BridgeError::protocol()); }
        let (result, effect) = match self.result {
            Some(Terminal::ProjectRecovery(t)) => (t.result, Some(t.effect)), None => (None, None),
            _ => return Err(BridgeError::protocol()),
        };
        Ok(recovery_wire::Projection { operation_id: self.operation_id, owner_generation: self.owner_generation,
            context, phase: self.phase.recovery(), intent_usable: self.intent_usable,
            outcome: self.outcome.map(Outcome::recovery), reason: self.reason.recovery()?, result, effect })
    }
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
                Some(Terminal::ProjectRecovery(t)) if t.outcome != recovery_wire::Outcome::Complete
                    && t.outcome != recovery_wire::Outcome::Unknown && t.settled() => self.result.clone(),
                Some(Terminal::IOSArchive(t)) if t.outcome != ios_wire::Outcome::Complete
                    && t.outcome != ios_wire::Outcome::Unknown && t.settled()
                    && t.disposition.as_ref().is_none_or(|d| d.output != ios_wire::OutputDisposition::RetainedLocalResult) => self.result.clone(),
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
            None => None, Some(Terminal::AndroidBuild(_) | Terminal::ProjectRecovery(_) | Terminal::IOSArchive(_)) => return Err(BridgeError::protocol()),
        };
        Ok(wire::Projection { operation_id: self.operation_id, owner_generation: self.owner_generation, context,
            phase: self.phase.offline(), intent_usable: self.intent_usable, outcome: self.outcome.map(Outcome::offline),
            reason: self.reason.offline()?, result })
    }
    fn android(self) -> Result<android_wire::Projection, BridgeError> {
        let Context::AndroidBuild(context) = self.context else { return Err(BridgeError::protocol()); };
        let (result, activity, disposition) = match self.result {
            Some(Terminal::AndroidBuild(t)) => (t.result, Some(t.activity), Some(t.disposition)),
            None => (None, None, None), Some(Terminal::OfflinePreflight(_) | Terminal::IOSArchive(_) | Terminal::ProjectRecovery(_)) => return Err(BridgeError::protocol()),
        };
        Ok(android_wire::Projection { operation_id: self.operation_id, owner_generation: self.owner_generation, context,
            phase: self.phase.android(), intent_usable: self.intent_usable, outcome: self.outcome.map(Outcome::android),
            reason: self.reason.android()?, stage: match self.stage { None => None, Some(Stage::AndroidBuild(stage)) => Some(stage), _ => return Err(BridgeError::protocol()) }, result, activity, disposition })
    }
    fn ios(self) -> Result<ios_wire::Projection, BridgeError> {
        let Context::IOSArchive(context) = self.context else { return Err(BridgeError::protocol()); };
        let (result, activity, disposition, report) = match self.result {
            Some(Terminal::IOSArchive(t)) => (t.result, Some(t.activity), t.disposition, t.report),
            None => (None, None, None, None), Some(Terminal::OfflinePreflight(_)) | Some(Terminal::AndroidBuild(_)) | Some(Terminal::ProjectRecovery(_)) => return Err(BridgeError::protocol()),
        };
        Ok(ios_wire::Projection { operation_id: self.operation_id, owner_generation: self.owner_generation, context,
            phase: self.phase.ios(), intent_usable: self.intent_usable, outcome: self.outcome.map(Outcome::ios),
            reason: self.reason.ios()?, stage: match self.stage { None => None, Some(Stage::IOSArchive(stage)) => Some(stage), _ => return Err(BridgeError::protocol()) }, result, activity, disposition, report })
    }
}
struct Session {
    domain: SavedCommandDomain, id: String, generation: String, context: Context, profile: Profile, clocks: Clocks,
    registration: u32, project: RegisteredRoot, recovery_stamp: Option<String>, request: AsyncMutex<Option<Vec<u8>>>,
    material: Mutex<Option<Arc<IOSSigningMaterial>>>, material_retired: AtomicBool,
    recovery: Option<Arc<IOSRecoveryObservation>>,
    android_selection: Option<Arc<android_catalog::Selection>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
    android_control: Option<Arc<AndroidUseControl>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
    android_close: Option<Arc<AndroidCloseSlot>>,
    native_failure: Mutex<Option<(Reason,Instant)>>,
    stop: watch::Sender<bool>, pipes: watch::Sender<Pipes>, frames: mpsc::Sender<Frame>, wake: Notify,
    native_audit_cutoff: watch::Sender<Instant>, native_cleanup_cutoff: watch::Sender<Instant>,
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
impl Session {
    // Bounded DATA publication only: no Registry/Document acquisition while
    // original native books are borrowed. Preserve the actual native timestamp.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn observe_android_failure(&self, failure: AdmissionFailure, at: Instant) { self.observe_native_failure(failure, at); }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn observe_native_failure(&self, failure: AdmissionFailure, at: Instant) {
        let reason = match failure { AdmissionFailure::Deadline => Reason::TimedOut,
            AdmissionFailure::Unknown => Reason::CleanupUnknown,
            _ if self.domain == SavedCommandDomain::AndroidBuild => Reason::ToolchainUnavailable,
            _ => Reason::RuntimeUnavailable };
        self.observe_failure_at(reason, at, failure == AdmissionFailure::Unknown);
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn observe_failure_at(&self, reason: Reason, at: Instant, unknown: bool) {
        // The caller already captured F. Preserve its finite reason without
        // acquiring Registry or replacing this original Session's min latch.
        self.note_android_local(at,unknown);
        let first = match self.native_failure.lock() {
            Ok(mut first) => {
                if first.is_none_or(|(_, before)| at < before) { *first = Some((reason, at)); }
                first.as_ref().map(|(_, at)| (*at).max(self.clocks.admitted).min(self.clocks.work))
            },
            Err(_) => { self.resource_unknown.store(true, Ordering::SeqCst); Some(self.clocks.admitted) },
        };
        if unknown { self.resource_unknown.store(true, Ordering::SeqCst); }
        let audit = self.audit_end(first); let cleanup = self.cleanup_end(first);
        self.native_audit_cutoff.send_if_modified(|current| if audit < *current { *current = audit; true } else { false });
        self.native_cleanup_cutoff.send_if_modified(|current| if cleanup < *current { *current = cleanup; true } else { false });
        self.stop.send_replace(true); self.wake.notify_waiters();
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn publish_native_failure(&self, first: Option<(AdmissionFailure, Instant)>) {
        if let Some((failure, at)) = first { self.observe_native_failure(failure, at); }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn native_cleanup_expired(&self, first: Option<(AdmissionFailure, Instant)>) -> bool {
        self.publish_native_failure(first);
        let expired = self.native_failure.is_poisoned() || Instant::now() >= *self.native_cleanup_cutoff.borrow();
        if expired { self.resource_unknown.store(true, Ordering::SeqCst); self.wake.notify_waiters(); }
        expired
    }
    fn leased_android(&self)->bool {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        {return self.android_control.is_some();}
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
        {false}
    }
    fn note_android_local(&self,at:Instant,unknown:bool) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if let Some(control)=&self.android_control{
            // at is this caller's already captured genuine event. Do not
            // resample in a supplied-time reducer or re-map remote DATA.
            control.local(at,at,unknown);
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
        let _=(at,unknown);
    }
    fn sample_android_control(&self) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if let Some(control)=&self.android_control{
            let data=control.data();
            let audit=control.cutoff(None,self.clocks.work);
            let cleanup=control.cutoff(None,self.clocks.finality);
            self.native_audit_cutoff.send_if_modified(|current|if audit<*current{*current=audit;true}else{false});
            self.native_cleanup_cutoff.send_if_modified(|current|if cleanup<*current{*current=cleanup;true}else{false});
            let failure=data.local_first.is_some() || data.failure.is_some_and(|value|value.first.is_some());
            let unknown=data.unknown && !self.resource_unknown.swap(true,Ordering::SeqCst);
            if failure || data.unknown {
                let stopped=self.stop.send_if_modified(|current|if !*current{*current=true;true}else{false});
                if stopped || unknown{self.wake.notify_waiters();}
            }
        }
    }
    fn android_control_stopped(&self)->bool {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        {return self.android_control.as_ref().is_some_and(|control|control.stopped());}
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
        {false}
    }
    fn finality_end(&self,first:Option<Instant>)->Instant {
        let end=self.clocks.settlement(first);
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if let Some(control)=&self.android_control{return control.cutoff(first,end);}
        end
    }
    fn audit_end(&self,first:Option<Instant>)->Instant {
        let end=self.clocks.audit_end(first);
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if let Some(control)=&self.android_control{return control.cutoff(first,end);}
        end
    }
    fn cleanup_end(&self,first:Option<Instant>)->Instant {
        let end=self.clocks.cleanup_end(first);
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if let Some(control)=&self.android_control{return control.cutoff(first,end);}
        end
    }
    async fn android_control_tick(&self) {
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if self.android_control.is_some(){tokio::time::sleep(android_leased::CONTROL_POLL).await;return;}
        pending::<()>().await
    }
    fn recovery_matches(&self) -> bool {
        match (&self.context, &self.recovery) {
            (Context::IOSArchive(context), Some(original)) if context.recovery() =>
                original.matches(&self.context, self.registration, &self.project),
            (Context::IOSArchive(context), None) if context.recovery() =>
                context.recovery.as_ref().is_some_and(|r| r.action == ios_wire::RecoveryAction::Inspect),
            (_, None) => true,
            _ => false,
        }
    }
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
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    offline_installed: Option<Arc<Mutex<OfflinePreflightRuntimeSlots>>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    offline_settlement: Option<JoinHandle<CloseOutcome>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    offline_return: Option<Result<CloseOutcome, tokio::task::JoinError>>,
    offline_started: bool, offline_joined: bool, offline_failed: bool,
    recovery_selected: bool,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    recovery_installed: Option<Arc<Mutex<ProjectRecoveryRuntimeSlots>>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    recovery_settlement: Option<JoinHandle<CloseOutcome>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    recovery_return: Option<Result<CloseOutcome, tokio::task::JoinError>>,
    recovery_started: bool, recovery_joined: bool, recovery_failed: bool,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    native: Option<Arc<Mutex<AndroidNativeBooks>>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    ios_native: Option<Arc<Mutex<IOSNativeBooks>>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    native_settlement: Option<JoinHandle<NativeSettlement>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    native_return: Option<Result<NativeSettlement, tokio::task::JoinError>>,
    native_started: bool, native_joined: bool, native_failed: bool,
    #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
    android_observations: Option<AndroidObservationSlot>,
    child: Option<Child>, waited: Option<ExitStatus>, wait_failed: bool,
    writer: Option<JoinHandle<WriteEnd>>, stdout: Option<JoinHandle<ReadEnd>>, stderr: Option<JoinHandle<ReadEnd>>,
    write_end: Option<WriteEnd>, out_end: Option<ReadEnd>, err_end: Option<ReadEnd>,
    write_failed: bool, out_failed: bool, err_failed: bool, frames: Option<mpsc::Receiver<Frame>>,
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum NativePhase { New, Inspecting, Ready, Claimed, Refused, Settling, Settled, Unknown }
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
struct AndroidNativeBooks {
    runtime: InstalledRuntimeCustody, tools: AndroidToolchainCustody,
    phase: NativePhase, failure: Option<AdmissionFailure>, settlement_started: bool,
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
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
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct IOSNativeBooks {
    runtime: IOSArchiveRuntimeSlots, tools: IOSXcodeSlots, selection: Option<VerifiedRuntime>,
    phase: NativePhase, failure: Option<AdmissionFailure>, settlement_started: bool, audit: watch::Receiver<Instant>, signed: bool, recovery: bool,
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl IOSNativeBooks {
    fn new(audit: watch::Receiver<Instant>) -> Self {
        Self::new_selected(audit, false, false)
    }
    fn new_selected(audit: watch::Receiver<Instant>, signed: bool, recovery: bool) -> Self {
        Self { runtime: IOSArchiveRuntimeSlots::new(), tools: IOSXcodeSlots::new(audit.clone()), selection: None,
            phase: NativePhase::New, failure: None, settlement_started: false, audit, signed, recovery }
    }
    fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> {
        match (self.runtime.first_failure(), self.tools.first_failure()) {
            (Some(a), Some(b)) => Some(if a.1 <= b.1 { a } else { b }), (a, b) => a.or(b),
        }
    }
    fn arm_acl_once(&mut self, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>)) -> Result<(), BridgeError> {
        if self.phase != NativePhase::New { return Err(BridgeError::cleanup_unknown()); }
        let runtime = self.runtime.arm_acl_once(end, stop); publish(self.runtime.first_failure());
        if let Err(failure) = runtime {
            self.failure.get_or_insert(failure); self.phase = NativePhase::Refused;
            return Err(SavedCommandDomain::IOSArchive.unavailable());
        }
        let tools = self.tools.arm_acl_once(end, stop); publish(self.tools.first_failure());
        if let Err(failure) = tools {
            self.failure.get_or_insert(failure); self.phase = NativePhase::Refused;
            return Err(SavedCommandDomain::IOSArchive.unavailable());
        }
        Ok(())
    }
    fn inspect_once(&mut self, runtime: &RuntimeConfig, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>)) -> Result<VerifiedRuntime, BridgeError> {
        if self.phase != NativePhase::New { return Err(BridgeError::cleanup_unknown()); }
        self.phase = NativePhase::Inspecting;
        let inspected = runtime.resolve_ios_archive_installed(&mut self.runtime, end, stop);
        publish_macos_returned_failure(inspected.as_ref().err().map(|_| AdmissionFailure::Inventory),
            || self.runtime.first_failure(), publish);
        let selected = match inspected {
            Ok(selected) => selected,
            Err(error) => { self.phase = NativePhase::Refused; self.failure.get_or_insert(AdmissionFailure::Inventory); return Err(error); },
        };
        self.selection = Some(VerifiedRuntime { python: selected.python.clone(), bootstrap: selected.bootstrap.clone(),
            core: selected.core.clone(), cwd: selected.cwd.clone() });
        let tools = if self.signed && self.recovery { Err(AdmissionFailure::Inventory) }
            else if self.recovery { self.tools.inspect_recovery_once(end, stop) }
            else if self.signed { self.tools.inspect_signed_once(end, stop) } else { self.tools.inspect_once(end, stop) };
        publish_macos_returned_failure(tools.as_ref().err().copied(),
            || self.tools.first_failure(), publish);
        if let Err(failure) = tools {
            self.phase = NativePhase::Refused; self.failure.get_or_insert(failure);
            return Err(SavedCommandDomain::IOSArchive.unavailable());
        }
        self.phase = NativePhase::Ready;
        Ok(selected)
    }
    fn selected_binding(&self, expected: &VerifiedRuntime) -> Result<(), AdmissionFailure> {
        if self.phase != NativePhase::Ready || self.failure.is_some() || self.settlement_started { return Err(AdmissionFailure::AlreadyUsed); }
        let selected = self.selection.as_ref().ok_or(AdmissionFailure::Unknown)?;
        if (&selected.python, &selected.bootstrap, &selected.core, &selected.cwd)
            != (&expected.python, &expected.bootstrap, &expected.core, &expected.cwd) { return Err(AdmissionFailure::Identity); }
        Ok(())
    }
    fn request_binding(&self, expected: &VerifiedRuntime) -> Result<ios_wire::ToolchainBinding, AdmissionFailure> {
        self.selected_binding(expected)?;
        if self.recovery { return Err(AdmissionFailure::Inventory); }
        self.tools.binding_data()
    }
    fn signing_binding(&self, expected: &VerifiedRuntime) -> Result<ios_wire::SigningToolBindings, AdmissionFailure> {
        if !self.signed { return Err(AdmissionFailure::Inventory); }
        let _ = self.request_binding(expected)?;
        self.tools.signing_binding_data()
    }
    fn recovery_binding(&self, expected: &VerifiedRuntime) -> Result<ios_wire::ToolIdentity, AdmissionFailure> {
        self.selected_binding(expected)?;
        if !self.recovery || self.signed { return Err(AdmissionFailure::Inventory); }
        self.tools.recovery_binding_data()
    }
    fn check_before_spawn(&mut self, selected: &VerifiedRuntime, end: Instant, stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>)) -> Result<(), AdmissionFailure> {
        self.selected_binding(selected)?;
        let result = (|| {
            self.runtime.transfer_once()?;
            let original = self.runtime.capability()?.prepare_once_observed(end, stop, publish)?;
            if (&original.python, &original.bootstrap, &original.core, &original.cwd)
                != (&selected.python, &selected.bootstrap, &selected.core, &selected.cwd) { return Err(AdmissionFailure::Identity); }
            let result = self.tools.check_before_spawn(end, stop);
            publish_macos_returned_failure(result.as_ref().err().copied(),
                || self.tools.first_failure(), publish);
            result
        })();
        if let Err(failure) = result { self.failure.get_or_insert(failure); self.phase = NativePhase::Refused; }
        result
    }
    fn claim_once(&mut self) -> Result<(), AdmissionFailure> {
        if self.phase != NativePhase::Ready || self.failure.is_some() || self.settlement_started { return Err(AdmissionFailure::AlreadyUsed); }
        self.runtime.capability()?.claim_once()?;
        self.phase = NativePhase::Claimed;
        Ok(())
    }
    fn interrupted(&mut self) {
        self.phase = NativePhase::Unknown; self.failure.get_or_insert(AdmissionFailure::Unknown);
        self.runtime.mark_interrupted(); self.tools.mark_interrupted();
    }
    fn settle(&mut self, used: bool, end: Instant,
        expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> NativeSettlement {
        let _ = expired(self.first_failure());
        if self.settlement_started || self.phase == NativePhase::Claimed && !used {
            return NativeSettlement { originals_closed: false, integrity: false };
        }
        self.settlement_started = true; self.phase = NativePhase::Settling;
        let mut integrity = !used || self.failure.is_none();
        if used {
            // Publish the first audit's actual F BEFORE entering its sibling.
            // Audits retain audit_end; native frees/FD closes use cleanup_end.
            let runtime = self.runtime.ios_check_after_use(end, &self.audit);
            publish_macos_returned_failure(runtime.as_ref().err().copied(),
                || self.runtime.first_failure(), &mut |first| { let _ = expired(first); });
            if let Err(failure) = runtime { self.failure.get_or_insert(failure); integrity = false; }
            let tools = self.tools.check_after_use(end);
            publish_macos_returned_failure(tools.as_ref().err().copied(),
                || self.tools.first_failure(), &mut |first| { let _ = expired(first); });
            if let Err(failure) = tools { self.failure.get_or_insert(failure); integrity = false; }
        }
        let tools = self.tools.settle_originals(expired);
        let runtime = self.runtime.settle_originals(expired);
        let _ = expired(self.first_failure());
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
        && r.active.as_ref().is_some_and(|a| !a.unknown && now < owner.finality_end(a.first_stop))
}
fn native_worker_lost(book: &Resources, owner: &Session) {
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    if owner.domain == SavedCommandDomain::OfflinePreflight {
        if let Some(native) = &book.offline_installed {
            match native.lock() { Ok(mut slots) => slots.mark_interrupted(), Err(error) => error.into_inner().mark_interrupted() }
        }
        return;
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    if owner.domain == SavedCommandDomain::ProjectRecovery {
        if let Some(native) = &book.recovery_installed {
            match native.lock() { Ok(mut slots) => slots.mark_interrupted(), Err(error) => error.into_inner().mark_interrupted() }
        }
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if owner.domain == SavedCommandDomain::IOSArchive {
        if let Some(native) = &book.ios_native {
            match native.lock() { Ok(mut native) => native.interrupted(), Err(error) => error.into_inner().interrupted() }
        }
        return;
    }
    if owner.domain != SavedCommandDomain::AndroidBuild { return; }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
    if let Some(native) = &book.native {
        // Called ONLY after the actual original worker's failed Ready return.
        let mut native=match native.lock(){Ok(native)=>native,Err(error)=>error.into_inner()};
        native.interrupted();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        native.publish(&mut |failure,at|owner.observe_android_failure(failure,at));
    }
}
fn native_final(book: &Resources, owner: &Session) -> bool {
    let domain=owner.domain;
    if domain == SavedCommandDomain::OfflinePreflight { return offline_installed_final(book); }
    if domain == SavedCommandDomain::ProjectRecovery { return recovery_installed_final(book); }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        domain == SavedCommandDomain::AndroidBuild && book.native_started && book.native_joined && !book.native_failed && book.native_settlement.is_none()
            && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, integrity: true })))
            && book.native.as_ref().is_some_and(|native| native.lock().is_ok_and(|native| native.settled()))
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if domain==SavedCommandDomain::AndroidBuild {
            // This branch is frozen/control DATA ONLY. The actual observer
            // captured observation readiness before transferring the whole
            // SH tail. Never re-enter native books for settled/bytes here.
            #[cfg(not(feature = "macos-android-registration-helper"))]
            {return owner.android_close.as_ref().is_some_and(|close|close.known());}
            #[cfg(feature = "macos-android-registration-helper")]
            {return false;}
        }
        domain==SavedCommandDomain::IOSArchive && book.native.is_none()
            && book.native_started && book.native_joined && !book.native_failed && book.native_settlement.is_none()
            && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, integrity: true })))
            && book.ios_native.as_ref().is_some_and(|native|native.try_lock().is_ok_and(|native|native.settled()))
    }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
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
    pub(crate) fn project_recovery(runtime: RuntimeConfig) -> Self { Self::new(runtime, SavedCommandDomain::ProjectRecovery) }
    pub(crate) fn offline_preflight(runtime: RuntimeConfig) -> Self { Self::new(runtime, SavedCommandDomain::OfflinePreflight) }
    pub(crate) fn ios_archive(runtime: RuntimeConfig) -> Self { Self::new(runtime, SavedCommandDomain::IOSArchive) }
    pub(crate) fn android_build(runtime: RuntimeConfig, toolchain: Option<AndroidToolchainProfile>) -> Self {
        Self::new_selected(runtime, SavedCommandDomain::AndroidBuild, toolchain)
    }
    pub(crate) fn android_registration_control(&self) -> Arc<AndroidRegistrationControl> {
        self.inner.android_registration_control.clone()
    }
    pub(crate) fn bind_original_android_document(&self, identity: &Arc<()>) {
        if self.inner.domain != SavedCommandDomain::AndroidBuild || !self.inner.android_original_owner { return; }
        let Ok(mut original) = self.inner.android_document.lock() else { return; };
        // A dead Weak is still a tombstone. No second document can rebind the
        // original owner, including through a cloned facade or RuntimeConfig.
        if original.is_none() { *original = Some(Arc::downgrade(identity)); }
    }
    pub(crate) fn android_original_document_matches(&self, identity: &Arc<()>) -> bool {
        self.inner.android_original_document_matches(Some(identity))
    }
    pub(crate) fn android_normal_selected(&self, identity: &Arc<()>) -> bool {
        let r = self.inner.lock();
        !r.disabled && !r.exhausted && !r.stopping && !r.document_lost && !self.inner.poisoned.load(Ordering::SeqCst)
            && !r.android_catalog.unknown() && !r.android_sources.unknown() && !r.android_registration.unknown()
            && !r.android_sources.busy() && !r.android_registration.busy()
            && self.inner.android_installed_selected(Some(identity),r.android_catalog.selection())
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
    pub(crate) fn prepare_ios(&self, input: ios_wire::Prepare, registration: u32, project: RegisteredRoot,
        gate: ios_wire::Availability) -> Result<ios_wire::Status, BridgeError> {
        self.prepare_ios_material(input, registration, project, gate, None)
    }
    pub(crate) fn prepare_ios_material(&self, input: ios_wire::Prepare, registration: u32, project: RegisteredRoot,
        gate: ios_wire::Availability, material: Option<Arc<IOSSigningMaterial>>) -> Result<ios_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        self.prepare_bound(Context::IOSArchive(input.context()), registration, project, Availability::from_ios(gate), material)?.ios()
    }
    pub(crate) fn prepared_ios_material(&self, operation: &str, generation: &str) -> Result<Option<Arc<IOSSigningMaterial>>, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        self.inner.lock().prepared.as_ref().filter(|p| p.projection.operation_id == operation && p.projection.owner_generation == generation)
            .map(|p| p.material.clone()).ok_or_else(|| self.inner.domain.invalid_owner())
    }
    pub(crate) fn start_android(&self, input: android_wire::Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>,
        gate: android_wire::Availability) -> Result<crate::android_build_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        let admitted = self.start(Start { operation_id: input.operation_id, owner_generation: input.owner_generation },
            admitted_at, registered, Availability::from_android(gate))?;
        Ok(crate::android_build_owner::Admitted::new(admitted.status.android()?, admitted.release))
    }
    pub(crate) fn start_ios(&self, input: ios_wire::Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>,
        gate: ios_wire::Availability) -> Result<crate::ios_archive_owner::Admitted, BridgeError> {
        self.start_ios_material(input, admitted_at, registered, gate, None)
    }
    pub(crate) fn start_ios_material(&self, input: ios_wire::Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>,
        gate: ios_wire::Availability, material: Option<Arc<IOSSigningMaterial>>) -> Result<crate::ios_archive_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        {
            let registry = self.inner.lock();
            let prepared = registry.prepared.as_ref().filter(|p| p.projection.operation_id == input.operation_id
                && p.projection.owner_generation == input.owner_generation).ok_or_else(|| self.inner.domain.invalid_owner())?;
            if !matches!(&prepared.projection.context, Context::IOSArchive(context) if input.consent_matches(context)) {
                return Err(self.inner.domain.invalid_owner());
            }
        }
        let admitted = self.start_bound(Start { operation_id: input.operation_id, owner_generation: input.owner_generation },
            admitted_at, registered, Availability::from_ios(gate), material)?;
        Ok(crate::ios_archive_owner::Admitted::new(admitted.status.ios()?, admitted.release))
    }
    pub(crate) fn status_android(&self, gate: android_wire::Availability) -> Result<android_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        self.status(Availability::from_android(gate))?.android()
    }
    pub(crate) fn status_ios(&self, gate: ios_wire::Availability) -> Result<ios_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        self.status(Availability::from_ios(gate))?.ios()
    }
    pub(crate) fn cancel_android(&self, operation: &str, generation: &str, gate: android_wire::Availability) -> Result<android_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::AndroidBuild)?;
        self.cancel(operation, generation, Availability::from_android(gate))?.android()
    }
    pub(crate) fn prepare_recovery(&self, input: recovery_wire::Prepare, registration: u32, project: RegisteredRoot,
        gate: recovery_wire::Availability) -> Result<recovery_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::ProjectRecovery)?;
        self.prepare(Context::ProjectRecovery(input.context()), registration, project, Availability::from_recovery(gate))?.recovery()
    }
    pub(crate) fn start_recovery(&self, input: recovery_wire::Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>,
        gate: recovery_wire::Availability) -> Result<crate::project_recovery_owner::Admitted, BridgeError> {
        self.require_domain(SavedCommandDomain::ProjectRecovery)?;
        let admitted = self.start(Start { operation_id: input.operation_id, owner_generation: input.owner_generation },
            admitted_at, registered, Availability::from_recovery(gate))?;
        Ok(crate::project_recovery_owner::Admitted::new(admitted.status.recovery()?, admitted.release))
    }
    pub(crate) fn status_recovery(&self, gate: recovery_wire::Availability) -> Result<recovery_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::ProjectRecovery)?;
        self.status(Availability::from_recovery(gate))?.recovery()
    }
    pub(crate) fn cancel_recovery(&self, operation: &str, generation: &str, gate: recovery_wire::Availability) -> Result<recovery_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::ProjectRecovery)?;
        self.cancel(operation, generation, Availability::from_recovery(gate))?.recovery()
    }
    pub(crate) fn cancel_ios(&self, operation: &str, generation: &str, gate: ios_wire::Availability) -> Result<ios_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::IOSArchive)?;
        self.cancel(operation, generation, Availability::from_ios(gate))?.ios()
    }
}

impl SavedCommandOwner {
    fn new(runtime: RuntimeConfig, domain: SavedCommandDomain) -> Self { Self::new_selected(runtime, domain, None) }
    fn new_selected(runtime: RuntimeConfig, domain: SavedCommandDomain, toolchain: Option<AndroidToolchainProfile>) -> Self {
        let android_original_owner = domain == SavedCommandDomain::AndroidBuild && runtime.claim_original_android_owner();
        let (changes, _) = watch::channel(0);
        Self { inner: Arc::new(Inner {
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            observation: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
            observation_identity: Arc::new(()),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
            recovery_observation: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
            ios_observation: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
            ios_observation_identity: Arc::new(()),
            android_original_owner, android_document: Mutex::new(None),
            android_registration_control: Arc::new(android_registration::ControlSlot::default()),
            #[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
            android_service_dispatcher:std::sync::OnceLock::new(),
            domain, runtime, toolchain, registry: Mutex::new(Registry { revision: 0, exhausted: false,
            disabled: false, stopping: false, document_lost: false, capability: Availability::RuntimeUnqualified,
            prepared: None, active: None, last: None, recovery_review: None, recovery: None, android_catalog: android_catalog::Catalog::default(), android_sources: android_sources::Sources::default(),
            android_registration: android_registration::Registration::default() }), changes, changed: Notify::new(), poisoned: AtomicBool::new(false),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: Mutex::new(None),
        }) }
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<u32> { self.inner.changes.subscribe() }
    pub(crate) fn stopping(&self) -> bool { self.inner.lock().stopping }
    pub(crate) fn disabled(&self) -> bool { let r = self.inner.lock(); r.disabled || r.exhausted
        || r.android_catalog.unknown() || r.android_sources.unknown() || r.android_registration.unknown()
        || self.inner.android_registration_control.is_unknown() || self.inner.poisoned.load(Ordering::SeqCst) }
    pub(crate) fn can_exit(&self) -> bool { self.reconcile(); let r = self.inner.lock();
        !self.inner.poisoned.load(Ordering::SeqCst) && r.active.is_none() && r.prepared.is_none()
            && !r.android_catalog.busy() && !r.android_sources.busy()
            && !r.android_registration.busy() && !r.android_registration.unknown()
            && self.inner.android_registration_control.can_exit() }
    pub(crate) fn busy(&self) -> bool {
        self.reconcile(); let r = self.inner.lock();
        self.inner.poisoned.load(Ordering::SeqCst) || r.active.is_some() || r.prepared.is_some()
            || r.android_catalog.busy() || r.android_sources.busy() || r.android_registration.busy()
            || r.android_registration.unknown() || self.inner.android_registration_control.owns_work()
    }
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
        self.prepare_bound(context, registration, project, gate, None)
    }
    fn prepare_bound(&self, mut context: Context, registration: u32, project: RegisteredRoot, gate: Availability,
        material: Option<Arc<IOSSigningMaterial>>) -> Result<Status, BridgeError> {
        let prepared_at = Instant::now(); // Before this intent's entropy; never renewed by polling.
        if context.domain() != self.inner.domain { return Err(self.inner.domain.invalid_owner()); }
        if !self.inner.ios_mode_qualified(&context, None) {
            return Err(prepare_refusal(self.inner.domain, Availability::RuntimeUnqualified));
        }
        if context.signed_ios() != material.is_some() || material.as_ref().is_some_and(|original|
            !matches!(&context, Context::IOSArchive(c) if original.matches(c, registration, &project))) {
            return Err(self.inner.domain.invalid_owner());
        }
        self.reconcile(); let mut r = self.inner.lock();
        let reason = self.inner.availability(&r, gate);
        if reason != Availability::Available { return Err(prepare_refusal(self.inner.domain, reason)); }
        let recovery = match &context {
            Context::IOSArchive(c) if c.recovery() && c.recovery.as_ref().is_some_and(|r| r.action != ios_wire::RecoveryAction::Inspect) => {
                Some(r.recovery.as_ref().filter(|o| o.matches(&context, registration, &project)).cloned().ok_or_else(||
                    BridgeError::new("ios_archive_unavailable", "Inspect current local recovery state in this project before reviewing its exact session."))?)
            },
            _ => None,
        };
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(observation) = self.inner.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?.as_ref() {
            observation.control.claim(match self.inner.domain {
                SavedCommandDomain::OfflinePreflight => crate::shell::installed_observation::commands::Domain::Offline,
                SavedCommandDomain::AndroidBuild => crate::shell::installed_observation::commands::Domain::Android,
                SavedCommandDomain::ProjectRecovery | SavedCommandDomain::IOSArchive => return Err(self.inner.domain.unavailable()),
            })?;
        }
        let mut recovery_stamp = None;
        let mut expires = prepared_at + INTENT;
        if let Context::ProjectRecovery(selected) = &mut context {
            if selected.action == recovery_wire::Action::Recover {
                let reviewed = r.recovery_review.as_ref().filter(|reviewed|
                    reviewed.registration == registration && reviewed.project == project && prepared_at < reviewed.expires
                    && reviewed.context.project_id == selected.project_id && reviewed.context.draft_revision == selected.draft_revision
                    && reviewed.context.baseline_generation == selected.baseline_generation && reviewed.observation.eligible())
                    .ok_or_else(|| self.inner.domain.invalid_owner())?;
                selected.review = Some(reviewed.observation.clone());
                recovery_stamp = Some(reviewed.stamp.clone()); expires = expires.min(reviewed.expires);
            }
            if !selected.valid() { return Err(self.inner.domain.invalid_owner()); }
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
        recovery_observation::prepare(&self.inner, &r, &context)?;
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        if let Some(observation) = self.inner.ios_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?.as_ref() {
            if self.inner.domain != SavedCommandDomain::IOSArchive || observation.original.is_some()
                || !matches!(&context, Context::IOSArchive(selected) if observation.control.permits_mode(selected.operation)) {
                return Err(self.inner.domain.unavailable());
            }
            observation.control.claim()?;
        }
        let id = nonce(self.inner.domain)?; let generation = nonce(self.inner.domain)?;
        if r.last.as_ref().is_some_and(|last| last.operation_id == id || last.owner_generation == generation) { return Err(self.inner.domain.unavailable()); }
        let projection = RunProjection { operation_id: id, owner_generation: generation, context,
            phase: Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: Reason::None, result: None, stage: None };
        if self.inner.domain == SavedCommandDomain::ProjectRecovery { r.recovery_review = None; }
        let android_selection = r.android_catalog.selection().cloned();
        r.prepared = Some(Prepared { projection, expires, registration, project, recovery_stamp, material, recovery, android_selection });
        self.inner.bump(&mut r);
        // After commit, only typed status or unknown/lost reply, never the three
        // fixed preallocation refusal codes used by the renderer controller.
        self.inner.snapshot_locked(&mut r, gate)
    }
    /// T is captured synchronously at DocumentBinding Start entry, before any
    /// await/entropy/runtime/acquisition. Consume matching consent FIRST.
    fn start(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability) -> Result<Admitted, BridgeError> {
        self.start_bound(input, admitted_at, registered, gate, None)
    }
    fn start_bound(&self, input: Start, admitted_at: Instant, registered: Option<(u32, RegisteredRoot)>, gate: Availability,
        material: Option<Arc<IOSSigningMaterial>>) -> Result<Admitted, BridgeError> {
        let mut r = self.inner.lock();
        if !r.prepared.as_ref().is_some_and(|p| p.projection.operation_id == input.operation_id && p.projection.owner_generation == input.owner_generation) {
            return Err(self.inner.domain.invalid_owner()); // Foreign/replayed Start never stops another owner.
        }
        let prepared = r.prepared.take().ok_or_else(|| self.inner.domain.invalid_owner())?; // One use, before executor/runtime/effects.
        let clocks = if prepared.projection.context.signed_ios() || prepared.projection.context.recovery_ios() {
            Clocks::for_context(&prepared.projection.context, admitted_at)
        } else { self.inner.start_clocks(admitted_at) };
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        let clocks = if prepared.projection.context.signed_ios()
            && self.inner.ios_observation.lock().is_ok_and(|book| book.as_ref().is_some_and(|o|
                o.original.is_none() && o.control.permits_mode(ios_wire::Operation::IOSSignedExport))) {
            Clocks::installed_ios_signed(admitted_at)
        } else { clocks };
        let material_matches = match (&prepared.material, &material) {
            (None, None) => !prepared.projection.context.signed_ios(),
            (Some(original), Some(current)) => Arc::ptr_eq(original, current) && matches!(&prepared.projection.context,
                Context::IOSArchive(context) if context.signed() && original.matches(context, prepared.registration, &prepared.project)),
            _ => false,
        };
        let recovery_matches = match (&prepared.projection.context, &prepared.recovery) {
            (Context::IOSArchive(c), Some(original)) if c.recovery() => r.recovery.as_ref().is_some_and(|current|
                Arc::ptr_eq(original, current) && original.matches(&prepared.projection.context, prepared.registration, &prepared.project)),
            (Context::IOSArchive(c), None) if c.recovery() => c.recovery.as_ref().is_some_and(|r| r.action == ios_wire::RecoveryAction::Inspect),
            (_, None) => true,
            _ => false,
        };
        // Starting any new work consumes the former inspected observation.
        // It cannot license a second recovery after even a known refusal.
        r.recovery = None;
        let mut refused = if Instant::now() >= prepared.expires { Some(Reason::IntentExpired) }
            else if !material_matches || !recovery_matches || !r.android_catalog.selection_matches(prepared.android_selection.as_ref(),&self.inner) || registered.as_ref().is_none_or(|(generation, project)| *generation != prepared.registration || project != &prepared.project) { Some(Reason::StaleIntent) }
            else if !self.inner.ios_mode_qualified(&prepared.projection.context, None) { Some(Reason::RuntimeUnavailable) }
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
        let (native_audit_cutoff, audit_cutoff) = watch::channel(clocks.audit_end(None));
        let (native_cleanup_cutoff, cleanup_cutoff) = watch::channel(clocks.cleanup_end(None));
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let _ = cleanup_cutoff;
        let (frames, receiver) = mpsc::channel(2);
        let context = prepared.projection.context;
        let projection = RunProjection { operation_id: input.operation_id.clone(), owner_generation: input.owner_generation.clone(),
            context: context.clone(), phase: Phase::Starting, intent_usable: false, outcome: None, reason: Reason::None, result: None, stage: None };
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        let android_native=if self.inner.domain==SavedCommandDomain::AndroidBuild{
            prepared.android_selection.as_ref().map(|selected|AndroidNativeBooks::new(
                selected.data().clone(),audit_cutoff.clone(),cleanup_cutoff.clone(),clocks))
        }else{None};
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        let android_control=android_native.as_ref().map(|native|native.control.clone());
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if self.inner.domain==SavedCommandDomain::AndroidBuild
            && android_native.as_ref().is_none_or(|native|!native.reserved_before_go()){
            return Err(self.inner.domain.unavailable());
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        let android_close=android_control.as_ref().map(|control|AndroidCloseSlot::reserved(executor.clone(),control.clone()));
        let owner = Arc::new(Session { domain: self.inner.domain, id: input.operation_id, generation: input.owner_generation, context, profile, clocks,
            registration: prepared.registration, project: prepared.project, recovery_stamp: prepared.recovery_stamp, request: AsyncMutex::new(None), stop, pipes, frames, wake: Notify::new(), native_audit_cutoff, native_cleanup_cutoff,
            material: Mutex::new(prepared.material), material_retired: AtomicBool::new(!clocks.signed),
            recovery: prepared.recovery, android_selection: prepared.android_selection.clone(), native_failure: Mutex::new(None),
            #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
            android_control,
            #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
            android_close,
            output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false), driver_done: AtomicBool::new(false),
            driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false), watchdog_joined: AtomicBool::new(false),
            watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false), startup: Mutex::new(Startup::default()),
            resources: AsyncMutex::new(Resources { frames: Some(receiver),
                offline_selected: self.inner.offline_installed_selected(),
                recovery_selected: self.inner.recovery_installed_selected(),
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                recovery_installed: self.inner.recovery_installed_selected().then(|| Arc::new(Mutex::new(ProjectRecoveryRuntimeSlots::new()))),
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                offline_installed: self.inner.offline_installed_selected().then(|| Arc::new(Mutex::new(OfflinePreflightRuntimeSlots::new()))),
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                native: if self.inner.domain == SavedCommandDomain::AndroidBuild {
                    self.inner.toolchain.clone().map(|profile| Arc::new(Mutex::new(AndroidNativeBooks::new(profile, audit_cutoff))))
                } else { None },
                #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
                android_observations: android_native.as_ref().map(|_|AndroidObservationSlot::default()),
                #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
                native: android_native.map(|native|Arc::new(Mutex::new(native))),
                #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "macos-android-registration-helper"))]
                native: None,
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                ios_native: (self.inner.domain == SavedCommandDomain::IOSArchive)
                    .then(|| Arc::new(Mutex::new(IOSNativeBooks::new_selected(audit_cutoff, clocks.signed, clocks.recovery)))),
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
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        if let Some(observation) = self.inner.ios_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?.as_mut() {
            if self.inner.domain != SavedCommandDomain::IOSArchive || observation.original.is_some()
                || !matches!(&owner.context, Context::IOSArchive(selected) if observation.control.permits_mode(selected.operation)) {
                return Err(self.inner.domain.unavailable());
            }
            observation.original = Some(owner.clone());
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
        recovery_observation::bind(&self.inner, &owner)?;
        let (release, enter) = oneshot::channel();
        // Every new roster slot precedes publication/spawn. No hosted-fixture
        // alternate bootstrap, other-owner permission or caller-owned runner.
        let mut book = owner.resources.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut driver = owner.driver.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut watchdog_slot = owner.watchdog.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut manager = owner.manager.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let mut observer = owner.observer.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        r.active = Some(Active { owner: owner.clone(), projection, first_stop: None, work_expired: false, context_invalidated: false,
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
    fn lifecycle_publisher(&self, reason: crate::android_registration_app_protocol::Reason)
        -> Option<android_registration::Publisher> {
        let mut publisher = self.inner.android_registration_control.reserve(android_registration::PublisherKind::General, true).ok()?;
        publisher.accept(reason).ok()?;
        Some(publisher)
    }
    fn lifecycle_time(&self, publisher: Option<&android_registration::Publisher>) -> Instant {
        if let Some(publisher) = publisher.filter(|publisher|
            publisher.accepted() && publisher.same_slot(&self.inner.android_registration_control)) { return publisher.at(); }
        // An impossible/missing outer publication is not a fresh known F. Keep
        // the SAME book Unknown; remaining projections only revoke authority.
        self.inner.android_registration_control.poisoned();
        Instant::now()
    }
    pub(crate) fn document_lost(&self) {
        let publisher = self.lifecycle_publisher(crate::android_registration_app_protocol::Reason::DocumentLost);
        self.document_lost_published(publisher.as_ref());
        if let Some(publisher) = publisher { publisher.finish(); }
    }
    pub(crate) fn document_lost_published(&self, publisher: Option<&android_registration::Publisher>) {
        let at = self.lifecycle_time(publisher);
        let mut r = self.inner.lock(); if r.document_lost { return; } r.document_lost = true; r.recovery_review = None;
        r.android_catalog.stop(crate::android_toolchain_catalog::Reason::DocumentLost,at);
        r.android_sources.stop(crate::android_tool_sources::Reason::DocumentLost,at);
        r.android_registration.stop(crate::android_registration_app_protocol::Reason::DocumentLost,at);
        r.recovery = None;
        if let Some(a) = r.active.as_mut() { a.context_invalidated = true; }
        self.inner.retire_prepared(&mut r, Reason::DocumentLost);
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::DocumentLost, at); }
        self.inner.bump(&mut r);
    }
    pub(crate) fn context_changed(&self) {
        let publisher = self.lifecycle_publisher(crate::android_registration_app_protocol::Reason::ContextChanged);
        self.context_changed_published(publisher.as_ref());
        if let Some(publisher) = publisher { publisher.finish(); }
    }
    pub(crate) fn context_changed_published(&self, publisher: Option<&android_registration::Publisher>) {
        let at = self.lifecycle_time(publisher);
        let mut r = self.inner.lock(); r.recovery_review = None; self.inner.retire_prepared(&mut r, Reason::ContextChanged);
        if r.android_catalog.stop(crate::android_toolchain_catalog::Reason::CatalogChanged,at)
            | r.android_sources.stop(crate::android_tool_sources::Reason::ContextChanged,at)
            | r.android_registration.stop(crate::android_registration_app_protocol::Reason::ContextChanged,at){self.inner.bump(&mut r);}
        r.recovery = None;
        if let Some(a) = r.active.as_mut() { a.context_invalidated = true; }
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::ContextChanged, at); }
    }
    pub(crate) fn registration_matches(&self, registration: u32) -> bool {
        let r = self.inner.lock(); r.active.as_ref().is_none_or(|a| a.owner.registration == registration)
            && r.prepared.as_ref().is_none_or(|p| p.registration == registration)
            && r.recovery_review.as_ref().is_none_or(|reviewed| reviewed.registration == registration)
            && r.recovery.as_ref().is_none_or(|o| o.original.registration == registration)
            && r.android_sources.registration_matches(registration)
            && r.android_registration.registration_matches(registration)
    }
    pub(crate) fn request_shutdown(&self) {
        let publisher = self.lifecycle_publisher(crate::android_registration_app_protocol::Reason::Shutdown);
        self.request_shutdown_published(publisher.as_ref());
        if let Some(publisher) = publisher { publisher.finish(); }
    }
    pub(crate) fn request_shutdown_published(&self, publisher: Option<&android_registration::Publisher>) {
        let at = self.lifecycle_time(publisher);
        let mut r = self.inner.lock(); r.stopping = true; r.recovery_review = None; self.inner.retire_prepared(&mut r, Reason::Shutdown);
        r.android_catalog.stop(crate::android_toolchain_catalog::Reason::Shutdown,at);
        r.android_sources.stop(crate::android_tool_sources::Reason::Shutdown,at);
        r.android_registration.stop(crate::android_registration_app_protocol::Reason::Shutdown,at);
        r.recovery = None;
        if let Some(a) = r.active.as_mut() { a.context_invalidated = true; }
        if let Some(owner) = r.active.as_ref().map(|a| a.owner.clone()) { self.inner.stop_locked(&mut r, &owner, Reason::Shutdown, at); }
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
        let owner = {
            let mut r = self.inner.lock(); self.inner.expire_prepared(&mut r, Instant::now());
            let mut changed=r.android_catalog.reconcile(&self.inner);
            let at=Instant::now();
            if !r.android_registration.sources_match(&r.android_sources) {
                // Real accepted source/lifecycle entry already fenced the
                // original BEFORE projection. Missing that F is a broken
                // publisher census, not permission to invent a late F here.
                if let Some((reason, first)) = r.android_registration.invalidation_failure() {
                    changed |= r.android_registration.stop(reason, first);
                } else {
                    self.inner.android_registration_control.poisoned();
                    self.inner.poisoned.store(true, Ordering::SeqCst);
                    changed |= r.android_registration.exhaust(at);
                }
            }
            if (r.disabled || r.exhausted || r.android_catalog.unknown() || r.android_sources.unknown()
                || self.inner.poisoned.load(Ordering::SeqCst)) && !r.android_registration.unknown(){
                changed|=r.android_registration.exhaust(at);
            }
            changed|=r.android_registration.reconcile(&self.inner);
            let newly_unknown=(r.android_catalog.unknown() || r.android_sources.unknown()
                || r.android_registration.unknown()) && !r.disabled;
            if newly_unknown{r.disabled=true;}
            if changed||newly_unknown{self.inner.bump(&mut r);}
            r.active.as_ref().map(|a| a.owner.clone())
        };
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
            // The private loan stays on the SAME Session until the actual
            // final Ready result is recorded and the original hard clock is
            // clear. Unknown/lost joins retain it; Drop is not settlement.
            if let Ok(mut material) = owner.material.lock() {
                if owner.clocks.signed != material.is_some() || owner.material_retired.load(Ordering::SeqCst) == owner.clocks.signed {
                    owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown_locked(&mut r, &owner); return;
                }
                material.take();
                owner.material_retired.store(true, Ordering::SeqCst);
            } else {
                owner.resource_unknown.store(true, Ordering::SeqCst); self.inner.unknown_locked(&mut r, &owner); return;
            }
            watchdog_slot.take();
            if let Some(mut active) = r.active.take() {
                if !Arc::ptr_eq(&active.owner, &owner) { r.active = Some(active); return; }
                active.projection.phase = if active.unknown { Phase::Unknown } else { Phase::Terminal };
                if active.projection.outcome.is_none() { set_failure_outcome(&mut active.projection); }
                if !active.unknown && !active.context_invalidated && !r.document_lost && !r.stopping {
                    if let Some(Terminal::IOSArchive(t)) = &active.projection.result {
                        if t.context.recovery.as_ref().is_some_and(|r| r.action == ios_wire::RecoveryAction::Inspect)
                            && t.settled() && t.report.is_some() && t.lifetime.stop_observed == ios_wire::CoreStop::None
                            && matches!(active.projection.reason, Reason::None | Reason::RecoveryAttention) {
                            r.recovery = Some(Arc::new(IOSRecoveryObservation { original: owner.clone(), terminal: t.clone() }));
                        }
                    }
                }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Ok(mut observation) = self.inner.observation.lock() {
                    if let Some(observation) = observation.as_mut().filter(|o| o.original.as_ref().is_some_and(|s| Arc::ptr_eq(s, &owner))) {
                        observation.retired = true;
                        observation.core_settled = active.accepted && active.terminal && active.projection.result.as_ref().is_some_and(Terminal::settled);
                        observation.android_lifetime = match active.projection.result.as_ref() {
                            Some(Terminal::AndroidBuild(t)) => Some(t.lifetime.clone()), _ => None,
                        };
                    }
                }
                if owner.domain == SavedCommandDomain::ProjectRecovery {
                    r.recovery_review = recovery_review_after_finality(&active, &owner, Instant::now());
                }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
                recovery_observation::retire(&self.inner, &active, &owner, r.recovery_review.is_some());
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
                if let Ok(mut observation) = self.inner.ios_observation.lock() {
                    if let Some(observation) = observation.as_mut().filter(|o| o.original.as_ref().is_some_and(|s| Arc::ptr_eq(s, &owner))) {
                        // Preserve actual core DATA before public() deliberately
                        // strips a result which cannot be exposed as success.
                        observation.retired = true;
                        observation.core_settled = active.accepted && active.terminal && active.projection.result.as_ref().is_some_and(Terminal::settled);
                        observation.terminal = match active.projection.result.as_ref() {
                            Some(Terminal::IOSArchive(terminal)) => Some(terminal.clone()), _ => None,
                        };
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
fn recovery_review_after_finality(active: &Active, owner: &Session, now: Instant) -> Option<RecoveryReview> {
    let Context::ProjectRecovery(context) = &owner.context else { return None; };
    let Terminal::ProjectRecovery(terminal) = active.projection.result.as_ref()? else { return None; };
    let expires = owner.clocks.admitted + INTENT;
    if active.projection.phase != Phase::Terminal || active.projection.outcome != Some(Outcome::Complete)
        || active.first_stop.is_some() || active.unknown || !active.final_join_seen || !active.accepted || !active.terminal
        || *owner.stop.borrow() || context.action != recovery_wire::Action::Inspect || now >= expires
        || terminal.outcome != recovery_wire::Outcome::Complete || !terminal.settled()
        || !owner.watchdog_joined.load(Ordering::SeqCst) || owner.resource_unknown.load(Ordering::SeqCst) { return None; }
    let observation = terminal.result.as_ref()?.observation.as_ref()?.clone();
    if !observation.eligible() { return None; }
    Some(RecoveryReview { context: context.clone(), observation, stamp: terminal.review_stamp.as_ref()?.clone(),
        expires, registration: owner.registration, project: owner.project.clone() })
}
struct FinalWake(std::sync::Weak<Inner>);
impl Wake for FinalWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { if let Some(inner) = self.0.upgrade() { inner.changes.send_modify(|_| {}); inner.changed.notify_one(); } }
}
fn record_join<T>(slot: &Mutex<Option<Result<T, tokio::task::JoinError>>>, result: Result<T, tokio::task::JoinError>) -> bool {
    match slot.lock() { Ok(mut slot) if slot.is_none() => { *slot = Some(result); true }, _ => false }
}
/// Pure readiness/custody helper, not another task or a receipt factory.
/// Acquire the fixed ORIGINAL return slot before polling. A poisoned vacant
/// slot still retains the actual return plus Unknown; an occupied slot is never
/// polled again. No result may be discarded by fallible post-Ready recording.
fn poll_android_original<T>(handle:&mut Option<JoinHandle<T>>,
    returned:&Mutex<Option<Result<T,tokio::task::JoinError>>>,seen:&AtomicBool,
    context:&mut TaskContext<'_>,mut unknown:impl FnMut())->Poll<bool>{
    let (mut slot,clean)=match returned.lock(){
        Ok(slot)=>(slot,true),Err(error)=>{unknown();(error.into_inner(),false)},
    };
    if seen.load(Ordering::SeqCst) || slot.is_some(){unknown();return Poll::Ready(false);}
    let Some(handle)=handle.as_mut()else{unknown();return Poll::Ready(false);};
    let Poll::Ready(result)=Pin::new(handle).poll(context)else{return Poll::Pending;};
    let joined=result.is_ok();
    *slot=Some(result);seen.store(true,Ordering::SeqCst);
    // The guard is gone before any next wait/close/finality decision.
    drop(slot);
    if !joined || !clean{unknown();}
    Poll::Ready(joined && clean)
}

#[cfg(test)]
mod android_join_slot_data_tests {
    use super::*;
    struct NoWake;
    impl Wake for NoWake {fn wake(self:Arc<Self>){}}
    #[test]
    fn empty_or_already_seen_slots_never_synthesize_an_original_join(){
        let waker=Waker::from(Arc::new(NoWake));let mut context=TaskContext::from_waker(&waker);
        let returned=Mutex::new(None::<Result<u8,tokio::task::JoinError>>);
        let seen=AtomicBool::new(false);let unknown=AtomicBool::new(false);
        let mut handle=None::<JoinHandle<u8>>;
        assert!(matches!(poll_android_original(&mut handle,&returned,&seen,&mut context,
            ||unknown.store(true,Ordering::SeqCst)),Poll::Ready(false)));
        assert!(unknown.load(Ordering::SeqCst) && !seen.load(Ordering::SeqCst));
        assert!(returned.lock().unwrap().is_none());
        unknown.store(false,Ordering::SeqCst);seen.store(true,Ordering::SeqCst);
        assert!(matches!(poll_android_original(&mut handle,&returned,&seen,&mut context,
            ||unknown.store(true,Ordering::SeqCst)),Poll::Ready(false)));
        assert!(unknown.load(Ordering::SeqCst) && returned.lock().unwrap().is_none());
    }
    #[test]
    fn occupied_or_poisoned_data_stays_in_its_same_original_slot(){
        // Scalar DATA only: no task, file, native tail or join witness is minted.
        let waker=Waker::from(Arc::new(NoWake));let mut context=TaskContext::from_waker(&waker);
        let returned=Mutex::new(Some(Ok::<_,tokio::task::JoinError>([7u8;32])));
        let seen=AtomicBool::new(false);let unknown=AtomicBool::new(false);
        let mut handle=None::<JoinHandle<[u8;32]>>;
        assert!(matches!(poll_android_original(&mut handle,&returned,&seen,&mut context,
            ||unknown.store(true,Ordering::SeqCst)),Poll::Ready(false)));
        assert!(unknown.load(Ordering::SeqCst));
        assert!(matches!(returned.lock().unwrap().as_ref(),Some(Ok(value)) if *value==[7;32]));
        let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            let _held=returned.lock().unwrap();panic!("inert original slot poison");
        }));
        unknown.store(false,Ordering::SeqCst);
        assert!(matches!(poll_android_original(&mut handle,&returned,&seen,&mut context,
            ||unknown.store(true,Ordering::SeqCst)),Poll::Ready(false)));
        assert!(unknown.load(Ordering::SeqCst) && !seen.load(Ordering::SeqCst));
        assert!(matches!(returned.lock().unwrap_err().into_inner().as_ref(),Some(Ok(value)) if *value==[7;32]));
    }
}
fn set_failure_outcome(p: &mut RunProjection) {
    if p.reason == Reason::None {
        p.reason = match p.context.domain() { SavedCommandDomain::OfflinePreflight => Reason::CommandIncomplete,
            SavedCommandDomain::AndroidBuild | SavedCommandDomain::IOSArchive => Reason::ProtocolError, SavedCommandDomain::ProjectRecovery => Reason::RecoveryIncomplete };
    }
    // Known retained work is not successful cancellation/disposal. Keep the
    // original first reason, but preserve the core's Failed disposition outcome.
    if let Some(Terminal::AndroidBuild(t)) = &p.result {
        if t.outcome == android_wire::Outcome::Failed && t.disposition.work == android_wire::WorkDisposition::RetainedWork {
            p.outcome = Some(Outcome::Failed); return;
        }
    }
    if let Some(Terminal::IOSArchive(t)) = &p.result {
        if t.outcome == ios_wire::Outcome::Failed && t.disposition.as_ref().is_some_and(|d| d.work == ios_wire::WorkDisposition::RetainedWork) {
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
    fn recovery_installed_selected(&self) -> bool {
        self.domain == SavedCommandDomain::ProjectRecovery && cfg!(feature = "custom-protocol")
            && self.runtime.project_recovery_installed_profile_available()
    }
    fn ios_mode_qualified(&self, context: &Context, original: Option<&Session>) -> bool {
        if context.domain() != self.domain { return false; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        {
            let Ok(slot) = self.ios_observation.lock() else { return false; };
            if let Some(observation) = slot.as_ref() {
                let Context::IOSArchive(selected) = context else { return false; };
                let same_original = match (original, observation.original.as_ref()) {
                    (None, None) => true,
                    (Some(owner), Some(bound)) => std::ptr::eq(bound.as_ref(), owner),
                    _ => false,
                };
                // A different observed mode never falls through to production
                // qualification, including unsigned use of a signed Control.
                return same_original && observation.control.permits_mode(selected.operation)
                    && (selected.operation != ios_wire::Operation::IOSUnsignedArchive || self.ios_unsigned_installed_selected());
            }
        }
        let _ = original;
        (!context.signed_ios() || IOS_SIGNED_NATIVE_QUALIFIED)
            && (!context.recovery_ios() || IOS_RECOVERY_NATIVE_QUALIFIED)
            && (context.domain() != SavedCommandDomain::IOSArchive || context.signed_ios() || context.recovery_ios()
                || self.ios_unsigned_installed_selected())
    }
    fn start_clocks(&self, admitted: Instant) -> Clocks {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        if self.domain == SavedCommandDomain::IOSArchive
            && self.ios_observation.lock().is_ok_and(|book| book.as_ref().is_some_and(|o|
                o.original.is_none() && o.control.permits_mode(ios_wire::Operation::IOSUnsignedArchive))) {
            return Clocks::installed_ios(admitted);
        }
        Clocks::new(self.domain, admitted)
    }
    fn offline_installed_selected(&self) -> bool {
        self.domain == SavedCommandDomain::OfflinePreflight && cfg!(feature = "custom-protocol")
            && self.runtime.offline_preflight_installed_profile_available()
    }
    fn ios_unsigned_installed_selected(&self) -> bool {
        self.domain == SavedCommandDomain::IOSArchive && cfg!(all(feature = "desktop-shell", feature = "custom-protocol",
            not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
            not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"),
            target_os = "macos", target_arch = "aarch64"))
            && self.runtime.ios_archive_installed_profile_available()
    }
    fn android_original_document_matches(&self, identity: Option<&Arc<()>>) -> bool {
        self.domain == SavedCommandDomain::AndroidBuild && self.android_original_owner
            && self.android_document.lock().is_ok_and(|document| document.as_ref().and_then(std::sync::Weak::upgrade)
                .is_some_and(|original| identity.is_none_or(|identity| Arc::ptr_eq(&original, identity))))
    }
    fn android_runtime_selected(&self, identity: Option<&Arc<()>>) -> bool {
        self.android_original_document_matches(identity) && self.runtime.android_build_installed_runtime_available()
    }
    fn android_installed_selected(&self, identity: Option<&Arc<()>>, selected: Option<&Arc<android_catalog::Selection>>) -> bool {
        // The caller may already own Registry. The immutable selection is an
        // explicit original input, never acquired by a hidden Registry relock.
        if !self.android_runtime_selected(identity){return false;}
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {let _=selected;self.toolchain.as_ref().is_some_and(AndroidToolchainProfile::installed_candidate_matches_compiled)}
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {self.toolchain.is_none() && selected.is_some_and(|selected|selected.matches_owner(self))}
        #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),all(target_os = "macos", target_arch = "aarch64"))))]
        {let _=selected;false}
    }
    fn qualified(&self, selected: Option<&Arc<android_catalog::Selection>>) -> bool {
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer")))))]
        if recovery_observation::qualified(self) { return true; }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        if self.domain == SavedCommandDomain::IOSArchive {
            let Ok(book) = self.ios_observation.lock() else { return false; };
            if let Some(observation) = book.as_ref() {
                // Only signed/refusal and empty-recovery observations grant a
                // held mode. Unsigned uses ordinary selection; no other mode
                // or failed Control falls through to that normal availability.
                return self.runtime.ios_archive_installed_profile_available()
                    && ([ios_wire::Operation::IOSSignedExport, ios_wire::Operation::IOSLocalRecovery]
                        .into_iter().any(|operation| observation.control.permits_mode(operation))
                        || self.ios_unsigned_installed_selected()
                            && observation.control.permits_mode(ios_wire::Operation::IOSUnsignedArchive));
            }
        }
        #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
            any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
        if self.domain == SavedCommandDomain::OfflinePreflight && self.fixture.lock().ok().and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade))
            .is_some_and(|permit| permit.permits(self)) { return true; }
        match self.domain {
            SavedCommandDomain::OfflinePreflight => self.offline_installed_selected(),
            SavedCommandDomain::AndroidBuild => self.android_installed_selected(None,selected),
            SavedCommandDomain::ProjectRecovery => {
                // Ordinary exact Mac selection is separate from Android
                // catalog authority and never toggles qualification evidence.
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                { self.recovery_installed_selected() }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                { RECOVERY_NATIVE_QUALIFIED && RECOVERY_RUNTIME_QUALIFIED && self.recovery_installed_selected() }
            },
            SavedCommandDomain::IOSArchive => self.ios_unsigned_installed_selected(),
        }
    }
    fn lock(&self) -> MutexGuard<'_, Registry> {
        match self.registry.lock() { Ok(r) => r, Err(error) => { self.poisoned.store(true, Ordering::SeqCst); self.android_registration_control.poisoned(); error.into_inner() } }
    }
    fn bump(&self, r: &mut Registry) {
        if r.disabled || r.exhausted || r.android_catalog.unknown() || r.android_sources.unknown()
            || r.android_registration.unknown() || self.poisoned.load(Ordering::SeqCst) {
            self.android_registration_control.poisoned();
        }
        if r.exhausted { return; }
        match r.revision.checked_add(1).filter(|n| *n < u32::MAX) {
            Some(next) => r.revision = next,
            None => { let at=Instant::now();
                self.android_registration_control.poisoned();
                r.exhausted = true; r.disabled = true; r.android_catalog.exhaust(); r.android_sources.exhaust();
                r.android_registration.exhaust(at);
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
        if r.disabled || r.exhausted || r.android_catalog.unknown() || r.android_sources.unknown()
            || r.android_registration.unknown() || self.poisoned.load(Ordering::SeqCst) || gate == Availability::CleanupUnknown { Availability::CleanupUnknown }
        else if r.stopping || gate == Availability::Shutdown { Availability::Shutdown }
        // No original can have started on an unsupported backend. Its missing
        // editing/crash hook must not falsely lock unrelated passive services.
        // Actual retained owners and Unknown still take their original gates.
        else if r.active.is_none() && r.prepared.is_none()
            && (Profile::current(self.domain).is_none() || gate == Availability::UnsupportedPlatform) { Availability::UnsupportedPlatform }
        else if r.document_lost || gate == Availability::DocumentLost { Availability::DocumentLost }
        else if r.active.is_some() || r.prepared.is_some() || r.android_catalog.busy() || r.android_sources.busy()
            || r.android_registration.busy() || gate == Availability::Busy { Availability::Busy }
        else if !self.qualified(r.android_catalog.selection()) {
            match self.domain {
                SavedCommandDomain::OfflinePreflight | SavedCommandDomain::IOSArchive => Availability::RuntimeUnqualified,
                SavedCommandDomain::AndroidBuild if !self.android_runtime_selected(None) => Availability::RuntimeUnqualified,
                SavedCommandDomain::AndroidBuild => Availability::ToolchainUnqualified,
                SavedCommandDomain::ProjectRecovery => Availability::RuntimeUnqualified,
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
            SavedCommandDomain::ProjectRecovery => {
                let status = recovery_wire::Status { schema_version: 1, status_revision: r.revision, availability: reason.recovery()?,
                    operation: operation.map(RunProjection::recovery).transpose()? };
                crate::edit_protocol::bounded(&status, recovery_wire::STATUS_LIMIT)?; Ok(Status::ProjectRecovery(status))
            },
            SavedCommandDomain::IOSArchive => {
                let status = ios_wire::Status { schema_version: 1, status_revision: r.revision, availability: reason.ios(),
                    operation: operation.map(RunProjection::ios).transpose()? };
                ios_wire::status_bytes(&status)?; Ok(Status::IOSArchive(status))
            }
        }
    }
    fn stop_locked(&self, r: &mut Registry, owner: &Session, reason: Reason, at: Instant) {
        let Some(active) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        owner.note_android_local(at,reason==Reason::CleanupUnknown);
        let at = at.min(owner.clocks.work).max(owner.clocks.admitted); let mut changed = false;
        let earlier = active.first_stop.is_none_or(|first| at < first);
        if earlier { active.first_stop = Some(at); changed = true; }
        let cleanup = owner.cleanup_end(active.first_stop);
        owner.native_cleanup_cutoff.send_if_modified(|current| if cleanup < *current { *current = cleanup; true } else { false });
        if matches!(owner.domain, SavedCommandDomain::AndroidBuild | SavedCommandDomain::IOSArchive) {
            let end = owner.audit_end(active.first_stop);
            owner.native_audit_cutoff.send_if_modified(|current| {
                if end < *current { *current = end; true } else { false }
            });
        }
        if (earlier || active.projection.reason == Reason::None) && reason != Reason::None { active.projection.reason = reason; changed = true; }
        if !active.unknown && active.projection.phase != Phase::Stopping { active.projection.phase = Phase::Stopping; changed = true; }
        if active.projection.reason != Reason::None { set_failure_outcome(&mut active.projection); }
        let first_signal = owner.stop.send_if_modified(|stopped| { if *stopped { false } else { *stopped = true; true } });
        if changed || first_signal { owner.wake.notify_waiters(); } if changed { self.bump(r); }
    }
    fn unknown_locked(&self, r: &mut Registry, owner: &Session) {
        self.unknown_locked_at(r, owner, Instant::now());
    }
    fn unknown_locked_at(&self, r: &mut Registry, owner: &Session, at: Instant) {
        // Time-aware callers already observed this event. Do not replace its
        // timestamp with a second clock sample during the Unknown transition.
        self.stop_locked(r, owner, Reason::CleanupUnknown, at);
        if let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) {
            if !a.unknown { a.unknown = true; a.projection.phase = Phase::Unknown; r.disabled = true; self.bump(r); }
        }
    }
    fn advance_locked(&self, r: &mut Registry, owner: &Session, now: Instant) {
        if !original_session(r,owner){return;}
        let Some(a) = r.active.as_ref().filter(|a| a.owner.id == owner.id) else { return; };
        if now >= owner.clocks.work && !a.work_expired {
            if let Some(a) = r.active.as_mut() { a.work_expired = true; }
            self.stop_locked(r, owner, Reason::TimedOut, owner.clocks.work);
        }
        // A native return after work cannot displace the earlier work deadline;
        // an actual F before work still shortens it and selects the first reason.
        let native_failure=match owner.native_failure.lock(){
            Ok(first)=>*first,Err(_)=>{owner.resource_unknown.store(true,Ordering::SeqCst);None},
        };
        if let Some((reason,at))=native_failure {self.stop_locked(r,owner,reason,at);}
        owner.sample_android_control();
        if owner.android_control_stopped() {
            // Control may carry a conservatively inverse-mapped pre-T F.
            // It tightens every endpoint, but never feeds the local event
            // latch or replaces the reason of an earlier genuine local event.
            let mut changed=false;
            if let Some(active)=r.active.as_mut().filter(|a|a.owner.id==owner.id) {
                if active.projection.reason==Reason::None {
                    active.projection.reason=Reason::ToolchainUnavailable;set_failure_outcome(&mut active.projection);changed=true;
                }
                if !active.unknown && active.projection.phase!=Phase::Stopping {active.projection.phase=Phase::Stopping;changed=true;}
            }
            if changed{self.bump(r);}
        }
        let finality_due = r.active.as_ref().is_some_and(|a| !a.unknown && now >= owner.finality_end(a.first_stop));
        if finality_due || self.poisoned.load(Ordering::SeqCst) || owner.resource_unknown.load(Ordering::SeqCst) { self.unknown_locked_at(r, owner, now); }
    }
    fn stop(&self, owner: &Session, reason: Reason) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.stop_locked(&mut r, owner, reason, Instant::now()); }
    fn unknown(&self, owner: &Session) { let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now()); self.unknown_locked(&mut r, owner); }
    fn endpoint(&self, owner: &Session) -> Option<Instant> {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, Instant::now());
        let a = r.active.as_ref().filter(|a| a.owner.id == owner.id)?;
        if a.unknown {None} else if a.first_stop.is_some() || owner.android_control_stopped() {
            Some(owner.finality_end(a.first_stop))
        } else {Some(owner.clocks.work.min(owner.finality_end(None)))}
    }
    fn accept(&self, owner: &Session, frame: Frame) { self.accept_at(owner, frame, Instant::now()); }
    fn accept_at(&self, owner: &Session, frame: Frame, now: Instant) {
        let mut r = self.lock(); self.advance_locked(&mut r, owner, now);
        if owner.domain != self.domain || owner.context.domain() != owner.domain {
            owner.resource_unknown.store(true, Ordering::SeqCst);
            self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked_at(&mut r, owner, now); return;
        }
        // Only these two typed streams exist; crossing domains is a protocol
        // failure, never a reinterpretation of an Offline terminal as Android.
        enum Incoming { Accepted(Option<Stage>), Progress(Stage), Terminal(Terminal) }
        let incoming = match (owner.domain, frame) {
            (SavedCommandDomain::OfflinePreflight, Frame::OfflinePreflight(wire::Frame::Accepted)) => Incoming::Accepted(None),
            (SavedCommandDomain::OfflinePreflight, Frame::OfflinePreflight(wire::Frame::Terminal(t))) => Incoming::Terminal(Terminal::OfflinePreflight(t)),
            (SavedCommandDomain::AndroidBuild, Frame::AndroidBuild(android_wire::Frame::Accepted)) => Incoming::Accepted(Some(Stage::AndroidBuild(android_wire::Stage::Accepted))),
            (SavedCommandDomain::AndroidBuild, Frame::AndroidBuild(android_wire::Frame::Progress(stage))) => Incoming::Progress(Stage::AndroidBuild(stage)),
            (SavedCommandDomain::AndroidBuild, Frame::AndroidBuild(android_wire::Frame::Terminal(t))) => Incoming::Terminal(Terminal::AndroidBuild(t)),
            (SavedCommandDomain::ProjectRecovery, Frame::ProjectRecovery(recovery_wire::Frame::Accepted)) => Incoming::Accepted(None),
            (SavedCommandDomain::ProjectRecovery, Frame::ProjectRecovery(recovery_wire::Frame::Terminal(t))) => Incoming::Terminal(Terminal::ProjectRecovery(t)),
            (SavedCommandDomain::IOSArchive, Frame::IOSArchive(ios_wire::Frame::Accepted)) => Incoming::Accepted(Some(Stage::IOSArchive(ios_wire::Stage::Accepted))),
            (SavedCommandDomain::IOSArchive, Frame::IOSArchive(ios_wire::Frame::Progress(stage))) => Incoming::Progress(Stage::IOSArchive(stage)),
            (SavedCommandDomain::IOSArchive, Frame::IOSArchive(ios_wire::Frame::Terminal(t))) => Incoming::Terminal(Terminal::IOSArchive(t)),
            _ => {
                owner.resource_unknown.store(true, Ordering::SeqCst);
                self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked_at(&mut r, owner, now); return;
            }
        };
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        let mut signed_inputs_bound = false;
        let Some(a) = r.active.as_mut().filter(|a| a.owner.id == owner.id) else { return; };
        match incoming {
            Incoming::Accepted(stage) if !a.accepted && !a.terminal => {
                a.accepted = true; a.projection.stage = stage;
                if a.first_stop.is_none() && !a.unknown { a.projection.phase = Phase::Running; } self.bump(&mut r);
            }
            Incoming::Progress(stage) if a.accepted && !a.terminal
                && a.projection.stage.is_some_and(|previous| stage.after(previous)) => {
                a.projection.stage = Some(stage); self.bump(&mut r);
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
                {
                    signed_inputs_bound = stage == Stage::IOSArchive(ios_wire::Stage::InputsBound)
                        && owner.context.signed_ios() && original_session(&r, owner);
                }
            }
            Incoming::Terminal(terminal) if a.accepted && !a.terminal => {
                let stage = match &terminal { Terminal::AndroidBuild(t) => Some(Stage::AndroidBuild(t.activity.stage)),
                    Terminal::IOSArchive(t) => Some(Stage::IOSArchive(t.activity.stage)),
                    Terminal::OfflinePreflight(_) | Terminal::ProjectRecovery(_) => None };
                if let Some(stage) = stage {
                    if a.projection.stage.is_none_or(|previous| !stage.at_or_after(previous)) {
                        owner.resource_unknown.store(true, Ordering::SeqCst);
                        self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked_at(&mut r, owner, now); return;
                    }
                    a.projection.stage = Some(stage);
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
                if !settled { owner.resource_unknown.store(true, Ordering::SeqCst); self.unknown_locked_at(&mut r, owner, now); }
            }
            _ => { owner.resource_unknown.store(true, Ordering::SeqCst); self.stop_locked(&mut r, owner, Reason::ProtocolError, now); self.unknown_locked_at(&mut r, owner, now); }
        }
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
        if signed_inputs_bound {
            // A witness callback may fail the observation. Do not keep the
            // registry (or any native/document borrow) across that callback.
            drop(r); observe_installed_ios_signed_inputs(self, owner);
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
    // Clone only the original Arc, never its private buffers. The Session keeps
    // that same loan after this writer returns until final native/core joins.
    let material = { match owner.material.lock() {
        Ok(material) => material.clone(),
        Err(_) => { failed = true; None },
    } };
    let header = material.as_ref().map(|value| value.header()).transpose();
    if owner.context.signed_ios() != material.is_some() || header.is_err()
        || material.as_ref().is_some_and(|value| !matches!(&owner.context, Context::IOSArchive(context)
            if value.matches(context, owner.registration, &owner.project))) { failed = true; }
    if !*stop.borrow() {
        match (input.io.as_mut(), request.as_ref()) {
            (Some(writer), Some(bytes)) if !failed && bytes.len() <= owner.domain.request_limit() => {
                let result = tokio::select! { biased;
                    _ = stop.changed() => None,
                    result = async {
                        writer.write_all(bytes).await?;
                        if let Some(material) = material.as_ref() {
                            let header = header.as_ref().ok().and_then(Option::as_ref)
                                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
                            let parts = material.parts().map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
                            writer.write_all(crate::asset_session::IOS_MATERIAL_PREFIX).await?;
                            writer.write_all(header).await?;
                            for (_, bytes) in parts { writer.write_all(bytes).await?; }
                            writer.write_all(crate::asset_session::IOS_MATERIAL_SUFFIX).await?;
                        }
                        Ok::<(), std::io::Error>(())
                    } => Some(result),
                };
                match result { Some(Ok(())) => sent = true, Some(Err(_)) => failed = true, None => {} }
            }
            _ => failed = true,
        }
    }
    request.take(); drop(request); // Retire only this original bounded input.
    if failed { inner.stop(&owner, Reason::ProtocolError); }
    if sent && !failed {
        // Hold this sole writer after the entire request/private phase. Closing
        // it is STOP, not ordinary framing or a renderer acknowledgment.
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
    ProjectRecovery { frames: usize, failed: bool },
    IOSArchive(ios_wire::FrameDecoder),
}
impl OutputDecoder {
    fn new(owner: &Session) -> Result<Self, BridgeError> {
        match (owner.domain, &owner.context) {
            (SavedCommandDomain::OfflinePreflight, Context::OfflinePreflight(_)) => Ok(Self::OfflinePreflight { frames: 0, failed: false }),
            (SavedCommandDomain::ProjectRecovery, Context::ProjectRecovery(_)) => Ok(Self::ProjectRecovery { frames: 0, failed: false }),
            (SavedCommandDomain::AndroidBuild, Context::AndroidBuild(context)) => {
                match owner.profile {
                    Profile::AndroidBuild(android_wire::Profile::LinuxX64) if owner.android_selection.is_none()=>
                        android_wire::FrameDecoder::new(&owner.id,&owner.generation,context).map(Self::AndroidBuild),
                    Profile::AndroidBuild(android_wire::Profile::MacArm64)=>{
                        let selected=owner.android_selection.as_ref().ok_or_else(BridgeError::protocol)?;
                        android_wire::FrameDecoder::new_macos(&owner.id,&owner.generation,context,selected.data()).map(Self::AndroidBuild)
                    },
                    _=>Err(BridgeError::protocol()),
                }
            },
            (SavedCommandDomain::IOSArchive, Context::IOSArchive(context)) =>
                ios_wire::FrameDecoder::new(&owner.id, &owner.generation, context).map(Self::IOSArchive),
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
            Self::ProjectRecovery { frames, failed } => {
                let result = match &owner.context {
                    Context::ProjectRecovery(context) if owner.domain == SavedCommandDomain::ProjectRecovery && !*failed && *frames < 2 =>
                        recovery_wire::decode(bytes, &owner.id, &owner.generation, context),
                    _ => Err(BridgeError::protocol()),
                };
                let result = result.and_then(|frame| {
                    if (*frames == 0 && matches!(&frame, recovery_wire::Frame::Accepted))
                        || (*frames == 1 && matches!(&frame, recovery_wire::Frame::Terminal(_))) { Ok(frame) }
                    else { Err(BridgeError::protocol()) }
                });
                match result {
                    Ok(frame) => { *frames += 1; Ok(Frame::ProjectRecovery(frame)) },
                    Err(error) => { *failed = true; Err(error) },
                }
            }
            Self::AndroidBuild(decoder) => decoder.push(bytes).map(Frame::AndroidBuild),
            Self::IOSArchive(decoder) => decoder.push(bytes).map(Frame::IOSArchive),
        }
    }
    fn finish(&mut self) -> bool { match self {
        Self::OfflinePreflight { frames, failed } | Self::ProjectRecovery { frames, failed } => { if *frames != 2 { *failed = true; } !*failed },
        Self::AndroidBuild(decoder) => decoder.finish().is_ok() && decoder.settled(),
        Self::IOSArchive(decoder) => decoder.finish().is_ok() && decoder.settled(),
    } }
}
async fn enqueue_frame(inner: &Inner, owner: &Session, frame: Frame) -> bool {
    match owner.domain {
        // Preserve the original two-frame Offline transport behavior exactly.
        SavedCommandDomain::OfflinePreflight | SavedCommandDomain::ProjectRecovery => owner.frames.try_send(frame).is_ok(),
        SavedCommandDomain::AndroidBuild | SavedCommandDomain::IOSArchive => {
            // A valid finite activity stream must not overflow a two-slot
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
                        let frame = if frames <= owner.context.frame_limit() {
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
        tokio::select! { result = join_slot(slot) => return result, _ = wake => {}, _ = clock_wait(end) => {},
            _ = owner.android_control_tick(), if end.is_some() => {} }
    }
}
fn offline_installed_final(book: &Resources) -> bool {
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    {
        if !book.offline_selected {
            return book.offline_installed.is_none() && !book.offline_started && !book.offline_joined && !book.offline_failed
                && book.offline_settlement.is_none() && book.offline_return.is_none();
        }
        book.offline_started && book.offline_joined && !book.offline_failed && book.offline_settlement.is_none()
            && matches!(book.offline_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && book.offline_installed.as_ref().is_some_and(|native| native.try_lock().is_ok_and(|slots| slots.settled()))
    }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    { !book.offline_selected && !book.offline_started && !book.offline_joined && !book.offline_failed }
}
fn offline_worker_returned(started: bool, joined: bool, failed: bool, handle: bool, error: bool) -> bool {
    if !started { !joined && !failed && !handle && !error }
    else if failed { !joined && handle && error }
    else { joined && !handle && !error }
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
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
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn offline_installed_claim_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    owner.domain == SavedCommandDomain::OfflinePreflight && inner.offline_installed_selected()
        && final_clock_clear(r, owner, now) && !inner.poisoned.load(Ordering::SeqCst)
        && !r.stopping && !r.document_lost && !*owner.stop.borrow() && now < owner.clocks.work
        && Profile::current(owner.domain) == Some(owner.profile)
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
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
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn acquire_offline_installed(inner: &Inner, owner: &Session, native: &Arc<Mutex<OfflinePreflightRuntimeSlots>>) {
    if owner.domain != SavedCommandDomain::OfflinePreflight || !inner.offline_installed_selected() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let mut slots = match native.lock() { Ok(slots) => slots, Err(_) => { inner.unknown(owner); return; } };
    let capability = match slots.capability() { Ok(capability) => capability, Err(_) => { inner.unknown(owner); return; } };
    let stop = owner.stop.subscribe();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let prepared = capability.prepare_once_observed(owner.clocks.work, &stop, &mut |first| owner.publish_native_failure(first));
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let prepared = capability.prepare_once(owner.clocks.work, &stop);
    let selected = match prepared {
        Ok(selected) => selected, Err(_) => { inner.stop(owner, Reason::RuntimeUnavailable); return; }
    };
    let mut command = Command::new(&selected.python);
    command.args(["-I", "-S", "-B"]).arg(&selected.bootstrap).arg(&selected.core)
        .current_dir(&selected.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if crate::runtime::macos_installed_environment(&mut command).is_err() {
        let at = Instant::now();
        owner.observe_failure_at(Reason::RuntimeUnavailable, at, false);
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
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
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    { let _ = (book, inner, owner); }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
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
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let original_owner = owner.clone();
            let (release, enter) = oneshot::channel();
            book.offline_started = true;
            book.offline_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(control) = hold { let _ = control.hold_settlement(hold_end); }
                let mut slots = match native.lock() { Ok(slots) => slots,
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots } };
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                { slots.settle_originals(&mut |first| original_owner.native_cleanup_expired(first)) }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                { slots.settle_originals() }
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

fn recovery_installed_final(book: &Resources) -> bool {
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    {
        if !book.recovery_selected {
            return book.recovery_installed.is_none() && !book.recovery_started && !book.recovery_joined && !book.recovery_failed
                && book.recovery_settlement.is_none() && book.recovery_return.is_none();
        }
        book.recovery_started && book.recovery_joined && !book.recovery_failed && book.recovery_settlement.is_none()
            && matches!(book.recovery_return.as_ref(), Some(Ok(CloseOutcome::Settled)))
            && book.recovery_installed.as_ref().is_some_and(|native| native.try_lock().is_ok_and(|slots| slots.settled()))
    }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    { !book.recovery_selected && !book.recovery_started && !book.recovery_joined && !book.recovery_failed }
}
fn recovery_worker_returned(started: bool, joined: bool, failed: bool, handle: bool, error: bool) -> bool {
    if !started { !joined && !failed && !handle && !error }
    else if failed { !joined && handle && error }
    else { joined && !handle && !error }
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn recovery_consumers_returned(book: &Resources, startup: &Startup, no_child_effect: bool) -> bool {
    if !recovery_worker_returned(book.inspection_started, book.inspection_joined, book.inspection_failed,
            book.inspection.is_some(), book.inspection_error.is_some())
        || !recovery_worker_returned(book.acquisition_started, book.acquisition_joined, book.acquisition_failed,
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
fn recovery_installed_closure_ready(r: &Registry, owner: &Session, claimed: bool, direct_returned: bool) -> bool {
    direct_returned && owner.domain == SavedCommandDomain::ProjectRecovery && original_session(r, owner)
        && (!claimed || r.active.as_ref().is_some_and(|a| a.accepted && a.terminal
            && matches!(a.projection.result.as_ref(), Some(Terminal::ProjectRecovery(t)) if t.lifetime.settled())))
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn recovery_installed_claim_clear(inner: &Inner, r: &Registry, owner: &Session, now: Instant) -> bool {
    owner.domain == SavedCommandDomain::ProjectRecovery && inner.recovery_installed_selected() && inner.qualified(owner.android_selection.as_ref())
        && final_clock_clear(r, owner, now) && !inner.poisoned.load(Ordering::SeqCst)
        && !r.stopping && !r.document_lost && !*owner.stop.borrow() && now < owner.clocks.work
        && Profile::current(owner.domain) == Some(owner.profile)
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn transfer_recovery_installed(book: &Resources, inner: &Inner, owner: &Session) -> Result<(), BridgeError> {
    if !book.recovery_selected || !book.inspection_started || !book.inspection_joined || book.inspection_failed
        || book.inspection.is_some() || book.inspection_error.is_some() || book.acquisition_started
        || book.acquisition_joined || book.acquisition_failed || book.acquisition.is_some() || book.acquisition_error.is_some() {
        return Err(BridgeError::cleanup_unknown());
    }
    let native = book.recovery_installed.as_ref().ok_or_else(BridgeError::cleanup_unknown)?;
    let mut slots = native.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !recovery_installed_claim_clear(inner, &r, owner, now) { return Err(owner.domain.unavailable()); }
    slots.transfer_once().map_err(|_| BridgeError::cleanup_unknown())
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
fn acquire_recovery_installed(inner: &Inner, owner: &Session, native: &Arc<Mutex<ProjectRecoveryRuntimeSlots>>) {
    if owner.domain != SavedCommandDomain::ProjectRecovery || !inner.recovery_installed_selected() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let mut slots = match native.lock() { Ok(slots) => slots, Err(_) => { inner.unknown(owner); return; } };
    let capability = match slots.capability() { Ok(capability) => capability, Err(_) => { inner.unknown(owner); return; } };
    let stop = owner.stop.subscribe();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let prepared = capability.prepare_once_observed(owner.clocks.work, &stop, &mut |first| owner.publish_native_failure(first));
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let prepared = capability.prepare_once(owner.clocks.work, &stop);
    let selected = match prepared {
        Ok(selected) => selected,
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Err(failure) => {
            // Keep an earlier native F, or publish this real Err before Registry.
            owner.publish_native_failure(Some((failure, Instant::now())));
            inner.stop(owner, Reason::RuntimeUnavailable); return;
        },
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        Err(_) => { inner.stop(owner, Reason::RuntimeUnavailable); return; }
    };
    let mut command = Command::new(&selected.python);
    command.args(["-I", "-S", "-B"]).arg(&selected.bootstrap).arg(&selected.core)
        .current_dir(&selected.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if crate::runtime::macos_installed_environment(&mut command).is_err() {
        owner.publish_native_failure(Some((AdmissionFailure::Native, Instant::now())));
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let mut startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
    let mut r = inner.lock(); let now = Instant::now(); inner.advance_locked(&mut r, owner, now);
    if !recovery_installed_claim_clear(inner, &r, owner, now) { return; }
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
async fn settle_recovery_installed(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    if owner.domain != SavedCommandDomain::ProjectRecovery { return; }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
    { let _ = (book, inner, owner); }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    {
        let Some(native) = book.recovery_installed.clone() else {
            if book.recovery_selected { inner.unknown(owner); }
            return;
        };
        if !book.recovery_started {
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
                recovery_installed_closure_ready(&r, owner, startup.attempted,
                    recovery_consumers_returned(book, &startup, slots.no_child_effect()))
            })();
            if !book.recovery_selected || !returned { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); return; }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let hold = recovery_observation::settlement_hold(inner, owner, book);
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            let hold_end = {
                let r = inner.lock(); owner.clocks.settlement(r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, owner)).and_then(|a| a.first_stop))
            };
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let original_owner = owner.clone();
            let (release, enter) = oneshot::channel();
            book.recovery_started = true;
            book.recovery_settlement = Some(tokio::task::spawn_blocking(move || {
                if enter.blocking_recv().is_err() { return CloseOutcome::Unknown; }
                #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if let Some(control) = hold { let _ = control.hold_settlement(hold_end); }
                let mut slots = match native.lock() { Ok(slots) => slots,
                    Err(error) => { let mut slots = error.into_inner(); slots.mark_interrupted(); slots } };
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                { slots.settle_originals(&mut |first| original_owner.native_cleanup_expired(first)) }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                { slots.settle_originals() }
            }));
            let _ = release.send(());
        }
        if !book.recovery_joined && !book.recovery_failed {
            if book.recovery_settlement.is_none() { inner.unknown(owner); return; }
            let result = join_with_clock(&mut book.recovery_settlement, inner, owner).await;
            let joined = result.is_ok();
            if book.recovery_return.is_some() { book.recovery_failed = true; }
            else { book.recovery_return = Some(result); book.recovery_joined = joined; book.recovery_failed = !joined; }
            if joined { book.recovery_settlement.take(); } else { native_worker_lost(book, owner); }
        }
        if !recovery_installed_final(book) { owner.resource_unknown.store(true, Ordering::SeqCst); inner.unknown(owner); }
    }
}

fn spawn_original(inner: &Inner, owner: &Session, runtime: VerifiedRuntime) {
    if owner.domain != SavedCommandDomain::OfflinePreflight {
        inner.stop(owner, Reason::ToolchainUnavailable); return;
    }
    // This gate remains distinct from source inspection. No packaged fallback,
    // environment-selected neutral cwd or other owner's permit is accepted.
    if inner.domain != owner.domain || !inner.qualified(owner.android_selection.as_ref()) || Profile::current(owner.domain) != Some(owner.profile) {
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
    if owner.domain != SavedCommandDomain::AndroidBuild || inner.domain != owner.domain || !inner.qualified(owner.android_selection.as_ref())
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
#[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
fn spawn_android_original(inner:&Inner,owner:&Session,runtime:VerifiedRuntime,native:Option<Arc<Mutex<AndroidNativeBooks>>>) {
    if owner.domain!=SavedCommandDomain::AndroidBuild || inner.domain!=owner.domain
        || !inner.qualified(owner.android_selection.as_ref()) || Profile::current(owner.domain)!=Some(owner.profile) {
        inner.stop(owner,Reason::ToolchainUnavailable);return;
    }
    let Some(native)=native else{inner.stop(owner,Reason::ToolchainUnavailable);return;};
    let mut native=match native.lock(){Ok(native)=>native,Err(_)=>{inner.unknown(owner);return;}};
    let mut command=Command::new(&runtime.python);
    command.args(["-I","-S","-B"]).arg(&runtime.bootstrap).arg(&runtime.core);
    command.current_dir(&runtime.cwd).env_clear().env("LANG","C").env("LC_ALL","C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    // The reviewed Mac runtime environment is fixed before native checks and
    // before the final original Start claim. Nothing executes after that claim
    // except this already-constructed command's single spawn attempt.
    if crate::runtime::macos_installed_environment(&mut command).is_err(){
        owner.observe_android_failure(AdmissionFailure::Ownership,Instant::now());return;
    }
    if native.check_before_spawn(&runtime,owner.clocks.work,&owner.stop.subscribe(),
        &mut |failure,at|owner.observe_android_failure(failure,at)).is_err(){return;}
    let mut startup=match owner.startup.lock(){Ok(startup)=>startup,Err(_)=>{inner.unknown(owner);return;}};
    let mut registry=inner.lock();inner.advance_locked(&mut registry,owner,Instant::now());
    if !original_session(&registry,owner) || registry.disabled || registry.exhausted || registry.stopping || registry.document_lost
        || !registry.android_catalog.selection_matches(owner.android_selection.as_ref(),inner)
        || *owner.stop.borrow() || Instant::now()>=owner.clocks.work || startup.attempted || startup.returned || startup.failed
        || startup.child.is_some() || native.phase!=NativePhase::Ready || native.first_failure().is_some() || native.settlement_started{return;}
    if native.claim_once().is_err(){drop(registry);inner.unknown(owner);return;}
    startup.attempted=true;
    drop(registry);
    match command.spawn(){
        Ok(child)=>{startup.child=Some(child);startup.returned=true;},
        Err(_)=>{startup.failed=true;owner.resource_unknown.store(true,Ordering::SeqCst);drop(startup);
            inner.stop(owner,Reason::RuntimeUnavailable);inner.unknown(owner);},
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn spawn_ios_original(inner: &Inner, owner: &Session, runtime: VerifiedRuntime, native: Option<Arc<Mutex<IOSNativeBooks>>>) {
    if owner.domain != SavedCommandDomain::IOSArchive || inner.domain != owner.domain || !inner.qualified(owner.android_selection.as_ref())
        || !inner.ios_mode_qualified(&owner.context, Some(owner))
        || Profile::current(owner.domain) != Some(owner.profile) { inner.stop(owner, Reason::ToolchainUnavailable); return; }
    if !owner.recovery_matches() { inner.stop(owner, Reason::StaleIntent); return; }
    let Some(native) = native else { inner.stop(owner, Reason::ToolchainUnavailable); return; };
    let mut native = match native.lock() { Ok(native) => native, Err(_) => { inner.unknown(owner); return; } };
    // Fixed reviewed bootstrap only. Xcode selection travels as owner DATA in
    // the bounded request, not ambient PATH/DEVELOPER_DIR or arbitrary argv.
    let mut command = Command::new(&runtime.python);
    command.args(["-I", "-S", "-B"]).arg(&runtime.bootstrap).arg(&runtime.core);
    command.current_dir(&runtime.cwd).env_clear().env("LANG", "C").env("LC_ALL", "C")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
    if crate::runtime::macos_installed_environment(&mut command).is_err() {
        let at = Instant::now();
        owner.observe_failure_at(Reason::ToolchainMismatch, at, false);
        inner.stop(owner, Reason::ToolchainMismatch); return;
    }
    if let Err(failure) = native.check_before_spawn(&runtime, owner.clocks.work, &owner.stop.subscribe(),
        &mut |first| owner.publish_native_failure(first)) {
        let at = Instant::now();
        owner.observe_failure_at(Reason::ToolchainMismatch, at, failure == AdmissionFailure::Unknown);
        inner.stop(owner, Reason::ToolchainMismatch); return;
    }
    let mut startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
    let mut registry = inner.lock(); inner.advance_locked(&mut registry, owner, Instant::now());
    if !original_session(&registry, owner) || registry.disabled || registry.exhausted || registry.stopping || registry.document_lost
        || *owner.stop.borrow() || Instant::now() >= owner.clocks.work || startup.attempted || startup.returned || startup.failed
        || startup.child.is_some() || native.phase != NativePhase::Ready || native.failure.is_some() || native.settlement_started { return; }
    if native.claim_once().is_err() { drop(registry); inner.unknown(owner); return; }
    startup.attempted = true;
    drop(registry);
    match command.spawn() {
        Ok(child) => { startup.child = Some(child); startup.returned = true; },
        Err(_) => { startup.failed = true; owner.resource_unknown.store(true, Ordering::SeqCst); drop(startup);
            inner.stop(owner, Reason::RuntimeUnavailable); inner.unknown(owner); },
    }
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
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
        && book.out_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.decoder_settled && (2..=owner.context.frame_limit()).contains(&e.frames))
        && book.err_end.as_ref().is_some_and(|e| e.eof && e.closed && !e.failed && e.frames == 0);
    let registry = inner.lock();
    io && original_session(&registry, owner) && registry.active.as_ref().is_some_and(|a| a.accepted && a.terminal
        && a.projection.result.as_ref().is_some_and(Terminal::settled))
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
async fn settle_native(book: &mut Resources, inner: &Arc<Inner>, owner: &Arc<Session>) {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if owner.domain==SavedCommandDomain::AndroidBuild {
        #[cfg(not(feature = "macos-android-registration-helper"))]
        android_leased::settle_start_observations(book,inner,owner).await;
        #[cfg(feature = "macos-android-registration-helper")]
        inner.unknown(owner);
        return;
    }
    if !book.native_started {
        let used = {
            let startup = match owner.startup.lock() { Ok(startup) => startup, Err(_) => { inner.unknown(owner); return; } };
            if !native_consumers_returned(book, &startup, inner, owner) { inner.unknown(owner); return; }
            startup.attempted
        };
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        let selected = (owner.domain == SavedCommandDomain::AndroidBuild).then(|| book.native.clone()).flatten();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let selected=(owner.domain==SavedCommandDomain::IOSArchive && book.native.is_none())
            .then(||book.ios_native.clone()).flatten();
        let Some(native) = selected else { inner.unknown(owner); return; };
        // Each book operation ALSO reads this same original Session cutoff, so
        // an earlier F during the audit tightens the running borrow immediately.
        let end = *owner.native_audit_cutoff.borrow();
        let (release, enter) = oneshot::channel();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let original_owner=owner.clone();
        book.native_started = true; // Pre-rostered slot claimed before worker creation/effects.
        book.native_settlement = Some(tokio::task::spawn_blocking(move || {
            if enter.blocking_recv().is_err() { return NativeSettlement { originals_closed: false, integrity: false }; }
            #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            {match native.lock() {
                Ok(mut native) => native.settle(used, end),
                Err(error) => { let mut native = error.into_inner(); native.interrupted(); native.settle(used, end) },
            }}
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {match native.lock(){
                Ok(mut native)=>native.settle(used,end,&mut |first| original_owner.native_cleanup_expired(first)),
                Err(error)=>{let mut native=error.into_inner();native.interrupted();
                    native.settle(used,end,&mut |first| original_owner.native_cleanup_expired(first))},
            }}
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
    if owner.domain == SavedCommandDomain::AndroidBuild && !inner.qualified(owner.android_selection.as_ref()) {
        inner.stop(owner, Reason::ToolchainUnavailable); return;
    }
    if owner.domain == SavedCommandDomain::IOSArchive
        && (!inner.qualified(owner.android_selection.as_ref()) || !inner.ios_mode_qualified(&owner.context, Some(owner.as_ref()))) {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let mut book = owner.resources.lock().await;
    inner.endpoint(owner);
    if *owner.stop.borrow() || Instant::now() >= owner.clocks.work { return; }
    let runtime = inner.runtime.clone(); let end = owner.clocks.work; let domain = owner.domain;
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let native = book.native.clone();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let ios_native = book.ios_native.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let offline_installed = book.offline_installed.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let recovery_installed = book.recovery_installed.clone();
    let stop = owner.stop.subscribe();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let inspection_owner=owner.clone();
    let (inspect_start, inspect_enter) = oneshot::channel();
    book.inspection_started = true;
    book.inspection = Some(tokio::task::spawn_blocking(move || {
        inspect_enter.blocking_recv().map_err(|_| {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if domain == SavedCommandDomain::OfflinePreflight {
                inspection_owner.observe_failure_at(Reason::RuntimeUnavailable, Instant::now(), false);
            }
            domain.unavailable()
        })?;
        match domain {
            SavedCommandDomain::OfflinePreflight => {
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                if let Some(native) = offline_installed {
                    let mut slots = native.lock().map_err(|_| {
                        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                        inspection_owner.publish_native_failure(Some((AdmissionFailure::Unknown, Instant::now())));
                        BridgeError::cleanup_unknown()
                    })?;
                    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                    {
                        let armed = slots.arm_acl_once(end, &stop);
                        publish_macos_returned_failure(armed.as_ref().err().copied(),
                            || slots.first_failure(), &mut |first| inspection_owner.publish_native_failure(first));
                        armed.map_err(|_| domain.unavailable())?;
                    }
                    let result = runtime.resolve_offline_preflight_installed(&mut slots, end, &stop);
                    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                    publish_macos_returned_failure(result.as_ref().err().map(|_| AdmissionFailure::Native),
                        || slots.first_failure(), &mut |first| inspection_owner.publish_native_failure(first));
                    return result;
                }
                let result = runtime.resolve_offline_preflight(end);
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                publish_macos_returned_failure(result.as_ref().err().map(|_| AdmissionFailure::Native),
                    || None, &mut |first| inspection_owner.publish_native_failure(first));
                result
            },
            SavedCommandDomain::ProjectRecovery => {
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                if let Some(native) = recovery_installed {
                    let mut slots = native.lock().map_err(|_| {
                        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                        inspection_owner.publish_native_failure(Some((AdmissionFailure::Unknown, Instant::now())));
                        BridgeError::cleanup_unknown()
                    })?;
                    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                    {
                        let armed = slots.arm_acl_once(end, &stop);
                        publish_macos_returned_failure(armed.as_ref().err().copied(),
                            || slots.first_failure(), &mut |first| inspection_owner.publish_native_failure(first));
                        armed.map_err(|_| domain.unavailable())?;
                    }
                    let result = runtime.resolve_project_recovery_installed(&mut slots, end, &stop);
                    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                    publish_macos_returned_failure(result.as_ref().err().map(|_| AdmissionFailure::Native),
                        || slots.first_failure(), &mut |first| inspection_owner.publish_native_failure(first));
                    return result;
                }
                runtime.resolve_project_recovery(end)
            },
            SavedCommandDomain::AndroidBuild => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                {
                    let native = native.ok_or_else(|| domain.unavailable())?;
                    let mut native = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    native.inspect_once(end, &stop)
                }
                #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
                {
                    let native=native.ok_or_else(||domain.unavailable())?;
                    let mut native=native.lock().map_err(|_|BridgeError::cleanup_unknown())?;
                    native.inspect_once(&runtime,end,&stop,&mut |failure,at|inspection_owner.observe_android_failure(failure,at))
                }
                #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                    all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))))]
                { let _ = stop; Err(domain.unavailable()) }
            },
            SavedCommandDomain::IOSArchive => {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                {
                    let native = ios_native.ok_or_else(|| domain.unavailable())?;
                    let mut native = native.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    native.arm_acl_once(end, &stop, &mut |first| inspection_owner.publish_native_failure(first))?;
                    native.inspect_once(&runtime, end, &stop, &mut |first| inspection_owner.publish_native_failure(first))
                }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                { let _ = stop; Err(domain.unavailable()) }
            },
        }
    }));
    let _ = inspect_start.send(()); // Original handle AND books registered before the first effect.
    let runtime = match join_with_clock(&mut book.inspection, inner, owner).await {
        Ok(result) => { book.inspection_joined = true; book.inspection.take(); match result {
            Ok(runtime) => runtime, Err(_) => { inner.stop(owner, if matches!(owner.domain, SavedCommandDomain::AndroidBuild | SavedCommandDomain::IOSArchive) {
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
        (Context::ProjectRecovery(context), Profile::ProjectRecovery(profile)) =>
            recovery_wire::request(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd, owner.recovery_stamp.as_deref()),
        (Context::AndroidBuild(context), Profile::AndroidBuild(profile)) => {
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
            {
                let binding = book.native.as_ref().and_then(|native| native.lock().ok())
                    .and_then(|native| native.request_binding(&runtime).ok());
                match binding { Some(binding) => android_wire::request(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd, &binding),
                    None => Err(owner.domain.unavailable()) }
            }
            #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))))]
            { let _ = (context, profile); Err(owner.domain.unavailable()) }
        }
        (Context::IOSArchive(context), Profile::IOSArchive(profile)) => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                let construct = || {
                    let native = book.ios_native.as_ref().ok_or_else(|| owner.domain.unavailable())?
                        .lock().map_err(|_| BridgeError::cleanup_unknown())?;
                    if native.signed != context.signed() || native.recovery != context.recovery() { return Err(owner.domain.invalid_owner()); }
                    if context.recovery() {
                        if !owner.recovery_matches() { return Err(owner.domain.invalid_owner()); }
                        let security = native.recovery_binding(&runtime).map_err(|_| owner.domain.unavailable())?;
                        return ios_wire::request_recovery(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd, &security);
                    }
                    let binding = native.request_binding(&runtime).map_err(|_| owner.domain.unavailable())?;
                    if context.signed() {
                        let tools = native.signing_binding(&runtime).map_err(|_| owner.domain.unavailable())?;
                        let material = owner.material.lock().map_err(|_| BridgeError::cleanup_unknown())?;
                        let original = material.as_ref().filter(|value| value.matches(context, owner.registration, &owner.project))
                            .ok_or_else(|| owner.domain.invalid_owner())?;
                        ios_wire::request_signed(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd,
                            &binding, &tools, &original.context_data())
                    } else {
                        ios_wire::request(&owner.id, &owner.generation, context, profile, &owner.project, &runtime.cwd, &binding)
                    }
                };
                construct()
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            { let _ = (context, profile); Err(owner.domain.unavailable()) }
        }
        _ => Err(BridgeError::protocol()),
    };
    match bytes { Ok(bytes) => *owner.request.lock().await = Some(bytes), Err(_) => { inner.stop(owner, Reason::ProtocolError); return; } }
    let acquisition_owner = owner.clone(); let acquisition_inner = inner.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let acquisition_native = book.native.clone();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let acquisition_ios = book.ios_native.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let offline_installed = book.offline_installed.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    let recovery_installed = book.recovery_installed.clone();
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    if offline_installed.is_some() && transfer_offline_installed(&book, inner, owner).is_err() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    if recovery_installed.is_some() && transfer_recovery_installed(&book, inner, owner).is_err() {
        inner.stop(owner, Reason::RuntimeUnavailable); return;
    }
    let (acquire_start, acquire_enter) = oneshot::channel();
    book.acquisition_started = true;
    book.acquisition = Some(tokio::task::spawn_blocking(move || {
        if acquire_enter.blocking_recv().is_ok() {
            match acquisition_owner.domain {
                SavedCommandDomain::OfflinePreflight => {
                    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                    if let Some(native) = offline_installed {
                        drop(runtime);
                        acquire_offline_installed(&acquisition_inner, &acquisition_owner, &native); return;
                    }
                    spawn_original(&acquisition_inner, &acquisition_owner, runtime);
                },
                SavedCommandDomain::ProjectRecovery => {
                    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
                    if let Some(native) = recovery_installed {
                        drop(runtime);
                        acquire_recovery_installed(&acquisition_inner, &acquisition_owner, &native); return;
                    }
                    spawn_original(&acquisition_inner, &acquisition_owner, runtime);
                },
                SavedCommandDomain::AndroidBuild => {
                    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                        all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
                    spawn_android_original(&acquisition_inner, &acquisition_owner, runtime, acquisition_native);
                    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                        all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))))]
                    acquisition_inner.stop(&acquisition_owner, Reason::ToolchainUnavailable);
                },
                SavedCommandDomain::IOSArchive => {
                    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                    spawn_ios_original(&acquisition_inner, &acquisition_owner, runtime, acquisition_ios);
                    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                    acquisition_inner.stop(&acquisition_owner, Reason::ToolchainUnavailable);
                },
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
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64")))]
    if matches!(owner.domain, SavedCommandDomain::AndroidBuild | SavedCommandDomain::IOSArchive) { settle_native(&mut book, inner, owner).await; }
    settle_offline_installed(&mut book, inner, owner).await;
    settle_recovery_installed(&mut book, inner, owner).await;
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
    let mut android_close_started=false;
    let settled = {
        let mut book = owner.resources.lock().await;
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
                    SavedCommandDomain::OfflinePreflight | SavedCommandDomain::ProjectRecovery => r.frames == 2,
                    SavedCommandDomain::AndroidBuild => (2..=8).contains(&r.frames),
                    SavedCommandDomain::IOSArchive => (2..=owner.context.frame_limit()).contains(&r.frames),
                })
                && book.err_end.as_ref().is_some_and(|r| r.frames == 0 && !r.failed)
                && book.write_end.as_ref().is_some_and(|r| r.sent && !r.failed)
        } else { true };
        let dependents=manager_joined && startup_settled && io_joined && io && protocol
            && owner.driver_joined.load(Ordering::SeqCst)
            && !owner.resource_unknown.load(Ordering::SeqCst);
        #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
        if owner.leased_android() {
            // All original dependent joins, EOF/decoder/terminal/disposition
            // facts and the intermediate native observation return precede
            // creation of this private consuming witness. Raw nonzero child
            // exit remains Unknown; no pre-close terminal certifies it.
            let observation_ready=book.ios_native.is_none() && book.android_observations.as_ref()
                .is_some_and(AndroidObservationSlot::frozen_ready);
            if !dependents || !observation_ready {false}
            else if let (Some(close),Some(slot))=(&owner.android_close,book.android_observations.as_mut()) {
                match slot.returned.as_mut() {
                    Some(Ok(data)) if data.entered && data.tail.is_some()=>{
                        let joins=AndroidOriginalJoins(AndroidJoinedOriginal::Start(owner.clone()));
                        android_close_started=close.start(&mut data.tail,joins);
                        // Last resource-book access. Only scalar/control/frozen
                        // data follows the moved tail; guards are released
                        // before the same close JoinHandle is awaited below.
                        android_close_started
                    },
                    Some(Ok(data)) if !data.entered && data.tail.is_none()=>{
                        let joins=AndroidOriginalJoins(AndroidJoinedOriginal::Start(owner.clone()));
                        close.finish_unentered(joins)
                    },
                    _=>false,
                }
            }else{false}
        }else{dependents && native_final(&book,&owner)}
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper"))))]
        {dependents && native_final(&book,&owner)}
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
    let settled=if owner.leased_android() {
        // NO Resources/native/Registry/Document lock is held during this wait.
        // A blocked/lost close remains the same original slot plus Unknown;
        // the already-existing watchdog continues its independent control tick.
        let closed=if android_close_started {android_leased::join_start_close(&inner,&owner).await}
            else{owner.android_close.as_ref().is_some_and(|close|close.known())};
        settled && closed && inner.endpoint(&owner).is_some()
    }else{settled};
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
    #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
    let settled = observe_installed_ios_final(&inner, &owner, settled).await;
    guard.complete = true; settled
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
impl SavedCommandOwner {
    pub(crate) fn installed_ios_identity(&self) -> std::sync::Weak<()> { Arc::downgrade(&self.inner.ios_observation_identity) }
    pub(crate) fn observe_installed_unsigned_selection(&self) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::IOSArchive || r.revision != 0 || r.active.is_some() || r.prepared.is_some() || r.last.is_some()
            || r.disabled || r.stopping || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || !self.inner.ios_unsigned_installed_selected() { return Err(self.inner.domain.unavailable()); }
        let slot = self.inner.ios_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        Ok(())
    }
    pub(crate) fn admit_installed_ios_observation(&self, token: crate::shell::installed_observation::ios::Admission) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::IOSArchive || r.revision != 0 || r.active.is_some() || r.prepared.is_some() || r.last.is_some()
            || r.disabled || r.stopping || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || !self.inner.runtime.ios_archive_installed_profile_available() { return Err(self.inner.domain.unavailable()); }
        let mut slot = self.inner.ios_observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        *slot = Some(InstalledIOSObservation { control: token.consume(&self.inner.ios_observation_identity)?,
            original: None, retired: false, core_settled: false, terminal: None });
        Ok(())
    }
    pub(crate) fn installed_ios_snapshot(&self) -> Option<crate::shell::installed_observation::ios::Snapshot> {
        installed_ios_snapshot(&self.inner)
    }
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
fn observe_installed_ios_signed_inputs(inner: &Inner, owner: &Session) {
    use crate::shell::installed_observation::ios::Case;
    let original = inner.ios_observation.lock().ok().map(|slot| slot.as_ref().map(|observation| {
        (observation.control.clone(), observation.original.as_ref().is_some_and(|original| std::ptr::eq(original.as_ref(), owner)))
    }));
    match original {
        Some(Some((control, true))) if control.case == Case::SignedCancel => {
            // DATA from the accepted original typed InputsBound frame only.
            // The existing observer/UI path issues ordinary exact-owner Cancel.
            control.signed_cancel_boundary(&owner.id, &owner.generation);
        },
        Some(None) | Some(Some((_, true))) => {},
        _ => inner.unknown(owner),
    }
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
fn installed_ios_snapshot(inner: &Inner) -> Option<crate::shell::installed_observation::ios::Snapshot> {
    use crate::shell::installed_observation::ios::{OriginalFacts, Snapshot};
    let (owner, control, retired, core_settled, recorded_terminal) = {
        let observation = inner.ios_observation.try_lock().ok()?;
        let observation = observation.as_ref()?;
        (observation.original.as_ref()?.clone(), observation.control.clone(), observation.retired, observation.core_settled, observation.terminal.clone())
    };
    if owner.domain != SavedCommandDomain::IOSArchive || inner.domain != SavedCommandDomain::IOSArchive { return None; }
    let Context::IOSArchive(context) = &owner.context else { return None; };
    if !control.permits_mode(context.operation) || owner.clocks.signed != context.signed()
        || owner.clocks.recovery != context.recovery() { return None; }
    // Read only the original records. Contention is unavailable evidence, not
    // a guessed success, another inspection, or a reason to replace any owner.
    let book = owner.resources.try_lock().ok()?;
    let startup = owner.startup.try_lock().ok()?;
    let native = book.ios_native.as_ref()?.try_lock().ok()?;
    let registry = inner.registry.try_lock().ok()?;
    let active = registry.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, &owner));
    let projection = active.map(|a| &a.projection)
        .or_else(|| registry.last.as_ref().filter(|p| p.operation_id == owner.id && p.owner_generation == owner.generation))?;
    let terminal = if retired { recorded_terminal } else { match projection.result.as_ref() {
        Some(Terminal::IOSArchive(terminal)) => Some(terminal.clone()), _ => None,
    } }?;
    let native_settlement_joined = book.native_started && book.native_joined && !book.native_failed && book.native_settlement.is_none()
        && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, .. })));
    let (cleanup_ms, material_loan_retired, material_loan_present) = if context.account_lifecycle() {
        let material = owner.material.try_lock().ok()?;
        (Some(owner.clocks.cleanup.duration_since(owner.clocks.admitted).as_millis().try_into().ok()?),
            Some(owner.material_retired.load(Ordering::SeqCst)), Some(material.is_some()))
    } else { (None, None, None) };
    // Finish each original join-result read in this statement so its
    // try_lock temporary drops before the owner at the tail return.
    let driver_joined = owner.driver_joined.load(Ordering::SeqCst) && !owner.driver_failed.load(Ordering::SeqCst)
        && matches!(owner.driver_return.try_lock().ok()?.as_ref(), Some(Ok(())));
    let manager_joined = !owner.manager_failed.load(Ordering::SeqCst)
        && matches!(owner.manager_return.try_lock().ok()?.as_ref(), Some(Ok(())));
    let observer_joined = matches!(owner.observer_return.try_lock().ok()?.as_ref(), Some(Ok(true)));
    let watchdog_joined = owner.watchdog_joined.load(Ordering::SeqCst) && !owner.watchdog_failed.load(Ordering::SeqCst)
        && matches!(owner.watchdog_return.try_lock().ok()?.as_ref(), Some(Ok(true)));
    Some(Snapshot { facts: OriginalFacts {
        operation_id: owner.id.clone(), owner_generation: owner.generation.clone(),
        inspection_joined: book.inspection_started && book.inspection_joined && !book.inspection_failed
            && book.inspection.is_none() && book.inspection_error.is_none(),
        acquisition_joined: book.acquisition_started && book.acquisition_joined && !book.acquisition_failed
            && book.acquisition.is_none() && book.acquisition_error.is_none(),
        attempted: startup.attempted,
        child_waited_success: startup.returned && !startup.failed && book.child.is_some() && !book.wait_failed
            && book.waited.as_ref().is_some_and(ExitStatus::success),
        stdin_closed: book.write_end.as_ref().is_some_and(|end| end.sent && end.closed && !end.failed),
        stdout_eof_closed: book.out_end.as_ref().is_some_and(|end| (2..=context.frame_limit()).contains(&end.frames)
            && end.eof && end.closed && !end.failed && end.decoder_settled),
        stderr_eof_closed: book.err_end.as_ref().is_some_and(|end| end.frames == 0 && end.eof && end.closed && !end.failed),
        io_joined: book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
            && !book.write_failed && !book.out_failed && !book.err_failed
            && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some(),
        core_lifetime_settled: if retired { core_settled } else {
            active.is_some_and(|a| a.accepted && a.terminal && a.projection.result.as_ref().is_some_and(Terminal::settled)) },
        runtime_ledger_settled: native.runtime.settled(), tools_ledger_settled: native.tools.settled(), native_settlement_joined,
        native_integrity: native_settlement_joined && native.settled() && native.failure.is_none()
            && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, integrity: true }))),
        driver_joined,
        manager_joined,
        observer_joined,
        watchdog_joined,
        retired_before_cutoff: retired, active_retained: active.is_some(),
        resource_unknown: owner.resource_unknown.load(Ordering::SeqCst) || active.is_some_and(|a| a.unknown)
            || registry.disabled || registry.exhausted || inner.poisoned.load(Ordering::SeqCst),
        work_ms: owner.clocks.work.duration_since(owner.clocks.admitted).as_millis().try_into().ok()?,
        hard_ms: owner.clocks.finality.duration_since(owner.clocks.admitted).as_millis().try_into().ok()?,
        cleanup_ms, material_loan_retired, material_loan_present,
    }, terminal })
}

#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-observation", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), target_os = "macos", target_arch = "aarch64"))]
async fn observe_installed_ios_final(inner: &Arc<Inner>, owner: &Arc<Session>, settled: bool) -> bool {
    if owner.domain != SavedCommandDomain::IOSArchive { return settled; }
    let original = inner.ios_observation.lock().ok().map(|slot| slot.as_ref().map(|observation| {
        (observation.control.clone(), observation.original.as_ref().is_some_and(|original| Arc::ptr_eq(original, owner)))
    }));
    let control = match original {
        Some(Some((control, true))) if control.holds_finality() => control,
        Some(None) | Some(Some((_, true))) => return settled,
        _ => { inner.unknown(owner); return false; },
    };
    let hold_limit = if owner.clocks.signed { owner.clocks.finality } else { owner.clocks.work };
    let Some(end) = inner.endpoint(owner).map(|end| end.min(hold_limit)) else {
        control.unavailable_witness(); inner.unknown(owner); return false;
    };
    let prepared = settled && Instant::now() < end
        && installed_ios_snapshot(inner).is_some_and(|snapshot| control.prepare_hold(snapshot));
    if !prepared { control.unavailable_witness(); inner.unknown(owner); return false; }
    // This is the existing original final observer, not an auxiliary waiter.
    // No native/resource/document/registry borrow survives this await. A new
    // STOP only SHORTENS the same pinned DATA hold's original cutoff.
    let mut held = Box::pin(control.hold_observer(end));
    loop {
        let wake = owner.wake.notified();
        let current = inner.endpoint(owner).map(|end| end.min(hold_limit));
        if current.is_none_or(|end| Instant::now() >= end) {
            control.unavailable_witness(); inner.unknown(owner); return false;
        }
        tokio::select! {
            biased;
            result = &mut held => {
                if !result || inner.endpoint(owner).is_none_or(|end| Instant::now() >= end.min(hold_limit)) {
                    control.unavailable_witness(); inner.unknown(owner); return false;
                }
                return settled;
            },
            _ = wake => {},
            _ = clock_wait(current) => {},
        }
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn installed_project_recovery_owner_data_check() -> bool {
    // Inert typed state only: no Prepare/Start, entropy, task, held root,
    // native inspection or positive worker/close return is constructed.
    fn inert(admitted: Instant) -> (SavedCommandOwner, Arc<Session>) {
        let application = SavedCommandOwner::project_recovery(RuntimeConfig::packaged(
            std::path::PathBuf::from("/inert-mrk-recovery-original-not-opened")));
        let domain = SavedCommandDomain::ProjectRecovery;
        let context = Context::ProjectRecovery(recovery_wire::tests::context());
        let clocks = Clocks::for_context(&context, admitted);
        let (stop, _) = watch::channel(false); let (pipes, _) = watch::channel(Pipes::Pending);
        let (frames, receiver) = mpsc::channel(2);
        let (native_audit_cutoff, _) = watch::channel(clocks.audit_end(None));
        let (native_cleanup_cutoff, _) = watch::channel(clocks.cleanup_end(None));
        let project = RegisteredRoot { path: std::path::PathBuf::from("/inert-mrk-recovery-project-not-opened"),
            identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        let owner = Arc::new(Session { domain, id: "a".repeat(32), generation: "b".repeat(32),
            context: context.clone(), profile: Profile::current(domain).unwrap(), clocks, registration: 1, project,
            recovery_stamp: None, request: AsyncMutex::new(None), material: Mutex::new(None), material_retired: AtomicBool::new(true),
            recovery: None, android_selection: None, native_failure: Mutex::new(None),
            #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
            android_control: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64", not(feature = "macos-android-registration-helper")))]
            android_close: None,
            stop, pipes, frames, wake: Notify::new(), native_audit_cutoff, native_cleanup_cutoff,
            output_bytes: AtomicUsize::new(0), resource_unknown: AtomicBool::new(false),
            driver_done: AtomicBool::new(false), driver_joined: AtomicBool::new(false), driver_failed: AtomicBool::new(false),
            watchdog_joined: AtomicBool::new(false), watchdog_failed: AtomicBool::new(false), manager_failed: AtomicBool::new(false),
            startup: Mutex::new(Startup::default()), resources: AsyncMutex::new(Resources { frames: Some(receiver), ..Resources::default() }),
            input: Arc::new(AsyncMutex::new(Pipe::default())), output: Arc::new(AsyncMutex::new(Pipe::default())),
            error: Arc::new(AsyncMutex::new(Pipe::default())), driver: AsyncMutex::new(None), watchdog: Mutex::new(None),
            manager: AsyncMutex::new(None), observer: AsyncMutex::new(None), driver_return: Mutex::new(None),
            manager_return: Mutex::new(None), observer_return: Mutex::new(None), watchdog_return: Mutex::new(None),
            #[cfg(all(test, debug_assertions, feature = "development-runtime", not(feature = "desktop-shell"),
                any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64"))))]
            fixture: None,
        });
        let projection = RunProjection { operation_id: owner.id.clone(), owner_generation: owner.generation.clone(), context,
            phase: Phase::Starting, intent_usable: false, outcome: None, reason: Reason::None, result: None, stage: None };
        application.inner.lock().active = Some(Active { owner: owner.clone(), projection, first_stop: None, work_expired: false,
            accepted: false, terminal: false, unknown: false, final_join_seen: false, context_invalidated: false });
        (application, owner)
    }
    if RECOVERY_NATIVE_QUALIFIED || RECOVERY_RUNTIME_QUALIFIED || INTENT != Duration::from_secs(300)
        || RECOVERY_WORK != Duration::from_secs(120) || RECOVERY_HARD != Duration::from_secs(130)
        || SETTLEMENT != Duration::from_secs(10) || Profile::current(SavedCommandDomain::ProjectRecovery).is_none() { return false; }
    let runtime = RuntimeConfig::packaged(std::path::PathBuf::from("/inert-mrk-recovery-selection-not-opened"));
    let selected = cfg!(feature = "custom-protocol") && runtime.project_recovery_installed_profile_available();
    let application = SavedCommandOwner::project_recovery(runtime.clone());
    {
        let r = application.inner.lock();
        if application.inner.recovery_installed_selected() != selected || application.inner.qualified(None) != selected
            || application.inner.android_installed_selected(None, None) || application.inner.android_original_owner
            || application.inner.toolchain.is_some() || r.android_catalog.selection().is_some() { return false; }
    }
    let Ok(status) = application.status_recovery(recovery_wire::Availability::Available) else { return false; };
    if status.operation.is_some() || !application.can_exit()
        || status.availability != if selected { recovery_wire::Availability::Available } else { recovery_wire::Availability::RuntimeUnqualified } {
        return false;
    }
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::AndroidBuild, SavedCommandDomain::IOSArchive] {
        if SavedCommandOwner::new(runtime.clone(), domain).inner.recovery_installed_selected() { return false; }
    }

    let (application, original) = inert(Instant::now() - Duration::from_secs(5)); let (_, foreign) = inert(original.clocks.admitted);
    let t = original.clocks.admitted; let early = t + Duration::from_secs(1); let late = t + Duration::from_secs(5);
    let cleanup = original.native_cleanup_cutoff.subscribe();
    if original.clocks.work != t + RECOVERY_WORK || original.clocks.finality != t + RECOVERY_HARD
        || original.clocks.cleanup != t + RECOVERY_HARD || original.clocks.signed || original.clocks.recovery
        || *cleanup.borrow() != t + RECOVERY_HARD { return false; }
    {
        let mut r = application.inner.lock();
        if !final_clock_clear(&r, &original, t) || final_clock_clear(&r, &foreign, t)
            || recovery_installed_closure_ready(&r, &foreign, false, true)
            || recovery_installed_closure_ready(&r, &original, true, true) { return false; }
        application.inner.stop_locked(&mut r, &original, Reason::Cancelled, late);
        if *cleanup.borrow() != late + SETTLEMENT { return false; }
        // This is the actual COMMON publisher, with Registry already held.
        // The original native observation shortens cleanup before projection.
        original.publish_native_failure(Some((AdmissionFailure::Ownership, early)));
        if *cleanup.borrow() != early + SETTLEMENT || r.active.as_ref().unwrap().first_stop != Some(late) { return false; }
        application.inner.advance_locked(&mut r, &original, late);
        if r.active.as_ref().unwrap().first_stop != Some(early)
            || r.active.as_ref().unwrap().projection.reason != Reason::RuntimeUnavailable { return false; }
        original.publish_native_failure(Some((AdmissionFailure::Native, late)));
        application.inner.stop_locked(&mut r, &original, Reason::Shutdown, late);
        if *cleanup.borrow() != early + SETTLEMENT || original.clocks.finality != t + RECOVERY_HARD
            || original.clocks.settlement(r.active.as_ref().unwrap().first_stop) != early + SETTLEMENT { return false; }
        application.inner.advance_locked(&mut r, &original, early + SETTLEMENT);
        if !r.active.as_ref().unwrap().unknown || !r.disabled
            || final_clock_clear(&r, &original, early + SETTLEMENT) { return false; }
        let revision = r.revision;
        application.inner.advance_locked(&mut r, &original, early + SETTLEMENT + Duration::from_secs(1));
        if r.revision != revision || r.active.as_ref().unwrap().first_stop != Some(early) { return false; }
    }
    // The actual COMMON publisher must establish F+10 before a delayed
    // Registry projection, including real Err with no Book first-F witness.
    for callback_failure in [None, Some(AdmissionFailure::Ownership)] {
        for returned in [AdmissionFailure::Native, AdmissionFailure::Identity] {
            let (application, original) = inert(Instant::now() - Duration::from_secs(5));
            let t = original.clocks.admitted; let observed = t + Duration::from_secs(2);
            let prior = callback_failure.map(|failure| (failure, t + Duration::from_secs(1)));
            let expected = prior.map_or(observed, |(_, at)| at); let projection_at = t + Duration::from_secs(5);
            let cleanup = original.native_cleanup_cutoff.subscribe();
            let mut r = application.inner.lock();
            original.publish_native_failure(prior);
            if *original.native_failure.lock().unwrap() != prior.map(|(_, at)| (Reason::RuntimeUnavailable, at))
                || *original.stop.borrow() != prior.is_some() || r.active.as_ref().unwrap().first_stop.is_some()
                || *cleanup.borrow() != prior.map_or(t + RECOVERY_HARD, |(_, at)| at + SETTLEMENT) { return false; }
            original.publish_native_failure(Some((returned, observed)));
            if *original.native_failure.lock().unwrap() != Some((Reason::RuntimeUnavailable, expected))
                || !*original.stop.borrow() || r.active.as_ref().unwrap().first_stop.is_some()
                || *cleanup.borrow() != expected + SETTLEMENT
                || *cleanup.borrow() == projection_at + SETTLEMENT { return false; }
            application.inner.stop_locked(&mut r, &original, Reason::RuntimeUnavailable, projection_at);
            application.inner.advance_locked(&mut r, &original, projection_at);
            if r.active.as_ref().unwrap().first_stop != Some(expected)
                || r.active.as_ref().unwrap().projection.reason != Reason::RuntimeUnavailable
                || *cleanup.borrow() != expected + SETTLEMENT
                || original.clocks.settlement(r.active.as_ref().unwrap().first_stop) != expected + SETTLEMENT
                || original.clocks.work != t + RECOVERY_WORK || original.clocks.finality != t + RECOVERY_HARD
                || !final_clock_clear(&r, &original, projection_at) { return false; }
        }
    }
    // Real returned-error publisher and SAME original Session latch, while its
    // Registry is already held. No task/native object or positive join exists.
    for kind in 0..3 {
        let (application, original) = inert(Instant::now() - Duration::from_secs(5));
        let t = original.clocks.admitted; let before = Instant::now();
        let queried = std::cell::Cell::new(None); let returned = std::cell::Cell::new(None);
        let cleanup = original.native_cleanup_cutoff.subscribe();
        let mut r = application.inner.lock();
        publish_macos_returned_failure(Some(AdmissionFailure::Identity), || {
            let at = Instant::now(); queried.set(Some(at));
            match kind {
                1 => Some((AdmissionFailure::Ownership, t + Duration::from_secs(1))),
                2 => Some((AdmissionFailure::Unknown, at + Duration::from_secs(1))),
                _ => None,
            }
        }, &mut |first| {
            if let Some((AdmissionFailure::Identity, at)) = first { returned.set(Some(at)); }
            original.publish_native_failure(first);
        });
        let Some(returned_at) = returned.get() else { return false; };
        let expected = if kind == 1 { t + Duration::from_secs(1) } else { returned_at };
        let clock_f = expected.max(t).min(original.clocks.work);
        let cutoff = original.clocks.cleanup_end(Some(clock_f));
        if returned_at < before || !queried.get().is_some_and(|at| returned_at <= at)
            || *original.native_failure.lock().unwrap() != Some((Reason::RuntimeUnavailable, expected))
            || *cleanup.borrow() != cutoff
            || r.active.as_ref().unwrap().first_stop.is_some()
            || original.resource_unknown.load(Ordering::SeqCst) != (kind == 2)
            || original.driver_joined.load(Ordering::SeqCst)
            || original.watchdog_joined.load(Ordering::SeqCst) { return false; }
        let delayed = clock_f + Duration::from_secs(5);
        application.inner.stop_locked(&mut r, &original, Reason::RuntimeUnavailable, delayed);
        application.inner.advance_locked(&mut r, &original, delayed);
        if r.active.as_ref().unwrap().first_stop != Some(clock_f)
            || *cleanup.borrow() != cutoff
            || original.clocks.work != t + RECOVERY_WORK || original.clocks.finality != t + RECOVERY_HARD
            || r.active.as_ref().unwrap().unknown != (kind == 2) { return false; }
    }
    {
        let (application, original) = inert(Instant::now() - Duration::from_secs(5));
        let observed = Instant::now(); let cleanup = original.native_cleanup_cutoff.subscribe();
        let clock_f = observed.max(original.clocks.admitted).min(original.clocks.work);
        let cutoff = original.clocks.cleanup_end(Some(clock_f));
        let mut r = application.inner.lock();
        // SAME method used by iOS environment/check errors: keep the caller's
        // original finite reason, with F captured before this held Registry.
        original.observe_failure_at(Reason::ToolchainMismatch, observed, false);
        original.publish_native_failure(Some((AdmissionFailure::Unknown, observed + Duration::from_secs(1))));
        if *original.native_failure.lock().unwrap() != Some((Reason::ToolchainMismatch, observed))
            || !original.resource_unknown.load(Ordering::SeqCst)
            || *cleanup.borrow() != cutoff
            || r.active.as_ref().unwrap().first_stop.is_some() { return false; }
        application.inner.advance_locked(&mut r, &original, clock_f + Duration::from_secs(2));
        if r.active.as_ref().unwrap().first_stop != Some(clock_f)
            || r.active.as_ref().unwrap().projection.reason !=
                (if observed < original.clocks.work { Reason::ToolchainMismatch } else { Reason::TimedOut })
            || !r.active.as_ref().unwrap().unknown { return false; }
    }
    for observed in [Duration::from_secs(1), Duration::from_secs(121)] {
        let (application, original) = inert(Instant::now() - Duration::from_secs(122)); let t = original.clocks.admitted;
        original.publish_native_failure(Some((AdmissionFailure::Native, t + observed)));
        let mut r = application.inner.lock(); application.inner.advance_locked(&mut r, &original, t + Duration::from_secs(122));
        let active = r.active.as_ref().unwrap();
        if active.first_stop != Some((t + observed).min(original.clocks.work))
            || active.projection.reason != if observed < RECOVERY_WORK { Reason::RuntimeUnavailable } else { Reason::TimedOut }
            || *original.native_cleanup_cutoff.borrow() != original.clocks.settlement(active.first_stop) { return false; }
    }
    let (_, expired) = inert(Instant::now() - RECOVERY_HARD - Duration::from_secs(1));
    if !expired.native_cleanup_expired(None) || !expired.resource_unknown.load(Ordering::SeqCst) { return false; }

    let (application, original) = inert(Instant::now() - RECOVERY_HARD); let t = original.clocks.admitted;
    application.inner.accept_at(&original, Frame::ProjectRecovery(recovery_wire::Frame::Accepted), t);
    application.inner.accept_at(&original,
        Frame::ProjectRecovery(recovery_wire::tests::terminal_frame(&recovery_wire::tests::context())), t);
    {
        let mut r = application.inner.lock(); let active = r.active.as_ref().unwrap();
        // A settled-looking core DTO is NOT an original final-join receipt and
        // never creates private review authority in this inert model.
        if !active.accepted || !active.terminal || active.final_join_seen || active.projection.public().result.is_some()
            || recovery_review_after_finality(active, &original, t).is_some() || r.recovery_review.is_some() { return false; }
        application.inner.advance_locked(&mut r, &original, t + RECOVERY_HARD);
        let active = r.active.as_ref().unwrap();
        if !active.unknown || recovery_review_after_finality(active, &original, t + RECOVERY_HARD).is_some() { return false; }
    }
    let expiry = SavedCommandOwner::project_recovery(runtime);
    {
        let mut r = expiry.inner.lock(); let expires = t + INTENT;
        r.prepared = Some(Prepared { projection: RunProjection { operation_id: original.id.clone(), owner_generation: original.generation.clone(),
            context: original.context.clone(), phase: Phase::AwaitingConsent, intent_usable: true, outcome: None,
            reason: Reason::None, result: None, stage: None }, expires, registration: original.registration, project: original.project.clone(),
            recovery_stamp: None, material: None, recovery: None, android_selection: None });
        expiry.inner.expire_prepared(&mut r, expires - Duration::from_nanos(1));
        if r.prepared.as_ref().is_none_or(|p| p.expires != expires) { return false; }
        expiry.inner.expire_prepared(&mut r, expires); let revision = r.revision;
        if r.prepared.is_some() || r.last.as_ref().is_none_or(|p| p.intent_usable || p.reason != Reason::IntentExpired
            || p.result.is_some()) { return false; }
        expiry.inner.expire_prepared(&mut r, expires + INTENT);
        if r.revision != revision || r.active.is_some() || r.recovery_review.is_some() { return false; }
    }
    let mut resources = Resources::default();
    if !recovery_installed_final(&resources) { return false; }
    resources.recovery_selected = true;
    if recovery_installed_final(&resources) { return false; }
    resources.recovery_installed = Some(Arc::new(Mutex::new(ProjectRecoveryRuntimeSlots::new())));
    if recovery_installed_final(&resources) { return false; }
    resources.inspection_started = true;
    if recovery_consumers_returned(&resources, &Startup::default(), true) { return false; }
    let complete = [(false, false, false, false, false), (true, true, false, false, false), (true, false, true, true, true)];
    for bits in 0u8..32 {
        let state = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0, bits & 16 != 0);
        if recovery_worker_returned(state.0, state.1, state.2, state.3, state.4) != complete.contains(&state) { return false; }
    }
    true
}
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[test]
fn installed_project_recovery_retains_original_clocks_review_and_finality() {
    assert!(installed_project_recovery_owner_data_check());
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn macos_saved_return_data_check() -> bool {
    use std::cell::Cell;
    let before = Instant::now(); let queried = Cell::new(None); let mut facts = Vec::new();
    publish_macos_returned_failure(Some(AdmissionFailure::Native), || {
        queried.set(Some(Instant::now())); None
    }, &mut |first| facts.push(first));
    let [None, Some((AdmissionFailure::Native, returned_at))] = facts.as_slice() else { return false; };
    if *returned_at < before || !queried.get().is_some_and(|at| *returned_at <= at) { return false; }
    let admitted = *returned_at; let delayed = admitted + Duration::from_secs(5);
    for domain in [SavedCommandDomain::OfflinePreflight, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
        let clocks = Clocks::new(domain, admitted);
        if clocks.cleanup_end(Some(*returned_at)) != *returned_at + SETTLEMENT
            || clocks.settlement(Some(*returned_at)) != *returned_at + SETTLEMENT
            || clocks.cleanup_end(Some(*returned_at)) == clocks.cleanup_end(Some(delayed)) { return false; }
    }
    // Existing signed/recovery policies are DATA here, never replaced by the
    // Supervisor's two-second grace or a test-supplied product clock.
    let signed = Clocks { cleanup: admitted + IOS_SIGNED_CLEANUP, finality: admitted + IOS_SIGNED_HARD,
        signed: true, ..Clocks::new(SavedCommandDomain::IOSArchive, admitted) };
    let recovery = Clocks { work: admitted + IOS_RECOVERY_WORK, cleanup: admitted + IOS_RECOVERY_CLEANUP,
        finality: admitted + IOS_RECOVERY_HARD, recovery: true, ..Clocks::new(SavedCommandDomain::IOSArchive, admitted) };
    for clocks in [signed, recovery] {
        if clocks.cleanup_end(Some(*returned_at)) != *returned_at + Duration::from_secs(120)
            || clocks.settlement(Some(*returned_at)) != *returned_at + Duration::from_secs(130)
            || clocks.cleanup_end(Some(clocks.finality)) != clocks.cleanup
            || clocks.settlement(Some(clocks.finality)) != clocks.finality { return false; }
    }

    let mut slots = OfflinePreflightRuntimeSlots::new();
    let (_sender, stop) = watch::channel(true); let before = Instant::now();
    // This is the actual native-free stopped arm guard and the SAME return
    // publisher called by the registered offline inspector, not a native mock.
    let armed = slots.arm_acl_once(before + Duration::from_secs(30), &stop);
    let mut reports = Vec::new();
    publish_macos_returned_failure(armed.as_ref().err().copied(), || slots.first_failure(),
        &mut |first| reports.push(first));
    let after = Instant::now();
    if !matches!(armed, Err(AdmissionFailure::Stopped)) || !slots.never_started()
        || !reports.iter().any(|row| matches!(row, Some((AdmissionFailure::Stopped, at))
            if before <= *at && *at <= after)) { return false; }
    true
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn installed_offline_owner_data_check() -> bool {
    // Inert state/clock models only. Exclude the qualification test's real
    // Prepare/getrandom call, hosted fixtures, runtime inspection and native IO.
    offline_tests::no_owner_startup_and_unsupported_status_do_not_claim_document_loss();
    offline_tests::intent_expires_with_a_new_revision_and_cancel_never_creates_an_owner();
    offline_tests::start_burns_before_unavailability_and_foreign_start_grants_nothing();
    offline_tests::whole_run_endpoints_and_first_stop_never_renew();
    offline_tests::complete_negative_is_provisional_and_not_first_failure();
    offline_tests::late_terminal_never_reverses_timeout_or_unknown_in_either_delivery_order();
    offline_tests::repeated_unknown_polling_does_not_publish_new_results_or_extend_clocks();
    if !macos_saved_return_data_check() { return false; }
    if !matches!(wire::Profile::current(), Some(wire::Profile::MacosArm64))
        || wire::CONSENT != "saved-offline-android-v1" { return false; }
    let runtime = RuntimeConfig::packaged(std::path::PathBuf::from("/inert-mrk-offline-owner-not-opened"));
    let selected = cfg!(feature = "custom-protocol") && runtime.offline_preflight_installed_profile_available();
    let owner = SavedCommandOwner::offline_preflight(runtime.clone());
    if owner.inner.offline_installed_selected() != selected { return false; }
    let Ok(status) = owner.status_offline(wire::Availability::Available) else { return false; };
    if status.operation.is_some() || !owner.can_exit()
        || status.availability != (if selected { wire::Availability::Available } else { wire::Availability::RuntimeUnqualified }) { return false; }
    for domain in [SavedCommandDomain::AndroidBuild, SavedCommandDomain::ProjectRecovery, SavedCommandDomain::IOSArchive] {
        if SavedCommandOwner::new(runtime.clone(), domain).inner.offline_installed_selected() { return false; }
    }
    let mut resources = Resources::default();
    if !offline_installed_final(&resources) { return false; }
    resources.offline_started = true;
    if offline_installed_final(&resources) { return false; }
    resources.offline_started = false; resources.offline_joined = true;
    if offline_installed_final(&resources) { return false; }
    resources.offline_joined = false; resources.offline_failed = true;
    if offline_installed_final(&resources) { return false; }
    resources.offline_failed = false;
    resources.offline_installed = Some(Arc::new(Mutex::new(OfflinePreflightRuntimeSlots::new())));
    if offline_installed_final(&resources) { return false; }
    resources.offline_selected = true;
    if offline_installed_final(&resources) { return false; }
    let complete = [(false, false, false, false, false), (true, true, false, false, false),
        (true, false, true, true, true)];
    for bits in 0u8..32 {
        let state = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0, bits & 16 != 0);
        if offline_worker_returned(state.0, state.1, state.2, state.3, state.4) != complete.contains(&state) { return false; }
    }
    true
}
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[test]
fn installed_offline_owner_keeps_domain_clocks_and_original_finality() {
    assert!(installed_offline_owner_data_check());
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
    pub(crate) fn installed_android_identity(&self) -> std::sync::Weak<()> { Arc::downgrade(&self.inner.observation_identity) }
    pub(crate) fn admit_installed_android_observation(&self, document: &Arc<()>, token: crate::shell::installed_observation::commands::AndroidAdmission) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::AndroidBuild || r.revision != 0 || r.active.is_some() || r.prepared.is_some() || r.last.is_some()
            || r.disabled || r.stopping || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || !token.document_matches(document) || !self.inner.android_installed_selected(Some(document),r.android_catalog.selection()) {
            return Err(self.inner.domain.unavailable());
        }
        let mut slot = self.inner.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        *slot = Some(InstalledObservation { control: token.consume(&self.inner.observation_identity)?, original: None,
            retired: false, core_settled: false, android_lifetime: None }); Ok(())
    }
    pub(crate) fn installed_android_snapshot(&self) -> Option<crate::shell::installed_observation::commands::AndroidSnapshot> {
        let (owner, retired, core_settled, recorded_lifetime) = {
            let book = self.inner.observation.lock().ok()?; let book = book.as_ref()?;
            if !book.control.case.android() { return None; }
            (book.original.as_ref()?.clone(), book.retired, book.core_settled, book.android_lifetime.clone())
        };
        if owner.domain != SavedCommandDomain::AndroidBuild || self.inner.domain != SavedCommandDomain::AndroidBuild { return None; }
        let book = owner.resources.try_lock().ok()?;
        let startup = owner.startup.try_lock().ok()?;
        let native = book.native.as_ref()?.try_lock().ok()?;
        let r = self.inner.lock();
        let active = r.active.as_ref().filter(|a| Arc::ptr_eq(&a.owner, &owner));
        let projection = active.map(|a| &a.projection)
            .or_else(|| r.last.as_ref().filter(|p| p.operation_id == owner.id && p.owner_generation == owner.generation))?;
        let lifetime = if retired { recorded_lifetime } else { match projection.result.as_ref() {
            Some(Terminal::AndroidBuild(t)) => Some(t.lifetime.clone()), _ => None,
        } }?;
        let native_joined = book.native_started && book.native_joined && !book.native_failed && book.native_settlement.is_none()
            && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, .. })));
        let facts = crate::shell::installed_observation::commands::OriginalFacts {
            domain: "android", id: owner.id.clone(), generation: owner.generation.clone(),
            inspection_joined: book.inspection_started && book.inspection_joined && !book.inspection_failed
                && book.inspection.is_none() && book.inspection_error.is_none(),
            acquisition_joined: book.acquisition_started && book.acquisition_joined && !book.acquisition_failed
                && book.acquisition.is_none() && book.acquisition_error.is_none(),
            attempted: startup.attempted,
            no_child: !startup.attempted && !startup.returned && !startup.failed && startup.child.is_none()
                && !book.acquisition_started && book.acquisition.is_none() && book.child.is_none(),
            child_waited_success: startup.returned && !startup.failed && book.child.is_some() && !book.wait_failed
                && book.waited.as_ref().is_some_and(ExitStatus::success),
            stdin_closed: book.write_end.as_ref().is_some_and(|v| v.sent && v.closed && !v.failed),
            stdout_eof_closed: book.out_end.as_ref().is_some_and(|v| (2..=android_wire::MAX_FRAMES).contains(&v.frames)
                && v.eof && v.closed && !v.failed),
            stderr_eof_closed: book.err_end.as_ref().is_some_and(|v| v.frames == 0 && v.eof && v.closed && !v.failed),
            io_joined: book.writer.is_none() && book.stdout.is_none() && book.stderr.is_none()
                && !book.write_failed && !book.out_failed && !book.err_failed
                && book.write_end.is_some() && book.out_end.is_some() && book.err_end.is_some(),
            core_lifetime_settled: if retired { core_settled } else {
                active.is_some_and(|a| a.accepted && a.terminal && a.projection.result.as_ref().is_some_and(Terminal::settled)) },
            runtime_ledger_settled: native.runtime.settled(), runtime_settlement_joined: native_joined,
            driver_joined: owner.driver_joined.load(Ordering::SeqCst) && matches!(owner.driver_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
            manager_joined: !owner.manager_failed.load(Ordering::SeqCst) && matches!(owner.manager_return.try_lock().ok()?.as_ref(), Some(Ok(()))),
            observer_joined: matches!(owner.observer_return.try_lock().ok()?.as_ref(), Some(Ok(true))),
            watchdog_joined: owner.watchdog_joined.load(Ordering::SeqCst) && !owner.watchdog_failed.load(Ordering::SeqCst)
                && matches!(owner.watchdog_return.try_lock().ok()?.as_ref(), Some(Ok(true))),
            retired_before_cutoff: retired, active_retained: active.is_some(),
            resource_unknown: owner.resource_unknown.load(Ordering::SeqCst) || active.is_some_and(|a| a.unknown)
                || self.inner.poisoned.load(Ordering::SeqCst),
        };
        Some(crate::shell::installed_observation::commands::AndroidSnapshot {
            facts, tools_ledger_settled: native.tools.settled(),
            native_integrity: native.settled() && native.failure.is_none() && native_joined
                && matches!(book.native_return.as_ref(), Some(Ok(NativeSettlement { originals_closed: true, integrity: true }))),
            lifetime, terminal: serde_json::to_value(projection.public().android().ok()?).ok()?,
        })
    }
    pub(crate) fn admit_installed_observation(&self, token: crate::shell::installed_observation::commands::OfflineAdmission) -> Result<(), BridgeError> {
        let r = self.inner.lock();
        if self.inner.domain != SavedCommandDomain::OfflinePreflight || r.revision != 0 || r.active.is_some() || r.prepared.is_some() || r.last.is_some()
            || r.disabled || r.stopping || r.document_lost || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst)
            || !self.inner.offline_installed_selected() { return Err(self.inner.domain.unavailable()); }
        let mut slot = self.inner.observation.lock().map_err(|_| BridgeError::cleanup_unknown())?;
        if slot.is_some() { return Err(self.inner.domain.unavailable()); }
        *slot = Some(InstalledObservation { control: token.consume()?, original: None, retired: false, core_settled: false, android_lifetime: None }); Ok(())
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
