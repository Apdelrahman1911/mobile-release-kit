//! Installed agent CLI frontend. No Python/Rust installation is needed by the
//! installed binary. Read access is separate from the single named local-check
//! execution permission. Both use the running Desktop's original owners.
use crate::service_protocol as p;
use p::{Error, Id};
use std::{ffi::OsString, io::Write, path::PathBuf};
#[path = "installed_cli_identity.rs"]
mod identity;
#[path = "installed_cli_identity_actions.rs"]
mod identity_actions;
#[path = "installed_cli_local_checks.rs"]
mod local_checks;
#[path = "installed_cli_android_build.rs"]
mod android_build;
#[path="installed_cli_build_requests.rs"]
mod build_requests;
#[path="installed_cli_ios_archive.rs"]
mod ios_archive;
#[path="installed_cli_git_index.rs"]
mod git_index;
#[path="installed_cli_git_commit.rs"]
mod git_commit;
#[path="installed_cli_version_reserve.rs"]
mod version_reserve;

const HELP: &str = "Mobile Release Kit agent CLI\n\n\
Usage:\n\
  mrk capabilities [--json]\n\
  mrk version-reserve-submit PROJECT_ID SERVICE_INSTANCE GRANT_ID REVIEW_ID --reviewed [--json]\n\
  mrk version-reserve-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk version-reserve-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk status [--json]\n\
  mrk projects [--json]\n\
  mrk observe PROJECT_ID [--json]\n\
  mrk android-tools PROJECT_ID [--json]\n\
  mrk requests PROJECT_ID [--json]\n\
  mrk repository PROJECT_ID [--json]\n\
  mrk git-index-scope PROJECT_ID [--json]\n\
  mrk git-index-prepare PROJECT_ID SERVICE_INSTANCE GRANT_ID [--json]\n\
  mrk git-index-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID PREPARE_OPERATION_ID REVIEW_ID [--json]\n\
  mrk git-index-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk git-index-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk git-commit-scope PROJECT_ID [--json]\n\
  mrk git-commit-prepare PROJECT_ID SERVICE_INSTANCE GRANT_ID [--json]\n\
  mrk git-commit-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID PREPARE_OPERATION_ID REVIEW_ID [--json]\n\
  mrk git-commit-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk git-commit-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk operations PROJECT_ID [--json]\n\
  mrk operation PROJECT_ID OPERATION_ID [--json]\n\
  mrk identity-request PROJECT_ID OBSERVATION_REVISION --stdin [--json]\n\
  mrk identity-request-status PROJECT_ID SERVICE_INSTANCE INTENT_ID [--json]\n\
  mrk identity-prepare PROJECT_ID SERVICE_INSTANCE INTENT_ID [--json]\n\
  mrk identity-start PROJECT_ID SERVICE_INSTANCE INTENT_ID SESSION_ID OWNER_GENERATION REVISION PLAN_TOKEN --reviewed [--json]\n\
  mrk identity-status PROJECT_ID SERVICE_INSTANCE INTENT_ID [--json]\n\
  mrk identity-cancel PROJECT_ID SERVICE_INSTANCE INTENT_ID [--json]\n\
  mrk local-check PROJECT_ID OBSERVATION_REVISION [--json]\n\
  mrk local-check-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk local-check-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk android-build-prepare PROJECT_ID OBSERVATION_REVISION [--json]\n\
  mrk android-build-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID OPERATION_ID OWNER_GENERATION [--json]\n\
  mrk android-build-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk android-build-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk ios-archive-prepare PROJECT_ID OBSERVATION_REVISION [--json]\n\
  mrk ios-archive-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID OPERATION_ID OWNER_GENERATION [--json]\n\
  mrk ios-archive-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk ios-archive-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n\
  mrk --help\n\n\
Capabilities describe this CLI without opening Desktop or reading project data.\n\
For the other commands, open Desktop, select a project, then enable agent read access in Settings.\n\
Reads return observations; they do not rerun actions or validate a release.\n\
requests lists retained local-check/build request IDs in this Desktop instance, not complete history or replay permission.\n\
android-tools returns historical Desktop catalogue labels, not current tools or project compatibility.\n\
repository returns historical Desktop Git counts; local refs only, no inspection, fetch or current-checkout claim.\n\
observe --json may include optional setup state codes, not a passed check or release approval.\n\
Identity requests additionally need the separate 15-minute Desktop request permission.\n\
In Desktop, read the requested source, then either continue locally or allow only that exact change once.\n\
Stdin is one closed JSON object: selection {platform,target,project}, desiredIdentity, identityIntent.\n\
Local checks require a separate one-use 15-minute project permission in Desktop.\n\
Configured project checks may run programs, modify files or contact the network; this is not a sandbox.\n\
Keep the printed instance/request IDs: inspect or cancel the same original, never replay it.\n\
Android build preparation and Start are separate, one-use requests for the exact saved inputs approved in Desktop.\n\
The 15-minute grant authorizes START, not renewed run time. Project code can have file/network/signing effects.\n\
Delegated identity edits need the original Desktop source review and separate one-use exact-change permission.\n\
There is no arbitrary edit, toolkit signing, credential or publishing route.\n";

struct Options { request: p::Request, json: bool }
enum Parsed { Help, Version, Capabilities { json: bool }, Request(Options) }
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Parsed, Error> {
    let args: Vec<OsString> = args.into_iter().take(8).collect();
    if args.len() > 5 { return Err(Error::InvalidRequest); }
    let mut words: Vec<&str> = args.iter().map(|a| a.to_str().ok_or(Error::InvalidRequest)).collect::<Result<_, _>>()?;
    if words.is_empty() || words == ["--help"] || words == ["-h"] { return Ok(Parsed::Help); }
    if words == ["--version"] { return Ok(Parsed::Version); }
    let json = words.last() == Some(&"--json");
    if json { words.pop(); }
    // Capability inspection is local static DATA, not an authenticated service
    // request. In particular it needs no request ID, state path or runtime.
    if words == ["capabilities"] { return Ok(Parsed::Capabilities { json }); }
    let request = match words.as_slice() {
        ["status"] => p::RequestBody::Info(p::Empty {}),
        ["projects"] => p::RequestBody::Projects(p::Empty {}),
        ["observe", project] => p::RequestBody::Observe(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["android-tools", project] => p::RequestBody::AndroidTools(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["requests", project] => p::RequestBody::Requests(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["repository", project] => p::RequestBody::Repository(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["operations", project] => p::RequestBody::Operations(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["operation", project, operation] => p::RequestBody::Operation(p::OperationQuery { project_id: Id::parse(project)?, operation_id: Id::parse(operation)? }),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed::Request(Options { request: p::Request { version: p::VERSION, request_id: Id::random()?, request }, json }))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandCapability {
    command: &'static str,
    arguments: &'static [&'static str],
    description: &'static str,
}
const READ_COMMANDS: [CommandCapability; 8] = [
    CommandCapability { command: "status", arguments: &[], description: "Read the current Desktop service access status." },
    CommandCapability { command: "projects", arguments: &[], description: "List projects allowed by the current read grant." },
    CommandCapability { command: "observe", arguments: &["PROJECT_ID"], description: "Read a saved project observation and optional redacted setup guidance, which may be stale." },
    CommandCapability { command: "android-tools", arguments: &["PROJECT_ID"], description: "Read historical Desktop catalogue labels; not live tools, inspection or project compatibility." },
    CommandCapability { command: "requests", arguments: &["PROJECT_ID"], description: "Discover current-instance local-check/Android/iOS request IDs; not complete history or replay permission." },
    CommandCapability { command: "repository", arguments: &["PROJECT_ID"], description: "Read historical Desktop Git counts; local refs only, no inspection or fetch." },
    CommandCapability { command: "operations", arguments: &["PROJECT_ID"], description: "List saved operation observations for a project." },
    CommandCapability { command: "operation", arguments: &["PROJECT_ID", "OPERATION_ID"], description: "Read one saved operation observation; it is not native finality authority." },
];
const LOCAL_CHECK_COMMANDS: [CommandCapability; 3] = [
    CommandCapability { command: "local-check", arguments: &["PROJECT_ID", "OBSERVATION_REVISION"], description: "Use one separately allowed saved local-project check; configured code may have effects." },
    CommandCapability { command: "local-check-status", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Inspect the same request and original operation without reexecution." },
    CommandCapability { command: "local-check-cancel", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Request STOP of the same original; cancellation is not settlement." },
];
const ANDROID_BUILD_COMMANDS: [CommandCapability; 4] = [
    CommandCapability { command: "android-build-prepare", arguments: &["PROJECT_ID", "OBSERVATION_REVISION"], description: "Prepare the exact Desktop-approved saved Android build; no Start or GO." },
    CommandCapability { command: "android-build-start", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID", "OPERATION_ID", "OWNER_GENERATION"], description: "Start that one original build once; project code may have file/network effects." },
    CommandCapability { command: "android-build-status", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Inspect the same preparation/build without replay." },
    CommandCapability { command: "android-build-cancel", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Request original STOP; no settlement is inferred." },
];
const GIT_INDEX_COMMANDS: [CommandCapability;5] = [
    CommandCapability {command:"git-index-scope",arguments:&["PROJECT_ID"],description:"Read the exact native Desktop-selected Stage/Unstage permission, not a fresh Git inspection."},
    CommandCapability {command:"git-index-prepare",arguments:&["PROJECT_ID","SERVICE_INSTANCE","GRANT_ID"],description:"Use one explicit Desktop selection to prepare the original local Git review; no Apply."},
    CommandCapability {command:"git-index-start",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID","PREPARE_OPERATION_ID","REVIEW_ID"],description:"Apply that exact native Stage/Unstage review once; never commit, switch, push or run arbitrary commands."},
    CommandCapability {command:"git-index-status",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Inspect the same original request without replay; history is not finality."},
    CommandCapability {command:"git-index-cancel",arguments:&["PROJECT_ID","SERVICE_INSTANCE","REQUEST_ID"],description:"Request STOP of the same original; no cleanup is inferred."},
];
const IOS_ARCHIVE_COMMANDS: [CommandCapability; 4] = [
    CommandCapability { command: "ios-archive-prepare", arguments: &["PROJECT_ID", "OBSERVATION_REVISION"], description: "Prepare the exact Desktop-approved saved iOS unsigned archive; no Start or GO." },
    CommandCapability { command: "ios-archive-start", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID", "OPERATION_ID", "OWNER_GENERATION"], description: "Start that one original build once; project code may have file/network effects." },
    CommandCapability { command: "ios-archive-status", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Inspect the same preparation/build without replay." },
    CommandCapability { command: "ios-archive-cancel", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "REQUEST_ID"], description: "Request original STOP; no settlement is inferred." },
];
const IDENTITY_REQUEST_COMMANDS: [CommandCapability; 2] = [
    CommandCapability { command: "identity-request", arguments: &["PROJECT_ID", "OBSERVATION_REVISION", "--stdin"], description: "Propose an identity change for explicit Desktop review; this does not apply an edit." },
    CommandCapability { command: "identity-request-status", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "INTENT_ID"], description: "Query the original proposal without replaying it; a linked operation has separate status." },
];

const IDENTITY_ACTION_COMMANDS: [CommandCapability; 4] = [
    CommandCapability { command: "identity-prepare", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "INTENT_ID"], description: "Preview the exact already-read identity proposal explicitly delegated in Desktop, once." },
    CommandCapability { command: "identity-start", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "INTENT_ID", "SESSION_ID", "OWNER_GENERATION", "REVISION", "PLAN_TOKEN", "--reviewed"], description: "Apply that exact original preview, once; never repeat after an unconfirmed acknowledgement." },
    CommandCapability { command: "identity-status", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "INTENT_ID"], description: "Read the same original delegated edit; history remains separate." },
    CommandCapability { command: "identity-cancel", arguments: &["PROJECT_ID", "SERVICE_INSTANCE", "INTENT_ID"], description: "Request STOP on that original edit; acknowledgement is not completed cleanup." },
];

/// A bounded description of this compiled interface, never a live ServiceInfo
/// response or a grant. Missing/unavailable Desktop is deliberately irrelevant.
fn capabilities(json: bool) -> Result<Vec<u8>, Error> {
    let mut bytes = if json {
        serde_json::to_vec(&serde_json::json!({
            "protocolVersion": p::VERSION,
            "scope": "compiled-interface",
            "runtimeChecked": false,
            "serviceTransportImplemented": cfg!(any(target_os = "linux", target_os = "macos")),
            "supportsDirectMutationCommands": false,
            "supportsExactDelegatedIdentityEdits": true,
            "supportsNamedProjectExecution": true,
            "operationsRequire": {"runningDesktop": true, "projectReadGrant": true},
            "observationScope": "saved-data-not-live-validation-or-native-authority",
            "idFormat": "32 lowercase hexadecimal characters; all-zero IDs are invalid",
            "jsonOption": "--json (last argument)",
            "commands": READ_COMMANDS,
            "androidTools": {"scope":"desktop-catalogue-observation", "freshness":"historical-not-revalidated",
                "projectCompatibility":"not-checked", "startsInspection":false, "persistsObservation":false},
            "localChecks": {
                "scope": "saved-local-android-project-checks", "defaultEnabled": false, "oneUse": true,
                "maxLeaseSeconds": crate::agent_local_checks::LIFETIME.as_secs(), "maxRetainedRequests": crate::agent_local_checks::LIMIT,
                "projectCodeEffectsPossible": true, "readGrantAuthorizesExecution": false,
                "requires": {"runningDesktop": true, "projectReadGrant": true, "separateProjectExecutionPermission": true},
                "commands": LOCAL_CHECK_COMMANDS,
            },
            "androidBuilds": {
                "scope": "saved-android-build-structure-and-version", "defaultEnabled": false, "oneUse": true,
                "maxStartWindowSeconds": crate::agent_android_build::START_WINDOW.as_secs(), "maxRetainedRequests": crate::agent_android_build::LIMIT,
                "prepareStartsBuild": false, "projectCodeEffectsPossible": true, "toolkitSigning": false, "storePublishing": false,
                "readGrantAuthorizesExecution": false, "nativeAvailabilityChecked": false,
                "requires": {"runningDesktop": true, "projectReadGrant": true, "separateSavedInputBuildPermission": true, "qualifiedSelectedTools": true},
                "commands": ANDROID_BUILD_COMMANDS,
            },
            "iosArchives": {
                "scope": "saved-ios-unsigned-archive", "defaultEnabled": false, "oneUse": true,
                "maxStartWindowSeconds": crate::agent_build_requests::START_WINDOW.as_secs(), "maxRetainedRequests": crate::agent_build_requests::LIMIT,
                "prepareStartsBuild": false, "projectCodeEffectsPossible": true, "toolkitSigning": false, "storePublishing": false,
                "readGrantAuthorizesExecution": false, "nativeAvailabilityChecked": false,
                "requires": {"runningDesktop": true, "projectReadGrant": true, "separateSavedInputBuildPermission": true, "qualifiedMacXcodeRuntime": true},
                "commands": IOS_ARCHIVE_COMMANDS, "archiveDigestAvailable": false,
                "sharesBuildGrantAndRequestLimitWithAndroid": true,
            },
            "identityActions": {
                "scope": "already-read-exact-identity-proposal", "defaultEnabled": false, "oneUse": true,
                "nativeAvailabilityChecked": false, "readGrantAuthorizesEdits": false, "proposalGrantAuthorizesEdits": false,
                "maxStartWindowSeconds": crate::agent_identity_requests::LIFETIME.as_secs(),
                "sharesProposalTombstones": true, "maxRetainedRequests": crate::agent_identity_requests::LIMIT,
                "requires": {"runningDesktop":true,"projectReadGrant":true,"originalNativeSourceRead":true,"separateExactChangeConsent":true},
                "commands": IDENTITY_ACTION_COMMANDS,
            },
            "gitIndex": {"scope":"desktop-selected-stage-or-unstage", "defaultEnabled":false,"oneUse":true,
                "maxStartWindowSeconds":crate::service_git_protocol::START_WINDOW.as_secs(),"maxRetainedRequests":crate::service_git_protocol::REQUEST_LIMIT,
                "readGrantAuthorizesWrites":false,"prepareApplies":false,"nativeAvailabilityChecked":false,
                "commit":false,"branchChanges":false,"push":false,"credentials":false,"requiresRunningDesktop":true,"commands":GIT_INDEX_COMMANDS},
            "versionReservation": {"scope":"one-desktop-native-review", "defaultEnabled":false,"oneUse":true,
                "maxReviewMs":crate::service_version_reserve_protocol::REVIEW_MS,"maxRetainedRequests":crate::service_version_reserve_protocol::REQUEST_LIMIT,
                "requiresProjectReadGrant":true,"requiresRunningDesktop":true,"readGrantAuthorizesReserve":false,
                "appliesSourceEdits":false,"nativeAvailabilityChecked":false,"commands":version_reserve::COMMANDS},
            "gitCommits": {"scope":"desktop-approved-whole-staged-index", "defaultEnabled":false,"oneUse":true,
                "maxStartWindowSeconds":crate::service_git_protocol::START_WINDOW.as_secs(),"maxRetainedRequests":crate::service_git_protocol::REQUEST_LIMIT,
                "sharesGrantAndRequestLimitWithGitIndex":true,"readOrIndexGrantAuthorizesCommit":false,"prepareApplies":false,"nativeAvailabilityChecked":false,
                "includesPrivateDraft":false,"hooks":false,"signing":false,"branchChanges":false,"push":false,"credentials":false,"requiresRunningDesktop":true,"commands":git_commit::COMMANDS},
            "repository": {"scope":"captured-desktop-git-observation", "freshness":"historical-not-revalidated", "basis":"local-refs-no-fetch", "startsInspection":false, "includesPaths":false},
            "requestDiscovery": {"scope":"current-host-retained-requests", "maxRequests":crate::service_request_catalogue::LIMIT, "savedHistory":false, "includesReports":false, "grantsExecution":false},
            "identityRequests": {
                "scope": "desktop-reviewed-proposal",
                "defaultEnabled": false,
                "cliApply": false,
                "maxLeaseSeconds": crate::agent_identity_requests::LIFETIME.as_secs(),
                "maxRetainedRequests": crate::agent_identity_requests::LIMIT,
                "requires": {"runningDesktop": true, "projectReadGrant": true, "separateProjectRequestPermission": true},
                "commands": IDENTITY_REQUEST_COMMANDS,
            },
        })).map_err(|_| Error::StateUnknown)?
    } else {
        let mut text = String::from("Compiled CLI capabilities (Desktop availability not checked).\n\
            Reads require a running Desktop and an explicit project read grant.\n\
            Saved observations are not live validation or native operation authority.\n\
            Android tool-catalogue labels are historical; this query does not inspect tools or check project compatibility.\n\
            Arbitrary edits, credentials, toolkit signing and publishing are not supported by this CLI.\n\
            iOS unsigned archives use the same one-use build grant and require the original qualified Mac/Xcode runtime.\n\
            A saved Android build needs a separate one-use exact-input Desktop START grant and selected qualified tools.\n\
            Prepare never starts a build; project code may have file/network/signing effects.\n\
            A named local check needs a separate one-use Desktop grant. Configured project code may have effects.\n\
            Identity proposals require a separate Desktop permission and explicit Desktop review/apply or exact one-use delegation.\n\
            Delegated edits reuse the same native source read and original session, never a headless writer.\n\n");
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            text.push_str("The local Desktop service transport is not implemented on this platform.\n\n");
        }
        for command in READ_COMMANDS.iter().chain(IDENTITY_REQUEST_COMMANDS.iter()).chain(IDENTITY_ACTION_COMMANDS.iter()).chain(LOCAL_CHECK_COMMANDS.iter()).chain(ANDROID_BUILD_COMMANDS.iter()).chain(IOS_ARCHIVE_COMMANDS.iter()).chain(GIT_INDEX_COMMANDS.iter()).chain(git_commit::COMMANDS.iter()) {
            text.push_str("  mrk "); text.push_str(command.command);
            for argument in command.arguments { text.push(' '); text.push_str(argument); }
            text.push_str(" [--json]\n    "); text.push_str(command.description); text.push('\n');
        }
        text.push_str("\nVersion reservation uses one already-reviewed native Desktop request; no source Apply or upload authority.\n");
        text.push_str("  mrk version-reserve-submit PROJECT_ID SERVICE_INSTANCE GRANT_ID REVIEW_ID --reviewed [--json]\n  mrk version-reserve-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n  mrk version-reserve-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]\n");
        text.push_str("\nLocal Git index changes need a separate one-use native Desktop selection. No commit, branch or push grant.\nUse service/project/request IDs returned by Desktop; native Git operation/review IDs are opaque strings.\n");
        text.into_bytes()
    };
    if json { bytes.push(b'\n'); }
    if bytes.len() > 12 * 1024 { return Err(Error::StateUnknown); }
    Ok(bytes)
}

/// Fixed platform app-data convention, matching Tauri app_local_data_dir().
/// These environment paths are ordinary native user context, never credentials
/// or request-controlled endpoint flags. The IPC reader checks full no-follow
/// ancestry, owner, reservation and exact private endpoint identity afterwards.
fn application_data() -> Result<PathBuf, Error> {
    #[cfg(target_os = "linux")]
    {
        let base = match std::env::var_os("XDG_DATA_HOME") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => PathBuf::from(std::env::var_os("HOME").ok_or(Error::Unavailable)?).join(".local/share"),
        };
        if !base.is_absolute() { return Err(Error::Unavailable); }
        Ok(base.join("dev.mobile-release-kit.desktop"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = PathBuf::from(std::env::var_os("HOME").ok_or(Error::Unavailable)?);
        if !home.is_absolute() { return Err(Error::Unavailable); }
        Ok(home.join("Library/Application Support/dev.mobile-release-kit.desktop"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    { Err(Error::UnsupportedPlatform) }
}

fn exit_code(error: Error) -> u8 {
    match error {
        Error::InvalidRequest => 2,
        Error::Unavailable | Error::UnsupportedPlatform => 3,
        Error::AccessDenied | Error::Expired => 4,
        Error::Busy | Error::Conflict | Error::RecoveryRequired => 5,
        Error::StateUnknown => 6,
    }
}
fn error_bytes(error: Error, json: bool) -> Vec<u8> {
    if json {
        // Only fixed literals and enum values, never exception/path/arguments.
        let value = serde_json::json!({"version":p::VERSION,"ok":false,"error":error,"message":error.message()});
        let mut bytes = serde_json::to_vec(&value).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"state_unknown\"}".to_vec());
        bytes.push(b'\n'); bytes
    } else { format!("{}\n", error.message()).into_bytes() }
}
fn human(response: &p::ResponseBody) -> String {
    fn project(project: &p::ProjectObservation) -> String {
        let state = match &project.observation {
            None => "no saved observation; open this project in Desktop",
            Some(observation) if observation.stale => "saved observation is stale; refresh in Desktop",
            Some(observation) => match observation.configuration.state {
                p::ConfigurationState::Missing => "saved release configuration is missing",
                p::ConfigurationState::Invalid => "saved release configuration has errors",
                p::ConfigurationState::FormatValid => "saved release configuration is format-valid (not release validation)",
                p::ConfigurationState::Unavailable => "saved release configuration could not be observed",
            },
        };
        format!("{}  {state}\n", project.project_id.as_str())
    }
    fn operation(operation: &p::OperationObservation) -> String {
        let state = match operation.state {
            p::OperationState::Prepared => "prepared", p::OperationState::Running => "running",
            p::OperationState::Succeeded => "succeeded", p::OperationState::Failed => "failed",
            p::OperationState::CancellationRequested => "cancellation requested", p::OperationState::Cancelled => "cancelled after settlement",
            p::OperationState::RecoveryRequired => "recovery required", p::OperationState::Unknown => "unknown",
        };
        format!("{}  {state}{} (reported observation, not authority)\n", operation.operation_id.as_str(), if operation.stale { "; stale" } else { "" })
    }
    match response {
        p::ResponseBody::Info(_) => "Connected to Desktop. The read grant cannot execute checks; execution needs a separate one-use grant. Saved observations are not release validation.\n".to_owned(),
        p::ResponseBody::Projects(projects) => if projects.is_empty() { "No projects are allowed for this read session.\n".to_owned() } else { projects.iter().map(project).collect() },
        p::ResponseBody::Observation(value) => {
            let mut text = project(value);
            match value.observation.as_ref().filter(|saved| !saved.stale).and_then(|saved|
                saved.setup_analysis.as_ref().filter(|analysis| analysis.matches(saved.configuration.state, saved.discovery_partial))) {
                Some(analysis) => text.push_str(&format!("  Setup guidance: {} saved requirement states; not checks or release approval. Use --json for codes.\n", analysis.requirements.len())),
                None => text.push_str("  Setup guidance unavailable for a current saved observation.\n"),
            }
            text
        },
        p::ResponseBody::Operations(operations) => if operations.is_empty() { "No operation observations have been published for this project.\n".to_owned() } else { operations.iter().map(operation).collect() },
        p::ResponseBody::Operation(value) => operation(value),
        p::ResponseBody::AndroidTools(value) => crate::service_android_tools::human(value),
        p::ResponseBody::Requests(value) => crate::service_request_catalogue::human(value),
        p::ResponseBody::Repository(value) => crate::service_repository_summary::human(value),
        p::ResponseBody::VersionReserveRequest(_) => "Use version-reserve-status with the same original request IDs.\n".into(),
        p::ResponseBody::GitCommitScope(_) | p::ResponseBody::GitCommitRequest(_) =>
            "Use the named git-commit command and its exact original request IDs to inspect this response.\n".into(),
        p::ResponseBody::GitIndexScope(_) | p::ResponseBody::GitIndexRequest(_) =>
            "Use the named git-index command and its exact original request IDs to inspect this response.\n".into(),
        p::ResponseBody::Error(error) => format!("{}\n", error.message()),
        p::ResponseBody::IdentityIntent(value) => identity::human(value),
        p::ResponseBody::IdentityAction(value) => identity_actions::human(value),
        p::ResponseBody::LocalCheck(value) => local_checks::human(value),
        p::ResponseBody::AndroidBuildRequest(value) => android_build::human(value),
        p::ResponseBody::IosArchiveRequest(value) => ios_archive::human(value),
    }
}

// Preserve the longest closed command (Start plus --json is ten words), and
// one rejection sentinel. No child may silently accept a truncated prefix.
fn collect_arguments(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    args.into_iter().take(11).collect()
}

/// Root wires the separate installed `mrk` executable to this single entry.
/// stdout has one bounded JSON document in --json mode; diagnostics are fixed.
pub fn run(args: impl IntoIterator<Item = OsString>) -> u8 {
    // Remember only the presence of the non-secret output switch. Rejected
    // argument contents are neither echoed nor included in a public response.
    let args = collect_arguments(args);
    let json = args.iter().any(|a| a == "--json");
    if identity::recognizes(&args) { return identity::run(args); }
    if version_reserve::recognizes(&args) { return version_reserve::run(args); }
    if git_index::recognizes(&args) { return git_index::run(args); }
    if git_commit::recognizes(&args) { return git_commit::run(args); }
    if identity_actions::recognizes(&args) { return identity_actions::run(args); }
    if local_checks::recognizes(&args) { return local_checks::run(args); }
    if android_build::recognizes(&args) { return android_build::run(args); }
    if ios_archive::recognizes(&args) { return ios_archive::run(args); }
    let output = match parse(args) {
        Ok(Parsed::Help) => { let _ = std::io::stdout().write_all(HELP.as_bytes()); return 0; }
        Ok(Parsed::Version) => { let _ = std::io::stdout().write_all(b"mrk application-observation protocol 1\n"); return 0; }
        Ok(Parsed::Capabilities { json }) => capabilities(json).map(|bytes| (0, bytes)),
        Ok(Parsed::Request(options)) => execute(options),
        Err(error) => Err(error),
    };
    let (code, bytes) = match output {
        Ok((code, bytes)) => (code, bytes), Err(error) => (exit_code(error), error_bytes(error, json)),
    };
    if std::io::stdout().write_all(&bytes).is_err() { return 6; }
    code
}
fn execute(options: Options) -> Result<(u8, Vec<u8>), Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let path = application_data()?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Unavailable)?;
        let response = runtime.block_on(crate::installed_cli_ipc::request(&path, &options.request))?;
        let code = match response.response { p::ResponseBody::Error(error) => exit_code(error), _ => 0 };
        let mut bytes = if options.json { p::encode_response(&response)? } else { human(&response.response).into_bytes() };
        if options.json { bytes.push(b'\n'); }
        Ok((code, bytes))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    { let _ = options; Err(Error::UnsupportedPlatform) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> { values.iter().map(OsString::from).collect() }
    #[test]
    fn repository_is_a_closed_historical_query_without_git_action_parameters() {
        let id = "11111111111111111111111111111111";
        let Parsed::Request(options) = parse(args(&["repository", id, "--json"])).unwrap() else { panic!("wrong command") };
        let wire = p::encode_request(&options.request).unwrap();
        assert!(matches!(p::decode_request(&wire).unwrap().request, p::RequestBody::Repository(_)));
        for extra in ["--fetch", "--diff", "--root", "--run", "--remote"] {
            assert!(parse(args(&["repository", id, extra])).is_err());
        }
        let mut input: serde_json::Value = serde_json::from_slice(&wire).unwrap(); input["request"]["params"]["fetch"] = serde_json::json!(true);
        assert!(p::decode_request(&serde_json::to_vec(&input).unwrap()).is_err());
        let data = crate::service_repository_summary::ObservationSlot::default();
        let source = crate::service_repository_summary::tests::source(); data.publish(source.clone(), crate::service_repository_summary::tests::captured(1));
        let mut response = p::Response { version: p::VERSION, request_id: options.request.request_id,
            service_instance: Id::parse(id).unwrap(), client_id: Id::parse(id).unwrap(), session_id: Id::parse(id).unwrap(),
            response: p::ResponseBody::Repository(data.view(Id::parse(id).unwrap(), &source.runtime_id, &source.canonical_root, source.device, source.inode)) };
        let bytes = p::encode_response(&response).unwrap(); assert!(bytes.len() < crate::service_repository_summary::VIEW_BYTES);
        assert!(human(&response.response).contains("historical") && human(&response.response).contains("no fetch"));
        if let p::ResponseBody::Repository(view) = &mut response.response { view.capture = crate::service_repository_summary::Capture::Unavailable; }
        assert!(p::encode_response(&response).is_err());
        let caps: serde_json::Value = serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
        assert_eq!(caps["repository"]["startsInspection"], false); assert_eq!(caps["repository"]["includesPaths"], false);
    }
    #[test]
    fn requests_is_discovery_only_and_rejects_action_parameters_and_foreign_instance() {
        let id = "11111111111111111111111111111111";
        let Parsed::Request(options) = parse(args(&["requests", id, "--json"])).unwrap() else { panic!("wrong command") };
        let wire = p::encode_request(&options.request).unwrap();
        assert!(matches!(p::decode_request(&wire).unwrap().request, p::RequestBody::Requests(_)));
        for extra in ["start", "cancel", "--report", "--root", "--all-projects"] {
            assert!(parse(args(&["requests", id, extra])).is_err());
        }
        let view = crate::service_request_catalogue::Catalogue {
            schema_version: 1, scope: crate::service_request_catalogue::Scope::CurrentHostRetainedRequests,
            sampling: crate::service_request_catalogue::Sampling::PerRequestNotAtomic,
            service_instance: Id::parse(id).unwrap(), project_id: Id::parse(id).unwrap(),
            do_not_replay: true, requests: vec![],
        };
        let mut response = p::Response { version: p::VERSION, request_id: options.request.request_id,
            service_instance: Id::parse(id).unwrap(), client_id: Id::parse(id).unwrap(), session_id: Id::parse(id).unwrap(),
            response: p::ResponseBody::Requests(view) };
        assert!(p::encode_response(&response).is_ok());
        assert!(human(&response.response).contains("restart does not prove earlier work settled"));
        response.service_instance = Id::parse("22222222222222222222222222222222").unwrap();
        assert!(p::encode_response(&response).is_err());
        let caps: serde_json::Value = serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
        assert_eq!(caps["requestDiscovery"]["grantsExecution"], false);
        assert_eq!(caps["requestDiscovery"]["includesReports"], false);
        assert_eq!(caps["requestDiscovery"]["maxRequests"], 64);
    }
    #[test]
    fn android_tools_is_a_closed_historical_read_with_no_action_parameters() {
        let id = "11111111111111111111111111111111";
        let Parsed::Request(options) = parse(args(&["android-tools", id, "--json"])).unwrap() else { panic!("wrong command") };
        assert!(matches!(&options.request.request, p::RequestBody::AndroidTools(_)));
        let wire = p::encode_request(&options.request).unwrap();
        assert!(matches!(p::decode_request(&wire).unwrap().request, p::RequestBody::AndroidTools(_)));
        let mut action: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        action["request"]["params"]["inspect"] = serde_json::json!(true);
        assert!(p::decode_request(&serde_json::to_vec(&action).unwrap()).is_err());
        for words in [vec!["android-tools", id, "--inspect"], vec!["android-tools", id, "--select", id],
            vec!["android-tools", "project-1"], vec!["android-tools", id, "--root", "/private/sentinel"]] {
            assert!(parse(args(&words)).is_err());
        }
        let slot = crate::service_android_tools::ObservationSlot::default();
        slot.publish(crate::service_android_tools::tests::catalogue());
        let response = p::ResponseBody::AndroidTools(slot.view(Id::parse(id).unwrap()));
        let text = human(&response);
        assert!(text.contains("historical") && text.contains("not checked") && text.contains("not current-tool"));
        let mut framed = p::Response { version: p::VERSION, request_id: Id::parse(id).unwrap(),
            service_instance: Id::parse(id).unwrap(), client_id: Id::parse(id).unwrap(), session_id: Id::parse(id).unwrap(), response };
        assert!(p::encode_response(&framed).is_ok());
        if let p::ResponseBody::AndroidTools(view) = &mut framed.response { view.capture = crate::service_android_tools::Capture::Unavailable; }
        assert!(p::encode_response(&framed).is_err());
        let caps: serde_json::Value = serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
        assert_eq!(caps["androidTools"]["startsInspection"], false);
        assert_eq!(caps["androidTools"]["projectCompatibility"], "not-checked");
    }
    #[test]
    fn installed_cli_has_only_closed_read_verbs_and_stable_json_errors() {
        assert!(matches!(parse(args(&["--help"])).unwrap(), Parsed::Help));
        assert!(matches!(parse(args(&["projects", "--json"])).unwrap(), Parsed::Request(_)));
        assert!(matches!(parse(args(&["capabilities"])).unwrap(), Parsed::Capabilities { json: false }));
        assert!(matches!(parse(args(&["capabilities", "--json"])).unwrap(), Parsed::Capabilities { json: true }));
        for input in [args(&["shell", "private sentinel"]), args(&["status", "--endpoint", "private sentinel"]),
            args(&["credentials", "--password", "private sentinel"]), args(&["observe", "project-1"]),
            args(&["capabilities", "private sentinel", "--json"]), args(&["--json", "capabilities"]),
            args(&["capabilities", "--json", "--json"]), args(&["build"]), args(&["release"])] {
            assert!(parse(input).is_err());
        }
        assert!(!String::from_utf8(error_bytes(Error::InvalidRequest, true)).unwrap().contains("sentinel"));
        assert_eq!(exit_code(Error::StateUnknown), 6);
    }

    #[test]
    fn capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals() {
        let bytes = capabilities(true).unwrap();
        assert!(bytes.len() <= 12 * 1024 && bytes.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["protocolVersion"], p::VERSION);
        assert_eq!(value["scope"], "compiled-interface");
        assert_eq!(value["runtimeChecked"], false);
        assert_eq!(value["supportsDirectMutationCommands"], false);
        assert_eq!(value["supportsNamedProjectExecution"], true);
        assert_eq!(value["localChecks"]["oneUse"], true);
        assert_eq!(value["localChecks"]["defaultEnabled"], false);
        assert_eq!(value["localChecks"]["readGrantAuthorizesExecution"], false);
        assert_eq!(value["localChecks"]["projectCodeEffectsPossible"], true);
        assert_eq!(value["localChecks"]["maxLeaseSeconds"], crate::agent_local_checks::LIFETIME.as_secs());
        assert_eq!(value["localChecks"]["maxRetainedRequests"], crate::agent_local_checks::LIMIT);
        assert_eq!(value["localChecks"]["commands"].as_array().unwrap().len(), 3);
        assert_eq!(value["androidBuilds"]["commands"].as_array().unwrap().len(), 4);
        assert_eq!(value["androidBuilds"]["prepareStartsBuild"], false);
        assert_eq!(value["androidBuilds"]["toolkitSigning"], false);
        assert_eq!(value["androidBuilds"]["maxStartWindowSeconds"], crate::agent_android_build::START_WINDOW.as_secs());
        assert_eq!(value["operationsRequire"], serde_json::json!({"runningDesktop":true,"projectReadGrant":true}));
        assert!(value.get("serviceInstance").is_none() && value.get("requestId").is_none());
        let commands = value["commands"].as_array().unwrap();
        assert_eq!(commands.len(), 8);
        // Each advertised command/argument order is accepted by the actual
        // parser, not a separate documentation-only command implementation.
        for command in commands {
            let mut words = vec![command["command"].as_str().unwrap()];
            for argument in command["arguments"].as_array().unwrap() {
                assert!(matches!(argument.as_str(), Some("PROJECT_ID" | "OPERATION_ID")));
                words.push("11111111111111111111111111111111");
            }
            words.push("--json");
            assert!(matches!(parse(args(&words)).unwrap(), Parsed::Request(_)));
        }
        let human = String::from_utf8(capabilities(false).unwrap()).unwrap();
        let actions = &value["identityActions"];
        assert_eq!(actions["defaultEnabled"], false); assert_eq!(actions["oneUse"], true);
        assert_eq!(actions["readGrantAuthorizesEdits"], false); assert_eq!(actions["proposalGrantAuthorizesEdits"], false);
        assert_eq!(actions["nativeAvailabilityChecked"], false); assert_eq!(actions["commands"].as_array().unwrap().len(), 4);
        assert_eq!(actions["requires"]["originalNativeSourceRead"], true);
        let identity = &value["identityRequests"];
        assert_eq!(identity["scope"], "desktop-reviewed-proposal");
        assert_eq!(identity["defaultEnabled"], false);
        assert_eq!(identity["cliApply"], false);
        assert_eq!(identity["maxLeaseSeconds"], crate::agent_identity_requests::LIFETIME.as_secs());
        assert_eq!(identity["maxRetainedRequests"], crate::agent_identity_requests::LIMIT);
        assert_eq!(identity["requires"]["separateProjectRequestPermission"], true);
        assert_eq!(identity["commands"].as_array().unwrap().len(), 2);
        assert_eq!(identity["commands"][0]["command"], "identity-request");
        assert_eq!(identity["commands"][0]["arguments"], serde_json::json!(["PROJECT_ID", "OBSERVATION_REVISION", "--stdin"]));
        assert_eq!(identity["commands"][1]["command"], "identity-request-status");
        assert_eq!(identity["commands"][1]["arguments"], serde_json::json!(["PROJECT_ID", "SERVICE_INSTANCE", "INTENT_ID"]));
        assert!(human.contains("mrk ios-archive-prepare") && human.contains("mrk android-build-prepare"));
        let ios=&value["iosArchives"];
        assert_eq!(ios["defaultEnabled"],false);assert_eq!(ios["oneUse"],true);
        assert_eq!(ios["nativeAvailabilityChecked"],false);assert_eq!(ios["toolkitSigning"],false);
        assert_eq!(ios["storePublishing"],false);assert_eq!(ios["archiveDigestAvailable"],false);
        assert_eq!(ios["maxRetainedRequests"],value["androidBuilds"]["maxRetainedRequests"]);
        assert_eq!(ios["sharesBuildGrantAndRequestLimitWithAndroid"],true);
        for command in ios["commands"].as_array().unwrap() {
            let mut words=vec![command["command"].as_str().unwrap()];
            for argument in command["arguments"].as_array().unwrap() {
                words.push(if argument=="OBSERVATION_REVISION" {"1"} else {"11111111111111111111111111111111"});
            }
            words.push("--json");assert!(build_requests::parse(crate::agent_ios_archive::FAMILY,&args(&words)).is_ok());
        }
        assert!(human.contains("mrk identity-request PROJECT_ID OBSERVATION_REVISION --stdin") && human.contains("explicit Desktop review/apply"));
    }

    #[test]
    fn setup_guidance_cli_is_optional_saved_data_and_stale_is_unavailable() {
        use crate::service_setup_guidance as guidance;
        let source = guidance::fixture(&[guidance::Platform::Android], p::ConfigurationState::FormatValid, false);
        let mut project = p::ProjectObservation {
            project_id: Id::parse(&"1".repeat(32)).unwrap(), registered_in_current_host: true,
            observation: Some(p::SavedObservation { revision: 1, stale: false,
                configuration: p::SavedConfiguration { state: p::ConfigurationState::FormatValid, bytes: None, sha256: None },
                discovery_partial: false, issue_count: 0,
                setup_analysis: guidance::project(Some(&source), p::ConfigurationState::FormatValid, false) }),
        };
        assert!(human(&p::ResponseBody::Observation(project.clone())).contains("not checks or release approval"));
        project.observation.as_mut().unwrap().stale = true;
        assert!(human(&p::ResponseBody::Observation(project.clone())).contains("Setup guidance unavailable"));
        project.observation.as_mut().unwrap().stale = false;
        project.observation.as_mut().unwrap().setup_analysis = None;
        assert!(human(&p::ResponseBody::Observation(project.clone())).contains("Setup guidance unavailable"));
        let old = serde_json::to_value(project).unwrap();
        assert!(old["observation"].get("setupAnalysis").is_none());
        let decoded: p::ProjectObservation = serde_json::from_value(old).unwrap();
        assert!(decoded.observation.unwrap().setup_analysis.is_none());
    }
}
