//! Installed agent CLI frontend. No Python/Rust installation is needed by the
//! installed binary. Only the running Desktop's explicitly allowed saved DATA
//! is accessible; native mutations are not smuggled through another entrypoint.
use crate::service_protocol as p;
use p::{Error, Id};
use std::{ffi::OsString, io::Write, path::PathBuf};

const HELP: &str = "Mobile Release Kit agent CLI\n\n\
Usage:\n\
  mrk status [--json]\n\
  mrk projects [--json]\n\
  mrk observe PROJECT_ID [--json]\n\
  mrk operations PROJECT_ID [--json]\n\
  mrk operation PROJECT_ID OPERATION_ID [--json]\n\
  mrk --help\n\n\
Open Desktop, select a project, then enable agent read access in Settings.\n\
Reads return saved observations; they do not rerun actions or validate a release.\n\
Native edits, builds, credentials and publishing are not exposed by this slice.\n";

struct Options { request: p::Request, json: bool }
enum Parsed { Help, Version, Request(Options) }
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Parsed, Error> {
    let args: Vec<OsString> = args.into_iter().take(8).collect();
    if args.len() > 5 { return Err(Error::InvalidRequest); }
    let mut words: Vec<&str> = args.iter().map(|a| a.to_str().ok_or(Error::InvalidRequest)).collect::<Result<_, _>>()?;
    if words.is_empty() || words == ["--help"] || words == ["-h"] { return Ok(Parsed::Help); }
    if words == ["--version"] { return Ok(Parsed::Version); }
    let json = words.last() == Some(&"--json");
    if json { words.pop(); }
    let request = match words.as_slice() {
        ["status"] => p::RequestBody::Info(p::Empty {}),
        ["projects"] => p::RequestBody::Projects(p::Empty {}),
        ["observe", project] => p::RequestBody::Observe(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["operations", project] => p::RequestBody::Operations(p::ProjectQuery { project_id: Id::parse(project)? }),
        ["operation", project, operation] => p::RequestBody::Operation(p::OperationQuery { project_id: Id::parse(project)?, operation_id: Id::parse(operation)? }),
        _ => return Err(Error::InvalidRequest),
    };
    Ok(Parsed::Request(Options { request: p::Request { version: p::VERSION, request_id: Id::random()?, request }, json }))
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
        p::ResponseBody::Info(_) => "Connected to Desktop with read-only access. Results are saved observations, not release validation.\n".to_owned(),
        p::ResponseBody::Projects(projects) => if projects.is_empty() { "No projects are allowed for this read session.\n".to_owned() } else { projects.iter().map(project).collect() },
        p::ResponseBody::Observation(value) => project(value),
        p::ResponseBody::Operations(operations) => if operations.is_empty() { "No operation observations have been published for this project.\n".to_owned() } else { operations.iter().map(operation).collect() },
        p::ResponseBody::Operation(value) => operation(value),
        p::ResponseBody::Error(error) => format!("{}\n", error.message()),
    }
}

/// Root wires the separate installed `mrk` executable to this single entry.
/// stdout has one bounded JSON document in --json mode; diagnostics are fixed.
pub fn run(args: impl IntoIterator<Item = OsString>) -> u8 {
    // Remember only the presence of the non-secret output switch. Rejected
    // argument contents are neither echoed nor included in a public response.
    let args: Vec<OsString> = args.into_iter().take(8).collect();
    let json = args.iter().any(|a| a == "--json");
    let output = match parse(args) {
        Ok(Parsed::Help) => { let _ = std::io::stdout().write_all(HELP.as_bytes()); return 0; }
        Ok(Parsed::Version) => { let _ = std::io::stdout().write_all(b"mrk application-observation protocol 1\n"); return 0; }
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
    fn installed_cli_has_only_closed_read_verbs_and_stable_json_errors() {
        assert!(matches!(parse(args(&["--help"])).unwrap(), Parsed::Help));
        assert!(matches!(parse(args(&["projects", "--json"])).unwrap(), Parsed::Request(_)));
        for input in [args(&["shell", "private sentinel"]), args(&["status", "--endpoint", "private sentinel"]),
            args(&["credentials", "--password", "private sentinel"]), args(&["observe", "project-1"])] {
            assert!(parse(input).is_err());
        }
        assert!(!String::from_utf8(error_bytes(Error::InvalidRequest, true)).unwrap().contains("sentinel"));
        assert_eq!(exit_code(Error::StateUnknown), 6);
    }
}
