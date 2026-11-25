//! Explicit foreground HISTORY entry in the existing signed `mrk` binary.
//! No hidden window, automatic background start, project script or fresh query.
use crate::service_protocol::Error;
use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
    time::Duration,
};

const HELP: &str = "mrk serve-history --project ABSOLUTE_PATH --allow-history-read-seconds 1..3600\n\
Foreground, one project, cached history only. No refresh, edit, build, signing or credentials.\n\
Uses the same private state and socket as Desktop; never starts Desktop or takes over its lock.\n\
Startup may create private project registration/state, never project files. All saved facts remain stale.\n\
Stop with Ctrl-C/SIGTERM, or let the explicit access period expire. No consent is restored on restart.\n\
Close this host before enabling Desktop agent/state access. A Desktop which already lost the lock\n\
may need to be reopened; seamless simultaneous GUI/headless operation is not implemented.\n";

struct Options {
    project: PathBuf,
    lifetime: Duration,
}
enum Parsed {
    Help,
    Serve(Options),
}
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Parsed, Error> {
    // Four fixed fields plus one rejection sentinel; never truncate to a valid
    // command. No user path or rejected word is echoed in a diagnostic.
    let words: Vec<_> = args.into_iter().take(5).collect();
    if words.len() == 1 && words[0] == "--help" {
        return Ok(Parsed::Help);
    }
    if words.len() != 4 || words[0] != "--project" || words[2] != "--allow-history-read-seconds" {
        return Err(Error::InvalidRequest);
    }
    let path = words[1].to_str().ok_or(Error::InvalidRequest)?;
    let project = Path::new(path);
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
        || !project.is_absolute()
        || project
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::InvalidRequest);
    }
    let seconds = words[3].to_str().ok_or(Error::InvalidRequest)?;
    if seconds.is_empty()
        || seconds.len() > 4
        || seconds.starts_with('0')
        || !seconds.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::InvalidRequest);
    }
    let seconds: u64 = seconds.parse().map_err(|_| Error::InvalidRequest)?;
    if !(1..=3600).contains(&seconds) {
        return Err(Error::InvalidRequest);
    }
    Ok(Parsed::Serve(Options {
        project: project.to_owned(),
        lifetime: Duration::from_secs(seconds),
    }))
}

/// Public only as the fixed bin-to-library seam. No native object or grant is
/// returned. Normal CLI commands never call this function.
pub fn run(args: impl IntoIterator<Item = OsString>) -> u8 {
    use std::io::Write;
    let parsed = match parse(args) {
        Ok(value) => value,
        Err(error) => return report_error(error),
    };
    match parsed {
        Parsed::Help => {
            if std::io::stdout().write_all(HELP.as_bytes()).is_ok() {
                0
            } else {
                6
            }
        }
        Parsed::Serve(options) => {
            #[cfg(all(
                feature = "installed-cli",
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            {
                native::run(options)
            }
            #[cfg(not(all(
                feature = "installed-cli",
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )))]
            {
                let _ = options;
                report_error(Error::UnsupportedPlatform)
            }
        }
    }
}
fn report_error(error: Error) -> u8 {
    use std::io::Write;
    let (code, message) = match error {
        Error::InvalidRequest => (2, "Use mrk serve-history --help; explicit project and bounded history consent are required.\n"),
        Error::UnsupportedPlatform => (3, "Foreground history is currently implemented only in the installed macOS CLI.\n"),
        Error::Unavailable => (3, "Foreground history could not start. No fallback host or grant was created.\n"),
        Error::AccessDenied | Error::Expired => (4, "This foreground history consent is stopped or expired; it was not renewed.\n"),
        Error::Busy => (5, "The private state is already held or busy. Close the existing host, then explicitly start again. No takeover was attempted.\n"),
        Error::Conflict | Error::RecoveryRequired => (5, "History source/state needs inspection. Preserve state; no reset, takeover or automatic retry occurred.\n"),
        Error::StateUnknown => (6, "History startup or shutdown is unconfirmed. Preserve the original state and endpoint; no clean completion is claimed.\n"),
    };
    if std::io::stderr().write_all(message.as_bytes()).is_err() {
        6
    } else {
        code
    }
}

#[cfg(all(
    feature = "installed-cli",
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
mod native {
    use super::*;
    use crate::{application_service::HistoryLease, application_service_host::ApplicationHost};
    use std::{io::Write, sync::Arc, time::Instant};
    use tokio::{
        signal::unix::{signal, Signal, SignalKind},
        task::{JoinError, JoinHandle},
    };

    #[derive(Clone, Copy)]
    enum Stop {
        Signal,
        LeaseExpired,
        StartupExpired,
    }
    fn application_data() -> Result<PathBuf, Error> {
        use nix::unistd::{geteuid, getuid, User};
        let uid = getuid();
        if uid.is_root() || uid != geteuid() {
            return Err(Error::AccessDenied);
        }
        let user = User::from_uid(uid)
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unavailable)?;
        if user.uid != uid || !user.dir.is_absolute() || user.dir.as_os_str().len() > 4096 {
            return Err(Error::Unavailable);
        }
        // Actual native account, NOT HOME/XDG or a request-selected endpoint.
        Ok(user
            .dir
            .join("Library/Application Support/dev.mobile-release-kit.desktop"))
    }
    pub(super) fn run(options: Options) -> u8 {
        let started = Instant::now();
        let lease = match HistoryLease::new(started, options.lifetime) {
            Ok(lease) => lease,
            Err(error) => return report_error(error),
        };
        let host = Arc::new(ApplicationHost::new_history(lease.clone()));
        // Default client runtime unchanged. All potentially blocking startup
        // and grant publication run on these fixed workers. The calling
        // block_on thread below polls signal/expiry independently of them.
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return report_error(Error::Unavailable),
        };
        let result = runtime.block_on(serve(host, lease, options.project));
        // Every original task was joined. Runtime destruction is NOT a source,
        // socket, Store or worker-close receipt.
        match result {
            Ok(()) => 0,
            Err(error) => report_error(error),
        }
    }
    async fn stopped(
        interrupt: &mut Signal,
        terminate: &mut Signal,
        lease: &HistoryLease,
        deadline: Instant,
    ) -> Result<Stop, Error> {
        let result = tokio::select! {
            biased;
            value = interrupt.recv() => value.map(|_| Stop::Signal).ok_or(Error::StateUnknown),
            value = terminate.recv() => value.map(|_| Stop::Signal).ok_or(Error::StateUnknown),
            _ = tokio::time::sleep_until(deadline.into()) => Ok(if deadline == lease.expires() { Stop::LeaseExpired } else { Stop::StartupExpired }),
        };
        // First action after observing signal/expiry/failure, before any
        // Host/Service mutex or synchronous cleanup filesystem call.
        lease.stop();
        result
    }
    async fn await_original<T>(
        work: &mut JoinHandle<T>,
        interrupt: &mut Signal,
        terminate: &mut Signal,
        lease: &HistoryLease,
        deadline: Instant,
    ) -> (Result<T, JoinError>, Option<Result<Stop, Error>>) {
        tokio::select! {
            biased;
            reason = stopped(interrupt, terminate, lease, deadline) => {
                // BORROW the same job through its genuine return. No abort,
                // detach, timeout Drop, or renewal after a blocked kernel call.
                ((&mut *work).await, Some(reason))
            }
            result = &mut *work => (result, None),
        }
    }
    async fn serve(
        host: Arc<ApplicationHost>,
        lease: Arc<HistoryLease>,
        project: PathBuf,
    ) -> Result<(), Error> {
        // On the calling thread before any source/account/Store effect. This
        // polling future itself never enters the synchronous owners. Runtime or
        // kernel stalls are not preempted; every grant still checks real time.
        let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| Error::Unavailable)?;
        let mut terminate = signal(SignalKind::terminate()).map_err(|_| Error::Unavailable)?;
        let deadline = host.history_deadline()?;
        let original_host = host.clone();
        let mut startup = tokio::spawn(async move {
            let app_data = application_data()?;
            original_host.prepare_history(project, app_data).await
        });
        let (started, mut stop) = await_original(
            &mut startup,
            &mut interrupt,
            &mut terminate,
            &lease,
            deadline,
        )
        .await;
        let mut error = None;
        match started {
            Err(_) => {
                host.history_join_failed();
                error = Some(Error::StateUnknown);
            }
            Ok(Err(reason)) => error = Some(reason),
            Ok(Ok(ticket)) if stop.is_none() && lease.current().is_ok() => {
                // Consuming the admission ticket is a separate retained job
                // only AFTER the actual original startup joined. Publication
                // rechecks the original deadline after every lock/IO wait.
                let original_host = host.clone();
                let original_lease = lease.clone();
                let mut publish = tokio::spawn(async move {
                    let status = original_host.finish_history(ticket)?;
                    original_lease.current()?;
                    let id = status.project_ids.first().ok_or(Error::StateUnknown)?;
                    let line = format!("Foreground cached history for {}. Access ends at the original consent deadline; no fresh reads or actions.\n", id.as_str());
                    std::io::stdout()
                        .write_all(line.as_bytes())
                        .map_err(|_| Error::Unavailable)
                });
                let (published, reason) = await_original(
                    &mut publish,
                    &mut interrupt,
                    &mut terminate,
                    &lease,
                    deadline,
                )
                .await;
                stop = reason;
                match published {
                    Err(_) => {
                        host.history_join_failed();
                        error = Some(Error::StateUnknown);
                    }
                    Ok(Err(reason)) => error = Some(reason),
                    Ok(Ok(())) if stop.is_none() => {
                        stop = Some(
                            stopped(&mut interrupt, &mut terminate, &lease, lease.expires()).await,
                        );
                    }
                    Ok(Ok(())) => {}
                }
            }
            Ok(Ok(_)) => {} // Joined startup but no new grant after STOP.
        }
        lease.stop();
        match stop {
            Some(Err(_)) => {
                host.history_join_failed();
                error = Some(Error::StateUnknown);
            }
            Some(Ok(Stop::Signal | Stop::LeaseExpired))
                if matches!(error, Some(Error::AccessDenied | Error::Expired)) =>
            {
                error = None
            }
            Some(Ok(Stop::StartupExpired))
                if error.is_none() || matches!(error, Some(Error::AccessDenied)) =>
            {
                error = Some(Error::Expired)
            }
            _ => {}
        }
        // The fence is already latched before blocking cleanup. Same original
        // listener/all clients join, then same endpoint/Service/Store close.
        // A kernel-stalled call may outlast the deadline: no preemption claim.
        let report = host.shutdown().await;
        if !report.settled() {
            return Err(Error::StateUnknown);
        }
        error.map_or(Ok(()), Err)
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }
    #[test]
    fn serve_history_requires_exact_foreground_consent_and_bounded_native_path() {
        let Parsed::Serve(options) = parse(args(&[
            "--project",
            "/native/project",
            "--allow-history-read-seconds",
            "900",
        ]))
        .unwrap() else {
            panic!("not serve")
        };
        assert_eq!(options.project, PathBuf::from("/native/project"));
        assert_eq!(options.lifetime, Duration::from_secs(900));
        assert!(matches!(parse(args(&["--help"])), Ok(Parsed::Help)));
        for bad in [
            vec![],
            vec!["--project", "/native/project"],
            vec![
                "--project",
                "relative",
                "--allow-history-read-seconds",
                "30",
            ],
            vec![
                "--project",
                "/native/../project",
                "--allow-history-read-seconds",
                "30",
            ],
            vec![
                "--project",
                "/native/project",
                "--allow-history-read-seconds",
                "3601",
            ],
            vec![
                "--project",
                "/native/project",
                "--allow-history-read-seconds",
                "0",
            ],
            vec![
                "--project",
                "/native/project",
                "--allow-history-read-seconds",
                "030",
            ],
            vec![
                "--project",
                "/native/project",
                "--allow-history-read-seconds",
                "30",
                "--daemon",
            ],
        ] {
            assert!(parse(args(&bad)).is_err());
        }
        let path = format!("/{}", "x".repeat(4096));
        assert!(parse(args(&[
            "--project",
            &path,
            "--allow-history-read-seconds",
            "30"
        ]))
        .is_err());
    }
}
