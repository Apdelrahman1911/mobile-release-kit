//! Fixed Installer routing. Actual source, child and namespace authority remain
//! with their existing owners; argv cannot supply a path or renew a deadline.
use std::{ffi::OsString, time::Instant};
use crate::{macos_xcode_parent as parent, macos_xcode_setup as profile,
    macos_xcode_source::{self as source_api, SetupSource}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route { Setup, Carrier, Copier(i32) }

fn route(args: &[OsString]) -> Option<Route> {
    match args {
        [] => Some(Route::Setup),
        [flag] if flag == "--carrier-preflight" => Some(Route::Carrier),
        [flag, value] if flag == "--private-copier" => {
            let text=value.to_str()?;
            if text.is_empty() || text.len()>10 || text.starts_with('0')
                || !text.bytes().all(|c|c.is_ascii_digit()) { return None; }
            text.parse::<i32>().ok().filter(|fd|*fd>=3).map(Route::Copier)
        }
        _ => None,
    }
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a,b) { (Some(a),Some(b))=>Some(a.min(b)), (Some(a),None)|(None,Some(a))=>Some(a), _=>None }
}

fn public_exit(selected: Route, outcome: Option<parent::SetupOutcome>,
    settled: bool, source_settled: bool, source_accepted: bool,
    first_failure: Option<Instant>, unknown: bool, timely: bool) -> i32 {
    if !settled || !source_settled || !source_accepted || first_failure.is_some() || unknown || !timely {
        return 1;
    }
    match (selected,outcome) {
        (Route::Setup,Some(parent::SetupOutcome::Prepared)) |
        (Route::Carrier,Some(parent::SetupOutcome::CarrierChecked)) => 0,
        (Route::Setup,Some(parent::SetupOutcome::NeedsRerun)) => 75,
        _ => 1,
    }
}

fn source_diagnostic(stage: parent::Stage, error: source_api::Failure) -> parent::Diagnostic {
    use source_api::Failure as Source;
    use parent::Failure as Target;
    let failure = match error {
        Source::Shape | Source::Changed => Target::Binding,
        Source::Clock => Target::Clock, Source::Access => Target::Access,
        Source::Io => Target::Read, Source::Close => Target::Close, Source::Used => Target::State,
    };
    parent::Diagnostic { stage, failure }
}

fn public_call(selected: Route, started: Instant) -> (i32, Option<parent::Diagnostic>) {
    let (work,finish,hard)=match profile::entry_endpoints(started,selected==Route::Carrier) {
        Ok(value)=>value, Err(_)=>return (1, Some(parent::Diagnostic { stage: parent::Stage::Finality, failure: parent::Failure::Clock })),
    };
    let mut source=match SetupSource::new(work,finish) {
        Ok(value)=>value, Err(error)=>return (1, Some(source_diagnostic(parent::Stage::Source,error))),
    };
    let admitted=source.admit();
    let mut diagnostic=admitted.err().map(|error|source_diagnostic(parent::Stage::Source,error));
    let mut first=source.first_failure();
    let (outcome,settled,unknown,safe_to_settle_source)=if admitted.is_ok() {
        let result=match selected {
            Route::Setup=>parent::setup_once(&mut source,work,finish,hard),
            Route::Carrier=>parent::carrier_once(&mut source,work,finish,hard),
            Route::Copier(_)=>unreachable!(),
        };
        first=earliest(first,result.first_failure);
        diagnostic=diagnostic.or(result.diagnostic);
        (result.outcome,result.settled,result.unknown,result.safe_to_settle_source)
    } else {
        // Failed admission has no borrowed consumer; close its actual partial
        // source originals independently, using its earliest recorded failure.
        first=earliest(first,Some(Instant::now()));
        (None,true,false,true)
    };
    if !safe_to_settle_source {
        // No POST/close while an original consumer may still use these objects.
        // Actual process exit is not recorded as positive original settlement.
        std::mem::forget(source);
        return (1,diagnostic.or(Some(parent::Diagnostic {
            stage: parent::Stage::Finality, failure: parent::Failure::Unknown,
        })));
    }
    first=earliest(first,source.first_failure());
    if outcome.is_none() || unknown || !settled {
        first=earliest(first,Some(Instant::now()));
    }
    let closed=source.settle(first);
    diagnostic=diagnostic.or_else(||closed.err().map(|error|source_diagnostic(parent::Stage::SourceSettle,error)));
    first=earliest(first,source.first_failure());
    let now=Instant::now();
    let code=public_exit(selected,outcome,settled,closed.is_ok() && source.settled(),
        source.accepted(),first,unknown,now>=started && now<work);
    if code == 1 && diagnostic.is_none() {
        diagnostic=Some(parent::Diagnostic { stage: parent::Stage::Finality,
            failure: if now<started || now>=work { parent::Failure::Clock } else { parent::Failure::Unknown } });
    }
    (code,diagnostic)
}

pub(crate) fn entry() -> i32 {
    let started=Instant::now();
    // Valid routes have at most two items. Three is already an error, so no
    // unbounded collection or UTF-8 unwrap is needed for arbitrary argv.
    let args: Vec<_>=std::env::args_os().skip(1).take(3).collect();
    let Some(selected)=route(&args) else { return 64; };
    if let Route::Copier(fd)=selected {
        // This parses no public clocks. The existing private entry requires
        // the real peer, inherited originals and original transferred deadlines.
        return parent::copier_entry(fd);
    }
    let (code,diagnostic)=public_call(selected,started);
    let message=match code {
        75=>"MRK Xcode setup: unfinished copy cleanup completed. Open this same signed package again to prepare Xcode.\n".to_owned(),
        0=>String::new(),
        _=>diagnostic.map(|value|value.line(parent::DiagnosticScope::Public)).unwrap_or_else(||
            "MRK Xcode setup refused or remains unconfirmed. Preserve the setup files; no prepared-tool success is claimed.\n".to_owned()),
    };
    if !message.is_empty() {
        // One bounded best-effort diagnostic, not a future-exit receipt. It
        // contains no exception, path, credential, source value or private frame.
        let _=std::io::Write::write(&mut std::io::stderr().lock(),message.as_bytes());
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_entry_routing_never_accepts_paths_clocks_or_noncanonical_fds() {
        let parse=|values:&[&str]|route(&values.iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(parse(&[]),Some(Route::Setup));
        assert_eq!(parse(&["--carrier-preflight"]),Some(Route::Carrier));
        assert_eq!(parse(&["--private-copier","3"]),Some(Route::Copier(3)));
        assert_eq!(parse(&["--private-copier","2147483647"]),Some(Route::Copier(i32::MAX)));
        for value in ["", "0", "2", "03", "+3", "-3", "3 ", "3.0", "2147483648", "99999999999", "/tmp/3"] {
            assert_eq!(parse(&["--private-copier",value]),None);
        }
        for values in [vec!["--carrier-preflight","3"],vec!["--private-copier"],
            vec!["--private-copier","3","extra"],vec!["--setup"],vec!["/tmp/Xcode.app"]] {
            assert_eq!(parse(&values),None);
        }
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(route(&["--private-copier".into(),OsString::from_vec(vec![0xff])]),None);
    }
    #[test]
    fn public_exit_requires_original_finality_and_distinguishes_cleanup() {
        use parent::SetupOutcome::{Prepared,NeedsRerun,CarrierChecked};
        let exit=|route,outcome|public_exit(route,Some(outcome),true,true,true,None,false,true);
        assert_eq!(exit(Route::Setup,Prepared),0);
        assert_eq!(exit(Route::Carrier,CarrierChecked),0);
        assert_eq!(exit(Route::Setup,NeedsRerun),75);
        assert_eq!(exit(Route::Setup,CarrierChecked),1);
        assert_eq!(exit(Route::Carrier,Prepared),1);
        assert_eq!(exit(Route::Carrier,NeedsRerun),1);
        assert_eq!(exit(Route::Copier(3),Prepared),1);
        for outcome in [Prepared,NeedsRerun,CarrierChecked] {
            for (settled,closed,accepted,first,unknown,timely) in [
                (false,true,true,None,false,true),(true,false,true,None,false,true),
                (true,true,false,None,false,true),(true,true,true,Some(Instant::now()),false,true),
                (true,true,true,None,true,true),(true,true,true,None,false,false),
            ] {
                assert_eq!(public_exit(Route::Setup,Some(outcome),settled,closed,accepted,first,unknown,timely),1);
            }
        }
        let start=Instant::now();
        for (carrier,seconds) in [(false,[3600,3720,3730]),(true,[450,570,580])] {
            let (w,f,h)=profile::entry_endpoints(start,carrier).unwrap();
            assert_eq!([w.duration_since(start).as_secs(),f.duration_since(start).as_secs(),h.duration_since(start).as_secs()],seconds);
        }
        let early=start-std::time::Duration::from_secs(1);
        assert_eq!(earliest(Some(start),Some(early)),Some(early));
        assert_eq!(earliest(None,Some(start)),Some(start));
    }
}
