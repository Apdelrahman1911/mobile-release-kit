//! Native-only conversions for exactly the unsigned/archive and signed/export
//! modes of the existing agent iOS owner. This is not a second Start path.
use super::*;

pub(super) fn compact_policy(input: &mut ios_wire::Prepare) {
    let Some(p) = &mut input.signing else {
        return;
    };
    fn compact(s: &mut String) {
        *s = std::mem::take(s).into_boxed_str().into_string();
    }
    compact(&mut p.team_id);
    compact(&mut p.distribution_certificate_sha256);
    for a in &mut p.assignments {
        compact(&mut a.kind);
        compact(&mut a.record_id);
    }
    p.assignments = std::mem::take(&mut p.assignments)
        .into_boxed_slice()
        .into_vec();
}

/// Added bounded comparison graph only. The original native material and its
/// bodies stay in the existing Asset/Saved operation census. Include one
/// simultaneous Context policy copy and the retained public summary.
pub(super) fn approval_backing(input: &ios_wire::Prepare, review: &agent::Review) -> Option<usize> {
    match (&input.signing, &review.signing) {
        (None, None) => Some(0),
        (Some(p), Some(r)) if p.assignments.capacity() <= 4 && r.capacity_valid() => {
            let mut heap = p
                .team_id
                .capacity()
                .checked_add(p.distribution_certificate_sha256.capacity())?
                .checked_add(
                    p.assignments
                        .capacity()
                        .checked_mul(std::mem::size_of::<ios_wire::SigningAssignment>())?,
                )?;
            for a in &p.assignments {
                heap = heap
                    .checked_add(a.kind.capacity())?
                    .checked_add(a.record_id.capacity())?;
            }
            heap.checked_mul(2)?
                .checked_add(r.heap_bytes()?)?
                .checked_add(
                    std::mem::size_of::<ios_wire::SigningPolicy>()
                        + std::mem::size_of::<agent::signed::Review>(),
                )
        }
        _ => None,
    }
}

pub(super) fn mode(c: &ios_wire::Context) -> Option<agent::Mode> {
    if c.recovery.is_some()
        || c.action.is_some()
        || c.draft_revision.is_none()
        || c.baseline_generation.is_none()
        || c.saved_config.is_none()
        || c.saved_version.is_none()
    {
        return None;
    }
    match (c.operation, c.signing.is_some()) {
        (ios_wire::Operation::IOSUnsignedArchive, false) => {
            Some(agent::Mode::SavedIosUnsignedArchive)
        }
        (ios_wire::Operation::IOSSignedExport, true) => Some(agent::Mode::SavedIosSignedExport),
        _ => None,
    }
}

pub(super) fn review(c: &ios_wire::Context) -> Result<agent::Review, BridgeError> {
    let mode = mode(c).ok_or_else(failure)?;
    let config = c.saved_config.as_ref().ok_or_else(failure)?;
    let signing = c.signing.as_ref().map(|p| agent::signed::Review {
        team_id: p.team_id.as_str().to_owned(),
        distribution_certificate_sha256: p.distribution_certificate_sha256.as_str().to_owned(),
        firebase: p.assignments.iter().any(|a| a.kind == "ios-firebase"),
        project_read_token: p.assignments.iter().any(|a| a.kind == "project-read-token"),
    });
    let result = agent::Review {
        mode,
        signing,
        saved_config: agent::Config {
            bytes: config.bytes,
            sha256: config.sha256.as_str().to_owned(),
        },
        saved_version: version(c.saved_version.as_ref().ok_or_else(failure)?),
    };
    if !result.valid() || result.signing.as_ref().is_some_and(|s| !s.capacity_valid()) {
        return Err(failure());
    }
    Ok(result)
}

pub(super) fn report(
    c: &ios_wire::Context,
    value: &ios_wire::ResultValue,
) -> Result<agent::Report, BridgeError> {
    // This is the already-validated native terminal, not a CLI-supplied path
    // or signed flag. Provisional terminal data is never public finality.
    let v = value.ordinary_build().ok_or_else(failure)?;
    let (scope, export) = match mode(c).ok_or_else(failure)? {
        agent::Mode::SavedIosUnsignedArchive
            if v.ipa.is_none() && v.ipa_bytes.is_none() && v.pairing.is_none() =>
        {
            (agent::Scope::LocalUnsignedIosArchiveObservation, None)
        }
        agent::Mode::SavedIosSignedExport if v.ipa.is_some() => {
            let p = v.pairing.as_ref().ok_or_else(failure)?;
            (
                agent::Scope::LocalSignedIosArtifactValidation,
                Some(agent::signed::Export {
                    ipa_bytes: v.ipa_bytes.ok_or_else(failure)?,
                    pairing: agent::signed::Pairing {
                        native_paths: p.native_paths,
                        native_identities: p.native_identities,
                        present_symbol_slices: p.present_symbol_slices,
                    },
                }),
            )
        }
        _ => return Err(failure()),
    };
    let result = agent::Report {
        scope,
        export,
        used_config: agent::Config {
            bytes: v.used_config.bytes,
            sha256: v.used_config.sha256.as_str().to_owned(),
        },
        used_version: version(&v.used_version),
        entries: v.entries,
        bytes: v.bytes,
    };
    if !result.valid() {
        return Err(failure());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_exact_export_mode_uses_signed_consent_summary_not_candidate_check_or_recovery() {
        let c = ios_wire::tests::signed_context();
        let r = review(&c).unwrap();
        assert_eq!(r.mode, agent::Mode::SavedIosSignedExport);
        let summary = r.signing.unwrap();
        assert_eq!(summary.team_id, c.signing.as_ref().unwrap().team_id);
        assert!(!summary.firebase && !summary.project_read_token);
        for operation in [
            ios_wire::Operation::IOSUnsignedArchive,
            ios_wire::Operation::IOSCandidateInputs,
            ios_wire::Operation::IOSSigningInputsCheck,
            ios_wire::Operation::IOSLocalRecovery,
        ] {
            let mut wrong = c.clone();
            wrong.operation = operation;
            assert!(mode(&wrong).is_none());
        }
        let mut no_policy = c.clone();
        no_policy.signing = None;
        assert!(mode(&no_policy).is_none());
        let mut partial = c.clone();
        partial.saved_version = None;
        assert!(mode(&partial).is_none());
        let mut candidate = c.clone();
        candidate.action = Some(ios_wire::CreateAction::Create);
        assert!(mode(&candidate).is_none());
        assert!(review(&ios_wire::tests::context())
            .unwrap()
            .signing
            .is_none());
    }

    #[test]
    fn actual_signed_terminal_decoder_precedes_sanitized_report_and_original_retirement() {
        let c = ios_wire::tests::signed_context();
        let raw = ios_wire::tests::signed_complete();
        let terminal = ios_wire::terminal(&raw, &c, &"a".repeat(32)).unwrap();
        let report = report(&c, terminal.result.as_ref().unwrap()).unwrap();
        assert_eq!(report.export.as_ref().unwrap().ipa_bytes, 512);
        assert_eq!(report.export.as_ref().unwrap().pairing.native_paths, 1);
        let public = serde_json::to_value(&report).unwrap();
        assert!(public.get("archive").is_none() && public.get("ipa").is_none());
        assert!(public.get("signing").is_none() && public.get("sha256").is_none());
        assert!(serde_json::to_vec(&report).unwrap().len() < agent::REPORT_LIMIT);
        let p = RunProjection {
            agent_build: None,
            agent_local_check: None,
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context: Context::IOSArchive(c.clone()),
            phase: Phase::Stopping,
            intent_usable: false,
            outcome: Some(Outcome::Complete),
            reason: Reason::None,
            stage: Some(Stage::IOSArchive(ios_wire::Stage::DisposingWork)),
            result: Some(Terminal::IOSArchive(terminal)),
        };
        let provisional = projection(&p, 3, false).unwrap();
        assert_eq!(provisional.settlement, service::Settlement::Pending);
        assert!(provisional.result.is_none());
        let mut retired = p;
        retired.phase = Phase::Terminal;
        let final_data = projection(&retired, 4, true).unwrap();
        assert!(final_data.valid_for(&review(&c).unwrap()));
        assert!(!final_data.valid_for(&review(&ios_wire::tests::context()).unwrap()));
        for field in [
            "inputClosed",
            "signingClosed",
            "buildInputsClosed",
            "materialRetired",
            "invocationClosed",
        ] {
            let mut bad = raw.clone();
            bad["lifetime"][field] = json!(false);
            assert!(
                ios_wire::terminal(&bad, &c, &"a".repeat(32)).is_err(),
                "{field}"
            );
        }
        retired.phase = Phase::Unknown;
        let unknown = projection(&retired, 5, false).unwrap();
        assert_eq!(unknown.settlement, service::Settlement::Unknown);
        assert!(unknown.result.is_none());
    }
}
