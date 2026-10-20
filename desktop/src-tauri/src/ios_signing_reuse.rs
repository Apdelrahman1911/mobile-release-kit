//! Closed comparison DATA for the existing IOSArchive owner's signing-input
//! check. This module owns no tools, private material, process or assignment.
//! A validated terminal still requires the SAME original native joins.

use super::*;

pub(crate) const PROTOCOL: &str = "mrk-ios-signing-inputs-check/1";
pub(crate) const CONSENT: &str = "saved-ios-signing-inputs-check-v1";
pub(crate) const SCOPE: &str = "local-ios-signing-inputs-validation";
pub(crate) const INTENT_SECONDS: u64 = 60;
pub(crate) const WORK_SECONDS: u64 = 300;
pub(crate) const FINALITY_SECONDS: u64 = 310;
pub(crate) const COMMAND_LIMIT: u32 = 7;
pub(crate) const PROFILE_LIMIT: u32 = 1;
pub(crate) const MAX_FRAMES: usize = 6;
const LIMITATIONS: [&str; 8] = [
    "saved-inputs-not-atomic",
    "single-primary-profile",
    "offline-not-live-revocation",
    "no-build-or-installed-signing-session",
    "no-provider-operation",
    "historical-input-check-not-credential-assignment",
    "release-readiness-not-assessed",
    "core-terminal-requires-original-native-finality",
];

pub(super) fn findings(rows: &[Finding]) -> bool {
    rows.len() <= 4
        && rows.iter().enumerate().all(|(index, row)| {
            matches!(
                row.check,
                CheckId::SigningMaterial
                    | CheckId::ProfileMaterial
                    | CheckId::FirebaseMaterial
                    | CheckId::OtherCoreFinding
            ) && rows[..index].iter().all(|prior| prior.check != row.check)
        })
}

pub(super) fn complete_findings(context: &Context, rows: &[Finding]) -> bool {
    let Some(signing) = &context.signing else {
        return false;
    };
    let firebase = signing
        .assignments
        .iter()
        .any(|row| row.kind == "ios-firebase");
    context.signing_check()
        && findings(rows)
        && rows.len() == (if firebase { 3 } else { 2 })
        && [CheckId::SigningMaterial, CheckId::ProfileMaterial]
            .into_iter()
            .chain(firebase.then_some(CheckId::FirebaseMaterial))
            .all(|check| {
                rows.iter()
                    .any(|row| row.check == check && row.status == CoreStatus::Pass)
            })
}

pub(super) fn no_artifacts(value: &Disposition) -> bool {
    value.snapshot == SnapshotDisposition::NotCreated
        && value.work == WorkDisposition::NotCreated
        && value.output == OutputDisposition::NotCreated
        && value.relative_directory.is_none()
}

// Canonical UTC seconds are historical comparison DATA, not a native clock or
// freshness receipt. Match Python's actual calendar parsing, including years.
fn timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| ![4, 7, 10, 13, 16, 19].contains(&i) && !b.is_ascii_digit())
    {
        return false;
    }
    let number = |a: usize, b: usize| {
        bytes[a..b]
            .iter()
            .fold(0_u32, |n, digit| n * 10 + u32::from(digit - b'0'))
    };
    let (year, month, day) = (number(0, 4), number(5, 7), number(8, 10));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    year > 0
        && (1..=days).contains(&day)
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    schema_version: u32,
    scope: String,
    checked_at: String,
    used_config: Content,
    used_version: SavedVersion,
    used_signing: SigningPolicy,
    pub(super) checks: Vec<Finding>,
    limitations: Vec<String>,
}
impl ResultData {
    pub(super) fn valid(&self, context: &Context) -> bool {
        context.signing_check()
            && self.schema_version == 1
            && self.scope == SCOPE
            && timestamp(&self.checked_at)
            && context.saved_config.as_ref() == Some(&self.used_config)
            && context.saved_version.as_ref() == Some(&self.used_version)
            && context.signing.as_ref() == Some(&self.used_signing)
            && complete_findings(context, &self.checks)
            && self.limitations == LIMITATIONS
    }
}

/// The caller supplies comparison facts from its original project, fixed
/// system-tool book and selected private material. This helper grants none.
pub(crate) fn request(
    operation: &str,
    generation: &str,
    context: &Context,
    profile: Profile,
    project: &RegisteredRoot,
    cwd: &Path,
    openssl: &ToolIdentity,
    signing_context: &Content,
) -> Result<Vec<u8>, BridgeError> {
    if !token(operation)
        || !token(generation)
        || !context.valid()
        || !context.signing_check()
        || !openssl.valid()
        || openssl.uid != 0
        || openssl.mode & 0o022 != 0
        || !signing_context.valid(512 * 1024)
    {
        return Err(invalid());
    }
    let observed = project
        .identity
        .posix()
        .map_err(|_| invalid())?
        .preflight_identity();
    let identity = RootIdentity {
        device: observed.device,
        inode: observed.inode,
        mode: observed.mode,
        uid: observed.uid,
        gid: observed.gid,
    };
    if !identity.valid() {
        return Err(invalid());
    }
    let data = json!({"protocol": PROTOCOL, "operationId": operation, "ownerGeneration": generation,
        "context": context, "native": {"profile": profile,
            "projectRoot": native_path(&project.path).ok_or_else(invalid)?, "rootIdentity": identity,
            "cwd": native_path(cwd).ok_or_else(invalid)?, "openssl": openssl, "signingContext": signing_context}});
    if !structure(&data) {
        return Err(invalid());
    }
    let mut bytes = bounded(&data, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    // Synthetic DATA only. No real credential, native tool, CMS, process or
    // runtime is inspected. Passing does not qualify the native mode.
    use super::*;

    pub(super) fn context() -> Context {
        let mut value = super::super::tests::signed_context();
        value.operation = Operation::IOSSigningInputsCheck;
        value.action = Some(CreateAction::CheckSigning);
        assert!(value.valid());
        value
    }
    fn complete() -> Value {
        let selected = context();
        let checks = json!([{"check":"signing-material","status":"PASS"},
            {"check":"profile-material","status":"PASS"}]);
        json!({"schemaVersion":1,"context":selected,"outcome":"complete","reason":"none",
            "activity":{"stage":"checking-inputs","findings":checks},
            "disposition":{"snapshot":"not-created","work":"not-created","output":"not-created","relativeDirectory":null},
            "result":{"schemaVersion":1,"scope":SCOPE,"checkedAt":"2026-10-20T12:34:56Z",
                "usedConfig":selected.saved_config,"usedVersion":selected.saved_version,"usedSigning":selected.signing,
                "checks":checks,"limitations":LIMITATIONS},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,
                "commands":5,"profileCalls":1,"stopObserved":"none","inputClosed":true,"handlersRestored":true,
                "invocationClosed":true,"snapshotClosed":true,"filesClosed":true,"namespaceClosed":true,
                "signingClosed":true,"buildInputsClosed":true,"materialRetired":true}})
    }
    fn check(value: &Value) -> Result<Terminal, BridgeError> {
        terminal(value, &context(), &"a".repeat(32))
    }

    #[test]
    fn check_requires_its_exact_action_private_roster_and_consent() {
        let selected = context();
        let mut raw = json!(selected);
        raw.as_object_mut().unwrap().remove("operation");
        raw.as_object_mut().unwrap().remove("platform");
        assert_eq!(prepare(&raw).unwrap().context(), selected);
        for action in [Value::Null, json!("create"), json!("inspect")] {
            let mut wrong = json!(selected);
            wrong["action"] = action;
            assert!(!Context::deserialize(&wrong).is_ok_and(|context| context.valid()));
        }
        let mut token_input = raw;
        token_input["signing"]["assignments"].as_array_mut().unwrap().push(json!({
            "kind":"project-read-token","recordId":"3".repeat(32),"recordRevision":1,"contextRevision":3}));
        assert!(prepare(&token_input).is_err());
        for consent in [
            CONSENT,
            super::super::CONSENT,
            SIGNED_CONSENT,
            CANDIDATE_CONSENT,
            RECOVERY_CONSENT,
        ] {
            let start = start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).unwrap();
            assert_eq!(start.consent_matches(&selected), consent == CONSENT);
        }
    }

    #[test]
    fn check_result_is_historical_and_not_an_artifact_or_assignment() {
        let value = complete();
        assert!(check(&value).is_ok());
        for field in ["usedConfig", "usedVersion", "usedSigning"] {
            let mut wrong = value.clone();
            if field == "usedSigning" {
                wrong["result"][field]["assignments"][0]["recordRevision"] = json!(2);
            } else {
                wrong["result"][field]["sha256"] = json!("f".repeat(64));
            }
            assert!(check(&wrong).is_err(), "{field}");
        }
        for field in [
            "certificateBinding",
            "releaseReady",
            "archive",
            "profileContent",
            "privateKey",
        ] {
            let mut wrong = value.clone();
            wrong["result"][field] = json!("not-authority");
            assert!(check(&wrong).is_err(), "{field}");
        }
        let mut wrong = value;
        wrong["disposition"]["work"] = json!("removed");
        assert!(check(&wrong).is_err());
    }

    #[test]
    fn every_original_close_and_exact_finite_counts_veto_complete() {
        let value = complete();
        for field in [
            "inputClosed",
            "handlersRestored",
            "invocationClosed",
            "snapshotClosed",
            "filesClosed",
            "namespaceClosed",
            "signingClosed",
            "buildInputsClosed",
            "materialRetired",
            "contained",
            "complete",
        ] {
            let mut wrong = value.clone();
            wrong["lifetime"][field] = json!(false);
            assert!(check(&wrong).is_err(), "{field}");
        }
        for count in [0, 1, 4, 8, 4096] {
            let mut wrong = value.clone();
            wrong["lifetime"]["commands"] = json!(count);
            assert!(check(&wrong).is_err());
        }
        for count in [0, 2, 3, 1024] {
            let mut wrong = value.clone();
            wrong["lifetime"]["profileCalls"] = json!(count);
            assert!(check(&wrong).is_err());
        }
        for stop in ["cancelled", "timed-out"] {
            let mut wrong = value.clone();
            wrong["lifetime"]["stopObserved"] = json!(stop);
            assert!(check(&wrong).is_err());
        }
        let mut fallback = value;
        fallback["lifetime"]["commands"] = json!(7);
        assert!(check(&fallback).is_ok());
    }

    #[test]
    fn raw_frames_keep_the_new_mode_and_fixed_stage_sequence() {
        let selected = context();
        let op = "a".repeat(32);
        let generation = "b".repeat(32);
        let frame = |sequence, kind, payload| {
            let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":op,
                "ownerGeneration":generation,"sequence":sequence,"kind":kind,"payload":payload}))
            .unwrap();
            bytes.push(b'\n');
            bytes
        };
        let mut decoder = FrameDecoder::new(&op, &generation, &selected).unwrap();
        assert!(decoder
            .push(&frame(
                0,
                "accepted",
                json!({"schemaVersion":1,"context":selected})
            ))
            .is_ok());
        for (i, stage) in [
            "inputs-bound",
            "checking-signing-tools",
            "validating-signing",
            "checking-inputs",
        ]
        .iter()
        .enumerate()
        {
            assert!(decoder
                .push(&frame(
                    (i + 1) as u32,
                    "progress",
                    json!({"schemaVersion":1,"stage":stage})
                ))
                .is_ok());
        }
        assert!(matches!(
            decoder.push(&frame(5, "terminal", complete())),
            Ok(Frame::Terminal(_))
        ));
        assert!(decoder.push(&frame(6, "terminal", complete())).is_err());
        for stage in [
            Stage::CheckingXcode,
            Stage::Preparing,
            Stage::Archiving,
            Stage::MaterializingSigning,
            Stage::Exporting,
            Stage::DisposingWork,
            Stage::RecoveringAccount,
        ] {
            assert!(!stage.valid(&selected));
        }
        for old in [
            super::super::tests::context(),
            super::super::tests::signed_context(),
            super::super::tests::recovery_context(),
        ] {
            assert!(!Stage::CheckingSigningTools.valid(&old));
            assert!(!Stage::CheckingInputs.valid(&old));
        }
    }

    #[test]
    fn incomplete_native_status_never_projects_success() {
        let value = check(&complete()).unwrap();
        let projection = Projection {
            operation_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            context: context(),
            phase: Phase::Terminal,
            intent_usable: false,
            outcome: Some(Outcome::Complete),
            reason: Reason::None,
            stage: Some(Stage::CheckingInputs),
            activity: Some(value.activity),
            disposition: value.disposition,
            result: value.result,
            report: None,
        };
        assert!(projection.valid());
        for phase in [
            Phase::Starting,
            Phase::Running,
            Phase::Stopping,
            Phase::Unknown,
        ] {
            let mut pending = projection.clone();
            pending.phase = phase;
            assert!(!pending.valid());
        }
        assert!(matches!(
            projection.result.as_ref(),
            Some(ResultValue::SigningCheck(_))
        ));
        assert!(projection
            .result
            .as_ref()
            .unwrap()
            .ordinary_build()
            .is_none());
    }

    #[test]
    fn timestamp_and_findings_refuse_ambiguous_or_incomplete_comparisons() {
        assert!(timestamp("2024-02-29T00:00:00Z"));
        for value in [
            "0000-01-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-10-20T24:00:00Z",
            "2026-10-20T01:01:60Z",
            "2026-10-20T01:01:01+00:00",
        ] {
            assert!(!timestamp(value), "{value}");
        }
        for change in ["duplicate", "extra", "failed"] {
            let mut value = complete();
            match change {
                "duplicate" => {
                    value["activity"]["findings"][1] = value["activity"]["findings"][0].clone()
                }
                "extra" => value["activity"]["findings"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"check":"firebase-material","status":"PASS"})),
                _ => value["activity"]["findings"][0]["status"] = json!("FAIL"),
            }
            value["result"]["checks"] = value["activity"]["findings"].clone();
            assert!(check(&value).is_err(), "{change}");
        }
    }
}
