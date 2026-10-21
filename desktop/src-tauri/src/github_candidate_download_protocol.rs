//! Closed primary-export DATA and same-original diagnostic cell. No transport,
//! path picker, credential or lifecycle authority is constructed by parsing.
use super::*;
use std::sync::{Arc, Mutex};

pub(crate) const CONSENT: &str = "github-candidate-primary-download-v1";
pub(crate) const RECEIPT: &str = "download-receipt.json";
pub(crate) const PRIMARY_LIMIT: u64 = 1024 * 1024 * 1024;
pub(crate) const RECEIPT_LIMIT: usize = 4096;
pub(crate) const DESTINATION_RESERVE: u64 = PRIMARY_LIMIT + 1024 * 1024;
// Same bounded Seed,128 nodes charged at1024B INCLUDING key/map/list backing;
// two64KiB streaming blocks, one additional full retained Result and32KiB for
// the complete fixed State/Trace/pins/paths/receipt/raw+typed overlap. This is
// added only to this original's containing admission, not a new capacity cap.
pub(crate) const RECEIPT_PARSE_RESERVE: usize = 128 * 1024;
pub(crate) const CONTROL_RESERVE: usize =
    2 * 65536 + RECEIPT_PARSE_RESERVE + RETAINED_REPLY_LIMIT + 32 * 1024;

pub(crate) fn names(selection: &Selection) -> Option<(String, String, &'static str)> {
    if !selection.valid() || selection.stage != Stage::Candidate {
        return None;
    }
    let (platform, primary) = match selection.platform {
        Platform::Android => ("android", "app-release.aab"),
        Platform::Ios => ("ios", "app.ipa"),
    };
    let name = format!(
        "candidate-{}-attempt-{}-{platform}",
        selection.run_id, selection.attempt
    );
    Some((name.clone(), format!(".{name}.pending"), primary))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Args {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) selection: Selection,
    consent_version: String,
    confirmed: bool,
}
impl Args {
    pub(crate) fn into_start(self) -> Result<StartArgs, BridgeError> {
        if self.consent_version != CONSENT
            || !self.confirmed
            || names(&self.selection).is_none()
            || !valid_id(&self.session_id)
            || !revision(self.expected_revision)
            || !revision(self.expected_connection_revision)
        {
            return Err(BridgeError::invalid());
        }
        Ok(StartArgs {
            session_id: self.session_id,
            expected_revision: self.expected_revision,
            expected_connection_revision: self.expected_connection_revision,
            selection: self.selection,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Pins {
    pub(crate) consent_version: String,
    pub(crate) parent_identity: DirectoryIdentity,
    pub(crate) staging_identity: DirectoryIdentity,
    pub(crate) primary_identity: FileIdentity,
    pub(crate) receipt_identity: FileIdentity,
}
impl Pins {
    pub(crate) fn valid(&self) -> bool {
        let dirs = [&self.parent_identity, &self.staging_identity];
        let files = [&self.primary_identity, &self.receipt_identity];
        let keys = [
            (&dirs[0].device, &dirs[0].inode),
            (&dirs[1].device, &dirs[1].inode),
            (&files[0].device, &files[0].inode),
            (&files[1].device, &files[1].inode),
        ];
        self.consent_version == CONSENT
            && dirs
                .iter()
                .all(|v| v.valid() && v.mode == 0o40700 && v.uid == dirs[0].uid)
            && files.iter().all(|v| {
                v.valid(0, false) && v.mode == 0o100600 && v.flags == 0 && v.uid == dirs[0].uid
            })
            && keys
                .iter()
                .enumerate()
                .all(|(i, key)| !keys[..i].contains(key))
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.consent_version
            .capacity()
            .checked_add(self.parent_identity.retained_heap_bytes()?)?
            .checked_add(self.staging_identity.retained_heap_bytes()?)?
            .checked_add(self.primary_identity.retained_heap_bytes()?)?
            .checked_add(self.receipt_identity.retained_heap_bytes()?)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Candidate {
    pub(crate) primary_sha256: String,
    pub(crate) primary_bytes: u64,
    pub(crate) receipt_sha256: String,
    pub(crate) receipt_bytes: u32,
}
impl Candidate {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.primary_sha256, 64)
            && (1..=PRIMARY_LIMIT).contains(&self.primary_bytes)
            && hex(&self.receipt_sha256, 64)
            && (1..=RECEIPT_LIMIT as u32).contains(&self.receipt_bytes)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.primary_sha256
            .capacity()
            .checked_add(self.receipt_sha256.capacity())
    }
}

pub(crate) fn result_eligible(result: &ResultData) -> bool {
    result.valid()
        && result.context.selection.stage == Stage::Candidate
        && result.verification == Verification::Verified
        && result
            .evidence
            .as_ref()
            .is_some_and(|v| matches!(v.outcome, Outcome::Mutated | Outcome::Reconciled))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    assurance: String,
    context: Context,
    authorized_by: Authority,
    artifact_id: String,
    artifact_sha256: String,
    candidate_manifest_sha256: String,
    operation_intent_sha256: String,
    provenance_sha256: String,
    primary: Primary,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Primary {
    file_name: String,
    bytes: u64,
    sha256: String,
}
pub(crate) fn receipt_matches(raw: &[u8], candidate: &Candidate, result: &ResultData) -> bool {
    use serde::de::DeserializeSeed;
    if raw.is_empty() || raw.len() > RECEIPT_LIMIT || !candidate.valid() || !result_eligible(result)
    {
        return false;
    }
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let mut count = 0usize;
    // Reject hostile small containers BEFORE allocating each next node. Old
    // public/History decoders are untouched; this is a fixed local receipt.
    let Ok(value) = (crate::bounded_json_seed::Seed {
        nodes: &mut count,
        depth: 0,
        node_limit: 128,
        depth_limit: 6,
    })
    .deserialize(&mut decoder) else {
        return false;
    };
    if decoder.end().is_err() || !nodes(&value) || !value.is_object() {
        return false;
    }
    let Ok(receipt) = serde_json::from_value::<Receipt>(value) else {
        return false;
    };
    let Some(evidence) = &result.evidence else {
        return false;
    };
    let Some((_, _, primary)) = names(&result.context.selection) else {
        return false;
    };
    receipt.schema_version == 1
        && receipt.assurance == "authenticated-historical-candidate-only"
        && receipt.context == result.context
        && receipt.authorized_by == evidence.authorized_by
        && numeric_id(&receipt.artifact_id)
        && hex(&receipt.artifact_sha256, 64)
        && receipt.candidate_manifest_sha256 == evidence.candidate_manifest_sha256
        && receipt.operation_intent_sha256 == evidence.operation_intent_sha256
        && receipt.provenance_sha256 == evidence.provenance_sha256
        && receipt.primary.file_name == primary
        && receipt.primary.bytes == candidate.primary_bytes
        && receipt.primary.sha256 == candidate.primary_sha256
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Publication {
    NotEntered,
    Entered,
    Refused,
    Published,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Durability {
    NotEntered,
    Entered,
    Durable,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Effect {
    pub(crate) relative_path: String,
    pub(crate) pending_path: String,
    pub(crate) publication: Publication,
    pub(crate) durability: Durability,
    pub(crate) closed: bool,
}
impl Effect {
    pub(crate) fn valid(&self, selection: &Selection) -> bool {
        names(selection).is_some_and(|(final_name, pending, _)| {
            self.relative_path == format!("release/downloads/{final_name}")
                && self.pending_path == format!("release/downloads/{pending}")
        }) && (self.publication == Publication::Published
            || self.durability == Durability::NotEntered)
            && (!self.closed
                || !matches!(
                    self.publication,
                    Publication::Entered | Publication::Unknown
                ) && !matches!(self.durability, Durability::Entered | Durability::Unknown))
    }
    pub(crate) fn exported(&self) -> bool {
        self.publication == Publication::Published
            && self.durability == Durability::Durable
            && self.closed
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.relative_path
            .capacity()
            .checked_add(self.pending_path.capacity())
    }
}

/// Only comparison DATA. Actual Resources/SourceBook still own every effect
/// and join. This cell survives the success-only Result being cleared.
pub(crate) struct Trace {
    effect: Mutex<Effect>,
}
impl Trace {
    pub(crate) fn new(selection: &Selection) -> Result<Arc<Self>, BridgeError> {
        let (name, pending, _) = names(selection).ok_or_else(BridgeError::invalid)?;
        Ok(Arc::new(Self {
            effect: Mutex::new(Effect {
                relative_path: format!("release/downloads/{name}"),
                pending_path: format!("release/downloads/{pending}"),
                publication: Publication::NotEntered,
                durability: Durability::NotEntered,
                closed: false,
            }),
        }))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Effect> {
        self.effect.lock().unwrap_or_else(|error| {
            let mut v = error.into_inner();
            // Preserve a positively returned rename; unknown is absorbing.
            if v.publication != Publication::Published {
                v.publication = Publication::Unknown;
            } else {
                v.durability = Durability::Unknown;
            }
            v.closed = false;
            v
        })
    }
    pub(crate) fn snapshot(&self) -> Effect {
        self.lock().clone()
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.lock().retained_bytes()?)
    }
    pub(crate) fn enter(&self) -> bool {
        let mut value = self.lock();
        if value.publication != Publication::NotEntered || value.closed {
            return false;
        }
        value.publication = Publication::Entered;
        true
    }
    pub(crate) fn returned(&self, applied: bool, collision: bool) {
        let mut value = self.lock();
        if value.publication != Publication::Entered {
            // A contradictory/late DATA callback cannot erase actual publication.
            if value.publication == Publication::Published {
                value.durability = Durability::Unknown;
            } else {
                value.publication = Publication::Unknown;
            }
            value.closed = false;
            return;
        }
        value.publication = if applied {
            Publication::Published
        } else if collision {
            Publication::Refused
        } else {
            Publication::Unknown
        };
    }
    pub(crate) fn sync_entered(&self) -> bool {
        let mut value = self.lock();
        if value.publication != Publication::Published || value.durability != Durability::NotEntered
        {
            return false;
        }
        value.durability = Durability::Entered;
        true
    }
    pub(crate) fn sync_returned(&self, positive: bool) {
        let mut value = self.lock();
        value.durability = if positive && value.durability == Durability::Entered {
            Durability::Durable
        } else {
            Durability::Unknown
        };
    }
    pub(crate) fn closed(&self, known: bool) {
        let mut value = self.lock();
        value.closed = known
            && !matches!(
                value.publication,
                Publication::Entered | Publication::Unknown
            )
            && !matches!(value.durability, Durability::Entered | Durability::Unknown);
    }
}

pub(crate) fn work_permits(
    now: std::time::Instant,
    end: std::time::Instant,
    first_failure: bool,
    stop: bool,
    current: bool,
) -> bool {
    now < end && !first_failure && !stop && current
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn selection() -> Selection {
        Selection {
            run_id: "123".into(),
            attempt: 2,
            stage: Stage::Candidate,
            platform: Platform::Android,
        }
    }
    // Strict in-memory DTOs only. No Original, ticket, receipt, IO or provider
    // is minted by these fixtures; the production driver remains the authority.
    fn result() -> ResultData {
        let selected = selection();
        let context = Context {
            schema_version: 1,
            project_binding: "a".repeat(64),
            config_sha256: "b".repeat(64),
            repository: "owner/repository".into(),
            repository_id: "1".into(),
            account_id: "2".into(),
            tooling_repository: TOOLING.into(),
            tooling_sha: "c".repeat(40),
            selection: selected.clone(),
        };
        let authority = serde_json::json!({"workflow":"Candidate", "callerPath":".github/workflows/mobile-candidate.yml",
            "reusableRepository":TOOLING, "reusablePath":".github/workflows/reusable-candidate.yml", "reusableCommit":"c".repeat(40),
            "runId":selected.run_id, "attempt":selected.attempt,"headSha":"d".repeat(40), "ref":"refs/heads/main", "event":"workflow_dispatch"});
        serde_json::from_value(serde_json::json!({"schemaVersion":1,"context":context,"observedAt":"2026-10-21T00:00:00Z",
            "verification":"verified","reason":"none","assurance":ASSURANCE,"evidence":{
            "artifactId":"11","artifactSha256":"e".repeat(64),"artifactName":"mobile-release-candidate-evidence-android","producerJobId":"12",
            "producedBy":authority,"authorizedBy":authority,"candidateSource":{"commit":"d".repeat(40),"tree":"f".repeat(40)},
            "operationSource":{"commit":"d".repeat(40),"tree":"f".repeat(40)},"version":{"name":"1.2.3","build":2},"applicationId":"app.example",
            "outcome":"reconciled","candidateManifestSha256":"1".repeat(64),"operationIntentSha256":"2".repeat(64),
            "receiptSha256":"3".repeat(64),"provenanceSha256":"4".repeat(64)}})).unwrap()
    }
    fn candidate() -> Candidate {
        Candidate {
            primary_sha256: "5".repeat(64),
            primary_bytes: 3,
            receipt_sha256: "6".repeat(64),
            receipt_bytes: 3,
        }
    }
    pub(crate) fn reply() -> Reply {
        serde_json::from_value(serde_json::json!({"protocol":PROTOCOL,"id":"data","requestSha256":"7".repeat(64),
            "result":result(),"reason":"none","download":candidate(),"lifetime":{"complete":true,"fatal":false,"contained":true,
            "commandDispatched":true,"commands":12,"verifierCalls":4,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":false}})).unwrap()
    }
    fn initial() -> Initial {
        let directory = |inode: &str| DirectoryIdentity {
            device: "1".into(),
            inode: inode.into(),
            mode: 0o40700,
            uid: 501,
            gid: 20,
        };
        let file = |inode: &str| FileIdentity {
            device: "1".into(),
            inode: inode.into(),
            mode: 0o100600,
            uid: 501,
            gid: 20,
            nlink: "1".into(),
            bytes: "0".into(),
            mtime_seconds: "0".into(),
            ctime_seconds: "0".into(),
            mtime_nanos: 0,
            ctime_nanos: 0,
            flags: 0,
        };
        Initial {
            protocol: PROTOCOL.into(),
            id: "data".into(),
            owner_generation: "original-data".into(),
            context: result().context,
            native: Native {
                profile: NativeProfile::Arm64,
                project_root: "/Users/example/project".into(),
                root_identity: directory("2"),
                config_identity: file("3"),
                work_root: "/private/tmp/owned-data".into(),
                work_identity: directory("4"),
                provider: Provider {
                    relative_path: "tools/gh".into(),
                    version: "2.88.1".into(),
                    target: NativeProfile::Arm64.target().into(),
                    source_manifest_sha256: "8".repeat(64),
                    sha256: "9".repeat(64),
                    identity: FileIdentity {
                        mode: 0o100555,
                        uid: 0,
                        bytes: "1".into(),
                        ..file("5")
                    },
                },
                parent_descriptor_reservation: 56,
                clock: Clock {
                    name: "CLOCK_UPTIME_RAW".into(),
                    work_end_ns: "1".into(),
                    hard_end_ns: "10000000001".into(),
                },
                download: Some(Pins {
                    consent_version: CONSENT.into(),
                    parent_identity: directory("6"),
                    staging_identity: directory("7"),
                    primary_identity: file("8"),
                    receipt_identity: file("9"),
                }),
            },
        }
    }
    #[test]
    fn download_consent_cannot_upgrade_old_read_or_other_stage() {
        let value = serde_json::json!({"sessionId":"same", "expectedRevision":1, "expectedConnectionRevision":2,
            "selection":selection(), "consentVersion":CONSENT, "confirmed":true});
        assert!(serde_json::from_value::<Args>(value.clone())
            .unwrap()
            .into_start()
            .is_ok());
        for (key, bad) in [
            ("confirmed", serde_json::json!(false)),
            ("consentVersion", serde_json::json!("read")),
            ("destination", serde_json::json!("/tmp/output")),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(serde_json::from_value::<Args>(changed)
                .map_err(|_| ())
                .and_then(|v| v.into_start().map_err(|_| ()))
                .is_err());
        }
        assert!(names(&Selection {
            stage: Stage::ProductionSubmit,
            ..selection()
        })
        .is_none());
    }
    #[test]
    fn download_diagnostic_is_not_publication_or_finality() {
        let trace = Trace::new(&selection()).unwrap();
        assert!(trace.snapshot().valid(&selection()));
        assert!(!trace.snapshot().exported());
        assert!(trace.enter());
        assert!(!trace.enter());
        trace.returned(true, false);
        assert!(!trace.snapshot().exported());
        assert!(trace.sync_entered());
        trace.sync_returned(true);
        assert!(!trace.snapshot().exported());
        trace.closed(true);
        assert!(trace.snapshot().exported());
        // DATA transition test only: no native call/close was performed here.
    }
    #[test]
    fn download_unknown_durability_retains_positive_rename_without_success() {
        let trace = Trace::new(&selection()).unwrap();
        assert!(trace.enter());
        trace.returned(true, false);
        assert!(trace.sync_entered());
        trace.sync_returned(false);
        trace.closed(true);
        let value = trace.snapshot();
        assert_eq!(value.publication, Publication::Published);
        assert_eq!(value.durability, Durability::Unknown);
        assert!(!value.closed && !value.exported());
    }
    #[test]
    fn download_cleanup_window_cannot_authorize_new_publication() {
        let now = std::time::Instant::now();
        let work = now + std::time::Duration::from_secs(1);
        assert!(work_permits(now, work, false, false, true));
        for (at, failed, stopped, current) in [
            (work, false, false, true),
            (now, true, false, true),
            (now, false, true, true),
            (now, false, false, false),
        ] {
            assert!(!work_permits(at, work, failed, stopped, current));
        }
    }
    #[test]
    fn download_candidate_and_complete_control_quote_are_bounded() {
        let value = Candidate {
            primary_sha256: "1".repeat(64),
            primary_bytes: PRIMARY_LIMIT,
            receipt_sha256: "2".repeat(64),
            receipt_bytes: RECEIPT_LIMIT as u32,
        };
        assert!(value.valid());
        assert!(!Candidate {
            primary_bytes: PRIMARY_LIMIT + 1,
            ..value.clone()
        }
        .valid());
        assert!(!Candidate {
            receipt_bytes: 0,
            ..value.clone()
        }
        .valid());
        let trace = Trace::new(&selection()).unwrap();
        assert!(
            2 * 65536
                + RECEIPT_PARSE_RESERVE
                + RETAINED_REPLY_LIMIT
                + trace.retained_bytes().unwrap()
                + 4 * std::mem::size_of::<Pins>()
                + 4 * RECEIPT_LIMIT
                <= CONTROL_RESERVE
        );
    }
    #[test]
    fn download_receipt_parser_requires_exact_historical_binding_and_bounded_nodes() {
        let result = result();
        let c = candidate();
        let evidence = result.evidence.as_ref().unwrap();
        let value = serde_json::json!({"schemaVersion":1,"assurance":"authenticated-historical-candidate-only","context":result.context,
            "authorizedBy":evidence.authorized_by,"artifactId":"20","artifactSha256":"a".repeat(64),
            "candidateManifestSha256":evidence.candidate_manifest_sha256,"operationIntentSha256":evidence.operation_intent_sha256,
            "provenanceSha256":evidence.provenance_sha256,"primary":{"fileName":"app-release.aab","bytes":c.primary_bytes,"sha256":c.primary_sha256}});
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(encoded.len() < RECEIPT_LIMIT);
        assert!(receipt_matches(&encoded, &c, &result));
        for (pointer, bad) in [
            ("/assurance", serde_json::json!("store-ready")),
            ("/authorizedBy/runId", serde_json::json!("999")),
            ("/context/accountId", serde_json::json!("999")),
            ("/operationIntentSha256", serde_json::json!("f".repeat(64))),
            ("/primary/fileName", serde_json::json!("app.ipa")),
            ("/primary/bytes", serde_json::json!(4)),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(!receipt_matches(
                &serde_json::to_vec(&changed).unwrap(),
                &c,
                &result
            ));
        }
        let mut extra = value.clone();
        extra["localPath"] = serde_json::json!("/elsewhere");
        assert!(!receipt_matches(
            &serde_json::to_vec(&extra).unwrap(),
            &c,
            &result
        ));
        let bomb = format!("{{\"x\":[{}]}}", vec!["{}"; 256].join(","));
        assert!(bomb.len() < RECEIPT_LIMIT);
        assert!(!receipt_matches(bomb.as_bytes(), &c, &result));
        let mut duplicate = encoded.clone();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"schemaVersion\":1}");
        assert!(!receipt_matches(&duplicate, &c, &result));
        let mut trailing = encoded;
        trailing.extend_from_slice(b"{}");
        assert!(!receipt_matches(&trailing, &c, &result));
    }
    #[test]
    fn download_private_terminal_presence_cannot_upgrade_old_initial_or_missing_lifetime() {
        let initial = initial();
        assert!(initial.encode().is_ok());
        let digest = request_digest(&initial.encode().unwrap());
        let mut frame = serde_json::json!({"protocol":PROTOCOL,"id":initial.id,"requestSha256":digest,"result":result(),"reason":"none","download":candidate(),
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":12,"verifierCalls":4,
            "inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":false}});
        let line = |value: &serde_json::Value| {
            let mut bytes = serde_json::to_vec(value).unwrap();
            bytes.push(b'\n');
            bytes
        };
        assert!(decode_reply(&line(&frame), &initial, &digest).is_ok());
        let mut old = initial.clone();
        old.native.download = None;
        assert!(decode_reply(&line(&frame), &old, &digest).is_err());
        for (pointer, bad) in [
            ("/download", serde_json::Value::Null),
            ("/lifetime/inputClosed", serde_json::json!(false)),
            ("/lifetime/stopObserved", serde_json::json!(true)),
            ("/lifetime/fatal", serde_json::json!(true)),
            (
                "/download/primaryBytes",
                serde_json::json!(PRIMARY_LIMIT + 1),
            ),
        ] {
            let mut changed = frame.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(decode_reply(&line(&changed), &initial, &digest).is_err());
        }
        frame.as_object_mut().unwrap().remove("download");
        assert!(decode_reply(&line(&frame), &initial, &digest).is_err());
        let old_raw = old.encode().unwrap();
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&old_raw).unwrap()["native"]
                .as_object()
                .unwrap()
                .contains_key("download")
        );
        let old_digest = request_digest(&old_raw);
        frame["requestSha256"] = serde_json::json!(old_digest);
        assert!(decode_reply(&line(&frame), &old, &old_digest).is_ok()); // old exact presence remains unchanged
    }
    #[test]
    fn download_unknown_state_keeps_diagnostics_without_minting_any_ticket() {
        let mut state = crate::github_history_session::State::new();
        let trace = Trace::new(&selection()).unwrap();
        assert!(trace.enter());
        trace.returned(true, false);
        assert!(trace.sync_entered());
        trace.sync_returned(false);
        state.view.session_id = Some("data".into());
        state.view.operation = Some(Operation {
            id: "unentered-data".into(),
            phase: Phase::Running,
            reason: Reason::None,
            selection: selection(),
            download: Some(trace.snapshot()),
        });
        state.view.result = Some(result());
        let before = state.snapshot();
        state.unknown();
        state.finish(before);
        assert!(state.active.is_none());
        assert!(state.view.result.is_none());
        assert!(state.view.fits_wire());
        let diagnostic = state.view.operation.as_ref().unwrap().download.clone();
        state.publish_settled(Err(BridgeError::protocol()), false, false);
        assert_eq!(state.view.operation.as_ref().unwrap().download, diagnostic);
        assert_eq!(state.view.reason, Reason::CleanupUnknown);
        assert!(state.retained_heap_bytes_if_quiescent().is_none());
        // No active ticket means this DATA test can never publish a settled result.
    }
}
