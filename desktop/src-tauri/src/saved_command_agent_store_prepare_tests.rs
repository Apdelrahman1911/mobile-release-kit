//! Reuses the existing unentered Saved fixture and actual closed core decoder.
//! No material, launch, Asset receipt, native retirement or provider execution.
use super::*;
fn id(c: char) -> s::Id {
    s::Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn query(kind: flow::Kind) -> Input {
    let mut v = serde_json::to_value(store_wire::tests::context()).unwrap();
    v.as_object_mut().unwrap().remove("operation");
    let (platform, query) = match kind {
        flow::Kind::IosVersions => ("ios", "ios-current-versions"),
        flow::Kind::AndroidVersions => ("android", "android-current-versions"),
        flow::Kind::PairedVersions => ("both", "paired-current-versions"),
        _ => unreachable!(),
    };
    v["platform"] = platform.into();
    v["query"] = query.into();
    if kind == flow::Kind::PairedVersions {
        v["iosRecord"] = serde_json::json!({"recordId":"d".repeat(32),"recordRevision":2});
    }
    Input::parse(kind, &v).unwrap()
}
fn ios() -> serde_json::Value {
    serde_json::json!({"observation":"observed","coverage":"asc-ios-current-inventory/1","revision":"a".repeat(64),"counts":{"builds":0,"buildUploads":0,"appStoreVersions":0},"maxBuild":0,"marketingVersion":null,"historicalUniqueness":"not-established"})
}
fn android() -> serde_json::Value {
    serde_json::json!({"observation":"temporary-edit-unconfirmed","coverage":"play-android-current-inventory/1","revision":null,"counts":null,"maxBuild":null,"marketingVersion":null,"temporaryEdit":"unconfirmed","historicalUniqueness":"not-established"})
}
fn android_observed() -> serde_json::Value {
    serde_json::json!({"observation":"observed","coverage":"play-android-current-inventory/1","revision":"a".repeat(64),"counts":{"tracks":0,"releases":0,"versionCodes":0,"bundles":0,"apks":0},"maxBuild":0,"marketingVersion":null,"temporaryEdit":"deleted","historicalUniqueness":"not-established"})
}
fn decoded(c: &store_wire::Context, payload: &serde_json::Value) -> store_wire::Terminal {
    let mut frame = serde_json::to_vec(&serde_json::json!({
        "protocol":store_wire::PROTOCOL,"operationId":"a".repeat(32),
        "ownerGeneration":"b".repeat(32),"sequence":1,"kind":"terminal","payload":payload
    }))
    .unwrap();
    frame.push(b'\n');
    let store_wire::Frame::Terminal(t) =
        store_wire::decode(&frame, &"a".repeat(32), &"b".repeat(32), c).unwrap()
    else {
        unreachable!()
    };
    t
}
fn sides(v: &serde_json::Value, paired: bool) -> Vec<&serde_json::Value> {
    if paired {
        vec![&v["inventory"]["android"], &v["inventory"]["ios"]]
    } else {
        vec![&v["inventory"]["current"]]
    }
}
#[test]
fn store_preparation_actual_core_decoder_projects_required_inconclusive_inventory() {
    for kind in [
        flow::Kind::AndroidVersions,
        flow::Kind::IosVersions,
        flow::Kind::PairedVersions,
    ] {
        let input = query(kind);
        let context = input.context();
        let Context::LocalStorePreflight(c) = &context else {
            unreachable!()
        };
        let current = match kind {
            flow::Kind::AndroidVersions => android(),
            flow::Kind::IosVersions => ios(),
            _ => serde_json::json!({"android":android(),"ios":ios()}),
        };
        let (scope, limitations, commands) = match kind {
            flow::Kind::AndroidVersions => (
                store_wire::play_versions::SCOPE,
                serde_json::json!(store_wire::play_versions::LIMITATIONS),
                6,
            ),
            flow::Kind::IosVersions => (
                store_wire::store_versions::SCOPE,
                serde_json::json!(store_wire::store_versions::LIMITATIONS),
                7,
            ),
            _ => (
                store_wire::paired_versions::SCOPE,
                serde_json::json!(store_wire::play_versions::LIMITATIONS),
                13,
            ),
        };
        let mut terminal = store_wire::tests::complete();
        terminal["context"] = serde_json::json!(c);
        terminal["result"] = serde_json::json!({"schemaVersion":1,"scope":scope,"findings":[],"limitations":limitations,"currentVersions":current});
        let r = flow::Review {
            review_id: id('a'),
            operation: p::Operation {
                operation_id: id('a'),
                owner_generation: id('b'),
                status_revision: 3,
            },
        };
        let selection = input.selection().unwrap();
        // Decodable Complete with zero commands/false dispatch cannot positively
        // attribute inventory. A genuine partial-pair/edit warning survives.
        for exact_commands in [false, true] {
            terminal["lifetime"]["commands"] =
                serde_json::json!(if exact_commands { commands } else { 0 });
            terminal["lifetime"]["commandDispatched"] = serde_json::json!(exact_commands);
            let t = decoded(c, &terminal);
            assert_eq!(
                t.current_inventory_data(c).is_some(),
                exact_commands && kind == flow::Kind::IosVersions
            );
            let projected =
                project_report(&Terminal::LocalStorePreflight(t), &context, &selection, &r)
                    .unwrap();
            assert!(projected.valid_for(&selection, &r));
            assert!(projected.bounded_capacity());
            let value = serde_json::to_value(projected).unwrap();
            assert!(value.get("account").is_none());
            assert!(value.get("lifetime").is_none());
            for side in sides(&value, kind == flow::Kind::PairedVersions) {
                if side["observation"] != "observed" {
                    for field in ["revision", "counts", "maxBuild", "marketingVersion"] {
                        assert!(side.get(field).unwrap().is_null());
                    }
                } else {
                    assert!(exact_commands && kind == flow::Kind::IosVersions);
                }
            }
            if kind != flow::Kind::IosVersions {
                assert!(value.to_string().contains("temporary-edit-unconfirmed"));
                if kind == flow::Kind::PairedVersions {
                    assert_eq!(value["inventory"]["ios"]["observation"], "inconclusive");
                    assert_eq!(
                        value["inventory"]["android"]["temporaryEdit"],
                        "unconfirmed"
                    );
                }
            }
        }
        // Every apparently observed side still needs the ORIGINAL exact command
        // and dispatched predicate, not only a valid terminal/result envelope.
        terminal["result"]["currentVersions"] = match kind {
            flow::Kind::AndroidVersions => android_observed(),
            flow::Kind::IosVersions => ios(),
            _ => serde_json::json!({"android":android_observed(),"ios":ios()}),
        };
        for (count, dispatched) in [
            (0, false),
            (commands, false),
            (commands - 1, true),
            (commands, true),
        ] {
            terminal["lifetime"]["commands"] = serde_json::json!(count);
            terminal["lifetime"]["commandDispatched"] = serde_json::json!(dispatched);
            let t = decoded(c, &terminal);
            let observed = count == commands && dispatched;
            assert_eq!(t.current_inventory_data(c).is_some(), observed);
            let projected =
                project_report(&Terminal::LocalStorePreflight(t), &context, &selection, &r)
                    .unwrap();
            assert!(projected.valid_for(&selection, &r));
            let value = serde_json::to_value(projected).unwrap();
            for side in sides(&value, kind == flow::Kind::PairedVersions) {
                assert_eq!(
                    side["observation"],
                    if observed { "observed" } else { "inconclusive" }
                );
                for field in ["revision", "counts", "maxBuild"] {
                    assert_eq!(side.get(field).unwrap().is_null(), !observed);
                }
            }
        }
        assert!(flow::ordinary_review(&selection, &r).is_none()); // cannot borrow old Submit grant.
        let start=store_wire::start(&serde_json::json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":store_wire::CONSENT})).unwrap();
        assert!(!start.matches_context(c)); // even Android needs the separate edit consent.
    }
    // Exercise the actual ordinary projection's serde Vec capacities too.
    let c = Context::LocalStorePreflight(store_wire::tests::context());
    let selection = selection(&c).unwrap();
    let r = flow::Review {
        review_id: id('a'),
        operation: p::Operation {
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 3,
        },
    };
    let t: store_wire::Terminal = serde_json::from_value(store_wire::tests::complete()).unwrap();
    assert!(
        project_report(&Terminal::LocalStorePreflight(t), &c, &selection, &r)
            .unwrap()
            .bounded_capacity()
    );
}

struct Linked {
    owner: SavedCommandOwner,
    prepared: Option<Prepared>,
    link: Arc<Binding>,
    inbox: requests::Inbox,
    caller: Option<queue::PrepareClaim>,
    _old: requests::Inbox,
    _doc: Arc<()>,
}
fn linked() -> Linked {
    linked_input(None)
}
fn linked_input(input: Option<Input>) -> Linked {
    let (mut owner, mut p, old, old_inbox, doc) = super::super::tests::binding();
    if let Some(input) = input {
        let context = input.context();
        owner = SavedCommandOwner::new(RuntimeConfig::packaged("/unopened-store-runtime".into()), context.domain());
        p.projection.context = context;
    }
    let source = old.scope();
    let scope = queue::Scope::new(
        source.project_id.clone(),
        source.runtime_id.clone(),
        id('4'),
        selection(&p.projection.context).unwrap(),
        source.root.clone(),
        source.device,
        source.inode,
        source.observation_revision,
        p.expires,
        source.read.clone(),
        source.document.clone(),
        source.witness.clone(),
        source.changes.clone(),
    );
    let inbox = requests::Inbox::new(id('2'));
    inbox.allow_preparation(scope.clone(), id('3')).unwrap();
    let input = p::Submit {
        origin: p::Query {
            project_id: id('1'),
            service_instance: id('2'),
            request_id: id('5'),
        },
        grant_id: id('3'),
        review_id: id('4'),
    };
    inbox
        .submit_preparation(input.clone(), Instant::now())
        .unwrap();
    let caller = inbox.claim_preparation().unwrap().unwrap();
    let entry = caller.entry.clone();
    let review = flow::Review {
        review_id: id('a'),
        operation: p::Operation {
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 1,
        },
    };
    entry.attach(review.clone(), p.expires).unwrap();
    // Only the existing unentered fixture's identity guard is under test.
    // There is deliberately NO material: matches()/native Start cannot succeed.
    let link = Arc::new(Binding {
        entry,
        owner: Arc::downgrade(&owner.inner),
        context: p.projection.context.clone(),
        registration: p.registration,
        root: p.project.clone(),
        material: Weak::new(),
        review,
        expires: p.expires,
        consumed: AtomicBool::new(false),
    });
    p.agent_store = None;
    p.agent_store_preparation = Some(link.clone());
    installed(&p).unwrap();
    Linked {
        owner,
        prepared: Some(p),
        link,
        inbox,
        caller: Some(caller),
        _old: old_inbox,
        _doc: doc,
    }
}
#[test]
fn store_preparation_losing_gui_start_checks_link_before_any_retirement_or_take() {
    // Same fixed 128KiB term as the Doc grant test: this is its remaining
    // 32KiB, not another quote. Native/old binding roots and bounded Context
    // copies coexist; payloads stay weak and under the original Store census.
    let cells = std::mem::size_of::<Binding>()
        + std::mem::size_of::<super::super::Binding>()
        + std::mem::size_of::<super::super::Approval>()
        + 2 * std::mem::size_of::<Context>();
    let heaps = 4 * 4096 + 4 * 1024 + 24 * 32;
    assert!(cells + heaps <= 32 * 1024, "{cells}+{heaps}");
    let mut f = linked();
    let p = f.prepared.take().unwrap();
    let original = p.projection.clone();
    let end = p.expires;
    f.owner.inner.lock().prepared = Some(p);
    for pair in [(id('a'), id('b')), (id('c'), id('d'))] {
        assert!(f
            .owner
            .ordinary_store_start_allowed(pair.0.as_str(), pair.1.as_str())
            .is_err());
    }
    {
        let r = f.owner.inner.lock();
        let p = r.prepared.as_ref().unwrap();
        assert_eq!(p.projection.operation_id, original.operation_id);
        assert_eq!(p.expires, end);
        assert!(Arc::ptr_eq(
            p.agent_store_preparation.as_ref().unwrap(),
            &f.link
        ));
        assert!(!f.link.consumed.load(Ordering::Acquire));
        assert!(!start_matches(p, None));
    }
    f.caller.take().unwrap().returned(true);
    f.link.entry.allow_start(&f.link.review, id('6')).unwrap();
    let input = p::Submit {
        origin: f.link.entry.origin().clone(),
        grant_id: id('6'),
        review_id: id('a'),
    };
    f.link.entry.submit_start(input, Instant::now()).unwrap();
    let call = f.inbox.claim_preparation().unwrap().unwrap();
    {
        let r = f.owner.inner.lock();
        let p = r.prepared.as_ref().unwrap();
        assert!(start_matches(p, Some(&f.link.entry)));
        assert!(!f.link.matches(&f.owner.inner, p));
        consume(p).unwrap();
        assert!(consume(p).is_err());
        assert!(!start_matches(p, Some(&f.link.entry)));
    }
    // Return of this inert guard call does not supply a native terminal.
    call.returned(false);
    assert!(f.link.entry.pending());
}
#[test]
fn store_preparation_read_end_and_delayed_earlier_revoke_keep_original_clock() {
    let mut f = linked();
    f.caller.take().unwrap().returned(true);
    let at = Instant::now();
    f.link
        .entry
        .cancel(p::Reason::UserCancelled, at + Duration::from_secs(2));
    assert_eq!(f.link.read_end(), f.link.entry.scope.read.end());
    f.link.entry.scope.read.revoke(at);
    assert_eq!(
        f.link.stop_at(at + Duration::from_secs(3)),
        Some((Reason::Cancelled, at))
    );
    f.link.entry.unknown(p::Reason::CleanupUnknown);
    assert_eq!(
        f.link.stop_at(at + Duration::from_secs(8)),
        Some((Reason::CleanupUnknown, at))
    );
    assert_eq!(f.link.entry.status().unwrap().phase, flow::Phase::Unknown);
}

// Fixed six-frame DATA delivery into the existing core decoder, not a helper
// process, ACK publisher or proof of any native/Store return.
fn stage_terminal(
    c: &prepare_wire::Context,
    terminal: serde_json::Value,
    operation: &str,
) -> Result<prepare_wire::Terminal, BridgeError> {
    let head = match c.later.as_ref().unwrap().stage {
        prepare_wire::StoreStage::ExternalTesting => 9,
        prepare_wire::StoreStage::ProductionSubmit => 13,
    };
    let rows = [
        ("accepted", serde_json::json!({"schemaVersion":1,"context":c})),
        ("lease-ready", serde_json::json!({})),
        ("history-head", serde_json::json!({"sequence":head-2,"sha256":"a".repeat(64)})),
        ("prepare-pending", serde_json::json!({"sequence":head-1,"sha256":"b".repeat(64)})),
        ("prepare-settled", serde_json::json!({"head":{"sequence":head,"sha256":"c".repeat(64)},"phase":"prepared"})),
        ("terminal", terminal),
    ];
    let mut decoder = prepare_wire::Decoder::new();
    let mut returned = None;
    for (sequence, (kind, payload)) in rows.into_iter().enumerate() {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "protocol":prepare_wire::PROTOCOL,"operationId":operation,
            "ownerGeneration":"b".repeat(32),"nonce":"c".repeat(32),
            "requestSha256":"d".repeat(64),"sequence":sequence,"kind":kind,"payload":payload
        })).unwrap();
        bytes.push(b'\n');
        match decoder.decode(&bytes, operation, &"b".repeat(32), c, &"c".repeat(32), &"d".repeat(64))? {
            prepare_wire::Frame::Accepted => assert_eq!(sequence, 0),
            prepare_wire::Frame::Event(_) => assert!((1..=4).contains(&sequence)),
            prepare_wire::Frame::Terminal(t) => { assert_eq!(sequence, 5); returned = Some(t); }
        }
    }
    assert!(decoder.finish());
    Ok(returned.unwrap())
}

#[test]
fn store_stage_prepare_uses_actual_core_decoder_lineage_and_distinct_report() {
    for ios in [false, true] {
        for production in [false, true] {
            use flow::Kind as K;
            let kind = match (ios, production) {
                (false, false) => K::AndroidExternalTesting,
                (true, false) => K::IosExternalTesting,
                (false, true) => K::AndroidProductionSubmit,
                (true, true) => K::IosProductionSubmit,
            };
            let raw = prepare_wire::tests::stage_input(ios, production);
            let input = Input::parse(kind, &raw).unwrap();
            let context = input.context();
            let Context::LocalStorePrepare(c) = &context else { unreachable!() };
            let selected = input.selection().unwrap();
            assert!(kind.prepares_intent());
            assert!(!kind.candidate());
            assert_eq!(selected.later.as_ref().unwrap().stage, kind.stage().unwrap().1);
            assert!(Input::parse(if ios { K::IosCandidate } else { K::AndroidCandidate }, &raw).is_err());
            let operation = prepare_wire::tests::STAGE_ID.replace('-', "");
            let review = flow::Review {
                review_id: s::Id::parse(&operation).unwrap(),
                operation: p::Operation { operation_id: s::Id::parse(&operation).unwrap(), owner_generation: id('b'), status_revision: 3 },
            };
            assert!(flow::ordinary_review(&selected, &review).is_none());
            let start = |consent: &str| prepare_wire::start(&serde_json::json!({
                "operationId":operation,"ownerGeneration":"b".repeat(32),"consentVersion":consent
            }));
            assert!(start(c.consent()).unwrap().matches_context(c));
            assert!(!start(prepare_wire::tests::context().consent()).unwrap().matches_context(c));
            // A delegation consent is not the native original's consent.
            assert!(start(kind.consent()).is_err());

            let value = prepare_wire::tests::stage_complete(ios, production);
            let t = Terminal::LocalStorePrepare(stage_terminal(c, value.clone(), &operation).unwrap());
            let report = project_report(&t, &context, &selected, &review).unwrap();
            assert!(report.valid_for(&selected, &review));
            assert!(report.bounded_capacity());
            let projected = serde_json::to_value(&report).unwrap();
            assert_eq!(projected["kind"], "stage-prepare");
            assert_eq!(projected["report"]["operationId"], prepare_wire::tests::STAGE_ID);
            assert_eq!(projected["report"]["headSequence"], if production { 13 } else { 9 });
            assert_eq!(projected["report"]["limitations"], serde_json::json!(flow::STAGE_LIMITATIONS));
            for field in ["sourceCommit", "sourceTree", "account", "supplementalAssignments", "context", "lifetime"] {
                assert!(projected["report"].get(field).is_none());
            }
            let mut different = selected.clone();
            different.later.as_mut().unwrap().predecessor_receipt_sha256 = "e".repeat(64);
            assert!(project_report(&t, &context, &different, &review).is_err());
            let mut wrong_owner = review.clone();
            wrong_owner.review_id = id('a'); wrong_owner.operation.operation_id = id('a');
            assert!(project_report(&t, &context, &selected, &wrong_owner).is_err());
            for cut in 0..7 {
                let mut bad = value.clone();
                match cut {
                    0 => bad["result"]["preparedIntent"]["operationId"] = "42345678-1234-4234-8234-123456789abc".into(),
                    1 => bad["result"]["preparedIntent"]["predecessorReceiptSha256"] = "e".repeat(64).into(),
                    2 => bad["result"]["preparedIntent"]["stage"] = (if production { "external-testing" } else { "production-submit" }).into(),
                    3 => bad["result"]["headSequence"] = serde_json::json!(if production { 12 } else { 8 }),
                    4 => bad["lifetime"]["commands"] = serde_json::json!(if ios { 14 } else { 13 }),
                    5 => bad["lifetime"]["commandDispatched"] = false.into(),
                    _ => bad["result"]["preparedIntent"]["destination"]["channel"] = "internal".into(),
                }
                assert!(stage_terminal(c, bad, &operation).is_err(), "{kind:?}/{cut}");
            }
        }
    }
}

#[test]
fn store_stage_public_uuid_relation_matches_original_native_uuid4_mapper() {
    let original = prepare_wire::tests::STAGE_ID.replace('-', "");
    for version in [b'3', b'4', b'5'] {
        for variant in [b'7', b'8', b'9', b'a', b'b', b'c'] {
            let mut raw = original.clone().into_bytes(); raw[12] = version; raw[16] = variant;
            let raw = String::from_utf8(raw).unwrap();
            let id = s::Id::parse(&raw).unwrap();
            let uuid = format!("{}-{}-{}-{}-{}", &raw[..8], &raw[8..12], &raw[12..16], &raw[16..20], &raw[20..]);
            let native = crate::android_build_protocol::candidate_uuid(&raw);
            assert_eq!(flow::stage_operation_matches(&uuid, &id), native.as_deref() == Some(uuid.as_str()));
            assert_eq!(native.is_some(), version == b'4' && matches!(variant, b'8' | b'9' | b'a' | b'b'));
            assert!(!flow::stage_operation_matches("12345678-1234-4234-8234-123456789abc", &id));
        }
    }
}

fn upload_input(ios: bool) -> Input {
    let mut raw = execute_wire::tests::input();
    if ios {
        raw["platform"] = "ios".into();
        raw["confirmation"] = "candidate:ios:1.2.3:42".into();
        raw.as_object_mut().unwrap().remove("toolchainSelection");
    }
    Input::parse(if ios { flow::Kind::IosCandidateUpload } else { flow::Kind::AndroidCandidateUpload }, &raw).unwrap()
}
const UPLOAD_AUTH: &str = "23456789-1234-4234-8234-123456789abc";
fn upload_terminal_value(c: &execute_wire::Context) -> serde_json::Value {
    let ios = c.platform == execute_wire::Platform::Ios;
    let mut receipt = serde_json::json!({
        "operationId":c.candidate_operation_id,"candidateSha256":c.candidate_sha256,"intentSha256":c.intent_sha256,
        "receiptSha256":"f".repeat(64),"authorizationId":UPLOAD_AUTH,"sourceCommit":"a".repeat(40),"sourceTree":"b".repeat(40),
        "version":{"name":c.saved_version.name,"build":c.saved_version.build},"observedAt":"2026-10-17T00:00:00Z",
        "result":"accepted","limitations":execute_wire::LIMITATIONS,
    });
    if ios {
        receipt["bundleId"] = "dev.example.app".into(); receipt["appStoreAppId"] = "0012345".into();
        receipt["destination"] = serde_json::json!({"channel":"testflight-internal"});
    } else {
        receipt["applicationId"] = "dev.example.app".into();
        receipt["destination"] = serde_json::json!({"channel":"internal","releaseStatus":"completed"});
    }
    serde_json::json!({"schemaVersion":1,"context":c,"outcome":"complete","reason":"none",
        "result":{"schemaVersion":1,"scope":if ios {"local-ios-store-execute"}else{"local-android-store-execute"},"headSequence":7,"executionReceipt":receipt},
        "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":if ios {16}else{14},
            "profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}})
}
// Original six-frame Execute decoder, not a synthetic native completion. The
// separately generated authorization remains distinct from Prepared/candidate.
fn upload_terminal(c: &execute_wire::Context, value: serde_json::Value) -> Result<execute_wire::Terminal, BridgeError> {
    let rows = [
        ("accepted", serde_json::json!({"schemaVersion":1,"context":c})),
        ("lease-ready", serde_json::json!({})),
        ("history-head", serde_json::json!({"sequence":5,"sha256":"a".repeat(64)})),
        ("execute-pending", serde_json::json!({"sequence":6,"sha256":"b".repeat(64)})),
        ("execute-settled", serde_json::json!({"head":{"sequence":7,"sha256":"c".repeat(64)},"phase":"settled-success"})),
        ("terminal", value),
    ];
    let mut decoder = execute_wire::Decoder::new(UPLOAD_AUTH)?;
    let mut terminal = None;
    for (sequence, (kind, payload)) in rows.into_iter().enumerate() {
        let mut bytes = serde_json::to_vec(&serde_json::json!({
            "protocol":execute_wire::PROTOCOL,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
            "nonce":"c".repeat(32),"requestSha256":"d".repeat(64),"sequence":sequence,"kind":kind,"payload":payload,
        })).unwrap(); bytes.push(b'\n');
        match decoder.decode(&bytes, &"a".repeat(32), &"b".repeat(32), c, &"c".repeat(32), &"d".repeat(64))? {
            execute_wire::Frame::Accepted => assert_eq!(sequence, 0),
            execute_wire::Frame::Event(_) => assert!((1..=4).contains(&sequence)),
            execute_wire::Frame::Terminal(t) => { assert_eq!(sequence, 5); terminal = Some(t); }
        }
    }
    assert!(decoder.finish());
    Ok(terminal.unwrap())
}
#[test]
fn store_candidate_upload_prepare_uses_original_execute_decoder_and_distinct_candidate_identity() {
    for ios in [false, true] {
        let input = upload_input(ios); let context = input.context();
        assert_eq!(context.domain(), SavedCommandDomain::LocalStoreExecute);
        let selected = input.selection().unwrap();
        let Context::LocalStoreExecute(c) = &context else { unreachable!() };
        assert_eq!(c.toolchain_selection.is_some(), !ios);
        assert!(c.later.is_none() && c.stage_operation_id.is_none());
        let review = flow::Review { review_id: id('a'), operation: p::Operation {
            operation_id: id('a'), owner_generation: id('b'), status_revision: 3,
        }};
        let start = |consent: &str| execute_wire::start(&serde_json::json!({
            "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent,
        }));
        assert!(start(c.consent()).unwrap().matches_context(c));
        for other in [prepare_wire::CONSENT, store_wire::CONSENT, selected.kind.consent()] {
            assert!(start(other).is_err()); // service consent cannot replace the original native consent.
        }
        let value = upload_terminal_value(c);
        let terminal = Terminal::LocalStoreExecute(upload_terminal(c, value.clone()).unwrap());
        let report = project_report(&terminal, &context, &selected, &review).unwrap();
        assert!(report.valid_for(&selected, &review) && report.bounded_capacity());
        let out = serde_json::to_value(&report).unwrap();
        assert_eq!(out["report"]["kind"], "execute");
        assert_eq!(out["report"]["release"]["operationId"], c.candidate_operation_id);
        assert_ne!(c.candidate_operation_id.replace('-', ""), review.operation.operation_id.as_str());
        assert_eq!(out["report"]["release"]["target"], if ios { "testflight-internal" } else { "play-internal" });
        for private in ["authorizationId", "sourceCommit", "context", "lifetime", "recordId", "toolchainSelection"] {
            assert!(!out.to_string().contains(private));
        }
        let mut wrong = selected.clone(); wrong.execute.as_mut().unwrap().intent_sha256 = "0".repeat(64);
        assert!(project_report(&terminal, &context, &wrong, &review).is_err());
        for cut in 0..7 {
            let mut bad = value.clone();
            match cut {
                0 => bad["result"]["executionReceipt"]["authorizationId"] = c.candidate_operation_id.clone().into(),
                1 => bad["result"]["executionReceipt"]["operationId"] = UPLOAD_AUTH.into(),
                2 => bad["result"]["executionReceipt"]["intentSha256"] = "0".repeat(64).into(),
                3 => bad["lifetime"]["commands"] = serde_json::json!(if ios { 15 } else { 13 }),
                4 => bad["lifetime"]["commandDispatched"] = false.into(),
                5 => bad["result"]["headSequence"] = 6.into(),
                _ => bad["lifetime"]["inputClosed"] = false.into(),
            }
            assert!(upload_terminal(c, bad).is_err(), "{ios}/{cut}");
        }
    }
}
#[test]
fn store_candidate_upload_link_rejects_losing_gui_start_without_retiring_prepared() {
    for ios in [false, true] {
        let mut f = linked_input(Some(upload_input(ios)));
        let p = f.prepared.take().unwrap(); let expires = p.expires;
        assert_eq!(p.projection.context.domain(), f.owner.inner.domain);
        f.owner.inner.lock().prepared = Some(p);
        assert!(f.owner.ordinary_store_start_allowed(id('a').as_str(), id('b').as_str()).is_err());
        let r = f.owner.inner.lock(); let original = r.prepared.as_ref().unwrap();
        assert_eq!(original.expires, expires);
        assert!(Arc::ptr_eq(original.agent_store_preparation.as_ref().unwrap(), &f.link));
        assert!(!f.link.consumed.load(Ordering::Acquire));
        assert!(!start_matches(original, None));
        assert!(!f.link.matches(&f.owner.inner, original)); // no material/Start is fabricated.
        drop(r);
        f.caller.take().unwrap().returned(false); // post-install lost/error reply stays Unknown.
        assert_eq!(f.link.entry.status().unwrap().phase, flow::Phase::Unknown);
        assert!(f.link.entry.pending());
        assert!(f.link.entry.allow_start(&f.link.review, id('6')).is_err());
    }
}
