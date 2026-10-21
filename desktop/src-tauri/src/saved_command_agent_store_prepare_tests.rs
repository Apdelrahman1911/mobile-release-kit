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
    let (owner, mut p, old, old_inbox, doc) = super::super::tests::binding();
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
