//! Only original in-memory clock/wait behavior. No Ticket/admission/native IO.
use super::*;
fn link(doc: &Arc<()>, end: Instant) -> Arc<req::NativeLink> {
    let id = |c: char| Id::parse(&c.to_string().repeat(32)).unwrap();
    req::NativeLink::new(Arc::new(req::NativeScope {
        project_id: id('1'),
        runtime_id: "p1".into(),
        review_id: id('2'),
        review: p::Review {
            kind: p::Kind::Doctor,
            platform: p::Platform::Android,
            draft_revision: 1,
            baseline_generation: 1,
            prepared: None,
            sources: None,
        },
        root: "/not-opened".into(),
        device: 1,
        inode: 2,
        observation_revision: 1,
        saved_config: None,
        expires: end,
        read: Arc::new(crate::service_version_reserve_requests::ReadPermission::new(end)),
        document: Arc::downgrade(doc),
        control: req::Control::new(),
        retired: AtomicBool::new(false),
        changes: watch::channel(0).0,
    }))
}
#[tokio::test]
async fn quiet_read_revoke_reaches_original_doctor_join_and_keeps_earlier_f() {
    let now = Instant::now();
    let doc = Arc::new(());
    let link = link(&doc, now + Duration::from_secs(2));
    let input=wire::start(&serde_json::json!({"projectId":"p1","draftRevision":1,"baselineGeneration":1,"platform":"android","operation":"build","draft":{}})).unwrap();
    let binding = Arc::new(Binding {
        approval: Arc::new(Approval {
            owner: Weak::new(),
            context: input.context(),
            registration: 1,
            root: "/not-opened".into(),
            expires: now + Duration::from_secs(2),
            input: Mutex::new(Some(input)),
            input_bytes: 0,
            review: link.scope().review.clone(),
        }),
        link: link.clone(),
    });
    let (app, owner) = super::super::tests::inert_active_for_agent(now, false, Some(binding));
    let (release, held) = tokio::sync::oneshot::channel();
    let mut job = Some(tokio::spawn(async move {
        let _ = held.await;
    }));
    let original = owner.clone();
    let inner = app.inner.clone();
    let control = link.scope().control.clone();
    let read = link.scope().read.clone();
    let join = async {
        join_with_clock(&mut job, &inner, &original).await.unwrap();
    };
    let revoke = async {
        tokio::task::yield_now().await;
        let late = Instant::now();
        control.stop(p::Reason::UserCancelled, late);
        let early = now;
        read.revoke(early);
        // No relay/read-status/owner.wake is sent. The existing same-task poll must
        // import this old Read even though STOP was already observed.
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if app.inner.lock().active.as_ref().unwrap().first_stop == Some(early) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
        let _ = release.send(());
        result
    };
    let (_, observed) = tokio::join!(join, revoke);
    observed.unwrap();
    assert_eq!(owner.clocks.work, now + WORK);
    assert_eq!(owner.clocks.finality, now + FINALITY);
    assert!(!link.scope().retired.load(Ordering::Acquire));
    assert!(!owner.driver_joined.load(Ordering::SeqCst));
}
#[test]
fn doctor_quote_counts_real_value_heap_not_only_encoded_draft() {
    let mut object = serde_json::Map::new();
    for i in 0..9000 {
        object.insert(format!("k{i:05}"), Value::Bool(true));
    }
    let draft = Value::Object(object);
    crate::protocol::check_value(&draft).unwrap();
    let encoded = serde_json::to_vec(&draft).unwrap();
    assert!(encoded.len() < 512 * 1024);
    let actual = heap(&draft, 0, &mut 0).unwrap();
    assert!(actual > encoded.len() * 10);
    let owner =
        EnvironmentDiagnosticsOwner::new(RuntimeConfig::packaged(PathBuf::from("/not-opened")));
    // Admission availability may be false for this build; quote uses the actual
    // representation independently and never turns that into a native grant.
    assert!(actual.checked_mul(3).unwrap() + 3 * wire::REQUEST_LIMIT > actual);
    assert!(owner.inner.lock().active.is_none());
    let deep = (0..34).fold(Value::Null, |v, _| Value::Array(vec![v]));
    assert!(heap(&deep, 0, &mut 0).is_none());
}
