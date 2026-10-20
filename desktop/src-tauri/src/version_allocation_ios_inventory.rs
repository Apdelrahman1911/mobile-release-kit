//! Explicit v2 current-inventory DATA on the SAME native allocation state port.
//! No arithmetic or independent authority; Python remains the sole proposer.
use super::*;
use crate::local_store_preflight_protocol::{store_versions as wire, Context};

pub(super) const PROTOCOL: &str = "mrk-version-allocation/2";
pub(super) const REQUEST_DOMAIN: &[u8] = b"mrk:allocation-request:2\0";
pub(super) const RESERVATION_DOMAIN: &[u8] = b"mrk:allocation-reservation:2\0";
pub(super) const POLICY_SCOPE: &str = "require-current-ios-inventory";

pub(super) fn observation_shape(value: &Value, request: &Request) -> bool {
    if !closed(
        value,
        &[
            "platform",
            "scope",
            "identityRevision",
            "contextRevision",
            "revision",
            "observedAt",
            "maxBuild",
            "marketingVersion",
            "counts",
            "complete",
            "formatSupported",
            "historicalUniqueness",
        ],
    ) || value["platform"] != "ios"
        || value["scope"] != wire::COVERAGE
        || value["identityRevision"] != request.0["identityRevision"]
        || value["contextRevision"] != request.0["storeContextRevision"]
        || !["identityRevision", "contextRevision", "revision"]
            .into_iter()
            .all(|k| string(&value[k], |s| hex(s, 64)))
        || !integer(&value["observedAt"], 0, i64::MAX as u64)
        || value["complete"] != true
        || value["formatSupported"] != true
    {
        return false;
    }
    serde_json::from_value::<wire::Summary>(json!({"observation":"observed","coverage":value["scope"],
        "revision":value["revision"],"counts":value["counts"],"maxBuild":value["maxBuild"],
        "marketingVersion":value["marketingVersion"],"historicalUniqueness":value["historicalUniqueness"]}))
        .is_ok_and(|s| s.observed())
}

/// Called only with the SAME joined Store owner observation. The original Doc
/// must still check its weak P8 assignment/source and policy age at admission,
/// pending ACK/PUT and reserved-edit handoff. This serializes DATA, not a grant.
pub(crate) fn observation_data(
    original: &crate::saved_command_owner::StoreVersionObservation,
    port: &VersionAllocationStatePort,
) -> Result<Value> {
    // Borrow the already durable full selected request, not an identity hash
    // supplied by the renderer or a newly reconstructed candidate.
    let request = Request(port.selected_request()?.clone());
    need(
        request_context_matches(&request, original.context())
            && original.current(
                std::time::Instant::now(),
                std::time::SystemTime::now(),
                request.0["policy"]["storeMaxAgeSeconds"]
                    .as_u64()
                    .unwrap_or(0),
            ),
    )?;
    let summary = original.summary();
    need(summary.observed())?;
    let context_revision = context_digest(original.context())?;
    Ok(
        json!({"platform":"ios","scope":wire::COVERAGE,"identityRevision":request.0["identityRevision"],
        "contextRevision":context_revision,"revision":summary.revision,"observedAt":original.observed_at(),
        "maxBuild":summary.max_build,"marketingVersion":summary.marketing_version,"counts":summary.counts,
        "complete":true,"formatSupported":true,"historicalUniqueness":"not-established"}),
    )
}
fn request_context_matches(request: &Request, context: &Context) -> bool {
    request.valid()
        && request.schema_version() == 2
        && context_digest(context).is_ok_and(|digest| request.0["storeContextRevision"] == digest)
        && request.0["source"]["configurationSha256"] == context.saved_config.sha256
        && request.0["source"]["versionSha256"] == context.saved_version.sha256
        && request.0["baseVersion"]["name"] == context.saved_version.name
        && request.0["baseVersion"]["build"] == context.saved_version.build
}
pub(crate) fn context_digest(context: &Context) -> Result<String> {
    // The actual original context has the same ASCII-escaped canonical form as
    // ios_store_versions / Python policy.digest; do not hash renderer JSON.
    need(wire::selected(context))?;
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(
            context,
            crate::local_store_preflight_protocol::IPC_LIMIT
        )?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_state_store::Fixture;

    fn request() -> Value {
        let mut value = super::super::tests::request();
        value["platforms"] = json!(["ios"]);
        value["storeContextRevision"] = json!("a".repeat(64));
        value["policy"]["schemaVersion"] = json!(2);
        value["policy"]["storeScope"] = json!(POLICY_SCOPE);
        value
    }
    fn observation() -> Value {
        json!({"platform":"ios","scope":wire::COVERAGE,"identityRevision":"b".repeat(64),
            "contextRevision":"a".repeat(64),"revision":"c".repeat(64),"observedAt":2000,
            "maxBuild":0,"marketingVersion":"2.0.0","counts":{"builds":0,"buildUploads":0,"appStoreVersions":1},
            "complete":true,"formatSupported":true,"historicalUniqueness":"not-established"})
    }
    fn pending(request: &Value) -> Value {
        let mut p = super::super::tests::pending(request);
        p["schemaVersion"] = json!(2);
        p["protocol"] = json!(PROTOCOL);
        p["reservation"]["requestSha256"] = json!(hash(REQUEST_DOMAIN, request).unwrap());
        p["reservation"]["storeObservations"] = json!([observation()]);
        let mut unsigned = p["reservation"].clone();
        unsigned.as_object_mut().unwrap().remove("sha256");
        p["reservation"]["sha256"] = json!(hash(RESERVATION_DOMAIN, &unsigned).unwrap());
        p
    }
    #[test]
    fn explicit_v2_shape_preserves_v1_and_refuses_scope_platform_or_context_substitution() {
        let legacy = Request(super::super::tests::request());
        assert!(legacy.valid());
        assert_eq!(
            legacy.request_hash().unwrap(),
            hash(b"mrk:allocation-request:1\0", &legacy).unwrap()
        );
        let newer = Request(request());
        assert!(newer.valid());
        let obs = observation();
        assert!(newer.observations_valid(&[obs.clone()]));
        assert!(!legacy.observations_valid(&[obs.clone()]));
        for (key, value) in [
            ("contextRevision", json!("f".repeat(64))),
            ("scope", json!("application-all-builds")),
            ("maxBuild", json!(4)),
            ("historicalUniqueness", json!("established")),
            ("complete", json!(false)),
        ] {
            let mut invalid = obs.clone();
            invalid[key] = value;
            assert!(!newer.observations_valid(&[invalid]));
        }
        for change in [json!(["android"]), json!(["android", "ios"])] {
            let mut invalid = request();
            invalid["platforms"] = change;
            assert!(!Request(invalid).valid());
        }
        let p: Pending = decode(pending(&newer.0)).unwrap();
        assert!(p.valid().is_ok());
        let mut down = pending(&newer.0);
        down["schemaVersion"] = json!(1);
        down["protocol"] = json!(ALLOCATION_PROTOCOL);
        assert!(decode::<Pending>(down).unwrap().valid().is_err());
    }
    #[test]
    fn same_original_namespace_retains_v2_pending_resolution_and_retry_data() {
        let f = Fixture::new();
        let (store, mut port) = super::super::tests::prepared(&f);
        // Explicitly replacing a selected unused candidate uses the existing
        // native compare guard; no automatic migration/remint/retry shortcut.
        let old = port.selected_request().unwrap().clone();
        let mut input = request();
        input.as_object_mut().unwrap().remove("candidateId");
        port.select_new(input, Some(&old)).unwrap();
        let selected = port.selected_request().unwrap().clone();
        let dialogue = |kind, observations: &[Value]| {
            dialogue::Request::from_port(
                &port,
                "inventory-fixture",
                kind,
                "17",
                dialogue::Clock::new(1, 2).unwrap(),
                observations,
            )
        };
        assert!(dialogue(dialogue::Kind::Reserve, &[]).is_err());
        assert!(dialogue(dialogue::Kind::Reserve, &[observation()]).is_ok());
        assert!(dialogue(dialogue::Kind::Reconcile, &[]).is_err());
        let p = pending(&selected);
        let before = port.snapshot().unwrap().revision;
        port.apply(before, &selected, Transition::Pending(p.clone()))
            .unwrap();
        assert!(dialogue::Request::from_port(
            &port,
            "inventory-fixture",
            dialogue::Kind::Reconcile,
            "17",
            dialogue::Clock::new(1, 2).unwrap(),
            &[]
        )
        .is_ok());
        let snapshot = store.read(Namespace::VersionAllocations).unwrap();
        let retained = State::parse(&snapshot).unwrap();
        assert_eq!(
            retained.authorities[0]
                .pending
                .as_ref()
                .unwrap()
                .reservation
                .request
                .0,
            selected
        );
        let advanced = super::super::tests::advanced(&p);
        let revision = port.snapshot().unwrap().revision;
        port.apply(
            revision,
            &selected,
            Transition::Checkpoint(advanced.clone()),
        )
        .unwrap();
        let revision = port.snapshot().unwrap().revision;
        port.apply(
            revision,
            &selected,
            Transition::Resolved {
                pending: p.clone(),
                checkpoint: advanced.clone(),
            },
        )
        .unwrap();
        let revision = port.snapshot().unwrap().revision;
        port.apply(
            revision,
            &selected,
            Transition::Reused {
                reservation: p["reservation"].clone(),
                checkpoint: advanced,
            },
        )
        .unwrap();
        assert_eq!(port.selected_request().unwrap(), &selected);
        assert_eq!(
            store
                .read(Namespace::VersionAllocations)
                .unwrap()
                .revision
                .0,
            revision.0 + 1
        );
        drop(port);
        store.close().unwrap();
    }
    #[test]
    fn current_inventory_must_match_the_selected_saved_bytes_and_version_not_only_an_app_hash() {
        let mut input = json!(crate::local_store_preflight_protocol::tests::context());
        input.as_object_mut().unwrap().remove("operation");
        input["platform"] = json!("ios");
        input["query"] = json!(wire::QUERY);
        let context = crate::local_store_preflight_protocol::prepare(&input)
            .unwrap()
            .context();
        let mut selected = request();
        selected["source"]["configurationSha256"] = json!(context.saved_config.sha256);
        selected["source"]["versionSha256"] = json!(context.saved_version.sha256);
        selected["baseVersion"] =
            json!({"name":context.saved_version.name,"build":context.saved_version.build});
        selected["storeContextRevision"] = json!(context_digest(&context).unwrap());
        assert!(request_context_matches(
            &Request(selected.clone()),
            &context
        ));
        for field in ["configurationSha256", "versionSha256"] {
            let mut changed = selected.clone();
            changed["source"][field] = json!("e".repeat(64));
            assert!(!request_context_matches(&Request(changed), &context));
        }
        let mut changed = selected.clone();
        changed["baseVersion"]["build"] = json!(999);
        assert!(!request_context_matches(&Request(changed), &context));
        let mut changed = context.clone();
        changed.credential_context_revision += 1;
        assert!(!request_context_matches(&Request(selected), &changed));
    }
}
