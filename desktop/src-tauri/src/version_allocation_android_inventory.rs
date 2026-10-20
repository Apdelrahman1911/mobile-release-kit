//! Explicit v3 current Play-inventory DATA on the SAME allocation port.
//! No second proposer, credential owner, namespace or historical-usage claim.
use super::*;
use crate::local_store_preflight_protocol::{play_versions as wire, Context};

pub(super) const PROTOCOL: &str = "mrk-version-allocation/3";
pub(super) const REQUEST_DOMAIN: &[u8] = b"mrk:allocation-request:3\0";
pub(super) const RESERVATION_DOMAIN: &[u8] = b"mrk:allocation-reservation:3\0";
pub(super) const POLICY_SCOPE: &str = "require-current-android-inventory";

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
            "temporaryEdit",
            "historicalUniqueness",
        ],
    ) || value["platform"] != "android"
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
    serde_json::from_value::<wire::Summary>(
        json!({"observation":"observed", "coverage":value["scope"],
        "revision":value["revision"], "counts":value["counts"], "maxBuild":value["maxBuild"],
        "marketingVersion":value["marketingVersion"], "temporaryEdit":value["temporaryEdit"],
        "historicalUniqueness":value["historicalUniqueness"]}),
    )
    .is_ok_and(|s| s.observed())
}

/// The caller still rematches the SAME original weak assigned material/source
/// and monotonic observation at admission, pending ACK and Edit handoff. An iOS
/// receipt follows its unchanged v2 function; neither receipt grants the other
/// platform or synthesizes a missing paired-platform observation.
pub(crate) fn current_observation_data(
    original: &crate::saved_command_owner::StoreVersionObservation,
    port: &VersionAllocationStatePort,
) -> Result<Value> {
    if crate::local_store_preflight_protocol::store_versions::selected(original.context()) {
        return ios_inventory::observation_data(original, port);
    }
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
    let summary = original
        .summary()
        .android()
        .ok_or_else(|| StateError::from(Error::InvalidRequest))?;
    need(summary.observed())?;
    let context_revision = current_context_digest(original.context())?;
    Ok(json!({"platform":"android", "scope":wire::COVERAGE,
        "identityRevision":request.0["identityRevision"], "contextRevision":context_revision,
        "revision":summary.revision, "observedAt":original.observed_at(), "maxBuild":summary.max_build,
        "marketingVersion":null, "counts":summary.counts, "complete":true, "formatSupported":true,
        "temporaryEdit":"deleted", "historicalUniqueness":"not-established"}))
}

fn request_context_matches(request: &Request, context: &Context) -> bool {
    request.valid()
        && request.schema_version() == 3
        && wire::selected(context)
        && current_context_digest(context)
            .is_ok_and(|digest| request.0["storeContextRevision"] == digest)
        && request.0["source"]["configurationSha256"] == context.saved_config.sha256
        && request.0["source"]["versionSha256"] == context.saved_version.sha256
        && request.0["baseVersion"]["name"] == context.saved_version.name
        && request.0["baseVersion"]["build"] == context.saved_version.build
}

pub(crate) fn current_context_digest(context: &Context) -> Result<String> {
    if crate::local_store_preflight_protocol::store_versions::selected(context) {
        return ios_inventory::context_digest(context);
    }
    need(wire::selected(context))?;
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(
            context,
            crate::local_store_preflight_protocol::IPC_LIMIT,
        )?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_state_store::Fixture;

    fn request() -> Value {
        let mut value = super::super::tests::request();
        value["platforms"] = json!(["android"]);
        value["storeContextRevision"] = json!("a".repeat(64));
        value["policy"]["schemaVersion"] = json!(3);
        value["policy"]["storeScope"] = json!(POLICY_SCOPE);
        value
    }
    fn observation() -> Value {
        json!({"platform":"android", "scope":wire::COVERAGE, "identityRevision":"b".repeat(64),
            "contextRevision":"a".repeat(64), "revision":"c".repeat(64), "observedAt":2000,
            "maxBuild":12, "marketingVersion":null,
            "counts":{"tracks":2, "releases":2, "versionCodes":3, "bundles":0, "apks":1},
            "complete":true, "formatSupported":true, "temporaryEdit":"deleted",
            "historicalUniqueness":"not-established"})
    }
    fn pending(request: &Value) -> Value {
        let mut value = super::super::tests::pending(request);
        value["schemaVersion"] = json!(3);
        value["protocol"] = json!(PROTOCOL);
        value["reservation"]["requestSha256"] = json!(hash(REQUEST_DOMAIN, request).unwrap());
        value["reservation"]["storeObservations"] = json!([observation()]);
        let mut unsigned = value["reservation"].clone();
        unsigned.as_object_mut().unwrap().remove("sha256");
        value["reservation"]["sha256"] = json!(hash(RESERVATION_DOMAIN, &unsigned).unwrap());
        value
    }

    #[test]
    fn explicit_v3_keeps_legacy_domains_and_requires_one_confirmed_android_inventory() {
        let legacy = Request(super::super::tests::request());
        assert!(legacy.valid());
        assert_eq!(
            legacy.request_hash().unwrap(),
            hash(b"mrk:allocation-request:1\0", &legacy).unwrap()
        );
        let mut ios = request();
        ios["policy"]["schemaVersion"] = json!(2);
        ios["policy"]["storeScope"] = json!(ios_inventory::POLICY_SCOPE);
        ios["platforms"] = json!(["ios"]);
        let ios = Request(ios);
        assert!(ios.valid());
        assert_eq!(
            ios.request_hash().unwrap(),
            hash(ios_inventory::REQUEST_DOMAIN, &ios).unwrap()
        );
        let selected = Request(request());
        assert!(selected.valid());
        assert!(selected.observations_valid(&[observation()]));
        assert!(!ios.observations_valid(&[observation()]));
        assert!(!legacy.observations_valid(&[observation()]));
        for (key, bad) in [
            ("temporaryEdit", json!("unconfirmed")),
            ("contextRevision", json!("f".repeat(64))),
            ("platform", json!("ios")),
            ("marketingVersion", json!("9.9.9")),
            ("maxBuild", json!(0)),
            ("historicalUniqueness", json!("established")),
            ("complete", json!(false)),
        ] {
            let mut value = observation();
            value[key] = bad;
            assert!(!selected.observations_valid(&[value]));
        }
        for platforms in [json!(["ios"]), json!(["android", "ios"])] {
            let mut value = request();
            value["platforms"] = platforms;
            assert!(!Request(value).valid());
        }
        let value: Pending = decode(pending(&selected.0)).unwrap();
        value.valid().unwrap();
        for (version, protocol) in [(1, ALLOCATION_PROTOCOL), (2, ios_inventory::PROTOCOL)] {
            let mut invalid = pending(&selected.0);
            invalid["schemaVersion"] = json!(version);
            invalid["protocol"] = json!(protocol);
            assert!(decode::<Pending>(invalid).unwrap().valid().is_err());
        }
    }

    #[test]
    fn android_candidate_uses_same_private_namespace_pending_and_durable_retry_ack() {
        let fixture = Fixture::new();
        let (store, mut port) = super::super::tests::prepared(&fixture);
        let previous = port.selected_request().unwrap().clone();
        let mut template = request();
        template.as_object_mut().unwrap().remove("candidateId");
        port.select_new(template, Some(&previous)).unwrap();
        let selected = port.selected_request().unwrap().clone();
        assert!(dialogue::Request::from_port(
            &port,
            "android-inventory-fixture",
            dialogue::Kind::Reserve,
            "17",
            dialogue::Clock::new(1, 2).unwrap(),
            &[observation()]
        )
        .is_ok());
        assert!(dialogue::Request::from_port(
            &port,
            "android-inventory-fixture",
            dialogue::Kind::Reserve,
            "17",
            dialogue::Clock::new(1, 2).unwrap(),
            &[]
        )
        .is_err());
        let pending = pending(&selected);
        let before = port.snapshot().unwrap().revision;
        port.apply(before, &selected, Transition::Pending(pending.clone()))
            .unwrap();
        let recorded = State::parse(&store.read(Namespace::VersionAllocations).unwrap()).unwrap();
        assert_eq!(
            recorded.authorities[0]
                .pending
                .as_ref()
                .unwrap()
                .reservation
                .request
                .0,
            selected
        );
        let advanced = super::super::tests::advanced(&pending);
        port.apply(
            port.snapshot().unwrap().revision,
            &selected,
            Transition::Checkpoint(advanced.clone()),
        )
        .unwrap();
        port.apply(
            port.snapshot().unwrap().revision,
            &selected,
            Transition::Resolved {
                pending: pending.clone(),
                checkpoint: advanced.clone(),
            },
        )
        .unwrap();
        let before_retry = port.snapshot().unwrap().revision;
        port.apply(
            before_retry,
            &selected,
            Transition::Reused {
                reservation: pending["reservation"].clone(),
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
            before_retry.0 + 1
        );
        drop(port);
        store.close().unwrap();
    }

    #[test]
    fn android_receipt_context_binds_real_platform_saved_source_and_credential_revision() {
        let mut value = json!(crate::local_store_preflight_protocol::tests::context());
        value.as_object_mut().unwrap().remove("operation");
        value["platform"] = json!("android");
        value["query"] = json!(wire::QUERY);
        let context = crate::local_store_preflight_protocol::prepare(&value)
            .unwrap()
            .context();
        let mut selected = request();
        selected["source"]["configurationSha256"] = json!(context.saved_config.sha256);
        selected["source"]["versionSha256"] = json!(context.saved_version.sha256);
        selected["baseVersion"] =
            json!({"name":context.saved_version.name,"build":context.saved_version.build});
        selected["storeContextRevision"] = json!(current_context_digest(&context).unwrap());
        assert!(request_context_matches(
            &Request(selected.clone()),
            &context
        ));
        for key in ["configurationSha256", "versionSha256"] {
            let mut changed = selected.clone();
            changed["source"][key] = json!("e".repeat(64));
            assert!(!request_context_matches(&Request(changed), &context));
        }
        value["credentialContextRevision"] = json!(context.credential_context_revision + 1);
        let changed = crate::local_store_preflight_protocol::prepare(&value)
            .unwrap()
            .context();
        assert!(!request_context_matches(&Request(selected), &changed));
    }
}
