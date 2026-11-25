//! v4 paired current inventories, on the SAME state port and ledger. Native
//! validates binding/shape; the existing Python policy is still sole proposer.
use super::*;
use crate::local_store_preflight_protocol::{paired_versions as wire, Context};
pub(super) const PROTOCOL: &str = "mrk-version-allocation/4";
pub(super) const REQUEST_DOMAIN: &[u8] = b"mrk:allocation-request:4\0";
pub(super) const RESERVATION_DOMAIN: &[u8] = b"mrk:allocation-reservation:4\0";
pub(super) const POLICY_SCOPE: &str = "require-current-shared-inventory";

pub(super) fn observations_shape(values: &[Value], request: &Request) -> bool {
    values.len() == 2
        && play_inventory::observation_shape(&values[0], request)
        && ios_inventory::observation_shape(&values[1], request)
        && values[0]["observedAt"] == values[1]["observedAt"]
}
pub(super) fn context_digest(context: &Context) -> Result<String> {
    need(wire::selected(context))?;
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(
            context,
            crate::local_store_preflight_protocol::IPC_LIMIT
        )?)
    ))
}
fn request_context_matches(request: &Request, context: &Context) -> bool {
    request.valid()
        && request.schema_version() == 4
        && wire::selected(context)
        && context_digest(context).is_ok_and(|hash| request.0["storeContextRevision"] == hash)
        && request.0["source"]["configurationSha256"] == context.saved_config.sha256
        && request.0["source"]["versionSha256"] == context.saved_version.sha256
        && request.0["baseVersion"]["name"] == context.saved_version.name
        && request.0["baseVersion"]["build"] == context.saved_version.build
}
pub(super) fn observation_data(
    original: &crate::saved_command_owner::StoreVersionObservation,
    port: &VersionAllocationStatePort,
) -> Result<Value> {
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
    let pair = original
        .summary()
        .pair()
        .ok_or_else(|| StateError::from(Error::InvalidRequest))?;
    need(pair.observed())?;
    let context = context_digest(original.context())?;
    let android = &pair.android;
    let ios = &pair.ios;
    // Both entries use the actual earliest native admission, never two fresh
    // times or a later second-query window. No renderer-supplied receipt.
    Ok(json!([
        {"platform":"android","scope":crate::local_store_preflight_protocol::play_versions::COVERAGE,
         "identityRevision":request.0["identityRevision"],"contextRevision":context,
         "revision":android.revision,"observedAt":original.observed_at(),"maxBuild":android.max_build,
         "marketingVersion":null,"counts":android.counts,"complete":true,"formatSupported":true,
         "temporaryEdit":"deleted","historicalUniqueness":"not-established"},
        {"platform":"ios","scope":crate::local_store_preflight_protocol::store_versions::COVERAGE,
         "identityRevision":request.0["identityRevision"],"contextRevision":context,
         "revision":ios.revision,"observedAt":original.observed_at(),"maxBuild":ios.max_build,
         "marketingVersion":ios.marketing_version,"counts":ios.counts,"complete":true,"formatSupported":true,
         "historicalUniqueness":"not-established"}
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        let mut r = super::super::tests::request();
        r["platforms"] = json!(["android", "ios"]);
        r["policy"]["schemaVersion"] = json!(4);
        r["policy"]["storeScope"] = json!(POLICY_SCOPE);
        r["policy"]["buildCeiling"] = json!(9999);
        r["storeContextRevision"] = json!("a".repeat(64));
        r
    }
    fn observations() -> Vec<Value> {
        vec![
            json!({"platform":"android","scope":"play-android-current-inventory/1","identityRevision":"b".repeat(64),"contextRevision":"a".repeat(64),"revision":"c".repeat(64),"observedAt":2000,"maxBuild":12,"marketingVersion":null,"counts":{"tracks":2,"releases":2,"versionCodes":3,"bundles":0,"apks":1},"complete":true,"formatSupported":true,"temporaryEdit":"deleted","historicalUniqueness":"not-established"}),
            json!({"platform":"ios","scope":"asc-ios-current-inventory/1","identityRevision":"b".repeat(64),"contextRevision":"a".repeat(64),"revision":"d".repeat(64),"observedAt":2000,"maxBuild":0,"marketingVersion":"2.0.0","counts":{"builds":0,"buildUploads":0,"appStoreVersions":1},"complete":true,"formatSupported":true,"historicalUniqueness":"not-established"}),
        ]
    }
    #[test]
    fn v4_order_and_earliest_time_do_not_reinterpret_v1_v2_v3_domains() {
        let r = Request(request());
        assert!(r.valid());
        assert!(r.observations_valid(&observations()));
        assert_eq!(r.request_hash().unwrap(), hash(REQUEST_DOMAIN, &r).unwrap());
        for version in [1, 2, 3] {
            let mut old = request();
            old["policy"]["schemaVersion"] = json!(version);
            if version == 1 {
                old["policy"].as_object_mut().unwrap().remove("storeScope");
                old.as_object_mut().unwrap().remove("storeContextRevision");
            } else {
                old["platforms"] = if version == 2 {
                    json!(["ios"])
                } else {
                    json!(["android"])
                };
                old["policy"]["storeScope"] = json!(if version == 2 {
                    ios_inventory::POLICY_SCOPE
                } else {
                    play_inventory::POLICY_SCOPE
                });
            }
            let old = Request(old);
            assert!(old.valid());
            assert!(!old.observations_valid(&observations()));
            assert_ne!(old.request_hash().unwrap(), r.request_hash().unwrap());
        }
        for index in 0..2 {
            for (key, bad) in [
                ("observedAt", json!(2001)),
                ("contextRevision", json!("f".repeat(64))),
                ("complete", json!(false)),
            ] {
                let mut obs = observations();
                obs[index][key] = bad;
                assert!(!r.observations_valid(&obs));
            }
        }
        let mut reversed = observations();
        reversed.reverse();
        assert!(!r.observations_valid(&reversed));
        assert!(!r.observations_valid(&observations()[..1]));
    }
    #[test]
    fn paired_candidate_pending_and_retry_use_the_original_namespace() {
        let fixture = crate::application_state_store::Fixture::new();
        let (store, mut port) = super::super::tests::prepared(&fixture);
        let previous = port.selected_request().unwrap().clone();
        let mut template = request();
        template.as_object_mut().unwrap().remove("candidateId");
        port.select_new(template, Some(&previous)).unwrap();
        let selected = port.selected_request().unwrap().clone();
        let mut p = super::super::tests::pending(&selected);
        p["schemaVersion"] = json!(4);
        p["protocol"] = json!(PROTOCOL);
        p["reservation"]["requestSha256"] = json!(hash(REQUEST_DOMAIN, &selected).unwrap());
        p["reservation"]["storeObservations"] = json!(observations());
        let mut unsigned = p["reservation"].clone();
        unsigned.as_object_mut().unwrap().remove("sha256");
        p["reservation"]["sha256"] = json!(hash(RESERVATION_DOMAIN, &unsigned).unwrap());
        port.apply(
            port.snapshot().unwrap().revision,
            &selected,
            Transition::Pending(p.clone()),
        )
        .unwrap();
        let advanced = super::super::tests::advanced(&p);
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
                pending: p.clone(),
                checkpoint: advanced.clone(),
            },
        )
        .unwrap();
        let before = port.snapshot().unwrap().revision;
        port.apply(
            before,
            &selected,
            Transition::Reused {
                reservation: p["reservation"].clone(),
                checkpoint: advanced,
            },
        )
        .unwrap();
        assert_eq!(port.selected_request().unwrap(), &selected);
        assert_eq!(port.snapshot().unwrap().revision.0, before.0 + 1);
        drop(port);
        store.close().unwrap();
    }
}
