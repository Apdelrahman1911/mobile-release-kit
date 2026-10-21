//! Additive request/pending DATA. Source still names the genuine branch B;
//! selecting a future tag neither moves a ref nor supplies a publishing grant.
use super::{closed, full_ref, Request};
use serde_json::Value;

pub(super) const PROTOCOL: &str = "mrk-version-allocation/5";
pub(super) const REQUEST_DOMAIN: &[u8] = b"mrk:allocation-request:5\0";
pub(super) const RESERVATION_DOMAIN: &[u8] = b"mrk:allocation-reservation:5\0";

pub(crate) fn reference(value: &str) -> bool {
    value.starts_with("refs/tags/") && full_ref(value)
}

/// The old exact shape remains exact. Null, unknown keys and a branch in the
/// optional tag slot are not aliases for the old shape. No Value clone.
pub(super) fn fields(value: &Value, old: &[&str]) -> bool {
    if let Some(tag) = value.get("futureTag") {
        tag.as_str().is_some_and(reference)
            && value
                .as_object()
                .is_some_and(|v| v.len() == old.len() + 1 && old.iter().all(|k| v.contains_key(*k)))
    } else {
        closed(value, old)
    }
}

pub(super) fn request_valid(request: &Request) -> bool {
    let Some(tag) = request.0.get("futureTag") else {
        return true;
    };
    tag.as_str().is_some_and(reference)
        && matches!(request.schema_version(), 2 | 3 | 4)
        && request.0["source"]["ref"]
            .as_str()
            .is_some_and(|r| r.starts_with("refs/heads/") && full_ref(r))
        && request.0["policy"]["mode"] == "automatic"
        && request.0["policy"]["rules"]
            .as_array()
            .is_some_and(|rules| rules.iter().any(|r| r["ref"] == *tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn future_tag_shapes_do_not_relabel_branch_or_accept_null() {
        for tag in ["refs/tags/v1.2", "refs/tags/release/next"] {
            assert!(reference(tag));
        }
        for tag in [
            "refs/heads/main",
            "refs/tags/",
            "refs/tags/v1\n",
            "refs/tags/a.lock",
            "refs/tags/a..b",
            "refs/tags/refs/x",
        ] {
            assert!(!reference(tag));
        }
        assert!(fields(&json!({"source":0}), &["source"]));
        assert!(fields(
            &json!({"source":0,"futureTag":"refs/tags/v1"}),
            &["source"]
        ));
        assert!(!fields(&json!({"source":0,"futureTag":null}), &["source"]));
        assert!(!fields(
            &json!({"source":0,"futureTag":"refs/tags/v1","extra":0}),
            &["source"]
        ));
    }

    #[test]
    fn future_wire_domain_is_separate_from_real_inventory_policy() {
        let old = Request(
            json!({"policy":{"schemaVersion":2,"mode":"automatic","rules":[{"ref":"refs/heads/main","increment":"build"}]},
            "source":{"ref":"refs/heads/main"}}),
        );
        assert!(request_valid(&old));
        assert_eq!(old.wire_version(), 2);
        let mut new = old.clone();
        new.0["futureTag"] = json!("refs/tags/v9");
        assert!(!request_valid(&new));
        new.0["policy"]["rules"][0]["ref"] = json!("refs/tags/v9");
        assert!(request_valid(&new));
        assert_eq!(new.schema_version(), 2);
        assert_eq!(new.wire_version(), 5);
        assert_ne!(old.request_hash().unwrap(), new.request_hash().unwrap());
        assert_eq!(new.reservation_domain(), RESERVATION_DOMAIN);
        new.0["source"]["ref"] = json!("refs/tags/v9");
        assert!(!request_valid(&new));
        new.0["source"]["ref"] = json!("refs/heads/main");
        new.0["policy"]["schemaVersion"] = json!(1);
        assert!(!request_valid(&new));
    }

    #[test]
    fn v5_pending_uses_the_same_retained_port_and_never_relabels_inventory_or_source() {
        use super::super::{hash, Transition};
        let fixture = crate::application_state_store::Fixture::new();
        let (store, mut port) = super::super::tests::prepared(&fixture);
        let previous = port.selected_request().unwrap().clone();
        let mut template = super::super::tests::request();
        template.as_object_mut().unwrap().remove("candidateId");
        template["platforms"] = json!(["ios"]);
        template["policy"]["schemaVersion"] = json!(2);
        template["policy"]["storeScope"] = json!("require-current-ios-inventory");
        template["policy"]["buildCeiling"] = json!(9999);
        template["policy"]["rules"][0]["ref"] = json!("refs/tags/release-next");
        template["futureTag"] = json!("refs/tags/release-next");
        template["storeContextRevision"] = json!("a".repeat(64));
        let original_source = template["source"].clone();
        port.select_new(template, Some(&previous)).unwrap();
        let selected = port.selected_request().unwrap().clone();
        let mut pending = super::super::tests::pending(&selected);
        pending["schemaVersion"] = json!(5);
        pending["protocol"] = json!(PROTOCOL);
        pending["reservation"]["requestSha256"] = json!(hash(REQUEST_DOMAIN, &selected).unwrap());
        pending["reservation"]["storeObservations"] = json!([{
            "platform":"ios", "scope":"asc-ios-current-inventory/1", "identityRevision":"b".repeat(64),
            "contextRevision":"a".repeat(64), "revision":"d".repeat(64), "observedAt":2000,
            "maxBuild":0, "marketingVersion":"2.0.0", "counts":{"builds":0,"buildUploads":0,"appStoreVersions":1},
            "complete":true, "formatSupported":true, "historicalUniqueness":"not-established"
        }]);
        let mut unsigned = pending["reservation"].clone();
        unsigned.as_object_mut().unwrap().remove("sha256");
        pending["reservation"]["sha256"] = json!(hash(RESERVATION_DOMAIN, &unsigned).unwrap());
        port.apply(
            port.snapshot().unwrap().revision,
            &selected,
            Transition::Pending(pending.clone()),
        )
        .unwrap();
        let retained = port.snapshot().unwrap();
        assert_eq!(port.selected_request().unwrap(), &selected);
        assert_eq!(selected["source"], original_source);
        assert_eq!(selected["policy"]["schemaVersion"], 2);
        // A legacy label cannot reinterpret a retained v5 request or gain an ACK.
        let mut wrong = pending.clone();
        wrong["schemaVersion"] = json!(2);
        wrong["protocol"] = json!(super::super::ios_inventory::PROTOCOL);
        assert!(port
            .apply(retained.revision, &selected, Transition::Pending(wrong))
            .is_err());
        assert_eq!(port.snapshot().unwrap().revision, retained.revision);
        let advanced = super::super::tests::advanced(&pending);
        port.apply(
            retained.revision,
            &selected,
            Transition::Checkpoint(advanced.clone()),
        )
        .unwrap();
        port.apply(
            port.snapshot().unwrap().revision,
            &selected,
            Transition::Resolved {
                pending,
                checkpoint: advanced,
            },
        )
        .unwrap();
        assert_eq!(port.selected_request().unwrap(), &selected);
        drop(port);
        store.close().unwrap();
    }
}
