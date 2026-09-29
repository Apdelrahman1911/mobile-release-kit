//! Qualification-observer DATA only, not native admission or exit authority.
//! Closed mode does not imply unavailable capability. The call site chooses
//! its expected lifecycle; neither mode nor the operation reason selects it.
//! The real caller retains status/bounds/serialization and the final lazy
//! document.assets_can_exit() check after this scalar predicate.
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lifecycle { Active, Lost, Final }

pub(crate) fn matches(value: &Value, id: u32, reason: &str, lifecycle: Lifecycle) -> bool {
    let (available, capability_reason) = match lifecycle {
        Lifecycle::Active => (true, "none"),
        Lifecycle::Lost => (false, "document-lost"),
        // status_data gives stopping precedence over lost_observed, even
        // when the original operation retains its document-lost reason.
        Lifecycle::Final => (false, "shutdown"),
    };
    let operation = &value["operation"];
    value["schemaVersion"] == 2 && value["mode"] == "closed" && value["capability"]["available"] == available
        && value["capability"]["reason"] == capability_reason
        && value["context"].is_null() && value["records"].as_array().is_some_and(Vec::is_empty)
        && value["assignments"].as_array().is_some_and(Vec::is_empty)
        && operation["operationId"] == id && operation["operation"] == "choose-project"
        && operation["phase"] == "idle" && operation["settlement"] == "known" && operation["reason"] == reason
        && operation["source"] == "not-run" && operation["selectionToken"].is_null()
        && operation["assessment"].is_null() && operation["preview"].is_null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Clone, Copy)]
    struct Case {
        label: &'static str, lifecycle: Lifecycle, id: u32, reason: &'static str,
        available: bool, capability_reason: &'static str,
    }
    // Five lifecycle/call-site states, including both selected-id values used
    // by the ordinary project-draft and lifecycle journeys.
    const CASES: [Case; 7] = [
        Case { label: "cancel-draft", lifecycle: Lifecycle::Active, id: 1, reason: "user-cancelled", available: true, capability_reason: "none" },
        Case { label: "selected-draft", lifecycle: Lifecycle::Active, id: 2, reason: "none", available: true, capability_reason: "none" },
        Case { label: "selected-lifecycle", lifecycle: Lifecycle::Active, id: 1, reason: "none", available: true, capability_reason: "none" },
        Case { label: "lost-before-quit", lifecycle: Lifecycle::Lost, id: 2, reason: "document-lost", available: false, capability_reason: "document-lost" },
        Case { label: "final-draft", lifecycle: Lifecycle::Final, id: 2, reason: "shutdown", available: false, capability_reason: "shutdown" },
        Case { label: "final-lifecycle", lifecycle: Lifecycle::Final, id: 1, reason: "shutdown", available: false, capability_reason: "shutdown" },
        Case { label: "final-lost", lifecycle: Lifecycle::Final, id: 2, reason: "document-lost", available: false, capability_reason: "shutdown" },
    ];
    fn status(case: Case) -> Value {
        json!({
            "schemaVersion": 2, "mode": "closed",
            "capability": { "available": case.available, "reason": case.capability_reason },
            "context": null, "records": [], "assignments": [],
            "operation": {
                "operationId": case.id, "operation": "choose-project", "phase": "idle",
                "settlement": "known", "reason": case.reason, "source": "not-run",
                "selectionToken": null, "assessment": null, "preview": null
            }
        })
    }
    fn accepts(value: &Value, case: Case) -> bool {
        matches(value, case.id, case.reason, case.lifecycle)
    }

    #[test]
    fn exact_callsite_states_keep_operation_reason_separate() {
        for case in CASES {
            assert!(accepts(&status(case), case), "{}", case.label);
        }
        let lost_final = CASES[6];
        let value = status(lost_final);
        assert_eq!(value["operation"]["reason"], "document-lost");
        assert_eq!(value["capability"]["reason"], "shutdown");
        assert!(!matches(&value, lost_final.id, lost_final.reason, Lifecycle::Lost));
    }

    #[test]
    fn every_other_lifecycle_capability_pair_is_refused() {
        const REASONS: [&str; 9] = [
            "none", "document-lost", "shutdown", "unsupported-platform",
            "unqualified", "closed", "cleanup-unknown", "NONE", "",
        ];
        for case in CASES {
            for available in [false, true] {
                for reason in REASONS {
                    let mut value = status(case);
                    value["capability"]["available"] = json!(available);
                    value["capability"]["reason"] = json!(reason);
                    assert_eq!(accepts(&value, case),
                        available == case.available && reason == case.capability_reason,
                        "{} / {available} / {reason}", case.label);
                }
            }
        }
        // In particular, the old unavailable-platform active assertion must
        // never return as an alternative to the current exact true/none pair.
        let case = CASES[0];
        let mut value = status(case);
        value["capability"] = json!({ "available": false, "reason": "unsupported-platform" });
        assert!(!accepts(&value, case));
    }

    #[test]
    fn missing_and_malformed_capability_values_are_refused() {
        for case in CASES {
            let mut missing = status(case);
            missing.as_object_mut().unwrap().remove("capability");
            assert!(!accepts(&missing, case), "{}", case.label);
            for bad in [Value::Null, json!({}), json!([]), json!(true), json!("none")] {
                let mut value = status(case);
                value["capability"] = bad;
                assert!(!accepts(&value, case), "{}", case.label);
            }
            for key in ["available", "reason"] {
                let mut missing = status(case);
                missing["capability"].as_object_mut().unwrap().remove(key);
                assert!(!accepts(&missing, case), "{} / {key}", case.label);
                for bad in [Value::Null, json!(0), json!([]), json!({})] {
                    let mut value = status(case);
                    value["capability"][key] = bad;
                    assert!(!accepts(&value, case), "{} / {key}", case.label);
                }
            }
            let mut text_boolean = status(case);
            text_boolean["capability"]["available"] = json!(case.available.to_string());
            assert!(!accepts(&text_boolean, case), "{}", case.label);
            let mut boolean_reason = status(case);
            boolean_reason["capability"]["reason"] = json!(false);
            assert!(!accepts(&boolean_reason, case), "{}", case.label);
        }
    }

    #[test]
    fn every_scalar_settlement_and_empty_state_guard_is_preserved() {
        for case in CASES {
            let original = status(case);
            let mutations = [
                ("/schemaVersion", json!(1)),
                ("/schemaVersion", json!("2")),
                ("/mode", json!("session")),
                ("/context", json!({})),
                ("/records", json!([{}])),
                ("/records", Value::Null),
                ("/assignments", json!([{}])),
                ("/assignments", Value::Null),
                ("/operation/operationId", json!(case.id + 1)),
                ("/operation/operationId", json!(case.id.to_string())),
                ("/operation/operation", json!("choose-file")),
                ("/operation/phase", json!("cleanup")),
                ("/operation/settlement", json!("unknown")),
                ("/operation/reason", json!("unexpected")),
                ("/operation/source", json!("pending")),
                ("/operation/selectionToken", json!("stale")),
                ("/operation/assessment", json!({})),
                ("/operation/preview", json!({})),
            ];
            for (pointer, bad) in mutations {
                let mut value = original.clone();
                *value.pointer_mut(pointer).unwrap() = bad;
                assert!(!accepts(&value, case), "{} / {pointer}", case.label);
            }
        }
    }

    #[test]
    fn missing_required_scalar_and_collection_fields_are_refused() {
        for case in CASES {
            for key in ["schemaVersion", "mode", "records", "assignments", "operation"] {
                let mut value = status(case);
                value.as_object_mut().unwrap().remove(key);
                assert!(!accepts(&value, case), "{} / {key}", case.label);
            }
            for key in ["operationId", "operation", "phase", "settlement", "reason", "source"] {
                let mut value = status(case);
                value["operation"].as_object_mut().unwrap().remove(key);
                assert!(!accepts(&value, case), "{} / {key}", case.label);
            }
        }
    }

    #[test]
    fn expected_operation_binding_is_not_inferred_from_status() {
        for case in CASES {
            let value = status(case);
            assert!(!matches(&value, case.id + 1, case.reason, case.lifecycle), "{}", case.label);
            assert!(!matches(&value, case.id, "unexpected", case.lifecycle), "{}", case.label);
        }
    }

    #[test]
    fn existing_nullable_value_indexing_semantics_are_unchanged() {
        // The old predicate used Value indexing followed by is_null, not
        // presence validation. Preserve that behavior for these nullable
        // fields only; missing required fields and capability pairs fail above.
        for case in CASES {
            let mut value = status(case);
            value.as_object_mut().unwrap().remove("context");
            for key in ["selectionToken", "assessment", "preview"] {
                value["operation"].as_object_mut().unwrap().remove(key);
            }
            assert!(accepts(&value, case), "{}", case.label);
        }
    }
}
