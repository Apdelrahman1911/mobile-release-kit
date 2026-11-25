//! Five fixed raw-JSON commands for the ORIGINAL identity EditOwner.
//! Renderer intent/correlation DATA only; no continuity, root, path grant,
//! credential, process, registration or alternative command endpoint.
use crate::{
    edit_commands,
    edit_protocol::token,
    error::BridgeError,
    project_identity_edit_protocol::{self as wire, Apply, Open, Prepare, Submission},
    protocol::{check_value, strict_json},
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

fn raw(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > wire::REQUEST_LIMIT {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !value.is_object() {
        return Err(BridgeError::invalid());
    }
    check_value(&value).map_err(|_| BridgeError::invalid())?;
    Ok(value)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BridgeError> {
    T::deserialize(&raw(bytes)?).map_err(|_| BridgeError::invalid())
}
pub(crate) fn open(bytes: &[u8]) -> Result<Open, BridgeError> {
    let value: Open = decode(bytes)?;
    if !value.valid() {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}
pub(crate) fn prepare(bytes: &[u8]) -> Result<Prepare, BridgeError> {
    let value: Prepare = decode(bytes)?;
    if !token(value.session_id()) || !token(value.revision()) {
        return Err(BridgeError::invalid());
    }
    if let Submission::Edit {
        desired_identity, ..
    } = value.submission()
    {
        // Bounded scalar only. The original retained selection/core enforce
        // the actual platform's application-ID grammar and continuity policy.
        if desired_identity.is_empty()
            || desired_identity.len() > 255
            || desired_identity
                .chars()
                .any(|c| c <= '\u{1f}' || c == '\u{7f}')
        {
            return Err(BridgeError::invalid());
        }
    }
    Ok(value)
}
pub(crate) fn apply(bytes: &[u8]) -> Result<Apply, BridgeError> {
    let value: Apply = decode(bytes)?;
    if !token(&value.session_id)
        || !token(&value.revision)
        || !token(&value.plan_token)
        || value.plan_token == value.revision
    {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}
pub(crate) fn close(bytes: &[u8]) -> Result<edit_commands::Close, BridgeError> {
    edit_commands::close(&raw(bytes)?)
}
pub(crate) fn status(bytes: &[u8]) -> Result<edit_commands::Status, BridgeError> {
    edit_commands::status(&raw(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }
    fn open_data() -> Value {
        json!({"intent":"edit","projectId":"a".repeat(32),"selection":{"platform":"android","target":":app","project":null}})
    }
    fn prepare_data() -> Value {
        json!({"intent":"edit","sessionId":"b".repeat(32),"revision":"c".repeat(32),
            "desiredIdentity":"com.example.newapp","identityIntent":"new-application"})
    }
    #[test]
    fn raw_open_has_only_target_intent_and_registered_id_not_continuity_or_root() {
        let original = open_data();
        assert!(open(&bytes(&original)).is_ok());
        for key in [
            "continuity",
            "root",
            "registeredIdentity",
            "force",
            "published",
            "planToken",
        ] {
            let mut changed = original.clone();
            changed[key] = json!("unknown");
            assert!(open(&bytes(&changed)).is_err());
        }
        let mut changed = original.clone();
        changed["selection"]["continuity"] = json!("unknown");
        assert!(open(&bytes(&changed)).is_err());
        changed = original;
        changed["selection"]
            .as_object_mut()
            .unwrap()
            .remove("project");
        assert!(open(&bytes(&changed)).is_err());
        assert!(open(&bytes(
            &json!({"intent":"recover","projectId":"a".repeat(32)})
        ))
        .is_ok());
        assert!(open(&bytes(
            &json!({"intent":"recover","projectId":"a".repeat(32),"selection":{}})
        ))
        .is_err());
    }
    #[test]
    fn prepare_and_apply_are_closed_and_bind_original_session_revision_and_mode() {
        let p = prepare_data();
        assert!(prepare(&bytes(&p)).is_ok());
        for (key, value) in [
            ("intent", json!("replace")),
            ("revision", json!("bad")),
            ("sessionId", Value::Null),
            ("desiredIdentity", json!("a".repeat(256))),
            ("desiredIdentity", json!("com.example.app\n")),
            ("identityIntent", json!("force")),
            ("root", json!("/inert")),
        ] {
            let mut bad = p.clone();
            bad[key] = value;
            assert!(prepare(&bytes(&bad)).is_err());
        }
        let recover =
            json!({"intent":"recover","sessionId":"b".repeat(32),"revision":"c".repeat(32)});
        assert!(prepare(&bytes(&recover)).is_ok());
        let mut bad = recover;
        bad["desiredIdentity"] = json!("com.example.newapp");
        assert!(prepare(&bytes(&bad)).is_err());
        let a = json!({"intent":"edit","sessionId":"b".repeat(32),"revision":"c".repeat(32),"planToken":"d".repeat(32)});
        assert!(apply(&bytes(&a)).is_ok());
        for (key, value) in [
            ("intent", Value::Null),
            ("revision", json!("bad")),
            ("planToken", json!("c".repeat(32))),
            ("desiredIdentity", json!("com.example.other")),
        ] {
            let mut bad = a.clone();
            bad[key] = value;
            assert!(apply(&bytes(&bad)).is_err());
        }
    }
    #[test]
    fn raw_json_duplicates_utf8_trailing_data_and_capacity_never_reach_an_owner() {
        for bad in [
            b"{\"intent\":\"edit\",\"intent\":\"recover\"}".as_slice(),
            b"{}{}",
            b"[]",
            b"null",
            b"{\"value\":NaN}",
            &[0xffu8][..],
        ] {
            assert!(raw(bad).is_err());
        }
        let mut too_large = vec![b' '; wire::REQUEST_LIMIT + 1];
        too_large[..2].copy_from_slice(b"{}");
        assert!(raw(&too_large).is_err());
        let deep = format!("{{\"a\":{}0{}}}", "[".repeat(65), "]".repeat(65));
        assert!(raw(deep.as_bytes()).is_err());
    }
    #[test]
    fn close_and_status_keep_original_small_exact_shapes() {
        assert!(close(&bytes(&json!({"sessionId":"b".repeat(32)}))).is_ok());
        assert!(close(&bytes(
            &json!({"sessionId":"b".repeat(32),"intent":"recover"})
        ))
        .is_err());
        assert!(status(b"{}").is_ok());
        assert!(status(b"{\"force\":true}").is_err());
        assert!(status(b"{\"a\":1,\"a\":2}").is_err());
    }
}
