//! Closed one-request/one-response protocol. No generic process or method IPC.
use std::{collections::BTreeSet, fmt, io};
use serde::{de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor}, Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use crate::error::BridgeError;

pub const PROTOCOL: u32 = 1;
pub const REQUEST_LIMIT: usize = 1024 * 1024;
pub const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
pub const STDERR_LIMIT: usize = 64 * 1024;
pub const DEPTH_LIMIT: usize = 32;
pub const NODE_LIMIT: usize = 20_000;

#[derive(Clone, Copy, Debug)]
pub enum Method { Capabilities, Catalog, ProjectSnapshot, ValidateConfig, SuggestConfig, PreviewConfig, ProposeGithubSetup, AssessCredentials, MetadataTextObserve, MetadataTextValidate, EnvironmentRequirements, ReleaseVersionObserve, CandidateEvidenceObserve }
impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities", Self::Catalog => "catalog",
            Self::ProjectSnapshot => "project.snapshot", Self::ValidateConfig => "config.validate",
            Self::SuggestConfig => "config.suggest", Self::PreviewConfig => "config.preview",
            Self::ProposeGithubSetup => "github.setup.propose",
            Self::AssessCredentials => "credentials.assess",
            Self::MetadataTextObserve => "metadata.text.observe",
            Self::MetadataTextValidate => "metadata.text.validate",
            Self::EnvironmentRequirements => "environment.requirements",
            Self::ReleaseVersionObserve => "release.version.observe",
            Self::CandidateEvidenceObserve => "artifacts.candidate.observe",
        }
    }
}

#[derive(Serialize)]
struct Request<'a> { protocol: u32, id: &'a str, method: &'a str, params: &'a Value }

struct BoundedWriter { bytes: Vec<u8>, limit: usize }
impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bounded JSON output exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn check_value(value: &Value) -> Result<(), BridgeError> {
    let mut stack = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((item, depth)) = stack.pop() {
        nodes += 1;
        if nodes > NODE_LIMIT || depth > DEPTH_LIMIT { return Err(BridgeError::invalid()); }
        match item {
            Value::Array(items) => {
                if depth >= DEPTH_LIMIT { return Err(BridgeError::invalid()); }
                if items.len() > NODE_LIMIT.saturating_sub(nodes + stack.len()) { return Err(BridgeError::invalid()); }
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            Value::Object(items) => {
                if depth >= DEPTH_LIMIT { return Err(BridgeError::invalid()); }
                // Python counts object keys as value nodes at depth + 1 too.
                if !items.is_empty() && depth + 1 > DEPTH_LIMIT { return Err(BridgeError::invalid()); }
                nodes = nodes.checked_add(items.len()).ok_or_else(BridgeError::invalid)?;
                if nodes > NODE_LIMIT { return Err(BridgeError::invalid()); }
                if items.len() > NODE_LIMIT.saturating_sub(nodes + stack.len()) { return Err(BridgeError::invalid()); }
                stack.extend(items.values().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn encode_request(id: &str, method: Method, params: &Value) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) { return Err(BridgeError::invalid()); }
    // Account for the envelope's additional depth and nodes, not just params.
    let request = Request { protocol: PROTOCOL, id, method: method.name(), params };
    check_value(params)?;
    let mut writer = BoundedWriter { bytes: Vec::new(), limit: REQUEST_LIMIT - 1 };
    serde_json::to_writer(&mut writer, &request).map_err(|_| BridgeError::invalid())?;
    // Strict parser also applies the envelope-inclusive depth/node contract.
    strict_json(&writer.bytes).map_err(|_| BridgeError::invalid())?;
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

struct Seed<'a> { nodes: &'a mut usize, depth: usize, node_limit: usize, depth_limit: usize }
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        *self.nodes += 1;
        if *self.nodes > self.node_limit || self.depth > self.depth_limit { return Err(de::Error::custom("JSON bounds exceeded")); }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("bounded strict JSON") }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> { Ok(Value::Bool(v)) }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> { Ok(Value::Number(v.into())) }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> { Ok(Value::Number(v.into())) }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| de::Error::custom("nonfinite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> { Ok(Value::String(v.to_owned())) }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> { Ok(Value::String(v)) }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= self.depth_limit { return Err(de::Error::custom("container nesting exceeded")); }
        let mut items = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed { nodes: self.nodes, depth: self.depth + 1,
            node_limit: self.node_limit, depth_limit: self.depth_limit })? { items.push(value); }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= self.depth_limit { return Err(de::Error::custom("container nesting exceeded")); }
        let mut items = Map::new();
        let mut names = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            *self.nodes += 1;
            if *self.nodes > self.node_limit || self.depth + 1 > self.depth_limit { return Err(de::Error::custom("JSON bounds exceeded")); }
            if !names.insert(key.clone()) { return Err(de::Error::custom("duplicate JSON key")); }
            let value = map.next_value_seed(Seed { nodes: self.nodes, depth: self.depth + 1,
                node_limit: self.node_limit, depth_limit: self.depth_limit })?;
            items.insert(key, value);
        }
        Ok(Value::Object(items))
    }
}

fn strict_json_with_limits(bytes: &[u8], node_limit: usize, depth_limit: usize) -> Result<Value, BridgeError> {
    std::str::from_utf8(bytes).map_err(|_| BridgeError::protocol())?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0usize;
    let value = Seed { nodes: &mut nodes, depth: 0, node_limit, depth_limit }
        .deserialize(&mut decoder).map_err(|_| BridgeError::protocol())?;
    decoder.end().map_err(|_| BridgeError::protocol())?;
    Ok(value)
}

pub fn strict_json(bytes: &[u8]) -> Result<Value, BridgeError> {
    strict_json_with_limits(bytes, NODE_LIMIT, DEPTH_LIMIT)
}

// Fixed protected Android-file admission only; never an IPC/renderer policy.
// The ordinary parser, runtime inventory and OS contract keep their old limits.
pub(crate) fn strict_android_tool_manifest_json(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.len() > crate::android_toolchain::MANIFEST_LIMIT { return Err(BridgeError::protocol()); }
    strict_json_with_limits(bytes, 150_000, 16)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineError { code: String, message: String, retryable: bool }

pub fn decode_response(bytes: &[u8], id: &str) -> Result<Value, BridgeError> {
    if bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}')
        || body.iter().any(|b| *b == b'\n' || *b == b'\r') { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    let object = value.as_object().ok_or_else(BridgeError::protocol)?;
    if object.get("protocol").and_then(Value::as_u64) != Some(u64::from(PROTOCOL))
        || object.get("id").and_then(Value::as_str) != Some(id) { return Err(BridgeError::protocol()); }
    let ok = object.get("ok").and_then(Value::as_bool).ok_or_else(BridgeError::protocol)?;
    let payload = if ok { "result" } else { "error" };
    if object.len() != 4 || !object.contains_key(payload) { return Err(BridgeError::protocol()); }
    if ok { return object.get("result").cloned().ok_or_else(BridgeError::protocol); }
    let error: EngineError = serde_json::from_value(object.get("error").cloned().ok_or_else(BridgeError::protocol)?)
        .map_err(|_| BridgeError::protocol())?;
    if error.retryable || !valid_id(&error.code) || error.message.is_empty() || error.message.len() > 1600
        || error.message.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}') {
        return Err(BridgeError::protocol());
    }
    let error = BridgeError::new(&error.code, &error.message);
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let error = error.with_linux_passive_cause(Some(crate::error::LinuxPassiveCause::EngineResponse));
    Err(error)
}

#[cfg(test)]
mod tests {
    // In-memory contract checks only: no child, IO, native SDK, or filesystem.
    use super::*;
    use serde_json::json;
    fn response(value: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&value).unwrap_or_default(); bytes.push(b'\n'); bytes
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[test]
    fn only_a_valid_engine_error_can_supply_the_engine_response_cause() {
        let valid = json!({"protocol":1,"id":"query-1","ok":false,
            "error":{"code":"runtime_unavailable","message":"inert engine message","retryable":false}});
        let error = decode_response(&response(valid.clone()), "query-1").unwrap_err();
        assert_eq!(error, BridgeError::new("runtime_unavailable", "inert engine message"));
        assert_eq!(error.linux_passive_cause(), Some(crate::error::LinuxPassiveCause::EngineResponse));
        let mut invalid = Vec::new();
        let mut row = valid.clone(); row["id"] = json!("other"); invalid.push(response(row));
        let mut row = valid.clone(); row["error"]["retryable"] = json!(true); invalid.push(response(row));
        let mut row = valid.clone(); row["error"]["message"] = json!("PRIVATE\nmessage"); invalid.push(response(row));
        let mut row = valid.clone(); row["error"]["code"] = json!("PRIVATE\ncode"); invalid.push(response(row));
        let mut row = valid.clone(); row["error"]["linux_passive_cause"] = json!("engine-response"); invalid.push(response(row));
        let mut row = valid.clone(); row["linux_passive_cause"] = json!("engine-response"); invalid.push(response(row));
        let mut frame = response(valid); frame.pop(); invalid.push(frame);
        for bytes in invalid {
            let error = decode_response(&bytes, "query-1").unwrap_err();
            assert_eq!(error.code, "protocol_error");
            assert_eq!(error.linux_passive_cause(), None);
        }
    }
    #[test]
    fn request_is_closed_correlated_and_newline_terminated() {
        let bytes = encode_request("query-1", Method::Capabilities, &json!({}));
        assert!(bytes.is_ok());
        let bytes = bytes.unwrap_or_default();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let parsed = strict_json(&bytes);
        assert_eq!(parsed.ok(), Some(json!({"protocol":1,"id":"query-1","method":"capabilities","params":{}})));
        for (method, name) in [(Method::SuggestConfig, "config.suggest"), (Method::PreviewConfig, "config.preview"),
                               (Method::ProposeGithubSetup, "github.setup.propose"),
                               (Method::MetadataTextObserve, "metadata.text.observe"), (Method::MetadataTextValidate, "metadata.text.validate"),
                               (Method::EnvironmentRequirements, "environment.requirements")] {
            let bytes = encode_request("query-2", method, &json!({})).unwrap_or_default();
            assert_eq!(strict_json(&bytes).ok().and_then(|value| value.get("method").cloned()), Some(json!(name)));
        }
    }
    #[test]
    fn assessment_method_has_only_the_fixed_wire_name() {
        // Registration only; no Supervisor, renderer invoke or native route.
        let bytes = encode_request("query-1", Method::AssessCredentials, &json!({})).unwrap_or_default();
        assert_eq!(strict_json(&bytes).ok(), Some(json!({
            "protocol": 1, "id": "query-1", "method": "credentials.assess", "params": {}
        })));
    }
    #[test]
    fn rejects_duplicates_at_every_object_depth() {
        assert!(strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json(br#"{"a":{"b":1,"b":2}}"#).is_err());
    }
    #[test]
    fn rejects_nonfinite_and_invalid_utf8() {
        for bytes in [b"NaN".as_slice(), b"Infinity", b"1e9999", &[0xff]] { assert!(strict_json(bytes).is_err()); }
    }
    #[test]
    fn depth_zero_and_thirty_two_are_the_shared_boundary() {
        let mut value = Value::Null;
        for _ in 0..DEPTH_LIMIT { value = Value::Array(vec![value]); }
        assert!(check_value(&value).is_ok());
        assert!(strict_json(&serde_json::to_vec(&value).unwrap_or_default()).is_ok());
        value = Value::Array(vec![value]);
        assert!(check_value(&value).is_err());
        assert!(strict_json(&serde_json::to_vec(&value).unwrap_or_default()).is_err());
    }
    #[test]
    fn object_keys_count_toward_the_node_limit() {
        let mut map = Map::new();
        for index in 0..9999 { map.insert(format!("key{index}"), Value::Null); }
        let mut value = Value::Object(map);
        assert!(check_value(&value).is_ok());
        assert!(strict_json(&serde_json::to_vec(&value).unwrap_or_default()).is_ok());
        if let Value::Object(map) = &mut value { map.insert("extra".into(), Value::Null); }
        assert!(check_value(&value).is_err());
        assert!(strict_json(&serde_json::to_vec(&value).unwrap_or_default()).is_err());
    }
    #[test]
    fn android_manifest_bounds_do_not_widen_the_ordinary_parser() {
        // JSON DATA only, not a tool manifest/profile or an installed capability.
        let mut value = Value::Array(vec![Value::Null; 149_999]);
        let raw = serde_json::to_vec(&value).unwrap();
        assert!(strict_android_tool_manifest_json(&raw).is_ok());
        assert!(strict_json(&raw).is_err());
        if let Value::Array(items) = &mut value { items.push(Value::Null); }
        assert!(strict_android_tool_manifest_json(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut nested = Value::Null;
        for _ in 0..16 { nested = Value::Array(vec![nested]); }
        assert!(strict_android_tool_manifest_json(&serde_json::to_vec(&nested).unwrap()).is_ok());
        nested = Value::Array(vec![nested]);
        let raw = serde_json::to_vec(&nested).unwrap();
        assert!(strict_android_tool_manifest_json(&raw).is_err() && strict_json(&raw).is_ok());
        for raw in [br#"{"a":1,"a":2}"#.as_slice(), b"NaN", b"{} {}", &[0xff]] {
            assert!(strict_android_tool_manifest_json(raw).is_err());
        }
        assert!(strict_android_tool_manifest_json(&vec![b' '; crate::android_toolchain::MANIFEST_LIMIT + 1]).is_err());
        assert_eq!((NODE_LIMIT, DEPTH_LIMIT), (20_000, 32));
    }
    #[test]
    fn thirty_third_empty_container_is_not_a_depth_thirty_two_scalar() {
        let mut value = Value::Array(Vec::new());
        for _ in 0..DEPTH_LIMIT { value = Value::Array(vec![value]); }
        assert!(check_value(&value).is_err());
        assert!(strict_json(&serde_json::to_vec(&value).unwrap_or_default()).is_err());
    }
    #[test]
    fn response_rejects_wrong_identity_unknown_keys_and_extra_frames() {
        for value in [
            json!({"protocol":1,"id":"other","ok":true,"result":{}}),
            json!({"protocol":true,"id":"query-1","ok":true,"result":{}}),
            json!({"protocol":1,"id":"query-1","ok":true,"result":{},"extra":0}),
            json!({"protocol":1,"id":"query-1","ok":"true","result":{}}),
        ] { assert!(decode_response(&response(value), "query-1").is_err()); }
        let bytes = response(json!({"protocol":1,"id":"query-1","ok":true,"result":{}}));
        assert!(decode_response(&[bytes.clone(), bytes].concat(), "query-1").is_err());
    }
    #[test]
    fn response_requires_exact_outer_framing_and_eof_bytes() {
        let valid = response(json!({"protocol":1,"id":"query-1","ok":true,"result":{"state":"unknown"}}));
        assert!(decode_response(&valid, "query-1").is_ok());
        assert!(decode_response(&valid[..valid.len()-1], "query-1").is_err());
        assert!(decode_response(&[b" ".to_vec(), valid.clone()].concat(), "query-1").is_err());
        let mut trailing = valid[..valid.len()-1].to_vec(); trailing.extend_from_slice(b" \n");
        assert!(decode_response(&trailing, "query-1").is_err());
    }
    #[test]
    fn service_errors_preserve_the_bounded_utf8_contract() {
        let error = |message: String| response(json!({"protocol":1,"id":"query-1","ok":false,"error":{"code":"invalid_params","message":message,"retryable":false}}));
        let result = decode_response(&error("é".repeat(800)), "query-1");
        assert_eq!(result.err().map(|error| error.code), Some("invalid_params".into()));
        for message in [String::new(), "é".repeat(801), "bad\0value".into()] {
            assert_eq!(decode_response(&error(message), "query-1").err().map(|error| error.code), Some("protocol_error".into()));
        }
        assert_eq!(decode_response(&error("\u{85}".into()), "query-1").err().map(|error| error.code), Some("invalid_params".into()));
    }
    #[test]
    fn envelope_limits_include_the_envelope_not_just_the_draft() {
        assert!(encode_request("query-1", Method::ValidateConfig, &json!({"draft":"x".repeat(REQUEST_LIMIT)})).is_err());
        let mut value = Value::Null;
        for _ in 0..DEPTH_LIMIT { value = Value::Array(vec![value]); }
        assert!(encode_request("query-1", Method::ValidateConfig, &value).is_err());
        assert!(decode_response(&vec![b' '; RESPONSE_LIMIT + 1], "query-1").is_err());
    }
}
