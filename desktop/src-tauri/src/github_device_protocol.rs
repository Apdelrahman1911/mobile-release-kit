//! Closed GitHub App device DATA and private one-shot framing. No network,
//! timers, owner, credential persistence or native qualification lives here.
use std::sync::OnceLock;
use serde::Deserialize;
use zeroize::Zeroize;
use crate::{error::BridgeError, github_connection_protocol::{self as connection, Reason}, protocol::valid_id};

pub(crate) const PROTOCOL: &str = "mrk-github-device/1";
pub(crate) const VERIFICATION_URI: &str = "https://github.com/login/device";
pub(crate) const AUTHORIZATION_SECONDS: u64 = 900;
pub(crate) const POLL_LIMIT: u32 = 180;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
const SERVER_SECONDS_LIMIT: u32 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step { Start, Poll }

// In particular no Debug, Clone or Serialize. The containing result and
// Supervisor mailbox must retain the same property. Rust-owned secret strings
// are erased on unsuccessful disposal; adoption moves, rather than clones.
pub(crate) struct Secret(String);
impl Secret {
    pub(crate) fn new(value: String) -> Self { Self(value) }
    pub(crate) fn as_str(&self) -> &str { &self.0 }
}
impl Drop for Secret { fn drop(&mut self) { self.0.zeroize(); } }
impl std::ops::Deref for Secret { type Target = str; fn deref(&self) -> &str { &self.0 } }
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        String::deserialize(decoder).map(Self)
    }
}

pub(crate) enum Outcome {
    Code { device_code: Secret, user_code: String, expires_in: u32, interval: u32 },
    Pending { interval: Option<u32> },
    SlowDown { interval: u32 },
    Token { token: Secret, expires_in: Option<u32> },
    Failed { reason: Reason, cooldown_seconds: Option<u32>, cooldown_blocked: bool },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { protocol: String, id: String, result: ResultWire }
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
enum ResultWire {
    Code { device_code: Secret, user_code: String, expires_in: u32, interval: u32 },
    Pending { #[serde(deserialize_with = "connection::nullable")] interval: Option<u32> },
    SlowDown { interval: u32 },
    Token { token: Secret, #[serde(deserialize_with = "connection::nullable")] expires_in: Option<u32> },
    Failed { reason: Reason, #[serde(deserialize_with = "connection::nullable")] cooldown_seconds: Option<u32>, cooldown_blocked: bool },
}

pub(crate) fn user_code(value: &str) -> bool {
    value.len() == 9 && value.as_bytes()[4] == b'-'
        && value.bytes().enumerate().all(|(i, b)| i == 4 || b.is_ascii_uppercase() || b.is_ascii_digit())
}
fn device_code(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn client_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn seconds(value: u32) -> bool { value > 0 && value <= SERVER_SECONDS_LIMIT }
fn token(value: &str) -> bool {
    value.starts_with("ghu_") && value.len() > 4 && value.len() <= 4096
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn failure(reason: Reason, delay: Option<u32>, blocked: bool) -> bool {
    matches!(reason, Reason::Unauthorized | Reason::Forbidden | Reason::NotFoundOrInaccessible
        | Reason::RateLimited | Reason::NetworkUnavailable | Reason::TlsFailed | Reason::ResponseInvalid
        | Reason::ResponseLimit | Reason::Expired | Reason::Cancelled | Reason::PublisherUnconfigured)
        && delay.is_none_or(|v| v > 0 && v <= connection::COOLDOWN_MAX_SECONDS)
        && !(blocked && delay.is_some())
        && (reason != Reason::RateLimited || blocked || delay.is_some())
        && (matches!(reason, Reason::RateLimited | Reason::ResponseInvalid) || !blocked && delay.is_none())
}

pub(crate) fn decode_response(id: &str, step: Step, bytes: &[u8]) -> Result<Outcome, BridgeError> {
    if !valid_id(id) || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(BridgeError::protocol());
    }
    // Typed closed deserialization rejects duplicate/unknown keys directly. No
    // generic Value clone, Debug, serialization or retained raw error is needed.
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| BridgeError::protocol())?;
    if envelope.protocol != PROTOCOL || envelope.id != id { return Err(BridgeError::protocol()); }
    match envelope.result {
        ResultWire::Code { device_code: code, user_code: user, expires_in, interval }
            if step == Step::Start && device_code(code.as_str()) && user_code(&user) && seconds(expires_in) && seconds(interval) =>
                Ok(Outcome::Code { device_code: code, user_code: user, expires_in, interval }),
        ResultWire::Pending { interval } if step == Step::Poll && interval.is_none_or(seconds) => Ok(Outcome::Pending { interval }),
        ResultWire::SlowDown { interval } if step == Step::Poll && seconds(interval) => Ok(Outcome::SlowDown { interval }),
        ResultWire::Token { token: value, expires_in } if step == Step::Poll && token(value.as_str())
            && expires_in.is_none_or(|v| v == 28_800) => Ok(Outcome::Token { token: value, expires_in }),
        ResultWire::Failed { reason, cooldown_seconds, cooldown_blocked } if failure(reason, cooldown_seconds, cooldown_blocked) =>
            Ok(Outcome::Failed { reason, cooldown_seconds, cooldown_blocked }),
        _ => Err(BridgeError::protocol()),
    }
}

pub(crate) fn encode_request(id: &str, step: Step, client: &str, code: Option<&str>) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !client_id(client) || match step {
        Step::Start => code.is_some(), Step::Poll => !code.is_some_and(device_code),
    } { return Err(BridgeError::invalid()); }
    let mut writer = connection::PrivateWriter { bytes: Vec::with_capacity(connection::REQUEST_LIMIT) };
    writer.append(b"{\"protocol\":\"mrk-github-device/1\",\"id\":")?;
    writer.string(id)?; writer.append(b",\"params\":{\"step\":")?;
    writer.string(match step { Step::Start => "start", Step::Poll => "poll" })?;
    writer.append(b",\"clientId\":")?; writer.string(client)?;
    writer.append(b",\"deviceCode\":")?; writer.nullable_id(code)?;
    writer.append(b"}}")?; writer.bytes.push(b'\n'); Ok(std::mem::take(&mut writer.bytes))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublisherFile { schema_version: u32, #[serde(deserialize_with = "connection::nullable")] publisher: Option<Publisher> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Publisher {
    pub(crate) client_id: String, pub(crate) app_slug: String, pub(crate) display_name: String,
    support_url: String, privacy_url: String, permissions: Permissions,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permissions { metadata: String, contents: String, actions: String }
fn public_https(value: &str) -> bool {
    value.starts_with("https://") && value.len() > 8 && value.len() <= 512
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !value[8..].starts_with('/') && !value.contains(['\\', '#', '@'])
}
fn parse_publisher(bytes: &[u8]) -> Option<Publisher> {
    if bytes.len() > 8192 { return None; }
    let value: PublisherFile = serde_json::from_slice(bytes).ok()?;
    if value.schema_version != 1 { return None; }
    let p = value.publisher?;
    if !client_id(&p.client_id) || !connection::plain(&p.display_name, 96)
        || p.app_slug.is_empty() || p.app_slug.len() > 100 || p.app_slug.starts_with('-') || p.app_slug.ends_with('-')
        || !p.app_slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !public_https(&p.support_url) || !public_https(&p.privacy_url)
        || p.permissions.metadata != "read" || p.permissions.contents != "read" || p.permissions.actions != "write" { return None; }
    Some(p)
}
pub(crate) fn publisher() -> Option<&'static Publisher> {
    static CONFIG: OnceLock<Option<Publisher>> = OnceLock::new();
    CONFIG.get_or_init(|| parse_publisher(include_bytes!("../../github-device-publisher.json"))).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn framed(result: &str) -> Vec<u8> { format!("{{\"protocol\":\"{PROTOCOL}\",\"id\":\"original\",\"result\":{result}}}\n").into_bytes() }
    #[test]
    fn private_results_are_role_bound_and_reject_contradictions() {
        let code = framed(r#"{"kind":"code","deviceCode":"0123456789012345678901234567890123456789","userCode":"AB12-CD34","expiresIn":900,"interval":5}"#);
        assert!(matches!(decode_response("original", Step::Start, &code), Ok(Outcome::Code { .. })));
        assert!(decode_response("original", Step::Poll, &code).is_err());
        for bad in [r#"{"kind":"pending","interval":true}"#, r#"{"kind":"pending"}"#,
            r#"{"kind":"slow-down","interval":0}"#, r#"{"kind":"pending","interval":null,"token":"secret"}"#,
            r#"{"kind":"token","token":"ghu_fixture","expiresIn":28800,"refreshToken":"secret"}"#,
            r#"{"kind":"token","token":"ghu_fixture","token":"ghu_other","expiresIn":null}"#] {
            assert!(decode_response("original", Step::Poll, &framed(bad)).is_err());
        }
        let good = framed(r#"{"kind":"token","token":"ghu_syntheticOnly","expiresIn":28800}"#);
        assert!(matches!(decode_response("original", Step::Poll, &good), Ok(Outcome::Token { .. })));
        assert!(decode_response("replacement", Step::Poll, &good).is_err());
    }
    #[test]
    fn request_and_publisher_inputs_never_supply_an_endpoint_or_scope() {
        assert!(encode_request("original", Step::Start, "Iv1.synthetic", None).is_ok());
        assert!(encode_request("original", Step::Start, "Iv1.synthetic", Some("unexpected")).is_err());
        assert!(encode_request("original", Step::Poll, "Iv1.synthetic", None).is_err());
        assert!(parse_publisher(br#"{"schemaVersion":1,"publisher":null}"#).is_none());
        assert!(parse_publisher(br#"{"schemaVersion":1,"publisher":null,"host":"elsewhere"}"#).is_none());
        assert!(user_code("AB12-CD34") && !user_code("AB12-CD34\n") && !user_code("ab12-cd34"));
    }
}
