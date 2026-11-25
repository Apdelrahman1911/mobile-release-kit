//! Private, offline format checks for an explicitly selected service-account key.
//! No ADC discovery, executable sources, HTTP request, or account projection.
use super::{apple, lexical_quota, poll, Failure, FileObservation, Observation, Observed,
    Pkcs8Algorithm, UnavailableReason};
use serde::Deserialize;
use zeroize::Zeroize;

const LIMIT: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAccount {
    #[serde(rename = "type")] kind: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    token_uri: String,
    #[serde(default, deserialize_with = "optional_text")]
    auth_uri: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    auth_provider_x509_cert_url: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    client_x509_cert_url: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    universe_domain: Option<String>,
}
fn optional_text<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<String>, D::Error> {
    String::deserialize(value).map(Some) // Omission allowed; explicit null is not a string.
}
impl Drop for ServiceAccount {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.private_key_id.zeroize();
        self.client_email.zeroize();
        self.client_id.zeroize();
        self.project_id.zeroize();
    }
}

pub(super) fn inspect(bytes: &[u8], stop: &mut dyn FnMut() -> bool) -> Result<FileObservation, Failure> {
    poll(stop)?;
    if bytes.len() > LIMIT { return Ok(FileObservation::unavailable(UnavailableReason::ParserLimit)); }
    lexical_quota(bytes, stop)?;
    // The closed flat schema bounds allocations by the already bounded input.
    // Serde rejects duplicate keys, unknown fields, nested values and trailing data.
    let key: ServiceAccount = serde_json::from_slice(bytes).map_err(|_| Failure::Malformed)?;
    poll(stop)?;
    let project = key.project_id.as_bytes();
    let project_valid = (6..=63).contains(&project.len()) && project[0].is_ascii_lowercase()
        && project.last().is_some_and(u8::is_ascii_alphanumeric)
        && project.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    let email_suffix = format!("@{}.iam.gserviceaccount.com", key.project_id);
    let email_name = key.client_email.strip_suffix(&email_suffix).unwrap_or("");
    let email_valid = (1..=64).contains(&email_name.len())
        && email_name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    let certificate_url_valid = key.client_x509_cert_url.as_ref().is_none_or(|value| {
        let suffix = value.strip_prefix("https://www.googleapis.com/robot/v1/metadata/x509/");
        suffix.is_some_and(|value| value == key.client_email || value == key.client_email.replace('@', "%40"))
    });
    if key.kind != "service_account" || !project_valid || !email_valid
        || key.private_key_id.len() != 40 || !key.private_key_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !(1..=32).contains(&key.client_id.len()) || !key.client_id.bytes().all(|b| b.is_ascii_digit())
        || key.token_uri != "https://oauth2.googleapis.com/token"
        || key.auth_uri.as_ref().is_some_and(|v| v != "https://accounts.google.com/o/oauth2/auth")
        || key.auth_provider_x509_cert_url.as_ref().is_some_and(|v| v != "https://www.googleapis.com/oauth2/v1/certs")
        || key.universe_domain.as_ref().is_some_and(|v| v != "googleapis.com")
        || !certificate_url_valid || !key.private_key.starts_with("-----BEGIN PRIVATE KEY-----\n") {
        return Err(Failure::Malformed);
    }
    // Existing bounded PKCS#8 envelope parser, not proof of mathematical key
    // validity, account ownership, token issuance or Google Play permissions.
    let parsed = apple::p8(key.private_key.as_bytes(), stop)?;
    if !matches!(parsed.0, Observation::Observed { data: Observed::Pkcs8 { algorithm: Pkcs8Algorithm::Rsa, .. } }) {
        return Err(Failure::Malformed);
    }
    poll(stop)?;
    Ok(FileObservation(Observation::Observed { data: Observed::GoogleServiceAccountJson { byte_count: bytes.len() as u64 } }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn sample() -> Value {
        // Synthetic RSA-labelled PKCS#8 envelope with an opaque one-byte body.
        // The format checker deliberately does not claim RSA key validity.
        json!({"type":"service_account", "project_id":"example-project",
            "private_key_id":"a".repeat(40), "client_email":"release@example-project.iam.gserviceaccount.com",
            "client_id":"123456789012345678901", "token_uri":"https://oauth2.googleapis.com/token",
            "private_key":"-----BEGIN PRIVATE KEY-----\nMBUCAQAwDQYJKoZIhvcNAQEBBQAEAQE=\n-----END PRIVATE KEY-----\n"})
    }
    #[test]
    fn selected_service_account_is_closed_and_private() {
        let key = sample(); let bytes = serde_json::to_vec(&key).unwrap();
        let value = serde_json::to_value(inspect(&bytes, &mut || false).ok().unwrap()).unwrap();
        assert_eq!(value, json!({"status":"observed", "format":"google-service-account-json", "byteCount":bytes.len()}));
        for (field, replacement) in [("type", json!("external_account")), ("token_uri", json!("https://example.invalid/token")),
            ("private_key", json!("not a key")), ("universe_domain", json!("example.invalid")),
            ("client_x509_cert_url", json!("https://example.invalid/key")), ("client_email", json!("other@example.invalid")),
            ("credential_source", json!({"executable":{"command":"unused"}})), ("auth_uri", Value::Null)] {
            let mut bad = key.clone(); bad[field] = replacement;
            assert!(inspect(&serde_json::to_vec(&bad).unwrap(), &mut || false).is_err());
        }
        let mut duplicate = bytes.clone(); duplicate.pop(); duplicate.extend_from_slice(b",\"type\":\"service_account\"}");
        assert!(inspect(&duplicate, &mut || false).is_err());
        assert!(matches!(inspect(&bytes, &mut || true), Err(Failure::Interrupted)));
        assert!(!inspect(&vec![b' '; LIMIT + 1], &mut || false).ok().unwrap().is_observed());
    }
}
