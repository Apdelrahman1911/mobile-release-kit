//! Closed UI intent/summary only. No renderer candidate, Source/Store receipt,
//! account, namespace, token, path or reserved-version authority is accepted.
use crate::{
    error::BridgeError,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
pub(crate) const LIMIT: usize = 8192;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Increment {
    Build,
    Patch,
    Minor,
    Major,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) project_id: String,
    pub(crate) reference: String,
    pub(crate) increment: Increment,
    pub(crate) new_candidate: bool,
    pub(crate) acknowledge_limitations: bool,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        valid_id(&self.project_id)
            && crate::supervisor::version_allocation_source_branch(&self.reference)
            && self.acknowledge_limitations
    }
    pub(crate) fn policy(&self) -> Value {
        json!({"schemaVersion":2,"mode":"automatic","rules":[{"ref":self.reference,"increment":self.increment}],
            "buildCeiling":9999,"storeMaxAgeSeconds":900,"storeScope":"require-current-ios-inventory"})
    }
}
pub(crate) enum Command {
    Status,
    Review(Review),
    Reserve {
        project_id: String,
        review_id: String,
    },
    Cancel(String),
    Edit {
        project_id: String,
        reservation_id: String,
    },
}
fn exact(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.len() == keys.len() && keys.iter().all(|k| v.contains_key(*k)))
}
pub(crate) fn decode(name: &str, raw: &[u8]) -> Result<Command, BridgeError> {
    if raw.is_empty() || raw.len() > LIMIT {
        return Err(BridgeError::invalid());
    }
    let v = strict_json(raw)?;
    if name == "version_reserve_status" && exact(&v, &[]) {
        return Ok(Command::Status);
    }
    if name == "version_reserve_review" {
        let input: Review = serde_json::from_value(v).map_err(|_| BridgeError::invalid())?;
        return if input.valid() {
            Ok(Command::Review(input))
        } else {
            Err(BridgeError::invalid())
        };
    }
    let required = match name {
        "version_reserve_start" => ["projectId", "reviewId"],
        "version_reserve_edit" => ["projectId", "reservationId"],
        "version_reserve_cancel" if exact(&v, &["operationId"]) => {
            return v["operationId"]
                .as_str()
                .filter(|s| valid_id(s))
                .map(|s| Command::Cancel(s.into()))
                .ok_or_else(BridgeError::invalid)
        }
        _ => return Err(BridgeError::invalid()),
    };
    if !exact(&v, &required)
        || !required
            .iter()
            .all(|k| v[*k].as_str().is_some_and(valid_id))
    {
        return Err(BridgeError::invalid());
    }
    let id = v[required[1]]
        .as_str()
        .ok_or_else(BridgeError::invalid)?
        .to_owned();
    let project = v["projectId"]
        .as_str()
        .ok_or_else(BridgeError::invalid)?
        .to_owned();
    Ok(if name == "version_reserve_start" {
        Command::Reserve {
            project_id: project,
            review_id: id,
        }
    } else {
        Command::Edit {
            project_id: project,
            reservation_id: id,
        }
    })
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Idle,
    Reading,
    Reviewed,
    Reserving,
    Reserved,
    Refused,
    CleanupUnknown,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewView {
    pub(crate) id: String,
    pub(crate) reference: String,
    pub(crate) increment: Increment,
    pub(crate) new_candidate: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReservationView {
    pub(crate) id: String,
    pub(crate) candidate_id: String,
    pub(crate) name: String,
    pub(crate) build: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u8,
    pub(crate) revision: u32,
    pub(crate) project_id: Option<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) phase: Phase,
    pub(crate) reason: &'static str,
    pub(crate) review: Option<ReviewView>,
    pub(crate) reservation: Option<ReservationView>,
}
impl Status {
    pub(crate) fn idle() -> Self {
        Self {
            schema_version: 1,
            revision: 0,
            project_id: None,
            operation_id: None,
            phase: Phase::Idle,
            reason: "none",
            review: None,
            reservation: None,
        }
    }
}
pub(crate) fn refused() -> BridgeError {
    BridgeError::new("version_reserve_changed","Read the saved iOS version and current App Store inventory again. The existing reservation is never recycled.")
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("version_reserve_unavailable","Automatic reservations need the installed iOS runtime, current Store inventory, and a connected shared counter. Manual versions are unchanged.")
}
pub(crate) fn not_started(error: BridgeError) -> BridgeError {
    if error.code == "cleanup_unknown" {
        error
    } else {
        BridgeError::new("version_reserve_not_started", error.message)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserve_intents_never_accept_renderer_source_floor_candidate_or_token() {
        let data = json!({"projectId":"project-1","reference":"refs/heads/main","increment":"patch","newCandidate":false,"acknowledgeLimitations":true});
        assert!(matches!(
            decode(
                "version_reserve_review",
                &serde_json::to_vec(&data).unwrap()
            ),
            Ok(Command::Review(_))
        ));
        for key in ["source", "candidateId", "observations", "token", "path"] {
            let mut invalid = data.clone();
            invalid[key] = json!("ignored");
            assert!(decode(
                "version_reserve_review",
                &serde_json::to_vec(&invalid).unwrap()
            )
            .is_err());
        }
        for (key, value) in [
            ("reference", json!("refs/tags/v1")),
            ("acknowledgeLimitations", json!(false)),
            ("increment", json!("manual")),
        ] {
            let mut invalid = data.clone();
            invalid[key] = value;
            assert!(decode(
                "version_reserve_review",
                &serde_json::to_vec(&invalid).unwrap()
            )
            .is_err());
        }
        assert!(decode("version_reserve_status", br#"{"extra":0}"#).is_err());
    }
}
