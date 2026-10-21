//! Fixed comparison DATA for combined Open -> Prepare. Never a path, baseline,
//! reservation, permission or writer supplied by the installed CLI.
use crate::{
    service_protocol::{Error, Id, Settlement},
    service_version_edit_protocol as edit,
};
pub use edit::Query;
use serde::{Deserialize, Serialize};
pub const REQUEST_BYTES: usize = 1024;
pub const STATUS_BYTES: usize = 8192;
pub(crate) const FRAME_BYTES: usize = (768 + 16) * 1024;
pub(crate) const FRAME_NODES: usize = 1024;
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Values {
    pub name: String,
    pub build: String,
}
impl Values {
    pub fn valid(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= 64
            && self.name.bytes().all(|b| (0x20..0x7f).contains(&b))
            && !self.build.is_empty()
            && self.build.len() <= 10
            && self.build.bytes().all(|b| b.is_ascii_digit())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Selection {
    Manual {
        values: Values,
    },
    Reserved {
        #[serde(rename = "reservationId")]
        reservation_id: Id,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub origin: Query,
    pub selection: Selection,
}
impl Prepare {
    pub fn validate(&self) -> Result<(), Error> {
        if matches!(&self.selection, Selection::Manual{values} if !values.valid()) {
            return Err(Error::InvalidRequest);
        }
        edit::bounded(self, REQUEST_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub session_id: Id,
    pub owner_generation: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checkout {
    pub revision: Id,
    pub source: String,
    pub ios_enabled: bool,
    pub values: Values,
    pub config_bytes: u32,
    pub config_sha256: String,
    pub version_bytes: u32,
    pub version_sha256: String,
}
impl Checkout {
    pub fn valid(&self) -> bool {
        self.values.valid()
            && !self.source.is_empty()
            && self.source.len() <= 512
            && !self.source.starts_with('/')
            && !self.source.contains(['\\', ':'])
            && self.source.bytes().all(|b| (0x20..0x7f).contains(&b))
            && self
                .source
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
            && self.config_bytes > 0
            && self.config_bytes <= 512 * 1024
            && edit::hex(&self.config_sha256)
            && self.version_bytes > 0
            && self.version_bytes <= 64 * 1024
            && edit::hex(&self.version_sha256)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Queued,
    Opening,
    Opened,
    Preparing,
    Reviewing,
    Applying,
    Stopping,
    Final,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub runtime_project_id: String,
    pub selection: Selection,
    pub revision: u32,
    pub phase: Phase,
    pub settlement: Settlement,
    #[serde(deserialize_with = "nullable")]
    pub original: Option<Original>,
    #[serde(deserialize_with = "nullable")]
    pub checkout: Option<Checkout>,
    #[serde(deserialize_with = "nullable")]
    pub proposed: Option<Values>,
    #[serde(deserialize_with = "nullable")]
    pub review: Option<edit::Review>,
    #[serde(deserialize_with = "nullable")]
    pub apply_request: Option<Query>,
    pub gui_owned: bool,
    pub cancel_requested: bool,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<edit::Final>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        Prepare {
            origin: self.origin.clone(),
            selection: self.selection.clone(),
        }
        .validate()?;
        if self.schema_version != 1
            || self.revision == 0
            || self.revision == u32::MAX
            || !self.do_not_replay
            || self.runtime_project_id.is_empty()
            || self.runtime_project_id.len() > 64
            || !self
                .runtime_project_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || (self.phase == Phase::Final) != (self.settlement == Settlement::Settled)
            || (self.phase == Phase::Unknown) != (self.settlement == Settlement::Unknown)
            || (self.phase == Phase::Final) != self.result.is_some()
            || self.checkout.is_some() != self.proposed.is_some()
            || self.checkout.as_ref().is_some_and(|c| !c.valid())
            || self.proposed.as_ref().is_some_and(|v| !v.valid())
            || self.checkout.is_some() && self.original.is_none()
            || self.review.is_some() && self.checkout.is_none()
            || matches!(self.phase, Phase::Opened | Phase::Preparing) && self.checkout.is_none()
            || matches!(self.phase, Phase::Reviewing | Phase::Applying) && self.review.is_none()
            || self.apply_request.as_ref().is_some_and(|q| {
                q.project_id != self.origin.project_id
                    || q.service_instance != self.origin.service_instance
                    || q.request_id == self.origin.request_id
            })
            || self.gui_owned && self.apply_request.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        if let Selection::Manual { values } = &self.selection {
            if self.proposed.as_ref().is_some_and(|p| p != values) {
                return Err(Error::InvalidRequest);
            }
        }
        if let Some(r) = &self.review {
            r.validate()?;
            let o = self.original.as_ref().ok_or(Error::InvalidRequest)?;
            let c = self.checkout.as_ref().ok_or(Error::InvalidRequest)?;
            let v = self.proposed.as_ref().ok_or(Error::InvalidRequest)?;
            if r.original.session_id != o.session_id
                || r.original.owner_generation != o.owner_generation
                || r.original.revision != c.revision
                || r.source != c.source
                || r.before_bytes != c.version_bytes
                || r.before_sha256 != c.version_sha256
                || r.name != v.name
                || r.build != v.build
                || matches!(self.selection, Selection::Reserved { .. }) != r.candidate_id.is_some()
            {
                return Err(Error::InvalidRequest);
            }
        }
        edit::bounded(self, STATUS_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_is_one_closed_manual_or_original_reservation_selection() {
        let origin = serde_json::json!({"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)});
        for selection in [
            serde_json::json!({"kind":"manual","values":{"name":"1.2","build":"8"}}),
            serde_json::json!({"kind":"reserved","reservationId":"d".repeat(32)}),
        ] {
            let v = serde_json::json!({"origin":origin,"selection":selection});
            let p: Prepare = serde_json::from_value(v.clone()).unwrap();
            assert!(p.validate().is_ok());
            for field in [
                "values",
                "root",
                "baseline",
                "candidateId",
                "window",
                "increment",
            ] {
                let mut bad = v.clone();
                bad[field] = serde_json::json!("extra");
                assert!(serde_json::from_value::<Prepare>(bad).is_err());
            }
        }
        for selection in [
            serde_json::json!({"kind":"manual","values":{"name":"1.2","build":"8"},"reservationId":"d".repeat(32)}),
            serde_json::json!({"kind":"reserved","reservationId":null}),
            serde_json::json!({"kind":"reserved","candidateId":"d".repeat(32)}),
        ] {
            assert!(serde_json::from_value::<Prepare>(
                serde_json::json!({"origin":origin,"selection":selection})
            )
            .is_err());
        }
        for values in [
            Values {
                name: "x".repeat(65),
                build: "1".into(),
            },
            Values {
                name: "1.2\n".into(),
                build: "1".into(),
            },
            Values {
                name: "1.2".into(),
                build: "-1".into(),
            },
        ] {
            assert!(!values.valid());
        }
    }

    #[test]
    fn compact_status_requires_nulls_and_exact_original_checkout_review() {
        let id = |n: u8| format!("{n:032x}");
        let raw = serde_json::json!({
            "schemaVersion":1,"origin":{"projectId":id(1),"serviceInstance":id(2),"requestId":id(3)},
            "runtimeProjectId":"native-project",
            "selection":{"kind":"manual","values":{"name":"1.2","build":"8"}},
            "revision":2,"phase":"reviewing","settlement":"pending",
            "original":{"sessionId":id(4),"ownerGeneration":id(5)},
            "checkout":{"revision":id(6),"source":"public/version.properties","iosEnabled":false,
                "values":{"name":"1.2","build":"7"},"configBytes":100,"configSha256":"a".repeat(64),
                "versionBytes":20,"versionSha256":"b".repeat(64)},
            "proposed":{"name":"1.2","build":"8"},
            "review":{"original":{"sessionId":id(4),"ownerGeneration":id(5),"revision":id(6),"planToken":id(7)},
                "nativeStatusRevision":9,"name":"1.2","build":"8","source":"public/version.properties",
                "beforeBytes":20,"beforeSha256":"b".repeat(64),"afterBytes":21,"afterSha256":"c".repeat(64),"candidateId":null},
            "applyRequest":null,"guiOwned":false,"cancelRequested":false,"result":null,"doNotReplay":true
        });
        let parse = |v| {
            serde_json::from_value::<Status>(v).and_then(|s| {
                s.validate()
                    .map_err(|_| <serde_json::Error as serde::de::Error>::custom("invalid"))?;
                Ok(s)
            })
        };
        assert!(parse(raw.clone()).is_ok());
        for field in [
            "original",
            "checkout",
            "proposed",
            "review",
            "applyRequest",
            "result",
        ] {
            let mut absent = raw.clone();
            absent.as_object_mut().unwrap().remove(field);
            assert!(parse(absent).is_err(), "required member {field}");
        }
        for (pointer, value) in [
            ("/review/original/sessionId", serde_json::json!(id(8))),
            ("/review/original/revision", serde_json::json!(id(8))),
            ("/review/source", serde_json::json!("another.properties")),
            ("/review/beforeSha256", serde_json::json!("d".repeat(64))),
            ("/review/beforeBytes", serde_json::json!(19)),
            ("/review/name", serde_json::json!("2.0")),
            (
                "/review/candidateId",
                serde_json::json!("11111111-1111-4111-8111-111111111111"),
            ),
            ("/checkout/configBytes", serde_json::json!(512 * 1024 + 1)),
            ("/checkout/versionBytes", serde_json::json!(64 * 1024 + 1)),
            ("/proposed/build", serde_json::json!("9")),
            (
                "/result",
                serde_json::json!({"effect":"committed","journal":"durable","cancelled":false,"applySubmitted":true}),
            ),
        ] {
            let mut bad = raw.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(parse(bad).is_err(), "{pointer}");
        }
        let mut reserved = raw;
        reserved["selection"] = serde_json::json!({"kind":"reserved","reservationId":id(10)});
        assert!(parse(reserved.clone()).is_err());
        reserved["review"]["candidateId"] =
            serde_json::json!("11111111-1111-4111-8111-111111111111");
        assert!(parse(reserved).is_ok()); // Comparison only, never a native handoff.
    }
}
