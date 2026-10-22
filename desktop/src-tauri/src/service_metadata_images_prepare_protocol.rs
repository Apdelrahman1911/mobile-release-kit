//! Comparison DATA for the already native-chosen/opened image Import. No path,
//! image bytes, picker, recovery or source/Apply authority crosses this wire.
pub use crate::service_configuration_protocol::Query;
use crate::{
    service_metadata_images_protocol as images,
    service_protocol::{Error, Id, Settlement},
};
use serde::{Deserialize, Serialize};
pub const REQUEST_BYTES: usize = 4096;
pub const STATUS_BYTES: usize = 8192;
pub const OBSERVATION_BYTES: usize = 6144;
pub(crate) const FRAME_BYTES: usize = 128 * 1024;
pub(crate) const FRAME_NODES: usize = 4096;
pub(crate) const FRAME_DEPTH: usize = 24;
pub const EVENT: &str = "mrk:agent-metadata-images-prepare";
pub(crate) use images::bounded;
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub session_id: Id,
    pub owner_generation: Id,
    pub revision: Id,
    pub native_status_revision: u32,
    pub baseline_generation: u32,
}
impl Original {
    pub fn validate(&self) -> Result<(), Error> {
        if self.native_status_revision == u32::MAX || self.baseline_generation == u32::MAX {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Item {
    pub item_id: Id,
    pub display_name: String,
    pub selected_bytes: u32,
    pub selected_sha256: String,
    #[serde(deserialize_with = "nullable")]
    pub before_sha256: Option<String>,
    pub can_replace: bool,
    pub replace_existing: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub original: Original,
    pub platform: images::Platform,
    pub locale: String,
    pub asset_type: String,
    pub opened_sha256: String,
    pub items: Vec<Item>,
}
impl Observation {
    pub fn validate(&self) -> Result<(), Error> {
        use crate::service_version_edit_protocol::hex;
        self.original.validate()?;
        if !crate::service_metadata_text_protocol::locale(&self.locale)
            || self.asset_type.is_empty()
            || self.asset_type.len() > 64
            || !self
                .asset_type
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            || !hex(&self.opened_sha256)
            || !(1..=10).contains(&self.items.len())
        {
            return Err(Error::InvalidRequest);
        }
        let mut total = 0u32;
        for (n, x) in self.items.iter().enumerate() {
            if x.display_name.is_empty()
                || x.display_name.len() > 255
                || x.display_name == "."
                || x.display_name == ".."
                || x.display_name
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\\')
                || !(1..=10485760).contains(&x.selected_bytes)
                || !hex(&x.selected_sha256)
                || x.before_sha256.as_ref().is_some_and(|v| !hex(v))
                || x.can_replace && x.before_sha256.is_none()
                || x.replace_existing
                || self.items[..n].iter().any(|old| old.item_id == x.item_id)
            {
                return Err(Error::InvalidRequest);
            }
            total = total
                .checked_add(x.selected_bytes)
                .ok_or(Error::InvalidRequest)?;
        }
        if total > 25165824 {
            return Err(Error::InvalidRequest);
        }
        bounded(self, OBSERVATION_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Read {
    pub origin: Query,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Choice {
    pub item_id: Id,
    pub replace_existing: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub origin: Query,
    pub observation_revision: u32,
    pub opened_sha256: String,
    pub choices: Vec<Choice>,
}
impl Prepare {
    pub fn validate(&self) -> Result<(), Error> {
        if self.observation_revision == 0
            || self.observation_revision == u32::MAX
            || !crate::service_version_edit_protocol::hex(&self.opened_sha256)
            || !(1..=10).contains(&self.choices.len())
            || self
                .choices
                .iter()
                .enumerate()
                .any(|(n, c)| self.choices[..n].iter().any(|x| x.item_id == c.item_id))
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, REQUEST_BYTES)
    }
    pub fn matches(&self, o: &Observation) -> bool {
        self.opened_sha256 == o.opened_sha256
            && self.choices.len() == o.items.len()
            && self.choices.iter().zip(&o.items).all(|(c, x)| {
                c.item_id == x.item_id
                    && (!c.replace_existing || x.can_replace && x.before_sha256.is_some())
            })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    QueuedRead,
    Reading,
    Editing,
    QueuedPrepare,
    Preparing,
    Reviewing,
    Transferred,
    Stopping,
    Final,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Final {
    pub prepared: bool,
    pub transferred: bool,
    pub gui: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub runtime_project_id: String,
    pub revision: u32,
    pub phase: Phase,
    pub settlement: Settlement,
    #[serde(deserialize_with = "nullable")]
    pub observation: Option<Observation>,
    #[serde(deserialize_with = "nullable")]
    pub choices: Option<Vec<Choice>>,
    #[serde(deserialize_with = "nullable")]
    pub review: Option<images::Review>,
    pub remaining_ms: u64,
    pub cancel_requested: bool,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<Final>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.runtime_project_id.is_empty()
            || self.runtime_project_id.len() > 64
            || !self
                .runtime_project_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || self.revision == 0
            || self.revision == u32::MAX
            || !self.do_not_replay
            || self.remaining_ms > 900000
            || (self.phase == Phase::Unknown) != (self.settlement == Settlement::Unknown)
            || (self.phase == Phase::Final) != (self.settlement == Settlement::Settled)
            || (self.phase == Phase::Final) != self.result.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(o) = &self.observation {
            o.validate()?;
        }
        if let Some(c) = &self.choices {
            let o = self.observation.as_ref().ok_or(Error::InvalidRequest)?;
            if c.len() != o.items.len()
                || !c.iter().zip(&o.items).all(|(c, x)| {
                    c.item_id == x.item_id
                        && (!c.replace_existing || x.can_replace && x.before_sha256.is_some())
                })
            {
                return Err(Error::InvalidRequest);
            }
        }
        if let Some(r) = &self.review {
            r.validate()?;
            let o = self.observation.as_ref().ok_or(Error::InvalidRequest)?;
            if self.choices.is_none()
                || r.original.session_id != o.original.session_id
                || r.original.owner_generation != o.original.owner_generation
                || r.original.revision != o.original.revision
                || r.original.baseline_generation != o.original.baseline_generation
                || r.original.draft_revision != 1
                || r.platform != o.platform
                || r.locale != o.locale
                || r.asset_type != o.asset_type
                || r.file_count as usize != o.items.len()
            {
                return Err(Error::InvalidRequest);
            }
        }
        if matches!(
            self.phase,
            Phase::Editing
                | Phase::QueuedPrepare
                | Phase::Preparing
                | Phase::Reviewing
                | Phase::Transferred
        ) && self.observation.is_none()
            || matches!(
                self.phase,
                Phase::QueuedPrepare | Phase::Preparing | Phase::Reviewing | Phase::Transferred
            ) && self.choices.is_none()
            || matches!(self.phase, Phase::Reviewing | Phase::Transferred) && self.review.is_none()
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, STATUS_BYTES - 256)
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use images::fixtures::*;
    pub(crate) fn observation() -> Observation {
        Observation {
            original: Original {
                session_id: id('a'),
                owner_generation: id('b'),
                revision: id('c'),
                native_status_revision: 3,
                baseline_generation: 1,
            },
            platform: images::Platform::Android,
            locale: "en-US".into(),
            asset_type: "phoneScreenshots".into(),
            opened_sha256: "8".repeat(64),
            items: vec![
                Item {
                    item_id: id('1'),
                    display_name: "01.png".into(),
                    selected_bytes: 2048,
                    selected_sha256: "9".repeat(64),
                    before_sha256: Some("4".repeat(64)),
                    can_replace: true,
                    replace_existing: false,
                },
                Item {
                    item_id: id('2'),
                    display_name: "02.png".into(),
                    selected_bytes: 2048,
                    selected_sha256: "9".repeat(64),
                    before_sha256: None,
                    can_replace: false,
                    replace_existing: false,
                },
            ],
        }
    }
    pub(crate) fn prepare(revision: u32) -> Prepare {
        Prepare {
            origin: query(),
            observation_revision: revision,
            opened_sha256: observation().opened_sha256,
            choices: vec![
                Choice {
                    item_id: id('1'),
                    replace_existing: false,
                },
                Choice {
                    item_id: id('2'),
                    replace_existing: false,
                },
            ],
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;
    #[test]
    fn inspection_and_complete_choices_are_bounded_data_not_paths_or_baselines() {
        let o = observation();
        o.validate().unwrap();
        let p = prepare(4);
        p.validate().unwrap();
        assert!(p.matches(&o));
        let mut v = serde_json::to_value(&o).unwrap();
        v["items"][0]
            .as_object_mut()
            .unwrap()
            .remove("beforeSha256");
        assert!(serde_json::from_value::<Observation>(v).is_err());
        for name in ["../01.png", "/tmp/01.png", "one\\two.png", "one\n.png"] {
            let mut x = o.clone();
            x.items[0].display_name = name.into();
            assert!(x.validate().is_err());
        }
        let mut bad = p.clone();
        bad.choices.swap(0, 1);
        assert!(!bad.matches(&o));
        bad = p.clone();
        bad.choices[1].replace_existing = true;
        assert!(!bad.matches(&o));
        bad = p.clone();
        bad.opened_sha256.push('\n');
        assert!(bad.validate().is_err());
        let mut private = serde_json::to_value(p).unwrap();
        private["expectedBaseline"] = serde_json::json!({});
        assert!(serde_json::from_value::<Prepare>(private).is_err());
    }
    #[test]
    fn ten_long_safe_names_fit_compact_reply_and_eleventh_never_truncates() {
        let mut o = observation();
        o.items.clear();
        for n in 1..=10 {
            let mut x = observation().items.remove(0);
            x.item_id = Id::parse(&format!("{n:032x}")).unwrap();
            x.display_name = format!("{n:02}{}.png", "a".repeat(220));
            o.items.push(x);
        }
        o.validate().unwrap();
        assert!(serde_json::to_vec(&o).unwrap().len() <= OBSERVATION_BYTES);
        o.items.push(observation().items.remove(0));
        assert!(o.validate().is_err());
        assert_eq!(o.items.len(), 11);
    }
}
