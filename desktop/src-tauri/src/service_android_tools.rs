//! Bounded catalogue-observation DATA shared with the transport-only CLI.
//!
//! This is neither a tool selection nor a project compatibility result. The
//! original Desktop relay is the only producer. Queries perform no inspection,
//! discovery, acquisition or filesystem revalidation.
use crate::service_protocol::{Error, Id};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub(crate) const ROW_LIMIT: usize = 32;
pub(crate) const LABEL_BYTES: usize = 128;
pub(crate) const VIEW_BYTES: usize = 2048;
// One bounded cell, one relay projection and up to eight transport replies.
// Native source Status and existing framed-transport buffers keep their own
// reservations. This is a conservative backing reservation, not an RSS cap.
pub(crate) const DOCUMENT_BACKING: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    DesktopCatalogueObservation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    HistoricalNotRevalidated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compatibility {
    NotChecked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capture {
    Unobserved,
    Observed,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Availability {
    Available,
    Busy,
    Shutdown,
    CleanupUnknown,
    DocumentLost,
    UnsupportedPlatform,
    RuntimeUnqualified,
    ToolchainUnqualified,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Idle,
    Reading,
    Stopping,
    Ready,
    Refused,
    Cancelled,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    None,
    NotInspected,
    Cancelled,
    TimedOut,
    DocumentLost,
    Shutdown,
    CatalogChanged,
    CatalogUnavailable,
    CleanupUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Versions {
    pub jdk_vendor: String,
    pub jdk_version: String,
    pub gradle_version: String,
    pub agp_version: String,
    pub sdk_platform: String,
    pub sdk_build_tools_version: String,
}
impl Versions {
    fn valid(&self) -> bool {
        [
            &self.jdk_vendor,
            &self.jdk_version,
            &self.gradle_version,
            &self.agp_version,
            &self.sdk_platform,
            &self.sdk_build_tools_version,
        ]
        .iter()
        .all(|value| {
            !value.is_empty()
                && value.len() <= LABEL_BYTES
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b" ._+()-".contains(&byte))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selected {
    /// Opaque display/comparison DATA, not a native selection receipt.
    pub instance: String,
    pub versions: Versions,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalogue {
    pub status_revision: u32,
    pub catalog_generation: u32,
    pub availability: Availability,
    pub phase: Phase,
    pub reason: Reason,
    pub row_count: u8,
    pub observed_selection: Option<Selected>,
}
impl Catalogue {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !(1..u32::MAX).contains(&self.status_revision)
            || self.catalog_generation == u32::MAX
            || usize::from(self.row_count) > ROW_LIMIT
            || self.observed_selection.as_ref().is_some_and(|selected| {
                self.phase != Phase::Ready
                    || self.unknown()
                    || self.catalog_generation == 0
                    || self.row_count == 0
                    || selected.instance.len() != 32
                    || !selected
                        .instance
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !selected.versions.valid()
            })
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
    fn unknown(&self) -> bool {
        self.phase == Phase::Unknown
            || self.reason == Reason::CleanupUnknown
            || self.availability == Availability::CleanupUnknown
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct View {
    pub project_id: Id,
    pub scope: Scope,
    pub freshness: Freshness,
    pub project_compatibility: Compatibility,
    pub capture: Capture,
    pub observation: Option<Catalogue>,
}
impl View {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if (self.capture == Capture::Observed) != self.observation.is_some() {
            return Err(Error::InvalidRequest);
        }
        if let Some(observation) = &self.observation {
            observation.validate()?;
        }
        Ok(())
    }
}

enum Value {
    Unobserved,
    Observed(Catalogue),
    Unavailable,
}
/// ONE volatile cell shared by the existing Host and its existing Service.
/// Every critical section is bounded memory only. It contains no native owner,
/// callback, project path, task, file or durable state. A failed/lost original
/// relay cannot be repaired by a later copy or a new read grant.
pub(crate) struct ObservationSlot {
    value: Mutex<Value>,
}
impl Default for ObservationSlot {
    fn default() -> Self {
        Self {
            value: Mutex::new(Value::Unobserved),
        }
    }
}
impl ObservationSlot {
    pub(crate) fn publish(&self, next: Catalogue) {
        if next.validate().is_err() {
            self.unavailable();
            return;
        }
        let Ok(mut value) = self.value.lock() else {
            return;
        };
        match &*value {
            Value::Unavailable => return,
            Value::Observed(old) if next.status_revision < old.status_revision => return,
            Value::Observed(old) if next.status_revision == old.status_revision => {
                if next != *old {
                    *value = Value::Unavailable;
                }
                return;
            }
            Value::Observed(old)
                if next.catalog_generation < old.catalog_generation
                    || old.unknown() && !next.unknown() =>
            {
                *value = Value::Unavailable;
                return;
            }
            _ => {}
        }
        *value = Value::Observed(next);
    }
    pub(crate) fn unavailable(&self) {
        if let Ok(mut value) = self.value.lock() {
            *value = Value::Unavailable;
        }
    }
    pub(crate) fn view(&self, project_id: Id) -> View {
        let (capture, observation) = match self.value.lock().as_deref() {
            Ok(Value::Unobserved) => (Capture::Unobserved, None),
            Ok(Value::Observed(value)) => (Capture::Observed, Some(value.clone())),
            _ => (Capture::Unavailable, None),
        };
        View {
            project_id,
            scope: Scope::DesktopCatalogueObservation,
            freshness: Freshness::HistoricalNotRevalidated,
            project_compatibility: Compatibility::NotChecked,
            capture,
            observation,
        }
    }
}

pub(crate) fn human(view: &View) -> String {
    let mut text = String::from("Desktop tool-catalogue observation; historical, not revalidated now.\nProject compatibility is not checked by this query.\n");
    let Some(observation) = &view.observation else {
        text.push_str(match view.capture {
            Capture::Unobserved => "No catalogue observation has reached this Desktop service yet.\n",
            _ => "The catalogue observation is unavailable; no empty catalogue or readiness is inferred.\n",
        });
        text.push_str(
            "Open Desktop to inspect tools; this command does not inspect or change them.\n",
        );
        return text;
    };
    let phase = match observation.phase {
        Phase::Idle => "not inspected",
        Phase::Reading => "inspection was running",
        Phase::Stopping => "inspection was stopping",
        Phase::Ready => "inspection reported completion",
        Phase::Refused => "inspection was refused",
        Phase::Cancelled => "inspection was cancelled",
        Phase::Unknown => "inspection outcome unknown",
    };
    let availability = match observation.availability {
        Availability::Available => "catalogue actions were available",
        Availability::Busy => "Desktop was busy",
        Availability::Shutdown => "Desktop was stopping",
        Availability::CleanupUnknown => "cleanup unknown",
        Availability::DocumentLost => "document lost",
        Availability::UnsupportedPlatform => "platform unsupported",
        Availability::RuntimeUnqualified => "runtime unqualified",
        Availability::ToolchainUnqualified => "toolchain unqualified",
    };
    text.push_str(&format!(
        "Catalogue: {phase}; {availability}; {} recorded rows.\n",
        observation.row_count
    ));
    let reason = match observation.reason {
        Reason::None | Reason::NotInspected => None,
        Reason::Cancelled => Some("cancelled"),
        Reason::TimedOut => Some("inspection timed out"),
        Reason::DocumentLost => Some("original document lost"),
        Reason::Shutdown => Some("Desktop shutdown"),
        Reason::CatalogChanged => Some("catalogue changed"),
        Reason::CatalogUnavailable => Some("catalogue unavailable"),
        Reason::CleanupUnknown => Some("original cleanup unconfirmed"),
    };
    if let Some(reason) = reason {
        text.push_str(&format!("Recorded reason: {reason}.\n"));
    }
    match &observation.observed_selection {
        Some(selected) => {
            let v = &selected.versions;
            text.push_str(&format!("Observed selected copy: {}\nJDK {} {}; Gradle {}; AGP {}; Android API {}; build tools {}.\n",
                selected.instance, v.jdk_vendor, v.jdk_version, v.gradle_version,
                v.agp_version, v.sdk_platform, v.sdk_build_tools_version));
        }
        None => text.push_str("No selected protected copy was reported in this observation.\n"),
    }
    text.push_str("Selection and version labels are not current-tool or build-readiness proof.\n");
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn catalogue() -> Catalogue {
        Catalogue {
            status_revision: 1,
            catalog_generation: 1,
            availability: Availability::Available,
            phase: Phase::Ready,
            reason: Reason::None,
            row_count: 1,
            observed_selection: Some(Selected {
                instance: "a".repeat(32),
                versions: Versions {
                    jdk_vendor: "Example".into(),
                    jdk_version: "21".into(),
                    gradle_version: "8.13".into(),
                    agp_version: "8.9.2".into(),
                    sdk_platform: "35".into(),
                    sdk_build_tools_version: "35.0.0".into(),
                },
            }),
        }
    }
    fn id() -> Id {
        Id::parse(&"1".repeat(32)).unwrap()
    }
    #[test]
    fn closed_historical_view_rejects_authority_and_unbounded_labels() {
        let slot = ObservationSlot::default();
        slot.publish(catalogue());
        let view = slot.view(id());
        view.validate().unwrap();
        let mut json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["freshness"], "historical-not-revalidated");
        assert_eq!(json["projectCompatibility"], "not-checked");
        json["projectCompatibility"] = serde_json::json!("compatible");
        assert!(serde_json::from_value::<View>(json).is_err());
        let mut json = serde_json::to_value(view).unwrap();
        json["observation"]["observedSelection"]["ownerUid"] = serde_json::json!(501);
        assert!(serde_json::from_value::<View>(json).is_err());
        for label in [
            "/private/source".to_owned(),
            "21\nsecret".to_owned(),
            "x".repeat(LABEL_BYTES + 1),
        ] {
            let mut value = catalogue();
            value
                .observed_selection
                .as_mut()
                .unwrap()
                .versions
                .jdk_version = label;
            assert!(value.validate().is_err());
        }
        let mut maximal = catalogue();
        let v = &mut maximal.observed_selection.as_mut().unwrap().versions;
        v.jdk_vendor = "x".repeat(LABEL_BYTES);
        v.jdk_version = v.jdk_vendor.clone();
        v.gradle_version = v.jdk_vendor.clone();
        v.agp_version = v.jdk_vendor.clone();
        v.sdk_platform = v.jdk_vendor.clone();
        v.sdk_build_tools_version = v.jdk_vendor.clone();
        slot.publish(Catalogue {
            status_revision: 2,
            ..maximal
        });
        assert!(serde_json::to_vec(&slot.view(id())).unwrap().len() <= VIEW_BYTES);
        assert!(
            std::mem::size_of::<ObservationSlot>()
                + 2 * std::mem::size_of::<usize>()
                + 10 * (std::mem::size_of::<Catalogue>() + 32 + 6 * LABEL_BYTES)
                <= DOCUMENT_BACKING
        );
    }
    #[test]
    fn revisions_deduplicate_without_replacing_newer_or_contradictory_observations() {
        let slot = ObservationSlot::default();
        let first = catalogue();
        slot.publish(first.clone());
        slot.publish(first.clone());
        assert_eq!(slot.view(id()).observation, Some(first.clone()));
        let next = Catalogue {
            status_revision: 3,
            observed_selection: None,
            ..first.clone()
        };
        slot.publish(next.clone());
        slot.publish(first);
        assert_eq!(slot.view(id()).observation, Some(next.clone()));
        slot.publish(Catalogue {
            row_count: 2,
            ..next
        });
        assert_eq!(slot.view(id()).capture, Capture::Unavailable);
        slot.publish(Catalogue {
            status_revision: 4,
            ..catalogue()
        });
        assert!(slot.view(id()).observation.is_none());
    }
    #[test]
    fn loss_unknown_and_unobserved_are_not_empty_or_ready() {
        let slot = ObservationSlot::default();
        assert_eq!(slot.view(id()).capture, Capture::Unobserved);
        let unknown = Catalogue {
            phase: Phase::Unknown,
            reason: Reason::CleanupUnknown,
            availability: Availability::CleanupUnknown,
            observed_selection: None,
            ..catalogue()
        };
        slot.publish(unknown.clone());
        assert_eq!(slot.view(id()).observation, Some(unknown));
        slot.publish(Catalogue {
            status_revision: 2,
            ..catalogue()
        });
        assert_eq!(slot.view(id()).capture, Capture::Unavailable);
        let lost = ObservationSlot::default();
        lost.unavailable();
        lost.publish(catalogue());
        assert_eq!(lost.view(id()).capture, Capture::Unavailable);
        assert!(lost.view(id()).observation.is_none());
        let human = human(&slot.view(id()));
        assert!(
            human.contains("historical")
                && human.contains("not checked")
                && human.contains("unavailable")
        );
    }
    #[test]
    fn generation_regression_and_invalid_pairs_fail_only_the_optional_view() {
        let slot = ObservationSlot::default();
        slot.publish(catalogue());
        slot.publish(Catalogue {
            status_revision: 2,
            catalog_generation: 0,
            observed_selection: None,
            ..catalogue()
        });
        assert_eq!(slot.view(id()).capture, Capture::Unavailable);
        let mut view = ObservationSlot::default().view(id());
        view.observation = Some(catalogue());
        assert!(view.validate().is_err());
        let mut value = catalogue();
        value.row_count = 33;
        assert!(value.validate().is_err());
        value.row_count = 0;
        assert!(value.validate().is_err());
    }
}
