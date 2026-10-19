//! Closed, redacted setup DATA from the same completed passive snapshot.
//!
//! This does not analyze a project, acquire a path, run a check, or authorize an
//! action. `configured` means a setting was present, never readiness. Only
//! finite codes survive; free text, references and identity values do not.
use crate::service_protocol::ConfigurationState;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

const SOURCE_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Android,
    Ios,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Local,
    Signing,
    Store,
    Automation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Configured,
    Detected,
    NeedsInput,
    Ambiguous,
    Unverified,
    Unsupported,
    Blocked,
    Deferred,
    NotChecked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementId {
    ProjectLayout,
    ReleaseSettings,
    VersionSource,
    AndroidIdentity,
    AndroidModule,
    AndroidVariant,
    AndroidTools,
    AndroidSigning,
    AndroidStore,
    AndroidTesting,
    IosIdentity,
    IosContainer,
    IosScheme,
    IosConfiguration,
    IosTools,
    IosSigning,
    IosStore,
    IosTesting,
    StoreMetadata,
    GithubAutomation,
}
const IDS: [RequirementId; 20] = {
    use RequirementId::*;
    [
        ProjectLayout,
        ReleaseSettings,
        VersionSource,
        AndroidIdentity,
        AndroidModule,
        AndroidVariant,
        AndroidTools,
        AndroidSigning,
        AndroidStore,
        AndroidTesting,
        IosIdentity,
        IosContainer,
        IosScheme,
        IosConfiguration,
        IosTools,
        IosSigning,
        IosStore,
        IosTesting,
        StoreMetadata,
        GithubAutomation,
    ]
};
impl RequirementId {
    fn included(self, platforms: &[Platform]) -> bool {
        use RequirementId::*;
        match self {
            AndroidIdentity | AndroidModule | AndroidVariant | AndroidTools | AndroidSigning
            | AndroidStore | AndroidTesting => platforms.contains(&Platform::Android),
            IosIdentity | IosContainer | IosScheme | IosConfiguration | IosTools | IosSigning
            | IosStore | IosTesting => platforms.contains(&Platform::Ios),
            StoreMetadata => !platforms.is_empty(),
            _ => true,
        }
    }
    fn stage(self) -> Stage {
        use RequirementId::*;
        match self {
            AndroidSigning | IosSigning => Stage::Signing,
            AndroidStore | AndroidTesting | IosStore | IosTesting | StoreMetadata => Stage::Store,
            GithubAutomation => Stage::Automation,
            _ => Stage::Local,
        }
    }
    fn uninspected(self) -> bool {
        matches!(
            self,
            Self::AndroidTools | Self::IosTools | Self::AndroidSigning | Self::IosSigning
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: RequirementId,
    pub stage: Stage,
    pub state: State,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupAnalysis {
    pub schema_version: u32,
    pub configuration_state: ConfigurationState,
    pub discovery_partial: bool,
    pub platforms: Vec<Platform>,
    pub requirements: Vec<Requirement>,
}
impl SetupAnalysis {
    pub(crate) fn matches(&self, configuration: ConfigurationState, partial: bool) -> bool {
        self.configuration_state == configuration && self.discovery_partial == partial
    }
    fn valid(&self) -> bool {
        if self.schema_version != 1
            || !matches!(
                self.platforms.as_slice(),
                [] | [Platform::Android] | [Platform::Ios] | [Platform::Android, Platform::Ios]
            )
        {
            return false;
        }
        let mut expected = IDS.into_iter().filter(|id| id.included(&self.platforms));
        for row in &self.requirements {
            if expected.next() != Some(row.id)
                || row.stage != row.id.stage()
                || row.id.uninspected() && row.state != State::NotChecked
                || row.state == State::Configured
                    && self.configuration_state != ConfigurationState::FormatValid
            {
                return false;
            }
        }
        expected.next().is_none()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source<'a> {
    schema_version: u32,
    #[serde(borrow)]
    scope: &'a str,
    configuration_state: ConfigurationState,
    discovery_partial: bool,
    platforms: Vec<Platform>,
    #[serde(borrow)]
    requirements: Vec<SourceRow<'a>>,
    #[serde(borrow)]
    limitations: Vec<&'a str>,
    #[serde(borrow)]
    assurance: Assurance<'a>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRow<'a> {
    id: RequirementId,
    stage: Stage,
    state: State,
    #[serde(borrow)]
    field: Option<&'a str>,
    #[serde(borrow)]
    reference: Option<&'a str>,
    #[serde(borrow)]
    summary: &'a str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assurance<'a> {
    #[serde(borrow)]
    basis: &'a str,
    project_code_executed: bool,
    tools_probed: bool,
    credentials_read: bool,
    git_observed: bool,
    store_contacted: bool,
    writes_performed: bool,
    #[serde(borrow)]
    release_readiness: &'a str,
}
impl Assurance<'_> {
    fn passive(&self) -> bool {
        self.basis == "static-text"
            && self.release_readiness == "unknown"
            && !self.project_code_executed
            && !self.tools_probed
            && !self.credentials_read
            && !self.git_observed
            && !self.store_contacted
            && !self.writes_performed
    }
}
fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.bytes().any(|c| c < 32 || c == 127)
}
fn reference(value: &str) -> bool {
    text(value, 512)
        && !value.starts_with('/')
        && !value.contains('\\')
        && !(value.as_bytes().get(1) == Some(&b':') && value.as_bytes()[0].is_ascii_alphabetic())
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}
fn bounded_rows(value: &Value, fields: &[&str]) -> bool {
    value
        .get("platforms")
        .and_then(Value::as_array)
        .is_some_and(|rows| rows.len() <= 2)
        && value
            .get("requirements")
            .and_then(Value::as_array)
            .is_some_and(|rows| rows.len() <= IDS.len() && rows.iter().all(|row| keys(row, fields)))
}

/// Optional input is already inside the original bounded passive response.
/// Borrow its strings; the closed shallow schema bounds nodes/depth without a
/// second JSON traversal framework. Only bounded enum vectors are retained.
pub(crate) fn project(
    value: Option<&Value>,
    configuration: ConfigurationState,
    partial: bool,
) -> Option<SetupAnalysis> {
    let value = value?;
    if !keys(
        value,
        &[
            "schemaVersion",
            "scope",
            "configurationState",
            "discoveryPartial",
            "platforms",
            "requirements",
            "limitations",
            "assurance",
        ],
    ) || !bounded_rows(
        value,
        &["id", "stage", "state", "field", "reference", "summary"],
    ) || !value
        .get("limitations")
        .and_then(Value::as_array)
        .is_some_and(|rows| rows.len() == 6)
    {
        return None;
    }
    let source = Source::deserialize(value).ok()?;
    if source.scope != "local-setup-guidance"
        || !source.assurance.passive()
        || !source.limitations.iter().all(|value| text(value, 512))
        || !source.requirements.iter().all(|row| {
            text(row.summary, 1024)
                && row.field.is_none_or(|value| text(value, 512))
                && row.reference.is_none_or(reference)
        })
    {
        return None;
    }
    // All containers/strings are bounded before serialization. This uses the
    // existing serde encoder (at most ~96KiB here), not a raw-input clone or a
    // new parser/owner; the shared core's tighter 16KiB output bound still wins.
    if serde_json::to_vec(value).ok()?.len() > SOURCE_BYTES {
        return None;
    }
    let projection = SetupAnalysis {
        schema_version: source.schema_version,
        configuration_state: source.configuration_state,
        discovery_partial: source.discovery_partial,
        platforms: source.platforms,
        requirements: source
            .requirements
            .into_iter()
            .map(|row| Requirement {
                id: row.id,
                stage: row.stage,
                state: row.state,
            })
            .collect(),
    };
    (projection.valid() && projection.matches(configuration, partial)).then_some(projection)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Stored {
    schema_version: u32,
    configuration_state: ConfigurationState,
    discovery_partial: bool,
    platforms: Vec<Platform>,
    requirements: Vec<Requirement>,
}
#[cfg(test)]
fn stored(value: &Value) -> Option<SetupAnalysis> {
    if !keys(
        value,
        &[
            "schemaVersion",
            "configurationState",
            "discoveryPartial",
            "platforms",
            "requirements",
        ],
    ) || !bounded_rows(value, &["id", "stage", "state"])
    {
        return None;
    }
    from_stored(Stored::deserialize(value).ok()?)
}
fn from_stored(source: Stored) -> Option<SetupAnalysis> {
    if source.platforms.len() > 2 || source.requirements.len() > IDS.len() {
        return None;
    }
    let projection = SetupAnalysis {
        schema_version: source.schema_version,
        configuration_state: source.configuration_state,
        discovery_partial: source.discovery_partial,
        platforms: source.platforms,
        requirements: source.requirements,
    };
    projection.valid().then_some(projection)
}

/// An old/unsupported optional projection cannot invalidate the base saved
/// observation. The enclosing transport/store retains all of its own bounds
/// and failure semantics. The owner also filters same config/partial context.
pub(crate) fn deserialize_optional<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SetupAnalysis>, D::Error> {
    // Standard serde buffering preserves duplicate members for the strict
    // typed attempt. Unsupported/ambiguous optional DATA is consumed without
    // converting that failure into a failure of the enclosing observation.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Optional {
        Known(Stored),
        Other(serde::de::IgnoredAny),
    }
    Ok(match Optional::deserialize(deserializer)? {
        Optional::Known(value) => from_stored(value),
        Optional::Other(_) => None,
    })
}

#[cfg(test)]
pub(crate) fn fixture(
    platforms: &[Platform],
    configuration: ConfigurationState,
    partial: bool,
) -> Value {
    // Synthetic DATA, not a generated observation or native qualification.
    serde_json::json!({
        "schemaVersion": 1, "scope": "local-setup-guidance", "configurationState": configuration,
        "discoveryPartial": partial, "platforms": platforms,
        "requirements": IDS.into_iter().filter(|id| id.included(platforms)).map(|id| serde_json::json!({
            "id": id, "stage": id.stage(), "state": State::NotChecked,
            "field": null, "reference": null, "summary": "Inert setup guidance.",
        })).collect::<Vec<_>>(),
        "limitations": vec!["Inert limitation."; 6],
        "assurance": {"basis": "static-text", "projectCodeExecuted": false, "toolsProbed": false,
            "credentialsRead": false, "gitObserved": false, "storeContacted": false,
            "writesPerformed": false, "releaseReadiness": "unknown"},
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn projected(value: &Value) -> Option<SetupAnalysis> {
        project(Some(value), ConfigurationState::FormatValid, false)
    }

    #[test]
    fn codes_only_projection_discards_all_arbitrary_text() {
        let mut input = fixture(
            &[Platform::Android, Platform::Ios],
            ConfigurationState::FormatValid,
            false,
        );
        input["requirements"][0]["summary"] = json!("private-summary-sentinel");
        input["requirements"][0]["field"] = json!("private-field-sentinel");
        input["requirements"][0]["reference"] = json!("private-path-sentinel/file");
        input["limitations"][0] = json!("private-limitation-sentinel");
        let output = projected(&input).unwrap();
        assert_eq!(output.requirements.len(), 20);
        let encoded = serde_json::to_string(&output).unwrap();
        for excluded in [
            "sentinel",
            "summary",
            "field",
            "reference",
            "limitations",
            "assurance",
            "ready",
        ] {
            assert!(!encoded.contains(excluded));
        }
        assert_eq!(
            stored(&serde_json::to_value(&output).unwrap()),
            Some(output)
        );
    }

    #[test]
    fn missing_malformed_and_wrong_saved_context_are_unavailable() {
        assert!(project(None, ConfigurationState::Missing, false).is_none());
        assert!(projected(&Value::Null).is_none());
        let good = fixture(&[Platform::Android], ConfigurationState::FormatValid, false);
        assert!(project(Some(&good), ConfigurationState::Invalid, false).is_none());
        assert!(project(Some(&good), ConfigurationState::FormatValid, true).is_none());
        for (field, invalid) in [
            ("schemaVersion", json!(2)),
            ("schemaVersion", json!(1.0)),
            ("scope", json!("release-ready")),
            ("configurationState", json!("ready")),
            ("discoveryPartial", json!(0)),
            ("platforms", json!(["other"])),
            ("platforms", json!(["android", "android"])),
            ("platforms", json!(["ios", "android"])),
            ("requirements", json!([])),
            ("extra", json!("ignored?")),
        ] {
            let mut input = good.clone();
            input[field] = invalid;
            assert!(projected(&input).is_none(), "{field}");
        }
    }

    #[test]
    fn requirements_are_closed_unique_and_scope_bound_not_ready() {
        let good = fixture(&[Platform::Android], ConfigurationState::FormatValid, false);
        for (field, invalid) in [
            ("id", json!("raw-application-id")),
            ("stage", json!("store")),
            ("state", json!("verified")),
            ("extra", json!(true)),
        ] {
            let mut input = good.clone();
            input["requirements"][0][field] = invalid;
            assert!(projected(&input).is_none(), "{field}");
        }
        let mut input = good.clone();
        input["requirements"][1] = input["requirements"][0].clone();
        assert!(projected(&input).is_none());
        let mut input = good.clone();
        input["requirements"].as_array_mut().unwrap().remove(1);
        assert!(projected(&input).is_none());
        for id in ["android-tools", "android-signing"] {
            let mut input = good.clone();
            let row = input["requirements"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            row["state"] = json!("configured");
            assert!(projected(&input).is_none());
        }
        let mut input = fixture(&[], ConfigurationState::Missing, true);
        input["requirements"][0]["state"] = json!("configured");
        assert!(project(Some(&input), ConfigurationState::Missing, true).is_none());
        // No-platform guidance still has the four explicit unknown requirements.
        let input = fixture(&[], ConfigurationState::Unavailable, true);
        assert_eq!(
            project(Some(&input), ConfigurationState::Unavailable, true)
                .unwrap()
                .requirements
                .len(),
            4
        );
    }

    #[test]
    fn effect_claims_and_bounded_ignored_fields_cannot_enter_the_projection() {
        let good = fixture(
            &[Platform::Android, Platform::Ios],
            ConfigurationState::FormatValid,
            false,
        );
        for field in [
            "projectCodeExecuted",
            "toolsProbed",
            "credentialsRead",
            "gitObserved",
            "storeContacted",
            "writesPerformed",
        ] {
            let mut input = good.clone();
            input["assurance"][field] = json!(true);
            assert!(projected(&input).is_none());
        }
        let mut input = good.clone();
        input["assurance"]["releaseReadiness"] = json!("ready");
        assert!(projected(&input).is_none());
        for invalid in [
            json!("x".repeat(1025)),
            json!("control\ntext"),
            json!({"nested": []}),
        ] {
            let mut input = good.clone();
            input["requirements"][0]["summary"] = invalid;
            assert!(projected(&input).is_none());
        }
        let mut input = good;
        for row in input["requirements"].as_array_mut().unwrap() {
            row["summary"] = json!("x".repeat(1024));
        }
        assert!(serde_json::to_vec(&input).unwrap().len() > SOURCE_BYTES);
        assert!(projected(&input).is_none());
    }

    #[test]
    fn optional_decoder_preserves_base_data_and_never_defaults_to_an_empty_list() {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Envelope {
            revision: u64,
            #[serde(default, deserialize_with = "deserialize_optional")]
            setup_analysis: Option<SetupAnalysis>,
        }
        let good = serde_json::to_value(
            projected(&fixture(
                &[Platform::Ios],
                ConfigurationState::FormatValid,
                false,
            ))
            .unwrap(),
        )
        .unwrap();
        let valid: Envelope =
            serde_json::from_value(json!({"revision": 7, "setupAnalysis": good})).unwrap();
        assert!(valid.setup_analysis.is_some());
        let duplicate =
            serde_json::to_string(&json!({"revision": 7, "setupAnalysis": valid.setup_analysis}))
                .unwrap()
                .replace(
                    "\"schemaVersion\":1",
                    "\"schemaVersion\":1,\"schemaVersion\":1",
                );
        assert!(serde_json::from_str::<Envelope>(&duplicate)
            .unwrap()
            .setup_analysis
            .is_none());
        let old: Envelope = serde_json::from_value(json!({"revision": 7})).unwrap();
        assert!(old.setup_analysis.is_none());
        for malformed in [
            Value::Null,
            json!({}),
            json!({"schemaVersion": 1, "requirements": []}),
            json!("not-guidance"),
        ] {
            let value: Envelope =
                serde_json::from_value(json!({"revision": 7, "setupAnalysis": malformed})).unwrap();
            assert_eq!(value.revision, 7);
            assert!(value.setup_analysis.is_none());
        }
        assert!(serde_json::from_value::<Envelope>(
            json!({"revision": "bad", "setupAnalysis": null})
        )
        .is_err());
        assert!(serde_json::from_value::<Envelope>(json!({"setupAnalysis": null})).is_err());
    }
}
