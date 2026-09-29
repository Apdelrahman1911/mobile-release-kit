//! Closed saved-metadata DATA; no file path, draft, credential or write authority.
//! Local policy lives in the core. Correlation rejects incomplete/unsafe reports.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{error::BridgeError, github_workflow_edit_protocol::value_bounds,
    metadata_text_edit_protocol::{self as text, Assurance, Platform}, protocol};

pub(crate) const RESULT_LIMIT: usize = 256 * 1024;
pub(crate) const RESULT_NODE_LIMIT: usize = 32_768;
pub(crate) const RESULT_DEPTH_LIMIT: usize = 12;
pub(crate) const RESPONSE_LIMIT: usize = RESULT_LIMIT + 4096;
const MAX_ROWS: usize = 2048;
const IOS_NOTES: [&str; 3] = ["review/ios-beta-notes.txt", "review/ios-notes.txt", "testflight/what-to-test.txt"];
const TEXT_ISSUES: [&str; 8] = ["metadata.empty-text", "metadata.nul", "metadata.placeholder",
    "metadata.secret-pattern", "metadata.url", "metadata.length", "metadata.utf8", "metadata.json"];
const IMAGE_ISSUES: [&str; 9] = ["image.empty", "image.limit", "image.format", "image.header",
    "image.extension", "image.dimensions", "image.device", "image.duplicate", "image.count"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Request { pub project_id: String, pub platform: Platform }
pub(crate) fn request(body: &Value) -> Result<Request, BridgeError> {
    value_bounds(body, 3, 512)?;
    let input = Request::deserialize(body).map_err(|_| BridgeError::invalid())?;
    if !protocol::valid_id(&input.project_id) { return Err(BridgeError::invalid()); }
    Ok(input)
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Kind { PublicText, AndroidNote, IosNote, Image }
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum FileState { Checked, Missing, Invalid }
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum State { Checked, Issues }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedConfig { bytes: u32, sha256: String }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRow {
    kind: Kind, id: String, path: Option<String>, locale: Option<String>,
    required: bool, state: FileState, issues: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageSet { locale: String, id: String, count: u32, required: bool, issues: Vec<String> }
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Report {
    schema_version: u32, platform: Platform, metadata_root: String, locales: Vec<String>,
    android_build: Option<u32>, saved_config: SavedConfig, scope: String,
    observation_scope: String, valid: bool, state: State, files: Vec<FileRow>,
    image_sets: Vec<ImageSet>, assurance: Assurance,
}
fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
fn exact_shape(value: &Value) -> bool {
    // Option fields must be explicit null, not silently defaulted by serde.
    keys(value, &["schemaVersion", "platform", "metadataRoot", "locales", "androidBuild",
        "savedConfig", "scope", "observationScope", "valid", "state", "files", "imageSets", "assurance"])
        && keys(&value["savedConfig"], &["bytes", "sha256"])
        && value["files"].as_array().is_some_and(|rows| rows.len() <= MAX_ROWS && rows.iter().all(|row|
            keys(row, &["kind", "id", "path", "locale", "required", "state", "issues"])))
        && value["imageSets"].as_array().is_some_and(|rows| rows.len() <= MAX_ROWS && rows.iter().all(|row|
            keys(row, &["locale", "id", "count", "required", "issues"])))
}
fn unique_codes(codes: &[String], allowed: &[&str]) -> bool {
    codes.len() <= allowed.len() && codes.iter().all(|code| allowed.contains(&code.as_str()))
        && codes.iter().collect::<BTreeSet<_>>().len() == codes.len()
}
fn suffix(name: &str, allowed: &[&str]) -> bool {
    name.rsplit_once('.').is_some_and(|(_, ext)| allowed.contains(&ext.to_ascii_lowercase().as_str()))
}
fn basename(name: &str) -> bool { !name.contains('/') && text::relative(name) }
// Transport syntax mirrors the existing core safe_name, not image/Store policy.
fn image_basename(name: &str) -> bool {
    let Some((stem, _)) = name.rsplit_once('.') else { return false; };
    basename(name) && name.len() <= 255 && stem.len() <= 251
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b' ' | b'-'))
        && !name.contains("..") && suffix(name, &["png", "jpg", "jpeg"])
}
fn image_policy<'a>(catalog: &'a Value, platform: Platform, id: &str) -> Option<&'a Value> {
    catalog["types"].as_array()?.iter().find(|row| row["platform"].as_str() == Some(platform.name()) && row["id"].as_str() == Some(id))
}
impl Report {
    fn valid_for(&self, platform: Platform, catalog: &Value) -> bool {
        if self.schema_version != 1 || self.platform != platform || self.locales.is_empty() || self.locales.len() > MAX_ROWS
            || !self.locales.windows(2).all(|pair| pair[0] < pair[1])
            || !self.locales.iter().all(|locale| text::target_context(&self.metadata_root, platform, locale))
            || self.scope != "configured-locales-canonical-images-fixed-notes"
            || self.observation_scope != "single-request-non-atomic" || !self.assurance.valid("static-text")
            || !(1..=512 * 1024).contains(&self.saved_config.bytes)
            || self.saved_config.sha256.len() != 64 || !self.saved_config.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.android_build == Some(0) || platform == Platform::Ios && self.android_build.is_some()
            || self.files.len() > MAX_ROWS || self.image_sets.len() > MAX_ROWS { return false; }
        let mut paths = BTreeSet::new();
        let mut fields = BTreeSet::new();
        let mut android_notes = BTreeSet::new();
        let mut ios_notes = BTreeSet::new();
        let mut images = BTreeMap::<(&str, &str), (u32, bool)>::new();
        for row in &self.files {
            if row.id.is_empty() || row.id.len() > 255
                || row.locale.as_ref().is_some_and(|locale| !self.locales.contains(locale))
                || row.path.as_ref().is_some_and(|path| path.len() > 512 || path.split('/').count() > 12 || !paths.insert(path.to_lowercase()))
                || (row.state == FileState::Checked) != row.issues.is_empty() { return false; }
            if row.state == FileState::Missing {
                if !row.required || row.issues != ["metadata.missing"] { return false; }
            } else {
                let allowed: &[&str] = match row.kind {
                    Kind::PublicText | Kind::IosNote => &TEXT_ISSUES,
                    Kind::AndroidNote => &["metadata.utf8", "metadata.android-note", "metadata.android-version"],
                    Kind::Image => &IMAGE_ISSUES[..8],
                };
                if !unique_codes(&row.issues, allowed) { return false; }
            }
            let locale = row.locale.as_deref();
            match row.kind {
                Kind::PublicText => {
                    let Some(locale) = locale else { return false; };
                    let required = platform.ids().iter().any(|id| id.name() == row.id);
                    if !basename(&row.id) || !suffix(&row.id, &["txt", "md", "json"])
                        || row.required != required || !fields.insert((locale, row.id.as_str()))
                        || row.path.as_deref() != Some(format!("{}/{}/{}/{}", self.metadata_root, platform.name(), locale, row.id).as_str())
                        || !row.path.as_ref().is_some_and(|path| text::relative(path))
                        || row.issues.iter().any(|code| code == "metadata.json") && !suffix(&row.id, &["json"]) { return false; }
                }
                Kind::AndroidNote => {
                    let Some(locale) = locale else { return false; };
                    if platform != Platform::Android || row.id != "release-notes" || !row.required || !android_notes.insert(locale) { return false; }
                    if let Some(build) = self.android_build {
                        let folder = format!("{}/android/{locale}/changelogs", self.metadata_root);
                        if !row.path.as_ref().is_some_and(|path| path == &format!("{folder}/{build}.txt") || path == &format!("{folder}/default.txt"))
                            || row.issues.iter().any(|code| code == "metadata.android-version") { return false; }
                    } else if row.path.is_some() || row.state != FileState::Invalid || row.issues != ["metadata.android-version"] { return false; }
                }
                Kind::IosNote => {
                    if platform != Platform::Ios || locale.is_some() || !row.required || !ios_notes.insert(row.id.as_str())
                        || !IOS_NOTES.iter().any(|name| name.rsplit('/').next() == Some(row.id.as_str())
                            && row.path.as_deref() == Some(format!("{}/{name}", self.metadata_root).as_str()))
                        || row.issues.iter().any(|code| code == "metadata.json") { return false; }
                }
                Kind::Image => {
                    let (Some(locale), Some(path)) = (locale, row.path.as_deref()) else { return false; };
                    let Some(policy) = image_policy(catalog, platform, &row.id) else { return false; };
                    if row.required || row.state == FileState::Missing || !text::relative(path) { return false; }
                    let Some((parent, name)) = path.rsplit_once('/') else { return false; };
                    let singleton = policy["singleton"].as_bool() == Some(true);
                    let folder = match platform {
                        Platform::Android if singleton => format!("{}/android/{locale}/images", self.metadata_root),
                        Platform::Android => format!("{}/android/{locale}/images/{}", self.metadata_root, row.id),
                        Platform::Ios => format!("{}/ios/screenshots/{locale}/{}", self.metadata_root, row.id),
                    };
                    if parent != folder || !image_basename(name)
                        || singleton && !["png", "jpg", "jpeg"].iter().any(|ext| name == format!("{}.{ext}", row.id)) { return false; }
                    let group = images.entry((locale, row.id.as_str())).or_default();
                    group.0 += 1;
                    group.1 |= row.issues.iter().any(|code| code == "image.duplicate");
                }
            }
        }
        if !self.locales.iter().all(|locale| platform.ids().iter().all(|id| fields.contains(&(locale.as_str(), id.name()))))
            || platform == Platform::Android && android_notes.len() != self.locales.len()
            || platform == Platform::Ios && ios_notes.len() != IOS_NOTES.len()
            || self.image_sets.len() != images.len() { return false; }
        let mut groups = BTreeSet::new();
        for group in &self.image_sets {
            let key = (group.locale.as_str(), group.id.as_str());
            let Some((count, duplicate)) = images.get(&key) else { return false; };
            let Some(max) = image_policy(catalog, platform, &group.id).and_then(|row| row["maxCount"].as_u64()) else { return false; };
            if group.required || group.count == 0 || group.count != *count || !groups.insert(key)
                || !unique_codes(&group.issues, &["image.count", "image.duplicate"])
                || group.issues.iter().any(|code| code == "image.count") != (u64::from(*count) > max)
                || group.issues.iter().any(|code| code == "image.duplicate") != *duplicate { return false; }
        }
        let valid = self.files.iter().all(|row| row.state == FileState::Checked) && self.image_sets.iter().all(|group| group.issues.is_empty());
        self.valid == valid && (self.state == State::Checked) == valid
    }
}
pub(crate) fn result(value: Value, platform: Platform) -> Result<Report, BridgeError> {
    protocol::check_metadata_validation_result(&value).map_err(|_| BridgeError::protocol())?;
    if !exact_shape(&value) { return Err(BridgeError::protocol()); }
    let report = Report::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    let catalog = crate::metadata_images_edit_protocol::catalog()?;
    if !report.valid_for(platform, &catalog) { return Err(BridgeError::protocol()); }
    Ok(report)
}

// Generated from the core's fixed error table; never accept exception text.
const PASSIVE_ERRORS: [(&str, &str); 13] = [
    ("metadata_validation_invalid_params", "Saved metadata validation requires a selected project and one platform."),
    ("metadata_validation_unavailable", "Saved metadata validation is unavailable on this platform."),
    ("metadata_validation_config_missing", "Save release/mobile-release.json before validating metadata."),
    ("metadata_validation_config_invalid", "Correct and save the project configuration before validating metadata."),
    ("metadata_validation_not_configured", "Enable the selected platform and save at least one configured locale."),
    ("metadata_validation_unsafe", "A requested metadata path or portable alias cannot be inspected safely."),
    ("metadata_validation_changed", "The selected configuration or metadata changed during this check. Run a new check."),
    ("metadata_validation_unreadable", "The selected metadata could not be read safely. No complete report was returned."),
    ("metadata_validation_limit", "The local check exceeded its bounded file, byte, entry, result or time limit. No complete report was returned."),
    ("metadata_validation_encoding", "The saved configuration is not valid UTF-8."),
    ("metadata_validation_sensitive", "The saved configuration may contain secret material. No values were returned."),
    ("metadata_validation_catalog_unavailable", "The bundled image policy is unavailable. No complete report was returned."),
    ("metadata_validation_cleanup_unknown", "Original metadata observation cleanup could not be confirmed."),
];
pub(crate) fn decode_envelope(bytes: &[u8], id: &str) -> Result<Value, BridgeError> {
    if bytes.len() > RESPONSE_LIMIT { return Err(BridgeError::protocol()); }
    protocol::decode_metadata_validation_response(bytes, id).map_err(|error| {
        if !error.retryable && (error == BridgeError::protocol()
            || PASSIVE_ERRORS.iter().any(|(code, message)| error.code == *code && error.message == *message)) { error }
        else { BridgeError::protocol() }
    })
}

#[cfg(test)]
#[path = "metadata_validation_protocol_tests.rs"]
mod tests;
