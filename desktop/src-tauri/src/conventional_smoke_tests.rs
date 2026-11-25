//! Fixed Linux conventional-runtime bootstrap smoke; no runner is supplied.
//! Reuses the existing trusted-development Case/owner, not installed custody.
//! The future command must supply the SAME independently accepted prepared
//! manifest/protocol pins to this artifact and probe_cpython_source_runtime.py.
//! Missing compiled anchors refuse before fixture input/filesystem access.
use super::*;
use std::{io::Read, os::unix::fs::MetadataExt};

const PROFILE: &str = "cpython-3.14.7-linux-x86_64-source-v1";
const SCOPE: &str = "conventional-runtime-bootstrap-smoke-v1";
const CASES: [&str; 2] = ["core-capabilities", "core-zip-catalog"];
const SELECTED: [&str; 6] = ["core.zip", "engine_bootstrap.py", "github-ca.pem", "python/bin/python3",
    "python/lib/libcrypto.so.3", "python/lib/libssl.so.3"];
const CA_SHA256: &str = "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f";

#[derive(Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreparedFile { path: String, sha256: String, size: u64 }

fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn anchors<'a>(manifest: Option<&'a str>, protocol: Option<&'a str>) -> Check<(&'a str, &'a str)> {
    match (manifest, protocol) {
        (Some(manifest), Some(protocol)) if sha(manifest) && sha(protocol) => Ok((manifest, protocol)),
        _ => Err("conventional_prepared_anchors_missing"),
    }
}
fn selected_records(value: &Value) -> Check<Vec<PreparedFile>> {
    let rows = value["files"].as_array().ok_or("conventional_prepared_files")?;
    let mut result = BTreeMap::new();
    for value in rows {
        if value["path"].as_str().is_some_and(|path| SELECTED.contains(&path)) {
            let row: PreparedFile = serde_json::from_value(value.clone()).map_err(|_| "conventional_prepared_row")?;
            require(row.size > 0 && row.size <= 64 * 1024 * 1024 && sha(&row.sha256), "conventional_prepared_row")?;
            require(!result.contains_key(&row.path), "conventional_prepared_duplicate")?;
            result.insert(row.path.clone(), row);
        }
    }
    require(result.len() == SELECTED.len(), "conventional_prepared_selected_missing")?;
    let ca = result.get("github-ca.pem").ok_or("conventional_prepared_ca")?;
    require(ca.size == 240216 && ca.sha256 == CA_SHA256, "conventional_prepared_ca")?;
    Ok(result.into_values().collect())
}
fn body_matches(row: &PreparedFile, bytes: &[u8]) -> bool {
    row.size == bytes.len() as u64 && row.sha256 == hash(bytes)
}
fn read_bound(path: &Path, limit: u64) -> Check<Vec<u8>> {
    // Ordinary preparation correspondence, not a native-custody/close witness.
    require(path.is_absolute() && path.canonicalize().map_err(|_| "conventional_path")? == path, "conventional_path")?;
    let before = fs::symlink_metadata(path).map_err(|_| "conventional_file")?;
    require(before.is_file() && before.nlink() == 1 && before.len() > 0 && before.len() <= limit,
        "conventional_file_bound")?;
    let state = |value: &fs::Metadata| (value.dev(), value.ino(), value.mode(), value.nlink(), value.len(),
        value.mtime(), value.mtime_nsec(), value.ctime(), value.ctime_nsec());
    let mut original = fs::File::open(path).map_err(|_| "conventional_file_open")?;
    require(state(&original.metadata().map_err(|_| "conventional_file_open")?) == state(&before), "conventional_file_changed")?;
    let mut bytes = Vec::new();
    original.by_ref().take(limit + 1).read_to_end(&mut bytes).map_err(|_| "conventional_file_read")?;
    require(bytes.len() as u64 == before.len()
        && state(&original.metadata().map_err(|_| "conventional_file_after")?) == state(&before)
        && state(&fs::symlink_metadata(path).map_err(|_| "conventional_file_after")?) == state(&before),
        "conventional_file_changed")?;
    Ok(bytes)
}
fn prepared_bindings(inputs: &Inputs, manifest_sha: &str, protocol_sha: &str) -> Check<Value> {
    let python = selected("MRK_DESKTOP_DEV_PYTHON")?;
    let bundle = python.parent().and_then(Path::parent).and_then(Path::parent).ok_or("conventional_layout")?;
    require(bundle.file_name().is_some_and(|name| name == "runtime")
        && python == bundle.join("python/bin/python3") && inputs.zip == bundle.join("core.zip")
        && !bundle.starts_with(&inputs.root), "conventional_prepared_layout")?;
    // Reuse the existing COMPLETE manifest/inventory inspector; no new census,
    // manifest schema, loader assertion or production admission is invented.
    let resource_dir = bundle.parent().ok_or("conventional_layout")?;
    let inspected = RuntimeConfig::packaged(resource_dir.to_path_buf())
        .inspect_bundle_for_packaging(Instant::now() + OPERATION_TIME).map_err(|_| "conventional_prepared_inventory")?;
    require(inspected.target == "x86_64-unknown-linux-gnu", "conventional_target")?;
    let raw = read_bound(&bundle.join("manifest.json"), 1024 * 1024)?;
    require(hash(&raw) == manifest_sha, "conventional_prepared_manifest_pin")?;
    let manifest = protocol::strict_json(&raw).map_err(|_| "conventional_prepared_manifest")?;
    require(manifest["protocolSha256"] == protocol_sha && inputs.bindings["engineSha256"] == protocol_sha,
        "conventional_protocol_pin")?;
    let rows = selected_records(&manifest)?;
    for row in &rows {
        let bytes = read_bound(&bundle.join(&row.path), 64 * 1024 * 1024)?;
        require(body_matches(row, &bytes), "conventional_prepared_body_pin")?;
        if row.path == "core.zip" {
            require(inputs.bindings["coreZipSha256"] == row.sha256, "conventional_zip_pin")?;
        }
        if row.path == "engine_bootstrap.py" {
            let source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().ok_or("conventional_source_layout")?
                .join("engine_bootstrap.py");
            let source_bytes = read_bound(&source, 64 * 1024)?;
            require(body_matches(row, &source_bytes) && source_bytes.as_slice() == include_bytes!("../../engine_bootstrap.py"),
                "conventional_checkout_bootstrap_differs")?;
        }
    }
    Ok(json!({"profile": PROFILE, "manifestSha256": manifest_sha, "protocolSha256": protocol_sha,
        "files": rows, "coreSelection": "prepared-zip-only", "checkoutBootstrapEqualsPrepared": true}))
}

fn receipt_value(status: &str, failure: Option<&str>, bindings: &Value, cases: &[Value]) -> Check<Value> {
    require(matches!(status, "running" | "failed" | "failed-retained" | "passed"), "conventional_receipt_state")?;
    if status == "passed" {
        require(failure.is_none() && cases.len() == CASES.len() && cases.iter().zip(CASES).all(|(row, name)|
            row["case"] == name && row["passed"] == true && row["failureCode"].is_null()), "conventional_exact_two_required")?;
    }
    Ok(json!({"schemaVersion": 1, "profile": PROFILE, "scope": SCOPE, "status": status,
        "allOwnersSettled": status == "passed", "failureCode": failure, "bindings": bindings, "cases": cases,
        "notVerified": ["installed-runtime-custody", "immutable-publication", "tls-handshake",
            "dns-or-github-authentication", "native-close-faults", "gui", "production-enablement"],
        "outerOriginalWaitRequired": true}))
}
fn write_receipt(path: &Path, status: &str, failure: Option<&str>, bindings: &Value, cases: &[Value]) -> Check<()> {
    let bytes = serde_json::to_vec(&receipt_value(status, failure, bindings, cases)?).map_err(|_| "conventional_receipt_encoding")?;
    require(bytes.len() <= 64 * 1024, "conventional_receipt_bound")?;
    fs::write(path, bytes).map_err(|_| "conventional_receipt_write")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "only a separately reviewed conventional-runtime smoke command; no runner supplied"]
async fn conventional_interpreter_bootstrap_smoke() {
    let (manifest_sha, protocol_sha) = anchors(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"),
        option_env!("MRK_BUNDLED_PROTOCOL_SHA256")).unwrap_or_else(|code| panic!("conventional smoke refused: {code}"));
    let inputs = Inputs::admit_mode(SCOPE).unwrap_or_else(|code| panic!("conventional smoke refused: {code}"));
    let prepared = prepared_bindings(&inputs, manifest_sha, protocol_sha)
        .unwrap_or_else(|code| panic!("conventional smoke refused: {code}"));
    let bindings = json!({"source": inputs.bindings, "prepared": prepared});
    let path = inputs.root.join("conventional-smoke-receipt.json");
    let mut cases = Vec::new();
    write_receipt(&path, "running", None, &bindings, &cases).unwrap_or_else(|code| panic!("conventional smoke refused: {code}"));
    for name in CASES {
        let unchanged = prepared_bindings(&inputs, manifest_sha, protocol_sha).is_ok_and(|value| value == prepared);
        if !unchanged {
            let _ = write_receipt(&path, "failed", Some("conventional_prepared_changed"), &bindings, &cases);
            panic!("conventional prepared inputs changed before a case");
        }
        // BOTH existing assertions consume the exact prepared ZIP. No fixture
        // Python module, source-core case, arbitrary selector or product change.
        let mut case = match Case::new(&inputs, name, None, true) {
            Ok(case) => case,
            Err(code) => { let _ = write_receipt(&path, "failed", Some(code), &bindings, &cases); panic!("conventional case refused: {code}"); },
        };
        let mut checked = exercise(&mut case).await;
        if !case.settle(checked.is_err()).await {
            cases.push(case.evidence(false, Some("custody_unresolved")));
            let _ = write_receipt(&path, "failed-retained", Some("custody_unresolved"), &bindings, &cases);
            // SAME old Case failure discipline: retain original runtime,
            // owners/resources and selection. No next case/reset/abort/cleanup.
            pending::<()>().await;
            return;
        }
        if checked.is_ok() { checked = case.native_facts(true, true); }
        if checked.is_ok() {
            checked = require(!case.supervisor.disabled()
                && prepared_bindings(&inputs, manifest_sha, protocol_sha).is_ok_and(|value| value == prepared),
                "conventional_final_facts_or_inputs_changed");
        }
        cases.push(case.evidence(checked.is_ok(), checked.err()));
        if let Err(code) = checked {
            let _ = write_receipt(&path, "failed", Some(code), &bindings, &cases);
            panic!("conventional case failed after settlement: {code}");
        }
        write_receipt(&path, "running", None, &bindings, &cases).unwrap_or_else(|code| panic!("conventional receipt failed: {code}"));
    }
    std::env::set_var("MRK_DESKTOP_DEV_CORE", &inputs.source); // Only after BOTH cases actually settled.
    write_receipt(&path, "passed", None, &bindings, &cases).unwrap_or_else(|code| panic!("conventional receipt failed: {code}"));
}

// Focused DATA-only contracts: no environment, files, tasks, child or runtime.
#[test]
fn conventional_missing_or_malformed_anchors_refuse() {
    assert!(anchors(None, None).is_err());
    assert!(anchors(Some(&"a".repeat(64)), None).is_err());
    assert!(anchors(Some(&"A".repeat(64)), Some(&"b".repeat(64))).is_err());
    assert!(anchors(Some(&"a".repeat(64)), Some(&"b".repeat(64))).is_ok());
}
#[test]
fn conventional_body_binding_requires_exact_original_size_and_hash() {
    let row = PreparedFile { path: "core.zip".into(), size: 5, sha256: hash(b"inert") };
    assert!(body_matches(&row, b"inert"));
    assert!(!body_matches(&row, b"other") && !body_matches(&row, b"inert\n"));
}
#[test]
fn conventional_selected_roster_requires_all_six_and_the_fixed_ca() {
    let mut rows: Vec<Value> = SELECTED.iter().map(|name| json!({"path": name, "size": 5, "sha256": hash(b"inert")})).collect();
    rows[2] = json!({"path": "github-ca.pem", "size": 240216, "sha256": CA_SHA256});
    assert!(selected_records(&json!({"files": rows})).is_ok());
    let mut missing = rows.clone(); missing.pop();
    assert!(selected_records(&json!({"files": missing})).is_err());
    let mut duplicate = rows.clone(); duplicate.push(rows[0].clone());
    assert!(selected_records(&json!({"files": duplicate})).is_err());
    rows[2]["sha256"] = json!(hash(b"not-the-fixed-ca"));
    assert!(selected_records(&json!({"files": rows})).is_err());
}
#[test]
fn conventional_receipt_cannot_label_old_or_partial_cases_as_passed() {
    let rows: Vec<Value> = CASES.iter().map(|name| json!({"case": name, "passed": true, "failureCode": null})).collect();
    let receipt = receipt_value("passed", None, &Value::Null, &rows).unwrap();
    assert_eq!(receipt["scope"], SCOPE);
    assert_ne!(receipt["scope"], "passive-hosted-v2");
    assert!(receipt_value("passed", None, &Value::Null, &rows[..1]).is_err());
    let mut reversed = rows.clone(); reversed.reverse();
    assert!(receipt_value("passed", None, &Value::Null, &reversed).is_err());
    assert!(receipt_value("passed", Some("failed"), &Value::Null, &rows).is_err());
    assert_eq!(receipt_value("failed-retained", Some("custody_unresolved"), &Value::Null, &rows).unwrap()["allOwnersSettled"], false);
}
