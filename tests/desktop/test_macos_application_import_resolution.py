"""Compile the actual application import hierarchy without executing its owners.

Set MRK_IMPORT_RESOLUTION_RUSTC to an admitted direct compiler. The fixture
copies production module declarations, parent globs, aliases and the six use
statements; unrelated implementation types are inert declarations. Three
compile-only controls distinguish include! resolution from runtime behavior.
"""
from pathlib import Path
import json
import os
import re
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "desktop/src-tauri/src"
RUSTC = os.environ.get("MRK_IMPORT_RESOLUTION_RUSTC")


def source(name):
    return (SOURCE / name).read_text(encoding="utf-8")


def declaration(filename, name):
    matches = re.findall(
        r'(?m)^(?:#\[path\s*=\s*"[^"]+"\]\n)?'
        r'(?:pub(?:\([^)]*\))?\s+)?mod\s+' + re.escape(name) + r'\s*;',
        source(filename),
    )
    if len(matches) != 1:
        raise AssertionError((filename, name, "one production module declaration required"))
    return matches[0]


def first_line(filename, pattern):
    return next(line.strip() for line in source(filename).splitlines()
                if re.match(pattern, line.strip()))


def hierarchy():
    files = {}
    roots = ("service_github_action_protocol", "service_github_action_requests",
             "asset_session", "github_connection_protocol", "github_connection_session")
    files["lib_application.rs"] = "\n".join(declaration("lib_application.rs", n) for n in roots) + "\n"
    files["asset_session.rs"] = "\n".join(declaration("asset_session.rs", n) for n in
        ("saved_observation", "apple_provisioning", "apple_key", "store_material")) + "\n"
    for filename, module, item in (
        ("asset_session_saved_observation.rs", "apple_provisioning", "AppleProvisioningSavedInput"),
        ("asset_session_store_material.rs", "apple_key", "p12::P12Material"),
    ):
        files[filename] = (first_line(filename, r"use super::\*;") + "\n"
            + declaration(filename, module) + "\n"
            + first_line(filename, r"pub\(crate\) use (?:self::)?" + module + "::" + item + ";") + "\n")
    # Distinct parent types ensure that resolving a parent name cannot pass.
    files["asset_session_apple_provisioning.rs"] = "pub(crate) struct AppleProvisioningDocumentInput;\n"
    files["asset_session_apple_provisioning_saved.rs"] = "pub(crate) struct AppleProvisioningSavedInput;\n"
    files["asset_session_apple_key.rs"] = "pub(crate) struct ParentKey;\n"
    files["asset_session_apple_key_material.rs"] = "pub(crate) mod p12 {pub(crate) struct P12Material;}\n"
    # Preserve the parent alias from the production grouped import.
    if "github_connection_protocol::{self as wire," not in source("github_connection_session.rs"):
        raise AssertionError("production parent wire alias changed")
    files["github_connection_session.rs"] = "use crate::github_connection_protocol as wire;\n" + "\n".join(
        declaration("github_connection_session.rs", n)
        for n in ("repository_create", "pull_request", "actions_retry", "activity")) + "\n"
    for parent, child in (
        ("github_repository_create_session.rs", "github_repository_operation_delegation.rs"),
        ("github_pull_request_session.rs", "github_pr_operation_delegation.rs"),
        ("github_actions_retry_session.rs", "github_retry_operation_delegation.rs"),
    ):
        files[parent] = first_line(parent, r"use super::\*;") + "\n" + declaration(parent, "operation") + "\n"
        files[child] = (first_line(child, r"use super::\*;") + "\n"
            + first_line(child, r"use crate::\{service_github_action_protocol as wire,") + "\n"
            + "pub(crate) fn select() { let _ = (|| {\n"
            + first_line(child, r"use (?:self::)?wire::\{") + "\n"
            + "let _: Option<(Hex,Record,Snapshot)> = None;});}\n")
    files["github_activity_session.rs"] = (declaration("github_activity_session.rs", "delegation")
        + "\n" + first_line("github_activity_session.rs", r"use super::\*;") + "\n")
    activity = source("service_github_activity_native.rs")
    matched = re.search(r"use (?:self::)?wire::activity::\{.*?\n\};", activity, re.S)
    if matched is None:
        raise AssertionError("production activity import missing")
    files["service_github_activity_native.rs"] = (
        first_line("service_github_activity_native.rs", r"use super::\*;") + "\n"
        + first_line("service_github_activity_native.rs", r"use crate::\{service_github_action_protocol as wire,")
        + "\n" + matched.group() + "\n")
    files["github_connection_protocol.rs"] = "pub(crate) struct OuterProtocol;\n"
    files["service_github_action_requests.rs"] = ""
    files["service_github_action_protocol.rs"] = (
        "pub(crate) mod dispatch {pub(crate) struct Hex;}\n"
        "pub(crate) mod operation {pub(crate) struct Record;pub(crate) struct Snapshot;}\n"
        "pub(crate) mod activity {pub(crate) fn decimal(){} pub(crate) const ROWS:usize=1;"
        + " ".join("pub(crate) struct " + n + ";" for n in
            ("Conclusion", "Coverage", "Pull", "PullState", "Run", "RunState", "Section", "SectionReason", "SectionState"))
        + "}\n")
    return files


@unittest.skipUnless(RUSTC, "requires an explicitly admitted direct Rust compiler")
class ApplicationImportResolution(unittest.TestCase):
    def test_actual_local_bindings_survive_application_include(self):
        compiler = Path(RUSTC)
        self.assertTrue(compiler.is_absolute() and compiler.is_file())
        evidence = os.environ.get("MRK_IMPORT_RESOLUTION_EVIDENCE")
        with tempfile.TemporaryDirectory(dir=os.environ.get("MRK_IMPORT_RESOLUTION_TEST_ROOT")) as temporary:
            root = Path(evidence) if evidence else Path(temporary)
            if evidence:
                root.mkdir(mode=0o700)
            files = hierarchy()
            results = []
            for label, included, original in (("inline-original", False, True),
                    ("included-original", True, True), ("included-current", True, False)):
                case = root / label
                case.mkdir(mode=0o700)
                for filename, body in files.items():
                    if original:
                        body = body.replace("use self::apple_provisioning", "use apple_provisioning")
                        body = body.replace("use self::apple_key", "use apple_key").replace("use self::wire", "use wire")
                    (case / filename).write_text(body, encoding="utf-8")
                (case / "lib.rs").write_text("#![allow(dead_code,unused_imports)]\n" +
                    ('include!("lib_application.rs");\n' if included else files["lib_application.rs"]), encoding="utf-8")
                command = [str(compiler), "--edition=2021", "--crate-type=lib", "--emit=metadata",
                           "--error-format=json", str(case / "lib.rs"), "-o", str(case / "resolution.rmeta")]
                started = time.monotonic()
                result = subprocess.run(command, cwd=case, capture_output=True, timeout=30)
                (case / "stdout.log").write_bytes(result.stdout)
                (case / "stderr.log").write_bytes(result.stderr)
                diagnostics = [json.loads(line) for line in result.stderr.splitlines() if line.startswith(b"{")]
                errors = [row for row in diagnostics if row.get("level") == "error" and row.get("code")]
                record = dict(case=label, command=command, originalReturn=result.returncode,
                    elapsedSeconds=time.monotonic()-started, errorCodes=[row["code"]["code"] for row in errors],
                    stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr), compiledProgramExecuted=False)
                (case / "original-return.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
                results.append(record)
                self.assertLessEqual(len(result.stdout), 65536)
                self.assertLessEqual(len(result.stderr), 262144)
            (root / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(results[0]["originalReturn"], 0, results[0])
            self.assertNotEqual(results[1]["originalReturn"], 0, results[1])
            self.assertEqual(results[1]["errorCodes"], ["E0659"] * 6, results[1])
            self.assertEqual(results[2]["originalReturn"], 0, results[2])


if __name__ == "__main__":
    unittest.main()
