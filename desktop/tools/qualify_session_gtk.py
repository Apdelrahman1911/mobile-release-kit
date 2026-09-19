"""Fixed direct-GTK SG1 outer consumer; SOURCE ONLY, NOT qualified.

Invoke only after distinct disposable-host/execution admission with the audited
interpreter's -I -S -B. This file is not a generic command, GUI selector, build
script or receipt-only certificate. Missing API/audit pins refuse before owned
file/native/process/socket acquisition. Interpreter/stdlib and pre-main loading
still require their separate exact audits. No environment value enables them.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

PROFILE = "linux-x11-atspi-direct-gtk-sg1-v1"
CASE = "SG1"
SCOPE = "session-gtk-five-dialog-v1"
BASELINE_COMMIT = "6768b284c0d01f6f70913799f4fadfdd572fb162"
BASELINE = "e6abe8fdc6df328da336301ebfa4fffb36555d58f5611873016ef4bc8df53c50"
FEATURES = b"test\ndebug_assertions\ndesktop-shell\ndevelopment-runtime\nx86_64-unknown-linux-gnu\n"
WITNESS = b"MRK_SHELL_EXIT_V1\n"
SYNTHETIC = bytes.fromhex("feedfeed0000000200000000")
NS = 1_000_000_000
# Deliberately absent. These four actual reviewed documents cover source/host,
# installed closure, loader/import closure and the sole stdout-writer graph.
# A distinct later review must bind NEW direct-GTK/outer APIs, not old labels.
API_INVENTORY: str | None = None
AUDIT_PINS: tuple[str, str, str, str] | None = None
FREEZE_FILE = Path("/opt/mrk-native-reviewed/session-gtk-freeze.json")
ROSTER = ("picker-cancel", "picker-select", "source-select", "quit-cancel", "quit-ok")
# Literal source DATA matched to Q's complete first-party roster. No runtime
# glob, Git discovery, source execution, generated include or module import.
SOURCES = (
    '.github/workflows/desktop-environment-diagnostics-native.yml',
    '.github/workflows/desktop-github-connection-tls.yml',
    '.github/workflows/desktop-github-workflow-apply-native.yml',
    'desktop/config_edit_bootstrap.py',
    'desktop/engine_bootstrap.py',
    'desktop/environment_bootstrap.py',
    'desktop/github_connection_bootstrap.py',
    'desktop/index.html',
    'desktop/native/linux-mount-observation/Cargo.toml',
    'desktop/native/linux-mount-observation/src/lib.rs',
    'desktop/native/session_gtk_input_linux.c',
    'desktop/package-lock.json',
    'desktop/package.json',
    'desktop/rust-toolchain.toml',
    'desktop/src-tauri/Cargo.lock',
    'desktop/src-tauri/Cargo.toml',
    'desktop/src-tauri/build.rs',
    'desktop/src-tauri/capabilities/main.json',
    'desktop/src-tauri/icons/icon.ico',
    'desktop/src-tauri/icons/icon.png',
    'desktop/src-tauri/icons/icon.svg',
    'desktop/src-tauri/src/asset_commands.rs',
    'desktop/src-tauri/src/asset_session.rs',
    'desktop/src-tauri/src/asset_source.rs',
    'desktop/src-tauri/src/bridge.rs',
    'desktop/src-tauri/src/credential_assessment.rs',
    'desktop/src-tauri/src/credential_format.rs',
    'desktop/src-tauri/src/document_lifetime.rs',
    'desktop/src-tauri/src/edit_commands.rs',
    'desktop/src-tauri/src/edit_hosted_tests.rs',
    'desktop/src-tauri/src/edit_owner.rs',
    'desktop/src-tauri/src/edit_protocol.rs',
    'desktop/src-tauri/src/environment.rs',
    'desktop/src-tauri/src/environment_diagnostics_hosted_tests.rs',
    'desktop/src-tauri/src/environment_diagnostics_owner.rs',
    'desktop/src-tauri/src/environment_diagnostics_protocol.rs',
    'desktop/src-tauri/src/error.rs',
    'desktop/src-tauri/src/github_commands.rs',
    'desktop/src-tauri/src/github_connection_protocol.rs',
    'desktop/src-tauri/src/github_connection_session.rs',
    'desktop/src-tauri/src/github_workflow_edit_protocol.rs',
    'desktop/src-tauri/src/hosted_tests.rs',
    'desktop/src-tauri/src/installed_runtime.rs',
    'desktop/src-tauri/src/lib.rs',
    'desktop/src-tauri/src/main.rs',
    'desktop/src-tauri/src/metadata_text_commands.rs',
    'desktop/src-tauri/src/metadata_text_edit_protocol.rs',
    'desktop/src-tauri/src/passive_management_tests.rs',
    'desktop/src-tauri/src/protocol.rs',
    'desktop/src-tauri/src/release_version_protocol.rs',
    'desktop/src-tauri/src/runtime.rs',
    'desktop/src-tauri/src/session_gtk_qualification.rs',
    'desktop/src-tauri/src/session_gtk_qualification/native_contract.rs',
    'desktop/src-tauri/src/shell.rs',
    'desktop/src-tauri/src/supervisor.rs',
    'desktop/src-tauri/tauri.conf.json',
    'desktop/src-tauri/tests/fixtures/github_core/_desktop_github_engine.py',
    'desktop/src-tauri/tests/fixtures/github_tls/api-expired.pem',
    'desktop/src-tauri/tests/fixtures/github_tls/api-valid.pem',
    'desktop/src-tauri/tests/fixtures/github_tls/other-root-ca.pem',
    'desktop/src-tauri/tests/fixtures/github_tls/root-ca.pem',
    'desktop/src-tauri/tests/fixtures/github_tls/server-key.pem',
    'desktop/src-tauri/tests/fixtures/github_tls/wrong-san.pem',
    'desktop/src-tauri/tests/fixtures/github_tls_namespace.sh',
    'desktop/src-tauri/tests/fixtures/github_tls_peer.py',
    'desktop/src-tauri/tests/fixtures/passive_core/__init__.py',
    'desktop/src-tauri/tests/fixtures/passive_core/_desktop_engine.py',
    'desktop/src-tauri/tests/session_gtk_qualification.rs',
    'desktop/src-tauri/tests/session_gtk_recipe.js',
    'desktop/src/App.tsx',
    'desktop/src/api.ts',
    'desktop/src/assetSessionController.ts',
    'desktop/src/assetSessionHelp.ts',
    'desktop/src/assetSessionProtocol.ts',
    'desktop/src/assetSessionTypes.ts',
    'desktop/src/bridge.ts',
    'desktop/src/catalog.ts',
    'desktop/src/certainty.ts',
    'desktop/src/components/Common.tsx',
    'desktop/src/components/ConfigSave.tsx',
    'desktop/src/components/CredentialSession.tsx',
    'desktop/src/components/DraftEditor.tsx',
    'desktop/src/components/DraftReview.tsx',
    'desktop/src/components/DraftSuggestions.tsx',
    'desktop/src/components/EnvironmentDiagnostics.tsx',
    'desktop/src/components/Fields.tsx',
    'desktop/src/components/GitHubConnection.tsx',
    'desktop/src/components/GitHubWorkflowApply.tsx',
    'desktop/src/components/Icon.tsx',
    'desktop/src/components/MetadataTextEditor.tsx',
    'desktop/src/components/RemovedFields.tsx',
    'desktop/src/configEdit.ts',
    'desktop/src/configEditController.ts',
    'desktop/src/configEditProtocol.ts',
    'desktop/src/credentialGuide.ts',
    'desktop/src/drafts.ts',
    'desktop/src/environment.ts',
    'desktop/src/environmentDiagnosticsController.ts',
    'desktop/src/environmentDiagnosticsProtocol.ts',
    'desktop/src/environmentDiagnosticsTypes.ts',
    'desktop/src/githubConnectionController.ts',
    'desktop/src/githubConnectionProtocol.ts',
    'desktop/src/githubConnectionTypes.ts',
    'desktop/src/githubSetupController.ts',
    'desktop/src/githubSetupProtocol.ts',
    'desktop/src/githubWorkflowEdit.ts',
    'desktop/src/githubWorkflowEditController.ts',
    'desktop/src/githubWorkflowEditProtocol.ts',
    'desktop/src/githubWorkflowEditTypes.ts',
    'desktop/src/main.tsx',
    'desktop/src/metadataText.ts',
    'desktop/src/metadataTextEditController.ts',
    'desktop/src/metadataTextProtocol.ts',
    'desktop/src/pages/Credentials.tsx',
    'desktop/src/pages/Dashboard.tsx',
    'desktop/src/pages/Environment.tsx',
    'desktop/src/pages/Future.tsx',
    'desktop/src/pages/GitHub.tsx',
    'desktop/src/pages/Metadata.tsx',
    'desktop/src/preparation.ts',
    'desktop/src/preview.ts',
    'desktop/src/releaseVersion.ts',
    'desktop/src/styles.css',
    'desktop/src/types.ts',
    'desktop/tools/qualify_session_gtk.py',
    'desktop/tsconfig.json',
    'desktop/vite.config.mjs',
    'pyproject.toml',
    'src/mobile_release/__init__.py',
    'src/mobile_release/__main__.py',
    'src/mobile_release/_command_process.py',
    'src/mobile_release/_desktop_edit_control.py',
    'src/mobile_release/_desktop_edit_engine.py',
    'src/mobile_release/_desktop_edit_protocol.py',
    'src/mobile_release/_desktop_engine.py',
    'src/mobile_release/_desktop_environment_control.py',
    'src/mobile_release/_desktop_environment_engine.py',
    'src/mobile_release/_desktop_environment_protocol.py',
    'src/mobile_release/_desktop_github_engine.py',
    'src/mobile_release/_github_connection_transport.py',
    'src/mobile_release/_lifetime_evidence.py',
    'src/mobile_release/_native_process.py',
    'src/mobile_release/_profile_callers.py',
    'src/mobile_release/_profile_process.py',
    'src/mobile_release/_store_lane_contract.py',
    'src/mobile_release/_store_lane_evidence.py',
    'src/mobile_release/_store_lane_files.py',
    'src/mobile_release/android.py',
    'src/mobile_release/android_upload_validation.py',
    'src/mobile_release/api/__init__.py',
    'src/mobile_release/api/_catalog.py',
    'src/mobile_release/api/_credential_assessment.py',
    'src/mobile_release/api/_credential_guide.py',
    'src/mobile_release/api/_environment.py',
    'src/mobile_release/api/_github_connection.py',
    'src/mobile_release/api/_github_setup.py',
    'src/mobile_release/api/_json.py',
    'src/mobile_release/api/_metadata_text.py',
    'src/mobile_release/api/_preview.py',
    'src/mobile_release/api/_release_version.py',
    'src/mobile_release/api/_snapshot.py',
    'src/mobile_release/api/_snapshot_windows.py',
    'src/mobile_release/api/_snapshot_windows_native.py',
    'src/mobile_release/api/contracts.py',
    'src/mobile_release/api/data/credential-guide-v1.json',
    'src/mobile_release/api/data/field-help.json',
    'src/mobile_release/api/data/github-connection-v1.json',
    'src/mobile_release/api/data/github-setup-v1.json',
    'src/mobile_release/api/data/metadata-text-help-v1.json',
    'src/mobile_release/api/data/project.schema.json',
    'src/mobile_release/build_inputs.py',
    'src/mobile_release/cancellation.py',
    'src/mobile_release/checked_files.py',
    'src/mobile_release/cli.py',
    'src/mobile_release/config.py',
    'src/mobile_release/config_edit.py',
    'src/mobile_release/config_payloads.py',
    'src/mobile_release/credential_policy.py',
    'src/mobile_release/credential_requirements.py',
    'src/mobile_release/credentials.py',
    'src/mobile_release/data/apple-profile-roots.pem',
    'src/mobile_release/discovery.py',
    'src/mobile_release/environment_diagnostics.py',
    'src/mobile_release/environment_diagnostics_tools.py',
    'src/mobile_release/errors.py',
    'src/mobile_release/github_workflow_edit.py',
    'src/mobile_release/init_transaction.py',
    'src/mobile_release/init_workspace_custody.py',
    'src/mobile_release/inspection.py',
    'src/mobile_release/ios.py',
    'src/mobile_release/ios_artifacts.py',
    'src/mobile_release/ios_der.py',
    'src/mobile_release/ios_entitlements.py',
    'src/mobile_release/ios_plist_binary.py',
    'src/mobile_release/ios_profile_auth.py',
    'src/mobile_release/ios_profile_trust.py',
    'src/mobile_release/ios_profiles.py',
    'src/mobile_release/ios_upload_validation.py',
    'src/mobile_release/local_signing.py',
    'src/mobile_release/macho.py',
    'src/mobile_release/metadata.py',
    'src/mobile_release/metadata_text.py',
    'src/mobile_release/metadata_text_edit.py',
    'src/mobile_release/owned_process.py',
    'src/mobile_release/preflight.py',
    'src/mobile_release/provenance.py',
    'src/mobile_release/reporting.py',
    'src/mobile_release/stores.py',
    'src/mobile_release/toolchain_policy.py',
    'src/mobile_release/tooling.py',
    'src/mobile_release/workflow.py',
    'src/mobile_release/workflow_payloads.py',
    'templates/workflows/mobile-candidate.yml',
    'templates/workflows/mobile-external-testing.yml',
    'templates/workflows/mobile-preflight.yml',
    'templates/workflows/mobile-production-submit.yml',
    'tests/native_desktop_config.py',
    'tests/native_desktop_config_eof.py',
    'tests/native_desktop_environment.py',
    'tests/workflow/command_bootstrap_fixture.py',
)
BUILD_KEYS = "baselineManifest sourceRoster contractSource helperSource launcherSource appBinary helperBinary launcherRuntime pythonRuntime frontend featuresSha256 apiInventory"
COMMON_KEYS = "v type case profile binding roots file writer writtenNs"
OWNERSHIP_KEYS = "method operation mainId dialogId tagOrdinal checkOrdinal checkedNs transientForMain"
TAIL_KEYS = {
    "ready": "helper registry sessionBusId a11yBusId subscriptions",
    "admission": "build readySha256 outer app helper appSpawnNs outerEndNs display fixtures pipes aliases sourceProfileSha256 installedClosureSha256 loaderClosureSha256 writerAuditSha256",
    "presented": "admissionSha256 n kind observedNs association dialog button dialogRole states buttonRole buttonAction",
    "go": "admissionSha256 n kind presentedSha256 action gate operation showOrdinal producerOrdinal ownership checkpointNs inputEndNs selected",
    "input": "admissionSha256 n kind presentedSha256 goSha256 action startedNs completedNs steps completion selected counts",
    "helper-settled": "admissionSha256 lastInputSha256 helper waitStatus waitNs stdout stderr",
}
NOT_VERIFIED = ["production-enablement", "native-other-cases", "credential-validity-or-unlock",
    "assessment-prepare-keep-save-assign", "edit-authorization", "packaged-runtime-custody", "physical-ux",
    "reload-rebind-unknown-recovery", "producer-stdout-close", "mobile-builds-stores-installers"]


class Refused(RuntimeError):
    """Sticky Unknown at the original owner; never an invitation to retry."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def now() -> int:
    n = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    require(0 <= n <= 2**64 - 1, "monotonic clock range")
    return n


def plus(n: int, delta: int) -> int:
    require(type(n) is int and 0 <= n <= 2**64 - 1 - delta, "endpoint overflow")
    return n + delta


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def h(value: Any, length: int = 64) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None, "digest shape")


def u(value: Any, maximum: int = 2**32 - 1, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= maximum, "unsigned integer type/range")
    return value


def d(value: Any) -> int:
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None, "decimal string")
    result = int(value)
    require(result <= 2**64 - 1, "decimal overflow")
    return result


def closed(value: Any, keys: str, *, ordered: bool = True) -> None:
    require(type(value) is dict, "object required")
    expected = keys.split()
    require(list(value) == expected if ordered else set(value) == set(expected), "closed record keys/order")


def boolean(value: Any) -> None:
    require(type(value) is bool, "boolean type")


class FiniteJson:
    """Bound bytes/tokens/depth before materializing objects; reject duplicates.

    Only an already bounded string token is passed to json.loads. Native DTOs
    require canonical declaration order and one LF. DATA has a larger key/map
    budget for all173 source names; final/prefix additionally require their
    producer's sorted compact encoding with no LF. Freeze DATA may be spaced.
    """
    def __init__(self, data: bytes, *, native: bool, large: bool = False):
        cap = (16384 if large else 4096) if native else 65536
        require(type(data) is bytes and 0 < len(data) <= cap and not data.startswith(b"\xef\xbb\xbf"), "JSON byte bound/BOM")
        self.text = data.decode("utf-8", errors="strict")
        self.at = self.tokens = 0
        self.native = native
        self.limit = (2048 if large else 768) if native else 16000
        self.depth = 12
        self.array = 128 if native else 512
        self.mapping = 128 if native else 256
        self.key_limit = 64 if native else 128
        self.integer_max = 2**32 - 1 if native else 2**64 - 1

    def space(self) -> None:
        if not self.native:
            while self.at < len(self.text) and self.text[self.at] in " \t\r\n":
                self.at += 1

    def token(self) -> None:
        self.tokens += 1
        require(self.tokens <= self.limit, "JSON token bound")

    def string(self, key: bool = False) -> str:
        self.token()
        start = self.at
        bound = self.key_limit if key else 512
        require(self.at < len(self.text) and self.text[self.at] == '"', "JSON string token")
        self.at += 1
        escaped = False
        while self.at < len(self.text):
            c = self.text[self.at]
            self.at += 1
            if c == '"' and not escaped:
                raw = self.text[start:self.at]
                require(len(raw.encode("utf-8")) <= bound * 6 + 2, "JSON escaped string bound")
                value = json.loads(raw)
                require(type(value) is str and len(value.encode("utf-8")) <= bound and "\x00" not in value
                        and (not key or value.isascii()), "JSON decoded string/key bound")
                return value
            require(ord(c) >= 32, "JSON control character")
            escaped = c == "\\" and not escaped
            require(self.at - start <= bound * 6 + 2, "JSON string scan bound")
        raise Refused("JSON unterminated string")

    def value(self, depth: int = 0) -> Any:
        self.space()
        require(depth <= self.depth and self.at < len(self.text), "JSON depth/end")
        c = self.text[self.at]
        if c == '"':
            return self.string()
        self.token()
        if c in "{[":
            self.at += 1
            self.space()
            result: Any = {} if c == "{" else []
            stop = "}" if c == "{" else "]"
            if self.at < len(self.text) and self.text[self.at] == stop:
                self.at += 1
                return result
            while True:
                require(len(result) < (self.mapping if c == "{" else self.array), "JSON collection bound")
                self.space()
                if c == "{":
                    key = self.string(key=True)
                    self.space()
                    require(key not in result and self.at < len(self.text) and self.text[self.at] == ":", "JSON duplicate/colon")
                    self.at += 1
                    result[key] = self.value(depth + 1)
                else:
                    result.append(self.value(depth + 1))
                self.space()
                require(self.at < len(self.text), "JSON collection end")
                delim = self.text[self.at]
                self.at += 1
                if delim == stop:
                    return result
                require(delim == ",", "JSON delimiter/whitespace")
        for word, result in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.at):
                self.at += len(word)
                return result
        start = self.at
        while self.at < len(self.text) and "0" <= self.text[self.at] <= "9":
            self.at += 1
            require(self.at - start <= 20, "JSON integer bound")
        token = self.text[start:self.at]
        require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None, "JSON integer/fraction/coercion")
        return u(int(token), self.integer_max)

    def parse(self, *, lf: bool) -> Any:
        value = self.value()
        self.space()
        require(self.text[self.at:] == ("\n" if lf else ""), "JSON trailing data/LF")
        return value


def id_schema(value: Any, *, directory: bool = False) -> None:
    closed(value, "device inode mode owner")
    d(value["device"])
    require(d(value["inode"]) != 0, "zero inode")
    u(value["mode"])
    u(value["owner"])
    if directory:
        require(value["mode"] == 0o40700 and value["owner"] != 0, "private nonroot directory")


def pid_schema(value: Any) -> None:
    closed(value, "pid startTicks")
    u(value["pid"], 4194304, 1)
    d(value["startTicks"])


def exe_schema(value: Any) -> None:
    closed(value, "file sha256")
    id_schema(value["file"])
    require(stat.S_ISREG(value["file"]["mode"]), "regular executable")
    h(value["sha256"])


def proc_schema(value: Any) -> None:
    closed(value, "identity executable")
    pid_schema(value["identity"])
    exe_schema(value["executable"])


def bus_name(value: Any) -> None:
    require(type(value) is str and len(value) <= 64 and re.fullmatch(r":[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", value) is not None, "D-Bus unique name")


def object_path(value: Any) -> None:
    require(type(value) is str and len(value) <= 256 and re.fullmatch(r"/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?", value) is not None, "D-Bus object path")


def ref_schema(value: Any) -> None:
    closed(value, "bus path")
    bus_name(value["bus"])
    object_path(value["path"])


def svc_schema(value: Any) -> None:
    closed(value, "owner process")
    bus_name(value["owner"])
    proc_schema(value["process"])


def pipe_schema(value: Any) -> None:
    closed(value, "device inode")
    d(value["device"])
    require(d(value["inode"]) > 0, "pipe inode")


def close_schema(value: Any) -> None:
    closed(value, "fd atNs result")
    u(value["fd"], 1048575)
    require(d(value["atNs"]) <= now() and value["result"] == "positive-consuming-close", "positive original close")


def stream_schema(value: Any) -> None:
    closed(value, "pipe bytes sha256 eof read close")
    pipe_schema(value["pipe"])
    u(value["bytes"], 16384)
    h(value["sha256"])
    require(value["eof"] is True and value["read"] == "original-complete", "original complete stream")
    close_schema(value["close"])


def action(kind: str) -> str:
    require(kind in ROSTER, "finite SG1 dialog kind")
    return {"picker-select": "select-project", "source-select": "select-source", "quit-ok": "ok"}.get(kind, "cancel")


def topology_ids(admission_sha: str, n: int) -> tuple[str, str]:
    """Run/stage correlation only, never native ownership or object search."""
    h(admission_sha)
    u(n, 5, 1)
    return f"mrk-sg1:{admission_sha}:main", f"mrk-sg1:{admission_sha}:d{n}"


def ownership_schema(value: Any, admission_sha: str, n: int, *, ordered: bool = True) -> None:
    closed(value, OWNERSHIP_KEYS, ordered=ordered)
    main_id, dialog_id = topology_ids(admission_sha, n)
    operation = u(value["operation"], 5, 1)
    tagged, checked = u(value["tagOrdinal"], 512, 1), u(value["checkOrdinal"], 512, 1)
    d(value["checkedNs"])
    require(value["method"] == "gtk-window-get-transient-for" and operation == n
            and value["mainId"] == main_id and value["dialogId"] == dialog_id
            and tagged < checked and value["transientForMain"] is True, "closed original GTK ownership witness")


def native_schema(v: Any) -> None:
    require(type(v) is dict and v.get("type") in TAIL_KEYS, "native record type")
    typ = v["type"]
    closed(v, COMMON_KEYS + " " + TAIL_KEYS[typ])
    require(type(v["v"]) is int and v["v"] == 1 and v["case"] == CASE and v["profile"] == PROFILE, "native SG1 common literals")
    h(v["binding"])
    closed(v["roots"], "run app native")
    for root in v["roots"].values():
        id_schema(root, directory=True)
    owner = v["roots"]["run"]["owner"]
    require(all(root["owner"] == owner for root in v["roots"].values()), "native root owners")
    id_schema(v["file"])
    require(v["file"]["mode"] == 0o100600 and v["file"]["owner"] == owner, "native file mode/owner")
    pid_schema(v["writer"])
    written = d(v["writtenNs"])
    require(written <= now(), "future native fact")
    if typ not in ("ready", "admission"):
        h(v["admissionSha256"])
    if typ == "ready":
        proc_schema(v["helper"])
        svc_schema(v["registry"])
        h(v["sessionBusId"], 32)
        h(v["a11yBusId"], 32)
        require(v["subscriptions"] == "direct-gtk-events-v1", "direct native subscriptions")
    elif typ == "admission":
        closed(v["build"], BUILD_KEYS)
        for value in v["build"].values():
            h(value)
        for key in ("readySha256", "sourceProfileSha256", "installedClosureSha256", "loaderClosureSha256", "writerAuditSha256"):
            h(v[key])
        for key in ("outer", "app", "helper"):
            proc_schema(v[key])
        spawn = d(v["appSpawnNs"])
        require(spawn <= written <= plus(spawn, 2 * NS) and d(v["outerEndNs"]) == plus(spawn, 90 * NS), "admission original clocks")
        x = v["display"]
        closed(x, "kind display server windowManager sessionBus a11yBus registry sandbox")
        require(x["kind"] == "x11" and x["sandbox"] == "intact-nonroot" and type(x["display"]) is str
                and re.fullmatch(r":[1-9][0-9]{0,3}", x["display"]) is not None, "fixed X11 display profile")
        for key in ("server", "windowManager"):
            proc_schema(x[key])
        svc_schema(x["registry"])
        for key in ("sessionBus", "a11yBus"):
            b = x[key]
            closed(b, "id process addressSha256")
            h(b["id"], 32)
            h(b["addressSha256"])
            proc_schema(b["process"])
        f = v["fixtures"]
        closed(f, "project source sourceSha256")
        id_schema(f["project"], directory=True)
        id_schema(f["source"])
        require(f["project"]["owner"] == f["source"]["owner"] == owner and f["source"]["mode"] == 0o100600
                and f["sourceSha256"] == sha(SYNTHETIC), "fixed synthetic fixture identities")
        closed(v["pipes"], "appStdout appStderr helperStdout helperStderr")
        closed(v["aliases"], "appStdoutWrite appStderrWrite helperStdoutWrite helperStderrWrite")
        for pipe in v["pipes"].values():
            pipe_schema(pipe)
        for receipt in v["aliases"].values():
            close_schema(receipt)
            require(d(receipt["atNs"]) <= written, "original alias closed before admission")
    elif typ == "presented":
        ref_schema(v["dialog"])
        ref_schema(v["button"])
        a = v["association"]
        closed(a, "route process application mainWindow parent mainId dialogId")
        require(a["route"] == "direct-gtk", "direct app GTK only")
        proc_schema(a["process"])
        for key in ("application", "mainWindow", "parent"):
            ref_schema(a[key])
        main_id, dialog_id = topology_ids(v["admissionSha256"], v["n"])
        require(a["mainId"] == main_id and a["dialogId"] == dialog_id, "original run/stage AccessibleId observations")
        require(a["parent"] == a["application"] and a["mainWindow"] != a["application"]
                and v["dialog"] not in (a["application"], a["mainWindow"], v["button"])
                and v["button"] not in (a["application"], a["mainWindow"])
                and all(ref["bus"] == a["application"]["bus"] for ref in (a["mainWindow"], a["parent"], v["dialog"], v["button"])),
                "same original direct-app accessible association")
        require(v["dialogRole"] in ("dialog", "file-chooser", "alert") and v["states"] == "showing-enabled-sensitive-modal-singleton"
                and v["buttonRole"] == "push-button" and v["buttonAction"] == "click" and d(v["observedNs"]) <= written,
                "positive modal presentation facts")
    elif typ == "go":
        h(v["presentedSha256"])
        u(v["operation"], 5, 1)
        shown, producer = u(v["showOrdinal"], 512, 1), u(v["producerOrdinal"], 512, 1)
        ownership = v["ownership"]
        ownership_schema(ownership, v["admissionSha256"], v["n"])
        checkpoint, end = d(v["checkpointNs"]), d(v["inputEndNs"])
        require(v["operation"] == v["n"] and ownership["tagOrdinal"] < shown < ownership["checkOrdinal"] < producer
                and d(ownership["checkedNs"]) <= checkpoint <= written < end
                and end == plus(checkpoint, 2 * NS), "GO original operation/ordinals/endpoint")
    elif typ == "input":
        h(v["presentedSha256"])
        h(v["goSha256"])
        require(d(v["startedNs"]) <= d(v["completedNs"]) <= written, "native input time order")
        expected = ["focus:true", "control-lock:normal", "keysym-l:normal", "control-unlock:normal", "set-location:true", "click:true"] if v["n"] in (2, 3) else ["click:true"]
        require(v["steps"] == expected, "finite native input primitives")
        completion = v["completion"]
        closed(completion, "route disappearance dialog")
        ref_schema(completion["dialog"])
        require(completion["route"] == "direct-gtk" and completion["disappearance"] in ("defunct", "removed-from-bound-root"), "same direct original disappearance route")
        closed(v["counts"], "events wireMessages queries nodes actions")
        for key, bound in (("events", 1024), ("wireMessages", 8192), ("queries", 4096), ("nodes", 512), ("actions", 15)):
            u(v["counts"][key], bound)
    elif typ == "helper-settled":
        h(v["lastInputSha256"])
        proc_schema(v["helper"])
        require(type(v["waitStatus"]) is int and v["waitStatus"] == 0 and d(v["waitNs"]) <= written, "helper original wait")
        for key in ("stdout", "stderr"):
            stream_schema(v[key])
            require(v[key]["bytes"] == 0 and v[key]["sha256"] == sha(b"") and d(v[key]["close"]["atNs"]) <= written, "both helper original streams empty/closed")
    if typ in ("presented", "go", "input"):
        n = u(v["n"], 5, 1)
        require(v["kind"] == ROSTER[n - 1], "fixed five-dialog SG1 roster")
        if typ != "presented":
            require(v["action"] == action(v["kind"]) and (v["selected"] is not None) == (n in (2, 3)), "fixed action/selection")
            if v["selected"] is not None:
                id_schema(v["selected"], directory=n == 2)
        if typ == "go":
            require(v["gate"] == ("preserved-close" if n == 1 else "presented"), "first original preserved-Close gate")


def native_bytes(value: dict[str, Any]) -> bytes:
    native_schema(value)
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    require(len(data) <= (16384 if value["type"] == "admission" else 4096), "native encoded bound")
    return data


def native_parse(data: bytes, typ: str) -> dict[str, Any]:
    value = FiniteJson(data, native=True, large=typ == "admission").parse(lf=True)
    native_schema(value)
    require(value["type"] == typ and native_bytes(value) == data, "native canonical original bytes")
    return value


def identity(st: os.stat_result) -> dict[str, Any]:
    return {"device": str(st.st_dev), "inode": str(st.st_ino), "mode": st.st_mode, "owner": st.st_uid}


def pipe_identity(st: os.stat_result) -> dict[str, str]:
    require(stat.S_ISFIFO(st.st_mode), "original FIFO required")
    return {"device": str(st.st_dev), "inode": str(st.st_ino)}


def stable(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino, a.st_mode, a.st_uid, a.st_nlink, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (
        b.st_dev, b.st_ino, b.st_mode, b.st_uid, b.st_nlink, b.st_size, b.st_mtime_ns, b.st_ctime_ns)


def exact_path(path: Path, *, immutable: bool = False) -> Path:
    require(path.is_absolute() and ".." not in path.parts and path.resolve(strict=True) == path, "exact path/no symlink components")
    if immutable:
        for component in (path, *path.parents):
            st = os.lstat(component)
            require(st.st_uid == 0 and not st.st_mode & 0o022, "root-owned immutable profile/closure")
    return path


@dataclass
class Descriptor:
    """Original number retained for evidence, but never reused after consumption."""
    original: int
    label: str
    live: int | None
    attempted: bool = False
    receipt: dict[str, Any] | None = None
    unknown: bool = False


class FileBook:
    def __init__(self) -> None:
        self.originals: list[Descriptor] = []
        self.unknown = False
        self.failure: str | None = None

    def fail(self, code: str) -> None:
        self.unknown = True
        if self.failure is None:
            self.failure = code

    def acquire(self, fd: int, label: str) -> Descriptor:
        # Inventory BEFORE checks/metadata/read/any user of the descriptor.
        owner = Descriptor(fd, label, fd)
        self.originals.append(owner)
        if not (3 <= fd <= 1048575 and len(self.originals) <= 4096):
            self.fail("original descriptor/acquisition bound")
            raise Refused("original descriptor/acquisition bound")
        return owner

    def close(self, owner: Descriptor) -> dict[str, Any]:
        require(owner.live is not None and not owner.attempted, "original consuming close once")
        fd = owner.live
        owner.live = None
        owner.attempted = True
        try:
            os.close(fd)  # audited CPython/libc; never retry EINTR or old number
        except OSError:
            owner.unknown = True
            self.fail("original consuming close unknown")
            raise Refused("original consuming close unknown") from None
        owner.receipt = {"fd": fd, "atNs": str(now()), "result": "positive-consuming-close"}
        return owner.receipt

    def pipe_pair(self, read_fd: int, write_fd: int, label: str) -> tuple[Descriptor, Descriptor]:
        # pipe2 returns two originals at once. Inventory BOTH before any failure
        # can unwind; do not strand the second behind a first-fd validation.
        reader = Descriptor(read_fd, label + ":read", read_fd)
        writer = Descriptor(write_fd, label + ":write-alias", write_fd)
        self.originals.extend((reader, writer))
        if not (3 <= read_fd <= 1048575 and 3 <= write_fd <= 1048575 and read_fd != write_fd and len(self.originals) <= 4096):
            self.fail("original pipe descriptor/acquisition bound")
            raise Refused("original pipe descriptor/acquisition bound")
        return reader, writer

    def read(self, path: Path, limit: int, *, private: bool = False, proc: bool = False) -> tuple[bytes, os.stat_result]:
        named = os.lstat(path)
        require(not self.unknown and stat.S_ISREG(named.st_mode) and (proc or (named.st_nlink == 1 and 0 <= named.st_size <= limit)), "named original file shape")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        owner = self.acquire(fd, "read:" + str(path))
        try:
            before = os.fstat(fd)
            require(stable(before, named), "opened/named identity")
            if private:
                require(before.st_mode == 0o100600 and before.st_uid == os.getuid(), "private file mode/owner")
            data = bytearray()
            while True:
                require(len(data) <= limit, "file read limit")
                part = os.read(fd, min(16384, limit + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            after, final = os.fstat(fd), os.lstat(path)
            require(stable(before, after) and stable(before, final) and len(data) <= limit and (proc or len(data) == before.st_size), "original complete stable read")
            return bytes(data), before
        except (OSError, Refused):
            self.fail("original file read unknown")
            raise
        finally:
            self.close(owner)

    def hash_file(self, path: Path, limit: int = 256 * 1024 * 1024, *, kernel_exe: bool = False) -> tuple[str, os.stat_result]:
        named = os.stat(path) if kernel_exe else os.lstat(path)
        require(not self.unknown and stat.S_ISREG(named.st_mode) and 0 <= named.st_size <= limit and named.st_nlink >= 1, "bounded regular artifact")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | (0 if kernel_exe else os.O_NOFOLLOW))
        owner = self.acquire(fd, "hash:" + str(path))
        try:
            before = os.fstat(fd)
            require(stable(before, named), "artifact opened identity")
            checksum, count = hashlib.sha256(), 0
            while True:
                part = os.read(fd, 16384)
                if not part:
                    break
                count += len(part)
                require(count <= limit, "artifact size limit")
                checksum.update(part)
            final = os.stat(path) if kernel_exe else os.lstat(path)
            require(count == before.st_size and stable(before, os.fstat(fd)) and stable(before, final), "artifact original complete read")
            return checksum.hexdigest(), before
        except (OSError, Refused):
            self.fail("artifact original unknown")
            raise
        finally:
            self.close(owner)

    def write_new(self, path: Path, data: bytes) -> os.stat_result:
        require(not self.unknown and len(data) <= 65536, "fixed ancillary file bound")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        owner = self.acquire(fd, "write:" + str(path))
        try:
            before = os.fstat(fd)
            require(before.st_mode == 0o100600 and before.st_nlink == 1 and before.st_size == 0 and before.st_uid == os.getuid(), "new original private file")
            count = os.write(fd, data)
            after = os.fstat(fd)
            require(count == len(data) and after.st_size == count and identity(before) == identity(after) and after.st_nlink == 1, "one full original write")
        except (OSError, Refused):
            self.fail("original write unknown")
            raise
        finally:
            self.close(owner)
        final = os.lstat(path)
        require(stable(after, final), "closed original file publication")
        return final

    def directory_entries(self, path: Path, libc: NativeLibC, maximum: int = 32) -> set[str]:
        # Raw public getdents64 over OUR retained original: no scandir iterator
        # finalizer or hidden DIR duplicate/closedir return is treated as proof.
        named = os.lstat(path)
        require(not self.unknown and stat.S_ISDIR(named.st_mode), "directory expected")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_NONBLOCK)
        owner = self.acquire(fd, "directory:" + str(path))
        names: set[str] = set()
        try:
            require(identity(os.fstat(fd)) == identity(named), "original directory identity")
            buf = ctypes.create_string_buffer(8192)
            while True:
                count = libc.getdents64(fd, buf, len(buf))
                require(0 <= count <= len(buf), "original directory read")
                if count == 0:
                    break
                data = buf.raw[:count]
                at = 0
                while at < count:
                    require(at + 20 <= count, "dirent prefix")
                    inode, _offset, length, _kind = struct.unpack_from("=QqHB", data, at)
                    require(inode != 0 and 20 <= length <= count - at and length % 8 == 0, "dirent structure")
                    raw = data[at + 19:at + length]
                    require(b"\0" in raw, "dirent name terminator")
                    name = raw.split(b"\0", 1)[0].decode("utf-8", errors="strict")
                    require(name not in names and len(names) < maximum + 2, "directory duplicate/entry bound")
                    if name in (".", ".."):
                        require(_kind == 4 and (name != "." or inode == named.st_ino), "original directory dot identities/types")
                    names.add(name)
                    at += length
            require({".", ".."} <= names and identity(os.fstat(fd)) == identity(named) and identity(os.lstat(path)) == identity(named), "original directory stable EOF")
            return names - {".", ".."}
        except (OSError, Refused):
            self.fail("directory original unknown")
            raise
        finally:
            self.close(owner)

    def synthetic(self, path: Path, libc: NativeLibC) -> os.stat_result:
        """Create/verify the12 synthetic bytes through the SAME original FD.

        No pathname read or reopen is permitted for this leaf. The actor/Q use
        only metadata; production SourceBook must prove its own real capture.
        """
        require(not self.unknown, "no fixture acquisition after Unknown")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        owner = self.acquire(fd, "synthetic-creation-original")
        try:
            before = os.fstat(fd)
            require(before.st_mode == 0o100600 and before.st_uid == os.getuid() and before.st_nlink == 1 and before.st_size == 0, "fresh synthetic creation inode")
            libc.ext_filesystem(fd)
            require(os.write(fd, SYNTHETIC) == len(SYNTHETIC), "one complete synthetic write")
            require(os.lseek(fd, 0, os.SEEK_SET) == 0, "same synthetic original read position")
            data = bytearray()
            reads = 0
            while True:
                require(reads < 13 and len(data) <= 12, "same synthetic size-plus-one read bound")
                part = os.read(fd, 13 - len(data))
                reads += 1
                if not part:
                    break
                data.extend(part)
            after = os.fstat(fd)
            require(2 <= reads <= 13 and bytes(data) == SYNTHETIC and after.st_size == 12 and after.st_nlink == 1
                    and identity(before) == identity(after) and stable(after, os.lstat(path)), "original synthetic bytes/EOF/identity")
        except (OSError, Refused):
            self.fail("synthetic creation original unknown")
            raise
        finally:
            self.close(owner)
        require(stable(after, os.lstat(path)), "closed original synthetic name changed")
        return after

    def ancestry(self, path: Path, libc: NativeLibC, *, source: os.stat_result | None = None) -> tuple[Ancestor, ...]:
        """Admission-only originals, including /; NOT SourceBook evidence.

        All DIRECTORY originals use fstatfs and a positive consuming close. The
        optional leaf must be the retained creation inode, and is never opened.
        An ext4 scratch mount below an overlay / therefore cannot be admitted.
        """
        require(not self.unknown and exact_path(path) == path and 1 <= len(path.parts) - 1 <= 12, "bounded exact full ancestry")
        result: list[Ancestor] = []
        current = Path("/")
        for index in range(len(path.parts)):
            if index:
                current = current / path.parts[index]
            named = os.lstat(current)
            leaf = source is not None and index + 1 == len(path.parts)
            if leaf:
                require(stable(named, source) and named.st_mode == 0o100600 and named.st_uid == os.getuid()
                        and named.st_nlink == 1 and named.st_size == 12, "synthetic original metadata only")
            else:
                require(stat.S_ISDIR(named.st_mode), "ancestor must be a directory")
                fd = os.open(current, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_NONBLOCK)
                owner = self.acquire(fd, "ancestry:" + str(current))
                try:
                    require(identity(os.fstat(fd)) == identity(named), "original ancestor opened identity")
                    libc.ext_filesystem(fd)
                    require(identity(os.fstat(fd)) == identity(named) and identity(os.lstat(current)) == identity(named), "original ancestor terminal identity")
                except (OSError, Refused):
                    self.fail("original ancestry unknown")
                    raise
                finally:
                    self.close(owner)
            require(identity(os.lstat(current)) == identity(named), "closed original ancestor changed")
            result.append(Ancestor(current, named))
        return tuple(result)


@dataclass(frozen=True)
class Ancestor:
    path: Path
    metadata: os.stat_result

    @property
    def identity(self) -> dict[str, Any]:
        return identity(self.metadata)


class StatFs(ctypes.Structure):
    # Exact Linux x86_64 GNU public struct statfs, audited before this route may
    # run. No libc guessing, dlopen search or opaque oversize buffer substitution.
    _fields_ = [("f_type", ctypes.c_long), ("f_bsize", ctypes.c_long),
                ("f_blocks", ctypes.c_ulong), ("f_bfree", ctypes.c_ulong), ("f_bavail", ctypes.c_ulong),
                ("f_files", ctypes.c_ulong), ("f_ffree", ctypes.c_ulong), ("f_fsid", ctypes.c_int * 2),
                ("f_namelen", ctypes.c_long), ("f_frsize", ctypes.c_long), ("f_flags", ctypes.c_long),
                ("f_spare", ctypes.c_long * 4)]


class NativeLibC:
    """Three fixed public APIs; the exact library/ABI need independent pins."""
    def __init__(self, path: Path):
        require(ctypes.sizeof(StatFs) == 120 and ctypes.alignment(StatFs) == 8, "unadmitted fstatfs ABI")
        self.library = ctypes.CDLL(str(path), use_errno=True)
        self.renameat2 = self.library.renameat2
        self.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        self.renameat2.restype = ctypes.c_int
        self.getdents64 = self.library.getdents64
        self.getdents64.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        self.getdents64.restype = ctypes.c_ssize_t
        self.fstatfs = self.library.fstatfs
        self.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(StatFs)]
        self.fstatfs.restype = ctypes.c_int

    def ext_filesystem(self, fd: int) -> None:
        facts = StatFs()
        require(self.fstatfs(fd, ctypes.byref(facts)) == 0 and facts.f_type == 0xEF53, "whole original ancestry must be ext-family, including /")

    def publish(self, pending: Path, final: Path) -> None:
        # AT_FDCWD / RENAME_NOREPLACE public Linux ABI; no retry or replacement.
        require(self.renameat2(-100, os.fsencode(pending), -100, os.fsencode(final), 1) == 0, "original atomic no-replace publication")


def process(book: FileBook, pid: int) -> dict[str, Any]:
    u(pid, 4194304, 1)
    path = Path("/proc") / str(pid)

    def sample() -> tuple[str, int]:
        data, _ = book.read(path / "stat", 4096, proc=True)
        end = data.rfind(b")")
        require(end > 1 and data.startswith(str(pid).encode("ascii") + b" ("), "original proc stat PID")
        parts = data[end + 1:].split()
        require(len(parts) >= 20, "original proc stat fields")
        start = parts[19].decode("ascii")
        d(start)
        parent = parts[1].decode("ascii")
        return start, u(d(parent), 4194304)

    start, parent = sample()
    target = os.readlink(path / "exe")
    require(len(os.fsencode(target)) <= 512 and target.startswith("/") and not target.endswith(" (deleted)"), "original proc executable link")
    digest, st = book.hash_file(path / "exe", kernel_exe=True)
    require((start, parent) == sample(), "original PID/start/executable changed")
    return {"identity": {"pid": pid, "startTicks": start}, "executable": {"file": identity(st), "sha256": digest}}


@dataclass
class Stream:
    book: FileBook
    reader: Descriptor
    writer: Descriptor
    pipe: dict[str, str]
    limit: int
    retain_limit: int
    data: bytearray = field(default_factory=bytearray)
    checksum: Any = field(default_factory=hashlib.sha256)
    count: int = 0
    eof: bool = False
    read_failed: bool = False

    @classmethod
    def create(cls, book: FileBook, label: str, limit: int, retention: int | None = None) -> Stream:
        require(len(ORIGINAL_STREAMS) < 14, "one SG1 original stream bound")
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        reader, writer = book.pipe_pair(read_fd, write_fd, label)
        # Retain the actual reader/writer BEFORE metadata or any subsequent
        # pipe/spawn can fail. An uncertain posix_spawn has no safe guessed PID,
        # but it never authorizes losing these original drainage owners.
        stream = cls(book, reader, writer, {}, limit, limit if retention is None else retention)
        ORIGINAL_STREAMS.append(stream)
        r, w = os.fstat(read_fd), os.fstat(write_fd)
        require(pipe_identity(r) == pipe_identity(w), "original pipe endpoints")
        stream.pipe = pipe_identity(r)
        return stream

    def drain(self) -> None:
        if self.eof or self.read_failed or self.reader.live is None:
            return
        try:
            # One bounded read per readiness turn. Overflow never replaces the
            # original reader; continue drainage with bounded retained storage.
            part = os.read(self.reader.live, 8192)
        except BlockingIOError:
            return
        except OSError:
            self.read_failed = True
            self.book.fail("original stream read unknown")
            return
        if not part:
            self.eof = True
            try:
                self.book.close(self.reader)
            except Refused:
                pass
            return
        self.count = min(self.limit + 1, self.count + len(part))
        self.checksum.update(part)
        self.data.extend(part[:max(0, self.retain_limit - len(self.data))])
        if self.count > self.limit:
            self.book.fail("original stream overflow")

    def complete(self) -> bool:
        return self.eof and not self.read_failed and self.reader.receipt is not None and self.writer.receipt is not None

    def facts(self) -> dict[str, Any]:
        require(self.complete() and self.count <= self.limit and self.limit <= 16384, "original helper stream unsettled")
        return {"pipe": self.pipe, "bytes": self.count, "sha256": self.checksum.hexdigest(), "eof": True,
                "read": "original-complete", "close": self.reader.receipt}


@dataclass
class Child:
    book: FileBook
    role: str
    pid: int
    spawn_ns: int
    stdout: Stream
    stderr: Stream
    proc: dict[str, Any] | None = None
    status: int | None = None
    wait_ns: int | None = None
    wait_unknown: bool = False
    term_requested: bool = False

    def observe_wait(self) -> None:
        if self.status is not None or self.wait_unknown:
            return
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)  # same original, never wait(-1)
            if pid == 0:
                return
            require(pid == self.pid, "original wait PID")
        except (OSError, Refused):
            self.wait_unknown = True
            self.book.fail("original wait unknown")
            return
        self.status, self.wait_ns = status, now()
        if status != 0:
            self.book.fail("original nonzero/signal wait")

    def complete(self) -> bool:
        return self.status == 0 and not self.wait_unknown and self.stdout.complete() and self.stderr.complete()


def spawn(book: FileBook, role: str, executable: Path, argv: tuple[str, ...], environment: dict[str, str], *, spawn_ns: int | None = None) -> Child:
    require(role in {"display", "wm", "session", "a11y", "registry", "helper", "app"}, "fixed spawn role")
    require(len(ORIGINAL_CHILDREN) < 7 and all(child.role != role for child in ORIGINAL_CHILDREN) and not book.unknown, "seven unique SG1 children/no spawn after Unknown")
    require(argv and argv[0] == str(executable), "fixed direct executable argv")
    stdout = Stream.create(book, role + ":stdout", 18 if role == "app" else 0 if role == "helper" else 65536,
                           19 if role == "app" else 1 if role == "helper" else 65536)
    stderr = Stream.create(book, role + ":stderr", 0 if role == "helper" else 65536, 1 if role == "helper" else 65536)
    null_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    null = book.acquire(null_fd, role + ":stdin-original")
    require(stat.S_ISCHR(os.fstat(null_fd).st_mode), "fixed stdin null device")
    actions = [(os.POSIX_SPAWN_DUP2, null_fd, 0), (os.POSIX_SPAWN_DUP2, stdout.writer.original, 1),
               (os.POSIX_SPAWN_DUP2, stderr.writer.original, 2)]
    # Every launcher-owned alias (including all prior original readers) is
    # explicitly excluded. Remaining host FDs require the independent immutable
    # runtime/writer graph; CLOEXEC is necessary, NOT that graph's proof.
    for owner in book.originals:
        if owner.live is not None:
            actions.append((os.POSIX_SPAWN_CLOSE, owner.live))
    started = now() if spawn_ns is None else spawn_ns
    require(started <= now(), "original spawn checkpoint")
    try:
        pid = os.posix_spawn(str(executable), argv, environment, file_actions=actions, setsigmask=())
    except OSError:
        book.fail("original spawn uncertain")
        raise Refused("original spawn uncertain") from None
    child = Child(book, role, pid, started, stdout, stderr)  # retain original return BEFORE /proc/read/close
    # The original Child must remain retained if ANY later observation fails.
    ORIGINAL_CHILDREN.append(child)
    book.close(stdout.writer)
    book.close(stderr.writer)
    book.close(null)
    child.proc = process(book, pid)
    return child


ORIGINAL_CHILDREN: list[Child] = []
ORIGINAL_STREAMS: list[Stream] = []


def progress(children: list[Child], timeout_ms: int = 5) -> None:
    start = now()
    poller = select.poll()
    streams: dict[int, Stream] = {}
    for stream in ORIGINAL_STREAMS:
        if stream.reader.live is not None and not stream.read_failed:
            streams[stream.reader.live] = stream
            poller.register(stream.reader.live, select.POLLIN | select.POLLHUP | select.POLLERR)
    try:
        events = poller.poll(max(5, min(timeout_ms, 50)))
    except OSError:
        for stream in ORIGINAL_STREAMS:
            stream.book.fail("original drain polling failed")
        time.sleep(0.005)
        return
    for fd, event in events:
        stream = streams[fd]
        if event & select.POLLNVAL:
            stream.read_failed = True
            stream.book.fail("original reader became invalid")
        else:
            stream.drain()
    for child in children:
        child.observe_wait()
    # Readiness can return immediately. It must not create a tight metadata or
    # waitpid loop, including on the permanently nonaccepting failure path.
    remainder = plus(start, 5_000_000) - now()
    if remainder > 0:
        time.sleep(remainder / NS)


def poll_spacing(end: int, attempts_left: int, children: list[Child]) -> None:
    """Spend the ORIGINAL endpoint, not an accidental 400*5ms startup limit."""
    require(attempts_left > 0 and now() < end, "metadata polling endpoint/count")
    delay = max(5_000_000, (end - now() + attempts_left - 1) // attempts_left)
    target = min(end, plus(now(), min(delay, 250_000_000)))
    while now() < target:
        progress(children, max(5, min(50, (target - now()) // 1_000_000)))


# Constructors register themselves before connection/auth/call work. A partially
# sent request or partially read reply survives failure along with its original
# descriptor, not merely an integer in the FileBook.
ORIGINAL_SOCKETS: list[Any] = []
ORIGINAL_PROTOCOLS: list[Any] = []


class LocalSocket:
    """One original nonblocking AF_UNIX connection; no reconnect/implicit close."""
    def __init__(self, book: FileBook, path: str, expected: Child, end: int):
        require(not book.unknown and len(ORIGINAL_SOCKETS) < 3 and len(os.fsencode(path)) <= 107, "fixed local connection budget/address")
        self.book = book
        self.owner: Descriptor | None = None
        self.transmit: bytes | None = None
        self.transmitted = 0
        self.transmit_end: int | None = None
        self.receiving: bytearray | None = None
        self.receive_length: int | None = None
        self.receive_end: int | None = None
        ORIGINAL_SOCKETS.append(self)
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        original = raw.fileno()
        try:
            self.owner = book.acquire(original, "control-socket:" + expected.role)
            result = raw.connect_ex(path)
            require(result in (0, errno.EINPROGRESS, errno.EAGAIN, errno.EALREADY), "original local connect")
            if result:
                self.ready(select.POLLOUT, end)
                require(raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, "original local connect completion")
            pid, uid, _gid = struct.unpack("=3i", raw.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid == expected.pid and uid == os.getuid(), "original spawned local service credentials")
        finally:
            # The wrapper never supplies positive close evidence, even if auth
            # or metadata fails. The original remains in our retained book.
            require(raw.detach() == original, "socket original detach")

    def ready(self, event: int, end: int) -> None:
        require(self.owner is not None and self.owner.live is not None and now() < end, "original socket endpoint")
        poller = select.poll()
        poller.register(self.owner.live, event | select.POLLHUP | select.POLLERR)
        while now() < end:
            remaining = (end - now()) // 1_000_000
            require(remaining >= 1, "socket endpoint rounding")
            result = poller.poll(min(remaining, 250))
            if not result:
                continue  # same pending request, no new call or renewed endpoint
            require(len(result) == 1 and result[0][0] == self.owner.live
                    and not result[0][1] & (select.POLLERR | select.POLLNVAL), "original socket readiness")
            return
        raise Refused("original socket endpoint expired")

    def send(self, data: bytes, end: int) -> None:
        require(type(data) is bytes and len(data) <= 16384 and self.owner is not None and self.owner.live is not None
                and self.transmit is None and not self.book.unknown, "one bounded socket output original")
        self.transmit, self.transmitted, self.transmit_end = data, 0, end
        while self.transmitted < len(data):
            self.ready(select.POLLOUT, end)
            count = os.write(self.owner.live, data[self.transmitted:])
            require(count > 0, "original socket write progress")
            self.transmitted += count  # continue only THIS original frame
        require(now() <= end, "original socket write endpoint")
        self.transmit = None

    def receive(self, length: int, end: int) -> bytes:
        require(0 <= length <= 16384 and self.owner is not None and self.owner.live is not None
                and self.receiving is None and not self.book.unknown, "one bounded socket input original")
        self.receiving, self.receive_length, self.receive_end = bytearray(), length, end
        while len(self.receiving) < length:
            self.ready(select.POLLIN, end)
            part = os.read(self.owner.live, length - len(self.receiving))
            require(bool(part), "original socket premature EOF")
            self.receiving.extend(part)
        require(now() <= end, "original socket read endpoint")
        data = bytes(self.receiving)
        self.receiving = None
        return data

    def close(self) -> None:
        require(self.owner is not None and self.transmit is None and self.receiving is None, "original connection frame unsettled")
        self.book.close(self.owner)


class DriverBus:
    """Finite authenticated PUBLIC D-Bus driver calls; no service activation.

    Only Hello/GetId and the original registry's owner/PID are queried. The
    direct actor owns its separate session/a11y connections. No monitoring,
    Unix-FD negotiation, desktop/PID scan or foreign dialog service exists here.
    """
    DRIVER = "org.freedesktop.DBus"
    PATH = "/org/freedesktop/DBus"

    def __init__(self, book: FileBook, address: str, child: Child, end: int):
        require(not book.unknown and len(ORIGINAL_PROTOCOLS) < 3 and address.startswith("unix:path=")
                and ";" not in address and "," not in address, "fixed private bus connection")
        self.book, self.address = book, address
        self.serial = 0
        self.pending: tuple[int, int] | None = None
        self.queries = self.messages = 0
        ORIGINAL_PROTOCOLS.append(self)
        self.socket = LocalSocket(book, address.removeprefix("unix:path="), child, end)
        uid = str(os.getuid()).encode("ascii").hex().encode("ascii")
        self.socket.send(b"\0AUTH EXTERNAL " + uid + b"\r\n", end)
        self.authentication = bytearray()
        while not self.authentication.endswith(b"\r\n"):
            require(len(self.authentication) < 128, "bus auth bound")
            self.authentication.extend(self.socket.receive(1, end))
        require(self.authentication.startswith(b"OK ") and len(self.authentication) == 37, "original bus EXTERNAL authentication")
        self.auth_id = bytes(self.authentication[3:-2]).decode("ascii")
        h(self.auth_id, 32)
        self.socket.send(b"BEGIN\r\n", end)  # no Unix-FD negotiation
        self.unique = self.call("Hello", None, end)
        bus_name(self.unique)
        self.id = self.call("GetId", None, end)
        h(self.id, 32)
        # AUTH identifies this server endpoint; GetId identifies the bus.
        # Retain both on this original authenticated socket, without equating
        # independently generated identities (or requiring inequality).

    @staticmethod
    def append(buf: bytearray, typ: str, value: Any) -> None:
        align = 1 if typ == "g" else 4
        buf.extend(b"\0" * (-len(buf) % align))
        if typ in ("s", "o"):
            raw = value.encode("utf-8")
            require(len(raw) <= 512 and b"\0" not in raw, "bounded D-Bus string")
            buf.extend(struct.pack("<I", len(raw)) + raw + b"\0")
        elif typ == "g":
            raw = value.encode("ascii")
            require(len(raw) <= 255, "signature bound")
            buf.extend(bytes((len(raw),)) + raw + b"\0")
        else:
            require(typ == "u", "closed driver type")
            buf.extend(struct.pack("<I", u(value)))

    @staticmethod
    def take(data: bytes, at: int, typ: str, endian: str) -> tuple[Any, int]:
        align = 1 if typ == "g" else 4
        aligned = (at + align - 1) & -align
        require(aligned <= len(data) and not any(data[at:aligned]), "D-Bus alignment padding")
        at = aligned
        if typ in ("s", "o", "g"):
            width = 1 if typ == "g" else 4
            require(at + width <= len(data), "D-Bus string prefix")
            length = data[at] if width == 1 else struct.unpack_from(endian + "I", data, at)[0]
            at += width
            require(length <= 512 and at + length < len(data) and data[at + length] == 0, "D-Bus bounded string")
            raw = data[at:at + length]
            require(b"\0" not in raw, "D-Bus string NUL")
            return raw.decode("utf-8", errors="strict"), at + length + 1
        require(typ == "u" and at + 4 <= len(data), "closed driver uint32")
        return struct.unpack_from(endian + "I", data, at)[0], at + 4

    def incoming(self, end: int) -> tuple[int, dict[int, Any], bytes, str]:
        header = self.socket.receive(16, end)
        order, typ, flags, version = header[:4]
        require(order in (ord("l"), ord("B")) and typ in (2, 3, 4) and flags & ~7 == 0 and version == 1, "driver wire header")
        endian = "<" if order == ord("l") else ">"
        body_len, serial, fields_len = struct.unpack_from(endian + "III", header, 4)
        padded = (fields_len + 7) & -8
        require(serial != 0 and 16 + padded + body_len <= 16384, "driver incoming 16KiB ceiling")
        raw = self.socket.receive(padded + body_len, end)
        require(not any(raw[fields_len:padded]), "driver body alignment")
        fields: dict[int, Any] = {}
        at = 0
        while at < fields_len:
            aligned = (at + 7) & -8
            require(not any(raw[at:aligned]) and aligned < fields_len and len(fields) < 16, "driver header dictionary bound")
            code = raw[aligned]
            signature, at = self.take(raw[:fields_len], aligned + 1, "g", endian)
            expected = {1: "o", 2: "s", 3: "s", 4: "s", 5: "u", 6: "s", 7: "s", 8: "g", 9: "u"}
            require(code in expected and code not in fields and signature == expected[code], "closed driver header field")
            fields[code], at = self.take(raw[:fields_len], at, signature, endian)
        require(at == fields_len and fields.get(9, 0) == 0, "no incoming Unix FDs")
        self.messages += 1
        require(self.messages <= 8192, "outer driver message budget")
        return typ, fields, raw[padded:], endian

    def call(self, member: str, name: str | None, end: int, *, may_absent: bool = False) -> Any:
        require(member in ("Hello", "GetId", "GetNameOwner", "GetConnectionUnixProcessID") and self.pending is None and not self.book.unknown, "one original public driver call")
        self.queries += 1
        require(self.queries <= 128, "outer fixed original driver query budget")
        start = now()
        milliseconds = min(250, (end - start) // 1_000_000)
        require(milliseconds >= 1, "public call rounded endpoint")
        call_end = plus(start, milliseconds * 1_000_000)
        self.serial += 1
        fields = bytearray()
        for code, typ, value in ((1, "o", self.PATH), (2, "s", self.DRIVER), (3, "s", member), (6, "s", self.DRIVER)):
            fields.extend(b"\0" * (-len(fields) % 8))
            fields.append(code)
            self.append(fields, "g", typ)
            self.append(fields, typ, value)
        body = bytearray()
        if name is not None:
            require(member in ("GetNameOwner", "GetConnectionUnixProcessID"), "driver argument roster")
            fields.extend(b"\0" * (-len(fields) % 8))
            fields.append(8)
            self.append(fields, "g", "g")
            self.append(fields, "g", "s")
            self.append(body, "s", name)
        frame = b"l\x01\x00\x01" + struct.pack("<III", len(body), self.serial, len(fields)) + fields + b"\0" * (-len(fields) % 8) + body
        self.pending = (self.serial, call_end)  # retained BEFORE first original write
        self.socket.send(bytes(frame), call_end)
        while True:
            typ, header, reply, endian = self.incoming(call_end)
            require(header.get(7) == self.DRIVER, "original driver reply sender")
            if typ == 4:
                require(header.get(1) == self.PATH and header.get(2) == self.DRIVER and header.get(3) == "NameAcquired" and header.get(8) == "s" and 4 not in header and 5 not in header, "only connection-local driver signal")
                value, at = self.take(reply, 0, "s", endian)
                bus_name(value)
                require(at == len(reply) and header.get(6) == value and (not hasattr(self, "unique") or value == self.unique), "driver signal shape/original connection")
                continue
            require(header.get(5) == self.serial, "original driver reply serial")
            require(header.get(6) is not None and (not hasattr(self, "unique") or header[6] == self.unique), "original driver reply destination")
            if typ == 3:
                error = header.get(4)
                require(may_absent and member == "GetNameOwner" and error == "org.freedesktop.DBus.Error.NameHasNoOwner" and header.get(8) == "s", "driver method error")
                explanation, at = self.take(reply, 0, "s", endian)
                require(type(explanation) is str and bool(explanation) and at == len(reply) and now() <= call_end, "original complete negative driver reply")
                self.pending = None  # fully validated normal negative readiness, not uncertainty
                return None
            signature = "u" if member == "GetConnectionUnixProcessID" else "s"
            require(header.get(8) == signature and 4 not in header, "driver normal reply signature")
            value, at = self.take(reply, 0, signature, endian)
            require(at == len(reply) and now() <= call_end, "original driver complete reply")
            self.pending = None
            return value
        # On timeout/error pending remains owned, never cancel or replace it.

    def service(self, role: str, child: Child, end: int) -> dict[str, Any]:
        names = {"registry": "org.a11y.atspi.Registry"}
        require(role in names, "closed service roster")
        owner = None
        for _ in range(32):
            require(now() < end, "original service startup endpoint")
            owner = self.call("GetNameOwner", names[role], end, may_absent=True)
            if owner is not None:
                break  # each earlier normal NameHasNoOwner was a complete call
            progress(ORIGINAL_CHILDREN, 5)
        bus_name(owner)
        pid = self.call("GetConnectionUnixProcessID", owner, end)
        require(pid == child.pid and child.proc == process(self.book, pid) and child.status is None, "original spawned service credentials")
        return {"owner": owner, "process": child.proc}

    def close(self) -> None:
        require(self.pending is None, "original control call unsettled")
        self.socket.close()


class X11Control:
    """Authenticated original Xvfb plus actual supporting-WM/PID readiness.

    Fixed public X11 setup/InternAtom/GetProperty wire only. No Xlib loader,
    xprop process, root-window scan, Xauthority fallback or reconnection. Normal
    absent atoms/properties permit another bounded readiness observation only
    after the prior reply settled. Error/timeout retains the original pending
    query forever on the nonaccepting path. Exact WM/EWMH behavior needs its pin.
    """
    def __init__(self, book: FileBook, path: Path, display: Child, cookie: bytes, end: int):
        require(not book.unknown and len(ORIGINAL_PROTOCOLS) < 3 and len(cookie) == 16, "original X11 setup admission")
        self.book = book
        self.serial = self.queries = 0
        self.pending: tuple[str, int, int] | None = ("setup", 0, end)
        self.supporting: int | None = None
        self.wm_process: dict[str, Any] | None = None
        self.settled = False
        ORIGINAL_PROTOCOLS.append(self)
        self.socket = LocalSocket(book, str(path), display, end)
        name = b"MIT-MAGIC-COOKIE-1"
        request = b"l\0" + struct.pack("<HHHHH", 11, 0, len(name), len(cookie), 0)
        request += name + b"\0" * (-len(name) % 4) + cookie + b"\0" * (-len(cookie) % 4)
        self.socket.send(request, end)
        self.setup_header = self.socket.receive(8, end)
        result, unused, major, minor, words = struct.unpack("<BBHHH", self.setup_header)
        require(result == 1 and unused == 0 and major == 11 and minor == 0 and 32 <= words * 4 <= 16384, "authenticated original X11 setup success")
        self.setup_body = self.socket.receive(words * 4, end)
        body = self.setup_body
        vendor, maximum_request = struct.unpack_from("<HH", body, 16)
        require(body[20] == 1 and body[21] <= 32 and vendor <= 4096 and maximum_request >= 6, "one bounded original X11 screen")
        at = 32 + ((vendor + 3) & -4) + body[21] * 8
        require(at + 40 <= len(body), "X11 original screen structure")
        self.root = struct.unpack_from("<I", body, at)[0]
        depths = body[at + 39]
        require(self.root != 0 and 1 <= depths <= 32, "X11 actual root/depths")
        at += 40
        visuals = 0
        for _ in range(depths):
            require(at + 8 <= len(body), "X11 bounded depth prefix")
            count = struct.unpack_from("<H", body, at + 2)[0]
            visuals += count
            require(visuals <= 512 and at + 8 + count * 24 <= len(body), "X11 bounded visual roster")
            at += 8 + count * 24
        require(at == len(body) and now() <= end, "original complete X11 setup body")
        self.pending = None

    def query(self, kind: str, frame: bytes, end: int) -> tuple[bytes, bytes]:
        require(kind in ("atom", "property") and self.pending is None and not self.settled and not self.book.unknown, "one original X11 readiness query")
        self.queries += 1
        require(self.queries <= 256, "X11 readiness query bound")
        self.serial += 1
        call_end = min(end, plus(now(), 250_000_000))
        require(now() < call_end and self.serial <= 256, "X11 original call endpoint/serial")
        self.pending = (kind, self.serial, call_end)  # before original write
        self.socket.send(frame, call_end)
        self.reply_header = self.socket.receive(32, call_end)
        header = self.reply_header
        require(header[0] == 1 and struct.unpack_from("<H", header, 2)[0] == self.serial, "original X11 normal reply/serial")
        extra = struct.unpack_from("<I", header, 4)[0]
        require(extra <= 1 and (kind != "atom" or extra == 0), "X11 closed reply payload")
        self.reply_body = self.socket.receive(extra * 4, call_end)
        require(now() <= call_end, "original complete X11 reply endpoint")
        # Each caller validates its reply BEFORE settling pending below.
        return header, self.reply_body

    def atom(self, name: str, end: int) -> int:
        require(name in ("_NET_SUPPORTING_WM_CHECK", "_NET_WM_PID"), "fixed X11 atom roster")
        raw = name.encode("ascii")
        frame = struct.pack("<BBHHH", 16, 1, 2 + (len(raw) + 3) // 4, len(raw), 0) + raw + b"\0" * (-len(raw) % 4)
        header, body = self.query("atom", frame, end)
        require(header[1] == 0 and not body, "original InternAtom reply")
        atom = struct.unpack_from("<I", header, 8)[0]
        self.pending = None
        return atom  # zero is a settled normal only-if-exists absence

    def property(self, window: int, atom: int, typ: int, end: int) -> int | None:
        require(window != 0 and atom != 0 and typ in (6, 33), "fixed X11 property/window types")
        frame = struct.pack("<BBHIIIII", 20, 0, 6, window, atom, typ, 0, 1)
        header, body = self.query("property", frame, end)
        actual, after, count = struct.unpack_from("<III", header, 8)
        if actual == 0:
            require(header[1] == 0 and after == 0 and count == 0 and not body, "original absent X11 property")
            value = None
        else:
            require(header[1] == 32 and actual == typ and after == 0 and count == 1 and len(body) == 4, "original one-word X11 property")
            value = struct.unpack("<I", body)[0]
        self.pending = None
        return value

    def ready_wm(self, wm: Child, end: int) -> None:
        require(wm.role == "wm" and wm.proc is not None and not self.settled, "original WM readiness owner")
        supporting_atom = pid_atom = 0
        for _ in range(32):
            require(now() < end and not self.book.unknown and wm.status is None, "original WM readiness endpoint")
            if not supporting_atom:
                supporting_atom = self.atom("_NET_SUPPORTING_WM_CHECK", end)
            if not pid_atom:
                pid_atom = self.atom("_NET_WM_PID", end)
            if supporting_atom and pid_atom:
                window = self.property(self.root, supporting_atom, 33, end)
                if window is not None:
                    require(window != 0 and (self.supporting is None or self.supporting == window), "no supporting-WM replacement")
                    self.supporting = window
                    same = self.property(window, supporting_atom, 33, end)
                    pid = self.property(window, pid_atom, 6, end)
                    require(same is None or same == window, "supporting-WM self association")
                    require(pid is None or pid == wm.pid, "supporting-WM original process association")
                    if same == window and pid == wm.pid:
                        require(self.property(self.root, supporting_atom, 33, end) == window
                                and wm.proc == process(self.book, wm.pid) and wm.status is None, "stable authenticated original WM readiness")
                        self.wm_process = wm.proc
                        self.settled = True
                        return
            progress(ORIGINAL_CHILDREN, 5)
        raise Refused("original WM readiness observation bound")

    def close(self) -> None:
        require(self.pending is None and self.settled and self.supporting is not None and self.wm_process is not None, "original X11 readiness unsettled")
        self.socket.close()


@dataclass(frozen=True)
class Freeze:
    repository: Path
    app: Path
    helper: Path
    python: Path
    libc: Path
    display: str
    source_sha: str
    frontend_sha: str
    sources: dict[str, str]
    artifacts: dict[str, str]
    executables: dict[str, Path]
    loader_paths: frozenset[str]
    audits: tuple[str, str, str, str]
    members: tuple[tuple[Path, str, int], ...]
    original_data: bytes
    original_metadata: os.stat_result

    @classmethod
    def admit(cls, book: FileBook) -> Freeze:
        # First executable gate: no file/libc/socket/process acquisition has yet
        # occurred through this launcher. Python pre-main/imports are a distinct
        # audited route, never certified by this in-main check.
        require(API_INVENTORY is not None and AUDIT_PINS is not None and type(AUDIT_PINS) is tuple
                and len(AUDIT_PINS) == 4, "reviewed SG1 API/host/loader/writer pins unavailable")
        h(API_INVENTORY)
        for pin in AUDIT_PINS:
            h(pin)
        require(sys.platform == "linux" and os.uname().machine == "x86_64" and os.getuid() != 0
                and os.geteuid() == os.getuid(), "disposable Linux GNU nonroot host required")
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.dont_write_bytecode
                and sys.flags.optimize == 0 and sys.flags.inspect == 0 and sys.flags.debug == 0, "exact launcher -I -S -B flags")
        require(len(sys.argv) == 1 and sys.version_info[:3] == (3, 14, 7), "no selector/unadmitted interpreter")
        data, original_metadata = book.read(exact_path(FREEZE_FILE, immutable=True), 65536)
        v = FiniteJson(data, native=False).parse(lf=False)
        closed(v, "version profile baselineCommit sourceSha frontendSha256 featuresSha256 apiInventory repository app helper python libc display sourceHashes executables installed loader audits", ordered=False)
        require(type(v["version"]) is int and v["version"] == 1 and v["profile"] == PROFILE and v["baselineCommit"] == BASELINE_COMMIT
                and v["apiInventory"] == API_INVENTORY and v["featuresSha256"] == sha(FEATURES), "reviewed SG1 source/feature freeze")
        h(v["sourceSha"], 40)
        h(v["frontendSha256"])

        def absolute(value: Any) -> Path:
            require(type(value) is str and 0 < len(value.encode("utf-8")) <= 512 and value.startswith("/")
                    and str(Path(value)) == value and not any(part in (".", "..") for part in value.split("/")), "literal absolute freeze path")
            return Path(value)

        repository = exact_path(absolute(v["repository"]))
        launcher = repository / "desktop/tools/qualify_session_gtk.py"
        require(Path(__file__).resolve(strict=True) == launcher and os.getcwd() == str(repository / "desktop/src-tauri"), "fixed actual launcher source/cwd")
        require(type(v["display"]) is str and re.fullmatch(r":[1-9][0-9]{0,3}", v["display"]) is not None
                and os.environ.get("DISPLAY") == v["display"], "fixed inherited display number")
        require(type(v["sourceHashes"]) is dict and set(v["sourceHashes"]) == set(SOURCES) and len(SOURCES) == 220, "complete frozen220 source roster")
        for path in SOURCES:
            h(v["sourceHashes"][path])
            actual, st = book.hash_file(exact_path(repository / path), 2 * 1024 * 1024)
            require(st.st_nlink == 1 and actual == v["sourceHashes"][path], "original source freeze changed")

        members: list[tuple[Path, str, int]] = []

        def member(value: Any, limit: int = 256 * 1024 * 1024) -> tuple[Path, str]:
            closed(value, "path sha256", ordered=False)
            h(value["sha256"])
            path = exact_path(absolute(value["path"]), immutable=True)
            actual, st = book.hash_file(path, limit)
            require(st.st_nlink == 1 and actual == value["sha256"], "original installed member changed")
            members.append((path, actual, limit))
            return path, actual

        paths: dict[str, Path] = {}
        artifacts: dict[str, str] = {}
        for role in ("app", "helper", "python", "libc"):
            paths[role], artifacts[role] = member(v[role])
        require(paths["python"] == Path(sys.executable).resolve(strict=True)
                and sys.orig_argv == [str(paths["python"]), "-I", "-S", "-B", str(launcher)], "actual audited original interpreter/source invocation")
        closed(v["executables"], "display wm session a11y registry", ordered=False)
        executables: dict[str, Path] = {}
        for role in ("display", "wm", "session", "a11y", "registry"):
            executables[role], artifacts[role] = member(v["executables"][role])
        for key in ("installed", "loader"):
            require(type(v[key]) is list and 1 <= len(v[key]) <= 128, "finite actual installed/loader roster")
            selected = [str(member(value)[0]) for value in v[key]]
            require(len(set(selected)) == len(selected), "duplicate closure member")
        loader_paths = frozenset(value["path"] for value in v["loader"])
        require(str(paths["python"]) in loader_paths and str(paths["libc"]) in loader_paths, "original runtime/libc loader membership")
        require(type(v["audits"]) is list and len(v["audits"]) == 4, "four actual independently reviewed documents")
        audit_bytes: list[bytes] = []
        for index, audit in enumerate(v["audits"]):
            path, actual = member(audit, 65536)
            require(actual == AUDIT_PINS[index], "actual reviewed audit pin mismatch")
            body, _ = book.read(path, 65536)
            require(sha(body) == actual, "audit original changed between explicit freeze reads")
            audit_bytes.append(body)
        # Topic checks are only scope exclusions. Acceptance requires the exact
        # separately reviewed hashes above, not the presence of these words.
        writer_topics = (b"pre-main", b"fork-only", b"dup/stdio", b"WebKit", b"owned GTK", b"rfd feature closure",
                         b"launcher file actions", b"actual Exit only", b"no inherited witness writers")
        require(all(topic in audit_bytes[3] for topic in writer_topics), "incomplete sole-writer audit scope")
        loader_topics = (b"CPython 3.14.7", b"posix_spawn", b"close EINTR", b"ctypes", b"fstatfs", b"getdents64", b"renameat2", b"lseek")
        require(all(topic in audit_bytes[2] for topic in loader_topics), "unreviewed outer import/public ABI route")
        profile_topics = (b"orderly SIGTERM handlers/normal-return", b"intact-nonroot", b"direct-gtk", b"_NET_SUPPORTING_WM_CHECK", b"_NET_WM_PID", b"including /")
        require(all(topic in audit_bytes[0] for topic in profile_topics), "unreviewed direct GTK/WM/ext ancestry/teardown profile")
        os_release, _ = book.read(exact_path(Path("/etc/os-release").resolve(strict=True), immutable=True), 4096)
        require(b"ID=ubuntu\n" in os_release and b'VERSION_ID="24.04"\n' in os_release, "unadmitted installed distribution")
        result = cls(repository=repository, app=paths["app"], helper=paths["helper"], python=paths["python"], libc=paths["libc"],
                     display=v["display"], source_sha=v["sourceSha"], frontend_sha=v["frontendSha256"], sources=v["sourceHashes"],
                     artifacts=artifacts, executables=executables, loader_paths=loader_paths, audits=AUDIT_PINS,
                     members=tuple(members), original_data=data, original_metadata=original_metadata)
        result.check_loader(book)
        return result

    def check_loader(self, book: FileBook) -> None:
        raw, _ = book.read(Path("/proc") / str(os.getpid()) / "maps", 128 * 1024, proc=True)
        mapped: set[str] = set()
        for line in raw.decode("utf-8").splitlines():
            parts = line.split(maxsplit=5)
            if len(parts) < 6 or parts[5].startswith("["):
                continue
            require(parts[5].startswith("/") and not parts[5].endswith(" (deleted)"), "unknown original launcher mapping")
            mapped.add(parts[5])
        require(mapped <= self.loader_paths, "actual launcher mappings outside reviewed loader closure")

    def check_child(self, child: Child) -> None:
        path = self.app if child.role == "app" else self.helper if child.role == "helper" else self.executables[child.role]
        require(child.proc is not None and child.proc["identity"]["pid"] == child.pid
                and child.proc["executable"] == {"file": identity(os.lstat(exact_path(path, immutable=True))), "sha256": self.artifacts[child.role]},
                "original spawned executable/file must equal admitted member")

    def recheck(self, book: FileBook) -> None:
        require(not book.unknown and stable(self.original_metadata, os.lstat(exact_path(FREEZE_FILE, immutable=True))), "original installed freeze metadata changed")
        for path in SOURCES:
            actual, st = book.hash_file(exact_path(self.repository / path), 2 * 1024 * 1024)
            require(st.st_nlink == 1 and actual == self.sources[path], "original source freeze changed")
        for path, expected, limit in self.members:
            actual, st = book.hash_file(exact_path(path, immutable=True), limit)
            require(st.st_nlink == 1 and actual == expected, "original admitted member changed")
        self.check_loader(book)

    def build(self) -> dict[str, str]:
        require(API_INVENTORY is not None, "API build pin unavailable")
        roster = "".join(path + " " + self.sources[path] + "\n" for path in SOURCES).encode("ascii")
        return {"baselineManifest": BASELINE, "sourceRoster": sha(roster),
                "contractSource": self.sources["desktop/src-tauri/src/session_gtk_qualification/native_contract.rs"],
                "helperSource": self.sources["desktop/native/session_gtk_input_linux.c"],
                "launcherSource": self.sources["desktop/tools/qualify_session_gtk.py"],
                "appBinary": self.artifacts["app"], "helperBinary": self.artifacts["helper"], "launcherRuntime": self.artifacts["python"],
                "pythonRuntime": self.artifacts["python"], "frontend": self.frontend_sha, "featuresSha256": sha(FEATURES), "apiInventory": API_INVENTORY}


def build_binding(build: dict[str, str]) -> str:
    closed(build, BUILD_KEYS)
    return sha(("MRK_NATIVE_BUILD_V1\n" + "".join(build[key] + "\n" for key in BUILD_KEYS.split())).encode("ascii"))


def private_directory(parent: Path, name: str) -> Path:
    path = parent / name
    os.mkdir(path, 0o700)
    st = os.lstat(path)
    require(st.st_mode == 0o40700 and st.st_uid == os.getuid(), "fresh private same-owner directory")
    return path


def metadata_wait(path: Path, end: int, children: list[Child]) -> None:
    # No polling opens, no connection attempt until the original name appears.
    for attempt in range(400):
        require(now() < end and not any(child.book.unknown for child in children), "original infrastructure readiness endpoint")
        try:
            os.lstat(path)
            return
        except FileNotFoundError:
            if attempt < 399:
                poll_spacing(end, 399 - attempt, children)
    raise Refused("original infrastructure metadata polling cap")


@dataclass
class Infrastructure:
    book: FileBook
    freeze: Freeze
    root: Path
    environment: dict[str, str]
    children: dict[str, Child]
    session: DriverBus
    a11y: DriverBus
    registry: dict[str, Any]
    x11: X11Control
    native_connections_closed: bool = False

    @classmethod
    def start(cls, book: FileBook, freeze: Freeze) -> Infrastructure:
        require(not book.unknown, "no infrastructure after Unknown")
        root = exact_path(Path(tempfile.mkdtemp(prefix="mrk-sg1-infra-", dir="/var/tmp")))
        require(os.lstat(root).st_mode == 0o40700 and os.lstat(root).st_uid == os.getuid(), "fresh original infrastructure root")
        home = private_directory(root, "home")
        runtime = private_directory(root, "run")
        config = private_directory(root, "config")
        session_address = "unix:path=" + str(root / "session.sock")
        a11y_address = "unix:path=" + str(root / "a11y.sock")
        cookie = os.getrandom(16)
        require(len(cookie) == 16, "original private Xauthority cookie acquisition")
        host = socket.gethostname().encode("ascii")
        require(0 < len(host) <= 255, "fixed Xauthority local host bound")
        number, auth_name = freeze.display[1:].encode("ascii"), b"MIT-MAGIC-COOKIE-1"
        auth = struct.pack(">H", 256) + b"".join(struct.pack(">H", len(value)) + value for value in (host, number, auth_name, cookie))
        auth_path = root / "Xauthority"
        book.write_new(auth_path, auth)
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LANGUAGE": "en_US:en",
                       "DISPLAY": freeze.display, "XAUTHORITY": str(auth_path), "XDG_RUNTIME_DIR": str(runtime), "XDG_CONFIG_HOME": str(config),
                       "XDG_CURRENT_DESKTOP": "GNOME", "GDK_BACKEND": "x11", "GTK_A11Y": "atspi",
                       "DBUS_SESSION_BUS_ADDRESS": session_address, "AT_SPI_BUS_ADDRESS": a11y_address}
        children: dict[str, Child] = {}

        def start(role: str, arguments: tuple[str, ...]) -> Child:
            executable = freeze.executables[role]
            child = spawn(book, role, executable, (str(executable), *arguments), environment)
            children[role] = child
            freeze.check_child(child)
            return child

        display_socket = Path("/tmp/.X11-unix") / ("X" + freeze.display[1:])
        for reserved in (display_socket, Path("/tmp/.X" + freeze.display[1:] + "-lock")):
            try:
                os.lstat(reserved)
            except FileNotFoundError:
                continue
            raise Refused("no existing/unowned X11 display slot")
        display = start("display", (freeze.display, "-screen", "0", "1280x800x24", "-nolisten", "tcp", "-auth", str(auth_path), "-noreset"))
        display_end = plus(display.spawn_ns, 5 * NS)
        metadata_wait(display_socket, display_end, ORIGINAL_CHILDREN)
        x11 = X11Control(book, display_socket, display, cookie, display_end)
        wm = start("wm", ("--sm-disable",))
        x11.ready_wm(wm, plus(wm.spawn_ns, 5 * NS))
        x11.close()  # actual authenticated readiness, not socket existence/spawn
        bus_config = ("<busconfig><type>session</type><auth>EXTERNAL</auth>"
                      "<policy context=\"default\"><allow user=\"" + str(os.getuid()) + "\"/>"
                      "<allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/>"
                      "</policy></busconfig>").encode("ascii")
        config_path = root / "bus.conf"
        book.write_new(config_path, bus_config)
        for role, address in (("session", session_address), ("a11y", a11y_address)):
            child = start(role, ("--nofork", "--nopidfile", "--config-file=" + str(config_path), "--address=" + address))
            metadata_wait(Path(address.removeprefix("unix:path=")), plus(child.spawn_ns, 5 * NS), ORIGINAL_CHILDREN)
        session = DriverBus(book, session_address, children["session"], plus(children["session"].spawn_ns, 5 * NS))
        a11y = DriverBus(book, a11y_address, children["a11y"], plus(children["a11y"].spawn_ns, 5 * NS))
        registry_child = start("registry", ())
        registry = a11y.service("registry", registry_child, plus(registry_child.spawn_ns, 5 * NS))
        require(not book.unknown and all(child.status is None for child in children.values()), "original infrastructure remains active")
        return cls(book, freeze, root, environment, children, session, a11y, registry, x11)

    def display_facts(self) -> dict[str, Any]:
        require(self.x11.settled and self.x11.wm_process == self.children["wm"].proc, "authenticated original WM readiness missing")

        def bus(role: str, connection: DriverBus) -> dict[str, Any]:
            return {"id": connection.id, "process": self.children[role].proc, "addressSha256": sha(connection.address.encode("utf-8"))}

        return {"kind": "x11", "display": self.freeze.display, "server": self.children["display"].proc, "windowManager": self.children["wm"].proc,
                "sessionBus": bus("session", self.session), "a11yBus": bus("a11y", self.a11y), "registry": self.registry, "sandbox": "intact-nonroot"}

    def teardown(self, outer_end: int) -> None:
        require(not self.book.unknown and not self.native_connections_closed, "no failure-path infrastructure cleanup")
        self.session.close()
        self.a11y.close()
        self.native_connections_closed = True
        # Source-audited cooperative normal-return handlers only, AFTER the
        # application conjunction. Not timeout disposal: signalled/nonzero waits
        # refuse. No repeated signal, SIGKILL, replacement wait or directory repair.
        for role in ("registry", "wm", "a11y", "session", "display"):
            child = self.children[role]
            child.observe_wait()
            require(now() < outer_end and child.status is None and not child.wait_unknown and not child.term_requested
                    and child.proc == process(self.book, child.pid), "original infrastructure termination identity")
            child.term_requested = True
            os.kill(child.pid, signal.SIGTERM)
            while now() < outer_end and not child.complete() and not self.book.unknown:
                progress(ORIGINAL_CHILDREN, 5)
            require(child.complete() and not self.book.unknown and now() < outer_end, "separate infrastructure normal wait/EOF/close custody")
        # Retain evidence/private directories. No unlink/rmtree repair.


@dataclass(frozen=True)
class NativeRecord:
    name: str
    value: dict[str, Any]
    data: bytes
    metadata: os.stat_result
    checked_ns: int

    @property
    def digest(self) -> str:
        return sha(self.data)


ORIGINAL_BRIDGES: list[Any] = []


class Bridge:
    """Fixed18-record SG1 channel; never an Exit command or receipt shortcut.

    Original read bytes/stat survive to final verification. Failed reads never
    reopen. O writes only admission/helper-settled through one original pending
    inode, one write, one consuming close, then renameat2 NOREPLACE.
    Q/R gate GO and C gates action. O corroborates their original facts without
    an acknowledgment channel; its checks do not pace C or precede C by claim.
    """
    def __init__(self, book: FileBook, freeze: Freeze, libc: NativeLibC, outer: dict[str, Any]):
        require(not book.unknown and not ORIGINAL_BRIDGES, "one SG1 fixture only/no acquisition after Unknown")
        self.book, self.freeze, self.libc, self.outer = book, freeze, libc, outer
        self.receipt_started: set[str] = set()
        self.receipts: dict[str, ReceiptRecord] = {}
        ORIGINAL_BRIDGES.append(self)  # before any original fixture acquisition
        self.root = exact_path(Path(tempfile.mkdtemp(prefix="mrk-sg1-", dir="/var/tmp")))
        require(len(os.fsencode(self.root)) <= 256 and not self.root.is_relative_to(freeze.repository)
                and not freeze.repository.is_relative_to(self.root), "private run root/source separation")
        self.app_root = private_directory(self.root, "app")
        self.native_root = private_directory(self.root, "native")
        self.project = private_directory(self.root, "project")
        self.outside = private_directory(self.root, "outside")
        self.source = self.outside / "synthetic.jks"
        self.project_chain = book.ancestry(self.project, libc)  # checks / before leaf creation/native spawn
        self.source_metadata = book.synthetic(self.source, libc)
        self.source_chain = book.ancestry(self.source, libc, source=self.source_metadata)
        self.project_id = self.project_chain[-1].identity
        self.source_id = self.source_chain[-1].identity
        self.roots = {key: identity(os.lstat(path)) for key, path in self.root_paths()}
        for value in self.roots.values():
            id_schema(value, directory=True)
            require(value["owner"] == os.getuid(), "original same-owner root")
        require(not any(ancestor.identity == self.project_id for ancestor in self.source_chain), "synthetic source physically outside project")
        require(book.directory_entries(self.root, libc) == {"app", "native", "project", "outside"}
                and not book.directory_entries(self.app_root, libc) and not book.directory_entries(self.native_root, libc)
                and not book.directory_entries(self.project, libc) and book.directory_entries(self.outside, libc) == {"synthetic.jks"}, "fresh fixed four-directory layout")
        self.build = freeze.build()
        self.binding = build_binding(self.build)
        self.roster = {"ready.json": "ready", "admission.json": "admission"}
        for n in range(1, 6):
            self.roster.update({f"d{n}.{typ}.json": typ for typ in ("presented", "go", "input")})
        self.roster["helper-settled.json"] = "helper-settled"
        self.records: dict[str, NativeRecord] = {}
        self.original_reads: dict[str, tuple[bytes, os.stat_result]] = {}
        self.original_writes: dict[str, tuple[bytes, os.stat_result]] = {}
        self.read_started: set[str] = set()
        self.write_started: set[str] = set()
        self.polls = 0
        self.payload_bound = 84 * 1024
        self.helper: Child | None = None
        self.app: Child | None = None
        self.infrastructure: Infrastructure | None = None
        self.end: int | None = None
        self.first_application: dict[str, Any] | None = None
        self.first_main: dict[str, Any] | None = None

    def root_paths(self) -> tuple[tuple[str, Path], ...]:
        return (("run", self.root), ("app", self.app_root), ("native", self.native_root))

    def fixtures(self) -> dict[str, Any]:
        return {"project": self.project_id, "source": self.source_id, "sourceSha256": sha(SYNTHETIC)}

    def selected(self, n: int) -> dict[str, Any] | None:
        return self.project_id if n == 2 else self.source_id if n == 3 else None

    def unchanged(self) -> None:
        for key, path in self.root_paths():
            require(exact_path(path) == path and identity(os.lstat(path)) == self.roots[key], "original run/native/app directory changed")
        for ancestor in (*self.project_chain, *self.source_chain):
            named = os.lstat(ancestor.path)
            require(identity(named) == ancestor.identity, "original full ancestry identity changed")
        require(exact_path(self.project) == self.project and exact_path(self.source) == self.source
                and stable(self.source_metadata, os.lstat(self.source)), "original synthetic leaf/path changed without reopen")

    def metadata_inventory(self) -> None:
        # Metadata-only polling at fixed names. Creation/final getdents closes
        # additionally exclude unknown names; source/writer audits exclude any
        # hidden payload/replacement in between. No directory iterator polling.
        self.unchanged()
        committed = pending = 0
        for name, typ in self.roster.items():
            cap = 16384 if typ == "admission" else 4096
            for suffix in ("", ".pending"):
                try:
                    st = os.lstat(self.native_root / (name + suffix))
                except FileNotFoundError:
                    require(suffix or name not in self.records, "committed original disappeared")
                    continue
                require(st.st_mode == 0o100600 and st.st_uid == os.getuid() and st.st_nlink == 1 and 0 <= st.st_size <= cap, "native metadata/payload bound")
                if suffix:
                    pending += st.st_size
                else:
                    committed += st.st_size
                    if name in self.records:
                        require(stable(st, self.records[name].metadata), "checked native original changed")
        require(committed <= self.payload_bound and pending <= self.payload_bound, "committed/pending aggregate84KiB bounds")

    def check_common(self, value: dict[str, Any], typ: str, st: os.stat_result, end: int) -> None:
        require(value["type"] == typ and value["case"] == CASE and value["binding"] == self.binding
                and value["roots"] == self.roots and value["file"] == identity(st), "original common record binding/identity")
        require(d(value["writtenNs"]) <= now() < end, "original record read/publication endpoint")
        if typ in ("admission", "helper-settled"):
            expected = self.outer["identity"]
        elif typ == "go":
            require(self.app is not None and self.app.proc is not None, "original app writer missing")
            expected = self.app.proc["identity"]
        else:
            require(self.helper is not None and self.helper.proc is not None, "original helper writer missing")
            expected = self.helper.proc["identity"]
        require(value["writer"] == expected, "original sole record writer")
        if typ not in ("ready", "admission"):
            require(value["admissionSha256"] == self.records["admission.json"].digest, "linked original admission bytes")

    def keep(self, name: str, value: dict[str, Any], data: bytes, st: os.stat_result, end: int) -> NativeRecord:
        require(name in self.roster and name not in self.records, "record cannot be replaced/reopened")
        self.check_common(value, self.roster[name], st, end)
        require(sum(len(record.data) for record in self.records.values()) + len(data) <= self.payload_bound, "retained native payload bound")
        record = NativeRecord(name, value, data, st, now())
        self.records[name] = record
        self.metadata_inventory()
        return record

    def read(self, name: str, end: int) -> NativeRecord:
        require(name in self.roster and name not in self.read_started and name not in self.records and not self.book.unknown, "one original native read")
        self.read_started.add(name)  # a failed first open/read is never retried
        path, typ = self.native_root / name, self.roster[name]
        found = False
        for attempt in range(400):
            require(now() < end and self.polls < 10000 and not self.book.unknown, "native metadata endpoint/count")
            self.polls += 1
            self.metadata_inventory()
            try:
                os.lstat(path)
                found = True
                break
            except FileNotFoundError:
                if attempt < 399:
                    poll_spacing(end, 399 - attempt, ORIGINAL_CHILDREN)
        require(found, "native metadata polling cap")
        data, st = self.book.read(path, 16384 if typ == "admission" else 4096, private=True)
        self.original_reads[name] = (data, st)  # retain before any parse/schema failure
        return self.keep(name, native_parse(data, typ), data, st, end)

    def app_alive(self) -> None:
        require(self.app is not None and self.app.proc is not None, "original app missing")
        self.app.observe_wait()
        require(self.app.status is None and not self.app.wait_unknown and not self.book.unknown, "original app must remain live before helper settlement")

    def publish(self, name: str, fields: dict[str, Any], end: int) -> NativeRecord:
        require(name in ("admission.json", "helper-settled.json") and name not in self.write_started
                and name not in self.records and not self.book.unknown, "original finite outer publication")
        self.write_started.add(name)
        self.metadata_inventory()
        typ, final = self.roster[name], self.native_root / name
        pending = self.native_root / (name + ".pending")
        require(now() < end, "original publication endpoint")
        self.app_alive()
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        owner = self.book.acquire(fd, "native-write:" + name)
        try:
            before = os.fstat(fd)
            require(before.st_mode == 0o100600 and before.st_nlink == 1 and before.st_size == 0 and before.st_uid == os.getuid(), "pending inode before encoding")
            value = {"v": 1, "type": typ, "case": CASE, "profile": PROFILE, "binding": self.binding,
                     "roots": self.roots, "file": identity(before), "writer": self.outer["identity"], "writtenNs": str(now()), **fields}
            data = native_bytes(value)
            require(native_parse(data, typ) == value and now() < end, "closed generated native DTO before one write")
            self.original_writes[name] = (data, before)  # same bytes/inode retained on a failed write/publication
            count = os.write(fd, data)
            after = os.fstat(fd)
            require(count == len(data) and after.st_size == count and after.st_nlink == 1 and identity(after) == identity(before)
                    and stable(after, os.lstat(pending)), "one complete stable native write")
        except (OSError, Refused):
            self.book.fail("original native write unknown")
            raise
        finally:
            self.book.close(owner)
        require(now() < end, "original close before publication endpoint")
        self.app_alive()  # Q cannot preclose/Exit before helper-settled appears
        self.libc.publish(pending, final)
        named = os.lstat(final)
        require(identity(named) == identity(after) and named.st_nlink == 1 and named.st_size == len(data), "same-inode no-replace publication")
        return self.keep(name, value, data, named, end)

    def ready(self, helper: Child, infrastructure: Infrastructure) -> NativeRecord:
        require(self.helper is None and helper.role == "helper" and helper.proc is not None, "original helper once")
        self.helper = helper
        record = self.read("ready.json", plus(helper.spawn_ns, 5 * NS))
        value = record.value
        require(value["helper"] == helper.proc and value["registry"] == infrastructure.registry
                and value["sessionBusId"] == infrastructure.session.id and value["a11yBusId"] == infrastructure.a11y.id, "independently held ready originals")
        helper.observe_wait()
        require(helper.spawn_ns <= d(value["writtenNs"]) <= plus(helper.spawn_ns, 5 * NS) and helper.status is None
                and not helper.wait_unknown and not self.book.unknown, "original ready timing/live helper")
        return record

    def admit(self, app: Child, infrastructure: Infrastructure) -> None:
        require(self.app is None and app.role == "app" and app.proc is not None and self.helper is not None, "original app once")
        self.app, self.infrastructure = app, infrastructure
        helper, ready = self.helper, self.records["ready.json"]
        require(app.proc["executable"]["sha256"] == self.build["appBinary"] and helper.proc["executable"]["sha256"] == self.build["helperBinary"]
                and self.outer["executable"]["sha256"] == self.build["launcherRuntime"], "actual original build/runtime artifacts")
        require(d(ready.value["writtenNs"]) <= app.spawn_ns <= min(plus(d(ready.value["writtenNs"]), 5 * NS), plus(helper.spawn_ns, 10 * NS)), "original ready-to-app endpoint")
        self.end = plus(app.spawn_ns, 90 * NS)
        require(self.end <= plus(helper.spawn_ns, 100 * NS), "fixed original outer endpoint")
        pipes = {"appStdout": app.stdout.pipe, "appStderr": app.stderr.pipe, "helperStdout": helper.stdout.pipe, "helperStderr": helper.stderr.pipe}
        require(len({(value["device"], value["inode"]) for value in pipes.values()}) == 4, "four distinct original pipes")
        aliases = {"appStdoutWrite": app.stdout.writer.receipt, "appStderrWrite": app.stderr.writer.receipt,
                   "helperStdoutWrite": helper.stdout.writer.receipt, "helperStderrWrite": helper.stderr.writer.receipt}
        require(all(value is not None for value in aliases.values()) and helper.status is None
                and all(child.status is None for child in infrastructure.children.values()), "original closed aliases/live infrastructure")
        fields = {"build": self.build, "readySha256": ready.digest, "outer": self.outer, "app": app.proc, "helper": helper.proc,
                  "appSpawnNs": str(app.spawn_ns), "outerEndNs": str(self.end), "display": infrastructure.display_facts(), "fixtures": self.fixtures(),
                  "pipes": pipes, "aliases": aliases, "sourceProfileSha256": self.freeze.audits[0], "installedClosureSha256": self.freeze.audits[1],
                  "loaderClosureSha256": self.freeze.audits[2], "writerAuditSha256": self.freeze.audits[3]}
        self.publish("admission.json", fields, min(plus(app.spawn_ns, 2 * NS), self.end))

    def dialogs(self) -> None:
        require(self.app is not None and self.helper is not None and self.infrastructure is not None and self.end is not None, "original admission before dialogs")
        previous: NativeRecord | None = None
        seen: set[tuple[str, str]] = set()
        for n, kind in enumerate(ROSTER, 1):
            presented = self.read(f"d{n}.presented.json", self.end)
            p = presented.value
            require(p["n"] == n and p["kind"] == kind and self.app.spawn_ns <= d(p["observedNs"]) <= d(p["writtenNs"]), "original presented order")
            if previous is not None:
                require(d(previous.value["writtenNs"]) <= d(p["observedNs"]), "next dialog before previous original input record")
            a = p["association"]
            require(a["process"] == self.app.proc, "direct GTK dialog must belong to original app")
            if n == 1:
                self.first_application, self.first_main = a["application"], a["mainWindow"]
                require(self.first_application != self.first_main, "distinct original application/main window")
            require(a["application"] == self.first_application and a["mainWindow"] == self.first_main
                    and a["parent"] == self.first_application, "all five retain original application/main window")
            main_id, dialog_id = topology_ids(self.records["admission.json"].digest, n)
            require(a["mainId"] == main_id and a["dialogId"] == dialog_id, "observed IDs bind original admission bytes, not reusable build")
            for ref in (p["dialog"], p["button"]):
                key = (ref["bus"], ref["path"])
                require(key not in seen and ref not in (self.first_application, self.first_main), "no accessible original reuse/adoption")
                seen.add(key)
            # Independently authenticate the event-derived unique app bus; no
            # enumeration, PID rediscovery or title-based dialog authority.
            pid = self.infrastructure.a11y.call("GetConnectionUnixProcessID", a["application"]["bus"], self.end)
            require(pid == self.app.pid and process(self.book, self.app.pid) == self.app.proc, "original app accessible credentials")
            go_end = min(plus(d(p["observedNs"]), 2 * NS), self.end)
            go = self.read(f"d{n}.go.json", go_end)
            g = go.value
            require(g["n"] == n and g["kind"] == kind and g["presentedSha256"] == presented.digest
                    and g["ownership"]["mainId"] == a["mainId"] and g["ownership"]["dialogId"] == a["dialogId"]
                    and d(p["writtenNs"]) <= d(g["ownership"]["checkedNs"]) <= d(g["checkpointNs"]) <= go_end
                    and d(g["writtenNs"]) <= go_end
                    and g["selected"] == self.selected(n) and d(g["inputEndNs"]) <= self.end, "original GO links/selection/endpoint")
            native_input = self.read(f"d{n}.input.json", d(g["inputEndNs"]))
            value = native_input.value
            require(value["n"] == n and value["kind"] == kind and value["presentedSha256"] == presented.digest and value["goSha256"] == go.digest
                    and value["selected"] == self.selected(n) and d(g["writtenNs"]) <= d(value["startedNs"]) <= d(value["completedNs"])
                    <= d(value["writtenNs"]) < d(g["inputEndNs"]) and value["completion"]["dialog"] == p["dialog"], "original input links/selection/disappearance/endpoint")
            counts = value["counts"]
            require(counts["actions"] == (1, 7, 13, 14, 15)[n - 1], "exact cumulative native action roster")
            if previous is not None:
                require(all(counts[key] >= previous.value["counts"][key] for key in counts), "original actor counters regressed")
            self.unchanged()
            previous = native_input
        # No app Exit/final receipt/recipe wait here. The helper returns on its
        # own last native completion while Q's recipe is waiting for this proof.
        self.settle_helper(previous)

    def settle_helper(self, last: NativeRecord | None) -> None:
        require(last is not None and self.helper is not None and self.end is not None, "last original input before helper settlement")
        completed = d(last.value["completedNs"])
        end = min(plus(completed, 2 * NS), self.end)
        while now() < end and not self.helper.complete() and not self.book.unknown:
            self.app_alive()
            progress(ORIGINAL_CHILDREN)
        helper = self.helper
        self.app_alive()
        require(helper.complete() and not self.book.unknown and helper.wait_ns is not None and completed <= helper.wait_ns <= end,
                "original helper wait0/EOF/read/consuming-close conjunction")
        stdout, stderr = helper.stdout.facts(), helper.stderr.facts()
        require(stdout["bytes"] == stderr["bytes"] == 0 and all(completed <= d(stream["close"]["atNs"]) <= end for stream in (stdout, stderr)), "empty original helper readers closed after final input")
        fields = {"admissionSha256": self.records["admission.json"].digest, "lastInputSha256": last.digest, "helper": helper.proc,
                  "waitStatus": 0, "waitNs": str(helper.wait_ns), "stdout": stdout, "stderr": stderr}
        self.publish("helper-settled.json", fields, end)

    def final_layout(self) -> None:
        require(len(self.records) == len(self.roster) == 18, "complete fixed18 native record roster")
        self.metadata_inventory()
        require(self.book.directory_entries(self.root, self.libc) == {"app", "native", "project", "outside"}
                and self.book.directory_entries(self.native_root, self.libc) == set(self.roster)
                and self.book.directory_entries(self.app_root, self.libc) == {"incomplete.json", "prefix.json", "final.json"}
                and not self.book.directory_entries(self.project, self.libc)
                and self.book.directory_entries(self.outside, self.libc) == {"synthetic.jks"}, "fixed complete layout/no pending/empty project")
        # incomplete is metadata-only: never read an early receipt then reopen.
        incomplete = os.lstat(self.app_root / "incomplete.json")
        require(incomplete.st_mode == 0o100600 and incomplete.st_uid == os.getuid() and incomplete.st_nlink == 1
                and incomplete.st_size == len(b'{"scope":"session-gtk-five-dialog-v1","status":"incomplete"}\n'), "original incomplete marker metadata")
        self.unchanged()


def fixed(actual: Any, expected: Any) -> None:
    """Closed recursive equality, preserving bool/int/null distinctions."""
    require(type(actual) is type(expected), "fixed DATA type")
    if isinstance(expected, dict):
        require(set(actual) == set(expected), "fixed DATA keys")
        for key in expected:
            fixed(actual[key], expected[key])
    elif isinstance(expected, list):
        require(len(actual) == len(expected), "fixed DATA list length")
        for value, reference in zip(actual, expected, strict=True):
            fixed(value, reference)
    else:
        require(actual == expected, "fixed DATA value")


def receipt_data(data: bytes) -> dict[str, Any]:
    value = FiniteJson(data, native=False).parse(lf=False)
    require(type(value) is dict and json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") == data,
            "original producer compact sorted DATA/no LF")
    return value


def source_books(actual: Any, bridge: Bridge) -> None:
    require(type(actual) is list and len(actual) == 5, "exact five original source books")
    for n, book in enumerate(actual, 1):
        closed(book, "notStarted originals reads eof", ordered=False)
        if n in (1, 4, 5):
            fixed(book, {"notStarted": True, "originals": [], "reads": 0, "eof": None})
            continue
        fixed(book["notStarted"], False)
        expected = list(bridge.project_chain)
        if n == 3:
            expected.extend(bridge.source_chain[1:])  # second branch shares slot0 only
        slots = book["originals"]
        require(type(slots) is list and len(slots) == len(expected) and 1 <= len(slots) <= 40, "original SourceBook descriptor roster")
        orders: list[list[int]] = []
        marks: list[int] = []
        for index, (slot, ancestor) in enumerate(zip(slots, expected, strict=True)):
            closed(slot, "slot parent identity size order", ordered=False)
            fixed(slot["slot"], index)
            parent = None if index == 0 else 0 if n == 3 and index == len(bridge.project_chain) else index - 1
            fixed(slot["parent"], parent)
            fixed(slot["identity"], ancestor.identity)
            fixed(slot["size"], 12 if n == 3 and index + 1 == len(slots) else None)
            order = slot["order"]
            require(type(order) is list and len(order) == 7, "seven original source lifecycle observations")
            for mark in order:
                u(mark, 8192, 1)
            require(all(a < b for a, b in zip(order, order[1:])), "reserve/acquire/adopt/validate/terminal/close/Ok order")
            orders.append(order)
            marks.extend(order)
        require(all(a[3] < b[0] for a, b in zip(orders, orders[1:])), "original source acquisitions sequential")
        require(all(a[4] > b[4] for a, b in zip(orders, orders[1:])), "all original terminal identities checked in reverse")
        require(max(order[3] for order in orders) < min(order[4] for order in orders)
                and max(order[4] for order in orders) < min(order[5] for order in orders), "whole acquisition/terminal/consuming-close phases")
        require(all(b[6] < a[5] for a, b in zip(orders, orders[1:])), "reverse nonoverlapping original consuming closes")
        if n == 2:
            fixed(book["reads"], 0)
            fixed(book["eof"], None)
        else:
            u(book["reads"], 13, 2)
            closed(book["eof"], "ordinal bytes", ordered=False)
            eof = u(book["eof"]["ordinal"], 8192, 1)
            fixed(book["eof"]["bytes"], 12)
            require(orders[-1][3] < eof < min(order[4] for order in orders), "genuine original capture EOF before terminal checks")
            marks.append(eof)
        # SourceBook::next has exactly these7 marks/original and one capture EOF;
        # reads themselves have a separate counter. Reject gaps/duplicates too.
        require(sorted(marks) == list(range(1, 7 * len(slots) + (1 if n == 3 else 0) + 1)), "complete unique original source trace")


def passive_and_edit(prefix: dict[str, Any]) -> None:
    passive = prefix["passive"]
    closed(passive, "stopping disabled registeredOwners originals", ordered=False)
    fixed(passive["stopping"], True)
    fixed(passive["disabled"], False)
    fixed(passive["registeredOwners"], 0)
    originals = passive["originals"]
    require(type(originals) is list and len(originals) == 2, "exact two real bootstrap passive originals")
    keys: set[int] = set()
    native_bools = ("inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success", "writer_joined", "writer_complete",
                    "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined", "driver_joined", "watchdog_joined")
    for original in originals:
        closed(original, "key native observerJoin", ordered=False)
        key = d(original["key"])
        require(key > 0 and key not in keys, "distinct retained original passive keys")
        keys.add(key)
        fixed(original["observerJoin"], "ok")
        native = original["native"]
        closed(native, " ".join((*native_bools, "stdout_bytes", "stderr_bytes")), ordered=False)
        for name in native_bools:
            fixed(native[name], True)
        u(native["stdout_bytes"], 4 * 1024 * 1024, 1)
        u(native["stderr_bytes"], 64 * 1024)
    fixed(prefix["edit"], {"documentBound": True, "documentLost": False, "authorized": False, "sessions": 0, "children": 0, "stopping": True})
    # Q retains/bootstrap-checks THESE owners before stage1 and rejoins only
    # their original remaining tails; final booleans alone are not that proof.


EVENT_KINDS = frozenset((
    "navigation", "load-started", "load-finished", "hook-installed", "document-lost",
    "coordinator-registered", "coordinator-joined", "child-registered", "child-joined",
    "construct-dispatch", "construct-enter", "adopted", "show", "response-enter", "response-decision", "filename", "response-leave",
    "topology-tagged", "topology-checked", "topology-retired",
    "close-dispatch", "close-enter", "close-ack", "close-leave", "destroy-enter", "destroy-leave",
    "release-dispatch", "release-enter", "handlers-detached", "released", "release-leave",
    "project-published", "header-observed", "candidate-published", "quit-stop", "close-stimulus", "close-prevented",
    "relay-joined", "checkpoint", "command-enter", "command-return", "recipe-returned",
))
COMMANDS = ("app-info", "catalog", "edit-status", "asset-status", "project", "open", "context", "choose", "environment-status")


class Events:
    """Independent exact prefix oracle, not acceptance of Q's status labels."""
    def __init__(self, actual: Any):
        require(type(actual) is list and 1 <= len(actual) <= 512, "bounded original SG1 event book")
        self.events = actual
        self.used: set[int] = set()
        for ordinal, event in enumerate(actual, 1):
            closed(event, "ordinal kind operation detail mainThread", ordered=False)
            fixed(event["ordinal"], ordinal)
            require(type(event["kind"]) is str and event["kind"] in EVENT_KINDS, "closed original event kind")
            u(event["operation"], 5)
            u(event["detail"], 8)
            boolean(event["mainThread"])

    def matching(self, kind: str, operation: int | None = None) -> list[dict[str, Any]]:
        return [event for event in self.events if event["kind"] == kind and (operation is None or event["operation"] == operation)]

    def use(self, event: dict[str, Any], *, main: bool | None = None) -> int:
        if main is not None:
            require(event["mainThread"] is main, "original callback/dispatch main-thread location")
        self.used.add(event["ordinal"])
        return event["ordinal"]

    def one(self, kind: str, operation: int, detail: int = 1, *, main: bool | None = None) -> int:
        selected = [event for event in self.matching(kind, operation) if event["detail"] == detail]
        require(len(selected) == 1, "required original event singleton")
        return self.use(selected[0], main=main)

    def ordinal(self, ordinal: int, kind: str, operation: int, detail: int) -> None:
        u(ordinal, len(self.events), 1)
        event = self.events[ordinal - 1]
        require(event["kind"] == kind and event["operation"] == operation and event["detail"] == detail, "actual command original event link")
        self.use(event)

    def finish(self) -> None:
        require(self.used == set(range(1, len(self.events) + 1)), "unexpected/unconsumed original event")


def command_facts(actual: Any, events: Events, stages: dict[int, int]) -> dict[tuple[str, int], dict[str, Any]]:
    require(type(actual) is list and len(actual) == 10, "ten exact real SG1 commands")
    expected = {("app-info", 0): 1, ("catalog", 0): 1, ("edit-status", 0): 1, ("asset-status", 0): 1,
                ("environment-status", 0): 1,
                ("project", 1): 2, ("project", 2): 3, ("open", 3): 1, ("context", 3): 1, ("choose", 3): 1}
    result: dict[tuple[str, int], dict[str, Any]] = {}
    previous_enter = 0
    for command in actual:
        closed(command, "kind stage entered returned reply", ordered=False)
        require(type(command["kind"]) is str and command["kind"] in COMMANDS, "closed actual command kind")
        stage = u(command["stage"], 3)
        key = (command["kind"], stage)
        require(key in expected and key not in result, "original command roster/repetition")
        fixed(command["reply"], expected[key])
        entered, returned = u(command["entered"], len(events.events), 1), u(command["returned"], len(events.events), 1)
        require(previous_enter < entered < returned, "original command registration/return order")
        previous_enter = entered
        events.ordinal(entered, "command-enter", stage, COMMANDS.index(command["kind"]))
        events.ordinal(returned, "command-return", stage, expected[key])
        if stage == 0:
            require(returned < stages[1], "all real bootstrap replies precede SG1 stage1")
        else:
            require(stages[stage] < entered and returned < stages[stage + 1], "original command contained in its SG1 stage")
        result[key] = command
    require(set(result) == set(expected) and len(events.matching("command-enter")) == len(events.matching("command-return")) == 10, "all actual command links accounted")
    require(result[("open", 3)]["returned"] < result[("context", 3)]["entered"]
            and result[("context", 3)]["returned"] < result[("choose", 3)]["entered"], "real Open/Context/Choose sequential replies")
    return result


def disposal_order(f: dict[str, int]) -> None:
    """Pure Q1 partial order; gtk_window_close only queues later GTK3 work.

    Ack is return from the close REQUEST, not destruction. The worker may see
    the destroyed flag and dispatch release between DestroyEnter/DestroyLeave;
    the queued main-thread release cannot enter before that callback unwinds.
    No product close/destroy/release scheduling is changed by this oracle.
    """
    for kind in ("response-decision", "response-leave", "close-dispatch", "close-enter", "close-ack", "close-leave", "destroy-enter", "destroy-leave",
                 "release-dispatch", "release-enter", "handlers-detached", "released", "release-leave", "coordinator-joined"):
        u(f[kind], 512, 1)
    require(f["response-decision"] < f["response-leave"] < f["close-enter"], "first response unwind before main close request")
    require(f["response-decision"] < f["close-dispatch"] < f["close-enter"] < f["close-ack"] < f["close-leave"]
            < f["destroy-enter"] < f["destroy-leave"], "queued GTK3 request ack/return before later destroy callback")
    require(f["close-ack"] < f["release-dispatch"] and f["destroy-enter"] < f["release-dispatch"] < f["release-enter"]
            and f["destroy-leave"] < f["release-enter"] and f["close-leave"] < f["release-enter"]
            < f["handlers-detached"] < f["released"] < f["release-leave"] < f["coordinator-joined"], "actual destroy unwind/release/handler/filter/dialog/TLS/join")


def disposal_response_order(f: dict[str, int], enter: int, leave: int) -> None:
    require(f["close-leave"] < enter < leave < f["destroy-enter"], "only later idle DeleteEvent response before actual destroy")


def diagnostics_observation(actual: Any, *, final: bool) -> None:
    closed(actual, "schemaVersion statusRevision capability active lastTerminal", ordered=False)
    fixed(actual["schemaVersion"], 1)
    u(actual["statusRevision"], (1 << 32) - 2)
    closed(actual["capability"], "available reason", ordered=False)
    fixed(actual["capability"]["available"], False)
    allowed = ("shutdown",) if final else ("busy", "document-lost", "runtime-unqualified")
    require(type(actual["capability"]["reason"]) is str and actual["capability"]["reason"] in allowed,
            "actual unavailable diagnostics observation")
    fixed(actual["active"], None)
    fixed(actual["lastTerminal"], None)


def prefix_facts(data: bytes, bridge: Bridge) -> None:
    prefix = receipt_data(data)
    closed(prefix, "scope case fixtureOnly events commands sources passive edit relayJoin recipeJoin documentBound selectedCancelPreserved frontendSubscriptions nativeOwnership diagnosticsBootstrap diagnosticsFinal", ordered=False)
    fixed(prefix["scope"], SCOPE)
    fixed(prefix["case"], CASE)
    for flag in ("fixtureOnly", "documentBound", "selectedCancelPreserved"):
        fixed(prefix[flag], True)
    fixed(prefix["relayJoin"], "ok")
    fixed(prefix["recipeJoin"], "ok")
    fixed(prefix["frontendSubscriptions"], {"sourcePinned": True, "names": ["config-edit-state", "asset-session-state", "environment-diagnostics-state-changed"],
          "evidence": "real-status-command-after-awaited-listen-in-pinned-controller"})
    diagnostics_observation(prefix["diagnosticsBootstrap"], final=False)
    diagnostics_observation(prefix["diagnosticsFinal"], final=True)
    require(prefix["diagnosticsFinal"]["statusRevision"] >= prefix["diagnosticsBootstrap"]["statusRevision"],
            "original diagnostics observation revisions do not reverse")
    source_books(prefix["sources"], bridge)
    passive_and_edit(prefix)
    ownerships = prefix["nativeOwnership"]
    require(type(ownerships) is list and len(ownerships) == 5, "five exact original topology proof/retirement records")
    events = Events(prefix["events"])
    for kind in ("topology-tagged", "topology-checked", "topology-retired"):
        require(len(events.matching(kind)) == 5, "five exact original topology events per kind")
    stages = {n: events.one("checkpoint", n, 1, main=False) for n in range(1, 6)}
    native = {n: events.one("checkpoint", n, 2, main=False) for n in range(1, 6)}
    require(all(stages[n] < stages[n + 1] for n in range(1, 5)) and len(events.matching("checkpoint")) == 10, "five distinct stage/native checkpoints")
    finished = events.one("load-finished", 0, main=True)
    for kind in ("navigation", "load-started", "hook-installed"):
        require(len(events.matching(kind)) == 1 and events.one(kind, 0, main=True) < finished, "actual original lifecycle before LoadFinished")
    require(len(events.matching("load-finished")) == 1 and not events.matching("document-lost") and finished < stages[1], "bound original lifecycle complete before recipe")
    # Navigation and LoadStarted need NOT be ordered against each other. Real
    # bootstrap commands may enter while load callbacks are still completing.
    commands = command_facts(prefix["commands"], events, stages)
    facts: dict[int, dict[str, int]] = {}
    ordinary = ("coordinator-registered", "construct-dispatch", "construct-enter", "adopted", "topology-tagged", "show", "topology-checked", "response-decision",
                "close-dispatch", "close-enter", "destroy-enter", "destroy-leave", "close-ack", "close-leave",
                "release-dispatch", "release-enter", "handlers-detached", "topology-retired", "released", "release-leave", "coordinator-joined")
    for n in range(1, 6):
        f: dict[str, int] = {}
        for kind in ordinary:
            detail = {"coordinator-registered": 1 if n >= 4 else 0,
                      "construct-enter": 1 if n <= 2 else 2 if n == 3 else 3,
                      "response-decision": 0 if n == 1 else 2 if n == 4 else 1}.get(kind, 1)
            main = False if kind.endswith("-dispatch") else None if kind in ("coordinator-registered", "coordinator-joined") else True
            require(len(events.matching(kind, n)) == 1, "exact original coordinator/native callback roster")
            f[kind] = events.one(kind, n, detail, main=main)
        responses, leaves = events.matching("response-enter", n), events.matching("response-leave", n)
        require(1 <= len(responses) <= 2 and len(responses) == len(leaves), "bounded real response/disposal callback multiplicity")
        for index, (enter, leave) in enumerate(zip(responses, leaves, strict=True)):
            a, b = events.use(enter, main=True), events.use(leave, main=True)
            require(a < b and leave["detail"] == 1, "original native response unwind")
            if index == 0:
                require(enter["detail"] == (1 if n in (2, 3, 5) else 2), "first actual Accept/Cancel response class")
            else:
                require(enter["detail"] == 3, "only close-generated DeleteEvent extra response")
                disposal_response_order(f, a, b)
        first_enter, first_leave = responses[0]["ordinal"], leaves[0]["ordinal"]
        f["response-enter"], f["response-leave"] = first_enter, first_leave
        require(stages[n] < f["coordinator-registered"] < f["construct-dispatch"] < f["construct-enter"] < f["adopted"] < f["topology-tagged"]
                < f["show"] < f["topology-checked"] < native[n] < first_enter < f["response-decision"] < first_leave < f["close-enter"],
                "original construction/topology/checkpoint/decision/unwind order")
        disposal_order(f)
        require(f["handlers-detached"] < f["topology-retired"] < f["released"], "original weak metadata retired before actual release completion")
        reads = events.matching("filename", n)
        require(len(reads) == (1 if n in (2, 3) else 0), "exact two accepted filename reads")
        for read in reads:
            require(read["detail"] == 1 and f["response-decision"] < events.use(read, main=True) < first_leave, "filename only once after acceptance/before unwind")
        stop = events.matching("quit-stop", n)
        require(len(stop) == (1 if n == 5 else 0), "STOP only at actual final Quit OK")
        for event in stop:
            require(event["detail"] == 1 and f["response-decision"] < events.use(event, main=True) < first_leave, "actual immediate STOP before response unwind")
        g = bridge.records[f"d{n}.go.json"].value
        require(g["operation"] == n and g["showOrdinal"] == f["show"] and g["producerOrdinal"] == native[n], "independent prefix/native GO original ordinal binding")
        retirement = ownerships[n - 1]
        closed(retirement, "proof retireOrdinal", ordered=False)
        proof = retirement["proof"]
        ownership_schema(proof, bridge.records["admission.json"].digest, n, ordered=False)
        fixed(proof, g["ownership"])
        require(proof["tagOrdinal"] == f["topology-tagged"] and proof["checkOrdinal"] == f["topology-checked"]
                and u(retirement["retireOrdinal"], 512, 1) == f["topology-retired"], "original GO proof and actual topology events/retirement linked")
        # The source-bound n5 retirement additionally follows all main weak
        # registration drops. This scalar is not native destroy/unwind evidence;
        # every original response/destroy/release/join check remains independent.
        if n < 5:
            require(f["coordinator-joined"] < stages[n + 1], "original disposal/join before next action")
        facts[n] = f
    stimuli, prevented = events.matching("close-stimulus"), events.matching("close-prevented")
    require(len(stimuli) == len(prevented) == 3, "three actual main-window Close stimuli/preventions")
    for n, stimulus, prevent in zip((1, 4, 5), stimuli, prevented, strict=True):
        require(stimulus["operation"] == prevent["operation"] == 0 and stimulus["detail"] == prevent["detail"] == 1, "fixed Close stimulus/response kind")
        a, b = events.use(stimulus, main=False), events.use(prevent, main=True)
        require(stages[n] < a < b < native[n], "actual prevented Close before native input gate")
        if n == 1:
            require(facts[1]["show"] < a and b < facts[1]["topology-checked"], "same original chooser shown/preserved before topology recheck")
        else:
            require(b < facts[n]["coordinator-registered"], "actual Close prevention precedes original quit construction")
    registered, joined = events.matching("child-registered"), events.matching("child-joined")
    require([(event["operation"], event["detail"]) for event in registered] == [(2, 1), (3, 2), (3, 3)]
            and [(event["operation"], event["detail"]) for event in joined] == [(2, 3), (3, 5), (3, 7)], "Probe/Tokens/Capture separate original incarnations")
    child_facts: dict[tuple[int, int], tuple[int, int]] = {}
    for op, tag in ((2, 1), (3, 2), (3, 3)):
        a, b = events.one("child-registered", op, tag, main=False), events.one("child-joined", op, tag * 2 + 1, main=False)
        require(facts[op]["coordinator-registered"] < a < b < facts[op]["coordinator-joined"], "registered original child positively joined before coordinator")
        if tag == 2:
            require(b < facts[3]["construct-dispatch"], "original Tokens child joins before chooser/capture reuse")
        else:
            require(facts[op]["release-leave"] < a, "original GUI release before Probe/Capture acquisition")
        child_facts[(op, tag)] = (a, b)
    header = events.one("header-observed", 3, main=False)
    require(child_facts[(3, 3)][0] < header < child_facts[(3, 3)][1], "header in original closed-source Capture incarnation")
    project, candidate = events.one("project-published", 2), events.one("candidate-published", 3)
    require(facts[2]["coordinator-joined"] < project < commands[("project", 2)]["returned"] < stages[3]
            and facts[3]["coordinator-joined"] < candidate < stages[4], "real project/candidate publication only after original joins")
    require(commands[("project", 1)]["entered"] < facts[1]["coordinator-registered"] < facts[1]["coordinator-joined"] < commands[("project", 1)]["returned"]
            and commands[("project", 2)]["entered"] < facts[2]["coordinator-registered"]
            and commands[("choose", 3)]["entered"] < facts[3]["coordinator-registered"] < commands[("choose", 3)]["returned"], "real command/original operation correlation")
    relay, recipe = events.one("relay-joined", 0, main=False), events.one("recipe-returned", 0, main=False)
    require(facts[5]["coordinator-joined"] < relay and facts[5]["response-leave"] < recipe, "original final quit/relay/recipe tails")
    events.finish()
    # The candidate/token/context/deadline equality is intentionally private in
    # the source-pinned producer. Do not manufacture independent values or put
    # secret tokens, GTK pointers, paths or deadlines into receipt authority.


def final_facts(data: bytes, bridge: Bridge) -> str:
    value = receipt_data(data)
    closed(value, "scope case status bindings prefixSha256 filesBeforeReceipt lastFile notVerified", ordered=False)
    fixed(value["scope"], SCOPE)
    fixed(value["case"], CASE)
    fixed(value["status"], "preclosed-fixture-only")
    fixed(value["bindings"], {"sourceSha": bridge.freeze.source_sha, "frontendSha256": bridge.freeze.frontend_sha,
          "artifactSha256": bridge.build["appBinary"], "pythonSha256": bridge.build["pythonRuntime"], "sourceHashes": bridge.freeze.sources,
          "native": {"profile": PROFILE, "admissionSha256": bridge.records["admission.json"].digest, "build": bridge.build}, "fixtureOnly": True})
    h(value["prefixSha256"])
    counts = value["filesBeforeReceipt"]
    closed(counts, "opened closeAttempted closeSettled unknown", ordered=False)
    opened = u(counts["opened"], 511, 1)
    fixed(counts["closeAttempted"], opened)
    fixed(counts["closeSettled"], opened)
    fixed(counts["unknown"], False)
    fixed(value["lastFile"], "positive-consuming-close-before-Exit-witness")
    fixed(value["notVerified"], NOT_VERIFIED)
    # Q's original final-file consuming close increments these by exactly one
    # before arming the sole actual Exit writer. The original whole witness and
    # source/sole-writer pins are necessary; this DATA label cannot prove that.
    return value["prefixSha256"]


@dataclass(frozen=True)
class ReceiptRecord:
    name: str
    data: bytes
    metadata: os.stat_result


@dataclass(frozen=True)
class AcceptedSG1:
    bridge: Bridge
    infrastructure: Infrastructure
    app: Child
    helper: Child
    final: ReceiptRecord
    prefix: ReceiptRecord
    accepted_ns: int


def whole_app(app: Child) -> None:
    require(app.role == "app" and app.complete() and app.wait_ns is not None and not app.book.unknown,
            "original app wait0/both EOFs/readers/positive consuming closes")
    require(app.stdout.count == len(WITNESS) == 18 and bytes(app.stdout.data) == WITNESS
            and app.stdout.checksum.hexdigest() == sha(WITNESS) and app.stderr.count <= 65536, "WHOLE original stdout exactly18B witness, not a prefix")


def original_receipt(bridge: Bridge, name: str) -> ReceiptRecord:
    require(name in ("final.json", "prefix.json") and bridge.app is not None and bridge.end is not None
            and now() < bridge.end and not bridge.book.unknown and name not in bridge.receipt_started, "one final original receipt read")
    whole_app(bridge.app)  # mandatory BEFORE final or prefix acquisition
    require((name == "final.json" and not bridge.receipts) or (name == "prefix.json" and set(bridge.receipts) == {"final.json"}), "final first, linked prefix once")
    bridge.receipt_started.add(name)  # no retry, even when first open/read fails
    data, metadata = bridge.book.read(bridge.app_root / name, 65536, private=True)
    original = ReceiptRecord(name, data, metadata)
    bridge.receipts[name] = original  # retain bytes/stat BEFORE parsing/checks
    return original


def case_run(book: FileBook, freeze: Freeze, libc: NativeLibC) -> AcceptedSG1:
    require(not ORIGINAL_CHILDREN and not ORIGINAL_STREAMS and not ORIGINAL_PROTOCOLS and not ORIGINAL_SOCKETS and not ORIGINAL_BRIDGES
            and not book.unknown and all(owner.live is None and owner.receipt is not None and not owner.unknown for owner in book.originals),
            "one SG1 only; no outstanding/unknown original before fixture")
    freeze.recheck(book)
    outer = process(book, os.getpid())
    require(outer["executable"] == {"file": identity(os.lstat(freeze.python)), "sha256": freeze.artifacts["python"]}, "actual original outer interpreter")
    bridge = Bridge(book, freeze, libc, outer)
    infrastructure = Infrastructure.start(book, freeze)
    bridge.infrastructure = infrastructure
    freeze.recheck(book)
    helper_start = now()
    helper_environment = {**infrastructure.environment, "MRK_SESSION_GTK_ROOT": str(bridge.root), "MRK_SESSION_GTK_CASE": CASE,
                          "MRK_NATIVE_BINDING": bridge.binding, "MRK_NATIVE_HELPER_SHA256": freeze.artifacts["helper"], "MRK_NATIVE_HELPER_SPAWN_NS": str(helper_start)}
    helper = spawn(book, "helper", freeze.helper, (str(freeze.helper),), helper_environment, spawn_ns=helper_start)
    freeze.check_child(helper)
    ready = bridge.ready(helper, infrastructure)
    prelaunch_end = min(plus(d(ready.value["writtenNs"]), 5 * NS), plus(helper.spawn_ns, 10 * NS))
    freeze.check_loader(book)
    progress(ORIGINAL_CHILDREN, 5)
    require(now() < prelaunch_end and not book.unknown and helper.status is None
            and all(child.status is None for child in infrastructure.children.values()), "actual authenticated host/helper readiness before witness pipe creation")
    # Every original infrastructure/helper already exists BEFORE spawn creates
    # the app witness pipe. File actions exclude our original aliases; this is
    # necessary but never a substitute for the separate descendant/writer audit.
    app_environment = {**infrastructure.environment, "MRK_SESSION_GTK_ROOT": str(bridge.root), "MRK_SESSION_GTK_CASE": CASE,
                       "MRK_SESSION_GTK_SCOPE": SCOPE, "MRK_SESSION_GTK_SOURCE_SHA": freeze.source_sha,
                       "MRK_SESSION_GTK_FRONTEND_SHA256": freeze.frontend_sha, "MRK_DESKTOP_DEV_CORE": str(freeze.repository / "src"),
                       "MRK_DESKTOP_DEV_PYTHON": str(freeze.python)}
    app = spawn(book, "app", freeze.app, (str(freeze.app),), app_environment)
    freeze.check_child(app)
    require(app.spawn_ns <= prelaunch_end, "original app spawn endpoint, not a renewed timeout")
    bridge.admit(app, infrastructure)
    bridge.dialogs()  # helper wait/EOF/close -> helper-settled WHILE app is live
    require(bridge.end is not None, "fixed original outer endpoint")
    while now() < bridge.end and not app.complete() and not book.unknown:
        progress(ORIGINAL_CHILDREN)
    whole_app(app)
    require(now() < bridge.end and helper.complete() and all(child.status is None for child in infrastructure.children.values()), "app completed before endpoint over original infrastructure")
    # Never read incomplete or an early prefix. Only after the original wait0,
    # both EOFs/readers/consuming closes and WHOLE witness do these reads occur.
    final = original_receipt(bridge, "final.json")
    prefix_sha = final_facts(final.data, bridge)
    prefix = original_receipt(bridge, "prefix.json")
    require(sha(prefix.data) == prefix_sha, "original final binds exact one-read prefix bytes")
    prefix_facts(prefix.data, bridge)
    bridge.final_layout()
    freeze.recheck(book)
    for original in (final, prefix):
        require(stable(original.metadata, os.lstat(bridge.app_root / original.name)), "checked original receipt changed; never reopen")
    require(now() < bridge.end and not book.unknown and helper.complete(), "original receipt/source/helper custody conjunction")
    # Only now may separately audited infrastructure request its own orderly
    # normal return. This cannot repair any app/helper/callback/file uncertainty.
    infrastructure.teardown(bridge.end)
    bridge.metadata_inventory()
    for original in (final, prefix):
        require(stable(original.metadata, os.lstat(bridge.app_root / original.name)), "original final/prefix changed during normal teardown")
    require(len(ORIGINAL_CHILDREN) == 7 and len(ORIGINAL_STREAMS) == 14 and all(child.complete() for child in ORIGINAL_CHILDREN)
            and all(owner.live is None and owner.receipt is not None and not owner.unknown for owner in book.originals)
            and infrastructure.native_connections_closed and not book.unknown and now() < bridge.end, "complete separate original infrastructure/descriptor custody")
    return AcceptedSG1(bridge, infrastructure, app, helper, final, prefix, now())


def hold_unknown(book: FileBook) -> None:
    """No timeout is cancellation; retain originals and bounded-storage drainage.

    No kill, abort, new signal, VM deletion, wait/read/close retry, late acceptance
    or replacement/next case. An uncertain original may intentionally keep this
    failed outer alive until the independently responsible disposable-host owner
    intervenes. Pending control frames and original books remain in memory.
    """
    while any(child.status is None or not child.stdout.eof or not child.stderr.eof for child in ORIGINAL_CHILDREN) or any(owner.live is not None for owner in book.originals):
        try:
            progress(ORIGINAL_CHILDREN, 50)
        except BaseException:
            book.fail("original failure drainage unknown")
            time.sleep(0.05)


def main() -> int:
    book = FileBook()
    try:
        freeze = Freeze.admit(book)  # None pins refuse before owned acquisition
        libc = NativeLibC(freeze.libc)
        freeze.check_loader(book)
        accepted = case_run(book, freeze, libc)
        require(accepted.bridge is ORIGINAL_BRIDGES[0] and len(ORIGINAL_BRIDGES) == 1 and not book.unknown, "one actual original SG1 conjunction")
        # Memory-only decision after the whole conjunction; not an app witness,
        # persisted certificate, production enablement or another-case permit.
        report = b"session-gtk: original SG1 fixture-only conjunction accepted\n"
        require(os.write(1, report) == len(report), "outer final report write incomplete")
        return 0
    except BaseException:
        book.fail("SG1 qualification Unknown; originals retained")
        try:
            os.write(2, b"session-gtk: Unknown; no next case; original custody retained\n")
        except OSError:
            pass  # one diagnostic attempt, never a retry or evidence of success
        hold_unknown(book)
        return 2


def inert_source_tests() -> None:
    """Focused pure proposals, never called by main; NOT executed/qualified.

    Separate exact pure-check admission is required. Only bounded literal DATA,
    scanner/type checks and Q1 ordinal relations are exercised. No process, FD,
    native schema clock, GTK, file reads, mock owner or qualification receipt.
    These can reject an oracle bug, never prove native API/custody behavior.
    """
    def rejects(function: Any, *args: Any) -> None:
        try:
            function(*args)
        except (Refused, UnicodeError, ValueError):
            return
        raise AssertionError("inert mutation accepted")

    for raw in (b'{"a":1,"a":2}', b'{"a":-1}', b'{"a":1.0}', b'{"a":1}x', b'{"a":18446744073709551616}', b'{"a":"\\u0000"}'):
        rejects(lambda data: FiniteJson(data, native=False).parse(lf=False), raw)
    rejects(fixed, {"done": 1}, {"done": True})
    source_map = {path: "a" * 64 for path in SOURCES}
    raw = json.dumps({"sourceHashes": source_map}, separators=(",", ":")).encode("ascii")
    fixed(FiniteJson(raw, native=False).parse(lf=False), {"sourceHashes": source_map})
    longest = max(SOURCES, key=len)
    assert len(SOURCES) == 220 and 64 < len(longest) <= 128 and len(WITNESS) == 18
    raw = (json.dumps({longest: "a" * 64}, separators=(",", ":")) + "\n").encode("ascii")
    rejects(lambda data: FiniteJson(data, native=True).parse(lf=True), raw)
    base = {"response-decision": 1, "response-leave": 3, "close-dispatch": 2, "close-enter": 4, "close-ack": 5, "close-leave": 6,
            "destroy-enter": 9, "destroy-leave": 11, "release-dispatch": 10, "release-enter": 12, "handlers-detached": 13,
            "released": 14, "release-leave": 15, "coordinator-joined": 16}
    disposal_order(base)  # release dispatch BETWEEN destroy enter/leave is legal
    disposal_order({**base, "destroy-leave": 10, "release-dispatch": 11})  # or after unwind
    disposal_order({**base, "response-leave": 2, "close-dispatch": 3})  # either side of first response leave
    synchronous = {**base, "destroy-enter": 5, "destroy-leave": 6, "close-ack": 7, "close-leave": 8,
                   "release-dispatch": 9, "release-enter": 10, "handlers-detached": 11, "released": 12,
                   "release-leave": 13, "coordinator-joined": 14}
    rejects(disposal_order, synchronous)
    rejects(disposal_order, {**base, "release-dispatch": 8})
    rejects(disposal_order, {**base, "destroy-leave": 13, "handlers-detached": 14, "released": 15, "release-leave": 16, "coordinator-joined": 17})
    rejects(disposal_order, {**base, "response-decision": True})
    disposal_response_order(base, 7, 8)
    for enter, leave in ((5, 6), (9, 10), (8, 7)):
        rejects(disposal_response_order, base, enter, leave)


if __name__ == "__main__":
    raise SystemExit(main())
