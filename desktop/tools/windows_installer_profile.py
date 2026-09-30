"""Compile-input DATA for the fixed Windows54 acquisition owner, not a launcher.

The caller must admit/retain the real source, tools, control and profile originals
and bind the complete compiler environment. Hash-bound supplied assertions are
not supplier authenticity, native observations or installer qualification.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "_mrk_windows_installer_profile_source", Path(__file__).with_name("windows_installer_source.py")
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Fixed Windows DATA3 source validator is unavailable")
source = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(source)
staging = source.staging
ProfileError = source.SourceError
require = source.require

MAX_PROFILE_BYTES = 8192
# These are roles, not another literal runtime roster or destination mapping.
OPAQUE_ORDER = ("publisher", "shell", "webview2", "applicationNotices", "webview2Notices")


def render_profile(inventory: bytes, admission: bytes, *, expected_inventory: str,
                   expected_admission: str) -> bytes:
    """Return one bounded canonical ASCII54-row profile, with no IO or execution.

    The exact input byte lengths and supplied digests bind both original controls.
    Nothing accepts a path, destination, executable source or runtime override.
    The separately built bridge is outside the52 payloads/54 acquisition inputs.
    """
    data, assertions = source._inputs(inventory, admission, expected_inventory, expected_admission)
    runtime = [row for row in data["files"] if row["role"] == "runtimeInput"]
    prefix = "runtime-input/" + staging.TARGET + "/" + assertions["runtimeManifestSha256"] + "/"
    require(len(runtime) == 47 and runtime[7]["path"] == prefix + "manifest.json"
            and runtime[7]["sha256"] == assertions["runtimeManifestSha256"],
            "Fixed acquisition runtime order or manifest binding differs")
    require(runtime[7]["size"] <= staging.MAX_MANIFEST_BYTES,
            "The acquisition runtime manifest exceeds its bound")
    require(2 * sum(row["size"] for row in runtime) <= staging.MAX_STAGE_BYTES,
            "Runtime inputs exceed the downstream publisher's two-read capacity")
    require(len(OPAQUE_ORDER) == 5 and set(OPAQUE_ORDER) == set(staging.OPAQUE_OUTPUTS),
            "Fixed acquisition opaque roles changed")
    by_path = {row["path"]: row for row in data["files"]}
    ordered = runtime + [by_path[staging.OPAQUE_OUTPUTS[role][0]] for role in OPAQUE_ORDER]
    rows = [{"size": row["size"], "sha256": row["sha256"]} for row in ordered]
    rows += [{"size": len(admission), "sha256": expected_admission},
             {"size": len(inventory), "sha256": expected_inventory}]
    require(len(rows) == 54, "Fixed acquisition input count differs")
    profile = {
        "schemaVersion": 1, "purpose": "windows-installer-acquisition-profile",
        "inputAssertions": "supplied-not-observed",
        **{key: assertions[key] for key in staging.COMMON_BINDINGS},
        "publisherSha256": assertions["publisher"]["sha256"],
        "admissionSha256": expected_admission, "inventorySha256": expected_inventory,
        "inputs": rows,
    }
    # No newline: these are bounded compile-time env! bytes, not a DATA3 file.
    result = json.dumps(profile, ensure_ascii=True, allow_nan=False,
                        sort_keys=True, separators=(",", ":")).encode("ascii")
    require(0 < len(result) <= MAX_PROFILE_BYTES, "Compiled input profile exceeds its bound")
    return result
