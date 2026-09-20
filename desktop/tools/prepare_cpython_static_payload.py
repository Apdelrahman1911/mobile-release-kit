"""Closed, host-only offline copy profile for the proposed direct CPython build.

No subprocess, candidate import, archive extraction, native query, strip, generic
preparer invocation or approval flag. A later source review must bind accepted
output, original-link provenance and public-notice hashes. Private policies are
only inert algorithm fixtures, never production admission or legal clearance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import NamedTuple

PROFILE = "cpython-3.14.7-linux-x86_64-static-v1"
TARGET = "x86_64-unknown-linux-gnu"
APPROVED_OUTPUT_INVENTORY_SHA256: str | None = None
APPROVED_STATIC_LINK_PROVENANCE_SHA256: str | None = None
APPROVED_NOTICE_INVENTORY_SHA256: str | None = None
LICENSE_BYTES = 13804
LICENSE_SHA256 = "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231"

# The generic preparer alone adds core.zip, six bootstraps, the CA and manifest.
MAX_FILES = 2048
MAX_ENTRIES = 8192
MAX_PATH_PARTS = 16
MAX_PATH_BYTES = 512
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
RESERVED_PAYLOAD_FILES = (
    "core.zip", "engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
    "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py", "github-ca.pem",
)
RESERVED_ENTRIES = len(RESERVED_PAYLOAD_FILES) + 1
# Unchanged aggregate reserve: core plus ZIP overhead, six bounded bootstraps,
# the fixed CA and final manifest. This is not a larger supplier byte budget.
RESOURCE_BYTE_HEADROOM = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_NODES = 20_000
MANIFEST_METADATA_HEADROOM = 4096
MAX_STAGE_FILES = 50000
MAX_STAGE_ENTRIES = 100000
MAX_STAGE_BYTES = 4 * 1024 * 1024 * 1024
MAX_EVIDENCE_FILES = 150000
MAX_EVIDENCE_ENTRIES = 200000
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 1024 * 1024 * 1024
MAX_INVENTORY_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_NOTICE_FILES = 128
MAX_NOTICE_ENTRIES = 512
MAX_NOTICE_BYTES = 2 * 1024 * 1024
MAX_NOTICE_INVENTORY_BYTES = 128 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
_STDLIB = "lib/python3.14/"
_EXEC_SOURCE = "bin/python3.14"
_EXEC_DESTINATION = "python/bin/python3"
_LICENSE_SOURCE = _STDLIB + "LICENSE.txt"
_SYSCONFIG_PY = _STDLIB + "_sysconfigdata__linux_x86_64-linux-gnu.py"
_SYSCONFIG_JSON = _STDLIB + "_sysconfig_vars__linux_x86_64-linux-gnu.json"
_BUILD_DETAILS = _STDLIB + "build-details.json"
_REQUIRED = frozenset({_EXEC_SOURCE, _LICENSE_SOURCE, _STDLIB + "os.py",
                       _STDLIB + "encodings/__init__.py", _SYSCONFIG_PY, _SYSCONFIG_JSON, _BUILD_DETAILS})
_EXCLUDED = frozenset({"test", "ensurepip", "idlelib", "turtledemo", "venv", "site-packages"})
_PHASES = ("zlib-configure", "zlib-build", "zlib-install", "libffi-configure", "libffi-build",
           "libffi-install", "python-configure", "hacl-build", "python-build", "python-install")
_GENERATED = (
    ("python/lib/python314.zip", b"PK\x05\x06" + b"\0" * 18, "empty-zip-v1"),
    ("python/lib/python3.14/lib-dynload/README.mrk",
     b"No shared extension modules are shipped in this profile.\n", "static-module-landmark-v1"),
)
_SENTINEL = b"INCOMPLETE publisher output; not an admitted runtime or handoff.\n"
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
             *(f"lpt{i}" for i in range(1, 10))}


class PayloadError(ValueError):
    pass


class _Policy(NamedTuple):
    output_inventory_sha256: str | None
    provenance_sha256: str | None
    notice_inventory_sha256: str | None
    license_size: int
    license_sha256: str


_PRODUCTION_POLICY = _Policy(APPROVED_OUTPUT_INVENTORY_SHA256, APPROVED_STATIC_LINK_PROVENANCE_SHA256,
                             APPROVED_NOTICE_INVENTORY_SHA256, LICENSE_BYTES, LICENSE_SHA256)

# Separate literal source-built/projected origin. These do not relax legacy
# original-link semantics or inherit any TLS/private-W acceptance.
SOURCE_PROFILE = "cpython-3.14.7-linux-x86_64-source-v1"
APPROVED_SOURCE_OUTPUT_SHA256: str | None = None
APPROVED_SOURCE_COMPONENTS_SHA256: str | None = None
APPROVED_SOURCE_NOTICES_SHA256: str | None = None


class _SourcePolicy(NamedTuple):
    output_inventory_sha256: str | None
    components_sha256: str | None
    notice_inventory_sha256: str | None
    license_size: int
    license_sha256: str


_SOURCE_PRODUCTION_POLICY = _SourcePolicy(APPROVED_SOURCE_OUTPUT_SHA256, APPROVED_SOURCE_COMPONENTS_SHA256,
    APPROVED_SOURCE_NOTICES_SHA256, LICENSE_BYTES, LICENSE_SHA256)


class _Item(NamedTuple):
    path: str
    content: bytes
    origin: dict


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PayloadError(message)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii") + b"\n"


def _keys(value: object, wanted: set[str]) -> dict:
    _need(type(value) is dict and set(value) == wanted, "Unexpected or missing publisher record fields")
    return value


def _sha(value: object) -> str:
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "Invalid SHA256")
    return value


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        _need(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def _decode(raw: bytes) -> object:
    _need(len(raw) <= MAX_INVENTORY_BYTES, "JSON byte ceiling exceeded")
    def nonfinite(_value: str) -> None:
        raise PayloadError("Nonfinite JSON value")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=nonfinite)
        _need(_canonical(value) == raw, "Noncanonical publisher JSON")
        return value
    except (UnicodeError, ValueError, RecursionError, TypeError):
        raise PayloadError("Invalid canonical publisher JSON") from None


def _version(record: dict) -> None:
    _need(type(record["schemaVersion"]) is int and record["schemaVersion"] == 1, "Unsupported schema version")


def _safe_name(name: str) -> bool:
    return (re.fullmatch(r"[A-Za-z0-9._+\-]+", name, flags=re.ASCII) is not None
            and name not in {".", ".."} and not name.endswith(".")
            and name.split(".", 1)[0].lower() not in _RESERVED)


def _relative(value: object) -> str:
    _need(type(value) is str and 0 < len(value) <= MAX_PATH_BYTES, "Invalid relative publisher path")
    parts = value.split("/")
    _need(len(parts) <= MAX_PATH_PARTS and all(_safe_name(part) for part in parts), "Nonportable publisher path")
    return value


def _absolute(path: Path) -> Path:
    _need(path.is_absolute() and ".." not in path.parts, "Explicit absolute local paths required")
    return path


def _state(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _ordinary(path: Path, *, directory: bool = False) -> os.stat_result:
    value = path.lstat()
    _need(not getattr(value, "st_file_attributes", 0) & 0x400
          and (stat.S_ISDIR(value.st_mode) if directory else
               stat.S_ISREG(value.st_mode) and value.st_nlink == 1), "Only ordinary directories/single-link files admitted")
    return value


def _directory(path: Path) -> Path:
    _absolute(path)
    for ancestor in reversed((path, *path.parents)):
        _ordinary(ancestor, directory=True)
    return path


def _absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise PayloadError("Output/report must be absent; no overwrite, adoption or cleanup")


def _read_checked(path: Path, *, limit: int) -> bytes:
    _directory(path.parent)
    before = _ordinary(path)
    _need(0 <= before.st_size <= limit, "Input byte ceiling exceeded")
    with path.open("rb") as stream:
        _need(_state(os.fstat(stream.fileno())) == _state(before), "Input changed before reading")
        raw = stream.read(before.st_size + 1)
        _need(_state(os.fstat(stream.fileno())) == _state(before), "Input changed during reading")
    _need(len(raw) == before.st_size and _state(path.lstat()) == _state(before), "Input changed after reading")
    return raw


def _checked(path: Path, expected: str, *, limit: int, size: int | None = None) -> bytes:
    raw = _read_checked(path, limit=limit)
    _need(_digest(raw) == _sha(expected) and (size is None or len(raw) == size), "Pinned input hash/size differs")
    return raw


def _record(value: object, *, limit: int, absolute: bool = False) -> dict:
    value = _keys(value, {"path", "size", "sha256"})
    if absolute:
        _need(type(value["path"]) is str, "Host input path must be text")
        _absolute(Path(value["path"]))
    else:
        _relative(value["path"])
    _need(type(value["size"]) is int and 0 <= value["size"] <= limit, "Invalid pinned file size")
    _sha(value["sha256"])
    return value


def _records(values: object, *, max_files: int, max_bytes: int, file_limit: int,
             absolute: bool = False) -> dict[str, dict]:
    _need(type(values) is list and 0 < len(values) <= max_files, "Inventory count exceeded or missing")
    result, total = {}, 0
    for value in values:
        value = _record(value, limit=file_limit, absolute=absolute)
        _need(value["path"] not in result, "Duplicate inventory path")
        result[value["path"]] = value
        total += value["size"]
    _need(list(result) == sorted(result) and total <= max_bytes, "Unsorted or excessive inventory")
    return result


def _ancestors(names) -> set[str]:
    result = set()
    for name in names:
        parts = name.split("/")
        result.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return result


def _tree(root: Path, *, max_files: int, max_entries: int, allow_listed_empty: bool = False) -> tuple[dict[str, Path], set[str]]:
    _directory(root)
    files, directories, seen, pending = {}, set(), set(), [root]
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as children:
            for child in children:
                path = parent / child.name
                name = _relative(path.relative_to(root).as_posix())
                _need(name.lower() not in seen and len(seen) < max_entries, "Tree collision/entry ceiling exceeded")
                seen.add(name.lower())
                value = path.lstat()
                if stat.S_ISDIR(value.st_mode):
                    _ordinary(path, directory=True)
                    directories.add(name)
                    pending.append(path)
                else:
                    _ordinary(path)
                    files[name] = path
                    _need(len(files) <= max_files, "Tree file ceiling exceeded")
    _need(allow_listed_empty or directories == _ancestors(files), "Empty or uninventoried directory")
    return files, directories


def _require_policy(policy: _Policy) -> None:
    # First operation, before ANY path inspection, file read or output creation.
    _need(all(value is not None for value in policy[:3]),
          "Production preparation is closed: accepted output, original-link and public-notice anchors are missing")
    for value in (*policy[:3], policy.license_sha256):
        _sha(value)
    _need(type(policy.license_size) is int and 0 < policy.license_size <= MAX_NOTICE_BYTES, "Invalid license policy")


def _host_inputs(raw: bytes, policy: _Policy) -> None:
    """Hash-check the independently reviewed host closure, not discover it."""
    document = _keys(_decode(raw), {"schemaVersion", "hostPython", "files"})
    _version(document)
    interpreter = _record(document["hostPython"], limit=MAX_EVIDENCE_FILE_BYTES, absolute=True)
    records = _records(document["files"], max_files=MAX_EVIDENCE_FILES, max_bytes=MAX_EVIDENCE_BYTES,
                       file_limit=MAX_EVIDENCE_FILE_BYTES, absolute=True)
    _need(records.get(interpreter["path"]) == interpreter, "Host Python missing from pinned host closure")
    if policy is _PRODUCTION_POLICY or policy is _SOURCE_PRODUCTION_POLICY:
        _need(os.path.realpath(sys.executable) == interpreter["path"] and sys.flags.isolated == 1
              and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
              "Use only the pinned host Python with -I -S -B; never the candidate")
    # Private fixtures only bind inert file data, and are always labelled as tests.
    for value in records.values():
        _checked(Path(value["path"]), value["sha256"], size=value["size"], limit=MAX_EVIDENCE_FILE_BYTES)


def _output_inventory(raw: bytes) -> dict:
    document = _keys(_decode(raw), {"schemaVersion", "profile", "target", "inputLockSha256",
                                   "hostInputsSha256", "stage", "finalInterpreter"})
    _version(document)
    _need(document["profile"] == PROFILE and document["target"] == TARGET, "Wrong output profile/target")
    _sha(document["inputLockSha256"])
    _sha(document["hostInputsSha256"])
    stage = _keys(document["stage"], {"sourcePrefix", "files", "directories"})
    _need(stage["sourcePrefix"] == "/work/stage/opt/mrk-python", "Wrong original stage prefix")
    records = _records(stage["files"], max_files=MAX_STAGE_FILES, max_bytes=MAX_STAGE_BYTES,
                       file_limit=MAX_FILE_BYTES)
    directories = stage["directories"]
    _need(type(directories) is list and len(directories) <= MAX_STAGE_ENTRIES
          and all(type(p) is str for p in directories), "Invalid stage directory roster")
    for name in directories:
        _relative(name)
    _need(directories == sorted(set(directories)), "Duplicate/unsorted stage directories")
    final = _keys(document["finalInterpreter"], {"stagePath", "linkId", "receiptSha256", "size", "sha256"})
    _need(final["stagePath"] == _EXEC_SOURCE and type(final["linkId"]) is str
          and re.fullmatch(r"link-[0-9]{6}", final["linkId"]) is not None, "Wrong final interpreter/link identity")
    _sha(final["receiptSha256"])
    final_record = _record({"path": final["stagePath"], "size": final["size"], "sha256": final["sha256"]}, limit=MAX_FILE_BYTES)
    _need(records.get(_EXEC_SOURCE) == final_record and final["size"] > 0, "Interpreter not bound to stage inventory")
    return document


def _retained(value: object, records: dict[str, dict]) -> dict:
    value = _keys(value, {"object", "size", "sha256"})
    _sha(value["sha256"])
    _need(value["object"] == "objects/" + value["sha256"], "Noncanonical retained object reference")
    record = {"path": value["object"], "size": value["size"], "sha256": value["sha256"]}
    _record(record, limit=MAX_EVIDENCE_FILE_BYTES)
    _need(records.get(value["object"]) == record, "Referenced original object absent from provenance inventory")
    return record


def _provenance(root: Path, raw: bytes, output: dict, notice_sha256: str) -> dict:
    document = _keys(_decode(raw), {"schemaVersion", "profile", "inputLockSha256", "noticeInventorySha256",
                                   "files", "linkedInputClosure", "dynamicClosure"})
    _version(document)
    _need(document["profile"] == PROFILE and document["inputLockSha256"] == output["inputLockSha256"]
          and document["noticeInventorySha256"] == notice_sha256, "Provenance/profile/notice binding differs")
    records = _records(document["files"], max_files=MAX_EVIDENCE_FILES, max_bytes=MAX_EVIDENCE_BYTES,
                       file_limit=MAX_EVIDENCE_FILE_BYTES)
    _need("CAPTURE-FAILED.json" not in records, "Original recorder failure cannot be admitted")
    actual, _ = _tree(root, max_files=MAX_EVIDENCE_FILES, max_entries=MAX_EVIDENCE_ENTRIES)
    _need(actual.keys() == records.keys(), "Original evidence files are extra, missing or renamed")
    # Every original byte, not only the final-link summary, remains required.
    for name, value in records.items():
        _checked(actual[name], value["sha256"], size=value["size"], limit=MAX_EVIDENCE_FILE_BYTES)
    for name in ("linkedInputClosure", "dynamicClosure"):
        value = _record(document[name], limit=MAX_RECEIPT_BYTES)
        _need(records.get(value["path"]) == value and value["size"] > 0, "Reviewed closure evidence absent")
    for phase in _PHASES:
        name = phase + ".json"
        _need(name in records and phase + ".log" in records, "Original build phase evidence missing")
        status = _keys(_decode(_read_checked(actual[name], limit=MAX_RECEIPT_BYTES)),
                       {"schemaVersion", "inputLockSha256", "phase", "originalExitCode", "logSha256",
                        "ignoredInstallError", "captureFailure", "incompleteLinkCaptures"})
        _version(status)
        _need(status["inputLockSha256"] == output["inputLockSha256"] and status["phase"] == phase
              and type(status["originalExitCode"]) is int and status["originalExitCode"] == 0
              and status["ignoredInstallError"] is False and status["captureFailure"] is False
              and status["incompleteLinkCaptures"] == []
              and status["logSha256"] == records[phase + ".log"]["sha256"], "Original build phase was not clean")
        if phase in {"python-configure", "python-build", "python-install"}:
            audit = records.get(phase + "-configuration.json")
            _need(audit is not None and audit["size"] > 0, "Generated-configuration source audit missing")
    final = output["finalInterpreter"]
    receipt_name = final["linkId"] + "/receipt.json"
    expected = records.get(receipt_name)
    _need(expected is not None and expected["sha256"] == final["receiptSha256"], "Original final-link receipt differs")
    receipt = _keys(_decode(_checked(actual[receipt_name], expected["sha256"], size=expected["size"], limit=MAX_RECEIPT_BYTES)),
        {"schemaVersion", "inputLockSha256", "linkId", "phase", "kind", "originalResult", "originalArgvSha256",
         "effectiveArgvSha256", "expandedArgvSha256", "cwd", "environmentSha256", "responseFiles", "linkerSha256",
         "stdout", "stderr", "analysisComplete", "artifacts", "inputs", "processFiles", "outputPath", "beforeLinkOutput"})
    _version(receipt)
    _need(receipt["inputLockSha256"] == output["inputLockSha256"] and receipt["linkId"] == final["linkId"]
          and receipt["kind"] == "linked" and _canonical(receipt["originalResult"]) == b'{"code":0,"kind":"exit"}\n'
          and receipt["analysisComplete"] is True and receipt["phase"] in {"python-build", "python-install"}
          and receipt["cwd"] == "/work/build/cpython" and receipt["outputPath"] == "/work/build/cpython/python",
          "Final output is not tied to a successful original interpreter link")
    for field, suffix in (("originalArgvSha256", "original.argv"), ("effectiveArgvSha256", "effective.argv"),
                          ("expandedArgvSha256", "expanded.argv"), ("environmentSha256", "environment.json")):
        value = records.get(final["linkId"] + "/" + suffix)
        _need(value is not None and value["sha256"] == _sha(receipt[field]), "Original invocation evidence absent")
    result_name = final["linkId"] + "/original-result.json"
    _need(result_name in actual and _read_checked(actual[result_name], limit=MAX_RECEIPT_BYTES) ==
          _canonical({"linkId": final["linkId"], "result": {"kind": "exit", "code": 0}}), "Original native result record differs")
    environment = _decode(_read_checked(actual[final["linkId"] + "/environment.json"], limit=MAX_RECEIPT_BYTES))
    _need(type(environment) is dict and environment.get("PYTHONSTRICTEXTENSIONBUILD") == "1",
          "Original link lacks the locked strict-build environment")
    _sha(receipt["linkerSha256"])
    for field in ("stdout", "stderr"):
        retained = _retained(receipt[field], records)
        original = records.get(final["linkId"] + "/" + field)
        _need(original is not None and (original["size"], original["sha256"]) ==
              (retained["size"], retained["sha256"]), "Original diagnostic/object binding differs")
    _need(type(receipt["responseFiles"]) is list and len(receipt["responseFiles"]) <= 128, "Invalid response evidence")
    for response in receipt["responseFiles"]:
        response = _keys(response, {"path", "object", "size", "sha256"})
        _retained({k: response[k] for k in ("object", "size", "sha256")}, records)
    artifacts = _keys(receipt["artifacts"], {"map", "deps", "output"})
    for name, artifact in artifacts.items():
        _keys(artifact, {"available", "size", "sha256", "retained"} | ({"observation"} if name == "output" else set()))
        _need(artifact["available"] is True and type(artifact["size"]) is int and artifact["size"] > 0,
              "Successful original link artifact unavailable")
        retained = _retained(artifact["retained"], records)
        _need((artifact["size"], artifact["sha256"]) == (retained["size"], retained["sha256"]), "Artifact/object binding differs")
        if name != "output":
            original = records.get(final["linkId"] + "/" + name)
            _need(original is not None and (original["size"], original["sha256"]) ==
                  (retained["size"], retained["sha256"]), "Original map/dependency binding differs")
    _need(artifacts["output"]["observation"] == "successful-original-link-output"
          and (artifacts["output"]["size"], artifacts["output"]["sha256"]) == (final["size"], final["sha256"]),
          "Installed interpreter is not byte-identical to the original final link")
    _need(type(receipt["inputs"]) is list and receipt["inputs"], "Original resolved-input evidence missing")
    before = receipt["beforeLinkOutput"]
    _need(type(before) is dict and type(before.get("available")) is bool, "Invalid pre-link output observation")
    if before["available"]:
        _keys(before, {"available", "retained"})
        _retained(before["retained"], records)
    else:
        _need(before == {"available": False, "reason": "absent-before-link"}, "Invalid absent pre-link observation")
    for item in receipt["inputs"]:
        _keys(item, {"path", "role", "observedRead", "origin", "retained", "selectedMembers"})
        _need(type(item["observedRead"]) is bool and type(item["selectedMembers"]) is list, "Invalid input attribution")
        _retained(item["retained"], records)
        for member in item["selectedMembers"]:
            _keys(member, {"name", "ordinal", "headerOffset", "size", "sha256", "retained"})
            _retained(member["retained"], records)
            _need((member["size"], member["sha256"]) ==
                  (member["retained"]["size"], member["retained"]["sha256"]), "Selected member byte binding differs")
    _need(type(receipt["processFiles"]) is list, "Invalid linker process-file evidence")
    for item in receipt["processFiles"]:
        _keys(item, {"path", "role", "available", "origin", "retained", "notAnIncorporatedArchiveMember"})
        _need(item["available"] is True and item["notAnIncorporatedArchiveMember"] is True,
              "Final-link plugin/process evidence unavailable")
        _retained(item["retained"], records)
    # Closure documents are hash-bound independent review, not re-proved here.
    # This copy helper neither derives a legal SBOM nor parses/runs an ELF image.
    return document


def _stage_items(root: Path, document: dict, policy: _Policy) -> tuple[list[_Item], list[dict]]:
    stage = document["stage"]
    records = {item["path"]: item for item in stage["files"]}
    actual, directories = _tree(root, max_files=MAX_STAGE_FILES, max_entries=MAX_STAGE_ENTRIES, allow_listed_empty=True)
    _need(actual.keys() == records.keys() and directories == set(stage["directories"]), "Reviewed stage roster differs")
    _need(_REQUIRED <= records.keys(), "Required installed interpreter/stdlib/metadata/license missing")
    items, omissions = [], []
    for name, record in sorted(records.items()):
        raw = _checked(actual[name], record["sha256"], size=record["size"], limit=MAX_FILE_BYTES)
        leaf = name.rsplit("/", 1)[-1]
        _need(not (leaf.endswith((".so", ".dylib", ".dll")) or ".so." in leaf),
              "Unexpected shared native output; do not hide it by pruning")
        destination, reason = None, "outside-standalone-payload"
        if name == _EXEC_SOURCE:
            destination = _EXEC_DESTINATION
        elif name == _LICENSE_SOURCE:
            _need((len(raw), _digest(raw)) == (policy.license_size, policy.license_sha256), "CPython LICENSE differs")
            destination = "python/LICENSE.txt"
        elif name.startswith(_STDLIB):
            relative = name[len(_STDLIB):]
            top = relative.split("/", 1)[0]
            if top in _EXCLUDED or top.startswith("config-3.14-"):
                reason = "excluded-stdlib-subtree"
            else:
                if top.startswith(("_sysconfigdata_", "_sysconfig_vars_")):
                    _need(name in {_SYSCONFIG_PY, _SYSCONFIG_JSON}, "Unexpected generated sysconfig ABI/name")
                if name.endswith(".py") or name in {_SYSCONFIG_JSON, _BUILD_DETAILS}:
                    destination = "python/" + name
                else:
                    reason = "non-python-stdlib-data-or-bytecode"
        if destination is None:
            omissions.append({**record, "reason": reason})
        else:
            items.append(_Item(destination, raw, {"kind": "installed-file", "path": name,
                "outputInventorySha256": policy.output_inventory_sha256,
                "originalLinkId": document["finalInterpreter"]["linkId"] if name == _EXEC_SOURCE else None}))
    return items, omissions


def _notice_items(root: Path, raw: bytes, policy: _Policy) -> list[_Item]:
    document = _keys(_decode(raw), {"schemaVersion", "profile", "pythonChangeSummary", "files"})
    _version(document)
    expected_profile = SOURCE_PROFILE if type(policy) is _SourcePolicy else PROFILE
    _need(document["profile"] == expected_profile and document["pythonChangeSummary"] == "PYTHON-CHANGES.txt",
          "A new direct-build Python change summary is required, not the PBS summary")
    records = _records(document["files"], max_files=MAX_NOTICE_FILES, max_bytes=MAX_NOTICE_BYTES,
                       file_limit=MAX_NOTICE_BYTES)
    _need("PYTHON-CHANGES.txt" in records and all(item["size"] > 0 for item in records.values()), "Empty/missing public notice")
    actual, _ = _tree(root, max_files=MAX_NOTICE_FILES, max_entries=MAX_NOTICE_ENTRIES)
    _need(actual.keys() == records.keys(), "Public notice files are extra, missing or renamed")
    return [_Item("python/licenses/" + name,
                  _checked(actual[name], item["sha256"], size=item["size"], limit=MAX_NOTICE_BYTES),
                  {"kind": "public-notice", "path": name, "noticeInventorySha256": policy.notice_inventory_sha256,
                   "pythonChangeSummary": name == "PYTHON-CHANGES.txt"}) for name, item in sorted(records.items())]


def _inventory(items: list[_Item]) -> list[dict]:
    return [{"path": item.path, "size": len(item.content), "sha256": _digest(item.content)}
            for item in sorted(items, key=lambda item: item.path)]


def _preflight_items(items: list[_Item]) -> set[str]:
    namespace, total = {}, 0
    for item in items:
        parts = _relative(item.path).split("/")
        _need(parts[0] == "python" and len(parts) > 1, "Payload must be below python/")
        for count in range(1, len(parts) + 1):
            name, kind = "/".join(parts[:count]), "file" if count == len(parts) else "directory"
            previous = namespace.get(name.lower())
            _need(previous is None or (previous == (name, kind) and kind == "directory"), "Payload path/ancestor collision")
            namespace[name.lower()] = (name, kind)
        _need(len(item.content) <= MAX_FILE_BYTES, "Payload file byte ceiling exceeded")
        total += len(item.content)
    _need(len(items) + len(RESERVED_PAYLOAD_FILES) <= MAX_FILES
          and len(namespace) + RESERVED_ENTRIES <= MAX_ENTRIES
          and total + RESOURCE_BYTE_HEADROOM <= MAX_TOTAL_BYTES, "Insufficient final resource headroom")
    inventory = _inventory(items)
    inventory.extend({"path": name, "size": RESOURCE_BYTE_HEADROOM, "sha256": "0" * 64} for name in RESERVED_PAYLOAD_FILES)
    _need(len(_canonical(inventory)) + MANIFEST_METADATA_HEADROOM <= MAX_MANIFEST_BYTES
          and 7 * len(inventory) + 32 <= MAX_MANIFEST_NODES, "Final manifest envelope exceeded")
    return {name for name, kind in namespace.values() if kind == "directory"}


def _report(policy: _Policy, output: dict, items: list[_Item], omissions: list[dict]) -> bytes:
    production = policy is _PRODUCTION_POLICY
    raw = _canonical({"schemaVersion": 1,
        "evidenceKind": "descriptive-copy-mapping" if production else "inert-algorithm-test",
        "profile": PROFILE if production else "not-a-production-profile",
        "notACompletionOrHandoffReceipt": True, "qualification": "no-native-supply-or-legal-qualification",
        "inputLockSha256": output["inputLockSha256"], "outputInventorySha256": policy.output_inventory_sha256,
        "originalLinkProvenanceSha256": policy.provenance_sha256, "noticeInventorySha256": policy.notice_inventory_sha256,
        "hostInputsSha256": output["hostInputsSha256"], "finalInterpreter": output["finalInterpreter"],
        "files": [dict(record, origin=item.origin) for item, record in
                  zip(sorted(items, key=lambda item: item.path), _inventory(items))],
        "omissions": omissions, "inputDirectories": output["stage"]["directories"],
        "reservedPayloadFiles": list(RESERVED_PAYLOAD_FILES), "reservedEntriesIncludingManifest": RESERVED_ENTRIES,
        "resourceByteHeadroom": RESOURCE_BYTE_HEADROOM})
    _need(len(raw) <= MAX_REPORT_BYTES, "Copy report byte ceiling exceeded")
    return raw


def _write_file(path: Path, raw: bytes, mode: int) -> None:
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        _need(stream.write(raw) == len(raw), "Short publisher output write")
        stream.flush()
        os.fsync(stream.fileno())


def _verify_output(root: Path, items: list[_Item], directories: set[str]) -> None:
    actual, actual_directories = _tree(root, max_files=MAX_FILES, max_entries=MAX_ENTRIES)
    expected = {item.path: item.content for item in items} | {"INCOMPLETE": _SENTINEL}
    _need(actual.keys() == expected.keys() and actual_directories == directories, "Written payload roster differs")
    for name, raw in expected.items():
        _need(_read_checked(actual[name], limit=len(raw)) == raw, "Written payload bytes differ")
        mode = 0o600 if name == "INCOMPLETE" else 0o755 if name == _EXEC_DESTINATION else 0o644
        _need(stat.S_IMODE(_ordinary(actual[name]).st_mode) == mode, "Written file mode differs")
    _need(stat.S_IMODE(_ordinary(root, directory=True).st_mode) == 0o700, "Written private root mode differs")
    for name in directories:
        _need(stat.S_IMODE(_ordinary(root / name, directory=True).st_mode) == 0o755, "Written directory mode differs")


def _write_payload(root: Path, report: Path, items: list[_Item], directories: set[str], mapping: bytes) -> None:
    _directory(root.parent)
    _directory(report.parent)
    _absent(root)
    _absent(report)
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    _write_file(root / "INCOMPLETE", _SENTINEL, 0o600)
    for name in sorted(directories, key=lambda value: (value.count("/"), value)):
        (root / name).mkdir(mode=0o755)
        os.chmod(root / name, 0o755)
    for item in sorted(items, key=lambda value: value.path):
        _write_file(root / item.path, item.content, 0o755 if item.path == _EXEC_DESTINATION else 0o644)
    _verify_output(root, items, directories)
    _write_file(report, mapping, 0o600)
    _need(_read_checked(report, limit=MAX_REPORT_BYTES) == mapping
          and stat.S_IMODE(_ordinary(report).st_mode) == 0o600, "Written report differs")
    _need(_read_checked(root / "INCOMPLETE", limit=len(_SENTINEL)) == _SENTINEL, "Incomplete marker changed")
    (root / "INCOMPLETE").unlink()  # No cleanup on failure; no reuse of partial output.


def _prepare_with_policy(stage: Path, output_inventory: Path, receipts: Path, provenance: Path,
                         notices: Path, notice_inventory: Path, host_inputs: Path,
                         output: Path, report: Path, policy: _Policy) -> dict[str, str]:
    _require_policy(policy)
    inputs = (stage, output_inventory, receipts, provenance, notices, notice_inventory, host_inputs)
    for path in (*inputs, output, report):
        _absolute(path)
    _need(report != output and output not in report.parents, "Report must be outside payload")
    _need(all(path not in inputs and all(root not in path.parents for root in (stage, receipts, notices))
              for path in (output, report)), "Output/report cannot mutate an input tree")
    _directory(output.parent)
    _directory(report.parent)
    _absent(output)
    _absent(report)
    out_raw = _checked(output_inventory, policy.output_inventory_sha256, limit=MAX_INVENTORY_BYTES)
    notice_raw = _checked(notice_inventory, policy.notice_inventory_sha256, limit=MAX_NOTICE_INVENTORY_BYTES)
    provenance_raw = _checked(provenance, policy.provenance_sha256, limit=MAX_INVENTORY_BYTES)
    document = _output_inventory(out_raw)
    _host_inputs(_checked(host_inputs, document["hostInputsSha256"], limit=MAX_INVENTORY_BYTES), policy)
    _provenance(receipts, provenance_raw, document, policy.notice_inventory_sha256)
    items, omissions = _stage_items(stage, document, policy)
    items.extend(_notice_items(notices, notice_raw, policy))
    items.extend(_Item(name, raw, {"kind": "generated", "recipe": recipe}) for name, raw, recipe in _GENERATED)
    directories = _preflight_items(items)
    mapping = _report(policy, document, items, omissions)
    _write_payload(output, report, items, directories, mapping)
    return {"operation": "publisher-copy-completed", "reportSha256": _digest(mapping),
            "evidenceKind": "descriptive-copy-mapping" if policy is _PRODUCTION_POLICY else "inert-algorithm-test",
            "qualification": "no-native-supply-or-legal-qualification"}


def prepare(stage: Path, output_inventory: Path, receipts: Path, provenance: Path,
            notices: Path, notice_inventory: Path, host_inputs: Path, output: Path, report: Path) -> dict[str, str]:
    """Closed production entry. No caller hash, policy, skip or approval override."""
    return _prepare_with_policy(stage, output_inventory, receipts, provenance, notices, notice_inventory,
                                host_inputs, output, report, _PRODUCTION_POLICY)


def _source_helpers():
    spec = importlib.util.spec_from_file_location("_mrk_source_copy_inputs", Path(__file__).with_name("cpython_static_inputs.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_source_policy(policy: _SourcePolicy) -> None:
    _need(type(policy) is _SourcePolicy and all(value is not None for value in policy[:3]),
          "Source preparation closed: accepted output, components and public notices missing")
    for value in (*policy[:3], policy.license_sha256):
        _sha(value)
    _need(type(policy.license_size) is int and 0 < policy.license_size <= MAX_NOTICE_BYTES, "Invalid source license policy")


def _source_output_inventory(raw: bytes) -> dict:
    helper = _source_helpers()
    doc = _keys(_decode(raw), {"schema", "profile", "target", "inputLockSha256", "hostInputsSha256",
                              "rootfsSha256", "result", "stage"})
    _need(doc["schema"] == "mrk-cpython-source-output-1" and doc["profile"] == SOURCE_PROFILE
          and doc["target"] == TARGET, "Different source output profile/schema")
    for field in ("inputLockSha256", "hostInputsSha256", "rootfsSha256"):
        _sha(doc[field])
    _need(_record(doc["result"], limit=MAX_RECEIPT_BYTES)["path"] == "source-result.json", "Different original source result")
    stage = _keys(doc["stage"], {"sourcePrefix", "files", "directories", "omissions"})
    _need(stage["sourcePrefix"] == "/work/stage" and type(stage["files"]) is list, "Different direct projection root")
    records = []
    for row in stage["files"]:
        _keys(row, {"path", "size", "sha256", "mode", "origin"})
        records.append({k: row[k] for k in ("path", "size", "sha256")})
        _need(row["mode"] == (0o755 if row["path"] == _EXEC_DESTINATION else 0o644), "Different projection mode")
        origin = row["origin"]
        _need(type(origin) is dict, "Missing original source/build projection binding")
        if origin.get("kind") == "generated-landmark":
            _keys(origin, {"kind", "rule"})
            _need((row["path"], origin["rule"]) in {(n, rule) for n, _, rule in _GENERATED}, "Unknown generated payload member")
        else:
            _keys(origin, {"kind", "path", "producerPhase"})
            _need(origin["kind"] in {"source-built", "source-projected"}, "Installed/link-id origin is not a source projection")
            _absolute(Path(origin["path"]))
            if origin["kind"] == "source-built":
                _need(type(row["size"]) is int and row["size"] > 0, "Empty original built/generated output")
                if row["path"] == _EXEC_DESTINATION:
                    wanted = ("/work/build/cpython/python", "python-build")
                elif row["path"] in {"python/lib/libcrypto.so.3", "python/lib/libssl.so.3"}:
                    wanted = ("/work/build/openssl/" + row["path"].rsplit("/", 1)[-1], "openssl-build")
                else:
                    leaf = row["path"].rsplit("/", 1)[-1]
                    _need(row["path"] in {"python/" + n for n in (_SYSCONFIG_PY, _SYSCONFIG_JSON, _BUILD_DETAILS)}
                          and re.fullmatch(r"/work/build/cpython/build/[A-Za-z0-9._+\-]+/" + re.escape(leaf), origin["path"]),
                          "Unexpected built/generated projection")
                    wanted = (origin["path"], "python-build")
                _need((origin["path"], origin["producerPhase"]) == wanted, "Different original producer path/phase")
            else:
                if row["path"] == "python/LICENSE.txt":
                    wanted = "/work/inputs/sources/cpython/LICENSE"
                else:
                    _need(row["path"].startswith("python/lib/python3.14/"), "Source projection outside stdlib")
                    leaf = row["path"][len("python/lib/python3.14/"):]
                    wanted = "/work/inputs/sources/cpython/Lib/" + leaf
                    _need(helper.source_stdlib_destination(leaf)[0] == row["path"],
                          "Excluded source member was projected")
                _need(origin["path"] == wanted and origin["producerPhase"] == "authenticated-source",
                      "Source projection lacks authenticated original path")
    listed = _records(records, max_files=MAX_FILES, max_bytes=MAX_TOTAL_BYTES - RESOURCE_BYTE_HEADROOM,
                      file_limit=MAX_FILE_BYTES)
    directories = stage["directories"]
    _need(type(directories) is list and directories == sorted(_ancestors(listed)), "Projection directory roster differs")
    required = {_EXEC_DESTINATION, "python/LICENSE.txt", "python/lib/libcrypto.so.3", "python/lib/libssl.so.3",
                *("python/" + n for n in (_SYSCONFIG_PY, _SYSCONFIG_JSON, _BUILD_DETAILS)),
                *(n for n, _, _ in _GENERATED), *("python/lib/python3.14/" + n for n in (
                    "os.py", "encodings/__init__.py", "ssl.py", "socket.py", "ctypes/__init__.py",
                    "xml/__init__.py", "xml/parsers/__init__.py", "xml/parsers/expat.py"))}
    _need(required <= listed.keys(), "Required projected interpreter/stdlib/TLS/XML/metadata absent")
    _need(type(stage["omissions"]) is list and len(stage["omissions"]) <= MAX_EVIDENCE_FILES, "Omission roster ceiling")
    omitted = []
    for row in stage["omissions"]:
        _keys(row, {"path", "size", "sha256", "reason"})
        _record({k: row[k] for k in ("path", "size", "sha256")}, limit=MAX_EVIDENCE_FILE_BYTES, absolute=True)
        prefix = "/work/inputs/sources/cpython/Lib/"
        _need(row["path"].startswith(prefix), "Unexpected omission source")
        destination, reason = helper.source_stdlib_destination(row["path"][len(prefix):])
        _need(destination is None and row["reason"] == reason, "Different deterministic source omission")
        omitted.append(row["path"])
    _need(omitted == sorted(set(omitted)), "Duplicate/unsorted source omissions")
    return doc


def _source_coverage(document: dict, rootfs: dict, notices: dict) -> None:
    """Closed conservative superset; reviewed conditions, not blanket RLE claims."""
    _need(document["coverage"] == "closed-input-conservative-superset"
          and document["sourceAvailabilityNotice"] == "SOURCE-AVAILABILITY.txt"
          and document["sourceAvailabilityNotice"] in notices, "Missing source-availability/coverage binding")
    expat_notice = _keys(document["bundledExpatNotice"], {"member", "file"})
    expat_file = _record(expat_notice["file"], limit=MAX_NOTICE_BYTES)
    _need(expat_notice["member"] == "Python-3.14.7/Modules/expat/COPYING" and expat_file["size"] == 1144
          and notices.get(expat_file["path"]) == expat_file, "Exact bundled Expat COPYING binding missing")

    def obligations(row: dict) -> None:
        _need(type(row["notices"]) is list and row["notices"] and row["notices"] == sorted(set(row["notices"]))
              and set(row["notices"]) <= notices.keys(), "Component notice coverage absent")
        _need(type(row["conditions"]) is list and row["conditions"] and len(row["conditions"]) <= 32
              and all(type(s) is str and 0 < len(s) <= 2048 for s in row["conditions"]),
              "File-scoped source/license/relinking conditions missing")

    roots = {r["id"]: r for r in rootfs["sources"]}
    packages = {}
    for row in rootfs["packages"]:
        packages.setdefault(row["sourceId"], []).append(row["id"])
    _need(len(roots) == 85 and sum(len(rows) for rows in packages.values()) == 151
          and roots.keys() == packages.keys(), "Different complete selected package/source closure")
    systems = document["systemSources"]
    _need(type(systems) is list and [r["sourceId"] for r in systems] == sorted(roots), "System-source coverage incomplete")
    possible = set()
    for row in systems:
        _keys(row, {"sourceId", "packageIds", "artifacts", "classification", "notices", "conditions"})
        _need(row["packageIds"] == sorted(packages[row["sourceId"]])
              and row["artifacts"] == roots[row["sourceId"]]["artifacts"], "Version/patch/package coverage differs")
        _need(row["classification"] in {"build-only", "possible-incorporation"}, "Different component classification")
        if row["classification"] == "possible-incorporation":
            possible.add(row["sourceId"])
            obligations(row)
        else:
            _need(row["notices"] == [] and type(row["conditions"]) is list and row["conditions"],
                  "Build-only classification needs its reviewed reason")
    _need({"gcc-13@13.3.0-6ubuntu2~24.04.1", "gcc-14@14.2.0-4ubuntu2~24.04.1",
           "glibc@2.39-0ubuntu8.9", "linux@6.8.0-139.139", "libxcrypt@1:4.4.36-4build1"} <= possible,
          "Compiler/runtime/startup/UAPI/libxcrypt conservative coverage absent")
    helper = _source_helpers()
    expected = {
        "cpython": ("3.14.7", "cpython", ["."]),
        "hacl": ("bundled-in-cpython-3.14.7", "cpython", ["Modules/_hacl/"]),
        "expat": ("2.8.2", "cpython", ["Include/pyexpat.h", "Modules/expat/", "Modules/pyexpat.c"]),
        "zlib": ("1.3.2", "zlib", ["."]), "libffi": ("3.4.8", "libffi", ["."]),
        "openssl": ("3.5.8", "openssl", ["."])}
    _need(type(document["nativeSources"]) is list and [r["id"] for r in document["nativeSources"]] == sorted(expected),
          "Native source coverage incomplete")
    for row in document["nativeSources"]:
        _keys(row, {"id", "version", "archiveSha256", "scope", "notices", "conditions"})
        version, archive, scope = expected[row["id"]]
        _need((row["version"], row["archiveSha256"], row["scope"]) ==
              (version, helper.SOURCE_ARCHIVES[archive][2], scope), "Different incorporated native version/subtree")
        obligations(row)
        if row["id"] == "expat":
            _need(expat_file["path"] in row["notices"], "Expat component omits its exact bundled COPYING")
    # Every native output is covered by the complete conservative union. This
    # intentionally does not claim these are observed per-link selected members.
    union = sorted(possible | set(expected))
    _need(document["outputCoverage"] == [{"path": name, "components": union} for name in
          sorted({_EXEC_DESTINATION, "python/lib/libcrypto.so.3", "python/lib/libssl.so.3"})],
          "Native outputs lack the full conservative component union")


def _source_evidence(root: Path, raw: bytes, output: dict, notice_raw: bytes, policy: _SourcePolicy) -> dict:
    doc = _keys(_decode(raw), {"schema", "profile", "inputLockSha256", "rootfsSha256", "resultSha256",
        "noticeInventorySha256", "coverage", "sourceAvailabilityNotice", "bundledExpatNotice", "nativeSources", "systemSources",
        "outputCoverage", "files", "configurationReview", "obligationReview"})
    _need(doc["schema"] == "mrk-cpython-source-components-1" and doc["profile"] == SOURCE_PROFILE
          and doc["inputLockSha256"] == output["inputLockSha256"] and doc["rootfsSha256"] == output["rootfsSha256"]
          and doc["resultSha256"] == output["result"]["sha256"]
          and doc["noticeInventorySha256"] == policy.notice_inventory_sha256, "Source result/coverage/notice bindings differ")
    records = _records(doc["files"], max_files=MAX_EVIDENCE_FILES, max_bytes=MAX_EVIDENCE_BYTES,
                       file_limit=MAX_EVIDENCE_FILE_BYTES)
    actual, _ = _tree(root, max_files=MAX_EVIDENCE_FILES, max_entries=MAX_EVIDENCE_ENTRIES)
    _need(actual.keys() == records.keys(), "Source evidence extra/missing/renamed")
    for name, row in records.items():
        _checked(actual[name], row["sha256"], size=row["size"], limit=MAX_EVIDENCE_FILE_BYTES)
    for name in ("configurationReview", "obligationReview"):
        row = _record(doc[name], limit=MAX_RECEIPT_BYTES)
        _need(records.get(row["path"]) == row and row["size"] > 0, "Independent configuration/conditions review absent")
    _need(records.get("source-result.json") == output["result"] and records.get("rootfs.json", {}).get("sha256") == output["rootfsSha256"]
          and records.get("input-lock.json", {}).get("sha256") == output["inputLockSha256"], "Original input/result evidence absent")
    rootfs = _decode(_read_checked(actual["rootfs.json"], limit=MAX_INVENTORY_BYTES))
    _need(rootfs["schema"] == "mrk-cpython-source-rootfs-1" and rootfs["profile"] == SOURCE_PROFILE, "Different root origin")
    notice = _decode(notice_raw)
    _need(notice["profile"] == SOURCE_PROFILE, "Cross-profile source notices")
    notice_records = _records(notice["files"], max_files=MAX_NOTICE_FILES, max_bytes=MAX_NOTICE_BYTES, file_limit=MAX_NOTICE_BYTES)
    _source_coverage(doc, rootfs, notice_records)
    result = _keys(_decode(_read_checked(actual["source-result.json"], limit=MAX_RECEIPT_BYTES)),
        {"schema", "profile", "inputLockSha256", "rootfsSha256", "executionReviewSha256", "state", "nativeQualification", "startMonotonicNs",
         "deadlineMonotonicNs", "endMonotonicNs", "phases", "projectionSha256"})
    _need(result["schema"] == "mrk-cpython-source-result-1" and result["profile"] == SOURCE_PROFILE
          and result["inputLockSha256"] == output["inputLockSha256"] and result["rootfsSha256"] == output["rootfsSha256"]
          and result["state"] == "mandatory-work-complete" and result["nativeQualification"] == "not-established"
          and all(type(result[k]) is int for k in ("startMonotonicNs", "endMonotonicNs", "deadlineMonotonicNs"))
          and result["startMonotonicNs"] < result["endMonotonicNs"] < result["deadlineMonotonicNs"]
          and result["deadlineMonotonicNs"] - result["startMonotonicNs"] == 2400 * 1_000_000_000,
          "Original source result failed/late or claims readiness")
    helper = _source_helpers()
    _need(records.get("execution-review.json", {}).get("sha256") == _sha(result["executionReviewSha256"]),
          "Original prerequisite execution review absent")
    helper.source_execution_review(_read_checked(actual["execution-review.json"], limit=MAX_INVENTORY_BYTES),
                                   result["executionReviewSha256"])
    spec = importlib.util.spec_from_file_location("_mrk_source_copy_recipe", Path(__file__).with_name("cpython_source_recipe.py"))
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    phase_specs = {row["name"]: row for row in recipe.fixed_phases()}
    _need([r["path"] for r in result["phases"]] == [name + ".json" for name in helper.SOURCE_PHASES],
          "Mandatory original source phase roster differs")
    previous = result["startMonotonicNs"]
    log_bytes = 0
    for name, row in zip(helper.SOURCE_PHASES, result["phases"]):
        _need(records.get(row["path"]) == _record(row, limit=MAX_RECEIPT_BYTES), "Original source phase record differs")
        phase = _keys(_decode(_read_checked(actual[row["path"]], limit=MAX_RECEIPT_BYTES)),
            {"schema", "profile", "inputLockSha256", "phase", "kind", "argv", "cwd", "environmentSha256",
             "startMonotonicNs", "endMonotonicNs", "deadlineMonotonicNs", "originalExitCode", "state",
             "observedIgnoredError", "stdout", "stderr", "dataFiles"})
        native = name not in {"openssl-layout", "python-project"}
        _need(phase["schema"] == helper.SOURCE_PHASE_SCHEMA and phase["profile"] == SOURCE_PROFILE
              and phase["inputLockSha256"] == output["inputLockSha256"] and phase["phase"] == name
              and phase["kind"] == ("native" if native else "data") and phase["state"] == "complete"
              and (type(phase["originalExitCode"]) is int and phase["originalExitCode"] == 0 if native else phase["originalExitCode"] is None)
              and phase["observedIgnoredError"] is False
              and all(type(phase[k]) is int for k in ("startMonotonicNs", "endMonotonicNs", "deadlineMonotonicNs"))
              and previous <= phase["startMonotonicNs"] <= phase["endMonotonicNs"] < result["endMonotonicNs"]
              and phase["deadlineMonotonicNs"] == result["deadlineMonotonicNs"], "Original mandatory phase failed/incomplete/late")
        previous = phase["endMonotonicNs"]
        _sha(phase["environmentSha256"])
        planned = phase_specs[name]
        _need(phase["argv"] == planned["argv"] and phase["cwd"] == planned["cwd"]
              and phase["environmentSha256"] == _digest(_canonical(planned["environment"])),
              "Original phase argv/cwd/environment differs from fixed recipe")
        stream_bytes = 0
        for field in ("stdout", "stderr"):
            stream = _record(phase[field], limit=16 << 20)
            _need(stream["path"] == name + "." + field and records.get(stream["path"]) == stream, "Original phase stream missing")
            stream_bytes += stream["size"]
        log_bytes += stream_bytes
        _need(stream_bytes <= 16 << 20 and log_bytes <= 256 << 20, "Original source log bound exceeded")
        for item in phase["dataFiles"]:
            _need(records.get(item["path"]) == _record(item, limit=MAX_INVENTORY_BYTES), "Original phase DATA missing")
        required_data = []
        if name in {"python-configure", "python-build"}:
            required_data = [name + "-" + relative.replace("/", "-") for relative in helper.SOURCE_CONFIG_FILES]
            if name == "python-build":
                required_data.append("python-build-pybuilddir.txt")
        elif name in {"openssl-configure", "openssl-build", "openssl-install"}:
            required_data = [name + "-" + relative.replace("/", "-") for relative in
                             (helper.SOURCE_OPENSSL_FILES[:2] if name == "openssl-configure" else helper.SOURCE_OPENSSL_FILES)]
        elif name in {"zlib-configure", "libffi-configure"}:
            required_data = [name + ("-configure.log" if name == "zlib-configure" else "-config.log")]
        elif name in {"openssl-layout", "python-project"}:
            required_data = [helper.SOURCE_OPENSSL_LAYOUT_DATA if name == "openssl-layout" else "source-projection.json"]
        _need([r["path"] for r in phase["dataFiles"]] == required_data, "Mandatory generated/configuration DATA missing")
    projection = _read_checked(actual["source-projection.json"], limit=MAX_INVENTORY_BYTES)
    _need(_digest(projection) == result["projectionSha256"]
          and _decode(projection) == {"profile": SOURCE_PROFILE, **output["stage"]}, "Projection/result byte correspondence differs")
    for phase in ("python-configure", "python-build"):
        files = {name: _read_checked(actual[phase + "-" + name.replace("/", "-")], limit=MAX_INVENTORY_BYTES)
                 for name in helper.SOURCE_CONFIG_FILES}
        helper.source_material_configuration(files, _read_checked(Path(__file__).with_name("cpython_source_setup.local"), limit=1 << 20),
            _read_checked(actual["source-patchlevel.h"], limit=1 << 20))
    generated = "/work/build/cpython/" + helper.source_pybuilddir(_read_checked(actual["python-build-pybuilddir.txt"], limit=4096)) + "/"
    for row in output["stage"]["files"]:
        leaf = row["path"].rsplit("/", 1)[-1]
        if leaf in helper.SOURCE_GENERATED_NAMES:
            _need(row["origin"]["path"] == generated + leaf, "Generated projection differs from original pybuilddir.txt")
    return doc


def _source_stage_items(root: Path, document: dict, policy: _SourcePolicy) -> list[_Item]:
    stage = document["stage"]
    actual, directories = _tree(root, max_files=MAX_FILES, max_entries=MAX_ENTRIES)
    records = {row["path"]: row for row in stage["files"]}
    _need(actual.keys() == records.keys() and directories == set(stage["directories"]), "Source projection roster changed")
    helper, items = _source_helpers(), []
    for name, row in records.items():
        raw = _checked(actual[name], row["sha256"], size=row["size"], limit=MAX_FILE_BYTES)
        _need(stat.S_IMODE(_ordinary(actual[name]).st_mode) == row["mode"], "Source projection mode changed")
        if name == _EXEC_DESTINATION:
            helper.source_elf(raw, "python")
        elif name in {"python/lib/libcrypto.so.3", "python/lib/libssl.so.3"}:
            helper.source_elf(raw, name.rsplit("/", 1)[-1])
        elif name == "python/LICENSE.txt":
            _need((len(raw), _digest(raw)) == (policy.license_size, policy.license_sha256), "Exact CPython license changed")
        if row["origin"]["kind"] == "generated-landmark":
            _need(any(name == n and raw == data and row["origin"]["rule"] == rule for n, data, rule in _GENERATED),
                  "Generated landmark bytes differ")
        items.append(_Item(name, raw, {**row["origin"], "outputInventorySha256": policy.output_inventory_sha256}))
    return items


def _prepare_source_with_policy(stage: Path, output_inventory: Path, receipts: Path, components: Path,
        notices: Path, notice_inventory: Path, host_inputs: Path, output: Path, report: Path, policy: _SourcePolicy) -> dict:
    _require_source_policy(policy)  # Before any caller path inspection or output effect.
    inputs = (stage, output_inventory, receipts, components, notices, notice_inventory, host_inputs)
    for path in (*inputs, output, report):
        _absolute(path)
    _need(report != output and output not in report.parents and all(path not in inputs
          and all(root not in path.parents for root in (stage, receipts, notices)) for path in (output, report)),
          "Source copy output/report overlaps input")
    _directory(output.parent)
    _directory(report.parent)
    _absent(output)
    _absent(report)
    document = _source_output_inventory(_checked(output_inventory, policy.output_inventory_sha256, limit=MAX_INVENTORY_BYTES))
    notice_raw = _checked(notice_inventory, policy.notice_inventory_sha256, limit=MAX_NOTICE_INVENTORY_BYTES)
    component_raw = _checked(components, policy.components_sha256, limit=MAX_INVENTORY_BYTES)
    _host_inputs(_checked(host_inputs, document["hostInputsSha256"], limit=MAX_INVENTORY_BYTES), policy)
    _source_evidence(receipts, component_raw, document, notice_raw, policy)
    items = _source_stage_items(stage, document, policy)
    items.extend(_notice_items(notices, notice_raw, policy))
    directories = _preflight_items(items)
    production = policy is _SOURCE_PRODUCTION_POLICY
    mapping = _canonical({"schemaVersion": 1, "profile": SOURCE_PROFILE if production else "not-a-production-profile",
        "evidenceKind": "descriptive-source-copy-mapping" if production else "inert-algorithm-test",
        "notACompletionOrHandoffReceipt": True, "qualification": "no-native-supply-or-legal-qualification",
        "inputLockSha256": document["inputLockSha256"], "outputInventorySha256": policy.output_inventory_sha256,
        "componentsSha256": policy.components_sha256, "noticeInventorySha256": policy.notice_inventory_sha256,
        "hostInputsSha256": document["hostInputsSha256"], "originalResult": document["result"],
        "files": [dict(record, origin=item.origin) for item, record in
                  zip(sorted(items, key=lambda item: item.path), _inventory(items))],
        "omissions": document["stage"]["omissions"], "inputDirectories": document["stage"]["directories"],
        "reservedPayloadFiles": list(RESERVED_PAYLOAD_FILES), "reservedEntriesIncludingManifest": RESERVED_ENTRIES,
        "resourceByteHeadroom": RESOURCE_BYTE_HEADROOM})
    _need(len(mapping) <= MAX_REPORT_BYTES, "Source copy report ceiling")
    _write_payload(output, report, items, directories, mapping)
    return {"operation": "source-publisher-copy-completed", "reportSha256": _digest(mapping),
            "evidenceKind": "descriptive-source-copy-mapping" if production else "inert-algorithm-test",
            "qualification": "no-native-supply-or-legal-qualification"}


def prepare_source(stage: Path, output_inventory: Path, receipts: Path, components: Path,
        notices: Path, notice_inventory: Path, host_inputs: Path, output: Path, report: Path) -> dict:
    """Literal closed source policy; no caller approval/hash/profile/skip option."""
    return _prepare_source_with_policy(stage, output_inventory, receipts, components, notices, notice_inventory,
                                       host_inputs, output, report, _SOURCE_PRODUCTION_POLICY)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "output-inventory", "receipts", "provenance", "notices", "notice-inventory",
                 "host-inputs", "output", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.stage, args.output_inventory, args.receipts, args.provenance,
                                 args.notices, args.notice_inventory, args.host_inputs, args.output, args.report), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.exit(1, "Static CPython copy refused or failed. Preserve inputs and partial private output; "
                       "no native, supply or legal qualification was performed.\n")


if __name__ == "__main__":
    main()
