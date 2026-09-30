"""Stage inert Windows installer inputs, never an installer or runtime launch.

The explicit admission SHA binds supplied assertions, not observed compiler/PE
provenance, supplier trust, signatures or native qualification. A separate review
must admit the actual built inputs before this DATA tool is executed. No WiX,
MSI/Burn activation graph, ACL mutation, download, build or executable invocation
is implemented here. Existing inputs and incomplete outputs are never replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

_SPEC = importlib.util.spec_from_file_location(
    "_mrk_windows_installer_payload", Path(__file__).with_name("prepare_windows_embedded_payload.py")
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Fixed Windows payload preparer is unavailable")
payload = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(payload)
preparation = payload.runtime_preparation
StagingError = payload.PreparationError

TARGET = payload.TARGET
ADMISSION_PURPOSE = "windows-installer-input-data"
INVENTORY_PURPOSE = "windows-installer-staging-data"
MAX_ADMISSION_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_NOTICES_BYTES = 4 * 1024 * 1024
MAX_WEBVIEW2_BYTES = 512 * 1024 * 1024
MAX_STAGE_BYTES = 1024 * 1024 * 1024
COMMON_BINDINGS = ("sourceCommit", "target", "runtimeManifestSha256", "protocolSha256", "coreVersion")
ARTIFACT_FEATURES = {
    "shell": ["desktop-shell", "custom-protocol"],
    "publisher": ["windows-runtime-publisher"],
}
# These are private staging names, NOT installation destinations or MSI rows.
OPAQUE_OUTPUTS = {
    "shell": ("shell/mobile-release-kit-desktop.exe", MAX_BINARY_BYTES),
    "publisher": ("publisher/mrk-windows-runtime-publish.exe", MAX_BINARY_BYTES),
    "webview2": ("prerequisites/MicrosoftEdgeWebView2RuntimeInstallerX64.exe", MAX_WEBVIEW2_BYTES),
    "applicationNotices": ("licenses/application-notices.txt", MAX_NOTICES_BYTES),
    "webview2Notices": ("licenses/webview2-notices.txt", MAX_NOTICES_BYTES),
}
QUALIFICATION = {
    "observedBuildProvenance": False,
    "validPeImages": False,
    "trustedSupplier": False,
    "verifiedSignatures": False,
    "nativeQualified": False,
    "installablePackage": False,
    "launcherActivated": False,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StagingError(message)


def _pin(value: object, length: int = 64) -> bool:
    return (type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None
            and value != "0" * length)


def _closed(value: object, keys: set[str], message: str) -> None:
    require(type(value) is dict and set(value) == keys, message)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate DATA field")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise StagingError("Nonfinite DATA value")


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data, object_pairs_hook=_unique, parse_constant=_invalid_constant)
        encoded = preparation.canonical(value)
    except StagingError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise StagingError("Malformed or excessive DATA JSON") from error
    require(type(value) is dict and encoded + b"\n" == data,
            "DATA must be one canonical UTF-8 JSON object and one newline")
    return value


def _file_record(value: dict, limit: int) -> None:
    require(type(value.get("size")) is int and 0 < value["size"] <= limit
            and _pin(value.get("sha256")), "A DATA file size or SHA is not bound")


def admission_bytes(path: Path, expected: str, source: str, target: str,
                    manifest: str, protocol: str) -> tuple[bytes, dict, tuple[int, ...]]:
    # Validate all caller-supplied bindings before even opening the admission.
    require(_pin(expected) and _pin(source, 40) and target == TARGET
            and _pin(manifest) and _pin(protocol), "Explicit DATA bindings are required")
    preparation._root(path.parent)
    require(preparation._safe_name(path.name), "Admission needs an ordinary file name")
    original = preparation._state(preparation._ordinary(path))
    raw = preparation.read_checked(path, limit=MAX_ADMISSION_BYTES)
    require(preparation._state(preparation._ordinary(path)) == original,
            "Admission identity changed while reading")
    require(preparation.digest(raw) == expected, "Admission bytes differ from the explicit SHA")
    value = _json(raw)
    _closed(value, {"schemaVersion", "purpose", *COMMON_BINDINGS, *OPAQUE_OUTPUTS},
            "Admission schema differs")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["purpose"] == ADMISSION_PURPOSE, "Admission profile differs")
    require((value["sourceCommit"], value["target"], value["runtimeManifestSha256"], value["protocolSha256"])
            == (source, target, manifest, protocol), "Admission source or anchors differ")
    require(type(value["coreVersion"]) is str and len(value["coreVersion"]) <= 32
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["coreVersion"]) is not None,
            "Explicit core version is required")
    for role, features in ARTIFACT_FEATURES.items():
        record = value[role]
        _closed(record, {*COMMON_BINDINGS, "profile", "features", "size", "sha256"},
                "Built artifact assertion schema differs")
        require(all(record[key] == value[key] for key in COMMON_BINDINGS)
                and record["profile"] == "release" and record["features"] == features,
                "Built artifact supplied source, anchors or feature assertions differ")
        _file_record(record, MAX_BINARY_BYTES)
    _closed(value["webview2"], {"kind", "size", "sha256"}, "WebView2 assertion schema differs")
    require(value["webview2"]["kind"] == "evergreen-standalone-offline-x64",
            "Only the asserted offline x64 WebView2 profile is staged")
    _file_record(value["webview2"], MAX_WEBVIEW2_BYTES)
    for role in ("applicationNotices", "webview2Notices"):
        _closed(value[role], {"size", "sha256"}, "Recipient notice assertion schema differs")
        _file_record(value[role], MAX_NOTICES_BYTES)
    return raw, value, original


def _fold(path: Path) -> tuple[str, ...]:
    return tuple(part.casefold() for part in path.parts)


def _paths(runtime: Path, output: Path, inputs: dict[str, Path]) -> None:
    # No resolve(): reparse/symlink ancestry is rejected by the existing helper,
    # never silently followed to a replacement path. Compare Windows casing even
    # when the inert staging/test host is POSIX.
    preparation._root(runtime)
    preparation._root(output.parent)
    require(preparation._safe_name(output.name), "Output needs an ordinary fixed name")
    for path in inputs.values():
        preparation._root(path.parent)
        require(preparation._safe_name(path.name), "Input needs an ordinary file name")
        preparation._ordinary(path)
    roots = [runtime, output, *inputs.values()]
    folded = [_fold(path) for path in roots]
    require(all(path.is_absolute() and ".." not in path.parts for path in roots),
            "Staging paths must be explicit absolute paths")
    for index, left in enumerate(folded):
        for right in folded[index + 1:]:
            require(left[:len(right)] != right and right[:len(left)] != left,
                    "Staging inputs and output overlap or alias by case")
    # Also refuse a directory alias (for example an existing bind mount) into
    # either of the only two runtime directories. This remains private DATA
    # hygiene, not native Windows custody or protection from a privileged writer.
    runtime_directories = []
    for path in (runtime, runtime / "python"):
        value = preparation._ordinary(path, directory=True)
        runtime_directories.append((value.st_dev, value.st_ino))
    for path in (output.parent, *(item.parent for item in inputs.values())):
        for parent in (path, *path.parents):
            value = preparation._ordinary(parent, directory=True)
            require((value.st_dev, value.st_ino) not in runtime_directories,
                    "An input or output parent aliases the runtime")
    with os.scandir(output.parent) as children:
        require(not any(child.name.casefold() == output.name.casefold() for child in children),
                "Staging never reuses, merges or replaces an output")


def runtime_inventory(runtime: Path, manifest_sha256: str, protocol_sha256: str,
                      core_version: str) -> list[dict]:
    """Reuse the current fixed Windows preparer's exact47 profile, not a new one."""
    preparation._root(runtime)
    expected = sorted({"manifest.json", "core.zip", preparation.GITHUB_CA_NAME,
                       *preparation.BOOTSTRAPS, "python/" + payload.NOTICE_NAME,
                       *("python/" + name for name, _, _ in payload.MEMBERS)})
    require(len(payload.MEMBERS) == 37 and len(preparation.BOOTSTRAPS) == 6 and len(expected) == 47,
            "The fixed Windows47 source profile changed")
    actual = preparation.files(runtime)
    require([path.relative_to(runtime).as_posix() for path in actual] == expected,
            "Runtime must contain exactly the existing47-file profile")
    raw = preparation.read_checked(runtime / "manifest.json", limit=MAX_MANIFEST_BYTES)
    require(preparation.digest(raw) == manifest_sha256, "Runtime manifest differs from D")
    value = _json(raw)
    _closed(value, {"schemaVersion", "protocol", "coreVersion", "target", "coreSha256",
                    "protocolSha256", "inventorySha256", "files"}, "Runtime manifest schema differs")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and type(value["protocol"]) is int and value["protocol"] == 1
            and value["target"] == TARGET and value["coreVersion"] == core_version
            and value["protocolSha256"] == protocol_sha256
            and _pin(value["coreSha256"]) and _pin(value["inventorySha256"]),
            "Runtime target, version, protocol or anchors differ")
    records = value["files"]
    require(type(records) is list and len(records) == 46, "Runtime manifest roster differs")
    for row in records:
        _closed(row, {"path", "size", "sha256"}, "Runtime file schema differs")
        _file_record(row, preparation.MAX_FILE_BYTES)
    require([row["path"] for row in records] == [name for name in expected if name != "manifest.json"]
            and preparation.digest(preparation.canonical(records)) == value["inventorySha256"],
            "Runtime inventory paths, order or hash differ")
    require(next(row["sha256"] for row in records if row["path"] == "core.zip") == value["coreSha256"],
            "Runtime core anchor differs")
    notices = preparation.read_checked(runtime / "python" / payload.NOTICE_NAME, limit=payload.MAX_NOTICE_BYTES)
    require(len(notices) == payload.NOTICE_BYTES and preparation.digest(notices) == payload.NOTICE_SHA256,
            "Runtime recipient notice differs from the fixed preparer")
    payload.check_supplier_copy(runtime / "python", notices)
    ca = preparation.read_checked(runtime / preparation.GITHUB_CA_NAME, limit=preparation.MAX_GITHUB_CA_BYTES)
    require(len(ca) == payload.GITHUB_CA_BYTES and preparation.digest(ca) == payload.GITHUB_CA_SHA256,
            "Runtime CA differs from the fixed preparer")
    return sorted([*records, {"path": "manifest.json", "size": len(raw), "sha256": manifest_sha256}],
                  key=lambda row: row["path"])


def _copy_data(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        stream = os.fdopen(fd, "wb")
        fd = None  # The stream now owns the one file close, including errors.
        with stream:
            require(stream.write(data) == len(data), "Staging write was incomplete")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)
    require(preparation.read_checked(path, limit=len(data)) == data, "Staging readback differs")


def stage(*, admission: Path, expected_admission: str, source: str, target: str,
          manifest: str, protocol: str, shell: Path, publisher: Path, runtime: Path,
          webview2: Path, application_notices: Path, webview2_notices: Path, output: Path) -> dict:
    raw, assertions, admission_original = admission_bytes(
        admission, expected_admission, source, target, manifest, protocol)
    inputs = {"admission": admission, "shell": shell, "publisher": publisher, "webview2": webview2,
              "applicationNotices": application_notices, "webview2Notices": webview2_notices}
    _paths(runtime, output, inputs)
    runtime_members = preparation.files(runtime)
    require(len(runtime_members) == 47, "Runtime must contain exactly the existing47-file profile")
    snapshots = {}
    identities = set()
    for path in [*inputs.values(), *runtime_members]:
        value = preparation._ordinary(path)
        require((value.st_dev, value.st_ino) not in identities, "Staging inputs alias one original")
        identities.add((value.st_dev, value.st_ino))
        snapshots[path] = preparation._state(value)
    require(snapshots[admission] == admission_original, "Admission identity changed before preflight")
    runtime_directories = {
        path: preparation._state(preparation._ordinary(path, directory=True))
        for path in (runtime, runtime / "python")
    }
    runtime_rows = runtime_inventory(runtime, manifest, protocol, assertions["coreVersion"])
    prefix = "runtime-input/" + TARGET + "/" + manifest + "/"
    files = [(prefix + row["path"], "runtimeInput", runtime / row["path"], row) for row in runtime_rows]
    files.extend((relative, role, inputs[role], assertions[role])
                 for role, (relative, _) in OPAQUE_OUTPUTS.items())
    files.sort(key=lambda item: item[0])
    names = [item[0] for item in files]
    require(len(files) == 52 and len(set(name.casefold() for name in names)) == 52
            and all(not name.startswith(("versions/", "Mobile Release Kit/")) for name in names),
            "Fixed private staging roster differs")
    require(sum(row["size"] for _, _, _, row in files) <= MAX_STAGE_BYTES, "Staging byte limit exceeded")
    # Existing bounded reads check same-file metadata and consuming closes.
    # Keep only hashes/identities here; copy one admitted file at a time, not a
    # gigabyte-sized allocation or a replacement native custody implementation.
    rows = []
    for relative, role, path, row in files:
        require(path in snapshots and preparation._state(preparation._ordinary(path)) == snapshots[path],
                "Input identity changed before preflight")
        data = preparation.read_checked(path, limit=row["size"])
        require(len(data) == row["size"] and preparation.digest(data) == row["sha256"]
                and preparation._state(preparation._ordinary(path)) == snapshots[path],
                "Input bytes or identity differ from their DATA binding")
        rows.append({"path": relative, "role": role, "size": len(data), "sha256": row["sha256"]})
        del data
    require(preparation.read_checked(admission, limit=MAX_ADMISSION_BYTES) == raw,
            "Admission changed during preflight")
    for path, snapshot in snapshots.items():
        require(preparation._state(preparation._ordinary(path)) == snapshot, "Input identity changed during preflight")
    _paths(runtime, output, inputs)
    # Initial input failure leaves output absent; any later failure preserves
    # the exclusively created incomplete tree. No cleanup, retry or adoption.
    output.mkdir(mode=0o700)
    directories = {parent for name in names for parent in Path(name).parents if parent != Path(".")}
    for relative in sorted(directories, key=lambda path: (len(path.parts), path.as_posix())):
        (output / relative).mkdir(mode=0o700)
    for relative, _, path, row in files:
        require(preparation._state(preparation._ordinary(path)) == snapshots[path],
                "Input identity changed before copying")
        data = preparation.read_checked(path, limit=row["size"])
        require(len(data) == row["size"] and preparation.digest(data) == row["sha256"],
                "Input changed before copying")
        _copy_data(output / relative, data)
        del data
    _copy_data(output / "admission.json", raw)
    inventory = {
        "schemaVersion": 1, "purpose": INVENTORY_PURPOSE,
        **{key: assertions[key] for key in COMMON_BINDINGS},
        "inputAssertions": "supplied-not-observed",
        "admissionSha256": expected_admission,
        "runtimeFileCount": 47, "payloadFileCount": 52,
        "payloadInventorySha256": preparation.digest(preparation.canonical(rows)),
        "files": rows, "qualification": dict(QUALIFICATION),
    }
    encoded = preparation.canonical(inventory) + b"\n"
    _copy_data(output / "inventory.json", encoded)
    require([path.relative_to(output).as_posix() for path in preparation.files(output)]
            == sorted([*names, "admission.json", "inventory.json"]), "Output gained or lost a member")
    for row in rows:
        content = preparation.read_checked(output / row["path"], limit=row["size"])
        require(len(content) == row["size"] and preparation.digest(content) == row["sha256"],
                "Final staged inventory differs")
        del content
    require(preparation.read_checked(output / "admission.json", limit=MAX_ADMISSION_BYTES) == raw
            and preparation.read_checked(output / "inventory.json", limit=MAX_MANIFEST_BYTES) == encoded,
            "Final DATA controls differ")
    require([path.relative_to(runtime).as_posix() for path in preparation.files(runtime)]
            == [row["path"] for row in runtime_rows], "Runtime roster changed during staging")
    for path, snapshot in snapshots.items():
        require(preparation._state(preparation._ordinary(path)) == snapshot, "Input identity changed during staging")
    for path, snapshot in runtime_directories.items():
        require(preparation._state(preparation._ordinary(path, directory=True)) == snapshot,
                "Runtime directory identity changed during staging")
    return {
        "schemaVersion": 1, "qualification": "inert-installer-inputs-only",
        "admissionSha256": expected_admission,
        "inventorySha256": hashlib.sha256(encoded).hexdigest(),
        "payloadInventorySha256": inventory["payloadInventorySha256"],
        "runtimeFileCount": 47, "payloadFileCount": 52, "outputFileCount": 54,
        "observedBuildProvenance": False, "validPeImages": False, "trustedSupplier": False,
        "verifiedSignatures": False, "nativeQualified": False, "installablePackage": False,
        "launcherActivated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--expected-admission", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", choices=[TARGET], required=True)
    parser.add_argument("--expected-manifest", required=True)
    parser.add_argument("--expected-protocol", required=True)
    for name in ("shell", "publisher", "runtime", "webview2", "application-notices", "webview2-notices", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = stage(admission=args.admission, expected_admission=args.expected_admission, source=args.source,
                       target=args.target, manifest=args.expected_manifest, protocol=args.expected_protocol,
                       shell=args.shell, publisher=args.publisher, runtime=args.runtime, webview2=args.webview2,
                       application_notices=args.application_notices, webview2_notices=args.webview2_notices,
                       output=args.output)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError, TypeError):
        parser.exit(1, "Windows installer DATA staging refused. Inputs and partial output were preserved; "
                    "no binary or installer was executed or qualified.\n")


if __name__ == "__main__":
    main()
