"""Non-executing DATA for a fresh public-source macOS Python producer.

This module has no CLI, filesystem access, process launch, download or supplier
activation. Its source nomination and projection are not a build recipe or
native result. Executable configure/Makefile arguments require their separate
upstream-source derivation and execution review before they can be added.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

SOURCE_PROFILE = "cpython-3.14.7-macos26-arm64-source-v1"
SOURCE_LOCK_BYTES = 5158
SOURCE_LOCK_SHA256 = "cbfc5dd6a120131efc8ca3c134b1da9798ffee464282a4ba8774b85a14f44688"
INTEL_SOURCE_PROFILE = "cpython-3.14.7-macos26-x86_64-source-v1"
INTEL_SOURCE_LOCK_BYTES = 5158
INTEL_SOURCE_LOCK_SHA256 = "e5196ca58c79a5381788e596744fee52385698fb1d3cfa998eaefc7295769430"
PYTHON_VERSION = "3.14.7"
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
MAX_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_SOURCE_ROWS = 20_000
MAX_SUPPLIER_FILES = 2035  # Consumer reserves ten bootstraps, core, CA and manifest.
MAX_SUPPLIER_BYTES = 464 * 1024 * 1024  # Combined consumer limit is 512 MiB.
MAX_PATH_COMPONENTS = 16
MAX_PATH_BYTES = 512
MAX_WORK_SECONDS = 45 * 60
MAX_CLEANUP_SECONDS = 120
MAX_BUILD_WORKERS = 2
MAX_PHASE_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_RETAINED_DIAGNOSTIC_BYTES = 32 * 1024 * 1024

# A plan of required operations, not commands or evidence that any ran.
PLANNED_PHASES = (
    "source-admission", "tool-admission", "network-denial",
    "zlib-configure", "zlib-build", "zlib-stage",
    "Apple-sdk-libffi-configuration",  # Private libffi source is not incorporated.
    "openssl-configure", "openssl-build", "openssl-stage",
    "python-configure", "python-configuration-check", "builtin-archives",
    "python-build", "python-projection", "native-signature",
    "native-modules", "native-loader", "native-tls", "native-relocation",
    "native-cancellation", "notice-correspondence", "finality-and-publication",
)

_COMPONENTS = ("cpython", "libffi", "openssl", "zlib")
_EXCLUDED_STDLIB = frozenset({
    "test", "ensurepip", "idlelib", "turtledemo", "venv", "site-packages",
    "tkinter", "turtle.py",
})
_RESERVED_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10)),
})
_REQUIRED_STDLIB = frozenset({
    "os.py", "encodings/__init__.py", "ssl.py", "socket.py", "hashlib.py",
    "hmac.py", "ctypes/__init__.py", "plistlib.py", "uuid.py", "subprocess.py",
    "urllib/request.py", "zipfile/__init__.py", "xml/parsers/expat.py",
    "sysconfig/__init__.py",
})


class RecipeRefused(ValueError):
    """A closed source/projection input differs; this is not a native outcome."""


@dataclass(frozen=True)
class NativeTarget:
    triple: str
    architecture: str
    openssl_target: str
    minimum_macos: str


@dataclass(frozen=True)
class SourceInput:
    component: str
    version: str
    url: str
    size: int
    sha256: str
    inventory_path: str
    inventory_size: int
    inventory_sha256: str
    original_prefix: str


@dataclass(frozen=True)
class SourceProjection:
    source: str
    destination: str
    size: int
    sha256: str
    mode: int = 0o444


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RecipeRefused(code)


def _pairs(rows: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in rows:
        _need(key not in result, "duplicate-source-json-key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise RecipeRefused("nonfinite-source-json")


def _bound_json(body: bytes, size: int, expected: str, limit: int) -> dict:
    _need(type(body) is bytes and type(size) is int and 0 < size <= limit
          and len(body) == size, "source-input-byte-bound")
    # Exact original bytes are authenticated before invoking the JSON parser.
    _need(hashlib.sha256(body).hexdigest() == expected, "source-input-digest")
    try:
        result = json.loads(body.decode("utf-8", "strict"),
                            object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RecipeRefused("source-json-shape") from error
    _need(type(result) is dict, "source-json-object")
    return result


def target_description(target: str) -> NativeTarget:
    """Describe the two closed targets; this is not native qualification."""
    if type(target) is str and target == ARM_TARGET:
        return NativeTarget(target, "arm64", "darwin64-arm64-cc", "26.0")
    if type(target) is str and target == INTEL_TARGET:
        return NativeTarget(target, "x86_64", "darwin64-x86_64-cc", "26.0")
    raise RecipeRefused("unsupported-macos-target")


def source_binding(target: str) -> dict:
    """Return fixed SOURCE pins, never a caller-selected digest or permission."""
    target_description(target)
    if target == ARM_TARGET:
        name, profile, size, sha = "source-lock.json", SOURCE_PROFILE, SOURCE_LOCK_BYTES, SOURCE_LOCK_SHA256
    else:
        name, profile, size, sha = ("source-lock-intel.json", INTEL_SOURCE_PROFILE,
                                   INTEL_SOURCE_LOCK_BYTES, INTEL_SOURCE_LOCK_SHA256)
    return {"path": "desktop/macos-cpython-source-inputs/" + name,
            "profile": profile, "bytes": size, "sha256": sha}


def source_nomination(lock_body: bytes, target: str) -> tuple[SourceInput, ...]:
    """Validate the exact selected target's nomination, never approval flags."""
    binding = source_binding(target)
    lock = _bound_json(lock_body, binding["bytes"], binding["sha256"], 64 * 1024)
    _need(lock["schemaVersion"] == 1 and lock["profile"] == binding["profile"]
          and lock["target"] == {"triple": target, "minimumMacOS": "26.0",
                                 "pythonVersion": PYTHON_VERSION, "gil": True},
          "source-nomination-identity")
    rows = lock["archiveSelections"]
    _need(type(rows) is list and tuple(row["id"] for row in rows) == _COMPONENTS,
          "source-component-roster")
    return tuple(SourceInput(
        row["id"], row["version"], row["url"], row["bytes"], row["sha256"],
        row["inventory"]["repositoryPath"], row["inventory"]["bytes"],
        row["inventory"]["sha256"], row["inventory"]["originalPrefix"],
    ) for row in rows)


def _relative_name(name: str) -> list[str]:
    _need(type(name) is str and 0 < len(name) <= 4096
          and "\\" not in name and all(ord(c) >= 32 and ord(c) != 127 for c in name),
          "source-relative-path")
    parts = name.split("/")
    _need(all(part not in {"", ".", ".."} for part in parts), "source-relative-path")
    return parts


def stdlib_destination(name: str) -> str | None:
    """Select Python SOURCE leaves, without reading/copying or loading them."""
    parts = _relative_name(name)
    leaf = parts[-1]
    _need(not (leaf.endswith((".so", ".dll", ".dylib", ".pyd")) or ".so." in leaf),
          "unexpected-native-source-member")
    if "__pycache__" in parts or leaf.endswith((".pyc", ".pyo")):
        return None
    if parts[0] in _EXCLUDED_STDLIB or not leaf.endswith(".py"):
        return None
    _need(not leaf.startswith(("_sysconfigdata_", "_sysconfig_vars_")),
          "source-cannot-substitute-generated-sysconfig")
    destination = "python/lib/python3.14/" + name
    output_parts = destination.split("/")
    _need(len(output_parts) <= MAX_PATH_COMPONENTS and len(destination) <= MAX_PATH_BYTES
          and all(re.fullmatch(r"[A-Za-z0-9._+\-]+", part, flags=re.ASCII) is not None
                  and not part.endswith(".")
                  and part.split(".", 1)[0].lower() not in _RESERVED_NAMES
                  for part in output_parts), "nonportable-payload-path")
    return destination


def stdlib_projection(lock_body: bytes, inventory_body: bytes,
                      target: str) -> tuple[SourceProjection, ...]:
    """Return a byte-preserving stdlib plan; no complete runtime is produced."""
    source = source_nomination(lock_body, target)[0]
    inventory = _bound_json(inventory_body, source.inventory_size,
                            source.inventory_sha256, MAX_INVENTORY_BYTES)
    _need(set(inventory) == {"files"} and type(inventory["files"]) is list
          and 0 < len(inventory["files"]) <= MAX_SOURCE_ROWS, "source-inventory-shape")
    seen_sources, seen_outputs, required, result = set(), set(), set(), []
    total = 0
    for row in inventory["files"]:
        _need(type(row) is dict and set(row) == {"path", "size", "sha256", "mode"}
              and type(row["path"]) is str and row["path"].startswith(source.original_prefix)
              and type(row["size"]) is int and 0 <= row["size"] <= MAX_SUPPLIER_BYTES
              and type(row["mode"]) is int and row["mode"] in {0o644, 0o755}
              and type(row["sha256"]) is str
              and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
              "source-inventory-row")
        name = row["path"][len(source.original_prefix):]
        _relative_name(name)
        _need(name not in seen_sources, "duplicate-source-member")
        seen_sources.add(name)
        if not name.startswith("Lib/"):
            continue
        relative = name[len("Lib/"):]
        destination = stdlib_destination(relative)
        if destination is None:
            continue
        _need(destination.casefold() not in seen_outputs, "payload-case-collision")
        seen_outputs.add(destination.casefold())
        total += row["size"]
        _need(len(result) < MAX_SUPPLIER_FILES and total <= MAX_SUPPLIER_BYTES,
              "stdlib-projection-bound")
        required.add(relative)
        result.append(SourceProjection(name, destination, row["size"], row["sha256"]))
    _need(_REQUIRED_STDLIB <= required, "required-stdlib-source-missing")
    # The binary, generated configuration, landmarks and notices are not present
    # in this partial projection; their later aggregate admission is mandatory.
    return tuple(sorted(result, key=lambda row: row.destination))
