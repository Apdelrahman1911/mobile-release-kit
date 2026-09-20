"""One conventional source build on an admitted disposable Ubuntu 24.04 runner.

SOURCE ONLY until the literal index selector and the separate C admissions are
independently approved.  No caller-supplied URL, command, limit, approval or retry.
The index is DATA outside L: helpers -> L -> prerequisite E -> A -> index ->
this final entry/command. E must not bind A, the index or this final command.

`prepare` is the sole network-enabled input preparation. `build` uses one
ordinary transient systemd service, bwrap, a real host account and the existing
run_owned recipe. unit-start/unit-stop are fixed service hooks, not a watcher.
`inside` verifies the effective sandbox before importing the admitted recipe.
No supply, copier, installed-runtime, TLS or loader acceptance is produced.
"""
from __future__ import annotations

import ast
import errno
import fcntl
import grp
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import ssl


APPROVED_HOSTED_INPUTS_SHA256: str | None = "2353367ac7f626843559c5626360345201a42ffb25076435d5aeb42954bcd610"
PROFILE = "cpython-3.14.7-linux-x86_64-source-v1"
PREP = Path("/var/tmp/mrk-cpython-source-preparation-v1")
BWRAP_PATH = PREP / "controller/bwrap"
BWRAP_RECEIPT = PREP / "preparation-results/controller-bubblewrap.json"
CONTROL = Path("/var/tmp/mrk-cpython-source-controller-v1")
WORK = Path("/var/tmp/mrk-cpython-source-work-v1")
PUBLIC = Path("/var/tmp/mrk-cpython-source-public-v1")
INPUTS = Path("/work/inputs")
INNER_CONTEXT = Path("/work/hosted-context.json")
ENTRY_NAME = "cpython_source_hosted.py"
INDEX_NAME = "hosted-inputs.json"
RECIPIENT_NAME = "recipient-materials.json"
HELPERS = tuple(sorted(("cpython_source_admission.py", "cpython_source_recipe.py",
    "cpython_source_setup.local", "cpython_static_inputs.py", "cpython_static_builder_data.py",
    "prepare_cpython_static_payload.py", "prepare_cpython_source_payload.py")))
SOURCES = ("cpython", "libffi", "openssl", "zlib")
CONTROLS = tuple(sorted(("transport-map.json", "expected-members.json", "selection.json",
    "root-request.json", "rootfs.json", "host-inputs.json", "source-lock.json",
    "source-execution-review.json", "core-source-files.json", "inventory-provenance.json",
    "github-ca.pem", RECIPIENT_NAME, *(name + "-source-inventory.json" for name in SOURCES))))
PHASES = ("zlib-configure", "zlib-build", "zlib-install", "libffi-configure", "libffi-build",
    "libffi-install", "openssl-configure", "openssl-build", "openssl-install", "openssl-layout",
    "python-configure", "builtin-archives", "python-build", "python-project")
MiB, GiB = 1 << 20, 1 << 30
CHUNK, JSON_LIMIT = 64 << 10, 32 * MiB
PREP_BYTES, PREP_ENTRIES, PREP_SECONDS = 2 * GiB, 32768, 600
WORK_BYTES, WORK_INODES, DEV_BYTES = 4 * GiB, 65536, 64 << 10
PUBLIC_BYTES, PUBLIC_FILES = 4 * GiB, 32768
RUNTIME_SECONDS, STOP_SECONDS, STOP_POST_SECONDS = 2400, 10, 10
# Runtime starts before the recipe. This is intentionally slightly tighter than
# its own 40min, not a new per-phase clock. systemd bounds stop and StopPost too.
CLIENT_SECONDS = RUNTIME_SECONDS + STOP_SECONDS + STOP_POST_SECONDS + 20
LIMITS = {resource.RLIMIT_AS: 512 * MiB, resource.RLIMIT_NOFILE: 128,
    resource.RLIMIT_NPROC: 64, resource.RLIMIT_FSIZE: GiB,
    resource.RLIMIT_CORE: 0, resource.RLIMIT_MEMLOCK: 0}
HOST_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C.UTF-8", "TZ": "UTC",
    "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"}
PROPERTIES = {
    "Type": "exec", "ExitType": "cgroup", "Restart": "no", "KillMode": "control-group",
    "OOMPolicy": "kill", "SendSIGKILL": "yes", "MemoryMax": "6G", "MemorySwapMax": "0",
    "TasksMax": "64", "CPUQuota": "200%", "RuntimeMaxSec": "2400s", "RuntimeRandomizedExtraSec": "0",
    "TimeoutStartSec": "10s", "TimeoutStopSec": "10s",
    "LimitAS": str(512 * MiB), "LimitNOFILE": "128", "LimitNPROC": "64",
    "LimitFSIZE": str(GiB), "LimitCORE": "0", "LimitMEMLOCK": "0",
    "NoNewPrivileges": "yes", "RestrictNamespaces": "~user", "Delegate": "no",
    "PrivateMounts": "yes", "ProtectControlGroups": "yes",
    "UMask": "0077"}
SHOW = ("Id", "InvocationID", "ControlGroup", "Type", "ExitType", "Restart", "KillMode",
    "OOMPolicy", "SendSIGKILL", "MemoryMax", "MemorySwapMax", "TasksMax", "RuntimeMaxUSec",
    "RuntimeRandomizedExtraUSec", "TimeoutStartUSec", "TimeoutStopUSec", "NoNewPrivileges",
    "RestrictNamespaces", "Delegate", "Result")
NS_NAMES = ("user", "mnt", "pid", "net", "ipc", "uts")
HOST_TOOLS = ("/usr/bin/python3.12", "/usr/bin/systemd-run", "/usr/bin/systemctl",
    "/usr/bin/mount", "/usr/bin/gzip", "/usr/bin/dpkg-deb", "/usr/sbin/useradd", "/usr/sbin/userdel")
RECIPIENT_SOURCES = (
    ("recipient-glibc-packaging", "glibc_2.39-0ubuntu8.9.debian.tar.xz", "tar-xz"),
    ("recipient-glibc-dsc", "glibc_2.39-0ubuntu8.9.dsc", "dsc"),
    ("recipient-glibc-upstream", "glibc_2.39.orig.tar.xz", "tar-xz"),
    ("recipient-glibc-signature", "glibc_2.39.orig.tar.xz.asc", "signature"))
RECIPIENT_DOCS = frozenset({"00-RUNTIME-NOTICE.txt", "PYTHON-CHANGES.txt", "SOURCE-AVAILABILITY.txt",
    "REBUILD.md", "MOBILE-RELEASE-KIT-LICENSE.txt", "34-LGPL-2.1.txt"})
# One authenticated controller-only package, outside the L/source/root roster.
# No installation: in particular its sysctl.d member is never materialized.
CONTROLLER_BWRAP = {
    "id": "controller-bubblewrap", "package": "bubblewrap", "version": "0.9.0-1ubuntu0.1", "architecture": "amd64",
    "transport": {
        "url": "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.1_amd64.deb",
        "format": "deb", "bytes": 50178,
        "sha256": "1b506492bd9c7fd0cdb4f02ac822f1d3e336b0aead5113c1239baf8db5db562a"},
    "decoded": {"bytes": 133120, "memberCount": 30,
        "sha256": "b2561ecbedb734301c7bd7cb254476d042be5da011e0e57ffc3ebc1077d5332e"},
    "member": {"path": "./usr/bin/bwrap", "size": 72160, "mode": 0o755,
        "sha256": "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"}}
_OWNER = None
_STAGE = "admission"


def stage(name: str) -> None:
    global _STAGE
    _STAGE = name


class Refused(ValueError):
    pass


def need(ok: bool, message: str) -> None:
    if not ok:
        raise Refused(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii") + b"\n"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha(value: object) -> str:
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "Missing SHA256 admission")
    return value


def relative(value: object) -> str:
    need(type(value) is str and 0 < len(value) <= 512
         and re.fullmatch(r"[A-Za-z0-9_./+@=,\-]+", value) is not None
         and all(part not in {"", ".", ".."} for part in value.split("/")), "Unsafe DATA path")
    return value


def source_member_name(identifier: str, value: str) -> str:
    # Source DATA spelling only: no strip/rename/expansion or file admission.
    # The pinned archive root and closed inventory below authorize each member.
    need(identifier in SOURCES and type(value) is str and 0 < len(value) <= 512
         and re.fullmatch(r"[A-Za-z0-9_./+@=,~ \-]+", value) is not None
         and all(part not in {"", ".", ".."} for part in value.split("/")), "Unsafe source DATA path")
    return value


def decode(raw: bytes) -> object:
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "Duplicate JSON field")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite JSON")))
    need(canonical(value) == raw, "Noncanonical control DATA")
    return value


def state(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directory(path: Path, *, root_owned: bool = False) -> None:
    need(path.is_absolute(), "Absolute directory required")
    for current in (path, *path.parents):
        item = current.lstat()
        need(stat.S_ISDIR(item.st_mode), "Nonordinary directory ancestor")
        if root_owned and current == path:
            need(item.st_uid == 0 and not item.st_mode & 0o022, "Controller directory is writable by another UID")


def read(path: Path, limit: int = JSON_LIMIT) -> bytes:
    directory(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "Nonordinary or oversized input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(state(os.fstat(fd)) == state(before), "Input changed before open")
        blocks, size = [], 0
        while block := os.read(fd, min(CHUNK, before.st_size - size + 1)):
            size += len(block)
            need(size <= before.st_size, "Input grew during read")
            blocks.append(block)
        need(size == before.st_size and state(os.fstat(fd)) == state(before) == state(path.lstat()),
             "Input changed during read")
    finally:
        os.close(fd)
    return b"".join(blocks)


def kernel(path: Path, limit: int = 64 << 10) -> str:
    # proc/cgroup files have nominal size0 and legitimately changing counters.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, limit + 1)
        need(len(raw) <= limit and not os.read(fd, 1), "Kernel property bound exceeded")
        return raw.decode("ascii")
    finally:
        os.close(fd)


def record(path: Path, limit: int = GiB) -> dict:
    directory(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
         "File correspondence bound/type differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    size, hashed = 0, hashlib.sha256()
    try:
        need(state(os.fstat(fd)) == state(before), "Correspondence changed before open")
        while block := os.read(fd, CHUNK):
            size += len(block)
            need(size <= before.st_size, "Correspondence grew")
            hashed.update(block)
        need(size == before.st_size and state(os.fstat(fd)) == state(before) == state(path.lstat()),
             "Correspondence changed during read")
    finally:
        os.close(fd)
    return {"path": str(path), "size": size, "sha256": hashed.hexdigest()}


def bound(path: Path, expected: dict, limit: int = JSON_LIMIT) -> bytes:
    raw = read(path, limit)
    need((len(raw), digest(raw)) == (expected["size"], sha(expected["sha256"])), "Pinned bytes differ")
    return raw


def write(path: Path, raw: bytes, mode: int = 0o444) -> dict:
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        for offset in range(0, len(raw), CHUNK):
            block = raw[offset:offset + CHUNK]
            need(os.write(fd, block) == len(block), "Short evidence write")
        os.fsync(fd)
    finally:
        os.close(fd)
    need(read(path, len(raw)) == raw and stat.S_IMODE(path.lstat().st_mode) == mode,
         "Evidence readback/mode differs")
    return {"path": str(path), "size": len(raw), "sha256": digest(raw)}


def copy(source: Path, target: Path, expected: dict, mode: int = 0o444) -> dict:
    # Bounded streaming copy, preserving the original bytes and original failure.
    need(record(source) == {**expected, "path": str(source)}, "Original copy input differs")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory(target.parent)
    original = source.lstat()
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    dst = None
    try:
        need(state(os.fstat(src)) == state(original), "Copy source changed")
        dst = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        os.fchmod(dst, mode)
        count = 0
        while block := os.read(src, CHUNK):
            count += len(block)
            need(count <= expected["size"] and os.write(dst, block) == len(block), "Copy bound/short write")
        need(count == expected["size"] and state(os.fstat(src)) == state(original) == state(source.lstat()),
             "Copy source correspondence changed")
        os.fsync(dst)
    finally:
        try:
            if dst is not None:
                os.close(dst)
        finally:
            os.close(src)
    actual = record(target)
    need(actual == {**expected, "path": str(target)}, "Copy readback differs")
    return actual


def literal(raw: bytes, name: str) -> str:
    # Inspect constants-only admission as DATA BEFORE any repository import.
    values = [node.value for node in ast.parse(raw).body if isinstance(node, ast.AnnAssign)
              and isinstance(node.target, ast.Name) and node.target.id == name]
    need(len(values) == 1 and isinstance(values[0], ast.Constant), "Admission literal missing")
    return sha(values[0].value)


def recipient_manifest(raw: bytes) -> dict:
    """Pinned recipient DATA only, not another native source/tool input."""
    doc = decode(raw)
    need(type(doc) is dict and set(doc) == {"schema", "profile", "scope", "sourceRoute", "texts", "sourceArchives"}
         and doc["schema"] == "mrk-cpython-recipient-materials-1" and doc["profile"] == PROFILE
         and doc["scope"] == "hosted-source-verification-only" and doc["sourceRoute"] == "LGPL-2.1-6a-6d",
         "Different recipient material contract")
    texts = doc["texts"]
    need(type(texts) is list and 1 <= len(texts) <= 40, "Recipient text count bound")
    names = []
    for row in texts:
        need(type(row) is dict and set(row) == {"path", "size", "sha256"}
             and type(row["size"]) is int and 0 < row["size"] <= 256 << 10, "Recipient text extent differs")
        name = relative(row["path"])
        need("/" not in name, "Recipient texts must be flat ordinary filenames")
        sha(row["sha256"])
        names.append(name)
    need(names == sorted(set(names)) and RECIPIENT_DOCS <= set(names)
         and sum(row["size"] for row in texts) <= MiB, "Recipient text roster/aggregate differs")
    sources = doc["sourceArchives"]
    need(type(sources) is list and len(sources) == len(RECIPIENT_SOURCES), "Recipient source roster differs")
    for row, (identifier, name, kind) in zip(sources, RECIPIENT_SOURCES):
        need(type(row) is dict and set(row) == {"id", "path", "transport"}
             and row["id"] == identifier and row["path"] == name, "Different recipient source role")
        item = row["transport"]
        need(type(item) is dict and set(item) == {"url", "format", "bytes", "sha256"}
             and item["format"] == kind and type(item["bytes"]) is int and 0 < item["bytes"] <= 20 * MiB
             and item["url"] == "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/g/glibc/" + name,
             "Different recipient source transport")
        sha(item["sha256"])
    need(sum(row["transport"]["bytes"] for row in sources) <= 20 * MiB, "Recipient source aggregate bound")
    return doc


def recipient_text_inputs(root: Path, doc: dict) -> dict[str, bytes]:
    # Only prepare() reads sibling text bodies. The inside admission sees the
    # small read-only control manifest, never these outside source/notice paths.
    return {row["path"]: bound(root / row["path"], row, 256 << 10) for row in doc["texts"]}


def admission(controls: Path, helpers: Path) -> dict:
    sha(APPROVED_HOSTED_INPUTS_SHA256)  # No mkdir, import, child or network before this gate.
    raw = read(controls / INDEX_NAME, 64 << 10)
    need(digest(raw) == APPROVED_HOSTED_INPUTS_SHA256, "Different hosted input index")
    index = decode(raw)
    need(type(index) is dict and set(index) == {"schema", "profile", "state", "controls", "recipeFiles"}
         and index["schema"] == "mrk-cpython-source-hosted-inputs-1" and index["profile"] == PROFILE
         and index["state"] == "reviewed-inputs-only", "Different hosted index contract")
    blobs, helper_bytes = {}, {}
    for field, roster, root, output in (("controls", CONTROLS, controls, blobs),
                                      ("recipeFiles", HELPERS, helpers, helper_bytes)):
        rows = index[field]
        need(type(rows) is list and [r["path"] for r in rows] == list(roster), "Hosted closed roster differs")
        need(sum(r["size"] for r in rows) <= 64 * MiB, "Control footprint differs")
        for row in rows:
            need(set(row) == {"path", "size", "sha256"} and type(row["size"]) is int
                 and 0 <= row["size"] <= JSON_LIMIT, "Invalid control correspondence")
            output[row["path"]] = bound(root / row["path"], row)
    pins = {r["path"]: r for r in index["controls"]}
    a = helper_bytes["cpython_source_admission.py"]
    for constant, leaf in (("APPROVED_SOURCE_LOCK_SHA256", "source-lock.json"),
                           ("APPROVED_SOURCE_EXECUTION_REVIEW_SHA256", "source-execution-review.json")):
        need(literal(a, constant) == pins[leaf]["sha256"], "C prerequisite admission differs")
    need(literal(a, "APPROVED_SOURCE_CORE_INPUTS_SHA256") == pins["core-source-files.json"]["sha256"],
         "Current core prerequisite admission differs")
    need(literal(helper_bytes["cpython_static_builder_data.py"], "APPROVED_ROOT_REQUEST_SHA256")
         == pins["root-request.json"]["sha256"], "Root preparation admission differs")
    lock, core = decode(blobs["source-lock.json"]), decode(blobs["core-source-files.json"])
    need(lock["profile"] == PROFILE and lock["coreSourceFiles"] == core, "Lock/current core differ")
    handoffs = {"desktop/engine_bootstrap.py", "desktop/config_edit_bootstrap.py",
        "desktop/github_connection_bootstrap.py", "desktop/environment_bootstrap.py",
        "desktop/offline_preflight_bootstrap.py", "desktop/android_build_bootstrap.py",
        "desktop/tools/prepare_runtime.py", "desktop/github-ca.pem"}
    need(type(core) is list and 8 < len(core) <= 2048 and sum(r["size"] for r in core) <= 64 * MiB,
         "Current core roster/byte bound differs")
    names = []
    for row in core:
        name = relative(Path(row["path"]).relative_to(INPUTS / "core-source").as_posix())
        need(set(row) == {"path", "size", "sha256"} and row["path"] == str(INPUTS / "core-source" / name)
             and (name in handoffs or name.startswith("src/mobile_release/"))
             and type(row["size"]) is int and 0 <= row["size"] <= 8 * MiB, "Foreign/oversized core input")
        sha(row["sha256"])
        names.append(name)
    need(names == sorted(set(names)) and handoffs <= set(names), "Incomplete current whole-core/handoff roster")
    for key, leaf in (("rootfs", "rootfs.json"), ("hostInputs", "host-inputs.json")):
        need(lock[key] == {**pins[leaf], "path": str(INPUTS / leaf)}, "Lock control path differs")
    recipe = sorted(({**r, "path": str(INPUTS / "recipe" / r["path"])} for r in index["recipeFiles"]
                     if r["path"] != "cpython_source_admission.py"), key=lambda r: r["path"])
    need(lock["recipeFiles"] == recipe, "Lock recipe path/hash roster differs")
    transport = decode(blobs["transport-map.json"])
    need(set(transport) == {"schema", "profile", "baseIdentityMetadata", "rootArchiveTransports",
                           "directSourceArchiveTransports"}
         and transport["schema"] == "mrk-cpython-source-transports-1" and transport["profile"] == PROFILE,
         "Different public transport contract")
    roots, sources, metadata = (transport[name] for name in
        ("rootArchiveTransports", "directSourceArchiveTransports", "baseIdentityMetadata"))
    need(len(roots) == 60 and len(sources) == 4 and len(metadata) == 2
         and [r["id"] for r in sources] == list(SOURCES), "Transport count/order differs")
    objects = [*roots, *sources, *metadata]
    need(len({r["id"] for r in objects}) == 66
         and sum(r["transport"]["bytes"] for r in objects) == 195334483
         and sum(r["decoded"]["bytes"] for r in roots) == 404951040, "Transport fixed aggregate differs")
    for row in objects:
        need(re.fullmatch(r"[a-z0-9][a-z0-9+._-]{0,100}", row["id"]) is not None, "Unsafe transport identifier")
        sha(row["transport"]["sha256"])
        need(type(row["transport"]["bytes"]) is int and 0 < row["transport"]["bytes"] <= GiB,
             "Transport size bound differs")
        https_url(row["transport"]["url"])
    need([s["id"] for s in lock["sources"]] == list(SOURCES), "Source lock roster differs")
    for source, supplied in zip(lock["sources"], sources):
        item, leaf = supplied["transport"], source["id"] + "-source-inventory.json"
        need(source["archive"] == {"path": str(INPUTS / "archives" / (source["id"] + ".archive")),
                                  "size": item["bytes"], "sha256": item["sha256"]}
             and source["inventory"] == {**pins[leaf], "path": str(INPUTS / leaf)}
             and source["root"] == str(INPUTS / "sources" / source["id"])
             and source["url"] == item["url"] and source["patches"] == [], "Source transport/lock differs")
    request = decode(blobs["root-request.json"])
    need(request["members"] == {**pins["expected-members.json"], "path": str(PREP / "controls/expected-members.json")}
         and request["selection"] == {**pins["selection.json"], "path": str(PREP / "controls/selection.json")}
         and request["streams"] == sorted(({"id": r["id"], "file": {
             "path": str(PREP / "decoded" / (r["id"] + ".tar")), "size": r["decoded"]["bytes"],
             "sha256": r["decoded"]["sha256"]}} for r in roots), key=lambda r: r["id"]),
         "Root request paths/correspondence differ")
    provenance = decode(blobs["inventory-provenance.json"])
    need(provenance["schema"] == "mrk-conventional-input-inventories-1"
         and provenance["state"] == "DATA_PREPARATION_ONLY"
         and sorted(r["id"] for r in provenance["sources"]) == list(SOURCES)
         and sum(r["regularBytes"] for r in provenance["sources"]) <= 384 * MiB
         and sum(r["regularFiles"] for r in provenance["sources"]) <= 13000,
         "Supplier source census/projection footprint differs")
    recipient = recipient_manifest(blobs[RECIPIENT_NAME])
    prerequisite = decode(blobs["source-execution-review.json"])
    need(prerequisite["requiredRecipientMaterials"]["manifest"] == {
        **pins[RECIPIENT_NAME], "path": str(INPUTS / RECIPIENT_NAME)}, "Recipient prerequisite binding differs")
    return {"index": index, "blobs": blobs, "helpers": helper_bytes, "lock": lock, "core": core,
            "transport": transport, "provenance": provenance, "recipient": recipient}


def owner_modules(root: Path, rows: list[dict]):
    global _OWNER
    if _OWNER is not None:
        return _OWNER
    for row in rows:
        name = Path(row["path"]).relative_to(INPUTS / "core-source")
        if str(name) == "desktop/github-ca.pem":
            continue
        need(record(root / name) == {**row, "path": str(root / name)}, "Host owner input differs")
    allowed = {str(root / Path(r["path"]).relative_to(INPUTS / "core-source")) for r in rows}
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(root / "src"))
        from mobile_release import owned_process
    finally:
        sys.path[:] = previous
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            need(getattr(module, "__file__", None) in allowed, "Foreign host owner import")
    _OWNER = owned_process
    return _OWNER


def run(argv: list[str], seconds: int = 30, *, environment: dict | None = None,
        require_zero: bool = True):
    need(_OWNER is not None and 1 <= seconds <= CLIENT_SECONDS, "Missing original owner/budget")
    result = _OWNER.run_owned(argv, environ=HOST_ENV if environment is None else environment,
        cwd=Path("/"), timeout=seconds, capture=True, text=False, output_limit=MiB,
        execution_scope=None, journal_binding=None, on_start=None, cleanup=False)
    need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
         and type(result.stderr) is bytes, "Original command result/capture incomplete")
    if require_zero:
        need(result.returncode == 0, "Original fixed command failed; no retry")
    return result


def remaining(deadline: float, maximum: int) -> int:
    value = math.floor(deadline - time.monotonic())
    need(value >= 1, "Original common deadline exhausted")
    return min(value, maximum)


def https_url(value: str) -> None:
    parsed = urllib.parse.urlsplit(value)
    need(parsed.scheme == "https" and parsed.hostname and parsed.username is None
         and parsed.password is None and parsed.port in {None, 443} and not parsed.fragment,
         "Only credential-free HTTPS input transport is permitted")


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 4
    max_repeats = 1

    def redirect_request(self, request, fp, code, message, headers, newurl):
        https_url(newurl)
        result = super().redirect_request(request, fp, code, message, headers, newurl)
        if result is not None and urllib.parse.urlsplit(request.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            result.remove_header("Authorization")
        return result


def download_inputs(data: dict, deadline: float) -> None:
    stage("transport-trust")
    context = ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), PublicRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    # Fixed anonymous public-pull token, never a repository/runner credential.
    # Do not retain its response, headers or value in evidence or diagnostics.
    stage("transport-token")
    token_url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull"
    with opener.open(token_url, timeout=remaining(deadline, 30)) as response:
        raw = response.read((16 << 10) + 1)
        need(len(raw) <= 16 << 10 and not response.read(1), "Anonymous token response bound")
    token = json.loads(raw)["token"]
    need(type(token) is str and 0 < len(token) <= 12 << 10 and all(33 <= ord(c) <= 126 for c in token),
         "Anonymous pull token format differs")
    objects = [*data["transport"]["rootArchiveTransports"],
        *data["transport"]["directSourceArchiveTransports"], *data["transport"]["baseIdentityMetadata"], CONTROLLER_BWRAP,
        *data["recipient"]["sourceArchives"]]
    for row in objects:
        stage("transport-" + row["id"])
        item = row["transport"]
        headers = {"Accept": "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"}
        if urllib.parse.urlsplit(item["url"]).hostname == "registry-1.docker.io":
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(item["url"], headers=headers)
        path = PREP / "objects" / item["sha256"]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
        total, hashed = 0, hashlib.sha256()
        try:
            with opener.open(request, timeout=remaining(deadline, 30)) as response:
                need(response.status == 200, "Input HTTP status differs")
                while block := response.read(CHUNK):
                    remaining(deadline, 30)
                    total += len(block)
                    need(total <= item["bytes"] and os.write(fd, block) == len(block), "Input transport byte/write bound")
                    hashed.update(block)
            need((total, hashed.hexdigest()) == (item["bytes"], item["sha256"]), "Input transport identity differs")
            os.fsync(fd)
        finally:
            os.close(fd)
        need(record(path) == {"path": str(path), "size": item["bytes"], "sha256": item["sha256"]},
             "Input transport readback differs")


def controller_bwrap_member(raw: bytes) -> bytes:
    # The complete decoded pin closes the package roster. Inspect bounded DATA
    # only; no tar extraction API applies names, links or metadata to the host.
    decoded, wanted = CONTROLLER_BWRAP["decoded"], CONTROLLER_BWRAP["member"]
    need((len(raw), digest(raw)) == (decoded["bytes"], decoded["sha256"]) and len(raw) <= MiB,
         "Controller bubblewrap decoded stream differs")
    seen, selected = set(), None
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            need(member.name not in seen and len(seen) < decoded["memberCount"],
                 "Controller bubblewrap member roster differs")
            seen.add(member.name)
            if member.name != wanted["path"]:
                continue
            need(member.type == tarfile.REGTYPE and not member.sparse and not member.linkname,
                 "Controller bubblewrap member is not ordinary")
            need(member.size == wanted["size"] and member.mode == wanted["mode"]
                 and not member.mode & 0o7000, "Controller bubblewrap member extent/mode differs")
            body = archive.extractfile(member)
            need(body is not None, "Controller bubblewrap member body missing")
            with body:
                selected = body.read(wanted["size"] + 1)
            need((len(selected), digest(selected)) == (wanted["size"], wanted["sha256"]),
                 "Controller bubblewrap member bytes differ")
    need(len(seen) == decoded["memberCount"] and selected is not None,
         "Controller bubblewrap member roster differs")
    return selected


def controller_bwrap_record() -> dict:
    directory(BWRAP_PATH.parent, root_owned=True)
    before = BWRAP_PATH.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
         and stat.S_IMODE(before.st_mode) == 0o555, "Prepared controller bubblewrap ownership/mode differs")
    wanted = CONTROLLER_BWRAP["member"]
    actual = record(BWRAP_PATH, wanted["size"])
    need(actual == {"path": str(BWRAP_PATH), "size": wanted["size"], "sha256": wanted["sha256"]}
         and state(BWRAP_PATH.lstat()) == state(before), "Prepared controller bubblewrap bytes changed")
    return {**actual, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "links": before.st_nlink}


def prepare_controller_bwrap(deadline: float) -> dict:
    stage("controller-bubblewrap-decoder")
    item = CONTROLLER_BWRAP["transport"]
    source = PREP / "objects" / item["sha256"]
    original = record(source)
    need(original == {"path": str(source), "size": item["bytes"], "sha256": item["sha256"]},
         "Controller bubblewrap archive differs")
    seconds = remaining(deadline, 30)
    result = run(["/usr/bin/dpkg-deb", "--fsys-tarfile", str(source)], seconds, require_zero=False)
    stdout = write(BWRAP_RECEIPT.with_suffix(".stdout"), result.stdout)
    stderr = write(BWRAP_RECEIPT.with_suffix(".stderr"), result.stderr)
    # Preserve the actual original result/capture before judging exit or member
    # acceptance. An owner exception produces no invented command receipt.
    write(BWRAP_RECEIPT, canonical({"schema": "mrk-cpython-source-controller-decoder-1",
        "id": CONTROLLER_BWRAP["id"], "archive": original, "argv": result.args,
        "originalExitCode": result.returncode, "originalOwnerReturned": True, "captureComplete": True,
        "timeoutSeconds": seconds, "outputLimitBytes": MiB, "stdout": stdout, "stderr": stderr}))
    need(result.returncode == 0, "Original controller bubblewrap decoder failed; no retry")
    stage("controller-bubblewrap-member")
    selected = controller_bwrap_member(result.stdout)
    remaining(deadline, PREP_SECONDS)
    stage("controller-bubblewrap-seal")
    write(BWRAP_PATH, selected, 0o555)
    return controller_bwrap_record()


def decode_root(identifier: str) -> None:
    # Fixed DATA exec adapter, not another owner/supervisor. run_owned owns the
    # original gzip/dpkg-deb exec and all its streams/descendants. Output is a
    # fresh size-capped preparation file, never a compiler's outside descriptor.
    data = admission(PREP / "controls", PREP / "inputs/recipe")
    rows = [r for r in data["transport"]["rootArchiveTransports"] if r["id"] == identifier]
    need(os.getuid() == 0 and len(rows) == 1, "Unknown fixed root decoder")
    row = rows[0]
    stage("root-decoder-" + identifier)
    source = PREP / "objects" / row["transport"]["sha256"]
    need(record(source) == {"path": str(source), "size": row["transport"]["bytes"],
                           "sha256": row["transport"]["sha256"]}, "Decoder input differs")
    size = row["decoded"]["bytes"]
    need(0 < size <= GiB, "Decoded root extent bound")
    resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
    resource.setrlimit(resource.RLIMIT_AS, (512 * MiB, 512 * MiB))
    fd = os.open(PREP / "decoded" / (identifier + ".tar"),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
    try:
        os.dup2(fd, 1, inheritable=True)
    finally:
        os.close(fd)
    if identifier == "base" and row["transport"]["format"] == "oci-tar-gzip-layer":
        argv = ["/usr/bin/gzip", "--decompress", "--stdout", str(source)]
    else:
        need(row["transport"]["format"] == "deb", "Different root decoder format")
        argv = ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(source)]
    os.execve(argv[0], argv, HOST_ENV)


def source_tree(data: dict, source: dict, deadline: float) -> None:
    """Ordinary DATA materialization against the supplier's complete inventory.

    The supplier owns the census and decoder/header review. No new accepted
    inventory is derived here, and tar metadata is never applied to the host.
    """
    identifier = source["id"]
    inventory = decode(data["blobs"][identifier + "-source-inventory.json"])["files"]
    planned = {r["path"]: r for r in inventory}
    provenance = next(r for r in data["provenance"]["sources"] if r["id"] == identifier)
    need(len(planned) == len(inventory) == provenance["regularFiles"]
         and sum(r["size"] for r in inventory) == provenance["regularBytes"] <= 256 * MiB,
         "Supplier source inventory extent differs")
    root = PREP / "inputs/sources" / identifier
    root.mkdir(mode=0o755)
    archive = PREP / "inputs/archives" / (identifier + ".archive")
    seen, directories = set(), set()
    with tarfile.open(archive, mode="r|*") as stream:
        for member in stream:
            remaining(deadline, PREP_SECONDS)
            name = source_member_name(identifier, member.name.rstrip("/"))
            prefix = provenance["archiveRoot"]
            need(name == prefix or name.startswith(prefix + "/"), "Source archive root differs")
            need(member.isreg() or member.isdir(), "Source aliases/special files forbidden")
            need(not member.sparse and not member.mode & 0o7000, "Source sparse/set-ID metadata forbidden")
            logical = str(INPUTS / "sources" / identifier) + name[len(prefix):]
            target = root if name == prefix else root / source_member_name(identifier, name[len(prefix) + 1:])
            if member.isdir():
                need(logical not in directories and logical not in seen, "Duplicate source directory")
                directories.add(logical)
                allowed = provenance["modeProjection"]["directories"]
                need(str(member.mode) in allowed and allowed[str(member.mode)] == 0o755, "Source directory mode differs")
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            need(logical in planned and logical not in seen and logical not in directories, "Unlisted/duplicate source body")
            row = planned[logical]
            need(member.size == row["size"] <= 64 * MiB and provenance["modeProjection"]["files"].get(str(member.mode))
                 == row["mode"] in {0o644, 0o755}, "Source extent/mode projection differs")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            body = stream.extractfile(member)
            need(body is not None, "Missing original source body")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, row["mode"])
            hashed, count = hashlib.sha256(), 0
            try:
                os.fchmod(fd, row["mode"])
                with body:
                    while block := body.read(CHUNK):
                        count += len(block)
                        need(count <= row["size"] and os.write(fd, block) == len(block), "Source body copy bound")
                        hashed.update(block)
                need((count, hashed.hexdigest()) == (row["size"], row["sha256"]), "Source body identity differs")
                os.fsync(fd)
            finally:
                os.close(fd)
            need(record(target) == {"path": str(target), "size": row["size"], "sha256": row["sha256"]},
                 "Source body readback differs")
            seen.add(logical)
    need(seen == set(planned) and directories == {r["path"] for r in provenance["directories"]},
         "Complete source file/directory roster differs")


def footprint(root: Path, maximum: int, entries: int, *, seal: bool = False) -> dict:
    count, allocated, pending = 0, 0, [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as children:
            for child in children:
                item = child.stat(follow_symlinks=False)
                count += 1
                allocated += max(item.st_blocks * 512, ((item.st_size + 4095) // 4096) * 4096)
                need(count <= entries and allocated <= maximum, "Preparation/retention footprint bound")
                need(item.st_uid == 0, "Noncontroller preparation owner")
                if stat.S_ISDIR(item.st_mode):
                    pending.append(Path(child.path))
                    if seal:
                        os.chmod(child.path, 0o555)
                elif stat.S_ISREG(item.st_mode):
                    need(item.st_nlink == 1, "Linked preparation body")
                else:
                    need(stat.S_ISLNK(item.st_mode) and Path(child.path).is_relative_to(PREP / "root"),
                         "Special preparation body")
    if seal:
        os.chmod(root, 0o555)
    return {"allocatedBytesUpperBound": allocated, "entries": count, "maximumBytes": maximum,
            "maximumEntries": entries}


def admit_root_report(expected: bytes) -> None:
    # The root materializer intentionally writes private0600 reports. This one
    # authenticated, nonsecret control must also be readable by the inside UID.
    # Do not change its writer/defaults or any other file's permissions.
    path = PREP / "inputs/rootfs.json"
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0
         and stat.S_IMODE(before.st_mode) == 0o600, "Original root report identity/mode differs")
    need(read(path) == expected, "Actual root materialization differs from expectation")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(state(os.fstat(fd)) == state(before) == state(path.lstat()), "Root report changed before admission")
        os.fchmod(fd, 0o444)
        after = os.fstat(fd)
        # fchmod deliberately changes mode/ctime, not identity or content.
        need(stat.S_IMODE(after.st_mode) == 0o444 and all(getattr(after, name) == getattr(before, name)
             for name in ("st_dev", "st_ino", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns")),
             "Root report mode/identity readback differs")
        need(read(path) == expected and state(os.fstat(fd)) == state(after) == state(path.lstat()),
             "Root report admission readback differs")
    finally:
        os.close(fd)  # A failed original close also refuses further preparation.


def context_from_environment() -> dict:
    source, run_id = os.environ.get("MRK_SOURCE_SHA", ""), os.environ.get("MRK_RUN_ID", "")
    need(re.fullmatch(r"[0-9a-f]{40}", source) is not None and source != "0" * 40
         and re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None
         and os.environ.get("MRK_RUN_ATTEMPT") == "1", "Fixed one-attempt source context missing")
    return {"sourceSha": source, "runId": run_id, "attempt": 1}


def platform_tools() -> list[dict]:
    tools = []
    for name in HOST_TOOLS:
        path = Path(name)
        stage("host-tool-" + path.name)  # Closed public roles, never an OS error's path/text.
        try:
            item = path.lstat()
            # Ubuntu's fixed controller mount may be root-owned04755. The already
            # root controller gains no privilege; no native-tool/drop rule changes.
            mount_suid = name == "/usr/bin/mount" and stat.S_IMODE(item.st_mode) == 0o4755
            need(stat.S_ISREG(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o2022
                 and (not item.st_mode & stat.S_ISUID or mount_suid),
                 "Required preinstalled root-owned platform tool unavailable; no repair")
            tools.append(record(path))
        except FileNotFoundError:
            raise Refused("Required preinstalled platform tool missing; no repair") from None
    return tools


def prepare() -> None:
    started = time.monotonic()
    need(os.getresuid() == (0, 0, 0) and sys.flags.isolated and sys.flags.no_site
         and sys.flags.dont_write_bytecode, "Use fixed privileged isolated preparation entry")
    checkout = Path(__file__).absolute().parents[2]
    data = admission(checkout / "desktop/cpython-source-inputs", checkout / "desktop/tools")
    stage("context")
    context = context_from_environment()
    deadline = started + PREP_SECONDS
    tools = platform_tools()
    stage("recipient-text-admission")
    texts = recipient_text_inputs(checkout / "desktop/cpython-source-inputs/recipient", data["recipient"])
    stage("input-directories")
    # The fixed preinstalled tools have refused before preparation effects.
    # Source/control files are copied once, not by another packaging framework.
    PREP.mkdir(mode=0o700)
    for name in ("controls", "controller", "objects", "decoded", "inputs", "inputs/recipe", "inputs/archives",
                 "inputs/sources", "inputs/core-source", "preparation-results", "recipient"):
        (PREP / name).mkdir(mode=0o700)
    write(PREP / "INCOMPLETE", b"Input preparation has no successful result.\n")
    for leaf, raw in data["blobs"].items():
        stage("input-control-" + leaf)
        write(PREP / "controls" / leaf, raw)
        if leaf != "rootfs.json":
            write(PREP / "inputs" / leaf, raw)
    stage("input-index")
    index = read(checkout / "desktop/cpython-source-inputs" / INDEX_NAME, 64 << 10)
    write(PREP / "controls" / INDEX_NAME, index)
    write(PREP / "inputs" / INDEX_NAME, index)
    stage("recipient-text-copy")
    for name, raw in texts.items():
        write(PREP / "recipient" / name, raw)
    for leaf, raw in data["helpers"].items():
        stage("input-helper-" + leaf)
        write(PREP / "inputs/recipe" / leaf, raw)
    stage("input-entry")
    entry = read(Path(__file__).absolute(), MiB)
    write(PREP / "inputs/recipe" / ENTRY_NAME, entry)
    for number, row in enumerate(data["core"], 1):
        stage(f"input-core-{number:04d}")  # Position in the admitted, bounded roster.
        name = Path(row["path"]).relative_to(INPUTS / "core-source")
        source = (checkout / "desktop/cpython-source-inputs/github-ca.pem" if str(name) == "desktop/github-ca.pem"
                  else checkout / name)
        copy(source, PREP / "inputs/core-source" / name, {**row, "path": str(source)})
    stage("owner-import")
    owner_modules(PREP / "inputs/core-source", data["core"])
    stage("transport")
    download_inputs(data, deadline)
    controller_bwrap = prepare_controller_bwrap(deadline)
    for row in data["transport"]["rootArchiveTransports"]:
        stage("root-decoder-" + row["id"])
        result = run(["/usr/bin/python3.12", "-I", "-S", "-B", str(PREP / "inputs/recipe" / ENTRY_NAME),
                      "decode-root", row["id"]], remaining(deadline, 120), require_zero=False)
        expected = {"path": str(PREP / "decoded" / (row["id"] + ".tar")),
                    "size": row["decoded"]["bytes"], "sha256": row["decoded"]["sha256"]}
        need(not result.stdout and len(result.stderr) <= 32 << 10, "Root decoder diagnostic bound differs")
        write(PREP / "preparation-results" / (row["id"] + ".json"), canonical({
            "id": row["id"], "originalExitCode": result.returncode,
            "stdout": result.stdout.decode("ascii"), "stderr": result.stderr.decode("ascii"), "expectedDecoded": expected}))
        need(result.returncode == 0, "Original root decoder failed; no retry")
        need(record(Path(expected["path"])) == expected, "Complete decoded root stream differs")
    stage("root-materialization")
    spec = importlib.util.spec_from_file_location("_mrk_hosted_root_data", PREP / "inputs/recipe/cpython_static_builder_data.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # Every imported helper was hash-pinned above.
    module.materialize_source_root(PREP / "controls/root-request.json", PREP / "root", PREP / "inputs/rootfs.json")
    stage("root-report-admission")
    admit_root_report(data["blobs"]["rootfs.json"])
    for source in data["lock"]["sources"]:
        stage("source-materialization-" + source["id"])
        target = PREP / "inputs/archives" / (source["id"] + ".archive")
        original = PREP / "objects" / source["archive"]["sha256"]
        copy(original, target, {**source["archive"], "path": str(original)})
        source_tree(data, source, deadline)
    remaining(deadline, PREP_SECONDS)
    stage("preparation-retention")
    space = footprint(PREP, PREP_BYTES - MiB, PREP_ENTRIES - 2, seal=True)
    # Temporarily keep only the controller top directory writable for this
    # original final result; its children are already sealed, with root ownership.
    os.chmod(PREP, 0o700)
    write(PREP / "prepared.json", canonical({"schema": "mrk-cpython-source-preparation-1", **context,
        "state": "input-correspondence-only", "entrySha256": digest(entry), "hostTools": tools,
        "controllerBwrap": controller_bwrap,
        "footprint": space, "elapsedSeconds": time.monotonic() - started,
        "networkPreparationComplete": True, "nativeQualification": "not-established"}))
    (PREP / "INCOMPLETE").unlink()
    os.chmod(PREP, 0o555)


def prepared() -> tuple[dict, dict]:
    directory(PREP, root_owned=True)
    data = admission(PREP / "controls", PREP / "inputs/recipe")
    saved = decode(read(PREP / "prepared.json", MiB))
    need(saved["schema"] == "mrk-cpython-source-preparation-1" and saved["networkPreparationComplete"] is True
         and saved["state"] == "input-correspondence-only" and not (PREP / "INCOMPLETE").exists()
         and digest(read(PREP / "inputs/recipe" / ENTRY_NAME, MiB)) == saved["entrySha256"],
         "Original input preparation did not complete")
    need(saved["controllerBwrap"] == controller_bwrap_record(), "Prepared controller bubblewrap record differs")
    owner_modules(PREP / "inputs/core-source", data["core"])
    return data, saved


def status_fields() -> dict:
    return dict(line.split(":", 1) for line in kernel(Path("/proc/self/status")).splitlines() if ":" in line)


def namespaces() -> dict:
    return {name: os.stat("/proc/self/ns/" + name).st_ino for name in NS_NAMES}


def mounts(*, only: str | None = None) -> dict:
    rows = {}
    for line in kernel(Path("/proc/self/mountinfo"), MiB).splitlines():
        left, right = line.split(" - ", 1)
        fields, fs = left.split(), right.split()
        point = fields[4]
        # The controller needs only its fresh work mount. Unrelated host stacks
        # and escaped names do not describe that mount. The inside caller keeps
        # the default complete view, including every writable-mount check.
        if only is not None and point != only:
            continue
        need(point not in rows, "Duplicate mountpoint in required view")
        need("\\" not in point, "Escaped mountpoint in required view")
        rows[point] = {"options": fields[5].split(","), "type": fs[0], "source": fs[1],
                       "superOptions": fs[2].split(","), "device": fields[2]}
    return rows


def task_capacity(path: Path) -> dict:
    item, table = os.statvfs(path), mounts(only=str(path))
    need(str(path) in table and table[str(path)]["type"] == "tmpfs", "Original work mount is not tmpfs")
    row = table[str(path)]
    need({"rw", "nosuid", "nodev"} <= set(row["options"])
         and item.f_blocks * item.f_frsize == WORK_BYTES and item.f_files == WORK_INODES,
         "Actual work byte/inode/mount limits differ")
    return {"bytes": item.f_blocks * item.f_frsize, "inodes": item.f_files,
            "freeBytes": item.f_bavail * item.f_frsize, "freeInodes": item.f_favail, "mount": row}


def thread_uses_account(fields: dict, uid: int, gid: int) -> bool:
    return (uid in map(int, fields["Uid"].split()) or gid in map(int, fields["Gid"].split())
            or gid in map(int, fields["Groups"].split()))


def new_account(name: str) -> tuple[int, int]:
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(name)
        except KeyError:
            pass
        else:
            raise Refused("Task account name already exists; no adoption/retry")
    result = run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--no-log-init",
                  "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name])
    account, group = pwd.getpwnam(name), grp.getgrnam(name)
    uid, gid = account.pw_uid, account.pw_gid
    users, groups = pwd.getpwall(), grp.getgrall()
    need(0 < uid < 1 << 31 and 0 < gid < 1 << 31 and group.gr_gid == gid and not group.gr_mem
         and account.pw_dir == "/nonexistent" and account.pw_shell == "/usr/sbin/nologin"
         and len(users) <= 4096 and len(groups) <= 4096
         and [p.pw_name for p in users if p.pw_uid == uid or p.pw_gid == gid] == [name]
         and [g.gr_name for g in groups if g.gr_gid == gid] == [name]
         and not any(name in g.gr_mem for g in groups), "Allocated account is not unique/nonprivileged")
    # One bounded allocation collision check, not a finality/ownership census.
    # Threads may have credentials differing from their process leader.
    count = 0
    with os.scandir("/proc") as processes:
        for process in processes:
            if not process.name.isdecimal():
                continue
            try:
                with os.scandir(Path(process.path) / "task") as threads:
                    for thread in threads:
                        count += 1
                        need(count <= 32768, "Host identity inspection bound")
                        try:
                            raw = kernel(Path(thread.path) / "status")
                        except FileNotFoundError:
                            continue  # No ownership or successful-finality inference.
                        fields = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
                        need(not thread_uses_account(fields, uid, gid),
                             "Another host task already uses allocated credentials")
            except FileNotFoundError:
                continue
    write(CONTROL / "account.json", canonical({"name": name, "uid": uid, "gid": gid,
        "originalUseraddExitCode": result.returncode, "hostThreadsInspected": count}))
    return uid, gid


def seconds_value(value: str) -> float:
    if value == "0":
        return 0
    units = {"us": 0.000001, "ms": 0.001, "s": 1, "min": 60, "h": 3600}
    tokens = re.findall(r"([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h)", value)
    need(tokens and " ".join(number + unit for number, unit in tokens) == value, "Unknown effective time format")
    return sum(float(number) * units[unit] for number, unit in tokens)


def userns_denied(value: str) -> bool:
    # systemctl renders the *allowed* namespace set, not necessarily '~user'.
    needed = {"mnt", "uts", "ipc", "pid", "net"}
    tokens = set(value.split())
    if value.isdecimal():
        mask = int(value)
        required = 0x00020000 | 0x04000000 | 0x08000000 | 0x20000000 | 0x40000000
        return not mask & 0x10000000 and mask & required == required
    return needed <= tokens <= needed | {"cgroup", "time"}


def show_unit(name: str) -> dict:
    result = run(["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(SHOW), name], 3)
    rows = result.stdout.decode("ascii").splitlines()
    values = dict(row.split("=", 1) for row in rows)
    need(len(values) == len(rows) and set(values) == set(SHOW) and values["Id"] == name,
         "Original unit property readback incomplete")
    for key in ("Type", "ExitType", "Restart", "KillMode", "OOMPolicy", "SendSIGKILL", "NoNewPrivileges", "Delegate"):
        need(values[key] == PROPERTIES[key], "Effective service policy differs")
    need(values["MemoryMax"] == str(6 * GiB) and values["MemorySwapMax"] == "0"
         and values["TasksMax"] == "64" and seconds_value(values["RuntimeMaxUSec"]) == RUNTIME_SECONDS
         and seconds_value(values["RuntimeRandomizedExtraUSec"]) == 0
         and seconds_value(values["TimeoutStartUSec"]) == 10
         and seconds_value(values["TimeoutStopUSec"]) == STOP_SECONDS
         and userns_denied(values["RestrictNamespaces"]), "Effective unit limits/namespace restriction differ")
    return values


def domain(context: dict) -> dict:
    unit = show_unit(context["unit"])
    invocation = os.environ.get("INVOCATION_ID", "")
    need(re.fullmatch(r"[0-9a-f]{32}", invocation) is not None and unit["InvocationID"] == invocation,
         "Original systemd invocation differs")
    membership = kernel(Path("/proc/self/cgroup"))
    expected = "/system.slice/" + context["unit"]
    need(membership == "0::" + expected + "\n" and unit["ControlGroup"] == expected,
         "Service is not in its exact unified aggregate domain")
    root = Path("/sys/fs/cgroup" + expected)
    need(kernel(root / "cgroup.type") == "domain\n", "Threaded/unknown cgroup domain")
    effective = {name: kernel(root / name).strip() for name in
        ("memory.max", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max")}
    need(effective["memory.max"] == str(6 * GiB) and effective["memory.swap.max"] == "0"
         and effective["memory.oom.group"] == "1" and effective["pids.max"] == "64", "Effective controller limits differ")
    quota, period = effective["cpu.max"].split()
    need(quota.isdecimal() and period.isdecimal() and int(quota) == 2 * int(period) and int(period) > 0,
         "Effective aggregate CPU quota differs")
    counters = {}
    for name in ("memory.events", "pids.events"):
        counters[name] = {key: int(value) for key, value in (line.split() for line in kernel(root / name).splitlines())}
    need({"max", "oom", "oom_kill"} <= set(counters["memory.events"]) and "max" in counters["pids.events"],
         "Effective failure counters unavailable")
    status = status_fields()
    need(status["NoNewPrivs"].strip() == "1" and status["Seccomp"].strip() == "2"
         and int(status["Seccomp_filters"]) >= 1, "Unit namespace syscall filter/no-new-privs not active")
    return {"unit": unit, "invocationId": invocation, "effective": effective, "events": counters,
            "memoryCurrent": int(kernel(root / "memory.current")),
            "memoryPeak": int(kernel(root / "memory.peak")), "pidsCurrent": int(kernel(root / "pids.current")),
            "seccomp": 2, "noNewPrivileges": True}


def no_denials(observation: dict) -> bool:
    events = observation["events"]
    return (all(value == 0 for key, value in events["memory.events"].items() if key not in {"low"})
            and all(value == 0 for value in events["pids.events"].values())
            and observation["memoryPeak"] <= 6 * GiB)


def bwrap_argv(context: dict) -> list[str]:
    # RestrictNamespaces=~user is the inherited systemd syscall restriction.
    # bwrap's sysctl-specific --assert-userns-disabled is not used as a proxy for
    # that effective restriction. In particular, NO --unshare-user/--unshare-all.
    command = [str(BWRAP_PATH), "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--die-with-parent", "--new-session", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP",
        "--ro-bind", str(PREP / "root"), "/", "--bind", str(WORK), "/work",
        "--ro-bind", str(PREP / "inputs"), str(INPUTS),
        "--ro-bind", str(CONTROL / "context.json"), str(INNER_CONTEXT),
        "--proc", "/proc", "--remount-ro", "/proc", "--size", str(DEV_BYTES), "--tmpfs", "/dev"]
    for name in ("null", "zero", "random", "urandom"):
        command.extend(("--dev-bind", "/dev/" + name, "/dev/" + name))
    for name, target in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
                         ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")):
        command.extend(("--symlink", target, "/dev/" + name))
    command += ["--dir", "/dev/shm", "--remount-ro", "/dev", "--bind", str(WORK / "shm"), "/dev/shm",
        # The capability-limited root bootstrap cannot enter task-owned0700
        # work. Enter it only after setpriv and inside()'s effective checks.
        "--chdir", "/", "--", "/usr/bin/setpriv", "--reuid", str(context["uid"]),
        "--regid", str(context["gid"]), "--clear-groups", "--no-new-privs", "--inh-caps=-all",
        "--ambient-caps=-all", "--bounding-set=-all", "--", "/usr/bin/python3.12", "-I", "-S", "-B",
        str(INPUTS / "recipe" / ENTRY_NAME), "inside"]
    return command


def unit_start() -> None:
    stage("unit-limits")
    data, saved = prepared()
    context = decode(read(CONTROL / "context.json", 64 << 10))
    need(os.getresuid() == (0, 0, 0) and context["sourceSha"] == saved["sourceSha"], "Unit start identity differs")
    observation = domain(context)
    need(no_denials(observation), "Resource failure before recipe creation")
    need(not list(WORK.iterdir()), "Original work mount must start empty")
    capacity = task_capacity(WORK)
    # Populated HERE, within the service's charged domain, not by the controller.
    (WORK / "shm").mkdir(mode=0o700)
    os.chown(WORK / "shm", context["uid"], context["gid"])
    write(CONTROL / "unit-start.json", canonical({"schema": "mrk-cpython-source-unit-start-1",
        "sourceSha": saved["sourceSha"], "capacity": capacity, **observation}))
    command = bwrap_argv(context)
    stage("namespace-entry")
    os.execve(command[0], command, data["lock"]["environment"])


def unit_stop() -> None:
    stage("unit-original-finality")
    started = time.monotonic()
    prepared()
    context = decode(read(CONTROL / "context.json", 64 << 10))
    observation = domain(context)
    result = {name: os.environ.get(name) for name in ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS")}
    need(all(type(value) is str and 0 < len(value) <= 128 for value in result.values()),
         "Original systemd completion variables unavailable")
    need(time.monotonic() - started < STOP_POST_SECONDS - 1, "StopPost evidence deadline exhausted")
    write(CONTROL / "unit-stop.json", canonical({"schema": "mrk-cpython-source-unit-stop-1",
        "sourceSha": context["sourceSha"], "completion": result, **observation}))
    need(time.monotonic() - started < STOP_POST_SECONDS, "StopPost original close/readback was late")
    # A nonzero hook cannot be erased by a file saying otherwise: the controller
    # also requires the ORIGINAL systemd-run --wait result and capture to be0.
    need(result == {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
         and no_denials(observation), "Unit failure/OOM/resource denial latched")


def inside() -> None:
    stage("sandbox-context")
    context = decode(read(INNER_CONTEXT, 64 << 10))
    stage("sandbox-identity")
    need(os.getresuid() == (context["uid"],) * 3 and os.getresgid() == (context["gid"],) * 3
         and context["uid"] > 0 and context["gid"] > 0 and os.getgroups() == [], "Real host credentials not dropped")
    stage("sandbox-namespaces")
    actual = namespaces()
    need(actual["user"] == context["hostNamespaces"]["user"]
         and all(actual[name] != context["hostNamespaces"][name] for name in NS_NAMES if name != "user"),
         "Missing namespace separation or remapped host UID")
    stage("sandbox-privileges")
    fields = status_fields()
    need(fields["NoNewPrivs"].strip() == "1" and fields["Seccomp"].strip() == "2"
         and int(fields["Seccomp_filters"]) >= 1
         and all(int(fields[name], 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
         "Privilege regain/capabilities or namespace filter failure")
    for kind, value in LIMITS.items():
        need(resource.getrlimit(kind) == (value, value), "Effective nonraiseable rlimit differs")
    stage("sandbox-descriptors")
    descriptors = os.listdir("/proc/self/fd")
    need(len(descriptors) <= 129 and all(name.isdecimal() for name in descriptors), "Descriptor roster bound")
    for fd in (int(name) for name in descriptors if int(name) > 2):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as error:
            need(error.errno == errno.EBADF, "Descriptor inspection failure")
        else:
            raise Refused("Inherited outside descriptor")
    need(stat.S_ISCHR(os.fstat(0).st_mode) and os.fstat(0).st_rdev == os.makedev(1, 3)
         and all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (1, 2)), "Stdio is not null plus original bounded pipes")
    stage("sandbox-mounts")
    table = mounts()
    need(table["/"]["options"].count("ro") == 1 and "ro" in table[str(INPUTS)]["options"]
         and "ro" in table["/proc"]["options"] and "ro" in table["/dev"]["options"],
         "Outside root/inputs/proc/dev is writable")
    devices = {"/dev/null": (1, 3), "/dev/zero": (1, 5), "/dev/random": (1, 8), "/dev/urandom": (1, 9)}
    for point, mount in table.items():
        if "rw" not in mount["options"]:
            continue
        need(point in {"/work", "/dev/shm", *devices}, "Unexpected writable store")
        if point in devices:
            item = Path(point).stat()
            need(stat.S_ISCHR(item.st_mode) and item.st_rdev == os.makedev(*devices[point]), "Different platform device")
    capacity = task_capacity(Path("/work"))
    need(os.stat("/dev/shm").st_dev == os.stat("/work").st_dev
         and os.stat("/dev/shm").st_ino == os.stat("/work/shm").st_ino
         and os.statvfs("/dev").f_blocks * os.statvfs("/dev").f_frsize == DEV_BYTES,
         "Shared memory/dev storage is outside the fixed bound")
    need(Path("/work").stat().st_uid == context["uid"] and stat.S_IMODE(Path("/work").stat().st_mode) == 0o700
         and not any((Path("/work") / name).exists() for name in ("build", "deps", "stage", "receipts", "home", "tmp")),
         "Work ownership/fresh recipe paths differ")
    stage("sandbox-inputs")
    data = admission(INPUTS, INPUTS / "recipe")
    stage("sandbox-environment")
    need(dict(os.environ) == data["lock"]["environment"] and os.path.realpath(sys.executable) == "/usr/bin/python3.12"
         and sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode, "Fixed root Python/environment differs")
    stage("sandbox-receipt")
    write(Path("/work/hosted-inside.json"), canonical({"schema": "mrk-cpython-source-inside-1",
        "uid": os.getuid(), "gid": os.getgid(), "namespaces": actual, "capacity": capacity,
        "capabilities": "all-zero", "noNewPrivileges": True, "seccomp": 2,
        "nativeQualification": "not-established"}))
    command = ["/usr/bin/python3.12", "-I", "-S", "-B", str(INPUTS / "recipe/cpython_source_recipe.py"),
               str(INPUTS / "source-lock.json")]
    stage("original-recipe-cwd")
    os.chdir("/work")
    stage("original-recipe-exec")
    os.execve(command[0], command, data["lock"]["environment"])


def receipt_roster() -> set[str]:
    names = {"source-copies.json", "input-lock.json", "execution-review.json", "rootfs.json", "source-patchlevel.h",
        "openssl-layout-data.json", "source-projection.json", "source-result.json", "source-output.json",
        "python-build-pybuilddir.txt", "zlib-configure-configure.log", "libffi-configure-config.log"}
    names.update(phase + suffix for phase in PHASES for suffix in (".json", ".stdout", ".stderr"))
    python = ("Makefile", "pyconfig.h", "Modules-config.c", "Modules-Setup.local", "Modules-Setup.bootstrap",
              "Modules-Setup.stdlib", "config.log")
    openssl = ("Makefile", "configdata.pm", "include-openssl-configuration.h", "include-openssl-opensslv.h")
    names.update(phase + "-" + leaf for phase in ("python-configure", "python-build") for leaf in python)
    names.update(phase + "-" + leaf for phase in ("openssl-build", "openssl-install") for leaf in openssl)
    names.update("openssl-configure-" + leaf for leaf in openssl[:2])
    return names


def original_results(data: dict) -> dict:
    root = WORK / "receipts"
    result = decode(read(root / "source-result.json"))
    need(result["schema"] == "mrk-cpython-source-result-1" and result["profile"] == PROFILE
         and result["state"] == "mandatory-work-complete" and len(result["phases"]) == 14
         and result["inputLockSha256"] == digest(data["blobs"]["source-lock.json"])
         and result["executionReviewSha256"] == digest(data["blobs"]["source-execution-review.json"])
         and result["rootfsSha256"] == digest(data["blobs"]["rootfs.json"])
         and result["deadlineMonotonicNs"] == result["startMonotonicNs"] + 2400 * 1_000_000_000
         and result["endMonotonicNs"] < result["deadlineMonotonicNs"], "Original recipe result incomplete/late")
    spec = importlib.util.spec_from_file_location("_mrk_hosted_fixed_recipe", PREP / "inputs/recipe/cpython_source_recipe.py")
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    retained, previous = 0, result["startMonotonicNs"]
    for row, fixed in zip(result["phases"], recipe.fixed_phases()):
        need(row["path"] == fixed["name"] + ".json", "Phase receipt ordering differs")
        phase = decode(bound(root / row["path"], row))
        need(phase["profile"] == PROFILE and phase["state"] == "complete" and phase["phase"] == fixed["name"]
             and phase["argv"] == fixed["argv"] and phase["cwd"] == fixed["cwd"]
             and phase["environmentSha256"] == digest(canonical(fixed["environment"]))
             and ((type(phase["originalExitCode"]) is int and phase["originalExitCode"] == 0)
                  if fixed["argv"] else phase["originalExitCode"] is None)
             and phase["kind"] == ("native" if fixed["argv"] else "data")
             and phase["inputLockSha256"] == result["inputLockSha256"]
             and phase["deadlineMonotonicNs"] == result["deadlineMonotonicNs"]
             and previous <= phase["startMonotonicNs"] <= phase["endMonotonicNs"] < result["deadlineMonotonicNs"]
             and phase["observedIgnoredError"] is False, "Original mandatory phase failed/differs")
        size = 0
        for stream in ("stdout", "stderr"):
            item = phase[stream]
            need(item["path"] == fixed["name"] + "." + stream, "Original stream path differs")
            raw = bound(root / item["path"], item, 16 * MiB)
            need(not any(marker in raw for marker in (b"(ignored)", b"*** Error compiling", b"Can't list ")),
                 "Observed ignored required-work failure")
            size += len(raw)
        retained += size
        need(size <= 16 * MiB and retained <= 256 * MiB, "Original capture bound exceeded")
        wanted = {name for name in receipt_roster() if name.startswith(fixed["name"] + "-")}
        if fixed["name"] == "python-project":
            wanted = {"source-projection.json"}
        need(len(phase["dataFiles"]) == len(wanted) and {r["path"] for r in phase["dataFiles"]} == wanted,
             "Missing original material configuration/DATA receipts")
        for item in phase["dataFiles"]:
            need(item["path"] in receipt_roster(), "Unlisted phase DATA receipt")
            bound(root / item["path"], item)
        previous = phase["endMonotonicNs"]
    need(previous <= result["endMonotonicNs"], "Result preceded original phase completion")
    projection_raw = read(root / "source-projection.json")
    need(digest(projection_raw) == result["projectionSha256"], "Original projection differs")
    output = decode(read(root / "source-output.json"))
    need(output["result"] == {**record(root / "source-result.json"), "path": "source-result.json"}
         and output["stage"] == {k: v for k, v in decode(projection_raw).items() if k != "profile"},
         "Output/result/projection correspondence differs")
    return decode(projection_raw)


class CappedTarWriter:
    def __init__(self, stream):
        self.stream, self.written = stream, 0

    def write(self, raw):
        self.written += len(raw)
        need(self.written <= PUBLIC_BYTES, "Public archive byte ceiling")
        need(self.stream.write(raw) == len(raw), "Public archive short write")
        return len(raw)


def recipient_retention_inputs(data: dict):
    """Fixed additions to the same bounded archive, not a new publisher."""
    for row in data["recipient"]["texts"]:
        yield PREP / "recipient" / row["path"], "recipient/notices/" + row["path"], row
    for row in data["recipient"]["sourceArchives"]:
        item = row["transport"]
        yield (PREP / "objects" / item["sha256"], "recipient/sources/" + row["path"],
               {"size": item["bytes"], "sha256": item["sha256"]})
    for row in data["core"]:
        name = Path(row["path"]).relative_to(INPUTS / "core-source").as_posix()
        yield PREP / "inputs/core-source" / name, "inputs/core-source/" + name, row
    # The original JSON preserves the decoder result and capture hashes. Its
    # stdout is the package's binary-bearing tar, not a recipient build input.
    # Keep raw capture private; do not redistribute it or the controller deb.
    for suffix in (".json", ".stderr"):
        path = BWRAP_RECEIPT.with_suffix(suffix)
        yield path, "preparation/" + path.name, None


def retain(data: dict, projection: dict) -> dict:
    """One allowlisted DATA archive, never runner/HOME/workspace recursion.

    Retain every ordinary original .o/.a/.lo in the four fixed build roots,
    material configuration, exact projection originals and projected bytes.
    Complete source archives retain all source/license members for review.
    """
    selected, reserved = {}, 0
    deadline = time.monotonic() + 240  # Post-finality DATA export only, not renewed build work.

    def add(path: Path, public_name: str, expected: dict | None = None):
        nonlocal reserved
        remaining(deadline, 240)
        relative(public_name)
        item = record(path)
        if expected is not None:
            need(item == {**expected, "path": str(path)}, "Original retained bytes differ")
        need(public_name not in selected, "Duplicate retained output")
        selected[public_name] = {"source": path, "record": item, "mode": stat.S_IMODE(path.lstat().st_mode)}
        reserved += item["size"] + 4096
        need(len(selected) <= PUBLIC_FILES and reserved <= PUBLIC_BYTES - MiB, "Public allowlist reservation exceeded")

    for name in sorted(receipt_roster()):
        if (WORK / "receipts" / name).exists():
            add(WORK / "receipts" / name, "work/receipts/" + name)
    add(WORK / "hosted-inside.json", "work/hosted-inside.json")
    originals = set()
    for item in projection["files"]:
        name = relative(item["path"])
        expected = {k: item[k] for k in ("path", "size", "sha256")}
        add(WORK / "stage" / name, "work/stage/" + name, expected)
        origin = item["origin"].get("path")
        if origin and origin not in originals:
            logical = Path(origin)
            need(logical.is_relative_to(Path("/work/build")) or logical.is_relative_to(INPUTS / "sources"),
                 "Projection original outside fixed public roots")
            original = PREP / "inputs" / logical.relative_to(INPUTS) if logical.is_relative_to(INPUTS) else WORK / logical.relative_to("/work")
            add(original, "originals/" + logical.relative_to("/work").as_posix(), expected)
            originals.add(origin)
    for source in data["lock"]["sources"]:
        path = PREP / "inputs/archives" / (source["id"] + ".archive")
        add(path, "inputs/archives/" + path.name, source["archive"])
    for identifier in SOURCES:
        root, pending, count = WORK / "build" / identifier, [WORK / "build" / identifier], 0
        while pending:
            with os.scandir(pending.pop()) as children:
                for child in children:
                    count += 1
                    need(count <= WORK_INODES, "Build artifact traversal bound")
                    info = child.stat(follow_symlinks=False)
                    path = Path(child.path)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                    elif path.suffix in {".o", ".a", ".lo"}:
                        add(path, "objects/" + path.relative_to(WORK / "build").as_posix())
    configurations = {
        "cpython": ("Makefile", "pyconfig.h", "Modules/config.c", "Modules/Setup.local", "Modules/Setup.bootstrap",
                    "Modules/Setup.stdlib", "config.log", "pybuilddir.txt"),
        "openssl": ("Makefile", "configdata.pm", "include/openssl/configuration.h", "include/openssl/opensslv.h"),
        "libffi": ("config.log", "Makefile"), "zlib": ("configure.log", "Makefile")}
    for identifier, names in configurations.items():
        for name in names:
            add(WORK / "build" / identifier / name, "configuration/" + identifier + "/" + name)
    for name in (*CONTROLS, INDEX_NAME):
        add(PREP / "controls" / name, "controls/" + name)
    for name in (*HELPERS, ENTRY_NAME):
        add(PREP / "inputs/recipe" / name, "recipe/" + name)
    for name in ("context.json", "account.json", "unit-absence.json", "unit-start.json", "unit-stop.json",
                 "client.json", "client.stdout", "client.stderr"):
        add(CONTROL / name, "controller/" + name)
    add(PREP / "prepared.json", "preparation/prepared.json")
    for source, name, expected in recipient_retention_inputs(data):
        add(source, name, expected)
    for row in data["transport"]["rootArchiveTransports"]:
        add(PREP / "preparation-results" / (row["id"] + ".json"), "preparation/" + row["id"] + ".json")
    inventory = []
    archive_path = PUBLIC / "hosted-evidence.tar"
    free = os.statvfs(PUBLIC)
    need(free.f_bavail * free.f_frsize >= reserved + 16 * MiB, "Public retention disk reservation unavailable")
    fd = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
    with os.fdopen(fd, "wb", buffering=0) as output:
        sink = CappedTarWriter(output)
        with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for name, item in sorted(selected.items()):
                remaining(deadline, 240)
                path, expected = item["source"], item["record"]
                before = path.lstat()
                source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                with os.fdopen(source_fd, "rb") as source:
                    need(state(os.fstat(source.fileno())) == state(before), "Original artifact changed before archive")
                    header = tarfile.TarInfo(name)
                    header.size, header.mode, header.mtime = expected["size"], item["mode"] & 0o777, 1785925789
                    archive.addfile(header, source)
                    need(state(os.fstat(source.fileno())) == state(before) == state(path.lstat()), "Original artifact changed during archive")
                inventory.append({"path": name, "originalPath": expected["path"], "size": expected["size"],
                                  "sha256": expected["sha256"], "originalMode": item["mode"]})
        output.flush()
        os.fsync(output.fileno())
    # Independently read every member of the original archive and require its
    # exact bytes, closed roster and complete count before exporting a summary.
    with tarfile.open(archive_path, mode="r:") as archive:
        members = iter(inventory)
        for member in archive:
            remaining(deadline, 240)
            expected = next(members, None)
            need(expected is not None and member.name == expected["path"] and member.isreg()
                 and member.size == expected["size"], "Public archive roster readback differs")
            hashed, count = hashlib.sha256(), 0
            with archive.extractfile(member) as source:
                while block := source.read(CHUNK):
                    count += len(block)
                    hashed.update(block)
            need((count, hashed.hexdigest()) == (expected["size"], expected["sha256"]), "Public archive bytes differ")
        need(next(members, None) is None, "Public archive lost an original member")
    saved = write(PUBLIC / "retained-files.json", canonical({"schema": "mrk-cpython-source-retention-1",
        "profile": PROFILE, "coverage": "conservative-component-review-required", "files": inventory}))
    archive_record = record(archive_path, PUBLIC_BYTES)
    remaining(deadline, 240)
    return {"archive": archive_record, "inventory": saved}


def build() -> None:
    need(os.getresuid() == (0, 0, 0), "Controller requires original privileged entry")
    data, saved = prepared()
    current = context_from_environment()
    need(all(saved[name] == value for name, value in current.items()), "Prepared source/run context differs")
    stage("platform-limits")
    need(kernel(Path("/proc/1/comm")) == "systemd\n"
         and {"memory", "pids", "cpu"} <= set(kernel(Path("/sys/fs/cgroup/cgroup.controllers")).split()),
         "Existing systemd/cgroup-v2 domain unavailable; do not repair host")
    for expected in saved["hostTools"]:
        need(record(Path(expected["path"])) == expected, "Platform tool changed after preparation")
    footprint(PREP, PREP_BYTES, PREP_ENTRIES)
    CONTROL.mkdir(mode=0o700)
    PUBLIC.mkdir(mode=0o755)
    os.chmod(PUBLIC, 0o755)
    name = "mrkcp" + current["runId"]
    unit = "mrk-cpython-source-" + current["runId"] + ".service"
    prior = run(["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit], require_zero=False)
    need(prior.returncode in {0, 1} and prior.stdout == b"not-found\n", "Transient unit already exists or query failed; no adoption")
    write(CONTROL / "unit-absence.json", canonical({"unit": unit, "loadState": "not-found",
        "originalExitCode": prior.returncode, "stdout": prior.stdout.decode("ascii"),
        "stderr": prior.stderr.decode("ascii")}))
    stage("host-account")
    uid, gid = new_account(name)
    WORK.mkdir(mode=0o700)
    stage("empty-work-mount")
    run(["/usr/bin/mount", "--types", "tmpfs", "--options",
        f"size={WORK_BYTES},nr_inodes={WORK_INODES},nosuid,nodev,mode=0700,uid={uid},gid={gid}",
        "mrk-cpython-source-work-v1", str(WORK)])
    task_capacity(WORK)
    need(not list(WORK.iterdir()) and WORK.stat().st_uid == uid and WORK.stat().st_gid == gid,
         "Controller did not create an empty task-owned mount")
    context = {"schema": "mrk-cpython-source-hosted-context-1", **current, "unit": unit,
        "user": name, "uid": uid, "gid": gid, "hostNamespaces": namespaces(),
        "indexSha256": APPROVED_HOSTED_INPUTS_SHA256, "entrySha256": saved["entrySha256"]}
    write(CONTROL / "context.json", canonical(context))
    entry = str(PREP / "inputs/recipe" / ENTRY_NAME)
    command = ["/usr/bin/systemd-run", "--unit=" + unit, "--service-type=exec", "--wait", "--pipe", "--quiet"]
    for key, value in PROPERTIES.items():
        if key != "Type":
            command.append("--property=" + key + "=" + value)
    command.append("--property=ExecStopPost=/usr/bin/python3.12 -I -S -B " + entry + " unit-stop")
    for key, value in HOST_ENV.items():
        command.append("--setenv=" + key + "=" + value)
    command += ["--", "/usr/bin/python3.12", "-I", "-S", "-B", entry, "unit-start"]
    stage("original-service")
    result = run(command, CLIENT_SECONDS, require_zero=False)
    write(CONTROL / "client.stdout", result.stdout)
    write(CONTROL / "client.stderr", result.stderr)
    write(CONTROL / "client.json", canonical({"schema": "mrk-cpython-source-systemd-client-1",
        **current, "unit": unit, "argv": command, "originalExitCode": result.returncode,
        "captureComplete": True, "originalOwnerReturned": True}))
    need(result.returncode == 0, "Original service/client failed; retain without inferred finality")
    stage("service-finality-readback")
    start, stop = (decode(read(CONTROL / name, MiB)) for name in ("unit-start.json", "unit-stop.json"))
    need(start["invocationId"] == stop["invocationId"] and stop["unit"]["Id"] == unit
         and start["sourceSha"] == stop["sourceSha"] == current["sourceSha"]
         and stop["completion"] == {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
         and no_denials(start) and no_denials(stop), "Original service/domain completion incomplete")
    stage("original-phase-results")
    projection = original_results(data)
    stage("public-retention")
    retained = retain(data, projection)
    # Only after original unit+client finality AND checked original retention.
    # No PID search, forced userdel, mount deletion or possibly-live tree cleanup.
    account = pwd.getpwnam(context["user"])
    stage("settled-account-deletion")
    need((account.pw_uid, account.pw_gid) == (uid, gid), "Task account changed before final deletion")
    deleted = run(["/usr/sbin/userdel", context["user"]])
    for lookup, key in ((pwd.getpwuid, uid), (grp.getgrgid, gid)):
        try:
            lookup(key)
        except KeyError:
            pass
        else:
            raise Refused("Original task account/group deletion incomplete")
    write(PUBLIC / "hosted-summary.json", canonical({"schema": "mrk-cpython-source-hosted-result-1",
        "profile": PROFILE, **current, "state": "original-source-build-evidence-retained",
        "unit": unit, "invocationId": stop["invocationId"], "originalClientExitCode": result.returncode,
        "originalUserdelExitCode": deleted.returncode, "retained": retained,
        "nativeQualification": "not-established", "supplyAcceptance": "not-established",
        "originalMountDisposition": "retained-until-disposable-runner-disposition",
        "runnerDispositionIsPhaseFinality": False}))


def main() -> None:
    os.umask(0o077)
    try:
        need(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
             "Fixed isolated Python flags required")
        if len(sys.argv) == 3 and sys.argv[1] == "decode-root":
            decode_root(sys.argv[2])
        else:
            need(len(sys.argv) == 2 and sys.argv[1] in {"prepare", "build", "unit-start", "unit-stop", "inside"},
                 "Only the fixed preparation/service entry modes are allowed")
            {"prepare": prepare, "build": build, "unit-start": unit_start, "unit-stop": unit_stop, "inside": inside}[sys.argv[1]]()
    except BaseException as error:
        # Refused messages are fixed source literals. Unexpected exception
        # *classes only*: never raw urllib/OS messages, tokens or transcripts.
        mode = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in {
            "prepare", "build", "unit-start", "unit-stop", "inside", "decode-root"} else "invalid-mode"
        condition = str(error) if type(error) is Refused else type(error).__name__
        need(len(condition) <= 256 and all(32 <= ord(c) <= 126 for c in condition), "Unsafe diagnostic classification")
        failure = {"schema": "mrk-cpython-source-hosted-failure-1", "profile": PROFILE,
            "operation": mode, "stage": _STAGE, "condition": condition, "state": "failed-or-unknown",
            "retry": "not-authorized", "taskCleanup": "not-inferred", "supplyAcceptance": "not-established"}
        if mode in {"prepare", "build"} and os.getuid() == 0:
            # Refusal permits only this small diagnostic output, never input,
            # account, mount, network or build preparation past a closed gate.
            if not PUBLIC.exists():
                PUBLIC.mkdir(mode=0o755)
                os.chmod(PUBLIC, 0o755)
            directory(PUBLIC, root_owned=True)
            write(PUBLIC / "hosted-failure.json", canonical(failure))
            # These are original bounded service/capture records, not a generic
            # log directory or a process rediscovery. No task tree is read on
            # uncertain finality. A diagnostic-copy error cannot produce pass.
            if mode == "build":
                for leaf in ("client.json", "client.stdout", "client.stderr", "unit-start.json", "unit-stop.json"):
                    source = CONTROL / leaf
                    if source.exists():
                        write(PUBLIC / ("diagnostic-" + leaf), read(source, MiB))
            elif _STAGE.startswith("root-decoder-"):
                source = PREP / "preparation-results" / (_STAGE.removeprefix("root-decoder-") + ".json")
                if source.exists():
                    write(PUBLIC / "diagnostic-preparation.json", read(source, MiB))
            elif _STAGE in {"controller-bubblewrap-decoder", "controller-bubblewrap-member", "controller-bubblewrap-seal"}:
                if BWRAP_RECEIPT.exists():
                    write(PUBLIC / "diagnostic-preparation.json", read(BWRAP_RECEIPT, MiB))
        raise SystemExit("Conventional hosted " + mode + "/" + _STAGE + ": " + condition
                         + "; retain original evidence; no retry") from None


if __name__ == "__main__":
    main()
