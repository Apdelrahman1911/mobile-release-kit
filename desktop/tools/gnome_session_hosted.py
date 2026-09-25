"""Fixed hosted carrier for the seven-case foreground GNOME SESSION fixture.

No general command runner, installer, release operation, or local fallback.
The catalogue deliberately refuses pre-use while supplier facts are incomplete.
All execution requires separate SOURCE/COMMAND admission; a preparatory receipt
is never native qualification.  Private source/runtime/account DATA stays local.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import tomllib
import urllib.parse

MIB = 1 << 20
TASK = Path("/var/tmp/mrk-gnome-session-native-v1")
PUBLIC = Path("/var/tmp/mrk-gnome-session-native-public-v1")
OUTER = Path("/var/tmp/mrk-gnome-session-native-outer-v1")
BWRAP_TARGET = Path("/usr/bin/bwrap")
BWRAP_SUPPLY = Path("/var/tmp/mrk-gnome-session-bwrap-supplier-v1")
BWRAP_SUPPLY_SCHEMA = "gnome-session-bwrap-supplier-1"
BWRAP_URL = "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.1_amd64.deb"
# One retained archive/member/provenance tuple, not an extensible installer.
BWRAP_SUPPLIER_SHA256 = "11fcec9d80eab025a3ca6f12b50a0d4a60f9901f8fb887e6c22d4a79711691b4"
PROFILE = "gnome-session-hosted-native-v1"
REF = "refs/heads/verify/desktop-gnome-session-native"
WORKFLOW = ".github/workflows/desktop-gnome-session-native.yml"
PRODUCT_TREE = "4f809afa38b6b814e8c8110df5599cbf5bc97677"
TARGET = "x86_64-unknown-linux-gnu"
SOURCE = Path(__file__).absolute().parents[2]
CONTROL = "desktop/tools/gnome_session_native/"
CARRIER_FILES = (WORKFLOW, "desktop/tools/gnome_session_hosted.py",
                 *(CONTROL + name for name in ("owner.py", "native-entry.sh", "compile-only.sh",
                    "host-admit.py", "prepare.py", "check-compile.py", "runtime-layout.json", "runtime-suppliers.json")),
                 "tests/desktop/test_gnome_session_hosted_contract.py")
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": "/nonexistent"}
FIXED_HOST_ROLES = {"/usr/bin/env", "/usr/bin/bash", "/usr/bin/timeout", "/usr/bin/head",
    "/usr/bin/cat", "/usr/bin/stat", "/usr/bin/sha256sum", "/usr/bin/bwrap", "/usr/bin/setpriv",
    "/usr/bin/x86_64-linux-gnu-readelf", "/usr/bin/python3.12", "/usr/bin/git", "/usr/bin/sudo",
    "/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/nologin", "/usr/bin/busctl",
    "/usr/lib/systemd/systemd", "/usr/bin/curl", "/usr/bin/xz", "/usr/bin/dpkg-deb",
    "/usr/bin/x86_64-linux-gnu-gcc-13", "/usr/bin/x86_64-linux-gnu-as", "/usr/bin/x86_64-linux-gnu-ar",
    "/usr/bin/x86_64-linux-gnu-ld.bfd", "/usr/bin/mkdir", "/etc/ld.so.cache",
    "/etc/ssl/certs/ca-certificates.crt"}
BOOTSTRAP_TRUST = {
    "profile": "github-hosted-disposable-source-bound-bootstrap-v1",
    "trusted": ["runner-and-os", "pinned-checkout-and-control-pin-step",
                "env-sudo-pam-setpriv-env-initial-isolated-python",
                "fixed-env-sudo-setpriv-bash-stat-mkdir-empty-pycache-before-first-python"],
    "retroactiveAuthentication": False, "subsequentExactGuardsRequired": True}
PYTHON_EXECUTABLE = "/usr/bin/python3.12"
PYTHON_PYCACHE = Path("/run/mrk-gnome-python-empty-pycache-v1")
PYTHON_STDLIB = "/usr/lib/python3.12"
PYTHON_SEARCH = ("/usr/lib/python312.zip", PYTHON_STDLIB, PYTHON_STDLIB + "/lib-dynload")
PYTHON_FFI = "/usr/lib/x86_64-linux-gnu/libffi.so.8.1.4"
PYTHON_REQUIRED_FILES = {PYTHON_EXECUTABLE, PYTHON_STDLIB + "/ctypes/__init__.py",
    PYTHON_STDLIB + "/lib-dynload/_ctypes.cpython-312-x86_64-linux-gnu.so", PYTHON_FFI}
# Only these observed chains extend the existing direct-regular-target rule.
# The shared-library seed is a link, not a regular file or an import directory.
PYTHON_LIBRARY_ALIAS = PYTHON_STDLIB + "/config-3.12-x86_64-linux-gnu/libpython3.12.so"
PYTHON_ALIAS_LINKS = {
    PYTHON_LIBRARY_ALIAS: "../../x86_64-linux-gnu/libpython3.12.so.1",
    "/usr/lib/x86_64-linux-gnu/libpython3.12.so.1": "libpython3.12.so.1.0",
    PYTHON_STDLIB + "/sitecustomize.py": "/etc/python3.12/sitecustomize.py"}
PYTHON_ALIAS_FILES = {
    "/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0": {
        "bytes": 9061000, "mode": "0o644",
        "sha256": "1021f236227334ded6d1bbbc4bb6f5d933f793d8397c969896cfbdf03ce96223"},
    "/etc/python3.12/sitecustomize.py": {
        "bytes": 155, "mode": "0o644",
        "sha256": "43d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e"}}
PYTHON_ALIAS_PARENTS = ("/", "/usr", "/usr/lib", PYTHON_STDLIB,
    PYTHON_STDLIB + "/config-3.12-x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/etc", "/etc/python3.12")
CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
CARGO_ACQUISITION = "gnome-cargo-admitted-files-only-v1"
CARGO_LIBRARY_ROOT = "/usr/lib/x86_64-linux-gnu/"
CARGO_DNS_TARGETS = ("/etc/gai.conf", "/etc/host.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf")
CARGO_ROOT_ALIASES = (("/lib", "usr/lib"), ("/lib64", "usr/lib64"),
                      ("/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
CARGO_RESOLVER = {"path": "/run/systemd/resolve/stub-resolv.conf", "uid": 991, "gid": 991,
                  "mode": "0o644", "bytes": 972,
                  "sha256": "47543085f48c15320df27d8ebf5bc398aa87df3c918862feb814785821ca0927"}
CARGO_RESOLVER_PARENTS = [
    {"path": path, "uid": owner, "gid": owner, "mode": "0o755"}
    for path, owner in (("/", 0), ("/run", 0), ("/run/systemd", 0), ("/run/systemd/resolve", 991))]
CARGO_RESOLVER_PARENT_OBSERVATION = {
    "role": "historical-resolver-parent-metadata-only",
    "observationSha256": "b6fa4db685fcd0ef054250768bdce34354006defbfcc590fcc21e5f2f6fb3e3b",
    "reviewSha256": "aae02924d5bc473e3b44f6e9656ca7b9d468aca2c9b042961c02e91021db20a3",
    "observationPointers": ["/parents/0", "/parents/6", "/parents/7", "/parents/8"],
    "parentOriginalsObserved": True, "resolverBodyObserved": False,
    "freshOriginalCustodyRequired": True}
CARGO_LIBGCC = "usr/lib/x86_64-linux-gnu/libgcc_s.so.1"
GIT_FORBIDDEN_CONTROLS = ("config.worktree", "commondir", "objects/info/alternates",
                          "objects/info/http-alternates", "info/attributes")
_OWNER = None
_WAITS = []
_ORIGINALS_SETTLED = True
_CATALOGUE = None
_PYCACHE = None
_PYTHON_ALIASES = None
_PINS = {}
_HOST_REFUSAL = ()
_SUPPLIERS = []
_EVIDENCE = {"context": None, "source": None, "hostToolOriginalsSha256": None,
             "hostToolSuppliers": None, "acquisition": None, "owner": None,
             "reservationSha256": None, "originalWorkflowWait": None,
             "bootstrap": None, "hostAuthenticationScope": None, "pythonRuntime": None,
             "bwrapSupply": None, "pythonPycache": None, "pythonAliasCustody": None}
OWNER_ROLES = ("namespace-probe", "compile", "artifact-elf", "native", "source-post")
OWNER_FINALITY = ("namespaceProbeAttempted", "namespaceProbePassed", "nativeEnvelopeAttempted", "nativeEntryObserved",
                  "nativeAccepted", "passed", "nestedNamespaceRetired", "completeSourceDependencyPostchecked",
                  "artifactReceiptPostchecked", "artifactPostchecked", "outerPrivateCohortQuiet", "hostReservationChecked",
                  "pythonPycacheSameLeaf", "pythonPycachePostchecked", "pythonPycacheHandlesClosed")
HOST_VERSION_ROLES = FIXED_HOST_ROLES - {"/etc/ld.so.cache", "/etc/ssl/certs/ca-certificates.crt"}
# Only these already authenticated native suppliers need the historical origin.
# Do not turn an exact archive allowance into trust in arbitrary snapshot paths.
SNAPSHOT_NATIVE_URLS = frozenset({
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/d/dbus/dbus-daemon_1.14.10-4ubuntu4.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260817T000000Z/pool/main/u/util-linux/util-linux_2.39.3-9ubuntu6.5_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/g/glib2.0/libglib2.0-0t64_2.80.0-6ubuntu3.8_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260901T000000Z/pool/main/libg/libgcrypt20/libgcrypt20_1.10.3-2ubuntu0.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/s/systemd/libsystemd0_255.4-1ubuntu8.17_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260817T000000Z/pool/main/p/p11-kit/libp11-kit0_0.25.3-4ubuntu2.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260901T000000Z/pool/main/g/glibc/libc6_2.39-0ubuntu8.8_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/g/gcc-14/libgcc-s1_14.2.0-4ubuntu2~24.04.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/d/dbus/libdbus-1-3_1.14.10-4ubuntu4.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/e/expat/libexpat1_2.6.1-2ubuntu0.4_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/libs/libselinux/libselinux1_3.5-2ubuntu2.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/a/audit/libaudit1_3.1.2-2.1build1.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/libc/libcap-ng/libcap-ng0_0.8.4-2build2_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/a/apparmor/libapparmor1_4.0.1really4.0.1-0ubuntu0.24.04.7_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260817T000000Z/pool/main/u/util-linux/libmount1_2.39.3-9ubuntu6.5_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/libf/libffi/libffi8_3.4.6-1build1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/p/pcre2/libpcre2-8-0_10.42-4ubuntu2.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/libg/libgpg-error/libgpg-error0_1.47-3build2.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/libc/libcap2/libcap2_2.66-5ubuntu2.4_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/l/lz4/liblz4-1_1.9.4-1build1.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/x/xz-utils/liblzma5_5.6.1+really5.4.5-1ubuntu0.3_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/libz/libzstd/libzstd1_1.5.5+dfsg2-2build1.1_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260817T000000Z/pool/main/u/util-linux/libblkid1_2.39.3-9ubuntu6.5_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/b/bash/bash_5.2.21-2ubuntu4_amd64.deb",
    "https://snapshot.ubuntu.com/ubuntu/20260916T000000Z/pool/main/n/ncurses/libtinfo6_6.4+20240113-1ubuntu2.2_amd64.deb",
})


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate-json-field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite-json")))


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def path_name(value):
    need(type(value) is str and 0 < len(value) <= 512 and re.fullmatch(r"[A-Za-z0-9_./@+=, -]+", value)
         and not value.startswith("/") and all(p not in ("", ".", "..") for p in value.split("/")), "relative-path-shape")
    return value


def read(path, limit=16 * MIB, *, root=True):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit
             and (not root or before.st_uid == before.st_gid == 0), "input-kind-owner-bound")
        parts, size = [], 0
        while part := os.read(fd, min(65536, before.st_size - size + 1)):
            size += len(part)
            need(size <= before.st_size, "input-grew")
            parts.append(part)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             "input-original-changed")
        raw = b"".join(parts)
        return raw, {"identity": identity(before), "bytes": size, "sha256": hashlib.sha256(raw).hexdigest(),
                     "mode": oct(stat.S_IMODE(before.st_mode))}
    finally:
        os.close(fd)


def write(path, raw, mode=0o400):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    actual, pin = read(path, max(len(raw), 1))
    need(actual == raw and pin["mode"] == oct(mode), "new-output-correspondence")
    return pin


def bounded_roster(root, *, files=16384, total=3 << 30):
    root = Path(root)
    s = root.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, "owned-roster-root")
    result, dirs, pending, size = [], [], [root], 0
    while pending:
        directory = pending.pop()
        before = directory.lstat()
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_dev == s.st_dev and not before.st_mode & 0o022, "owned-roster-directory-state")
        with os.scandir(directory) as original:
            entries = sorted(original, key=lambda entry: entry.name)
        need(len(result) + len(dirs) + len(entries) <= files, "owned-roster-node-bound")
        dirs.append({"path": str(directory), "entries": [e.name for e in entries],
                     "mode": oct(stat.S_IMODE(before.st_mode)), "identity": identity(before)})
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            need(info.st_uid == 0 and info.st_dev == s.st_dev, "owned-roster-owner-device")
            if stat.S_ISDIR(info.st_mode):
                pending.append(Path(entry.path))
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "owned-roster-file-kind")
                _, pin = read(entry.path, 512 * MIB)
                need(pin["identity"] == identity(info), "owned-roster-entry-changed")
                result.append({"path": entry.path, **pin})
                size += pin["bytes"]
                need(size <= total, "owned-roster-byte-bound")
        need(identity(directory.lstat()) == identity(before)
             and sorted(os.listdir(directory)) == [entry.name for entry in entries], "owned-roster-directory-changed")
    need(identity(root.lstat()) == identity(s), "owned-roster-root-changed")
    return {"files": sorted(result, key=lambda row: row["path"]), "directories": dirs, "bytes": size,
            "rootIdentity": identity(s)}


def source_directories(root, names, *, original=False):
    """Closed source directory inventory, including empty-directory refusal."""
    root = Path(root)
    wanted, allowed = set(names), {"."}
    for name in wanted:
        allowed.update(str(path) for path in Path(path_name(name)).parents)
    seen, result, pending = set(), [], [root]
    while pending:
        directory = pending.pop()
        relative = directory.relative_to(root).as_posix()
        before = directory.lstat()
        need(relative in allowed and stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o022
             and (original or before.st_uid == before.st_gid == 0), "source-directory-state")
        with os.scandir(directory) as stream:
            entries = sorted(stream, key=lambda entry: entry.name)
        selected = [entry for entry in entries if not (original and directory == root and entry.name == ".git")]
        need(len(seen) + len(result) + len(selected) <= 4096, "source-directory-node-bound")
        for entry in selected:
            info = entry.stat(follow_symlinks=False)
            path = Path(entry.path)
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            else:
                name = path.relative_to(root).as_posix()
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and name in wanted and name not in seen,
                     "source-file-inventory-kind")
                seen.add(name)
        need(identity(before) == identity(directory.lstat())
             and sorted(os.listdir(directory)) == [entry.name for entry in entries], "source-directory-changed")
        result.append({"relative": relative, "entries": [entry.name for entry in selected],
                       "mode": oct(stat.S_IMODE(before.st_mode)), "identity": identity(before)})
    need(seen == wanted and {row["relative"] for row in result} == allowed, "complete-source-directory-inventory")
    return sorted(result, key=lambda row: row["relative"])


def workflow_context(environment):
    need(environment.get("RUNNER_ENVIRONMENT") == "github-hosted" and environment.get("RUNNER_OS") == "Linux"
         and environment.get("RUNNER_ARCH") == "X64" and environment.get("ImageOS") == "ubuntu24", "hosted-ubuntu24-only")
    need(environment.get("GITHUB_REF") == REF, "dedicated-verification-ref")
    repository, commit = environment.get("GITHUB_REPOSITORY", ""), environment.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
         and re.fullmatch(r"[0-9a-f]{40}", commit) and commit != "0" * 40, "repository-source-shape")
    need(environment.get("GITHUB_WORKFLOW_SHA") == commit
         and environment.get("GITHUB_WORKFLOW_REF") == repository + "/" + WORKFLOW + "@" + REF,
         "workflow-source-binding")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        need(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(name, "")), "run-attempt-shape")
    event = environment.get("GITHUB_EVENT_NAME")
    need((event == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == commit)
         or (event == "push" and environment.get("MRK_PUSH_EVENT_AFTER") == commit), "reviewed-event-source")
    need(environment.get("ImageVersion") == "20260907.300.1", "unadmitted-runner-image")
    return {"sourceSha": commit, "repository": repository, "ref": REF, "workflow": WORKFLOW,
            "runId": environment["GITHUB_RUN_ID"], "attempt": environment["GITHUB_RUN_ATTEMPT"],
            "imageVersion": environment["ImageVersion"], "platform": "ubuntu-24.04-x86_64"}


def catalogue_ready(value):
    need(value.get("schema") == "gnome-session-hosted-suppliers-1", "supplier-catalogue-schema")
    need(value.get("unresolved") == [], "supplier-facts-unresolved")
    need(value.get("bootstrapTrust") == BOOTSTRAP_TRUST, "explicit-provider-bootstrap-boundary")
    need(value.get("hostAbsent") == ["/etc/ld.so.preload"], "host-absent-input-contract")
    need(value.get("productTree") == PRODUCT_TREE and len(value.get("product", [])) == 964,
         "frozen-product-inventory")
    need(type(value.get("hostFiles")) is list and 0 < len(value["hostFiles"]) <= 16384
         and FIXED_HOST_ROLES <= {row["path"] for row in value["hostFiles"]}, "host-tool-role-closure")
    need(type(value.get("hostDirectories")) is list and value["hostDirectories"], "host-runtime-directory-closure")
    python_runtime_catalogue(value)
    for row in value["hostFiles"]:
        if row["path"] in HOST_VERSION_ROLES:
            need(all(type(row.get(key)) is str and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", row[key])
                     for key in ("package", "version"))
                 and type(row.get("provenance")) is dict and row["provenance"], "host-tool-supplier-version-provenance")
    need(type(value.get("nativePackages")) is list and len(value["nativePackages"]) == 29,
         "native-supplier-count")
    need(all(type(row.get("package")) is str and re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", row["package"])
             and type(row.get("version")) is str and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", row["version"])
             for row in value["nativePackages"]), "native-supplier-package-version")
    need({row["component"] for row in value.get("rust", [])} == {"cargo", "rustc", "rust-std"}, "rust-component-closure")
    need(all(row.get("releaseVersion") == "1.98.0" and type(row.get("componentDeclaredVersion")) is str
             and re.fullmatch(r"[A-Za-z0-9.+:~_() -]{1,128}", row["componentDeclaredVersion"])
             for row in value["rust"]), "fixed-rust-supplier-version")
    rust_targets = set()
    for row in (*value["nativePackages"], *value["rust"]):
        need(type(row.get("bytes")) is int and 0 < row["bytes"] <= 256 * MIB
             and re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", ""))
             and type(row.get("decodedBytes")) is int and 0 < row["decodedBytes"] <= 768 * MIB
             and re.fullmatch(r"[0-9a-f]{64}", row.get("decodedSha256", ""))
             and type(row.get("memberLimit")) is int and 1 <= row["memberLimit"] <= 32768
             and type(row.get("expandedLimit")) is int and 0 < row["expandedLimit"] <= 768 * MIB
             and row.get("provenance") and type(row.get("members")) is list and row["members"],
             "supplier-archive-member-provenance")
        public_url(row["url"])
        need(row["format"] in ("deb", "tar.xz"), "fixed-supplier-decoder-format")
        selected, targets = set(), set()
        for member in row["members"]:
            name, target = path_name(member["member"]), path_name(member["target"])
            need(name not in selected and target not in targets and type(member["bytes"]) is int
                 and 0 < member["bytes"] <= 512 * MIB and re.fullmatch(r"[0-9a-f]{64}", member["sha256"])
                 and member["archiveMode"] in ("0o644", "0o755")
                 and member["mode"] in ("0o400", "0o444", "0o500", "0o555", "0o600", "0o644", "0o755"),
                 "supplier-regular-member-contract")
            selected.add(name)
            targets.add(target)
            if row["format"] == "tar.xz":
                need(target not in rust_targets, "rust-supplier-target-collision")
                rust_targets.add(target)
    need({"bin/cargo", "bin/rustc"} <= rust_targets, "rust-fixed-tool-layout-missing")
    need(len(value.get("cargoPackages", [])) == len(value.get("registryPackages", [])) == 102,
         "locked-compiled-supplier-count")
    need(value.get("caFile") in {row["path"] for row in value["hostFiles"]}, "acquisition-ca-not-authenticated")
    cargo_mount_selection(value)
    bwrap_host_peers(value)
    return value


def bwrap_archive(catalogue):
    row = catalogue.get("bwrapSupplier")
    need(type(row) is dict and hashlib.sha256(canonical(row)).hexdigest() == BWRAP_SUPPLIER_SHA256,
         "fixed-bwrap-supplier-contract")
    return row


def bwrap_host_peers(catalogue):
    """Only the fixed target is separate; every other host input stays guarded."""
    row = bwrap_archive(catalogue)
    member = row["members"][0]
    targets = [item for item in catalogue["hostFiles"] if item["path"] == str(BWRAP_TARGET)]
    expected = {"bytes": member["bytes"], "sha256": member["sha256"], "mode": "0o755",
                "package": row["package"], "version": row["version"], "provenance": row["provenance"]}
    need(len(targets) == 1 and all(targets[0].get(key) == value for key, value in expected.items()),
         "bwrap-target-supplier-correspondence")
    return {**catalogue, "hostFiles": [item for item in catalogue["hostFiles"] if item is not targets[0]]}


def authenticate_bwrap_absent(catalogue, *, after=False):
    """The one admitted pre-state, never an option on ordinary host admission."""
    peers = bwrap_host_peers(catalogue)
    directories = []
    for row in peers["hostDirectories"]:
        if row["path"] == str(BWRAP_TARGET.parent):
            entries = row["entries"]
            need(type(entries) is list and entries == sorted(set(entries))
                 and BWRAP_TARGET.name in entries, "bwrap-parent-final-roster")
            row = {**row, "entries": [name for name in entries if name != BWRAP_TARGET.name]}
        directories.append(row)
    peers["hostDirectories"] = directories
    need(str(BWRAP_TARGET) not in _PINS, "bwrap-prestate-already-pinned")
    root_absent(BWRAP_TARGET, "bwrap-supplier-target")
    authenticate_host(peers, after=after)


def native_layout(catalogue, layout):
    """Bind the selected34 bodies and three retained tars, not just their count."""
    need(layout.get("hostedCarrierSchema") == "gnome-session-hosted-layout-1"
         and layout["credentials"]["actualNonzeroUid"] == layout["credentials"]["actualNonzeroGid"] == 61000,
         "native-hosted-layout-schema")
    selected = {}
    for package in catalogue["nativePackages"]:
        for member in package["members"]:
            target = path_name(member["target"])
            need(target not in selected, "native-supplier-target-collision")
            selected[target] = (package, member)
    need(set(selected) == {"native/" + str(i).zfill(2) for i in range(31)}
         | {"package-members/" + str(i).zfill(2) for i in range(3)}, "native-complete-supplier-targets")
    need(len(layout["installedFileMounts"]) == 31 and len(layout["stagedPackageMembers"]) == 3,
         "native-body-layout-count")
    destinations, used = set(), set()
    for row in layout["installedFileMounts"]:
        need(row["path"].startswith("/inputs/"), "native-private-supplier-path")
        target = row["path"][len("/inputs/"):]
        need(target.startswith("native/") and target in selected and target not in used, "native-supplier-layout-unique")
        _, member = selected[target]
        need(all(member[key] == row[key] for key in ("bytes", "sha256", "mode"))
             and row["nativeDestination"] == "/" + member["member"], "native-member-layout-correspondence")
        need(row["nativeDestination"] not in destinations, "native-destination-collision")
        destinations.add(row["nativeDestination"])
        used.add(target)
    for i, row in enumerate(layout["stagedPackageMembers"]):
        package, member = selected["package-members/" + str(i).zfill(2)]
        need(package["retainedTar"] == str(i).zfill(2) + ".tar"
             and row["sourceTar"] == "/inputs/native-tars/" + package["retainedTar"]
             and package["decodedBytes"] == row["tarBytes"] and package["decodedSha256"] == row["tarSha256"]
             and all(member[key] == row[key] for key in ("bytes", "sha256", "member"))
             and row["nativeDestination"] == "/" + member["member"]
             and row["nativeDestination"] not in destinations, "native-retained-tar-correspondence")
        destinations.add(row["nativeDestination"])
    return layout


def python_alias_catalogue(catalogue):
    """Fixed two-hop library and one-hop source chains; no general traversal."""
    files = {row["path"]: row for row in catalogue["hostFiles"]}
    directories = {row["path"] for row in catalogue["hostDirectories"]}
    aliases = {row["path"]: row["target"] for row in catalogue["hostAliases"]}
    need(len(files) == len(catalogue["hostFiles"]) and len(directories) == len(catalogue["hostDirectories"])
         and len(aliases) == len(catalogue["hostAliases"]), "python-runtime-path-unique")
    for path, target in PYTHON_ALIAS_LINKS.items():
        need(aliases.get(path) == target and path not in files.keys() | directories,
             "python-alias-fixed-chain")
    for path, expected in PYTHON_ALIAS_FILES.items():
        need(path in files and path not in aliases.keys() | directories
             and all(files[path].get(key) == value for key, value in expected.items()),
             "python-alias-fixed-terminal")


def python_runtime_catalogue(catalogue):
    """Keep the whole selected tree; old source caches remain pinned DATA."""
    files = {row["path"] for row in catalogue["hostFiles"]}
    directories = {row["path"]: row for row in catalogue["hostDirectories"]}
    need(type(catalogue.get("hostAliases")) is list, "python-runtime-alias-roster")
    aliases = {row["path"]: row["target"] for row in catalogue["hostAliases"]}
    need(len(files) == len(catalogue["hostFiles"]) and len(directories) == len(catalogue["hostDirectories"])
         and len(aliases) == len(catalogue["hostAliases"]), "python-runtime-path-unique")
    python_alias_catalogue(catalogue)
    need(PYTHON_REQUIRED_FILES <= files and set(PYTHON_SEARCH[1:]) <= directories.keys()
         and aliases.get("/usr/lib/x86_64-linux-gnu/libffi.so.8") == "libffi.so.8.1.4",
         "python-runtime-required-inputs")
    need(PYTHON_SEARCH[0] not in files | directories.keys() | aliases.keys(), "python-zip-must-be-absent")
    prefix = PYTHON_STDLIB + "/"
    selected = {path for path in files | directories.keys() | aliases.keys()
                if path == PYTHON_STDLIB or path.startswith(prefix)}
    need(len(selected) <= 16384, "python-runtime-node-bound")
    for path in selected:
        need(sum((path in files, path in directories, path in aliases)) == 1, "python-runtime-kind-unique")
        if path != PYTHON_STDLIB:
            parent, name = path.rsplit("/", 1)
            need(parent in directories and name in directories[parent]["entries"], "python-runtime-parent-roster")
        if path in directories:
            entries = directories[path]["entries"]
            need(type(entries) is list and len(entries) <= 16384 and all(type(name) is str
                 and 0 < len(name) <= 255 and name not in (".", "..") and "/" not in name and "\0" not in name
                 for name in entries) and entries == sorted(set(entries)), "python-runtime-entry-roster")
            need(all(path + "/" + name in selected for name in entries), "python-runtime-unpinned-entry")
        if path in aliases:
            # Preserve direct regular targets except for the one exact two-link
            # library chain already checked above. Never follow arbitrary hops.
            target = os.path.normpath(os.path.join(os.path.dirname(path), aliases[path]))
            if path == PYTHON_LIBRARY_ALIAS:
                target = os.path.normpath(os.path.join(os.path.dirname(target), aliases[target]))
            need(target in files, "python-runtime-alias-target")
    # The prefix redirects only normal source-cache lookups. It does not disable
    # explicit/SourcelessFileLoader pyc or zipimport. Refuse new direct/alias pyc
    # routes, and keep every pinned cache row and its source counterpart.
    pycs = {path for path in selected if path.endswith(".pyc")}
    for path in pycs:
        parent, name = path.rsplit("/", 1)
        need(path in files and parent.endswith("/__pycache__")
             and name.endswith(".cpython-312.pyc") and name != ".cpython-312.pyc",
             "python-runtime-direct-bytecode-route")
        source = parent.removesuffix("/__pycache__") + "/" + name.removesuffix(".cpython-312.pyc") + ".py"
        need(source in files | aliases.keys(), "python-runtime-cache-source")
    need(all(not path.endswith(".pyc") and not target.endswith(".pyc")
             for path, target in aliases.items()), "python-runtime-bytecode-alias")
    return {"stdlibInputs": len(selected), "pinnedSourceCacheDataRows": len(pycs)}


def root_absent(path, label):
    path = Path(path)
    parent = path.parent
    before = parent.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
         and not before.st_mode & 0o022, label + "-parent")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise Refused(label + "-unreadable") from error
    else:
        raise Refused(label + "-occupied")
    need(identity(before) == identity(parent.lstat()), label + "-parent-changed")


def authenticate_absent_host_inputs(catalogue):
    # Neither a present nor dangling preload path is absent. This is not
    # retroactive admission of the earlier provider/bootstrap interpreter.
    need(catalogue.get("hostAbsent") == ["/etc/ld.so.preload"], "host-absent-input-contract")
    root_absent("/etc/ld.so.preload", "host-absent-input")


def authenticate_python_runtime(catalogue):
    counts = python_runtime_catalogue(catalogue)
    need(sys.executable == PYTHON_EXECUTABLE and tuple(sys.path) == PYTHON_SEARCH
         and sys.implementation.name == "cpython" and sys.implementation.cache_tag == "cpython-312"
         and sys.prefix == sys.base_prefix == sys.exec_prefix == sys.base_exec_prefix == "/usr"
         and sys.flags.isolated and sys.flags.no_site and sys.flags.optimize == 0
         and sys.dont_write_bytecode and type(sys.pycache_prefix) is str
         and sys.pycache_prefix == str(PYTHON_PYCACHE), "actual-python-runtime-selection")
    original = pycache_original()
    for name in ("/usr", "/usr/bin", "/usr/lib", "/usr/lib/x86_64-linux-gnu"):
        info = Path(name).lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
             "python-runtime-parent")
    root_absent(PYTHON_SEARCH[0], "python-zip-search")
    # Startup protection is the explicit trusted bootstrap, not this later
    # assertion. C/A/W keeps this exact -X policy before -c on every reexec.
    _EVIDENCE["pythonRuntime"] = {"executable": PYTHON_EXECUTABLE, "searchPath": list(PYTHON_SEARCH),
        "bytecodePolicy": "fixed-normal-source-cache-miss; existing-pyc-pinned-data; implicit-writes-disabled",
        "pycachePrefix": str(PYTHON_PYCACHE),
        "pycacheOriginalSha256": hashlib.sha256(canonical(original)).hexdigest(),
        "normalSourceCacheInputs": 0, "sourcelessOrZipExecutionDisabled": False,
        "oldCachesPhysicallyInaccessible": False, "libffiTarget": PYTHON_FFI, **counts}


def authenticate_host(catalogue, *, after=False):
    authenticate_absent_host_inputs(catalogue)
    selected = python_alias_originals() if after else python_alias_begin(catalogue)
    # This is actual payload correspondence, never a version-string substitute.
    for row in catalogue["hostFiles"]:
        if row["path"] in selected["files"]:
            pin = selected["files"][row["path"]]  # Already hashed through its held original descriptor.
        else:
            _, pin = read(row["path"], 128 * MIB)
        need(all(pin[key] == row[key] for key in ("bytes", "sha256", "mode")), "host-tool-payload-differs")
        if after:
            need(_PINS[row["path"]] == pin, "host-tool-original-changed")
        else:
            need(row["path"] not in _PINS, "host-tool-duplicate")
            _PINS[row["path"]] = pin
    for row in catalogue["hostDirectories"]:
        path = Path(row["path"])
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
             and sorted(os.listdir(path)) == row["entries"], "host-runtime-directory-differs")
    for row in catalogue["hostAliases"]:
        path = Path(row["path"])
        need(path.is_symlink() and path.lstat().st_uid == 0 and os.readlink(path) == row["target"],
             "host-tool-alias-differs")
    authenticate_python_runtime(catalogue)
    # Package versions describe source-admitted, byte-matched original payloads.
    # No executable --version probe occurred, and declarations alone do not pass.
    _EVIDENCE["hostToolOriginalsSha256"] = hashlib.sha256(canonical(_PINS)).hexdigest()
    _EVIDENCE["hostAuthenticationScope"] = "post-provider-bootstrap; controller-owned-runtime-correspondence-only; not-retroactive"
    _EVIDENCE["hostToolSuppliers"] = [{"role": Path(row["path"]).name, "package": row["package"],
        "packageVersion": row["version"], "bytes": _PINS[row["path"]]["bytes"],
        "sha256": _PINS[row["path"]]["sha256"], "provenanceSha256": hashlib.sha256(canonical(row["provenance"])).hexdigest(),
        "basis": "authenticated-supplier-payload-correspondence; version-probe-not-run"}
        for row in catalogue["hostFiles"] if row["path"] in HOST_VERSION_ROLES]


def public_originals(rows):
    """Finite fields from run_owned returns; no made-up separate reader exits."""
    need(type(rows) is list and len(rows) <= 256, "public-original-count")
    result = []
    for row in rows:
        need(type(row) is dict and re.fullmatch(r"[a-z][a-z0-9-]{0,79}", row.get("role", "")), "public-original-role")
        result.append({"role": row["role"], "returned": row.get("returned") is True,
            "originalsSettled": row.get("originalsSettled") is True,
            "exitCode": row.get("exitCode") if type(row.get("exitCode")) is int else None,
            "stdoutBytes": row.get("stdoutBytes") if type(row.get("stdoutBytes")) is int else None,
            "stderrBytes": row.get("stderrBytes") if type(row.get("stderrBytes")) is int else None,
            "captureFinality": "original-run-owned-return" if row.get("returned") is True else "unestablished"})
    return result


def record_source_evidence(binding, binding_sha):
    _EVIDENCE["source"] = {"sourceSha": binding["sourceSha"], "fullTree": binding["fullTree"],
        "productTree": binding["productTree"], "productFiles": binding["productFiles"],
        "completeSourceFiles": binding["completeSourceFiles"], "sourceBindingSha256": binding_sha,
        "sourceIndexSha256": binding["sourceIndexSha256"], "gitIndexSha256": binding["gitIndexSha256"],
        "completeOriginalInventorySha256": hashlib.sha256(canonical(binding["sourceFiles"])).hexdigest(),
        "controls": [{"role": row["path"].removeprefix("/source/"), "bytes": row["bytes"], "sha256": row["sha256"]}
                     for row in binding["sourceFiles"] if row["path"].removeprefix("/source/") in CARRIER_FILES]}


def public_evidence():
    return {"schema": "gnome-session-public-original-evidence-1", **_EVIDENCE,
            "phaseOriginals": public_originals(_WAITS),
            "partialSupplierAcquisitions": list(_SUPPLIERS) if _EVIDENCE["acquisition"] is None else None}


def source_product(catalogue):
    wanted = set()
    for row in catalogue["product"]:
        relative = path_name(row["path"])
        need(relative not in wanted, "product-inventory-duplicate")
        wanted.add(relative)
        _, pin = read(SOURCE / relative, 32 * MIB, root=False)
        need(pin["bytes"] == row["bytes"] and pin["sha256"] == row["sha256"]
             and bool(int(pin["mode"], 8) & 0o111) == (row["gitMode"] == "100755"), "frozen-product-differs")
    need(not wanted.intersection(CARRIER_FILES), "carrier-product-overlap")
    names = sorted(wanted | set(CARRIER_FILES))
    need(len(names) <= 1024, "source-file-count-bound")
    source_directories(SOURCE, names, original=True)
    return names


def owner_modules(root, catalogue):
    global _OWNER
    allowed = set()
    for row in catalogue["product"]:
        if row["path"].startswith("src/mobile_release/"):
            raw, pin = read(root / row["path"], 32 * MIB, root=(root != SOURCE))
            need(pin["sha256"] == row["sha256"] and len(raw) == row["bytes"], "original-owner-source-differs")
            allowed.add(str(root / row["path"]))
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(root / "src"))
        from mobile_release import owned_process
    finally:
        sys.path[:] = previous
    for name, module in tuple(sys.modules.items()):
        if name == "mobile_release" or name.startswith("mobile_release."):
            need(getattr(module, "__file__", None) in allowed, "foreign-original-owner-import")
    _OWNER = owned_process


def remaining(deadline, maximum):
    seconds = math.floor(deadline - time.monotonic())
    need(seconds >= 1 and 1 <= maximum <= 900, "original-phase-deadline")
    return min(seconds, maximum)


def command(role, argv, *, maximum, deadline, output_limit=MIB, environment=None):
    global _ORIGINALS_SETTLED
    need(_OWNER is not None and re.fullmatch(r"[a-z][a-z0-9-]{0,79}", role), "original-command-role")
    row = {"role": role, "returned": False, "originalsSettled": False, "exitCode": None}
    _WAITS.append(row)
    try:
        result = _OWNER.run_owned(argv, environ=ENV if environment is None else environment,
            cwd=Path("/"), timeout=remaining(deadline, maximum), capture=True, text=False,
            output_limit=output_limit, execution_scope=None, journal_binding=None, on_start=None, cleanup=False)
        need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
             and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) < output_limit,
             "original-capture-shape-bound")
        row.update(returned=True, originalsSettled=True, exitCode=result.returncode,
                   stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr))
        return result
    except BaseException:
        # No retry/cleanup authority is inferred from a later observer or an
        # exception string, even if namespace disposal will contain this job.
        _ORIGINALS_SETTLED = False
        raise
    finally:
        if (TASK / "journals").is_dir():
            write(TASK / "journals" / (role + ".json"), canonical(row))


def host_module(catalogue):
    global _HOST_REFUSAL
    path = TASK / "source" / CONTROL / "host-admit.py"
    spec = importlib.util.spec_from_file_location("mrk_gnome_host_admit", path)
    need(spec is not None and spec.loader is not None, "host-admission-loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _HOST_REFUSAL = module.Refused
    return module, module.HostAdmission(command, catalogue["hostFacts"])


def git_configuration(raw, repository):
    """A tiny literal checkout profile, not Git's extensible configuration grammar."""
    need(0 < len(raw) <= 16384 and raw.endswith(b"\n")
         and all(byte in (9, 10) or 32 <= byte < 127 for byte in raw), "checkout-git-config-shape")
    allowed = {
        ("[core]", "repositoryformatversion"): {"0"}, ("[core]", "filemode"): {"true"},
        ("[core]", "bare"): {"false"}, ("[core]", "logallrefupdates"): {"true"},
        ('[remote "origin"]', "url"): {"https://github.com/" + repository, "https://github.com/" + repository + ".git"},
        ('[remote "origin"]', "fetch"): {"+refs/heads/*:refs/remotes/origin/*"}, ("[gc]", "auto"): {"0"}}
    sections = {section for section, _ in allowed}
    section, seen = None, set()
    for line in raw.decode("ascii").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line in sections:
            section = line
            continue
        key, equal, value = line.partition("=")
        pair = (section, key.strip())
        need(equal and pair in allowed and pair not in seen and value.strip() in allowed[pair],
             "checkout-git-config-literal")
        seen.add(pair)
    need(seen == allowed.keys(), "checkout-git-config-incomplete")


def checkout_git_controls(root, owner, repository):
    git = root / ".git"
    directories = []
    for relative in ("", "info", "objects", "objects/info"):
        path = git / relative
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == owner
             and not info.st_mode & 0o022, "checkout-git-control-parent")
        directories.append({"path": relative, "identity": identity(info)})
    for relative in GIT_FORBIDDEN_CONTROLS:
        try:
            (git / relative).lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise Refused("checkout-git-control-unreadable") from error
        else:
            raise Refused("checkout-git-control-occupied")
    files = {}
    for relative in ("config", "info/exclude"):
        path = git / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            need(relative == "info/exclude", "checkout-git-config-missing")
            files[relative] = {"absent": True}
            continue
        need(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == owner
             and not info.st_mode & 0o022, "checkout-git-control-file")
        raw, pin = read(path, 16384, root=False)
        need(pin["identity"] == identity(info), "checkout-git-control-changed")
        if relative == "config":
            git_configuration(raw, repository)
        files[relative] = pin
    need(all(identity((git / row["path"]).lstat()) == row["identity"] for row in directories),
         "checkout-git-control-parent-changed")
    return {"files": files, "absent": list(GIT_FORBIDDEN_CONTROLS), "directories": directories}


def checkout_admission(repository):
    """Admit only the fixed runner checkout, never ambient Git trust/config."""
    need(type(repository) is str and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository),
         "checkout-repository-shape")
    name = repository.split("/", 1)[1]
    need(name not in (".", ".."), "checkout-repository-component")
    home = Path("/home/runner")
    expected = home / "work" / name / name
    need(SOURCE == expected, "fixed-runner-checkout-path")
    runner = home.lstat()
    need(stat.S_ISDIR(runner.st_mode) and runner.st_uid > 0 and runner.st_gid > 0
         and not runner.st_mode & 0o022, "fixed-runner-home-owner")
    outer = OUTER.lstat()
    need(stat.S_ISDIR(outer.st_mode) and outer.st_uid == runner.st_uid and outer.st_gid > 0
         and stat.S_IMODE(outer.st_mode) == 0o700, "runner-original-output-owner")
    owner = (outer.st_uid, outer.st_gid)
    directories = []
    for path in (*reversed(expected.parents), expected, expected / ".git"):
        info = path.lstat()
        allowed_uids = (0, owner[0]) if path == home or home in path.parents else (0,)
        need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022
             and (info.st_uid in allowed_uids if path != expected and path != expected / ".git"
                  else (info.st_uid, info.st_gid) == owner), "fixed-runner-checkout-owner")
        # Entries may change only where separately permitted (the original
        # workflow output root); directory replacement/alias/permission cannot.
        directories.append({"path": str(path), "identity": [identity(info)[i] for i in (0, 1, 2, 4, 5)]})
    return {"repository": repository, "path": str(expected), "uid": owner[0], "gid": owner[1],
            "directories": directories, "gitControls": checkout_git_controls(expected, owner, repository)}


def git_output(args, deadline, role, checkout):
    need(checkout_admission(checkout["repository"]) == checkout, "original-checkout-admission-changed")
    try:
        result = command(role, ["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                              "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
                              "-c", "safe.directory=" + checkout["path"],
                              "-C", str(SOURCE), *args], maximum=15, deadline=deadline, output_limit=MIB,
                         environment={**ENV, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                                      "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"})
    finally:
        need(checkout_admission(checkout["repository"]) == checkout, "original-checkout-admission-changed")
    need(result.returncode == 0 and result.stderr == b"", "original-source-git-failed")
    return result.stdout


def save_host(path, snapshot):
    # Raw account bytes are private only. No human-readable snapshot is printed.
    value = {**snapshot, "accounts": {name: {**row, "raw": row["raw"].hex()}
                                     for name, row in snapshot["accounts"].items()}}
    write(path, canonical(value))


def load_host(path):
    value = decode(read(path)[0])
    value["accounts"] = {name: {**row, "raw": bytes.fromhex(row["raw"])} for name, row in value["accounts"].items()}
    return value


def reserve_host(host, deadline):
    before = host.capture("before-creation", deadline, created=False)
    save_host(TASK / "controls/host-before-creation.json", before)
    host.provision(deadline)
    after = host.capture("after-creation", deadline, created=True, baseline=before)
    save_host(TASK / "controls/host-after-creation.json", after)
    return before, after


def prepare(context, catalogue, names):
    checkout = checkout_admission(context["repository"])
    need(not TASK.exists() and not TASK.is_symlink() and not PUBLIC.exists() and not PUBLIC.is_symlink(),
         "fresh-task-root-required")
    TASK.mkdir(mode=0o700)
    PUBLIC.mkdir(mode=0o755)
    for name in ("controls", "source", "inputs", "journals", "logs", "download", "temporary"):
        (TASK / name).mkdir(mode=0o700)
    empty_capath = capath_state(TASK / "download", create=True)
    deadline = time.monotonic() + 60
    original_sha = git_output(["rev-parse", "HEAD"], deadline, "source-commit", checkout).decode("ascii").strip()
    tree = git_output(["rev-parse", "HEAD^{tree}"], deadline, "source-tree", checkout).decode("ascii").strip()
    need(original_sha == context["sourceSha"] and re.fullmatch(r"[0-9a-f]{40}", tree), "actual-checkout-source-differs")
    need(git_output(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=all"],
                    deadline, "source-status", checkout) == b"",
         "actual-checkout-not-clean")
    index = git_output(["ls-files", "--stage", "-z"], deadline, "source-index", checkout)
    modes = {}
    for record in index.split(b"\0")[:-1]:
        header, name = record.decode("utf-8", "strict").split("\t", 1)
        mode, blob, stage = header.split()
        need(mode in ("100644", "100755") and stage == "0" and name not in modes
             and re.fullmatch(r"[0-9a-f]{40}", blob), "tracked-source-record")
        modes[name] = (mode, blob)
    need(index.endswith(b"\0") and sorted(modes) == names, "tracked-complete-source-roster")
    source_rows = []
    for name in names:
        raw, original = read(SOURCE / name, 32 * MIB, root=False)
        mode, blob = modes[name]
        need(hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() == blob,
             "tracked-source-blob-differs")
        path = TASK / "source" / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pin = write(path, raw, 0o500 if mode == "100755" else 0o400)
        source_rows.append({"path": "/source/" + name, "bytes": pin["bytes"], "sha256": pin["sha256"],
                            "mode": pin["mode"], "gitMode": mode, "original": original,
                            "snapshotIdentity": pin["identity"]})
    source_index = b"".join((row["sha256"] + "  " + row["path"] + "\n").encode("utf-8") for row in source_rows)
    write(TASK / "controls/app-sources.sha256", source_index)
    outer = OUTER.lstat()
    need(stat.S_ISDIR(outer.st_mode) and outer.st_uid != 0 and stat.S_IMODE(outer.st_mode) == 0o700
         and list(OUTER.iterdir()) == [], "original-workflow-output-directory")
    binding = {"schema": "gnome-session-source-binding-1", **context, "fullTree": tree,
               "productTree": PRODUCT_TREE, "productFiles": 964, "completeSourceFiles": len(source_rows),
               "sourceIndexSha256": hashlib.sha256(source_index).hexdigest(), "sourceFiles": source_rows,
               "snapshotDirectories": source_directories(TASK / "source", names),
               "originalSourceDirectories": source_directories(SOURCE, names, original=True),
               "gitIndexSha256": hashlib.sha256(index).hexdigest(), "originalSourceRoot": str(SOURCE),
               "checkoutAdmission": checkout, "pythonPycache": pycache_original(),
               "workflowOuterRootIdentity": identity(outer), "startedMonotonic": time.monotonic(),
               "workflowDeadlineMonotonic": time.monotonic() + 1800}
    binding_pin = write(TASK / "controls/source-binding.json", canonical(binding))
    record_source_evidence(binding, binding_pin["sha256"])
    write(TASK / "controls/host-tool-originals.json", canonical(_PINS))
    module, host = host_module(catalogue)
    before, after = reserve_host(host, deadline)
    python_alias_finish()
    pycache_finish()
    write(TASK / "controls/prepared.json", canonical({"schema": PROFILE, "sourceSha": context["sourceSha"],
          "sourceBindingSha256": hashlib.sha256(canonical(binding)).hexdigest(), "hostAccountCreated": True,
          "emptyCapath": empty_capath}))
    write(PUBLIC / "prepare.json", canonical({**context, "phase": "prepare", "passed": True,
          "productFiles": 964, "completeSourceFiles": len(source_rows), "fullTree": tree,
          "host": module.public_projection([before, after], account_created=True), "nativeQualified": False,
          "evidence": public_evidence()}), 0o444)


def binding_for(context):
    raw, pin = read(TASK / "controls/source-binding.json", MIB)
    need(pin["mode"] == "0o400", "source-binding-mode")
    binding = decode(raw)
    need(binding["schema"] == "gnome-session-source-binding-1"
         and all(binding[key] == value for key, value in context.items()), "source-binding-context-differs")
    need(checkout_admission(binding["repository"]) == binding["checkoutAdmission"],
         "original-checkout-admission-changed")
    prepared = decode(read(TASK / "controls/prepared.json", MIB)[0])
    need(prepared["sourceBindingSha256"] == pin["sha256"] and prepared["hostAccountCreated"] is True,
         "original-preparation-incomplete")
    need(binding["pythonPycache"] == pycache_original(), "source-binding-pycache-original-changed")
    need(decode(read(TASK / "controls/host-tool-originals.json", 16 * MIB)[0]) == _PINS,
         "original-host-tool-custody-changed")
    names = []
    for row in binding["sourceFiles"]:
        need(row["path"].startswith("/source/"), "source-binding-path")
        relative = path_name(row["path"].removeprefix("/source/"))
        names.append(relative)
        _, actual = read(TASK / "source" / relative, 32 * MIB)
        need(all(actual[key] == row[key] for key in ("bytes", "sha256", "mode"))
             and actual["identity"] == row["snapshotIdentity"], "source-snapshot-changed")
        _, original = read(SOURCE / relative, 32 * MIB, root=False)
        need(original == row["original"], "original-checkout-changed")
    need(len(set(names)) == len(names) == binding["completeSourceFiles"]
         and source_directories(TASK / "source", names) == binding["snapshotDirectories"]
         and source_directories(SOURCE, names, original=True) == binding["originalSourceDirectories"],
         "source-directory-custody-changed")
    record_source_evidence(binding, pin["sha256"])
    return binding, pin["sha256"]


def public_url(value):
    parsed = urllib.parse.urlsplit(value)
    allowed_origin = parsed.hostname in {"archive.ubuntu.com", "security.ubuntu.com",
        "static.rust-lang.org", "static.crates.io", "index.crates.io"} or value in SNAPSHOT_NATIVE_URLS or value == BWRAP_URL
    need(parsed.scheme == "https" and allowed_origin
         and parsed.username is None and parsed.password is None and parsed.port in (None, 443)
          and not parsed.fragment and not parsed.query, "supplier-anonymous-official-https")


def directory_custody(info):
    # Child creation changes nlink/timestamps, never this original directory's
    # device, inode, type/mode or ownership. Not a directory-content claim.
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def python_alias_originals():
    """Check the same finite held parent/link/file objects throughout this phase."""
    state = _PYTHON_ALIASES
    need(state is not None and state["ready"] and not state["closed"], "python-alias-originals-required")

    def parents():
        for path, row in state["parents"].items():
            actual = os.fstat(row["fd"])
            named = (Path("/").lstat() if path == "/" else os.stat(Path(path).name,
                dir_fd=state["parents"][str(Path(path).parent)]["fd"], follow_symlinks=False))
            need(stat.S_ISDIR(actual.st_mode) and actual.st_uid == actual.st_gid == 0
                 and stat.S_IMODE(actual.st_mode) == 0o755
                 and directory_custody(actual) == row["custody"] == directory_custody(named),
                 "python-alias-parent-original-changed")

    def leaf(path, row):
        before = os.fstat(row["fd"])
        named = os.stat(Path(path).name, dir_fd=state["parents"][str(Path(path).parent)]["fd"],
                        follow_symlinks=False)
        need(identity(before) == row["identity"] == identity(named), "python-alias-leaf-original-changed")
        return before

    parents()
    links, files = [], {}
    for path, row in state["links"].items():
        before = leaf(path, row)
        target = PYTHON_ALIAS_LINKS[path]
        need(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o777
             and before.st_size == len(target.encode("ascii")), "python-alias-link-state")
        need(os.readlink(Path(path).name, dir_fd=state["parents"][str(Path(path).parent)]["fd"])
             == target, "python-alias-link-text")
        leaf(path, row)
        links.append({"path": path, "target": target, "identity": row["identity"]})
    for path, row in state["files"].items():
        before = leaf(path, row)
        expected = PYTHON_ALIAS_FILES[path]
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1 and oct(stat.S_IMODE(before.st_mode)) == expected["mode"]
             and before.st_size == expected["bytes"], "python-alias-terminal-state")
        size, digest = 0, hashlib.sha256()
        while part := os.pread(row["fd"], min(65536, expected["bytes"] - size + 1), size):
            size += len(part)
            need(size <= expected["bytes"], "python-alias-terminal-grew")
            digest.update(part)
        need(size == expected["bytes"] and digest.hexdigest() == expected["sha256"],
             "python-alias-terminal-bytes")
        leaf(path, row)
        files[path] = {**expected, "identity": row["identity"]}
    # A link or earlier terminal must not change while a later body is hashed.
    for path, row in (*state["links"].items(), *state["files"].items()):
        leaf(path, row)
    parents()
    return {"parents": [{"path": path, "custody": row["custody"]} for path, row in state["parents"].items()],
            "links": links, "files": files}


def python_alias_begin(catalogue):
    """Fresh phase admission; do not reuse a historical inode or a prior phase FD."""
    global _PYTHON_ALIASES
    need(_PYTHON_ALIASES is None, "python-alias-phase-already-started")
    python_alias_catalogue(catalogue)
    state = {"fds": [], "parents": {}, "links": {}, "files": {}, "ready": False,
             "admitted": False, "closed": False}
    _PYTHON_ALIASES = state
    _EVIDENCE["pythonAliasCustody"] = {"originalSha256": None, "parentCount": 8, "linkCount": 3,
        "terminalCount": 2, "phaseCustodyPostchecked": False, "phaseHandlesClosed": False,
        "postcheckErrors": 0, "closeErrors": 0,
        "scope": "fixed-selected-chains; fresh-phase-originals; not-retroactive-bootstrap-or-runtime-qualification"}
    try:
        for path in PYTHON_ALIAS_PARENTS:
            parent_fd = None if path == "/" else state["parents"][str(Path(path).parent)]["fd"]
            fd = os.open(path if parent_fd is None else Path(path).name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            state["fds"].append(fd)  # Own before any fallible observation.
            actual = os.fstat(fd)
            named = (Path("/").lstat() if parent_fd is None else
                     os.stat(Path(path).name, dir_fd=parent_fd, follow_symlinks=False))
            need(stat.S_ISDIR(actual.st_mode) and actual.st_uid == actual.st_gid == 0
                 and stat.S_IMODE(actual.st_mode) == 0o755
                 and directory_custody(actual) == directory_custody(named), "python-alias-protected-parent")
            state["parents"][path] = {"fd": fd, "custody": directory_custody(actual)}
        for kind, paths in (("links", PYTHON_ALIAS_LINKS), ("files", PYTHON_ALIAS_FILES)):
            for path in paths:
                parent_fd = state["parents"][str(Path(path).parent)]["fd"]
                before = os.stat(Path(path).name, dir_fd=parent_fd, follow_symlinks=False)
                need(before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                     and (stat.S_ISLNK(before.st_mode) if kind == "links" else stat.S_ISREG(before.st_mode)),
                     "python-alias-leaf-kind")
                flags = os.O_PATH if kind == "links" else os.O_RDONLY | os.O_NONBLOCK
                fd = os.open(Path(path).name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
                state["fds"].append(fd)
                need(identity(before) == identity(os.fstat(fd)), "python-alias-open-original-changed")
                state[kind][path] = {"fd": fd, "identity": identity(before)}
        state["ready"] = True
        original = python_alias_originals()
        _EVIDENCE["pythonAliasCustody"]["originalSha256"] = hashlib.sha256(canonical(original)).hexdigest()
        state["admitted"] = True
        return original
    except BaseException:
        python_alias_finish(failed=True)
        raise


def python_alias_finish(*, failed=False):
    """Postcheck and consuming-close before publication; never mask a primary error."""
    global _ORIGINALS_SETTLED
    state = _PYTHON_ALIASES
    if state is None or state["closed"]:
        need(failed or state is not None and _EVIDENCE["pythonAliasCustody"]["phaseCustodyPostchecked"]
             and _EVIDENCE["pythonAliasCustody"]["phaseHandlesClosed"], "python-alias-phase-not-closed")
        return
    body_error, close_errors = None, 0
    try:
        if state["admitted"]:
            python_alias_originals()
            _EVIDENCE["pythonAliasCustody"]["phaseCustodyPostchecked"] = True
        need(failed or state["admitted"] and _ORIGINALS_SETTLED, "python-alias-consuming-originals-unsettled")
    except BaseException as error:
        body_error = error
        _EVIDENCE["pythonAliasCustody"]["postcheckErrors"] += 1
    finally:
        state["closed"] = True
        while state["fds"]:
            fd = state["fds"].pop()  # Detach even when close reports Unknown; never retry it.
            try:
                os.close(fd)
            except BaseException:
                close_errors += 1
                _ORIGINALS_SETTLED = False
        _EVIDENCE["pythonAliasCustody"]["phaseHandlesClosed"] = close_errors == 0
        _EVIDENCE["pythonAliasCustody"]["closeErrors"] = close_errors
    if not failed:
        if body_error is not None:
            raise body_error
        need(not close_errors, "python-alias-original-close-unknown")


def pycache_empty(fd):
    """Read at most one directory entry; own the iterator before using it."""
    global _ORIGINALS_SETTLED
    scan, body_failed = None, False
    try:
        scan = os.scandir(fd)
        need(next(scan, None) is None, "pycache-not-empty")
    except BaseException:
        body_failed = True
        raise
    finally:
        if scan is not None:
            try:
                scan.close()
            except BaseException:
                _ORIGINALS_SETTLED = False
                if not body_failed:
                    raise Refused("pycache-scan-close-unknown")


def pycache_original():
    """Check the same held host originals, not a newly empty replacement."""
    state = _PYCACHE
    need(state is not None and not state["closed"] and len(state["fds"]) == 3
         and state["original"] is not None, "pycache-original-custody-required")
    original, fds = state["original"], state["fds"]

    def parents():
        for index, row in enumerate(original["parents"]):
            actual = os.fstat(fds[index])
            named = (Path("/").lstat() if index == 0 else
                     os.stat("run", dir_fd=fds[0], follow_symlinks=False))
            need(stat.S_ISDIR(actual.st_mode) and actual.st_uid == actual.st_gid == 0
                 and not actual.st_mode & 0o022
                 and directory_custody(actual) == row["custody"] == directory_custody(named),
                 "pycache-parent-original-changed")

    parents()
    before = os.fstat(fds[-1])
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
         and stat.S_IMODE(before.st_mode) == 0o555, "pycache-not-protected")
    need(identity(before) == original["identity"] ==
         identity(os.stat(PYTHON_PYCACHE.name, dir_fd=fds[1], follow_symlinks=False)),
         "pycache-leaf-original-changed")
    pycache_empty(fds[-1])
    need(identity(os.fstat(fds[-1])) == original["identity"] ==
         identity(os.stat(PYTHON_PYCACHE.name, dir_fd=fds[1], follow_symlinks=False)),
         "pycache-leaf-original-changed")
    parents()
    return original


def pycache_begin(expected=None):
    """First bootstrap admission, or exact comparison with the first phase."""
    global _PYCACHE
    need(_PYCACHE is None, "pycache-phase-already-started")
    state = {"fds": [], "original": None, "closed": False}
    _PYCACHE = state  # Own partial acquisition before the first fstat.
    _EVIDENCE["pythonPycache"] = {"path": str(PYTHON_PYCACHE), "originalSha256": None,
        "phaseCustodyPostchecked": False, "phaseHandlesClosed": False,
        "startupAuthority": "explicit-trusted-bootstrap-before-first-python; not-retroactive",
        "retirement": "leave-protected-for-disposable-vm-only"}
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        state["fds"].append(fd)
        parents = []
        for path, part in ((Path("/"), "run"), (Path("/run"), PYTHON_PYCACHE.name)):
            info = os.fstat(fd)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                 and not info.st_mode & 0o022, "pycache-protected-parent")
            parents.append({"path": str(path), "custody": directory_custody(info)})
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            state["fds"].append(fd)
        state["original"] = {"path": str(PYTHON_PYCACHE), "identity": identity(os.fstat(fd)),
                             "parents": parents, "entries": []}
        original = pycache_original()
        need(expected is None or original == expected, "pycache-first-phase-original-changed")
        _EVIDENCE["pythonPycache"]["originalSha256"] = hashlib.sha256(canonical(original)).hexdigest()
        return original
    except BaseException:
        pycache_finish(failed=True)
        raise


def pycache_for_phase(context, phase):
    expected = None
    if phase != "supply-bwrap":
        stage = bwrap_stage_identity()
        raw, pin = read(BWRAP_SUPPLY / "before.json", 16 * MIB)
        before = decode(raw)
        need(pin["mode"] == "0o400" and before["schema"] == BWRAP_SUPPLY_SCHEMA
             and all(before.get(key) == value for key, value in context.items())
             and before["stageIdentity"] == stage, "pycache-first-phase-control")
        expected = before["pythonPycache"]
        need(type(expected) is dict, "pycache-first-phase-original-required")
    return pycache_begin(expected)


def pycache_finish(*, failed=False):
    """Postcheck/close once before success; preserve any primary body failure."""
    global _ORIGINALS_SETTLED
    state = _PYCACHE
    if state is None or state["closed"]:
        need(failed or state is not None and _EVIDENCE["pythonPycache"]["phaseHandlesClosed"],
             "pycache-phase-not-closed")
        return
    body_error, close_failed = None, False
    try:
        if state["original"] is not None:
            pycache_original()
            _EVIDENCE["pythonPycache"]["phaseCustodyPostchecked"] = True
        need(failed or _ORIGINALS_SETTLED, "pycache-consuming-originals-unsettled")
    except BaseException as error:
        body_error = error
    finally:
        state["closed"] = True
        while state["fds"]:
            fd = state["fds"].pop()  # Detach before close: failure is never retried.
            try:
                os.close(fd)
            except BaseException:
                close_failed = True
                _ORIGINALS_SETTLED = False
        _EVIDENCE["pythonPycache"]["phaseHandlesClosed"] = not close_failed
    if not failed:
        if body_error is not None:
            raise body_error
        need(not close_failed, "pycache-original-close-unknown")


def capath_state(download_root, *, create=False):
    """One original empty directory, never an ambient/default certificate tree.

    The parent chain may gain archive siblings, so its *custody* is compared;
    the empty leaf keeps its complete original identity and empty roster.
    Every directory descriptor is closed once, including partial acquisition.
    """
    global _ORIGINALS_SETTLED
    root = Path(download_root)
    need(root in (TASK / "download", BWRAP_SUPPLY / "inputs/download"), "fixed-capath-root")
    target = root / "empty-capath"
    held, parents, result, close_failed, body_failed = [], [], None, False, False
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held.append(fd)
        paths = [Path("/")]
        for part in target.parts[1:]:
            parent = os.fstat(fd)
            path = paths[-1]
            need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0
                 and (not parent.st_mode & 0o022 or path == Path("/var/tmp")
                      and stat.S_IMODE(parent.st_mode) == 0o1777), "capath-protected-parent")
            need(directory_custody(path.lstat()) == directory_custody(parent), "capath-parent-original")
            parents.append({"path": str(path), "custody": directory_custody(parent)})
            if create and path == root:
                os.mkdir(part, 0o500, dir_fd=fd)  # Exclusive; an existing empty directory is not adopted.
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            held.append(fd)
            paths.append(path / part)
        original = os.fstat(fd)
        need(stat.S_ISDIR(original.st_mode) and original.st_uid == original.st_gid == 0
             and stat.S_IMODE(original.st_mode) == 0o500 and os.listdir(fd) == [], "capath-not-protected-empty")
        need(identity(original) == identity(os.fstat(fd)) == identity(target.lstat()), "capath-original-changed")
        for parent, parent_fd in zip(parents, held):
            need(directory_custody(os.fstat(parent_fd)) == parent["custody"]
                 == directory_custody(Path(parent["path"]).lstat()), "capath-parent-original")
        result = {"path": str(target), "identity": identity(original), "parents": parents, "entries": []}
    except BaseException:
        body_failed = True
        raise
    finally:
        for fd in reversed(held):
            try:
                os.close(fd)
            except BaseException:
                close_failed = True
                _ORIGINALS_SETTLED = False
        # Keep the original read/validation failure primary. A concurrent
        # close failure still latches Unknown and never skips remaining closes.
        if close_failed and not body_failed:
            need(False, "capath-original-close-unknown")
    return result


def acquisition_capath(download_root):
    root = Path(download_root)
    need(root in (TASK / "download", BWRAP_SUPPLY / "inputs/download"), "fixed-capath-root")
    control = BWRAP_SUPPLY / "before.json" if root == BWRAP_SUPPLY / "inputs/download" else TASK / "controls/prepared.json"
    raw, pin = read(control, 16 * MIB)
    need(pin["mode"] == "0o400", "capath-control-mode")
    expected = decode(raw)["emptyCapath"]
    need(capath_state(root) == expected, "capath-custody-changed")
    need(_CATALOGUE["caFile"] == CA_FILE and CA_FILE in _PINS, "fixed-ca-original-required")
    # The bundle is a distinct protected original. --cacert alone would still
    # leave curl's compiled directory fallback reachable.
    for path in (Path("/"), Path("/etc"), Path("/etc/ssl"), Path("/etc/ssl/certs")):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not info.st_mode & 0o022, "ca-protected-ancestry")
    need(read(CA_FILE, 4 * MIB)[1] == _PINS[CA_FILE], "ca-original-changed")
    return expected


def acquire_archive(row, role, deadline, *, download_root=None):
    public_url(row["url"])
    download_root = TASK / "download" if download_root is None else Path(download_root)
    need(download_root == TASK / "download"
         or (download_root == BWRAP_SUPPLY / "inputs/download" and role == "bwrap"
             and hashlib.sha256(canonical(row)).hexdigest() == BWRAP_SUPPLIER_SHA256),
         "fixed-supplier-download-root")
    destination = download_root / (role + ".archive")
    need(not destination.exists() and not destination.is_symlink(), "fresh-supplier-output")
    capath = acquisition_capath(download_root)
    argv = ["/usr/bin/curl", "--disable", "--fail", "--silent", "--show-error", "--proto", "=https",
             "--proxy", "", "--retry", "0", "--connect-timeout", "15", "--max-time", "120",
             "--max-filesize", str(row["bytes"]), "--cacert", _CATALOGUE["caFile"],
             "--capath", capath["path"],
             "--output", str(destination), "--", row["url"]]
    result = command("download-" + role, argv, maximum=125, deadline=deadline, output_limit=65536)
    need(acquisition_capath(download_root) == capath, "capath-download-original-changed")
    need(result.returncode == 0 and result.stdout == b"" and result.stderr == b"", "supplier-original-download-failed")
    _, pin = read(destination, row["bytes"])
    need(pin["bytes"] == row["bytes"] and pin["sha256"] == row["sha256"], "supplier-archive-correspondence")
    decoded = download_root / (role + ".tar")
    # Fixed standard decoder only; no installer or package maintainer scripts.
    decoder = (["/usr/bin/dpkg-deb", "--fsys-tarfile", str(destination)] if row["format"] == "deb"
               else ["/usr/bin/xz", "--decompress", "--stdout", "--single-stream", str(destination)])
    shell = 'set -euC; umask 077; ulimit -c 0; ulimit -f "$1"; output=$2; shift 2; exec "$@" > "$output"'
    result = command("decode-" + role, ["/usr/bin/bash", "--noprofile", "--norc", "-c", shell,
                     "mrk-fixed-supplier-decoder", str(math.ceil(row["decodedBytes"] / 1024)), str(decoded), *decoder],
                     maximum=90, deadline=deadline, output_limit=65536)
    need(result.returncode == 0 and result.stdout == b"" and result.stderr == b"", "supplier-original-decoder-failed")
    _, actual = read(decoded, row["decodedBytes"])
    need(actual["bytes"] == row["decodedBytes"] and actual["sha256"] == row["decodedSha256"],
         "supplier-decoded-correspondence")
    need(read(destination, row["bytes"])[1] == pin, "supplier-archive-changed-during-decode")
    _SUPPLIERS.append({"role": role, "package": row.get("package"), "component": row.get("component"),
        "packageVersion": row.get("version"), "releaseVersion": row.get("releaseVersion"),
        "componentDeclaredVersion": row.get("componentDeclaredVersion"),
        "archive": {key: pin[key] for key in ("bytes", "sha256")},
        "decoded": {key: actual[key] for key in ("bytes", "sha256")},
        "originalArchiveIdentitySha256": hashlib.sha256(canonical(pin["identity"])).hexdigest(),
        "originalDecodedIdentitySha256": hashlib.sha256(canonical(actual["identity"])).hexdigest(),
        "provenanceSha256": hashlib.sha256(canonical(row["provenance"])).hexdigest(),
        "selectedMembers": None})
    return decoded


def selected_members(path, row, destination_root):
    wanted = {path_name(item["member"]): item for item in row["members"]}
    need(len(wanted) == len(row["members"]), "supplier-selected-member-duplicate")
    seen, count, size, selected = set(), 0, 0, []
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = identity(os.fstat(fd))
        with os.fdopen(os.dup(fd), "rb") as stream, tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                count += 1
                size += member.size
                need(count <= row["memberLimit"] and size <= row["expandedLimit"], "supplier-expanded-bound")
                name = member.name.removeprefix("./")
                if name in wanted:
                    item = wanted[name]
                    need(name not in seen and member.isreg() and member.size == item["bytes"]
                         and oct(member.mode) == item["archiveMode"], "supplier-selected-member-kind-mode")
                    seen.add(name)
                    source = archive.extractfile(member)
                    need(source is not None, "supplier-selected-member-stream")
                    with source:
                        raw = source.read(item["bytes"] + 1)
                    need(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"],
                         "supplier-selected-member-content")
                    target = destination_root / path_name(item["target"])
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    pin = write(target, raw, int(item["mode"], 8))
                    selected.append({"member": name, "target": item["target"], **pin})
        need(seen == set(wanted) and identity(os.fstat(fd)) == before == identity(Path(path).lstat()),
             "supplier-selected-members-complete-original")
    finally:
        os.close(fd)
    return {"count": len(selected), "bytes": sum(item["bytes"] for item in selected),
            "originalsSha256": hashlib.sha256(canonical(selected)).hexdigest()}


def bwrap_close_parents(parents):
    error = None
    while parents:
        _, fd, _ = parents.pop()
        try:
            os.close(fd)
        except OSError as failure:
            error = failure  # Never retry a possibly closed original descriptor.
    if error is not None:
        raise Refused("bwrap-parent-close-unsettled") from error


def bwrap_parent_handles():
    parents = []
    try:
        for path in (Path("/"), Path("/usr"), BWRAP_TARGET.parent):
            fd = os.open(str(path) if not parents else path.name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=None if not parents else parents[-1][1])
            parents.append((path, fd, None))
            info = os.fstat(fd)
            parents[-1] = (path, fd, identity(info))
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                 and not info.st_mode & 0o022 and identity(info) == identity(path.lstat()),
                 "bwrap-protected-parent")
        return parents
    except BaseException:
        bwrap_close_parents(parents)
        raise


def bwrap_parent_snapshot(parents):
    rows = []
    for path, fd, original in parents:
        current = identity(os.fstat(fd))
        need(all(current[key] == original[key] for key in (0, 1, 2, 3, 4, 5))
             and current == identity(path.lstat()), "bwrap-parent-original-changed")
        rows.append({"path": str(path), "identity": current})
    before = identity(os.fstat(parents[-1][1]))
    entries = sorted(os.listdir(parents[-1][1]))
    need(len(entries) <= 16384 and before == rows[-1]["identity"] == identity(os.fstat(parents[-1][1])),
         "bwrap-parent-entry-bound")
    return {"parents": rows, "entries": entries}


def bwrap_parent_transition(before, after):
    need(len(before["parents"]) == len(after["parents"]) == 3
         and BWRAP_TARGET.name not in before["entries"]
         and after["entries"] == sorted([*before["entries"], BWRAP_TARGET.name])
         and all(old["path"] == new["path"] and all(old["identity"][key] == new["identity"][key]
                     for key in (0, 1, 2, 3, 4, 5))
                 for old, new in zip(before["parents"], after["parents"])),
         "bwrap-only-declared-parent-transition")


def bwrap_native_roots_absent():
    for path in (TASK, PUBLIC):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise Refused("bwrap-native-root-occupied")


def bwrap_stage_identity():
    info = BWRAP_SUPPLY.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
         and stat.S_IMODE(info.st_mode) == 0o700, "bwrap-private-stage-owner")
    return identity(info)[:6]


def bwrap_sources(names):
    need(len(names) == 975 and names == sorted(set(names)), "bwrap-complete-source-roster")
    return {"files": {name: read(SOURCE / name, 32 * MIB, root=False)[1] for name in names},
            "directories": source_directories(SOURCE, names, original=True)}


def bwrap_original_waits():
    return [{"role": role, "returned": True, "originalsSettled": True, "exitCode": 0,
             "stdoutBytes": 0, "stderrBytes": 0}
            for role in ("download-bwrap", "decode-bwrap")]


def bwrap_input_originals(row, supplier):
    root = BWRAP_SUPPLY / "inputs"
    roster = bounded_roster(root, files=8, total=MIB)
    files = {Path(item["path"]).relative_to(root).as_posix(): item for item in roster["files"]}
    member = row["members"][0]
    expected = {"download/bwrap.archive": (row["bytes"], row["sha256"], "0o600"),
                "download/bwrap.tar": (row["decodedBytes"], row["decodedSha256"], "0o600"),
                "staged/bwrap": (member["bytes"], member["sha256"], "0o400")}
    need(files.keys() == expected.keys() and len(roster["directories"]) == 4
          and {Path(item["path"]).relative_to(root).as_posix() for item in roster["directories"]}
              == {".", "download", "download/empty-capath", "staged"}
          and all(item["mode"] == ("0o500" if item["path"] == str(root / "download/empty-capath") else "0o700")
                  for item in roster["directories"])
         and all(tuple(files[name][key] for key in ("bytes", "sha256", "mode")) == value
                 for name, value in expected.items()), "bwrap-fixed-private-inputs")
    selected = {"member": member["member"], "target": member["target"],
                **{key: files["staged/bwrap"][key] for key in ("identity", "bytes", "sha256", "mode")}}
    expected_supplier = {"role": "bwrap", "package": row["package"], "component": None,
        "packageVersion": row["version"], "releaseVersion": None, "componentDeclaredVersion": None,
        "archive": {key: files["download/bwrap.archive"][key] for key in ("bytes", "sha256")},
        "decoded": {key: files["download/bwrap.tar"][key] for key in ("bytes", "sha256")},
        "provenanceSha256": hashlib.sha256(canonical(row["provenance"])).hexdigest(),
        "originalArchiveIdentitySha256": hashlib.sha256(canonical(files["download/bwrap.archive"]["identity"])).hexdigest(),
        "originalDecodedIdentitySha256": hashlib.sha256(canonical(files["download/bwrap.tar"]["identity"])).hexdigest(),
        "selectedMembers": {"count": 1, "bytes": member["bytes"],
                            "originalsSha256": hashlib.sha256(canonical([selected])).hexdigest()}}
    need(supplier == expected_supplier, "bwrap-acquisition-originals-changed")
    return roster


def bwrap_file_original(fd, parent_fd, member, mode):
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
         and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode
         and before.st_size == member["bytes"], "bwrap-owned-leaf-state")
    os.lseek(fd, 0, os.SEEK_SET)
    parts, size = [], 0
    while part := os.read(fd, min(65536, member["bytes"] - size + 1)):
        size += len(part)
        need(size <= member["bytes"], "bwrap-owned-leaf-grew")
        parts.append(part)
    raw = b"".join(parts)
    need(size == member["bytes"] and hashlib.sha256(raw).hexdigest() == member["sha256"]
         and identity(before) == identity(os.fstat(fd))
             == identity(os.stat(BWRAP_TARGET.name, dir_fd=parent_fd, follow_symlinks=False)),
         "bwrap-owned-leaf-correspondence")
    return {"identity": identity(before), "bytes": size, "sha256": member["sha256"], "mode": oct(mode)}


def bwrap_create_leaf(raw, member, parent_fd, before_enable):
    need(len(raw) == member["bytes"] and hashlib.sha256(raw).hexdigest() == member["sha256"],
         "bwrap-staged-body-differs")
    # Only a new canonical leaf. It is never executable while being written or
    # before its bytes and all previously admitted inputs have been postchecked.
    fd = os.open(BWRAP_TARGET.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent_fd)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, "bwrap-owned-leaf-short-write")
            offset += count
        os.fsync(fd)
        nonexecuting = bwrap_file_original(fd, parent_fd, member, 0o600)
        before_enable()
        need(bwrap_file_original(fd, parent_fd, member, 0o600) == nonexecuting,
             "bwrap-owned-leaf-changed-before-enable")
        os.fchmod(fd, 0o755)
        os.fsync(fd)
        installed = bwrap_file_original(fd, parent_fd, member, 0o755)
        need(all(installed["identity"][key] == nonexecuting["identity"][key] for key in (0, 1, 3, 4, 5, 6, 7)),
             "bwrap-owned-leaf-replaced")
        return installed
    finally:
        os.close(fd)


def bwrap_supply_evidence(pin, installed):
    _EVIDENCE["bwrapSupply"] = {"receiptSha256": pin["sha256"],
        "supplierContractSha256": BWRAP_SUPPLIER_SHA256, "newCanonicalLeaf": True,
        "bytes": installed["bytes"], "sha256": installed["sha256"],
        "originalsSettled": True, "nativeQualified": False}


def supply_bwrap(context, catalogue, names):
    # catalogue_ready has already required COMPLETE admitted supplier facts.
    # This phase never calls owner_argv: ordinary C/A/W curl/decoder ownership
    # precedes the unchanged native bwrap namespace launch.
    row = bwrap_archive(catalogue)
    parents, stage, old_umask = [], None, None
    try:
        parents = bwrap_parent_handles()
        parent_before = bwrap_parent_snapshot(parents)
        authenticate_bwrap_absent(catalogue)
        need(BWRAP_TARGET.name not in parent_before["entries"]
             and bwrap_parent_snapshot(parents) == parent_before, "bwrap-exact-absent-parent")
        bwrap_native_roots_absent()
        sources = bwrap_sources(names)
        for path in (Path("/var"), Path("/var/tmp")):
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                 and (not info.st_mode & 0o022 or path == Path("/var/tmp")
                      and stat.S_IMODE(info.st_mode) == 0o1777), "bwrap-stage-parent")
        need(not BWRAP_SUPPLY.exists() and not BWRAP_SUPPLY.is_symlink(), "fresh-bwrap-stage-required")
        old_umask = os.umask(0o077)
        BWRAP_SUPPLY.mkdir(mode=0o700)
        for name in ("inputs", "inputs/download", "inputs/staged"):
            (BWRAP_SUPPLY / name).mkdir(mode=0o700)
        empty_capath = capath_state(BWRAP_SUPPLY / "inputs/download", create=True)
        stage = bwrap_stage_identity()
        before = {"schema": BWRAP_SUPPLY_SCHEMA, **context, "stageIdentity": stage,
                  "hostOriginals": dict(_PINS), "sourceOriginals": sources, "parentBefore": parent_before,
                  "emptyCapath": empty_capath, "pythonPycache": pycache_original()}
        before_pin = write(BWRAP_SUPPLY / "before.json", canonical(before))
        # No new bootstrap trust: actual host/Python/config and source checks
        # above precede even importing the existing C/A/W implementation.
        owner_modules(SOURCE, catalogue)
        deadline = time.monotonic() + 240
        decoded = acquire_archive(row, "bwrap", deadline, download_root=BWRAP_SUPPLY / "inputs/download")
        need(len(_SUPPLIERS) == 1, "bwrap-single-acquisition")
        _SUPPLIERS[0]["selectedMembers"] = selected_members(decoded, row, BWRAP_SUPPLY / "inputs/staged")
        need(_ORIGINALS_SETTLED and _WAITS == bwrap_original_waits(), "bwrap-originals-not-successful")
        inputs = bwrap_input_originals(row, _SUPPLIERS[0])
        authenticate_bwrap_absent(catalogue, after=True)
        need(bwrap_parent_snapshot(parents) == parent_before
             and bwrap_sources(names) == sources and _PINS == before["hostOriginals"],
             "bwrap-prestate-originals-changed")
        raw, staged = read(BWRAP_SUPPLY / "inputs/staged/bwrap", row["members"][0]["bytes"])
        need(staged["mode"] == "0o400", "bwrap-staged-nonexecuting")

        def before_enable():
            bwrap_native_roots_absent()
            bwrap_parent_transition(parent_before, bwrap_parent_snapshot(parents))
            authenticate_host(bwrap_host_peers(catalogue), after=True)
            need(_ORIGINALS_SETTLED and _WAITS == bwrap_original_waits()
                 and _PINS == before["hostOriginals"] and bwrap_sources(names) == sources
                  and bwrap_input_originals(row, _SUPPLIERS[0]) == inputs
                  and acquisition_capath(BWRAP_SUPPLY / "inputs/download") == empty_capath
                   and pycache_original() == before["pythonPycache"]
                 and read(BWRAP_SUPPLY / "before.json", 16 * MIB)[1] == before_pin
                 and bwrap_stage_identity() == stage, "bwrap-before-enable-originals-changed")

        installed = bwrap_create_leaf(raw, row["members"][0], parents[-1][1], before_enable)
        need(str(BWRAP_TARGET) not in _PINS, "bwrap-new-pin-collision")
        _PINS[str(BWRAP_TARGET)] = installed  # Add one new owned original; never reset old pins.
        authenticate_host(catalogue, after=True)
        parent_after = bwrap_parent_snapshot(parents)
        bwrap_parent_transition(parent_before, parent_after)
        bwrap_native_roots_absent()
        need(_ORIGINALS_SETTLED and _WAITS == bwrap_original_waits()
             and _PINS == {**before["hostOriginals"], str(BWRAP_TARGET): installed}
              and bwrap_sources(names) == sources and bwrap_input_originals(row, _SUPPLIERS[0]) == inputs
              and acquisition_capath(BWRAP_SUPPLY / "inputs/download") == empty_capath
                   and pycache_original() == before["pythonPycache"]
             and read(BWRAP_SUPPLY / "before.json", 16 * MIB)[1] == before_pin
             and bwrap_stage_identity() == stage
             and sorted(os.listdir(BWRAP_SUPPLY)) == ["before.json", "inputs"],
             "bwrap-complete-poststate-changed")
        bwrap_close_parents(parents)
        os.umask(old_umask)
        old_umask = None
        python_alias_finish()
        pycache_finish()
        receipt = {"schema": BWRAP_SUPPLY_SCHEMA, **context, "phase": "supply-bwrap",
                   "passed": True, "originalsSettled": True, "parentHandlesClosed": True,
                   "nativeQualified": False, "supplierContractSha256": BWRAP_SUPPLIER_SHA256,
                   "beforeSha256": before_pin["sha256"], "installed": installed,
                   "parentAfter": parent_after, "inputOriginals": inputs,
                   "pythonPycache": before["pythonPycache"], "pythonPycacheHandlesClosed": True,
                   "supplierOriginal": _SUPPLIERS[0], "waits": list(_WAITS)}
        pin = write(BWRAP_SUPPLY / "receipt.json", canonical(receipt))
        bwrap_supply_evidence(pin, installed)
    except BaseException:
        # A partial canonical leaf or unsettled producer is never adopted,
        # retried, removed, made executable by recovery, or native authority.
        if stage is not None:
            try:
                need(bwrap_stage_identity() == stage, "bwrap-failure-stage-changed")
                write(BWRAP_SUPPLY / "refusal.json", canonical({"schema": BWRAP_SUPPLY_SCHEMA, **context,
                    "passed": False, "originalsSettled": _ORIGINALS_SETTLED, "waits": list(_WAITS),
                    "cleanupVerified": False, "disposition": "retained-for-disposable-vm-retirement"}))
            except BaseException:
                pass
        raise
    finally:
        try:
            bwrap_close_parents(parents)
        finally:
            if old_umask is not None:
                os.umask(old_umask)


def bwrap_supply_for(context, catalogue, names):
    """Fresh full host admission plus this same-source/run receipt, not replay."""
    need(_ORIGINALS_SETTLED, "bwrap-prior-originals-unsettled")
    row = bwrap_archive(catalogue)
    stage = bwrap_stage_identity()
    need(sorted(os.listdir(BWRAP_SUPPLY)) == ["before.json", "inputs", "receipt.json"],
         "bwrap-stage-not-successfully-closed")
    raw, before_pin = read(BWRAP_SUPPLY / "before.json", 16 * MIB)
    before = decode(raw)
    raw, receipt_pin = read(BWRAP_SUPPLY / "receipt.json", 16 * MIB)
    receipt = decode(raw)
    need(before_pin["mode"] == receipt_pin["mode"] == "0o400"
         and before["schema"] == receipt["schema"] == BWRAP_SUPPLY_SCHEMA
         and all(before.get(key) == receipt.get(key) == value for key, value in context.items())
         and before["stageIdentity"] == stage and receipt["phase"] == "supply-bwrap"
         and receipt["passed"] is True and receipt["originalsSettled"] is True
         and receipt["parentHandlesClosed"] is True and receipt["nativeQualified"] is False
         and receipt["pythonPycacheHandlesClosed"] is True
         and receipt["pythonPycache"] == before["pythonPycache"] == pycache_original()
         and receipt["supplierContractSha256"] == BWRAP_SUPPLIER_SHA256
         and receipt["beforeSha256"] == before_pin["sha256"]
         and receipt["waits"] == bwrap_original_waits(), "bwrap-receipt-context-finality")
    need(str(BWRAP_TARGET) not in before["hostOriginals"]
          and _PINS == {**before["hostOriginals"], str(BWRAP_TARGET): receipt["installed"]}
          and bwrap_sources(names) == before["sourceOriginals"]
          and acquisition_capath(BWRAP_SUPPLY / "inputs/download") == before["emptyCapath"]
         and bwrap_input_originals(row, receipt["supplierOriginal"]) == receipt["inputOriginals"],
         "bwrap-receipt-originals-changed")
    parents = bwrap_parent_handles()
    try:
        current = bwrap_parent_snapshot(parents)
        bwrap_parent_transition(before["parentBefore"], current)
        bwrap_parent_transition(before["parentBefore"], receipt["parentAfter"])
    finally:
        bwrap_close_parents(parents)
    need(bwrap_stage_identity() == stage
         and read(BWRAP_SUPPLY / "before.json", 16 * MIB)[1] == before_pin
         and read(BWRAP_SUPPLY / "receipt.json", 16 * MIB)[1] == receipt_pin,
         "bwrap-receipt-changed-during-check")
    bwrap_supply_evidence(receipt_pin, receipt["installed"])


def cargo_mount_selection(catalogue):
    """Finite file mounts, never host /usr, /etc, a cache or a provider directory.

    The catalogue is source-bound. This guard cannot turn an arbitrary host row
    or non-root resolver into authority for an executable/configuration mount.
    Missing ABI dependencies fail in this closed view; there is no host fallback.
    """
    selection = catalogue.get("cargoAcquisition", {})
    need(selection.get("profile") == CARGO_ACQUISITION, "cargo-acquisition-profile")
    libraries, aliases = selection.get("hostLibraries"), selection.get("libraryAliases")
    need(type(libraries) is list and 0 < len(libraries) <= 96 and libraries == sorted(set(libraries))
         and all(type(path) is str and path.startswith(CARGO_LIBRARY_ROOT)
                 and re.fullmatch(r"[A-Za-z0-9_.+-]+\.so(?:\.[A-Za-z0-9_.+-]+)*",
                                  path.removeprefix(CARGO_LIBRARY_ROOT)) for path in libraries),
         "cargo-finite-library-paths")
    need({CARGO_LIBRARY_ROOT + name for name in ("ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6",
          "libnss_dns.so.2", "libnss_files.so.2", "libresolv.so.2")} <= set(libraries),
         "cargo-loader-resolver-files")
    host = {row["path"]: row for row in catalogue["hostFiles"]}
    data = [CA_FILE, *CARGO_DNS_TARGETS[:-1]]
    need(set(libraries + data + [str(BWRAP_TARGET)]) <= host.keys()
         and catalogue["caFile"] == CA_FILE, "cargo-mounted-host-input-missing")
    need(type(aliases) is list and len(aliases) <= 96, "cargo-library-alias-list")
    seen = set()
    for row in aliases:
        path, target = row["path"], row["target"]
        need(path.startswith(CARGO_LIBRARY_ROOT) and path not in seen | set(libraries)
             and re.fullmatch(r"[A-Za-z0-9_.+-]+\.so(?:\.[A-Za-z0-9_.+-]+)*",
                              path.removeprefix(CARGO_LIBRARY_ROOT))
             and type(target) is str and "/" not in target and CARGO_LIBRARY_ROOT + target in libraries,
             "cargo-library-alias-target")
        seen.add(path)
    need([row["path"] for row in aliases] == sorted(seen), "cargo-library-alias-order")
    resolver = selection.get("resolverData", {})
    need(resolver.get("role") == "cargo-acquisition-resolver-snapshot-only"
         and all(resolver.get(key) == value for key, value in CARGO_RESOLVER.items())
         and CARGO_RESOLVER["path"] not in host, "cargo-resolver-not-general-runtime-authority")
    cargo_resolver_parent_contract(resolver)
    gcc = [member for row in catalogue["nativePackages"] for member in row["members"]
           if member["member"] == CARGO_LIBGCC]
    need(len(gcc) == 1 and gcc[0]["target"] == "native/09"
         and CARGO_LIBRARY_ROOT + "libgcc_s.so.1" not in set(libraries) | seen, "cargo-private-libgcc-source")
    mounts = [(path, path) for path in libraries + data]
    mounts.append((str(TASK / "inputs" / gcc[0]["target"]), "/" + CARGO_LIBGCC))
    return {"files": mounts, "aliases": [*CARGO_ROOT_ALIASES, *((row["path"], row["target"]) for row in aliases)],
            "hostFiles": sorted(libraries + data + [str(BWRAP_TARGET)])}


def cargo_resolver_parent_contract(row):
    # The older body observation did not measure these parents. Keep this
    # separately accepted historical metadata distinct from fresh live custody.
    need(type(row.get("parentRequirements")) is list
         and canonical(row["parentRequirements"]) == canonical(CARGO_RESOLVER_PARENTS)
         and type(row.get("parentObservation")) is dict
         and canonical(row["parentObservation"]) == canonical(CARGO_RESOLVER_PARENT_OBSERVATION),
         "cargo-resolver-parent-observation-contract")


def cargo_resolver_data(catalogue):
    """One exact, non-executable DATA source; never relax read(root=True).

    The last parent is owned by the fixed resolver service, not by root. These
    exact parent metadata has separate accepted historical observation. It is
    NOT live-object authority: each invocation still checks its own originals.
    Only a protected root-owned snapshot is visible to Cargo.
    """
    global _ORIGINALS_SETTLED
    row = catalogue["cargoAcquisition"]["resolverData"]
    need(row.get("role") == "cargo-acquisition-resolver-snapshot-only"
         and all(row.get(key) == value for key, value in CARGO_RESOLVER.items()), "cargo-resolver-data-contract")
    cargo_resolver_parent_contract(row)
    held, parents, close_failed, body_failed = [], [], False, False
    target = Path(CARGO_RESOLVER["path"])
    try:
        for path in (Path("/"), Path("/run"), Path("/run/systemd"), target.parent):
            fd = os.open(str(path) if not held else path.name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=held[-1] if held else None)
            held.append(fd)
            info = os.fstat(fd)
            owner = 991 if path == target.parent else 0
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == owner
                 and stat.S_IMODE(info.st_mode) == 0o755
                 and directory_custody(info) == directory_custody(path.lstat()), "cargo-resolver-parent")
            parents.append({"path": str(path), "custody": directory_custody(info)})
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=held[-1])
        held.append(fd)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == CARGO_RESOLVER["uid"] and before.st_gid == CARGO_RESOLVER["gid"]
             and stat.S_IMODE(before.st_mode) == 0o644 and before.st_size == CARGO_RESOLVER["bytes"],
             "cargo-resolver-leaf")
        parts, size = [], 0
        while part := os.read(fd, CARGO_RESOLVER["bytes"] - size + 1):
            parts.append(part)
            size += len(part)
            need(size <= CARGO_RESOLVER["bytes"], "cargo-resolver-grew")
        raw = b"".join(parts)
        need(size == CARGO_RESOLVER["bytes"] and hashlib.sha256(raw).hexdigest() == CARGO_RESOLVER["sha256"]
             and identity(before) == identity(os.fstat(fd)) == identity(target.lstat()), "cargo-resolver-original")
        for parent, parent_fd in zip(parents, held):
            need(directory_custody(os.fstat(parent_fd)) == parent["custody"]
                 == directory_custody(Path(parent["path"]).lstat()), "cargo-resolver-parent-changed")
        return raw, {"file": {**CARGO_RESOLVER, "identity": identity(before)}, "parents": parents}
    except BaseException:
        body_failed = True
        raise
    finally:
        for fd in reversed(held):
            try:
                os.close(fd)
            except BaseException:
                close_failed = True
                _ORIGINALS_SETTLED = False
        if close_failed and not body_failed:
            need(False, "cargo-resolver-close-unknown")


def cargo_input_originals(catalogue, binding, selection):
    """Originals on both sides of the one existing metadata command."""
    host = {}
    for path in selection["hostFiles"]:
        _, pin = read(path, 128 * MIB)
        need(path in _PINS and pin == _PINS[path], "cargo-host-original-changed")
        host[path] = pin
    inputs = bounded_roster(TASK / "inputs", files=16384, total=2 << 30)
    expected = {}
    for row in (*catalogue["nativePackages"], *catalogue["rust"]):
        prefix = TASK / "inputs/rust" if row["format"] == "tar.xz" else TASK / "inputs"
        for member in row["members"]:
            path = str(prefix / path_name(member["target"]))
            need(path not in expected, "cargo-supplier-input-collision")
            expected[path] = {key: member[key] for key in ("bytes", "sha256", "mode")}
        if row.get("retainedTar") is not None:
            path = str(TASK / "inputs/native-tars" / path_name(row["retainedTar"]))
            need(path not in expected, "cargo-supplier-input-collision")
            expected[path] = {"bytes": row["decodedBytes"], "sha256": row["decodedSha256"], "mode": "0o600"}
    actual = {row["path"]: row for row in inputs["files"]}
    need(actual.keys() == expected.keys() and all(all(actual[path][key] == value for key, value in row.items())
         for path, row in expected.items()), "cargo-private-supplier-input-differs")
    directories = {str(TASK / "inputs")}
    for path in expected:
        directories.update(str(parent) for parent in Path(path).parents if parent.is_relative_to(TASK / "inputs"))
    need({row["path"] for row in inputs["directories"]} == directories
         and all(row["mode"] == "0o700" for row in inputs["directories"]), "cargo-private-input-directory-roster")
    source, names = {}, []
    for row in binding["sourceFiles"]:
        need(row["path"].startswith("/source/"), "cargo-source-binding-path")
        name = path_name(row["path"].removeprefix("/source/"))
        _, pin = read(TASK / "source" / name, 32 * MIB)
        need(pin["identity"] == row["snapshotIdentity"]
             and all(pin[key] == row[key] for key in ("bytes", "sha256", "mode")), "cargo-source-original-changed")
        source[name] = pin
        names.append(name)
    need(source_directories(TASK / "source", names) == binding["snapshotDirectories"], "cargo-source-directories-changed")
    return {"host": host, "inputs": inputs, "source": source, "capath": acquisition_capath(TASK / "download")}


def cargo_acquisition_argv(selection):
    # This namespace is acquisition-only and retains networking. The offline
    # native owner below is deliberately unchanged. The existing C/A/W still
    # owns/waits/captures this one command; no second ownership harness exists.
    args = [str(BWRAP_TARGET), "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
            "--die-with-parent", "--new-session", "--clearenv", "--cap-drop", "ALL"]
    for source, target in selection["files"]:
        args += ["--ro-bind", source, "/trust/ca.pem" if target == CA_FILE else target]
    for path, target in selection["aliases"]:
        args += ["--symlink", target, path]
    for name in ("source", "inputs/rust"):
        path = str(TASK / name)
        args += ["--ro-bind", path, path]
    args += ["--ro-bind", str(TASK / "download/empty-capath"), "/trust/empty",
             "--ro-bind", str(TASK / "temporary/resolv.conf"), "/etc/resolv.conf"]
    for name in ("cargo", "home", "rustup", "tmp"):
        path = str(TASK / "temporary" / name)
        args += ["--bind", path, path]
    args += ["--proc", "/proc", "--dev", "/dev", "--remount-ro", "/", "--remount-ro", "/dev", "--chdir", "/"]
    environment = {**ENV, "HOME": str(TASK / "temporary/home"), "TMPDIR": str(TASK / "temporary/tmp"),
                   "CARGO_HOME": str(TASK / "temporary/cargo"), "RUSTUP_HOME": str(TASK / "temporary/rustup"),
                   "RUSTC": str(TASK / "inputs/rust/bin/rustc"), "CARGO_HTTP_PROXY": "",
                   "CARGO_HTTP_SSL_CAINFO": "/trust/ca.pem", "CARGO_HTTP_SSL_VERIFY": "true",
                   "SSL_CERT_FILE": "/trust/ca.pem", "SSL_CERT_DIR": "/trust/empty", "CARGO_HTTP_TIMEOUT": "30",
                   "CARGO_NET_RETRY": "0", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse"}
    for key, value in environment.items():
        args += ["--setenv", key, value]
    return [*args, "--", str(TASK / "inputs/rust/bin/cargo"), "metadata", "--locked", "--no-default-features",
            "--filter-platform", TARGET, "--format-version", "1", "--manifest-path",
            str(TASK / "source/desktop/src-tauri/Cargo.toml")]


def cargo_prepare(catalogue, binding, deadline):
    selection = cargo_mount_selection(catalogue)
    home = TASK / "temporary/cargo"
    writable = {}
    for name in ("cargo", "home", "rustup", "tmp"):
        path = TASK / "temporary" / name
        path.mkdir(mode=0o700)
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == 0o700 and os.listdir(path) == [], "cargo-fresh-writable-root")
        writable[str(path)] = directory_custody(info)
    # Metadata is not a compile/build-script action, but Cargo may probe rustc.
    # Its exact supplied toolchain stays readonly and admitted, not presumed unused.
    source = TASK / "source"
    for ancestor in (source, *source.parents):
        for name in (".cargo/config", ".cargo/config.toml"):
            path = ancestor / name
            need(not path.exists() and not path.is_symlink(), "ambient-cargo-configuration")
    lock = tomllib.loads(read(source / "desktop/src-tauri/Cargo.lock", 2 * MIB)[0].decode("utf-8"))
    need(all(row.get("source") in (None, "registry+https://github.com/rust-lang/crates.io-index")
             for row in lock["package"]), "cargo-fixed-registry-source-only")
    resolver_raw, resolver = cargo_resolver_data(catalogue)
    resolver_snapshot = write(TASK / "temporary/resolv.conf", resolver_raw)
    originals = cargo_input_originals(catalogue, binding, selection)
    argv = cargo_acquisition_argv(selection)
    result = command("locked-headless-metadata", argv, maximum=420, deadline=deadline, output_limit=8 * MIB)
    # Never start a postcheck/decoder after an unknown original lifetime. The
    # original command raises first and leaves its absorbing unsettled latch.
    need(cargo_input_originals(catalogue, binding, selection) == originals
         and cargo_resolver_data(catalogue)[1] == resolver
         and read(TASK / "temporary/resolv.conf", 4096)[1] == resolver_snapshot
         and all(directory_custody(Path(path).lstat()) == original for path, original in writable.items()),
         "cargo-acquisition-originals-changed")
    need(result.returncode == 0, "locked-metadata-original-failed")
    metadata = decode(result.stdout)
    need(type(metadata) is dict and metadata.get("version") == 1, "locked-metadata-shape")
    # The archived102 suppliers remain independently bound to Cargo.lock. More
    # resolver metadata is not itself another compiled package/qualification.
    checksums = {row["name"] + "-" + row["version"]: row["checksum"] for row in lock["package"] if "checksum" in row}
    base = home / "registry"
    registry = "index.crates.io-1949cf8c6b5b557f"
    # Actual Cargo cache names have to match the accepted tool's fixed sparse
    # layout. No host Cargo cache is copied or modified.
    original = bounded_roster(base, files=16384, total=512 * MIB)
    archives = []
    for path in sorted((base / "cache" / registry).iterdir()):
        need(path.suffix == ".crate", "cargo-cache-member-kind")
        package = path.name[:-6]
        _, pin = read(path, 32 * MIB)
        need(package in checksums and pin["sha256"] == checksums[package], "cargo-archive-lock-checksum")
        archives.append({"path": str(path), "filename": path.name, "package": package,
                         **{key: pin[key] for key in ("bytes", "sha256", "mode")}})
    selected = {row["package"] + "-" + row["version"]: row for row in catalogue["cargoPackages"]}
    need(0 < len(archives) <= 211 and set(selected) <= {row["package"] for row in archives}, "cargo-selected-supplier-closure")
    for row in archives:
        if row["package"] in selected:
            expected = selected[row["package"]]
            need(row["sha256"] == expected["sha256"] and row["bytes"] == expected["bytes"], "retained-cargo-supplier-differs")
    index = base / "index" / registry
    config_raw, config_pin = read(index / "config.json", 4096)
    config = decode(config_raw)
    need(config.get("dl") == "https://static.crates.io/crates" and config.get("api") == "https://crates.io",
         "cargo-index-authority")
    indexes = []
    for path in sorted((index / ".cache").rglob("*")):
        if path.is_dir():
            continue
        _, pin = read(path, 16 * MIB)
        indexes.append({"path": str(path), "relative": path.relative_to(index / ".cache").as_posix(),
                        **{key: pin[key] for key in ("bytes", "sha256", "mode")}})
    need(95 <= len(indexes) <= 443, "cargo-index-roster-bound")
    sources = [{"path": str(path), "name": path.name} for path in sorted((base / "src" / registry).iterdir())]
    need({row["name"] for row in sources} == {row["package"] for row in archives}, "cargo-expanded-source-roster")
    # Ordinary Cargo's expansion is compared to its admitted archive as inert
    # DATA before any candidate build script can consume it.
    for row in archives:
        seen = set()
        expanded = base / "src" / registry / row["package"]
        with tarfile.open(row["path"], mode="r|gz") as archive:
            members, expanded_bytes = 0, 0
            for member in archive:
                members += 1
                expanded_bytes += member.size
                need(members <= 8192 and expanded_bytes <= 64 * MIB and member.size <= 32 * MIB,
                     "crate-expanded-bound")
                name = path_name(member.name)
                need(name.startswith(row["package"] + "/") and (member.isdir() or member.isreg()), "crate-root-member-kind")
                if member.isdir():
                    continue
                relative = name[len(row["package"]) + 1:]
                need(relative not in seen, "crate-member-duplicate")
                seen.add(relative)
                stream = archive.extractfile(member)
                need(stream is not None, "crate-member-stream")
                with stream:
                    raw = stream.read(member.size + 1)
                actual, _ = read(expanded / relative, 32 * MIB)
                need(raw == actual and len(raw) == member.size, "crate-expanded-correspondence")
        actual = {path.relative_to(expanded).as_posix() for path in expanded.rglob("*") if path.is_file()}
        need(actual == seen | {".cargo-ok"}, "crate-expanded-complete-roster")
    # No mutation after capture: the original metadata command and readers have
    # joined; all following compile inputs are readonly mounts.
    need(bounded_roster(base, files=16384, total=512 * MIB) == original, "cargo-originals-changed")
    return {"archives": archives, "indexes": indexes, "registrySources": sources,
            "inputRoster": originals["inputs"],
            "acquisitionSelection": {"profile": CARGO_ACQUISITION,
                "argvSha256": hashlib.sha256(canonical(argv)).hexdigest(),
                "mountSelectionSha256": hashlib.sha256(canonical(selection)).hexdigest(),
                "originalsSha256": hashlib.sha256(canonical(originals)).hexdigest(),
                "resolverOriginalSha256": hashlib.sha256(canonical(resolver)).hexdigest(),
                "resolverSnapshotSha256": resolver_snapshot["sha256"],
                "emptyCapathOriginalSha256": hashlib.sha256(canonical(originals["capath"])).hexdigest(),
                "originalMetadataWaitRole": "locked-headless-metadata", "prePostCorrespondence": True,
                "namespace": "explicit-file-view-with-acquisition-network-only", "nativeQualified": False},
            "indexConfig": {"path": str(index / "config.json"), **{key: config_pin[key] for key in ("bytes", "sha256", "mode")}},
            "checkedFiles": original["files"], "registryOriginals": original,
            "registryDirectories": original["directories"], "registryPackages": catalogue["registryPackages"],
            "sourceBindingSha256": hashlib.sha256(canonical(binding)).hexdigest()}


def remap_inputs(value):
    """Paths change at the readonly mount; original identities never do."""
    if isinstance(value, dict):
        return {key: remap_inputs(item) for key, item in value.items()}
    if isinstance(value, list):
        return [remap_inputs(item) for item in value]
    if isinstance(value, str):
        for source, target in ((TASK / "inputs", "/inputs"), (TASK / "temporary/cargo/registry", "/registry")):
            if value == str(source) or value.startswith(str(source) + "/"):
                return target + value[len(str(source)):]
    return value


def registry_originals(stage):
    need(stage in ("before-owner", "after-owner", "before-cleanup"), "fixed-registry-custody-stage")
    expected = decode(read(TASK / "controls/registry-roster.json", 16 * MIB)[0])
    need(bounded_roster(TASK / "temporary/cargo/registry", files=16384, total=512 * MIB) == expected,
         "private-registry-originals-" + stage)
    return expected


def acquire(context, catalogue):
    binding, binding_sha = binding_for(context)
    deadline = min(time.monotonic() + 900, binding["workflowDeadlineMonotonic"])
    native = TASK / "inputs/native"
    native.mkdir(mode=0o700)
    (TASK / "inputs/native-tars").mkdir(mode=0o700)
    rust = TASK / "inputs/rust"
    rust.mkdir(mode=0o700)
    for index, row in enumerate(catalogue["nativePackages"]):
        path = acquire_archive(row, "native-" + str(index), deadline)
        _SUPPLIERS[-1]["selectedMembers"] = selected_members(path, row, TASK / "inputs")
        if row.get("retainedTar") is not None:
            target = TASK / "inputs/native-tars" / path_name(row["retainedTar"])
            raw, _ = read(path, row["decodedBytes"])
            write(target, raw, 0o600)
    for row in catalogue["rust"]:
        path = acquire_archive(row, "rust-" + row["component"], deadline)
        _SUPPLIERS[-1]["selectedMembers"] = selected_members(path, row, rust)
    cargo = cargo_prepare(catalogue, binding, deadline)
    cargo_selection = cargo.pop("acquisitionSelection")
    registry = cargo.pop("registryOriginals")
    registry_pin = write(TASK / "controls/registry-roster.json", canonical(registry))
    input_roster = cargo.pop("inputRoster")  # Already checked before/after the same owned metadata command.
    # Map only private task roots to fixed namespace destinations. Host tools
    # stay separate; the inner native namespace never mounts the host /usr.
    inputs = remap_inputs(cargo)
    inputs["sourceDirectories"] = [{"path": "/source" + ("/" + row["relative"] if row["relative"] != "." else ""),
                                    **{key: row[key] for key in ("entries", "mode", "identity")}}
                                   for row in binding["snapshotDirectories"]]
    inputs["checkedFiles"] += [{"path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"], "mode": row["mode"],
                               "identity": row["snapshotIdentity"]}
                              for row in binding["sourceFiles"]]
    inputs["checkedFiles"] += remap_inputs([{key: row[key] for key in ("path", "bytes", "sha256", "mode", "identity")}
                                      for row in input_roster["files"]
                                      if not row["path"].startswith(str(TASK / "inputs/rust") + "/")])
    # Large fixed compiler/stdlib files have the complete original host/input
    # pre/post rosters and readonly mounts. Keep F's32MiB source/registry bound
    # rather than silently widening it for a large Rust LLVM library.
    inputs_pin = write(TASK / "controls/inputs.json", canonical(inputs))
    layout = decode(read(TASK / "source" / CONTROL / "runtime-layout.json", MIB)[0])
    runtime = [{key: row[key] for key in ("path", "bytes", "sha256", "mode")} for row in layout["installedFileMounts"]]
    runtime += [{"path": row["sourceTar"], "bytes": row["tarBytes"], "sha256": row["tarSha256"], "mode": "0o600"}
                for row in layout["stagedPackageMembers"]]
    for name in ("owner.py", "native-entry.sh", "compile-only.sh", "prepare.py", "check-compile.py"):
        _, pin = read(TASK / "source" / CONTROL / name, MIB)
        runtime.append({"path": "/" + name, **{key: pin[key] for key in ("bytes", "sha256", "mode")}})
    for name in ("app-sources.sha256", "inputs.json", "source-binding.json"):
        _, pin = read(TASK / "controls" / name, 16 * MIB)
        runtime.append({"path": "/" + name, **{key: pin[key] for key in ("bytes", "sha256", "mode")}})
    runtime_pin = write(TASK / "controls/runtime-inputs.json", canonical(runtime))
    input_pin = write(TASK / "controls/input-roster.json", canonical(input_roster))
    _EVIDENCE["acquisition"] = {"suppliers": list(_SUPPLIERS),
        "cargoSelection": cargo_selection,
        "registryFiles": len(registry["files"]), "registryDirectories": len(registry["directories"]),
        "registryBytes": registry["bytes"], "compiledRegistryPackages": len(catalogue["registryPackages"]),
        "compiledRegistryPackagesSha256": hashlib.sha256(canonical(catalogue["registryPackages"])).hexdigest(),
        "controlInputs": [{"role": role, **{key: pin[key] for key in ("bytes", "sha256")}}
                          for role, pin in (("registry-roster.json", registry_pin), ("inputs.json", inputs_pin),
                                            ("runtime-inputs.json", runtime_pin), ("input-roster.json", input_pin))]}
    python_alias_finish()
    pycache_finish()
    write(TASK / "controls/acquired.json", canonical({"schema": PROFILE, "sourceSha": context["sourceSha"],
          "sourceBindingSha256": binding_sha, "originalsSettled": _ORIGINALS_SETTLED, "waits": _WAITS,
          "networkPreparationComplete": True, "evidence": _EVIDENCE["acquisition"]}))
    write(PUBLIC / "acquire.json", canonical({**context, "phase": "acquire", "passed": True,
          "lockedCompiledRegistryPackages": len(catalogue["registryPackages"]), "nativeBodies": 34,
          "originalsSettled": _ORIGINALS_SETTLED, "nativeQualified": False, "evidence": public_evidence()}), 0o444)


def acquisition_for(context, binding_sha):
    value = decode(read(TASK / "controls/acquired.json", MIB)[0])
    need(value["schema"] == PROFILE and value["sourceSha"] == context["sourceSha"]
         and value["sourceBindingSha256"] == binding_sha and value["networkPreparationComplete"] is True
         and value["originalsSettled"] is True, "original-acquisition-not-settled")
    controls = value["evidence"]["controlInputs"]
    need([row["role"] for row in controls] == ["registry-roster.json", "inputs.json", "runtime-inputs.json", "input-roster.json"],
         "original-acquisition-control-roles")
    for row in controls:
        _, pin = read(TASK / "controls" / row["role"], 16 * MIB)
        need(pin["mode"] == "0o400" and all(pin[key] == row[key] for key in ("bytes", "sha256")),
             "original-acquisition-control-changed")
    _EVIDENCE["acquisition"] = value["evidence"]
    return value


def owner_argv():
    args = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "690s", "/usr/bin/bwrap",
            "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
            "--die-with-parent", "--new-session", "--clearenv", "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64", "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
            "--symlink", "/usr/bin/gcc", "/etc/alternatives/cc",
            "--ro-bind", str(TASK / "source"), "/source", "--ro-bind", str(TASK / "inputs"), "/inputs",
            "--ro-bind", str(TASK / "temporary/cargo/registry"), "/registry", "--proc", "/proc", "--dev", "/dev",
            "--size", "2147483648", "--tmpfs", "/tmp", "--size", "67108864", "--tmpfs", "/native-fixture-backing",
            "--dir", "/run", "--ro-bind", str(PYTHON_PYCACHE), str(PYTHON_PYCACHE)]
    for name in ("owner.py", "native-entry.sh", "compile-only.sh", "prepare.py", "check-compile.py", "runtime-layout.json"):
        args += ["--ro-bind", str(TASK / "source" / CONTROL / name), "/" + name]
    for name in ("app-sources.sha256", "inputs.json", "source-binding.json", "runtime-inputs.json", "account-reservation.json"):
        args += ["--ro-bind", str(TASK / "controls" / name), "/" + name]
    args += ["--remount-ro", "/", "--remount-ro", "/dev", "--chdir", "/tmp"]
    for key, value in {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}.items():
        args += ["--setenv", key, value]
    args += ["--cap-drop", "ALL"]
    for capability in ("CHOWN", "DAC_READ_SEARCH", "SETGID", "SETUID", "SETPCAP", "SYS_ADMIN"):
        args += ["--cap-add", "CAP_" + capability]
    args += ["--", "/usr/bin/setpriv", "--clear-groups",
             "--bounding-set=-all,+chown,+dac_read_search,+setgid,+setuid,+setpcap,+sys_admin",
             "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--",
             "/usr/bin/python3.12", "-I", "-S", "-B", "-X", "pycache_prefix=/run/mrk-gnome-python-empty-pycache-v1", "/owner.py"]
    shell = 'set -euo pipefail; umask 077; ulimit -v 4194304; ulimit -t 300; ulimit -n 256; ulimit -c 0; ulimit -f 1048576; exec "$@"'
    return ["/usr/bin/bash", "--noprofile", "--norc", "-c", shell, "mrk-fixed-native-owner", *args]


def framed_owner(raw, binding, binding_sha):
    need(type(raw) is bytes and 0 < len(raw) < 8 * MIB and raw.endswith(b"\n"), "owner-original-frame-bound")
    lines = raw.splitlines()
    rows = [decode(line[len(b"GNOME_NATIVE_RESULT="):]) for line in lines if line.startswith(b"GNOME_NATIVE_RESULT=")]
    need(len(rows) == 1 and lines[-1].startswith(b"GNOME_NATIVE_RESULT="), "one-terminal-owner-original")
    report = rows[0]
    need(report.get("schema") == "gnome-native-original-result-1"
         and report.get("sourceSha") == binding["sourceSha"] and report.get("sourceTree") == binding["fullTree"]
         and report.get("sourceBindingSha256") == binding_sha and report.get("uid") == report.get("gid") == 61000,
         "owner-original-source-identity")
    need(report.get("completeSourceFiles") == binding["completeSourceFiles"] and report.get("productFiles") == 964
         and report.get("productTree") == PRODUCT_TREE and report.get("hostArtifactsExported") is False,
         "owner-full-carrier-binding")
    return report


def compiler_wait(raw):
    prefix = b"VAULT_FINALITY_COMPILE_WAITS=libtest:"
    rows = [decode(line[len(prefix):]) for line in raw.splitlines() if line.startswith(prefix)]
    need(len(rows) == 1 and type(rows[0]) is dict
         and set(rows[0]) == {"originalCargoEnvelopeExit", "logReaderExit"}
         and all(type(value) is int and -128 <= value <= 255 for value in rows[0].values()), "compiler-original-wait-frame")
    return rows[0]


def parse_owner(raw, binding, binding_sha):
    report = framed_owner(raw, binding, binding_sha)
    need(all(report.get(key) is True for key in OWNER_FINALITY) and report.get("errors") == [], "owner-original-finality")
    artifact = report.get("artifact", {})
    need(artifact.get("sameInode") is True and artifact.get("copiedOrExported") is False
         and type(artifact.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
         and type(artifact.get("bytes")) is int and 0 < artifact["bytes"] < 128 * MIB
         and all(type(artifact.get(key)) is list and len(artifact[key]) == 9
                 and all(type(value) is int for value in artifact[key]) for key in ("before", "afterModeTransition"))
         and type(report.get("stagedInputsPreNativeChecked")) is int and report["stagedInputsPreNativeChecked"] >= 8,
         "owner-original-artifact-staging-custody")
    need(report.get("runtimeInputsPrechecked") == report.get("runtimeInputsPostchecked") == report.get("runtimeInputsExpected")
         and type(report.get("runtimeInputsExpected")) is int and report["runtimeInputsExpected"] >= 34,
         "owner-runtime-post-accounting")
    evidence = report.get("nativeEvidence", {})
    need(evidence.get("cases") == ["existing", "missing", "duplicate", "stop-after-secret", "deadline-after-secret", "owner-loss", "fresh-session-absent"]
         and type(evidence.get("actualLibtestPassed")) is int and evidence["actualLibtestPassed"] == 1 and evidence.get("persistent") is False
         and evidence.get("installedProvider") is False and evidence.get("gui") is False, "owner-seven-cases")
    need([row.get("role") for row in report.get("waits", [])] == list(OWNER_ROLES),
         "owner-original-role-order")
    for row in report["waits"]:
        need(type(row.get("originalEnvelopeExit")) is int and type(row.get("originalReaderExit")) is int
             and row["originalEnvelopeExit"] == row["originalReaderExit"] == 0
             and row.get("readerTimedOut") is False and row.get("cleanupErrors") == []
             and type(row.get("logBytes")) is int and 0 <= row["logBytes"] < 8 * MIB
             and type(row.get("logSha256")) is str and re.fullmatch(r"[0-9a-f]{64}", row["logSha256"])
             and "operationError" not in row and "logError" not in row, "owner-original-returned-readers")
    need(compiler_wait(raw) == {"originalCargoEnvelopeExit": 0, "logReaderExit": 0}, "compiler-original-waits-failed")
    return report


def public_owner(raw, binding, binding_sha):
    """Project only bounded result facts; a failed/incomplete frame is not proof."""
    try:
        report = framed_owner(raw, binding, binding_sha)
    except Exception:
        report = None
    def boolean(value):
        return value if type(value) is bool else None
    def integer(value, maximum=8 * MIB):
        return value if type(value) is int and -128 <= value <= maximum else None
    def digest(value):
        return value if type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) else None
    result = {"sourceBoundResultObserved": report is not None,
        "originalOutputSha256": hashlib.sha256(raw).hexdigest() if type(raw) is bytes and len(raw) < 8 * MIB else None,
        "finality": {key: boolean(report.get(key)) if report is not None else None for key in OWNER_FINALITY},
        "waits": [], "compilerWait": None, "artifact": None, "nativeEvidence": None,
        "checks": {key: integer(report.get(key)) if report is not None else None for key in
                   ("stagedInputsPreNativeChecked", "runtimeInputsPrechecked", "runtimeInputsPostchecked", "runtimeInputsExpected")},
        "errorCount": len(report["errors"]) if report is not None and type(report.get("errors")) is list else None}
    rows = report.get("waits") if report is not None else None
    if not (type(rows) is list and len(rows) <= len(OWNER_ROLES)
            and all(type(row) is dict and row.get("role") in OWNER_ROLES for row in rows)
            and len({row["role"] for row in rows}) == len(rows)):
        rows = None
    for role in OWNER_ROLES:
        row = next((item for item in rows if item["role"] == role), None) if rows is not None else None
        result["waits"].append({"role": role, "invocationRecorded": row is not None if rows is not None else None,
            "originalEnvelopeExit": integer(row.get("originalEnvelopeExit"), 255) if row else None,
            "originalReaderExit": integer(row.get("originalReaderExit"), 255) if row else None,
            "readerTimedOut": boolean(row.get("readerTimedOut")) if row else None,
            "cleanupErrorCount": len(row["cleanupErrors"]) if row and type(row.get("cleanupErrors")) is list else None,
            "operationErrorRecorded": "operationError" in row if row else None,
            "logErrorRecorded": "logError" in row if row else None,
            "logBytes": integer(row.get("logBytes")) if row else None,
            "logSha256": digest(row.get("logSha256")) if row else None})
    if report is None:
        return result
    try:
        result["compilerWait"] = compiler_wait(raw)
    except Exception:
        pass  # No frame, duplicate or malformed frame stays unknown, not exit0.
    artifact = report.get("artifact")
    if type(artifact) is dict:
        result["artifact"] = {"sha256": digest(artifact.get("sha256")), "bytes": integer(artifact.get("bytes"), 128 * MIB),
            "sameInode": boolean(artifact.get("sameInode")), "copiedOrExported": boolean(artifact.get("copiedOrExported"))}
        for key in ("before", "afterModeTransition"):
            value = artifact.get(key)
            result["artifact"][key + "IdentitySha256"] = (hashlib.sha256(canonical(value)).hexdigest()
                if type(value) is list and len(value) == 9 and all(type(item) is int for item in value) else None)
    native = report.get("nativeEvidence")
    cases = ["existing", "missing", "duplicate", "stop-after-secret", "deadline-after-secret", "owner-loss", "fresh-session-absent"]
    if type(native) is dict:
        result["nativeEvidence"] = {"cases": native.get("cases") if native.get("cases") == cases else None,
            "actualLibtestPassed": integer(native.get("actualLibtestPassed"), 1),
            **{key: boolean(native.get(key)) for key in ("persistent", "installedProvider", "gui")}}
    return result


def owner_diagnostic(raw):
    """Finite failed-entry labels only; not admission or substituted output."""
    result = {"entryRefusal": None, "outerNetworkClass": None}
    if type(raw) is not bytes or len(raw) >= 8 * MIB:
        return result
    for line in raw.splitlines():
        if re.fullmatch(rb"MRK_GNOME_NATIVE_ENTRY refused=true site=[a-z-]{1,48}", line):
            value = line.rsplit(b"=", 1)[1].decode("ascii")
            # Do not publish arbitrary new producer strings.
            if value in {"network-interface", "network-roster", "shell-uid", "status-uid-values", "status-gid-values",
                         "status-groups", "fd-inheritance", "mapping-row", "fixture-cd", "fixture-pwd"}:
                result["entryRefusal"] = value
        if line.startswith(b"GNOME_NATIVE_NETWORK_SNAPSHOT="):
            try:
                value = decode(line.split(b"=", 1)[1])
            except Exception:
                continue
            if type(value) is dict and set(value) == {"outerClass"} and value["outerClass"] in {
                    "loopback-only", "non-loopback", "unreadable", "invalid"}:
                result["outerNetworkClass"] = value["outerClass"]
    return result


def refusal_code(error):
    code = str(error) if isinstance(error, Refused) or isinstance(error, _HOST_REFUSAL) else type(error).__name__
    return code if re.fullmatch(r"[A-Za-z0-9_-]{1,96}", code) else "controller-refused"


def collect_checks(checks):
    """Run independent postconditions; a later success never clears a failure."""
    values, errors = {}, []
    for role, check in checks:
        try:
            values[role] = check()
        except Exception as error:
            errors.append({"role": role, "refusal": refusal_code(error)})
    return values, errors


def run_native(context, catalogue):
    binding, binding_sha = binding_for(context)
    acquisition_for(context, binding_sha)
    module, host = host_module(catalogue)
    saved = load_host(TASK / "controls/host-after-creation.json")
    before = host.capture("before-owner", min(time.monotonic() + 30, binding["workflowDeadlineMonotonic"]),
                          created=True, baseline=saved)
    save_host(TASK / "controls/host-before-owner.json", before)
    states = [load_host(TASK / "controls/host-before-creation.json"), saved, before]
    reservation = {"schema": "gnome-session-host-reservation-1", "sourceBindingSha256": binding_sha,
                   **module.public_projection(states, account_created=True)}
    reservation_pin = write(TASK / "controls/account-reservation.json", canonical(reservation))
    _EVIDENCE["reservationSha256"] = reservation_pin["sha256"]
    # Authenticate all private supplied inputs immediately before the original
    # 690s namespace/owner. No second compile/test invocation exists.
    expected = decode(read(TASK / "controls/input-roster.json", 16 * MIB)[0])
    need(bounded_roster(TASK / "inputs", files=16384, total=2 << 30) == expected, "private-inputs-before-owner")
    registry_originals("before-owner")
    result, errors = None, []
    try:
        result = command("native-owner", owner_argv(), maximum=710, deadline=binding["workflowDeadlineMonotonic"], output_limit=8 * MIB)
    except Exception as error:
        errors.append({"role": "native-owner-original", "refusal": refusal_code(error)})
    # Original failure is latched before any parser/postcondition can succeed.
    if result is not None and (result.returncode != 0 or result.stderr):
        errors.append({"role": "native-owner-original", "refusal": "native-owner-original-failed"})

    def host_post():
        # Unknown original lifetime is not an after-settlement snapshot or
        # authority to start another helper. Pure DATA postchecks still run.
        need(_ORIGINALS_SETTLED, "host-post-originals-unsettled")
        after = host.capture("after-settlement", min(time.monotonic() + 30, binding["workflowDeadlineMonotonic"]),
                             created=True, baseline=saved)
        save_host(TASK / "controls/host-after-settlement.json", after)
        states.append(after)
        return True

    def inputs_post():
        need(bounded_roster(TASK / "inputs", files=16384, total=2 << 30) == expected, "private-inputs-after-owner")
        return True

    checks = []
    if result is not None:
        checks += [("owner-stdout", lambda: write(TASK / "logs/native-owner.stdout", result.stdout)),
                   ("owner-stderr", lambda: write(TASK / "logs/native-owner.stderr", result.stderr)),
                   ("owner-report", lambda: parse_owner(result.stdout, binding, binding_sha))]
    checks += [("host-after-settlement", host_post), ("private-inputs", inputs_post),
               ("registry-originals", lambda: registry_originals("after-owner")),
               ("source-custody", lambda: binding_for(context)),
               ("host-tool-custody", lambda: authenticate_host(catalogue, after=True))]
    values, post_errors = collect_checks(checks)
    errors.extend(post_errors)
    _EVIDENCE["owner"] = public_owner(result.stdout if result is not None else None, binding, binding_sha)
    if not _ORIGINALS_SETTLED:
        errors.append({"role": "original-finality", "refusal": "originals-unsettled"})
    if errors:
        write(TASK / "controls/native-failure.json", canonical({"schema": PROFILE, **context, "passed": False,
              "errors": errors, "originalsSettled": _ORIGINALS_SETTLED, "waits": _WAITS,
              "checked": list(values), "cleanupVerified": False}))
        write(PUBLIC / "owner-diagnostic.json", canonical({**context, "passed": False,
              "originalOwnerExit": result.returncode if result is not None else None,
              "originalsSettled": _ORIGINALS_SETTLED, "errors": errors, "checked": list(values),
              "diagnostic": owner_diagnostic(result.stdout if result is not None else None),
              "nativeQualified": False, "cleanupVerified": False, "evidence": public_evidence()}), 0o444)
        raise Refused("native-owner-or-postconditions-failed")
    need(result is not None and "owner-report" in values, "original-native-report-missing")
    report = values["owner-report"]
    python_alias_finish()
    pycache_finish()
    write(TASK / "controls/native-result.json", canonical({"schema": PROFILE, **context, "passed": True,
          "owner": report, "host": module.public_projection(states, account_created=True),
          "reservationSha256": reservation_pin["sha256"],
          "originalsSettled": _ORIGINALS_SETTLED, "waits": _WAITS, "outerNamespaceRetired": True}))
    # Preserve actual owner DATA even if the later workflow writer/finalizer
    # gate fails. This receipt explicitly does NOT qualify the hosted result.
    write(PUBLIC / "native.json", canonical({**context, "phase": "run", "ownerPassed": True,
          "host": module.public_projection(states, account_created=True), "evidence": public_evidence(),
          "originalWorkflowStepSuccess": None, "finalizerAccepted": False, "nativeQualified": False}), 0o444)


def original_outer(context, binding):
    s = OUTER.lstat()
    original = binding["workflowOuterRootIdentity"]
    need(identity(s)[:6] == original[:6] and stat.S_IMODE(s.st_mode) == 0o700, "original-output-root-changed")
    raw, pin = read(OUTER / "waits.json", 8192, root=False)
    need(pin["identity"][4] == original[4] and pin["mode"] == "0o600", "original-output-owner-mode")
    value = decode(raw)
    need(value == {"schema": PROFILE, "sourceSha": context["sourceSha"], "runId": context["runId"],
                  "attempt": context["attempt"], "originalWait": True, "exitCode": 0,
                  "outputWritersClosed": True, "statusWriterCloseGate": "original-step-success-required"},
         "original-step-output-finality")
    for name in ("stdout", "stderr"):
        _, info = read(OUTER / name, MIB, root=False)
        need(info["identity"][4] == original[4] and info["mode"] == "0o600", "original-step-stream-state")
    return value


def remove_settled(root, roster):
    # Only a just-reauthenticated finite task-owned roster; no recursive rm,
    # process-name stopping, shared-cache cleanup, or removal of source/evidence.
    need(Path(root).is_relative_to(TASK) and bounded_roster(root, files=32768, total=3 << 30) == roster,
         "settled-cleanup-correspondence")
    for row in roster["files"]:
        _, pin = read(row["path"], 768 * MIB)
        need(pin == {key: row[key] for key in ("identity", "bytes", "sha256", "mode")}, "settled-cleanup-file-changed")
        Path(row["path"]).unlink()
    for row in sorted(roster["directories"], key=lambda item: len(Path(item["path"]).parts), reverse=True):
        actual = identity(Path(row["path"]).lstat())
        need(all(actual[key] == row["identity"][key] for key in (0, 1, 2, 4, 5)), "settled-cleanup-directory-changed")
        Path(row["path"]).rmdir()


def settle(context, catalogue):
    binding, binding_sha = binding_for(context)
    acquisition_for(context, binding_sha)
    need(os.environ.get("MRK_ORIGINAL_OUTCOME") == "success", "actual-original-workflow-step-not-successful")
    _EVIDENCE["originalWorkflowWait"] = original_outer(context, binding)
    value = decode(read(TASK / "controls/native-result.json", MIB)[0])
    need(value["passed"] is True and value["originalsSettled"] is True
         and value["outerNamespaceRetired"] is True and value["host"]["phases"] ==
         ["before-creation", "after-creation", "before-owner", "after-settlement"], "original-native-settlement")
    _, reservation_pin = read(TASK / "controls/account-reservation.json", MIB)
    need(reservation_pin["mode"] == "0o400" and reservation_pin["sha256"] == value["reservationSha256"],
         "original-reservation-receipt-correspondence")
    _EVIDENCE["reservationSha256"] = reservation_pin["sha256"]
    raw, _ = read(TASK / "logs/native-owner.stdout", 8 * MIB)
    need(value["owner"] == parse_owner(raw, binding, binding_sha), "original-owner-receipt-correspondence")
    _EVIDENCE["owner"] = public_owner(raw, binding, binding_sha)
    _EVIDENCE["nativeControllerOriginals"] = public_originals(value["waits"])
    authenticate_host(catalogue, after=True)
    acquisition_capath(TASK / "download")
    registry = registry_originals("before-cleanup")
    # Delete this subtree against its acquisition originals, not a newly
    # adopted cleanup inventory. The parent temporary roster is read afterwards.
    remove_settled(TASK / "temporary/cargo/registry", registry)
    removed = registry["bytes"]
    for name in ("download", "temporary", "inputs"):
        path = TASK / name
        roster = (decode(read(TASK / "controls/input-roster.json", 16 * MIB)[0]) if name == "inputs"
                  else bounded_roster(path, files=32768, total=3 << 30))
        removed += roster["bytes"]
        remove_settled(path, roster)
    # Even this still-live interpreter needs the protected prefix. It is
    # deliberately outside TASK cleanup and is retired only with the whole VM.
    python_alias_finish()
    pycache_finish()
    write(PUBLIC / "result.json", canonical({**context, "fullTree": binding["fullTree"], "phase": "settle",
          "passed": True, "originalStepSuccess": True, "originalOutputWritersClosed": True,
          "originalsSettled": True, "entrySmokePassed": True, "freshCompileCount": 1, "nativeCasesPassed": 7,
          "host": value["host"], "disposedTaskInputBytes": removed, "nativeArtifactExported": False,
          "sessionTransportQualified": True, "persistentQualified": False, "installedProviderQualified": False,
          "guiQualified": False, "desktopReady": False, "evidence": public_evidence()}), 0o444)


def main():
    global _CATALOGUE
    phase = None
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in ("supply-bwrap", "prepare", "acquire", "run", "settle")
             and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
             and type(sys.pycache_prefix) is str and sys.pycache_prefix == str(PYTHON_PYCACHE),
             "fixed-isolated-controller-entry")
        phase = sys.argv[1]
        need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0) and os.getgroups() == []
             and os.uname().machine == "x86_64", "authenticated-cleared-groups-root-entry")
        # This fixed sudo/PAM/interpreter entry is provider bootstrap, not a
        # retroactively byte-admitted execution. Its failure has no fallback.
        _EVIDENCE["bootstrap"] = {**BOOTSTRAP_TRUST, "clearedGroupsRootEntryObserved": True}
        context = workflow_context(dict(os.environ))
        _EVIDENCE["context"] = context
        catalogue = catalogue_ready(decode(read(SOURCE / CONTROL / "runtime-suppliers.json", 16 * MIB, root=False)[0]))
        native_layout(catalogue, decode(read(SOURCE / CONTROL / "runtime-layout.json", MIB, root=False)[0]))
        _CATALOGUE = catalogue
        pycache_for_phase(context, phase)
        names = source_product(catalogue)
        if phase == "supply-bwrap":
            supply_bwrap(context, catalogue, names)
        else:
            # The pre-state is never accepted by an ordinary native phase.
            authenticate_host(catalogue)
            bwrap_supply_for(context, catalogue, names)
            owner_modules(SOURCE, catalogue)
            {"prepare": lambda: prepare(context, catalogue, names), "acquire": lambda: acquire(context, catalogue),
             "run": lambda: run_native(context, catalogue), "settle": lambda: settle(context, catalogue)}[phase]()
        need(_PYCACHE is not None and _PYCACHE["closed"]
             and _EVIDENCE["pythonPycache"]["phaseCustodyPostchecked"]
             and _EVIDENCE["pythonPycache"]["phaseHandlesClosed"], "pycache-phase-not-closed")
        need(_PYTHON_ALIASES is not None and _PYTHON_ALIASES["closed"]
             and _EVIDENCE["pythonAliasCustody"]["phaseCustodyPostchecked"]
             and _EVIDENCE["pythonAliasCustody"]["phaseHandlesClosed"], "python-alias-phase-not-closed")
        return 0
    except BaseException as error:
        python_alias_finish(failed=True)
        pycache_finish(failed=True)
        code = refusal_code(error)
        # There are no raw paths, account tables, stdout, tokens, or provider
        # diagnostic excerpts in the only public failure output.
        print("GNOME_HOSTED_REFUSAL=" + code, flush=True)
        if phase and PUBLIC.is_dir() and PUBLIC.lstat().st_uid == 0:
            destination = PUBLIC / (phase + "-refusal.json")
            try:
                write(destination, canonical({"schema": PROFILE, "phase": phase, "passed": False,
                      "refusal": code, "originalsSettled": _ORIGINALS_SETTLED,
                      "cleanupVerified": False, "disposition": "retained-for-disposable-vm-retirement",
                      "evidence": public_evidence()}), 0o444)
            except Exception:
                print("GNOME_HOSTED_FAILURE_EVIDENCE=unavailable", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
