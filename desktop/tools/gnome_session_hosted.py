"""Fixed hosted carrier for the seven-case foreground GNOME SESSION fixture.

No general command runner, installer, release operation, or local fallback.
The catalogue deliberately refuses pre-use while supplier facts are incomplete.
All execution requires separate SOURCE/COMMAND admission; a preparatory receipt
is never native qualification.  Private source/runtime/account DATA stays local.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
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
    "/usr/bin/x86_64-linux-gnu-readelf", "/usr/bin/git", "/usr/bin/sudo",
    "/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/nologin", "/usr/bin/busctl",
    "/usr/lib/systemd/systemd", "/usr/bin/curl", "/usr/bin/xz", "/usr/bin/dpkg-deb",
    "/usr/bin/x86_64-linux-gnu-gcc-13", "/usr/bin/x86_64-linux-gnu-as", "/usr/bin/x86_64-linux-gnu-ar",
    "/usr/bin/x86_64-linux-gnu-ld.bfd", "/usr/bin/mkdir", "/etc/ld.so.cache",
    "/etc/ssl/certs/ca-certificates.crt"}
BOOTSTRAP_TRUST = {'profile': 'github-hosted-disposable-source-bound-bootstrap-v2', 'trusted': ['runner-and-os', 'pinned-checkout-and-control-pin-step', 'env-sudo-pam-setpriv-env-provider-isolated-python-for-bounded-DATA-only', 'fixed-env-sudo-setpriv-bash-stat-mkdir-empty-pycache-before-first-python', 'pinned-download-artifact-v8-exact-V-artifact-admission', 'source-authenticated-unchanged-unpack-and-complete-Python-only-projection', 'fixed-timeout-mount-bind-remount-ro-before-first-private-python'], 'retroactiveAuthentication': False, 'subsequentExactGuardsRequired': True}
# V is retained DATA evidence, never a guarantee of the next hosted image.
SUPPORTED_IMAGE_VERSION = "20260920.314.1"
CONTROLLER_RUNTIME_SCHEMA = "gnome-session-controller-runtime-2"
CONTROLLER_ORIGINALS_SCHEMA = "gnome-session-controller-runtime-originals-2"
CONTROLLER_RUNTIME_SHA256 = "4a413ee3d374b2b8f4609e817f87a0c35f018af3a6e3b945a23655e38e2b2071"
PYTHON_ROOT = Path("/run/mrk-gnome-controller-runtime-v2")
PYTHON_STAGE = Path("/run/mrk-gnome-controller-stage-v2")
PYTHON_SUPPLIER = Path("/var/tmp/mrk-gnome-controller-supplier-v2")
PYTHON_ORIGINALS = PYTHON_STAGE / "originals.json"
PYTHON_EXECUTABLE = str(PYTHON_ROOT / "python/bin/python3")
PYTHON_PYCACHE = Path("/run/mrk-gnome-python-empty-pycache-v1")
PYTHON_STDLIB = str(PYTHON_ROOT / "python/lib/python3.14")
PYTHON_SEARCH = (str(PYTHON_ROOT / "python/lib/python314.zip"), PYTHON_STDLIB, PYTHON_STDLIB + "/lib-dynload")
PYTHON_REQUIRED_FILES = {PYTHON_EXECUTABLE, PYTHON_SEARCH[0], PYTHON_STDLIB + "/ctypes/__init__.py",
    PYTHON_STDLIB + "/lib-dynload/README.mrk", str(PYTHON_ROOT / "python/lib/libcrypto.so.3"),
    str(PYTHON_ROOT / "python/lib/libssl.so.3")}
PYTHON_BUILTINS = ('_abc', '_ast', '_bisect', '_blake2', '_codecs', '_collections', '_contextvars', '_ctypes', '_datetime', '_functools', '_heapq', '_hmac', '_imp', '_io', '_json', '_locale', '_md5', '_opcode', '_operator', '_posixsubprocess', '_random', '_sha1', '_sha2', '_sha3', '_signal', '_socket', '_sre', '_ssl', '_stat', '_string', '_struct', '_suggestions', '_symtable', '_sysconfig', '_thread', '_tokenize', '_tracemalloc', '_types', '_typing', '_warnings', '_weakref', 'atexit', 'binascii', 'builtins', 'errno', 'faulthandler', 'fcntl', 'gc', 'itertools', 'marshal', 'math', 'posix', 'pwd', 'pyexpat', 'resource', 'select', 'sys', 'time', 'unicodedata', 'zlib')

CONTROLLER_CHECK_SCHEMA = "gnome-controller-runtime-check-1"
CONTROLLER_CHECK_ROOT = Path("/var/tmp/mrk-gnome-controller-check-v1")
CONTROLLER_CHECK_SOURCE = CONTROLLER_CHECK_ROOT / "source"
CONTROLLER_CHECK_TEST = "CarrierContracts.test_real_command_spec_keeps_only_the_fixed_cache_policy_on_every_reexec"
CONTROLLER_CHECK_LIMIT = 131072
# No accepted loader/config/provider selection capsule exists in current S.
# A later SOURCE admission must bind its literal digest AND its finite DATA
# below. Neither an environment switch nor unresolved=[] can supply that fact.
CONTROLLER_CHECK_HOST_SHA256 = None

# Disposable measurement authority is separate from production qualification.
# These receipts can never enter controller_check_ready or a native phase.
CONTROLLER_CHARACTERIZATION_REF = "refs/heads/verify/desktop-gnome-controller-characterization"
CONTROLLER_CHARACTERIZATION_SCHEMA = "gnome-controller-host-characterization-1"
CONTROLLER_CHARACTERIZATION_ORIGINALS = "gnome-controller-characterization-originals-1"
CONTROLLER_CHARACTERIZATION_PHASES = ("stage-controller-characterization",
    "characterize-controller-host", "post-controller-characterization")
CONTROLLER_CHARACTERIZATION_AUTHORITY = "source-reviewed-disposable-hosted-fixed-body-measurement-only"
CONTROLLER_CHARACTERIZATION_HOSTS = tuple("/usr/lib/x86_64-linux-gnu/" + name for name in (
    "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6", "libgcc_s.so.1", "libdl.so.2", "libpthread.so.0"))
CONTROLLER_CHARACTERIZATION_REQUIRED = frozenset(CONTROLLER_CHARACTERIZATION_HOSTS[:2])
CONTROLLER_CHARACTERIZATION_CONFIG = ("/etc/ld.so.cache", "/etc/ssl/openssl.cnf")
CONTROLLER_CHARACTERIZATION_DIRS = ("/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu/ossl-modules")
_CONTROLLER_CHARACTERIZATION_ACTIVE = False
_CONTROLLER_CHARACTERIZATION_INPUTS = None
_CONTROLLER_CHARACTERIZATION_STAGE = None
_CONTROLLER_CHARACTERIZATION_READ_BYTES = None

CONTROLLER_CHECK_SYMBOLS = frozenset(("fcntl", "close", "sigaction", "posix_spawn",
    "posix_spawn_file_actions_init", "posix_spawn_file_actions_destroy",
    "posix_spawn_file_actions_adddup2", "posix_spawn_file_actions_addclosefrom_np",
    "gnu_get_libc_version"))
CONTROLLER_AUDIT_STAGES = frozenset((
    "audit-install", "load-carrier", "load-host", "load-owner", "load-data", "load-core",
    "compile-prepare", "compile-check", "memory-tar", "native-abi", "load-contract",
    "run-contract", "body-final", "post-reconcile", "post-host", "post-origins",
    "post-mappings", "post-finish"))
CONTROLLER_AUDIT_RULES = frozenset((
    "open-path-type", "open-path-set", "open-flags-type", "open-write-flags",
    "directory-fd-identity", "directory-target", "environment-window", "environment-key",
    "loader-name", "loader-python-count", "loader-native-count", "loader-callsite",
    "symbol-window", "symbol-callsite", "symbol-shape", "symbol-not-admitted", "symbol-duplicate",
    "denied-ctypes", "denied-socket", "denied-subprocess", "denied-pty", "denied-shutil",
    "denied-tempfile", "denied-os-effect", "denied-thread", "denied-input"))
_CONTROLLER_AUDIT_FAMILIES = {
    "ctypes": "denied-ctypes", "socket": "denied-socket", "subprocess": "denied-subprocess",
    "pty": "denied-pty", "shutil": "denied-shutil", "tempfile": "denied-tempfile",
    "os": "denied-os-effect", "_thread": "denied-thread", "builtins": "denied-input"}

_CONTROLLER_SOURCE = None
_CONTROLLER_CHECK_STATE = None

CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
CARGO_ACQUISITION = "gnome-cargo-admitted-files-only-v1"
CARGO_LIBRARY_ROOT = "/usr/lib/x86_64-linux-gnu/"
CARGO_DNS_TARGETS = ("/etc/gai.conf", "/etc/host.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf")
CARGO_ROOT_ALIASES = (("/lib", "usr/lib"), ("/lib64", "usr/lib64"),
                      ("/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
CARGO_RESOLVER = {"path": "/run/systemd/resolve/stub-resolv.conf", "uid": 991, "gid": 991,
                  "mode": "0o644", "bytes": 972,
                  "sha256": "47543085f48c15320df27d8ebf5bc398aa87df3c918862feb814785821ca0927"}
CARGO_LIBGCC = "usr/lib/x86_64-linux-gnu/libgcc_s.so.1"
GIT_FORBIDDEN_CONTROLS = ("config.worktree", "commondir", "objects/info/alternates",
                          "objects/info/http-alternates", "info/attributes")
_OWNER = None
_WAITS = []
_ORIGINALS_SETTLED = True
_CATALOGUE = None
_PYCACHE = None
_PYTHON_RUNTIME = None
_PINS = {}
_HOST_REFUSAL = ()
_SUPPLIERS = []
_EVIDENCE = {"context": None, "source": None, "hostToolOriginalsSha256": None,
             "hostToolSuppliers": None, "acquisition": None, "owner": None,
             "reservationSha256": None, "originalWorkflowWait": None,
             "bootstrap": None, "hostAuthenticationScope": None, "pythonRuntime": None,
             "bwrapSupply": None, "pythonPycache": None, "controllerRuntime": None}
OWNER_ROLES = ("namespace-probe", "compile", "artifact-elf", "native", "source-post")
OWNER_FINALITY = ("namespaceProbeAttempted", "namespaceProbePassed", "nativeEnvelopeAttempted", "nativeEntryObserved",
                  "nativeAccepted", "passed", "nestedNamespaceRetired", "completeSourceDependencyPostchecked",
                  "artifactReceiptPostchecked", "artifactPostchecked", "outerPrivateCohortQuiet", "hostReservationChecked",
                  "pythonPycacheSameLeaf", "pythonPycachePostchecked", "pythonPycacheHandlesClosed",
                  "controllerRuntimeSameRoot", "controllerRuntimePostchecked", "controllerRuntimeHandlesClosed",
                  "oldPythonMasksChecked", "oldPythonMasksPostchecked")
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
    global _CONTROLLER_CHARACTERIZATION_READ_BYTES, _ORIGINALS_SETTLED
    path = Path(path)
    first = None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit
             and (not root or before.st_uid == before.st_gid == 0), "input-kind-owner-bound")
        parts, size = [], 0
        while part := os.read(fd, min(65536, before.st_size - size + 1)):
            size += len(part)
            if _CONTROLLER_CHARACTERIZATION_READ_BYTES is not None:
                _CONTROLLER_CHARACTERIZATION_READ_BYTES += len(part)
                need(_CONTROLLER_CHARACTERIZATION_READ_BYTES <= 512 * MIB,
                     "controller-characterization-total-read-bound")
            need(size <= before.st_size, "input-grew")
            parts.append(part)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             "input-original-changed")
        raw = b"".join(parts)
        return raw, {"identity": identity(before), "bytes": size, "sha256": hashlib.sha256(raw).hexdigest(),
                     "mode": oct(stat.S_IMODE(before.st_mode))}
    except BaseException as error:
        first = error
        raise
    finally:
        try:
            os.close(fd)
        except BaseException:
            if not _CONTROLLER_CHARACTERIZATION_ACTIVE:
                raise
            _ORIGINALS_SETTLED = False
            if first is None:
                raise Refused("controller-characterization-input-close-unknown")


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
    return _workflow_context(environment, REF)


def _workflow_context(environment, ref):
    need(environment.get("RUNNER_ENVIRONMENT") == "github-hosted" and environment.get("RUNNER_OS") == "Linux"
         and environment.get("RUNNER_ARCH") == "X64" and environment.get("ImageOS") == "ubuntu24", "hosted-ubuntu24-only")
    need(environment.get("GITHUB_REF") == ref, "dedicated-verification-ref")
    repository, commit = environment.get("GITHUB_REPOSITORY", ""), environment.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
         and re.fullmatch(r"[0-9a-f]{40}", commit) and commit != "0" * 40, "repository-source-shape")
    need(environment.get("GITHUB_WORKFLOW_SHA") == commit
         and environment.get("GITHUB_WORKFLOW_REF") == repository + "/" + WORKFLOW + "@" + ref,
         "workflow-source-binding")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        need(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(name, "")), "run-attempt-shape")
    event = environment.get("GITHUB_EVENT_NAME")
    need((event == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == commit)
         or (event == "push" and environment.get("MRK_PUSH_EVENT_AFTER") == commit), "reviewed-event-source")
    need(environment.get("ImageVersion") == SUPPORTED_IMAGE_VERSION, "unadmitted-runner-image")
    return {"sourceSha": commit, "repository": repository, "ref": ref, "workflow": WORKFLOW,
            "runId": environment["GITHUB_RUN_ID"], "attempt": environment["GITHUB_RUN_ATTEMPT"],
            "imageVersion": environment["ImageVersion"], "platform": "ubuntu-24.04-x86_64"}



def controller_characterization_context(environment, *, post=False):
    # No inherited loader/provider/configuration variables or caller-selected
    # repository, attempt, entry, path or command are measurement authority.
    fields = {"RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
        "GITHUB_REF", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_EVENT_NAME",
        "MRK_EXPECTED_SHA", "MRK_PUSH_EVENT_AFTER"}
    if post:
        fields |= {"MRK_CONTROLLER_STAGE_OUTCOME", "MRK_CONTROLLER_CHECK_OUTCOME"}
    need(set(environment) == set(ENV) | fields and all(environment.get(k) == v for k, v in ENV.items()),
         "controller-characterization-clean-environment")
    need(environment["GITHUB_REPOSITORY"] == "Apdelrahman1911/mobile-release-kit"
         and environment["GITHUB_RUN_ATTEMPT"] == "1", "controller-characterization-fixed-repository-attempt")
    return {**_workflow_context(environment, CONTROLLER_CHARACTERIZATION_REF), "measurementOnly": True}


def controller_characterization_binding(context):
    need(context.get("ref") == CONTROLLER_CHARACTERIZATION_REF
         and context.get("repository") == "Apdelrahman1911/mobile-release-kit"
         and context.get("attempt") == "1" and context.get("measurementOnly") is True
         and context.get("workflow") == WORKFLOW and context.get("imageVersion") == SUPPORTED_IMAGE_VERSION,
         "controller-characterization-not-production-authority")


def catalogue_ready(value):
    need(value.get("schema") == "gnome-session-hosted-suppliers-2", "supplier-catalogue-schema")
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


def python_runtime_catalogue(catalogue):
    """One source-literal H -> V Python projection, never host3.12 authority."""
    runtime = catalogue.get("controllerRuntime")
    need(type(runtime) is dict and runtime.get("schema") == CONTROLLER_RUNTIME_SCHEMA,
         "controller-runtime-schema")
    need(runtime.get("prefix") == str(PYTHON_ROOT) and runtime.get("executable") == PYTHON_EXECUTABLE
         and runtime.get("version") == [3, 14, 7] and runtime.get("cacheTag") == "cpython-314"
         and runtime.get("pythonPrefix") == str(PYTHON_ROOT / "python")
         and runtime.get("searchPath") == list(PYTHON_SEARCH), "controller-runtime-selection")
    need(runtime.get("builtins") == list(PYTHON_BUILTINS) and runtime.get("sharedExtensionModules") == []
         and "_ctypes" in runtime["builtins"], "controller-runtime-static-builtins")
    projection = runtime.get("projection")
    need(type(projection) is dict and set(projection) == {"files", "directories", "aliases"}
         and projection["aliases"] == [], "controller-runtime-no-aliases")
    files, directories = projection["files"], projection["directories"]
    need(type(files) is list and len(files) == 598 and type(directories) is list and len(directories) == 53,
         "controller-runtime-complete-projection")
    paths, total = [], 0
    for row in files:
        need(type(row) is dict and set(row) == {"path", "bytes", "sha256", "archiveMode", "mode", "origin"},
             "controller-runtime-file-fields")
        name = path_name(row["path"])
        need(name.startswith("python/") and not name.endswith((".pyc", ".pyo"))
             and "/__pycache__/" not in name and type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 * MIB
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
             and row["archiveMode"] == ("0o755" if name == "python/bin/python3" else "0o644")
             and row["mode"] == ("0o555" if name == "python/bin/python3" else "0o444"),
             "controller-runtime-file-contract")
        paths.append(name)
        total += row["bytes"]
    need(paths == sorted(set(paths)) and len({name.lower() for name in paths}) == len(paths)
         and total == 27303244, "controller-runtime-file-roster")
    wanted = {"."}
    for name in paths:
        wanted.update(str(parent) for parent in Path(name).parents)
    directory_names = []
    for row in directories:
        need(type(row) is dict and set(row) == {"path", "mode", "entries"}
             and row["path"] in wanted and row["mode"] == "0o555", "controller-runtime-directory-contract")
        name = row["path"]
        children = sorted({str(Path(path).relative_to(name)).split("/")[0]
                           for path in paths if name == "." or path.startswith(name + "/")})
        need(row["entries"] == children, "controller-runtime-parent-roster")
        directory_names.append(name)
    need(directory_names == sorted(wanted), "controller-runtime-directory-roster")
    selected = {str(PYTHON_ROOT / row["path"]) for row in files}
    need(PYTHON_REQUIRED_FILES <= selected
         and {row["path"] for row in files if row["path"].startswith("python/lib/python3.14/lib-dynload/")}
             == {"python/lib/python3.14/lib-dynload/README.mrk"}, "controller-runtime-required-inputs")
    zip_row = next(row for row in files if row["path"] == "python/lib/python314.zip")
    need({key: zip_row[key] for key in ("path", "bytes", "sha256")} == runtime.get("emptyZip")
         == {"path": "python/lib/python314.zip", "bytes": 22,
             "sha256": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"},
         "controller-runtime-present-empty-zip")
    need(hashlib.sha256(canonical(projection)).hexdigest() == runtime.get("projectionSha256")
         and hashlib.sha256(canonical(runtime)).hexdigest() == CONTROLLER_RUNTIME_SHA256,
         "controller-runtime-literal-provenance")
    # Host libffi and every unrelated supplier remain independent obligations.
    for key in ("hostFiles", "hostDirectories", "hostAliases"):
        rows = catalogue[key]
        need(type(rows) is list and len({row["path"] for row in rows}) == len(rows)
             and all(row["path"] not in ("/usr/bin/python3", "/usr/bin/python3.12", "/usr/lib/python3.12")
                     and not row["path"].startswith("/usr/lib/python3.12/") for row in rows),
             "old-python-not-active-authority")
    return {"runtimeFiles": len(files), "runtimeDirectories": len(directories),
            "runtimeBytes": total, "normalSourceCacheInputs": 0, "pinnedSourceCacheDataRows": 0}


def controller_runtime_roster(runtime, *, readonly):
    """Bind every member and parent; no symlink, cache or extra empty directory."""
    global _ORIGINALS_SETTLED
    roster = bounded_roster(PYTHON_ROOT, files=700, total=32 * MIB)
    files = {Path(row["path"]).relative_to(PYTHON_ROOT).as_posix(): row for row in roster["files"]}
    directories = {Path(row["path"]).relative_to(PYTHON_ROOT).as_posix(): row for row in roster["directories"]}
    wanted_files = {row["path"]: row for row in runtime["projection"]["files"]}
    wanted_directories = {row["path"]: row for row in runtime["projection"]["directories"]}
    need(files.keys() == wanted_files.keys() and directories.keys() == wanted_directories.keys(),
         "controller-runtime-actual-roster")
    for name, row in files.items():
        need(all(row[key] == wanted_files[name][key] for key in ("bytes", "sha256", "mode")),
             "controller-runtime-actual-member")
    for name, row in directories.items():
        need(all(row[key] == wanted_directories[name][key] for key in ("mode", "entries")),
             "controller-runtime-actual-parent")
    if readonly:
        # A readonly parent does not establish the flags of a nested file bind.
        # Retain only one transient original at a time, below the fixed FD cap.
        for rows, directory in ((files.values(), False), (directories.values(), True)):
            for row in rows:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if directory:
                    flags |= os.O_DIRECTORY
                fd, failed = None, False
                try:
                    fd = os.open(row["path"], flags)
                    need(identity(os.fstat(fd)) == row["identity"] == identity(Path(row["path"]).lstat())
                         and os.fstatvfs(fd).f_flag & os.ST_RDONLY, "controller-runtime-not-readonly-original")
                except BaseException:
                    failed = True
                    raise
                finally:
                    if fd is not None:
                        try:
                            os.close(fd)
                        except BaseException:
                            _ORIGINALS_SETTLED = False
                            if _PYTHON_RUNTIME is not None:
                                _PYTHON_RUNTIME["closeFailed"] = True
                            if not failed:
                                raise Refused("controller-runtime-member-close-unknown")
    return roster


def controller_artifact_originals(data, runtime):
    """Reuse the conventional exact47-file artifact admission, not a downloader."""
    expected = data.records(runtime["preparedArtifact"]["files"])
    root = PYTHON_SUPPLIER
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid != 0 and stat.S_IMODE(info.st_mode) == 0o700,
         "controller-artifact-original-root")
    need(not (root / ".git").exists() and not (root / ".git").is_symlink(), "controller-artifact-extra-git")
    directories = source_directories(root, sorted(expected), original=True)
    originals = []
    for name, row in expected.items():
        path = root / name
        before = identity(path.lstat())
        data.bound(path, row)
        need(identity(path.lstat()) == before, "controller-artifact-original-changed")
        originals.append({"path": name, **row, "identity": before})
    need(source_directories(root, sorted(expected), original=True) == directories
         and identity(root.lstat()) == identity(info), "controller-artifact-roster-changed")
    return {"files": originals, "directories": directories, "rootIdentity": identity(info)}


def controller_prepared_runtime(runtime):
    root = PYTHON_STAGE / "prepared/runtime"
    roster = bounded_roster(root, files=700, total=32 * MIB)
    expected = {row["path"]: {"bytes": row["bytes"], "sha256": row["sha256"], "mode": row["archiveMode"]}
                for row in runtime["projection"]["files"]}
    for row in runtime["preparedRuntime"]["nonPythonFiles"]:
        expected[row["path"]] = {"bytes": row["size"], "sha256": row["sha256"], "mode": oct(row["mode"])}
    actual = {Path(row["path"]).relative_to(root).as_posix(): row for row in roster["files"]}
    need(len(expected) == 607 and actual.keys() == expected.keys()
         and roster["bytes"] == runtime["preparedRuntime"]["fileBytes"]
         and all(all(actual[name][key] == row[key] for key in ("bytes", "sha256", "mode"))
                 for name, row in expected.items()), "controller-prepared-complete-runtime")
    parents = {"."}
    for name in expected:
        parents.update(str(parent) for parent in Path(name).parents)
    need({Path(row["path"]).relative_to(root).as_posix() for row in roster["directories"]} == parents
         and all(row["mode"] == "0o700" for row in roster["directories"]), "controller-prepared-parent-roster")
    raw, _ = read(root / "manifest.json", MIB)
    manifest = decode(raw)
    wanted = [{"path": name, "size": row["bytes"], "sha256": row["sha256"]}
              for name, row in sorted(expected.items()) if name != "manifest.json"]
    need(manifest.get("files") == wanted and len(wanted) == 606
         and hashlib.sha256(canonical(wanted).removesuffix(b"\n")).hexdigest()
             == manifest.get("inventorySha256") == runtime["preparedRuntime"]["inventorySha256"],
         "controller-prepared-manifest-projection")
    return roster



def controller_proc(path, limit):
    """Two fixed kernel DATA views; never a process observer or a command."""
    need(path in ("/proc/self/mountinfo", "/proc/self/maps", "/proc/self/fd"), "controller-check-proc-role")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parts, size = [], 0
        while part := os.read(fd, min(65536, limit - size + 1)):
            parts.append(part)
            size += len(part)
            need(size <= limit, "controller-check-proc-bound")
        return b"".join(parts)
    finally:
        os.close(fd)


def controller_source_mounts(original):
    """Exact mount correspondence as well as every member's readonly FD flag."""
    original = Path(original)
    need(original.is_absolute() and str(original) == os.path.normpath(original)
         and original != CONTROLLER_CHECK_SOURCE, "controller-source-original-root")
    rows = []
    raw = controller_proc("/proc/self/mountinfo", MIB)
    for line in raw.decode("ascii").splitlines():
        fields = line.split(" ")
        need(len(fields) >= 10 and len(rows) < 4096 and "-" in fields, "controller-source-mountinfo-shape")
        split = fields.index("-")
        need(split >= 6 and len(fields) == split + 4, "controller-source-mountinfo-fields")
        # The fixed checkout/view spelling has no mountinfo escapes. Refuse
        # rather than normalize an alias or substitute another mount identity.
        if "\\" in fields[4]:
            continue
        rows.append({"id": fields[0], "parent": fields[1], "device": fields[2],
                     "root": fields[3], "point": fields[4], "options": fields[5],
                     "optional": fields[6:split], "filesystem": fields[split + 1],
                     "source": fields[split + 2], "superOptions": fields[split + 3]})
    candidates = [row for row in rows if original == Path(row["point"])
                  or Path(row["point"]) in original.parents]
    need(candidates, "controller-source-original-mount-missing")
    parent = max(candidates, key=lambda row: len(row["point"]))
    views = [row for row in rows if row["point"] == str(CONTROLLER_CHECK_SOURCE)]
    need(len(views) == 1, "controller-source-view-mount-missing")
    view = views[0]
    underlying = str(Path(parent["root"]) / original.relative_to(parent["point"]))
    need(view["id"] != parent["id"] and view["root"] == underlying
         and view["device"] == parent["device"] and view["filesystem"] == parent["filesystem"]
         and "ro" in view["options"].split(","), "controller-source-not-readonly-bind")
    return {"original": parent, "view": view}


def controller_source_snapshot(root, names, *, readonly):
    global _ORIGINALS_SETTLED
    root = Path(root)
    files = {name: read(root / name, 32 * MIB, root=False)[1] for name in names}
    directories = source_directories(root, names, original=True)
    rows = [(root / name, pin, False) for name, pin in files.items()]
    rows += [(root / row["relative"], row, True) for row in directories]
    for path, pin, directory in rows:
        fd, first = None, None
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(path, flags | (os.O_DIRECTORY if directory else 0))
            need(identity(os.fstat(fd)) == pin["identity"] == identity(path.lstat())
                 and (not readonly or os.fstatvfs(fd).f_flag & os.ST_RDONLY),
                 "controller-source-member-replaced-or-writable")
        except BaseException as error:
            first = error
            raise
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    _ORIGINALS_SETTLED = False
                    if _CONTROLLER_SOURCE is not None:
                        _CONTROLLER_SOURCE["closeFailed"] = True
                    if first is None:
                        raise Refused("controller-source-member-close-unknown")
    return {"files": files, "directories": directories}


def controller_native_pristine():
    for path in (TASK, PUBLIC):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise Refused("controller-check-native-root-occupied")
    info = OUTER.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
         "controller-check-native-outer-kind")
    with os.scandir(OUTER) as stream:
        need(next(stream, None) is None, "controller-check-native-outer-not-empty")
    need(identity(OUTER.lstat()) == identity(info), "controller-check-native-outer-changed")
    return identity(info)


def controller_check_output_root():
    """Only the workflow's exclusive non-root evidence leaf, never PUBLIC."""
    info, parent = CONTROLLER_CHECK_ROOT.lstat(), CONTROLLER_CHECK_ROOT.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0
         and parent.st_mode & stat.S_ISVTX
         and stat.S_ISDIR(info.st_mode) and info.st_uid != 0
         and stat.S_IMODE(info.st_mode) == 0o700, "controller-check-exclusive-output-root")
    return {"parent": directory_custody(parent), "root": directory_custody(info)}


def controller_source_begin(binding):
    global _CONTROLLER_SOURCE
    need(_CONTROLLER_SOURCE is None, "controller-source-phase-already-started")
    state = {"binding": binding, "fds": [], "closed": False, "closeFailed": False,
             "postchecked": False, "handlesClosed": False}
    _CONTROLLER_SOURCE = state  # Own each partial original before using it.
    need(binding["viewRoot"] == str(CONTROLLER_CHECK_SOURCE)
         and len(binding["originals"]["files"]) == 975, "controller-source-staging-binding")
    for path in (Path(binding["originalRoot"]), CONTROLLER_CHECK_SOURCE):
        state["fds"].append(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
    controller_source_original()


def controller_source_original():
    state = _CONTROLLER_SOURCE
    need(state is not None and not state["closed"] and len(state["fds"]) == 2,
         "controller-source-original-required")
    binding = state["binding"]
    roots = (Path(binding["originalRoot"]), CONTROLLER_CHECK_SOURCE)
    original = next(row["identity"] for row in binding["originals"]["directories"] if row["relative"] == ".")
    for path, fd in zip(roots, state["fds"]):
        need(identity(os.fstat(fd)) == original == identity(path.lstat()), "controller-source-bind-root-replaced")
    need(bool(os.fstatvfs(state["fds"][0]).f_flag & os.ST_RDONLY) == binding["originalReadonly"]
         and os.fstatvfs(state["fds"][1]).f_flag & os.ST_RDONLY, "controller-source-bind-flags-changed")
    names = sorted(binding["originals"]["files"])
    # Both views have the SAME native identities. Only their relative path
    # spelling is normalized; catalogue/helper pins are never rewritten.
    for root, readonly in ((roots[0], False), (roots[1], True)):
        need(controller_source_snapshot(root, names, readonly=readonly) == binding["originals"],
             "controller-source-original-or-view-changed")
    need(controller_source_mounts(roots[0]) == binding["mounts"]
         and controller_check_output_root() == binding["outputCustody"]
         and controller_native_pristine() == binding["nativeOuter"], "controller-source-bind-custody-changed")
    return binding["originals"]


def controller_source_finish(*, failed=False):
    global _ORIGINALS_SETTLED
    state = _CONTROLLER_SOURCE
    if state is None or state["closed"]:
        return
    first = None
    try:
        controller_source_original()
        state["postchecked"] = True
    except BaseException as error:
        first = error
    finally:
        state["closed"] = True
        while state["fds"]:
            fd = state["fds"].pop()
            try:
                os.close(fd)
            except BaseException:
                state["closeFailed"] = True
                _ORIGINALS_SETTLED = False
        state["handlesClosed"] = not state["closeFailed"]
    if not failed:
        if first is not None:
            raise first
        need(state["handlesClosed"], "controller-source-close-unknown")


def controller_stage_source(names):
    originals = bwrap_sources(names)
    fd = os.open(SOURCE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        original_readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
        need(identity(os.fstat(fd)) == identity(SOURCE.lstat()), "controller-source-original-root-changed")
    finally:
        os.close(fd)
    binding = {"originalRoot": str(SOURCE), "viewRoot": str(CONTROLLER_CHECK_SOURCE),
               "originals": originals, "originalReadonly": original_readonly,
               "mounts": controller_source_mounts(SOURCE), "outputCustody": controller_check_output_root(),
               "nativeOuter": controller_native_pristine()}
    controller_source_begin(binding)
    return binding


def controller_check_ready(catalogue):
    """Positive, source-literal finite DATA gate; current missing evidence REFUSES.

    This is not catalogue_ready and cannot authorize any of its five phases.
    The future subset's exact digest must be independently SOURCE-admitted; a
    supplier row or runtime's unresolved providerSelection string is not proof.
    """
    python_runtime_catalogue(catalogue)
    need(catalogue.get("schema") == "gnome-session-hosted-suppliers-2"
         and catalogue.get("bootstrapTrust") == BOOTSTRAP_TRUST
         and catalogue.get("productTree") == PRODUCT_TREE and len(catalogue.get("product", [])) == 964,
         "controller-check-source-runtime-contract")
    selected = catalogue.get("controllerCheckInputs")
    need(type(CONTROLLER_CHECK_HOST_SHA256) is str
         and re.fullmatch(r"[0-9a-f]{64}", CONTROLLER_CHECK_HOST_SHA256)
         and type(selected) is dict, "controller-check-loader-evidence-unresolved")
    need(hashlib.sha256(canonical(selected)).hexdigest() == CONTROLLER_CHECK_HOST_SHA256
         and set(selected) == {"schema", "imageVersion", "runtimeSha256", "mappedHostFiles",
                               "configurationFiles", "directories", "aliases", "absent", "selectionEvidence"}
         and selected["schema"] == "gnome-controller-check-loader-inputs-1"
         and selected["imageVersion"] == SUPPORTED_IMAGE_VERSION
         and selected["runtimeSha256"] == CONTROLLER_RUNTIME_SHA256, "controller-check-loader-source-binding")
    evidence = selected["selectionEvidence"]
    need(type(evidence) is dict and set(evidence) == {"loaderSearchSha256", "providerConfigSha256", "actualMappingsSha256"}
         and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in evidence.values()),
         "controller-check-positive-selection-evidence")
    for key, maximum in (("mappedHostFiles", 32), ("configurationFiles", 32), ("directories", 32),
                         ("aliases", 32), ("absent", 128)):
        rows = selected[key]
        need(type(rows) is list and 0 < len(rows) <= maximum and all(type(path) is str for path in rows)
             and rows == sorted(set(rows)) and all(path.startswith("/") and os.path.normpath(path) == path
             and re.fullmatch(r"[A-Za-z0-9_./+-]+", path) for path in rows), "controller-check-finite-input-paths")
    need({"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/libc.so.6"}
         <= set(selected["mappedHostFiles"])
         and all(path.startswith("/usr/lib/x86_64-linux-gnu/") for path in selected["mappedHostFiles"])
         and {"/etc/ld.so.cache", "/etc/ssl/openssl.cnf"} <= set(selected["configurationFiles"])
         and all(path.startswith(("/etc/", "/usr/lib/ssl/")) for path in selected["configurationFiles"])
         and {"/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu/ossl-modules"}
             <= set(selected["directories"])
         and {path for path, _ in CARGO_ROOT_ALIASES} <= set(selected["aliases"])
         and "/etc/ld.so.preload" in selected["absent"], "controller-check-reached-loader-selector-closure")
    tables = {key: {row["path"]: row for row in catalogue[key]}
              for key in ("hostFiles", "hostDirectories", "hostAliases")}
    need(all(len(tables[key]) == len(catalogue[key]) for key in tables), "controller-check-input-duplicates")
    files, directories, aliases, absent, parents = {}, [], [], [], {}
    for path in sorted(set(selected["mappedHostFiles"] + selected["configurationFiles"])):
        need(path in tables["hostFiles"], "controller-check-host-file-evidence-missing")
        expected = tables["hostFiles"][path]
        _, pin = read(path, 16 * MIB)
        need(all(pin[key] == expected[key] for key in ("bytes", "sha256", "mode")),
             "controller-check-host-file-differs")
        files[path] = pin
    for path in selected["directories"]:
        need(path in tables["hostDirectories"], "controller-check-host-directory-evidence-missing")
        expected, directory = tables["hostDirectories"][path], Path(path)
        before = directory.lstat()
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
             and not before.st_mode & 0o022 and type(expected["entries"]) is list
             and len(expected["entries"]) <= 4096, "controller-check-host-directory-shape")
        with os.scandir(directory) as stream:
            entries = []
            for entry in stream:
                need(len(entries) < 4096, "controller-check-host-directory-bound")
                entries.append(entry.name)
        need(sorted(entries) == expected["entries"] == sorted(set(expected["entries"]))
             and oct(stat.S_IMODE(before.st_mode)) == expected["mode"]
             and identity(directory.lstat()) == identity(before), "controller-check-host-directory-differs")
        directories.append({"path": path, "identity": identity(before), "entries": sorted(entries)})
    for path in selected["aliases"]:
        need(path in tables["hostAliases"], "controller-check-host-alias-evidence-missing")
        before = Path(path).lstat()
        need(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0,
             "controller-check-host-alias-kind")
        target = os.readlink(path)
        need(target == tables["hostAliases"][path]["target"] and identity(Path(path).lstat()) == identity(before),
             "controller-check-host-alias-differs")
        aliases.append({"path": path, "identity": identity(before), "target": target})
    for path in selected["absent"]:
        root_absent(path, "controller-check-selector-absent")
        absent.append(path)
    for path in (*files, *selected["directories"], *selected["aliases"], *absent):
        for parent in Path(path).parents:
            if str(parent) in parents:
                continue
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                 "controller-check-host-protected-parent")
            parents[str(parent)] = directory_custody(info)
    return {"catalogueSha256": CONTROLLER_CHECK_HOST_SHA256, "files": files, "directories": directories,
            "aliases": aliases, "absent": absent, "parents": parents,
            "mappedHostFiles": selected["mappedHostFiles"], "selectionEvidence": evidence}




def controller_characterization_parent(path, inputs):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
         "controller-characterization-protected-parent")
    prior = inputs["parents"].setdefault(str(path), directory_custody(info))
    need(prior == directory_custody(info), "controller-characterization-parent-replaced")
    return info


def controller_characterization_directory(path):
    """Existing finite roster mechanics; never a recursive host census."""
    path, rows = Path(path), []
    before = path.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and not before.st_mode & 0o022,
         "controller-characterization-directory-kind")
    with os.scandir(path) as stream:
        for entry in stream:
            need(len(rows) < 4096 and len(entry.name) <= 255
                 and re.fullmatch(r"[A-Za-z0-9_.+@:=,-]+", entry.name),
                 "controller-characterization-directory-bound")
            rows.append(entry.name)
    need(identity(before) == identity(path.lstat()), "controller-characterization-directory-changed")
    return {"path": str(path), "identity": identity(before), "mode": oct(stat.S_IMODE(before.st_mode)),
            "entries": sorted(rows)}


def controller_characterization_retain_directory(path, inputs):
    path = str(path)
    prior = next((row for row in inputs["directories"] if row["path"] == path), None)
    if prior is None:
        need(len(inputs["directories"]) < 32, "controller-characterization-directory-count")
        inputs["directories"].append(controller_characterization_directory(path))
    else:
        need(prior == controller_characterization_directory(path), "controller-characterization-directory-replaced")


def controller_characterization_absence(path, inputs):
    """Record the first genuinely absent edge; dangling/inaccessible is not absent."""
    path = Path(path)
    need(path.is_absolute() and os.path.normpath(path) == str(path), "controller-characterization-absence-path")
    parent = Path("/")
    controller_characterization_parent(parent, inputs)
    for index, part in enumerate(path.parts[1:]):
        child = parent / part
        before = controller_characterization_parent(parent, inputs)
        try:
            info = child.lstat()
        except FileNotFoundError:
            controller_characterization_retain_directory(parent, inputs)
            need(identity(before) == identity(parent.lstat()), "controller-characterization-absence-parent-changed")
            edge = str(child)
            if edge not in inputs["absent"]:
                need(len(inputs["absent"]) < 128, "controller-characterization-absence-count")
                inputs["absent"].append(edge)
            return {"requested": str(path), "firstAbsent": edge, "parent": str(parent)}
        except OSError as error:
            raise Refused("controller-characterization-absence-unreadable") from error
        need(index < len(path.parts) - 2 and stat.S_ISDIR(info.st_mode)
             and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
             "controller-characterization-alternate-provider-present")
        parent = child
    raise Refused("controller-characterization-absence-unproved")


def controller_characterization_post_inputs(inputs):
    """All retained originals are attempted even if an earlier POST fails."""
    state = {"firstFailure": None, "errors": [], "post": {}}
    def same(actual, expected):
        need(actual == expected, "controller-characterization-host-original-changed")
    for path, pin in inputs["files"].items():
        controller_attempt(state, "file", lambda path=path, pin=pin: same(read(path, 16 * MIB)[1], pin))
    for row in inputs["directories"]:
        controller_attempt(state, "directory", lambda row=row: same(controller_characterization_directory(row["path"]), row))
    for row in inputs["aliases"]:
        def alias(row=row):
            info = Path(row["path"]).lstat()
            need(stat.S_ISLNK(info.st_mode) and identity(info) == row["identity"]
                 and os.readlink(row["path"]) == row["target"]
                 and identity(Path(row["path"]).lstat()) == row["identity"],
                 "controller-characterization-alias-changed")
        controller_attempt(state, "alias", alias)
    for path in inputs["absent"]:
        controller_attempt(state, "absence", lambda path=path: root_absent(path, "controller-characterization-first-edge"))
    for path, original in inputs["parents"].items():
        controller_attempt(state, "parent", lambda path=path, original=original: same(
            directory_custody(Path(path).lstat()), original))
    if state["firstFailure"] is not None:
        raise Refused(state["firstFailure"]["refusal"])


def controller_characterization_inputs(catalogue):
    global _CONTROLLER_CHARACTERIZATION_INPUTS
    python_runtime_catalogue(catalogue)
    need(catalogue.get("schema") == "gnome-session-hosted-suppliers-2"
         and catalogue.get("bootstrapTrust") == BOOTSTRAP_TRUST
         and catalogue.get("productTree") == PRODUCT_TREE and len(catalogue.get("product", [])) == 964,
         "controller-characterization-source-runtime-contract")
    need(_CONTROLLER_CHARACTERIZATION_INPUTS is None, "controller-characterization-originals-already-started")
    inputs = {"schema": "gnome-controller-characterization-input-originals-1",
        "authority": CONTROLLER_CHARACTERIZATION_AUTHORITY, "complete": False,
        "files": {}, "directories": [], "aliases": [], "absent": [], "parents": {},
        "absenceRoutes": [], "mappedHostFiles": sorted(CONTROLLER_CHARACTERIZATION_HOSTS)}
    _CONTROLLER_CHARACTERIZATION_INPUTS = inputs  # Partial originals owned BEFORE further reads.
    for path in (*CONTROLLER_CHARACTERIZATION_HOSTS, *CONTROLLER_CHARACTERIZATION_CONFIG,
                 *CONTROLLER_CHARACTERIZATION_DIRS, *(path for path, _ in CARGO_ROOT_ALIASES)):
        for parent in reversed(Path(path).parents):
            controller_characterization_parent(parent, inputs)
    for path in sorted((*CONTROLLER_CHARACTERIZATION_HOSTS, *CONTROLLER_CHARACTERIZATION_CONFIG)):
        raw, pin = read(path, 16 * MIB)
        need(not int(pin["mode"], 8) & 0o022, "controller-characterization-mutable-file")
        if path in CONTROLLER_CHARACTERIZATION_HOSTS:
            need(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                 and raw[18:20] == b"\x3e\x00", "controller-characterization-host-elf")
        inputs["files"][path] = pin
    for path in CONTROLLER_CHARACTERIZATION_DIRS:
        controller_characterization_retain_directory(path, inputs)
    for path, target in CARGO_ROOT_ALIASES:
        info = Path(path).lstat()
        need(stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
             and os.readlink(path) == target and identity(Path(path).lstat()) == identity(info),
             "controller-characterization-root-alias")
        inputs["aliases"].append({"path": path, "target": target, "identity": identity(info)})
    # /lib and /lib64 are exactly the retained merged-/usr aliases above.
    # Private RUNPATH/hwcaps closure is the complete alias-free Python projection.
    sonames = tuple(Path(path).name for path in CONTROLLER_CHARACTERIZATION_HOSTS)
    targets = {"/etc/ld.so.preload"}
    for directory in CONTROLLER_CHARACTERIZATION_DIRS[:3]:
        for level in ("x86-64-v2", "x86-64-v3", "x86-64-v4"):
            targets.update(directory + "/glibc-hwcaps/" + level + "/" + name for name in sonames)
        if directory != "/usr/lib/x86_64-linux-gnu":
            targets.update(directory + "/" + name for name in sonames
                           if directory + "/" + name != "/usr/lib64/ld-linux-x86-64.so.2")
    for path in sorted(targets):
        inputs["absenceRoutes"].append(controller_characterization_absence(path, inputs))
    for key in ("directories", "aliases"):
        inputs[key].sort(key=lambda row: row["path"])
    inputs["absent"].sort()
    need(len(canonical(inputs)) <= 8 * MIB, "controller-characterization-metadata-bound")
    controller_characterization_post_inputs(inputs)
    inputs["complete"] = True
    return inputs


def controller_characterization_post_host(catalogue, receipt):
    python_runtime_catalogue(catalogue)
    inputs = receipt["controllerCheckInputs"]
    need(inputs.get("schema") == "gnome-controller-characterization-input-originals-1"
         and inputs.get("authority") == CONTROLLER_CHARACTERIZATION_AUTHORITY and inputs.get("complete") is True
         and inputs.get("mappedHostFiles") == sorted(CONTROLLER_CHARACTERIZATION_HOSTS),
         "controller-characterization-input-binding")
    controller_characterization_post_inputs(inputs)


def stage_controller_runtime(context, catalogue, catalogue_pin):
    return _stage_controller_runtime(context, catalogue, catalogue_pin, characterization=False)


def stage_controller_characterization(context, catalogue, catalogue_pin):
    global _CONTROLLER_CHECK_STATE, _CONTROLLER_CHARACTERIZATION_STAGE
    controller_characterization_binding(context)
    state = {"firstFailure": None, "errors": [], "post": {}}
    _CONTROLLER_CHECK_STATE = state
    stage = {"files": [(SOURCE / CONTROL / "runtime-suppliers.json", catalogue_pin)], "copies": [],
             "artifact": None, "prepared": None, "data": None, "runtime": catalogue["controllerRuntime"],
             "enabled": False}
    _CONTROLLER_CHARACTERIZATION_STAGE = stage
    try:
        _stage_controller_runtime(context, catalogue, catalogue_pin, characterization=True)
    except BaseException as error:
        controller_failure(state, "stage", error)
    finally:
        # These independent POSTs also run when the artifact/copy/writer failed
        # part-way through staging. None enables, deletes or adopts a partial leaf.
        def same(actual, expected):
            need(actual == expected, "controller-characterization-stage-input-changed")
        for path, pin in stage["files"]:
            controller_attempt(state, "stageFile", lambda path=path, pin=pin: same(
                read(path, 16 * MIB, root=not str(path).startswith(str(SOURCE) + "/"))[1], pin))
        if stage["artifact"] is not None:
            controller_attempt(state, "artifact", lambda: same(
                controller_artifact_originals(stage["data"], stage["runtime"]), stage["artifact"]))
        if stage["prepared"] is not None:
            controller_attempt(state, "prepared", lambda: same(
                controller_prepared_runtime(stage["runtime"]), stage["prepared"]))
        for copied_row in stage["copies"]:
            def copied(copied_row=copied_row):
                path, row, original = copied_row["path"], copied_row["row"], copied_row["original"]
                _, pin = read(path, 16 * MIB)
                need(original is not None and pin == original
                     and pin["bytes"] == row["bytes"] and pin["sha256"] == row["sha256"]
                     and pin["mode"] == (row["mode"] if stage["enabled"] else "0o444"),
                     "controller-characterization-partial-copy-post")
            controller_attempt(state, "copy", copied)
        if _CONTROLLER_CHARACTERIZATION_INPUTS is not None:
            controller_attempt(state, "host", lambda: controller_characterization_post_inputs(
                _CONTROLLER_CHARACTERIZATION_INPUTS))
        for role, finish in (("source", controller_source_finish), ("cache", pycache_finish)):
            controller_attempt(state, role, lambda finish=finish: finish(failed=state["firstFailure"] is not None))
    need(state["firstFailure"] is None and _ORIGINALS_SETTLED, "controller-characterization-stage-not-settled")
    print("GNOME_CONTROLLER_CHARACTERIZATION_STAGED=measurement-only;readonly-mount-still-required", flush=True)


def _stage_controller_runtime(context, catalogue, catalogue_pin, *, characterization):
    """Explicit provider-only bounded DATA bootstrap. Never starts a candidate."""
    python_runtime_catalogue(catalogue)
    need(catalogue["schema"] == "gnome-session-hosted-suppliers-2"
         and catalogue["bootstrapTrust"] == BOOTSTRAP_TRUST, "controller-bootstrap-boundary")
    runtime = catalogue["controllerRuntime"]
    provider = runtime["bootstrap"]["python"]
    need(sys.executable == provider["path"] and sys.version_info[:2] == (3, 12)
         and sys.prefix == sys.base_prefix == "/usr", "controller-bootstrap-provider-selection")
    _, provider_pin = read(provider["path"], 16 * MIB)
    if characterization:
        _CONTROLLER_CHARACTERIZATION_STAGE["files"].append((Path(provider["path"]), provider_pin))
    need(provider_pin["bytes"] == provider["size"] and provider_pin["sha256"] == provider["sha256"]
         and provider_pin["mode"] == "0o755", "controller-bootstrap-provider-body")
    need(Path("/bin").is_symlink() and os.readlink("/bin") == "usr/bin"
         and Path("/usr/bin/python3").is_symlink() and os.readlink("/usr/bin/python3") == "python3.12",
         "controller-bootstrap-old-alias")
    for path in (PYTHON_ROOT, PYTHON_STAGE):
        root_absent(path, "controller-runtime-exclusive-root")
    parents = []
    for path in (Path("/"), Path("/run")):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
             "controller-bootstrap-protected-parent")
        parents.append({"path": str(path), "custody": directory_custody(info)})
    root_absent("/etc/ld.so.preload", "host-absent-input")
    root_absent("/usr/lib/python312.zip", "old-python-zip")
    source_binding = controller_stage_source(source_product(catalogue))
    check_inputs = (controller_characterization_inputs(catalogue) if characterization
                    else controller_check_ready(catalogue))  # Production's positive gate remains mandatory.
    helper = runtime["bootstrap"]["unpackHelper"]
    helper_path = SOURCE / helper["path"]
    _, helper_pin = read(helper_path, helper["size"], root=False)
    if characterization:
        _CONTROLLER_CHARACTERIZATION_STAGE["files"].append((helper_path, helper_pin))
    need(helper_pin["bytes"] == helper["size"] and helper_pin["sha256"] == helper["sha256"],
         "controller-unpack-helper-before-import")
    # Only this authenticated product DATA helper; no V core or GN owner import.
    spec = importlib.util.spec_from_file_location("_mrk_gnome_runtime_data", helper_path)
    data = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(data)
    need(read(helper_path, helper["size"], root=False)[1] == helper_pin, "controller-unpack-helper-changed")
    artifact = controller_artifact_originals(data, runtime)
    if characterization:
        _CONTROLLER_CHARACTERIZATION_STAGE.update(artifact=artifact, data=data)
    PYTHON_STAGE.mkdir(mode=0o700)
    data.unpack(PYTHON_SUPPLIER / "prepared-runtime.tar", runtime["archive"], PYTHON_STAGE / "prepared")
    prepared = controller_prepared_runtime(runtime)
    if characterization:
        _CONTROLLER_CHARACTERIZATION_STAGE["prepared"] = prepared
    PYTHON_ROOT.mkdir(mode=0o700)
    for row in runtime["projection"]["directories"]:
        if row["path"] != ".":
            (PYTHON_ROOT / row["path"]).mkdir(mode=0o700)
    # Do not enable the interpreter until the complete tar/manifest/projection
    # and all original DATA inputs have actually been postchecked.
    for row in runtime["projection"]["files"]:
        original = PYTHON_STAGE / "prepared/runtime" / row["path"]
        expected = {"path": row["path"], "size": row["bytes"], "sha256": row["sha256"]}
        if characterization:
            copied_row = {"path": PYTHON_ROOT / row["path"], "row": row, "original": None}
            _CONTROLLER_CHARACTERIZATION_STAGE["copies"].append(copied_row)
        data.copy(original, PYTHON_ROOT / row["path"], expected, 0o444)
        if characterization:
            copied_row["original"] = read(copied_row["path"], 16 * MIB)[1]
    need(controller_prepared_runtime(runtime) == prepared
         and controller_artifact_originals(data, runtime) == artifact
         and read(helper_path, helper["size"], root=False)[1] == helper_pin
         and read(provider["path"], 16 * MIB)[1] == provider_pin
         and read(SOURCE / CONTROL / "runtime-suppliers.json", 16 * MIB, root=False)[1] == catalogue_pin,
         "controller-bootstrap-original-postcheck")
    controller_source_original()
    if characterization:
        controller_characterization_post_host(catalogue, {"controllerCheckInputs": check_inputs})
        executable_copy = next(row for row in _CONTROLLER_CHARACTERIZATION_STAGE["copies"]
                               if str(row["path"]) == PYTHON_EXECUTABLE)
        need(read(PYTHON_EXECUTABLE, 16 * MIB)[1] == executable_copy["original"],
             "controller-characterization-executable-before-mode")
    else:
        need(controller_check_ready(catalogue) == check_inputs, "controller-bootstrap-check-inputs-postcheck")
    os.chmod(PYTHON_EXECUTABLE, 0o555)
    if characterization:
        pin = read(PYTHON_EXECUTABLE, 16 * MIB)[1]
        previous = executable_copy["original"]
        need(pin["sha256"] == previous["sha256"] and pin["mode"] == "0o555"
             and all(pin["identity"][i] == previous["identity"][i] for i in (0, 1, 3, 4, 5, 6, 7)),
             "controller-characterization-executable-mode-transition")
        executable_copy["original"] = pin
    for row in reversed(runtime["projection"]["directories"]):
        os.chmod(PYTHON_ROOT / row["path"], 0o555)
    if characterization:
        _CONTROLLER_CHARACTERIZATION_STAGE["enabled"] = True
    projection = controller_runtime_roster(runtime, readonly=False)
    need(all(directory_custody(Path(row["path"]).lstat()) == row["custody"] for row in parents),
         "controller-bootstrap-parent-replaced")
    receipt = {"schema": CONTROLLER_CHARACTERIZATION_ORIGINALS if characterization else CONTROLLER_ORIGINALS_SCHEMA, **context,
        "controllerCatalogueSha256": CONTROLLER_RUNTIME_SHA256, "sourceCatalogue": catalogue_pin,
        "unpackHelper": helper_pin, "providerPython": provider_pin, "artifact": artifact,
        "preparedRuntime": prepared, "projection": projection, "parents": parents,
        "sourceBinding": source_binding, "controllerCheckInputs": check_inputs,
        "pythonPycache": pycache_original(), "readonlyMountRequiredBeforePrivateStartup": True,
        "retirement": "disposable-vm-only"}
    write(PYTHON_ORIGINALS, canonical(receipt))
    need(controller_runtime_roster(runtime, readonly=False) == projection,
         "controller-bootstrap-staged-original-changed")
    # The workflow's fixed trusted bind/remount-ro follows. This receipt does
    # not pretend that it has already happened or that the provider was absent.
    controller_source_finish()
    pycache_finish()
    if not characterization:
        print("GNOME_HOSTED_CONTROLLER_RUNTIME_STAGED=598-files;readonly-mount-still-required", flush=True)


def controller_runtime_original():
    state = _PYTHON_RUNTIME
    need(state is not None and not state["closed"] and len(state["fds"]) == 3
         and state["receipt"] is not None, "controller-runtime-original-required")
    receipt = state["receipt"]
    for index, row in enumerate(receipt["parents"]):
        actual = os.fstat(state["fds"][index])
        named = Path(row["path"]).lstat()
        need(directory_custody(actual) == directory_custody(named) == row["custody"],
             "controller-runtime-parent-replaced")
    leaf = os.fstat(state["fds"][-1])
    need(identity(leaf) == identity(PYTHON_ROOT.lstat()) == receipt["projection"]["rootIdentity"]
         and os.fstatvfs(state["fds"][-1]).f_flag & os.ST_RDONLY, "controller-runtime-root-replaced-or-writable")
    need(read(PYTHON_ORIGINALS, MIB)[1] == state["receiptPin"]
         and controller_runtime_roster(state["runtime"], readonly=True) == receipt["projection"],
         "controller-runtime-original-changed")
    return receipt["projection"]


def controller_runtime_begin(context, catalogue):
    return _controller_runtime_begin(context, catalogue, CONTROLLER_ORIGINALS_SCHEMA)


def controller_characterization_runtime_begin(context, catalogue):
    controller_characterization_binding(context)
    return _controller_runtime_begin(context, catalogue, CONTROLLER_CHARACTERIZATION_ORIGINALS)


def _controller_runtime_begin(context, catalogue, originals_schema):
    global _PYTHON_RUNTIME
    need(_PYTHON_RUNTIME is None, "controller-runtime-phase-already-started")
    state = {"fds": [], "receipt": None, "receiptPin": None, "closed": False, "closeFailed": False,
             "runtime": catalogue["controllerRuntime"]}
    _PYTHON_RUNTIME = state  # Partial handles are owned before first fstat.
    _EVIDENCE["controllerRuntime"] = {"path": str(PYTHON_ROOT), "sourceProjectionSha256":
        state["runtime"]["projectionSha256"], "originalsSha256": None,
        "phaseCustodyPostchecked": False, "phaseHandlesClosed": False,
        "startupAuthority": "explicit-provider-DATA-staging-and-readonly-mount-before-private-startup",
        "retirement": "leave-readonly-for-disposable-vm-only"}
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    state["fds"].append(fd)
    for part in ("run", PYTHON_ROOT.name):
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
             "controller-runtime-protected-parent")
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        state["fds"].append(fd)
    stage = PYTHON_STAGE.lstat()
    need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == stage.st_gid == 0
         and stat.S_IMODE(stage.st_mode) == 0o700, "controller-runtime-original-stage")
    raw, pin = read(PYTHON_ORIGINALS, MIB)
    receipt = decode(raw)
    need(pin["mode"] == "0o400" and receipt["schema"] == originals_schema
         and all(receipt.get(key) == value for key, value in context.items())
         and receipt["controllerCatalogueSha256"] == CONTROLLER_RUNTIME_SHA256
         and receipt["readonlyMountRequiredBeforePrivateStartup"] is True
         and receipt["retirement"] == "disposable-vm-only", "controller-runtime-staging-binding")
    need(receipt["sourceCatalogue"] == read(SOURCE / CONTROL / "runtime-suppliers.json", 16 * MIB, root=False)[1]
         and receipt["unpackHelper"] == read(SOURCE / "desktop/tools/conventional_runtime_data.py", 19198, root=False)[1],
         "controller-runtime-bootstrap-source-changed")
    state["receipt"], state["receiptPin"] = receipt, pin
    projection = controller_runtime_original()
    for row in projection["files"]:
        need(row["path"] not in _PINS, "controller-runtime-duplicate-original")
        _PINS[row["path"]] = {key: row[key] for key in ("identity", "bytes", "sha256", "mode")}
    need(str(PYTHON_ORIGINALS) not in _PINS, "controller-runtime-duplicate-receipt")
    _PINS[str(PYTHON_ORIGINALS)] = pin
    _EVIDENCE["controllerRuntime"]["originalsSha256"] = pin["sha256"]


def controller_runtime_binding():
    return {"catalogueSha256": CONTROLLER_RUNTIME_SHA256,
            "originals": _PYTHON_RUNTIME["receiptPin"], "projection": controller_runtime_original(),
            "builtins": list(PYTHON_BUILTINS), "searchPath": list(PYTHON_SEARCH)}


def controller_runtime_finish(*, failed=False):
    global _ORIGINALS_SETTLED
    state = _PYTHON_RUNTIME
    if state is None or state["closed"]:
        need(failed or state is not None and _EVIDENCE["controllerRuntime"]["phaseHandlesClosed"],
             "controller-runtime-phase-not-closed")
        return
    body_error, close_failed = None, state.get("closeFailed", False)
    try:
        if state["receipt"] is not None:
            controller_runtime_original()
            _EVIDENCE["controllerRuntime"]["phaseCustodyPostchecked"] = True
        need(failed or _ORIGINALS_SETTLED, "controller-runtime-consuming-originals-unsettled")
    except BaseException as error:
        body_error = error
    finally:
        state["closed"] = True
        while state["fds"]:
            fd = state["fds"].pop()
            try:
                os.close(fd)
            except BaseException:
                close_failed = True
                _ORIGINALS_SETTLED = False
        close_failed = close_failed or state.get("closeFailed", False)
        _EVIDENCE["controllerRuntime"]["phaseHandlesClosed"] = not close_failed
    if not failed:
        if body_error is not None:
            raise body_error
        need(not close_failed, "controller-runtime-close-unknown")


def phase_finish(*, failed=False):
    """Independent custody chains close once; none can mask first failure."""
    first = None
    for finish in (controller_runtime_finish, pycache_finish, controller_source_finish):
        try:
            finish(failed=failed)
        except BaseException as error:
            if first is None:
                first = error
    if first is not None and not failed:
        raise first



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
         and sys.version_info[:3] == (3, 14, 7) and sys.implementation.name == "cpython"
         and sys.implementation.cache_tag == "cpython-314" and tuple(sorted(sys.builtin_module_names)) == PYTHON_BUILTINS
         and sys.prefix == sys.base_prefix == sys.exec_prefix == sys.base_exec_prefix == str(PYTHON_ROOT / "python")
         and sys.flags.isolated and sys.flags.no_site and sys.flags.optimize == 0
         and sys.dont_write_bytecode and type(sys.pycache_prefix) is str
         and sys.pycache_prefix == str(PYTHON_PYCACHE), "actual-python-runtime-selection")
    original = pycache_original()
    controller_runtime_original()
    need(_PYTHON_RUNTIME["receipt"]["pythonPycache"] == original, "controller-runtime-pycache-original")
    spec = importlib.util.find_spec("_ctypes")
    need(spec is not None and spec.origin == "built-in", "controller-runtime-ctypes-not-builtin")
    root_absent("/usr/lib/python312.zip", "old-python-zip")
    # Startup was source-bound provider DATA + a readonly mount, not a later
    # retroactive assertion. C/AW propagates this executable and exact -X policy.
    _EVIDENCE["pythonRuntime"] = {"executable": PYTHON_EXECUTABLE, "searchPath": list(PYTHON_SEARCH),
        "bytecodePolicy": "complete-no-pyc-private-projection; fixed-empty-normal-source-cache; writes-disabled",
        "pycachePrefix": str(PYTHON_PYCACHE),
        "pycacheOriginalSha256": hashlib.sha256(canonical(original)).hexdigest(),
        "sourcelessOrZipExecutionDisabled": False, "emptyZipPresentAndPinned": True,
        "ctypes": "static-builtin", "builtinModules": 60,
        "oldCachesPhysicallyInaccessible": False,
        "ownerOldProfileExclusion": "required-before-startup-readonly-masks-and-actual-original-checks",
        "controllerRuntimeOriginalsSha256": _PYTHON_RUNTIME["receiptPin"]["sha256"], **counts}



def authenticate_host(catalogue, *, after=False):
    authenticate_absent_host_inputs(catalogue)
    # This is actual payload correspondence, never a version-string substitute.
    for row in catalogue["hostFiles"]:
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
               "controllerRuntime": controller_runtime_binding(),
               "workflowOuterRootIdentity": identity(outer), "startedMonotonic": time.monotonic(),
               "workflowDeadlineMonotonic": time.monotonic() + 1800}
    binding_pin = write(TASK / "controls/source-binding.json", canonical(binding))
    record_source_evidence(binding, binding_pin["sha256"])
    write(TASK / "controls/host-tool-originals.json", canonical(_PINS))
    module, host = host_module(catalogue)
    before, after = reserve_host(host, deadline)
    phase_finish()
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
    need(binding["controllerRuntime"] == controller_runtime_binding(), "source-binding-controller-runtime-changed")
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
    expected = _PYTHON_RUNTIME["receipt"]["pythonPycache"]
    need(type(expected) is dict, "pycache-first-phase-original-required")
    if phase != "supply-bwrap":
        stage = bwrap_stage_identity()
        raw, pin = read(BWRAP_SUPPLY / "before.json", 16 * MIB)
        before = decode(raw)
        need(pin["mode"] == "0o400" and before["schema"] == BWRAP_SUPPLY_SCHEMA
             and all(before.get(key) == value for key, value in context.items())
             and before["stageIdentity"] == stage, "pycache-first-phase-control")
        need(before["pythonPycache"] == expected and type(expected) is dict,
             "pycache-first-phase-original-required")
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
        phase_finish()
        receipt = {"schema": BWRAP_SUPPLY_SCHEMA, **context, "phase": "supply-bwrap",
                   "passed": True, "originalsSettled": True, "parentHandlesClosed": True,
                   "nativeQualified": False, "supplierContractSha256": BWRAP_SUPPLIER_SHA256,
                   "beforeSha256": before_pin["sha256"], "installed": installed,
                   "parentAfter": parent_after, "inputOriginals": inputs,
                   "pythonPycache": before["pythonPycache"], "pythonPycacheHandlesClosed": True,
                   "controllerRuntimeHandlesClosed": _EVIDENCE["controllerRuntime"]["phaseHandlesClosed"],
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
         and receipt["pythonPycacheHandlesClosed"] is True and receipt["controllerRuntimeHandlesClosed"] is True
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
    gcc = [member for row in catalogue["nativePackages"] for member in row["members"]
           if member["member"] == CARGO_LIBGCC]
    need(len(gcc) == 1 and gcc[0]["target"] == "native/09"
         and CARGO_LIBRARY_ROOT + "libgcc_s.so.1" not in set(libraries) | seen, "cargo-private-libgcc-source")
    mounts = [(path, path) for path in libraries + data]
    mounts.append((str(TASK / "inputs" / gcc[0]["target"]), "/" + CARGO_LIBGCC))
    return {"files": mounts, "aliases": [*CARGO_ROOT_ALIASES, *((row["path"], row["target"]) for row in aliases)],
            "hostFiles": sorted(libraries + data + [str(BWRAP_TARGET)])}


def cargo_resolver_data(catalogue):
    """One exact, non-executable DATA source; never relax read(root=True).

    The last parent is owned by the fixed resolver service, not by root. These
    exact parent predicates are requirements, NOT an assertion that an earlier
    observation proved them. The catalogue keeps that missing fact unresolved.
    Only a protected root-owned snapshot is visible to Cargo.
    """
    global _ORIGINALS_SETTLED
    row = catalogue["cargoAcquisition"]["resolverData"]
    need(row.get("role") == "cargo-acquisition-resolver-snapshot-only"
         and all(row.get(key) == value for key, value in CARGO_RESOLVER.items()), "cargo-resolver-data-contract")
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
    phase_finish()
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


def owner_startup_guard():
    """Bash is already an admitted role; the guard precedes private Python."""
    runtime = controller_runtime_original()
    zip_pin = next(row["identity"] for row in runtime["files"] if row["path"] == PYTHON_SEARCH[0])
    cache_pin = pycache_original()["identity"]
    def stat_token(pin):
        need(type(pin) is list and len(pin) == 9 and all(type(value) is int and value >= 0 for value in pin),
             "owner-mask-original-identity")
        return ":".join([str(pin[0]), str(pin[1]), format(pin[2], "x"), *map(str, pin[3:7])])
    script = r'''set -euo pipefail
zip_original="$1"; cache_original="$2"; shift 2
[[ "$#" -eq 7 && "$1" == /run/mrk-gnome-controller-runtime-v2/python/bin/python3 ]]
[[ -L /bin && -L /lib && -L /usr/bin/python3 && ! -L /usr/bin/python3.12 ]]
for path in /run/mrk-gnome-controller-runtime-v2/python/lib/python314.zip /usr/bin/python3.12 /usr/bin/python3 /bin/python3.12 /bin/python3; do
    [[ -f "$path" && ! -x "$path" ]]
    [[ "$(/usr/bin/stat --dereference --printf='%d:%i:%f:%h:%u:%g:%s' -- "$path")" == "$zip_original" ]]
done
for path in /run/mrk-gnome-python-empty-pycache-v1 /usr/lib/python3.12 /lib/python3.12; do
    [[ -d "$path" && ! -L "$path" ]]
    [[ "$(/usr/bin/stat --dereference --printf='%d:%i:%f:%h:%u:%g:%s' -- "$path")" == "$cache_original" ]]
done
[[ ! -e /usr/lib/python312.zip && ! -L /usr/lib/python312.zip ]]
runtime_ro=0; zip_ro=0; stdlib_ro=0; cache_ro=0; records=0
while IFS=' ' read -r mount_id parent_id device root point options rest; do
    (( ++records <= 4096 ))
    case "$point" in
      /run/mrk-gnome-controller-runtime-v2) [[ ",$options," == *,ro,* ]]; (( ++runtime_ro == 1 ));;
      /usr/bin/python3.12) [[ ",$options," == *,ro,* ]]; (( ++zip_ro == 1 ));;
      /usr/lib/python3.12) [[ ",$options," == *,ro,* ]]; (( ++stdlib_ro == 1 ));;
      /run/mrk-gnome-python-empty-pycache-v1) [[ ",$options," == *,ro,* ]]; (( ++cache_ro == 1 ));;
    esac
done </proc/self/mountinfo
(( runtime_ro == 1 && zip_ro == 1 && stdlib_ro == 1 && cache_ro == 1 ))
exec /usr/bin/env -i PATH=/usr/bin:/bin HOME=/tmp TMPDIR=/tmp LANG=C LC_ALL=C TZ=UTC PWD=/tmp "$@"
'''
    return ["/usr/bin/bash", "--noprofile", "--norc", "-c", script, "mrk-private-python-mask-guard",
            stat_token(zip_pin), stat_token(cache_pin)]



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
            "--dir", "/run", "--ro-bind", str(PYTHON_PYCACHE), str(PYTHON_PYCACHE),
            "--ro-bind", str(PYTHON_ROOT), str(PYTHON_ROOT),
            "--ro-bind", PYTHON_SEARCH[0], "/usr/bin/python3.12",
            "--ro-bind", str(PYTHON_PYCACHE), "/usr/lib/python3.12",
            "--ro-bind", str(PYTHON_ORIGINALS), "/controller-runtime-originals.json"]
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
             *owner_startup_guard(), PYTHON_EXECUTABLE, "-I", "-S", "-B", "-X",
             "pycache_prefix=/run/mrk-gnome-python-empty-pycache-v1", "/owner.py"]
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
    need(type(report.get("controllerRuntimeInputsExpected")) is int
         and report.get("controllerRuntimeInputsPrechecked") == report.get("controllerRuntimeInputsPostchecked")
             == report["controllerRuntimeInputsExpected"] == 598, "owner-controller-runtime-post-accounting")
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
                   ("stagedInputsPreNativeChecked", "runtimeInputsPrechecked", "runtimeInputsPostchecked", "runtimeInputsExpected",
                    "controllerRuntimeInputsPrechecked", "controllerRuntimeInputsPostchecked", "controllerRuntimeInputsExpected")},
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
    phase_finish()
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
    phase_finish()
    write(PUBLIC / "result.json", canonical({**context, "fullTree": binding["fullTree"], "phase": "settle",
          "passed": True, "originalStepSuccess": True, "originalOutputWritersClosed": True,
          "originalsSettled": True, "entrySmokePassed": True, "freshCompileCount": 1, "nativeCasesPassed": 7,
          "host": value["host"], "disposedTaskInputBytes": removed, "nativeArtifactExported": False,
          "sessionTransportQualified": True, "persistentQualified": False, "installedProviderQualified": False,
          "guiQualified": False, "desktopReady": False, "evidence": public_evidence()}), 0o444)


def controller_check_stdio():
    # scandir owns one temporary descriptor. Check its closure before admission;
    # opening a second directory FD would itself pollute this initial roster.
    with os.scandir("/proc/self/fd") as stream:
        names = []
        for entry in stream:
            need(len(names) < 4, "controller-check-inherited-fd-bound")
            names.append(entry.name)
    need(sorted(names) == ["0", "1", "2", "3"], "controller-check-stdio-only")
    try:
        os.fstat(3)
    except OSError as error:
        need(error.errno == 9, "controller-check-fd-scan-close-unknown")
    else:
        raise Refused("controller-check-fd-scan-not-closed")
    stdin = os.fstat(0)
    need(stat.S_ISCHR(stdin.st_mode) and stdin.st_rdev == os.makedev(1, 3), "controller-check-fixed-stdin")
    for fd, name in ((1, "stdout"), (2, "stderr")):
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_size == 0 and identity(info) == identity((CONTROLLER_CHECK_ROOT / name).lstat()),
             "controller-check-fixed-stdio-original")


def controller_module_origins(receipt, extras=()):
    """Every live/imported module belongs to this GN source or supplied Python."""
    allowed = {str(CONTROLLER_CHECK_SOURCE / name): pin for name, pin in receipt["sourceBinding"]["originals"]["files"].items()}
    allowed.update({row["path"]: row for row in receipt["projection"]["files"]})
    modules = [(name, module) for name, module in tuple(sys.modules.items()) if module is not None]
    modules += [(module.__name__, module) for module in extras]
    records = []
    for name, module in modules:
        spec, filename = getattr(module, "__spec__", None), getattr(module, "__file__", None)
        origin = getattr(spec, "origin", None)
        if origin == "built-in":
            need(name in PYTHON_BUILTINS, "controller-check-foreign-builtin")
        elif origin == "frozen":
            need(spec.loader is importlib.machinery.FrozenImporter
                 and (filename is None or filename in allowed), "controller-check-foreign-frozen-module")
        else:
            need(type(filename) is str and filename in allowed
                 and (origin == filename or name == "__main__" and origin is None),
                 "controller-check-foreign-module-origin")
            need(read(filename, 32 * MIB, root=False)[1] == {
                 key: allowed[filename][key] for key in ("identity", "bytes", "sha256", "mode")},
                 "controller-check-module-original-changed")
        records.append({"module": name, "origin": origin if origin in ("built-in", "frozen") else filename})
    need(tuple(sys.path) == PYTHON_SEARCH, "controller-check-search-path-not-restored")
    return sorted(records, key=lambda row: (row["module"], str(row["origin"])))



def controller_check_mappings(receipt):
    return _controller_collect_mappings(receipt, characterization=False)


def controller_characterization_mappings(receipt):
    need(receipt.get("schema") == CONTROLLER_CHARACTERIZATION_ORIGINALS,
         "controller-characterization-mapping-receipt")
    return _controller_collect_mappings(receipt, characterization=True)


def _controller_mapping_rows(receipt, rows, *, characterization):
    selected = receipt["controllerCheckInputs"]
    wanted = {path: selected["files"][path] for path in selected["mappedHostFiles"]}
    runtime_files = {row["path"]: row for row in receipt["projection"]["files"]}
    private = {str(PYTHON_ROOT / name) for name in
               ("python/bin/python3", "python/lib/libcrypto.so.3", "python/lib/libssl.so.3")}
    wanted.update({path: runtime_files[path] for path in private})
    if characterization:
        need(selected["mappedHostFiles"] == sorted(CONTROLLER_CHARACTERIZATION_HOSTS),
             "controller-characterization-mapping-ceiling")
        required = set(CONTROLLER_CHARACTERIZATION_REQUIRED) | private
    else:
        required = set(wanted)
    need(type(rows) is list and 0 < len(rows) <= 1024, "controller-check-mapping-bound")
    seen, executable = set(), set()
    for fields in rows:
        need(type(fields) is list and 5 <= len(fields) <= 6 and all(type(value) is str for value in fields)
             and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", fields[0])
             and re.fullmatch(r"[r-][w-][x-][ps]", fields[1])
             and re.fullmatch(r"[0-9a-f]+", fields[2])
             and re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", fields[3])
             and re.fullmatch(r"[0-9]+", fields[4]), "controller-check-mapping-shape")
        path, executes = fields[5] if len(fields) == 6 else "", fields[1][2] == "x"
        need(not executes or fields[1][1] != "w", "controller-check-writable-executable-mapping")
        if path.startswith("/"):
            need(path in wanted, "controller-check-foreign-mapped-provider")
            device, inode = wanted[path]["identity"][:2]
            need(fields[3] == format(os.major(device), "02x") + ":" + format(os.minor(device), "02x")
                 and fields[4] == str(inode), "controller-check-mapped-provider-original")
            seen.add(path)
            if executes:
                executable.add(path)
        else:
            need(path in ("", "[heap]", "[stack]", "[vvar]", "[vvar_vclock]", "[vdso]", "[vsyscall]")
                 and fields[4] == "0" and fields[3] == "00:00", "controller-check-foreign-anonymous-mapping")
            need(not executes or path in ("[vdso]", "[vsyscall]"), "controller-check-anonymous-executable-mapping")
    need(required <= seen <= set(wanted) and (characterization or seen == set(wanted)),
         "controller-check-mapped-provider-closure")
    need(executable == seen, "controller-check-provider-executable-coverage")
    return sorted(seen)


def _controller_collect_mappings(receipt, *, characterization):
    raw = controller_proc("/proc/self/maps", CONTROLLER_CHECK_LIMIT)
    rows = [line.split(None, 5) for line in raw.decode("ascii").splitlines()]
    files = _controller_mapping_rows(receipt, rows, characterization=characterization)
    # Raw rows and addresses never leave the bounded, private stdout file.
    return {"sha256": hashlib.sha256(raw).hexdigest(), "rows": rows, "files": files}


class ControllerCheckAudit:
    """Absorbing effect refusal around exact pinned calls, NOT a ctypes sandbox."""
    def __init__(self, receipt):
        source = receipt["sourceBinding"]
        self.reads = {str(Path(root) / name) for root in (source["originalRoot"], source["viewRoot"])
                      for name in source["originals"]["files"]}
        self.reads.update(row["path"] for row in receipt["projection"]["files"])
        self.reads.update(receipt["controllerCheckInputs"]["files"])
        self.reads.update((str(PYTHON_ORIGINALS), "/proc/self/maps", "/proc/self/mountinfo"))
        self.directories = {str(Path(root) / row["relative"]) for root in (source["originalRoot"], source["viewRoot"])
                            for row in source["originals"]["directories"]}
        self.directories.update(row["path"] for row in receipt["projection"]["directories"])
        # Mandatory host POST retains these exact paths/full identities, not a /usr prefix.
        self.directories.update(row["path"] for row in receipt["controllerCheckInputs"]["directories"])
        self.directories.update((str(OUTER), str(PYTHON_PYCACHE)))
        self.reads.update(self.directories)
        self.directory_ids = [row["identity"] for row in source["originals"]["directories"]]
        self.directory_ids.extend(row["identity"] for row in receipt["projection"]["directories"])
        self.directory_ids.extend(row["identity"] for row in receipt["controllerCheckInputs"]["directories"])
        self.directory_ids.extend((source["nativeOuter"], receipt["pythonPycache"]["identity"]))
        # CPython may try its normal source-cache path even with -B. Only exact
        # derivations from pinned sources are allowed; the retained cache is
        # empty PRE/POST, and no sourceless/cache origin is admitted.
        self.reads.update(importlib.util.cache_from_source(path) for path in tuple(self.reads) if path.endswith(".py"))
        self.first = None
        self.stage = "audit-install"
        self.denial = None
        self.native_code = None
        self.native_window = False
        self.native_handles = 0
        self.python_handles = 0
        self.symbols = []
        self.contract_window = False
        self.environment = dict(os.environ)

    def reject(self, rule, *, event=None):
        if self.first is None:
            self.first = "controller-check-effect-denied"
            try:
                # Only a closed label survives. Classification/allocation cannot
                # replace the original refusal, even if this metadata is lost.
                if event is not None:
                    rule = _CONTROLLER_AUDIT_FAMILIES[event.partition(".")[0]]
                self.denial = {"stage": self.stage, "rule": rule}
            finally:
                raise Refused(self.first)
        raise Refused(self.first)

    def from_code(self, code):
        frame = sys._getframe(1)
        for _ in range(12):
            if frame is None:
                return False
            if frame.f_code is code:
                return True
            frame = frame.f_back
        return False

    def __call__(self, event, args):
        if event == "open":
            path, mode, flags = args
            # Preserve the original ordered disjuncts, each evaluated once.
            if type(path) is not str:
                self.reject("open-path-type")
            elif path not in self.reads:
                self.reject("open-path-set")
            elif type(flags) is not int:
                self.reject("open-flags-type")
            elif flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                self.reject("open-write-flags")
        elif event in ("os.listdir", "os.scandir"):
            target = args[0]
            if type(target) is int:
                if identity(os.fstat(target)) not in self.directory_ids:
                    self.reject("directory-fd-identity")
            elif type(target) is not str or target not in self.directories:
                self.reject("directory-target")
        elif event in ("os.putenv", "os.unsetenv"):
            key = args[0].decode("ascii") if type(args[0]) is bytes else args[0]
            # The one real test intentionally patches/restores this process's
            # own environment; never a child environment or an account change.
            if not self.contract_window:
                self.reject("environment-window")
            elif key not in set(self.environment) | {"PYTHONPYCACHEPREFIX"}:
                self.reject("environment-key")
        elif event == "ctypes.dlopen":
            if args != (None,):
                self.reject("loader-name")
            frame = sys._getframe(1)
            python_api = False
            for _ in range(8):
                if frame is None:
                    break
                python_api |= (frame.f_code.co_filename == PYTHON_STDLIB + "/ctypes/__init__.py"
                               and frame.f_code.co_name == "<module>")
                frame = frame.f_back
            if python_api:
                self.python_handles += 1
                if self.python_handles != 1:
                    self.reject("loader-python-count")
            elif self.native_window and self.from_code(self.native_code):
                self.native_handles += 1
                if self.native_handles != 1:
                    self.reject("loader-native-count")
            else:
                self.reject("loader-callsite")
        elif event == "ctypes.dlsym":
            if not self.native_window:
                self.reject("symbol-window")
            elif not self.from_code(self.native_code):
                self.reject("symbol-callsite")
            elif len(args) != 2:
                self.reject("symbol-shape")
            elif args[1] not in CONTROLLER_CHECK_SYMBOLS:
                self.reject("symbol-not-admitted")
            elif args[1] in self.symbols:
                self.reject("symbol-duplicate")
            self.symbols.append(args[1])
        elif event.startswith(("ctypes.", "socket.", "subprocess.", "pty.", "shutil.", "tempfile.")):
            self.reject(None, event=event)
        elif event in ("os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty", "os.kill", "os.killpg",
                       "os.startfile", "os.chdir", "os.fchdir", "os.chmod", "os.chown", "os.chroot", "os.truncate",
                       "os.link", "os.symlink", "os.rename", "os.remove", "os.rmdir", "os.mkdir", "os.utime",
                       "os.setxattr", "os.removexattr", "os.setuid", "os.setgid", "os.setgroups",
                       "os.setresuid", "os.setresgid", "os.setreuid", "os.setregid", "os.unshare", "os.setns",
                       "_thread.start_new_thread", "_thread.start_joinable_thread", "builtins.input"):
            self.reject(None, event=event)
        # Once caught, a denial remains failed even if a dependency consumes the
        # exception. Read-only POST/stdio still run; there is no reset API.


def controller_audit_diagnostic(body):
    """Closed failure DATA only; never event arguments or a success authority."""
    code = "controller-check-audit-diagnostic-shape"
    need(type(body) is dict and type(body.get("passed")) is bool
         and type(body.get("auditDenied")) is bool and "auditDenial" in body, code)
    denial = body["auditDenial"]
    if not body["auditDenied"]:
        need(denial is None, code)
        return None
    need(body["passed"] is False and type(denial) is dict and set(denial) == {"stage", "rule"}
         and type(denial["stage"]) is str and denial["stage"] in CONTROLLER_AUDIT_STAGES
         and type(denial["rule"]) is str and denial["rule"] in CONTROLLER_AUDIT_RULES, code)
    # bodyPassed may be true: the first denial can occur in the retained POST.
    result = {"stage": denial["stage"], "rule": denial["rule"]}
    need(len(canonical(result)) <= 256, code)
    return result


def controller_load_module(name, relative):
    path = CONTROLLER_CHECK_SOURCE / relative
    need(name not in sys.modules, "controller-check-module-name-occupied")
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "controller-check-source-loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def controller_tar_compatibility():
    import io
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("controller-runtime.txt")
        member.size, member.mode, member.mtime = 3, 0o644, 0
        archive.addfile(member, io.BytesIO(b"GN\n"))
    raw = buffer.getvalue()
    need(len(raw) == 10240, "controller-check-memory-tar-bound")
    for mode in ("r:", "r|"):
        with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as archive:
            iterator = iter(archive)
            member = next(iterator)
            need(member.name == "controller-runtime.txt" and member.isfile() and member.size == 3,
                 "controller-check-memory-tar-member")
            with archive.extractfile(member) as stream:
                need(stream.read(4) == b"GN\n" and stream.read(1) == b"", "controller-check-memory-tar-data")
            need(next(iterator, None) is None, "controller-check-memory-tar-extra")
    return ["r:", "r|"]


def controller_run_contract(module):
    import io
    import unittest
    suite = unittest.TestLoader().loadTestsFromName(CONTROLLER_CHECK_TEST, module)
    need(suite.countTestCases() == 1, "controller-check-exact-one-contract")
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0, failfast=True).run(suite)
    need(result.testsRun == 1 and result.wasSuccessful() and not any((
         result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses)),
         "controller-check-contract-not-clean")
    return {"id": CONTROLLER_CHECK_TEST, "testsRun": 1, "failures": 0, "errors": 0,
            "skips": 0, "expectedFailures": 0, "unexpectedSuccesses": 0, "failfast": True}


def controller_check_body(receipt, state):
    return _controller_fixed_check_body(receipt, state, controller_check_mappings)


def controller_characterization_body(receipt, state):
    return _controller_fixed_check_body(receipt, state, controller_characterization_mappings)


def _controller_fixed_check_body(receipt, state, mapping_reader):
    need(tuple(sys.path) == PYTHON_SEARCH, "controller-check-original-search")
    state["originsBefore"] = controller_module_origins(receipt)
    state["mappingsBefore"] = mapping_reader(receipt)
    audit = ControllerCheckAudit(receipt)
    state["audit"] = audit
    sys.addaudithook(audit)
    audit.stage = "load-carrier"
    modules = [controller_load_module("_mrk_controller_check_carrier", "desktop/tools/gnome_session_hosted.py")]
    audit.stage = "load-host"
    modules.append(controller_load_module("_mrk_controller_check_host", CONTROL + "host-admit.py"))
    audit.stage = "load-owner"
    modules.append(controller_load_module("_mrk_controller_check_owner", CONTROL + "owner.py"))
    audit.stage = "load-data"
    modules.append(controller_load_module("_mrk_controller_check_data", "desktop/tools/conventional_runtime_data.py"))
    audit.stage = "load-core"
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(CONTROLLER_CHECK_SOURCE / "src"))
        from mobile_release import owned_process, _command_process, _native_process
    finally:
        sys.path[:] = previous
    modules.extend((owned_process, _command_process, _native_process))
    # These two files execute top-level work. Their exact text is compiled
    # ONLY: never imported, exec'd, or dispatched to a main.
    for stage, relative in (("compile-prepare", CONTROL + "prepare.py"), ("compile-check", CONTROL + "check-compile.py")):
        audit.stage = stage
        path = CONTROLLER_CHECK_SOURCE / relative
        raw, _ = read(path, MIB, root=False)
        compile(raw, str(path), "exec", dont_inherit=True, optimize=0)
    state["compiledOnly"] = ["prepare.py", "check-compile.py"]
    audit.stage = "memory-tar"
    state["tarModes"] = controller_tar_compatibility()
    audit.stage = "native-abi"
    audit.native_code = _native_process._Native.__init__.__code__
    audit.native_window = True
    try:
        native = _native_process._Native()
    finally:
        audit.native_window = False
    # The unchanged constructor's only C call is gnu_get_libc_version. Symbol
    # resolution is not permission to call Acquisition, .call, spawn or libc.
    need(audit.native_handles == 1 and set(audit.symbols) == CONTROLLER_CHECK_SYMBOLS
         and len(audit.symbols) == len(CONTROLLER_CHECK_SYMBOLS)
         and native.abi.family == "linux-glibc" and native.abi.architecture == "x86_64",
         "controller-check-actual-native-admission")
    state["nativeAdmission"] = {"abi": _native_process._abi_record(native.abi),
                               "publicSymbols": sorted(audit.symbols), "onlyLibcCall": "gnu_get_libc_version"}
    audit.stage = "load-contract"
    contract = controller_load_module("_mrk_controller_check_contract", "tests/desktop/test_gnome_session_hosted_contract.py")
    modules.extend((contract, contract.C, contract.H, contract.N))
    state["modules"], state["nativeRoot"] = modules, native
    need(contract.C is not sys.modules["__main__"] and contract.C not in modules[:3]
         and contract.C._PINS is not _PINS and contract.C._EVIDENCE is not _EVIDENCE
         and contract.C._PYTHON_RUNTIME is None and contract.C._PYCACHE is None,
         "controller-check-test-custody-not-separate")
    originals = (_PYTHON_RUNTIME, _PYCACHE, _CONTROLLER_SOURCE, _PINS)
    audit.stage = "run-contract"
    audit.contract_window = True
    try:
        state["contract"] = controller_run_contract(contract)
    finally:
        audit.contract_window = False
    audit.stage = "body-final"
    need(all(left is right for left, right in zip(originals, (_PYTHON_RUNTIME, _PYCACHE, _CONTROLLER_SOURCE, _PINS)))
         and dict(os.environ) == audit.environment, "controller-check-test-mutated-live-custody")
    need(audit.first is None, "controller-check-effect-denied")
    return True



def controller_failure(state, role, error):
    failure = {"role": role, "refusal": refusal_code(error)}
    if state["firstFailure"] is None:
        state["firstFailure"] = failure
    state["errors"].append(failure)


def controller_attempt(state, role, action):
    try:
        value = action()
        state["post"][role] = True
        return value
    except BaseException as error:
        state["post"][role] = False
        controller_failure(state, role, error)
        return None


def controller_staging_receipt(context):
    return _controller_staging_receipt(context, characterization=False)


def controller_characterization_staging_receipt(context):
    controller_characterization_binding(context)
    return _controller_staging_receipt(context, characterization=True)


def _controller_staging_receipt(context, *, characterization):
    stage = PYTHON_STAGE.lstat()
    need(stat.S_ISDIR(stage.st_mode) and stage.st_uid == stage.st_gid == 0
         and stat.S_IMODE(stage.st_mode) == 0o700, "controller-check-original-stage")
    raw, pin = read(PYTHON_ORIGINALS, MIB)
    receipt = decode(raw)
    need(pin["mode"] == "0o400" and receipt["schema"] == (CONTROLLER_CHARACTERIZATION_ORIGINALS if characterization else CONTROLLER_ORIGINALS_SCHEMA)
         and all(receipt.get(key) == value for key, value in context.items())
         and receipt["controllerCatalogueSha256"] == CONTROLLER_RUNTIME_SHA256
         and receipt["readonlyMountRequiredBeforePrivateStartup"] is True
         and receipt["retirement"] == "disposable-vm-only"
         and receipt["sourceBinding"]["viewRoot"] == str(CONTROLLER_CHECK_SOURCE)
         and ((characterization and receipt["controllerCheckInputs"].get("authority") == CONTROLLER_CHARACTERIZATION_AUTHORITY
               and receipt["controllerCheckInputs"].get("complete") is True)
              or (not characterization
                  and receipt["controllerCheckInputs"]["catalogueSha256"] == CONTROLLER_CHECK_HOST_SHA256)),
         "controller-check-staging-binding")
    return receipt


def controller_post_host(catalogue, receipt):
    need(controller_check_ready(catalogue) == receipt["controllerCheckInputs"],
         "controller-check-host-originals-changed")


def controller_finish_check(state):
    # phase_finish attempts all independent held chains even on the first
    # exception. A POST/close cannot replace an earlier body failure.
    try:
        phase_finish(failed=state["firstFailure"] is not None)
    except BaseException as error:
        controller_failure(state, "finish", error)
    for role, evidence in (("runtime", _EVIDENCE.get("controllerRuntime")),
                           ("cache", _EVIDENCE.get("pythonPycache"))):
        ok = (evidence is not None and evidence["phaseCustodyPostchecked"] is True
              and evidence["phaseHandlesClosed"] is True)
        state["post"][role] = ok
        if not ok:
            controller_failure(state, role, Refused("controller-check-original-post-or-close-unproved"))
    state["post"]["source"] = bool(_CONTROLLER_SOURCE is not None and _CONTROLLER_SOURCE["closed"]
        and _CONTROLLER_SOURCE["postchecked"] and _CONTROLLER_SOURCE["handlesClosed"])
    if not state["post"]["source"]:
        controller_failure(state, "source", Refused("controller-check-source-post-or-close-unproved"))
    if not _ORIGINALS_SETTLED:
        controller_failure(state, "originals", Refused("controller-check-originals-unknown"))


def check_controller_runtime(context, catalogue):
    return _check_controller_runtime(context, catalogue, characterization=False)


def characterize_controller_host(context, catalogue):
    controller_characterization_binding(context)
    return _check_controller_runtime(context, catalogue, characterization=True)


def _check_controller_runtime(context, catalogue, *, characterization):
    schema = CONTROLLER_CHARACTERIZATION_SCHEMA if characterization else CONTROLLER_CHECK_SCHEMA
    phase = "characterize-controller-host" if characterization else "check-controller-runtime"
    staging_receipt = controller_characterization_staging_receipt if characterization else controller_staging_receipt
    runtime_begin = controller_characterization_runtime_begin if characterization else controller_runtime_begin
    post_host = controller_characterization_post_host if characterization else controller_post_host
    mapping_reader = controller_characterization_mappings if characterization else controller_check_mappings
    fixed_body = controller_characterization_body if characterization else controller_check_body
    global _CONTROLLER_CHECK_STATE
    state = {"firstFailure": None, "errors": [], "post": {}, "bodyPassed": False}
    _CONTROLLER_CHECK_STATE = state
    receipt = None
    try:
        need(SOURCE == CONTROLLER_CHECK_SOURCE and sys.executable == PYTHON_EXECUTABLE,
             "controller-check-readonly-source-entry")
        controller_check_stdio()
        receipt = staging_receipt(context)
        runtime_begin(context, catalogue)
        # There is deliberately no bwrap before.json at this point.
        pycache_begin(receipt["pythonPycache"])
        controller_source_begin(receipt["sourceBinding"])
        authenticate_python_runtime(catalogue)
        post_host(catalogue, receipt)
        state["bodyPassed"] = fixed_body(receipt, state) is True
    except BaseException as error:
        controller_failure(state, "body", error)
    finally:
        audit = state.get("audit")
        if audit is not None:
            audit.stage = "post-reconcile"
        if receipt is not None:
            if characterization:
                # An early runtime/ABI error cannot suppress other retained
                # source/cache chains. Never retry a partially acquired chain.
                for role, owned, begin in (
                    ("sourceBegin", _CONTROLLER_SOURCE, lambda: controller_source_begin(receipt["sourceBinding"])),
                    ("runtimeBegin", _PYTHON_RUNTIME, lambda: runtime_begin(context, catalogue)),
                    ("cacheBegin", _PYCACHE, lambda: pycache_begin(receipt["pythonPycache"]))):
                    if owned is None:
                        controller_attempt(state, role, begin)
            if audit is not None:
                audit.stage = "post-host"
            controller_attempt(state, "host", lambda: post_host(catalogue, receipt))
            if audit is not None:
                audit.stage = "post-origins"
            state["originsAfter"] = controller_attempt(state, "moduleOrigins",
                lambda: controller_module_origins(receipt, state.get("modules", ())))
            def mapping_post():
                actual = mapping_reader(receipt)
                if characterization and state.get("mappingsBefore") is not None:
                    need(actual["files"] == state["mappingsBefore"]["files"],
                         "controller-characterization-selected-closure-changed")
                return actual
            if audit is not None:
                audit.stage = "post-mappings"
            state["mappingsAfter"] = controller_attempt(state, "mappings", mapping_post)
        if audit is not None and audit.first is not None:
            controller_failure(state, "audit", Refused(audit.first))
        if audit is not None:
            audit.stage = "post-finish"
        controller_finish_check(state)
    passed = state["bodyPassed"] and state["firstFailure"] is None
    frame = {"schema": schema, **context, "phase": phase,
             "passed": passed, "bodyPassed": state["bodyPassed"], "firstFailure": state["firstFailure"],
             "errors": state["errors"], "post": state["post"], "originalsSettled": _ORIGINALS_SETTLED,
             "auditDenied": audit is not None and audit.first is not None,
             "auditDenial": None if audit is None else audit.denial,
             "controllerCatalogueSha256": CONTROLLER_RUNTIME_SHA256,
             "contract": state.get("contract"), "compiledOnly": state.get("compiledOnly"),
             "tarModes": state.get("tarModes"), "nativeAdmission": state.get("nativeAdmission"),
             "originsBefore": state.get("originsBefore"), "originsAfter": state.get("originsAfter"),
             "mappingsBefore": state.get("mappingsBefore"), "mappingsAfter": state.get("mappingsAfter")}
    raw = canonical(frame)
    if len(raw) >= CONTROLLER_CHECK_LIMIT:
        controller_failure(state, "stdout", Refused("controller-check-private-frame-bound"))
        frame = {"schema": schema, **context, "phase": phase,
                 "passed": False, "bodyPassed": False, "firstFailure": state["firstFailure"],
                 "errors": state["errors"], "post": state["post"], "originalsSettled": False,
                 "auditDenied": audit is not None and audit.first is not None,
                 "auditDenial": None if audit is None else audit.denial}
        raw, passed = canonical(frame), False
    # Only original stdio. No task/public roots, side-file writer, new process,
    # cleanup, replacement observer, or swallowed writer error can pass.
    sys.stdout.write(raw.decode("ascii"))
    sys.stdout.flush()
    return 0 if passed else 1


def controller_original_join(context, outcome, body, waits):
    return _controller_original_join(context, outcome, body, waits, characterization=False)


def controller_characterization_original_join(context, outcome, body, waits):
    controller_characterization_binding(context)
    return _controller_original_join(context, outcome, body, waits, characterization=True)


def _controller_original_join(context, outcome, body, waits, *, characterization):
    """Pure finality join; provider POST is not an original process wait."""
    schema = CONTROLLER_CHARACTERIZATION_SCHEMA if characterization else CONTROLLER_CHECK_SCHEMA
    phase = "characterize-controller-host" if characterization else "check-controller-runtime"
    need(outcome == "success" and type(waits) is dict
         and waits.get("schema") == schema
         and all(waits.get(key) == context[key] for key in ("sourceSha", "runId", "attempt"))
         and waits.get("originalWait") is True and type(waits.get("exitCode")) is int
         and waits["exitCode"] == 0 and waits.get("outputWritersClosed") is True
         and waits.get("statusWriterCloseGate") == "original-step-success-required",
         "controller-check-original-wait-or-writer-unproved")
    need(type(body) is dict and body.get("schema") == schema
         and all(body.get(key) == value for key, value in context.items())
         and body.get("phase") == phase
         and body.get("passed") is True and body.get("bodyPassed") is True
         and body.get("firstFailure") is None and body.get("errors") == []
         and body.get("originalsSettled") is True and body.get("auditDenied") is False
         and "auditDenial" in body and body["auditDenial"] is None
         and body.get("controllerCatalogueSha256") == CONTROLLER_RUNTIME_SHA256
         and body.get("post") == {"source": True, "runtime": True, "cache": True,
                                  "host": True, "moduleOrigins": True, "mappings": True}
         and body.get("contract") == {"id": CONTROLLER_CHECK_TEST, "testsRun": 1, "failures": 0, "errors": 0,
             "skips": 0, "expectedFailures": 0, "unexpectedSuccesses": 0, "failfast": True}
         and body.get("compiledOnly") == ["prepare.py", "check-compile.py"]
         and body.get("tarModes") == ["r:", "r|"], "controller-check-body-not-accepted")
    native = body.get("nativeAdmission")
    need(type(native) is dict and set(native) == {"abi", "publicSymbols", "onlyLibcCall"}
         and native["onlyLibcCall"] == "gnu_get_libc_version"
         and native["publicSymbols"] == sorted(CONTROLLER_CHECK_SYMBOLS)
         and type(native["abi"]) is dict and native["abi"].get("schema") == "mrk-native-process-abi-v1"
         and native["abi"].get("family") == "linux-glibc" and native["abi"].get("architecture") == "x86_64",
         "controller-check-native-record-missing")
    before, after = body.get("originsBefore"), body.get("originsAfter")
    need(type(before) is list and type(after) is list and 0 < len(before) <= len(after) <= 1024
         and all(row in after for row in before), "controller-check-origin-post-missing")
    maps = [body.get("mappingsBefore"), body.get("mappingsAfter")]
    need(all(type(row) is dict and set(row) == {"sha256", "rows", "files"}
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
             and type(row["rows"]) is list and 0 < len(row["rows"]) <= 1024
             and type(row["files"]) is list and 0 < len(row["files"]) <= 35
             and all(type(path) is str for path in row["files"])
             and row["files"] == sorted(set(row["files"])) for row in maps)
         and maps[0]["files"] == maps[1]["files"], "controller-check-mapping-post-missing")
    return {"originalWait": True, "exitCode": 0, "outputWritersClosed": True,
            "statusWriterClosed": True, "stdoutEOF": True, "stderrEOF": True,
            "basis": "original-step-success-plus-bounded-original-file-EOF-not-a-replacement-wait"}


def post_controller_check(context, catalogue):
    return _post_controller_check(context, catalogue, characterization=False)


def post_controller_characterization(context, catalogue):
    controller_characterization_binding(context)
    return _post_controller_check(context, catalogue, characterization=True)


def _post_controller_check(context, catalogue, *, characterization):
    """Provider3.12 DATA only; runs after failure/timeout/ABI error as well."""
    schema = CONTROLLER_CHARACTERIZATION_SCHEMA if characterization else CONTROLLER_CHECK_SCHEMA
    staging_receipt = controller_characterization_staging_receipt if characterization else controller_staging_receipt
    runtime_begin = controller_characterization_runtime_begin if characterization else controller_runtime_begin
    post_host = controller_characterization_post_host if characterization else controller_post_host
    original_join = controller_characterization_original_join if characterization else controller_original_join
    global _CONTROLLER_CHECK_STATE
    state = {"firstFailure": None, "errors": [], "post": {}}
    _CONTROLLER_CHECK_STATE = state
    receipt, body, waits, original = None, None, None, None
    diagnostic = None
    provider = catalogue["controllerRuntime"]["bootstrap"]["python"]
    need(sys.executable == provider["path"] and sys.version_info[:2] == (3, 12)
         and sys.prefix == sys.base_prefix == "/usr", "controller-check-post-provider-only")
    _, provider_pin = read(provider["path"], 16 * MIB)
    need(provider_pin["bytes"] == provider["size"] and provider_pin["sha256"] == provider["sha256"]
         and provider_pin["mode"] == "0o755", "controller-check-post-provider-body")
    controller_check_output_root()
    stage_outcome = os.environ.get("MRK_CONTROLLER_STAGE_OUTCOME")
    outcome = os.environ.get("MRK_CONTROLLER_CHECK_OUTCOME")
    need(stage_outcome in ("success", "failure", "cancelled", "skipped")
         and outcome in ("success", "failure", "cancelled", "skipped"), "controller-check-original-outcome-shape")
    if stage_outcome != "success":
        controller_failure(state, "stage", Refused("controller-check-original-stage-not-success"))
    # Read the private body first so its original first error survives a later
    # wait/status writer or POST failure. Raw body/maps never reach public DATA.
    try:
        raw, pin = read(CONTROLLER_CHECK_ROOT / "stdout", CONTROLLER_CHECK_LIMIT, root=False)
        need(pin["bytes"] < CONTROLLER_CHECK_LIMIT and pin["mode"] == "0o600",
             "controller-check-stdout-bound")
        body = decode(raw)
        need(type(body) is dict and body.get("schema") == schema
             and all(body.get(key) == value for key, value in context.items())
             and body.get("phase") == ("characterize-controller-host" if characterization else "check-controller-runtime"),
             "controller-check-private-body-binding")
        first = body.get("firstFailure")
        if first is not None:
            need(type(first) is dict and set(first) == {"role", "refusal"}
                 and all(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,96}", value) for value in first.values()),
                 "controller-check-private-refusal-shape")
            controller_failure(state, "body", Refused(first["refusal"]))
        diagnostic = controller_audit_diagnostic(body)
    except BaseException as error:
        controller_failure(state, "body-original", error)
    try:
        raw, pin = read(CONTROLLER_CHECK_ROOT / "stderr", CONTROLLER_CHECK_LIMIT, root=False)
        need(raw == b"" and pin["mode"] == "0o600", "controller-check-stderr-not-empty")
        raw, pin = read(CONTROLLER_CHECK_ROOT / "waits.json", 4096, root=False)
        need(pin["mode"] == "0o600", "controller-check-wait-original-mode")
        waits = decode(raw)
        original = original_join(context, outcome, body, waits)
    except BaseException as error:
        controller_failure(state, "wait-writers", error)
    try:
        receipt = staging_receipt(context)
    except BaseException as error:
        controller_failure(state, "staging-original", error)
    try:
        if receipt is not None:
            # Separate attempts: a changed source/runtime never suppresses the
            # retained cache or other original's provider-DATA POST.
            controller_attempt(state, "sourceBegin", lambda: controller_source_begin(receipt["sourceBinding"]))
            controller_attempt(state, "runtimeBegin", lambda: runtime_begin(context, catalogue))
            controller_attempt(state, "cacheBegin", lambda: pycache_begin(receipt["pythonPycache"]))
            controller_attempt(state, "host", lambda: post_host(catalogue, receipt))
            need(read(provider["path"], 16 * MIB)[1] == receipt["providerPython"] == provider_pin,
                 "controller-check-provider-original-changed")
    except BaseException as error:
        controller_failure(state, "provider", error)
    finally:
        controller_finish_check(state)
    passed = state["firstFailure"] is None and original is not None
    candidate = None
    if characterization and passed:
        try:
            candidate = controller_characterization_documents(context, receipt, body)
        except BaseException as error:
            controller_failure(state, "candidate-publication", error)
            passed = False
    frame = {"schema": schema, **context,
             "phase": "post-controller-characterization" if characterization else "post-controller-check",
             "passed": passed, "firstFailure": state["firstFailure"], "errors": state["errors"],
             "originalCheckOutcome": outcome, "originalStageOutcome": stage_outcome,
             "originalWaitAndWriters": original, "providerDataPost": state["post"],
             "originalsSettled": _ORIGINALS_SETTLED, "checkBodyPassed": body is not None and body.get("passed") is True,
             "auditDenial": diagnostic,
             "runtimeQualified": False, "compilerQualified": False, "nativeQualified": False, "desktopReady": False,
             "scope": "supplied-GN-import-ABI-and-one-inert-argv-contract-only",
             "privateSourceAndMappingsUploaded": False, "retirement": "retain-readonly-views-and-runtime-until-disposable-vm-retirement"}
    if characterization:
        frame["scope"] = "fixed-supplied-body-host-selection-measurement-only"
        frame["candidate"] = candidate
        frame["independentReturnOriginalAndJobCompletionRequired"] = True
    # Exclusive publication only after actual original EOF/POST attempts. A
    # write/close exception fails the step; it cannot change firstFailure.
    write(CONTROLLER_CHECK_ROOT / "receipt.json", canonical(frame), 0o444)
    print("GNOME_CONTROLLER_CHECK_POST=" + ("passed" if passed else "failed"), flush=True)
    return 0 if passed else 1




def controller_characterization_documents(context, receipt, body):
    """Closed sanitized candidate DATA; not expected-value adoption or qualification."""
    controller_characterization_binding(context)
    before, after = body["mappingsBefore"], body["mappingsAfter"]
    for mapping in (before, after):
        need(_controller_mapping_rows(receipt, mapping["rows"], characterization=True) == mapping["files"],
             "controller-characterization-return-mapping-correspondence")
    need(before["files"] == after["files"], "controller-characterization-selected-closure-changed")
    inputs = receipt["controllerCheckInputs"]
    private = {row["path"]: row for row in receipt["projection"]["files"]}
    originals = {**inputs["files"], **private}
    selected = [{"path": path, **{key: originals[path][key] for key in ("identity", "bytes", "sha256", "mode")},
                 "executableCoverageBefore": True, "executableCoverageAfter": True} for path in before["files"]]
    header = {"schema": CONTROLLER_CHARACTERIZATION_SCHEMA, **context,
        "authority": CONTROLLER_CHARACTERIZATION_AUTHORITY, "controllerRuntimeSha256": CONTROLLER_RUNTIME_SHA256,
        "sourceCatalogueSha256": receipt["sourceCatalogue"]["sha256"],
        "sourceOriginalsSha256": hashlib.sha256(canonical(receipt["sourceBinding"])).hexdigest(),
        "productionQualified": False, "independentDataAcceptanceRequired": True}
    actual = {**header, "document": "actualMappings", "selected": selected,
        "mappedHostFiles": [path for path in before["files"] if path in CONTROLLER_CHARACTERIZATION_HOSTS],
        "mappedPrivateFiles": [path for path in before["files"] if path in private],
        "originalMapsSha256": {"before": before["sha256"], "after": after["sha256"]},
        "sameSelectedOriginalsBeforeAfter": True, "rawAddressesExported": False}
    actual_sha = hashlib.sha256(canonical(actual)).hexdigest()
    # source_elf accepted allowed/required constraints, not a retained exact
    # DT_NEEDED roster. Do not invent a more specific supplier observation.
    allowed_host = ["libc.so.6", "libdl.so.2", "libgcc_s.so.1", "libm.so.6", "libpthread.so.0"]
    loader = {**header, "document": "loaderSearch", "actualMappingsSha256": actual_sha,
        "inputOriginals": inputs, "inputPostEqual": True, "cacheInterpretation": "opaque-original-bytes;not-decoded",
        "environment": {**ENV, **{key: os.environ[key] for key in
            ("RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion", "GITHUB_REF", "GITHUB_SHA",
             "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
             "GITHUB_EVENT_NAME", "MRK_EXPECTED_SHA", "MRK_PUSH_EVENT_AFTER")}},
        "supplierLoaderConstraints": {
            "python": {"runpath": "$ORIGIN/../lib", "rpath": None,
                "allowedNeeded": sorted(allowed_host + ["libcrypto.so.3", "libssl.so.3"]),
                "requiredNeeded": ["libc.so.6", "libcrypto.so.3", "libssl.so.3"]},
            "libcrypto.so.3": {"runpath": "$ORIGIN", "rpath": None,
                "allowedNeeded": allowed_host, "requiredNeeded": ["libc.so.6"]},
            "libssl.so.3": {"runpath": "$ORIGIN", "rpath": None,
                "allowedNeeded": sorted(allowed_host + ["libcrypto.so.3"]),
                "requiredNeeded": ["libc.so.6", "libcrypto.so.3"]}},
        "privateRunpathClosure": "complete-598-file-alias-free-readonly-projection;no-alternate-hwcaps",
        "scope": "one-fixed-image-source-and-observed-selection;not-all-cpu-or-general-loader-qualification"}
    provider = {**header, "document": "providerConfig", "actualMappingsSha256": actual_sha,
        "supplierOutputSha256": "e647aaa18464665a7912a3627a27351ce604cb4cb85a483daaffb919016108fa",
        "supplierResultSha256": "45979ebb3325dfa5564d82323e37888804efd8bbe3be14ed2af6dfc29ea5fed8",
        "acceptedVInventorySha256": "df3b32cd1d36ce3f75ac6deef7e0b4cd1f786911caba38df4b6befd1afae4e9c",
        "generatedConfiguration": {
            "configdata.pm": "99a50037964cecf0af6adb42b359cd92f2b6c68d9ef010b5e24353e36ec31b9c",
            "build-Makefile": "b0ade76170bf4c3ece168c13fa98c7f256780e230faf52dafe4191e2469e59c0",
            "install-Makefile": "54482f291f7a5b7f21dbdc8a896c02fd10372e8a873f953a54f65d8c172d6187",
            "configuration.h": "e7c403cf3611f222e10e5f2b41df3affcca9cca191c71c39173af27a73b86695",
            "opensslv.h": "a69760824fbaeae38fe70c7548e11b482de43c2c088c876ed7ffd35dae00279e"},
        "configurationFactsBasis": "independently-accepted-generated-H-config-to-exact-V-projection",
        "disabled": ["autoload-config", "dso", "engine", "legacy", "module"],
        "modules": [], "installModules": [], "openssldir": "/nonexistent/mobile-release-kit/openssl",
        "version": "3.5.8", "explicitConfigurationOrProviderLoadInFixedBody": False,
        "configurationOriginals": {path: inputs["files"][path] for path in CONTROLLER_CHARACTERIZATION_CONFIG},
        "providerDirectoryOriginal": next(row for row in inputs["directories"]
            if row["path"] == "/usr/lib/x86_64-linux-gnu/ossl-modules"),
        "hostGuardPostEqual": True, "actualPrivateMappings": [row for row in selected if row["path"] in private]}
    # The source-literal controllerRuntime digest already binds H -> V provenance
    # and each actual readonly private body; no provider FFI probe is introduced.
    documents = {"loader-search.json": loader, "provider-config.json": provider, "actual-mappings.json": actual}
    need(all(len(canonical(document)) < CONTROLLER_CHECK_LIMIT for document in documents.values())
         and sum(len(canonical(document)) for document in documents.values()) <= 3 * MIB,
         "controller-characterization-public-document-bound")
    pins = {}
    for name, document in documents.items():
        pin = write(CONTROLLER_CHECK_ROOT / name, canonical(document), 0o444)
        pins[name] = {key: pin[key] for key in ("bytes", "sha256", "mode")}
    return {"documents": pins, "selectionEvidence": {
        "loaderSearchSha256": pins["loader-search.json"]["sha256"],
        "providerConfigSha256": pins["provider-config.json"]["sha256"],
        "actualMappingsSha256": pins["actual-mappings.json"]["sha256"]},
        "automaticAdoption": False, "independentReturnOriginalAndJobCompletionRequired": True}


def main():
    global _CATALOGUE, _CONTROLLER_CHARACTERIZATION_ACTIVE, _CONTROLLER_CHARACTERIZATION_READ_BYTES
    phase = None
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in ("stage-controller-runtime", "check-controller-runtime", "post-controller-check",
             "supply-bwrap", "prepare", "acquire", "run", "settle", *CONTROLLER_CHARACTERIZATION_PHASES)
             and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
             and type(sys.pycache_prefix) is str and sys.pycache_prefix == str(PYTHON_PYCACHE),
             "fixed-isolated-controller-entry")
        phase = sys.argv[1]
        need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0) and os.getgroups() == []
             and os.uname().machine == "x86_64", "authenticated-cleared-groups-root-entry")
        _EVIDENCE["bootstrap"] = {**BOOTSTRAP_TRUST, "clearedGroupsRootEntryObserved": True}
        characterization = phase in CONTROLLER_CHARACTERIZATION_PHASES
        # Own early stage-read closes before any catalogue/cache/stage state exists.
        _CONTROLLER_CHARACTERIZATION_ACTIVE = characterization
        context = (controller_characterization_context(dict(os.environ),
            post=phase == "post-controller-characterization") if characterization else workflow_context(dict(os.environ)))
        # Staging keeps its existing120s/4GiB DATA envelope. The supplied body
        # and independent provider POST have the tighter total-read ceiling.
        _CONTROLLER_CHARACTERIZATION_READ_BYTES = 0 if characterization and phase != "stage-controller-characterization" else None
        _EVIDENCE["context"] = context
        raw, catalogue_pin = read(SOURCE / CONTROL / "runtime-suppliers.json", 16 * MIB, root=False)
        value = decode(raw)
        if phase == "stage-controller-characterization":
            pycache_begin()
            stage_controller_characterization(context, value, catalogue_pin)
            return 0
        if phase == "characterize-controller-host":
            return characterize_controller_host(context, value)
        if phase == "post-controller-characterization":
            return post_controller_characterization(context, value)
        if phase == "stage-controller-runtime":
            # A closed provider-only DATA step, not a sixth controlled/native
            # phase and not clearance of any remaining supplier prerequisite.
            pycache_begin()
            stage_controller_runtime(context, value, catalogue_pin)
            return 0
        if phase == "check-controller-runtime":
            return check_controller_runtime(context, value)
        if phase == "post-controller-check":
            return post_controller_check(context, value)
        need(sys.executable == PYTHON_EXECUTABLE, "private-controller-entry-required")
        catalogue = catalogue_ready(value)  # Still before tools/owner imports.
        native_layout(catalogue, decode(read(SOURCE / CONTROL / "runtime-layout.json", MIB, root=False)[0]))
        _CATALOGUE = catalogue
        controller_runtime_begin(context, catalogue)
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
        need(_PYTHON_RUNTIME is not None and _PYTHON_RUNTIME["closed"]
             and _EVIDENCE["controllerRuntime"]["phaseCustodyPostchecked"]
             and _EVIDENCE["controllerRuntime"]["phaseHandlesClosed"], "controller-runtime-phase-not-closed")
        return 0
    except BaseException as error:
        phase_finish(failed=True)
        code = refusal_code(error)
        if phase in ("check-controller-runtime", "characterize-controller-host"):
            # The fixed check already owns its one stdout frame. A failed
            # original writer is Unknown, not authority to retry that writer.
            return 1
        # There are no raw paths, account tables, stdout, tokens, or provider
        # diagnostic excerpts in the only public failure output.
        print("GNOME_HOSTED_REFUSAL=" + code, flush=True)
        if phase in ("stage-controller-runtime", "post-controller-check",
                     "stage-controller-characterization", "post-controller-characterization"):
            try:
                controller_check_output_root()
                first = (_CONTROLLER_CHECK_STATE or {}).get("firstFailure")
                write(CONTROLLER_CHECK_ROOT / (phase + "-refusal.json"),
                      canonical({"schema": CONTROLLER_CHARACTERIZATION_SCHEMA if phase in CONTROLLER_CHARACTERIZATION_PHASES else CONTROLLER_CHECK_SCHEMA,
                                  "phase": phase, "passed": False,
                                 "firstFailure": first or {"role": phase, "refusal": code},
                                 "publicationOrEntryRefusal": code, "originalsSettled": _ORIGINALS_SETTLED,
                                 "sourcePostchecked": bool(_CONTROLLER_SOURCE is not None
                                     and _CONTROLLER_SOURCE["postchecked"] and _CONTROLLER_SOURCE["handlesClosed"]),
                                 "retirement": "disposable-vm-only", "evidence": public_evidence()}), 0o444)
            except Exception:
                print("GNOME_HOSTED_FAILURE_EVIDENCE=unavailable", flush=True)
        elif phase and PUBLIC.is_dir() and PUBLIC.lstat().st_uid == 0:
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
