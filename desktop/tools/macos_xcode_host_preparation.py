"""One fixed, nonroot prerequisite for this disposable GitHub Mac engineering job.

This is NOT a consumer repair tool or a native-policy exception. Only an audited
root:admin /Applications 0775 may become 0755, once, before any candidate worker.
Concrete native Book/ACL/toolchain protection runs independently afterward.
A result file is provisional until this original helper has closed every owner
and returned zero. Unknown command retirement blocks until job/VM disposal.

Public Apple ABI references (read-only documentation, not imported suppliers):
  xnu bsd/sys/cdefs.h blob 8b810050fab1aaf227de97edcfd0e55f6ae3fc2b:
    Mac ARM64 has ONLY_64_BIT_INO_T=1, hence INODE64 has NO symbol suffix.
  xnu bsd/sys/stat.h SHA256
    dd8154be80f467ba57d4edaa7c6617bd32db54bfebdda892b390f9b0364fe488
  xnu bsd/sys/mount.h SHA256
    049682e582ede05082580d55a5db0647d1ef057dc7966443fab54438f6acdeb5
  xnu bsd/sys/fcntl.h SHA256
    0f93c8918a70ffafe20bfe9c72e671fde67438cbee9f9de8c2f87b5c704c9a9e
  xnu bsd/sys/xattr.h blob 9fb79d25620663de72c13ab46af42a122125b9c7
  xnu bsd/sys/signal.h blob 9ecad9af653c7167650ce23a5066f2041d41e69c:
    public sigaction union-pointer/mask/flags layout and SIGCHLD/NOCLDWAIT.
  Libc include/signal.h blob 6f00b8e04750a8548e5f158a60c5c84b787d3bb6:
    undecorated sigaction(int, const struct sigaction *, struct sigaction *).
  xnu sys/_types.h blob 5aa02f270135bca45af4d073df9ca7279091ef6e and
    _sigset_t.h blob 51844dddbb0ed1c217d6a8878ac435c7790744e7: uint32 mask.
  Libc include/sys/acl.h and gen/filesec.c: FILESEC_ACL returns an owned
    acl_copy_int_native allocation. Presence is zero/nonzero, not necessarily 1.
No candidate native library, executable discovery, compiler or Xcode query occurs.
"""

import ctypes
import errno
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-aqua"
WORKFLOW = ".github/workflows/desktop-macos-aqua.yml"
HELPER = "desktop/tools/macos_xcode_host_preparation.py"
TEST_SOURCE = "tests/desktop/test_macos_xcode_host_preparation.py"
WORKSPACE = "/Users/runner/work/mobile-release-kit/mobile-release-kit"
RUNNER_TEMP = "/Users/runner/work/_temp"
INVENTORY = "source-inventory.json"
INTENT = "xcode-host-preparation-intent.json"
RESULT = "xcode-host-preparation-result.json"
CLASSIFICATION_ARG = "--classify-installed"
CLASSIFICATION_RESULT = "xcode-installed-classification-result.json"
COMMAND = ("/usr/bin/sudo", "-n", "--", "/bin/chmod", "-h", "0755", "/Applications")
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_ORIGINALS = 40
MAX_ENTRIES = 512
MAX_PATH = 4096
MAX_RECORD = 131072
MAX_STREAM = 4096
PREPARATION_SECONDS = 60.0
COMMAND_SECONDS = 10.0
STOP_GRACE_SECONDS = 2.0
DARWIN_SIGCHLD = 20
SA_RESTART = 0x0002
SA_NOCLDSTOP = 0x0008
SA_NOCLDWAIT = 0x0020
SAFE_SIGCHLD_FLAGS = SA_RESTART | SA_NOCLDSTOP
# These are public Darwin fcntl.h constants, only used after the ARM64 gate.
O_EXEC = 0x40000000
O_SYMLINK = 0x00200000
UF_COMPRESSED = 0x00000020
UF_HIDDEN = 0x00008000
SF_RESTRICTED = 0x00080000
SF_NOUNLINK = 0x00100000
SF_FIRMLINK = 0x00800000
KNOWN_PROTECTIVE_FLAGS = SF_RESTRICTED | SF_NOUNLINK | SF_FIRMLINK
# Neither nounlink nor firmlink is permission to clear a flag. Restricted,
# immutable/append, dataless and every unknown flag refuse the write target.
MODE_ONLY_FLAGS = SF_NOUNLINK | SF_FIRMLINK
MNT_RDONLY = 0x1
MNT_NOEXEC = 0x4
MNT_NOSUID = 0x8
MNT_UNION = 0x20
MNT_LOCAL = 0x1000
MNT_ROOTFS = 0x4000
MNT_IGNORE_OWNERSHIP = 0x200000
MNT_AUTOMOUNTED = 0x400000
MNT_SNAPSHOT = 0x40000000
ENVIRONMENT_KEYS = frozenset((
    "PATH", "HOME", "LANG", "LC_ALL", "TZ", "RUNNER_ENVIRONMENT", "RUNNER_OS",
    "RUNNER_ARCH", "RUNNER_TEMP", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME",
    "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_WORKSPACE",
    "MRK_EXPECTED_SHA", "MRK_MACOS_INSTALL_SOURCE_COMMIT", "MRK_MACOS_WORK",
    "__CF_USER_TEXT_ENCODING",
))


class Refused(Exception):
    """A bounded diagnostic code, not an accepted-error capability."""


class Deadline:
    def __init__(self):
        self.end = time.monotonic() + PREPARATION_SECONDS

    def check(self):
        if time.monotonic() >= self.end:
            raise Refused("preparation-deadline")


def full9(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns]


def _json_bytes(value, limit=MAX_RECORD):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    if len(data) > limit:
        raise Refused("record-bound")
    return data


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused("duplicate-json-key")
        value[key] = item
    return value


def _validate_context(environment, identity, uname, version, python_flags):
    """Pure validation; no environment value selects an effect path or mode."""
    actual_keys = set(environment)
    if actual_keys != ENVIRONMENT_KEYS:
        # Key names only: never inspect values on a set mismatch. Bound each
        # intermediate before escaping, then the displayed escaped name too.
        details = []
        for kind, names in (("missing", ENVIRONMENT_KEYS - actual_keys),
                            ("extra", actual_keys - ENVIRONMENT_KEYS)):
            selected = sorted(names)[:8]
            escaped = [ascii(name[:64]) for name in selected]
            truncated = any(len(name) > 64 or len(shown) > 64
                            for name, shown in zip(selected, escaped))
            details.append(f"{kind}Count={len(names)} {kind}ListTruncated={len(names) > 8} "
                           f"{kind}NameTruncated={truncated} "
                           f"{kind}=[{', '.join(shown[:64] for shown in escaped)}]")
        raise Refused("startup-environment-not-closed " + " ".join(details))
    if any(not isinstance(v, str) or not v or len(v.encode()) > MAX_PATH
           or "\0" in v or "\n" in v or "\r" in v for v in environment.values()):
        raise Refused("startup-value-shape")
    if (environment["PATH"] != SAFE_PATH or environment["LANG"] != "C"
            or environment["LC_ALL"] != "C" or environment["TZ"] != "UTC"):
        raise Refused("startup-fixed-environment")
    uid, euid, gid, egid = identity
    if uid == 0 or uid != euid or gid != egid:
        raise Refused("nonroot-real-user-required")
    if environment["__CF_USER_TEXT_ENCODING"] != f"0x{uid:X}:0:0":
        raise Refused("startup-cf-encoding-not-fixed")
    if (uname != ("Darwin", "arm64") or tuple(version) != (3, 14, 7)
            or tuple(python_flags) != (1, 1, 1)):
        raise Refused("fixed-platform-data-python-required")
    e = environment
    if (e["RUNNER_ENVIRONMENT"] != "github-hosted" or e["RUNNER_OS"] != "macOS"
            or e["RUNNER_ARCH"] != "ARM64" or e["GITHUB_REPOSITORY"] != REPOSITORY
            or e["GITHUB_EVENT_NAME"] != "push" or e["GITHUB_REF"] != REF
            or e["GITHUB_JOB"] != "aqua"):
        raise Refused("dedicated-hosted-route-required")
    source = e["GITHUB_SHA"]
    if (not re.fullmatch(r"[0-9a-f]{40}", source)
            or any(e[k] != source for k in ("GITHUB_WORKFLOW_SHA", "MRK_EXPECTED_SHA",
                                            "MRK_MACOS_INSTALL_SOURCE_COMMIT"))
            or e["GITHUB_WORKFLOW_REF"] != REPOSITORY + "/" + WORKFLOW + "@" + REF):
        raise Refused("exact-source-route-required")
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", e[k])
           for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")):
        raise Refused("positive-run-attempt-required")
    work = e["MRK_MACOS_WORK"]
    if (e["GITHUB_WORKSPACE"] != WORKSPACE or e["RUNNER_TEMP"] != RUNNER_TEMP
            or e["HOME"] != work
            or not re.fullmatch(re.escape(RUNNER_TEMP) + r"/mrk-macos-aqua\.[A-Za-z0-9]{8}", work)):
        raise Refused("fresh-fixed-job-paths-required")
    return {"source": source, "workflowSource": e["GITHUB_WORKFLOW_SHA"],
            "runId": e["GITHUB_RUN_ID"], "runAttempt": e["GITHUB_RUN_ATTEMPT"],
            "jobKey": "aqua", "repository": REPOSITORY, "ref": REF,
            "workspace": WORKSPACE, "work": work, "uid": uid, "gid": gid,
            "runnerEnvironment": "github-hosted", "machine": "arm64"}


class Timespec(ctypes.Structure):
    _fields_ = (("seconds", ctypes.c_int64), ("nanoseconds", ctypes.c_int64))


class DarwinStat(ctypes.Structure):
    _fields_ = (
        ("dev", ctypes.c_int32), ("mode", ctypes.c_uint16), ("links", ctypes.c_uint16),
        ("ino", ctypes.c_uint64), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("rdev", ctypes.c_int32), ("atime", Timespec), ("mtime", Timespec),
        ("ctime", Timespec), ("birthtime", Timespec), ("size", ctypes.c_int64),
        ("blocks", ctypes.c_int64), ("blksize", ctypes.c_int32),
        ("flags", ctypes.c_uint32), ("gen", ctypes.c_uint32), ("lspare", ctypes.c_int32),
        ("qspare", ctypes.c_int64 * 2),
    )

    def nine(self):
        for value in (self.mtime, self.ctime, self.birthtime):
            if not 0 <= value.nanoseconds < 1000000000:
                raise Refused("native-stat-nanoseconds")
        return [self.dev, self.ino, self.mode, self.uid, self.gid, self.links, self.size,
                self.mtime.seconds * 1000000000 + self.mtime.nanoseconds,
                self.ctime.seconds * 1000000000 + self.ctime.nanoseconds]


class DarwinStatFS(ctypes.Structure):
    _fields_ = (
        ("bsize", ctypes.c_uint32), ("iosize", ctypes.c_int32),
        ("blocks", ctypes.c_uint64), ("bfree", ctypes.c_uint64),
        ("bavail", ctypes.c_uint64), ("files", ctypes.c_uint64), ("ffree", ctypes.c_uint64),
        ("fsid", ctypes.c_int32 * 2), ("owner", ctypes.c_uint32), ("type", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("subtype", ctypes.c_uint32),
        ("fstypename", ctypes.c_char * 16), ("mounton", ctypes.c_char * 1024),
        ("mountfrom", ctypes.c_char * 1024), ("flags_ext", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 7),
    )


class DarwinSigaction(ctypes.Structure):
    # Public userspace struct, NOT the larger kernel __sigaction trampoline ABI.
    _fields_ = (("handler", ctypes.c_void_p), ("mask", ctypes.c_uint32),
                ("flags", ctypes.c_int32))


def _check_abi():
    expected = {
        DarwinSigaction: (16, {"handler": 0, "mask": 8, "flags": 12}),
        DarwinStat: (144, {"dev": 0, "mode": 4, "links": 6, "ino": 8, "uid": 16,
                          "gid": 20, "rdev": 24, "atime": 32, "mtime": 48,
                          "ctime": 64, "birthtime": 80, "size": 96, "blocks": 104,
                          "blksize": 112, "flags": 116, "gen": 120, "lspare": 124,
                          "qspare": 128}),
        DarwinStatFS: (2168, {"bsize": 0, "iosize": 4, "blocks": 8, "fsid": 48,
                             "owner": 56, "type": 60, "flags": 64, "subtype": 68,
                             "fstypename": 72, "mounton": 88, "mountfrom": 1112,
                             "flags_ext": 2136, "reserved": 2140}),
    }
    if (ctypes.sizeof(ctypes.c_int) != 4 or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(ctypes.c_size_t) != 8 or sys.byteorder != "little"
            or ctypes.sizeof(Timespec) != 16):
        raise Refused("darwin-arm64-widths-required")
    for structure, (size, offsets) in expected.items():
        if ctypes.sizeof(structure) != size or ctypes.alignment(structure) != 8:
            raise Refused("darwin-arm64-structure-size")
        if any(getattr(structure, field).offset != offset for field, offset in offsets.items()):
            raise Refused("darwin-arm64-structure-offset")


def _call(function, *arguments):
    ctypes.set_errno(0)
    result = function(*arguments)
    return result, ctypes.get_errno()


def _acl_snapshot(library, descriptor, expected):
    """Same native empty-ACL rule. `expected` comes from this held FD's os.fstat.

    This function has no path lookup, ACL setter, FD transfer or errno-only
    absence shortcut. The mockable library seam is for DATA tests, not CLI input.
    """
    value = {"empty": False, "kind": "unavailable", "present": None, "phase": 0,
             "callResult": 0, "errno": 0, "aclFreeResult": None,
             "aclFreeErrno": None, "filesecFreeReturned": False}
    fsec = None
    acl = ctypes.c_void_p()
    owned_acl = False

    def fail(phase, returned, observed_errno):
        if value["phase"] == 0:
            value.update(phase=phase, callResult=returned, errno=observed_errno)

    try:
        fsec, observed_errno = _call(library.filesec_init)
        if not fsec:
            fail(1, 0, observed_errno)
        else:
            snapshot = DarwinStat()
            returned, observed_errno = _call(library.fstatx_np, descriptor,
                                             ctypes.byref(snapshot), fsec)
            if returned != 0:
                fail(2, returned, observed_errno)
            else:
                observed = snapshot.nine()
                value["snapshotFull9"] = observed
                value["snapshotFlags"] = snapshot.flags
                value["snapshotBirthtimeNs"] = (snapshot.birthtime.seconds * 1000000000
                                                + snapshot.birthtime.nanoseconds)
                if observed != expected:
                    fail(2, returned, 0)
                else:
                    for phase, prop, ctype, wanted in (
                            (3, 1, ctypes.c_uint32, snapshot.uid),
                            (4, 2, ctypes.c_uint32, snapshot.gid),
                            (5, 4, ctypes.c_uint16, snapshot.mode)):
                        actual = ctype()
                        returned, observed_errno = _call(library.filesec_get_property,
                                                         fsec, prop, ctypes.byref(actual))
                        if returned != 0 or actual.value != wanted:
                            fail(phase, returned, observed_errno if returned else 0)
                            break
                    if value["phase"] == 0:
                        present = ctypes.c_int()
                        returned, observed_errno = _call(library.filesec_query_property,
                                                         fsec, 5, ctypes.byref(present))
                        if returned != 0:
                            fail(6, returned, observed_errno)
                        else:
                            value["present"] = present.value
                            if present.value == 0:
                                value.update(empty=True, kind="absent")
                            else:
                                returned, observed_errno = _call(library.filesec_get_property,
                                                                 fsec, 5, ctypes.byref(acl))
                                if returned != 0:
                                    fail(7, returned, observed_errno)
                                elif acl.value in (None, 0, 1):
                                    fail(8, 0, 0)
                                else:
                                    owned_acl = True
                                    returned, observed_errno = _call(library.acl_valid, acl)
                                    if returned != 0:
                                        fail(9, returned, observed_errno)
                                    else:
                                        entry = ctypes.c_void_p()
                                        returned, observed_errno = _call(library.acl_get_entry,
                                                                         acl, 0, ctypes.byref(entry))
                                        if returned == 0:
                                            value["kind"] = "contains-entry"
                                            fail(11, returned, 0)
                                        elif returned == -1 and observed_errno == errno.EINVAL:
                                            value.update(empty=True, kind="empty-valid-acl")
                                        else:
                                            fail(10, returned, observed_errno)
    except Exception as error:
        value["exception"] = type(error).__name__
        fail(13, 0, 0)
    finally:
        if owned_acl:
            # Consume once even when the return is uncertain; do not retry free.
            owned_acl = False
            try:
                returned, observed_errno = _call(library.acl_free, acl)
                value["aclFreeResult"] = returned
                value["aclFreeErrno"] = observed_errno
                if returned != 0:
                    fail(12, returned, observed_errno)
                    value["empty"] = False
            except Exception as error:
                value["aclFreeException"] = type(error).__name__
                fail(12, 0, 0)
                value["empty"] = False
        if fsec:
            try:
                library.filesec_free(fsec)  # void API; successful return is required.
                value["filesecFreeReturned"] = True
            except Exception as error:
                value["filesecFreeException"] = type(error).__name__
                fail(14, 0, 0)
        if value["phase"] or not value["filesecFreeReturned"]:
            value["empty"] = False
    return value


class DarwinAPI:
    def __init__(self, deadline):
        # No fallback to x86 $INODE64 or stat64 names. cdefs.h gives undecorated
        # 64-bit-inode ABI on the exact ARM64 platform already admitted above.
        _check_abi()
        self.deadline = deadline
        self.library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        pointer = ctypes.c_void_p
        integer = ctypes.c_int
        size = ctypes.c_size_t
        prototypes = {
            "issetugid": (integer, []),
            "sigaction": (integer, [integer, ctypes.POINTER(DarwinSigaction),
                                     ctypes.POINTER(DarwinSigaction)]),
            "sysctlbyname": (integer, [ctypes.c_char_p, pointer, ctypes.POINTER(size), pointer, size]),
            "fstatfs": (integer, [integer, ctypes.POINTER(DarwinStatFS)]),
            "filesec_init": (pointer, []), "filesec_free": (None, [pointer]),
            "fstatx_np": (integer, [integer, ctypes.POINTER(DarwinStat), pointer]),
            "filesec_get_property": (integer, [pointer, integer, pointer]),
            "filesec_query_property": (integer, [pointer, integer, ctypes.POINTER(integer)]),
            "acl_valid": (integer, [pointer]),
            "acl_get_entry": (integer, [pointer, integer, ctypes.POINTER(pointer)]),
            "acl_free": (integer, [pointer]),
            "flistxattr": (ctypes.c_ssize_t, [integer, pointer, size, integer]),
            "fgetxattr": (ctypes.c_ssize_t, [integer, ctypes.c_char_p, pointer, size,
                                          ctypes.c_uint32, integer]),
        }
        for name, (result, arguments) in prototypes.items():
            function = getattr(self.library, name)
            function.restype = result
            function.argtypes = arguments
        self.deadline.check()
        if self.library.issetugid() != 0:
            raise Refused("issetugid-refused")
        version = ctypes.create_string_buffer(64)
        length = size(64)
        returned, _ = _call(self.library.sysctlbyname, b"kern.osproductversion",
                            version, ctypes.byref(length), None, 0)
        if (returned != 0 or not 1 < length.value <= 64
                or version.raw[length.value - 1:length.value] != b"\0"):
            raise Refused("real-macos-version-unavailable")
        self.version = version.raw[:length.value - 1].decode("ascii", "strict")
        if not re.fullmatch(r"26\.[0-9]+(?:\.[0-9]+)?", self.version):
            raise Refused("real-macos26-required")

    def waitable_sigchld(self):
        self.deadline.check()
        if (signal.SIGCHLD != DARWIN_SIGCHLD
                or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
            raise Refused("default-darwin-sigchld-required")
        value = DarwinSigaction()
        # NULL new-action is a read, never a reset of caller/global policy.
        returned, _ = _call(self.library.sigaction, DARWIN_SIGCHLD, None,
                             ctypes.byref(value))
        if returned != 0:
            raise Refused("native-sigchld-action-unavailable")
        observed = {"handler": value.handler or 0, "mask": value.mask, "flags": value.flags}
        if (observed["handler"] != 0 or value.flags & SA_NOCLDWAIT
                or value.flags & ~SAFE_SIGCHLD_FLAGS):
            raise Refused("native-sigchld-not-default-waitable")
        self.deadline.check()
        return observed

    def filesystem(self, descriptor):
        self.deadline.check()
        value = DarwinStatFS()
        returned, observed_errno = _call(self.library.fstatfs, descriptor, ctypes.byref(value))
        if returned != 0:
            raise OSError(observed_errno or errno.EIO, "fstatfs")
        def text(field, limit):
            raw = bytes(field)
            if not raw or len(raw) >= limit:
                raise Refused("filesystem-string-bound")
            return raw.decode("utf-8", "strict")
        # Free-block/file counters are not mount identity and may change for
        # unrelated OS writes. All identity/permission-bearing fields are held.
        return {"typeName": text(value.fstypename, 16), "fsid": list(value.fsid),
                "owner": value.owner, "type": value.type, "flags": value.flags,
                "subtype": value.subtype, "flagsExt": value.flags_ext,
                "mountOn": text(value.mounton, 1024), "mountFrom": text(value.mountfrom, 1024)}

    def xattrs(self, descriptor):
        def names():
            self.deadline.check()
            count, observed_errno = _call(self.library.flistxattr, descriptor, None, 0, 0)
            if count < 0:
                raise OSError(observed_errno or errno.EIO, "flistxattr")
            if count > 4096:
                raise Refused("xattr-name-byte-bound")
            buffer = ctypes.create_string_buffer(max(1, count))
            got, observed_errno = _call(self.library.flistxattr, descriptor, buffer, count, 0)
            if got != count:
                raise Refused("xattr-name-snapshot-changed")
            raw = buffer.raw[:count]
            if raw and not raw.endswith(b"\0"):
                raise Refused("xattr-name-termination")
            values = raw[:-1].split(b"\0") if raw else []
            if (len(values) > 16 or len(set(values)) != len(values)
                    or any(not x or len(x) > 255 for x in values)):
                raise Refused("xattr-name-roster")
            return sorted(values)
        before = names()
        result = []
        total = 0
        for name in before:
            self.deadline.check()
            count, observed_errno = _call(self.library.fgetxattr, descriptor, name, None, 0, 0, 0)
            if count < 0:
                raise OSError(observed_errno or errno.EIO, "fgetxattr")
            total += count
            if count > 32768 or total > 65536:
                raise Refused("xattr-value-bound")
            buffer = ctypes.create_string_buffer(max(1, count))
            got, _ = _call(self.library.fgetxattr, descriptor, name, buffer, count, 0, 0)
            if got != count:
                raise Refused("xattr-value-snapshot-changed")
            result.append({"name": name.decode("utf-8", "strict"), "size": count,
                           "sha256": hashlib.sha256(buffer.raw[:count]).hexdigest()})
        if names() != before:
            raise Refused("xattr-roster-changed")
        return result


def _application_mode(value):
    if (len(value) != 9 or value[3:5] != [0, 80]
            or value[2] not in (stat.S_IFDIR | 0o775, stat.S_IFDIR | 0o755)):
        raise Refused("applications-exact-root-admin-mode")
    return "chmod" if value[2] == stat.S_IFDIR | 0o775 else "noop"


def _sibling(target):
    if not isinstance(target, str) or not 1 <= len(target.encode()) <= 1024:
        raise Refused("xcode-alias-bound")
    name = target.removeprefix("/Applications/")
    if (name == "Xcode.app" or len(name.encode()) > 255
            or not re.fullmatch(r"Xcode[A-Za-z0-9._+-]*\.app", name)):
        raise Refused("xcode-one-sibling-alias")
    return name


def _selection_alias_owner(owner, account):
    # The one alias chooses a sibling name; it never authenticates that sibling.
    return account != 0 and owner in (0, account)


def _sudo_xattr_basis(node, snapshot, root_filesystem):
    """Prove stability, NOT readable/empty xattrs or a cryptographic seal."""
    if (node.path != "/usr/bin/sudo" or node.role != "os-provisioner-sudo"
            or node.kind != "file" or node.policy != "sudo"):
        raise Refused("sudo-snapshot-fixed-role-required")
    identity = snapshot["full9"]
    mode, flags = identity[2], snapshot["flags"]
    if (not stat.S_ISREG(mode) or identity[3:6] != [0, 0, 1]
            or mode & 0o3022 or not mode & stat.S_ISUID or not mode & 0o111
            or not isinstance(flags, int) or not flags & SF_RESTRICTED
            or flags & ~_observation_flags("sudo", "file")):
        raise Refused("sudo-snapshot-protected-original-required")
    filesystem = snapshot.get("filesystem")
    required = MNT_RDONLY | MNT_LOCAL | MNT_ROOTFS | MNT_SNAPSHOT
    forbidden = MNT_NOEXEC | MNT_NOSUID | MNT_UNION | MNT_IGNORE_OWNERSHIP | MNT_AUTOMOUNTED
    if (not filesystem or filesystem != root_filesystem
            or filesystem["typeName"] != "apfs" or filesystem["owner"] != 0
            or filesystem["mountOn"] != "/"
            or filesystem["flags"] & required != required
            or filesystem["flags"] & forbidden):
        raise Refused("sudo-snapshot-original-readonly-root-apfs-required")
    return {"observed": False, "basis": "same-held-readonly-root-apfs-snapshot",
            "filesystem": dict(filesystem)}


def _unchanged_payload(snapshot):
    # ACL call diagnostics contain the matching current stat mode/ctime. Only
    # the semantic ACL state is compared as an extra; the current full9 below
    # has its own narrowly typed Applications transition rule.
    return {key: value for key, value in snapshot.items()
            if key not in ("full9", "aclDiagnostic")}


def _observation_flags(policy, kind):
    # Public stat.h: visibility/compression do not confer permission. These
    # allowances never reach the writable Applications target or private work.
    extra = UF_HIDDEN if policy == "native" and kind == "directory" else 0
    if policy in ("native", "sudo") and kind == "file":
        extra |= UF_COMPRESSED
    return KNOWN_PROTECTIVE_FLAGS | extra


def _same_snapshot(before, after, transition=False):
    if not before or not after or _unchanged_payload(before) != _unchanged_payload(after):
        return False
    left, right = before["full9"], after["full9"]
    if not transition:
        return left == right
    return (left[2] == stat.S_IFDIR | 0o775 and right[2] == stat.S_IFDIR | 0o755
            and right[8] >= left[8]
            and all(left[index] == right[index] for index in (0, 1, 3, 4, 5, 6, 7)))


class Node:
    def __init__(self, path, role, parent, name, kind, policy):
        self.path, self.role, self.parent, self.name = path, role, parent, name
        self.kind, self.policy = kind, policy
        self.fd = None
        self.pre = None
        self.post = None
        self.expected = None
        self.bytes = None
        self.alias_target = None
        self.checks = []
        self.close_state = "not-opened"
        self.budgeted = False

    def data(self):
        return {"path": self.path, "role": self.role, "kind": self.kind,
                "policy": self.policy, "available": self.fd is not None,
                "pre": self.pre, "post": self.post, "checks": self.checks,
                "aliasTarget": self.alias_target,
                "contentSha256": hashlib.sha256(self.bytes).hexdigest() if self.bytes is not None else None,
                "finalClose": "pending-original-helper-exit" if self.fd is not None else self.close_state}


class Originals:
    def __init__(self, api, context, deadline, budget=None, classification=False):
        self.api, self.context, self.deadline = api, context, deadline
        # Candidate ledgers share this one count with their still-held common
        # originals. A failed consuming close permanently withholds capacity.
        self.budget = budget if budget is not None else {"live": 0, "peak": 0, "uncertain": False}
        self.classification = classification
        self.receipt_names = (CLASSIFICATION_RESULT,) if classification else (INTENT, RESULT)
        self.nodes = {}
        self.errors = []
        self.absences = []
        self.work = None
        self.work_admitted = False
        self.work_names = [INVENTORY]
        self.work_transitions = []
        self.applications = None
        self.intent_pin = None
        self.result_fd = None
        self.result_pin = None
        self.result_bytes = None
        self.result_budgeted = False
        self.source_binding = None
        self.receipt_attempts = set()

    def reserve(self, code):
        self.deadline.check()
        if self.budget["uncertain"]:
            raise Refused("original-close-uncertain-no-new-acquisition")
        if self.budget["live"] >= MAX_ORIGINALS:
            raise Refused(code)
        self.budget["live"] += 1
        self.budget["peak"] = max(self.budget["peak"], self.budget["live"])

    def consuming_close(self, descriptor, budgeted=True):
        try:
            os.close(descriptor)
        except BaseException:
            self.budget["uncertain"] = True
            raise
        if budgeted:
            self.budget["live"] -= 1

    def error(self, stage, role, code, observed_errno=0):
        if len(self.errors) >= 256:
            raise Refused("error-record-bound")
        self.errors.append({"stage": stage, "role": role, "code": str(code)[:128],
                            "errno": observed_errno if isinstance(observed_errno, int) else 0})

    def roster(self, node):
        self.deadline.check()
        values = []
        # scandir(fd) owns a transient duplicate too; it is not a free slot.
        self.reserve("roster-descriptor-bound")
        try:
            iterator = os.scandir(node.fd)
        except OSError:
            self.budget["live"] -= 1  # No descriptor was returned.
            raise
        except BaseException:
            self.budget["uncertain"] = True
            raise
        try:
            for entry in iterator:
                self.deadline.check()
                name = entry.name
                if (len(values) >= MAX_ENTRIES or not name or name in (".", "..")
                        or len(name.encode("utf-8", "strict")) > 255):
                    raise Refused("directory-roster-bound")
                values.append(name)
        finally:
            try:
                iterator.close()
            except BaseException:
                self.budget["uncertain"] = True
                self.error("close", node.role, "roster-original-close-unknown")
                raise
            self.budget["live"] -= 1
        if len(set(values)) != len(values):
            raise Refused("duplicate-directory-entry")
        return sorted(values)

    def named_stat(self, node):
        if node.parent is None:
            return os.stat("/", follow_symlinks=False)
        return os.stat(node.name, dir_fd=node.parent.fd, follow_symlinks=False)

    def metadata(self, node, current, phase):
        mode = current.st_mode
        expected_type = {"directory": stat.S_ISDIR, "file": stat.S_ISREG,
                         "alias": stat.S_ISLNK}[node.kind]
        if not expected_type(mode):
            self.error(phase, node.role, "type-refused")
            return False
        if node.policy in ("native", "applications", "sudo", "alias"):
            if node.policy == "alias":
                if not _selection_alias_owner(current.st_uid, self.context["uid"]):
                    self.error(phase, node.role, "alias-root-or-current-account-required")
            elif current.st_uid != 0:
                self.error(phase, node.role, "root-owner-required")
            if node.policy == "applications":
                try:
                    _application_mode(full9(current))
                except Refused as error:
                    self.error(phase, node.role, error)
            elif node.policy == "alias":
                if current.st_nlink != 1 or not 1 <= current.st_size <= 1024:
                    self.error(phase, node.role, "alias-link-size")
            elif node.policy == "sudo":
                if (mode & 0o3022 or not mode & stat.S_ISUID or current.st_gid != 0
                        or current.st_nlink != 1 or not mode & 0o111):
                    self.error(phase, node.role, "fixed-os-sudo-not-protected-setuid-executable")
            elif mode & 0o7022:
                self.error(phase, node.role, "native-protected-mode-07022")
            if node.kind == "file" and (current.st_nlink != 1 or not mode & 0o111):
                self.error(phase, node.role, "single-link-executable-required")
        else:
            if current.st_uid not in (0, self.context["uid"]) or mode & 0o7022:
                self.error(phase, node.role, "context-owner-mode")
            if node.policy in ("work", "source-file") and current.st_uid != self.context["uid"]:
                self.error(phase, node.role, "job-user-original-required")
            if node.policy == "work" and mode != stat.S_IFDIR | 0o700:
                self.error(phase, node.role, "fresh-work-not-private")
            if node.kind == "file" and current.st_nlink != 1:
                self.error(phase, node.role, "context-single-link-required")
        return True

    def snapshot(self, node, phase):
        self.deadline.check()
        initial = os.fstat(node.fd)
        value = {"full9": full9(initial), "flags": getattr(initial, "st_flags", None)}
        named = self.named_stat(node)
        if full9(named) != value["full9"] or getattr(named, "st_flags", None) != value["flags"]:
            self.error(phase, node.role, "held-name-mismatch")
        valid_type = self.metadata(node, initial, phase)
        if not valid_type:
            return value
        if node.policy in ("native", "applications", "sudo", "alias", "work", "source-file"):
            try:
                filesystem = self.api.filesystem(node.fd)
                value["filesystem"] = filesystem
                if (filesystem["typeName"] != "apfs" or not filesystem["flags"] & MNT_LOCAL
                        or filesystem["flags"] & (MNT_UNION | MNT_AUTOMOUNTED | MNT_IGNORE_OWNERSHIP)):
                    self.error(phase, node.role, "native-apfs-local-mount-policy")
                if node.kind == "file" and node.policy in ("native", "sudo"):
                    if filesystem["flags"] & MNT_NOEXEC:
                        self.error(phase, node.role, "executable-noexec-mount")
                    if node.policy == "sudo" and filesystem["flags"] & MNT_NOSUID:
                        self.error(phase, node.role, "sudo-nosuid-mount")
                if (node.policy == "applications" and initial.st_mode == stat.S_IFDIR | 0o775
                        and filesystem["flags"] & MNT_RDONLY):
                    self.error(phase, node.role, "applications-readonly-mount")
            except (OSError, Refused, UnicodeError) as error:
                self.error(phase, node.role, "filesystem-" + type(error).__name__, getattr(error, "errno", 0))
            diagnostic = _acl_snapshot(self.api.library, node.fd, value["full9"])
            value["aclDiagnostic"] = diagnostic
            value["acl"] = {"empty": diagnostic["empty"], "kind": diagnostic["kind"],
                            "present": diagnostic["present"]}
            if not diagnostic["empty"]:
                self.error(phase, node.role, "native-empty-acl-required", diagnostic["errno"])
            if diagnostic.get("snapshotFlags") != value["flags"]:
                self.error(phase, node.role, "native-python-flags-mismatch")
            value["birthtimeNs"] = diagnostic.get("snapshotBirthtimeNs")
            if node.policy == "sudo":
                # O_EXEC need not authorize xattr reads. This fixed role needs
                # stability, not empty attributes. Positively prove an immutable
                # root snapshot before substituting that basis; never catch an
                # EACCES and call it success. All other roles still read xattrs.
                value["xattrs"] = None
                try:
                    root = self.nodes.get("/")
                    if root is None or root.fd is None or not root.expected:
                        raise Refused("sudo-snapshot-held-root-unavailable")
                    self.deadline.check()
                    root_filesystem = self.api.filesystem(root.fd)
                    if root_filesystem != root.expected.get("filesystem"):
                        raise Refused("sudo-snapshot-held-root-changed")
                    value["xattrStability"] = _sudo_xattr_basis(node, value, root_filesystem)
                except (OSError, Refused, UnicodeError) as error:
                    self.error(phase, node.role, str(error) if isinstance(error, Refused)
                               else "sudo-snapshot-observation-failed", getattr(error, "errno", 0))
            else:
                try:
                    value["xattrs"] = self.api.xattrs(node.fd)
                except (OSError, Refused, UnicodeError) as error:
                    self.error(phase, node.role, "xattr-" + type(error).__name__, getattr(error, "errno", 0))
            flags = value["flags"]
            if not isinstance(flags, int) or flags & ~_observation_flags(node.policy, node.kind):
                self.error(phase, node.role, "unknown-immutable-append-or-dataless-flags")
            elif (node.policy == "applications" and initial.st_mode == stat.S_IFDIR | 0o775
                  and flags & ~MODE_ONLY_FLAGS):
                self.error(phase, node.role, "applications-flags-not-mode-only-eligible")
        if node.kind == "alias":
            target = os.readlink(node.name, dir_fd=node.parent.fd)
            _sibling(target)
            value["aliasTarget"] = target
        if node.policy in ("applications", "source-directory", "work"):
            value["roster"] = self.roster(node)
        final = os.fstat(node.fd)
        final_named = self.named_stat(node)
        if (full9(final) != value["full9"] or full9(final_named) != value["full9"]
                or getattr(final, "st_flags", None) != value["flags"]
                or getattr(final_named, "st_flags", None) != value["flags"]):
            self.error(phase, node.role, "snapshot-changed-during-observation")
        self.deadline.check()
        return value

    def open(self, parent, name, kind, policy, role):
        self.deadline.check()
        path = "/" if parent is None and name == "/" else (
            (parent.path.rstrip("/") + "/" + name) if parent is not None else name)
        if path in self.nodes:
            node = self.nodes[path]
            if node.kind != kind:
                self.error("acquire", role, "duplicate-path-role-type")
            return node
        node = Node(path, role, parent, name, kind, policy)
        self.nodes[path] = node
        if (len(path.encode()) > MAX_PATH or (parent is not None and parent.fd is None)
                or (parent is None and name != "/")):
            self.error("acquire", role, "unavailable-parent-or-path")
            return node
        try:
            named = self.named_stat(node)
            expected = {"directory": stat.S_ISDIR, "file": stat.S_ISREG, "alias": stat.S_ISLNK}[kind]
            if not expected(named.st_mode):
                if self.classification:
                    # A type-negative never follows this name. A later strict
                    # named POST is required before calling it a stable negative.
                    node.pre = {"full9": full9(named), "flags": getattr(named, "st_flags", None)}
                    node.expected = node.pre
                self.error("acquire", role, "unavailable-invalid-type-no-follow")
                return node
            flags = os.O_NONBLOCK | os.O_CLOEXEC
            if kind == "alias":
                # Darwin O_SYMLINK clears FOLLOW itself (vfs_vnops.c). Acquire
                # the alias vnode, not its target, through the original parent.
                flags |= O_SYMLINK | os.O_RDONLY
            else:
                flags |= os.O_NOFOLLOW
                # O_EXEC explicitly excludes FREAD/FWRITE. O_EVTONLY alone
                # does not: it may still require content-read authorization.
                flags |= O_EXEC if policy == "sudo" else os.O_RDONLY
            if kind == "directory":
                flags |= os.O_DIRECTORY
            self.reserve("original-descriptor-bound")
            try:
                node.fd = os.open(name, flags, **({} if parent is None else {"dir_fd": parent.fd}))
            except OSError:
                self.budget["live"] -= 1  # Definitively no returned original.
                raise
            except BaseException:
                self.budget["uncertain"] = True
                node.close_state = "unknown"
                raise
            node.budgeted = True
            node.close_state = "owned"
            if full9(os.fstat(node.fd)) != full9(named):
                self.error("acquire", role, "lstat-opened-identity-mismatch")
            node.pre = self.snapshot(node, "initial")
            node.expected = node.pre
            if kind == "alias":
                node.alias_target = node.pre.get("aliasTarget")
        except (OSError, Refused, UnicodeError) as error:
            self.error("acquire", role, type(error).__name__ + ":" + (str(error) if isinstance(error, Refused) else "observation-failed"),
                       getattr(error, "errno", 0))
        return node

    def chain(self, parent, components, prefix, policy="native"):
        for index, name in enumerate(components):
            parent = self.open(parent, name, "directory", policy, prefix + ":" + str(index))
        return parent

    def context_chain(self, path, final_policy):
        if not path.startswith("/") or any(x in ("", ".", "..") for x in path[1:].split("/")):
            raise Refused("context-path-shape")
        parent = self.nodes["/"]
        parts = path[1:].split("/")
        for index, name in enumerate(parts):
            policy = final_policy if index == len(parts) - 1 else "shared-identity"
            parent = self.open(parent, name, "directory", policy, "context:" + name)
        return parent

    def read(self, node, limit):
        self.deadline.check()
        if node.fd is None or node.pre is None or node.kind != "file":
            raise Refused("unavailable-source-original")
        size = node.pre["full9"][6]
        if not 0 <= size <= limit:
            raise Refused("source-read-bound")
        os.lseek(node.fd, 0, os.SEEK_SET)
        chunks = []
        used = 0
        while True:
            self.deadline.check()
            block = os.read(node.fd, min(65536, limit + 1 - used))
            if not block:
                break
            chunks.append(block)
            used += len(block)
            if used > size or used > limit:
                raise Refused("source-original-grew")
        if used != size or full9(os.fstat(node.fd)) != node.pre["full9"]:
            raise Refused("source-original-read-changed")
        data = b"".join(chunks)
        if node.bytes is not None and node.bytes != data:
            raise Refused("source-original-bytes-changed")
        node.bytes = data
        return data

    def absence(self, parent, name, role):
        observation = {"parent": parent.path, "name": name, "role": role, "absent": False}
        if parent.fd is None:
            self.error("absence", role, "unavailable-parent")
        else:
            try:
                os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                observation["absent"] = True
            except OSError as error:
                self.error("absence", role, "absence-not-established", error.errno)
            else:
                self.error("absence", role, "preexisting-installation-or-worker-input")
        self.absences.append((parent, observation))

    def refresh_work(self, added):
        errors_before = len(self.errors)
        current = self.snapshot(self.work, "own-receipt-create")
        previous = self.work.expected
        expected_names = sorted([*self.work_names, added])
        required = {"full9", "flags", "filesystem", "aclDiagnostic", "acl",
                    "birthtimeNs", "xattrs", "roster"}
        if (not previous or not required.issubset(previous) or not required.issubset(current)
                or len(previous["full9"]) != 9 or len(current["full9"]) != 9):
            raise Refused("private-work-changed-beyond-own-receipt:incomplete-snapshot")
        before, after = previous["full9"], current["full9"]
        faults = []
        if len(self.errors) != errors_before:
            faults.append("snapshot-errors")
        if previous["roster"] != self.work_names:
            faults.append("prior-roster")
        if added not in self.receipt_names or added in self.work_names:
            faults.append("receipt-name")
        if after[:5] != before[:5]:
            faults.append("identity")
        if previous["filesystem"].get("typeName") != "apfs":
            faults.append("not-apfs")
        # This APFS private directory contains only independently admitted
        # regular inventory/receipt leaves. One exclusive own entry adds one
        # link; arbitrary nlink drift or any extra roster entry is not allowed.
        if (before[5] != 2 + len(self.work_names) or after[5] != before[5] + 1
                or after[5] != 2 + len(expected_names)):
            faults.append("links")
        if after[7] < before[7] or after[8] < before[8]:
            faults.append("clock")
        if ({k: v for k, v in _unchanged_payload(current).items() if k != "roster"}
                != {k: v for k, v in _unchanged_payload(previous).items() if k != "roster"}):
            faults.append("extras")
        if current["roster"] != expected_names:
            faults.append("roster")
        if faults:
            # Fixed labels and native link integers only, never arbitrary names
            # or environment/file contents. Useful even if RESULT already exists.
            raise Refused("private-work-changed-beyond-own-receipt:"
                          + ",".join(faults) + f";links={before[5]}->{after[5]}")
        self.work_names = expected_names
        self.work_transitions.append({"added": added, "full9": current["full9"], "roster": expected_names})
        self.work.expected = current

    def recheck(self, phase, applications_transition=False):
        self.deadline.check()
        for node in self.nodes.values():
            if node.fd is None:
                if self.classification and node.pre is not None and node.close_state == "not-opened":
                    try:
                        named = self.named_stat(node)
                        node.post = {"full9": full9(named), "flags": getattr(named, "st_flags", None)}
                        if not _same_snapshot(node.pre, node.post):
                            self.error(phase, node.role, "type-negative-name-changed")
                    except (OSError, Refused, UnicodeError) as error:
                        self.error(phase, node.role, "type-negative-post-unavailable", getattr(error, "errno", 0))
                continue
            count = len(self.errors)
            try:
                observed = self.snapshot(node, phase)
                before = node.expected
                if node.policy == "shared-identity" and not self.classification:
                    same = (before is not None and before["full9"][:5] == observed["full9"][:5]
                            and before["flags"] == observed["flags"])
                else:
                    same = _same_snapshot(before, observed,
                                          applications_transition and node is self.applications)
                if not same:
                    self.error(phase, node.role, "original-post-identity-or-extra-mismatch")
                if node.bytes is not None:
                    self.read(node, 2 * 1024 * 1024)
                if phase in ("post", "refusal-post", "final-before-closes"):
                    node.post = observed
                elif not same:
                    node.checks.append({"phase": phase, "mismatch": observed})
            except (OSError, Refused, UnicodeError) as error:
                self.error(phase, node.role, type(error).__name__, getattr(error, "errno", 0))
            node.checks.append({"phase": phase, "passed": len(self.errors) == count})
        for parent, observation in self.absences:
            if parent.fd is None:
                continue
            try:
                os.stat(observation["name"], dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as error:
                self.error(phase, observation["role"], "absence-no-longer-established", error.errno)
            else:
                self.error(phase, observation["role"], "stale-installation-appeared")
        if self.intent_pin is not None:
            current = os.stat(INTENT, dir_fd=self.work.fd, follow_symlinks=False)
            if full9(current) != self.intent_pin["full9"]:
                self.error(phase, "intent", "immutable-intent-name-changed")
        if self.result_fd is not None:
            current = full9(os.fstat(self.result_fd))
            result_name = self.result_pin["name"]
            if result_name not in self.receipt_names:
                raise Refused("fixed-result-name-required")
            named = full9(os.stat(result_name, dir_fd=self.work.fd, follow_symlinks=False))
            os.lseek(self.result_fd, 0, os.SEEK_SET)
            observed = bytearray()
            while True:
                self.deadline.check()
                block = os.read(self.result_fd, min(65536, MAX_RECORD + 1 - len(observed)))
                if not block:
                    break
                observed.extend(block)
                if len(observed) > MAX_RECORD:
                    raise Refused("final-result-readback-bound")
            if (current != self.result_pin["full9"] or named != current
                    or full9(os.fstat(self.result_fd)) != current
                    or full9(os.stat(result_name, dir_fd=self.work.fd, follow_symlinks=False)) != current
                    or bytes(observed) != self.result_bytes):
                self.error(phase, "result", "original-result-readback-changed")
        self.deadline.check()

    def receipt(self, name, value, retain=False):
        if (self.work is None or self.work.fd is None or not self.work_admitted
                or name not in self.receipt_names or (retain and self.result_fd is not None)):
            raise Refused("receipt-private-work-unavailable")
        if name in self.receipt_attempts:
            raise Refused("receipt-name-already-attempted")
        self.deadline.check()
        data = _json_bytes(value)
        self.reserve("receipt-descriptor-bound")
        self.receipt_attempts.add(name)
        try:
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=self.work.fd)
        except OSError:
            self.budget["live"] -= 1
            raise
        except BaseException:
            self.budget["uncertain"] = True
            raise
        retained = False
        try:
            offset = 0
            while offset < len(data):
                self.deadline.check()
                count = os.write(descriptor, data[offset:])
                if count <= 0:
                    raise Refused("receipt-write")
                offset += count
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            os.fsync(self.work.fd)
            before = full9(os.fstat(descriptor))
            os.lseek(descriptor, 0, os.SEEK_SET)
            reread = bytearray()
            while True:
                self.deadline.check()
                block = os.read(descriptor, min(65536, MAX_RECORD + 1 - len(reread)))
                if not block:
                    break
                reread.extend(block)
                if len(reread) > MAX_RECORD:
                    raise Refused("receipt-readback-bound")
            if (bytes(reread) != data or full9(os.fstat(descriptor)) != before
                    or full9(os.stat(name, dir_fd=self.work.fd, follow_symlinks=False)) != before
                    or before[2] != stat.S_IFREG | 0o400 or before[5] != 1):
                raise Refused("receipt-readback-identity")
            self.refresh_work(name)
            pin = {"name": name, "full9": before, "size": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(), "fsyncedReadback": True}
            if retain:
                self.result_fd = descriptor
                self.result_pin = pin
                self.result_bytes = data
                self.result_budgeted = True
                retained = True
            return pin
        finally:
            if not retained:
                self.consuming_close(descriptor)  # Failure vetoes the claim; never retry.

    def close_all(self):
        errors = []
        if self.result_fd is not None:
            descriptor, self.result_fd = self.result_fd, None
            budgeted, self.result_budgeted = self.result_budgeted, False
            try:
                self.consuming_close(descriptor, budgeted)
            except BaseException:
                errors.append("result-original-close-unknown")
        for node in reversed(list(self.nodes.values())):
            if node.fd is None:
                continue
            descriptor, node.fd = node.fd, None
            budgeted, node.budgeted = node.budgeted, False
            node.close_state = "closing"
            try:
                self.consuming_close(descriptor, budgeted)
                node.close_state = "closed"
            except BaseException:
                node.close_state = "unknown"
                errors.append(node.role + ":original-close-unknown")
        return errors


def _collect_xcode_chain(book, applications, selected, stop_on_error=False):
    """The same eleven concrete roles, never an alternate selector/tool query."""
    if selected is None:
        app = Node("/Applications/Xcode.app", "selected-xcode-unavailable", applications,
                   "Xcode.app", "directory", "native")
    else:
        app = book.open(applications, selected, "directory", "native", "selected-xcode")
    nodes = [app]
    for parent_index, name, kind, role in (
            (0, "Contents", "directory", "xcode-developer:0"),
            (1, "Developer", "directory", "xcode-developer:1"),
            (2, "usr", "directory", "xcode-tool-bin:0"),
            (3, "bin", "directory", "xcode-tool-bin:1"),
            (4, "xcodebuild", "file", "xcodebuild"),
            (2, "Platforms", "directory", "iphoneos-sdk:0"),
            (6, "iPhoneOS.platform", "directory", "iphoneos-sdk:1"),
            (7, "Developer", "directory", "iphoneos-sdk:2"),
            (8, "SDKs", "directory", "iphoneos-sdk:3"),
            (9, "iPhoneOS.sdk", "directory", "iphoneos-sdk:4")):
        if stop_on_error and book.errors:
            break
        nodes.append(book.open(nodes[parent_index], name, kind, "native", role))
    return nodes


def _collect_prerequisites(book):
    """Batch all safely reachable roles; one bad ancestor does not hide siblings."""
    root = book.open(None, "/", "directory", "native", "root")
    applications = book.open(root, "Applications", "directory", "applications", "applications")
    book.applications = applications
    selected = "Xcode.app"
    if applications.fd is not None:
        try:
            named = os.stat("Xcode.app", dir_fd=applications.fd, follow_symlinks=False)
            if stat.S_ISLNK(named.st_mode):
                alias = book.open(applications, "Xcode.app", "alias", "alias", "xcode-alias")
                if (alias.pre is None or not _selection_alias_owner(alias.pre["full9"][3], book.context["uid"])
                        or alias.pre["full9"][5] != 1
                        or not 1 <= alias.pre["full9"][6] <= 1024 or alias.alias_target is None):
                    raise Refused("invalid-alias-no-descendant-follow")
                selected = _sibling(alias.alias_target)
        except (OSError, Refused, UnicodeError) as error:
            book.error("selection", "xcode-alias", type(error).__name__, getattr(error, "errno", 0))
            selected = None
    _collect_xcode_chain(book, applications, selected)
    system_bin = book.chain(root, ("usr", "bin"), "fixed-system-bin")
    for name in ("security", "codesign", "openssl"):
        book.open(system_bin, name, "file", "native", "signing-recovery:" + name)
    book.open(system_bin, "sudo", "file", "sudo", "os-provisioner-sudo")
    bin_directory = book.open(root, "bin", "directory", "native", "fixed-os-bin")
    book.open(bin_directory, "chmod", "file", "native", "os-provisioner-chmod")
    library = book.open(root, "Library", "directory", "shared-identity", "installation-parent")
    support = book.open(library, "Application Support", "directory", "shared-identity", "installation-support")
    book.absence(support, "MobileReleaseKit", "fixed-install-root-and-versioned-runtime")
    book.absence(applications, "Mobile Release Kit.app", "legacy-app-location")
    book.absence(applications, "MobileReleaseKit.app", "legacy-unspaced-app-location")


def _inventory_tree(files):
    tree = {}
    paths = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "gitMode", "blob", "size", "sha256"}:
            raise Refused("inventory-leaf-schema")
        name = item["path"]
        if (not isinstance(name, str) or not name or len(name.encode()) > MAX_PATH
                or "\\" in name or "\0" in name or any(p in ("", ".", "..") for p in name.split("/"))
                or name in paths or item["gitMode"] not in ("100644", "100755")
                or not isinstance(item["blob"], str) or not re.fullmatch(r"[0-9a-f]{40}", item["blob"])
                or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or type(item["size"]) is not int or not 0 <= item["size"] <= 32 * 1024 * 1024):
            raise Refused("inventory-leaf-shape")
        paths.add(name)
        components = name.split("/")
        branch = tree
        for component in components[:-1]:
            branch = branch.setdefault(component, {})
            if not isinstance(branch, dict):
                raise Refused("inventory-file-directory-collision")
        if components[-1] in branch:
            raise Refused("inventory-directory-file-collision")
        branch[components[-1]] = (item["gitMode"], item["blob"])
    def digest(branch):
        body = bytearray()
        for name in sorted(branch, key=lambda n: n.encode() + (b"/" if isinstance(branch[n], dict) else b"")):
            item = branch[name]
            mode, oid = ("40000", digest(item)) if isinstance(item, dict) else item
            body.extend(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()
    return digest(tree)


def _bind_source(book):
    context_errors = len(book.errors)
    work = book.context_chain(book.context["work"], "work")
    book.work = work
    if (work.pre is None or work.pre.get("roster") != [INVENTORY]
            or len(book.errors) != context_errors):
        raise Refused("fresh-private-work-must-contain-only-source-inventory")
    book.work_admitted = True
    inventory_node = book.open(work, INVENTORY, "file", "source-file", "complete-source-inventory")
    raw = book.read(inventory_node, 2 * 1024 * 1024)
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (not isinstance(value, dict) or set(value) != {"source", "tree", "files"}
            or value["source"] != book.context["source"] or not isinstance(value["tree"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["tree"])
            or not isinstance(value["files"], list) or not 1 <= len(value["files"]) <= 4096
            or _inventory_tree(value["files"]) != value["tree"]):
        raise Refused("complete-source-inventory-binding")
    leaves = {item["path"]: item for item in value["files"]}
    if any(name not in leaves for name in (HELPER, WORKFLOW, TEST_SOURCE)):
        raise Refused("reviewed-three-leaf-inventory-required")
    checkout = book.context_chain(WORKSPACE, "source-directory")
    bindings = []
    for name in (WORKFLOW, HELPER):
        components = name.split("/")
        parent = book.chain(checkout, components[:-1], "source:" + name, "source-directory")
        node = book.open(parent, components[-1], "file", "source-file", "source:" + name)
        data = book.read(node, 131072)
        item = leaves[name]
        if (len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]
                or hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != item["blob"]):
            raise Refused("source-helper-workflow-not-original-inventory")
        bindings.append({"path": name, "size": len(data), "sha256": item["sha256"], "blob": item["blob"]})
    expected_argv = [WORKSPACE + "/" + HELPER] + ([CLASSIFICATION_ARG] if book.classification else [])
    if (os.getcwd() != WORKSPACE or os.path.abspath(__file__) != WORKSPACE + "/" + HELPER
            or sys.argv != expected_argv):
        raise Refused("fixed-helper-launch-path-required")
    book.source_binding = {"source": value["source"], "tree": value["tree"],
                           "completeInventorySha256": hashlib.sha256(raw).hexdigest(),
                           "inventoryLeaves": len(leaves), "heldSourceBindings": bindings}


def _eligible_action(book):
    if book.errors or book.applications is None or book.applications.pre is None:
        return None
    return _application_mode(book.applications.pre["full9"])


def _classification_objects(book):
    """Compact policy facts, not a recursive inventory or native admission."""
    result = []
    for node in book.nodes.values():
        before, after = node.pre or {}, node.post or {}
        fs, acl = before.get("filesystem", {}), before.get("acl", {})
        result.append({"role": node.role, "name": node.name, "kind": node.kind,
                       "preFull9": before.get("full9"), "postFull9": after.get("full9"),
                       "flags": before.get("flags"), "aclKind": acl.get("kind"),
                       "filesystemType": fs.get("typeName"), "filesystemFlags": fs.get("flags"),
                       "filesystemOwner": fs.get("owner"),
                       "xattrCount": len(before["xattrs"]) if isinstance(before.get("xattrs"), list) else None,
                       "strictPostMatched": _same_snapshot(node.pre, node.post),
                       "finalClose": "pending-original-helper-exit" if node.fd is not None else node.close_state})
    return result


def _classification_policy_known(book):
    # These are observed policy negatives, not substitutes for failed reads.
    # Every acquired original still needs its complete snapshot and strict POST.
    known = {"root-owner-required", "native-protected-mode-07022", "single-link-executable-required",
             "native-apfs-local-mount-policy", "executable-noexec-mount",
             "unknown-immutable-append-or-dataless-flags", "unavailable-invalid-type-no-follow",
             "native-empty-acl-required"}
    if any(error["code"] not in known for error in book.errors):
        return False
    required = {"full9", "flags", "filesystem", "acl", "aclDiagnostic", "birthtimeNs", "xattrs"}
    for node in book.nodes.values():
        if not _same_snapshot(node.pre, node.post):
            return False
        if node.close_state == "not-opened":
            # Only a twice-observed wrong type has no original to consume.
            if not any(error["role"] == node.role and error["code"] == "unavailable-invalid-type-no-follow"
                       for error in book.errors):
                return False
            continue
        if node.close_state != "closed":
            return False
        for snapshot in (node.pre, node.post):
            if not required.issubset(snapshot):
                return False
            diagnostic = snapshot["aclDiagnostic"]
            if (not diagnostic.get("filesecFreeReturned") or diagnostic.get("aclFreeException")
                    or diagnostic.get("filesecFreeException") or diagnostic.get("exception")
                    or diagnostic.get("snapshotFull9") != snapshot["full9"]
                    or diagnostic.get("snapshotFlags") != snapshot["flags"]):
                return False
            if snapshot["acl"]["empty"]:
                if diagnostic.get("phase") != 0:
                    return False
            elif (diagnostic.get("kind") != "contains-entry" or diagnostic.get("phase") != 11
                  or diagnostic.get("aclFreeResult") != 0):
                return False
    return not book.budget["uncertain"]


def _classify_candidate(common, name):
    book = Originals(common.api, common.context, common.deadline,
                     budget=common.budget, classification=True)
    alias = None
    close_errors = []
    try:
        common.deadline.check()
        if name == "Xcode.app" and stat.S_ISLNK(
                os.stat(name, dir_fd=common.applications.fd, follow_symlinks=False).st_mode):
            # Observe the one selection alias itself; never walk its target.
            alias = book.open(common.applications, name, "alias", "alias", "xcode-alias-selection-only")
        else:
            _collect_xcode_chain(book, common.applications, name, stop_on_error=True)
        book.recheck("post")
        common.recheck("classification-candidate-post")
        common.deadline.check()
    except BaseException as error:
        book.error("classification", "candidate", type(error).__name__
                   + (":" + str(error) if isinstance(error, Refused) else ""), getattr(error, "errno", 0))
    finally:
        close_errors = book.close_all()
    for detail in close_errors:
        common.error("close", "candidate", detail)
    known = not common.errors and not close_errors and _classification_policy_known(book)
    complete_chain = alias is None and len(book.nodes) == 11 and not book.errors
    outcome = "unresolved"
    if known:
        outcome = "ineligible" if book.errors or alias is not None else ("eligible" if complete_chain else "unresolved")
    return {"name": name, "outcome": outcome, "completeChain": complete_chain,
            "selectionDataOnly": alias is not None,
            "selectionTarget": alias.alias_target if alias is not None else None,
            "reasons": book.errors, "objects": _classification_objects(book),
            "closeErrors": close_errors}


def _classification_report(book, state):
    return {"schemaVersion": 1, "scope": "dedicated-disposable-macos-xcode-installed-classification",
            "context": book.context, "sourceBinding": book.source_binding,
            "phase": "classification-final-closes-pending", "prepared": False,
            "consumerQualified": False, "nativeQualified": False,
            "command": {"claimed": False, "retirement": "not-started"}, "intent": None,
            "completionAuthority": "same-original-helper-exit0-after-all-input-work-result-closes",
            "applicationsActionStillRequired": _application_mode(book.applications.pre["full9"])
            if book.applications is not None and book.applications.pre is not None and not book.errors else None,
            "classification": state, "commonObjects": _classification_objects(book),
            "errors": book.errors[:16], "errorCount": len(book.errors), "errorsTruncated": len(book.errors) > 16,
            "bounds": {"absoluteSeconds": 60, "aggregateDescriptors": MAX_ORIGINALS,
                       "applicationsEntries": MAX_ENTRIES, "recordBytes": MAX_RECORD},
            "descriptorBudgetBeforeReceipt": dict(book.budget)}


def _classify_installed(book, state):
    """Sequential observation only; no old 38-original preparer or command owner."""
    root = book.open(None, "/", "directory", "native", "root")
    book.applications = book.open(root, "Applications", "directory", "applications", "applications")
    _bind_source(book)
    book.recheck("classification-common-before-enumeration")
    if book.errors or book.applications.pre is None:
        raise Refused("classification-common-admission-incomplete")
    roster = book.applications.pre["roster"]
    names = []
    for name in roster:
        try:
            if name != "Xcode.app":
                _sibling(name)
        except Refused:
            continue
        names.append(name)
    state.update(rosterEntries=len(roster), candidateNames=len(names), excludedNames=len(roster) - len(names))
    for name in names:
        book.deadline.check()
        record = _classify_candidate(book, name)
        state["observations"].append(record)
        try:
            # Leave a fixed small margin for final common observations/errors;
            # the actual final escaped aggregate is checked again by receipt.
            _json_bytes(_classification_report(book, state), MAX_RECORD - 8192)
        except Refused:
            state["observations"].pop()
            state["omittedObservations"] += 1
            raise Refused("classification-report-bound")
        if record["outcome"] == "unresolved" or book.budget["uncertain"] or book.errors:
            raise Refused("classification-candidate-incomplete")
        # No next candidate can acquire a slot before all previous closes and
        # this same absolute deadline check; uncertain capacity is never reused.
        book.deadline.check()
    book.recheck("post")
    if book.errors:
        raise Refused("classification-common-post-incomplete")
    state["complete"] = True


def _classification_main(deadline):
    book = None
    state = {"complete": False, "observations": [], "omittedObservations": 0,
             "rosterEntries": None, "candidateNames": None, "excludedNames": None}
    result_written = False
    final_errors = []
    try:
        u = os.uname()
        context = _validate_context(dict(os.environ),
                                    (os.getuid(), os.geteuid(), os.getgid(), os.getegid()),
                                    (u.sysname, u.machine), sys.version_info[:3],
                                    (sys.flags.isolated, sys.flags.no_site, sys.dont_write_bytecode))
        api = DarwinAPI(deadline)
        context["macosVersion"] = api.version
        context["dataPython"] = "3.14.7-isolated-no-site-no-bytecode"
        book = Originals(api, context, deadline, classification=True)
        _classify_installed(book, state)
        book.receipt(CLASSIFICATION_RESULT, _classification_report(book, state), retain=True)
        result_written = True
        book.recheck("final-before-closes")
        if book.errors:
            state["complete"] = False
        deadline.check()
    except BaseException as error:
        state["complete"] = False
        final_errors.append(type(error).__name__ + (":" + str(error) if isinstance(error, Refused) else ""))
        if book is not None:
            try:
                book.error("classification", "helper", final_errors[-1], getattr(error, "errno", 0))
                if (book.work_admitted and not result_written
                        and CLASSIFICATION_RESULT not in book.receipt_attempts):
                    book.receipt(CLASSIFICATION_RESULT, _classification_report(book, state), retain=True)
                    result_written = True
            except BaseException as report_error:
                final_errors.append("result-" + type(report_error).__name__)
    finally:
        if book is not None:
            final_errors.extend(book.close_all())
    try:
        deadline.check()
    except Refused:
        final_errors.append("final-deadline")
    if (book is not None and state["complete"] and result_written and not final_errors
            and not book.budget["uncertain"] and book.budget["live"] == 0):
        return 0  # Complete classification, including a complete negative, NOT preparation.
    if book is not None:
        # Unknown custody can forbid even receipt acquisition. Preserve the
        # bounded original close cause using inherited stderr, never a new FD.
        close_details = [{"role": item["role"][:64], "code": item["code"][:128]}
                         for item in book.errors if item["stage"] == "close"][:4]
        if close_details:
            print("Classification original close uncertainty: "
                  + _json_bytes(close_details, 8192).decode("ascii").rstrip(), file=sys.stderr, flush=True)
    print("Xcode installed classification incomplete; no preparation/native authority."
          + (" Final owner errors: " + ",".join(final_errors) if final_errors else ""),
          file=sys.stderr, flush=True)
    return 1


def _command_acknowledged(value):
    pid, status = value.get("originalPid"), value.get("rawWaitStatus")
    return (value.get("claimed") is True and value.get("spawnReturned") is True
            and value.get("waitApi") == "os.waitpid-original-PID-WNOHANG"
            and type(pid) is int and pid > 0 and type(value.get("waitedPid")) is int
            and value.get("waitedPid") == pid and type(status) is int
            and 0 <= status <= 65535 and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            and value.get("waitStatusLost") is False
            and value.get("joinedOriginal") is True and value.get("returncode") == 0
            and type(value.get("returncode")) is int and value.get("stdoutEof") is True
            and value.get("stderrEof") is True and value.get("stdoutClosed") is True
            and value.get("stderrClosed") is True and value.get("errors") == []
            and value.get("retirement") == "settled")


class FixedCommandOwner:
    def __init__(self, work, deadline, retained_originals, api):
        self.work, self.deadline, self.api = work, deadline, api
        self.retained_originals = retained_originals
        self.process = None
        self.streams = {}
        self.capture = {"stdout": bytearray(), "stderr": bytearray()}
        self.signal_policy = None
        self.numeric_route = False
        self.numeric_retired = False
        self.state = {"argv": list(COMMAND), "claimed": False, "spawnReturned": False,
                      "originalPid": None, "waitedPid": None, "rawWaitStatus": None,
                      "waitApi": "os.waitpid-original-PID-WNOHANG", "waitStatusLost": False,
                      "joinedOriginal": False, "returncode": None,
                      "stdoutEof": False, "stderrEof": False,
                      "stdoutClosed": False, "stderrClosed": False,
                      "sigchldPolicy": None, "sigchldChecks": 0,
                      "numericSignalRoute": "not-created",
                      "retirement": "not-started", "errors": [], "signals": []}

    def note(self, code):
        if code not in self.state["errors"] and len(self.state["errors"]) < 16:
            self.state["errors"].append(code)

    def check_sigchld(self):
        self.state["sigchldChecks"] += 1
        observed = self.api.waitable_sigchld()
        if self.signal_policy is None:
            self.signal_policy = observed
            self.state["sigchldPolicy"] = observed
        elif observed != self.signal_policy:
            raise Refused("native-sigchld-policy-drift")

    def retire_numeric(self, reason):
        self.numeric_route = False
        self.numeric_retired = True
        self.state["numericSignalRoute"] = reason

    def wait_original(self):
        if self.state["joinedOriginal"]:
            return  # The one terminal original receipt is latched, never reaped twice.
        if self.numeric_retired:
            raise Refused("original-numeric-routes-permanently-retired")
        # Disable any numeric signal route BEFORE a call that may reap the child.
        self.numeric_route = False
        self.state["numericSignalRoute"] = "retired-before-original-wait"
        self.check_sigchld()
        waited, status = os.waitpid(self.state["originalPid"], os.WNOHANG)
        if type(waited) is not int or type(status) is not int:
            raise Refused("original-wait-status-shape")
        if waited == 0:
            if status != 0:
                raise Refused("original-no-result-status-ambiguous")
            self.numeric_route = True
            self.state["numericSignalRoute"] = "armed-only-by-original-wait-no-result"
            return
        self.retire_numeric("retired-terminal-or-ambiguous-wait")
        if (waited != self.state["originalPid"] or not 0 <= status <= 65535
                or not (os.WIFEXITED(status) or os.WIFSIGNALED(status))):
            raise Refused("original-wait-not-exact-terminal-status")
        observed = os.waitstatus_to_exitcode(status)
        # CPython poll/wait may turn ECHILD into zero. Neither is called here.
        # Setting this only from our raw receipt prevents destructor reaping.
        self.process.returncode = observed
        self.state.update(waitedPid=waited, rawWaitStatus=status,
                          joinedOriginal=True, returncode=observed)

    def signal_original(self, number, label, stop_end):
        if self.numeric_retired or not self.numeric_route or self.state["joinedOriginal"]:
            raise Refused("original-signal-route-not-waitable")
        # Consume this route even if sigaction or kill raises. A second route
        # requires another actual waitpid(original, WNOHANG) no-result receipt.
        self.numeric_route = False
        self.state["numericSignalRoute"] = "consumed-before-" + label
        self.check_sigchld()
        if time.monotonic() >= stop_end:
            raise Refused("original-stop-route-deadline")
        self.state["signals"].append("original-" + label + "-attempted-once")
        os.kill(self.state["originalPid"], number)

    def run(self):
        if self.state["claimed"]:
            raise Refused("privileged-claim-already-used")
        self.deadline.check()
        self.check_sigchld()  # Actual readonly sigaction before any child/effect.
        # At most two retained capture descriptors in addition to the originals.
        # Popen's temporary launch plumbing is closed by its own constructor.
        if self.retained_originals + 2 > MAX_ORIGINALS:
            raise Refused("command-original-and-capture-descriptor-bound")
        command_end = min(self.deadline.end - STOP_GRACE_SECONDS,
                          time.monotonic() + COMMAND_SECONDS)
        if command_end <= time.monotonic():
            raise Refused("no-command-retirement-budget")
        self.state.update(claimed=True, retirement="unknown")
        environment = {"PATH": SAFE_PATH, "HOME": self.work, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
        try:
            self.process = subprocess.Popen(COMMAND, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            cwd="/", env=environment, close_fds=True,
                                            start_new_session=True)
            self.state["spawnReturned"] = True
            if type(self.process.pid) is not int or self.process.pid <= 0:
                raise Refused("original-child-pid-unavailable")
            self.state["originalPid"] = self.process.pid
            for name, stream in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
                self.streams[name] = stream
                os.set_blocking(stream.fileno(), False)
        except BaseException as error:
            self.retire_numeric("retired-unknown-spawn-or-capture")
            self.note("spawn-or-capture-" + type(error).__name__)
            return self.state  # Unknown; caller must retain this owner and park.
        stop_started = None
        terminated = False
        killed = False
        while True:
            now = time.monotonic()
            # Late terminal/EOF observations never bypass the command deadline.
            if now >= command_end and stop_started is None:
                self.note("original-command-deadline")
                stop_started = now
            pending = {stream.fileno(): name for name, stream in self.streams.items()
                       if not self.state[name + "Eof"]}
            try:
                if not self.state["joinedOriginal"]:
                    try:
                        self.wait_original()
                    except BaseException as error:
                        self.retire_numeric("retired-unknown-original-status")
                        self.state["waitStatusLost"] = True
                        self.note("original-wait-" + type(error).__name__)
                        break  # ECHILD/ambiguity: no synthetic zero or numeric stop.
                if self.state["joinedOriginal"] and not pending:
                    break
                if self.state["errors"] and stop_started is None:
                    stop_started = now
                if stop_started is not None:
                    stop_end = min(stop_started + STOP_GRACE_SECONDS, self.deadline.end)
                    if time.monotonic() >= stop_end:
                        break
                    try:
                        if not self.state["joinedOriginal"] and not terminated:
                            terminated = True
                            self.signal_original(signal.SIGTERM, "SIGTERM", stop_end)
                        elif (now >= stop_started + 1.0 and not killed
                              and not self.state["joinedOriginal"]):
                            killed = True
                            self.signal_original(signal.SIGKILL, "SIGKILL", stop_end)
                    except BaseException as error:
                        self.retire_numeric("retired-unknown-signal-route")
                        self.note("original-signal-" + type(error).__name__)
                        break
                ready, _, _ = select.select(list(pending), [], [], 0.05)
                for descriptor in ready:
                    name = pending[descriptor]
                    try:
                        block = os.read(descriptor, MAX_STREAM + 1)
                    except BlockingIOError:
                        continue
                    if not block:
                        self.state[name + "Eof"] = True
                    elif len(self.capture[name]) + len(block) > MAX_STREAM:
                        available = MAX_STREAM - len(self.capture[name])
                        self.capture[name].extend(block[:available])
                        self.note(name + "-bound")
                    else:
                        self.capture[name].extend(block)
            except BaseException as error:
                self.note("original-owner-" + type(error).__name__)
                if stop_started is None:
                    stop_started = now
                if now >= stop_started + STOP_GRACE_SECONDS:
                    break
                time.sleep(0.01)
        self.retire_numeric("retired-terminal" if self.state["joinedOriginal"]
                            else "retired-unknown-original-status")
        if self.state["joinedOriginal"] and self.state["stdoutEof"] and self.state["stderrEof"]:
            for name, stream in self.streams.items():
                try:
                    stream.close()
                    self.state[name + "Closed"] = stream.closed
                    if not stream.closed:
                        self.note(name + "-close-not-returned")
                except BaseException as error:
                    self.note(name + "-close-" + type(error).__name__)
            if self.state["stdoutClosed"] and self.state["stderrClosed"]:
                self.state["retirement"] = "settled"
            # An uncertain capture close is still Unknown, not failed-but-retired.
        if time.monotonic() >= command_end:
            self.note("original-command-deadline")  # Includes final capture closes.
        for name, captured in self.capture.items():
            self.state[name + "Capture"] = {"bytes": len(captured),
                                            "sha256": hashlib.sha256(captured).hexdigest()}
        return self.state

    def park_until_disposal(self):
        # Deliberately no retry, restore, successful return, worker handoff or
        # speculative close. The workflow's finite timeout/VM teardown is the
        # outer owner. This original process retains child/pipes/books meanwhile.
        print("Xcode host preparation: original command retirement unknown; awaiting job disposal.",
              file=sys.stderr, flush=True)
        while True:
            try:
                signal.pause()
            except KeyboardInterrupt:
                continue


def _report(book, context, command, phase, eligible=False):
    return {"schemaVersion": 1, "scope": "dedicated-disposable-macos-xcode-ancestor-preparation",
            "context": context, "sourceBinding": book.source_binding,
            "phase": phase, "prepared": False,
            "provisionalPostAuditPassed": eligible,
            "completionAuthority": "same-original-helper-exit0-after-all-input-work-result-closes",
            "objects": [node.data() for node in book.nodes.values()],
            "absences": [observation for _, observation in book.absences],
            "workTransitions": book.work_transitions, "intent": book.intent_pin,
            "command": command, "errors": book.errors,
            "nativeQualified": False, "consumerQualified": False,
            "stockConsumer0775StillRejected": True,
            "disposal": {"providerObligation": "normal-per-job-GitHub-hosted-VM-teardown",
                         "physicallyVerified": False, "restore0775Command": None},
            "bounds": {"preparationSeconds": 60, "commandSeconds": 10, "stopGraceSeconds": 2,
                       "retainedDescriptorsIncludingCaptures": 40, "applicationsEntries": 512,
                       "streamBytesEach": 4096, "recordBytes": MAX_RECORD}}


def main():
    deadline = Deadline()
    if sys.argv[1:] == [CLASSIFICATION_ARG]:
        return _classification_main(deadline)
    book = None
    owner = None
    unknown = False
    candidate_success = False
    result_written = False
    command = {"claimed": False, "retirement": "not-started"}
    context = None
    final_errors = []
    try:
        if len(sys.argv) != 1:
            raise Refused("no-cli-arguments")
        u = os.uname()
        context = _validate_context(dict(os.environ),
                                    (os.getuid(), os.geteuid(), os.getgid(), os.getegid()),
                                    (u.sysname, u.machine), sys.version_info[:3],
                                    (sys.flags.isolated, sys.flags.no_site, sys.dont_write_bytecode))
        api = DarwinAPI(deadline)
        context["macosVersion"] = api.version
        context["dataPython"] = "3.14.7-isolated-no-site-no-bytecode"
        book = Originals(api, context, deadline)
        _collect_prerequisites(book)
        # This same step has not launched any candidate/toolchain worker. The
        # earlier unchanged inventory is SOURCE/DATA and the work roster proves
        # no earlier job preparer/tool binding output is being replayed.
        _bind_source(book)
        choice = None
        try:
            choice = _eligible_action(book)
        except Refused as error:
            book.error("eligibility", "applications", error)
        if not book.errors and choice is not None:
            book.recheck("before-intent")
        if not book.errors and choice is not None:
            intent = _report(book, context,
                             {"argv": list(COMMAND), "claimed": False, "selectedAction": choice},
                             "immutable-intent-before-sole-claim")
            book.intent_pin = book.receipt(INTENT, intent)
            # Intent descriptor already closed successfully; original input FDs
            # stay held. Creating this one known work entry is the only update
            # to the work directory expectation. Everything else is reobserved.
            book.recheck("immediate-before-claim")
            if not book.errors:
                if choice == "chmod":
                    owner = FixedCommandOwner(context["work"], deadline,
                                              sum(n.fd is not None for n in book.nodes.values()), api)
                    command = owner.run()
                    unknown = command["retirement"] != "settled"
                    if unknown:
                        book.error("command", "fixed-sudo-chmod", "original-retirement-unknown")
                    elif not _command_acknowledged(command):
                        book.error("command", "fixed-sudo-chmod", "original-command-not-acknowledged-success")
                else:
                    command = {"claimed": False, "retirement": "not-invoked-observed-noop",
                               "reason": "original-applications-already-root-admin0755"}
                if not unknown:
                    # Only an actual acknowledged successful original command
                    # earns the mode/ctime allowance. Noop/failure is exact full9.
                    book.recheck("post", applications_transition=(choice == "chmod"
                                                                  and _command_acknowledged(command)))
                    candidate_success = not book.errors
        if not unknown and not candidate_success:
            book.recheck("refusal-post")
        if unknown:
            # No invented post-state while an original effect may still run.
            book.receipt(RESULT, _report(book, context, command,
                                        "original-command-unretired-no-post-acceptance"), retain=True)
            result_written = True
            owner.park_until_disposal()
        if book.work is not None and book.work.fd is not None:
            book.receipt(RESULT, _report(book, context, command,
                                        "post-audit-passed-final-closes-pending" if candidate_success
                                        else "refused-final-closes-pending", candidate_success), retain=True)
            result_written = True
            book.recheck("final-before-closes", applications_transition=_command_acknowledged(command))
            candidate_success = candidate_success and not book.errors
            deadline.check()
    except BaseException as error:
        candidate_success = False
        if owner is not None and owner.state["claimed"] and owner.state["retirement"] != "settled":
            unknown = True
            owner.retire_numeric("retired-unknown-helper-exception")
            command = owner.state
        final_errors.append(type(error).__name__ + (":" + str(error) if isinstance(error, Refused) else ""))
        if book is not None:
            try:
                book.error("helper", "preparation", final_errors[-1], getattr(error, "errno", 0))
                if (not result_written and RESULT not in book.receipt_attempts
                        and book.work is not None and book.work.fd is not None):
                    # Exclusive create only. A partial/existing result is never
                    # overwritten or converted into success by another attempt.
                    book.receipt(RESULT, _report(book, context, command,
                                                "refused-exception-final-closes-pending"), retain=True)
                    result_written = True
            except Exception as reporting_error:
                final_errors.append("result-" + type(reporting_error).__name__)
        if unknown and owner is not None:
            owner.park_until_disposal()
    finally:
        if book is not None:
            final_errors.extend(book.close_all())
    try:
        deadline.check()
    except Refused:
        final_errors.append("final-deadline")
    if candidate_success and result_written and not final_errors:
        # No filesystem owner remains. The workflow's original successful step,
        # not prepared=false provisional JSON, is the sole preparation result.
        return 0
    print("Xcode host preparation refused; provisional records are not preparation authority."
          + (" Final owner errors: " + ",".join(final_errors) if final_errors else ""),
          file=sys.stderr, flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
