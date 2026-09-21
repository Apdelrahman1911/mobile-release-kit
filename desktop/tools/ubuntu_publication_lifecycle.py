"""Fixed Ubuntu P0/F1 lifecycle and installed candidate, never qualification.

The system manager owns the root service before its first input copy. Inside it
the protected current core owns ordinary commands. The nonroot systemd client
wait is necessary evidence, not authority to clean up privileged descendants.
No accounts, namespace/mount changes, general commands, retry or published-runtime cleanup.
"""
from __future__ import annotations

from copy import deepcopy
import errno
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time


ENTRY = "desktop/tools/ubuntu_publication_lifecycle.py"
TARGET = "x86_64-unknown-linux-gnu"
PACKAGE = "mobile-release-kit-desktop"
M = "e3375ff140d69df54b2445f756711e0245d397ba6ded76e8559732ec2e4e3801"
F1 = "3a075688d6bc7f69dbdaa017b5327d8ca892e12b49b0c2012a6cbea1f79a6061"
Q = "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e"
VERSIONS = {"P0": (M, "0.0.0+mrk.lifecycle.0"), "F1": (F1, "0.0.0+mrk.lifecycle.1")}
ROOT_TEST = "runtime_publication::platform_native_tests::root_exact_ubuntu_platform"
USER_TEST = "installed_runtime::platform_native_tests::nonroot_exact_ubuntu_platform"
INSTALLED_TESTS = {key: "supervisor::tests::installed_candidate_a_" + suffix for key, suffix in (
    ("positive", "capabilities_and_catalog_retire_originals"),
    ("refuse-writable", "writable_ancestor_refuses_and_retires"),
    ("refuse-pth", "extra_startup_refuses_and_retires"),
    ("deadline", "deadline_before_claim_retires"),
    ("shutdown", "shutdown_with_child_retires"),
    ("emfile", "creation_emfile_retains_unknown"),
    ("overlap", "child_spans_f1_publication"))}
CHILD_MARKER = "MRK_INSTALLED_NATIVE_CHILD="
EMFILE_MARKER = "MRK_INSTALLED_NATIVE_EMFILE_RETAINED_UNKNOWN"
SHELL_CASES = ("normal", "positive", "quit-outstanding")
SHELL_FEATURES = ["custom-protocol", "desktop-shell"]
SHELL_PROJECT_SOURCE = (b'plugins { id("com.android.application") }\n'
                        b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
# Fixed synthetic output DATA, not a second configuration serializer. The
# focused contract compares these bytes with the actual pure core suggestion
# and payload builders after the native Value wire's sorted-key round trip.
# Keeping DATA here avoids executing extra core modules in the root lifecycle.
SHELL_PROJECT_CONFIG = b'''{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "release/version.properties"
  }
}
'''
SHELL_PROJECT_IGNORE = (b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n"
                        b".mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n"
                        b".mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n")
SHELL_PROJECT_MARKER = b"MRK_INSTALLED_SHELL_PROJECT_DRAFT="
SHELL_PROJECT_RECEIPT = {
    "schemaVersion": 2, "fixture": "android-config-save-v1", "projectGateContract": True,
    "methods": "eight-passive", "passiveActions": False,
    "cancel": {"operation": 1, "widget": "cancel", "guiSettled": True, "originalsSettled": True, "registered": False},
    "select": {"operation": 2, "widget": "select", "filenameRead": True, "guiSettled": True, "originalsSettled": True, "registered": True},
    "snapshot": {"initial": "missing", "androidHint": True, "sourceFiles": 1},
    "suggestion": {"coreProvenance": True, "explicitAdoption": True},
    "save": {"capability": True, "requests": {"open": 2, "prepare": 2, "apply": 1, "close": 0},
             "bindingsMatched": True, "draftRevisions": [1, 1], "baselineGenerations": [1, 2],
             "reviewMatched": True, "confirmation": {"opened": 2, "keepReviewing": True, "applyBeforeAck": 0, "acknowledged": True},
             "outcome": ["committed", "clean", "settled", "none"], "nativeFinality": "settled",
             "savedVisible": True, "baselineAdvanced": True},
    "readback": {"fresh": True, "domMatched": True, "draftMatched": True, "size": 692,
                 "sha256": "4b3a5aaa718b018101ee0fcd0e612285be8a1b93cab20c5ff15e8d441069b917"},
    "noop": {"reviewMatched": True, "apply": 0, "quitOutstanding": True,
             "outcome": ["not_started", "not_created", "settled", "cancelled"], "nativeReason": "shutdown"},
    "originals": {"sessions": 2, "writerFrames": [3, 2], "stdoutFrames": [3, 3],
                  "startupJoined": 2, "childWaited": 2, "ioSettled": 2, "ownersJoined": 2,
                  "runtimeLedgerSettled": 2, "runtimeSettlementJoined": 2},
    "quit": {"operation": 3, "originalsSettled": True, "relayJoined": True, "exit": True},
    "guidance": {
        "draftUnchanged": True,
        "requirements": {"requestResultDomMatched": True, "context": "android/build", "roles": 3,
                         "presence": "unknown", "version": "unknown", "inspection": "not-run",
                         "nativeInspection": "unavailable", "dependencies": "unknown"},
        "github": {"requestResultDomMatched": True, "explicitInputs": True, "browserEdit": "insertText",
                   "comparison": "not-supplied", "workflowCount": 4, "tooling": "format-only", "githubContacted": False,
                   "repositoryObserved": False, "toolingRefResolved": False, "templateCompatibility": "unknown", "applyAvailable": False},
        "assuranceActions": False, "releaseReadiness": "unknown",
    },
}
OS_SONAMES = {"libc.so.6", "ld-linux-x86-64.so.2", "libm.so.6", "libmvec.so.1", "libdl.so.2",
              "libpthread.so.0", "librt.so.1", "libutil.so.1", "libgcc_s.so.1"}
PRIVATE_SONAMES = {"libssl.so.3", "libcrypto.so.3"}
DEFAULT_LIBRARY_DIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib")
HWCAPS = ("x86-64-v4", "x86-64-v3", "x86-64-v2")
PREFIX = Path("/var/lib/mobile-release-kit/versions") / TARGET
INPUT = Path("/usr/lib/mobile-release-kit/runtime-input") / TARGET
HELPER = "/usr/lib/mobile-release-kit/mrk-runtime-publish"
HOST_PATH = "/usr/bin:/bin"
DPKG_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LIMIT, JSON_LIMIT, FILE_LIMIT, TOTAL_LIMIT = 2 << 20, 1 << 20, 512 << 20, 32 << 20
CLIENT_RESERVATION = 40  # start10 + stop10 + StopPost10 + original-client10
PROPERTIES = {
    "User": "root", "Group": "root", "WorkingDirectory": "/", "UMask": "0077",
    "ExitType": "cgroup", "Restart": "no", "KillMode": "control-group",
    "SendSIGKILL": "yes", "OOMPolicy": "kill", "Delegate": "no", "NoNewPrivileges": "yes",
    "MemoryMax": "6G", "MemorySwapMax": "0", "TasksMax": "64", "CPUQuota": "200%",
    "RuntimeRandomizedExtraSec": "0", "TimeoutStartSec": "10s", "TimeoutStopSec": "10s",
}
SHOW = ("Id", "InvocationID", "ControlGroup", "Type", "User", "Group", "WorkingDirectory",
        "UMask", "ExitType", "Restart", "KillMode", "SendSIGKILL", "OOMPolicy", "Delegate",
        "NoNewPrivileges", "MemoryMax", "MemorySwapMax", "TasksMax", "RuntimeMaxUSec",
        "RuntimeRandomizedExtraUSec", "TimeoutStartUSec", "TimeoutStopUSec", "PrivateMounts",
        "PrivateTmp", "PrivateUsers", "PrivateNetwork", "ProtectControlGroups", "Result")
TOOLS = ("/usr/bin/python3.12", "/usr/bin/systemctl", "/usr/bin/dpkg", "/usr/bin/dpkg-query",
         "/usr/bin/dpkg-deb", "/usr/bin/dpkg-split", "/usr/bin/tar", "/usr/bin/setpriv", "/usr/bin/env", "/usr/bin/dash",
         "/usr/sbin/ldconfig", "/usr/sbin/start-stop-daemon")
NEEDRESTART_CONFIG = Path("/etc/dpkg/dpkg.cfg.d/needrestart")
NEEDRESTART_CONFIG_PIN = (274, "a906969392a7a72cbe731718792a98c396f8aee414760b8b0c51fbc7477d5ca7")
NEEDRESTART_SCRIPT = Path("/usr/lib/needrestart/dpkg-status")
NEEDRESTART_SCRIPT_PIN = (1045, "7431617eeb9f795caa235078f4d3c59fc46661f68f6188ebc80c781ad83f4010")
NEEDRESTART_OPTION = "status-logger=(test -x /usr/lib/needrestart/dpkg-status && /usr/lib/needrestart/dpkg-status || cat > /dev/null)"
NEEDRESTART_TOOLS = ("cat", "mkdir", "touch")
NEEDRESTART_MARKERS = {"unpacked", "errored"}
TOOLS += tuple("/usr/bin/" + name for name in NEEDRESTART_TOOLS)
PACKAGE_ACTIONS = {"unpack": "--unpack", "configure": "--configure", "upgrade": "--install",
                   "upgrade-unpack": "--unpack", "upgrade-configure": "--configure",
                   "duplicate": "--install", "remove": "--remove", "purge": "--purge"}
SCRIPT_PINS = {"postinst": (403, "1592b55fbace8275427a0275528a45e5a92539d8b5c1cb063105a7bd8a956df4"),
               "prerm": (264, "0416fe9a7db28e04499f68e4280a55041001d379335c51b5d53ff47abc246b00"),
               "postrm": (216, "6170e316095f747b772f081778c610734651136cebcde0cf7a3cebbc0bb3737a")}
PUBLISHED = b"Immutable runtime payload published. Product execution remains unqualified.\n"
REFUSAL = "Runtime publication refused: {}. Partial or published objects were not removed; do not repair or retry automatically.\n"
CORE_PINS = {
    "__init__.py": (144, "557bcb0cdcf7f7ef329f04f82cf388c746bb73eba34857b97782a8bcf2e596b2"),
    "owned_process.py": (7631, "430a596c5069b7acf248334d1f60fdd12ad8212cf9c2e9dfef717c9ba2179c02"),
    "_command_process.py": (169926, "075fa6e9838017feb6a1716ab3a75074e3a65dffe8b217613aff7e87c0201f68"),
    "_native_process.py": (62175, "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4"),
    "cancellation.py": (29094, "1840232213e877e26c4cebd1434b3b851f9fa4c6961baa26eeaae9fa1442db78"),
    "_lifetime_evidence.py": (18536, "d64948f26984ed692030834221f0cfd93b85117da89b4860f8b69a6f7919e1b3"),
    "_store_lane_contract.py": (9500, "8726cf9bdb053b3d7f30eb9c8307c18239dc518476b2f895ef1610efa65e040e"),
    "errors.py": (749, "26427cedbd05945c1a869af20228f9a04fe1e30d950a2dc246dd0795708a0853"),
}
DATA_PIN = (19198, "b22b83554231bef19178fbb8723acfed71e4476df14048bd9b4c763b937743d5")

# The workflow carries these exact bytes in MRK_UBUNTU_LIFECYCLE_BOOTSTRAP.
# Only the entry digest is fixed separately, so there is no self-hash cycle.
# This code runs as the original service's ExecStart, not before that domain.
BOOTSTRAP = r'''import hashlib, os, re, stat, sys
from pathlib import Path
def need(ok):
    if not ok: raise SystemExit(70)
def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
    for d in (p.parent,*p.parents): need(stat.S_ISDIR(d.lstat().st_mode))
    s=p.lstat(); need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=1048576)
    f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        need(identity(os.fstat(f))==identity(s)); b=b''
        while True:
            c=os.read(f,min(65536,s.st_size-len(b)+1))
            if not c: break
            b+=c; need(len(b)<=s.st_size)
        need(len(b)==s.st_size and identity(os.fstat(f))==identity(s)==identity(p.lstat()))
    finally: os.close(f)
    return b
def write(p,b):
    f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444)
    try:
        os.fchmod(f,0o444)
        for i in range(0,len(b),65536): need(os.write(f,b[i:i+65536])==len(b[i:i+65536]))
        os.fsync(f)
    finally: os.close(f)
    need(read(p)==b)
need(len(sys.argv)==6 and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
entry,entry_sha,request,request_sha,root=sys.argv[1:]
need(all(re.fullmatch(r'[0-9a-f]{64}',v) for v in (entry_sha,request_sha)))
need(re.fullmatch(r'/var/lib/mrk-ubuntu-native-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}',root))
raw,control=read(Path(entry)),read(Path(request))
need(hashlib.sha256(raw).hexdigest()==entry_sha and hashlib.sha256(control).hexdigest()==request_sha)
r=Path(root)
for d in r.parents:
    s=d.lstat(); need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022)
os.umask(0o077); r.mkdir(mode=0o700); (r/'private').mkdir(mode=0o700)
write(r/'entry.py',raw); write(r/'private/handoff.json',control)
write(r/'private/bootstrap-pins.txt',(entry_sha+'\n'+request_sha+'\n').encode('ascii'))
os.execv('/usr/bin/python3.12',['/usr/bin/python3.12','-I','-S','-B',str(r/'entry.py'),'unit-start'])
'''

_D = _OWNER = None
_ROOT = None
_END = 0.0
_COMMANDS, _FILES = [], []
_TOTAL = 0
_FAILED = False
_PHASE = "entry"


class Refused(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Refused(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def decode(raw, limit=JSON_LIMIT):
    need(type(raw) is bytes and 0 < len(raw) <= limit, "Bounded lifecycle JSON required")
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "Duplicate lifecycle field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite lifecycle JSON")))


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def absolute(value):
    need(type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./+\-]+", value) is not None
         and str(Path(value)) == value and not value.startswith("//")
         and all(part not in {".", ".."} for part in value.split("/")[1:]), "Fixed absolute lifecycle path required")
    return Path(value)


def directory(path, protected=False):
    need(path.is_absolute(), "Absolute directory required")
    for parent in (path, *path.parents):
        item = parent.lstat()
        detail = " path=" + ascii(str(parent)) + " mode=" + oct(item.st_mode) + " uid=" + str(item.st_uid) + " gid=" + str(item.st_gid)
        need(stat.S_ISDIR(item.st_mode), "Nonordinary lifecycle ancestor" + detail)
        if protected:
            need(item.st_uid == item.st_gid == 0 and not item.st_mode & 0o022, "Unprotected lifecycle ancestor" + detail)


def record(path, limit=FILE_LIMIT, *, content=False):
    directory(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "Nonordinary or oversized lifecycle file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    digest, count, blocks = hashlib.sha256(), 0, []
    try:
        need(identity(os.fstat(fd)) == identity(before), "Lifecycle file changed before read")
        while block := os.read(fd, 64 << 10):
            count += len(block)
            need(count <= before.st_size, "Lifecycle file grew")
            digest.update(block)
            if content:
                blocks.append(block)
        need(count == before.st_size and identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
             "Lifecycle file changed during read")
    finally:
        os.close(fd)
    need(identity(path.lstat()) == identity(before), "Lifecycle file changed after original close")
    result = {"path": str(path), "size": count, "sha256": digest.hexdigest()}
    return (result, b"".join(blocks)) if content else result


def read(path, limit=JSON_LIMIT):
    return record(path, limit, content=True)[1]


def copy_pinned(source, target, expected, mode=0o444):
    need(record(source, expected["size"]) == {**expected, "path": str(source)}, "Pinned copy source differs")
    directory(target.parent, protected=True)
    before = source.lstat()
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    dst = None
    try:
        need(identity(os.fstat(src)) == identity(before), "Copy source changed before open")
        dst = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        os.fchmod(dst, mode)
        count = 0
        while block := os.read(src, 64 << 10):
            count += len(block)
            need(count <= expected["size"] and os.write(dst, block) == len(block), "Copy bound or short write")
        need(count == expected["size"] and identity(os.fstat(src)) == identity(before) == identity(source.lstat()),
             "Copy source drift")
        os.fsync(dst)
    finally:
        try:
            if dst is not None:
                os.close(dst)
        finally:
            os.close(src)
    need(record(target, expected["size"]) == {**expected, "path": str(target)}
         and target.stat().st_uid == target.stat().st_gid == 0 and stat.S_IMODE(target.stat().st_mode) == mode
         and (target.stat().st_dev, target.stat().st_ino) != (before.st_dev, before.st_ino), "Protected copy readback differs")


def handoff(path, digest):
    need(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "Missing handoff pin")
    raw = read(path)
    need(hashlib.sha256(raw).hexdigest() == digest, "Handoff bytes differ")
    value = decode(raw)
    need(type(value) is dict and not ("installed" in value and "shell" in value)
         and set(value) == {"sourceSha", "runId", "attempt", "deadline", "runnerUid", "runnerGid",
         "source", "taskRoot", "library", "packages", "compilerRecords"}
         | ({"installed"} if "installed" in value else {"shell"} if "shell" in value else set()),
         "Fixed handoff fields differ")
    need(re.fullmatch(r"[0-9a-f]{40}", value["sourceSha"]) is not None and value["sourceSha"] != "0" * 40,
         "Missing source binding")
    for key in ("runId", "attempt"):
        need(type(value[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[key]) is not None, "Original job identity differs")
    need(type(value["deadline"]) in {int, float} and math.isfinite(value["deadline"]) and value["deadline"] > 0,
         "Original finite endpoint required")
    need(all(type(value[key]) is int and 0 < value[key] < (1 << 31) for key in ("runnerUid", "runnerGid")), "Nonroot runner IDs required")
    source, task = absolute(value["source"]), absolute(value["taskRoot"])
    need(not source.is_relative_to(task) and not task.is_relative_to(source), "Source/task overlap")
    need(type(value["compilerRecords"]) is dict and type(value["packages"]) is dict
         and set(value["packages"]) == set(VERSIONS), "Fixed compiler/package DATA missing")
    for label, row in (("library", value["library"]), *value["packages"].items()):
        keys = {"path", "size", "sha256"} | (set() if label == "library" else {"manifestSha256", "version"})
        need(type(row) is dict and set(row) == keys and type(row["size"]) is int and 0 < row["size"] <= FILE_LIMIT,
             "Fixed artifact fields/bound differ")
        need(type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
             and absolute(row["path"]).is_relative_to(task), "Artifact escaped original task")
        if label != "library":
            need((row["manifestSha256"], row["version"]) == VERSIONS[label], "Fixture package anchor/version differs")
    paths = [value["library"]["path"], *(row["path"] for row in value["packages"].values())]
    need(len(set(paths)) == 3, "Artifact path alias")
    if "installed" in value:
        installed = value["installed"]
        need(type(installed) is dict and set(installed) == {"case", "candidate", "candidateCompiler", "candidateRosterSha256",
                                                         "candidateProducerAttempt", "candidateArtifactId", "acceptedU", "loaderPolicy"}
             and installed["case"] in {"positive", "refuse-writable", "refuse-pth"}, "Fixed installed handoff fields/case differ")
        need(type(installed["candidateProducerAttempt"]) is str
             and re.fullmatch(r"[1-9][0-9]{0,19}", installed["candidateProducerAttempt"]) is not None
             and type(installed["candidateArtifactId"]) is str
             and re.fullmatch(r"[1-9][0-9]{0,19}", installed["candidateArtifactId"]) is not None
             and int(installed["candidateProducerAttempt"]) <= int(value["attempt"]), "Original candidate producer attempt differs")
        row, compiler, accepted = installed["candidate"], installed["candidateCompiler"], installed["acceptedU"]
        need(type(row) is dict and set(row) == {"path", "size", "sha256"} and type(row["size"]) is int and 0 < row["size"] <= FILE_LIMIT
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
             and absolute(row["path"]).is_relative_to(task) and row["path"] not in paths, "Installed candidate artifact differs")
        need(type(compiler) is dict and compiler["sourceSha"] == value["sourceSha"] and compiler["features"] == []
             and (compiler["runId"], compiler["attempt"]) == (value["runId"], installed["candidateProducerAttempt"])
             and compiler["manifestSha256"] == M and compiler["protocolSha256"] == Q
             and all(compiler["exportedArtifacts"]["candidate"][key] == row[key] for key in ("size", "sha256"))
             and type(installed["candidateRosterSha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", installed["candidateRosterSha256"]) is not None, "Fresh candidate compiler/source profile differs")
        need(type(accepted) is dict and set(accepted) == {"sourceSha", "runId", "attempt", "artifactId"}
             and accepted["sourceSha"] == value["compilerRecords"]["sourceSha"]
             and re.fullmatch(r"[0-9a-f]{40}", accepted["sourceSha"]) is not None
             and all(type(accepted[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", accepted[key]) is not None
                     for key in ("runId", "attempt", "artifactId")), "Original accepted U provenance was relabelled or omitted")
    if "shell" in value:
        shell_handoff(value, paths)
    return value


def shell_handoff(value, original_paths):
    """The fixed connection is neither J's libtest nor a new package source."""
    shell = value["shell"]
    need(type(shell) is dict and set(shell) == {"binaries", "compiler", "rosterSha256", "producerAttempt",
         "artifactId", "acceptedU", "loaderPolicy"}, "Fixed shell handoff fields differ")
    need(all(type(shell[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", shell[key]) is not None
             for key in ("producerAttempt", "artifactId")) and int(shell["producerAttempt"]) <= int(value["attempt"])
         and type(shell["rosterSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", shell["rosterSha256"]) is not None,
         "Original shell producer/roster binding differs")
    binaries, compiler, accepted = shell["binaries"], shell["compiler"], shell["acceptedU"]
    need(type(binaries) is dict and set(binaries) == {"normal", "observer"}, "Normal/observer shell pair missing")
    paths = list(original_paths)
    for role, row in binaries.items():
        need(type(row) is dict and set(row) == {"path", "size", "sha256"} and type(row["size"]) is int
             and 0 < row["size"] <= FILE_LIMIT and type(row["sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
             and absolute(row["path"]).is_relative_to(absolute(value["taskRoot"])) and row["path"] not in paths,
             "Original shell artifact differs: " + role)
        paths.append(row["path"])
    need(type(compiler) is dict and compiler.get("sourceSha") == value["sourceSha"]
         and compiler.get("features") == SHELL_FEATURES
         and (compiler.get("runId"), compiler.get("attempt")) == (value["runId"], shell["producerAttempt"])
         and compiler.get("manifestSha256") == M and compiler.get("protocolSha256") == Q
         and type(compiler.get("exportedArtifacts")) is dict
         and set(compiler["exportedArtifacts"]) == set(binaries)
         and all(compiler["exportedArtifacts"][role][key] == row[key]
                 for role, row in binaries.items() for key in ("size", "sha256")),
         "Original normal/observer source, features or output bytes differ")
    need(type(accepted) is dict and set(accepted) == {"sourceSha", "runId", "attempt", "artifactId"}
         and accepted["sourceSha"] == value["compilerRecords"]["sourceSha"]
         and re.fullmatch(r"[0-9a-f]{40}", accepted["sourceSha"]) is not None
         and all(type(accepted[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", accepted[key]) is not None
                 for key in ("runId", "attempt", "artifactId")), "Shell reused U provenance was relabelled")


def root_path(value):
    return Path("/var/lib/mrk-ubuntu-native-" + value["runId"] + "-" + value["attempt"])


def service_properties(deadline, now=None):
    now = time.monotonic() if now is None else now
    need(type(deadline) in {int, float} and math.isfinite(deadline) and 0 < deadline - now <= 1200,
         "Original service endpoint missing or renewed")
    runtime = math.floor(deadline - now) - CLIENT_RESERVATION
    need(runtime > 0, "No positive service lifetime remains after original cleanup reservation")
    return {**PROPERTIES, "RuntimeMaxSec": str(runtime) + "s"}


def service_argv(handoff_path, handoff_sha256, entry_sha256):
    handoff_path = absolute(str(handoff_path))
    value = handoff(handoff_path, handoff_sha256)
    need(os.getresuid() == (value["runnerUid"],) * 3 and os.getresgid() == (value["runnerGid"],) * 3,
         "Original nonroot launch role differs")
    need(os.environ.get("MRK_UBUNTU_LIFECYCLE_BOOTSTRAP") == BOOTSTRAP, "Workflow bootstrap literal differs")
    entry = absolute(value["source"]) / ENTRY
    need(type(entry_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", entry_sha256) is not None
         and record(entry, JSON_LIMIT)["sha256"] == entry_sha256, "Workflow entry pin differs")
    properties = service_properties(value["deadline"])
    return _service_argv(value, handoff_path, handoff_sha256, entry_sha256, properties)


def _service_argv(value, handoff_path, handoff_sha256, entry_sha256, properties):
    root = root_path(value)
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
            "/usr/bin/systemd-run", "--unit=" + root.name + ".service", "--service-type=exec", "--wait", "--pipe", "--quiet"]
    argv += ["--property=" + key + "=" + item for key, item in properties.items()]
    argv += ["--property=ExecStopPost=/usr/bin/python3.12 -I -S -B " + str(root / "entry.py") + " unit-stop"]
    for key, item in {"PATH": HOST_PATH, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": str(root / "private/home"),
                      "MRK_LIFECYCLE_RUNTIME_SECONDS": properties["RuntimeMaxSec"][:-1]}.items():
        argv.append("--setenv=" + key + "=" + item)
    argv += ["--", "/usr/bin/python3.12", "-I", "-S", "-B", "-c", BOOTSTRAP,
             str(absolute(value["source"]) / ENTRY), entry_sha256, str(handoff_path), handoff_sha256, str(root)]
    return argv


def _root_ids():
    need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "Original root credentials differ")
    status = _status()
    need(all(status[key].split() == ["0"] * 4 for key in ("Uid", "Gid"))
         and status["NoNewPrivs"].strip() == "1", "Root filesystem IDs/no-new-privs differ")


def _kernel(path, limit=64 << 10):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, limit + 1)
        need(len(raw) <= limit and not os.read(fd, 1), "Kernel DATA bound exceeded")
        return raw.decode("ascii")
    finally:
        os.close(fd)


def _status():
    return dict(line.split(":", 1) for line in _kernel("/proc/self/status").splitlines() if ":" in line)


def _namespaces(root_role):
    # Published include/uapi/linux/nsfs.h: NS_GET_NSTYPE = _IO(0xb7,3).
    # A successful type ioctl witnesses real nsfs, not a lookalike regular file.
    names = [("user", "/proc/self/ns/user", 0x10000000), ("pid", "/proc/self/ns/pid", 0x20000000),
             ("mnt", "/proc/self/ns/mnt", 0x00020000)]
    if root_role:
        names.append(("init-mnt", "/proc/1/ns/mnt", 0x00020000))
    originals, result, failure = [], {}, None
    try:
        for name, path, kind in names:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            originals.append(fd)
            item = os.fstat(fd)
            need(stat.S_ISREG(item.st_mode) and item.st_uid == item.st_gid == 0 and item.st_nlink == 1
                 and fcntl.ioctl(fd, 0xb703) == kind, "Real initial namespace type/owner differs")
            result[name] = list(identity(item))
        for (name, _, _), fd in zip(names, originals):
            need(list(identity(os.fstat(fd))) == result[name], "Original namespace changed")
        need(result["user"][1] == 0xeffffffd and result["pid"][1] == 0xeffffffc, "Noninitial user/PID namespace")
        if root_role:
            need(result["mnt"] == result.pop("init-mnt"), "Not the real initial mount namespace")
        for name in ("uid_map", "gid_map"):
            need(_kernel("/proc/self/" + name, 4096).split() == ["0", "0", "4294967295"], "Noninitial ID map")
    finally:
        for fd in reversed(originals):
            try:
                os.close(fd)
            except OSError as error:
                failure = error
        if failure is not None:
            raise Refused("Original namespace close failed") from failure
    # namespaces(7): cross-process identity is device/inode. nsfs may recreate
    # its pseudo-inode timestamps after close; full original-FD checks above
    # remain exact throughout each observation. Lists survive JSON unchanged.
    return {name: row[:2] for name, row in result.items()}


def _modules(root, *, owner):
    global _D, _OWNER
    base = root / "source"
    expected = {"src/mobile_release/" + name: pin for name, pin in CORE_PINS.items()}
    expected["desktop/tools/conventional_runtime_data.py"] = DATA_PIN
    for name, (size, digest) in expected.items():
        path = base / name
        directory(path.parent, protected=True)
        need(record(path, size) == {"path": str(path), "size": size, "sha256": digest}
             and path.stat().st_uid == path.stat().st_gid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o444,
             "Protected host source differs before import")
    if _D is None:
        spec = importlib.util.spec_from_file_location("_lifecycle_data", base / "desktop/tools/conventional_runtime_data.py")
        _D = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_D)
    if owner and _OWNER is None:
        previous = sys.path[:]
        try:
            sys.path.insert(0, str(base / "src"))
            from mobile_release import owned_process, _command_process
        finally:
            sys.path[:] = previous
        allowed = {str(base / "src/mobile_release" / name) for name in CORE_PINS}
        for name, module in tuple(sys.modules.items()):
            if name == "mobile_release" or name.startswith("mobile_release."):
                need(getattr(module, "__file__", None) in allowed, "Foreign root owner import")
        _OWNER = owned_process


def _context(*, copying=False):
    global _ROOT, _END
    root = Path(__file__).absolute().parent
    need(re.fullmatch(r"/var/lib/mrk-ubuntu-native-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}", str(root)) is not None,
         "Only the protected service entry is allowed")
    directory(root, protected=True)
    directory(root / "private", protected=True)
    pins = read(root / "private/bootstrap-pins.txt", 130).decode("ascii").splitlines()
    need(len(pins) == 2 and all(re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins)
         and record(root / "entry.py", JSON_LIMIT)["sha256"] == pins[0], "Bootstrap entry correspondence differs")
    value = handoff(root / "private/handoff.json", pins[1])
    need(root == root_path(value), "Original root/job binding differs")
    _ROOT, _END = root, float(value["deadline"])
    if copying:
        need(time.monotonic() < _END and set(p.name for p in root.iterdir()) == {"entry.py", "private"}, "Root entry reused or expired")
        _capacity(value)
        for name in ("source", "source/src", "source/src/mobile_release", "source/desktop", "source/desktop/tools", "public", "private/home"):
            (root / name).mkdir(mode=0o700)
        source = absolute(value["source"])
        for name, (size, digest) in CORE_PINS.items():
            relative = "src/mobile_release/" + name
            copy_pinned(source / relative, root / "source" / relative, {"path": str(source / relative), "size": size, "sha256": digest})
        relative = "desktop/tools/conventional_runtime_data.py"
        copy_pinned(source / relative, root / "source" / relative,
                    {"path": str(source / relative), "size": DATA_PIN[0], "sha256": DATA_PIN[1]})
        candidates = [("candidate", value["installed"]["candidate"], root / "installed-tests", 0o555)] if "installed" in value else []
        if "shell" in value:
            candidates = [(role, row, root / ("shell-" + role), 0o555) for role, row in value["shell"]["binaries"].items()]
        for label, row, target, mode in [("library", value["library"], root / "platform-tests", 0o555), *candidates,
             *((key, row, root / "private" / (key + ".deb"), 0o400) for key, row in value["packages"].items())]:
            before = absolute(row["path"]).lstat()
            need(before.st_uid == value["runnerUid"] and before.st_gid == value["runnerGid"], "Original artifact owner differs")
            copy_pinned(absolute(row["path"]), target, {key: row[key] for key in ("path", "size", "sha256")}, mode)
        for name in ("source/src/mobile_release", "source/src", "source/desktop/tools", "source/desktop", "source"):
            os.chmod(root / name, 0o555)
        os.chmod(root / "public", 0o755)
        os.chmod(root, 0o711)
    _modules(root, owner=True)
    return value, pins[1]


def _capacity(value):
    capacity = value["compilerRecords"].get("capacity")
    need(type(capacity) is dict and set(capacity) == {"runtimeBytes", "installedBytes", "installedEntries"}, "Original capacity DATA missing")
    need(type(capacity["runtimeBytes"]) is int and 0 < capacity["runtimeBytes"] <= 1 << 30, "Runtime capacity bound differs")
    for name in ("installedBytes", "installedEntries"):
        rows = capacity[name]
        maximum = 4 << 30 if name == "installedBytes" else 32768
        need(type(rows) is dict and set(rows) == set(VERSIONS)
             and all(type(n) is int and 0 < n <= maximum for n in rows.values()), "Package capacity DATA differs")
    required = (sum(row["size"] for row in value["packages"].values()) + value["library"]["size"]
                + (value["installed"]["candidate"]["size"] if "installed" in value else 0)
                + (sum(row["size"] for row in value["shell"]["binaries"].values()) if "shell" in value else 0)
                + 2 * capacity["runtimeBytes"] + 1 + 2 * max(capacity["installedBytes"].values()) + TOTAL_LIMIT + JSON_LIMIT)
    inodes = 2 * max(capacity["installedEntries"].values()) + 2 * 8192 + 128
    need(len({Path(name).stat().st_dev for name in ("/", "/var", "/var/lib", "/usr")}) == 1,
         "Capacity DATA does not cover the same root package/publication filesystem")
    space = os.statvfs("/var/lib")
    need(space.f_bavail * space.f_frsize >= required and space.f_favail >= inodes, "Insufficient original host capacity; do not clear caches")


def _retain(name, raw):
    global _TOTAL
    need(_ROOT is not None and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,100}", name) is not None
         and type(raw) is bytes and len(raw) <= LIMIT and _TOTAL + len(raw) <= TOTAL_LIMIT, "Fixed capture bound differs")
    row = _D.write(_ROOT / "public" / name, raw, 0o444)
    _TOTAL += len(raw)
    _FILES.append({**row, "path": name})


def _environment():
    return {"PATH": HOST_PATH, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": str(_ROOT / "private/home")}


def _command_capture(label, argv, result, seconds):
    need(type(result) is subprocess.CompletedProcess and result.args == argv and type(result.returncode) is int
         and type(result.stdout) is bytes and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= LIMIT,
         "Original root command result incomplete")
    _retain(label + ".stdout", result.stdout)
    _retain(label + ".stderr", result.stderr)
    _COMMANDS.append({"phase": label, "argv": argv, "exitCode": result.returncode, "timeoutSeconds": seconds})


def command(label, argv, *, maximum=120, codes=(0,), env=None, endpoint=None):
    global _FAILED, _PHASE
    _PHASE = label
    need(not _FAILED and _OWNER is not None, "Prior root command failed or owner missing")
    _root_ids()
    # The fixed overlap configure may only SHORTEN this original endpoint.
    need(endpoint is None or type(endpoint) in {int, float} and math.isfinite(endpoint), "Fixed finite command cap required")
    bound = _END if endpoint is None else min(_END, endpoint)
    started = time.monotonic()
    seconds = min(maximum, math.floor(bound - started))
    need(seconds > 0, "Original root command endpoint exhausted")
    _FAILED = True
    result = _OWNER.run_owned(argv, environ=_environment() if env is None else env, cwd=Path("/"), timeout=seconds,
        capture=True, text=False, output_limit=LIMIT, execution_scope=None, journal_binding=None, cleanup=False)
    _command_capture(label, argv, result, seconds)
    if endpoint is not None:
        _COMMANDS[-1].update(originalEndpoint=bound, startMonotonic=started)
    accepted = result.returncode in codes and time.monotonic() < bound
    if not accepted and label in {"native-root", "native-user", "observe-unpacked", "observe-p0",
                                 "observe-upgrade", "observe-duplicate", "observe-remove", "observe-purge"}:
        # Only these fixed credential-free fixtures may expose bounded DATA
        # from the SAME returned capture. This is not another read or receipt.
        diagnostic = {"phase": label, "exitCode": result.returncode, "timeoutSeconds": seconds,
            "stdoutBytes": len(result.stdout), "stderrBytes": len(result.stderr),
            "stdoutPrefix": result.stdout[:1024].decode("utf-8", errors="backslashreplace"),
            "stderrPrefix": result.stderr[:1024].decode("utf-8", errors="backslashreplace")}
        sys.stderr.write("Fixture command failure DATA: " + canonical(diagnostic).decode("ascii"))
    need(accepted, "Original root command failed or completed late")
    _FAILED = False
    return result


def seconds_value(value):
    if value == "0":
        return 0
    units = {"us": 0.000001, "ms": 0.001, "s": 1, "min": 60, "h": 3600}
    tokens = re.findall(r"([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h)", value)
    need(tokens and " ".join(number + unit for number, unit in tokens) == value, "Unknown effective time format")
    return sum(float(number) * units[unit] for number, unit in tokens)


def _domain(value, label):
    unit = root_path(value).name + ".service"
    result = command(label + "-unit-show", ["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(SHOW), unit], maximum=3)
    rows = result.stdout.decode("ascii").splitlines()
    props = dict(line.split("=", 1) for line in rows)
    need(len(props) == len(rows) and set(props) == set(SHOW) and props["Id"] == unit and props["Type"] == "exec", "Original service properties incomplete")
    for key in ("User", "Group", "WorkingDirectory", "UMask", "ExitType", "Restart", "KillMode", "SendSIGKILL", "OOMPolicy", "Delegate", "NoNewPrivileges"):
        need(props[key] == PROPERTIES[key], "Effective service ownership policy differs")
    need(all(props[key] == "no" for key in ("PrivateMounts", "PrivateTmp", "PrivateUsers", "PrivateNetwork", "ProtectControlGroups")),
         "Service substitutes an initial namespace/view")
    runtime = os.environ.get("MRK_LIFECYCLE_RUNTIME_SECONDS", "")
    need(runtime.isdecimal() and 0 < int(runtime) < 1200 and seconds_value(props["RuntimeMaxUSec"]) == int(runtime)
         and seconds_value(props["RuntimeRandomizedExtraUSec"]) == 0
         and seconds_value(props["TimeoutStartUSec"]) == seconds_value(props["TimeoutStopUSec"]) == 10,
         "Effective service time limits differ")
    invocation = os.environ.get("INVOCATION_ID", "")
    group = "/system.slice/" + unit
    need(re.fullmatch(r"[0-9a-f]{32}", invocation) is not None and props["InvocationID"] == invocation
         and props["ControlGroup"] == group and _kernel("/proc/self/cgroup") == "0::" + group + "\n", "Original service invocation/domain differs")
    cgroup = Path("/sys/fs/cgroup" + group)
    need(_kernel(cgroup / "cgroup.type") == "domain\n", "Original cgroup is not an aggregate domain")
    effective = {name: _kernel(cgroup / name).strip() for name in ("memory.max", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max")}
    need(props["MemoryMax"] == effective["memory.max"] == str(6 << 30) and props["MemorySwapMax"] == effective["memory.swap.max"] == "0"
         and props["TasksMax"] == effective["pids.max"] == "64" and effective["memory.oom.group"] == "1", "Effective aggregate limits differ")
    quota, period = effective["cpu.max"].split()
    need(quota.isdecimal() and period.isdecimal() and int(period) > 0 and int(quota) == 2 * int(period), "Effective CPU ceiling differs")
    events = {name: {key: int(number) for key, number in (line.split() for line in _kernel(cgroup / name).splitlines())}
              for name in ("memory.events", "pids.events")}
    need({"max", "oom", "oom_kill"} <= set(events["memory.events"]) and "max" in events["pids.events"], "Aggregate denial counters missing")
    need(all(number == 0 for key, number in events["memory.events"].items() if key != "low")
         and all(number == 0 for number in events["pids.events"].values()), "Original aggregate resource denial")
    return {"sourceSha": value["sourceSha"], "unit": props, "invocationId": invocation, "effective": effective, "events": events}


def config_options(raw):
    need(type(raw) is bytes and len(raw) <= 64 << 10 and b"\0" not in raw, "Dpkg configuration bound differs")
    lines = [line.strip() for line in raw.decode("ascii").splitlines()]
    options = [line for line in lines if line and not line.startswith("#")]
    need(all(line in {"no-debsig", "log /var/log/dpkg.log"} for line in options), "Unreviewed dpkg option/hook/exclusion")
    return options


def dpkg_config_options(path, raw):
    # The generic hook refusal stays closed. Only this complete distribution
    # file, at its fixed pathname, selects the independently reviewed logger.
    if path == NEEDRESTART_CONFIG:
        need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == NEEDRESTART_CONFIG_PIN,
             "Exact needrestart configuration differs")
        return [NEEDRESTART_OPTION]
    return config_options(raw)


def protected_record(path, limit=FILE_LIMIT):
    directory(path.parent, protected=True)
    before = path.lstat()
    need(before.st_uid == before.st_gid == 0 and not before.st_mode & 0o7022, "Root input has mutable/special permissions")
    result = record(path, limit)
    need(identity(path.lstat()) == identity(before), "Protected input changed after readback")
    return {**result, "identity": list(identity(before))}


def needrestart_inputs():
    script = protected_record(NEEDRESTART_SCRIPT, NEEDRESTART_SCRIPT_PIN[0])
    need((script["size"], script["sha256"]) == NEEDRESTART_SCRIPT_PIN
         and stat.S_IMODE(script["identity"][2]) == 0o755, "Exact needrestart logger differs")
    search = []
    for name in NEEDRESTART_TOOLS:
        shadow = Path("/usr/sbin") / name
        directory(shadow.parent, protected=True)
        _absent(shadow)  # DPKG_PATH searches this before the admitted /usr/bin.
        search.append(str(shadow))
    null = Path("/dev/null")
    directory(null.parent, protected=True)
    parents = {str(path): list(identity(path.lstat())[:5]) for path in (null.parent, *null.parent.parents)}
    for path in (null.parent, *null.parent.parents):
        _xattrs(path, True)
    before = null.lstat()
    need(stat.S_ISCHR(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
         and stat.S_IMODE(before.st_mode) == 0o666 and (os.major(before.st_rdev), os.minor(before.st_rdev)) == (1, 3),
         "Fallback is not the original root-owned null device")
    _xattrs(null, False)
    need(identity(null.lstat()) == identity(before)
         and all(list(identity(Path(path).lstat())[:5]) == row for path, row in parents.items()), "Null-device binding drift")
    return {"script": script, "absentEarlierSearch": search,
            "nullDevice": {"identity": list(identity(before)[:6]), "device": [1, 3], "parents": parents}}


def needrestart_state():
    # Mutable package-manager state is deliberately NOT part of dpkg_policy's
    # immutable equality. Nothing here creates, repairs or adopts a host object.
    run, base = Path("/run"), Path("/run/needrestart")
    directory(run, protected=True)
    _xattrs(run, True)
    run_identity = list(identity(run.lstat())[:5])
    try:
        before = base.lstat()
    except FileNotFoundError:
        _absent(base)
        need(list(identity(run.lstat())[:5]) == run_identity, "Marker parent drift")
        return {"runIdentity": run_identity, "directory": None, "markers": {}}
    directory(base, protected=True)
    need(not before.st_mode & 0o7000 and before.st_nlink == 2, "Nonordinary marker directory")
    _xattrs(base, True)
    markers = {}
    with os.scandir(base) as entries:
        for entry in entries:
            need(entry.name in NEEDRESTART_MARKERS and entry.name not in markers and len(markers) < 2,
                 "Unexpected needrestart marker entry")
            path = base / entry.name
            _xattrs(path, False)
            markers[entry.name] = protected_record(path, 0)
    need(identity(base.lstat()) == identity(before) and list(identity(run.lstat())[:5]) == run_identity,
         "Marker namespace changed during observation")
    return {"runIdentity": run_identity, "directory": list(identity(before)), "markers": markers}


def needrestart_transition(before, after):
    # These snapshots do not acknowledge logger completion, consumed input or
    # guaranteed marker creation. Dpkg does not wait for/ack its status logger.
    def original(row, kind, links):
        need(type(row) is list and len(row) == 9 and all(type(number) is int for number in row)
             and row[0] >= 0 and row[1] > 0 and stat.S_IFMT(row[2]) == kind
             and row[3] == row[4] == 0 and row[5] == links and row[6] >= 0 and not row[2] & 0o7022,
             "Unprotected or aliased marker identity")
    empty_sha = hashlib.sha256(b"").hexdigest()
    for value in (before, after):
        need(type(value) is dict and set(value) == {"runIdentity", "directory", "markers"}
             and type(value["runIdentity"]) is list and len(value["runIdentity"]) == 5
             and all(type(number) is int for number in value["runIdentity"])
             and stat.S_ISDIR(value["runIdentity"][2]) and value["runIdentity"][3:] == [0, 0]
             and not value["runIdentity"][2] & 0o7022
             and type(value["markers"]) is dict and set(value["markers"]) <= NEEDRESTART_MARKERS,
             "Invalid bounded marker observation")
        if value["directory"] is None:
            need(not value["markers"], "Markers without the original directory")
        else:
            original(value["directory"], stat.S_IFDIR, 2)
        aliases = set()
        for name, row in value["markers"].items():
            need(type(row) is dict and set(row) == {"path", "size", "sha256", "identity"}
                 and row["path"] == "/run/needrestart/" + name and type(row["size"]) is int
                 and row["size"] == 0 and row["sha256"] == empty_sha, "Marker content or name differs")
            original(row["identity"], stat.S_IFREG, 1)
            pair = tuple(row["identity"][:2])
            need(row["identity"][6] == 0 and pair not in aliases, "Nonempty or aliased marker")
            aliases.add(pair)
    need(before["runIdentity"] == after["runIdentity"], "Original marker parent replaced")
    if before["directory"] is not None:
        need(after["directory"] is not None and before["directory"][:6] == after["directory"][:6],
             "Original marker directory replaced or changed authority")
        if set(before["markers"]) == set(after["markers"]):
            need(before["directory"][6] == after["directory"][6], "Marker directory changed without a known creation")
    elif after["directory"] is not None:
        need(stat.S_IMODE(after["directory"][2]) == 0o755, "New marker directory did not use dpkg umask 022")
    need(set(before["markers"]) <= set(after["markers"]), "Existing marker removed")
    for name, row in after["markers"].items():
        if name in before["markers"]:
            need(row["identity"][:7] == before["markers"][name]["identity"][:7], "Original marker replaced or changed authority/content")
        else:
            need(stat.S_IMODE(row["identity"][2]) == 0o644, "New marker did not use dpkg umask 022")


def private_dpkg_log():
    path = _ROOT / "private/dpkg.log"
    directory(path.parent, protected=True)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
         and stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= LIMIT, "Untrusted or oversized private dpkg log")
    _xattrs(path, False)
    need(identity(path.lstat()) == identity(before), "Private dpkg log changed during observation")
    # Append DATA is diagnostic only; this binding claims no successful write
    # or durability and deliberately excludes changing size/times/content.
    return {"path": str(path), "identity": list(identity(before)[:6])}


def package_command(label, argv, *, policy, codes=(0,), endpoint=None):
    global _FAILED, _PHASE
    try:
        _PHASE = label
        need(not _FAILED and label in PACKAGE_ACTIONS and type(argv) is list and len(argv) == 5
             and argv[:3] == ["/usr/bin/dpkg", "--debug=2", "--no-triggers"] and argv[3] == PACKAGE_ACTIONS[label],
             "Fixed package mutation required")
        need(dpkg_policy() == policy, "Dpkg configuration/helper input changed before " + label)
        actual = argv[:4] + ["--log=" + str(_ROOT / "private/dpkg.log"), argv[4]]
        before = needrestart_state()
        needrestart_transition(before, before)
        previous = [row["needrestartMarkers"]["after"] for row in _COMMANDS if "needrestartMarkers" in row]
        if previous:
            needrestart_transition(previous[-1], before)
        options = {} if endpoint is None else {"endpoint": endpoint}
        result = command(label, actual, maximum=240, codes=codes, env={**_environment(), "PATH": DPKG_PATH}, **options)
        # Only a positive return of the SAME original command owner permits any
        # post-state access (including expected dpkg collision exit 1).
        _FAILED = True
        need(private_dpkg_log() == policy["logBinding"], "Original private dpkg log changed")
        after = needrestart_state()
        needrestart_transition(before, after)
        need(time.monotonic() < min(_END, _END if endpoint is None else endpoint), "Package observation completed late")
        need(_COMMANDS and _COMMANDS[-1]["phase"] == label and _COMMANDS[-1]["argv"] == actual,
             "Original package command record missing")
        _COMMANDS[-1]["needrestartMarkers"] = {"before": before, "after": after, "loggerCompletionClaimed": False}
        _FAILED = False
        return result
    except BaseException:
        _FAILED = True
        raise


def verify_package_observations(commands, root):
    previous = None
    for row in commands:
        if row["phase"] not in PACKAGE_ACTIONS:
            need("needrestartMarkers" not in row and row["argv"][0] != "/usr/bin/dpkg", "Unwrapped package command")
            continue
        need(row["argv"][:5] == ["/usr/bin/dpkg", "--debug=2", "--no-triggers", PACKAGE_ACTIONS[row["phase"]],
                                 "--log=" + str(root / "private/dpkg.log")]
             and len(row["argv"]) == 6, "Closed package command differs")
        observed = row.get("needrestartMarkers")
        need(type(observed) is dict and set(observed) == {"before", "after", "loggerCompletionClaimed"}
             and observed["loggerCompletionClaimed"] is False, "Marker observation is missing or claims logger acknowledgement")
        if previous is not None:
            needrestart_transition(previous, observed["before"])
        needrestart_transition(observed["before"], observed["after"])
        previous = observed["after"]


def dpkg_policy(*, home=None):
    result = {"tools": [protected_record(Path(name)) for name in TOOLS], "configs": [], "shellLinks": [],
              "needrestartInputs": needrestart_inputs()}
    for name, targets in (("/bin", {"usr/bin", "/usr/bin"}), ("/sbin", {"usr/sbin", "/usr/sbin"}),
                          ("/usr/bin/sh", {"dash", "/usr/bin/dash"})):
        path = Path(name)
        directory(path.parent, protected=True)
        before = path.lstat()
        need(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1,
             "Untrusted fixed dpkg shell/PATH link")
        target = os.readlink(path)
        need(target in targets and identity(path.lstat()) == identity(before), "Fixed dpkg shell/PATH target differs")
        result["shellLinks"].append({"path": name, "target": target, "identity": list(identity(before))})
    base = Path("/etc/dpkg")
    directory(base, protected=True)
    paths = [base / "dpkg.cfg"]
    fragments = base / "dpkg.cfg.d"
    directory(fragments, protected=True)
    before = identity(fragments.stat())
    children = sorted(fragments.iterdir())
    need(len(children) <= 64, "Dpkg configuration entry bound")
    # Inspect ALL entries; do not hide a hook behind a guessed filename filter.
    paths.extend(children)
    for path in paths:
        row = protected_record(path, 64 << 10)
        row["options"] = dpkg_config_options(path, read(path, 64 << 10))
        need(protected_record(path, 64 << 10) == {key: row[key] for key in ("path", "size", "sha256", "identity")}, "Dpkg config drift")
        result["configs"].append(row)
    need(before == identity(fragments.stat()), "Dpkg config directory drift")
    result["directory"] = list(before)
    if home is None:
        result["logBinding"] = private_dpkg_log()
    home = _ROOT / "private/home" if home is None else home
    directory(home)
    need(not list(home.iterdir()), "Dpkg HOME is no longer empty")
    return result


def _absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise Refused("Required fresh lifecycle name is occupied")


def denied(error):
    need(isinstance(error, OSError) and error.errno in {errno.EACCES, errno.EPERM}, "Not an actual nonroot permission denial")
    return error.errno


def _xattrs(path, is_directory):
    def refusal(name, result, number=None):
        # Diagnose only the observation already made below. Never resolve or
        # reopen a refused path, disclose private names, or print xattr bytes.
        text = str(path)
        public = ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/share", "/usr/local/share",
                  "/lib", "/lib64", "/bin", "/sbin", str(PREFIX))
        fixed = {"/", "/usr", "/usr/local", "/opt", "/var", "/var/lib", "/var/cache",
                 "/var/lib/mobile-release-kit", "/var/lib/mobile-release-kit/versions", "/etc", "/etc/glvnd",
                 "/etc/ld.so.cache", "/etc/alternatives", "/run", "/run/needrestart",
                 "/run/needrestart/unpacked", "/run/needrestart/errored", "/dev", "/dev/null"}
        scoped = (text in fixed or any(text == root or text.startswith(root + "/") for root in public)
                  or any(text == root or kind == "directory" and text.startswith(root + "/")
                         for root, kind in SHELL_DATA_ROOTS))
        grammar = (text == "/" or 0 < len(text) <= 4096 and re.fullmatch(r"/[A-Za-z0-9_./+@\-]+", text)
                   and all(part not in {"", ".", ".."} for part in text.split("/")[1:]))
        shown = text if scoped and grammar else "<redacted>"
        truncated = len(shown) > 256
        number = str(number) if type(number) is int and 0 <= number <= 4095 else "unknown"
        return ("Extended attribute refused: path=" + shown[:256] + " pathTruncated=" + str(truncated).lower()
                + " kind=" + ("directory" if is_directory else "non-directory") + " attribute=" + name
                + " result=" + result + " errno=" + (number if result == "errno" else "none"))

    for name in ("system.posix_acl_access", "system.posix_acl_default" if is_directory else "security.capability"):
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            if error.errno != errno.ENODATA:
                raise Refused(refusal(name, "errno", error.errno)) from None
        else:
            raise Refused(refusal(name, "present"))


def _tree(root, manifest, *, published):
    directory(root, protected=True)
    raw = read(root / "manifest.json")
    need(hashlib.sha256(raw).hexdigest() == manifest and len(raw) == (85440 if manifest == M else 85441), "Published manifest bytes differ")
    data = _D.decode(raw, JSON_LIMIT)
    need(data["target"] == TARGET and data["protocolSha256"] == Q and data["protocol"] == data["schemaVersion"] == 1, "Runtime DATA profile differs")
    files = _D.records(data["files"])
    need(len(files) == 606, "Runtime payload roster count differs")
    files["manifest.json"] = {"path": "manifest.json", "size": len(raw), "sha256": manifest}
    directories = {""} | {str(parent) for name in files for parent in Path(name).parents if str(parent) != "."}
    pending, seen, rows, aliases = [root], set(), {}, set()
    while pending:
        path = pending.pop()
        relative = path.relative_to(root).as_posix() if path != root else ""
        item = path.lstat()
        need(item.st_uid == item.st_gid == 0, "Runtime owner differs")
        is_directory = stat.S_ISDIR(item.st_mode)
        mode = (0o555 if published else 0o755) if is_directory else (0o555 if relative == "python/bin/python3" else 0o444)
        need(stat.S_IMODE(item.st_mode) == mode and (is_directory or stat.S_ISREG(item.st_mode)), "Runtime object type/mode differs")
        _xattrs(path, is_directory)
        if is_directory:
            need(relative in directories and relative not in seen, "Extra runtime directory")
            children = sorted(path.iterdir())
            need(len(children) + len(seen) <= 8192, "Runtime enumeration bound")
            pending.extend(reversed(children))
            row = {"identity": list(identity(item))}
        else:
            need(relative in files and relative not in seen, "Extra runtime file")
            row = {"identity": list(identity(item)), **record(path, files[relative]["size"])}
            need(row["size"] == files[relative]["size"] and row["sha256"] == files[relative]["sha256"], "Runtime body differs")
            row.pop("path")
            pair = (item.st_dev, item.st_ino)
            need(pair not in aliases, "Runtime inode alias")
            aliases.add(pair)
        need(identity(path.lstat()) == identity(item), "Runtime identity changed during readback")
        rows[relative] = row
        seen.add(relative)
    need(seen == set(files) | directories, "Incomplete runtime membership")
    # Recheck directory bindings after every child has been consumed.
    for name in directories:
        need(list(identity((root / name).lstat())) == rows[name]["identity"], "Runtime directory changed during traversal")
    return rows


def _denials(root, label):
    payload, added = root / "core.zip", root / ".mrk-denied-add"
    file_destination = root / ".mrk-denied-file"
    version_destination = root.parent / (".mrk-denied-version-" + label)
    for path in (added, file_destination, version_destination):
        _absent(path)
    results = []
    for operation, path, flags in (("writer", payload, os.O_WRONLY), ("add", added, os.O_WRONLY | os.O_CREAT | os.O_EXCL)):
        try:
            fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        except OSError as error:
            results.append({"operation": operation, "errno": denied(error)})
        else:
            os.close(fd)  # consume once, never write, unlink, rollback or retry
            raise Refused("Nonroot unexpectedly acquired a protected writer")
    for operation, source, destination in (("rename-file", payload, file_destination), ("rename-version", root, version_destination)):
        try:
            os.rename(source, destination)
        except OSError as error:
            results.append({"operation": operation, "errno": denied(error)})
        else:
            raise Refused("Nonroot unexpectedly renamed a protected object; preserve it")
    return results


def _prefixes(labels):
    rows = {}
    for path, children in ((Path("/var/lib/mobile-release-kit"), {"versions"}),
                           (Path("/var/lib/mobile-release-kit/versions"), {TARGET}),
                           (PREFIX, {VERSIONS[label][0] for label in labels})):
        directory(path, protected=True)
        before = path.lstat()
        need(stat.S_IMODE(before.st_mode) == 0o755 and {child.name for child in path.iterdir()} == children,
             "Publication prefix mode or exact sibling membership differs")
        _xattrs(path, True)
        need(identity(path.lstat()) == identity(before), "Publication prefix changed during readback")
        rows[str(path)] = list(identity(before))
    return rows


def observe(phase):
    need(phase in {"unpacked", "p0", "upgrade", "duplicate", "remove", "purge"}, "Unknown fixed observation")
    root = Path(__file__).absolute().parent
    directory(root, protected=True)
    start = decode(read(root / "public/unit-start.json"))
    need(root == Path("/var/lib") / start["unit"]["Id"].removesuffix(".service"), "Observer root binding differs")
    _modules(root, owner=False)
    uid, gid = start["runnerUid"], start["runnerGid"]
    status = _status()
    need(os.getresuid() == (uid,) * 3 and os.getresgid() == (gid,) * 3 and not os.getgroups()
         and all(status[key].split() == [str(number)] * 4 for key, number in (("Uid", uid), ("Gid", gid)))
         and status["NoNewPrivs"].strip() == "1"
         and all(int(status[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")), "Dropped observer credentials differ")
    need(_namespaces(False) == start["namespaces"], "Observer namespace identity differs")
    need(time.monotonic() < start["deadline"], "Observer original endpoint expired")
    for manifest in (M, F1):
        _absent(PREFIX / (".publish-" + manifest))
    labels = [] if phase == "unpacked" else (["P0"] if phase == "p0" else ["P0", "F1"])
    if phase in {"unpacked", "p0"}:
        _absent(PREFIX / F1)
    if phase == "unpacked":
        _absent(Path("/var/lib/mobile-release-kit"))
    prefixes = _prefixes(labels) if labels else {}
    result = {"phase": phase, "published": {}, "inputs": {}, "denials": {}, "prefixes": prefixes}
    if phase == "unpacked":
        result["inputs"]["P0"] = _tree(INPUT / M, M, published=False)
    for label in labels:
        manifest = VERSIONS[label][0]
        path = PREFIX / manifest
        before = _tree(path, manifest, published=True)
        if (phase, label) in {("p0", "P0"), ("upgrade", "F1")}:
            original = _tree(INPUT / manifest, manifest, published=False)
            need(set(original) == set(before), "Input/publication membership differs")
            for name, row in before.items():
                need(row["identity"][:2] != original[name]["identity"][:2], "Publication adopted a package input inode")
            result["inputs"][label] = original
        result["denials"][label] = _denials(path, label)
        after = _tree(path, manifest, published=True)
        need(before == after, "Published objects changed during denial observations")
        result["published"][label] = after
    if len(labels) == 2:
        left, right = (result["published"][label] for label in labels)
        need(set(left) == set(right), "Coexisting version membership differs")
        for name in left:
            need(left[name]["identity"][:2] != right[name]["identity"][:2], "Published versions share an inode")
            if "sha256" in left[name] and name != "manifest.json":
                need((left[name]["size"], left[name]["sha256"]) == (right[name]["size"], right[name]["sha256"]), "Fixture payload changed")
    need(not labels or _prefixes(labels) == prefixes, "Publication prefix changed during denial observations")
    raw = canonical(result)
    need(len(raw) <= LIMIT and time.monotonic() < start["deadline"], "Observer bound expired")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def _drop(value, argv):
    return ["/usr/bin/setpriv", "--reuid", str(value["runnerUid"]), "--regid", str(value["runnerGid"]),
            "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--", *argv]


def native_result(stdout, stderr, name):
    need(name in {ROOT_TEST, USER_TEST} and type(stdout) is bytes and len(stdout) <= LIMIT and stderr == b"",
         "Native singleton capture differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    need(len(lines) == 3 and lines[:2] == ["running 1 test", "test " + name + " ... ok"]
         and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
                          r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[2]) is not None,
         "Exact native singleton did not pass once")


def package_state(result):
    if result.returncode == 1:
        need(result.stdout == b"" and result.stderr == ("dpkg-query: no packages found matching " + PACKAGE + "\n").encode("ascii"),
             "Dpkg-query failure is not the exact absent outcome")
        return {"status": "absent", "version": ""}
    need(result.returncode == 0 and result.stderr == b"", "Dpkg-query original outcome differs")
    rows = result.stdout.decode("ascii").splitlines()
    need(len(rows) == 1 and len(rows[0].split("\t")) == 2, "Dpkg-query status/version record differs")
    status, version = rows[0].split("\t")
    if status in {"unknown ok not-installed", "purge ok not-installed"} and version == "":
        return {"status": "absent", "version": ""}
    need(status in {"install ok unpacked", "install ok installed", "install ok half-configured", "deinstall ok config-files"}
         and version in {row[1] for row in VERSIONS.values()}, "Unreviewed actual package state/version")
    return {"status": status, "version": version}


def _scripts(phase, wanted):
    rows = {}
    for name, (size, digest) in SCRIPT_PINS.items():
        path = Path("/var/lib/dpkg/info") / (PACKAGE + "." + name)
        if name not in wanted:
            _absent(path)
            continue
        row = protected_record(path, size)
        need(row["size"] == size and row["sha256"] == digest and stat.S_IMODE(row["identity"][2]) == 0o755,
             "Installed maintainer script bytes/mode differ")
        rows[name] = row
    _retain("scripts-" + phase + ".json", canonical(rows))
    return rows


def script_trace(stderr, expected):
    rows = []
    for line in stderr.decode("ascii").splitlines():
        if "fork/exec " not in line:
            continue
        matched = re.fullmatch(r"D000002: fork/exec /var/lib/dpkg/info/" + re.escape(PACKAGE)
                               + r"\.(postinst|prerm|postrm) \( ([a-z0-9.+ -]*) \)", line)
        need(matched is not None, "Unreviewed dpkg maintainer-script execution diagnostic")
        rows.append((matched[1], tuple(matched[2].split())))
    need(rows == expected, "Actual dpkg maintainer-script order/arguments differ")
    return rows


PRODUCT_PATHS = (Path("/usr/bin/mobile-release-kit-desktop"), Path("/usr/lib/mobile-release-kit"),
                 Path("/usr/share/doc/mobile-release-kit"), Path("/usr/share/applications/mobile-release-kit.desktop"))
ROOT_PHASES = ("start-unit-show", "native-root", "native-user", "state-initial", "unpack", "state-unpacked",
               "nonroot-helper", "observe-unpacked", "configure", "state-p0", "observe-p0", "upgrade",
               "state-upgrade", "observe-upgrade", "duplicate", "state-duplicate", "observe-duplicate",
               "remove", "state-remove", "observe-remove", "purge", "state-purge", "observe-purge")


def root_phases(value):
    if "shell" in value:
        return (ROOT_PHASES[0], "loader-diagnostics", "loader-cache", *ROOT_PHASES[1:11],
                *("shell-" + case for case in SHELL_CASES), "state-shell-finished")
    if "installed" not in value:
        return ROOT_PHASES
    case = value["installed"]["case"]
    initial = (ROOT_PHASES[0], "loader-diagnostics", "loader-cache", *ROOT_PHASES[1:8])
    if case != "positive":
        return (*initial, "installed-" + case, "state-refusal")
    return (*initial, *ROOT_PHASES[8:11], "installed-positive", "installed-deadline", "installed-shutdown", "installed-emfile",
            "upgrade-unpack", "state-upgrade-unpacked", "upgrade-configure", "installed-overlap", *ROOT_PHASES[12:])


def result_state(value):
    if "shell" in value:
        return "normal-shell-installed-runtime-connection-observed"
    if "installed" not in value:
        return "p0-f1-lifecycle-observed"
    return "installed-passive-positive-and-lifecycle-observed" if value["installed"]["case"] == "positive" else "installed-passive-refusal-observed"


def public_files(value):
    fixed = {phase + "." + suffix for phase in (*root_phases(value), "stop-unit-show") for suffix in ("stdout", "stderr")}
    fixed |= {"unit-start.json", "unit-result.json", "unit-stop.json", "inputs.json", "dpkg-policy.json", "scripts-unpacked.json", "binaries-unpacked.json"}
    if "shell" in value:
        return fixed | {"loader-entry.json", "loader-final.json", "loader-runtime.json", "shell-cases.json",
                        "shell-normal-control.json", "shell-positive-project-before.json", "shell-positive-project-after.json",
                        "published-before-upgrade.txt", "mutation-denials.txt"} \
            | {"shell-root-data-" + str(index) + ".json" for index in range(len(SHELL_DATA_ROOTS))}
    installed = value.get("installed")
    if installed is not None:
        fixed |= {"loader-entry.json", "loader-final.json", "installed-cases.json"}
        if installed["case"] != "positive":
            return fixed | {"refusal-fixture-before.json", "refusal-fixture-after.json"}
        fixed |= {"loader-runtime.json", "installed-overlap-join.json", "scripts-upgrade-unpacked.json", "binaries-upgrade-unpacked.json"}
    fixed |= {"mutation-denials.txt", "binaries-upgrade.json"}
    fixed |= {"scripts-" + phase + ".json" for phase in ("before-upgrade", "upgrade", "duplicate", "remove", "purge")}
    fixed |= {"published-" + phase + ".txt" for phase in ("before-upgrade", "after-upgrade", "after-duplicate", "after-remove", "after-purge")}
    return fixed


def lifecycle_states(value):
    rows = [("initial", "absent", None), ("unpacked", "install ok unpacked", "P0")]
    if "shell" in value:
        rows += [("p0", "install ok installed", "P0"), ("shell-finished", "install ok installed", "P0")]
    elif "installed" in value and value["installed"]["case"] != "positive":
        rows.append(("refusal", "install ok unpacked", "P0"))
    else:
        rows += [("p0", "install ok installed", "P0"), ("upgrade", "install ok installed", "F1"),
                 ("duplicate", "install ok half-configured", "F1"), ("remove", "deinstall ok config-files", "F1"), ("purge", "absent", None)]
        if "installed" in value:
            rows.append(("upgrade-unpacked", "install ok unpacked", "F1"))
    return {phase: {"status": status, "version": VERSIONS[variant][1] if variant else ""} for phase, status, variant in rows}


def _no_package_data():
    for path in PRODUCT_PATHS:
        _absent(path)


def _no_admin_data():
    path = Path("/var/lib/dpkg/info")
    directory(path, protected=True)
    need(not any(item.name.startswith((PACKAGE + ".", PACKAGE + ":")) for item in path.iterdir()),
         "Prior/remaining package administrative DATA exists")


def _binaries(value, phase, label):
    rows = {}
    expected = value["compilerRecords"].get("binaries")
    need(type(expected) is dict and set(expected) == {"P0", "F1", "fixture"}, "Original compiler binary pins missing")
    for key, path in ((label, Path(HELPER)), ("fixture", PRODUCT_PATHS[0])):
        row = protected_record(path)
        pin = expected[key]
        need(type(pin) is dict and set(pin) == {"path", "size", "sha256"}
             and type(pin["size"]) is int and row["size"] == pin["size"] and row["sha256"] == pin["sha256"]
             and stat.S_IMODE(row["identity"][2]) == 0o755, "Installed compiler output bytes/mode differ")
        rows[key] = row
    _retain("binaries-" + phase + ".json", canonical(rows))


def loader_diagnostics(raw):
    """Bounded DATA from the already-bound OS loader; never a resolver."""
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT and raw.endswith(b"\n"), "Loader diagnostic capture bound differs")
    rows = {}
    component = r"[A-Za-z_][A-Za-z0-9_]*(?:\[0x[0-9a-f]{1,8}\])?"
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        need(separator and len(rows) < 4096 and len(key) <= 256 and key not in rows
             and re.fullmatch(component + r"(?:\." + component + r")*", key) is not None
             and len(value) <= 8192 and re.fullmatch(r'0x[0-9a-f]{1,16}|"(?:[^"\\\x00-\x1f]|\\[0-7]{3}|\\["\\])*"', value) is not None,
             "Loader diagnostic grammar/duplicate differs")
        rows[key] = value
    fixed = {"dl_dst_lib": '"lib/x86_64-linux-gnu"', "dso.ld": '"ld-linux-x86-64.so.2"',
             "dso.libc": '"libc.so.6"', "path.rtld": '"/lib64/ld-linux-x86-64.so.2"',
             "version.version": '"2.39"', "dl_hwcaps_subdirs": '"' + ":".join(HWCAPS) + '"'}
    need(all(rows.get(key) == value for key, value in fixed.items()), "Fixed OS loader profile differs")
    directories = {"path.system_dirs[0x" + format(index, "x") + "]": '"' + path + '/"'
                   for index, path in enumerate(DEFAULT_LIBRARY_DIRS)}
    need({key: value for key, value in rows.items() if key.startswith("path.system_dirs")} == directories,
         "Compiled OS default library directories differ")
    active = rows.get("dl_hwcaps_subdirs_active", "")
    need(re.fullmatch(r"0x[0-7]", active) is not None, "Unknown active OS hwcaps mask")
    return {"defaultDirectories": list(DEFAULT_LIBRARY_DIRS), "hwcaps": list(HWCAPS), "activeMask": int(active, 16),
            "checkedTiers": list(HWCAPS), "policy": "Conservatively check all three tiers, including inactive tiers."}


def loader_cache(raw, version, *, shell_names=None):
    relevant = OS_SONAMES | PRIVATE_SONAMES
    if shell_names is not None:
        need(type(shell_names) is list and shell_names == sorted(set(shell_names)) and 1 <= len(shell_names) <= 256
             and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}", name) is not None
                     for name in shell_names), "Bounded explicit shell cache roster differs")
        relevant = set(shell_names) | PRIVATE_SONAMES
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT and raw.endswith(b"\n"), "Loader cache listing bound differs")
    lines = raw.decode("ascii").splitlines()
    header = re.fullmatch(r"([0-9]{1,5}) libs found in cache `/etc/ld\.so\.cache'", lines[0])
    need(header is not None and 0 < int(header[1]) <= 8192, "Fixed loader cache header differs")
    count = int(header[1])
    footer = "Cache generated by: ldconfig (Ubuntu GLIBC " + version + ") stable release version 2.39"
    need(len(lines) in {count + 1, count + 2} and (len(lines) == count + 1 or lines[-1] == footer),
         "Loader cache row count/generator differs")
    result = []
    for line in lines[1:count + 1]:
        found = re.fullmatch(r"\t([A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}) \(([A-Za-z0-9_., :\"\-]{1,128})\) => (/[A-Za-z0-9_./+\-]{1,4095})", line)
        need(found is not None, "Loader cache row grammar differs")
        name, flags, path = found.groups()
        absolute(path)
        eligible = False
        if name in relevant:
            # Relevant foreign ABI rows are explicit, never mistaken for this
            # x86-64 ABI. Unknown flag/hwcap semantics refuse rather than guess.
            need(flags == "libc6" or re.fullmatch(r'libc6,x86-64(?:, hwcap: "x86-64-v[234]")?', flags) is not None,
                 "Relevant loader cache ABI/hwcap flags differ")
            eligible = flags != "libc6"
        result.append({"soname": name, "flags": flags, "path": path, "eligibleX86_64": eligible})
    return result


def loader_candidates(names, rows):
    need(type(names) is list and names == sorted(set(names)) and set(names) <= OS_SONAMES | PRIVATE_SONAMES,
         "Fixed SONAME candidate roster differs")
    choices = {(row["soname"], row["path"]) for row in rows if row["soname"] in names and row["eligibleX86_64"]}
    choices |= {(name, directory + "/" + suffix + name) for name in names for directory in DEFAULT_LIBRARY_DIRS
                for suffix in ("", *("glibc-hwcaps/" + tier + "/" for tier in HWCAPS))}
    return sorted(choices)


def loader_selected(row, admitted):
    need(row.get("absent") is True or row["path"] == admitted["path"] and row["identity"] == admitted["identity"]
         and all(row[key] == admitted[key] for key in ("size", "sha256")),
         "Eligible cache/default/hwcaps dependency is an alternative object")


def shell_loader_candidates(names, rows, tiers):
    """An absent tier directory excludes every child, without thousands of duplicate proofs."""
    need(type(names) is list and names == sorted(set(names)) and 1 <= len(names) <= 256
         and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}", name) for name in names),
         "Bounded shell global provider roster differs")
    fixed = {directory + "/glibc-hwcaps/" + tier for directory in DEFAULT_LIBRARY_DIRS for tier in HWCAPS}
    need(type(tiers) is dict and set(tiers) == fixed and all(type(present) is bool for present in tiers.values()),
         "Complete original shell hwcaps directory presence missing")
    choices = {(row["soname"], row["path"]) for row in rows if row["soname"] in names and row["eligibleX86_64"]}
    choices |= {(name, directory + "/" + name) for name in names for directory in DEFAULT_LIBRARY_DIRS}
    choices |= {(name, directory + "/" + name) for directory, present in tiers.items() if present for name in names}
    return sorted(choices)


def shell_global_names(libraries):
    # A global SONAME selector may canonically resolve through alternatives.
    # Only these two fixed RUNPATH selectors are outside the global search;
    # canonical subdirectories never confer that exemption.
    private = {"libpxbackend-1.0.so": "/usr/lib/x86_64-linux-gnu/libproxy/libpxbackend-1.0.so",
               "libpulsecommon-16.1.so": "/usr/lib/x86_64-linux-gnu/pulseaudio/libpulsecommon-16.1.so"}
    names = []
    for name, row in libraries.items():
        selected = row["file"]["selectedPath"]
        if selected == "/usr/lib/x86_64-linux-gnu/" + name:
            names.append(name)
        else:
            need(name in private and selected == private[name], "Unadmitted nonglobal shell provider selector")
    return sorted(names)


def mount_scope(raw, initial, device):
    need(type(raw) is str and raw == initial and 0 < len(raw) <= JSON_LIMIT and raw.endswith("\n") and "\0" not in raw,
         "Original initial mount table differs/unbounded")
    roots, ids, points = [], set(), set()
    for line in raw.splitlines():
        fields = line.split(" ")
        need(len(ids) < 4096 and all(fields) and fields.count("-") == 1, "Mount table grammar/bound differs")
        at = fields.index("-")
        need(at >= 6 and len(fields) == at + 4 and re.fullmatch(r"[1-9][0-9]{0,9}", fields[0]) is not None
             and fields[0] not in ids and re.fullmatch(r"[1-9][0-9]{0,9}", fields[1]) is not None
             and re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", fields[2]) is not None
             and fields[5].split(",")[0] in {"ro", "rw"}, "Mount table identity/options differ")
        ids.add(fields[0])
        decoded = []
        for path in fields[3:5]:
            need(path.startswith("/") and re.fullmatch(r"(?:[^\\\x00-\x20]|\\(?:040|011|012|134))+", path) is not None,
                 "Mount table path escapes differ")
            decoded.append(re.sub(r"\\(040|011|012|134)", lambda found: chr(int(found[1], 8)), path))
        points.add(decoded[1])
        tags = set()
        for option in fields[6:at]:
            tag, separator, number = option.partition(":")
            need(tag not in tags and ((tag == "unbindable" and not separator)
                 or (tag in {"shared", "master", "propagate_from"} and re.fullmatch(r"[1-9][0-9]{0,9}", number))),
                 "Unknown/duplicate mount propagation or ID-map option")
            tags.add(tag)
        if decoded[1] == "/":
            need(decoded[0] == "/" and fields[at + 1] in {"ext4", "xfs"}, "Root is not the admitted complete native filesystem")
            major, minor = (int(part) for part in fields[2].split(":"))
            need((major, minor) == (os.major(device), os.minor(device)), "Root mount device differs")
            roots.append({"mountId": int(fields[0]), "device": device, "filesystem": fields[at + 1]})
    need(len(roots) == 1, "Initial full root mount is missing/ambiguous")
    return {"sha256": hashlib.sha256(raw.encode("ascii")).hexdigest(), "root": roots[0], "mountpoints": sorted(points)}


def _mount_scope():
    return mount_scope(_kernel("/proc/self/mountinfo", JSON_LIMIT), _kernel("/proc/1/mountinfo", JSON_LIMIT), Path("/").stat().st_dev)


def _mount_path(scope, path):
    need(not any(point != "/" and (str(path) == point or str(path).startswith(point + "/")) for point in scope["mountpoints"]),
         "Loader path crosses an unadmitted nested mount")


def _data_identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns]


def _loader_binding(path, scope, *, directory_only=False, absent=False, limit=FILE_LIMIT):
    """Finite OS/A names only: original root link ancestry, ACLs and mount scope.

    Matches CI's file DATA shape but adds actual root ACL/mount observations.
    Directory mtime/ctime is not frozen across legitimate package installs.
    """
    path = absolute(str(path))
    pending, resolved, links, ancestry = list(path.parts[1:]), Path("/"), [], {}

    def ancestor(name, item):
        need(stat.S_ISDIR(item.st_mode) and item.st_uid == item.st_gid == 0 and not item.st_mode & 0o7022
             and item.st_dev == scope["root"]["device"], "Unprotected/wrong-mount loader ancestor")
        _xattrs(name, True)
        ancestry[str(name)] = [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid]

    ancestor(resolved, resolved.lstat())
    steps, missing = 0, None
    while pending:
        steps += 1
        need(steps <= 256, "Loader original ancestry/link bound exceeded")
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        candidate = resolved / part
        _mount_path(scope, candidate)
        try:
            item = candidate.lstat()
        except FileNotFoundError:
            need(absent, "Required loader object absent")
            missing = str(candidate)
            resolved = candidate.joinpath(*pending)
            break
        need(item.st_uid == item.st_gid == 0 and item.st_dev == scope["root"]["device"], "Loader object owner/mount differs")
        if stat.S_ISLNK(item.st_mode):
            target = os.readlink(candidate)
            need(item.st_nlink == 1 and len(links) < 40 and len(target) <= 4096
                 and re.fullmatch(r"[A-Za-z0-9_./+\-]+", target) is not None
                 and identity(candidate.lstat()) == identity(item), "Loader original link differs")
            links.append([str(candidate), _data_identity(item), target])
            target = Path(target)
            if target.is_absolute():
                resolved, parts = Path("/"), target.parts[1:]
            else:
                parts = target.parts
            pending = [*parts, *pending]
        else:
            need(not item.st_mode & 0o7022, "Loader object writable/special mode")
            resolved = candidate
            if pending or directory_only:
                ancestor(resolved, item)
            else:
                need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, "Loader object is not an ordinary file")
                _xattrs(resolved, False)
    result = {"path": str(resolved), "selectedPath": str(path), "links": links, "ancestry": ancestry}
    if missing is not None:
        result.update(absent=True, absentAt=missing)
    elif directory_only:
        result["directory"] = ancestry[str(resolved)]
    else:
        before = resolved.lstat()
        result.update(record(resolved, limit), identity=_data_identity(before))
        need(identity(resolved.lstat()) == identity(before), "Original loader file changed during readback")
    for name, expected in ancestry.items():
        item = Path(name).lstat()
        need([item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid] == expected, "Original loader ancestry changed")
        _xattrs(Path(name), True)
    for name, expected, target in links:
        need(_data_identity(Path(name).lstat()) == expected and os.readlink(name) == target, "Original loader link changed")
    if missing is None:
        need(path.resolve(strict=True) == resolved, "Original loader canonical path changed")
    else:
        _absent(Path(missing))
    return result


def _installed_loader_start(value, namespaces):
    policy = value["installed"]["loaderPolicy"]
    need(type(policy) is dict and set(policy) == {"libraries", "loader", "ldconfig", "cache", "packages", "osNames", "graph", "externalPrerequisites"},
         "Fixed installed loader policy fields differ")
    names, graph = policy["osNames"], policy["graph"]
    candidate = value["installed"]["candidateCompiler"]["nativeInputs"]
    old = value["compilerRecords"]["nativeInputs"]
    need(type(names) is list and names == sorted(set(names)) and set(names) <= OS_SONAMES
         and set(names) == set(graph["osNames"]) | set(old["outputs"]["libtest"]["objects"])
         and {"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"} <= set(names)
         and set(policy["libraries"]) == set(names) and graph["candidate"] == candidate["outputs"]["candidate"]
         and not set(graph["candidate"]["objects"]) & PRIVATE_SONAMES
         and graph["manifestSha256"] == M and graph["protocolSha256"] == Q, "Complete original candidate/U/A OS closure differs")
    scope, bindings = _mount_scope(), {}
    for name, row in policy["libraries"].items():
        need(row["elf"] == candidate["sharedObjects"][name]["elf"] == old["sharedObjects"][name]["elf"]
             and all(row["file"][key] == candidate["sharedObjects"][name]["file"][key] == old["sharedObjects"][name]["file"][key]
                     for key in ("size", "sha256")), "OS file differs from either original compiler record")
    for row in [*(row["file"] for row in policy["libraries"].values()), policy["loader"], policy["ldconfig"], policy["cache"]]:
        current = _loader_binding(Path(row["selectedPath"]), scope)
        need(current == row, "Root loader input differs from the original current-VM binding")
        bindings[row["selectedPath"]] = current
    need(policy["loader"]["path"] == policy["libraries"]["ld-linux-x86-64.so.2"]["file"]["path"]
         and policy["loader"]["selectedPath"] == "/lib64/ld-linux-x86-64.so.2"
         and policy["ldconfig"]["selectedPath"] == "/usr/sbin/ldconfig.real" and policy["cache"]["selectedPath"] == "/etc/ld.so.cache",
         "Fixed admitted loader/cache/static-tool names differ")
    for leaf, expected in (("platform-tests", value["library"]), ("installed-tests", value["installed"]["candidate"])):
        row = _loader_binding(_ROOT / leaf, scope)
        need(all(row[key] == expected[key] for key in ("size", "sha256")), "Fresh protected native test copy differs")
        bindings[str(_ROOT / leaf)] = row
    preload = _loader_binding(Path("/etc/ld.so.preload"), scope, absent=True)
    need(preload.get("absent") is True, "Ambient loader preload is present")
    bindings["/etc/ld.so.preload"] = preload
    diagnostics = command("loader-diagnostics", ["/lib64/ld-linux-x86-64.so.2", "--list-diagnostics"], maximum=15, env={"LANG": "C", "LC_ALL": "C"})
    need(diagnostics.stderr == b"", "OS loader emitted a diagnostic failure")
    profile = loader_diagnostics(diagnostics.stdout)
    cache = command("loader-cache", ["/usr/sbin/ldconfig.real", "-p"], maximum=15, env={"LANG": "C", "LC_ALL": "C"})
    need(cache.stderr == b"", "Static ldconfig emitted a diagnostic failure")
    cache_rows = loader_cache(cache.stdout, policy["packages"]["libc-bin"][2])
    for directory_name in DEFAULT_LIBRARY_DIRS:
        bindings[directory_name] = _loader_binding(Path(directory_name), scope, directory_only=True)
    for name, path in loader_candidates(names, cache_rows):
        row = _loader_binding(Path(path), scope, absent=True)
        loader_selected(row, policy["libraries"][name]["file"])
        bindings[path] = row
    proof = {"scope": scope, "namespaces": namespaces, "bindings": bindings, "diagnostics": profile,
             "cacheRows": [row for row in cache_rows if row["soname"] in set(names) | PRIVATE_SONAMES],
             "entryObjects": names, "payloadAdmitted": False,
             "externalPrerequisites": policy["externalPrerequisites"]}
    _installed_loader_check(proof)
    _retain("loader-entry.json", canonical(proof))
    return proof


def _installed_loader_check(proof):
    need(_namespaces(True) == proof["namespaces"] and _mount_scope() == proof["scope"], "Original loader namespace/mount interval changed")
    for path, expected in proof["bindings"].items():
        row = _loader_binding(Path(path), proof["scope"], directory_only="directory" in expected, absent=expected.get("absent", False))
        need(row == expected, "Original loader/preload/cache/search binding changed")
    need(time.monotonic() < _END, "Original loader interval closed late")


SHELL_DATA_ROOTS = (
    ("/etc/gtk-3.0", "directory"), ("/etc/fonts", "directory"),
    ("/usr/share/fontconfig", "directory"), ("/usr/share/fonts", "directory"),
    ("/usr/local/share/fonts", "directory"), ("/var/cache/fontconfig", "directory"),
    ("/usr/share/glib-2.0/schemas", "directory"),
    ("/usr/share/glvnd/egl_vendor.d", "directory"), ("/etc/glvnd/egl_vendor.d", "directory"),
    ("/usr/share/drirc.d", "directory"), ("/etc/drirc", "file"),
    ("/usr/share/X11/xkb", "directory"), ("/usr/share/X11/locale", "directory"),
    ("/usr/share/icons/Adwaita", "directory"), ("/usr/share/icons/hicolor", "directory"),
    ("/usr/share/themes/Adwaita", "directory"), ("/usr/share/mime/mime.cache", "file"),
    ("/usr/share/hunspell", "directory"), ("/usr/share/hyphen", "directory"),
    ("/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache", "file"),
    ("/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache", "file"),
    ("/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules.cache", "file"),
)
SHELL_MODULE_CACHES = {
    "/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache": "/usr/lib/x86_64-linux-gnu/gio/modules",
    "/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache": "/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders",
    "/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules.cache": "/usr/lib/x86_64-linux-gnu/gtk-3.0/3.0.0/immodules",
}


def shell_generated_data(path):
    return (path in SHELL_MODULE_CACHES or path.startswith("/var/cache/fontconfig/")
            or path == "/var/cache/fontconfig" or path == "/usr/share/glib-2.0/schemas/gschemas.compiled"
            or path == "/usr/share/mime/mime.cache"
            or path.startswith("/usr/share/icons/") and Path(path).name == "icon-theme.cache"
            or path.startswith(("/usr/share/fonts/", "/usr/local/share/fonts/")) and Path(path).name == ".uuid")


def shell_module_cache(path, raw):
    """Only the module selectors in the three fixed generated DATA formats."""
    need(path in SHELL_MODULE_CACHES and type(raw) is bytes and len(raw) <= 1 << 20 and b"\0" not in raw,
         "Fixed shell module catalogue bound differs")
    rows, root = [], SHELL_MODULE_CACHES[path]
    if path.endswith("/giomodule.cache"):
        for line in raw.decode("ascii").splitlines():
            found = re.fullmatch(r"([A-Za-z0-9_+.-]+\.so): ([A-Za-z0-9_,; +.-]+)", line)
            need(found is not None, "GIO module catalogue grammar differs")
            rows.append(root + "/" + found[1])
    else:
        for block in re.split(r"\n[ \t]*\n", raw.decode("ascii")):
            lines = [line.strip() for line in block.splitlines() if line.strip() and not line.startswith("#")]
            if not lines:
                continue
            found = re.fullmatch(r'"(/[^"\\\x00-\x20]+\.so)"', lines[0])
            need(found is not None and len(lines) >= 2 and len(lines) <= 512,
                 "GTK/pixbuf module catalogue stanza differs")
            selected = str(absolute(found[1]))
            need(Path(selected).parent == Path(root), "Module catalogue selects another directory")
            rows.append(selected)
    need(len(rows) <= 512 and len(rows) == len(set(rows)), "Duplicate/oversized module catalogue selection")
    return sorted(rows)


def shell_data_snapshot(bind_path):
    """Finite protected OS DATA only; no invocation, extraction or new owner.

    bind_path accepts the existing directory_only/absent/limit flags. Compiler
    and root use their own protected bindings; root additionally proves mounts
    and ACLs. Supplier summaries are portable. Generated caches are separate
    current-VM receipts, never purported package/compiler inputs. Full detail
    is split only by these fixed roots, each within the old 2 MiB file bound.
    """
    details, suppliers, caches, selections, egl = {}, {}, {}, {}, {}
    count, total, retained, unique = 0, 0, 0, {}
    for root_name, kind in SHELL_DATA_ROOTS:
        root = Path(root_name)
        detail = {"entries": [], "files": {}, "links": {}, "ancestry": {}, "directories": {}, "absences": {}}
        rows, generated, pending = [], [], [(root, kind)]

        def merge(binding):
            for name, value in binding["ancestry"].items():
                need(name not in detail["ancestry"] or detail["ancestry"][name] == value, "Shell DATA ancestry drift")
                detail["ancestry"][name] = value
            for name, state, target in binding["links"]:
                value = [state, target]
                need(name not in detail["links"] or detail["links"][name] == value, "Shell DATA link drift")
                detail["links"][name] = value

        while pending:
            path, selected_kind = pending.pop()
            count += 1
            need(count <= 32768 and len(path.parts) - len(root.parts) <= 16, "Shell DATA entry/depth bound")
            binding = bind_path(path, directory_only=selected_kind == "directory", absent=True, limit=64 << 20)
            merge(binding)
            relative = str(path.relative_to(root))
            row = {"path": relative, "kind": selected_kind, "present": not binding.get("absent", False)}
            is_cache = shell_generated_data(str(path))
            if not row["present"]:
                need(path == root, "Shell DATA member disappeared during inventory")
                detail["absences"][str(path)] = {key: binding[key] for key in ("path", "absentAt")}
            elif selected_kind == "directory":
                need(not path.is_symlink(), "Shell DATA directory alias is not a reviewed root")
                before = identity(path.lstat())
                children = sorted(child.name for child in path.iterdir())
                need(len(children) <= 8192 and all(re.fullmatch(r"[A-Za-z0-9_.+@\-]+", name) for name in children),
                     "Shell DATA directory membership bound/grammar")
                row.update(canonical=binding["path"], mode=stat.S_IMODE(binding["directory"][2]),
                           children=[name for name in children if not shell_generated_data(str(path / name))])
                detail["directories"][str(path)] = {"path": binding["path"], "identity": binding["directory"], "children": children}
                for name in reversed(children):
                    child = path / name
                    item = child.lstat()
                    need(stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode),
                         "Nonordinary shell DATA child")
                    pending.append((child, "directory" if stat.S_ISDIR(item.st_mode) else "file"))
                need(identity(path.lstat()) == before, "Shell DATA directory changed while listing")
            else:
                need(not binding["identity"][2] & 0o111, "Executable input cannot enter the shell DATA-only profile")
                file = {key: binding[key] for key in ("size", "sha256", "identity")}
                canonical_path = binding["path"]
                need(canonical_path not in detail["files"] or detail["files"][canonical_path] == file, "Shell DATA file drift")
                detail["files"][canonical_path] = file
                row.update(canonical=canonical_path, size=file["size"], sha256=file["sha256"],
                           mode=stat.S_IMODE(file["identity"][2]), links=[[name, target] for name, _, target in binding["links"]])
                if canonical_path not in unique:
                    unique[canonical_path] = file
                    total += file["size"]
                else:
                    need(unique[canonical_path] == file, "Shell DATA alias changed its original target")
                need(total <= 512 << 20, "Shell DATA canonical byte bound")
                if str(path) in SHELL_MODULE_CACHES:
                    raw = read(Path(canonical_path), 1 << 20)
                    need(len(raw) == file["size"] and hashlib.sha256(raw).hexdigest() == file["sha256"], "Module cache changed while parsing")
                    selections[str(path)] = shell_module_cache(str(path), raw)
                if str(path.parent) in {"/usr/share/glvnd/egl_vendor.d", "/etc/glvnd/egl_vendor.d"}:
                    need(path.suffix == ".json", "Unexpected EGL vendor DATA member")
                    raw = read(Path(canonical_path), 64 << 10)
                    need(len(raw) == file["size"] and hashlib.sha256(raw).hexdigest() == file["sha256"], "EGL selector changed while parsing")
                    value = decode(raw, 64 << 10)
                    need(type(value) is dict and set(value) == {"file_format_version", "ICD"}
                         and value["file_format_version"] == "1.0.0" and type(value["ICD"]) is dict
                         and set(value["ICD"]) == {"library_path"}, "Fixed EGL ICD format differs")
                    library = value["ICD"]["library_path"]
                    need(type(library) is str and re.fullmatch(r"(?:/usr/lib/x86_64-linux-gnu/)?libEGL_[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*", library),
                         "EGL vendor selects an unreviewed provider path")
                    egl[str(path)] = str(Path("/usr/lib/x86_64-linux-gnu") / library)
            detail["entries"].append(row)
            (generated if is_cache else rows).append(row)
        for name, item in detail["directories"].items():
            current = bind_path(Path(name), directory_only=True)
            need(current["directory"] == item["identity"] and sorted(child.name for child in Path(name).iterdir()) == item["children"],
                 "Shell DATA directory membership changed after inventory")
        for target, entries in ((suppliers, rows), (caches, generated)):
            ordered = sorted(entries, key=lambda row: row["path"])
            target[root_name] = {"kind": kind, "present": ordered[0]["present"] if ordered else None, "entryCount": len(ordered),
                "fileCount": sum(row["kind"] == "file" and row["present"] for row in ordered),
                "byteCount": sum(row.get("size", 0) for row in ordered), "sha256": hashlib.sha256(canonical(ordered)).hexdigest()}
        detail["entries"].sort(key=lambda row: row["path"])
        size = len(canonical(detail))
        retained += size
        need(size <= LIMIT and retained <= 16 << 20, "Fixed per-root shell DATA detail/total bound")
        details[root_name] = detail
    for path in SHELL_MODULE_CACHES:
        selections.setdefault(path, [])
    return {"suppliers": {"roots": suppliers, "sha256": hashlib.sha256(canonical(suppliers)).hexdigest()},
            "caches": {"roots": caches, "sha256": hashlib.sha256(canonical(caches)).hexdigest()},
            "moduleSelections": selections, "eglLibraries": egl, "details": details}


SHELL_LOADER_RETAINED = ("graph", "osFiles", "moduleRoots", "runtimeData", "loader", "ldconfig", "cache", "osNames", "externalPrerequisites")
SHELL_LOADER_OMITTED = ("libraries", "programs", "modules", "scripts", "packages")


def expand_shell_loader_policy(compact, compiler):
    """One lossless wire version; return a private view, never expand inputs.json."""
    need(type(compact) is dict and set(compact) == {"schemaVersion", *SHELL_LOADER_RETAINED},
         "Fixed compact shell loader policy fields differ")
    need(type(compact["schemaVersion"]) is int and compact["schemaVersion"] == 1,
         "Unsupported compact shell loader policy version")
    need(all(type(compact[key]) is dict for key in SHELL_LOADER_RETAINED if key not in {"osNames", "externalPrerequisites"})
         and type(compact["osNames"]) is list and type(compact["externalPrerequisites"]) is str,
         "Compact shell loader policy shape differs")
    pin = compiler.get("nativeRecord") if type(compiler) is dict else None
    need(type(pin) is dict and set(pin) == {"path", "size", "sha256"}
         and type(pin["size"]) is int and pin["size"] > 0 and type(pin["sha256"]) is str,
         "Original shell native graph binding is missing")
    raw = canonical(compact["graph"])
    need(len(raw) == pin["size"] and hashlib.sha256(raw).hexdigest() == pin["sha256"],
         "Shell native graph lost its original compiler binding")
    policy = deepcopy({key: compact[key] for key in SHELL_LOADER_RETAINED})
    graph = policy["graph"]
    need(all(type(graph.get(key)) is dict for key in ("osFiles", "sharedObjects", "programs", "modules", "scripts", "osPackages"))
         and set(policy["osFiles"]) == set(graph["osFiles"]), "Compact shell native reconstruction roster differs")
    for selected, row in policy["osFiles"].items():
        # protected_host_file/D.state and _loader_binding/_data_identity both
        # use these seven fields, not the separate nine-field lifecycle identity.
        need(type(row) is dict and {"path", "selectedPath", "size", "sha256", "identity"} <= set(row)
             and row["selectedPath"] == selected and type(row["identity"]) is list and len(row["identity"]) == 7
             and all(type(part) is int for part in row["identity"]), "Compact shell current file identity differs")
        portable = {key: row[key] for key in ("path", "selectedPath", "size", "sha256")}
        portable["mode"] = stat.S_IMODE(row["identity"][2])
        need(canonical(portable) == canonical(graph["osFiles"][selected]),
             "Compact shell current file differs from its compiler")
    for kind, source in (("libraries", "sharedObjects"), ("programs", "programs"), ("modules", "modules"), ("scripts", "scripts")):
        policy[kind] = {}
        for name, original in graph[source].items():
            fields = {"file", "package", "interpreter" if kind == "scripts" else "elf"}
            need(type(original) is dict and set(original) == fields and type(original["file"]) is dict
                 and set(original["file"]) == {"path", "selectedPath", "size", "sha256", "mode"},
                 "Compact shell executable reconstruction shape differs")
            selected = original["file"]["selectedPath"]
            need(type(selected) is str and selected in policy["osFiles"]
                 and canonical(original["file"]) == canonical(graph["osFiles"][selected]),
                 "Compact shell executable lost its current file binding")
            row = deepcopy(original)
            row["file"]["identity"] = list(policy["osFiles"][selected]["identity"])
            policy[kind][name] = row
    policy["packages"] = deepcopy(graph["osPackages"])
    return policy


def compact_shell_loader_policy(policy, compiler):
    """Omit duplicates only after comparison with the fully checked VM policy."""
    need(type(policy) is dict and set(policy) == {*SHELL_LOADER_RETAINED, *SHELL_LOADER_OMITTED},
         "Fixed full shell loader policy fields differ")
    compact = {"schemaVersion": 1, **{key: policy[key] for key in SHELL_LOADER_RETAINED}}
    expanded = expand_shell_loader_policy(compact, compiler)
    need(canonical(expanded) == canonical(policy), "Compact shell loader reconstruction differs from the checked original")
    return deepcopy(compact)


def _shell_loader_start(value, namespaces):
    """Separate GTK/WebKit entry policy; never widens the feature-off J gate."""
    shell, old = value["shell"], value["compilerRecords"]["nativeInputs"]
    policy = expand_shell_loader_policy(shell["loaderPolicy"], shell["compiler"])
    graph = policy["graph"]
    need(graph["manifestSha256"] == M and graph["protocolSha256"] == Q
         and set(graph["outputs"]) == set(shell["binaries"]), "Shell native graph lost its original compiler binding")
    names = policy["osNames"]
    need(type(names) is list and names == sorted(set(names)) and 1 <= len(names) <= 256
         and set(names) == set(policy["libraries"]) == set(graph["sharedObjects"])
         and set(old["outputs"]["libtest"]["objects"]) <= set(names), "Shell/U complete entry closure differs")
    scope, bindings = _mount_scope(), {}
    for name, row in policy["libraries"].items():
        original = graph["sharedObjects"][name]
        need(row["elf"] == original["elf"] and all(row["file"][key] == original["file"][key] for key in ("size", "sha256")),
             "Shell current provider differs from its compiler")
        if name in old["sharedObjects"]:
            prior = old["sharedObjects"][name]
            need(row["elf"] == prior["elf"] and all(row["file"][key] == prior["file"][key] for key in ("size", "sha256")),
                 "Common shell/U provider differs from accepted U")
    for row in [*policy["osFiles"].values(), policy["loader"], policy["ldconfig"], policy["cache"]]:
        current = _loader_binding(Path(row["selectedPath"]), scope)
        need(current == row, "Root shell helper/module/data input differs from this VM's admitted binding")
        bindings[row["selectedPath"]] = current
    for kind, originals in (("libraries", graph["sharedObjects"]), ("programs", graph["programs"]),
                             ("modules", graph["modules"]), ("scripts", graph["scripts"])):
        need(set(policy[kind]) == set(originals), "Shell executable/module roster differs from compiler")
        for name, row in policy[kind].items():
            bound = bindings[row["file"]["selectedPath"]]
            portable = {key: bound[key] for key in ("path", "selectedPath", "size", "sha256")}
            portable["mode"] = stat.S_IMODE(bound["identity"][2])
            need(portable == originals[name]["file"] and row["file"] == {**portable, "identity": bound["identity"]},
                 "Shell executable/module provider lost its protected current binding")
    modules = policy["moduleRoots"]
    for path, row in modules.items():
        binding = _loader_binding(Path(path), scope, directory_only=True, absent=True)
        need(binding == row["binding"] and (row["children"] == [] if binding.get("absent") else
             sorted(child.name for child in Path(path).iterdir()) == row["children"]),
             "Shell module directory or membership differs from original admission")
        bindings[path] = binding
    shell_module_proof(graph, modules, bindings)
    for row in graph["privateSearch"]:
        binding = _loader_binding(Path(row["path"]), scope, absent=True)
        shell_private_selected(row, binding, policy["libraries"][row["name"]]["file"])
        need(row["path"] not in bindings or bindings[row["path"]] == binding, "Shell private search path changed")
        bindings[row["path"]] = binding
    need(policy["loader"]["path"] == policy["libraries"]["ld-linux-x86-64.so.2"]["file"]["path"]
         and policy["loader"]["selectedPath"] == "/lib64/ld-linux-x86-64.so.2"
         and policy["ldconfig"]["selectedPath"] == "/usr/sbin/ldconfig.real"
         and policy["cache"]["selectedPath"] == "/etc/ld.so.cache", "Fixed shell loader/cache names differ")
    copies = [("platform-tests", value["library"]), *(("shell-" + role, row) for role, row in shell["binaries"].items())]
    for leaf, expected in copies:
        row = _loader_binding(_ROOT / leaf, scope)
        need(all(row[key] == expected[key] for key in ("size", "sha256")), "Protected normal/observer/U platform copy differs")
        bindings[str(_ROOT / leaf)] = row
    bindings["/etc/ld.so.preload"] = _loader_binding(Path("/etc/ld.so.preload"), scope, absent=True)
    need(bindings["/etc/ld.so.preload"].get("absent") is True, "Ambient loader preload is present")
    diagnostics = command("loader-diagnostics", ["/lib64/ld-linux-x86-64.so.2", "--list-diagnostics"], maximum=15,
                          env={"LANG": "C", "LC_ALL": "C"})
    need(diagnostics.stderr == b"", "Shell loader diagnostic command failed")
    profile = loader_diagnostics(diagnostics.stdout)
    cache = command("loader-cache", ["/usr/sbin/ldconfig.real", "-p"], maximum=15, env={"LANG": "C", "LC_ALL": "C"})
    need(cache.stderr == b"", "Shell static loader-cache command failed")
    libc = next(row for row in policy["packages"].values() if row["binaryPackage"].split(":")[0] == "libc6")
    cache_rows = loader_cache(cache.stdout, libc["version"], shell_names=names)
    for name in DEFAULT_LIBRARY_DIRS:
        bindings[name] = _loader_binding(Path(name), scope, directory_only=True)
    # Only ordinary global providers use the cache/default search policy.
    # Private RUNPATH providers keep their exact per-requester static graph;
    # they must not be relabelled as globally selected cache libraries.
    global_names = shell_global_names(policy["libraries"])
    tiers = {}
    for directory in DEFAULT_LIBRARY_DIRS:
        for tier in HWCAPS:
            path = directory + "/glibc-hwcaps/" + tier
            row = _loader_binding(Path(path), scope, directory_only=True, absent=True)
            bindings[path] = row
            tiers[path] = row.get("absent") is not True
    for name, path in shell_loader_candidates(sorted(global_names), cache_rows, tiers):
        row = _loader_binding(Path(path), scope, absent=True)
        loader_selected(row, policy["libraries"][name]["file"])
        bindings[path] = row
    snapshot = shell_data_snapshot(lambda path, **options: _loader_binding(path, scope, **options))
    data = shell_data_projection(snapshot)
    need(data == {key: policy["runtimeData"][key] for key in data}
         and data["suppliers"] == graph["runtimeData"]["suppliers"]
         and data["eglLibraries"] == graph["runtimeData"]["eglLibraries"]
         and all(set(paths) <= set(graph["modules"]) for paths in data["moduleSelections"].values()),
         "Root supplier DATA, current cache or module selector differs")
    need(type(policy["runtimeData"]["records"]) is list and len(policy["runtimeData"]["records"]) == len(SHELL_DATA_ROOTS),
         "Original current-VM shell DATA detail roster missing")
    data["records"] = []
    for index, (path, _) in enumerate(SHELL_DATA_ROOTS):
        leaf, raw = "shell-root-data-" + str(index) + ".json", canonical(snapshot["details"][path])
        need(policy["runtimeData"]["records"][index] == {"path": "shell-consumer-data-" + str(index) + ".json",
             "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
             "Root shell DATA identity differs from the original current-VM admission")
        _retain(leaf, raw)
        data["records"].append({"path": leaf, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    proof = {"scope": scope, "namespaces": namespaces, "bindings": bindings, "diagnostics": profile,
             "cacheRows": [row for row in cache_rows if row["soname"] in set(names) | PRIVATE_SONAMES],
             "entryObjects": names, "globalObjects": sorted(global_names), "hwcapsTiers": tiers,
             "moduleRoots": modules, "privateSearch": graph["privateSearch"], "runtimeData": data, "runtimeDataRechecked": False,
             "payloadAdmitted": False, "externalPrerequisites": policy["externalPrerequisites"]}
    _installed_loader_check(proof)
    _retain("loader-entry.json", canonical(proof))
    return proof


def shell_data_projection(snapshot):
    return {key: snapshot[key] for key in ("suppliers", "caches", "moduleSelections", "eglLibraries")}


def shell_module_proof(graph, roots, bindings):
    """Finite module membership DATA, including absence; not a loader action."""
    need(type(roots) is dict and set(roots) == set(graph["moduleRoots"]), "Original module-root roster differs")
    selected = set()
    for path, row in roots.items():
        need(type(row) is dict and set(row) == {"binding", "children"} and bindings.get(path) == row["binding"]
             and type(row["children"]) is list and row["children"] == sorted(set(row["children"]))
             and len(row["children"]) <= 256, "Original module-directory proof is incomplete")
        present = row["binding"].get("absent") is not True
        need(present or not row["children"], "Absent module directory has children")
        names = [name for name in row["children"] if path + "/" + name not in SHELL_MODULE_CACHES]
        need(all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.+\-]+\.so", name) for name in names)
             and graph["moduleRoots"][path] == {"present": present, "modules": names},
             "Module membership differs from the original compiled profile")
        selected.update(path + "/" + name for name in names)
    need(selected == set(graph["modules"]), "An original module was added or omitted")


def shell_private_selected(candidate, binding, provider):
    """Every per-requester alternative is checked, not just private providers."""
    need(type(candidate) is dict and set(candidate) == {"requester", "runpath", "name", "path", "selected"}
         and type(candidate["selected"]) is bool
         and candidate["selected"] == (candidate["path"] == provider["selectedPath"]),
         "Original private requester/candidate selection differs")
    if candidate["selected"]:
        need(binding.get("absent") is not True, "Selected private shell provider is absent")
        loader_selected(binding, provider)
    else:
        need(binding.get("absent") is True, "Private shell search can shadow an admitted dependency")


def _shell_data_check(proof):
    # One final rewalk, not a fresh copy of the same large DATA evidence.
    # Initial complete details remain retained; final hashes include actual
    # inode/link/cache bytes and directory membership as well as summaries.
    for path, row in proof["moduleRoots"].items():
        current = _loader_binding(Path(path), proof["scope"], directory_only=True, absent=True)
        need(current == row["binding"] and (row["children"] == [] if current.get("absent") else
             sorted(child.name for child in Path(path).iterdir()) == row["children"]), "Original module membership changed")
    snapshot = shell_data_snapshot(lambda path, **options: _loader_binding(path, proof["scope"], **options))
    need(shell_data_projection(snapshot) == shell_data_projection(proof["runtimeData"]),
         "Original shell supplier/cache/selector interval changed")
    for index, (path, _) in enumerate(SHELL_DATA_ROOTS):
        raw = canonical(snapshot["details"][path])
        need(proof["runtimeData"]["records"][index] == {"path": "shell-root-data-" + str(index) + ".json",
             "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "Original complete shell DATA binding changed")
    need(time.monotonic() < _END, "Original shell DATA interval closed late")
    proof["runtimeDataRechecked"] = True


def _installed_payload(value, proof, original):
    # NOT reached by either refusal. Their deliberately invalid M must reach
    # real Rust inspection, after only the libtest/platform OS-entry gate.
    profile = value["shell"] if "shell" in value else value["installed"]
    need(("shell" in value or profile["case"] == "positive") and _tree(PREFIX / M, M, published=True) == original,
         "Positive published A changed before payload admission")
    policy = (expand_shell_loader_policy(profile["loaderPolicy"], profile["compiler"])
              if "shell" in value else profile["loaderPolicy"])
    graph = policy["graph"]
    fixed = {"python/bin/python3": (None, "$ORIGIN/../lib"), "python/lib/libssl.so.3": ("libssl.so.3", "$ORIGIN"),
             "python/lib/libcrypto.so.3": ("libcrypto.so.3", "$ORIGIN")}
    need(set(graph["runtime"]) == set(fixed) and graph["runtimeObjects"] == sorted(PRIVATE_SONAMES | {"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"}),
         "Fixed complete A native graph differs")
    expected = {}
    for relative, (soname, runpath) in fixed.items():
        row, admitted = original[relative], graph["runtime"][relative]
        need(admitted["elf"]["soname"] == soname and admitted["elf"]["runpath"] == runpath
             and all(row[key] == admitted["file"][key] for key in ("size", "sha256")), "Private A ELF/RUNPATH original differs")
        path = PREFIX / M / relative
        binding = _loader_binding(path, proof["scope"])
        need(binding["identity"][:2] == row["identity"][:2], "Published A native inode differs")
        proof["bindings"][str(path)] = binding
        role = soname or "python"
        expected[role] = {"paths": [str(path)], "deviceMajor": os.major(row["identity"][0]),
                          "deviceMinor": os.minor(row["identity"][0]), "inode": row["identity"][1]}
    for relative in ("python/lib/glibc-hwcaps", *("python/lib/" + name for name in proof["entryObjects"] if name not in PRIVATE_SONAMES),
                     *(prefix + name for prefix in ("", "python/", "python/bin/") for name in ("pyvenv.cfg", "python3._pth", "pybuilddir.txt"))):
        path = PREFIX / M / relative
        binding = _loader_binding(path, proof["scope"], absent=True)
        need(binding.get("absent") is True, "Private A startup/hwcaps/OS override exists")
        proof["bindings"][str(path)] = binding
    for name in ("ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"):
        admitted = policy["libraries"][name]["file"]
        paths = [prefix + name for prefix in ("/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/")]
        if name == "ld-linux-x86-64.so.2":
            paths.append("/lib64/" + name)
        need(all(proof["bindings"][path].get("identity") == admitted["identity"] for path in paths), "Reported OS map alias is not independently bound")
        expected[name] = {"paths": sorted(paths), "deviceMajor": os.major(admitted["identity"][0]),
                          "deviceMinor": os.minor(admitted["identity"][0]), "inode": admitted["identity"][1]}
    proof["payloadAdmitted"] = True
    _installed_loader_check(proof)
    result = {"expectedMaps": expected, "privateObjects": sorted(PRIVATE_SONAMES),
              "shadowedCacheRows": [row for row in proof["cacheRows"] if row["soname"] in PRIVATE_SONAMES],
              "shadowedDefaultNames": [directory + "/" + tier + name for directory in DEFAULT_LIBRARY_DIRS
                   for tier in ("", *("glibc-hwcaps/" + tier + "/" for tier in HWCAPS)) for name in sorted(PRIVATE_SONAMES)],
              "selection": "For each private SONAME, the exact protected A RUNPATH object precedes cache/default/hwcaps OS rows. "
                           "All private hwcaps alternatives and OS-name overrides are absent in complete A. No private OS alternative is eligible.",
              "manifestSha256": M, "protocolSha256": Q}
    _retain("loader-runtime.json", canonical(result))
    return expected


def installed_result(stdout, stderr, case, code, expected):
    need(case in INSTALLED_TESTS and type(stdout) is bytes and 0 < len(stdout) <= LIMIT and stderr == b""
         and type(code) is int and code == (79 if case == "emfile" else 0), "Installed original carrier capture/exit differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    prefix = "test " + INSTALLED_TESTS[case] + " ... "
    count = {"positive": 2, "shutdown": 1, "overlap": 2}.get(case, 0)
    if case == "emfile":
        need(lines == ["running 1 test", prefix, EMFILE_MARKER], "Exact exit79 retained-Unknown marker/harness differs")
        return {"case": case, "exitCode": 79, "libtestPassed": False, "nativeCleanupProven": False,
                "originalCarrierComplete": True, "marker": EMFILE_MARKER, "maps": []}
    need(len(lines) == (count + 4 if count else 3) and lines[0] == "running 1 test"
         and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[-1]) is not None,
         "Installed exact libtest roster differs")
    observations = []
    if count:
        need(lines[1] == prefix and lines[-2] == "ok" and type(expected) is dict and len(expected) == 6,
             "Installed nocapture harness or admitted mapping set differs")
        for line in lines[2:-2]:
            need(line.startswith(CHILD_MARKER) and len(line) <= 8192 + len(CHILD_MARKER), "Installed child marker is not standalone/bounded")
            rows = decode(line[len(CHILD_MARKER):].encode("ascii"), 8192)
            need(type(rows) is list and len(rows) == 6 and all(type(row) is dict for row in rows)
                 and [row.get("role") for row in rows] == sorted(expected), "Installed child mapping roles differ")
            for row in rows:
                need(type(row) is dict and set(row) == {"role", "path", "deviceMajor", "deviceMinor", "inode"}
                     and row["path"] in expected[row["role"]]["paths"]
                     and all(type(row[key]) is int and row[key] == expected[row["role"]][key] for key in ("deviceMajor", "deviceMinor", "inode"))
                     and 0 <= row["deviceMajor"] < 1 << 32 and 0 <= row["deviceMinor"] < 1 << 32 and 0 < row["inode"] < 1 << 64,
                     "Actual retained-child mapping differs from independently admitted inode")
            observations.append(rows)
        need(case != "overlap" or observations[0] == observations[1], "Same original old child mappings changed across publication")
    else:
        need(lines[1] == prefix + "ok", "Installed refusal/deadline test emitted extra output")
    return {"case": case, "exitCode": 0, "libtestPassed": True, "maps": observations}


def _installed_environment(value):
    return {"LANG": "C", "LC_ALL": "C", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_SHA": value["sourceSha"], "GITHUB_RUN_ID": value["runId"], "GITHUB_RUN_ATTEMPT": value["attempt"]}


def _installed_argv(value, case):
    need(case in INSTALLED_TESTS, "Only fixed candidate test selectors are permitted")
    return _drop(value, [str(root_path(value) / "installed-tests"), INSTALLED_TESTS[case], "--exact", "--ignored", "--test-threads=1", "--nocapture"])


def _installed_case(value, case, proof, expected=None):
    _installed_loader_check(proof)
    result = command("installed-" + case, _installed_argv(value, case), maximum=60 if case == "positive" else 30,
                     codes=(79,) if case == "emfile" else (0,), env=_installed_environment(value))
    observed = installed_result(result.stdout, result.stderr, case, result.returncode, expected)
    _installed_loader_check(proof)
    return observed


def _refusal_fixture(value, proof):
    case = value["installed"]["case"]
    need(case in {"refuse-writable", "refuse-pth"}, "Only the two fixed never-published fixtures are permitted")
    proof["bindings"]["/var/lib"] = _loader_binding(Path("/var/lib"), proof["scope"], directory_only=True)
    original = _tree(INPUT / M, M, published=False)
    app = Path("/var/lib/mobile-release-kit")
    _absent(app)
    prefixes = (app, app / "versions", PREFIX)
    for path in prefixes:
        path.mkdir(mode=0o700)
    directories = sorted((name for name, row in original.items() if "sha256" not in row), key=lambda name: (len(Path(name).parts), name))
    for name in directories:
        (PREFIX / M / name).mkdir(mode=0o700)
    for name, row in original.items():
        if "sha256" in row:
            path = INPUT / M / name
            copy_pinned(path, PREFIX / M / name, {"path": str(path), "size": row["size"], "sha256": row["sha256"]},
                        0o555 if name == "python/bin/python3" else 0o444)
    for name in reversed(directories):
        os.chmod(PREFIX / M / name, 0o555)
    for path in reversed(prefixes):
        os.chmod(path, 0o755)
    fresh = _tree(PREFIX / M, M, published=True)
    need(set(fresh) == set(original) and all(fresh[name]["identity"][:2] != row["identity"][:2] for name, row in original.items()),
         "Never-published fixture adopted a package input inode")
    if case == "refuse-writable":
        # This application ancestor is newly created HERE and has never been
        # published. No accepted/published M is modified, repaired or retried.
        os.chmod(app, 0o777)
    else:
        path = PREFIX / M / "python/bin/python3._pth"
        _D.write(path, b"# inert unlisted startup DATA; must never be executed\n", 0o444)
        row = record(path, 128)
        fresh["python/bin/python3._pth"] = {key: row[key] for key in ("size", "sha256")}
        fresh["python/bin/python3._pth"]["identity"] = list(identity(path.lstat()))
        fresh["python/bin"]["identity"] = list(identity(path.parent.lstat()))
    fixture = {"case": case, "neverPublished": True, "manifestSha256": M,
               "prefixes": {str(path): list(identity(path.lstat())) for path in (Path("/var"), Path("/var/lib"), *prefixes)}, "tree": fresh}
    _refusal_fixture_check(fixture)
    _retain("refusal-fixture-before.json", canonical(fixture))
    return fixture


def _refusal_fixture_check(fixture):
    # Identity/byte readback of deliberately invalid DATA, NOT runtime admission.
    # In particular, this does not call positive-only protected _tree on the
    # writable fixture and accidentally short-circuit the real Rust refusal.
    for name, expected in fixture["prefixes"].items():
        path = Path(name)
        need(list(identity(path.lstat())) == expected, "Never-published fixture prefix changed")
        _xattrs(path, True)
    rows = fixture["tree"]
    need(0 < len(rows) <= 8192, "Fixed refusal fixture membership bound")
    for name, row in rows.items():
        path = PREFIX / M / name
        item = path.lstat()
        need(list(identity(item)) == row["identity"], "Never-published fixture identity changed")
        if "sha256" in row:
            observed = record(path, row["size"])
            need(all(observed[key] == row[key] for key in ("size", "sha256")), "Never-published fixture bytes changed")
        else:
            prefix = name + "/" if name else ""
            children = {other[len(prefix):] for other in rows if other.startswith(prefix) and other != name and "/" not in other[len(prefix):]}
            need(stat.S_ISDIR(item.st_mode) and {child.name for child in path.iterdir()} == children,
                 "Never-published fixture membership changed")
        _xattrs(path, "sha256" not in row)
        need(list(identity(path.lstat())) == row["identity"], "Never-published fixture readback drift")
    for manifest in (M, F1):
        _absent(PREFIX / (".publish-" + manifest))
    _absent(PREFIX / F1)


def overlap_endpoint(raw, started, service_endpoint):
    need(type(raw) is bytes and 0 < len(raw) <= 32 and re.fullmatch(rb"[1-9][0-9]{0,19}\n", raw) is not None
         and int(raw[:-1]) < 1 << 64 and all(type(value) in {float, int} and math.isfinite(value) for value in (started, service_endpoint)),
         "Original old-child endpoint DATA is invalid")
    # Round toward the past, never outward; this is only a conservative cap on
    # scheduling. Neither the DATA nor a late return renews the Rust 10s clock.
    decoded = math.nextafter(int(raw[:-1]) / 1_000_000_000, -math.inf)
    return min(decoded, started + 10, service_endpoint)


def _overlap_controls(value):
    control = _ROOT / "control"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o711)
    _xattrs(control, True)
    ready, release = control / "passive-ready", control / "passive-release"
    fd = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(fd, 0, value["runnerGid"])
        os.fchmod(fd, 0o620)
        os.fsync(fd)
    finally:
        os.close(fd)
    item = ready.lstat()
    need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and item.st_uid == 0 and item.st_gid == value["runnerGid"]
         and stat.S_IMODE(item.st_mode) == 0o620 and item.st_size == 0, "Fresh fixed ready DATA differs")
    _xattrs(ready, False)
    _D.write(release, b"pending\n", 0o444)
    return {"readyIdentity": list(identity(item)[:6]), "release": protected_record(release, 32),
            "controlIdentity": list(identity(control.lstat())[:6])}


def _overlap_worker(holder, argv, env, seconds):
    # This exact original thread owns its own cancellation installation and
    # restoration. It never calls command(), _retain(), or global bookkeeping.
    guard, errors = None, []
    try:
        guard = _OWNER.DefaultCancellation(_OWNER.ProcessCleanupError, "overlap worker cancellation restoration unproven")
        guard.install()
        guard.activate()
        holder["result"] = _OWNER.run_owned(argv, environ=env, cwd=Path("/"), timeout=seconds, capture=True, text=False,
                                           output_limit=LIMIT, cancellation=guard, execution_scope=None, journal_binding=None, cleanup=False)
    except BaseException as error:
        errors.append(error)
    finally:
        if guard is not None:
            for operation in (guard.restore, guard.check):
                try:
                    operation()
                except BaseException as error:
                    errors.append(error)
            try:
                holder["guardState"] = guard.handler_state
            except BaseException as error:
                errors.append(error)
        holder["errors"] = errors


def _overlap_ready_bytes(controls):
    # This one ready file is intentionally mutable scheduling DATA. Bind the
    # same original inode/authority and consume its original descriptor once,
    # but permit its size/time to change during the one legitimate Rust write.
    ready = _ROOT / "control/passive-ready"
    need(list(identity(ready.lstat())[:6]) == controls["readyIdentity"], "Original scheduling ready inode changed")
    fd = os.open(ready, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(list(identity(before)[:6]) == controls["readyIdentity"] and 0 <= before.st_size <= 32, "Original ready descriptor differs")
        raw = os.read(fd, 33)
        after = os.fstat(fd)
        need(len(raw) <= 32 and list(identity(after)[:6]) == controls["readyIdentity"] and 0 <= after.st_size <= 32,
             "Original ready descriptor bound/identity differs")
    finally:
        os.close(fd)
    need(list(identity(ready.lstat())[:6]) == controls["readyIdentity"], "Original scheduling ready inode changed after close")
    return raw


def _overlap_ready(worker, controls, started, service_endpoint):
    cap = min(started + 10, service_endpoint)
    while time.monotonic() < cap:
        raw = _overlap_ready_bytes(controls)
        if raw.endswith(b"\n"):
            return overlap_endpoint(raw, started, service_endpoint)
        need(not raw or re.fullmatch(rb"[0-9]{1,20}", raw) is not None, "Scheduling ready DATA is invalid")
        need(worker.is_alive(), "Original overlap worker returned before readiness")
        time.sleep(0.005)
    raise Refused("Original old-child ready endpoint expired")


def _overlap_release(controls, endpoint):
    control = _ROOT / "control"
    release, fresh = control / "passive-release", control / "passive-release-next"
    need(time.monotonic() < endpoint and list(identity(control.lstat())[:6]) == controls["controlIdentity"]
         and protected_record(release, 32) == controls["release"] and read(release, 32) == b"pending\n",
         "Original release DATA changed or configure window expired")
    _D.write(fresh, b"release\n", 0o444)
    row = protected_record(fresh, 32)
    need(row["identity"][:2] != controls["release"]["identity"][:2] and time.monotonic() < endpoint,
         "Fresh release inode aliases original or completed late")
    os.replace(fresh, release)
    observed = protected_record(release, 32)
    need(all(observed[key] == row[key] for key in ("size", "sha256")) and observed["identity"][:8] == row["identity"][:8]
         and time.monotonic() < endpoint,
         "Atomic original release readback differs or is late")


def _installed_overlap(value, policy, proof, expected):
    global _FAILED, _PHASE
    # Admission checks precede the old-child window. The package wrapper's
    # final policy/marker checks still share its original configure endpoint.
    need(not _FAILED and dpkg_policy() == policy, "Dpkg policy changed before fixed overlap")
    _installed_loader_check(proof)
    controls = _overlap_controls(value)
    argv, env = _installed_argv(value, "overlap"), _installed_environment(value)
    service_endpoint = _END - CLIENT_RESERVATION - 1  # Conservative original service work limit; never renewed.
    seconds = min(30, math.floor(service_endpoint - time.monotonic()))
    need(seconds > 0, "No original carrier work budget remains for overlap")
    holder = {}
    worker = threading.Thread(target=_overlap_worker, args=(holder, argv, env, seconds), name="mrk-installed-original-overlap", daemon=False)
    failure, join_error, capture_error, joined, released = None, None, None, False, False
    configure_trace, endpoint, started = None, None, time.monotonic()
    _PHASE = "installed-overlap"
    try:
        worker.start()
        endpoint = _overlap_ready(worker, controls, started, service_endpoint)
        result = package_command("upgrade-configure", ["/usr/bin/dpkg", "--debug=2", "--no-triggers", "--configure", PACKAGE],
                                 policy=policy, endpoint=endpoint)
        configure_trace = script_trace(result.stderr, [("postinst", ("configure", VERSIONS["P0"][1]))])
        need(result.stdout.splitlines(keepends=True).count(PUBLISHED) == 1 and b"Runtime publication refused:" not in result.stderr
             and time.monotonic() < endpoint, "Timely real F1 configure publication not observed")
        _overlap_release(controls, endpoint)
        released = True
    except BaseException as error:
        failure = error
    finally:
        # Even failed start/readiness/configure/release must attempt the SAME
        # original join. No late/failed worker is orphaned into a success path.
        _FAILED = True
        try:
            worker.join(max(0.0, _END - time.monotonic()))
            joined = not worker.is_alive()
        except BaseException as error:
            join_error = error
        if joined and "result" in holder:
            try:
                _command_capture("installed-overlap", argv, holder["result"], seconds)
            except BaseException as error:
                capture_error = error
    _PHASE = "installed-overlap"
    _retain("installed-overlap-join.json", canonical({"joined": joined, "releaseWritten": released,
        "workerGuardState": holder.get("guardState") if joined else None, "workerErrorCount": len(holder.get("errors", [])) if joined else None,
        "startMonotonic": started, "configureEndpoint": endpoint, "originalServiceEndpoint": service_endpoint,
        "originalDeadline": _END, "carrierTimeoutSeconds": seconds, "readyIdentity": controls["readyIdentity"]}))
    for error in (failure, join_error, capture_error, *(holder.get("errors", []) if joined else [])):
        if error is not None:
            raise error
    need(joined and released and holder.get("guardState") == "RESTORED" and "result" in holder and time.monotonic() < _END,
         "Original overlap worker/guard/result was not completely joined")
    result = holder["result"]
    observed = installed_result(result.stdout, result.stderr, "overlap", result.returncode, expected)
    _installed_loader_check(proof)
    _FAILED = False
    return observed, configure_trace


def shell_environment(value, case):
    need(case in SHELL_CASES, "Unknown fixed shell case")
    home = root_path(value) / ("gui-" + case)
    return {"PATH": HOST_PATH, "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "HOME": str(home / "home"), "TMPDIR": str(home / "tmp"), "XDG_RUNTIME_DIR": str(home / "runtime"),
            "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"), "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_DIRS": str(home / "empty-config"), "XDG_DATA_DIRS": "/usr/share",
            "GDK_BACKEND": "x11", "GSETTINGS_BACKEND": "memory", "GIO_USE_VFS": "local", "GTK_THEME": "Adwaita",
            "DISPLAY": ":99", "XAUTHORITY": str(home / "Xauthority"),
            "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=" + str(home / "runtime/absent-system-bus"),
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_SHA": value["sourceSha"],
            **({"MRK_DESKTOP_HOSTED_CHECKS": "installed-shell-connection-v1"} if case != "normal" else {})}


def shell_argv(value, case):
    environment = shell_environment(value, case)
    command = [str(root_path(value) / ("shell-normal" if case == "normal" else "shell-observer"))]
    if case != "normal":
        command.append(case)
    return _drop(value, ["/usr/bin/dbus-run-session", "--dbus-daemon=/usr/bin/dbus-daemon",
        "--config-file=" + str(root_path(value) / ("shell-" + case + "-bus.conf")), "--",
        "/usr/bin/xvfb-run", "--server-num=99", "--auth-file=" + environment["XAUTHORITY"],
        "--error-file=/dev/stderr", "--server-args=-screen 0 1280x1024x24 -noreset", *command])


def _shell_project_inventory(value, *, saved=False):
    """Fixed fixture only, before launch or AFTER original exit and finality.

    This never repairs/removes a pending transaction or scans an unexpected
    subtree. Ordinary GUI caches are outside the project. Failed/Unknown work
    cannot reach the saved observation through the original shell-result gate.
    """
    need(_ROOT == root_path(value) and type(saved) is bool, "Positive fixture differs from the original service root or phase")
    root = _ROOT / "positive-project"
    directory(root.parent, protected=True)
    owner = (value["runnerUid"], value["runnerGid"])
    directories = [(".", [".gitignore", "app", "release"] if saved else ["app"], 0o700, owner),
                   ("app", ["build.gradle.kts"], 0o555, (0, 0))]
    if saved:
        directories.append(("release", ["mobile-release.json"], 0o755, owner))
    rows, original_directories = [], []
    for relative, expected, mode, owners in directories:
        path = root if relative == "." else root / relative
        directory(path)
        before = path.lstat()
        need(stat.S_IMODE(before.st_mode) == mode and (before.st_uid, before.st_gid) == owners,
             "Positive fixture directory ownership or mode differs")
        children = []
        with os.scandir(path) as entries:
            for entry in entries:
                need(len(children) < len(expected) and entry.name in expected, "Unexpected positive fixture entry")
                children.append(entry.name)
        need(sorted(children) == expected and identity(path.lstat()) == identity(before), "Positive fixture directory changed")
        rows.append({"path": relative, "kind": "directory", "identity": list(identity(before)), "children": expected})
        original_directories.append((path, identity(before)))
    files = [("app/build.gradle.kts", SHELL_PROJECT_SOURCE, 0o444, (0, 0))]
    if saved:
        files.extend((("release/mobile-release.json", SHELL_PROJECT_CONFIG, 0o600, owner),
                      (".gitignore", SHELL_PROJECT_IGNORE, 0o600, owner)))
    for relative, expected, mode, owners in files:
        path = root / relative
        before = path.lstat()
        need(stat.S_IMODE(before.st_mode) == mode and (before.st_uid, before.st_gid) == owners,
             "Positive fixture file ownership or mode differs")
        observed = record(path, len(expected))
        need(observed["size"] == len(expected) and observed["sha256"] == hashlib.sha256(expected).hexdigest()
             and identity(path.lstat()) == identity(before), "Positive fixture file bytes or identity differ")
        rows.append({**observed, "path": relative, "kind": "file", "identity": list(identity(before))})
    absent = [] if saved else [".gitignore", "release"]
    for relative in absent:
        _absent(root / relative)
    need(all(identity(path.lstat()) == original for path, original in original_directories),
         "Positive fixture parent changed during its bounded inventory")
    return {"schemaVersion": 2, "fixture": "android-config-save-v1", "root": str(root), "saved": saved,
            "entries": rows, "absent": absent}


def shell_project_fixture(value, before_raw, after_raw):
    """Closed DATA correspondence, never permission to inspect possible-live work."""
    before, after = decode(before_raw, 8192), decode(after_raw, 8192)
    owner = (value["runnerUid"], value["runnerGid"])
    inventories = []
    for document, raw, saved in ((before, before_raw, False), (after, after_raw, True)):
        need(type(document) is dict and set(document) == {"schemaVersion", "fixture", "root", "saved", "entries", "absent"}
             and canonical(document) == raw and type(document["schemaVersion"]) is int and document["schemaVersion"] == 2
             and document["fixture"] == "android-config-save-v1" and document["saved"] is saved
             and document["root"] == str(root_path(value) / "positive-project")
             and document["absent"] == ([] if saved else [".gitignore", "release"]), "Positive fixture inventory is incomplete or out of phase")
        roster = [(".", stat.S_IFDIR | 0o700, owner, [".gitignore", "app", "release"] if saved else ["app"]),
                  ("app", stat.S_IFDIR | 0o555, (0, 0), ["build.gradle.kts"])]
        if saved:
            roster.append(("release", stat.S_IFDIR | 0o755, owner, ["mobile-release.json"]))
        roster.append(("app/build.gradle.kts", stat.S_IFREG | 0o444, (0, 0), SHELL_PROJECT_SOURCE))
        if saved:
            roster.extend((("release/mobile-release.json", stat.S_IFREG | 0o600, owner, SHELL_PROJECT_CONFIG),
                           (".gitignore", stat.S_IFREG | 0o600, owner, SHELL_PROJECT_IGNORE)))
        rows = document["entries"]
        need(type(rows) is list and len(rows) == len(roster), "Positive fixture node roster differs")
        observed = {}
        for row, (relative, mode, owners, expected) in zip(rows, roster):
            is_directory = stat.S_ISDIR(mode)
            wanted = {"path", "kind", "identity", "children"} if is_directory else {"path", "kind", "identity", "size", "sha256"}
            need(type(row) is dict and set(row) == wanted and row["path"] == relative
                 and row["kind"] == ("directory" if is_directory else "file"), "Positive fixture node kind/path differs")
            original = row["identity"]
            need(type(original) is list and len(original) == 9 and all(type(number) is int and 0 <= number < 1 << 64 for number in original)
                 and original[0] > 0 and original[1] > 0 and original[2] == mode and tuple(original[3:5]) == owners
                 and 0 < original[5] <= 16 and original[6] <= 1 << 20, "Positive fixture original identity differs")
            if is_directory:
                need(row["children"] == expected, "Positive fixture has an unexpected child or pending transaction")
            else:
                need(original[5] == 1 and original[6] == len(expected) and type(row["size"]) is int
                     and row["size"] == len(expected) and row["sha256"] == hashlib.sha256(expected).hexdigest(),
                     "Positive fixture source or saved output does not match exact expected DATA")
            observed[relative] = row
        need(all(row["identity"][0] == observed["."]["identity"][0] for row in rows)
             and len({tuple(row["identity"][:2]) for row in rows}) == len(rows), "Positive fixture node aliases or cross-device entries differ")
        inventories.append(observed)
    first, last = inventories
    # The config transaction necessarily changes root timestamps/size/link count,
    # not its dev/inode/type/mode/ownership. The unrelated hint is exact in full.
    need(first["."]["identity"][:5] == last["."]["identity"][:5]
         and all(first[name] == last[name] for name in ("app", "app/build.gradle.kts")),
         "Positive fixture root was replaced or its unrelated hint changed")
    return {"fixture": "android-config-save-v1", "rootRetained": True, "hintUnchanged": True,
            "savedOutputsMatched": True, "noUnexpectedEntries": True, "noPendingState": True,
            "entryCount": 6, "sourceBytes": len(SHELL_PROJECT_SOURCE), "releaseMode": 0o755,
            "config": {"size": len(SHELL_PROJECT_CONFIG), "sha256": hashlib.sha256(SHELL_PROJECT_CONFIG).hexdigest(), "mode": 0o600},
            "gitignore": {"size": len(SHELL_PROJECT_IGNORE), "sha256": hashlib.sha256(SHELL_PROJECT_IGNORE).hexdigest(), "mode": 0o600},
            "before": {"size": len(before_raw), "sha256": hashlib.sha256(before_raw).hexdigest()},
            "after": {"size": len(after_raw), "sha256": hashlib.sha256(after_raw).hexdigest()}}


def shell_project_receipt(raw):
    receipt = decode(raw, 2048)
    # Canonical comparison is deliberately type-sensitive: Python's True == 1
    # cannot turn missing boolean/original settlement DATA into a success.
    need(canonical(receipt) == canonical(SHELL_PROJECT_RECEIPT), "Positive project/draft receipt is missing, malformed or premature")
    return receipt


def _shell_prepare(value, case):
    base, environment = _ROOT / ("gui-" + case), shell_environment(value, case)
    for path in (base, *(base / name for name in ("home", "tmp", "runtime", "config", "cache", "data", "empty-config"))):
        path.mkdir(mode=0o700)
        os.chown(path, value["runnerUid"], value["runnerGid"])
    auth = Path(environment["XAUTHORITY"])
    _D.write(auth, b"", 0o600)
    os.chown(auth, value["runnerUid"], value["runnerGid"])
    bus = base / "runtime/session-bus"
    need(len(str(bus).encode("ascii")) < 108, "Private D-Bus socket exceeds native path bound")
    # Deliberately no include, service directory/helper, systemd activation,
    # pidfile, fork or syslog. The config's protected parent is not app-writable.
    config = ("<busconfig><type>session</type><listen>unix:path=" + str(bus)
        + "</listen><auth>EXTERNAL</auth><policy context=\"default\">"
        + "<allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/>"
        + "</policy></busconfig>\n").encode("ascii")
    _D.write(_ROOT / ("shell-" + case + "-bus.conf"), config, 0o444)
    for path in (Path("/tmp/.X99-lock"), Path("/tmp/.X11-unix/X99"), bus, base / "runtime/absent-system-bus"):
        _absent(path)  # Conflict is failure, never permission to repair/remove.
    if case == "positive":
        project = _ROOT / "positive-project"
        project.mkdir(mode=0o700)
        (project / "app").mkdir(mode=0o700)
        _D.write(project / "app/build.gradle.kts", SHELL_PROJECT_SOURCE, 0o444)
        # Only this original fixture root is app-writable. The inert source and
        # its directory remain root-owned/read-only; Save must not change them.
        os.chmod(project / "app", 0o555)
        os.chown(project, value["runnerUid"], value["runnerGid"])
        _retain("shell-positive-project-before.json", canonical(_shell_project_inventory(value)))
    return environment


def shell_result(stdout, stderr, case, code, expected):
    """Original bounded captures, not wrapper zero or an observation delay."""
    need(case in SHELL_CASES and type(code) is int and code == 0
         and type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= LIMIT,
         "Original shell capture failed/incomplete")
    lines = [line for line in stdout.splitlines() + stderr.splitlines() if line.startswith(b"MRK_")]
    marker = b"MRK_INSTALLED_SHELL_OBSERVATION=" + case.encode("ascii") + b"-verified"
    contracts = b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified"
    if case == "positive":
        output = [line for line in stdout.splitlines() if line.startswith(b"MRK_")]
        diagnostics = [line for line in stderr.splitlines() if line.startswith(b"MRK_")]
        need(len(output) == 3 and output[0] == contracts and output[1].startswith(SHELL_PROJECT_MARKER)
             and output[2] == marker and diagnostics == [b"MRK_DESKTOP_CAPABILITIES=available", b"MRK_DESKTOP_CATALOGUE=returned"],
             "Positive original bootstrap/contract/receipt/completion order differs")
        receipt = shell_project_receipt(output[1][len(SHELL_PROJECT_MARKER):])
        return {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                "maps": [], "projectDraft": receipt}
    if case == "normal":
        wanted = [b"MRK_DESKTOP_CAPABILITIES=available", b"MRK_DESKTOP_CATALOGUE=returned"]
        need(sorted(lines) == sorted(wanted), "Actual normal capabilities/catalogue or observer completion missing")
        return {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": False, "maps": []}
    # The outstanding case cannot advertise success. Its IPC caller may retire
    # before the fixed unavailable diagnostic; only the held original's later
    # genuine settlement/map report plus completed GUI observation is required.
    maps = [line for line in lines if line.startswith(CHILD_MARKER.encode("ascii"))]
    remaining = [line for line in lines if line not in maps]
    need(sorted(remaining) in (sorted([contracts, marker]), sorted([contracts, marker, b"MRK_DESKTOP_CAPABILITIES=unavailable"]))
         and len(maps) == 1 and len(maps[0]) <= 8192 + len(CHILD_MARKER)
         and type(expected) is dict and len(expected) == 6, "Outstanding original/GUI completion differs")
    rows = decode(maps[0][len(CHILD_MARKER):], 8192)
    need(type(rows) is list and len(rows) == 6 and all(type(row) is dict for row in rows)
         and [row.get("role") for row in rows] == sorted(expected), "Outstanding original child roles differ")
    for row in rows:
        need(set(row) == {"role", "path", "deviceMajor", "deviceMinor", "inode"}
             and row["path"] in expected[row["role"]]["paths"]
             and all(type(row[key]) is int and row[key] == expected[row["role"]][key]
                     for key in ("deviceMajor", "deviceMinor", "inode")), "Outstanding original child mapping differs")
    return {"case": case, "exitCode": 0, "bootstrapReturned": False, "domAndGtkObserved": True, "maps": [rows]}


def shell_window_ids(raw):
    need(type(raw) is bytes and len(raw) <= 128, "Private display window response exceeds bound")
    rows = raw.splitlines()
    need(len(rows) <= 2 and all(re.fullmatch(rb"[1-9][0-9]{0,9}", row) is not None for row in rows),
         "Private display returned malformed/unbounded window IDs")
    values = [int(row) for row in rows]
    need(len(set(values)) == len(values) and all(value < 1 << 32 for value in values), "Duplicate/oversized XID")
    return values


def _shell_window_pid(value, pid):
    # Selection DATA only. Never use this numeric ID to wait, signal, clean,
    # claim process custody or reconstruct a lost original worker.
    need(type(pid) is int and 0 < pid < 1 << 31, "Private shell window PID differs")
    proc = Path("/proc") / str(pid)
    status = dict(line.split(":", 1) for line in _kernel(proc / "status").splitlines() if ":" in line)
    need(all(status[key].split() == [str(value[id_key])] * 4 for key, id_key in (("Uid", "runnerUid"), ("Gid", "runnerGid")))
         and status["NoNewPrivs"].strip() == "1"
         and _kernel(proc / "cgroup") == "0::/system.slice/" + _ROOT.name + ".service\n"
         and os.readlink(proc / "exe") == str(_ROOT / "shell-normal"), "Window does not report this task's original normal executable")


def _shell_normal_failure(holder, argv, *, joined, stage, inputs, commands, error,
                          join_error=None, capture_error=None):
    """Best-effort diagnosis from original memory, never finality or read authority.

    A failed service cannot export its private files. Its existing stderr can
    still explain a failed synthetic, no-project normal launch. In particular,
    an unjoined holder is never inspected and no diagnostic error replaces the
    operation's original failure.
    """
    try:
        safe_messages = {
            "Normal window controller endpoint expired",
            "Normal original returned before controller command",
            "Normal window controller command bound exhausted",
            "No original controller command budget remains",
            "Original normal shell returned before Quit",
            "Original private shell window did not become visible in the finite observation",
            "Original normal shell/controller did not settle",
            "Original shell capture failed/incomplete",
            "Actual normal capabilities/catalogue or observer completion missing",
            "owned command failed, timed out, or produced incomplete output",
            "owned command cleanup could not be confirmed",
            "owned command executable could not be started",
            "owned command produced incomplete output",
            "owned command output exceeds its bound",
        }

        def error_data(original):
            name = type(original).__name__
            row = {"type": name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "other"}
            # Never call exception formatting: it may contain argv, environment
            # or other context, or itself raise. Only fixed public messages pass.
            args = original.args
            if type(args) is tuple and len(args) == 1 and type(args[0]) is str and args[0] in safe_messages:
                row["message"] = args[0]
            return row

        errors = [item for item in (error, join_error, capture_error) if item is not None]
        result = None
        data = {"schemaVersion": 1, "scope": "original-normal-failure-diagnostic-only",
                "qualified": False, "cleanupEstablished": False, "joined": joined,
                "stage": stage, "inputs": inputs, "controllerCommands": len(commands),
                "lastControllerCommand": commands[-1]["phase"] if commands else None,
                "workerGuardState": None, "workerErrorCount": None, "capture": None}
        if joined:
            state = holder.get("guardState")
            data["workerGuardState"] = state if state in ("NEW", "INSTALLED", "ACTIVE", "RESTORED", "UNKNOWN") else "other"
            worker_errors = holder.get("errors", [])
            if type(worker_errors) is list:
                data["workerErrorCount"] = len(worker_errors)
                errors.extend(worker_errors[:4])
            result = holder.get("result")
        data["errors"] = [error_data(item) for item in errors[:4]]
        data["errorsTruncated"] = len(errors) > 4
        if (type(result) is subprocess.CompletedProcess and result.args == argv
                and type(result.returncode) is int and type(result.stdout) is bytes
                and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= LIMIT):
            captured = {"exitCode": result.returncode}
            for name, raw, head, tail in (("stdout", result.stdout, 256, 256),
                                          ("stderr", result.stderr, 1024, 2048)):
                prefix, suffix = raw[:head], raw[max(head, len(raw) - tail):]
                captured[name] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                  "head": prefix.decode("utf-8", "replace"), "tail": suffix.decode("utf-8", "replace"),
                                  "truncated": len(prefix) + len(suffix) < len(raw)}
            data["capture"] = captured
        marker = b"MRK_INSTALLED_SHELL_FAILURE="
        raw = marker + canonical(data)
        if len(raw) > 32768:
            # JSON escaping counts toward the complete output cap too.
            for row in (data["capture"] or {}).values():
                if type(row) is dict:
                    row.pop("head", None)
                    row.pop("tail", None)
                    row["truncated"] = row["size"] != 0
            raw = marker + canonical(data)
        if len(raw) <= 32768:
            sys.stderr.write(raw.decode("ascii"))
            sys.stderr.flush()
    except BaseException:
        pass  # A diagnostic is not authority to replace the original error.


def _shell_normal(value, environment, expected):
    global _FAILED, _PHASE
    need(not _FAILED, "Prior shell/root failure")
    _FAILED, _PHASE = True, "shell-normal"
    started = time.monotonic()
    end = min(started + 45, _END - CLIENT_RESERVATION - 1)
    seconds = min(60, math.floor(_END - CLIENT_RESERVATION - started))
    need(seconds > 45 and end > started + 35, "Insufficient original normal-window lifetime remains")
    argv, holder, commands = shell_argv(value, "normal"), {}, []
    worker = threading.Thread(target=_overlap_worker, args=(holder, argv, environment, seconds),
                              name="mrk-installed-shell-normal", daemon=False)
    failure, join_error, capture_error, joined, inputs = None, None, None, False, 0
    stage, diagnostic_attempted = "start", False

    def diagnose(error):
        nonlocal diagnostic_attempted
        if not diagnostic_attempted:
            diagnostic_attempted = True
            _shell_normal_failure(holder, argv, joined=joined, stage=stage, inputs=inputs, commands=commands,
                                  error=error, join_error=join_error, capture_error=capture_error)

    def xdo(label, args, *, codes=(0,)):
        need(time.monotonic() < end, "Normal window controller endpoint expired")
        need(worker.is_alive(), "Normal original returned before controller command")
        need(len(commands) < 96, "Normal window controller command bound exhausted")
        timeout = min(5, math.floor(end - time.monotonic()))
        need(timeout > 0, "No original controller command budget remains")
        command_argv = _drop(value, ["/usr/bin/xdotool", *args])
        result = _OWNER.run_owned(command_argv, environ=environment, cwd=Path("/"), timeout=timeout,
            capture=True, text=False, output_limit=4096, execution_scope=None, journal_binding=None, cleanup=False)
        need(type(result) is subprocess.CompletedProcess and result.args == command_argv and type(result.returncode) is int
             and type(result.stdout) is bytes and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= 4096,
             "Original private-display controller result incomplete")
        commands.append({"phase": label, "argv": command_argv, "exitCode": result.returncode,
                         "stdout": result.stdout.decode("ascii"), "stderr": result.stderr.decode("ascii"), "timeoutSeconds": timeout})
        need(result.returncode in codes and time.monotonic() < end, "Original private-display command failed/late")
        return result

    def search(title, pid=None):
        args = ["search", "--onlyvisible", "--all", "--maxdepth", "1", "--limit", "2"]
        if pid is not None:
            args += ["--pid", str(pid)]
        return xdo("search", [*args, "--name", title], codes=(0, 1))

    def wait_window(title, pid=None):
        for _ in range(64):
            result = search(title, pid)
            if result.returncode == 0:
                need(result.stderr == b"", "Successful private window query emitted a diagnostic")
                ids = shell_window_ids(result.stdout)
                need(len(ids) == 1, "Private normal window is missing/ambiguous")
                return ids[0]
            need(result.stdout == b"", "Unsuccessful private window query returned an ID")
            time.sleep(min(0.1, max(0.0, end - time.monotonic())))
        raise Refused("Original private shell window did not become visible in the finite observation")

    def input_key(window, title, pid, key):
        nonlocal inputs
        _shell_window_pid(value, pid)
        result = search(title, pid)
        need(result.returncode == 0 and result.stderr == b"" and shell_window_ids(result.stdout) == [window],
             "Same private XID/title/PID no longer corresponds before input")
        focused = xdo("focus", ["windowfocus", "--sync", str(window)])
        need(focused.stdout == focused.stderr == b"", "Private focus command emitted a diagnostic")
        observed = xdo("focus-readback", ["getwindowfocus", "-f"])
        need(observed.stderr == b"" and shell_window_ids(observed.stdout) == [window], "Exact private focus was not read back")
        _shell_window_pid(value, pid)
        result = xdo("key", ["key", "--clearmodifiers", key])
        need(result.stdout == result.stderr == b"", "Private XTEST key command emitted a diagnostic")
        inputs += 1

    try:
        worker.start()
        stage = "initial-window"
        title = "^Mobile Release Kit$"
        window = wait_window(title)
        reported = xdo("window-pid", ["getwindowpid", str(window)])
        need(reported.stderr == b"" and re.fullmatch(rb"[1-9][0-9]{0,9}\n", reported.stdout) is not None,
             "Normal private window PID was not returned")
        pid = int(reported.stdout)
        _shell_window_pid(value, pid)
        # Scheduling margin only, never a success receipt. Both genuine
        # original core returns are still required from the bounded capture.
        stage = "bootstrap-margin"
        margin = min(time.monotonic() + 22, end - 8)
        while time.monotonic() < margin:
            need(worker.is_alive(), "Original normal shell returned before Quit")
            time.sleep(min(0.25, max(0.0, margin - time.monotonic())))
        stage = "quit-input"
        input_key(window, title, pid, "ctrl+q")
        title = r"^Quit and discard unsaved drafts\?$"
        stage = "quit-dialog"
        dialog = wait_window(title, pid)
        need(dialog != window, "GTK Quit did not create its own real dialog")
        stage = "quit-confirmation"
        input_key(dialog, title, pid, "alt+o")
    except BaseException as error:
        failure = error
    finally:
        try:
            # A failed start return does not prove that no thread was created.
            # Attempt the same original join even then; an unstarted join error
            # remains a failure, never a guessed no-worker receipt.
            worker.join(max(0.0, min(_END, started + seconds + 20) - time.monotonic()))
            joined = not worker.is_alive()
        except BaseException as error:
            join_error = error
        if joined and "result" in holder:
            try:
                _command_capture("shell-normal", argv, holder["result"], seconds)
            except BaseException as error:
                capture_error = error
    errors = (failure, join_error, capture_error, *(holder.get("errors", []) if joined else []))
    primary = next((error for error in errors if error is not None), None)
    if primary is not None:
        diagnose(primary)
    else:
        stage = "final-verification"
    try:
        _retain("shell-normal-control.json", canonical({"joined": joined, "inputs": inputs, "commands": commands,
            "workerGuardState": holder.get("guardState") if joined else None,
            "workerErrorCount": len(holder.get("errors", [])) if joined else None,
            "startMonotonic": started, "controllerEndpoint": end, "carrierTimeoutSeconds": seconds,
            "originalDeadline": _END, "errorType": type(failure).__name__ if failure is not None else None}))
        for error in errors:
            if error is not None:
                raise error
        need(joined and inputs == 2 and holder.get("guardState") == "RESTORED" and "result" in holder
             and time.monotonic() < _END, "Original normal shell/controller did not settle")
        result = holder["result"]
        observed = shell_result(result.stdout, result.stderr, "normal", result.returncode, expected)
    except BaseException as error:
        diagnose(error)
        raise
    _FAILED = False
    return observed


def _finish_body(value, request_sha, start, states, observations, traces, cases, loader):
    need(tuple(row["phase"] for row in _COMMANDS) == root_phases(value) and states == lifecycle_states(value)
         and not _FAILED and time.monotonic() < _END, "Original fixed root command/state roster incomplete or late")
    verify_package_observations(_COMMANDS, root_path(value))
    extra = {}
    if "installed" in value:
        installed = value["installed"]
        wanted = {"positive", "deadline", "shutdown", "emfile", "overlap"} if installed["case"] == "positive" else {installed["case"]}
        need(set(cases) == wanted, "Original fixed installed case roster incomplete")
        _installed_loader_check(loader)
        _retain("loader-final.json", canonical(loader))
        _retain("installed-cases.json", canonical(cases))
        extra = {"case": installed["case"], "candidateRosterSha256": installed["candidateRosterSha256"],
                 "candidateProducerAttempt": installed["candidateProducerAttempt"], "candidateArtifactId": installed["candidateArtifactId"],
                 "consumerAttempt": value["attempt"], "acceptedU": installed["acceptedU"],
                 "lifecycleComplete": installed["case"] == "positive", "fixturePublished": installed["case"] == "positive"}
    elif "shell" in value:
        shell = value["shell"]
        need(set(cases) == set(SHELL_CASES), "Original fixed shell case roster incomplete")
        _shell_data_check(loader)
        _installed_loader_check(loader)
        _retain("loader-final.json", canonical(loader))
        _retain("shell-cases.json", canonical(cases))
        extra = {"shellRosterSha256": shell["rosterSha256"], "shellProducerAttempt": shell["producerAttempt"],
                 "shellArtifactId": shell["artifactId"], "consumerAttempt": value["attempt"], "acceptedU": shell["acceptedU"],
                 "packageLifecycleQualified": False, "shellPackageBuilt": False}
    if "installed" not in value or value["installed"]["case"] == "positive":
        _retain("mutation-denials.txt", canonical({phase: row["denials"] for phase, row in observations.items()}))
    _retain("unit-result.json", canonical({"sourceSha": value["sourceSha"], "handoffSha256": request_sha,
        "entrySha256": start["entrySha256"], "invocationId": start["invocationId"], "unit": start["unit"]["Id"],
        "state": result_state(value), "productQualified": False, "states": states, "scriptTraces": traces,
        "commands": _COMMANDS, "files": list(_FILES), "originalDeadline": value["deadline"], **extra}))
    need(time.monotonic() < _END, "Original lifecycle result closed late")
    print("Root lifecycle body completed; original StopPost/client finality pending.", flush=True)


def unit_start():
    _root_ids()
    value, request_sha = _context(copying=True)
    _D.write(_ROOT / "private/dpkg.log", b"", 0o600)
    namespaces = _namespaces(True)
    policy = dpkg_policy()
    start = {**_domain(value, "start"), "runnerUid": value["runnerUid"], "runnerGid": value["runnerGid"],
             "deadline": value["deadline"], "namespaces": namespaces, "handoffSha256": request_sha,
             "entrySha256": record(_ROOT / "entry.py", JSON_LIMIT)["sha256"]}
    _retain("unit-start.json", canonical(start))
    _retain("inputs.json", canonical(value))
    _retain("dpkg-policy.json", canonical(policy))
    loader = (_installed_loader_start(value, namespaces) if "installed" in value
              else _shell_loader_start(value, namespaces) if "shell" in value else None)
    env = {**_environment(), "MRK_UBUNTU_PUBLICATION_NATIVE": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    for label, test in (("native-root", ROOT_TEST), ("native-user", USER_TEST)):
        argv = [str(_ROOT / "platform-tests"), test, "--exact", "--ignored", "--test-threads=1"]
        result = command(label, _drop(value, argv) if label == "native-user" else argv, env=env)
        native_result(result.stdout, result.stderr, test)
    _no_package_data()
    _no_admin_data()
    _absent(Path("/var/lib/mobile-release-kit"))
    states, observations, traces, cases = {}, {}, {}, {}

    def state(phase, status, variant):
        result = command("state-" + phase, ["/usr/bin/dpkg-query", "-W", "-f=${Status}\t${Version}\n", PACKAGE], maximum=15, codes=(0, 1))
        actual = package_state(result)
        states[phase] = actual
        need(actual == {"status": status, "version": VERSIONS[variant][1] if variant else ""}, "Actual package state differs in " + phase)

    def mutate(phase, action, item, expected, *, collision=False, published=False):
        argv = ["/usr/bin/dpkg", "--debug=2", "--no-triggers", action, str(item)]
        result = package_command(phase, argv, policy=policy, codes=(1,) if collision else (0,))
        traces[phase] = script_trace(result.stderr, expected)
        if collision:
            line = REFUSAL.format("a staging or published name already exists").encode("ascii")
            need(result.stderr.splitlines(keepends=True).count(line) == 1 and PUBLISHED not in result.stdout
                 and sum(part.startswith(b"Runtime publication refused:") for part in result.stderr.splitlines()) == 1,
                 "Duplicate failed without the exact single collision refusal")
        elif published:
            need(result.stdout.splitlines(keepends=True).count(PUBLISHED) == 1 and b"Runtime publication refused:" not in result.stderr,
                 "Dpkg did not execute exactly one successful publisher")
        else:
            need(PUBLISHED not in result.stdout and b"Runtime publication refused:" not in result.stderr, "Unexpected publisher execution")

    def observation(phase):
        argv = ["/usr/bin/python3.12", "-I", "-S", "-B", str(_ROOT / "entry.py"), "observe", phase]
        result = command("observe-" + phase, _drop(value, argv))
        need(result.stderr == b"", "Nonroot observer emitted a diagnostic")
        actual = decode(result.stdout, LIMIT)
        need(type(actual) is dict and actual.get("phase") == phase, "Wrong original observer phase")
        observations[phase] = actual
        if phase == "upgrade":
            need(actual["published"]["P0"] == observations["p0"]["published"]["P0"], "P0 changed during normal upgrade")
        elif phase in {"duplicate", "remove", "purge"}:
            need(actual["published"] == observations["upgrade"]["published"], "Coexisting publications changed in " + phase)
        names = {"p0": "before-upgrade", "upgrade": "after-upgrade", "duplicate": "after-duplicate", "remove": "after-remove", "purge": "after-purge"}
        if phase in names:
            _retain("published-" + names[phase] + ".txt", canonical(actual["published"]))

    p0, f1 = VERSIONS["P0"][1], VERSIONS["F1"][1]
    state("initial", "absent", None)
    mutate("unpack", "--unpack", _ROOT / "private/P0.deb", [])
    state("unpacked", "install ok unpacked", "P0")
    _scripts("unpacked", set(SCRIPT_PINS))
    _binaries(value, "unpacked", "P0")
    _absent(Path("/var/lib/mobile-release-kit"))
    refused = command("nonroot-helper", _drop(value, [HELPER]), codes=(1,))
    need(refused.stdout == b"" and refused.stderr == REFUSAL.format("the fixed release or administrator platform is unsupported").encode("ascii"),
         "Installed helper did not give the exact nonroot Profile refusal")
    observation("unpacked")
    if "installed" in value and value["installed"]["case"] != "positive":
        fixture = _refusal_fixture(value, loader)
        case = value["installed"]["case"]
        cases[case] = _installed_case(value, case, loader)
        _refusal_fixture_check(fixture)
        _retain("refusal-fixture-after.json", canonical(fixture))
        state("refusal", "install ok unpacked", "P0")
        _finish_body(value, request_sha, start, states, observations, traces, cases, loader)
        return
    mutate("configure", "--configure", PACKAGE, [("postinst", ("configure",))], published=True)
    state("p0", "install ok installed", "P0")
    observation("p0")
    if "shell" in value:
        original = observations["p0"]["published"]["P0"]
        expected = _installed_payload(value, loader, original)
        for case in SHELL_CASES:
            environment = _shell_prepare(value, case)
            if case == "normal":
                cases[case] = _shell_normal(value, environment, expected)
            else:
                result = command("shell-" + case, shell_argv(value, case), maximum=60, env=environment)
                cases[case] = shell_result(result.stdout, result.stderr, case, result.returncode, expected)
                if case == "positive":
                    after = canonical(_shell_project_inventory(value, saved=True))
                    _retain("shell-positive-project-after.json", after)
                    shell_project_fixture(value, read(_ROOT / "public/shell-positive-project-before.json", 8192), after)
        need(_tree(PREFIX / M, M, published=True) == original, "Published A changed during shell observations")
        state("shell-finished", "install ok installed", "P0")
        _finish_body(value, request_sha, start, states, observations, traces, cases, loader)
        return
    if "installed" in value:
        original = observations["p0"]["published"]["P0"]
        expected = _installed_payload(value, loader, original)
        for case in ("positive", "deadline", "shutdown", "emfile"):
            cases[case] = _installed_case(value, case, loader, expected)
            need(_tree(PREFIX / M, M, published=True) == original, "Published A changed during installed candidate observations")
    _scripts("before-upgrade", set(SCRIPT_PINS))
    if "installed" in value:
        mutate("upgrade-unpack", "--unpack", _ROOT / "private/F1.deb", [("prerm", ("upgrade", f1)), ("postrm", ("upgrade", f1))])
        state("upgrade-unpacked", "install ok unpacked", "F1")
        _scripts("upgrade-unpacked", set(SCRIPT_PINS))
        _binaries(value, "upgrade-unpacked", "F1")
        _absent(INPUT / M)
        _tree(INPUT / F1, F1, published=False)
        need(_tree(PREFIX / M, M, published=True) == original, "Original published M changed before old-child registration")
        cases["overlap"], traces["upgrade-configure"] = _installed_overlap(value, policy, loader, expected)
    else:
        mutate("upgrade", "--install", _ROOT / "private/F1.deb",
               [("prerm", ("upgrade", f1)), ("postrm", ("upgrade", f1)), ("postinst", ("configure", p0))], published=True)
    state("upgrade", "install ok installed", "F1")
    _scripts("upgrade", set(SCRIPT_PINS))
    _binaries(value, "upgrade", "F1")
    _absent(INPUT / M)
    observation("upgrade")
    mutate("duplicate", "--install", _ROOT / "private/F1.deb",
           [("prerm", ("upgrade", f1)), ("postrm", ("upgrade", f1)), ("postinst", ("configure", f1))], collision=True)
    state("duplicate", "install ok half-configured", "F1")
    _scripts("duplicate", set(SCRIPT_PINS))
    observation("duplicate")
    mutate("remove", "--remove", PACKAGE, [("prerm", ("remove",)), ("postrm", ("remove",))])
    state("remove", "deinstall ok config-files", "F1")
    _scripts("remove", {"postrm"})
    _no_package_data()
    observation("remove")
    mutate("purge", "--purge", PACKAGE, [("postrm", ("purge",))])
    state("purge", "absent", None)
    _scripts("purge", set())
    _no_package_data()
    _no_admin_data()
    observation("purge")
    _finish_body(value, request_sha, start, states, observations, traces, cases, loader)


def _no_denials(observation):
    events = observation.get("events")
    need(type(events) is dict and set(events) == {"memory.events", "pids.events"}
         and all(type(rows) is dict for rows in events.values())
         and {"max", "oom", "oom_kill"} <= set(events["memory.events"]) and "max" in events["pids.events"],
         "Original aggregate denial counters missing")
    need(all(type(number) is int and number >= 0 for rows in events.values() for number in rows.values())
         and all(number == 0 for key, number in events["memory.events"].items() if key != "low")
         and all(number == 0 for number in events["pids.events"].values()), "Original aggregate resource denial")


def verify_finality(start, stop, client_exit_code):
    """Pure original-result correspondence; not a replacement wait/query."""
    need(type(client_exit_code) is int and client_exit_code == 0, "Original service client did not exit zero")
    need(type(start) is dict and type(stop) is dict, "Original service observations missing")
    for key in ("sourceSha", "entrySha256", "handoffSha256", "invocationId", "deadline", "namespaces", "unit", "effective"):
        need(key in start and key in stop and type(start[key]) is type(stop[key]) and start[key] == stop[key],
             "Original service correspondence differs: " + key)
    need(type(start["sourceSha"]) is str and re.fullmatch(r"[0-9a-f]{40}", start["sourceSha"]) is not None
         and all(type(start[key]) is str and re.fullmatch(r"[0-9a-f]{64}", start[key]) is not None for key in ("entrySha256", "handoffSha256"))
         and type(start["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", start["invocationId"]) is not None,
         "Original service identity/pins missing")
    need(type(start["unit"]) is dict and type(start["unit"].get("Id")) is str
         and start["unit"].get("InvocationID") == start["invocationId"] and start["unit"].get("Result") == "success"
         and start["unit"].get("ControlGroup") == "/system.slice/" + start["unit"]["Id"]
         and stop.get("completion") == {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"},
         "Original root service/StopPost completion differs")
    _no_denials(start)
    _no_denials(stop)


def unit_stop():
    global _END
    stop_end = time.monotonic() + 9  # Cleanup-only bound; no package/probe work is reachable here.
    _root_ids()
    value, request_sha = _context()
    _END = stop_end
    completion = {name: os.environ.get(name) for name in ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS")}
    need(all(type(item) is str and 0 < len(item) <= 128 for item in completion.values()), "Original systemd completion variables missing")
    start = decode(read(_ROOT / "public/unit-start.json"))
    outcome = record(_ROOT / "public/unit-result.json", JSON_LIMIT)
    stop = {**_domain(value, "stop"), "entrySha256": record(_ROOT / "entry.py", JSON_LIMIT)["sha256"],
            "handoffSha256": request_sha, "deadline": value["deadline"], "namespaces": _namespaces(True),
            "completion": completion, "result": {**outcome, "path": "unit-result.json"},
            "commands": list(_COMMANDS), "files": list(_FILES)}
    _retain("unit-stop.json", canonical(stop))
    verify_finality(start, stop, 0)  # Actual original client zero is independently required by the nonroot collector.
    need(time.monotonic() < stop_end, "Original StopPost metadata close/readback was late")
    print("Root lifecycle StopPost completed.", flush=True)


def installed_closed_result(value, outcome, raw_files):
    """Pure correspondence after the unchanged original-client/finality gate."""
    installed = value["installed"]
    for key in ("case", "candidateRosterSha256", "candidateProducerAttempt", "candidateArtifactId", "acceptedU"):
        need(outcome.get(key) == installed[key], "Closed installed source/artifact provenance differs")
    positive = installed["case"] == "positive"
    need(outcome.get("consumerAttempt") == value["attempt"] and outcome.get("lifecycleComplete") is positive
         and outcome.get("fixturePublished") is positive, "Closed refusal was relabelled as a publication lifecycle")
    entry, final = (decode(raw_files["loader-" + phase + ".json"], LIMIT) for phase in ("entry", "final"))
    for key in ("scope", "namespaces", "diagnostics", "cacheRows", "entryObjects", "externalPrerequisites"):
        need(entry[key] == final[key], "Closed original loader interval differs")
    need(entry["payloadAdmitted"] is False and final["payloadAdmitted"] is positive
         and all(final["bindings"].get(path) == row for path, row in entry["bindings"].items()), "Original entry bindings changed or refusal admitted payload")
    policy = installed["loaderPolicy"]
    need(loader_diagnostics(raw_files["loader-diagnostics.stdout"]) == entry["diagnostics"]
         and raw_files["loader-diagnostics.stderr"] == raw_files["loader-cache.stderr"] == b"", "Original OS loader command capture differs")
    rows = loader_cache(raw_files["loader-cache.stdout"], policy["packages"]["libc-bin"][2])
    need(entry["entryObjects"] == policy["osNames"]
         and entry["cacheRows"] == [row for row in rows if row["soname"] in set(policy["osNames"]) | PRIVATE_SONAMES],
         "Closed all-SONAME cache roster differs")
    for name, path in loader_candidates(policy["osNames"], rows):
        need(path in entry["bindings"], "Closed original cache/default/hwcaps candidate omitted")
        loader_selected(entry["bindings"][path], policy["libraries"][name]["file"])
    cases = decode(raw_files["installed-cases.json"])
    wanted = {"positive", "deadline", "shutdown", "emfile", "overlap"} if positive else {installed["case"]}
    need(type(cases) is dict and set(cases) == wanted, "Closed original installed case roster differs")
    expected = None
    if positive:
        runtime = decode(raw_files["loader-runtime.json"])
        expected = runtime["expectedMaps"]
        need(set(expected) == {"python", "libssl.so.3", "libcrypto.so.3", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"}
             and runtime["manifestSha256"] == M and runtime["protocolSha256"] == Q
             and runtime["privateObjects"] == sorted(PRIVATE_SONAMES)
             and runtime["shadowedCacheRows"] == [row for row in entry["cacheRows"] if row["soname"] in PRIVATE_SONAMES],
             "Closed private A map/search correspondence differs")
        for role, row in expected.items():
            need(type(row) is dict and set(row) == {"paths", "deviceMajor", "deviceMinor", "inode"}
                 and type(row["paths"]) is list and 0 < len(row["paths"]) <= 3, "Closed admitted child mapping shape differs")
            for path in row["paths"]:
                binding = final["bindings"].get(path)
                need(type(binding) is dict and "identity" in binding
                     and (row["deviceMajor"], row["deviceMinor"], row["inode"])
                         == (os.major(binding["identity"][0]), os.minor(binding["identity"][0]), binding["identity"][1]),
                     "Closed map alias was not independently bound")
        joined = decode(raw_files["installed-overlap-join.json"])
        configure = next(row for row in outcome["commands"] if row["phase"] == "upgrade-configure")
        need(joined["joined"] is joined["releaseWritten"] is True and joined["workerGuardState"] == "RESTORED"
             and type(joined["workerErrorCount"]) is int and joined["workerErrorCount"] == 0 and joined["originalDeadline"] == value["deadline"]
             and joined["originalServiceEndpoint"] == value["deadline"] - CLIENT_RESERVATION - 1
             and joined["configureEndpoint"] <= min(joined["startMonotonic"] + 10, joined["originalServiceEndpoint"])
             and configure["originalEndpoint"] == joined["configureEndpoint"]
             and type(configure["timeoutSeconds"]) is int
             and 0 < configure["timeoutSeconds"] <= math.floor(configure["originalEndpoint"] - configure["startMonotonic"]),
             "Closed original worker join/configure remaining-clock evidence differs")
    else:
        before = decode(raw_files["refusal-fixture-before.json"], LIMIT)
        after = decode(raw_files["refusal-fixture-after.json"], LIMIT)
        need(before == after and before["neverPublished"] is True and before["case"] == installed["case"] and before["manifestSha256"] == M,
             "Closed deliberately never-published refusal fixture changed")
    commands = {row["phase"]: row for row in outcome["commands"]}
    for case in wanted:
        phase = "installed-" + case
        need(commands[phase]["argv"] == _installed_argv(value, case), "Closed original candidate test argv differs")
        observed = installed_result(raw_files[phase + ".stdout"], raw_files[phase + ".stderr"], case, commands[phase]["exitCode"], expected)
        need(observed == cases[case], "Closed original installed case result differs")
    return {"case": installed["case"], "candidateRosterSha256": installed["candidateRosterSha256"],
            "candidateProducerAttempt": installed["candidateProducerAttempt"], "candidateArtifactId": installed["candidateArtifactId"],
            "consumerAttempt": value["attempt"], "acceptedU": installed["acceptedU"], "cases": cases,
            "lifecycleComplete": positive, "fixturePublished": positive}


def shell_closed_loader(value, raw_files):
    """Reconcile retained originals; never query a possibly live GUI process."""
    policy = expand_shell_loader_policy(value["shell"]["loaderPolicy"], value["shell"]["compiler"])
    entry, final = (decode(raw_files["loader-" + phase + ".json"], LIMIT) for phase in ("entry", "final"))
    for key in ("scope", "namespaces", "diagnostics", "cacheRows", "entryObjects", "globalObjects", "hwcapsTiers",
                "moduleRoots", "privateSearch", "runtimeData", "externalPrerequisites"):
        need(entry[key] == final[key], "Closed original shell loader/DATA interval differs: " + key)
    need(entry["payloadAdmitted"] is False and final["payloadAdmitted"] is True
         and entry["runtimeDataRechecked"] is False and final["runtimeDataRechecked"] is True
         and all(final["bindings"].get(path) == row for path, row in entry["bindings"].items()),
         "Original shell entry/DATA bindings changed or final recheck is missing")
    need(loader_diagnostics(raw_files["loader-diagnostics.stdout"]) == entry["diagnostics"]
         and raw_files["loader-diagnostics.stderr"] == raw_files["loader-cache.stderr"] == b"",
         "Original shell loader command capture differs")
    names = policy["osNames"]
    libc = next(row for row in policy["packages"].values() if row["binaryPackage"].split(":")[0] == "libc6")
    rows = loader_cache(raw_files["loader-cache.stdout"], libc["version"], shell_names=names)
    global_names = shell_global_names(policy["libraries"])
    need(entry["entryObjects"] == names and entry["globalObjects"] == global_names
         and entry["cacheRows"] == [row for row in rows if row["soname"] in set(names) | PRIVATE_SONAMES],
         "Closed all-SONAME shell cache roster differs")
    for path, present in entry["hwcapsTiers"].items():
        bound = entry["bindings"].get(path, {})
        need("directory" in bound if present else bound.get("absent") is True,
             "Original shell hwcaps directory presence has no binding")
    for name, path in shell_loader_candidates(global_names, rows, entry["hwcapsTiers"]):
        need(path in entry["bindings"], "Closed original shell cache/default/hwcaps candidate omitted")
        loader_selected(entry["bindings"][path], policy["libraries"][name]["file"])
    need(entry["moduleRoots"] == policy["moduleRoots"] and entry["privateSearch"] == policy["graph"]["privateSearch"],
         "Closed original shell module/private-search roster differs")
    shell_module_proof(policy["graph"], entry["moduleRoots"], entry["bindings"])
    for row in entry["privateSearch"]:
        need(row["path"] in entry["bindings"], "Closed original per-requester candidate omitted")
        shell_private_selected(row, entry["bindings"][row["path"]], policy["libraries"][row["name"]]["file"])
    data = entry["runtimeData"]
    need(shell_data_projection(data) == shell_data_projection(policy["runtimeData"])
         and len(data["records"]) == len(policy["runtimeData"]["records"]) == len(SHELL_DATA_ROOTS),
         "Closed original runtime DATA/cache summary differs")
    for index, pin in enumerate(data["records"]):
        leaf = "shell-root-data-" + str(index) + ".json"
        raw = raw_files[leaf]
        need(pin == {"path": leaf, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
             "Closed complete original shell DATA bytes differ")
        need(policy["runtimeData"]["records"][index] == {**pin, "path": "shell-consumer-data-" + str(index) + ".json"},
             "Closed shell DATA is not the originally admitted current-VM identity")
    runtime = decode(raw_files["loader-runtime.json"])
    expected = runtime["expectedMaps"]
    need(set(expected) == {"python", "libssl.so.3", "libcrypto.so.3", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"}
         and runtime["manifestSha256"] == M and runtime["protocolSha256"] == Q
         and runtime["privateObjects"] == sorted(PRIVATE_SONAMES)
         and runtime["shadowedCacheRows"] == [row for row in entry["cacheRows"] if row["soname"] in PRIVATE_SONAMES]
         and runtime["shadowedDefaultNames"] == [directory + "/" + tier + name for directory in DEFAULT_LIBRARY_DIRS
             for tier in ("", *("glibc-hwcaps/" + tier + "/" for tier in HWCAPS)) for name in sorted(PRIVATE_SONAMES)],
         "Closed private A/OS shell namespace correspondence differs")
    for role, row in expected.items():
        if role == "python" or role in PRIVATE_SONAMES:
            relative = "python/bin/python3" if role == "python" else "python/lib/" + role
            paths = [str(PREFIX / M / relative)]
            provider = policy["graph"]["runtime"][relative]["file"]
        else:
            paths = sorted([directory + "/" + role for directory in DEFAULT_LIBRARY_DIRS[:2]]
                           + (["/lib64/" + role] if role == "ld-linux-x86-64.so.2" else []))
            provider = policy["libraries"][role]["file"]
        need(type(row) is dict and set(row) == {"paths", "deviceMajor", "deviceMinor", "inode"} and row["paths"] == paths
             and all(type(row[key]) is int for key in ("deviceMajor", "deviceMinor", "inode")),
             "Closed original A mapping role or aliases differ")
        for path in paths:
            binding = final["bindings"].get(path)
            need(type(binding) is dict and "identity" in binding
                 and all(binding[key] == provider[key] for key in ("size", "sha256"))
                 and (row["deviceMajor"], row["deviceMinor"], row["inode"])
                     == (os.major(binding["identity"][0]), os.minor(binding["identity"][0]), binding["identity"][1]),
                 "Closed original child-map alias lacks its independently bound inode/bytes")
    return expected


def shell_closed_result(value, outcome, raw_files):
    """Correspondence only, after the same original-client/StopPost gate."""
    shell = value["shell"]
    for key, field in (("shellRosterSha256", "rosterSha256"), ("shellProducerAttempt", "producerAttempt"),
                       ("shellArtifactId", "artifactId"), ("acceptedU", "acceptedU")):
        need(outcome.get(key) == shell[field], "Closed shell original provenance differs")
    need(outcome.get("consumerAttempt") == value["attempt"] and outcome.get("packageLifecycleQualified") is False
         and outcome.get("shellPackageBuilt") is False, "Connection was relabelled as a shell package qualification")
    expected = shell_closed_loader(value, raw_files)
    cases = decode(raw_files["shell-cases.json"])
    need(type(cases) is dict and set(cases) == set(SHELL_CASES), "Closed original shell case roster differs")
    commands = {row["phase"]: row for row in outcome["commands"]}
    for case in SHELL_CASES:
        phase = "shell-" + case
        need(commands[phase]["argv"] == shell_argv(value, case), "Closed original shell argv differs")
        result = shell_result(raw_files[phase + ".stdout"], raw_files[phase + ".stderr"], case, commands[phase]["exitCode"], expected)
        need(canonical(result) == canonical(cases[case]) if case == "positive" else result == cases[case],
             "Closed original shell capture differs")
    fixture = shell_project_fixture(value, raw_files["shell-positive-project-before.json"], raw_files["shell-positive-project-after.json"])
    control = decode(raw_files["shell-normal-control.json"])
    need(control.get("joined") is True and control.get("inputs") == 2 and control.get("workerGuardState") == "RESTORED"
         and control.get("workerErrorCount") == 0 and control.get("errorType") is None
         and control.get("originalDeadline") == value["deadline"] and type(control.get("commands")) is list
         and 11 <= len(control["commands"]) <= 96, "Original normal controller/worker finality differs")
    keys = [row for row in control["commands"] if row["phase"] == "key"]
    need(len(keys) == 2 and all(row["exitCode"] == 0 and row["stdout"] == row["stderr"] == "" for row in keys)
         and [row["argv"] for row in keys] == [_drop(value, ["/usr/bin/xdotool", "key", "--clearmodifiers", key]) for key in ("ctrl+q", "alt+o")],
         "Normal window did not use the two fixed original XTEST commands")
    p0 = decode(raw_files["observe-p0.stdout"], LIMIT)
    need(set(p0["published"]) == {"P0"}
         and decode(raw_files["published-before-upgrade.txt"], LIMIT) == p0["published"],
         "Original unchanged P0 publication observation differs")
    return {"shellRosterSha256": shell["rosterSha256"], "shellProducerAttempt": shell["producerAttempt"],
            "shellArtifactId": shell["artifactId"], "consumerAttempt": value["attempt"], "acceptedU": shell["acceptedU"],
            "cases": cases, "projectDraft": {"native": cases["positive"]["projectDraft"], "fixture": fixture},
            "packageLifecycleQualified": False, "shellPackageBuilt": False}


def verify_service_result(handoff_path, handoff_sha256, entry_sha256, client_result, public_destination):
    # This gate precedes every read of R. An exception/partial/nonzero original
    # client result authorizes neither possible-live DATA access nor cleanup.
    need(type(client_result) is subprocess.CompletedProcess and type(client_result.returncode) is int
         and client_result.returncode == 0 and type(client_result.args) is list
         and type(client_result.stdout) is bytes and type(client_result.stderr) is bytes
         and len(client_result.stdout) + len(client_result.stderr) <= LIMIT, "Original service client result incomplete/failed")
    handoff_path = absolute(str(handoff_path))
    value = handoff(handoff_path, handoff_sha256)
    need(os.getresuid() == (value["runnerUid"],) * 3 and os.getresgid() == (value["runnerGid"],) * 3
         and time.monotonic() < value["deadline"], "Original nonroot collector identity/endpoint differs")
    runtime = [arg.removeprefix("--property=RuntimeMaxSec=") for arg in client_result.args if arg.startswith("--property=RuntimeMaxSec=")]
    need(len(runtime) == 1 and re.fullmatch(r"[1-9][0-9]{0,3}s", runtime[0]) is not None and int(runtime[0][:-1]) < 1200,
         "Original client finite lifetime argument missing")
    properties = {**PROPERTIES, "RuntimeMaxSec": runtime[0]}
    need(client_result.args == _service_argv(value, handoff_path, handoff_sha256, entry_sha256, properties), "Original service client argv differs")
    root = root_path(value)
    directory(root / "public", protected=True)
    start = decode(read(root / "public/unit-start.json"))
    stop = decode(read(root / "public/unit-stop.json"))
    verify_finality(start, stop, client_result.returncode)
    need(start["sourceSha"] == value["sourceSha"] and start["entrySha256"] == entry_sha256
         and start["handoffSha256"] == handoff_sha256 and start["unit"]["Id"] == root.name + ".service"
         and start["deadline"] == value["deadline"] and start["runnerUid"] == value["runnerUid"] and start["runnerGid"] == value["runnerGid"],
         "Original service/handoff correspondence differs")
    _modules(root, owner=False)
    outcome_raw = read(root / "public/unit-result.json")
    outcome = decode(outcome_raw)
    need(_D.same(decode(read(root / "public/inputs.json")), value)
         and stop["result"] == {"path": "unit-result.json", "size": len(outcome_raw), "sha256": hashlib.sha256(outcome_raw).hexdigest()},
         "Original closed root result/input pin differs")
    need(outcome["state"] == result_state(value) and outcome["productQualified"] is False
         and outcome["sourceSha"] == value["sourceSha"] and outcome["handoffSha256"] == handoff_sha256
         and outcome["entrySha256"] == entry_sha256 and outcome["invocationId"] == start["invocationId"]
         and outcome["unit"] == start["unit"]["Id"] and outcome["originalDeadline"] == value["deadline"]
         and tuple(row["phase"] for row in outcome["commands"]) == root_phases(value)
         and len(stop["commands"]) == 1 and stop["commands"][0]["phase"] == "stop-unit-show"
         and stop["commands"][0]["exitCode"] == 0, "Original lifecycle phase/result roster differs")
    for row in outcome["commands"]:
        codes = (79,) if row["phase"] == "installed-emfile" else (0, 1) if row["phase"] in {"state-initial", "state-purge"} else ((1,) if row["phase"] in {"nonroot-helper", "duplicate"} else (0,))
        need(type(row["exitCode"]) is int and row["exitCode"] in codes, "Original lifecycle phase exit differs")
    verify_package_observations(outcome["commands"], root)
    rows = outcome["files"] + stop["files"] + [stop["result"]]
    for name in ("unit-stop.json",):
        pin = record(root / "public" / name, JSON_LIMIT)
        rows.append({**pin, "path": name})
    fixed = public_files(value)
    need(len(rows) <= 128 and len({row["path"] for row in rows}) == len(rows)
         and {path.name for path in (root / "public").iterdir()} == {row["path"] for row in rows} == fixed,
         "Original fixed public evidence roster differs")
    total, raw_files = 0, {}
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "size", "sha256"} and type(row["path"]) is str
             and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,100}", row["path"]) is not None
             and type(row["size"]) is int and 0 <= row["size"] <= LIMIT, "Original evidence record bound differs")
        path = root / "public" / row["path"]
        protected = protected_record(path, row["size"])
        raw = read(path, row["size"])
        need(protected["size"] == row["size"] and protected["sha256"] == row["sha256"]
             and hashlib.sha256(raw).hexdigest() == row["sha256"] and stat.S_IMODE(protected["identity"][2]) == 0o444,
             "Original root evidence bytes/mode changed")
        total += len(raw)
        need(total <= TOTAL_LIMIT and time.monotonic() < value["deadline"], "Original evidence aggregate/endpoint exceeded")
        raw_files[row["path"]] = raw
    states = lifecycle_states(value)
    need(outcome["states"] == states, "Original lifecycle package-state assertions differ")
    extra = (installed_closed_result(value, outcome, raw_files) if "installed" in value
             else shell_closed_result(value, outcome, raw_files) if "shell" in value else {})
    unpacked = decode(raw_files["observe-unpacked.stdout"], LIMIT)
    need(unpacked["published"] == {}, "Original unpack did not preserve publication absence")
    if "shell" not in value and ("installed" not in value or value["installed"]["case"] == "positive"):
        snapshots = {phase: decode(raw_files["observe-" + phase + ".stdout"], LIMIT) for phase in ("p0", "upgrade", "duplicate", "remove", "purge")}
        need(set(snapshots["p0"]["published"]) == {"P0"} and set(snapshots["upgrade"]["published"]) == {"P0", "F1"}
             and snapshots["p0"]["published"]["P0"] == snapshots["upgrade"]["published"]["P0"]
             and all(snapshots[phase]["published"] == snapshots["upgrade"]["published"] for phase in ("duplicate", "remove", "purge")),
             "Original complete two-version retention assertions differ")
    # One finality-gated bounded copy, not a new wait, root query or disposition.
    public_destination = absolute(str(public_destination))
    directory(public_destination)
    need(public_destination.is_relative_to(absolute(value["taskRoot"])) and public_destination.stat().st_uid == value["runnerUid"],
         "Original nonroot evidence destination differs")
    exported = []
    for name, raw in {**raw_files, "client.stdout": client_result.stdout, "client.stderr": client_result.stderr}.items():
        exported.append(_D.write(public_destination / ("lifecycle-" + name), raw, 0o600))
    need(time.monotonic() < value["deadline"], "Original evidence export closed late")
    return {"state": result_state(value), "unit": start["unit"]["Id"], "invocationId": start["invocationId"],
            "sourceSha": value["sourceSha"], "files": exported, "productQualified": False,
            "disposition": ("never-published-refusal-fixture-unpacked-package-and-root-task-retained-no-cleanup-claim"
                            if "installed" in value and value["installed"]["case"] != "positive"
                            else "published-versions-and-root-task-retained-until-disposable-vm-disposition"), **extra}


def main():
    global _FAILED
    role = sys.argv[1] if len(sys.argv) > 1 else "missing"
    try:
        need(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode, "Fixed isolated OS Python invocation required")
        os.umask(0o077)
        if sys.argv[1:] == ["unit-start"]:
            unit_start()
        elif sys.argv[1:] == ["unit-stop"]:
            unit_stop()
        elif len(sys.argv) == 3 and role == "observe":
            observe(sys.argv[2])
        else:
            raise Refused("Only fixed root lifecycle/StopPost/nonroot-observer arguments are allowed")
    except BaseException as error:
        _FAILED = True
        reason = str(error).replace("\n", " ")[:512] or type(error).__name__
        phase = _PHASE if role != "observe" else "observe-" + (sys.argv[2] if len(sys.argv) == 3 else "invalid")
        if role in {"unit-start", "unit-stop"} and _ROOT is not None and _D is not None:
            try:
                _retain(role + "-error.json", canonical({"phase": phase, "reason": reason, "errorType": type(error).__name__,
                    "commands": list(_COMMANDS), "files": list(_FILES), "laterLaunchesClosed": True, "cleanupProven": False,
                    "completion": {name: os.environ.get(name, "")[:128] for name in ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS")}
                                  if role == "unit-stop" else None}))
            except BaseException:
                sys.stderr.write("Lifecycle failure evidence could not be closed/read back; do not infer success.\n")
        sys.stderr.write("Lifecycle refused in " + role + "/" + phase + ": " + reason + "; no retry, repair or cleanup.\n")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
