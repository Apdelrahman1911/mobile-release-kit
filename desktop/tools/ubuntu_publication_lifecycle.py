"""One disposable Ubuntu P0/F1 package lifecycle, never product qualification.

The system manager owns the root service before its first input copy. Inside it
the protected current core owns ordinary commands. The nonroot systemd client
wait is necessary evidence, not authority to clean up privileged descendants.
No accounts, namespace/mount changes, general commands, retry or /opt cleanup.
"""
from __future__ import annotations

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
PREFIX = Path("/opt/mobile-release-kit/versions") / TARGET
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
    need(type(value) is dict and set(value) == {"sourceSha", "runId", "attempt", "deadline", "runnerUid", "runnerGid",
         "source", "taskRoot", "library", "packages", "compilerRecords"}, "Fixed handoff fields differ")
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
    return value


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
    return result


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
        for label, row, target, mode in [("library", value["library"], root / "platform-tests", 0o555),
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
                + 2 * capacity["runtimeBytes"] + 1 + 2 * max(capacity["installedBytes"].values()) + TOTAL_LIMIT + JSON_LIMIT)
    inodes = 2 * max(capacity["installedEntries"].values()) + 2 * 8192 + 128
    need(len({Path(name).stat().st_dev for name in ("/", "/var/lib", "/usr", "/opt")}) == 1,
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


def command(label, argv, *, maximum=120, codes=(0,), env=None):
    global _FAILED, _PHASE
    _PHASE = label
    need(not _FAILED and _OWNER is not None, "Prior root command failed or owner missing")
    _root_ids()
    seconds = min(maximum, math.floor(_END - time.monotonic()))
    need(seconds > 0, "Original root command endpoint exhausted")
    _FAILED = True
    result = _OWNER.run_owned(argv, environ=_environment() if env is None else env, cwd=Path("/"), timeout=seconds,
        capture=True, text=False, output_limit=LIMIT, execution_scope=None, journal_binding=None, cleanup=False)
    need(type(result) is subprocess.CompletedProcess and result.args == argv and type(result.returncode) is int
         and type(result.stdout) is bytes and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= LIMIT,
         "Original root command result incomplete")
    _retain(label + ".stdout", result.stdout)
    _retain(label + ".stderr", result.stderr)
    _COMMANDS.append({"phase": label, "argv": argv, "exitCode": result.returncode, "timeoutSeconds": seconds})
    accepted = result.returncode in codes and time.monotonic() < _END
    if not accepted and label in {"native-root", "native-user"}:
        # Only these fixed credential-free fixtures may expose bounded DATA
        # from the SAME returned capture. This is not another read or receipt.
        diagnostic = {"phase": label, "exitCode": result.returncode,
            "stdoutBytes": len(result.stdout), "stderrBytes": len(result.stderr),
            "stdoutPrefix": result.stdout[:1024].decode("utf-8", errors="backslashreplace"),
            "stderrPrefix": result.stderr[:1024].decode("utf-8", errors="backslashreplace")}
        sys.stderr.write("Native platform failure DATA: " + canonical(diagnostic).decode("ascii"))
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
    for name in ("system.posix_acl_access", "system.posix_acl_default" if is_directory else "security.capability"):
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            need(error.errno == errno.ENODATA, "Extended-attribute absence is unproven")
        else:
            raise Refused("Published object grants extra mutation/execution authority")


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
    for path, children in ((Path("/opt/mobile-release-kit"), {"versions"}),
                           (Path("/opt/mobile-release-kit/versions"), {TARGET}),
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
    need(_namespaces(False) == start["namespaces"] and time.monotonic() < start["deadline"], "Observer namespace or original endpoint differs")
    for manifest in (M, F1):
        _absent(PREFIX / (".publish-" + manifest))
    labels = [] if phase == "unpacked" else (["P0"] if phase == "p0" else ["P0", "F1"])
    if phase in {"unpacked", "p0"}:
        _absent(PREFIX / F1)
    if phase == "unpacked":
        _absent(Path("/opt/mobile-release-kit"))
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
    env = {**_environment(), "MRK_UBUNTU_PUBLICATION_NATIVE": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    for label, test in (("native-root", ROOT_TEST), ("native-user", USER_TEST)):
        argv = [str(_ROOT / "platform-tests"), test, "--exact", "--ignored", "--test-threads=1"]
        result = command(label, _drop(value, argv) if label == "native-user" else argv, env=env)
        native_result(result.stdout, result.stderr, test)
    _no_package_data()
    _no_admin_data()
    _absent(Path("/opt/mobile-release-kit"))
    states, observations, traces = {}, {}, {}

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
    _absent(Path("/opt/mobile-release-kit"))
    refused = command("nonroot-helper", _drop(value, [HELPER]), codes=(1,))
    need(refused.stdout == b"" and refused.stderr == REFUSAL.format("the fixed release or administrator platform is unsupported").encode("ascii"),
         "Installed helper did not give the exact nonroot Profile refusal")
    observation("unpacked")
    mutate("configure", "--configure", PACKAGE, [("postinst", ("configure",))], published=True)
    state("p0", "install ok installed", "P0")
    observation("p0")
    _scripts("before-upgrade", set(SCRIPT_PINS))
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
    need(tuple(row["phase"] for row in _COMMANDS) == ROOT_PHASES and not _FAILED and time.monotonic() < _END,
         "Original fixed root command roster incomplete or late")
    verify_package_observations(_COMMANDS, root_path(value))
    _retain("mutation-denials.txt", canonical({phase: row["denials"] for phase, row in observations.items()}))
    _retain("unit-result.json", canonical({"sourceSha": value["sourceSha"], "handoffSha256": request_sha,
        "entrySha256": start["entrySha256"], "invocationId": start["invocationId"], "unit": start["unit"]["Id"],
        "state": "p0-f1-lifecycle-observed", "productQualified": False, "states": states, "scriptTraces": traces,
        "commands": _COMMANDS, "files": list(_FILES), "originalDeadline": value["deadline"]}))
    need(time.monotonic() < _END, "Original lifecycle result closed late")
    print("Root lifecycle body completed; original StopPost/client finality pending.", flush=True)


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
    need(outcome["state"] == "p0-f1-lifecycle-observed" and outcome["productQualified"] is False
         and outcome["sourceSha"] == value["sourceSha"] and outcome["handoffSha256"] == handoff_sha256
         and outcome["entrySha256"] == entry_sha256 and outcome["invocationId"] == start["invocationId"]
         and outcome["unit"] == start["unit"]["Id"] and outcome["originalDeadline"] == value["deadline"]
         and tuple(row["phase"] for row in outcome["commands"]) == ROOT_PHASES
         and len(stop["commands"]) == 1 and stop["commands"][0]["phase"] == "stop-unit-show"
         and stop["commands"][0]["exitCode"] == 0, "Original lifecycle phase/result roster differs")
    for row in outcome["commands"]:
        codes = (0, 1) if row["phase"] in {"state-initial", "state-purge"} else ((1,) if row["phase"] in {"nonroot-helper", "duplicate"} else (0,))
        need(type(row["exitCode"]) is int and row["exitCode"] in codes, "Original lifecycle phase exit differs")
    verify_package_observations(outcome["commands"], root)
    rows = outcome["files"] + stop["files"] + [stop["result"]]
    for name in ("unit-stop.json",):
        pin = record(root / "public" / name, JSON_LIMIT)
        rows.append({**pin, "path": name})
    fixed = {phase + "." + suffix for phase in (*ROOT_PHASES, "stop-unit-show") for suffix in ("stdout", "stderr")}
    fixed |= {"unit-start.json", "unit-result.json", "unit-stop.json", "inputs.json", "dpkg-policy.json", "mutation-denials.txt"}
    fixed |= {"scripts-" + phase + ".json" for phase in ("unpacked", "before-upgrade", "upgrade", "duplicate", "remove", "purge")}
    fixed |= {"binaries-unpacked.json", "binaries-upgrade.json"}
    fixed |= {"published-" + phase + ".txt" for phase in ("before-upgrade", "after-upgrade", "after-duplicate", "after-remove", "after-purge")}
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
    states = {phase: {"status": status, "version": VERSIONS[variant][1] if variant else ""} for phase, status, variant in (
        ("initial", "absent", None), ("unpacked", "install ok unpacked", "P0"), ("p0", "install ok installed", "P0"),
        ("upgrade", "install ok installed", "F1"), ("duplicate", "install ok half-configured", "F1"),
        ("remove", "deinstall ok config-files", "F1"), ("purge", "absent", None))}
    need(outcome["states"] == states, "Original lifecycle package-state assertions differ")
    snapshots = {phase: decode(raw_files["observe-" + phase + ".stdout"], LIMIT)
                 for phase in ("unpacked", "p0", "upgrade", "duplicate", "remove", "purge")}
    need(snapshots["unpacked"]["published"] == {} and set(snapshots["p0"]["published"]) == {"P0"}
         and set(snapshots["upgrade"]["published"]) == {"P0", "F1"}
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
    return {"state": "p0-f1-lifecycle-observed", "unit": start["unit"]["Id"], "invocationId": start["invocationId"],
            "sourceSha": value["sourceSha"], "files": exported, "productQualified": False,
            "disposition": "published-versions-and-root-task-retained-until-disposable-vm-disposition"}


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
