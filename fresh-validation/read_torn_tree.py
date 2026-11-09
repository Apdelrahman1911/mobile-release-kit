"""Fixed, read-only torn-Fresh snapshot. SOURCE PREPARATION; entry is disabled.

No journal semantics, path arguments, subprocesses, write-mode opens, cleanup,
repair or Installer invocation. A snapshot is not installation/recovery success.
"""
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

# Replace only in an independently reviewed final source/input binding.
EXECUTION_BINDING = None
METADATA_SHA = "704071b6965e49f611fe0993672bfb905d6be9f15800bc21cd37672eee5bc33c"
ROOT = "/Library/Application Support/MobileReleaseKit"
LAUNCHER = "/Applications/Mobile Release Kit.app"
EXPORT_PREFIX = "MobileReleaseKit-InstallerResult-v2-"
# Derived from the final signed input/inventory and fixed first-frame boundary.
# These cannot be chosen by CLI or raised after a failed native original.
SNAPSHOT_BOUNDS = None
SECONDS = 120
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
GATES = (
    ("registration-reservation-v1", b"MRK-MACOS-REGISTRATION-RESERVATION-v1\n"),
    ("maintenance-gate-v1", b"MRK-MACOS-MAINTENANCE-GATE-v1\n"),
)


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def signature(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_flags]


def component(name):
    return (type(name) is str and 0 < len(name.encode("utf-8")) <= 255
            and name not in (".", "..") and "/" not in name and "\0" not in name)


def control_projection(origin_raw, intent_raw):
    """Bounded origin/intent correlation only; never parse the torn journal."""
    def pairs(values):
        output = {}
        for key, value in values:
            need(key not in output, "snapshot-control-duplicate")
            output[key] = value
        return output
    def read(raw):
        need(type(raw) is bytes and 0 < len(raw) <= 16384, "snapshot-control-bound")
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(Refused("snapshot-control-constant")))
        need(type(value) is dict, "snapshot-control-shape")
        return value
    origin, intent = read(origin_raw), read(intent_raw)
    need(type(origin.get("schemaVersion")) is int and origin["schemaVersion"] == 1
         and origin.get("kind") == "mrk-macos-fresh-output-origin-v1"
         and origin.get("target") == "aarch64-apple-darwin"
         and type(origin.get("invocation")) is str
         and re.fullmatch(r"[0-9a-f]{32}", origin["invocation"])
         and origin["invocation"] != "0" * 32
         and type(origin.get("requestId")) is str
         and re.fullmatch(r"[0-9a-f]{32}", origin["requestId"])
         and origin["requestId"] not in ("0" * 32, origin["invocation"])
         and intent.get("invocation") == origin["invocation"]
         and intent.get("requestId") == origin["requestId"]
         and origin.get("intentSha256") == sha(intent_raw), "snapshot-origin-intent-correlation")
    return {"invocation": origin["invocation"], "requestId": origin["requestId"],
            "intentSha256": sha(intent_raw), "originSha256": sha(origin_raw),
            "journalSemanticsAccepted": False}


class Metadata:
    """The existing reviewed read-only ACL/stat/xattr-name observer."""

    def __init__(self, clock):
        self.clock = clock
        self.clock()
        path = Path(__file__).absolute().with_name("darwin_metadata.py")
        fd = os.open(path, FLAGS)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= 128 * 1024, "metadata-source-shape")
            self.source_requested_bytes = before.st_size + 1
            raw = os.read(fd, self.source_requested_bytes)
            need(len(raw) == before.st_size and sha(raw) == METADATA_SHA
                 and signature(os.fstat(fd)) == signature(before)
                 == signature(os.stat(path, follow_symlinks=False)), "metadata-source-binding")
        finally:
            os.close(fd)
        spec = importlib.util.spec_from_loader("fixed_fresh_snapshot_metadata", loader=None)
        self.module = importlib.util.module_from_spec(spec)
        exec(compile(raw, str(path), "exec"), self.module.__dict__)
        self.module._check_abi()
        self.clock()
        self.lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        P, I = ctypes.c_void_p, ctypes.c_int
        prototypes = {
            "filesec_init": (P, []), "filesec_free": (None, [P]),
            "fstatx_np": (I, [I, ctypes.POINTER(self.module.DarwinStat), P]),
            "filesec_get_property": (I, [P, I, P]),
            "filesec_query_property": (I, [P, I, ctypes.POINTER(I)]),
            "acl_valid": (I, [P]), "acl_get_entry": (I, [P, I, ctypes.POINTER(P)]),
            "acl_free": (I, [P]), "flistxattr": (ctypes.c_ssize_t, [I, P, ctypes.c_size_t, I]),
        }
        for name, (result, arguments) in prototypes.items():
            call = getattr(self.lib, name)
            call.restype, call.argtypes = result, arguments

    def observe(self, fd):
        self.clock()
        before = os.fstat(fd)
        value = self.module._acl_snapshot(self.lib, fd, signature(before)[:9])
        need(value["empty"] and value["snapshotFlags"] == 0, "snapshot-acl-or-flags")
        # Torn first-file scope permits no xattrs. No attribute values are read.
        need(self.lib.flistxattr(fd, None, 0, 0) == 0, "snapshot-xattrs")
        need(signature(os.fstat(fd)) == signature(before), "snapshot-native-post")
        self.clock()
        return {"birthNs": value["snapshotBirthtimeNs"], "aclEmpty": True,
                "xattrNames": [], "flags": 0}


class Snapshot:
    def __init__(self, bounds):
        need(type(bounds) is dict and set(bounds) == {"maxNodes", "maxDepth", "maxLogicalBytes",
             "maxFileBytes", "maxRequestedReadBytes", "maxLiveOriginals", "maxOutputBytes"}
             and all(type(n) is int and n > 0 for n in bounds.values()), "snapshot-source-bounds")
        self.bounds = bounds
        self.deadline = time.monotonic_ns() + SECONDS * 1_000_000_000
        self.originals, self.rows, self.directories, self.control_data = [], {}, [], {}
        self.total, self.requested, self.closed, self.device = 0, 0, False, None
        self.metadata = Metadata(self.clock)
        self.requested += self.metadata.source_requested_bytes
        need(self.requested <= self.bounds["maxRequestedReadBytes"], "snapshot-requested-read-bound")

    def clock(self):
        need(time.monotonic_ns() < self.deadline, "snapshot-deadline")

    def opened(self, parent, name, directory, *, ancestor=False):
        self.clock()
        need(len(self.originals) < self.bounds["maxLiveOriginals"], "snapshot-original-bound")
        need(name == "/" and parent is None or component(name), "snapshot-component")
        entry = {"fd": None, "parent": parent, "name": name, "identity": None,
                 "ancestor": ancestor, "closed": True}
        self.originals.append(entry)  # Reserve the slot before acquiring a native original.
        fd = os.open(name, FLAGS | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        entry["fd"], entry["closed"] = fd, False
        info = os.fstat(fd)
        entry["identity"] = signature(info)
        need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
             and info.st_uid == 0 and (ancestor or info.st_gid == 0)
             and not info.st_mode & (0o002 if ancestor else 0o022)
             and (ancestor or info.st_flags == 0), "snapshot-object-protection")
        if not ancestor:
            need(self.device is None or info.st_dev == self.device, "snapshot-mount-boundary")
        self.post(entry)
        return entry

    def post(self, entry):
        self.clock()
        current = signature(os.fstat(entry["fd"]))
        named = signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False))
        if entry["ancestor"]:
            need(current[:5] == entry["identity"][:5] and current[9] == entry["identity"][9]
                 and current == named, "snapshot-ancestor-post")
        else:
            need(current == named == entry["identity"], "snapshot-object-post")

    def chain(self, path):
        need(path in ("/Library/Application Support", "/Applications"), "fixed-parent-only")
        entry = self.opened(None, "/", True, ancestor=True)
        for name in path.strip("/").split("/"):
            entry = self.opened(entry["fd"], name, True, ancestor=True)
        return entry

    def names(self, entry):
        self.post(entry)
        names = []
        limit = 4096 if entry["ancestor"] else self.bounds["maxNodes"]
        with os.scandir(entry["fd"]) as iterator:
            for child in iterator:
                need(len(names) < limit and component(child.name), "snapshot-roster-bound")
                names.append(child.name)
        need(len(names) == len(set(names)), "snapshot-roster-duplicate")
        return sorted(names)

    def leaf(self, parent, name):
        entry = self.opened(parent["fd"], name, False)
        info = entry["identity"]
        need(info[5] == 1 and 0 <= info[6] <= self.bounds["maxFileBytes"], "snapshot-file-bound")
        self.total += info[6]
        need(self.total <= self.bounds["maxLogicalBytes"], "snapshot-total-bound")
        capture = name == "fresh-output-origin-v1.json" or re.fullmatch(r"\.maintenance-[0-9a-f]{32}\.intent\.json", name)
        if capture:
            need(name not in self.control_data and len(self.control_data) < 2 and info[6] <= 16384,
                 "snapshot-two-fixed-control-files")
        digest, count, control = hashlib.sha256(), 0, bytearray()
        while count < info[6]:
            self.clock()
            requested = min(65536, info[6] - count)
            self.requested += requested
            need(self.requested <= self.bounds["maxRequestedReadBytes"], "snapshot-requested-read-bound")
            block = os.pread(entry["fd"], requested, count)
            need(block, "snapshot-short-file")
            digest.update(block)
            if capture:
                control.extend(block)
            count += len(block)
        self.requested += 1
        need(self.requested <= self.bounds["maxRequestedReadBytes"], "snapshot-requested-read-bound")
        need(not os.pread(entry["fd"], 1, count), "snapshot-file-growth")
        self.post(entry)
        if capture:
            self.control_data[name] = bytes(control)
        return entry, {"kind": "file", "identity": info, "bytes": count,
                       "sha256": digest.hexdigest(), "native": self.metadata.observe(entry["fd"])}

    def walk(self, entry, relative="", depth=0):
        self.clock()
        need(depth <= self.bounds["maxDepth"] and len(self.rows) < self.bounds["maxNodes"], "snapshot-tree-bound")
        names = self.names(entry)
        row = {"kind": "directory", "identity": entry["identity"],
               "native": self.metadata.observe(entry["fd"]), "names": names}
        self.rows[relative] = row
        self.directories.append((entry, names))
        for name in names:
            self.clock()
            need(len(self.rows) < self.bounds["maxNodes"], "snapshot-tree-bound")
            path = name if not relative else relative + "/" + name
            info = os.stat(name, dir_fd=entry["fd"], follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                self.walk(self.opened(entry["fd"], name, True), path, depth + 1)
            else:
                need(stat.S_ISREG(info.st_mode), "snapshot-link-or-special-file")
                _, self.rows[path] = self.leaf(entry, name)
        self.post(entry)

    def collect(self):
        support = self.chain("/Library/Application Support")
        applications = self.chain("/Applications")
        # This reader is only for torn Fresh, never clean success or recovery.
        try:
            os.stat("Mobile Release Kit.app", dir_fd=applications["fd"], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("torn-snapshot-launcher-present")
        root = self.opened(support["fd"], "MobileReleaseKit", True)
        self.device = root["identity"][0]
        for name, expected in GATES:
            entry, row = self.leaf(root, name)
            need(row["bytes"] == len(expected) and row["sha256"] == sha(expected), "snapshot-gate-bytes")
            fcntl.flock(entry["fd"], fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.walk(root)
        need("installation-v2.json" not in self.rows and ".fresh-conservation-v1" not in self.rows,
             "torn-snapshot-unexpected-publication")
        intents = [name for name in self.control_data if name.startswith(".maintenance-")]
        need(len(intents) == 1 and "fresh-output-origin-v1.json" in self.control_data,
             "snapshot-one-origin-intent-pair")
        projection = control_projection(self.control_data["fresh-output-origin-v1.json"], self.control_data[intents[0]])
        stage = ".install-" + projection["invocation"]
        need(intents[0] == ".maintenance-" + projection["invocation"] + ".intent.json"
             and self.rows[intents[0]]["sha256"] == projection["intentSha256"]
             and self.rows[stage + "/fresh-output-origin-v1.json"]["sha256"] == projection["originSha256"],
             "snapshot-correlated-file-rows")
        # The public result channel is outside the private product root.
        # Preserve only its fixed MRK names; unrelated support entries are never read.
        exports = {}
        for name in self.names(support):
            if name.startswith(EXPORT_PREFIX):
                request = name[len(EXPORT_PREFIX):-5] if name.endswith(".json") else ""
                need(len(request) == 32 and all(c in "0123456789abcdef" for c in request)
                     and request == projection["requestId"] and not exports, "snapshot-export-name")
                _, exports[name] = self.leaf(support, name)
                need(exports[name]["bytes"] == 0 and exports[name]["sha256"] == sha(b"")
                     and stat.S_IMODE(exports[name]["identity"][2]) == 0o600, "cut-reserved-empty-export")
        need(len(exports) == 1, "one-cut-reserved-request-export")
        need(sorted(n for n in self.names(support) if n.startswith(EXPORT_PREFIX)) == sorted(exports),
             "snapshot-export-roster-post")
        try:
            os.stat("Mobile Release Kit.app", dir_fd=applications["fd"], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("torn-snapshot-launcher-post-present")
        for entry, names in self.directories:
            need(self.names(entry) == names, "snapshot-directory-post")
        for entry in self.originals:
            self.post(entry)
        result = {"schemaVersion": 1, "kind": "mrk-fixed-torn-physical-snapshot-v1",
                  "root": ROOT, "launcherAbsent": True, "rows": self.rows,
                  "requestExports": exports, "logicalFileBytes": self.total,
                  "originIntentCorrelation": projection,
                  "requestedReadBytes": self.requested, "resourceBounds": self.bounds,
                  "semanticJournalAccepted": False, "mutationPerformed": False,
                  "installationQualified": False, "recoveryQualified": False}
        need(len(encoded(result)) <= self.bounds["maxOutputBytes"] - 1024, "snapshot-output-bound")
        return result

    def finish(self):
        errors = []
        for entry in reversed(self.originals):
            fd, entry["fd"] = entry["fd"], None  # Consumed before close; never retry.
            if fd is not None:
                try:
                    os.close(fd)
                    entry["closed"] = True
                except OSError as error:
                    errors.append(error.errno)
        self.closed = not errors and all(entry["closed"] for entry in self.originals)
        need(self.closed, "snapshot-original-close-unknown")
        self.clock()


def main():
    # Deliberately before platform probes, imports of metadata or protected reads.
    need(EXECUTION_BINDING is not None, "source-preparation-only")
    need(len(sys.argv) == 1 and sys.platform == "darwin"
         and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         "fixed-root-reader-route")
    # The final binder must close these actual hosted identifiers, never a caller path.
    need(os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("RUNNER_OS") == "macOS" and os.environ.get("RUNNER_ARCH") == "ARM64"
         and all(os.environ.get(key) == EXECUTION_BINDING[key] for key in
                 ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")),
         "fixed-hosted-binding")
    need(SNAPSHOT_BOUNDS is not None, "snapshot-inventory-quote-unbound")
    need(len(encoded(EXECUTION_BINDING)) <= 900, "snapshot-fixed-binding-size")
    snapshot = Snapshot(SNAPSHOT_BOUNDS)
    failure, result = None, None
    try:
        result = snapshot.collect()
    except BaseException as error:
        failure = error
    try:
        snapshot.finish()
    except BaseException as error:
        if failure is None:
            failure = error
    if failure is not None:
        raise failure
    result.update(originalClosesKnown=True, transportState="pending-original-process-exit",
                  binding=EXECUTION_BINDING)
    body = encoded(result)
    need(len(body) <= SNAPSHOT_BOUNDS["maxOutputBytes"] and os.write(1, body) == len(body), "snapshot-output-short")


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # No partial snapshot or private error text is accepted as observation.
        os.write(2, b"fixed-torn-snapshot-refused\n")
        raise SystemExit(1)

