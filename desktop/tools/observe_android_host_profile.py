"""Command-free portable Android host-profile DATA, never runtime admission.

The metadata job does not install Android configurations or run their consumers.
Its SDK/configuration source rules are explicitly prospective. The existing
native owner must still bind its own originals and run the fresh paired font
and provider consumers before material acquisition and compilation.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

TOOLS = Path(__file__).absolute().parent
SOURCE = TOOLS.parent.parent
SCHEMA = "mrk-android-host-profile-data-v1"
OUTPUT_NAME = "android-host-profile.json"
READ_LIMIT = 384 << 20
OUTPUT_LIMIT = 2 << 20
WORK_SECONDS, ACTION_SECONDS = 120, 130
FINAL_READ_RESERVE = 12 << 20  # Part of READ_LIMIT, never additional credit.
LINK_CAPACITY = 4097  # One extra byte detects an overlong/truncated ordinary link.
# A file binding with absent=True can perform40 preliminary,40 original,
#40 first-resolution,40 POST and40 final-resolution reads. This temporary
# availability is WITHIN the ledger, not a charge/refund estimate.
BIND_LINK_MARGIN = 200 * LINK_CAPACITY
PROVIDER_FILE = "android_material_data/host-profile-providers.json"
PROVIDER_SHA256 = "edd6b7fb76b042d5b86b35ac258a80ee27e42ed912fbd646c717e491c293c8c6"
SOURCE_FILES = (
    ".github/workflows/desktop-ubuntu-publication.yml",
    *("desktop/tools/" + name for name in (
        "observe_android_host_profile.py", "observe_hosted_android.py", "observe_hosted_python.py",
        "ci_ubuntu_publication.py", "ci_foundation.py", "conventional_runtime_data.py",
        "ubuntu_publication_lifecycle.py", "android_material_preparation.py", "android_hosted_data.py",
        "stock_trust_correspondence.py", "ubuntu_stock_ca_policy.json", "hosted_glibc_policy.py",
        "prepare_hosted_ubuntu_data.py", "android_material_data/policy.json",
        "android_material_data/fonts.json", PROVIDER_FILE)),
)
PREPARATION_PROGRAMS = ("/usr/bin/bash", "/usr/bin/dpkg-deb", "/usr/bin/python3.12",
                        "/usr/bin/fc-cat", "/usr/bin/fc-list", "/usr/bin/curl")
PREPARATION_PACKAGES = {"/usr/bin/bash": "bash", "/usr/bin/dpkg-deb": "dpkg",
    "/usr/bin/python3.12": "python3.12-minimal", "/usr/bin/fc-cat": "fontconfig",
    "/usr/bin/fc-list": "fontconfig", "/usr/bin/curl": "curl"}
EXTRA_PACKAGES = ("bash", "dpkg", "python3.12-minimal", "curl", "ca-certificates", "ca-certificates-java",
                  "fontconfig-config", "fonts-dejavu-core",
                  "fonts-dejavu-extra", "fonts-lato", "fonts-liberation", "fonts-noto-color-emoji")
NETWORK_CONFIGURATION = {
    "/etc/gai.conf": {"defaults": True},
    "/etc/nsswitch.conf": {"databases": {
        "ethers": ["db", "files"], "group": ["files", "systemd"],
        "gshadow": ["files", "systemd"], "hosts": ["files", "dns"], "netgroup": ["nis"],
        "networks": ["files"], "passwd": ["files", "systemd"], "protocols": ["db", "files"],
        "rpc": ["db", "files"], "services": ["db", "files"], "shadow": ["files", "systemd"],
    }},
}
# These are the version definitions of the independently pinned liblzma.so.5,
# not an arbitrary XZ label family or permission to select another provider.
PREPARATION_XZ_LABELS = {"XZ_5.0", "XZ_5.2", "XZ_5.1.2alpha", "XZ_5.2.2", "XZ_5.4"}
DIAGNOSTIC_PHASES = {
    "observation", "preparation-file", "preparation-elf", "font-snapshot", "font-suppliers",
    "font-roster", "font-file", "font-configuration", "font-local-configuration",
    "font-cache", "font-cache-marker", "trust-policy", "trust-custom", "trust-pem",
    "trust-jks", "trust-config", "trust-complete", "trust-custom-post", "package-status",
    "package-source", "package-available", "package-members", "package-provider",
    "package-preparation", "package-font", "package-identity",
}
PROFILE_REFUSALS = {
    "profile-file-bound", "profile-file-open-changed", "profile-file-read-type", "profile-file-grew",
    "profile-file-read-changed", "profile-file-post-changed", "profile-file-original",
    "profile-parsed-body-correspondence", "profile-parsed-original-changed",
    "profile-file-correspondence", "profile-public-alias", "profile-snapshot-unavailable",
    "profile-font-suppliers", "profile-font-roster", "profile-font-file",
    "profile-font-local-configuration", "profile-font-cache-version", "profile-font-cache-marker",
    "profile-custom-ca-not-empty", "profile-custom-ca-changed", "profile-package-correspondence",
    "profile-package-unavailable", "profile-package-member-changed", "profile-package-member-roster",
    "profile-provider-package-membership", "profile-preparation-package-membership",
    "profile-font-package-membership", "profile-package-public-identity",
    "profile-preparation-elf-role", "profile-preparation-elf-source", "profile-preparation-elf-names",
    "profile-preparation-elf-labels", "directory-open-changed", "directory-read-changed",
    "package-selection", "package-duplicate", "package-field", "package-not-installed",
    "package-member-duplicate",
}
FONT_REFUSALS = {
    "Android font configuration bound/entity differs": "font-configuration-bound-or-entity",
    "Android font configuration DTD differs": "font-configuration-dtd",
    "Android font configuration root differs": "font-configuration-root",
    "Android font configuration element bound": "font-configuration-element-bound",
    "Android font configuration namespace/remapping differs": "font-configuration-namespace-or-remapping",
    "Android font configuration selector attributes differ": "font-configuration-selector-attributes",
    "Android font configuration selector differs": "font-configuration-selector",
}


def local(name):
    spec = importlib.util.spec_from_file_location("_android_profile_" + name, TOOLS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = local("observe_hosted_android")  # Resource-free definitions only; never collect()/main().


def need(value, label):
    BASE.need(value, label)


def failure_detail(reader, error, role, providers, fonts):
    """Finite source labels only; no exception text, private name or host body.

    The old reason/firstFailure contract remains unchanged. At most three short
    strings fit well inside the existing64KiB failure/output slack for77 roles.
    """
    phase = getattr(reader, "phase", "observation")
    label = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
    refusal = BASE.diagnostic_reason(error)
    if isinstance(error, BASE.Stopped):
        refusal = label if label in {"read-budget", "deadline", "action-deadline"} else "resource-limit"
    elif isinstance(error, ValueError):
        if label in PROFILE_REFUSALS:
            refusal = label
        elif label in FONT_REFUSALS:
            refusal = FONT_REFUSALS[label]
    detail = {"phase": phase if type(phase) is str and phase in DIAGNOSTIC_PHASES else "observation",
              "refusal": refusal}
    allowed = set()
    if role == "fonts":
        allowed = set(fonts["supplierRoots"]) | set(fonts["directories"]) | set(fonts["files"]) | set(fonts["absences"])
        allowed.update("/var/cache/fontconfig/" + name for name in fonts["directories"]["/var/cache/fontconfig"])
    elif role == "stockTrust":
        allowed = {BASE.CUSTOM_CA_ROOT, *(name for name, _, _ in BASE.TRUST_INPUTS)}
    elif role == "packages":
        allowed = {name.split(":", 1)[0] for name in providers["packages"]} | set(EXTRA_PACKAGES)
        allowed.update(row["file"]["path"] for row in [*providers["osLibraries"].values(), *providers["programs"].values()])
        allowed.update(PREPARATION_PROGRAMS)
        allowed.update(row["path"] for row in fonts["files"].values())
    elif role.startswith("preparation:"):
        allowed = set(PREPARATION_PROGRAMS)
    subject = getattr(reader, "profile_subject", None)
    if type(subject) is str and len(subject) <= 192 and subject in allowed:
        detail["subject"] = subject
    return detail


def full_state(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class BoundedReadlink:
    """One ordinary read-only Linux filesystem API; not a native test/consumer.

    Bind only on the explicit observer path. CDLL(None) uses this process's
    already loaded libc, never a searched library/path or a fallback provider.
    """
    def __init__(self):
        need(sys.platform == "linux" and os.uname().machine == "x86_64", "profile-link-platform")
        import ctypes
        self.ctypes = ctypes
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.call = self.libc.readlink
        self.call.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
        self.call.restype = ctypes.c_ssize_t

    def __call__(self, path, capacity):
        need(capacity == LINK_CAPACITY, "profile-link-capacity")
        name = os.fsencode(path)
        need(name.startswith(b"/") and b"\x00" not in name and len(name) <= 4096, "profile-link-name")
        buffer = self.ctypes.create_string_buffer(capacity)
        count = self.call(name, buffer, capacity)
        if count < 0:
            raise OSError(self.ctypes.get_errno(), "bounded-link-read")
        need(0 < count < capacity, "profile-link-truncated")
        return buffer.raw[:count]


class Reader(BASE.Reader):
    """One repeated-I/O ledger including every actual bounded link read.

    Protected bindings retain the existing original/file/alias POST checks.
    The observer's explicit resolver replaces only opaque Path.resolve in its
    optional branch; native/default behavior is unchanged. Failed body/link
    reads keep their reservation. All parser and final reads use this ledger.
    """
    def __init__(self, publisher, deadline):
        super().__init__(publisher, deadline)
        self.remaining = READ_LIMIT
        self.final_reserve = 0
        self.link_api = None

    def point(self):
        super().point()
        if self.remaining <= self.final_reserve:
            raise BASE.Stopped("read-budget")

    def charged(self, limit, action, *, overread=1, nested_margin=0):
        self.point()
        available = self.remaining - self.final_reserve
        if available <= overread + nested_margin:
            raise BASE.Stopped("read-budget")
        bound = min(limit, available - overread - nested_margin)
        reserved = bound + overread
        self.remaining -= reserved
        value, consumed = action(bound)
        need(type(consumed) is int and 0 <= consumed <= bound, "read-accounting")
        self.remaining += reserved - consumed
        self.point()
        return value

    def readlink(self, path):
        self.point()
        path = Path(path)
        before = path.lstat()
        need(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1, "profile-link-original")
        def action(bound):
            need(bound == LINK_CAPACITY, "profile-link-capacity")
            if self.link_api is None:
                self.link_api = BoundedReadlink()
            raw = self.link_api(path, bound)
            need(type(raw) is bytes and 0 < len(raw) < LINK_CAPACITY, "profile-link-truncated")
            need(full_state(path.lstat()) == full_state(before), "profile-link-changed")
            return os.fsdecode(raw), len(raw)
        return self.charged(LINK_CAPACITY, action, overread=0)

    def resolve(self, path):
        self.point()
        path = Path(path)
        need(path.is_absolute() and ".." not in path.parts, "profile-resolve-role")
        pending, resolved, originals, links, steps = list(path.parts[1:]), Path("/"), [], 0, 0
        while pending:
            self.point()
            steps += 1
            need(steps <= 256, "profile-resolve-components")
            part = pending.pop(0)
            if part == ".":
                continue
            if part == "..":
                resolved = resolved.parent
                continue
            candidate = resolved / part
            item = candidate.lstat()
            originals.append((candidate, full_state(item)))
            if stat.S_ISLNK(item.st_mode):
                links += 1
                need(links <= 40, "profile-resolve-links")
                target = Path(self.readlink(candidate))
                if target.is_absolute():
                    resolved, parts = Path("/"), target.parts[1:]
                else:
                    parts = target.parts
                pending = [*parts, *pending]
            else:
                need(not pending or stat.S_ISDIR(item.st_mode), "profile-resolve-directory")
                resolved = candidate
        for name, original in reversed(originals):
            self.point()
            need(full_state(name.lstat()) == original, "profile-resolve-changed")
        return resolved

    def bind(self, path, *, directory_only=False, absent=False, limit=64 << 20):
        def action(bound):
            value = self.s.shell_host_binding(Path(path), directory_only=directory_only, absent=absent,
                limit=bound, link_reader=self.readlink, resolver=self.resolve, record_reader=self._file_record)
            return value, value.get("size", 0)
        return self.charged(limit, action, nested_margin=BIND_LINK_MARGIN)

    def _original_file(self, path, bound, *, body=False):
        """No buffered prefetch: the enclosing charge covers at most bound+1.

        Keep the original descriptor until full-state POST; consume its one
        close even after a read/check failure. Native/default DATA helpers are
        unchanged. Source, parser, hash and output readbacks all use this path.
        """
        path = Path(path)
        self.s.D.directory(path.parent)
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= bound, "profile-file-bound")
        original = full_state(before)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        failure = None
        try:
            need(full_state(os.fstat(fd)) == original, "profile-file-open-changed")
            hashed, count, blocks = hashlib.sha256(), 0, []
            while True:
                # Read credit is already reserved by the enclosing charged()
                # operation. Check its ORIGINAL clock, not an unreserved budget.
                if BASE.time.monotonic() >= self.deadline:
                    raise BASE.Stopped("deadline")
                block = os.read(fd, min(64 << 10, before.st_size - count + 1))
                need(type(block) is bytes, "profile-file-read-type")
                if not block:
                    break
                count += len(block)
                need(count <= before.st_size, "profile-file-grew")
                hashed.update(block)
                if body:
                    blocks.append(block)
            need(count == before.st_size and full_state(os.fstat(fd)) == original,
                 "profile-file-read-changed")
        except BaseException as error:
            failure = error
            raise
        finally:
            closing, fd = fd, None  # Original custody consumed before sole close.
            try:
                os.close(closing)
            except BaseException as error:
                if failure is None:
                    raise
                failure.add_note("profile original file close failed: " + type(error).__name__)
        need(full_state(path.lstat()) == original, "profile-file-post-changed")
        return {"path": path.name, "size": count, "sha256": hashed.hexdigest()}, b"".join(blocks) if body else None

    def _file_record(self, path, bound):
        return self._original_file(path, bound)[0]

    def _body(self, name, bound):
        _, raw = self._original_file(name, bound, body=True)
        return raw, len(raw)

    def write(self, path, raw):
        """Preserve the existing exclusive writer and BOTH exact readbacks."""
        path = Path(path)
        self.s.D.directory(path.parent)
        with path.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            need(output.write(raw) == len(raw), "profile-output-short-write")
            output.flush()
            os.fsync(output.fileno())
        need(self._body(path, len(raw))[0] == raw, "profile-output-readback")
        return self._file_record(path, len(raw))

    def _profile_file(self, name, limit):
        row = self.bind(name, limit=limit)
        item = Path(row["path"]).lstat()
        need(item.st_uid == item.st_gid == 0 and list(self.s.D.state(item)) == row["identity"],
             "profile-file-original")
        return {**row, "uid": 0, "gid": 0, "mode": stat.S_IMODE(item.st_mode)}

    def file(self, name, limit, parse=None):
        before = self._profile_file(name, limit)
        result = {"status": "observed", "file": before}
        if parse is not None:
            raw = self.body(before["path"], limit)
            need(len(raw) == before["size"] and hashlib.sha256(raw).hexdigest() == before["sha256"],
                 "profile-parsed-body-correspondence")
            result["data"] = parse(raw)
            self.point()
            need(self.s.D.same(before, self._profile_file(name, limit)), "profile-parsed-original-changed")
        return result

    def body(self, path, limit):
        return self.charged(limit, lambda bound: self._body(str(path), bound), overread=1)

    def source(self, relative):
        self.point()
        path = SOURCE / relative
        before = full_state(path.lstat())
        row = self.charged(2 << 20, lambda bound: self._source_record(path, bound))
        need(full_state(path.lstat()) == before, "profile-source-original")
        return {"path": relative, "size": row["size"], "sha256": row["sha256"]}, before

    def _source_record(self, path, bound):
        value = self._file_record(path, bound)
        return value, value["size"]

    def output_root(self, run):
        # The shared native helper would repeat an uncharged Python-file read.
        # Reuse its PURE complete source profile and private-directory check,
        # but bind the original interpreter through this same charged reader.
        host = self.s.C.conventional_hosted_python_profile(self.s.D)
        expected = host["images"][run["ImageVersion"]]
        need(sys.executable == expected["path"] == "/usr/bin/python3.12", "profile-original-python")
        row = self.file(expected["path"], 16 << 20)["file"]
        need(row["path"] == expected["path"] and row["mode"] == 0o755
             and {key: row[key] for key in ("size", "sha256")} == {key: expected[key] for key in ("size", "sha256")},
             "profile-original-python")
        parent = Path(os.environ.get("RUNNER_TEMP", ""))
        need(parent.is_absolute() and ".." not in parent.parts, "profile-output-parent")
        root = parent / ("mrk-desktop-tools-" + run["GITHUB_RUN_ID"] + "-" + run["GITHUB_RUN_ATTEMPT"])
        self.point()
        return root, self.s.directory_identity(root)

    def custom_ca(self):
        # The existing protected empty-directory reader exports no member names
        # or bodies. Its directory/absence/recheck calls now share this ledger.
        return super().directory(BASE.CUSTOM_CA_ROOT, custom=True, bind_path=self.bind)


def public_file(row, expected, *, selected=None, public_aliases=()):
    """Only exact source-named selections, aliases and targets may leave here."""
    wanted = {key: expected[key] for key in ("path", "size", "sha256", "mode")}
    actual = {key: row[key] for key in ("path", "size", "sha256")}
    actual["mode"] = row.get("mode", stat.S_IMODE(row["identity"][2]) if "identity" in row else None)
    selected = selected if selected is not None else expected.get("selectedPath", expected["path"])
    need(actual == wanted and row.get("selectedPath") == selected, "profile-file-correspondence")
    aliases = []
    root_aliases = {"/bin": "/usr/bin", "/lib": "/usr/lib", "/lib64": "/usr/lib64", "/sbin": "/usr/sbin"}
    allowed_names = {selected, expected["path"], *public_aliases, *root_aliases, *root_aliases.values()}
    for name in tuple(allowed_names):
        for alias, canonical in root_aliases.items():
            for source, target in ((alias, canonical), (canonical, alias)):
                if name.startswith(source + "/"):
                    allowed_names.add(target + name[len(source):])
    for name, _, target in row.get("links", []):
        need(name in allowed_names and type(target) is str and 0 < len(target) <= 4096,
             "profile-public-alias")
        destination = os.path.normpath(os.path.join(str(Path(name).parent), target))
        allowed = {destination, os.path.relpath(destination, str(Path(name).parent))}
        need(destination in allowed_names and target in allowed
             and (name not in root_aliases or destination == root_aliases[name]), "profile-public-alias")
        aliases.append({"path": name, "target": target, "destination": destination})
    return {**wanted, "selectedPath": selected, "aliases": aliases}


def observed_file(reader, name, expected=None, *, limit=16 << 20, parse=None, public_aliases=()):
    row = reader.file(name, limit, parse)
    if expected is None:
        # Only fixed canonical preparation/configuration roles use this mode.
        expected = {"path": name, "size": row["file"]["size"], "sha256": row["file"]["sha256"],
                    "mode": row["file"]["mode"]}
    result = {"status": "observed", "file": public_file(row["file"], expected, selected=name, public_aliases=public_aliases)}
    if "data" in row:
        result["data"] = row["data"]
    return result


def source_documents(reader):
    provider_raw = reader.body(TOOLS / PROVIDER_FILE, 256 << 10)
    need(hashlib.sha256(provider_raw).hexdigest() == PROVIDER_SHA256, "profile-provider-source")
    providers = json.loads(provider_raw)
    need(len(providers["osLibraries"]) == 53 and len(providers["packages"]) == 51
         and len(providers["toolObjects"]) == 88 and providers["nativeSelectionProven"] is False
         and providers["symbolBindingProven"] is False, "profile-provider-source")
    policy = json.loads(reader.body(TOOLS / "android_material_data/policy.json", 256 << 10))
    raw = reader.body(TOOLS / "android_material_data/fonts.json", 128 << 10)
    need(hashlib.sha256(raw).hexdigest() == policy["documents"]["fonts.json"]["sha256"], "profile-font-source")
    fonts = json.loads(raw)
    need(len(fonts["fontFiles"]) == 53 and len(fonts["configurationFiles"]) == 35
         and len(fonts["directories"]) == 13, "profile-font-source")
    for name, row in fonts["providers"].items():
        actual = providers["osLibraries"].get(name, {})
        need(actual.get("file") == row["file"] and actual.get("package") == row["package"]
             and all(actual.get("elf", {}).get(key) == item for key, item in row["elf"].items()),
             "profile-font-provider-source")
    for name, row in fonts["consumers"].items():
        actual = providers["programs"].get(name, {})
        need(actual.get("file") == row["file"]
             and all(actual.get("elf", {}).get(key) == item for key, item in row["elf"].items()),
             "profile-font-consumer-source")
    return providers, fonts, policy


def snapshot_projection(snapshot):
    # The details (original IDs and complete host names) stay in memory only.
    return {"status": "observed", "suppliers": snapshot["suppliers"], "caches": snapshot["caches"],
            "cacheConsumerExecutionProven": False, "generatorExecutionProven": False}


def font_correspondence(reader, snapshot, fonts, material):
    reader.phase, reader.profile_subject = "font-snapshot", None
    need(snapshot is not None, "profile-snapshot-unavailable")
    for name, row in fonts["supplierRoots"].items():
        reader.phase, reader.profile_subject = "font-suppliers", name
        need(snapshot["suppliers"]["roots"][name] == row, "profile-font-suppliers")
    reader.phase, reader.profile_subject = "font-snapshot", None
    directories, entries = {}, {}
    for root, detail in snapshot["details"].items():
        directories.update(detail["directories"])
        for row in detail["entries"]:
            name = root if row["path"] == "." else root + "/" + row["path"]
            entries[name] = row
    for name, children in fonts["directories"].items():
        reader.phase, reader.profile_subject = "font-roster", name
        need(name in directories and directories[name]["children"] == children, "profile-font-roster")
    files = {}
    for name, expected in fonts["files"].items():
        reader.phase, reader.profile_subject = "font-file", name
        reader.point()
        row = entries.get(name, {})
        need(row.get("present") is True and row.get("kind") == "file"
             and {"path": row.get("canonical"), **{k: row.get(k) for k in ("size", "sha256", "mode")}} == expected,
             "profile-font-file")
        files[name] = expected
    configurations = {}
    public_aliases = {directory + "/" + child for directory, children in fonts["directories"].items() for child in children}
    public_aliases.update(row["path"] for row in fonts["files"].values())
    for name in fonts["configurationFiles"]:
        reader.phase, reader.profile_subject = "font-configuration", name
        row = observed_file(reader, name, fonts["files"][name], limit=64 << 10,
                            parse=material._font_config_io, public_aliases=public_aliases)
        configurations[name] = row["data"]
    reader.phase, reader.profile_subject = "font-local-configuration", "/etc/fonts/local.conf"
    absent = reader.bind("/etc/fonts/local.conf", absent=True, limit=64 << 10)
    need(absent.get("absent") is True, "profile-font-local-configuration")
    caches = {}
    for directory in material.FONT_DIRECTORIES:
        name = "/var/cache/fontconfig/" + hashlib.md5(directory.encode("ascii")).hexdigest() + "-le64.cache-9"
        reader.phase, reader.profile_subject = "font-cache", name
        row = entries.get(name, {})
        need(row.get("present") is True and row.get("kind") == "file" and row.get("canonical") == name,
             "profile-font-cache-version")
        caches[name] = {"directory": directory, **{key: row[key] for key in ("size", "sha256", "mode")}}
    def marker(raw):
        need(raw.startswith(b"Signature: 8a477f597d28d172789f06886806bc55\n")
             and all(not line or line.startswith(b"#") for line in raw.splitlines()[1:]), "profile-font-cache-marker")
        return {"standardCacheDirectory": True}
    name = "/var/cache/fontconfig/CACHEDIR.TAG"
    reader.phase, reader.profile_subject = "font-cache-marker", name
    row = entries[name]
    observed_file(reader, name, {"path": name, **{k: row[k] for k in ("size", "sha256", "mode")}}, limit=4096, parse=marker)
    return {"status": "observed", "files": files, "directories": fonts["directories"],
            "absences": fonts["absences"], "configurations": configurations, "caches": caches,
            "completeSourceRosterMatches": True, "freshFontConsumersRequired": True, "fontConsumersExecuted": False}


def loader_correspondence(reader, providers, lifecycle):
    names = sorted(set(providers["osLibraries"]) | set(providers["expectedGlobalAbsences"]))
    tiers, directories = {}, {}
    for directory in lifecycle.DEFAULT_LIBRARY_DIRS:
        reader.point()
        row = reader.bind(directory, directory_only=True)
        need(row["path"] in {"/usr/lib", "/usr/lib/x86_64-linux-gnu"}, "profile-loader-directory")
        directories[directory] = {"present": True, "canonical": row["path"]}
        for tier in lifecycle.HWCAPS:
            path = directory + "/glibc-hwcaps/" + tier
            row = reader.bind(path, directory_only=True, absent=True)
            tiers[path] = row.get("absent") is not True
            directories[path] = {"present": tiers[path]}
    alternatives = {}
    for soname, path in lifecycle.shell_loader_candidates(names, [], tiers):
        reader.point()
        row = reader.bind(path, absent=True, limit=16 << 20)
        if row.get("absent") is True:
            alternatives[path] = {"absent": True}
        else:
            need(soname not in providers["expectedGlobalAbsences"], "profile-global-absence")
            expected = providers["osLibraries"][soname]["file"]
            alternatives[path] = {"absent": False, "file": public_file(row, expected, selected=path,
                public_aliases=(expected["selectedPath"],))}
    need(len(directories) + len(alternatives) + 1 <= 1024, "profile-loader-alternatives-bound")
    row = reader.bind("/etc/ld.so.preload", absent=True, limit=64 << 10)
    need(row.get("absent") is True, "profile-loader-preload")
    # Actual cache decoding/list-diagnostics remains with the original native
    # paired consumers. No textual ldconfig output is invented from this hash.
    cache = observed_file(reader, "/etc/ld.so.cache", limit=2 << 20)
    configuration = observed_file(reader, "/etc/ld.so.conf", limit=64 << 10)
    before = reader.bind("/etc/ld.so.conf.d", directory_only=True)
    children = sorted(child.name for child in Path("/etc/ld.so.conf.d").iterdir())
    reader.point()
    public_names = {"libc.conf", "x86_64-linux-gnu.conf", "i386-linux-gnu.conf",
                    "fakeroot-x86_64-linux-gnu.conf", "zz_i386-biarch-compat.conf", "zz_x32-biarch-compat.conf"}
    need(len(children) <= 32 and set(children) <= public_names, "profile-loader-config-roster")
    configs = {}
    for name in children:
        path = "/etc/ld.so.conf.d/" + name
        # Names are public fixed package configuration, but their body is never
        # emitted and cannot authorize another candidate search location here.
        configs[path] = observed_file(reader, path, limit=64 << 10)["file"]
    need(reader.s.D.same(before, reader.bind("/etc/ld.so.conf.d", directory_only=True))
         and sorted(child.name for child in Path("/etc/ld.so.conf.d").iterdir()) == children,
         "profile-loader-config-changed")
    return {"status": "observed", "directories": directories, "alternatives": alternatives,
            "preloadAbsent": True, "cache": cache["file"], "configuration": configuration["file"],
            "configurationMembers": configs, "cacheDecoded": False,
            "freshOriginalProviderConsumersRequired": True, "providerConsumersExecuted": False}


def stock_correspondence(reader, trust_module):
    reader.phase, reader.profile_subject = "trust-policy", None
    policy = trust_module.Policy(reader.body(TOOLS / trust_module.POLICY_FILE, trust_module.POLICY_LIMIT))
    reader.phase, reader.profile_subject = "trust-custom", BASE.CUSTOM_CA_ROOT
    custom = reader.custom_ca()
    need(custom.get("status") == "empty", "profile-custom-ca-not-empty")
    components, files = {}, {}
    for name, limit, kind in BASE.TRUST_INPUTS:
        reader.phase, reader.profile_subject = "trust-" + kind, name
        row = observed_file(reader, name, limit=limit, parse=lambda raw, k=kind: getattr(policy, k)(raw, reader.point))
        components[kind], files[kind] = row["data"], row["file"]
    reader.phase, reader.profile_subject = "trust-complete", None
    complete = policy.complete(components, custom)
    reader.phase, reader.profile_subject = "trust-custom-post", BASE.CUSTOM_CA_ROOT
    need(reader.custom_ca() == custom, "profile-custom-ca-changed")
    return {"status": "observed", "policySha256": trust_module.POLICY_SHA256, "files": files,
            "correspondence": complete, "customCa": custom, "producerExecutionProven": False}


def package_correspondence(reader, providers, fonts):
    reader.phase, reader.profile_subject = "package-status", None
    package_names = sorted({name.split(":", 1)[0] for name in providers["packages"]} | set(EXTRA_PACKAGES))
    row = reader.file("/var/lib/dpkg/status", 24 << 20,
                      lambda raw: BASE.package_status(raw, packages=package_names))
    packages = row["data"]
    for expected in providers["packages"].values():
        name = expected["binaryPackage"].split(":", 1)[0]
        reader.phase, reader.profile_subject = "package-source", name
        fields = packages[name].get("fields", {})
        source = fields.get("Source", name)
        match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^()\s]+)\))?", source)
        need(match is not None and fields.get("Architecture") == expected["architecture"]
             and fields.get("Version") == expected["version"] and match[1] == expected["sourcePackage"]
             and (match[2] or fields["Version"]) == expected["sourceVersion"], "profile-package-correspondence")
    for name, row in packages.items():
        reader.phase, reader.profile_subject = "package-available", name
        need(row.get("status") == "observed", "profile-package-unavailable")
    wanted = {item["file"]["path"] for item in [*providers["osLibraries"].values(), *providers["programs"].values()]}
    wanted |= set(PREPARATION_PROGRAMS) | {row["path"] for row in fonts["files"].values()}
    wanted |= {"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/java/cacerts", "/etc/ca-certificates.conf"}
    membership = {}
    for package in package_names:
        reader.phase, reader.profile_subject = "package-members", package
        reader.point()
        candidates = ["/var/lib/dpkg/info/" + package + suffix for suffix in (".list", ":amd64.list")]
        present = []
        for path in candidates:
            original = reader.bind(path, absent=True, limit=512 << 10)
            if original.get("absent") is not True:
                observed = reader.file(path, 512 << 10, lambda raw: BASE.package_members(raw, wanted, digests=False))
                need(reader.s.D.same(original, {key: value for key, value in observed["file"].items()
                                               if key not in {"uid", "gid", "mode"}}), "profile-package-member-changed")
                present.append(observed["data"]["selectedMembers"])
        need(len(present) == 1, "profile-package-member-roster")
        membership[package] = sorted(present[0])
    # Membership is a separate witness, never a claim that dpkg/installer ran.
    for row in [*providers["osLibraries"].values(), *providers["programs"].values()]:
        reader.phase, reader.profile_subject = "package-provider", row["file"]["path"]
        need(row["file"]["path"] in membership[row["package"].split(":", 1)[0]], "profile-provider-package-membership")
    for name, package in PREPARATION_PACKAGES.items():
        reader.phase, reader.profile_subject = "package-preparation", name
        need(name in membership[package], "profile-preparation-package-membership")
    font_packages = {name for name in package_names if name.startswith("fonts-") or name == "fontconfig-config"}
    for row in fonts["files"].values():
        reader.phase, reader.profile_subject = "package-font", row["path"]
        need(row["path"] in {path for package in font_packages for path in membership[package]}, "profile-font-package-membership")
    public_packages = {}
    for name, row in packages.items():
        reader.phase, reader.profile_subject = "package-identity", name
        fields = row["fields"]
        source = re.fullmatch(r"([a-z0-9][a-z0-9+.-]{0,127})(?: \(([^()\s]{1,128})\))?", fields.get("Source", name))
        version = fields.get("Version", "")
        need(source is not None and fields.get("Package") == name
             and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]{0,127}", version)
             and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]{0,127}", source[2] or version), "profile-package-public-identity")
        public_packages[name] = {"status": "observed", "package": name, "architecture": fields["Architecture"],
            "version": version, "sourcePackage": source[1], "sourceVersion": source[2] or version}
    return {"status": "observed", "packages": public_packages, "selectedMembership": membership,
            "packageAuthenticityEstablished": False, "packageCommandExecuted": False}


def public_preparation_elf(value, expected=None):
    """Only ordinary fixed-role ELF ABI labels, never embedded private paths."""
    fields = {"interpreter", "needed", "soname", "versionNeeds", "versionDefinitions", "rpath", "runpath"}
    need(type(value) is dict and set(value) == fields
         and value["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
         and value["soname"] is None and value["rpath"] is None and value["runpath"] is None
         and value["versionDefinitions"] == [], "profile-preparation-elf-role")
    if expected is not None:
        need(value == {**expected, "rpath": None, "runpath": None}, "profile-preparation-elf-source")
    else:
        names, versions = value["needed"], value["versionNeeds"]
        need(type(names) is list and 1 <= len(names) <= 32 and len(set(names)) == len(names)
             and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_+.-]{0,191}", name)
                     and ".so" in name for name in names)
             and type(versions) is dict and set(versions) <= set(names), "profile-preparation-elf-names")
        labels = []
        for provider, values in versions.items():
            need(type(values) is list and 1 <= len(values) <= 64, "profile-preparation-elf-labels")
            labels.extend((provider, label) for label in values)
        need(len(labels) <= 128 and all(type(label) is str and len(label) <= 96
             and (re.fullmatch(r"(?:GLIBC|GLIBCXX|CXXABI|CURL_OPENSSL|LIBCURL_OPENSSL|LIBLZMA|LIBMD|"
                               r"NCURSES6_TINFO|ZLIB|OPENSSL|LIBXML2)_[0-9]{1,8}(?:\.[0-9]{1,8}){0,5}", label)
                  or provider == "liblzma.so.5" and label in PREPARATION_XZ_LABELS)
             for provider, label in labels), "profile-preparation-elf-labels")
    return value


def preparation_file(reader, name, fonts):
    reader.phase, reader.profile_subject = "preparation-file", name
    known = fonts["consumers"].get(name)
    def parse(raw):
        reader.phase = "preparation-elf"
        result = public_preparation_elf(reader.s.elf_dependencies(raw, android_data=True),
                                        None if known is None else known["elf"])
        reader.phase = "preparation-file"
        return result
    row = observed_file(reader, name, None if known is None else known["file"], parse=parse)
    row["elfSourceCorrespondence"] = known is not None
    row["freshNativeConsumerRequired"] = True
    return row


def prospective_rules(policy, material, hosted, deadline):
    configs = {name: {"status": "prospective-source-rule", "consumed": False,
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "configuration": material._network_configuration_data(name, raw, deadline)} for name, raw in hosted.CONFIGURATION.items()}
    source_inputs = None
    if hosted.selected(policy):
        source_inputs = hosted.rule(material, policy)["provisioning"]["sourceInputs"]
    sdk = {hosted.SOURCE_SDK + "/" + name: {"status": "prospective-source-rule", "consumed": False,
        "limit": limits[0], "pin": None if source_inputs is None else source_inputs[hosted.SOURCE_SDK + "/" + name]}
        for name, limits in hosted.SOURCE_INPUTS.items()}
    return {"configuration": configs, "sdk": sdk, "sdkSourcePinsIndependentlyAdmitted": source_inputs is not None,
            "observedOrConsumed": False, "newConsent": False}


def collect(reader, run, providers, fonts, policy, *, lifecycle, material, hosted, trust):
    observations, snapshot = {}, None
    record = {"schema": SCHEMA, "run": run, "observations": observations,
              "prospective": prospective_rules(policy, material, hosted, reader.deadline), "firstFailure": None, "stopped": None,
              "runtimeAdmission": False, "nativeQualification": False, "newConsent": False,
              "collectionComplete": False, "profileActivated": False, "observationComplete": False,
              "requiredNativeConsumers": ["fc-cat", "fc-list", "ld-linux-list-diagnostics", "ldconfig-p"],
              "readLimitBytes": READ_LIMIT, "snapshotCanonicalLimitBytes": 512 << 20}

    def attempt(name, action):
        reader.phase, reader.profile_subject = "observation", None
        try:
            reader.point()
            value = action()
            reader.point()
            observations[name] = value
            need(len(reader.s.D.canonical(record)) <= OUTPUT_LIMIT - (64 << 10), "profile-output-bound")
            return value
        except BASE.Stopped as error:
            label = error.args[0] if error.args and error.args[0] in {"read-budget", "deadline", "action-deadline"} else "resource-limit"
            observations[name] = {"status": "unavailable", "reason": label,
                                  **failure_detail(reader, error, name, providers, fonts)}
            record["stopped"] = label
            record["firstFailure"] = record["firstFailure"] or {"role": name, "reason": label}
            raise
        except (OSError, ValueError, UnicodeError, KeyError, RecursionError) as error:
            label = BASE.reason(error)
            observations[name] = {"status": "unavailable", "reason": label,
                                  **failure_detail(reader, error, name, providers, fonts)}
            record["firstFailure"] = record["firstFailure"] or {"role": name, "reason": label}
            return None

    try:
        def image():
            value = observed_file(reader, BASE.IMAGE_DATA, limit=64 << 10, parse=BASE.image_identity)
            need(value["data"]["identity"] == material.SDK_IMAGE, "profile-image-correspondence")
            return value
        if attempt("image", image) is None:
            record["stopped"] = "image-unavailable"
            record["collectionChargedReadBytes"] = READ_LIMIT - reader.remaining
            return record
        def data_snapshot():
            nonlocal snapshot
            snapshot = lifecycle.shell_data_snapshot(reader.bind, body_reader=reader.body)
            return snapshot_projection(snapshot)
        attempt("shellData", data_snapshot)
        for name, row in providers["osLibraries"].items():
            attempt("provider:" + name, lambda r=row: observed_file(reader, r["file"]["selectedPath"], r["file"]))
        for name, row in providers["programs"].items():
            attempt("program:" + name, lambda r=row: observed_file(reader, r["file"]["selectedPath"], r["file"]))
        for name in PREPARATION_PROGRAMS:
            attempt("preparation:" + name, lambda n=name: preparation_file(reader, n, fonts))
        for label in ("loader", "ldconfig"):
            row = providers[label]
            attempt(label, lambda r=row: observed_file(reader, r["selectedPath"], r))
        attempt("loaderAlternatives", lambda: loader_correspondence(reader, providers, lifecycle))
        attempt("fonts", lambda: font_correspondence(reader, snapshot, fonts, material))
        attempt("stockTrust", lambda: stock_correspondence(reader, trust))
        for name, expected in NETWORK_CONFIGURATION.items():
            def network(n=name, e=expected):
                row = observed_file(reader, n, limit=material.CONFIGURATION_LIMIT,
                                    parse=lambda raw: material._network_configuration_data(n, raw, reader.deadline))
                need(row["data"] == e, "profile-network-source-correspondence")
                return row
            attempt("configuration:" + name, network)
        attempt("packages", lambda: package_correspondence(reader, providers, fonts))
        record["collectionComplete"] = record["observationComplete"] = record["firstFailure"] is None
    except BASE.Stopped as error:
        label = error.args[0] if error.args and error.args[0] in {"read-budget", "deadline", "action-deadline"} else "resource-limit"
        record["stopped"] = record["stopped"] or label
        record["firstFailure"] = record["firstFailure"] or {"role": "collection", "reason": label}
    record["collectionChargedReadBytes"] = READ_LIMIT - reader.remaining
    return record


def main():
    started = time.monotonic()
    work_end, action_end = started + WORK_SECONDS, started + ACTION_SECONDS
    previous = None
    try:
        need(sys.argv[1:] == [] and sys.platform == "linux" and os.uname().machine == "x86_64"
             and sys.version_info[:2] == (3, 12) and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1
             and os.getresuid()[0] > 0 and os.getresgid()[0] > 0
             and len(set(os.getresuid())) == len(set(os.getresgid())) == 1, "profile-isolated-context")
        def expired(_signal, _frame):
            raise BASE.Stopped("deadline" if time.monotonic() < action_end else "action-deadline")
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "profile-preexisting-timer")
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, work_end - time.monotonic()))
        python = local("observe_hosted_python")
        need(sys.executable == python.PATH, "profile-original-python")
        run = BASE.context(os.environ, python.context)
        need(run.get("ImageOS") == "ubuntu24" and run.get("ImageVersion") == "20260920.314.1", "profile-image-context")
        publisher, lifecycle = local("ci_ubuntu_publication"), local("ubuntu_publication_lifecycle")
        material, hosted, trust = local("android_material_preparation"), local("android_hosted_data"), local("stock_trust_correspondence")
        reader = Reader(publisher, work_end)
        root, original = reader.output_root(run)
        before = [reader.source(path) for path in SOURCE_FILES]
        need(sum(row[0]["size"] for row in before) + 2 * OUTPUT_LIMIT + (512 << 10) < FINAL_READ_RESERVE,
             "profile-final-read-reserve")
        reader.final_reserve = FINAL_READ_RESERVE
        providers, fonts, policy = source_documents(reader)
        record = collect(reader, run, providers, fonts, policy, lifecycle=lifecycle, material=material, hosted=hosted, trust=trust)
        # Fixed original complete-action endpoint, not a new phase clock or new
        # read allowance. This reserve was withheld from work in the SAME ledger.
        reader.final_reserve, reader.deadline = 0, action_end
        signal.setitimer(signal.ITIMER_REAL, max(0.001, action_end - time.monotonic()))
        after = [reader.source(path) for path in SOURCE_FILES]
        need(before == after, "profile-source-post")
        record["sourceFiles"] = [row[0] for row in before]
        record["sourcePrePostMatched"] = True
        record["chargedReadBytesBeforeOutput"] = READ_LIMIT - reader.remaining
        raw = publisher.D.canonical(record)
        need(len(raw) <= OUTPUT_LIMIT, "profile-output-bound")
        # Preserve BOTH output readbacks, now unbuffered/exactly counted.
        # The same ledger reserves both bodies plus one growth byte each.
        # A failed write/readback retains the entire reservation.
        def publish(bound):
            need(bound == 2 * len(raw), "profile-output-read-reservation")
            return reader.write(root / OUTPUT_NAME, raw), 2 * len(raw)
        reader.charged(2 * len(raw), publish, overread=2)
        need(publisher.directory_identity(root) == original, "profile-output-root")
        reader.point()
        print("MRK-ANDROID-HOST-PROFILE-DATA " + json.dumps({"schema": SCHEMA, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "observationComplete": record["observationComplete"],
            "runtimeAdmission": False, "nativeQualification": False,
            "chargedReadBytesIncludingFinality": READ_LIMIT - reader.remaining}, sort_keys=True, separators=(",", ":")), flush=True)
        if not record["observationComplete"]:
            raise SystemExit(70)
    except SystemExit:
        raise
    except BaseException:
        print("MRK-ANDROID-HOST-PROFILE-REFUSED context-source-or-output", file=sys.stderr, flush=True)
        raise SystemExit(70)
    finally:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    main()
