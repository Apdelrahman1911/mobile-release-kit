"""Finite public hosted prerequisites, not Android admission or licence consent.

This metadata-only entry never invokes a tool or opens a network connection.
It reuses protected OS readers; missing facts stay missing. Producer execution
and a later VM's generated inputs require their own reviewed correspondence.
"""
from __future__ import annotations

import hashlib
import importlib.util
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

TOOLS = Path(__file__).absolute().parent
METADATA_REF = "refs/heads/verify/desktop-shell-host-metadata"
SCHEMA = "mrk-hosted-android-prerequisite-data-v1"
OUTPUT_NAME = "android-host-materials.json"
OUTPUT_LIMIT = 1 << 20
READ_LIMIT = 192 << 20
# Separate conservative ceiling of the existing G observer: two512MiB nft
# streaming reads, three32MiB package reads, and all small fixed/proc inputs.
# These are existing limits, not permission to acquire a binary or open a tool.
GITHUB_READ_LIMIT = 1152 << 20
SECONDS = 45
MAX_CA_FILES = 512
CA_ROOT = "/usr/share/ca-certificates"
CUSTOM_CA_ROOT = "/usr/local/share/ca-certificates"
SDK_LICENSE = "/usr/local/lib/android/sdk/licenses/android-sdk-license"
IMAGE_DATA = "/imagegeneration/imagedata.json"
HELPERS = ("echo", "sed", "tr", "uname", "xargs")
PROVIDERS = ("libacl.so.1", "libasound.so.2", "libgif.so.7", "libpcsclite.so.1")
PROGRAMS = (*("/usr/bin/" + name for name in HELPERS),
            "/usr/bin/curl", "/usr/bin/bash", "/usr/bin/dpkg-deb", "/usr/bin/python3.12",
            "/usr/bin/fc-list", "/usr/bin/fc-cat")
PRODUCERS = (
    "/usr/sbin/update-ca-certificates",
    "/etc/ca-certificates/update.d/jks-keystore",
    "/usr/share/ca-certificates-java/ca-certificates-java.jar",
    "/var/lib/dpkg/info/ca-certificates.postinst",
    "/var/lib/dpkg/info/ca-certificates-java.postinst",
)
PACKAGES = ("coreutils", "sed", "findutils", "libacl1", "libasound2t64", "libgif7",
            "libpcsclite1", "curl", "bash", "dpkg", "python3.12",
            "ca-certificates", "ca-certificates-java", "openjdk-17-jre-headless",
            "fontconfig", "fontconfig-config", "libfontconfig1")
SOURCE_FILES = ("observe_hosted_android.py", "observe_hosted_python.py",
                "ci_ubuntu_publication.py", "ci_foundation.py", "conventional_runtime_data.py",
                "ubuntu_publication_lifecycle.py", "hosted_glibc_policy.py")


class Refused(ValueError):
    pass


class Stopped(Refused):
    """An aggregate limit stops all subsequent observations, not just one row."""


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def local(name):
    need(name in {"ci_ubuntu_publication", "observe_hosted_python"}, "module-role")
    spec = importlib.util.spec_from_file_location("_host_android_" + name, TOOLS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context(env, python_context):
    need((env.get("GITHUB_REF"), env.get("MRK_INSTALLED_SHELL_CASE"), env.get("GITHUB_JOB"),
          env.get("GITHUB_RUN_ATTEMPT")) == (METADATA_REF, "host-metadata-only", "compile", "1"),
         "metadata-only-route")
    return python_context(env)


def reason(error):
    if isinstance(error, FileNotFoundError):
        return "absent"
    if isinstance(error, PermissionError):
        return "permission-denied"
    if isinstance(error, OSError):
        return "read-or-close-error"
    return "invalid-or-changed"


def diagnostic_reason(error):
    """Finite public labels only; never reflect exception text or path values."""
    fixed = {
        "parsed-body-correspondence", "parsed-original-changed", "original-owner-changed",
        "original-binding-changed", "supplier-directory-role", "supplier-directory-type",
        "supplier-directory-owner", "supplier-directory-permissions", "supplier-directory-open-changed",
        "supplier-directory-post-changed", "supplier-file-role", "supplier-file-type",
        "supplier-file-owner", "supplier-file-permissions", "supplier-file-links", "supplier-file-bound",
        "supplier-file-open-changed", "supplier-file-grew", "supplier-file-short", "supplier-file-post-changed",
        "public-directory-roster", "supplier-ca-root", "supplier-ca-directory", "supplier-ca-member",
        "supplier-ca-roster-changed", "receipt-format", "receipt-roster", "image-duplicate", "image-object",
        "image-field", "image-origin-url", "image-public-label", "image-known-fields-missing",
    }
    shared = {
        "Absolute native OS input required": "file-path",
        "Unprotected native OS root": "file-ancestry",
        "Native OS input link/ancestry bound": "file-ancestry-bound",
        "Native OS input has a nonroot owner": "file-owner",
        "Native OS input link changed/exceeded bound": "file-link",
        "Native OS input has nonordinary/writable/special ancestry": "file-ancestry",
        "Resolved native OS input differs": "file-binding",
        "Native OS input is not an ordinary file": "file-type-or-links",
        "Native OS ancestry changed while reading": "file-ancestry-changed",
        "Native OS link changed while reading": "file-link-changed",
        "Native OS input binding changed": "file-binding-changed",
    }
    value = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
    if isinstance(error, ValueError):
        if value in fixed:
            return value
        if value in shared:
            return shared[value]
    return reason(error)


class Reader:
    """Accounting for this finite observation only; not a new command owner."""

    def __init__(self, publisher, deadline):
        self.s = publisher
        self.deadline = deadline
        self.remaining = READ_LIMIT
        self.phase = "observation"

    def point(self):
        if time.monotonic() >= self.deadline:
            raise Stopped("deadline")
        if self.remaining <= 0:
            raise Stopped("read-budget")

    def charged(self, limit, action, *, overread=64 << 10):
        self.point()
        # Existing readers may consume one bounded final block before detecting
        # growth. Reserve that block even when the read raises and reports no
        # count; a failed observation cannot silently refund unknown I/O.
        if self.remaining <= overread:
            raise Stopped("read-budget")
        bound = min(limit, self.remaining - overread)
        reserved = bound + overread
        self.remaining -= reserved
        value, consumed = action(bound)
        need(type(consumed) is int and 0 <= consumed <= bound, "read-accounting")
        self.remaining += reserved - consumed
        self.point()
        return value

    def file(self, name, limit, parse=None):
        # All callers supply a fixed path or a bounded public distro CA member.
        self.phase = "file-bind"
        before = self.charged(limit, lambda bound: self._record(name, bound))
        result = {"status": "observed", "file": before}
        if parse is not None:
            self.phase = "file-body"
            raw = self.charged(limit, lambda bound: self._body(before["path"], bound), overread=1)
            need(len(raw) == before["size"] and hashlib.sha256(raw).hexdigest() == before["sha256"],
                 "parsed-body-correspondence")
            self.phase = "file-parse"
            result["data"] = parse(raw)
            self.phase = "file-rebind"
            after = self.charged(limit, lambda bound: self._record(name, bound))
            need(self.s.D.same(before, after), "parsed-original-changed")
        return result

    def _record(self, name, bound):
        row = self.s.protected_host_file(Path(name), bound)
        item = Path(row["path"]).lstat()
        need(item.st_uid == item.st_gid == 0, "original-owner-changed")
        need(list(self.s.D.state(item)) == row["identity"], "original-binding-changed")
        return {**row, "uid": 0, "gid": 0, "mode": stat.S_IMODE(item.st_mode)}, row["size"]

    def _body(self, name, bound):
        raw = self.s.D.read(Path(name), bound)
        return raw, len(raw)

    @contextmanager
    def ca_namespace(self, name):
        """Supplier-only ordinary directories: never follow an alias to custom CA data."""
        need(name in (CA_ROOT, CA_ROOT + "/mozilla"), "supplier-directory-role")
        self.point()
        originals, ancestry, parent, full = [], {}, None, Path("/")
        with ExitStack() as closes:
            for part in ("/", *Path(name).parts[1:]):
                before = os.stat(part, dir_fd=parent, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode), "supplier-directory-type")
                need(before.st_uid == before.st_gid == 0, "supplier-directory-owner")
                need(not before.st_mode & 0o7022, "supplier-directory-permissions")
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
                try:
                    closes.callback(os.close, fd)
                except BaseException:
                    os.close(fd)
                    raise
                stamp = (*self.s.D.state(before), before.st_uid, before.st_gid)
                current = os.fstat(fd)
                need((*self.s.D.state(current), current.st_uid, current.st_gid) == stamp,
                     "supplier-directory-open-changed")
                originals.append((part, parent, fd, stamp))
                full = full / part
                ancestry[str(full)] = [before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid]
                parent = fd
            binding = {"path": name, "selectedPath": name, "links": [], "ancestry": ancestry,
                       "directory": ancestry[name]}
            try:
                yield parent, binding, closes
            finally:
                for part, parent, fd, stamp in reversed(originals):
                    for current in (os.fstat(fd), os.stat(part, dir_fd=parent, follow_symlinks=False)):
                        need((*self.s.D.state(current), current.st_uid, current.st_gid) == stamp,
                             "supplier-directory-post-changed")
        self.point()

    def ca_file(self, name):
        path = Path(name)
        need(str(path.parent) == CA_ROOT + "/mozilla"
             and re.fullmatch(r"[A-Za-z0-9_.+-]{1,156}\.crt", path.name), "supplier-file-role")
        def observe(bound):
            with self.ca_namespace(str(path.parent)) as (parent, binding, closes):
                before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need(stat.S_ISREG(before.st_mode), "supplier-file-type")
                need(before.st_uid == before.st_gid == 0, "supplier-file-owner")
                need(not before.st_mode & 0o7022, "supplier-file-permissions")
                need(before.st_nlink == 1, "supplier-file-links")
                need(0 < before.st_size <= bound, "supplier-file-bound")
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=parent)
                try:
                    closes.callback(os.close, fd)
                except BaseException:
                    os.close(fd)
                    raise
                original = (*self.s.D.state(before), before.st_uid, before.st_gid)
                current = os.fstat(fd)
                need((*self.s.D.state(current), current.st_uid, current.st_gid) == original,
                     "supplier-file-open-changed")
                hashed, count = hashlib.sha256(), 0
                while True:
                    self.point()
                    block = os.read(fd, min(64 << 10, before.st_size - count + 1))
                    if not block:
                        break
                    count += len(block)
                    need(count <= before.st_size, "supplier-file-grew")
                    hashed.update(block)
                need(count == before.st_size, "supplier-file-short")
                for current in (os.fstat(fd), os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
                    need((*self.s.D.state(current), current.st_uid, current.st_gid) == original,
                         "supplier-file-post-changed")
                row = {"path": name, "selectedPath": name, "size": count, "sha256": hashed.hexdigest(),
                       "identity": list(self.s.D.state(before)), "links": [], "ancestry": binding["ancestry"],
                       "uid": 0, "gid": 0, "mode": stat.S_IMODE(before.st_mode)}
            return {"status": "observed", "file": row}, count
        return self.charged(64 << 10, observe)

    def directory(self, name, *, custom=False):
        self.point()
        if not custom and name in (CA_ROOT, CA_ROOT + "/mozilla"):
            with self.ca_namespace(name) as (fd, binding, _):
                names = []
                with os.scandir(fd) as entries:
                    for entry in entries:
                        self.point()
                        need(len(names) < MAX_CA_FILES and re.fullmatch(r"[A-Za-z0-9_.+-]{1,160}", entry.name),
                             "public-directory-roster")
                        names.append(entry.name)
            return {"status": "observed", "directory": binding, "names": sorted(names)}
        need(custom and name == CUSTOM_CA_ROOT, "custom-directory-role")
        before = self.s.shell_host_binding(Path(name), directory_only=True, absent=True)
        if before.get("absent"):
            return {"status": "absent"}
        selected = Path(before["path"])
        fd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            original = os.fstat(fd)
            need([original.st_dev, original.st_ino, original.st_mode, original.st_uid, original.st_gid]
                 == before["directory"], "directory-open-changed")
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.point()
                    # Do not retain/export even one custom name or read its body.
                    names.append(None)
                    break
            need(self.s.D.state(os.fstat(fd)) == self.s.D.state(original)
                 and self.s.D.state(selected.lstat()) == self.s.D.state(original)
                 and self.s.D.same(self.s.shell_host_binding(Path(name), directory_only=True), before),
                 "directory-read-changed")
        finally:
            os.close(fd)
        self.point()
        return {"status": "nonempty" if names else "empty",
                "customBodiesRead": False, "customNamesExported": False}


def license_ids(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096
         and re.fullmatch(rb"\n?(?:[0-9a-f]{40}\n)*[0-9a-f]{40}\n?", raw), "receipt-format")
    ids = raw.decode("ascii").strip("\n").split("\n")
    need(len(ids) == len(set(ids)) and len(ids) <= 64, "receipt-roster")
    return {"existingIds": ids, "originProven": False, "newConsent": False}


def image_identity(raw):
    # Do not reflect arbitrary JSON from even this public metadata file.
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "image-duplicate")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict, "image-object")
    result = {}
    for key in ("image_version", "image_name", "os_name", "os_version", "image_url", "image_release"):
        if key not in value:
            continue
        item = value[key]
        need(type(item) is str and 0 < len(item) <= 512 and item.isascii()
             and all(32 <= ord(c) < 127 for c in item), "image-field")
        if key in {"image_url", "image_release"}:
            need(re.fullmatch(r"https://github\.com/actions/runner-images/[A-Za-z0-9_.\-/]+", item),
                 "image-origin-url")
        else:
            need(re.fullmatch(r"[A-Za-z0-9 ._()+\-/]+", item), "image-public-label")
        result[key] = item
    need(result, "image-known-fields-missing")
    return {"identity": result, "producerExecutionProven": False}


def package_status(raw):
    result = {name: {"status": "absent"} for name in PACKAGES}
    seen = set()
    for paragraph in raw.decode("utf-8").split("\n\n"):
        lines = paragraph.splitlines()
        names = [line[9:] for line in lines if line.startswith("Package: ")]
        if len(names) != 1 or names[0] not in result:
            continue
        name = names[0]
        need(name not in seen, "package-duplicate")
        seen.add(name)
        fields = {}
        for line in lines:
            key, separator, value = line.partition(": ")
            if separator and key in {"Package", "Status", "Version", "Architecture", "Source", "Depends"}:
                need(key not in fields and 0 < len(value) <= 2048 and value.isascii()
                     and all(32 <= ord(c) < 127 for c in value), "package-field")
                fields[key] = value
        need(fields.get("Status") == "install ok installed" and fields.get("Architecture") in {"amd64", "all"}
             and "Version" in fields, "package-not-installed")
        result[name] = {"status": "observed", "fields": fields}
    return result


def supplier_cas(reader):
    reader.phase = "ca-root"
    root = reader.directory(CA_ROOT)
    need(root["status"] == "observed" and root["names"] == ["mozilla"], "supplier-ca-root")
    reader.phase = "ca-mozilla"
    directory = reader.directory(CA_ROOT + "/mozilla")
    need(directory["status"] == "observed" and directory["names"], "supplier-ca-directory")
    rows = []
    for name in directory["names"]:
        reader.phase = "ca-member"
        need(name.endswith(".crt"), "supplier-ca-member")
        rows.append(reader.ca_file(CA_ROOT + "/mozilla/" + name))
    reader.phase = "ca-final"
    need(reader.s.D.same(reader.directory(CA_ROOT), root)
         and reader.s.D.same(reader.directory(CA_ROOT + "/mozilla"), directory), "supplier-ca-roster-changed")
    return {"status": "observed", "root": root, "directory": directory, "files": rows,
            "certificateBodiesExported": False}


def package_members(raw, wanted, *, digests):
    """Only names already observed at the fixed public inputs may be exported."""
    result = {}
    for line in raw.decode("utf-8").splitlines():
        if digests:
            match = re.fullmatch(r"([0-9a-f]{32})  (.+)", line)
            need(match is not None, "package-digest-format")
            digest, name = match.groups()
            name = "/" + name
        else:
            name, digest = line, None
        if name in wanted:
            need(name not in result, "package-member-duplicate")
            result[name] = digest
    return {"selectedMembers": result, "packageAuthenticityEstablished": False}


def selected_input_paths(observations):
    """Only fixed public inputs and the bounded supplier CA roster, not errors."""
    files = [row["file"] for name, row in observations.items()
             if not name.startswith("/var/lib/dpkg/info/") and row.get("status") == "observed"
             and "file" in row]
    ca = observations.get("supplierCaInputs", {})
    if ca.get("status") == "observed":
        files.extend(row["file"] for row in ca["files"])
    return {path for row in files for path in (row["path"], row["selectedPath"])}


def github_materials(publisher, reader):
    # Reuse the already reviewed, command-free collector without changing its
    # limits, policy or globals. It is not subject to Android's separate counter.
    reader.point()
    lifecycle = publisher.local("ubuntu_publication_lifecycle")
    need(lifecycle.FILE_LIMIT == 512 << 20 and len(lifecycle.SHELL_GITHUB_BOUNDARY_INPUTS) == 12,
         "shared-collector-read-envelope")
    value = lifecycle.shell_github_boundary_host_materials()
    reader.point()
    return value


def collect(publisher, run, deadline):
    reader = Reader(publisher, deadline)
    observations = {}
    record = {"schema": SCHEMA, "run": run, "runtimeAdmission": False, "nativeQualification": False,
              "newConsent": False, "collectionComplete": False, "producerOriginProven": False,
              "observations": observations, "stopped": None,
              "readBounds": {"android": READ_LIMIT, "github": GITHUB_READ_LIMIT,
                             "combined": READ_LIMIT + GITHUB_READ_LIMIT},
              "remainingWork": ["review-target-provider-and-configuration-correspondence",
                                "validate-same-vm-generated-input-producers",
                                "establish-hosted-sdk-receipt-origin",
                                "review-static-policy-before-any-admission"]}
    tasks = []
    for name in PROGRAMS:
        tasks.append((name, lambda n=name: reader.file(n, 16 << 20,
                      lambda raw: publisher.shell_elf_record(raw, role="program", selected=n))))
    for name in PROVIDERS:
        path = "/usr/lib/x86_64-linux-gnu/" + name
        tasks.append((path, lambda p=path: reader.file(p, 8 << 20,
                      lambda raw: publisher.shell_elf_record(raw, role="provider", selected=p))))
    for name in PRODUCERS:
        tasks.append((name, lambda n=name: reader.file(n, 2 << 20)))
    for name, bound in (("/etc/ssl/certs/ca-certificates.crt", 4 << 20),
                        ("/etc/ssl/certs/java/cacerts", 8 << 20),
                        ("/etc/ca-certificates.conf", 256 << 10)):
        tasks.append((name, lambda n=name, b=bound: reader.file(n, b)))
    tasks.extend([
        ("selectedPackages", lambda: reader.file("/var/lib/dpkg/status", 24 << 20, package_status)),
        ("supplierCaInputs", lambda: supplier_cas(reader)),
        ("customCaInputs", lambda: reader.directory(CUSTOM_CA_ROOT, custom=True)),
        ("sdkLicense", lambda: reader.file(SDK_LICENSE, 4096, license_ids)),
        ("imageGeneration", lambda: reader.file(IMAGE_DATA, 64 << 10, image_identity)),
    ])
    # Exact list/metadata DATA provides a package-membership witness without a
    # dpkg/ldd/readelf invocation. Both literal architecture spellings are bounded;
    # unavailable alternatives do not become successful package correspondence.
    for package in PACKAGES:
        for suffix in (".list", ":amd64.list", ".md5sums", ":amd64.md5sums"):
            path = "/var/lib/dpkg/info/" + package + suffix
            tasks.append((path, lambda p=path, d=suffix.endswith("md5sums"): reader.file(p, 512 << 10,
                lambda raw: package_members(raw, selected_input_paths(observations), digests=d))))
    tasks.append(("githubNormalBoundary", lambda: github_materials(publisher, reader)))
    observations.update({name: {"status": "not-observed"} for name, _ in tasks})
    need(len(observations) == len(tasks) <= 128, "observation-roster")
    for name, action in tasks:
        reader.phase = "observation"
        try:
            reader.point()
            row = action()
            reader.point()
            # Admission is deliberately impossible in this observer. The shared
            # GitHub collector retains its own strict failure list and false flags.
            if name == "githubNormalBoundary":
                need(row.get("qualified") is False and row.get("runtimeSelfAdmission") is False
                     and row.get("nftExecuted") is False and row.get("dnsQueryIssued") is False,
                     "boundary-data-only")
                row = {"status": "observed", "data": row}
            prospective = {**record, "observations": {**observations, name: row}}
            if len(publisher.D.canonical(prospective)) > OUTPUT_LIMIT - 4096:
                raise Stopped("output-budget")
            observations[name] = row
        except Stopped as error:
            record["stopped"] = error.args[0]
            observations[name] = {"status": "unavailable", "reason": error.args[0]}
            if name in {"supplierCaInputs", "sdkLicense", "imageGeneration"}:
                observations[name].update(phase=reader.phase, refusal=error.args[0])
            break
        except (OSError, ValueError, UnicodeError, KeyError, RecursionError) as error:
            observations[name] = {"status": "unavailable", "reason": reason(error)}
            if name in {"supplierCaInputs", "sdkLicense", "imageGeneration"}:
                observations[name].update(phase=reader.phase, refusal=diagnostic_reason(error))
    record["androidChargedReadBytes"] = READ_LIMIT - reader.remaining
    return record


def main():
    try:
        started = time.monotonic()
        python = local("observe_hosted_python")
        run = context(os.environ, python.context)
        need(sys.argv[1:] == [] and sys.platform == "linux" and os.uname().machine == "x86_64"
             and sys.version_info[:2] == (3, 12) and os.path.realpath(sys.executable) == python.PATH
             and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1
             and os.getresuid()[0] > 0 and os.getresgid()[0] > 0
             and len(set(os.getresuid())) == len(set(os.getresgid())) == 1,
             "isolated-original-interpreter")
        publisher = local("ci_ubuntu_publication")
        root = publisher.shell_tools_input_root()
        original = publisher.directory_identity(root)
        source = [{**publisher.D.file_record(TOOLS / name, 2 << 20), "path": "desktop/tools/" + name}
                  for name in SOURCE_FILES]
        record = collect(publisher, run, started + SECONDS)
        after = [{**publisher.D.file_record(TOOLS / name, 2 << 20), "path": "desktop/tools/" + name}
                 for name in SOURCE_FILES]
        need(publisher.D.same(source, after), "collector-source-changed")
        record["sourceFiles"] = source
        raw = publisher.D.canonical(record)
        need(len(raw) <= OUTPUT_LIMIT, "output-bound")
        need(time.monotonic() < started + 60, "output-deadline")
        publisher.D.write(root / OUTPUT_NAME, raw)
        need(publisher.D.read(root / OUTPUT_NAME, OUTPUT_LIMIT) == raw
             and publisher.directory_identity(root) == original
             and time.monotonic() < started + 60, "output-original-readback")
        print("MRK-HOSTED-ANDROID-DATA " + json.dumps({"schema": SCHEMA, "size": len(raw),
              "sha256": hashlib.sha256(raw).hexdigest(), "runtimeAdmission": False,
              "nativeQualification": False, "collectionComplete": False, "stopped": record["stopped"]},
              sort_keys=True, separators=(",", ":")), flush=True)
        if record["stopped"] is not None:
            raise SystemExit(70)
    except SystemExit:
        raise
    except BaseException:
        print("MRK-HOSTED-ANDROID-REFUSED context-source-or-output", file=sys.stderr, flush=True)
        raise SystemExit(70)


if __name__ == "__main__":
    main()
