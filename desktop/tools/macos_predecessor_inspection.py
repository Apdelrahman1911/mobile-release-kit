#!/usr/bin/env python3
"""One delivered ARM DMG -> public descriptor DATA. Never install or run its code.

This is not P0 enrollment, signature verification, or a generic package reader.
The three entry points are only for the fixed dispatch job in candidate-consume.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-predecessor-inspection"
SOURCE = "bf9d397bde641aae4b4cd205f3c962e899557650"
TREE = "f3d2f9117d1f29e080c5138fa9675426fb79e247"
RUN, ATTEMPT, ARTIFACT = "39179866174", "1", "12157830080"
TARGET = "aarch64-apple-darwin"
ZIP_BYTES = 110520583
ZIP_SHA = "4216ed3bdaed64fc3cd94f84571ecdecd4d854dee0314c48ac3a52f5f444a5a7"
IMAGE_BYTES = 110513802
IMAGE_SHA = "d8d7af6e1d0d336c43937ab18a76af200ff9a5c4078e22df8c9af5110e3a2e58"
PACKAGE_BYTES = 109923778
PACKAGE_SHA = "98edbc4f965800be699972db523e6a25c9b47a6051068b2bcf02a5c173a7720a"
DESCRIPTOR_SHA = "e38a1c30604dce88710a37d09151291cec74c006ff58f8996ec48335b656a60e"
SIGNATURE_SHA = "67528c3f94f6ec95a12521533adc0c89a017d5e97408bdbbe25a323b84364459"
INVENTORY_SHA = "9ba42c36e3b4f332e64300ce6de881b220886b5454335065813c3c40add4d586"
RUNTIME_SHA = "4b45dc85aac03b7b5883045d89e8bd6f8ea642d5368d715a45ec84e807509c1c"
PROTOCOL_SHA = "083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5"
KIB, MIB, GIB = 1024, 1024**2, 1024**3
CAPTURE = 64 * KIB
STOP = False
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refused(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def decode(body, limit):
    need(type(body) is bytes and 0 < len(body) <= limit, "json-bound")
    value = json.loads(body, object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False, "json-constant"))
    pending, count = [(value, 0)], 0
    while pending:
        row, depth = pending.pop(); count += 1
        need(depth <= 32 and count <= 50000, "json-shape-bound")
        if type(row) is dict:
            pending.extend((v, depth + 1) for v in row.values())
        elif type(row) is list:
            pending.extend((v, depth + 1) for v in row)
    return value


def encoded(value):
    return (json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n").encode("ascii")


def point(end, *, cleanup=False):
    need(time.monotonic() < end, "deadline")
    need(cleanup or not STOP, "interrupted")


def root_context():
    # ARM64 is the fixed artifact target, not executable code on this Intel host.
    need(sys.platform == "darwin" and platform.machine() == "x86_64" and os.getuid() != 0,
         "host-target")
    expected = {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": REF,
                "RUNNER_TEMP": "/Users/runner/work/_temp",
                "GITHUB_WORKSPACE": "/Users/runner/work/mobile-release-kit/mobile-release-kit"}
    need(all(os.environ.get(k) == v for k, v in expected.items()), "dispatch-context")
    source = os.environ.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", source) is not None
         and source == os.environ.get("GITHUB_WORKFLOW_SHA"), "helper-source")
    context = {"source": source, "runId": os.environ.get("GITHUB_RUN_ID", ""),
               "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "")}
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", context[k]) is not None
             for k in ("runId", "runAttempt")), "caller-context")
    root = Path(os.environ.get("MRK_PREDECESSOR_WORK", ""))
    need(root.parent == Path(expected["RUNNER_TEMP"])
         and re.fullmatch(r"mrk-predecessor\.[A-Za-z0-9]{8}", root.name) is not None, "work-path")
    fd = os.open(root, READ | os.O_DIRECTORY)
    try:
        original = identity(os.fstat(fd))[:5]
        need(original == identity(root.lstat())[:5] and original[2] == stat.S_IFDIR | 0o700
             and original[3:5] == [os.getuid(), os.getgid()], "work-original")
    except BaseException:
        os.close(fd); raise
    return root, fd, original, context


def same_root(root, fd, original):
    need(identity(os.fstat(fd))[:5] == identity(root.lstat())[:5] == original, "work-changed")


def disk(fd, minimum):
    value = os.fstatvfs(fd)
    need(value.f_bavail * value.f_frsize >= minimum, "disk-reserve")


def write_at(fd, name, body, limit):
    need(type(body) is bytes and 0 < len(body) <= limit and "/" not in name, "output-bound")
    out = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        view = memoryview(body)
        while view:
            written = os.write(out, view); need(written > 0, "output-write"); view = view[written:]
        os.fsync(out)
        before = identity(os.fstat(out))
        need(before == identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
             and before[5:7] == [1, len(body)]
             and os.pread(out, len(body) + 1, 0) == body, "output-readback")
    finally:
        os.close(out)


def read_at(fd, relative, limit, end, *, body=True, mounted=False):
    """Retain every parent; no archive-provided path is passed to this reader."""
    parts = relative.split("/")
    need(all(v not in ("", ".", "..") for v in parts) and not relative.startswith("/"), "input-path")
    parents, current, source = [], fd, None
    try:
        for name in parts[:-1]:
            child = os.open(name, READ | os.O_DIRECTORY, dir_fd=current)
            parents.append((current, name, child, identity(os.fstat(child))[:5])); current = child
        source = os.open(parts[-1], READ, dir_fd=current)
        before = identity(os.fstat(source))
        need(stat.S_ISREG(before[2]) and before[5] == 1 and 0 < before[6] <= limit
             and (before[3] in (0, os.getuid()) if mounted else before[3] == os.getuid())
             and (stat.S_IMODE(before[2]) == 0o444 if mounted else not before[2] & 0o022), "input-metadata")
        digest, retained, count = hashlib.sha256(), bytearray(), 0
        while True:
            point(end)
            data = os.read(source, min(64 * KIB, before[6] + 1 - count))
            count += len(data); need(count <= before[6], "input-length")
            if not data: break
            digest.update(data)
            if body: retained.extend(data)
        need(count == before[6] and before == identity(os.fstat(source))
             == identity(os.stat(parts[-1], dir_fd=current, follow_symlinks=False)), "input-changed")
        for parent, name, child, original in parents:
            need(identity(os.fstat(child))[:5] == identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5]
                 == original, "input-parent-changed")
        return bytes(retained), {"bytes": count, "sha256": digest.hexdigest(), "identity": before}
    finally:
        try:
            if source is not None: os.close(source)
        finally:
            for _, _, child, _ in reversed(parents): os.close(child)


def preview_data(raw):
    value = decode(raw, 16 * KIB)
    expected = {"schemaVersion": 2, "scope": "current-macos-candidate", "sourceCommit": SOURCE,
                "sourceTree": TREE, "runId": RUN, "runAttempt": ATTEMPT,
                "workflow": ".github/workflows/desktop-macos-installed.yml", "platform": "macOS26-arm64",
                "packageRole": "ordinary-image", "instrumented": False,
                "distributionBytes": IMAGE_BYTES, "distributionSha256": IMAGE_SHA,
                "packageSize": PACKAGE_BYTES, "packageSha256": PACKAGE_SHA,
                "descriptorSha256": DESCRIPTOR_SHA, "signatureSha256": SIGNATURE_SHA,
                "installerInventorySha256": INVENTORY_SHA, "runtimeManifestSha256": RUNTIME_SHA}
    need(type(value) is dict and all(type(value.get(k)) is type(v) and value[k] == v for k, v in expected.items()),
         "preview-binding")
    # These are historical DATA, not a successful qualification for this operation.
    need(all(value.get(k) is False for k in ("fullM2Qualified", "fullUIQualified", "productReady",
                                            "maintenanceQualified", "distributionQualified")), "preview-not-qualified")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def redirect_data(address):
    need(type(address) is str and 0 < len(address) <= 8192, "artifact-redirect")
    parsed = urllib.parse.urlsplit(address)
    need(parsed.scheme == "https" and parsed.username is None and parsed.password is None
         and not parsed.fragment and parsed.port in (None, 443) and parsed.path.startswith("/")
         and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.blob\.core\.windows\.net",
                          parsed.hostname or "") is not None, "artifact-redirect")
    return address


def metadata_data(run, artifact):
    need(type(run) is dict and type(artifact) is dict and type(run.get("id")) is int
         and run["id"] == int(RUN) and type(run.get("run_attempt")) is int and run["run_attempt"] == int(ATTEMPT)
         and run.get("head_sha") == SOURCE and run.get("path") == ".github/workflows/desktop-macos-installed.yml"
         and type(run.get("repository")) is dict and run["repository"].get("full_name") == REPOSITORY,
         "run-binding")
    need(type(artifact.get("id")) is int and artifact["id"] == int(ARTIFACT)
         and type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] == ZIP_BYTES
         and artifact.get("expired") is False and artifact.get("digest") == "sha256:" + ZIP_SHA
         and type(artifact.get("workflow_run")) is dict
         and artifact["workflow_run"].get("id") == int(RUN)
         and artifact["workflow_run"].get("head_sha") == SOURCE, "artifact-binding")


def zip_roster(rows):
    sizes = {"MobileReleaseKit.dmg": IMAGE_BYTES, "PREVIEW.json": 2968, "README.md": 3433}
    need(len(rows) == 3 and {row.filename for row in rows} == set(sizes), "zip-roster")
    for row in rows:
        mode = row.external_attr >> 16
        need(not row.is_dir() and not row.flag_bits & 1 and row.compress_type == 0
             and row.file_size == row.compress_size == sizes[row.filename]
             and stat.S_IFMT(mode) in (0, stat.S_IFREG), "zip-member")


def acquire(root, fd, original, context):
    import zipfile
    end = time.monotonic() + 300
    need(not os.listdir(fd), "work-not-empty"); disk(fd, 4 * GIB)
    token = os.environ.pop("GITHUB_TOKEN", "")
    need(0 < len(token) <= 4096 and "\n" not in token and "\r" not in token, "read-token")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def request(address, authenticated):
        point(end); same_root(root, fd, original)
        headers = {"Accept-Encoding": "identity", "Connection": "close", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if authenticated: headers["Authorization"] = "Bearer " + token
        try:
            response = opener.open(urllib.request.Request(address, headers=headers), timeout=min(10, max(.01, end - time.monotonic())))
        except urllib.error.HTTPError as error:
            response = error
        try:
            rows = list(response.headers.items())
            need(len(rows) <= 64 and all(len(k) <= 256 and len(v) <= 8192 for k, v in rows), "response-headers")
            lowered = [k.lower() for k, _ in rows]
            need(len(lowered) == len(set(lowered)) and response.headers.get("Content-Encoding", "identity") == "identity",
                 "response-headers")
        except BaseException:
            response.close(); raise
        return response
    api = "https://api.github.com/repos/" + REPOSITORY
    def metadata(path):
        with request(api + path, True) as response:
            need(response.code == 200 and not response.headers.get("Location"), "metadata-status")
            data = bytearray()
            while True:
                point(end)
                block = response.read(min(64 * KIB, 256 * KIB + 1 - len(data)))
                data.extend(block); need(len(data) <= 256 * KIB, "metadata-bound")
                if not block: break
            return decode(bytes(data), 256 * KIB)
    metadata_data(metadata("/actions/runs/" + RUN + "/attempts/" + ATTEMPT),
                  metadata("/actions/artifacts/" + ARTIFACT))
    with request(api + "/actions/artifacts/" + ARTIFACT + "/zip", True) as response:
        need(response.code == 302, "artifact-status")
        address = redirect_data(response.headers.get("Location"))
    archive = os.open("artifact.zip", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with request(address, False) as response:
            need(response.code == 200 and not response.headers.get("Location")
                 and response.headers.get("Content-Length", str(ZIP_BYTES)) == str(ZIP_BYTES), "artifact-response")
            count, digest = 0, hashlib.sha256()
            while True:
                point(end); disk(fd, GIB)
                data = response.read(min(64 * KIB, ZIP_BYTES + 1 - count))
                count += len(data); need(count <= ZIP_BYTES, "artifact-length")
                if not data: break
                digest.update(data); view = memoryview(data)
                while view:
                    point(end); written = os.write(archive, view); need(written > 0, "artifact-write"); view = view[written:]
            need(count == ZIP_BYTES and digest.hexdigest() == ZIP_SHA, "artifact-digest")
        os.fsync(archive)
        _, zip_info = read_at(fd, "artifact.zip", ZIP_BYTES, end, body=False)
        need(zip_info["bytes"] == ZIP_BYTES and zip_info["sha256"] == ZIP_SHA, "artifact-readback")
        # Check the directory bound before ZipFile allocates its member records.
        tail = os.pread(archive, min(ZIP_BYTES, 65557), max(0, ZIP_BYTES - 65557))
        import struct
        at = tail.rfind(b"PK\x05\x06"); need(at >= 0 and at + 22 <= len(tail), "zip-end")
        _, diskno, central_disk, count_disk, total, size, offset, comment = struct.unpack_from("<4s4H2LH", tail, at)
        need(diskno == central_disk == 0 and count_disk == total == 3 and size <= 64 * KIB
             and offset + size == ZIP_BYTES - len(tail) + at and at + 22 + comment == len(tail), "zip-directory")
        with os.fdopen(os.dup(archive), "rb") as stream, zipfile.ZipFile(stream) as zipped:
            zip_roster(zipped.infolist())
            for name, limit, expected in (("MobileReleaseKit.dmg", IMAGE_BYTES, IMAGE_SHA), ("PREVIEW.json", 2968, None)):
                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
                try:
                    count, digest = 0, hashlib.sha256()
                    with zipped.open(name, "r") as member:
                        while True:
                            point(end); disk(fd, GIB)
                            data = member.read(min(64 * KIB, limit + 1 - count))
                            count += len(data); need(count <= limit, "zip-output-bound")
                            if not data: break
                            digest.update(data); view = memoryview(data)
                            while view:
                                written = os.write(out, view); need(written > 0, "zip-output-write"); view = view[written:]
                    need(count == limit and (expected is None or digest.hexdigest() == expected), "zip-output-digest")
                    os.fsync(out)
                finally: os.close(out)
    finally: os.close(archive)
    token = None
    raw, preview = read_at(fd, "PREVIEW.json", 16 * KIB, end); preview_data(raw)
    _, image = read_at(fd, "MobileReleaseKit.dmg", IMAGE_BYTES, end, body=False)
    need(image["sha256"] == IMAGE_SHA, "image-readback"); same_root(root, fd, original)
    write_at(fd, "acquisition.json", encoded({"root": original, "caller": context, "zip": zip_info,
             "image": image, "preview": preview}), 8 * KIB)


def native(root, fd, original, calls, role, argv, endpoint, maximum, *, cleanup=False):
    """Only three fixed inspection calls; wait, pipe bounds and disk share one loop."""
    need(role in ("memory", "attach", "detach") and all(v["role"] != role for v in calls), "native-once")
    point(endpoint, cleanup=cleanup); same_root(root, fd, original)
    end = min(endpoint, time.monotonic() + maximum)
    row = {"role": role, "entered": False, "returned": False, "pipesClosed": False, "returncode": None}
    calls.append(row)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
           "TMPDIR": str(root / "tmp")}
    child, selector, streams, failure = None, selectors.DefaultSelector(), {}, None
    killed = False
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=root, env=env, start_new_session=True, close_fds=True, bufsize=0)
        row["entered"] = True
        for label, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
            streams[stream.fileno()] = stream; selector.register(stream, selectors.EVENT_READ, label)
        while streams or child.poll() is None:
            try:
                point(end - 2, cleanup=cleanup); same_root(root, fd, original)
                if not cleanup: disk(fd, GIB)  # SAME original wait, not just entry/exit.
            except BaseException as error:
                if failure is None: failure = error
            if failure is not None:
                if not killed:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    killed = True
                need(time.monotonic() < end, "native-join-unknown")
            for key, _ in selector.select(min(.1, max(0, end - time.monotonic()))):
                label, stream = key.data, key.fileobj
                data = os.read(stream.fileno(), 64 * KIB if failure is not None else min(64 * KIB, CAPTURE + 1 - len(captured[label])))
                if failure is None:
                    captured[label].extend(data)
                    if len(captured[label]) > CAPTURE: failure = Refused("native-output-bound")
                if not data:
                    selector.unregister(stream); streams.pop(stream.fileno()); stream.close()
        row["returncode"] = child.wait(timeout=max(.01, end - time.monotonic()))
        row["returned"] = row["pipesClosed"] = True
        if failure is not None: raise failure
        # Bounded private memory only: no native transcript or filesystem-write
        # failure can hide a returned attach before its exact device is parsed.
        return row["returncode"], bytes(captured["stdout"]), bytes(captured["stderr"])
    finally:
        selector.close()
        if child is not None and not row["returned"]:
            if not killed:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            try:
                row["returncode"] = child.wait(timeout=max(.01, min(2, end - time.monotonic())))
                row["returned"] = True
            except subprocess.TimeoutExpired: pass
        for stream in streams.values(): stream.close()
        # Closing our pipe is not a substituted EOF/original child return.


def available_memory(body):
    text = body.decode("ascii")
    match = re.match(r"Mach Virtual Memory Statistics: \(page size of ([0-9]+) bytes\)\n", text)
    need(match is not None and int(match[1]) in (4096, 16384), "memory-shape")
    pages = []
    for name in ("free", "inactive", "speculative"):
        rows = re.findall(r"^Pages " + name + r":\s+([0-9]+)\.$", text, re.MULTILINE)
        need(len(rows) == 1, "memory-shape"); pages.append(int(rows[0]))
    return int(match[1]) * sum(pages)


def task_tree(root, end):
    count, total, pending = 0, 0, [(root, 0)]
    while pending:
        parent, depth = pending.pop(); point(end)
        need(depth <= 64 and stat.S_ISDIR(parent.lstat().st_mode), "task-directory")
        with os.scandir(parent) as entries:
            for entry in entries:
                point(end); info = entry.stat(follow_symlinks=False); count += 1
                need(count <= 32768 and info.st_uid == os.getuid()
                     and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), "task-node")
                if stat.S_ISDIR(info.st_mode): pending.append((Path(entry.path), depth + 1))
                else:
                    total += info.st_size
                    need(info.st_nlink == 1 and info.st_size <= 512 * MIB and total <= GIB, "task-bound")
    return count, total


def data_module():
    spec = importlib.util.spec_from_file_location("_predecessor_stage_data", Path(__file__).with_name("stage_macos_installed.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def package_allocation(end, phase, live, packed, output, *, parents=0):
    """Existing codec copy quote inside the same admitted 3GiB, not an OS quota."""
    point(end)
    need(phase in ("install-product-toc", "install-product-member", "xar-toc", "xar-member",
                   "scripts-inflate", "cpio-window", "cpio-slice"), "package-codec-phase")
    need(all(type(v) is int and 0 <= v <= 8 * 512 * MIB for v in (live, packed, output, parents)),
         "package-codec-values")
    # The same prepared-package live/copy expression, with additional reserved
    # TOC/CPIO tables/names and control memory. Parent aliases are counted once.
    need(live + 3 * packed + 2 * (output + 1) + parents + 256 * MIB <= 3 * GIB,
         "package-codec-bound")


def package_controls(stager, mounted, expected, end):
    """Only the exact original complete package supplies these two public bodies."""
    point(end)
    need(3 * PACKAGE_BYTES + 256 * MIB <= 3 * GIB, "package-reader-bound")
    package, observed = read_at(mounted, "Install.pkg", PACKAGE_BYTES, end, mounted=True)
    need(observed == expected and observed["bytes"] == PACKAGE_BYTES
         and observed["sha256"] == PACKAGE_SHA, "package-original-changed")
    parents = 0
    def allocation(phase, live, packed, output):
        package_allocation(end, phase, live, packed, output, parents=parents)
    members = stager.install_product_members(package, allocation_budget=allocation)
    # This function owns the full read; inspect has no caller-held package body.
    # Each parser already counts its own input, including our same-object alias.
    del package
    if stager.INSTALL_COMPONENT in members:
        inner = members[stager.INSTALL_COMPONENT]
        del members
        component = stager.xar_members(inner, allocation_budget=allocation)
        del inner
    else:
        component = {name: members[stager.INSTALL_COMPONENT + "/" + name] for name in ("PackageInfo", "Scripts")}
        del members
    need(set(component) == {"PackageInfo", "Scripts"}, "package-component")
    package_info, packed = component["PackageInfo"], component["Scripts"]
    del component
    need(type(package_info) is bytes and 0 < len(package_info) <= 16 * KIB
         and type(packed) is bytes and 0 < len(packed) <= 512 * MIB
         and stager.MAX_BYTES == 512 * MIB, "package-controls-bound")
    parents = len(package_info)  # Remains independently live during Scripts/CPIO.
    if packed[:2] == b"\x1f\x8b":
        allocation("scripts-inflate", len(packed), len(packed), stager.MAX_BYTES)
        archive = stager.inflate(packed, stager.MAX_BYTES, gzip=True)
    else:
        archive = packed
    del packed
    rows = stager.cpio_members(archive, allocation_budget=allocation, store_runtime=True)
    del archive
    member = rows.get("input/" + stager.INSTALLATION_INVENTORY_NAME)
    need(type(member) is tuple and len(member) == 2 and member[1] == 0o444
         and type(member[0]) is bytes and 0 < len(member[0]) <= 12 * MIB
         and hashlib.sha256(member[0]).hexdigest() == INVENTORY_SHA, "package-inventory")
    inventory = member[0]
    del rows, member
    # All archive graphs leave before release_data performs inventory JSON work.
    return package_info, inventory


def release_data(stager, descriptor, inventory, package_info):
    producer = stager.maintenance_producer_data(descriptor, target=TARGET)
    release = producer["releaseSet"]["current"]
    need(all(release[k] == v for k, v in {"sourceCommit": SOURCE, "protocolSha256": PROTOCOL_SHA,
         "packageSha256": PACKAGE_SHA, "runtimeManifestSha256": RUNTIME_SHA, "inventorySha256": INVENTORY_SHA}.items()),
         "release-binding")
    selection = stager.BuildSelection(TARGET, release["packageVersion"], release["release"])
    stager.package_info(package_info, selection=selection)
    rows = stager.observation_inventory_bytes(inventory, INVENTORY_SHA, RUNTIME_SHA, selection=selection)
    policies = [v for v in producer["signingPolicies"] if v["sha256"] == release["signingPolicySha256"]]
    need(len(policies) == 1, "signing-policy-binding")
    return release, policies[0], len(rows), sum(row["size"] for row in rows.values())


def inspection_failure_data(error, stager):
    """Finite public source locations, never exception text or frame locals."""
    kind = {Refused: "inspection-refused", ValueError: "value-error", TypeError: "type-error",
            KeyError: "key-error", AttributeError: "attribute-error", RuntimeError: "runtime-error"}.get(type(error), "other")
    if type(error) is vars(stager).get("Refused"): kind = "staging-refused"
    number = None
    if isinstance(error, OSError):
        kind = "os-error"; value = OSError.errno.__get__(error)
        if type(value) is int and 0 <= value <= 65535: number = value
    origins = ((globals(), __file__, "macos_predecessor_inspection.py"),
               (vars(stager), str(Path(__file__).with_name("stage_macos_installed.py")), "stage_macos_installed.py"))
    frames, tb = [], BaseException.__traceback__.__get__(error)
    for _ in range(32):
        if tb is None: break
        for namespace, path, name in origins:
            if (tb.tb_frame.f_globals is namespace and namespace.get("__file__") == path
                    and tb.tb_frame.f_code.co_filename == path and type(tb.tb_lineno) is int and 0 < tb.tb_lineno < 1000000):
                frames.append({"file": name, "line": tb.tb_lineno}); frames = frames[-4:]
                break
        tb = tb.tb_next
    return {"kind": kind, "errno": number, "locations": frames}


def inspect(root, fd, original, context):
    work_end = time.monotonic() + 600; cleanup_end = work_end + 60
    raw, _ = read_at(fd, "acquisition.json", 8 * KIB, work_end)
    acquired = decode(raw, 8 * KIB)
    need(type(acquired) is dict and set(acquired) == {"root", "caller", "zip", "image", "preview"}
         and acquired["root"] == original and acquired["caller"] == context, "acquisition-original")
    for name, key, size, digest in (("artifact.zip", "zip", ZIP_BYTES, ZIP_SHA),
                                   ("MobileReleaseKit.dmg", "image", IMAGE_BYTES, IMAGE_SHA)):
        _, observed = read_at(fd, name, size, work_end, body=False)
        need(observed == acquired[key] and observed["sha256"] == digest, "acquired-input-changed")
    preview, observed = read_at(fd, "PREVIEW.json", 16 * KIB, work_end)
    need(observed == acquired["preview"], "acquired-preview-changed"); preview_data(preview)
    disk(fd, 4 * GIB); os.mkdir("tmp", 0o700, dir_fd=fd)
    stager, calls = data_module(), []
    code, out, _ = native(root, fd, original, calls, "memory", ["/usr/bin/vm_stat"], work_end, 10)
    measured = available_memory(out) if code == 0 else None
    print("MRK_PREDECESSOR_INSPECTION_MEMORY=" + encoded({"exitCode": code,
          "availableEstimateBytes": measured, "requiredBytes": 3 * GIB}).decode("ascii").rstrip("\n"), flush=True)
    need(code == 0, "memory-probe-exit")
    need(measured >= 3 * GIB, "memory-reserve")
    mount = root / "mount"
    need(not os.path.lexists(mount), "inspection-destination-occupied")
    mounted, device, mount_id, device_id, error = None, None, None, None, None
    returned, originals, image_post = None, {}, None
    try:
        code, out, err = native(root, fd, original, calls, "attach", ["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse",
            "-noautoopen", "-owners", "on", "-mountpoint", str(mount), "-plist", str(root / "MobileReleaseKit.dmg")], work_end, 60)
        device = stager.distribution_mount_data(out, err, code, mount)
        mounted = os.open("mount", READ | os.O_DIRECTORY, dir_fd=fd); mount_id = identity(os.fstat(mounted))[:5]
        info = os.stat(device, follow_symlinks=False)
        caller_uid = os.getuid()
        print("MRK_PREDECESSOR_INSPECTION_DEVICE=" + encoded({"modeType": stat.S_IFMT(info.st_mode),
              "uid": info.st_uid, "callerUid": caller_uid}).decode("ascii").rstrip("\n"), flush=True)
        # Darwin media owner-uid may select this caller instead of the root default.
        need((stat.S_ISBLK(info.st_mode) or stat.S_ISCHR(info.st_mode))
             and info.st_uid in (0, caller_uid), "mounted-device")
        device_id = identity(info)[:5] + [info.st_rdev]
        def same_mount():
            same_root(root, fd, original)
            need(mount_id == identity(os.fstat(mounted))[:5] == identity(mount.lstat())[:5]
                 and os.fstatvfs(mounted).f_flag & os.ST_RDONLY, "mount-changed-or-writable")
            info = os.stat(device, follow_symlinks=False)
            need(device_id == identity(info)[:5] + [info.st_rdev], "mount-device-changed")
        same_mount(); need(set(os.listdir(mounted)) == {"Install.pkg", "producer.json", "producer.sig"}, "mounted-roster")
        bodies = {}
        for name, limit, expected in (("Install.pkg", PACKAGE_BYTES, PACKAGE_SHA),
                                     ("producer.json", 64 * KIB, DESCRIPTOR_SHA), ("producer.sig", 16 * KIB, SIGNATURE_SHA)):
            body, observed = read_at(mounted, name, limit, work_end, body=name != "Install.pkg", mounted=True)
            need(observed["sha256"] == expected and (name != "Install.pkg" or observed["bytes"] == PACKAGE_BYTES), "mounted-digest")
            originals[name] = observed
            if name != "Install.pkg": bodies[name] = body
        same_mount()
        package_info, inventory = package_controls(stager, mounted, originals["Install.pkg"], work_end)
        same_mount()
        inventory_info = {"bytes": len(inventory), "sha256": hashlib.sha256(inventory).hexdigest()}
        release, policy, count, size = release_data(stager, bodies["producer.json"], inventory, package_info)
        for name, before in originals.items():
            _, after = read_at(mounted, name, before["bytes"], work_end, body=False, mounted=True)
            need(after == before, "mounted-post-changed")
        _, after = read_at(fd, "MobileReleaseKit.dmg", IMAGE_BYTES, work_end, body=False)
        image_post = after
        need(after == acquired["image"], "image-post-changed"); same_mount()
        bodies["install-inventory.json"] = inventory
        returned = {"bodies": bodies, "release": release, "signingPolicy": policy, "inventoryFiles": count,
                    "inventoryPayloadBytes": size, "inventory": {k: inventory_info[k] for k in ("bytes", "sha256")}}
    except BaseException as caught:
        error = caught
    finally:
        # Known joined post-attach failure still detaches THIS original, never an
        # inferred/rediscovered mount. Cleanup cannot erase the first failure.
        try:
            if device is not None and mounted is not None and device_id is not None:
                need(all(c["returned"] and c["pipesClosed"] for c in calls), "native-return-unknown")
                same_mount()
                consumed, mounted = mounted, None; os.close(consumed)
                code, _, _ = native(root, fd, original, calls, "detach", ["/usr/bin/hdiutil", "detach", device],
                                     cleanup_end, 60, cleanup=True)
                need(code == 0 and not os.path.lexists(mount), "detach-not-confirmed")
            else:
                need(False, "attach-unknown")
        except BaseException as caught:
            if error is None: error = caught
        finally:
            if mounted is not None:
                try: os.close(mounted)
                except OSError as caught:
                    if error is None: error = caught
    if error is not None:
        # Only after the original cleanup attempt; this DATA never grants a
        # detach/return/completion or replaces the retained first failure.
        try:
            failure = inspection_failure_data(error, stager)
            if image_post is not None and image_post != acquired["image"]:
                before = acquired["image"]
                fields = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs")
                failure["imagePost"] = {"bytesEqual": image_post["bytes"] == before["bytes"],
                    "sha256Equal": image_post["sha256"] == before["sha256"],
                    "identityChanged": [name for index, name in enumerate(fields)
                                        if image_post["identity"][index] != before["identity"][index]]}
            print("MRK_PREDECESSOR_INSPECTION_FAILURE=" + encoded(failure).decode("ascii").rstrip("\n"),
                  file=sys.stderr, flush=True)
        except BaseException: pass
        raise error
    need(returned is not None and [row["role"] for row in calls] == ["memory", "attach", "detach"]
         and all(row["returned"] and row["pipesClosed"] and row["returncode"] == 0 for row in calls), "inspection-incomplete")
    point(work_end); same_root(root, fd, original)
    summary = {"schemaVersion": 1, "kind": "delivered-predecessor-inspection-data-v1", "dataOnly": True,
               "nativeQualificationInferred": False, "updateActivated": False, "productReady": False,
               "target": TARGET, "source": SOURCE, "tree": TREE, "runId": RUN, "runAttempt": ATTEMPT,
               "artifactId": ARTIFACT, "artifactBytes": ZIP_BYTES, "artifactSha256": ZIP_SHA,
               "imageBytes": IMAGE_BYTES, "imageSha256": IMAGE_SHA, "helperCaller": context,
               "release": returned["release"], "signingPolicy": returned["signingPolicy"],
               "inventoryFiles": returned["inventoryFiles"], "inventoryPayloadBytes": returned["inventoryPayloadBytes"],
               "inventory": returned["inventory"], "mountedFiles": {name: {k: v[k] for k in ("bytes", "sha256")}
               for name, v in originals.items()}, "originalCalls": calls, "originalMountDetached": True}
    os.mkdir("output", 0o700, dir_fd=fd); output = os.open("output", READ | os.O_DIRECTORY, dir_fd=fd)
    try:
        for name, body in returned["bodies"].items():
            write_at(output, name, body, {"producer.json": 64 * KIB, "producer.sig": 16 * KIB,
                                         "install-inventory.json": 12 * MIB}[name])
        write_at(output, "inspection.json", encoded(summary), 16 * KIB)
        output_id = identity(os.fstat(output))[:5]
    finally: os.close(output)
    write_at(fd, "completed.json", encoded({"root": original, "caller": context, "output": output_id,
             "originalMountDetached": True, "originalCalls": calls}), 8 * KIB)


def cleanup(root, fd, original, context):
    # No completion (including killed/unknown acquisition/inspection) => retain.
    if not os.path.lexists(root / "completed.json"):
        print("MRK_PREDECESSOR_INSPECTION=retained-unfinished"); return
    end = time.monotonic() + 60
    body, _ = read_at(fd, "completed.json", 8 * KIB, end); record = decode(body, 8 * KIB)
    need(type(record) is dict and set(record) == {"root", "caller", "output", "originalMountDetached", "originalCalls"}
         and record["root"] == original and record["caller"] == context
         and record["originalMountDetached"] is True and not os.path.lexists(root / "mount"), "cleanup-original")
    calls = record["originalCalls"]
    need(type(calls) is list and [v.get("role") for v in calls] == ["memory", "attach", "detach"]
         and all(v.get("entered") is True and v.get("returned") is True and v.get("pipesClosed") is True
                 and type(v.get("returncode")) is int and v["returncode"] == 0 for v in calls), "cleanup-returns")
    need(identity((root / "output").lstat())[:5] == record["output"], "cleanup-output")
    task_tree(root, end)
    same_root(root, fd, original); point(end)
    # fd-based rmtree never follows a replaced child symlink. An error retains the
    # remainder on the disposable host; never delete an outside root.
    need(shutil.rmtree.avoids_symlink_attacks, "cleanup-platform")
    parent = os.open(root.parent, READ | os.O_DIRECTORY)
    try:
        need(identity(os.stat(root.name, dir_fd=parent, follow_symlinks=False))[:5] == original, "cleanup-parent")
        shutil.rmtree(root.name, dir_fd=parent)
    finally: os.close(parent)


def main():
    global STOP
    def stop(_number, _frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    fd = None
    try:
        need(mode in ("acquire", "inspect", "cleanup"), "fixed-mode")
        root, fd, original, context = root_context()
        {"acquire": acquire, "inspect": inspect, "cleanup": cleanup}[mode](root, fd, original, context)
        os.close(fd); fd = None
        print("MRK_PREDECESSOR_INSPECTION=" + mode + "-returned")
        return 0
    except BaseException as error:
        reason = error.args[0] if type(error) is Refused and len(error.args) == 1 else "unavailable-or-unknown"
        print("MRK_PREDECESSOR_INSPECTION=refused:" + str(reason), file=sys.stderr)
        return 1
    finally:
        if fd is not None: os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
