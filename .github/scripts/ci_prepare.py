"""Acquire pinned public DATA before any project code runs.

The trusted controller calls prepare_inputs with its original monotonic deadline
and a private, create-only destination. This module never installs/imports a
download, evaluates Ruby/package metadata, runs a command, or restores a cache.
The caller must retain the returned inventory, verify it, and make inputs readable
but immutable before starting the isolated project identity. inputs.json is a
diagnostic copy, not a receipt that another invocation may adopt.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
import re
import shutil
import ssl
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path


CHUNK = 64 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_ASSET_BYTES = 8 * 1024 * 1024
MAX_TAR_BYTES = 16 * 1024 * 1024
DISK_RESERVE = 4 * 1024**3 + 512 * 1024**2
PYTHON_PINS = {
    "pip": "24.0", "setuptools": "80.9.0", "wheel": "0.45.1",
    "attrs": "26.1.0", "jsonschema": "4.25.1",
    "jsonschema-specifications": "2025.9.1", "referencing": "0.36.2",
    "rpds-py": "0.27.1", "typing-extensions": "4.16.0",
}
REQUIREMENT_GROUPS = {
    "pip": ("pip",),
    "build": ("setuptools", "wheel"),
    "test": ("attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py", "typing-extensions"),
}
ASSET_KEYS = {"name", "version", "filename", "url", "bytes", "sha256"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GEM_SPEC = re.compile(r"    ([A-Za-z0-9_][A-Za-z0-9_.-]*) \(([0-9][A-Za-z0-9_.]*)\)\Z")
GEM_CHECKSUM = re.compile(r"  ([A-Za-z0-9_][A-Za-z0-9_.-]*) \(([0-9][A-Za-z0-9_.]*)\) sha256=([0-9a-f]{64})\Z")


class PreparationError(RuntimeError):
    """A fixed preparation failure; no partially prepared directory is usable."""


def remaining(deadline: float) -> float:
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise PreparationError("invalid_preparation_deadline")
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise PreparationError("preparation_deadline_expired")
    return seconds


@contextmanager
def closing(resource):
    """A secondary close error cannot replace the original acquisition failure."""
    try:
        yield resource
    except BaseException as primary:
        try:
            resource.close()
        except BaseException:
            primary.add_note("additional preparation resource close failure")
        raise
    else:
        resource.close()


def read_data(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    failure = None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise PreparationError("invalid_preparation_source_file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(CHUNK, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != info.st_size:
            raise PreparationError("preparation_source_size_changed")
        return bytes(data)
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            os.close(descriptor)
        except BaseException:
            if failure is None:
                raise
            failure.add_note("additional preparation source close failure")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PreparationError("duplicate_preparation_key")
        result[key] = value
    return result


def checked_url(url: str, hosts: frozenset[str]) -> None:
    if type(url) is not str or not 0 < len(url) <= 8192 or any(ord(char) < 33 or ord(char) > 126 for char in url):
        raise PreparationError("invalid_asset_url")
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in hosts or parts.port not in (None, 443)
            or parts.username is not None or parts.password is not None or parts.fragment):
        raise PreparationError("unapproved_asset_url")


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str], deadline: float):
        self.hosts, self.deadline = hosts, deadline
        self.count = 0

    def http_error_302(self, request, response, code, message, headers):
        # The stock handler calls response.read() without a size limit. Do not
        # consume a redirect body: close this response before the next request.
        with closing(response):
            locations = headers.get_all("Location", [])
            self.count += 1
            if len(locations) != 1 or self.count > 3 or request.get_method() != "GET":
                raise PreparationError("invalid_asset_redirect")
            url = urllib.parse.urljoin(request.full_url, locations[0])
            checked_url(url, self.hosts)
            follow = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "MRK-offline-inputs/1"})
        return self.parent.open(follow, timeout=min(30, remaining(self.deadline)))

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class Budget:
    def __init__(self, root: Path, deadline: float):
        self.root, self.deadline, self.written = root, deadline, 0

    def space(self, prospective: int) -> None:
        remaining(self.deadline)
        if prospective < 0 or self.written + prospective > MAX_INPUT_BYTES:
            raise PreparationError("preparation_aggregate_size_limit")
        if shutil.disk_usage(self.root).free < DISK_RESERVE + prospective:
            raise PreparationError("preparation_disk_reserve")

    def write(self, output, data: bytes) -> None:
        self.space(len(data))
        self.written += len(data)
        view = memoryview(data)
        while view:
            remaining(self.deadline)
            count = output.write(view)
            if type(count) is not int or not 0 < count <= len(view):
                raise PreparationError("preparation_short_write")
            view = view[count:]


def stream_file(stream, path: Path, budget: Budget, *, maximum: int, digest: str, size: int | None) -> dict:
    budget.space(maximum if size is None else size)
    received, actual = 0, hashlib.sha256()
    with closing(open(path, "xb", buffering=0)) as output:
        os.fchmod(output.fileno(), 0o600)
        read = getattr(stream, "read1", stream.read)
        while True:
            remaining(budget.deadline)
            chunk = read(min(CHUNK, maximum + 1 - received))
            remaining(budget.deadline)
            if type(chunk) is not bytes:
                raise PreparationError("invalid_asset_stream")
            if not chunk:
                break
            received += len(chunk)
            if received > maximum:
                raise PreparationError("asset_size_limit")
            actual.update(chunk)
            budget.write(output, chunk)
        if (size is not None and received != size) or actual.hexdigest() != digest:
            raise PreparationError("asset_bytes_or_hash_mismatch")
    remaining(budget.deadline)
    return {"path": path.relative_to(budget.root).as_posix(), "bytes": received, "sha256": actual.hexdigest()}


def download(asset: dict, relative: str, hosts: frozenset[str], budget: Budget) -> dict:
    checked_url(asset["url"], hosts)
    # ProxyHandler({}) excludes ambient proxies; no auth/netrc handler is added.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects(hosts, budget.deadline),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(asset["url"], headers={"Accept-Encoding": "identity", "User-Agent": "MRK-offline-inputs/1"})
    maximum = asset.get("bytes", MAX_ASSET_BYTES)
    try:
        response = opener.open(request, timeout=min(30, remaining(budget.deadline)))
    except urllib.error.HTTPError as error:
        with closing(error):
            raise PreparationError("asset_http_error") from error
    with closing(response):
        checked_url(response.geturl(), hosts)
        lengths = response.headers.get_all("Content-Length", [])
        if (response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity"
                or len(lengths) > 1 or (lengths and (not re.fullmatch(r"[0-9]{1,10}", lengths[0])
                                                  or not 0 < int(lengths[0]) <= maximum))):
            raise PreparationError("invalid_asset_response")
        if lengths and "bytes" in asset and int(lengths[0]) != asset["bytes"]:
            raise PreparationError("asset_content_length_mismatch")
        record = stream_file(response, budget.root / relative, budget, maximum=maximum,
                             digest=asset["sha256"], size=asset.get("bytes"))
    remaining(budget.deadline)
    return {**record, "name": asset["name"], "version": asset["version"], "kind": "download"}


def validate_asset(asset: dict, extra: set[str] | frozenset[str] = frozenset()) -> None:
    if type(asset) is not dict or set(asset) != ASSET_KEYS | extra:
        raise PreparationError("invalid_asset_record")
    if (any(type(asset[key]) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]+", asset[key])
            for key in ("name", "version", "filename"))
            or type(asset["bytes"]) is not int or not 0 < asset["bytes"] <= MAX_ASSET_BYTES
            or type(asset["sha256"]) is not str or not SHA256.fullmatch(asset["sha256"])):
        raise PreparationError("invalid_asset_identity")


def load_assets(source_root: Path, platform: str) -> tuple[dict, list[dict], list[dict], str, str]:
    """Parse ordinary committed JSON/lock text, never a Gemfile or gemspec."""
    if platform not in ("linux", "macos"):
        raise PreparationError("unsupported_preparation_platform")
    manifest_bytes = read_data(source_root / ".github/verification-tools.json", 128 * 1024)
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_pairs)
    if (type(manifest) is not dict or set(manifest) != {"schema", "python", "ruby", "fiddle", "gemfile_lock_sha256", "locked_gem_count", "wheels", "bundler", "actionlint"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["python"] != "3.11" or manifest["ruby"] != "3.3.12" or manifest["fiddle"] != "1.1.2"
            or type(manifest["locked_gem_count"]) is not int or manifest["locked_gem_count"] != 99
            or type(manifest["wheels"]) is not list or len(manifest["wheels"]) != 10):
        raise PreparationError("invalid_tool_manifest")
    by_platform = {name: {} for name in ("linux", "macos")}
    filenames = set()
    for asset in manifest["wheels"]:
        validate_asset(asset, {"platforms"})
        if (asset["name"] not in PYTHON_PINS or asset["version"] != PYTHON_PINS[asset["name"]]
                or type(asset["platforms"]) is not list or asset["platforms"] not in (["linux"], ["macos"], ["linux", "macos"])
                or asset["filename"] in filenames):
            raise PreparationError("invalid_python_asset_inventory")
        filenames.add(asset["filename"])
        suffix = "py3-none-any.whl"
        if asset["name"] == "rpds-py":
            if len(asset["platforms"]) != 1:
                raise PreparationError("invalid_python_platform_wheel")
            suffix = "cp311-cp311-" + ("manylinux_2_17_x86_64.manylinux2014_x86_64.whl" if asset["platforms"] == ["linux"] else "macosx_11_0_arm64.whl")
        if asset["filename"] != f'{asset["name"].replace("-", "_")}-{asset["version"]}-{suffix}':
            raise PreparationError("invalid_python_wheel_filename")
        checked_url(asset["url"], frozenset({"files.pythonhosted.org"}))
        for target in asset["platforms"]:
            if asset["name"] in by_platform[target]:
                raise PreparationError("duplicate_python_platform_asset")
            by_platform[target][asset["name"]] = asset
    if any(set(values) != set(PYTHON_PINS) for values in by_platform.values()):
        raise PreparationError("incomplete_python_asset_inventory")
    selected = by_platform[platform]
    bundler, actionlint = manifest["bundler"], manifest["actionlint"]
    validate_asset(bundler)
    validate_asset(actionlint, {"binary"})
    if (bundler["name"], bundler["version"], bundler["filename"]) != ("bundler", "4.0.16", "bundler-4.0.16.gem"):
        raise PreparationError("invalid_bundler_pin")
    if (actionlint["name"], actionlint["version"], actionlint["filename"]) != ("actionlint", "1.7.12", "actionlint_1.7.12_linux_amd64.tar.gz"):
        raise PreparationError("invalid_actionlint_pin")
    binary = actionlint["binary"]
    if (type(binary) is not dict or set(binary) != {"filename", "bytes", "sha256"} or binary["filename"] != "actionlint"
            or type(binary["bytes"]) is not int or not 0 < binary["bytes"] <= MAX_ASSET_BYTES
            or type(binary["sha256"]) is not str or not SHA256.fullmatch(binary["sha256"])):
        raise PreparationError("invalid_actionlint_binary_pin")
    checked_url(bundler["url"], frozenset({"rubygems.org"}))
    checked_url(actionlint["url"], frozenset({"github.com"}))
    lock_bytes = read_data(source_root / "Gemfile.lock", 128 * 1024)
    lock_hash = hashlib.sha256(lock_bytes).hexdigest()
    if lock_hash != manifest["gemfile_lock_sha256"]:
        raise PreparationError("gem_lock_pin_changed")
    text = lock_bytes.decode("utf-8")
    if (text.count("\nCHECKSUMS\n") != 1 or text.count("  remote: https://rubygems.org/\n") != 1
            or not text.endswith("RUBY VERSION\n  ruby 3.3.12\n\nBUNDLED WITH\n  4.0.16\n")):
        raise PreparationError("unsupported_gem_lock")
    specs, checksums = {}, {}
    for line in text.split("\nCHECKSUMS\n", 1)[0].splitlines():
        match = GEM_SPEC.fullmatch(line)
        if match:
            name, version = match.groups()
            if name in specs:
                raise PreparationError("duplicate_gem_spec")
            specs[name] = version
    for line in text.split("\nCHECKSUMS\n", 1)[1].split("\nRUBY VERSION\n", 1)[0].splitlines():
        if not line:
            continue
        match = GEM_CHECKSUM.fullmatch(line)
        if not match or match[1] in checksums:
            raise PreparationError("invalid_gem_checksum_inventory")
        checksums[match[1]] = (match[2], match[3])
    if (len(specs) != 99 or set(specs) != set(checksums) or "bundler" in specs
            or specs.get("fiddle") != manifest["fiddle"]
            or any(version != checksums[name][0] for name, version in specs.items())):
        raise PreparationError("incomplete_gem_checksum_inventory")
    gems = [{"name": name, "version": version, "filename": f"{name}-{version}.gem",
             "url": f"https://rubygems.org/downloads/{name}-{version}.gem", "sha256": checksums[name][1]}
            for name, version in sorted(specs.items())]
    return manifest, list(selected.values()), [*gems, bundler], hashlib.sha256(manifest_bytes).hexdigest(), lock_hash


class TarReader:
    """Cap expanded bytes BEFORE tarfile allocates a claimed extended header."""
    def __init__(self, source, deadline: float):
        self.source, self.deadline, self.consumed = source, deadline, 0

    def read(self, size: int) -> bytes:
        remaining(self.deadline)
        if type(size) is not int or size < 0 or self.consumed + size > MAX_TAR_BYTES:
            raise PreparationError("actionlint_expanded_size_limit")
        data = self.source.read(size)
        self.consumed += len(data)
        remaining(self.deadline)
        return data


def extract_actionlint(asset: dict, budget: Budget) -> dict:
    """Write ONE pinned regular member; never extract archive paths or execute it."""
    record, count = None, 0
    with closing(open(budget.root / "actionlint" / asset["filename"], "rb")) as compressed:
        with closing(gzip.GzipFile(fileobj=compressed)) as expanded:
            reader = TarReader(expanded, budget.deadline)
            with closing(tarfile.open(fileobj=reader, mode="r|")) as archive:
                for member in archive:
                    count += 1
                    if count > 32 or not member.isfile() or not 0 <= member.size <= MAX_ASSET_BYTES:
                        raise PreparationError("invalid_actionlint_tar_member")
                    if member.name != "actionlint":
                        continue
                    binary = asset["binary"]
                    if record is not None or member.size != binary["bytes"] or member.mode != 0o755:
                        raise PreparationError("invalid_actionlint_binary_member")
                    with closing(archive.extractfile(member)) as source:
                        record = stream_file(source, budget.root / "actionlint/actionlint", budget,
                                             maximum=binary["bytes"], digest=binary["sha256"], size=binary["bytes"])
            # Complete gzip CRC/trailer validation, with the same expansion cap.
            while reader.read(CHUNK):
                pass
    if record is None:
        raise PreparationError("missing_actionlint_binary")
    return {**record, "name": "actionlint", "version": asset["version"], "kind": "extracted-binary"}


def write_data(relative: str, data: bytes, budget: Budget, *, name: str, kind: str) -> dict:
    budget.space(len(data))
    with closing(open(budget.root / relative, "xb", buffering=0)) as output:
        os.fchmod(output.fileno(), 0o600)
        budget.write(output, data)
    return {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "name": name, "version": "1", "kind": kind}


def prepare_inputs(*, source_root: Path, destination: Path, platform: str, deadline: float) -> dict:
    """Return a live complete file inventory; failure leaves private partial DATA.

    No project child may exist yet. The controller owns both canonical roots and
    the parent directory, enforces its independent job timeout, and makes this
    returned file set read-only only after the original call succeeds. All paths
    in the result are relative to destination; no previous inputs.json is read.
    """
    remaining(deadline)
    source_root, destination = Path(source_root), Path(destination)
    if (not source_root.is_absolute() or source_root.resolve(strict=True) != source_root
            or not destination.is_absolute() or destination.parent.resolve(strict=True) != destination.parent
            or destination.name in ("", ".", "..") or destination.is_relative_to(source_root)):
        raise PreparationError("invalid_preparation_roots")
    parent = destination.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
        raise PreparationError("preparation_parent_not_private")
    manifest, wheels, gems, manifest_hash, lock_hash = load_assets(source_root, platform)
    remaining(deadline)
    if shutil.disk_usage(destination.parent).free < DISK_RESERVE + MAX_INPUT_BYTES:
        raise PreparationError("preparation_disk_reserve")
    destination.mkdir(mode=0o700)  # Existing directories/symlinks are NEVER resumed.
    budget = Budget(destination, deadline)
    for name in ("python", "gems", *(("actionlint",) if platform == "linux" else ())):
        (destination / name).mkdir(mode=0o700)
    files = []
    for asset in wheels:
        files.append(download(asset, "python/" + asset["filename"], frozenset({"files.pythonhosted.org"}), budget))
    for asset in gems:
        files.append(download(asset, "gems/" + asset["filename"], frozenset({"rubygems.org"}), budget))
    requirements = {}
    selected = {asset["name"]: asset for asset in wheels}
    for group, names in REQUIREMENT_GROUPS.items():
        relative = f"python/{group}-requirements.txt"
        data = "".join(f'{name}=={PYTHON_PINS[name]} --hash=sha256:{selected[name]["sha256"]}\n' for name in names).encode("ascii")
        files.append(write_data(relative, data, budget, name=group, kind="requirements"))
        requirements[group] = relative
    actionlint = actionlint_archive = None
    if platform == "linux":
        actionlint_archive = "actionlint/" + manifest["actionlint"]["filename"]
        files.append(download(manifest["actionlint"], actionlint_archive,
                              frozenset({"github.com", "release-assets.githubusercontent.com"}), budget))
        files.append(extract_actionlint(manifest["actionlint"], budget))
        actionlint = "actionlint/actionlint"
    result = {"schema": 1, "platform": platform, "python": "python", "gems": "gems",
              "bundler": "gems/" + manifest["bundler"]["filename"], "actionlint": actionlint,
              "actionlint_archive": actionlint_archive, "requirements": requirements,
              "manifest_sha256": manifest_hash, "lock_sha256": lock_hash,
              "files": sorted(files, key=lambda item: item["path"])}
    diagnostic = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("ascii")
    result["files"].append(write_data("inputs.json", diagnostic, budget, name="inputs", kind="inventory"))
    result["files"].sort(key=lambda item: item["path"])
    remaining(deadline)
    return result
