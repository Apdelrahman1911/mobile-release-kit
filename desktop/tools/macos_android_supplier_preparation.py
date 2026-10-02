#!/usr/bin/env python3
"""Fixed, nonshipping macOS Android supplier DATA preparation.

No vendor command, installer, root operation, license acceptance, application
import, subprocess or native tool execution. Root's original external owner
bounds this process. The unchanged metadata probe is a SEPARATE invocation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

PREPARATION_SECONDS = 600
CHUNK = 65536
DOWNLOAD_LIMIT = 256 * 1024 * 1024
WRITE_LIMIT = 384 * 1024 * 1024
READ_LIMIT = 1024 * 1024 * 1024
UNCOMPRESSED_LIMIT = 256 * 1024 * 1024
FILE_LIMIT = 256 * 1024 * 1024
ENTRY_LIMIT = 32768
FILE_COUNT_LIMIT = 16384
DEPTH_LIMIT = 16
FD_LIMIT = 64
OUTPUT_LIMIT = 256 * 1024
ROSTER_LIMIT = 32768
STOCK_CA = "/private/etc/ssl/cert.pem"
INPUTS = ("jdkHome", "sdkPlatform", "sdkBuildTools", "gradleRoot", "gradleLauncher", "agpAapt2", "bundletool")
AGP_BASE = "https://dl.google.com/dl/android/maven2/com/android/tools/build/"
AAPT2_URL = AGP_BASE + "aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar"
# This is deliberately closed source data, not an arbitrary URL/config interface.
SOURCES = {
    "agp-pom": (AGP_BASE + "gradle/8.9.2/gradle-8.9.2.pom", 12001,
                "97719184aefa93d3c5e8296c39860532227b8801a34c73376c0d9d0db7aa5580", 12001),
    "agp-module": (AGP_BASE + "gradle/8.9.2/gradle-8.9.2.module", 13768,
                   "048f328cf1d56f1e52d71be7d0115c5c9a900add50c939029c86275e0bca38b9", 13768),
    "aapt2-sha256": (AAPT2_URL + ".sha256", 256, None, None),
    "aapt2-osx": (AAPT2_URL, 16 * 1024 * 1024, None, None),
    "gradle": ("https://github.com/gradle/gradle-distributions/releases/download/v8.14.5/gradle-8.14.5-bin.zip",
               138068841, "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854", 138068841),
    "bundletool": ("https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar",
                   32520401, "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29", 32520401),
    "sdk-repository": ("https://dl.google.com/android/repository/repository2-3.xml", 4 * 1024 * 1024, None, None),
}


class Refused(Exception):
    """Only fixed public reason codes, never raw paths or exception strings."""


class Deadline(Refused):
    pass


class CleanupUnknown(Refused):
    pass


def nine(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"


def absolute(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value.encode("utf-8")) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise Refused("invalid_original_path")
    parts = value.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise Refused("invalid_original_path")
    return parts


def relative(value):
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512
            or "\\" in value or ":" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise Refused("archive_member_name")
    parts = value.split("/")
    if (len(parts) > DEPTH_LIMIT or any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255
            or part.endswith((".", " ")) for part in parts)):
        raise Refused("archive_member_name")
    return parts


class Budget:
    def __init__(self):
        self.end = time.monotonic() + PREPARATION_SECONDS
        self.expired = False
        self.errors = []
        self.fds = 0
        self.peak_fds = 0
        self.read_bytes = 0
        self.download_bytes = 0
        self.download_observed_bytes = 0
        self.download_unknown_reads = 0
        self.written_bytes = 0
        self.entries = 0
        self.files = 0
        self.uncompressed_bytes = 0

    def point(self):
        self.expired = self.expired or time.monotonic() >= self.end
        if self.expired:
            raise Deadline("preparation_wall_bound")
        if self.errors:
            raise CleanupUnknown("original_cleanup_unknown")

    def before_open(self):
        self.point()
        if self.fds >= FD_LIMIT:
            raise Refused("descriptor_bound")

    def synced(self, fd, label):
        self.point()
        try:
            os.fsync(fd)
        except BaseException:
            self.errors.append(label + "_sync_unknown")
            raise CleanupUnknown("original_output_sync_unknown")
        self.point()

    def acquired(self):
        # Caller stores a returned original BEFORE this can fail.
        self.fds += 1
        self.peak_fds = max(self.peak_fds, self.fds)
        if self.fds > FD_LIMIT:
            raise Refused("descriptor_bound")
        self.point()

    def close_fd(self, fd, label):
        try:
            os.close(fd)  # Exactly one consuming attempt, no numeric retry.
        except BaseException:
            self.errors.append(label + "_close_unknown")
        finally:
            self.fds -= 1

    def close_object(self, value, label):
        try:
            value.close()
        except BaseException:
            self.errors.append(label + "_close_unknown")

    def charge_read(self, amount):
        self.point()
        if amount < 0 or self.read_bytes + amount > READ_LIMIT:
            raise Refused("read_bound")
        self.read_bytes += amount


class InputPath:
    """Read-only original no-follow chain; no discovery, resolution or writes."""
    def __init__(self, budget, path, *, folder=False):
        self.budget = budget
        self.items = []
        self.fd = None
        self.path = path
        try:
            parts = absolute(path)
            parent = None
            for index, name in enumerate(["/"] + parts):
                budget.point()
                last = index == len(parts)
                directory = not last or folder
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                budget.point()
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                if directory:
                    flags |= os.O_DIRECTORY
                budget.before_open()
                fd = os.open(name, flags, dir_fd=parent)
                self.items.append((fd, parent, name, nine(before), not last))
                budget.acquired()
                after = os.fstat(fd)
                if (nine(before) != nine(after) or directory and not stat.S_ISDIR(after.st_mode)
                        or not directory and (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1)):
                    raise Refused("changed_or_invalid_original")
                if after.st_uid not in (0, os.getuid()):
                    raise Refused("foreign_original_owner")
                parent = fd
            self.fd = parent
        except BaseException:
            self.close()
            raise

    def close(self):
        while self.items:
            fd, parent, name, before, shared = self.items.pop()
            try:
                held = nine(os.fstat(fd))
                named = nine(os.stat(name, dir_fd=parent, follow_symlinks=False))
                if not (held[:5] == before[:5] == named[:5] if shared else held == before == named):
                    self.budget.errors.append("input_postidentity")
            except BaseException:
                self.budget.errors.append("input_postidentity")
            finally:
                self.budget.close_fd(fd, "input")
        self.fd = None

    def read(self, limit):
        self.budget.point()
        size = os.fstat(self.fd).st_size
        if not 0 <= size <= limit:
            raise Refused("input_size_bound")
        out = bytearray()
        while len(out) < size:
            self.budget.charge_read(min(CHUNK, size - len(out)))
            part = os.pread(self.fd, min(CHUNK, size - len(out)), len(out))
            self.budget.point()
            if not part:
                raise Refused("input_short_read")
            out.extend(part)
        self.budget.charge_read(1)
        if os.pread(self.fd, 1, size):
            raise Refused("input_extent_changed")
        return bytes(out)


def original_bytes(budget, path, limit):
    original = InputPath(budget, path)
    try:
        raw = original.read(limit)
    finally:
        original.close()
    budget.point()
    return raw


class PrivateFiles:
    """Only exclusive children of one existing empty task-owned directory."""
    def __init__(self, budget, path):
        self.budget = budget
        self.root = InputPath(budget, path, folder=True)
        self.path = path
        self.dirs = {"": self.root.fd}
        self.identities = {}
        self.rows = []
        self.active = []
        try:
            state = os.fstat(self.root.fd)
            self.identities[""] = nine(state)[:5]
            if (state.st_uid != os.getuid() or stat.S_IMODE(state.st_mode) != 0o700
                    or os.listdir(self.root.fd)):
                raise Refused("original_empty_private_output_required")
            # Our own creations change size/times, not root identity/authority.
            fd, parent, name, before, _ = self.root.items[-1]
            self.root.items[-1] = (fd, parent, name, before, True)
        except BaseException:
            self.close()
            raise

    def directory(self, name):
        if name in self.dirs:
            return self.dirs[name]
        parts = relative(name)
        parent_name = "/".join(parts[:-1])
        parent = self.directory(parent_name)
        self.budget.point()
        if self.budget.entries >= ENTRY_LIMIT:
            raise Refused("entry_bound")
        os.mkdir(parts[-1], 0o700, dir_fd=parent)
        # A completed mkdir is tracked before the next fallible observation.
        self.rows.append({"path": name, "kind": "directory", "privateMode": 0o700, "complete": False})
        self.budget.entries += 1
        self.budget.before_open()
        fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.dirs[name] = fd
        self.budget.acquired()
        state = os.fstat(fd)
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid != os.getuid()
                or stat.S_IMODE(state.st_mode) != 0o700
                or nine(state) != nine(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))):
            raise Refused("created_directory_changed")
        self.identities[name] = nine(state)[:5]
        self.budget.synced(fd, "directory")
        self.budget.synced(parent, "directory_parent")
        self.rows[-1]["complete"] = True
        return fd

    def create(self, name, *, archive=None):
        parts = relative(name)
        parent_name = "/".join(parts[:-1])
        parent = self.directory(parent_name)
        self.budget.point()
        if self.budget.files >= FILE_COUNT_LIMIT or self.budget.entries >= ENTRY_LIMIT:
            raise Refused("file_or_entry_bound")
        self.budget.before_open()
        fd = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        row = {"path": name, "kind": "file", "privateMode": 0o600, "bytes": 0,
               "sha256": None, "complete": False}
        if archive is not None:
            row["archiveMember"] = archive
        token = {"fd": fd, "parent": parent, "name": parts[-1], "before": None, "row": row}
        self.active.append(token)
        self.rows.append(row)
        self.budget.files += 1
        self.budget.entries += 1
        self.budget.acquired()
        state = os.fstat(fd)
        token["before"] = nine(state)[:6]
        if (not stat.S_ISREG(state.st_mode) or state.st_nlink != 1 or state.st_uid != os.getuid()
                or stat.S_IMODE(state.st_mode) != 0o600 or state.st_size != 0):
            raise Refused("created_file_changed")
        return token

    def write(self, token, raw):
        self.budget.point()
        row = token["row"]
        if (len(raw) > CHUNK or row["bytes"] + len(raw) > FILE_LIMIT
                or self.budget.written_bytes + len(raw) > WRITE_LIMIT):
            raise Refused("write_bound")
        view = memoryview(raw)
        while view:
            self.budget.point()
            count = os.write(token["fd"], view)
            if count <= 0:
                raise Refused("output_short_write")
            row["bytes"] += count
            self.budget.written_bytes += count
            view = view[count:]

    def finish(self, token, expected_sha=None, expected_size=None):
        self.budget.point()
        fd, row = token["fd"], token["row"]
        self.budget.synced(fd, "output")
        before = nine(os.fstat(fd))
        if (before[:6] != token["before"] or before[6] != row["bytes"]
                or expected_size is not None and row["bytes"] != expected_size):
            raise Refused("output_identity_or_extent")
        digest = hashlib.sha256()
        offset = 0
        while offset < row["bytes"]:
            amount = min(CHUNK, row["bytes"] - offset)
            self.budget.charge_read(amount)
            part = os.pread(fd, amount, offset)
            self.budget.point()
            if len(part) != amount:
                raise Refused("output_readback_short")
            digest.update(part)
            offset += amount
        self.budget.charge_read(1)
        if os.pread(fd, 1, offset):
            raise Refused("output_readback_extent")
        after = nine(os.fstat(fd))
        named = nine(os.stat(token["name"], dir_fd=token["parent"], follow_symlinks=False))
        observed = digest.hexdigest()
        if before != after or after != named or expected_sha is not None and observed != expected_sha:
            raise Refused("output_digest_or_identity")
        row["sha256"] = observed
        row["complete"] = True
        row["identity"] = list(after)
        self.budget.synced(token["parent"], "output_parent")
        self.close_token(token)
        self.budget.point()
        return row

    def account_refused(self, token):
        # Keep known partial/refused bytes for original-owner accounting, never
        # expose them as a selected supplier. No attempt after a time/sync/close
        # uncertainty; the original owner then handles a negative incomplete run.
        self.budget.point()
        token["row"]["selectionUse"] = "refused-data-only"
        return self.finish(token)

    def close_token(self, token):
        if token in self.active:
            self.active.remove(token)
        fd, token["fd"] = token["fd"], None
        if fd is not None:
            self.budget.close_fd(fd, "output")

    def put(self, name, raw):
        token = self.create(name)
        try:
            for at in range(0, len(raw), CHUNK):
                self.write(token, raw[at:at + CHUNK])
            return self.finish(token, hashlib.sha256(raw).hexdigest(), len(raw))
        finally:
            if token["fd"] is not None:
                self.close_token(token)

    def read(self, row, limit):
        raw = original_bytes(self.budget, self.path + "/" + row["path"], limit)
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise Refused("prepared_body_changed")
        return raw

    def check(self):
        self.budget.point()
        expected = {name: set() for name in self.dirs}
        for row in self.rows:
            parent, _, leaf = row["path"].rpartition("/")
            expected[parent].add(leaf)
            state = os.stat(leaf, dir_fd=self.dirs[parent], follow_symlinks=False)
            if not row["complete"]:
                raise Refused("prepared_output_incomplete_or_changed")
            if row["kind"] == "file":
                if not row["complete"] or list(nine(state)) != row.get("identity"):
                    raise Refused("prepared_output_incomplete_or_changed")
        for name, fd in self.dirs.items():
            self.budget.point()
            if nine(os.fstat(fd))[:5] != self.identities[name] or set(os.listdir(fd)) != expected[name]:
                raise Refused("private_namespace_changed")
            if name:
                parent, _, leaf = name.rpartition("/")
                if nine(os.stat(leaf, dir_fd=self.dirs[parent], follow_symlinks=False))[:5] != self.identities[name]:
                    raise Refused("private_directory_replaced")
            self.budget.synced(fd, "namespace")

    def close(self):
        while self.active:
            self.close_token(self.active[-1])
        for name in reversed(list(self.dirs)):
            if name:
                fd = self.dirs.pop(name)
                self.budget.close_fd(fd, "directory")
        self.root.close()
        self.dirs.clear()


def fixed_source(role):
    if role not in SOURCES:
        raise Refused("fixed_supplier_role_required")
    return SOURCES[role]


def release_redirect(location):
    # Same fixed GitHub asset condition used by the existing Android material
    # reader. Signed public redirect queries are PRIVATE, never in the report.
    if (not isinstance(location, str) or not 0 < len(location) <= 8192 or "\\" in location
            or not all(33 <= ord(c) <= 126 for c in location)):
        raise Refused("supplier_redirect_refused")
    value = urllib.parse.urlsplit(location)
    if (value.scheme != "https" or value.netloc != "release-assets.githubusercontent.com"
            or not re.fullmatch(r"/github-production-release-asset/[0-9]{1,20}/[0-9a-fA-F-]{36}", value.path)
            or not value.query or value.fragment):
        raise Refused("supplier_redirect_refused")
    return location


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def response_headers(response):
    headers = response.headers
    if len(headers) > 128 or sum(len(k) + len(v) + 4 for k, v in headers.items()) > 128 * 1024:
        raise Refused("supplier_header_bound")
    out = {}
    for name in ("Content-Length", "Content-Encoding", "Transfer-Encoding", "Location"):
        values = headers.get_all(name, [])
        if len(values) > 1:
            raise Refused("supplier_header_collision")
        if values:
            out[name.lower()] = values[0].strip()
    if out.get("content-encoding", "identity").lower() != "identity":
        raise Refused("supplier_encoding_refused")
    if "content-length" in out and not re.fullmatch(r"[0-9]{1,12}", out["content-length"]):
        raise Refused("supplier_extent_header")
    if "transfer-encoding" in out and (out["transfer-encoding"].lower() != "chunked" or "content-length" in out):
        raise Refused("supplier_transfer_framing_refused")
    return out


class Downloads:
    def __init__(self, budget, files):
        self.budget, self.files = budget, files
        self.records = []
        # No ambient proxy, netrc, credentials, user CA, SSL environment or
        # platform Keychain configuration is consulted by this context.
        original = InputPath(budget, STOCK_CA)
        try:
            if any(before[3] != 0 or before[2] & 0o022 for _, _, _, before, _ in original.items):
                raise Refused("stock_ca_authority_unavailable")
            ca = original.read(1024 * 1024)
        finally:
            original.close()
        budget.point()
        if b"-----BEGIN CERTIFICATE-----" not in ca:
            raise Refused("stock_ca_unavailable")
        self.ca_sha256 = hashlib.sha256(ca).hexdigest()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=ca.decode("ascii", "strict"))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=context))

    def response(self, url):
        self.budget.point()
        request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "Connection": "close",
                                                       "User-Agent": "MobileReleaseKit-SupplierMetadata/1"}, method="GET")
        try:
            response = self.opener.open(request, timeout=max(0.01, min(10.0, self.budget.end - time.monotonic())))
        except urllib.error.HTTPError as error:
            response = error  # A returned error body is still an original to close.
        return response

    def get(self, role, *, published_sha=None):
        url, limit, source_sha, exact_size = fixed_source(role)
        if published_sha is not None and (role != "aapt2-osx" or not re.fullmatch(r"[0-9a-f]{64}", published_sha)):
            raise Refused("fixed_published_checksum_required")
        expected_sha = source_sha or published_sha
        if role == "aapt2-osx" and expected_sha is None:
            raise Refused("aapt2_checksum_required")
        record = {"role": role, "url": url, "status": "attempted", "httpStatus": None,
                  "sourceSha256": source_sha, "publishedSha256": published_sha,
                  "observedSha256": None, "bytes": None, "redirected": False, "readOutcomeUnknown": False,
                  "authenticationTier": "fixed-source-sha256-and-official-https" if source_sha else
                      "official-https-and-published-sha256" if published_sha else "official-https-observed-metadata"}
        self.records.append(record)
        response = None
        token = None
        try:
            response = self.response(url)
            self.budget.point()
            headers = response_headers(response)
            record["httpStatus"] = response.code
            if url.startswith("https://github.com/"):
                if response.code != 302:
                    raise Refused("fixed_github_asset_redirect_required")
                location = release_redirect(headers.get("location"))
                self.budget.close_object(response, "http_response")
                response = None
                self.budget.point()
                record["redirected"] = True
                response = self.response(location)
                self.budget.point()
                headers = response_headers(response)
                record["httpStatus"] = response.code
            if response.code != 200 or "location" in headers:
                raise Refused("official_supplier_unavailable")
            if "content-length" in headers:
                declared = int(headers["content-length"])
                if declared > limit or exact_size is not None and declared != exact_size:
                    raise Refused("supplier_declared_extent")
            else:
                declared = None
            token = self.files.create("bodies/" + role)
            digest = hashlib.sha256()
            count = 0
            while True:
                self.budget.point()
                allowance = min(CHUNK, limit - count + 1, DOWNLOAD_LIMIT - self.budget.download_bytes)
                if allowance <= 0:
                    raise Refused("supplier_download_bound")
                # Reserve the documented maximum decoded body read BEFORE the
                # call. An exception may conceal partially consumed data: retain
                # that full allowance, never refund/claim exact observed bytes.
                self.budget.download_bytes += allowance
                try:
                    part = response.read(allowance)
                except BaseException:
                    self.budget.download_unknown_reads += 1
                    record["readOutcomeUnknown"] = True
                    raise Refused("supplier_body_read_outcome_unknown") from None
                if not isinstance(part, bytes) or len(part) > allowance:
                    self.budget.download_unknown_reads += 1
                    record["readOutcomeUnknown"] = True
                    raise Refused("supplier_body_read_outcome_unknown")
                self.budget.download_bytes -= allowance - len(part)
                self.budget.download_observed_bytes += len(part)
                count += len(part)
                self.budget.point()
                if count > limit or self.budget.download_bytes > DOWNLOAD_LIMIT:
                    raise Refused("supplier_download_bound")
                if not part:
                    break
                digest.update(part)
                self.files.write(token, part)
            observed = digest.hexdigest()
            if (declared is not None and count != declared or exact_size is not None and count != exact_size
                    or expected_sha is not None and observed != expected_sha):
                raise Refused("supplier_body_digest_or_extent")
            row = self.files.finish(token, observed, count)
            record.update(status="captured", observedSha256=observed, bytes=count)
            return row
        except (Deadline, CleanupUnknown):
            record["status"] = "interrupted"
            raise
        except BaseException:
            record["status"] = "refused"
            if token is not None and token["fd"] is not None:
                self.files.account_refused(token)
            raise
        finally:
            if token is not None and token["fd"] is not None:
                self.files.close_token(token)
            if response is not None:
                self.budget.close_object(response, "http_response")


def zip_members(infos, kind):
    """Validate the entire authenticated directory, not just extracted members."""
    if kind not in ("gradle", "aapt2") or not infos or len(infos) > ENTRY_LIMIT:
        raise Refused("archive_roster_bound")
    names = {}
    spellings = {}
    directories = set()
    total = 0
    files = 0
    selected = []
    for info in infos:
        if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise Refused("archive_encoding_refused")
        isdir = info.is_dir()
        if info.orig_filename != info.filename:
            raise Refused("archive_truncated_member_name")
        name = info.filename[:-1] if isdir else info.filename
        parts = relative(name)
        mode = info.external_attr >> 16
        kind_bits = stat.S_IFMT(mode)
        if kind_bits not in (0, stat.S_IFDIR if isdir else stat.S_IFREG) or mode & 0o7000:
            raise Refused("archive_link_or_special_mode")
        if isdir and info.file_size != 0 or not 0 <= info.file_size <= FILE_LIMIT:
            raise Refused("archive_member_extent")
        folded = name.casefold()
        if folded in names:
            raise Refused("archive_duplicate_or_case_collision")
        names[folded] = (name, isdir)
        for count in range(1, len(parts) + 1):
            spelling = "/".join(parts[:count])
            folded_spelling = spelling.casefold()
            if spellings.get(folded_spelling, spelling) != spelling:
                raise Refused("archive_duplicate_or_case_collision")
            spellings[folded_spelling] = spelling
            if count < len(parts):
                directories.add(folded_spelling)
        if kind == "gradle" and parts[0] != "gradle-8.14.5":
            raise Refused("fixed_gradle_archive_root")
        if not isdir:
            total += info.file_size
            files += 1
        if kind == "gradle" or name == "aapt2":
            selected.append((info, name, isdir, mode))
    if any(parent in names and not names[parent][1] for parent in directories):
        raise Refused("archive_parent_file_collision")
    if total > UNCOMPRESSED_LIMIT or files > FILE_COUNT_LIMIT or len(names.keys() | directories) > ENTRY_LIMIT:
        raise Refused("archive_total_bound")
    if kind == "gradle":
        for name in ("gradle-8.14.5/bin/gradle", "gradle-8.14.5/lib/gradle-launcher-8.14.5.jar"):
            if names.get(name) != (name, False):
                raise Refused("fixed_gradle_role_missing")
    elif len(selected) != 1 or selected[0][1:3] != ("aapt2", False):
        raise Refused("fixed_aapt2_member_required")
    return selected, total, files


class ChargedArchive:
    """One known original file, seekable for ZipFile without a second descriptor."""
    def __init__(self, budget, fd, size):
        self.budget, self.fd, self.size, self.at = budget, fd, size, 0

    def tell(self):
        return self.at

    def seek(self, offset, whence=0):
        self.budget.point()
        target = offset if whence == 0 else self.at + offset if whence == 1 else self.size + offset if whence == 2 else -1
        if not 0 <= target <= self.size:
            raise Refused("archive_seek_bound")
        self.at = target
        return target

    def read(self, size=-1):
        self.budget.point()
        amount = self.size - self.at if size is None or size < 0 else min(size, self.size - self.at)
        if amount > 4 * 1024 * 1024:
            raise Refused("archive_read_window")
        self.budget.charge_read(amount)
        data = os.pread(self.fd, amount, self.at)
        self.budget.point()
        if len(data) != amount:
            raise Refused("archive_original_extent")
        self.at += amount
        return data

    def seekable(self):
        return True


def extract(budget, files, row, kind):
    original = InputPath(budget, files.path + "/" + row["path"])
    archive = None
    try:
        current = nine(os.fstat(original.fd))
        if list(current) != row["identity"]:
            raise Refused("archive_original_changed")
        wrapper = ChargedArchive(budget, original.fd, row["bytes"])
        archive = zipfile.ZipFile(wrapper, "r")
        selected, total, count = zip_members(archive.infolist(), kind)
        if (budget.uncompressed_bytes + total > UNCOMPRESSED_LIMIT
                or budget.files + count > FILE_COUNT_LIMIT):
            raise Refused("aggregate_archive_bound")
        budget.uncompressed_bytes += total
        # Full Gradle DATA, exactly the one native aapt2 DATA member. This is
        # private mode0600/0700, NOT the original archive execution mode.
        for info, name, directory, archive_mode in selected:
            budget.point()
            target = "fixtures/" + name if kind == "gradle" else "fixtures/agp-aapt2"
            if directory:
                files.directory(target)
                continue
            token = files.create(target, archive={"role": kind, "archiveSha256": row["sha256"],
                                                  "name": name, "mode": archive_mode, "bytes": info.file_size})
            stream = None
            try:
                stream = archive.open(info, "r")
                received = 0
                while True:
                    budget.point()
                    part = stream.read(min(CHUNK, info.file_size - received + 1))
                    budget.point()
                    received += len(part)
                    if received > info.file_size:
                        raise Refused("archive_expanded_extent")
                    if not part:
                        break
                    files.write(token, part)
                if received != info.file_size:
                    raise Refused("archive_expanded_short")
                files.finish(token, expected_size=info.file_size)
            except (Deadline, CleanupUnknown):
                raise
            except BaseException:
                if token["fd"] is not None:
                    files.account_refused(token)
                raise
            finally:
                if stream is not None:
                    budget.close_object(stream, "archive_member")
                if token["fd"] is not None:
                    files.close_token(token)
    finally:
        if archive is not None:
            budget.close_object(archive, "archive")
        original.close()
    budget.point()


def properties(raw, wanted):
    if len(raw) > 65536:
        raise Refused("version_metadata_bound")
    values = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        key, found, value = line.partition("=")
        key = key.strip()
        if found and key in wanted:
            value = value.strip().strip('"')
            if key in values or not value or len(value) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise Refused("version_metadata_schema")
            values[key] = value
    return values


def local_selection(budget, environment, role):
    """Exact original public runner inputs, not PATH or installed-tool discovery."""
    if role == "jdkHome":
        path = environment.get("JAVA_HOME_17_arm64")
        absolute(path)
        value = properties(original_bytes(budget, path + "/release", 65536), {"JAVA_VERSION", "IMPLEMENTOR", "OS_ARCH"})
        if (set(value) != {"JAVA_VERSION", "IMPLEMENTOR", "OS_ARCH"} or not value["JAVA_VERSION"].startswith("17.")
                or value["OS_ARCH"] not in ("aarch64", "arm64")):
            raise Refused("jdk17_native_metadata_required")
    elif role in ("sdkPlatform", "sdkBuildTools"):
        root = environment.get("ANDROID_HOME")
        absolute(root)
        path = root + ("/platforms/android-35" if role == "sdkPlatform" else "/build-tools/35.0.0")
        value = properties(original_bytes(budget, path + "/source.properties", 65536), {"Pkg.Revision", "AndroidVersion.ApiLevel"})
        if (role == "sdkPlatform" and (value.get("Pkg.Revision") != "2" or value.get("AndroidVersion.ApiLevel") != "35")
                or role == "sdkBuildTools" and value.get("Pkg.Revision") != "35.0.0"):
            raise Refused("intended_sdk_version_required")
    else:
        raise Refused("fixed_local_role_required")
    # The original path has been inspected, but it is not frozen/admitted. The
    # separate probe reopens/rechecks actual originals; no custody is transferred.
    return path, value


def checksum(raw):
    if not re.fullmatch(rb"[0-9a-fA-F]{64}(?:\r?\n)?", raw):
        raise Refused("published_sha256_schema")
    return raw.strip().decode("ascii").lower()


def sdk_packages(raw):
    """Only two fixed package metadata selections; no download URL authority."""
    if len(raw) > 4 * 1024 * 1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise Refused("sdk_catalog_bound_or_dtd")
    tree = ET.fromstring(raw)
    local = lambda node: node.tag.rsplit("}", 1)[-1]
    selected = {}
    wanted = {"platforms;android-35": "2", "build-tools;35.0.0": "35.0.0"}
    for package in tree:
        if local(package) != "remotePackage" or package.attrib.get("path") not in wanted:
            continue
        name = package.attrib["path"]
        if name in selected:
            raise Refused("sdk_catalog_package_collision")
        revision = [child for child in package if local(child) == "revision"]
        if len(revision) != 1:
            raise Refused("sdk_catalog_revision")
        numbers = {}
        for child in revision[0]:
            key = local(child)
            if key not in ("major", "minor", "micro") or key in numbers or not re.fullmatch(r"[0-9]{1,3}", child.text or ""):
                raise Refused("sdk_catalog_revision")
            numbers[key] = int(child.text)
        expected = (2, 0, 0) if name.startswith("platforms;") else (35, 0, 0)
        if (numbers.get("major"), numbers.get("minor", 0), numbers.get("micro", 0)) != expected:
            raise Refused("sdk_catalog_wrong_revision")
        rows = []
        for archive in package.iter():
            if local(archive) != "archive":
                continue
            host = [child.text for child in archive if local(child) == "host-os"]
            arch = [child.text for child in archive if local(child) == "host-arch"]
            if (len(host) > 1 or len(arch) > 1 or any(not isinstance(item, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", item) for item in host + arch)):
                raise Refused("sdk_catalog_host_collision")
            if host and host != ["macosx"]:
                continue
            complete = [child for child in archive if local(child) == "complete"]
            if len(complete) != 1:
                raise Refused("sdk_catalog_complete_archive")
            fields = {}
            for child in complete[0]:
                key = local(child)
                if key in fields:
                    raise Refused("sdk_catalog_archive_collision")
                fields[key] = child
            if not {"size", "checksum", "url"} <= set(fields):
                raise Refused("sdk_catalog_archive_metadata")
            url = fields["url"].text or ""
            digest = fields["checksum"].text or ""
            algorithm = fields["checksum"].attrib.get("type", "sha1")
            size = fields["size"].text or ""
            if (not re.fullmatch(r"[A-Za-z0-9_.-]+\.zip", url) or algorithm not in ("sha1", "sha256")
                    or not re.fullmatch(r"[0-9a-fA-F]{40}" if algorithm == "sha1" else r"[0-9a-fA-F]{64}", digest)
                    or not re.fullmatch(r"[0-9]{1,10}", size) or not 0 < int(size) <= FILE_LIMIT):
                raise Refused("sdk_catalog_archive_value")
            rows.append({"url": "https://dl.google.com/android/repository/" + url,
                         "publishedChecksumAlgorithm": algorithm, "publishedChecksum": digest.lower(),
                         "bytes": int(size), "hostOs": host[0] if host else "any", "hostArch": arch[0] if arch else "not-declared",
                         "payloadAcquired": False, "installedCorrespondenceVerified": False})
            if len(rows) > 8:
                raise Refused("sdk_catalog_archive_bound")
        if not rows:
            raise Refused("sdk_catalog_fixed_package_missing")
        selected[name] = {"revision": wanted[name], "archives": rows}
    if set(selected) != set(wanted):
        raise Refused("sdk_catalog_fixed_package_missing")
    return selected


def roster_bytes(roster, attempts):
    if (set(roster) != set(INPUTS) or set(attempts) != set(INPUTS) or not any(roster.values())
            or any(row.get("status") not in ("selected", "refused") for row in attempts.values())
            or any((attempts[key]["status"] == "selected") != (roster[key] is not None) for key in INPUTS)):
        raise Refused("no_observed_roster_or_incomplete_attempts")
    for path in roster.values():
        if path is not None:
            absolute(path)
    raw = canonical(roster)
    if len(raw) > ROSTER_LIMIT:
        raise Refused("private_roster_bound")
    return raw


def failure_reason(error):
    if isinstance(error, Refused):
        return str(error)
    if isinstance(error, FileNotFoundError):
        return "original_unavailable"
    if isinstance(error, urllib.error.URLError):
        return "official_transport_unavailable"
    if isinstance(error, (OSError, ValueError, UnicodeError, zipfile.BadZipFile, ET.ParseError)):
        return "invalid_or_unavailable_data"
    return "preparation_refused"


def process_descriptor_bound():
    # Entered only AFTER main's actual Darwin/nonroot admission. This lowers
    # only this process's soft limit, never its hard limit or an existing tighter
    # bound. It is not a transport census or a second process owner.
    import resource
    before = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = 128 if before[0] == resource.RLIM_INFINITY else min(before[0], 128)
    if target <= 0 or before[1] != resource.RLIM_INFINITY and target > before[1]:
        raise Refused("process_descriptor_limit_unavailable")
    if target != before[0]:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, before[1]))
    after = resource.getrlimit(resource.RLIMIT_NOFILE)
    if after != (target, before[1]):
        raise Refused("process_descriptor_limit_not_established")
    return {"beforeSoft": before[0], "soft": after[0], "hard": after[1], "hardUnchanged": True}


def emit_report(budget, report, code):
    # This is still the ORIGINAL preparation endpoint. A prepared JSON body is
    # not positive original process return: encoding and EVERY stdout return
    # must stay timely too. Root separately requires original return/closed
    # bounded capture; nonzero exit never validates even a full prepared body.
    try:
        raw = canonical(report)
        if len(raw) > OUTPUT_LIMIT:
            raw = canonical({"schemaVersion": 1, "status": "output-bound", "qualification": "none", "rosterPublished": False})
            code = 78
        view = memoryview(raw)
        while view:
            budget.expired = budget.expired or time.monotonic() >= budget.end
            if budget.expired:
                return 79 if code == 79 else 78
            count = os.write(1, view)
            if count <= 0 or count > len(view):
                return 79
            view = view[count:]
            budget.expired = budget.expired or time.monotonic() >= budget.end
            if budget.expired:
                return 79 if code == 79 else 78
        return code
    except BaseException:
        # Never publish local exception/path/transcript text or retry an
        # uncertain original write. External capture retains its actual prefix.
        return 79


def main():
    budget = Budget()
    files = None
    download = None
    roster = {key: None for key in INPUTS}
    attempts = {key: {"status": "not-attempted"} for key in INPUTS}
    report = {"schemaVersion": 1, "qualification": "metadata-fixture-preparation-only",
              "status": "partial", "selections": attempts, "rosterPublished": False,
              "completePayloadProvenance": False, "nativeExecution": False,
              "rootOperations": False, "licenseAcceptance": False,
              "jdkOfficialArchiveCorrespondence": "not-collected-await-actual-vendor-and-version",
              "sdkOfficialArchiveCorrespondence": "metadata-only-not-installed-correspondence",
              "fixtureModes": "private0600-and0700-not-vendor-execution-modes",
              "limits": {"seconds": PREPARATION_SECONDS, "downloadBytes": DOWNLOAD_LIMIT,
                         "writeBytes": WRITE_LIMIT, "readBytes": READ_LIMIT, "uncompressedBytes": UNCOMPRESSED_LIMIT,
                         "entries": ENTRY_LIMIT, "files": FILE_COUNT_LIMIT, "depth": DEPTH_LIMIT,
                         "descriptors": FD_LIMIT, "outputBytes": OUTPUT_LIMIT}}
    code = 78
    try:
        if (len(sys.argv) != 2 or sys.platform != "darwin" or os.uname().sysname != "Darwin"
                or os.uname().machine != "arm64" or os.getuid() == 0 or os.geteuid() != os.getuid()
                or sys.version_info < (3, 11) or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode):
            raise Refused("actual_nonroot_isolated_native_host_required")
        report["nativeHost"] = {"system": os.uname().sysname, "release": os.uname().release, "machine": os.uname().machine}
        report["processDescriptorLimit"] = process_descriptor_bound()
        files = PrivateFiles(budget, sys.argv[1])
        for role in INPUTS[:3]:
            budget.point()
            attempts[role] = {"status": "attempted"}
            try:
                path, versions = local_selection(budget, os.environ, role)
                roster[role] = path
                attempts[role] = {"status": "selected", "versionFields": versions,
                                  "provenance": "actual-public-runner-original-not-official-archive-correspondence"}
            except (Deadline, CleanupUnknown):
                raise
            except Exception as error:
                attempts[role] = {"status": "refused", "reason": failure_reason(error)}
        transport_failure = None
        try:
            download = Downloads(budget, files)
            report["stockCaSha256"] = download.ca_sha256
        except (Deadline, CleanupUnknown):
            raise
        except Exception as error:
            transport_failure = failure_reason(error)
            report["transportPrerequisite"] = transport_failure
        # Architecture-bearing aapt2 is acquired before the larger portable
        # Gradle fixture. A refusal does not discard other useful fixed inputs.
        for group in (("agpAapt2",), ("gradleRoot", "gradleLauncher"), ("bundletool",)):
            budget.point()
            for role in group:
                attempts[role] = {"status": "attempted"}
            try:
                if transport_failure is not None:
                    raise Refused("stock_transport_prerequisite_unavailable")
                if group[0] == "agpAapt2":
                    download.get("agp-pom")
                    download.get("agp-module")
                    published = checksum(files.read(download.get("aapt2-sha256"), 256))
                    body = download.get("aapt2-osx", published_sha=published)
                    extract(budget, files, body, "aapt2")
                    roster["agpAapt2"] = files.path + "/fixtures/agp-aapt2"
                elif group[0] == "gradleRoot":
                    body = download.get("gradle")
                    extract(budget, files, body, "gradle")
                    roster["gradleRoot"] = files.path + "/fixtures/gradle-8.14.5"
                    roster["gradleLauncher"] = roster["gradleRoot"] + "/lib/gradle-launcher-8.14.5.jar"
                else:
                    body = download.get("bundletool")
                    roster["bundletool"] = files.path + "/" + body["path"]
                for role in group:
                    attempts[role] = {"status": "selected", "provenance": "authenticated-official-fixture-data-not-native-admission"}
            except (Deadline, CleanupUnknown):
                raise
            except Exception as error:
                for role in group:
                    roster[role] = None
                    attempts[role] = {"status": "refused", "reason": failure_reason(error)}
        budget.point()
        if download is not None:
            try:
                report["sdkOfficialPackageMetadata"] = sdk_packages(files.read(download.get("sdk-repository"), 4 * 1024 * 1024))
            except (Deadline, CleanupUnknown):
                raise
            except Exception as error:
                report["sdkMetadataRefusal"] = failure_reason(error)
        # No all-null or unattempted roster is ever published as a probe input.
        raw = roster_bytes(roster, attempts)
        row = files.put("roster.json", raw)
        files.check()
        report.update(rosterPublished=True, inputRosterSha256=row["sha256"],
                      status="prepared" if all(value is not None for value in roster.values()) else "prepared-with-refused-inputs")
        code = 0 if report["status"] == "prepared" else 2
    except BaseException as error:
        report["failure"] = failure_reason(error)
        report["status"] = "preparation-refused"
        code = 78
    finally:
        if files is not None:
            report["outputs"] = [{key: value for key, value in row.items() if key != "identity"} for row in files.rows]
            files.close()
        if download is not None:
            report["supplierResponses"] = download.records
    budget.expired = budget.expired or time.monotonic() >= budget.end
    if budget.expired:
        report.update(status="preparation-refused", failure="preparation_wall_bound", rosterPublished=False)
        code = 78
    report["cleanup"] = "known-originals-closed" if not budget.errors and budget.fds == 0 else "unknown"
    report["cleanupErrors"] = budget.errors[:64]
    report["accounting"] = {"readBytes": budget.read_bytes, "downloadBytes": budget.download_bytes,
                            "downloadObservedBytes": budget.download_observed_bytes,
                             "downloadUnknownReadCount": budget.download_unknown_reads,
                             "downloadByteAccounting": "returned-body-exact-plus-reserved-allowance-for-unknown-reads",
                             "writtenBytes": budget.written_bytes, "uncompressedBytes": budget.uncompressed_bytes,
                            "entries": budget.entries, "files": budget.files, "peakDescriptors": budget.peak_fds,
                            "remainingDescriptors": budget.fds,
                            "descriptorScope": "returned-filesystem-originals; at-most-one-stdlib-http-response",
                            "nativeTransportDescriptorCensus": False}
    if budget.errors or budget.fds:
        report["rosterPublished"] = False
        code = 79
    return emit_report(budget, report, code)


if __name__ == "__main__":
    raise SystemExit(main())
