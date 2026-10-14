#!/usr/bin/env python3
"""One read-only engineering log query; never submission or release authority."""
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import types

BASE = "84e745a02668b9e5f7f30a407a04d829f34572d9"
SUBMISSION = "ffc5e13c-0d54-4033-b02e-b327c5bf07d3"
LOG_SHA = "04d9d2a292ee65984f54abaec50c2c0921ea7f354508f6558ea09cabe513c774"
ARCHIVE = "MobileReleaseKit.dmg"
REF = "refs/heads/verify/desktop-macos-notary-log"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-notary-log.yml@" + REF
KEY_VARIABLE = "MRK_MACOS_NOTARY_API_KEY_BASE64"
PROFILE = {"schemaVersion": 1, "mode": "app-store-connect-team-key", "teamId": "7CGZ2343AA",
           "keyId": "59VQCHM463", "issuerId": "375572d7-6413-4f28-96af-2f39c49227fe"}
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
REPORT = "macos-notary-log-diagnostic.json"
SOURCE_PINS = {
    "desktop/tools/macos_android_helper_package.py": (558617, "f2b5e3fdc2ec67b593f8fd5876c5ec7181dd6cb30eb3687ecc84d518b1cb98e0"),
    "desktop/tools/stage_macos_installed.py": (374430, "da4cb87ca73f7086ac00ded23359faaf5a305e0ab934136f3cfb3da0586788bf"),
    "desktop/tools/macos_aqua_qualification.py": (464005, "437a511006207712756ad6a69c1ba84370cb0029cb20341b2f1dcbcc74b410a3"),
    "desktop/tools/macos_e2_native_fixture.py": (390457, "bcfbaf9ec8a8ae3253ef0ac91a1e73256de00a9adb6a9d280f64127b340cd51e"),
    "desktop/packaging/macos-notary-service.json": (149, "aef87ad93100be46f171523a830a5f6b67188c33748049aa843ea253c65e29b5"),
}
OWNER_PINS = {
    "owned_process.py": "ba23e4c65a916c297190c028bd5fd934723ef496105a46ec45c2a2e4b2f22b59",
    "_command_process.py": "ad1b7b7140d219674efd326ec529315fdf5a9fd55701a069d7f930a86e702a43",
    "_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "cancellation.py": "eff29612208b2d6d81afa5638fa998778b17f39107357bb7a2f954facdc2628a",
}
LOG_LABELS = frozenset(("notary-json-bound", "notary-json-keys", "notary-json-constant",
    "notary-json-format", "notary-json-object", "notary-fixed-archive-name", "notary-log-binding",
    "notary-uuid", "notary-log-metadata", "notary-log-status-code", "notary-log-issues-bound",
    "notary-log-issue-shape", "notary-log-issue-metadata", "notary-log-issue-code",
    "notary-log-tickets-bound", "notary-log-ticket-shape", "notary-log-success-with-errors"))
PROBE_LABELS = frozenset(("source-selection", "helper-source", "projection-site", "diagnostic-bound",
    "original-admission", "original-admission-delta", "key-purpose", "key-root", "key-write", "key-original",
    "key-readback", "key-mode", "key-retirement-census", "key-close-unknown", "key-unlink-original",
    "key-root-not-empty", "key-root-close-unknown", "key-root-original", "key-retirement", "key-retirement-unknown",
    "probe-deadline", "probe-platform", "probe-context", "donor-source", "source-pin", "source-profile",
    "probe-source", "detached-source", "owner-source", "probe-tmp", "tool-original-admission",
    "source-post", "probe-role", "probe-original-reserve", "probe-original-return", "probe-original-nonzero",
    "probe-resolver", "probe-log-original-digest", "probe-key-finality", "probe-work-census",
    "probe-tmp-close", "probe-work-close", "probe-work-original", "probe-work-retirement",
    "probe-tool-close", "probe-input-close", "probe-final-close"))
KEYS = ("logFormatVersion", "jobId", "status", "archiveFilename", "issues", "ticketContents",
        "statusSummary", "statusCode", "uploadDate", "sha256")


class Refused(ValueError):
    """Closed probe labels; no raw error rendering."""


def need(value, label):
    if not value:
        raise Refused(label)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def passive_namespace(body, names, *, methods=()):
    """Exact selected existing SOURCE, never import the historical hosted main."""
    tree = ast.parse(body)
    selected = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in names]
    need(len(selected) == len(names) and {node.name for node in selected} == set(names), "source-selection")
    if methods:
        operation = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Operation"]
        need(len(operation) == 1, "source-selection")
        chosen = [node for node in operation[0].body if isinstance(node, ast.FunctionDef) and node.name in methods]
        need(len(chosen) == len(methods) and {node.name for node in chosen} == set(methods), "source-selection")
        selected.extend(chosen)
    namespace = dict(ast=ast, base64=base64, hashlib=hashlib, json=json, os=os, Path=Path, re=re,
                     stat=stat, sys=sys, time=time, READ_FLAGS=os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     NOTARY_XCODE=Path("/Applications/Xcode.app/Contents/Developer"),
                     NOTARY_ZIP_NAME="MobileReleaseKit-notary-payload.zip", NOTARY_KEY_VARIABLE=KEY_VARIABLE,
                     OWNER_PINS=dict(OWNER_PINS))
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<authenticated-passive-source>", "exec"), namespace)
    return namespace


def helper_namespace(body):
    need(len(body) == SOURCE_PINS["desktop/tools/macos_android_helper_package.py"][0]
         and digest(body) == SOURCE_PINS["desktop/tools/macos_android_helper_package.py"][1], "helper-source")
    return passive_namespace(body, {"Refused", "need", "digest", "signature", "notary_json", "notary_uuid",
        "notary_text", "notary_log_data", "notary_key_data"},
        methods={"register", "close", "notary_tool", "notary_tool_post"})


def classify_log(body, helper_body):
    """Execute all known current predicates; independent submitted SHA is UNKNOWN."""
    namespace = helper_namespace(helper_body)
    tree = ast.parse(helper_body)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "notary_log_data")
    original_ast = ast.dump(function, include_attributes=False)
    ticket_sites = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "need" and len(node.args) == 2
                    and isinstance(node.args[1], ast.Constant) and node.args[1].value == "notary-log-ticket-shape"]
    expected_architecture = ("row.get('arch') in ('arm64', 'x86_64', 'i386') or (archive_name in "
        "('MobileReleaseKit.pkg', 'MobileReleaseKit.dmg', 'Remove.pkg', 'MobileReleaseKit-Remove.dmg') "
        "and row['path'] == archive_name and (row.get('arch') is None))")
    need(len(ticket_sites) == 1 and isinstance(ticket_sites[0].args[0], ast.BoolOp)
         and isinstance(ticket_sites[0].args[0].op, ast.And) and len(ticket_sites[0].args[0].values) == 7
         and ast.unparse(ticket_sites[0].args[0].values[-1]) == expected_architecture, "projection-site")
    shape_function = ast.parse("def _diagnostic_non_architecture_ticket_shape(row):\n    return True\n").body[0]
    shape_function.body[0].value = ast.BoolOp(op=ast.And(), values=ticket_sites[0].args[0].values[:-1])
    exec(compile(ast.fix_missing_locations(ast.Module(body=[shape_function], type_ignores=[])),
                 "<exact-ticket-shape-diagnostic>", "exec"), namespace)
    sites = [node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id == "need" and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
             and node.args[1].value == "notary-log-upload-sha256"]
    need(len(sites) == 1 and ast.unparse(sites[0].args[0]) == "value['sha256'] == archive_sha256", "projection-site")
    observed = []
    namespace["observe_unknown_hash"] = lambda: observed.append(True)
    sites[0].func = ast.Name(id="observe_unknown_hash", ctx=ast.Load())
    sites[0].args = []
    function.name = "_diagnostic_log_projection"
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), "<diagnostic-only-log-projection>", "exec"), namespace)
    failure = None
    try:
        namespace["_diagnostic_log_projection"](body, {"id": SUBMISSION, "status": "Accepted"}, None, archive_name=ARCHIVE)
    except BaseException as error:
        failure = (error.args[0] if type(error) is namespace["Refused"] and len(error.args) == 1
                   and type(error.args[0]) is str and error.args[0] in LOG_LABELS else "unclassified")
    result = {"schemaVersion": 1, "kind": "fixed-notary-log-diagnostic", "diagnosticOnly": True,
        "nativeSuccessInferred": False, "productReady": False, "deliveryInferred": False,
        "originalParserPassInferred": False, "submittedImageShaComparison": "unknown-expected",
        "hashPredicateReached": bool(observed), "firstKnownFailure": failure,
        "firstKnownFailurePosition": ("none" if failure is None else "after-unknown-hash" if observed else "before-unknown-hash"),
        "exactOriginalFirstFailure": ("known-before-hash" if failure in LOG_LABELS and not observed else "unresolved"),
        "knownPredicateResult": "refused" if failure is not None else "other-known-predicates-passed-hash-unknown",
        "parserAstSha256": digest(original_ast.encode()), "knownKeyPresenceMask": 0,
        "knownKeyTypeMasks": {name: 0 for name in ("null", "boolean", "integer", "string", "list", "object", "other")},
        "unknownKeyCount": None, "ticketRowCount": None, "issueRowCount": None,
        "exactNestedPackageAbsentArchRows": 0, "exactNestedPackageNullArchRows": 0,
        "exactArchiveAbsentArchRows": 0, "exactArchiveNullArchRows": 0,
        "malformedNonArchitectureTicketRows": None,
        "architectureClasses": {name: 0 for name in ("arm64", "x86_64", "i386", "absent", "null", "other-string", "wrong-type")},
        "ticketPathClasses": {name: 0 for name in ("exact-archive", "exact-nested-Install.pkg", "under-Install.pkg", "other-relative", "other-invalid")}}
    try:
        value = namespace["notary_json"](body, 1024 * 1024)
    except BaseException:
        value = None
    if type(value) is dict:
        result["knownKeyPresenceMask"] = sum(1 << index for index, key in enumerate(KEYS) if key in value)
        for index, key in enumerate(KEYS):
            if key in value:
                item = value[key]
                category = ("null" if item is None else "boolean" if type(item) is bool else
                            "integer" if type(item) is int else "string" if type(item) is str else
                            "list" if type(item) is list else "object" if type(item) is dict else "other")
                result["knownKeyTypeMasks"][category] |= 1 << index
        result["unknownKeyCount"] = sum(key not in KEYS for key in value)
        for field, output in (("issues", "issueRowCount"), ("ticketContents", "ticketRowCount")):
            rows = value.get(field)
            result[output] = 0 if rows is None else len(rows) if type(rows) is list and len(rows) <= 2048 else None
        rows = value.get("ticketContents")
        if rows is None or type(rows) is list and len(rows) <= 2048:
            result["malformedNonArchitectureTicketRows"] = 0
        for row in rows if type(rows) is list and len(rows) <= 2048 else ():
            if not namespace["_diagnostic_non_architecture_ticket_shape"](row):
                result["malformedNonArchitectureTicketRows"] += 1
            if type(row) is dict and row.get("path") == ARCHIVE:
                if "arch" not in row:
                    result["exactArchiveAbsentArchRows"] += 1
                elif row["arch"] is None:
                    result["exactArchiveNullArchRows"] += 1
            if type(row) is dict and row.get("path") == ARCHIVE + "/Install.pkg":
                if "arch" not in row:
                    result["exactNestedPackageAbsentArchRows"] += 1
                elif row["arch"] is None:
                    result["exactNestedPackageNullArchRows"] += 1
            if type(row) is not dict:
                result["architectureClasses"]["wrong-type"] += 1
                result["ticketPathClasses"]["other-invalid"] += 1
                continue
            arch = row.get("arch")
            category = ("absent" if "arch" not in row else "null" if arch is None else
                        arch if type(arch) is str and arch in ("arm64", "x86_64", "i386") else
                        "other-string" if type(arch) is str else "wrong-type")
            result["architectureClasses"][category] += 1
            path = row.get("path")
            category = "other-invalid"
            if type(path) is str and namespace["notary_text"](path, 4096):
                category = ("exact-archive" if path == ARCHIVE else "exact-nested-Install.pkg" if path == ARCHIVE + "/Install.pkg" else
                            "under-Install.pkg" if path.startswith(ARCHIVE + "/Install.pkg/") else
                            "other-relative" if not path.startswith("/") and not any(p in ("", ".", "..") for p in path.split("/")) else "other-invalid")
            result["ticketPathClasses"][category] += 1
    need(len(json.dumps(result, separators=(",", ":")).encode()) <= 16 * 1024, "diagnostic-bound")
    return result


class Admission:
    """One finite pre-open quote over genuine donor Originals, no new owner."""
    def __init__(self, originals):
        self.book, self.reserved = originals, 0

    def reserve(self, count):
        need(type(count) is int and 0 <= count and self.reserved + count <= 96, "original-admission")
        self.reserved += count  # Nonrefunded even when the subsequent original refuses.

    def directory(self, path):
        path, missing = Path(path), 0
        current = path
        while current not in self.book.directories:
            missing += 1
            if current == Path("/"):
                break
            current = current.parent
        self.reserve(missing)
        before = len(self.book.entries)
        entry = self.book.directory(path)
        need(len(self.book.entries) - before == missing, "original-admission-delta")
        return entry

    def fresh_directory(self, parent, name):
        need(type(name) is str and (name in ("notary-key", "tmp")
             or re.fullmatch(r"mrk-notary-log-probe\.[0-9a-f]{24}", name)), "original-admission")
        self.reserve(1)  # Before mkdir or the first new original open; never refund.
        self.book.check_one(parent)
        before = len(self.book.entries)
        os.mkdir(name, 0o700, dir_fd=parent["fd"])
        entry = self.book.directory(parent["path"] / name)
        need(len(self.book.entries) - before == 1 and stat.S_IMODE(entry["identity"][2]) == 0o700
             and entry["identity"][3:5] == (os.getuid(), os.getgid()), "original-admission-delta")
        return entry

    def file(self, path, limit, **policy):
        self.directory(Path(path).parent)
        self.reserve(1)
        before = len(self.book.entries)
        value = self.book.file(path, limit, **policy)
        need(len(self.book.entries) - before == 1, "original-admission-delta")
        return value


@contextlib.contextmanager
def private_key(admission, work_entry, body, clock, settled, no_xattrs, calls):
    """Original known closure only. This fixed probe never claims Apple authentication."""
    book, root, entry = admission.book, None, None
    state = {"created": False, "closed": False, "retired": False}
    primary = None
    name = "AuthKey_" + PROFILE["keyId"] + ".p8"
    try:
        need(type(body) is bytes and 0 < len(body) <= 8192 and len(calls) == 1
             and calls[0] == {"role": "resolve-notarytool", "entered": True, "returned": True,
                              "capturesSettled": True, "returncode": 0} and settled(), "key-purpose")
        clock(); book.check_one(work_entry)
        root = admission.fresh_directory(work_entry, "notary-key")
        need(not os.listdir(root["fd"]) and stat.S_IMODE(root["identity"][2]) == 0o700, "key-root")
        admission.reserve(1)  # Before the exclusive original open, never in register.
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root["fd"])
        entry = book.register(fd, root["path"] / name, "file")
        entry["parent"] = root
        state["created"] = True
        offset = 0
        while offset < len(body):
            clock(); count = os.write(fd, body[offset:]); need(count > 0, "key-write"); offset += count
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
             and info.st_nlink == 1 and info.st_size == len(body) and stat.S_IMODE(info.st_mode) == 0o600, "key-original")
        entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                             info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(book.read(entry) == body, "key-readback")
        os.fchmod(fd, 0o400); os.fsync(fd)
        after = os.fstat(fd)
        identity = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        need(identity[:2] == entry["identity"][:2] and identity[2] == stat.S_IFREG | 0o400
             and identity[3:8] == entry["identity"][3:8], "key-mode")
        entry["identity"] = identity
        no_xattrs(fd)
        need(book.read(entry) == body, "key-readback")
        clock(); book.check_one(work_entry)
        yield str(root["path"] / name), state
    except BaseException as error:
        primary = error
    finally:
        if root is not None and entry is not None and entry["identity"] is not None and settled():
            try:
                clock(work=False); book.check_one(work_entry); book.check_one(root)
                no_xattrs(entry["fd"])
                need(os.listdir(root["fd"]) == [name] and book.read(entry) == body, "key-retirement-census")
                book.close(entry); need(entry["closed"], "key-close-unknown"); state["closed"] = True
                named = os.stat(name, dir_fd=root["fd"], follow_symlinks=False)
                need((named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid, named.st_nlink,
                      named.st_size, named.st_mtime_ns, named.st_ctime_ns) == entry["identity"], "key-unlink-original")
                os.unlink(name, dir_fd=root["fd"]); need(not os.listdir(root["fd"]), "key-root-not-empty")
                book.check_one(root); book.close(root); need(root["closed"], "key-root-close-unknown")
                named = os.stat("notary-key", dir_fd=work_entry["fd"], follow_symlinks=False)
                need((named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid) == root["identity"], "key-root-original")
                os.rmdir("notary-key", dir_fd=work_entry["fd"])
                need("notary-key" not in os.listdir(work_entry["fd"]), "key-retirement")
                state["retired"] = True; clock(work=False)
            except BaseException as error:
                state["cleanupErrorClass"] = "unclassified-retirement"
                if primary is None:
                    primary = error
        elif root is not None and primary is None:
            primary = Refused("key-retirement-unknown")
        if primary is not None:
            raise primary


def main():
    book = admission = tools = work_entry = tmp_entry = None
    authentication, context_admitted = None, False
    calls, source_entries = [], []
    stage, failure, report = "admission", None, None
    started, observed = time.monotonic_ns(), [time.monotonic_ns()]
    def clock(*, work=True):
        now = time.monotonic_ns()
        need(started <= observed[0] <= now < started + (180 if work else 240) * 1_000_000_000, "probe-deadline")
        observed[0] = now
        return now
    def settled():
        return all(row["returned"] and row["capturesSettled"] for row in calls)
    try:
        need(sys.platform == "darwin" and sys.version_info >= (3, 11) and os.getuid() != 0
             and os.getuid() == os.geteuid() and len(sys.argv) == 1, "probe-platform")
        env = os.environ
        source = env.get("GITHUB_SHA")
        need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source) and source != "0" * 40
             and source == env.get("GITHUB_WORKFLOW_SHA") and env.get("GITHUB_ACTIONS") == "true"
             and env.get("GITHUB_REPOSITORY") == REPOSITORY and env.get("GITHUB_REF") == REF
             and env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("GITHUB_EVENT_NAME") == "push"
             and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("RUNNER_OS") == "macOS"
             and env.get("RUNNER_ARCH") == "ARM64" and env.get("GITHUB_WORKSPACE") == str(CHECKOUT)
             and env.get("GITHUB_JOB") == "diagnose"
             and all(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(k, "")) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "probe-context")
        context_admitted = True
        # Bootstrap only the exact passive donor; then keep its genuine original open.
        donor = (CHECKOUT / "desktop/tools/macos_e2_native_fixture.py").read_bytes()
        need((len(donor), digest(donor)) == SOURCE_PINS["desktop/tools/macos_e2_native_fixture.py"], "donor-source")
        original_ns = passive_namespace(donor, {"Originals", "Refused", "need", "signature"})
        book = original_ns["Originals"](); admission = Admission(book)
        checkout_entry = admission.directory(CHECKOUT)
        for relative, (size, sha) in SOURCE_PINS.items():
            entry, body = admission.file(CHECKOUT / relative, size, modes=(0o644, 0o444))
            need(len(body) == size and digest(body) == sha, "source-pin")
            source_entries.append((entry, body))
        bodies = {str(entry["path"].relative_to(CHECKOUT)): body for entry, body in source_entries}
        helper = helper_namespace(bodies["desktop/tools/macos_android_helper_package.py"])
        xattrs = passive_namespace(bodies["desktop/tools/stage_macos_installed.py"], {"no_xattrs", "need", "Refused"})
        xattrs["_DARWIN_XATTRS"] = None
        need(helper["notary_json"](bodies["desktop/packaging/macos-notary-service.json"], 1024) == PROFILE, "source-profile")
        entry, body = admission.file(Path(__file__), 65536, modes=(0o644, 0o444))
        need(digest(body) == env.get("MRK_NOTARY_LOG_PROBE_SHA256"), "probe-source")
        source_entries.append((entry, body))
        entry, body = admission.file(CHECKOUT / ".git/HEAD", 64, modes=(0o644, 0o444))
        need(body == (source + "\n").encode(), "detached-source"); source_entries.append((entry, body))
        for relative, sha in OWNER_PINS.items():
            entry, body = admission.file(CHECKOUT / "src/mobile_release" / relative, 256 * 1024, modes=(0o644, 0o444))
            need(digest(body) == sha, "owner-source"); source_entries.append((entry, body))
        owner_ns = passive_namespace(bodies["desktop/tools/macos_aqua_qualification.py"], {"load_owner", "need", "Refused", "digest"})
        owner = owner_ns["load_owner"](CHECKOUT)
        parent = admission.directory(WORK_PARENT)
        work = WORK_PARENT / ("mrk-notary-log-probe." + os.urandom(12).hex())
        work_entry = admission.fresh_directory(parent, work.name)
        tmp_entry = admission.fresh_directory(work_entry, "tmp")
        need(not os.listdir(tmp_entry["fd"]), "probe-tmp")
        tools = types.SimpleNamespace(entries=[], entry_registry={}, errors=[], app_absence=None, update=None,
                                      phase="finalize-image", notary_tools={})
        for name in ("register", "close", "notary_tool", "notary_tool_post"):
            setattr(tools, name, types.MethodType(helper[name], tools))
        admission.reserve(1)
        tool = tools.notary_tool("notarytool")
        need(len(tools.entries) == 1, "tool-original-admission")
        def post():
            clock(); book.check()
            for original, contents in source_entries:
                need(book.read(original) == contents, "source-post")
            tools.notary_tool_post(tool)
        native_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work), "TMPDIR": str(work / "tmp") + "/",
                      "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer"}
        def call(role, argv, maximum, limit):
            nonlocal stage
            need(role == ("resolve-notarytool", "log")[len(calls)] and settled(), "probe-role")
            post(); now = clock(); timeout = min(maximum, (started + 180_000_000_000 - now - 3_000_000_000) // 1_000_000_000)
            need(timeout >= 1, "probe-original-reserve")
            row = {"role": role, "entered": True, "returned": False, "capturesSettled": False}
            calls.append(row); stage = role
            try:
                result = owner.run_owned(argv, environ=native_env, cwd=work, timeout=timeout, capture=True, text=False, output_limit=limit)
            except BaseException as error:
                for key, attribute in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanupComplete", "cleanup_complete")):
                    value = getattr(error, attribute, None)
                    row[key] = value if type(value) is bool else None
                raise
            need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int
                 and type(result.args) in (list, tuple) and tuple(result.args) == tuple(argv)
                 and type(result.stdout) is bytes and type(result.stderr) is bytes
                 and len(result.stdout) + len(result.stderr) <= limit, "probe-original-return")
            row.update(returned=True, capturesSettled=True, returncode=result.returncode)
            post(); need(result.returncode == 0, "probe-original-nonzero")
            return result
        resolved = call("resolve-notarytool", ["/usr/bin/xcrun", "--find", "notarytool"], 30, 4096)
        need(resolved.stdout in ((str(tool["fixed"]) + "\n").encode(), (str(tool["path"]) + "\n").encode())
             and resolved.stderr == b"", "probe-resolver")
        key_body = helper["notary_key_data"](env)
        with private_key(admission, work_entry, key_body, clock, settled, xattrs["no_xattrs"], calls) as (key_path, authentication):
            result = call("log", [str(tool["path"]), "log", SUBMISSION, "--key", key_path,
                "--key-id", PROFILE["keyId"], "--issuer", PROFILE["issuerId"]], 120, 1024 * 1024)
            need(digest(result.stdout) == LOG_SHA, "probe-log-original-digest")
            report = classify_log(result.stdout, bodies["desktop/tools/macos_android_helper_package.py"])
            result = key_body = None  # No raw log/key digest in public output.
        need(authentication == {"created": True, "closed": True, "retired": True}, "probe-key-finality")
        report.update(notaryKeyLifecycle=authentication, originalLogShaMatched=True, originalCalls=calls,
            source=source, parserSource=BASE, runId=env["GITHUB_RUN_ID"], runAttempt=env["GITHUB_RUN_ATTEMPT"],
            workflow=WORKFLOW, job="diagnose", fixedSubmission=SUBMISSION)
        post(); stage = "retirement"
        need(set(os.listdir(work_entry["fd"])) == {"tmp"} and not os.listdir(tmp_entry["fd"]), "probe-work-census")
        book.close(tmp_entry); need(tmp_entry["closed"], "probe-tmp-close")
        os.rmdir("tmp", dir_fd=work_entry["fd"])
        book.check_one(work_entry); book.close(work_entry); need(work_entry["closed"], "probe-work-close")
        named = os.stat(work.name, dir_fd=parent["fd"], follow_symlinks=False)
        need((named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid) == work_entry["identity"], "probe-work-original")
        os.rmdir(work.name, dir_fd=parent["fd"]); need(work.name not in os.listdir(parent["fd"]), "probe-work-retirement")
        for original in tools.entries:
            tools.close(original)
        need(not tools.errors and all(entry["closed"] for entry in tools.entries), "probe-tool-close")
        for original, contents in source_entries:
            book.close(original)
        need(all(original["closed"] for original, contents in source_entries), "probe-input-close")
        clock(work=False)
        report.update(workRetired=True, queryInputAndToolOriginalsClosed=True, diagnosticOperationComplete=True,
                      reportParentFinalityRequiresOriginalExit=True, outerFinalityRequired=True)
        admission.directory(CHECKOUT); admission.reserve(1)
        payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
        need(len(payload) <= 16 * 1024, "diagnostic-bound")
        book.publish(CHECKOUT / REPORT, payload, mode=0o600)
        need(book.finish(), "probe-final-close"); clock(work=False)
        return 0
    except BaseException as error:
        failure = (error.args[0] if type(error) is Refused and len(error.args) == 1
                   and type(error.args[0]) is str and error.args[0] in PROBE_LABELS else "unclassified")
        # Independent finite diagnostics may be published without erasing an unknown
        # private operation. Never overwrite an existing success/provisional report.
        if context_admitted and book is not None:
            try:
                clock(work=False)
                admission.directory(CHECKOUT); admission.reserve(1)
                public = {"schemaVersion": 1, "kind": "fixed-notary-log-probe-refused", "stage": stage,
                    "failure": failure, "diagnosticOnly": True, "nativeSuccessInferred": False,
                    "productReady": False, "deliveryInferred": False, "knownChildSettlement": settled(),
                    "notaryKeyLifecycle": authentication, "originalCalls": calls, "rawOutputPublished": False,
                    "source": source, "parserSource": BASE, "runId": env["GITHUB_RUN_ID"],
                    "runAttempt": env["GITHUB_RUN_ATTEMPT"], "workflow": WORKFLOW,
                    "job": "diagnose", "outerFinalityRequired": True}
                payload = (json.dumps(public, sort_keys=True, separators=(",", ":")) + "\n").encode()
                need(len(payload) <= 16 * 1024, "diagnostic-bound")
                book.publish(CHECKOUT / REPORT, payload, mode=0o600)
                clock(work=False)
            except BaseException:
                pass  # Retain original failure, never retry or use another output.
    finally:
        # Unknown child settlement means private originals are retained, not erased.
        if settled():
            if tools is not None:
                for entry in tools.entries:
                    tools.close(entry)
            if book is not None:
                book.finish()
    print(json.dumps({"schemaVersion": 1, "kind": "fixed-notary-log-probe-refused", "stage": stage,
        "failure": failure, "diagnosticOnly": True, "nativeSuccessInferred": False, "productReady": False,
        "deliveryInferred": False, "knownChildSettlement": settled(), "rawOutputPublished": False}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
