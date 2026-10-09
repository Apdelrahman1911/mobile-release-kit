#!/usr/bin/env python3
"""Three read-only Intel system-image observations, never supplier authority.

Only Apple's fixed root-admitted CLT dyld_info executes. No vendor image is dlopened, compiled,
installed or qualified. A missing selected image is an ordinary negative result.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import stat
import sys
import time

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-intel-os-providers"
WORKFLOW_PATH = ".github/workflows/desktop-macos-intel-os-providers.yml"
WORKFLOW = REPOSITORY + "/" + WORKFLOW_PATH + "@" + REF
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
SELF = "desktop/tools/macos_intel_os_providers.py"
FIXTURE = "desktop/tools/macos_e2_native_fixture.py"
QUALIFICATION = "desktop/tools/macos_aqua_qualification.py"
SOURCE_PINS = {
    'desktop/tools/macos_aqua_qualification.py': (455054, '8273006e10b2414108d887453f2b5cd8796c23b022d9edd839b58294d39f9246'),
    'src/mobile_release/owned_process.py': (9037, '0c7c87c7eaf27629be2eb33c195a956b6c40b7b5883214a08e15f255ac4939b8'),
    'src/mobile_release/_command_process.py': (172299, '30781e5b264fbcdb4c09028829e0606095a79e5c7a194556484f5ca8b2bfad69'),
    'src/mobile_release/_native_process.py': (62175, '70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4'),
    'src/mobile_release/cancellation.py': (31041, '5f469444f42b5ad6a69ecce8161a7d83e67303c92a221a31f88c079f4ff29d35'),
    'desktop/tools/macos_e2_native_fixture.py': (390498, 'e4ac0883d7a077d59cc065e3467b4052a47476838f7d0a98cc0e17caaee892a8'),
    'src/mobile_release/__init__.py': (144, '557bcb0cdcf7f7ef329f04f82cf388c746bb73eba34857b97782a8bcf2e596b2'),
    'src/mobile_release/errors.py': (749, '26427cedbd05945c1a869af20228f9a04fe1e30d950a2dc246dd0795708a0853'),
    'src/mobile_release/_lifetime_evidence.py': (19072, 'f79d21c9846d7527b9c08f474ef47bc57515f592a090b7c61ba9046a82232da3'),
    'src/mobile_release/_store_lane_contract.py': (9500, '8726cf9bdb053b3d7f30eb9c8307c18239dc518476b2f895ef1610efa65e040e'),
    'src/mobile_release/_store_lane_evidence.py': (17638, 'bcea0084032ffbd43c15f5682f456965aff812e5007d3211a5afe605fc4d5872'),
}
CAPTURE_LIMIT = 65536
TOOL_LIMIT = 16 * 1024 * 1024
FILE_LIMIT = 8 * 1024 * 1024
RECORD_LIMIT = 512 * 1024
SYSTEM_PLIST = Path("/System/Library/CoreServices/SystemVersion.plist")
XCRUN = Path("/usr/bin/xcrun")
DEVELOPER_DIR = Path("/Library/Developer/CommandLineTools")
SELECTED_TOOL = DEVELOPER_DIR / "usr/bin/dyld_info"
ARCHES = ("x86_64", "x86_64h")
PROVIDERS = (
    "/System/Library/Frameworks/JavaVM.framework/Versions/A/JavaVM",
    "/usr/lib/libgcc_s.1.dylib",
    "/usr/lib/libncurses.5.4.dylib",
)
ROLES = ("resolve-dyld-info", "provider-javavm", "provider-libgcc", "provider-ncurses")
OPTIONS = ("-arch", "x86_64", "-arch", "x86_64h", "-platform", "-uuid", "-linked_dylibs", "-rpaths")
ATTRIBUTES = ("upward", "delay-init", "weak-link", "re-export")
DIRECTORY_SLOTS = ("library", "developer", "command-line-tools", "usr", "bin")
DIRECTORY_PATHS = (Path("/Library"), Path("/Library/Developer"), DEVELOPER_DIR,
                   DEVELOPER_DIR / "usr", SELECTED_TOOL.parent)
DIAGNOSTIC_LIMIT = 1536
DIAGNOSTIC_PHASES = ("host-admission", "source-admission", "host-system-version", "private-work",
                     "fixed-observations", "source-post", "publication")
DIAGNOSTIC_STAGES = ("host-admission", "bootstrap-open", "bootstrap-read", "bootstrap-load",
                     "source-pins", "source-entry", "source-git-head", "owner-load", "source-summary",
                     "bootstrap-close", "system-admission", "work-create", "resolver-admission",
                     "call-pre", "call", "call-return", "call-post", "resolver-return",
                     "selected-tool-path", "selected-tool-admission", "provider-decode",
                     "observations-post", "source-post", "source-close", "publication")
DIAGNOSTIC_REASONS = (
    'closed-record-bound',
    'context-deadline',
    'created-directory-original',
    'descriptor-capacity',
    'detached-source',
    'directory-owner-mode',
    'directory-spelling',
    'file-limit-capacity',
    'file-original-policy',
    'final-summary-write',
    'fixed-entry',
    'fixed-original-order',
    'fixture-original',
    'fixture-pin',
    'fixture-post',
    'host-route',
    'host-system-version',
    'hosted-route',
    'image-complete-output',
    'image-exact-header',
    'image-load-row',
    'image-output-text',
    'image-path-text',
    'image-platform-row',
    'image-platform-spelling',
    'image-platform-value',
    'image-return-contract',
    'image-rpath-count',
    'image-section',
    'missing-image-original',
    'observation-original',
    'original-call-roster',
    'original-changed',
    'original-grew',
    'original-handle-bound',
    'original-owner-return',
    'original-short-read',
    'original-unbound',
    'output-bound',
    'output-close-unknown',
    'output-readback',
    'output-short-write',
    'owner-already-imported',
    'owner-source-pin',
    'owner-source-route',
    'publication-close',
    'publication-original-directories',
    'publication-original-finality',
    'python-route',
    'resolver-return-contract',
    'selected-alias-changed',
    'selected-alias-post',
    'selected-alias-target',
    'selected-alias-text',
    'selected-applications-root',
    'selected-bundle-alias',
    'selected-bundle-original',
    'selected-tool-admission',
    'selected-tool-output-bound',
    'selected-tool-path',
    'selected-tool-spelling',
    'source-complete-post',
    'source-module-collision',
    'source-module-loader',
    'source-pin',
    'source-run-binding',
    'system-tool-evidence-depth',
    'system-tool-original',
    'system-tool-post',
    'system-tool-root-ancestor',
    'system-version-complete-post',
    'system-version-post',
)
DIAGNOSTIC_ERRNOS = {errno.EACCES: "EACCES", errno.EPERM: "EPERM", errno.ENOENT: "ENOENT",
                     errno.ELOOP: "ELOOP", errno.ENOTDIR: "ENOTDIR", errno.EIO: "EIO",
                     errno.EBADF: "EBADF", errno.EMFILE: "EMFILE", errno.ENFILE: "ENFILE",
                     errno.ENOSPC: "ENOSPC", errno.EROFS: "EROFS"}


def need(value, label):
    if not value:
        raise RuntimeError(label)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def load(path, name):
    need(name not in sys.modules, "source-module-collision")
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "source-module-loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def selected_tool_path(body):
    need(type(body) is bytes and 0 < len(body) <= 512, "selected-tool-output-bound")
    text = body.decode("ascii")
    need(text.endswith("\n") and text.count("\n") == 1
         and text[:-1] == str(SELECTED_TOOL), "selected-tool-path")
    path = Path(text[:-1])
    need(len(path.parts) <= 16 and str(path) == os.path.normpath(path), "selected-tool-spelling")
    return path


def root_ancestors(book, entry):
    parent = entry.get("parent")
    count = 0
    while parent is not None:
        count += 1
        need(count <= 40 and parent["identity"][3] == 0
             and stat.S_ISDIR(parent["identity"][2])
             and not parent["identity"][2] & 0o022, "system-tool-root-ancestor")
        book.check_one(parent)
        parent = parent.get("parent")


def system_tool(book, path):
    entry, body = book.file(path, TOOL_LIMIT, uid=0, modes=(0o555, 0o755))
    root_ancestors(book, entry)
    need(entry["identity"][3] == 0 and 0 < len(body) <= TOOL_LIMIT, "system-tool-original")
    return {"entry": entry, "path": path, "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(), "alias": None}


def selected_tool(book, selected):
    # No alternate developer root, resolver fallback, or alias is admissible.
    need(selected_tool_path((str(selected) + "\n").encode("ascii")) == selected,
         "selected-tool-admission")
    tool = system_tool(book, selected)  # Existing no-follow file/ancestor custody.
    tool.update(selected=selected)
    tool_post(book, tool)
    return tool


def tool_post(book, tool):
    need(tool["alias"] is None, "selected-tool-admission")
    root_ancestors(book, tool["entry"])
    body = book.read(tool["entry"])
    need(len(body) == tool["bytes"] and hashlib.sha256(body).hexdigest() == tool["sha256"],
         "system-tool-post")


def tool_evidence(tool):
    ancestors = []
    parent = tool["entry"].get("parent")
    while parent is not None:
        need(len(ancestors) < 40, "system-tool-evidence-depth")
        ancestors.append({"path": str(parent["path"]), "directoryIdentity": parent["identity"]})
        parent = parent.get("parent")
    alias = tool["alias"]
    return {"path": str(tool["path"]), "selectedPath": str(tool.get("selected", tool["path"])),
            "bytes": tool["bytes"], "sha256": tool["sha256"], "originalIdentity": tool["entry"]["identity"],
            "ancestors": ancestors, "oneHopAlias": None if alias is None else {
                "name": alias["name"], "text": alias["text"], "identity": alias["identity"],
                "parent": str(alias["parent"]["path"]), "parentIdentity": alias["parent"]["identity"]}}


def path_text(value):
    need(0 < len(value) <= 1024 and value == value.strip()
         and all(32 <= ord(c) <= 126 for c in value), "image-path-text")
    return value


def observation(path, returncode, stdout, stderr):
    """Decode only full, bounded Apple metadata; never treat exit0 as an image."""
    need(path in PROVIDERS and type(returncode) is int
         and type(stdout) is bytes and type(stderr) is bytes
         and len(stdout) + len(stderr) <= CAPTURE_LIMIT, "observation-original")
    if not stdout:
        missing = ("dyld_info: '" + path + "' file not found\n").encode("ascii")
        no_arch = ("dyld_info: '" + path + "' does not contain specified arch(s)\n").encode("ascii")
        need((stderr == missing and returncode in (0, 1))
             or (stderr == no_arch and returncode == 1), "missing-image-original")
        return {"path": path, "state": "not-observed", "selectedIntelImageObserved": False,
                "reason": "path-not-found" if stderr == missing else "no-selected-intel-image", "images": []}
    need(returncode == 0 and stderr == b"", "image-return-contract")
    text = stdout.decode("ascii")
    need(text.endswith("\n") and all(c == "\n" or 32 <= ord(c) <= 126 for c in text),
         "image-output-text")
    lines = text[:-1].split("\n")
    index, images, seen = 0, [], set()
    prefixes = []
    for mask in range(16):
        attrs = tuple(name for bit, name in enumerate(ATTRIBUTES) if mask & (1 << bit))
        printed = "".join(name + " " for name in attrs)
        prefixes.append(("        " + f"{printed:<12}" + "   ", attrs))
    prefixes.append(("        " + f"{'lazy-load':<12}" + "   ", ("lazy-load",)))

    def take(expected):
        nonlocal index
        need(index < len(lines) and lines[index] == expected, "image-section")
        index += 1

    while index < len(lines):
        matches = [arch for arch in ARCHES if lines[index] == path + " [" + arch + "]:"]
        need(len(matches) == 1 and matches[0] not in seen and len(images) < 2, "image-exact-header")
        arch = matches[0]
        seen.add(arch)
        index += 1
        take("    -platform:")
        take("        platform     minOS      sdk")
        need(index < len(lines), "image-platform-row")
        row = lines[index]
        fields = row.split()
        # Apple Platform::canLoad explicitly accepts zippered dylibs for macOS.
        # Retain that original platform identity instead of relabeling it macOS.
        need(len(fields) == 3 and fields[0] in ("macOS", "zippered(macOS/Catalyst)")
             and all(re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,5}){0,2}", v) is not None for v in fields[1:]),
             "image-platform-value")
        platform, min_os, sdk = fields
        need(row == f" {platform:>15}     {min_os:<7}   {sdk:<7}", "image-platform-spelling")
        index += 1
        take("    -uuid:")
        uuid = None
        if index < len(lines) and re.fullmatch(r"        [0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", lines[index]):
            uuid = lines[index][8:]
            index += 1
        take("    -linked_dylibs:")
        take("        attributes     load path")
        loads = []
        while index < len(lines) and lines[index] != "    -rpaths:":
            line = lines[index]
            match = [(prefix, attrs) for prefix, attrs in prefixes if line.startswith(prefix)]
            need(len(match) == 1 and len(loads) < 128, "image-load-row")
            prefix, attrs = match[0]
            loads.append({"attributes": list(attrs), "path": path_text(line[len(prefix):])})
            index += 1
        take("    -rpaths:")
        rpaths = []
        while index < len(lines) and lines[index].startswith("        "):
            need(len(rpaths) < 64, "image-rpath-count")
            rpaths.append(path_text(lines[index][8:]))
            index += 1
        images.append({"architecture": arch, "platform": platform, "minimumOS": min_os,
                       "sdk": sdk, "uuid": uuid, "loads": loads, "rpaths": rpaths})
    need(images and index == len(lines), "image-complete-output")
    return {"path": path, "state": "observed", "selectedIntelImageObserved": True,
            "reason": "exact-selected-image-metadata", "images": images}


def failure_kind(error):
    return next((name for name, kind in (("RuntimeError", RuntimeError), ("OSError", OSError),
                                         ("UnicodeDecodeError", UnicodeDecodeError), ("ValueError", ValueError))
                 if type(error) is kind), "other")


def directory_refusal_data(fixture, book, deadline, first_new_entry, error):
    """New samples after refusal; never bind or admit the rejected original."""
    try:
        if type(error) is not fixture.Refused or error.args != ("directory-owner-mode",):
            return None
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        entries = book.entries
        if (type(entries) is not list or type(first_new_entry) is not int
                or not 0 <= first_new_entry < len(entries) <= 2048
                or not 1 <= len(entries) - first_new_entry <= len(DIRECTORY_SLOTS)):
            return None
        entry = entries[-1]
        if (type(entry) is not dict or entry.get("kind") != "directory"
                or entry.get("identity", False) is not None or entry.get("closed") is not False
                or type(entry.get("fd")) is not int or entry["fd"] < 0 or "parent" in entry):
            return None
        path = entry.get("path")
        if not isinstance(path, Path) or str(path) != os.path.normpath(path):
            return None
        if path not in DIRECTORY_PATHS:
            return None
        slot = DIRECTORY_SLOTS[DIRECTORY_PATHS.index(path)]
        parent = book.directories.get(path.parent)
        if (type(parent) is not dict or parent.get("path") != path.parent
                or book.directories.get(path) is entry):
            return None
        book.check_one(parent)
        fd = entry["fd"]
        before = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent["fd"], follow_symlinks=False)
        after = os.fstat(fd)
        book.check_one(parent)
        current_uid = os.getuid()
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        if (book.entries is not entries or entry is not entries[-1]
                or book.directories.get(path.parent) is not parent or entry["fd"] != fd or entry["closed"] is not False
                or entry["identity"] is not None or identity(before) != identity(named)
                or identity(before) != identity(after)):
            return None
        return {"when": "after-refusal", "ancestorSlot": slot, "sameOriginal": True,
                "permissionBits": stat.S_IMODE(before.st_mode),
                "isDirectory": stat.S_ISDIR(before.st_mode), "ownerIsRoot": before.st_uid == 0,
                "ownerIsCurrent": before.st_uid == current_uid,
                "groupWritable": bool(before.st_mode & 0o020),
                "otherWritable": bool(before.st_mode & 0o002)}
    except BaseException:
        return None  # Preserve the primary error and all original retirement obligations.


def emit_refusal(error, phase, progress, calls, tools, *, record_prepared,
                 source_post_known, source_closed, bootstrap_closed, post_failed, close_failed):
    """Best-effort fixed stderr DATA, never a result or permission to clean/publish."""
    try:
        args = error.args if isinstance(error, BaseException) else ()
        reason = (args[0] if type(args) is tuple and len(args) == 1 and type(args[0]) is str
                  and args[0] in DIAGNOSTIC_REASONS else "unclassified")
        original_rows = []
        for index, role in enumerate(ROLES):
            row = calls[index] if index < len(calls) and type(calls[index]) is dict else None
            row = row if row is not None and row.get("role") == role else None
            original_rows.append({"role": role, "attempted": row is not None,
                                  "returned": row is not None and row.get("originalReturned") is True,
                                  **{name: row.get(name) if row is not None and type(row.get(name)) is bool else None
                                     for name in ("dispatched", "contained", "cleanupComplete")}})
        slot = progress.get("sourceSlot")
        number = error.errno if isinstance(error, OSError) else None
        directory = progress.get("directoryAfterRefusal")
        if not (reason == "directory-owner-mode" and phase == "fixed-observations"
                and progress.get("stage") == "selected-tool-admission"
                and progress.get("role") == ROLES[0] and "dyld_info" not in tools
                and type(directory) is dict and set(directory) == {
                    "when", "ancestorSlot", "sameOriginal", "permissionBits", "isDirectory",
                    "ownerIsRoot", "ownerIsCurrent", "groupWritable", "otherWritable"}
                and type(directory["when"]) is str and directory["when"] == "after-refusal"
                and type(directory["ancestorSlot"]) is str and directory["ancestorSlot"] in DIRECTORY_SLOTS
                and directory["sameOriginal"] is True and type(directory["permissionBits"]) is int
                and 0 <= directory["permissionBits"] <= 0o7777
                and all(type(directory[name]) is bool for name in
                        ("isDirectory", "ownerIsRoot", "ownerIsCurrent", "groupWritable", "otherWritable"))):
            directory = None
        data = {"type": "mrk-intel-os-provider-refusal-v1", "diagnosticOnly": True,
                "completeEvidence": False, "supplierAuthority": False,
                "phase": phase if phase in DIAGNOSTIC_PHASES else "unknown",
                "stage": progress.get("stage") if progress.get("stage") in DIAGNOSTIC_STAGES else "unknown",
                "role": progress.get("role") if progress.get("role") in ROLES else None,
                "sourceSlot": slot if type(slot) is int and 0 <= slot < len(SOURCE_PINS) + 2 else None,
                "directoryAfterRefusal": directory,
                "reason": reason, "errorKind": failure_kind(error) if error is not None else "none",
                "errnoName": DIAGNOSTIC_ERRNOS.get(number, "other") if type(number) is int else None,
                "recordPrepared": record_prepared is True, "resolverAdmitted": "xcrun" in tools,
                "selectedToolAdmitted": "dyld_info" in tools,
                "sourcePostKnown": source_post_known is True, "sourceClosesKnown": source_closed is True,
                "bootstrapCloseKnown": bootstrap_closed is True,
                "postFailureSeen": post_failed is True, "closeFailureSeen": close_failed is True,
                "originalCalls": original_rows}
        body = (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False) + "\n").encode("ascii")
        if len(body) <= DIAGNOSTIC_LIMIT:
            os.write(2, body)  # Single best-effort bounded write; never retry an uncertain write.
    except BaseException:
        pass  # A diagnostic failure cannot convert refusal to success or expose raw exceptions.


def observe_providers(fixture, book, owner, deadline, work, calls, tools, progress):
    """One fixed resolver and three independent queries through the existing owner."""
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work / "home"),
                   "TMPDIR": str(work / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                   "DEVELOPER_DIR": str(DEVELOPER_DIR)}

    def checkpoint():
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        book.check()
        for tool in tools.values():
            tool_post(book, tool)

    def command(role, argv):
        need(len(calls) < len(ROLES) and role == ROLES[len(calls)], "fixed-original-order")
        progress.update(stage="call-pre", role=role, sourceSlot=None)
        checkpoint()
        timeout = fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        row = {"role": role, "argv": argv, "originalReturned": False, "returncode": None,
               "timeoutSeconds": timeout, "captureLimitBytes": CAPTURE_LIMIT}
        calls.append(row)
        progress["stage"] = "call"
        try:
            result = owner.run_owned(argv, environ=environment, cwd=work, timeout=timeout,
                                     capture=True, text=False, output_limit=CAPTURE_LIMIT)
        except BaseException as error:
            row["errorType"] = next((n for n in ("ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown", "ProcessInterrupted")
                                     if type(error) is getattr(owner, n, None)), "other")
            for field, attribute in (("dispatched", "dispatched"), ("contained", "contained"),
                                     ("cleanupComplete", "cleanup_complete")):
                value = getattr(error, attribute, None)
                row[field] = value if type(value) is bool else None
            raise
        progress["stage"] = "call-return"
        fixture.completed(result, argv, CAPTURE_LIMIT)
        row.update(originalReturned=True, returncode=result.returncode,
                   stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
                   stdoutSha256=hashlib.sha256(result.stdout).hexdigest(),
                   stderrSha256=hashlib.sha256(result.stderr).hexdigest(),
                   stdoutBase64=base64.b64encode(result.stdout).decode("ascii"),
                   stderrBase64=base64.b64encode(result.stderr).decode("ascii"))
        progress["stage"] = "call-post"
        checkpoint()
        return result

    progress.update(stage="resolver-admission", role=ROLES[0], sourceSlot=None)
    tools["xcrun"] = system_tool(book, XCRUN)
    # Refuse an absent/untrusted CLT installation before invoking a shim.
    developer = book.directory(DEVELOPER_DIR)
    need(developer["identity"][3] == 0 and stat.S_ISDIR(developer["identity"][2])
         and not developer["identity"][2] & 0o022, "system-tool-root-ancestor")
    root_ancestors(book, developer)
    result = command(ROLES[0], [str(XCRUN), "--find", "dyld_info"])
    progress["stage"] = "resolver-return"
    need(result.returncode == 0 and result.stderr == b"", "resolver-return-contract")
    progress["stage"] = "selected-tool-path"
    selected = selected_tool_path(result.stdout)
    progress["stage"] = "selected-tool-admission"
    first_new_entry = len(book.entries)
    try:
        tools["dyld_info"] = selected_tool(book, selected)
    except BaseException as error:
        progress["directoryAfterRefusal"] = directory_refusal_data(fixture, book, deadline, first_new_entry, error)
        raise
    checkpoint()
    observations = []
    for role, path in zip(ROLES[1:], PROVIDERS):
        result = command(role, [str(tools["dyld_info"]["path"]), *OPTIONS, path])
        progress["stage"] = "provider-decode"
        try:
            value = observation(path, result.returncode, result.stdout, result.stderr)
        except (RuntimeError, UnicodeDecodeError) as error:
            value = {"path": path, "state": "unresolved", "selectedIntelImageObserved": None,
                     "reason": "unrecognized-tool-result", "decoderFailureKind": failure_kind(error), "images": []}
        observations.append(value)
    progress.update(stage="observations-post", role=None, sourceSlot=None)
    checkpoint()
    need([row["role"] for row in calls] == list(ROLES)
         and all(row["originalReturned"] is True for row in calls), "original-call-roster")
    return observations


def publish_record(fixture, publication_root, publication_directories, record, deadline,
                   *, source_post_known, source_closed, bootstrap_closed):
    need(source_post_known is True and source_closed is True and bootstrap_closed is True
         and all(row["originalReturned"] is True for row in record["originalCalls"]), "publication-original-finality")
    publisher = fixture.Originals()
    try:
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        publisher.directory(publication_root)
        need(set(publisher.directories) == set(publication_directories)
             and all(publisher.directories[path]["identity"] == original
                     for path, original in publication_directories.items()), "publication-original-directories")
        record["sourceAndInputClosesKnown"] = True
        body = fixture.canonical(record)
        need(len(body) <= RECORD_LIMIT, "closed-record-bound")
        publisher.publish(publication_root / "result.json", body)
        need(publisher.finish(), "publication-close")
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        summary = fixture.canonical({"diagnosticCompleted": record["diagnosticCompleted"],
                                     "questionsSettled": record["questionsSettled"],
                                     "supplierAuthority": False, "source": record["source"],
                                     "resultSha256": hashlib.sha256(body).hexdigest()})
        need(len(summary) <= 512 and os.write(1, summary) == len(summary), "final-summary-write")
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        return record["questionsSettled"] is True
    finally:
        # Existing Originals consumes each descriptor before close, even on error.
        publisher.finish()


def main():
    started = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    deadline = started + 120 * 1_000_000_000
    bootstrap = None
    book = None
    failure = None
    failure_phase, failure_progress = None, None
    post_failed = close_failed = False
    progress = {"stage": "host-admission", "role": None, "sourceSlot": None}
    calls, tools = [], {}
    source_post_known = source_closed = bootstrap_closed = False
    record = publication_root = publication_directories = None
    phase = "host-admission"
    held, source_rows = {}, {}
    system_entry, system_body = None, None
    try:
        need(sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated
             and sys.flags.no_site and sys.flags.dont_write_bytecode, "python-route")
        need(sys.argv == [str(CHECKOUT / SELF)] and Path.cwd() == CHECKOUT, "fixed-entry")
        need(os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid()
             and os.uname().sysname == "Darwin" and os.uname().machine == "x86_64", "host-route")
        expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY,
                    "GITHUB_EVENT_NAME": "push", "GITHUB_REF": REF, "GITHUB_WORKFLOW_REF": WORKFLOW,
                    "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "X64"}
        need(all(os.environ.get(k) == v for k, v in expected.items()), "hosted-route")
        commit = os.environ.get("GITHUB_SHA", "")
        run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
        need(re.fullmatch(r"[0-9a-f]{40}", commit)
             and all(re.fullmatch(r"[1-9][0-9]{0,19}", s) for s in (run_id, attempt)), "source-run-binding")
        os.umask(0o077)
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need(soft == resource.RLIM_INFINITY or soft >= 256, "descriptor-capacity")
        _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        need(hard == resource.RLIM_INFINITY or hard >= FILE_LIMIT, "file-limit-capacity")
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        phase = "source-admission"
        progress["stage"] = "bootstrap-open"
        bootstrap = os.open(CHECKOUT / FIXTURE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        progress["stage"] = "bootstrap-read"
        before = os.fstat(bootstrap)
        size, sha = SOURCE_PINS[FIXTURE]
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and before.st_size == size, "fixture-original")
        body = os.pread(bootstrap, size + 1, 0)
        need(len(body) == size and hashlib.sha256(body).hexdigest() == sha
             and os.pread(bootstrap, 1, size) == b"", "fixture-pin")
        progress["stage"] = "bootstrap-load"
        fixture = load(CHECKOUT / FIXTURE, "_mrk_intel_os_provider_fixture")
        need(identity(os.fstat(bootstrap)) == identity(before)
             == identity(os.stat(CHECKOUT / FIXTURE, follow_symlinks=False)), "fixture-post")
        book = fixture.Originals()
        for slot, (name, (size, sha)) in enumerate(SOURCE_PINS.items()):
            progress.update(stage="source-pins", sourceSlot=slot)
            entry, body = book.file(CHECKOUT / name, 1024 * 1024, modes=(0o600, 0o644))
            need(len(body) == size and hashlib.sha256(body).hexdigest() == sha, "source-pin")
            held[name] = entry
        for slot, name in enumerate((SELF, WORKFLOW_PATH), len(SOURCE_PINS)):
            progress.update(stage="source-entry", sourceSlot=slot)
            entry, body = book.file(CHECKOUT / name, 65536, modes=(0o600, 0o644))
            held[name] = entry
        progress.update(stage="source-git-head", sourceSlot=None)
        _head, head = book.file(CHECKOUT / ".git/HEAD", 64, modes=(0o600, 0o644))
        need(head == (commit + "\n").encode("ascii"), "detached-source")
        book.check()
        progress["stage"] = "owner-load"
        qualification = load(CHECKOUT / QUALIFICATION, "_mrk_intel_os_provider_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        book.check()
        progress["stage"] = "source-summary"
        source_rows = {n: {"bytes": e["identity"][6], "sha256": hashlib.sha256(book.read(e)).hexdigest()}
                       for n, e in held.items()}
        progress["stage"] = "bootstrap-close"
        fd, bootstrap = bootstrap, None
        os.close(fd)
        bootstrap_closed = True
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        phase = "host-system-version"
        progress["stage"] = "system-admission"
        system_entry, system_body = book.file(SYSTEM_PLIST, 65536, uid=0, modes=(0o444, 0o644))
        root_ancestors(book, system_entry)
        system = plistlib.loads(system_body)
        need(type(system) is dict and type(system.get("ProductVersion")) is str
             and re.fullmatch(r"26(?:\.[0-9]{1,3}){0,2}", system["ProductVersion"])
             and type(system.get("ProductBuildVersion")) is str
             and re.fullmatch(r"[0-9A-Za-z.]{1,32}", system["ProductBuildVersion"]), "host-system-version")

        def mkdir(path):
            parent = book.directory(path.parent)
            os.mkdir(path.name, 0o700, dir_fd=parent["fd"])
            entry = book.directory(path)
            need(entry["identity"][3] == os.getuid()
                 and stat.S_IMODE(entry["identity"][2]) == 0o700, "created-directory-original")
            book.check_one(entry)

        phase = "private-work"
        progress["stage"] = "work-create"
        work = WORK_PARENT / ("mrk-intel-os-providers-" + run_id + "-" + attempt)
        mkdir(work)
        for name in ("home", "tmp", "report"):
            mkdir(work / name)
        publication_root = work / "report"
        publication_directories = {path: book.directories[path]["identity"]
                                   for path in (publication_root, *publication_root.parents)}
        record = {"schemaVersion": 1, "type": "mrk-intel-os-provider-observation-v1", "source": commit,
                  "workflow": WORKFLOW, "runId": run_id, "runAttempt": attempt,
                  "diagnosticCompleted": False, "questionsSettled": False, "diagnosticOnly": True,
                  "publicationProvisionalUntilOriginalCallerZero": True,
                  "sourceInputs": source_rows, "originalCalls": calls, "observations": [],
                  "host": {"runner": "macos-26-intel", "machine": "x86_64",
                           "productVersion": system["ProductVersion"], "productBuildVersion": system["ProductBuildVersion"],
                           "systemPlistSha256": hashlib.sha256(system_body).hexdigest()},
                  "vendorPayloadExecuted": False, "requestedProviderDlopen": False,
                  "runtimeQualified": False, "supplierAuthority": False, "privateScratchRetired": False,
                  "clock": "CLOCK_MONOTONIC", "deadlineBudgetSeconds": 120}
        phase = "fixed-observations"
        observations = observe_providers(fixture, book, owner, deadline, work, calls, tools, progress)
        record["observations"] = observations
        record["diagnosticCompleted"] = True
        record["questionsSettled"] = all(row["state"] in ("observed", "not-observed") for row in observations)
        need(book.read(system_entry) == system_body, "system-version-post")
        phase = "source-post"
    except BaseException as error:
        failure = error
        failure_phase, failure_progress = phase, dict(progress)
    finally:
        if bootstrap is not None:
            progress.update(stage="bootstrap-close", role=None, sourceSlot=None)
            fd, bootstrap = bootstrap, None
            try:
                os.close(fd)
                bootstrap_closed = True
            except BaseException as error:
                close_failed = True
                if failure is None:
                    failure = error
                    failure_phase, failure_progress = phase, dict(progress)
        if book is not None:
            progress.update(stage="source-post", role=None, sourceSlot=None)
            try:
                book.check()
                for slot, (name, entry) in enumerate(held.items()):
                    progress["sourceSlot"] = slot
                    body = book.read(entry)
                    need(len(body) == source_rows[name]["bytes"]
                         and hashlib.sha256(body).hexdigest() == source_rows[name]["sha256"], "source-complete-post")
                progress["sourceSlot"] = None
                for tool in tools.values():
                    tool_post(book, tool)
                if system_entry is not None:
                    need(book.read(system_entry) == system_body, "system-version-complete-post")
                source_post_known = True
            except BaseException as error:
                post_failed = True
                if failure is None:
                    failure = error
                    failure_phase, failure_progress = phase, dict(progress)
            progress.update(stage="source-close", role=None, sourceSlot=None)
            try:
                source_closed = book.finish()
                close_failed = close_failed or source_closed is not True
            except BaseException as error:
                close_failed = True
                if failure is None:
                    failure = error
                    failure_phase, failure_progress = phase, dict(progress)
    if (record is None or not source_post_known or not source_closed or not bootstrap_closed
            or not all(row["originalReturned"] is True for row in calls)):
        emit_refusal(failure, failure_phase or phase, failure_progress or progress, calls, tools,
                     record_prepared=record is not None, source_post_known=source_post_known,
                     source_closed=source_closed, bootstrap_closed=bootstrap_closed,
                     post_failed=post_failed, close_failed=close_failed)
        return 1
    record["tools"] = {name: tool_evidence(tool) for name, tool in tools.items()}
    record["captureElapsedNs"] = str(time.clock_gettime_ns(time.CLOCK_MONOTONIC) - started)
    if failure is not None:
        record.update(diagnosticCompleted=False, questionsSettled=False,
                      failure={"phase": phase, "kind": failure_kind(failure)})
    try:
        progress.update(stage="publication", role=None, sourceSlot=None)
        passed = publish_record(fixture, publication_root, publication_directories, record, deadline,
                                source_post_known=source_post_known, source_closed=source_closed,
                                bootstrap_closed=bootstrap_closed)
        return 0 if passed else 1
    except BaseException as error:
        emit_refusal(failure if failure is not None else error, failure_phase or "publication",
                     failure_progress or progress, calls, tools, record_prepared=record is not None,
                     source_post_known=source_post_known, source_closed=source_closed,
                     bootstrap_closed=bootstrap_closed, post_failed=post_failed, close_failed=close_failed)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
