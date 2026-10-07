#!/usr/bin/env python3
"""Three read-only Intel system-image observations, never supplier authority.

Only Apple's selected dyld_info executes. No vendor image is dlopened, compiled,
installed or qualified. A missing selected image is an ordinary negative result.
"""
from __future__ import annotations

import base64
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
    'desktop/tools/macos_aqua_qualification.py': (455054, '324f5ca9d6a67a3c21ff5106e442440f050fe1266fb62b3ac30892e4a19e65d1'),
    'src/mobile_release/owned_process.py': (9037, '0c7c87c7eaf27629be2eb33c195a956b6c40b7b5883214a08e15f255ac4939b8'),
    'src/mobile_release/_command_process.py': (172299, '30781e5b264fbcdb4c09028829e0606095a79e5c7a194556484f5ca8b2bfad69'),
    'src/mobile_release/_native_process.py': (62175, '70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4'),
    'src/mobile_release/cancellation.py': (31041, '5f469444f42b5ad6a69ecce8161a7d83e67303c92a221a31f88c079f4ff29d35'),
    'desktop/tools/macos_e2_native_fixture.py': (281171, 'd93b8149c52ce82843f580ef09548a64a88da342c9904576e4981b122bfd98cb'),
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
APPLICATIONS = Path("/Applications")
TOOL_SUFFIX = "Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_info"
VERSIONED_XCODE = r"Xcode_[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}\.app"
TOOL_PATTERN = r"/Applications/(Xcode\.app|" + VERSIONED_XCODE + r")/" + re.escape(TOOL_SUFFIX)
ARCHES = ("x86_64", "x86_64h")
PROVIDERS = (
    "/System/Library/Frameworks/JavaVM.framework/Versions/A/JavaVM",
    "/usr/lib/libgcc_s.1.dylib",
    "/usr/lib/libncurses.5.4.dylib",
)
ROLES = ("resolve-dyld-info", "provider-javavm", "provider-libgcc", "provider-ncurses")
OPTIONS = ("-arch", "x86_64", "-arch", "x86_64h", "-platform", "-uuid", "-linked_dylibs", "-rpaths")
ATTRIBUTES = ("upward", "delay-init", "weak-link", "re-export")


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
         and re.fullmatch(TOOL_PATTERN, text[:-1]) is not None, "selected-tool-path")
    path = Path(text[:-1])
    need(len(path.parts) <= 16 and str(path) == os.path.normpath(path), "selected-tool-spelling")
    return path


def alias_bundle(text):
    need(type(text) is str and 0 < len(text) <= 512 and text.isascii(), "selected-alias-text")
    name = text.removeprefix("/Applications/")
    need(re.fullmatch(VERSIONED_XCODE, name) is not None
         and text in (name, "/Applications/" + name), "selected-alias-target")
    return APPLICATIONS / name


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
    # The resolver cannot authorize arbitrary paths or arbitrary realpath chains.
    need(selected_tool_path((str(selected) + "\n").encode("ascii")) == selected,
         "selected-tool-admission")
    parent = book.directory(APPLICATIONS)
    need(parent["identity"][3] == 0 and not parent["identity"][2] & 0o022,
         "selected-applications-root")
    root_ancestors(book, parent)
    bundle = APPLICATIONS / selected.parts[2]
    info = os.stat(bundle.name, dir_fd=parent["fd"], follow_symlinks=False)
    alias = None
    canonical = selected
    if stat.S_ISLNK(info.st_mode):
        need(bundle.name == "Xcode.app" and info.st_uid == 0 and info.st_nlink == 1
             and 0 < info.st_size <= 512, "selected-bundle-alias")
        text = os.readlink(bundle.name, dir_fd=parent["fd"])
        canonical = alias_bundle(text) / TOOL_SUFFIX
        alias = {"parent": parent, "name": bundle.name, "identity": identity(info), "text": text}
        need(identity(os.stat(bundle.name, dir_fd=parent["fd"], follow_symlinks=False)) == alias["identity"]
             and os.readlink(bundle.name, dir_fd=parent["fd"]) == text, "selected-alias-post")
    else:
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             "selected-bundle-original")
    tool = system_tool(book, canonical)  # No-follow rejects every other alias.
    tool.update(selected=selected, alias=alias)
    tool_post(book, tool)
    return tool


def tool_post(book, tool):
    alias = tool["alias"]
    if alias is not None:
        parent = alias["parent"]
        book.check_one(parent)
        need(parent["identity"][3] == 0
             and identity(os.stat(alias["name"], dir_fd=parent["fd"], follow_symlinks=False)) == alias["identity"]
             and os.readlink(alias["name"], dir_fd=parent["fd"]) == alias["text"]
             and alias_bundle(alias["text"]) / TOOL_SUFFIX == tool["path"], "selected-alias-changed")
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
        need(len(fields) == 3 and fields[0] == "macOS"
             and all(re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,5}){0,2}", v) is not None for v in fields[1:]),
             "image-platform-value")
        min_os, sdk = fields[1:]
        need(row == f" {'macOS':>15}     {min_os:<7}   {sdk:<7}", "image-platform-spelling")
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
        images.append({"architecture": arch, "platform": "macOS", "minimumOS": min_os,
                       "sdk": sdk, "uuid": uuid, "loads": loads, "rpaths": rpaths})
    need(images and index == len(lines), "image-complete-output")
    return {"path": path, "state": "observed", "selectedIntelImageObserved": True,
            "reason": "exact-selected-image-metadata", "images": images}


def failure_kind(error):
    return next((name for name, kind in (("RuntimeError", RuntimeError), ("OSError", OSError),
                                         ("UnicodeDecodeError", UnicodeDecodeError), ("ValueError", ValueError))
                 if type(error) is kind), "other")


def observe_providers(fixture, book, owner, deadline, work, calls, tools):
    """One fixed resolver and three independent queries through the existing owner."""
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work / "home"),
                   "TMPDIR": str(work / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}

    def checkpoint():
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        book.check()
        for tool in tools.values():
            tool_post(book, tool)

    def command(role, argv):
        need(len(calls) < len(ROLES) and role == ROLES[len(calls)], "fixed-original-order")
        checkpoint()
        timeout = fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        row = {"role": role, "argv": argv, "originalReturned": False, "returncode": None,
               "timeoutSeconds": timeout, "captureLimitBytes": CAPTURE_LIMIT}
        calls.append(row)
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
        fixture.completed(result, argv, CAPTURE_LIMIT)
        row.update(originalReturned=True, returncode=result.returncode,
                   stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
                   stdoutSha256=hashlib.sha256(result.stdout).hexdigest(),
                   stderrSha256=hashlib.sha256(result.stderr).hexdigest(),
                   stdoutBase64=base64.b64encode(result.stdout).decode("ascii"),
                   stderrBase64=base64.b64encode(result.stderr).decode("ascii"))
        checkpoint()
        return result

    tools["xcrun"] = system_tool(book, XCRUN)
    result = command(ROLES[0], [str(XCRUN), "--find", "dyld_info"])
    need(result.returncode == 0 and result.stderr == b"", "resolver-return-contract")
    tools["dyld_info"] = selected_tool(book, selected_tool_path(result.stdout))
    checkpoint()
    observations = []
    for role, path in zip(ROLES[1:], PROVIDERS):
        result = command(role, [str(tools["dyld_info"]["path"]), *OPTIONS, path])
        try:
            value = observation(path, result.returncode, result.stdout, result.stderr)
        except (RuntimeError, UnicodeDecodeError) as error:
            value = {"path": path, "state": "unresolved", "selectedIntelImageObserved": None,
                     "reason": "unrecognized-tool-result", "decoderFailureKind": failure_kind(error), "images": []}
        observations.append(value)
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
        bootstrap = os.open(CHECKOUT / FIXTURE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(bootstrap)
        size, sha = SOURCE_PINS[FIXTURE]
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and before.st_size == size, "fixture-original")
        body = os.pread(bootstrap, size + 1, 0)
        need(len(body) == size and hashlib.sha256(body).hexdigest() == sha
             and os.pread(bootstrap, 1, size) == b"", "fixture-pin")
        fixture = load(CHECKOUT / FIXTURE, "_mrk_intel_os_provider_fixture")
        need(identity(os.fstat(bootstrap)) == identity(before)
             == identity(os.stat(CHECKOUT / FIXTURE, follow_symlinks=False)), "fixture-post")
        book = fixture.Originals()
        for name, (size, sha) in SOURCE_PINS.items():
            entry, body = book.file(CHECKOUT / name, 1024 * 1024, modes=(0o600, 0o644))
            need(len(body) == size and hashlib.sha256(body).hexdigest() == sha, "source-pin")
            held[name] = entry
        for name in (SELF, WORKFLOW_PATH):
            entry, body = book.file(CHECKOUT / name, 65536, modes=(0o600, 0o644))
            held[name] = entry
        _head, head = book.file(CHECKOUT / ".git/HEAD", 64, modes=(0o600, 0o644))
        need(head == (commit + "\n").encode("ascii"), "detached-source")
        book.check()
        qualification = load(CHECKOUT / QUALIFICATION, "_mrk_intel_os_provider_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        book.check()
        source_rows = {n: {"bytes": e["identity"][6], "sha256": hashlib.sha256(book.read(e)).hexdigest()}
                       for n, e in held.items()}
        fd, bootstrap = bootstrap, None
        os.close(fd)
        bootstrap_closed = True
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        phase = "host-system-version"
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
        observations = observe_providers(fixture, book, owner, deadline, work, calls, tools)
        record["observations"] = observations
        record["diagnosticCompleted"] = True
        record["questionsSettled"] = all(row["state"] in ("observed", "not-observed") for row in observations)
        need(book.read(system_entry) == system_body, "system-version-post")
        phase = "source-post"
    except BaseException as error:
        failure = error
    finally:
        if bootstrap is not None:
            fd, bootstrap = bootstrap, None
            try:
                os.close(fd)
                bootstrap_closed = True
            except BaseException as error:
                if failure is None:
                    failure = error
        if book is not None:
            try:
                book.check()
                for name, entry in held.items():
                    body = book.read(entry)
                    need(len(body) == source_rows[name]["bytes"]
                         and hashlib.sha256(body).hexdigest() == source_rows[name]["sha256"], "source-complete-post")
                for tool in tools.values():
                    tool_post(book, tool)
                if system_entry is not None:
                    need(book.read(system_entry) == system_body, "system-version-complete-post")
                source_post_known = True
            except BaseException as error:
                if failure is None:
                    failure = error
            try:
                source_closed = book.finish()
            except BaseException as error:
                if failure is None:
                    failure = error
    if (record is None or not source_post_known or not source_closed or not bootstrap_closed
            or not all(row["originalReturned"] is True for row in calls)):
        print("Intel OS observation refused before known original finality; no complete evidence.", file=sys.stderr)
        return 1
    record["tools"] = {name: tool_evidence(tool) for name, tool in tools.items()}
    record["captureElapsedNs"] = str(time.clock_gettime_ns(time.CLOCK_MONOTONIC) - started)
    if failure is not None:
        record.update(diagnosticCompleted=False, questionsSettled=False,
                      failure={"phase": phase, "kind": failure_kind(failure)})
    try:
        passed = publish_record(fixture, publication_root, publication_directories, record, deadline,
                                source_post_known=source_post_known, source_closed=source_closed,
                                bootstrap_closed=bootstrap_closed)
        return 0 if passed else 1
    except BaseException:
        print("Intel OS metadata publication refused; retained files are provisional, not qualification.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
