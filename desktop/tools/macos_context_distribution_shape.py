#!/usr/bin/env python3
"""Fixed synthetic productbuild metadata reproduction; never an installation gate.

The two original tools only create packages. The observer is an inert shell
file, not the native context observer, and neither script is executed. The
normal fixture, compiler graphs and all package acceptance policies are unchanged.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import time

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-context-distribution-shape"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-context-distribution-shape.yml@" + REF
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
SELF = "desktop/tools/macos_context_distribution_shape.py"
FIXTURE = "desktop/tools/macos_e2_native_fixture.py"
QUALIFICATION = "desktop/tools/macos_aqua_qualification.py"
WORKFLOW_PATH = ".github/workflows/desktop-macos-context-distribution-shape.yml"
SOURCE_PINS = {
    'desktop/tools/macos_e2_native_fixture.py': (240157, '24eedcc8bfbe88afd7d7605e6174fcc380ee60e8df92861841f6c97e2a5efd64'),
    'desktop/tools/macos_aqua_qualification.py': (406490, '6a46ad67e58c4428b9564d00eccc71ba3ea805591f9d5ee6cabf25ae9f31b698'),
    'src/mobile_release/__init__.py': (144, '557bcb0cdcf7f7ef329f04f82cf388c746bb73eba34857b97782a8bcf2e596b2'),
    'src/mobile_release/owned_process.py': (9037, '0c7c87c7eaf27629be2eb33c195a956b6c40b7b5883214a08e15f255ac4939b8'),
    'src/mobile_release/_command_process.py': (172299, '30781e5b264fbcdb4c09028829e0606095a79e5c7a194556484f5ca8b2bfad69'),
    'src/mobile_release/_native_process.py': (62175, '70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4'),
    'src/mobile_release/cancellation.py': (31041, '5f469444f42b5ad6a69ecce8161a7d83e67303c92a221a31f88c079f4ff29d35'),
    'src/mobile_release/errors.py': (749, '26427cedbd05945c1a869af20228f9a04fe1e30d950a2dc246dd0795708a0853'),
    'src/mobile_release/_lifetime_evidence.py': (19072, 'f79d21c9846d7527b9c08f474ef47bc57515f592a090b7c61ba9046a82232da3'),
    'src/mobile_release/_store_lane_contract.py': (9500, '8726cf9bdb053b3d7f30eb9c8307c18239dc518476b2f895ef1610efa65e040e'),
    'src/mobile_release/_store_lane_evidence.py': (17638, 'bcea0084032ffbd43c15f5682f456965aff812e5007d3211a5afe605fc4d5872'),
}
CAPTURE_LIMIT = 65536
PACKAGE_LIMIT = 8 * 1024 * 1024
INERT_OBSERVER = b"#!/bin/sh\nexit 0\n"


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


def main():
    # One endpoint begins before source, tool or output acquisition.
    started = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    deadline = started + 120 * 1_000_000_000
    bootstrap = None
    book = None
    failure = None
    calls = []
    source_closed = False
    try:
        need(sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated
             and sys.flags.no_site and sys.flags.dont_write_bytecode, "python-route")
        need(sys.argv == [str(CHECKOUT / SELF)] and Path.cwd() == CHECKOUT, "fixed-entry")
        need(os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid()
             and os.uname().sysname == "Darwin" and os.uname().machine == "arm64", "host-route")
        expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY,
                    "GITHUB_EVENT_NAME": "push", "GITHUB_REF": REF,
                    "GITHUB_WORKFLOW_REF": WORKFLOW, "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64"}
        need(all(os.environ.get(k) == v for k, v in expected.items()), "hosted-route")
        commit = os.environ.get("GITHUB_SHA", "")
        run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
        need(re.fullmatch(r"[0-9a-f]{40}", commit)
             and all(re.fullmatch(r"[1-9][0-9]{0,19}", s) for s in (run_id, attempt)), "source-run-binding")
        os.umask(0o077)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need(soft == resource.RLIM_INFINITY or soft >= 256, "descriptor-capacity")
        _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        need(hard == resource.RLIM_INFINITY or hard >= PACKAGE_LIMIT, "file-limit-capacity")
        resource.setrlimit(resource.RLIMIT_FSIZE, (PACKAGE_LIMIT, PACKAGE_LIMIT))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        # Bootstrap exactly the reviewed DATA-only fixture, then use its original
        # no-follow book for the full source/ancestor/loaded-owner closure.
        bootstrap = os.open(CHECKOUT / FIXTURE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(bootstrap)
        size, sha = SOURCE_PINS[FIXTURE]
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and before.st_size == size, "fixture-original")
        body = os.pread(bootstrap, size + 1, 0)
        need(len(body) == size and hashlib.sha256(body).hexdigest() == sha
             and os.pread(bootstrap, 1, size) == b"", "fixture-pin")
        fixture = load(CHECKOUT / FIXTURE, "_mrk_context_shape_fixture")
        need(identity(os.fstat(bootstrap)) == identity(before)
             == identity(os.stat(CHECKOUT / FIXTURE, follow_symlinks=False)), "fixture-post")
        book = fixture.Originals()
        held = {}
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
        qualification = load(CHECKOUT / QUALIFICATION, "_mrk_context_shape_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        book.check()
        source_rows = {n: {"bytes": e["identity"][6], "sha256": fixture.digest(book.read(e))}
                       for n, e in held.items()}
        fd, bootstrap = bootstrap, None
        os.close(fd)  # Consumed once; a failed close vetoes publication.

        def checkpoint():
            fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
            book.check()

        def mkdir(path, mode=0o700):
            parent = book.directory(path.parent)
            os.mkdir(path.name, 0o700, dir_fd=parent["fd"])
            entry = book.directory(path)
            need(entry["identity"][3] == os.getuid(), "created-directory-owner")
            os.fchmod(entry["fd"], mode)  # Only this exclusive original.
            entry["identity"] = identity(os.fstat(entry["fd"]))[:5]
            need(stat.S_IMODE(entry["identity"][2]) == mode, "created-directory-mode")
            book.check_one(entry)

        work = WORK_PARENT / ("mrk-context-distribution-shape-" + run_id + "-" + attempt)
        mkdir(work)
        for name in ("home", "tmp", "scripts", "report"):
            mkdir(work / name, 0o755 if name == "scripts" else 0o700)
        originals = []
        def publish_input(path, body, mode=0o600):
            book.publish(path, body, mode)
            entry, observed = book.file(path, PACKAGE_LIMIT, modes=(mode,))
            need(observed == body, "generated-input-readback")
            originals.append((entry, body))

        identifier, component_name = fixture.CONTEXT_IDENTIFIERS[1], fixture.CONTEXT_PACKAGES[1]
        script = ("#!/bin/sh\nexec \"${0%/*}/mrk-context-observer\" product"
                  " \"${PACKAGE_PATH+x}\" \"${PACKAGE_PATH-}\" \"$@\"\n").encode("ascii")
        publish_input(work / "scripts/mrk-context-observer", INERT_OBSERVER, 0o555)
        publish_input(work / "scripts/postinstall", script, 0o555)
        distribution = fixture.context_distribution()
        fixture.context_xml(distribution, 65536)
        publish_input(work / "Distribution", distribution)
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work / "home"),
                       "TMPDIR": str(work / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                       "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}
        tools = {}
        for tool in ("/usr/bin/pkgbuild", "/usr/bin/productbuild"):
            entry, body = book.file(Path(tool), 4 * 1024 * 1024, uid=0, modes=(0o555, 0o755))
            tools[tool] = {"bytes": len(body), "sha256": fixture.digest(body)}
        def command(role, argv):
            checkpoint()
            timeout = fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
            row = {"role": role, "originalReturned": False, "returncode": None,
                   "timeoutSeconds": timeout, "captureLimitBytes": CAPTURE_LIMIT}
            calls.append(row)
            try:
                result = owner.run_owned(argv, environ=environment, cwd=work, timeout=timeout,
                                         capture=True, text=False, output_limit=CAPTURE_LIMIT)
            except BaseException as error:
                row["errorType"] = next((n for n in ("ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown", "ProcessInterrupted")
                                         if type(error) is getattr(owner, n, None)), "other")
                row["dispatched"] = getattr(error, "dispatched", None) if type(getattr(error, "dispatched", None)) is bool else None
                row["contained"] = getattr(error, "contained", None) if type(getattr(error, "contained", None)) is bool else None
                row["cleanupComplete"] = getattr(error, "cleanup_complete", None) if type(getattr(error, "cleanup_complete", None)) is bool else None
                raise
            fixture.completed(result, argv, CAPTURE_LIMIT)
            row.update(originalReturned=True, returncode=result.returncode,
                       stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr),
                       stdoutSha256=fixture.digest(result.stdout), stderrSha256=fixture.digest(result.stderr))
            checkpoint()
            need(result.returncode == 0, "original-command-failed")
            need(all(book.read(entry) == body for entry, body in originals), "generated-input-post")

        command("component-build", ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(work / "scripts"),
                "--identifier", identifier, "--version", "1", "--install-location", "/",
                "--ownership", "recommended", "--compression", "legacy", str(work / component_name)])
        component, component_body = book.file(work / component_name, PACKAGE_LIMIT, modes=(0o600, 0o644))
        component_members = fixture.context_xar(component_body)
        fixture.context_package_info(component_members["PackageInfo"], identifier)
        command("product-build", ["/usr/bin/productbuild", "--distribution", str(work / "Distribution"),
                "--package-path", str(work), str(work / fixture.CONTEXT_PACKAGES[2])])
        product, product_body = book.file(work / fixture.CONTEXT_PACKAGES[2], PACKAGE_LIMIT, modes=(0o600, 0o644))
        product_members = fixture.context_xar(product_body, product=True)
        generated = product_members["Distribution"]
        fixture.context_xml(generated, 65536)
        if component_name in product_members:
            need(product_members[component_name] == component_body, "embedded-component-original")
        else:
            need({k.removeprefix(component_name + "/"): v for k, v in product_members.items() if k != "Distribution"}
                 == component_members, "embedded-component-original")
        need(book.read(component) == component_body and book.read(product) == product_body
             and all(book.read(entry) == body for entry, body in originals), "completed-package-post")
        checkpoint()
        need([row["role"] for row in calls] == ["component-build", "product-build"]
             and all(row["originalReturned"] and row["returncode"] == 0 for row in calls), "original-call-roster")
        publication_root = work / "report"
        publication_directories = {path: book.directories[path]["identity"]
                                   for path in (publication_root, *publication_root.parents)}
        record = {"schemaVersion": 1, "type": "mrk-context-distribution-shape-v1", "source": commit,
                  "runId": run_id, "runAttempt": attempt, "diagnosticCompleted": True, "diagnosticOnly": True,
                  "publicationProvisionalUntilOriginalCallerZero": True,
                  "sourceInputs": source_rows, "tools": tools, "originalCalls": calls,
                  "sourceDistribution": {"bytes": len(distribution), "sha256": fixture.digest(distribution)},
                  "generatedDistribution": {"bytes": len(generated), "sha256": fixture.digest(generated)},
                  "component": {"bytes": len(component_body), "sha256": fixture.digest(component_body)},
                  "product": {"bytes": len(product_body), "sha256": fixture.digest(product_body)},
                  "inertObserverSubstitution": True, "scriptsExecuted": False,
                  "installerEntered": False, "rustCompilerEntered": False, "serviceEntered": False,
                  "signingEntered": False, "fixtureAccepted": False, "installationQualified": False,
                  "privateScratchRetired": False, "rawLogsIncluded": False,
                  "clock": "CLOCK_MONOTONIC", "captureElapsedNs": str(time.clock_gettime_ns(time.CLOCK_MONOTONIC) - started)}
    except BaseException as error:
        failure = error
    finally:
        if bootstrap is not None:
            fd, bootstrap = bootstrap, None
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None:
                    failure = error
        if book is not None:
            try:
                book.check()
            except BaseException as error:
                if failure is None:
                    failure = error
            try:
                source_closed = book.finish()
            except BaseException as error:
                if failure is None:
                    failure = error
    if failure is not None or not source_closed:
        # No raw exception text, captures, environment, packages or provisional
        # XML is published on failure/unknown. Never replace its original outcome.
        print("Distribution reproduction refused; no metadata publication or installation evidence.", file=sys.stderr)
        return 1

    publisher = fixture.Originals()
    try:
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        publisher.directory(publication_root)
        need(set(publisher.directories) == set(publication_directories)
             and all(publisher.directories[path]["identity"] == original
                     for path, original in publication_directories.items()), "publication-original-directories")
        record["sourceAndInputClosesKnown"] = True
        publisher.publish(work / "report/source-Distribution.xml", distribution)
        publisher.publish(work / "report/generated-Distribution.xml", generated)
        body = fixture.canonical(record)
        need(len(body) <= 16384, "closed-record-bound")
        publisher.publish(work / "report/result.json", body)
        need(publisher.finish(), "publication-close")
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        summary = fixture.canonical({"diagnosticCompleted": True, "installationQualified": False,
                                     "source": commit, "resultSha256": fixture.digest(body)})
        need(len(summary) <= 512 and os.write(1, summary) == len(summary), "final-summary-write")
        fixture.context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), 30)
        return 0
    except BaseException:
        publisher.finish()
        print("Distribution metadata publication failed; do not admit provisional files.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
