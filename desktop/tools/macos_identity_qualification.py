"""Four fixed identity fixtures for the existing installed observation owner.

Import is DATA only. No process, project discovery, build, Store, credential or
cleanup owner is introduced. The parent Fixtures retains every descriptor and
the parent run_owned return remains the sole invocation-settlement boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import re
from contextlib import ExitStack

SCOPE = "project-identity-native"
CASES = ("identity-android-apply", "identity-ios-apply",
         "identity-rollback-recovery", "identity-committed-cleanup")
RECOVERY_CASES = CASES[2:]
OLD, NEW = "com.example.reader", "com.example.another"
CONFIG_PATH = "release/mobile-release.json"
ANDROID_PATH = "app/build.gradle.kts"
PBX_PATH = "iosApp/Reader.xcodeproj/project.pbxproj"
SCHEME_PATH = "iosApp/Reader.xcodeproj/xcshareddata/xcschemes/Reader.xcscheme"
XCCONFIG_PATH = "iosApp/Config/Release.xcconfig"
PENDING = ".mobile-release-init"
FOREIGN = b"APP_ID=com.example.foreign\n"
LATER = b"// Later user edit; metadata cleanup must not touch this file.\n"
KEEP = b"Public unrelated source; preserve exactly.\n"
VERSION = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
SOURCE = b'''plugins { id("com.android.application") }
android {
 namespace = "com.example.source"
 defaultConfig {
  applicationId = "com.example.reader"
  versionCode = 1
 }
 buildTypes { debug { applicationIdSuffix = ".debug" } }
}
'''
PBX = b'''// !$*UTF8*$!
{ archiveVersion = 1; objectVersion = 56; objects = {
000000000000000000000001 = { isa = PBXProject; mainGroup = 000000000000000000000002; buildConfigurationList = 000000000000000000000004; targets = (000000000000000000000003,00000000000000000000000A); };
000000000000000000000002 = { isa = PBXGroup; sourceTree = "<group>"; children = (00000000000000000000000E); };
000000000000000000000004 = { isa = XCConfigurationList; buildConfigurations = (000000000000000000000005,000000000000000000000006); };
000000000000000000000005 = { isa = XCBuildConfiguration; name = Debug; buildSettings = {}; };
000000000000000000000006 = { isa = XCBuildConfiguration; name = Release; buildSettings = {}; };
000000000000000000000003 = { isa = PBXNativeTarget; name = Reader; productType = "com.apple.product-type.application"; buildConfigurationList = 000000000000000000000007; };
000000000000000000000007 = { isa = XCConfigurationList; buildConfigurations = (000000000000000000000008,000000000000000000000009); };
000000000000000000000008 = { isa = XCBuildConfiguration; name = Debug; buildSettings = { PRODUCT_BUNDLE_IDENTIFIER = com.example.reader; GENERATE_INFOPLIST_FILE = YES; }; };
000000000000000000000009 = { isa = XCBuildConfiguration; name = Release; baseConfigurationReference = 00000000000000000000000E; buildSettings = { GENERATE_INFOPLIST_FILE = YES; }; };
00000000000000000000000E = { isa = PBXFileReference; path = Config/Release.xcconfig; sourceTree = SOURCE_ROOT; };
00000000000000000000000A = { isa = PBXNativeTarget; name = ReaderTests; productType = "com.apple.product-type.bundle.unit-test"; buildConfigurationList = 00000000000000000000000B; };
00000000000000000000000B = { isa = XCConfigurationList; buildConfigurations = (00000000000000000000000C,00000000000000000000000D); };
00000000000000000000000C = { isa = XCBuildConfiguration; name = Debug; buildSettings = { PRODUCT_BUNDLE_IDENTIFIER = com.example.tests; }; };
00000000000000000000000D = { isa = XCBuildConfiguration; name = Release; buildSettings = { PRODUCT_BUNDLE_IDENTIFIER = com.example.tests; }; };
}; rootObject = 000000000000000000000001; }
'''
SCHEME = b'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme version="1.3">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES">
  <BuildActionEntries><BuildActionEntry buildForArchiving="YES" buildForRunning="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="000000000000000000000003"
    ReferencedContainer="container:Reader.xcodeproj" BlueprintName="Reader" BuildableName="Reader.app"/>
  </BuildActionEntry></BuildActionEntries>
 </BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
'''
XCCONFIG = b"// Literal release identity, owned only by Reader Release.\nPRODUCT_BUNDLE_IDENTIFIER = com.example.reader\n"
IGNORE = (b"# MRK Mac Aqua user ignore\nuser-output/\n.mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n"
          b".mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n"
          b".mobile-release-metadata-text-cleanup/\n.mobile-release-version-prepare/\n.mobile-release-version/\n"
          b".mobile-release-version-cleanup/\n.mobile-release-metadata-images-prepare/\n.mobile-release-metadata-images/\n"
          b".mobile-release-metadata-images-cleanup/\n")


def config(case):
    """Public literal fixture serialization, not production config admission."""
    if case not in CASES:
        raise ValueError("identity fixture case")
    ios = case == CASES[1]
    value = {"android": {"enabled": False} if ios else {
        "applicationId": OLD, "enabled": True, "identityStatus": "unverified", "module": ":app", "variant": "release"},
        "ios": {"archiveConfiguration": "Release", "bundleId": OLD, "enabled": True,
                "identityStatus": "unverified", "project": "iosApp/Reader.xcodeproj", "scheme": "Reader"} if ios else {"enabled": False},
        "metadata": {"androidLocales": [] if ios else ["en-US"], "iosLocales": ["en-US"] if ios else [], "root": "release/store"},
        "projectChecks": {"androidArtifact": [], "iosArtifact": [], "preflight": []}, "schemaVersion": 1,
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "version": {"buildKey": "BUILD_NUMBER", "nameKey": "VERSION_NAME", "source": "version.properties"}}
    return (json.dumps(value, indent=2) + "\n").encode()


def files(case, stage="initial"):
    if case not in CASES or stage not in ("initial", "pending", "before", "final") or (
            stage in ("pending", "before") and case not in RECOVERY_CASES):
        raise ValueError("identity fixture stage")
    changed = stage != "initial" and not (stage == "final" and case == CASES[2])
    rows = {".gitignore": IGNORE, CONFIG_PATH: config(case), "keep.txt": KEEP, "version.properties": VERSION}
    if case == CASES[1]:
        rows.update({PBX_PATH: PBX, SCHEME_PATH: SCHEME, XCCONFIG_PATH: XCCONFIG,
                     "iosApp/Reader.swift": b"// Unrelated Swift source; preserve exactly.\n"})
    else:
        rows.update({ANDROID_PATH: SOURCE, "settings.gradle.kts": b'include(":app")\n',
                     "app/src/Unrelated.kt": b"package com.example.source\n// Preserve the source package.\n"})
    if changed:
        for path in (CONFIG_PATH, PBX_PATH, XCCONFIG_PATH) if case == CASES[1] else (CONFIG_PATH, ANDROID_PATH):
            rows[path] = rows[path].replace(OLD.encode(), NEW.encode())
    if stage == "pending" or case == CASES[3] and stage in ("before", "final"):
        rows["gradle.properties"] = FOREIGN
    if case == CASES[3] and stage in ("before", "final"):
        rows[ANDROID_PATH] += LATER
        rows["keep.txt"] += LATER
    if stage in ("pending", "before"):
        rows.update({PENDING + "/old-1": SOURCE, PENDING + "/old-2": config(case)})
    return rows


def controls(case, stage):
    if case not in RECOVERY_CASES or stage not in ("pending", "before"):
        return ()
    return tuple(PENDING + "/" + name for name in (
        "header.json", "plan.json", "COMMITTED" if case == CASES[3] else "commit.pending", "rollback.pending"))


def directories(rows):
    result = {".": set()}
    for path in rows:
        parts = path.split("/")
        for i, part in enumerate(parts):
            result.setdefault("/".join(parts[:i]) or ".", set()).add(part)
    return {name: (0o700, tuple(sorted(entries))) for name, entries in sorted(result.items(), key=lambda pair: (pair[0].count("/"), pair[0]))}


def fixture_data(case, final):
    rows = files(case, "final" if final else "initial")
    return rows, directories(rows)


# One real identity transaction; observers call the original operation first.
# A foreign controlling file causes the original inventory guard to leave its
# REAL journal pending. There is no synthetic journal, cleanup suppression,
# substitute outcome or process-loss claim. Tests execute this identical body.
PRODUCER_BODY = r'''
def produce(root, case):
    import os, sys, threading
    from pathlib import Path
    from mobile_release import build_inputs as bi, init_transaction as tx, project_identity_edit as edit
    from mobile_release.project_identity import IdentitySelection
    from mobile_release.config_edit import CoreEditOutcome
    from mobile_release.cancellation import CleanupScope, DefaultCancellation
    from mobile_release.errors import ValidationError
    from mobile_release.init_workspace_custody import InitRootLease
    def need(value):
        if not value:
            raise ValueError("identity precursor refused")
    need(case in ("identity-rollback-recovery", "identity-committed-cleanup")
         and type(root) is type(Path(".")) and root.is_absolute() and root.name == case
         and threading.current_thread() is threading.main_thread())
    committed = case == "identity-committed-cleanup"
    originals, reached = [], []
    init, move, factory = bi._FD.__init__, tx.InitWorkspace._move, tx._rename_function
    def observed_init(slot, guard):
        need(len(originals) < 2048)
        init(slot, guard)
        originals.append(slot)  # Before this original can open anything.
    guard = DefaultCancellation(ValidationError, "identity precursor custody failed")
    lease = None
    def inject():
        need(not reached and lease is not None)
        reached.append(True)  # A failed/unknown publication is never repeated.
        slot = bi._FD(guard)
        with bi._fd_cleanup(slot):
            fd = slot.open("gradle.properties", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=lease.directory.fd)
            body = b"APP_ID=com.example.foreign\n"
            need(os.write(fd, body) == len(body))
            os.fsync(fd)
            held = os.fstat(fd)
            named = os.stat("gradle.properties", dir_fd=lease.directory.fd, follow_symlinks=False)
            need(held == named and held.st_nlink == 1 and held.st_size == len(body))
    def observed_move(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
        result = move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
        if not committed and destination == "mobile-release.json" and source.startswith("new-"):
            inject()
        return result
    def observed_factory():
        rename = factory()
        def observed_rename(source_fd, source, destination_fd, destination):
            result = rename(source_fd, source, destination_fd, destination)
            if committed and destination == "COMMITTED":
                inject()
            return result
        return observed_rename
    bi._FD.__init__ = observed_init
    try:
        registered = root.stat()
        lease = InitRootLease(root, cancellation=guard, profile=tx.TypedEditProfile.PROJECT_IDENTITY,
            registered_identity={"device": registered.st_dev, "inode": registered.st_ino,
                "mode": registered.st_mode, "uid": registered.st_uid, "gid": registered.st_gid})
        cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
        try:
            with cleanup:
                guard.install(); guard.activate(); lease.acquire()
                checkout = edit.capture_project_identity_edit(lease, IdentitySelection("android", ":app", continuity="unknown"))
                need(checkout.view["state"] == "supported")
                plan = edit.prepare_project_identity_edit(lease, checkout, expected_revision=checkout.revision,
                    desired_identity="com.example.another", intent="new-application")
                tx.InitWorkspace._move, tx._rename_function = observed_move, observed_factory
                try:
                    outcome = edit.apply_project_identity_edit(lease, plan)
                finally:
                    tx.InitWorkspace._move, tx._rename_function = move, factory
                need(outcome == CoreEditOutcome("committed" if committed else "unknown",
                     "recovery_required", "settled", "stale_revision") and reached == [True])
        finally:
            cleanup.__exit__(*sys.exc_info())
        # Memory-only original facts after cleanup. No fresh FS/core operation.
        need(lease.closed and lease._active is None
             and all(scope.closed for scope in lease._scopes) and guard.handler_state == "RESTORED"
             and not guard.lifetime_ledger.fatal and 0 < len(originals) <= 2048)
        need(all(slot.guard is guard and slot.number is None and slot.close_state == "CLOSED"
                 and slot.open_state in ("NEW", "OPEN", "NO_EFFECT") for slot in originals))
        return {"schemaVersion": 1, "case": case, "effect": outcome.effect, "journal": outcome.journal,
            "resources": outcome.resources, "reason": outcome.reason,
            "originalLeaseClosed": True, "originalScopesClosed": True, "originalDescriptorsClosed": True,
            "handlersRestored": True, "attemptedDescriptors": sum(slot.open_state != "NEW" for slot in originals),
            "neverOpenedDescriptors": sum(slot.open_state == "NEW" for slot in originals),
            "controlledLateInventoryChange": True, "processLossEvidence": False,
            "followupCoreOrFilesystemOperation": False}
    finally:
        bi._FD.__init__, tx.InitWorkspace._move, tx._rename_function = init, move, factory
'''

PRODUCER = r'''
import json, os, sys, threading
from pathlib import Path
try:
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv) == 4
            and threading.current_thread() is threading.main_thread()):
        raise ValueError()
    core = Path(sys.argv[1])
    if not core.is_absolute():
        raise ValueError()
    sys.path.insert(0, str(core))
''' + "\n".join("    " + line if line else "" for line in PRODUCER_BODY.splitlines()) + r'''
    import mobile_release.init_transaction as original
    if Path(original.__file__).parent != core / "mobile_release":
        raise ValueError()
    result = produce(Path(sys.argv[2]), sys.argv[3])
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
except BaseException:
    sys.stderr.write("identity precursor refused; preserve original fixtures\n")
    sys.stderr.flush()
    sys.exit(2)
'''


def producer_result(result, case, need):
    need(case in RECOVERY_CASES and type(result) is subprocess.CompletedProcess and result.returncode == 0
         and type(result.stdout) is bytes and 0 < len(result.stdout) <= 2048 and result.stderr == b"",
         "identity-precursor-return")
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "identity-precursor-duplicate")
            value[key] = item
        return value
    value = json.loads(result.stdout, object_pairs_hook=pairs)
    counts = [value.get(key) for key in ("attemptedDescriptors", "neverOpenedDescriptors")] if type(value) is dict else []
    need(len(counts) == 2 and all(type(n) is int and 0 <= n <= 2048 for n in counts)
         and 0 < counts[0] <= sum(counts) <= 2048, "identity-precursor-descriptors")
    expected = {"schemaVersion": 1, "case": case, "effect": "committed" if case == CASES[3] else "unknown",
        "journal": "recovery_required", "resources": "settled", "reason": "stale_revision",
        "originalLeaseClosed": True, "originalScopesClosed": True, "originalDescriptorsClosed": True,
        "handlersRestored": True, "attemptedDescriptors": counts[0], "neverOpenedDescriptors": counts[1],
        "controlledLateInventoryChange": True, "processLossEvidence": False, "followupCoreOrFilesystemOperation": False}
    # Exact type comparison: 1 is not a boolean settlement fact.
    need(type(value) is dict and value.keys() == expected.keys()
         and all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()), "identity-precursor-facts")
    return value


def _need(value, reason):
    if not value:
        raise ValueError(reason)


def _signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def capture(custody, case, stage):
    """Finite leaf of the SAME Fixtures descriptor/close ledger, not a scanner."""
    _need(case in custody.cases and not custody.inflight, "identity-capture-before-return")
    expected = files(case, stage)
    private = controls(case, stage)
    roster = directories((*expected, *private))
    rows = {}
    with ExitStack() as children:
        opened = {".": custody.projects[case]}
        for path, (mode, names) in roster.items():
            if path != ".":
                parent, _, leaf = path.rpartition("/")
                opened[path] = children.enter_context(custody._temporary(custody._open(leaf, opened[parent or "."], directory=True)))
                custody._named(opened[parent or "."], leaf, opened[path], mode)
            fd = opened[path]
            before = _signature(os.fstat(fd))
            actual = custody._roster(fd, names, "identity-fixture-roster")
            rows[path] = (before, None, actual)
            for name in names:
                relative = name if path == "." else path + "/" + name
                if relative in expected:
                    fact = custody._file(fd, name, expected[relative])
                    rows[relative] = (fact.identity, fact.sha256, None)
                elif relative in private:
                    original = _signature(os.stat(name, dir_fd=fd, follow_symlinks=False))
                    _need(original[2] == stat.S_IFREG | 0o600 and original[3:6] == (custody.uid, custody.gid, 1)
                          and 0 < original[6] <= 65536, "identity-control-file")
                    with custody._temporary(custody._open(name, fd)) as control:
                        _need(_signature(os.fstat(control)) == original, "identity-control-open")
                        data, left = [], original[6] + 1
                        while left:
                            block = os.read(control, left)
                            if not block:
                                break
                            data.append(block); left -= len(block)
                        body = b"".join(data)
                        _need(len(body) == original[6] and _signature(os.fstat(control)) == original
                              and _signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == original, "identity-control-read")
                    rows[relative] = (original, hashlib.sha256(body).hexdigest(), None)
            _need(_signature(os.fstat(fd)) == before, "identity-directory-read")
        for path, fd in opened.items():
            _need(_signature(os.fstat(fd)) == rows[path][0], "identity-directory-current")
            if path != ".":
                parent, _, name = path.rpartition("/")
                custody._named(opened[parent or "."], name, fd, 0o700)
    _need(set(rows) == set(roster) | set(expected) | set(private) and len(rows) <= 36, "identity-fixed-inventory")
    return rows


def _transition(before, after, case, stage):
    """Compare original metadata; source-path names are compiled fixture DATA."""
    initial = files(case)
    target = files(case, stage)
    for path, (fact, digest, entries) in before.items():
        if path not in after:
            _need(stage == "final" and path.startswith(PENDING), "identity-missing-original")
            continue
        current = after[path]
        if entries is not None:
            _need(current[0][:5] == fact[:5], "identity-parent-original")
        elif path in initial and target.get(path) == initial[path] and not (
                case == CASES[2] and stage == "final" and path in (CONFIG_PATH, ANDROID_PATH)):
            _need(current == (fact, digest, entries), "identity-untouched-original")
        elif stage == "pending" and path in (CONFIG_PATH, ANDROID_PATH):
            backup = after[PENDING + ("/old-2" if path == CONFIG_PATH else "/old-1")]
            _need(backup[0][:8] == fact[:8] and backup[1] == digest and current[0][0] == fact[0]
                  and current[0][1] != fact[1] and current[0][2:6] == fact[2:6], "identity-original-backup")
        elif stage == "final" and not case in RECOVERY_CASES and path in (CONFIG_PATH, ANDROID_PATH, PBX_PATH, XCCONFIG_PATH):
            _need(current[0][0] == fact[0] and current[0][1] != fact[1] and current[0][2:6] == fact[2:6], "identity-new-publication")


def _preserve_foreign(custody, case, expected):
    """One exclusive rename of our exact returned original, never unlink/retry."""
    import ctypes
    import sys
    _need(sys.platform == "darwin" and case == CASES[2] and not custody.inflight, "identity-preserve-platform")
    source, destination = custody.projects[case], custody.states[case]
    _need(_signature(os.stat("gradle.properties", dir_fd=source, follow_symlinks=False)) == expected[0], "identity-foreign-changed")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source, b"gradle.properties", destination, b"identity-foreign-control", 0x4) != 0:
        raise OSError(ctypes.get_errno(), "identity exclusive preservation refused")
    preserved = custody._file(destination, "identity-foreign-control", FOREIGN)
    _need(preserved.identity[:8] == expected[0][:8] and preserved.sha256 == expected[1], "identity-foreign-preservation")
    return preserved


def _later_edit(custody, case, path, expected):
    _need(case == CASES[3] and path in (ANDROID_PATH, "keep.txt") and not custody.inflight, "identity-later-edit")
    parent, _, leaf = path.rpartition("/")
    with ExitStack() as children:
        fd = custody.projects[case]
        if parent:
            fd = children.enter_context(custody._temporary(custody._open(parent, fd, directory=True)))
            custody._named(custody.projects[case], parent, fd, 0o700)
        _need(_signature(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) == expected[0], "identity-later-original")
        # Same original Fixtures fd/sole-close ledger. Fixed leaf only; no
        # general write/path option added to its read helper.
        out = os.open(leaf, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        custody.fds.add(out)
        with custody._temporary(out):
            _need(_signature(os.fstat(out)) == expected[0], "identity-later-open")
            _need(os.write(out, LATER) == len(LATER), "identity-later-write")
            os.fsync(out)
            actual = _signature(os.fstat(out))
            _need(actual == _signature(os.stat(leaf, dir_fd=fd, follow_symlinks=False))
                  and actual[:6] == expected[0][:6] and actual[6] == expected[0][6] + len(LATER), "identity-later-return")


def before_invocation(custody, case, run_owned, environ):
    """Leaf invoked by the existing run_cases, never an alternative runner."""
    _need(case in CASES and not custody.inflight and case not in custody.identity_inventories, "identity-invocation-reused")
    custody._namespace()
    initial = capture(custody, case, "initial")
    _need(initial == {p: (n.identity, n.sha256, n.entries) for p, n in custody.originals[case].items()},
          "identity-initial-originals-changed")
    # Before any process, latch this one attempt. An error never backfills or
    # admits the case again, even if no result could be observed.
    custody.identity_inventories[case] = {"initial": initial}
    if case in RECOVERY_CASES:
        executable, core = custody.recovery_runtime_paths()  # Actual current installed originals only.
        argv = [executable, "-I", "-S", "-B", "-c", PRODUCER, core, str(custody.path / case), case]
        custody.case, custody.stage, custody.inflight, custody.last_returned = case, "identity-precursor", True, False
        result = run_owned(argv, environ=environ, cwd=custody.path / "state" / case,
                           timeout=30, capture=True, text=False, output_limit=2048)
        _need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
              and all(type(s) is str for s in result.args) and type(result.returncode) is int
              and type(result.stdout) is bytes and type(result.stderr) is bytes
              and len(result.stdout) + len(result.stderr) <= 2048, "identity-precursor-original-return")
        custody.inflight, custody.last_returned = False, True
        facts = producer_result(result, case, _need)
        custody.recovery_runtime_paths()  # Same original input graph after the actual join.
        pending = capture(custody, case, "pending")
        _transition(initial, pending, case, "pending")
        custody.identity_precursors[case] = facts
        custody.identity_inventories[case]["pending"] = pending
        if case == CASES[2]:
            custody.identity_preserved = _preserve_foreign(custody, case, pending["gradle.properties"])
        else:
            for path in (ANDROID_PATH, "keep.txt"):
                _later_edit(custody, case, path, pending[path])
        custody.identity_inventories[case]["before"] = capture(custody, case, "before")
    else:
        custody.identity_inventories[case]["before"] = initial


def before_call(custody, case):
    _need(case in custody.identity_inventories and not custody.inflight, "identity-before-original")
    stage = "before" if case in RECOVERY_CASES else "initial"
    _need(capture(custody, case, stage) == custody.identity_inventories[case]["before"], "identity-before-changed")
    if case == CASES[2]:
        _need(custody._file(custody.states[case], "identity-foreign-control", FOREIGN) == custody.identity_preserved, "identity-preserved-changed")


def readback(custody, case, report):
    _need(not custody.inflight and custody.last_returned, "identity-readback-without-return")
    custody._namespace()
    current = capture(custody, case, "final")
    before = custody.identity_inventories[case]["before"]
    initial = custody.identity_inventories[case]["initial"]
    if case == CASES[2]:
        for path, row in initial.items():
            if row[2] is None:
                _need(current[path][0][:8] == row[0][:8] and current[path][1] == row[1], "identity-rollback-original")
        _need(custody._file(custody.states[case], "identity-foreign-control", FOREIGN) == custody.identity_preserved, "identity-preserved-changed")
    elif case == CASES[3]:
        _need(all(current[p] == row for p, row in before.items() if row[2] is None and not p.startswith(PENDING + "/")), "identity-committed-user-edit")
    _transition(initial, current, case, "final")
    hashes = {p: current[p][1] for p in files(case, "final")}
    _need(report["files"] == hashes, "identity-native-independent-readback")
    return {"completeRoster": True, "expectedBytesAndModes": True, "originalIdentitiesMatched": True,
            "transactionResidueAbsent": True, "files": hashes, "precursor": custody.identity_precursors.get(case),
            "samePathUserEditPreserved": case == CASES[3], "processLossEvidence": False}


def report(value, case, need):
    """Strict bounded comparison DATA; cannot supply a native finality getter."""
    keys = {"scope", "case", "identityUiAutomation", "sessions", "files", "controlledPrecursorRequired",
            "processLossEvidence", "buildOrStoreVerified", "namespaceRefactor", "shippingBinaryQualified"}
    need(case in CASES and type(value) is dict and value.keys() == keys and value["scope"] == "original-project-identity-v1"
         and value["case"] == case and type(value["sessions"]) is list and len(value["sessions"]) == (2 if case == CASES[0] else 1), "identity-report")
    for key in ("identityUiAutomation", "processLossEvidence", "buildOrStoreVerified", "namespaceRefactor", "shippingBinaryQualified"):
        need(value[key] is False, "identity-report-claims")
    need(value["controlledPrecursorRequired"] is (case in RECOVERY_CASES)
         and value["files"] == {p: hashlib.sha256(body).hexdigest() for p, body in files(case, "final").items()}, "identity-report-files")
    ids, projects, generations = set(), set(), set()
    for i, row in enumerate(value["sessions"]):
        closed = case == CASES[0] and i == 0
        need(type(row) is dict and row.keys() == {"sessionId", "projectId", "ownerGeneration", "intent", "revision", "planToken", "coreOutcome",
             "nativeReason", "nativeFinality", "lateSettled", "reviewMatched", "originalsJoined", "writerFrames", "stdoutFrames", "closedWithoutApply", "fileReadback"}, "identity-session-shape")
        for key in ("sessionId", "ownerGeneration", "revision", "planToken"):
            need(type(row[key]) is str and re.fullmatch(r"[0-9a-f]{32}", row[key]) is not None, "identity-session-binding")
        need(row["sessionId"] not in ids and row["revision"] != row["planToken"] and type(row["projectId"]) is str
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", row["projectId"]) is not None, "identity-session-id")
        ids.add(row["sessionId"]); projects.add(row["projectId"]); generations.add(row["ownerGeneration"])
        need(row["intent"] == ("recover" if case in RECOVERY_CASES else "edit") and row["closedWithoutApply"] is closed
             and all(row[k] is True for k in ("reviewMatched", "originalsJoined", "fileReadback")) and row["lateSettled"] is False
             and row["nativeReason"] == ("discarded" if closed else "none") and row["nativeFinality"] == "settled"
             and type(row["writerFrames"]) is int and row["writerFrames"] == (2 if closed else 3)
             and type(row["stdoutFrames"]) is int and row["stdoutFrames"] == 3, "identity-original-facts")
        need(row["coreOutcome"] == {"effect": "not_started" if closed else "rolled_back" if case == CASES[2] else "committed",
             "journal": "not_created" if closed else "clean", "resources": "settled", "reason": "cancelled" if closed else "none"}, "identity-core-outcome")
    need(len(projects) == 1 and len(generations) == 1, "identity-original-generation")
    return value
