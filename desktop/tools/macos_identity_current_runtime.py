#!/usr/bin/env python3
"""Closed identity/tool/upload-key observations on one current installed observer.

Import is DATA-only. The explicit main entry uses the existing Fixtures and
run_cases/owned_process owners; it never prepares, signs or installs a runtime.
An ordinary shipping image cannot be substituted for the compiled observer.
"""
from pathlib import Path
import os
import re
import sys


SCOPE = "project-identity-native"
PUSH_SCOPE = "git-push-native"
PUSH_CREATE_SCOPE = "git-push-create-native"
UPSTREAM_SCOPE = "git-upstream-native"
FETCH_SCOPE = "git-fetch-native"
GIT_SCOPE = "git-native"
TOOLS_SCOPE = "tool-setup"
SERVICE_SCOPE = "tool-service-prerequisite"
UPLOAD_SCOPES = ("upload-key-roundtrip", "upload-key-stop-before-go", "upload-key-stop-after-new")
COLD_SCOPE = "upload-key-cold-restart"
BACKUP_SCOPE = "upload-key-backup-roundtrip"
ROLE = "installed-shell-observation"
TARGET = "aarch64-apple-darwin"
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
REF = "refs/heads/verify/desktop-macos-candidate"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-installed.yml@" + REF
# These are the existing observer preparation owners, including their required
# notarization. No distribution image, desktop cdylib, Xcode or test-suite role.
PACKAGE_PHASES = (
    "prepare", "sign-vault-helper", "sign-installed-cli", "sign-remover",
    "verify-before", "sign-desktop-payload",
    "sign-root-app", "verify-after", "notarize-payload", "sign-root-installer",
    "finalize-package", "package-install",
)
DATA_PHASES = ("select-github-tools-signed", "project-history-provider", "project-github-seal")


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def package_role(environment, phase, target):
    """Closed additional scope check, not a replacement for package admission."""
    scope = environment.get("MRK_MACOS_NATIVE_SCOPE", "disabled")
    if scope == "disabled":
        return None  # Preserve every original ordinary/prepared role decision.
    need(scope in (SCOPE, TOOLS_SCOPE, FETCH_SCOPE, PUSH_SCOPE, GIT_SCOPE) and target == TARGET
         and environment.get("GITHUB_REF") == REF
         and environment.get("MRK_MACOS_PACKAGE_ROLE") == ROLE
         and phase in PACKAGE_PHASES + DATA_PHASES, "identity-native-package-scope")
    return ROLE


def current_context(environment, target):
    """Fixed current-job DATA. No caller-selected source, work root or case."""
    need(environment.get("MRK_MACOS_NATIVE_SCOPE") in (SCOPE, TOOLS_SCOPE, FETCH_SCOPE, PUSH_SCOPE, GIT_SCOPE)
         and package_role(environment, "package-install", target) == ROLE,
         "identity-native-entry-scope")
    source = environment.get("GITHUB_SHA", "")
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and source != "0" * 40, "identity-native-source")
    required = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": REF,
        "GITHUB_WORKSPACE": str(CHECKOUT), "GITHUB_WORKFLOW_REF": WORKFLOW,
        "GITHUB_WORKFLOW_SHA": source, "MRK_EXPECTED_SHA": source,
        "MRK_MACOS_INSTALL_SOURCE_COMMIT": source,
        "MRK_MACOS_STORE_RUNTIME": "signed-component",
    }
    need(all(environment.get(key) == value for key, value in required.items()),
         "identity-native-current-route")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = environment.get(key)
        need(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value),
             "identity-native-run")
    value = environment.get("MRK_MACOS_WORK")
    need(type(value) is str and re.fullmatch(
        r"/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}", value),
        "identity-native-work")
    need(all(environment.get(key, "disabled") == "disabled" for key in (
        "MRK_MACOS_AQUA_SCOPE", "MRK_MACOS_SAME_PACKAGE_SCOPE",
        "MRK_MACOS_XCODE_SETUP_SCOPE", "MRK_MACOS_REMOVAL_CASE")),
        "identity-native-single-scope")
    return source, environment["GITHUB_RUN_ID"], environment["GITHUB_RUN_ATTEMPT"], Path(value)


def observation_scope(environment, scope):
    """One source-selected package, separate explicit driver invocations.

    Tool scope keeps the same installed observer for identity first, then its
    separate service prerequisite and unchanged three tool journeys. After
    actual catalogue preparation, each upload-key case is a separate explicit
    invocation. This is not prerequisite proof, a generic selector or a retry.
    """
    native = environment.get("MRK_MACOS_NATIVE_SCOPE")
    need(type(scope) is str and ((native == SCOPE and scope == SCOPE) or (native == PUSH_SCOPE and scope == PUSH_SCOPE) or (native == FETCH_SCOPE and scope == FETCH_SCOPE)
         or (native == GIT_SCOPE and scope in (FETCH_SCOPE, PUSH_SCOPE, PUSH_CREATE_SCOPE, UPSTREAM_SCOPE))
         or (native == TOOLS_SCOPE and scope in (SCOPE, SERVICE_SCOPE, TOOLS_SCOPE, *UPLOAD_SCOPES, COLD_SCOPE, BACKUP_SCOPE))),
         "current-native-observation-scope")
    return scope


def arguments(argv):
    if argv == ["--target", TARGET]:
        return SCOPE  # Preserve the original identity-only invocation.
    need(type(argv) is list and len(argv) == 4 and argv[:3] == ["--target", TARGET, "--scope"]
         and type(argv[3]) is str and argv[3] in (SCOPE, FETCH_SCOPE, PUSH_SCOPE, PUSH_CREATE_SCOPE, UPSTREAM_SCOPE, SERVICE_SCOPE, TOOLS_SCOPE, *UPLOAD_SCOPES, COLD_SCOPE, BACKUP_SCOPE),
         "identity-native-arguments")
    return argv[3]


def _native_user():
    import platform
    import pwd
    import stat
    import threading
    need(Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_identity_current_runtime.py"
         and Path.cwd() == CHECKOUT, "identity-native-source-driver")
    need(sys.platform == "darwin" and sys.maxsize == 2 ** 63 - 1
         and platform.machine() == "arm64" and platform.mac_ver()[0].split(".")[0] == "26"
         and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1,
         "identity-native-platform")
    uid, gid = os.getuid(), os.getgid()
    need(uid > 0 and uid == os.geteuid() and gid == os.getegid()
         and threading.current_thread() is threading.main_thread(), "identity-native-main-user")
    username = pwd.getpwuid(uid).pw_name
    console = os.stat("/dev/console", follow_symlinks=False)
    need(username == "runner" and stat.S_ISCHR(console.st_mode) and console.st_uid == uid,
         "identity-native-console-user")
    return uid, gid, username


def _load_observer():
    import importlib.util
    name = "_mrk_identity_current_observer"
    need(name not in sys.modules, "identity-native-observer-imported")
    spec = importlib.util.spec_from_file_location(name, CHECKOUT / "desktop/tools/macos_aqua_qualification.py")
    need(spec is not None and spec.loader is not None, "identity-native-observer-loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # Retain the original before its loader can fail.
    spec.loader.exec_module(module)
    return module


def _admit_runtime(aqua, fixtures, binding, work, environment):
    # The existing owner retains real installed inventory/record/M/core/Python;
    # it neither adopts a legacy supplier receipt nor creates another runtime.
    fixtures.admit_normal_account_runtime(CHECKOUT, work, application_source=binding.source)
    aqua.need(len(fixtures.normal_stager_registrations) == 1, "identity-native-stager-original")
    stage = fixtures.normal_stager_registrations[0]
    checkout = aqua._gate_directory(fixtures, str(CHECKOUT))
    git = aqua._gate_directory(fixtures, ".git", checkout)
    head, _ = aqua._gate_file(fixtures, "HEAD", git, 41)
    aqua.need(head == (binding.source + "\n").encode("ascii"), "identity-native-detached-source")
    desktop = aqua._gate_directory(fixtures, "desktop", checkout)
    inputs = aqua._gate_directory(fixtures, "macos-installed-inputs", desktop)
    packaging = aqua._gate_directory(fixtures, "packaging", desktop)
    # SAME pure source parsers, but the original inputs remain in Fixtures' FD
    # book through every case POST rather than reopening nominal equal paths.
    python_body, _ = aqua._gate_file(fixtures, "python-signed-runtime-binding.json", inputs, 4096)
    producer, _ = aqua._gate_file(fixtures, "macos-install-producer-signing.profile", packaging, 1024)
    service, _ = aqua._gate_file(fixtures, "macos-android-service-signing.profile", packaging, 512)
    python = stage.signed_runtime_binding_data(python_body, producer, service, target=binding.target)
    store_body, _ = aqua._gate_file(fixtures, "store-signed-component.json", inputs, 4096)
    store = stage.signed_store_selection_data(store_body, target=binding.target)
    work_fd = aqua._gate_directory(fixtures, str(work), private=True)
    runtime_body, _ = aqua._gate_file(fixtures, "runtime-binding.json", work_fd, 16384)
    source_body, _ = aqua._gate_file(fixtures, "source-binding.json", work_fd, 65536)
    _, composed = stage.composed_runtime_binding_data(runtime_body, python, store, target=binding.target)
    info = os.fstat(work_fd)
    source = stage.composed_source_binding_data(source_body, runtime_body, composed, environment,
        (info.st_dev, info.st_ino, info.st_uid))
    aqua.need(source.get("packageRole") == ROLE, "identity-native-observer-role")
    # Join computed CURRENT M to the already-held installed manifest. This adds
    # a hash checkpoint to the same FD book, never a reopen or second close.
    originals = [item for item in fixtures.recovery_runtime_originals if item[1] == "manifest.json"]
    aqua.need(len(originals) == 1, "identity-native-installed-manifest")
    parent, name, fd, before = originals[0]
    record = {"parent": parent, "name": name, "fd": fd, "full9": before,
              "sha256": composed["runtimeManifestSha256"]}
    fixtures.gate_files.append(record)
    native = environment.get("MRK_MACOS_NATIVE_SCOPE")
    git = native in (FETCH_SCOPE, PUSH_SCOPE, GIT_SCOPE)
    aqua.need(not git or 0 < before[6] <= stage.MANIFEST_BYTES, "current-git-manifest-bound")
    manifest, actual = aqua._gate_file_read(record, capture=git)
    aqua.need(actual == record["sha256"], "identity-native-current-manifest")
    if git:
        # Source-selected singleton/combined images cannot stand in for each
        # other. This parses the SAME held bytes; Fixtures and the native Book
        # retain every entry, including the other pair, through original POST.
        _, rows = stage.manifest_files(manifest, actual, current=True, target=binding.target)
        expected = (stage.GIT_OBSERVATION_BOOTSTRAPS if native == GIT_SCOPE else
                    stage.FETCH_OBSERVATION_BOOTSTRAPS if native == FETCH_SCOPE else stage.PUSH_OBSERVATION_BOOTSTRAPS)
        aqua.need(set(rows) & stage.GIT_OBSERVATION_BOOTSTRAPS == expected, "current-git-observation-roster")
        if native == GIT_SCOPE:
            # The existing normal observer holds M/core/Python. Retain these
            # four additional fixed originals in that SAME book so an unused
            # peer is also checked after each original producer returns.
            for entry in sorted(stage.GIT_OBSERVATION_BOOTSTRAPS):
                original, hashed, _ = fixtures._recovery_read(parent, entry, 0, 64 * 1024, 0o444, retain=True)
                entry_parent, entry_name, entry_fd, entry_before = fixtures.recovery_runtime_originals[-1]
                fixtures.normal_runtime_policy[entry_fd] = original[2]
                fixtures.gate_files.append({"parent": entry_parent, "name": entry_name, "fd": entry_fd,
                    "full9": entry_before, "sha256": rows[entry]["sha256"]})
                aqua.need(original[6] == rows[entry]["size"] and hashed == rows[entry]["sha256"],
                          "current-git-entry-correspondence")
    _current(aqua, fixtures)


def _current(aqua, fixtures):
    aqua._gate_recheck(fixtures)
    fixtures.recovery_runtime_paths()


def _run(aqua, binding, uid, gid, username, work, environment, *, scope=SCOPE):
    """One fixed invocation; test doubles never supply production authority."""
    fixtures = owner = error = None
    count = 0
    cases = ()
    not_executed = ()
    try:
        observation_scope(environment, scope)
        cases = aqua.TOOLS.RUN_ORDER if scope == TOOLS_SCOPE else aqua.selected_cases(scope)
        fixtures = aqua.Fixtures(binding, uid, gid, scope)
        fixtures.prepare()
        _admit_runtime(aqua, fixtures, binding, work, environment)
        owner = aqua.load_owner(CHECKOUT)
        _current(aqua, fixtures)

        def emit_checked(value):
            nonlocal count
            aqua.need(count < len(cases) and value.get("case") == cases[count], "identity-native-case-order")
            _current(aqua, fixtures)  # Only after run_cases' original return/readback.
            aqua.emit_record(value, sys.stdout)
            count += 1

        not_executed = aqua.run_cases(binding, fixtures, owner.run_owned, uid, username, emit_checked, scope=scope)
        aqua.need(type(not_executed) is tuple and all(case in cases for case in not_executed)
                  and len(set(not_executed)) == len(not_executed) and count == len(cases)
                  and len(cases) == (2 if scope == COLD_SCOPE else 1 if scope in (*UPLOAD_SCOPES, BACKUP_SCOPE) else {SCOPE: 4, FETCH_SCOPE: 4, PUSH_SCOPE: 3, PUSH_CREATE_SCOPE: 5, UPSTREAM_SCOPE: 1, SERVICE_SCOPE: 1, TOOLS_SCOPE: 3}[scope]),
                  "identity-native-incomplete")
        aqua.need(not not_executed or scope in (SERVICE_SCOPE, TOOLS_SCOPE, *UPLOAD_SCOPES, BACKUP_SCOPE), "identity-native-incomplete")
        _current(aqua, fixtures)
    except BaseException as caught:
        error = caught
    if fixtures is not None and not fixtures.inflight:
        try:
            fixtures.close()
        except BaseException as caught:
            if error is None:
                error = caught
    if error is not None:
        try:
            aqua.emit_record(aqua.diagnostic(error, owner, fixtures), sys.stderr)
        except BaseException:
            pass  # No retry or masking of the original unknown/failed call.
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    try:
        kind = "macos-git-upstream-current-complete" if scope == UPSTREAM_SCOPE else "macos-git-push-create-current-complete" if scope == PUSH_CREATE_SCOPE else "macos-git-push-current-complete" if scope == PUSH_SCOPE else "macos-git-fetch-current-complete" if scope == FETCH_SCOPE else "macos-upload-key-backup-current-complete" if scope == BACKUP_SCOPE else "macos-upload-key-cold-restart-complete" if scope == COLD_SCOPE else "macos-upload-key-current-complete" if scope in UPLOAD_SCOPES else (
            "macos-identity-current-complete" if scope == SCOPE else (
                "macos-tool-service-current-complete" if scope == SERVICE_SCOPE else "macos-tool-setup-current-complete"))
        if not_executed:
            # Only a parsed report after actual original return/readback/close
            # can be unexecuted. No runtime error or unknown becomes exit78.
            # Do not manufacture Ready or automatically run another case.
            upload = scope in (*UPLOAD_SCOPES, BACKUP_SCOPE)
            aqua.emit_record({"schemaVersion": 1, "type": "macos-upload-key-current-unexecuted" if upload else "macos-tool-current-unexecuted",
                **binding.public(), "target": binding.target, "scope": scope,
                "notExecuted": list(not_executed), "allOriginalCallsReturned": True,
                "fixtureHandlesClosed": True, "manualStep": (
                    "Resolve the reported vault or protected JDK catalogue prerequisite before a new explicit invocation; no automatic retry was performed."
                    if upload else "Resolve the reported service prerequisite before starting the tool cases; no automatic retry was performed."),
                "shippingBinaryQualified": False, "distributionQualified": False}, sys.stdout)
            return 78
        aqua.emit_record({"schemaVersion": 1, "type": kind,
            **binding.public(), "target": binding.target, "cases": list(cases),
            "allOriginalCallsReturned": True, "independentReadbacks": True, "fixtureHandlesClosed": True,
            "currentInstalledRuntime": True, "instrumentedEngineeringApp": True,
            "shippingBinaryQualified": False, "distributionQualified": False,
            "processLossEvidence": False, **({"cleanProcessRestart": True, "backupRoundtrip": False,
                "physicalPickerQualified": False} if scope == COLD_SCOPE else {
                "cleanProcessRestart": False, "backupRoundtrip": True,
                "physicalPickerQualified": False} if scope == BACKUP_SCOPE else {})}, sys.stdout)
    except BaseException:
        return 1
    return 0


def main():
    try:
        scope = arguments(sys.argv[1:])
        environment = dict(os.environ)
        observation_scope(environment, scope)
        source, run, attempt, work = current_context(environment, TARGET)
        uid, gid, username = _native_user()
        aqua = _load_observer()
        binding = aqua.Binding(source, run, attempt, TARGET).checked()
        os.umask(0o077)
        return _run(aqua, binding, uid, gid, username, work, environment, scope=scope)
    except BaseException as error:
        # No source paths, environment values, transcripts or exception text.
        try:
            sys.stderr.write('{"schemaVersion":1,"type":"macos-identity-current-failure",'
                             '"reason":"entry-refused","shippingBinaryQualified":false}\n')
            sys.stderr.flush()
        except BaseException:
            pass
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
