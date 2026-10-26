#!/usr/bin/env python3
"""Closed identity/tool/upload-key/Git observations on one installed observer.

Import is DATA-only. The explicit main entry uses the existing Fixtures and
run_cases/owned_process owners; it never prepares, signs or installs a runtime.
An ordinary shipping image cannot be substituted for the compiled observer.
The explicit retained mode separates its original compiled fixture tuple from
the current helper job; its fresh Installer receipt never recreates old work.
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
GIT_CLI_SCOPES = ("git-index-cli-native", "git-branch-cli-native")
TOOLS_SCOPE = "tool-setup"
PUBLIC_TOOLS_SCOPE = "tool-public-acquisition"  # Internal only; same tool-setup image.
SERVICE_SCOPE = "tool-service-prerequisite"
CLI_SCOPE = "installed-cli-local-check"
UPLOAD_SCOPES = ("upload-key-roundtrip", "upload-key-stop-before-go", "upload-key-stop-after-new")
COLD_SCOPE = "upload-key-cold-restart"
BACKUP_SCOPE = "upload-key-backup-roundtrip"
BACKUP_CLI_SCOPE = "upload-key-backup-cli"
ROLE = "installed-shell-observation"
TARGET = "aarch64-apple-darwin"
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
REF = "refs/heads/verify/desktop-macos-candidate"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-installed.yml@" + REF
HELPER_ROOT = CHECKOUT / ".candidate-consumer-helper"
RETAINED_REF = "refs/heads/verify/desktop-macos-observer-reuse"
RETAINED_WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-candidate-consume.yml@" + RETAINED_REF
RETAINED_SELECTION = "desktop/macos-installed-inputs/retained-observer-selection.json"
RETAINED_GIT_SELECTION = "desktop/macos-installed-inputs/retained-git-observer-selection.json"
RETAINED_GIT_TUPLE = ("ed91b0dd582ca35a6dc57556aa73d60f1fc852a2", "40132594293", "1")
RETAINED_GIT_SCOPES = (*GIT_CLI_SCOPES, FETCH_SCOPE, PUSH_SCOPE, PUSH_CREATE_SCOPE, UPSTREAM_SCOPE)
RETAINED_SCOPES = (SCOPE, SERVICE_SCOPE, TOOLS_SCOPE, PUBLIC_TOOLS_SCOPE, CLI_SCOPE,
                   *UPLOAD_SCOPES, COLD_SCOPE, BACKUP_SCOPE, BACKUP_CLI_SCOPE, *RETAINED_GIT_SCOPES)
# Fixed current helper SOURCE, not a second content-hash or supplier authority.
# Tool and Git retain their corresponding existing helper originals separately.
RETAINED_HELPER_FILES = (
    "macos_identity_current_runtime.py", "macos_aqua_qualification.py",
    "macos_candidate_carrier.py", "macos_fixed_carrier_resume.py",
    "macos_identity_qualification.py", "macos_tool_setup_observation.py",
    "macos_tool_acquisition_observation.py", "macos_cli_local_check_observation.py",
    "macos_upload_key_observation.py", "macos_upload_key_restart_observation.py",
    "macos_upload_key_backup_observation.py", "macos_upload_key_cli_observation.py",
)
RETAINED_GIT_HELPER_FILES = (*RETAINED_HELPER_FILES[:4],
    "macos_git_fetch_qualification.py", "macos_git_push_qualification.py",
    "macos_git_push_create_qualification.py", "macos_git_upstream_qualification.py",
    "macos_cli_local_check_observation.py", "macos_git_cli_observation.py",
)
# A source-selected observer host is not a product minimum-OS or Git build
# nomination. Keep the exact old host; only combined Git admits the preview.
HOST_PROFILES = (
    ("macos-26", "arm64", "github-hosted-macos26-arm64", "26"),
    ("xcode-27", "arm64", "github-hosted-xcode27-arm64", "27"),
)
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


def _host_profile(environment):
    selected = tuple(environment.get(key) for key in (
        "MRK_MACOS_RUNNER", "MRK_MACOS_MACHINE", "MRK_MACOS_HOSTED_JOB"))
    profile = next((row for row in HOST_PROFILES if row[:3] == selected), None)
    need(profile is not None and (profile[3] == "26"
         or environment.get("MRK_MACOS_NATIVE_SCOPE") == GIT_SCOPE),
         "current-native-host-profile")
    return profile


def package_role(environment, phase, target):
    """Closed additional scope check, not a replacement for package admission."""
    scope = environment.get("MRK_MACOS_NATIVE_SCOPE", "disabled")
    if scope == "disabled":
        return None  # Preserve every original ordinary/prepared role decision.
    need(scope in (SCOPE, TOOLS_SCOPE, FETCH_SCOPE, PUSH_SCOPE, GIT_SCOPE) and target == TARGET
         and environment.get("GITHUB_REF") == REF
         and environment.get("MRK_MACOS_PACKAGE_ROLE") == ROLE
         and phase in PACKAGE_PHASES + DATA_PHASES, "identity-native-package-scope")
    _host_profile(environment)
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
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": (
            "workflow_dispatch" if environment.get("MRK_MACOS_PREPARED_RESUME") == "true" else "push"),
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


def retained_context(environment, target):
    """Actual current consumer context, never the retained observer's job."""
    source = environment.get("GITHUB_SHA", "")
    need(target == TARGET and type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and source != "0" * 40, "retained-observer-helper-source")
    git = environment.get("MRK_CANDIDATE_MODE") == "install-retained-git-observer"
    required = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": RETAINED_REF,
        "GITHUB_WORKSPACE": str(CHECKOUT), "GITHUB_WORKFLOW_REF": RETAINED_WORKFLOW,
        "GITHUB_WORKFLOW_SHA": source, "MRK_MACOS_TARGET": TARGET,
        "MRK_CANDIDATE_MODE": "install-retained-git-observer" if git else "install-retained-observer",
        "MRK_MACOS_NATIVE_SCOPE": GIT_SCOPE if git else TOOLS_SCOPE,
        "MRK_MACOS_PACKAGE_ROLE": ROLE,
    }
    if git:
        required.update(MRK_CANDIDATE_SOURCE=RETAINED_GIT_TUPLE[0],
            MRK_MACOS_INSTALL_SOURCE_COMMIT=RETAINED_GIT_TUPLE[0], MRK_EXPECTED_SHA=source,
            MRK_MACOS_STORE_RUNTIME="signed-component", DEVELOPER_DIR="/Library/Developer/CommandLineTools")
    need(all(environment.get(key) == value for key, value in required.items()), "retained-observer-current-route")
    need(_host_profile(environment)[0] == ("xcode-27" if git else "macos-26"), "retained-observer-host")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        need(type(environment.get(key)) is str and re.fullmatch(r"[1-9][0-9]{0,19}", environment[key]),
             "retained-observer-current-run")
    work = environment.get("MRK_MACOS_WORK")
    need(type(work) is str and re.fullmatch(
        r"/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}", work), "retained-observer-current-work")
    need(all(environment.get(key, "disabled") == "disabled" for key in (
        "MRK_MACOS_AQUA_SCOPE", "MRK_MACOS_SAME_PACKAGE_SCOPE", "MRK_MACOS_XCODE_SETUP_SCOPE",
        "MRK_MACOS_REMOVAL_CASE")), "retained-observer-single-scope")
    return source, environment["GITHUB_RUN_ID"], environment["GITHUB_RUN_ATTEMPT"], Path(work)


def observation_scope(environment, scope):
    """One source-selected package, separate explicit driver invocations.

    Tool scope keeps the same installed observer for identity first, then its
    separate service prerequisite and unchanged three tool journeys. After
    actual catalogue preparation, each upload-key case is a separate explicit
    invocation. This is not prerequisite proof, a generic selector or a retry.
    """
    native = environment.get("MRK_MACOS_NATIVE_SCOPE")
    need(type(scope) is str and ((native == SCOPE and scope == SCOPE) or (native == PUSH_SCOPE and scope == PUSH_SCOPE) or (native == FETCH_SCOPE and scope == FETCH_SCOPE)
         or (native == GIT_SCOPE and scope in (FETCH_SCOPE, PUSH_SCOPE, PUSH_CREATE_SCOPE, UPSTREAM_SCOPE, *GIT_CLI_SCOPES))
         or (native == TOOLS_SCOPE and scope in (SCOPE, SERVICE_SCOPE, TOOLS_SCOPE, PUBLIC_TOOLS_SCOPE, CLI_SCOPE, *UPLOAD_SCOPES, COLD_SCOPE, BACKUP_SCOPE, BACKUP_CLI_SCOPE))),
         "current-native-observation-scope")
    return scope


def arguments(argv):
    if argv == ["--target", TARGET, "--scope", TOOLS_SCOPE, "--tool-cases", "public-acquisition"]:
        return PUBLIC_TOOLS_SCOPE
    if argv == ["--target", TARGET]:
        return SCOPE  # Preserve the original identity-only invocation.
    need(type(argv) is list and len(argv) == 4 and argv[:3] == ["--target", TARGET, "--scope"]
         and type(argv[3]) is str and argv[3] in (*GIT_CLI_SCOPES, SCOPE, FETCH_SCOPE, PUSH_SCOPE, PUSH_CREATE_SCOPE, UPSTREAM_SCOPE, SERVICE_SCOPE, TOOLS_SCOPE, CLI_SCOPE, *UPLOAD_SCOPES, COLD_SCOPE, BACKUP_SCOPE, BACKUP_CLI_SCOPE),
         "identity-native-arguments")
    return argv[3]


def entry_arguments(argv):
    retained = type(argv) is list and argv[:1] == ["--retained-observer"]
    scope = arguments(argv[1:] if retained else argv)
    need(not retained or scope in RETAINED_SCOPES, "retained-observer-scope")
    return scope, retained


def _native_user(environment, *, retained=False):
    import platform
    import pwd
    import stat
    import threading
    profile = _host_profile(environment)
    source = HELPER_ROOT if retained else CHECKOUT
    need(Path(__file__).absolute() == source / "desktop/tools/macos_identity_current_runtime.py"
         and Path.cwd() == CHECKOUT, "identity-native-source-driver")
    # Observe once, bound and compare that exact value, then carry it as DATA.
    # Never reread a changed host value merely to decorate a successful report.
    version = platform.mac_ver()[0]
    need(sys.platform == "darwin" and sys.maxsize == 2 ** 63 - 1
         and platform.machine() == "arm64" and type(version) is str
         and len(version) <= 32 and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}", version)
         and version.split(".")[0] == profile[3]
         and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1,
         "identity-native-platform")
    uid, gid = os.getuid(), os.getgid()
    need(uid > 0 and uid == os.geteuid() and gid == os.getegid()
         and threading.current_thread() is threading.main_thread(), "identity-native-main-user")
    username = pwd.getpwuid(uid).pw_name
    console = os.stat("/dev/console", follow_symlinks=False)
    need(username == "runner" and stat.S_ISCHR(console.st_mode) and console.st_uid == uid,
         "identity-native-console-user")
    return uid, gid, username, (profile[0], version)


def _load_observer(*, retained=False):
    import importlib.util
    name = "_mrk_identity_current_observer"
    need(name not in sys.modules, "identity-native-observer-imported")
    source = HELPER_ROOT if retained else CHECKOUT
    spec = importlib.util.spec_from_file_location(name, source / "desktop/tools/macos_aqua_qualification.py")
    need(spec is not None and spec.loader is not None, "identity-native-observer-loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # Retain the original before its loader can fail.
    spec.loader.exec_module(module)
    return module


def _retained_selection(environment):
    # Trusted current SOURCE only. This bounded first read proposes a fixture
    # tuple; admission retains/rechecks the original before any process owner.
    import importlib
    need("desktop.tools.macos_candidate_carrier" not in sys.modules, "retained-observer-parser-imported")
    sys.path.insert(0, str(HELPER_ROOT))
    try:
        parser = importlib.import_module("desktop.tools.macos_candidate_carrier")
    finally:
        sys.path.pop(0)
    need(Path(parser.__file__).absolute() == HELPER_ROOT / "desktop/tools/macos_candidate_carrier.py",
         "retained-observer-parser-source")
    git = parser.retained_git_context(environment)
    path = RETAINED_GIT_SELECTION if git else RETAINED_SELECTION
    with (HELPER_ROOT / path).open("rb") as original:
        body = original.read(8193)
    need(0 < len(body) <= 8192, "retained-observer-selection-bound")
    selected = parser.retained_observer_selection_data(parser.decode(body))
    need(selected["nativeScope"] == environment.get("MRK_MACOS_NATIVE_SCOPE"), "retained-observer-source-scope")
    return parser, body, selected


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


def prepared_binding(environment):
    # The artifact action checks the service digest; the existing prepared
    # owner rechecks API provenance, every member hash and all original closes.
    import importlib
    sys.path.insert(0, str(CHECKOUT))
    try:
        parser = importlib.import_module('desktop.tools.macos_prepared_package')
    finally:
        sys.path.pop(0)
    need(Path(parser.__file__).absolute() == CHECKOUT / 'desktop/tools/macos_prepared_package.py',
         'prepared-native-parser-source')
    return parser.native_binding(environment)


def _admit_prepared_runtime(aqua, fixtures, binding, work, environment, prepared):
    source, run, attempt, actual_work = current_context(environment, binding.target)
    manifest = prepared.manifest
    origin = manifest['origin']
    aqua.need(prepared.native_compatible and actual_work == work
              and prepared.consumer['runId'] == run and prepared.consumer['runAttempt'] == attempt
              and (binding.source, binding.run, binding.attempt) ==
                  (origin['source'], origin['runId'], origin['runAttempt'])
              and origin['nativeScope'] == environment['MRK_MACOS_NATIVE_SCOPE'], 'prepared-native-fixture-origin')
    checkout = aqua._gate_directory(fixtures, str(CHECKOUT))
    git = aqua._gate_directory(fixtures, '.git', checkout)
    head, _ = aqua._gate_file(fixtures, 'HEAD', git, 41)
    aqua.need(head == (source + '\n').encode('ascii'), 'prepared-native-source-head')
    work_fd = aqua._gate_directory(fixtures, str(work), private=True)
    transport = aqua._gate_directory(fixtures, 'prepared-input', work_fd)
    body, _ = aqua._gate_file(fixtures, 'PREPARED.json', transport, 16384)
    aqua.need(aqua._gate_json(body, 16384) == manifest, 'prepared-native-manifest-changed')
    fixtures.admit_normal_account_runtime(CHECKOUT, work, application_source=binding.source)
    aqua.need(len(fixtures.normal_stager_registrations) == 1, 'prepared-native-stager')
    stage = fixtures.normal_stager_registrations[0]
    selection = stage.source_build_selection(binding.target)
    aqua.need((selection.release, selection.package_version) == (manifest['release'], manifest['packageVersion']),
              'prepared-native-release')
    names = {'package-install.status': 4, 'package-request-id.txt': 33, 'package-audit.json': 16384,
             'producer-descriptor-input.json': 65536, 'android-helper-package-install.json': 16384,
             'installation-observation.json': 65536, 'installer-output.status': 4}
    anchors = {name: aqua._gate_file(fixtures, name, work_fd, limit)[0] for name, limit in names.items()}
    current = aqua.Binding(source, run, attempt, binding.target).checked()
    expected = dict(environment, MRK_MACOS_INSTALL_INVENTORY_SHA256=manifest['inventorySha256'],
                    MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=manifest['runtimeManifestSha256'])
    aqua._gate_installation(anchors['installation-observation.json'], anchors['installer-output.status'],
        current, expected, stage, selection, anchors, workflow=WORKFLOW, application_source=prepared.source)
    receipt = aqua._gate_json(anchors['android-helper-package-install.json'], 16384)
    package = next(row for row in manifest['members'] if row['name'] == 'MobileReleaseKit.pkg')
    aqua.need(receipt['distribution']['packageSha256'] == package['sha256']
              and receipt['distribution']['packageBytes'] == package['bytes'], 'prepared-native-installed-package')
    installed_manifest, _ = _retained_installed_original(aqua, fixtures, 'manifest.json', stage.MANIFEST_BYTES,
        expected=manifest['runtimeManifestSha256'], capture=True)
    _retained_installed_original(aqua, fixtures, stage.INSTALLATION_INVENTORY_NAME, stage.INVENTORY_BYTES,
        expected=manifest['inventorySha256'])
    record_body, _ = _retained_installed_original(aqua, fixtures, stage.INSTALLATION_RECORD_NAME,
        stage.INSTALLATION_RECORD_LIMIT, capture=True)
    observation = aqua._gate_json(anchors['installation-observation.json'], 65536)
    aqua.need(stage.decode(record_body).get('instance') == observation['invocation'], 'prepared-native-fresh-instance')
    _, rows = stage.manifest_files(installed_manifest, manifest['runtimeManifestSha256'], current=True, target=binding.target)
    if origin['nativeScope'] == GIT_SCOPE:
        aqua.need(set(rows) & stage.GIT_OBSERVATION_BOOTSTRAPS == stage.GIT_OBSERVATION_BOOTSTRAPS,
                  'prepared-git-bootstrap-roster')
        parent = next(item[0] for item in fixtures.recovery_runtime_originals if item[1] == 'manifest.json')
        for entry in sorted(stage.GIT_OBSERVATION_BOOTSTRAPS):
            original, hashed, _ = fixtures._recovery_read(parent, entry, 0, 64 * 1024, 0o444, retain=True)
            entry_parent, entry_name, entry_fd, entry_before = fixtures.recovery_runtime_originals[-1]
            fixtures.normal_runtime_policy[entry_fd] = original[2]
            fixtures.gate_files.append(dict(parent=entry_parent, name=entry_name, fd=entry_fd,
                full9=entry_before, sha256=rows[entry]['sha256']))
            aqua.need(original[6] == rows[entry]['size'] and hashed == rows[entry]['sha256'], 'prepared-git-bootstrap-bytes')
    _current(aqua, fixtures)
    return dict(origin=dict(origin), consumerRunId=run, consumerRunAttempt=attempt,
                freshInstallReceiptSha256=aqua.digest(anchors['android-helper-package-install.json']), productReady=False)


def _retained_installed_original(aqua, fixtures, name, limit, *, expected=None, capture=False):
    """Hash the SAME installed original, retained in the existing Fixtures book."""
    originals = [item for item in fixtures.recovery_runtime_originals if item[1] == name]
    aqua.need(len(originals) == 1, "retained-observer-installed-original")
    parent, name, fd, before = originals[0]
    aqua.need(0 < before[6] <= limit, "retained-observer-installed-bound")
    record = {"parent": parent, "name": name, "fd": fd, "full9": before, "sha256": expected}
    fixtures.gate_files.append(record)
    body, actual = aqua._gate_file_read(record, capture=capture)
    aqua.need(expected is None or actual == expected, "retained-observer-installed-digest")
    record["sha256"] = actual
    return body, before[6]


def _admit_retained_runtime(aqua, fixtures, binding, work, environment, retained):
    helper_source, run, attempt, actual_work = retained_context(environment, binding.target)
    parser, proposed_body, selected = retained
    origin = selected["origin"]
    git_scope = environment.get("MRK_MACOS_NATIVE_SCOPE") == GIT_SCOPE
    aqua.need(selected["nativeScope"] == environment.get("MRK_MACOS_NATIVE_SCOPE")
              and (not git_scope or (binding.source, binding.run, binding.attempt) == RETAINED_GIT_TUPLE)
              and work == actual_work and environment.get("MRK_CANDIDATE_SOURCE") == binding.source
              and (binding.source, binding.run, binding.attempt, binding.target) ==
              tuple(origin[key] for key in ("source", "runId", "runAttempt", "target")),
              "retained-observer-original-tuple")
    checkout = aqua._gate_directory(fixtures, str(CHECKOUT))
    git = aqua._gate_directory(fixtures, ".git", checkout)
    head, _ = aqua._gate_file(fixtures, "HEAD", git, 41)
    aqua.need(head == (binding.source + "\n").encode("ascii"), "retained-observer-product-head")
    helper = aqua._gate_directory(fixtures, HELPER_ROOT.name, checkout)
    git = aqua._gate_directory(fixtures, ".git", helper)
    head, _ = aqua._gate_file(fixtures, "HEAD", git, 41)
    aqua.need(head == (helper_source + "\n").encode("ascii"), "retained-observer-helper-head")
    helper_desktop = aqua._gate_directory(fixtures, "desktop", helper)
    helper_inputs = aqua._gate_directory(fixtures, "macos-installed-inputs", helper_desktop)
    selection_path = RETAINED_GIT_SELECTION if git_scope else RETAINED_SELECTION
    body, _ = aqua._gate_file(fixtures, Path(selection_path).name, helper_inputs, 8192)
    aqua.need(body == proposed_body and parser.retained_observer_selection_data(parser.decode(body)) == selected,
              "retained-observer-selection-changed")
    helper_tools = aqua._gate_directory(fixtures, "tools", helper_desktop)
    for name in RETAINED_GIT_HELPER_FILES if git_scope else RETAINED_HELPER_FILES:
        aqua._gate_file(fixtures, name, helper_tools, 1024 * 1024, capture=False)
    helper_src = aqua._gate_directory(fixtures, "src", helper)
    helper_core = aqua._gate_directory(fixtures, "mobile_release", helper_src)
    for name in (*aqua.OWNER_FILES, "__init__.py", "errors.py", "_lifetime_evidence.py", "_store_lane_contract.py"):
        aqua._gate_file(fixtures, name, helper_core, 256 * 1024, capture=False)
    work_fd = aqua._gate_directory(fixtures, str(work), private=True)
    receipt_body, receipt_original = aqua._gate_file(fixtures, "retained-observer-install.json", work_fd, 16384)
    status, _ = aqua._gate_file(fixtures, "retained-observer-install.status", work_fd, 2)
    aqua.need(status == b"0\n", "retained-observer-original-consumer-return")
    receipt = parser.decode(receipt_body)
    aqua.need(type(receipt) is dict, "retained-observer-receipt")
    info = os.fstat(work_fd)
    # helperTree is the earlier consumer's actual Git observation, NOT another
    # runtime tree observation obtained by passing the same field to a parser.
    receipt = parser.retained_observer_install_receipt_data(receipt, selected, helper_source,
        receipt.get("helperTree"), run, attempt, (info.st_dev, info.st_ino, info.st_uid))
    # No old work, composition receipt or Store archive is recreated. This
    # owner loads the ORIGINAL product stager/release and holds installed I/M,
    # protected record, core and Python under its unchanged root-owned policy.
    fixtures.admit_normal_account_runtime(CHECKOUT, work, application_source=binding.source)
    aqua.need(len(fixtures.normal_stager_registrations) == 1, "retained-observer-stager-original")
    stage = fixtures.normal_stager_registrations[0]
    desktop = aqua._gate_directory(fixtures, "desktop", checkout)
    inputs = aqua._gate_directory(fixtures, "macos-installed-inputs", desktop)
    packaging = aqua._gate_directory(fixtures, "packaging", desktop)
    python_body, _ = aqua._gate_file(fixtures, "python-signed-runtime-binding.json", inputs, 4096)
    producer, _ = aqua._gate_file(fixtures, "macos-install-producer-signing.profile", packaging, 1024)
    service, _ = aqua._gate_file(fixtures, "macos-android-service-signing.profile", packaging, 512)
    python = stage.signed_runtime_binding_data(python_body, producer, service, target=binding.target)
    store_body, _ = aqua._gate_file(fixtures, "store-signed-component.json", inputs, 4096)
    stage.signed_store_selection_data(store_body, target=binding.target)
    releases = [row for row in fixtures.gate_files
                if row["name"] == str(CHECKOUT / "desktop/macos-installed-inputs/build-release.json")]
    aqua.need(len(releases) == 1, "retained-observer-product-release-original")
    release_body, actual = aqua._gate_file_read(releases[0], capture=True)
    aqua.need(actual == releases[0]["sha256"], "retained-observer-product-release-changed")
    release = stage.build_release_data(release_body, target=binding.target)
    signed = stage.maintenance_release_data(receipt["release"], binding.target)
    aqua.need(all(signed[key] == release[key] for key in ("packageVersion", "release"))
              and signed["sourceCommit"] == binding.source and signed["protocolSha256"] == stage.CURRENT_PROTOCOL,
              "retained-observer-product-release")
    manifest, _ = _retained_installed_original(aqua, fixtures, "manifest.json", stage.MANIFEST_BYTES,
        expected=signed["runtimeManifestSha256"], capture=True)
    _, rows = stage.manifest_files(manifest, signed["runtimeManifestSha256"], current=True, target=binding.target)
    if git_scope:
        aqua.need(set(rows) & stage.GIT_OBSERVATION_BOOTSTRAPS == stage.GIT_OBSERVATION_BOOTSTRAPS,
                  "retained-git-observation-roster")
        parent = next(item[0] for item in fixtures.recovery_runtime_originals if item[1] == "manifest.json")
        # Same four root-owned originals as current Git, including unused peers;
        # never borrow Tool's manifest or treat matching names as signed bytes.
        for entry in sorted(stage.GIT_OBSERVATION_BOOTSTRAPS):
            original, hashed, _ = fixtures._recovery_read(parent, entry, 0, 64 * 1024, 0o444, retain=True)
            entry_parent, entry_name, entry_fd, entry_before = fixtures.recovery_runtime_originals[-1]
            fixtures.normal_runtime_policy[entry_fd] = original[2]
            fixtures.gate_files.append({"parent": entry_parent, "name": entry_name, "fd": entry_fd,
                "full9": entry_before, "sha256": rows[entry]["sha256"]})
            aqua.need(original[6] == rows[entry]["size"] and hashed == rows[entry]["sha256"],
                      "retained-git-entry-correspondence")
    _, size = _retained_installed_original(aqua, fixtures, stage.INSTALLATION_INVENTORY_NAME, stage.INVENTORY_BYTES,
        expected=signed["inventorySha256"])
    aqua.need(size == receipt["inventory"]["bytes"], "retained-observer-installed-inventory-size")
    record_body, _ = _retained_installed_original(aqua, fixtures, stage.INSTALLATION_RECORD_NAME,
        stage.INSTALLATION_RECORD_LIMIT, capture=True)
    record = stage.decode(record_body)
    aqua.need(type(record) is dict and record.get("instance") == receipt["freshInstall"]["instance"]
              == receipt["freshInstall"]["invocation"], "retained-observer-fresh-installed-instance")
    _retained_installed_original(aqua, fixtures, "python3", stage.MAX_BYTES, expected=python["signedPythonSha256"])
    _current(aqua, fixtures)
    # Bounded public provenance, not the private receipt/work identity or any
    # recovered historical finality. Runtime/native observations still follow.
    return {"origin": dict(origin), "helperSource": helper_source,
        "helperTreeObservedByConsumer": receipt["helperTree"], "consumerRunId": run, "consumerRunAttempt": attempt,
        "freshInstallReceiptSha256": receipt_original["sha256"], "originalConsumerReturnedZero": True,
        "installedInstanceSha256": aqua.digest(record["instance"].encode("ascii")),
        "runtimeManifestSha256": signed["runtimeManifestSha256"], "inventorySha256": signed["inventorySha256"],
        "productReady": False, "uiQualified": False, "p0Qualified": False}


def retained_fixture_context(environment, target, uid, gid):
    """Read-only fixture namespace DATA after actual current admission/close.

    The caller supplies its single checked _native_user observation. No fixture
    prepare, process owner, native call or old job environment is created here.
    Every eventual runtime invocation independently retains its own originals.
    """
    _, _, _, work = retained_context(environment, target)
    need(environment.get("MRK_MACOS_NATIVE_SCOPE") == TOOLS_SCOPE, "retained-observer-tool-fixture")
    need(type(uid) is int and type(gid) is int and uid > 0 and gid >= 0
         and uid == os.getuid() == os.geteuid() and gid == os.getgid() == os.getegid(),
         "retained-observer-fixture-user")
    retained = _retained_selection(environment)
    origin = retained[2]["origin"]
    aqua = _load_observer(retained=True)
    binding = aqua.Binding(origin["source"], origin["runId"], origin["runAttempt"], target).checked()
    fixtures = aqua.Fixtures(binding, uid, gid, TOOLS_SCOPE)
    error = None
    try:
        _admit_retained_runtime(aqua, fixtures, binding, work, environment, retained)
    except BaseException as caught:
        error = caught
    try:
        fixtures.close()  # Existing consuming close; never retried on failure.
    except BaseException as caught:
        if error is None:
            error = caught
    if error is not None:
        raise error
    return binding.source, binding.run, binding.attempt, work


def _current(aqua, fixtures):
    aqua._gate_recheck(fixtures)
    fixtures.recovery_runtime_paths()


def _run(aqua, binding, uid, gid, username, work, environment, *, scope=SCOPE, host=None, retained=None, prepared=None, prepared_owner=None):
    """One fixed invocation; test doubles never supply production authority."""
    fixtures = owner = error = None
    count = 0
    cases = ()
    not_executed = ()
    provenance = {}
    try:
        observation_scope(environment, scope)
        cases = aqua.TOOLS.RUN_ORDER if scope == TOOLS_SCOPE else aqua.selected_cases(scope)
        fixtures = aqua.Fixtures(binding, uid, gid, scope)
        fixtures.prepare()
        if prepared is not None:
            aqua.need(retained is None, "prepared-native-single-mode")
            provenance = {"runtimeMode": "prepared-package", "preparedPackage":
                _admit_prepared_runtime(aqua, fixtures, binding, work, environment, prepared)}
        elif retained is None:
            _admit_runtime(aqua, fixtures, binding, work, environment)
        else:
            aqua.need(scope in RETAINED_SCOPES, "retained-observer-scope")
            provenance = {"runtimeMode": "retained-observer", "retainedObserver":
                _admit_retained_runtime(aqua, fixtures, binding, work, environment, retained)}
        aqua.need((prepared is None) == (prepared_owner is None), "prepared-native-owner-pair")
        owner = prepared_owner if prepared is not None else aqua.load_owner(HELPER_ROOT if retained is not None else CHECKOUT)
        _current(aqua, fixtures)

        def emit_checked(value):
            nonlocal count
            aqua.need(count < len(cases) and value.get("case") == cases[count], "identity-native-case-order")
            _current(aqua, fixtures)  # Only after run_cases' original return/readback.
            aqua.emit_record({**value, **provenance} if provenance else value, sys.stdout)
            count += 1

        not_executed = aqua.run_cases(binding, fixtures, owner.run_owned, uid, username, emit_checked, scope=scope)
        aqua.need(type(not_executed) is tuple and all(case in cases for case in not_executed)
                  and len(set(not_executed)) == len(not_executed) and count == len(cases)
                  and len(cases) == (2 if scope in (COLD_SCOPE, PUBLIC_TOOLS_SCOPE) else 1 if scope in (*GIT_CLI_SCOPES, *UPLOAD_SCOPES, BACKUP_SCOPE, BACKUP_CLI_SCOPE) else {SCOPE: 4, FETCH_SCOPE: 4, PUSH_SCOPE: 3, PUSH_CREATE_SCOPE: 5, UPSTREAM_SCOPE: 1, SERVICE_SCOPE: 1, TOOLS_SCOPE: 3, CLI_SCOPE: 1}[scope]),
                  "identity-native-incomplete")
        aqua.need(not not_executed or scope in (SERVICE_SCOPE, TOOLS_SCOPE, PUBLIC_TOOLS_SCOPE, *UPLOAD_SCOPES, BACKUP_SCOPE), "identity-native-incomplete")
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
        kind = "macos-git-cli-current-complete" if scope in GIT_CLI_SCOPES else "macos-tool-public-acquisition-current-complete" if scope == PUBLIC_TOOLS_SCOPE else "macos-upload-key-backup-cli-current-complete" if scope == BACKUP_CLI_SCOPE else "macos-installed-cli-current-complete" if scope == CLI_SCOPE else "macos-git-upstream-current-complete" if scope == UPSTREAM_SCOPE else "macos-git-push-create-current-complete" if scope == PUSH_CREATE_SCOPE else "macos-git-push-current-complete" if scope == PUSH_SCOPE else "macos-git-fetch-current-complete" if scope == FETCH_SCOPE else "macos-upload-key-backup-current-complete" if scope == BACKUP_SCOPE else "macos-upload-key-cold-restart-complete" if scope == COLD_SCOPE else "macos-upload-key-current-complete" if scope in UPLOAD_SCOPES else (
            "macos-identity-current-complete" if scope == SCOPE else (
                "macos-tool-service-current-complete" if scope == SERVICE_SCOPE else "macos-tool-setup-current-complete"))
        if not_executed:
            # Only a parsed report after actual original return/readback/close
            # can be unexecuted. No runtime error or unknown becomes exit78.
            # Do not manufacture Ready or automatically run another case.
            upload = scope in (*UPLOAD_SCOPES, BACKUP_SCOPE, BACKUP_CLI_SCOPE)
            aqua.emit_record({"schemaVersion": 1, "type": "macos-retained-observer-unexecuted" if retained is not None else "macos-upload-key-current-unexecuted" if upload else "macos-tool-current-unexecuted",
                **provenance,
                **binding.public(), "target": binding.target, "scope": scope,
                "notExecuted": list(not_executed), "allOriginalCallsReturned": True,
                "fixtureHandlesClosed": True, "manualStep": (
                    "Resolve the reported vault or protected JDK catalogue prerequisite before a new explicit invocation; no automatic retry was performed."
                    if upload else "The independent cancellation case returned; cold acquisition needs the reported genuinely absent host sources. No discovery override or retry was performed." if scope == PUBLIC_TOOLS_SCOPE else "Resolve the reported service prerequisite before starting the tool cases; no automatic retry was performed."),
                "shippingBinaryQualified": False, "distributionQualified": False}, sys.stdout)
            return 78
        aqua.emit_record({"schemaVersion": 1, "type": "macos-retained-observer-complete" if retained is not None else kind,
            **provenance, **({"scope": scope} if retained is not None else {}),
            **binding.public(), "target": binding.target, "cases": list(cases),
            # Only main passes its SAME checked native observation. Old direct
            # DATA fixtures omit it rather than manufacturing a host claim.
            **({"host": {"runner": host[0], "osVersion": host[1]}} if host is not None else {}),
            "allOriginalCallsReturned": True, "independentReadbacks": True, "fixtureHandlesClosed": True,
            "currentInstalledRuntime": retained is None, "instrumentedEngineeringApp": True,
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
        scope, retained_mode = entry_arguments(sys.argv[1:])
        environment = dict(os.environ)
        observation_scope(environment, scope)
        source, run, attempt, work = (retained_context if retained_mode else current_context)(environment, TARGET)
        uid, gid, username, host = _native_user(environment, retained=True) if retained_mode else _native_user(environment)
        retained = _retained_selection(environment) if retained_mode else None
        prepared, prepared_owner = (prepared_binding(environment)
            if environment.get("MRK_MACOS_PREPARED_TEST") == "true" else (None, None))
        need(prepared is None or not retained_mode, "prepared-native-single-mode")
        if prepared is not None:
            origin = prepared.origin
            source, run, attempt = origin["source"], origin["runId"], origin["runAttempt"]
        aqua = _load_observer(retained=True) if retained_mode else _load_observer()
        if retained is not None:
            origin = retained[2]["origin"]
            source, run, attempt = origin["source"], origin["runId"], origin["runAttempt"]
        binding = aqua.Binding(source, run, attempt, TARGET).checked()
        os.umask(0o077)
        return _run(aqua, binding, uid, gid, username, work, environment, scope=scope, host=host, prepared=prepared, prepared_owner=prepared_owner,
                    **({"retained": retained} if retained is not None else {}))
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
