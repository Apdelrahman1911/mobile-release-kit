from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from .config import ConfigurationError, ReleaseConfig, ReleaseVersion
from .credentials import (
    credential_values_for_purpose,
    credential_values_from_environment,
)
from .discovery import GitContext
from .errors import MutationGuardError, StoreOperationError, ValidationError
from .reporting import Finding, Status
from .provenance import (
    _reject_duplicate_pairs,
    load_store_receipt,
    load_operation_intent,
    validate_operation_intent,
    validate_store_precondition,
    validate_store_receipt,
    validate_create_retry_inventory,
    canonical_sha256,
    workflow_authority,
)
from .tooling import _complete_tooling_root, resolve_tooling_root

LANES = {
    ("candidate", "android"): "android_internal_upload",
    ("candidate", "ios"): "ios_testflight_internal",
    ("external-testing", "android"): "android_external_promote",
    ("external-testing", "ios"): "ios_testflight_external",
    ("production-submit", "android"): "android_production_draft",
    ("production-submit", "ios"): "ios_app_store_submit",
}
ENVIRONMENTS = {
    "candidate": "mobile-candidate",
    "external-testing": "mobile-external-testing",
    "production-submit": "mobile-production",
}
STORE_OPERATION_ENVIRONMENT_NAMES = {
    "MOBILE_RELEASE_ANDROID_AAB_PATH",
    "MOBILE_RELEASE_ANDROID_MAPPING_PATH",
    "MOBILE_RELEASE_IOS_IPA_PATH",
    "MOBILE_RELEASE_IOS_ARCHIVE_PATH",
    "MOBILE_RELEASE_IOS_DSYMS_PATH",
}
RUNTIME_ENVIRONMENT_NAMES = {
    "BUNDLE_APP_CONFIG",
    "BUNDLE_DEPLOYMENT",
    "BUNDLE_PATH",
    "BUNDLE_WITHOUT",
    "CI",
    "GEM_HOME",
    "GEM_PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TMPDIR",
    "TZ",
}


def _runtime_environment(source: Mapping[str, str]) -> dict[str, str]:
    return {name: source[name] for name in RUNTIME_ENVIRONMENT_NAMES if source.get(name)}


def _repository_path(config: ReleaseConfig, value: str | Path, label: str) -> Path:
    """Return a repository-contained path without following any committed symlink."""

    try:
        return config.project_path(os.fspath(value))
    except ConfigurationError as error:
        raise StoreOperationError(
            f"{label} must remain inside the repository without symbolic links"
        ) from error


def _private_app_directory(config: ReleaseConfig, relative: str) -> Path:
    directory = _repository_path(config, relative, "tool-owned Store directory")
    if directory.exists() and not directory.is_dir():
        raise StoreOperationError("tool-owned Store path must be a directory")
    directory.mkdir(parents=True, exist_ok=True)
    # Recheck after creation so a pre-existing symlinked parent can never be hidden by mkdir.
    return _repository_path(config, relative, "tool-owned Store directory")


def _play_state_journal_path(receipt_path: Path) -> Path:
    """Derive the one journal path shared by Python, Fastlane, and workflows."""

    return receipt_path.with_name(f"{receipt_path.stem}-play-state.json")


@dataclass(frozen=True)
class StoreRequest:
    stage: str
    platform: str
    confirmation: str
    execute: bool
    output_dir: Path
    store_receipt: Path | None = None
    store_precondition: Path | None = None
    prepare: bool = False
    operation_intent: Path | None = None
    recovery_run_id: str | None = None
    recovery_confirmation: str | None = None


def expected_confirmation(stage: str, platform: str, release: ReleaseVersion) -> str:
    return f"{stage}:{platform}:{release.name}:{release.build}"


def guard_ci_mutation(
    *,
    request: StoreRequest,
    config: ReleaseConfig,
    release: ReleaseVersion,
    git: GitContext,
    environ: Mapping[str, str] | None = None,
) -> None:
    env = environ if environ is not None else os.environ
    if request.stage not in ENVIRONMENTS or (request.stage, request.platform) not in LANES:
        raise MutationGuardError("unsupported CI Store operation")
    expected = expected_confirmation(request.stage, request.platform, release)
    if request.confirmation != expected:
        raise MutationGuardError(f"confirmation must exactly equal {expected!r}")
    if env.get("GITHUB_ACTIONS") != "true":
        raise MutationGuardError("Store operations are restricted to GitHub Actions")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise MutationGuardError("Store operations require an explicit workflow_dispatch event")
    if env.get("MOBILE_RELEASE_CI_MUTATIONS_ALLOWED") != "true":
        raise MutationGuardError("MOBILE_RELEASE_CI_MUTATIONS_ALLOWED must be explicitly true")
    expected_environment = ENVIRONMENTS[request.stage]
    if env.get("MOBILE_RELEASE_ENVIRONMENT") != expected_environment:
        raise MutationGuardError(f"Store operation requires the {expected_environment} environment")
    if not git.repository or not git.repository_id or not git.commit or not git.tree or not git.ref:
        raise MutationGuardError("immutable GitHub repository/source identity is incomplete")
    if request.recovery_run_id:
        if not re.fullmatch(r"[1-9][0-9]*", request.recovery_run_id):
            raise MutationGuardError("recovery_run_id must be a positive workflow run ID")
        dispatch_sha = env.get("MOBILE_RELEASE_DISPATCH_SHA") or env.get("GITHUB_SHA")
        if not dispatch_sha or not re.fullmatch(r"[0-9A-Fa-f]{40}", dispatch_sha):
            raise MutationGuardError("recovery requires the immutable dispatch head SHA")
    elif env.get("GITHUB_SHA") != git.commit:
        raise MutationGuardError("GITHUB_SHA does not exactly match the checked-out Git commit")
    if git.dirty is not False:
        raise MutationGuardError("Store operation requires a provably clean worktree")
    expected_branch = config.section("source").get(
        "productionBranch" if request.stage == "production-submit" else "candidateBranch", "main"
    )
    if git.ref != f"refs/heads/{expected_branch}":
        raise MutationGuardError(
            f"actual dispatch ref {git.ref!r} is not the configured {expected_branch!r} branch"
        )
    platform_config = config.section(request.platform)
    if platform_config.get("identityStatus") != "approved":
        raise MutationGuardError("Store identity must be explicitly approved in reviewed configuration")


def _store_environment(
    config: ReleaseConfig,
    release: ReleaseVersion,
    request: StoreRequest,
    receipt_path: Path,
    tooling_root: Path,
) -> dict[str, str]:
    source_environment = os.environ.copy()
    env = _runtime_environment(source_environment)
    credentials = credential_values_for_purpose(
        config,
        credential_values_from_environment(source_environment),
        stage="production" if request.stage == "production-submit" else request.stage,
        purpose="store",
        platforms=(request.platform,),
    )
    env.update(credentials)
    for name in STORE_OPERATION_ENVIRONMENT_NAMES:
        if not (raw_path := source_environment.get(name)):
            continue
        artifact = _repository_path(config, raw_path, name)
        if not artifact.is_file():
            raise StoreOperationError(f"{name} must identify a regular release artifact")
        env[name] = str(artifact)
    platform_config = config.section(request.platform)
    identity_key = "applicationId" if request.platform == "android" else "bundleId"
    env.update(
        {
            "MOBILE_RELEASE_OPERATION": LANES[(request.stage, request.platform)],
            "MOBILE_RELEASE_PLATFORM": request.platform,
            "MOBILE_RELEASE_APP_IDENTITY": platform_config[identity_key],
            "MOBILE_RELEASE_MARKETING_VERSION": release.name,
            "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
            "MOBILE_RELEASE_STORE_RECEIPT_PATH": str(receipt_path),
            "MOBILE_RELEASE_CONFIG_PATH": str(config.path),
            "MOBILE_RELEASE_APP_ROOT": str(config.root),
            "BUNDLE_GEMFILE": str(tooling_root / "Gemfile"),
            "MOBILE_RELEASE_STORE_MODE": "prepare" if request.prepare else "execute",
            # Selected by the pinned installed CLI, never a caller-controlled
            # environment command. Fastlane invokes only the toolkit's isolated
            # current-upload validator through this interpreter.
            "MOBILE_RELEASE_VALIDATION_PYTHON": str(Path(sys.executable).absolute()),
            "MOBILE_RELEASE_VALIDATION_MODULE_ROOT": str(Path(__file__).resolve().parent.parent),
        }
    )
    if request.operation_intent:
        intent_path = _repository_path(config, request.operation_intent, "operation intent path")
        if not request.prepare and not intent_path.is_file():
            raise StoreOperationError("operation intent must be a regular repository file")
        env["MOBILE_RELEASE_OPERATION_INTENT_PATH"] = str(intent_path)
    if request.recovery_run_id:
        env["MOBILE_RELEASE_RECOVERY_RUN_ID"] = request.recovery_run_id
    if request.recovery_confirmation:
        env["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = request.recovery_confirmation
    authority = workflow_authority(request.stage)
    env["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = json.dumps(
        authority, sort_keys=True, separators=(",", ":")
    )
    if request.platform == "android":
        if request.stage == "candidate":
            # Public validation inputs only. Missing/stale tools must block a
            # NEW upload in the isolated helper, not historical reconciliation.
            for name in ("MOBILE_RELEASE_BUNDLETOOL_JAR", "JAVA_HOME"):
                if source_environment.get(name):
                    env[name] = source_environment[name]
        track = {
            "candidate": "internal",
            "external-testing": platform_config.get("externalTrack", {}).get("name", ""),
            "production-submit": "production",
        }[request.stage]
        env["MOBILE_RELEASE_DESTINATION_TRACK"] = track
        journal_path = _play_state_journal_path(receipt_path)
        journal_path = _repository_path(config, journal_path, "Play state journal path")
        env["MOBILE_RELEASE_PLAY_STATE_PATH"] = str(journal_path)
    else:
        journal_path = receipt_path.with_name(f"{receipt_path.stem}-apple-state.json")
        journal_path = _repository_path(config, journal_path, "Apple state journal path")
        env["MOBILE_RELEASE_APPLE_STATE_PATH"] = str(journal_path)
        env["MOBILE_RELEASE_ASC_APP_ID"] = str(platform_config.get("appStoreAppId", ""))
        env["MOBILE_RELEASE_TESTFLIGHT_EXTERNAL_GROUP"] = str(
            platform_config.get("externalTestFlightGroup", "")
        )
        review = platform_config.get("review", {})
        env["MOBILE_RELEASE_APPLE_USES_NON_EXEMPT_ENCRYPTION"] = str(
            review.get("usesNonExemptEncryption", False)
        ).lower()
        env["MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_REQUIRED"] = str(
            review.get("demoAccountRequired", False)
        ).lower()
    return env


def _require_fastlane_bundle(tooling_root: Path) -> None:
    gemfile = tooling_root / "Gemfile"
    environment = _runtime_environment(os.environ)
    environment.update(
        {
            "BUNDLE_GEMFILE": str(gemfile),
            "FASTLANE_HIDE_CHANGELOG": "true",
            "FASTLANE_OPT_OUT_USAGE": "true",
            "FASTLANE_SKIP_DOCS": "true",
            "FASTLANE_SKIP_UPDATE_CHECK": "true",
        }
    )
    if shutil.which("ruby") is None:
        raise StoreOperationError(
            "Pinned Store tooling requires Ruby 3.3.x. Install Ruby 3.3 and Bundler; "
            "dependencies are never installed automatically."
        )

    def run(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                argv,
                cwd=tooling_root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    ruby = run(["ruby", "-e", "print RUBY_VERSION"])
    if ruby is None or ruby.returncode or not re.fullmatch(r"3\.3\.\d+", ruby.stdout.strip()):
        raise StoreOperationError(
            "Pinned Store tooling requires Ruby 3.3.x. Select Ruby 3.3 before running "
            "online preflight or a Store lane."
        )
    bundler = run(["bundle", "--version"])
    if bundler is None or bundler.returncode:
        raise StoreOperationError(
            "Bundler is unavailable for the pinned Store tooling. Install Bundler under Ruby 3.3; "
            "dependencies are never installed automatically."
        )
    completed = run(["bundle", "check"])
    if completed is None or completed.returncode:
        command = (
            f"BUNDLE_GEMFILE={shlex.quote(str(gemfile))} "
            "bundle install --jobs 4 --retry 3"
        )
        raise StoreOperationError(
            "Pinned Fastlane dependencies from Gemfile.lock are unavailable. "
            f"Run `{command}` with Ruby 3.3, then rerun preflight; dependencies are never "
            "installed automatically."
        )


def _run_store_lane(
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    request: StoreRequest,
) -> Path:
    lane = LANES[(request.stage, request.platform)]
    receipt_path = (
        request.store_precondition or request.output_dir / "store-precondition.json"
        if request.prepare
        else request.store_receipt
        or Path(
            os.environ.get(
                "MOBILE_RELEASE_STORE_RECEIPT_PATH", request.output_dir / "raw-store-receipt.json"
            )
        )
    )
    receipt_path = _repository_path(config, receipt_path, "Store receipt path")
    tooling_root = resolve_tooling_root()
    if tooling_root is None:
        raise StoreOperationError(
            "shared Fastlane assets are unavailable; install the complete pinned distribution "
            "or set MOBILE_RELEASE_TOOLING_ROOT"
        )
    runner = tooling_root / "fastlane/run_lane.rb"
    if not _complete_tooling_root(tooling_root):
        raise StoreOperationError("pinned shared Fastlane/Gem bundle is incomplete")
    _require_fastlane_bundle(tooling_root)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    if receipt_path.exists() or receipt_path.is_symlink():
        raise StoreOperationError(
            "Store output path already exists; authoritative state is never overwritten"
        )
    command = ["bundle", "exec", "ruby", str(runner), lane]
    try:
        with tempfile.TemporaryDirectory(prefix="mobile-release-store-run-") as temporary:
            runner_directory = Path(temporary)
            runner_directory.chmod(0o700)
            completed = subprocess.run(
                command,
                cwd=runner_directory,
                env=_store_environment(config, release, request, receipt_path, tooling_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60 * 60,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise StoreOperationError(f"Store lane failed or timed out: {lane}") from error
    if completed.returncode:
        raise StoreOperationError(f"Store lane failed with exit {completed.returncode}: {lane}")
    return receipt_path


def prepare_store_operation(
    *, config: ReleaseConfig, release: ReleaseVersion, request: StoreRequest
) -> dict[str, object]:
    if not request.prepare or request.execute:
        raise StoreOperationError("Store preparation requires prepare-only mode")
    initial_path = _repository_path(config, request.store_precondition or request.output_dir / "store-precondition.json", "Store precondition path")
    if initial_path.exists():
        # A raw precondition has no source/authority binding until sealed into
        # an intent. Preserve this diagnostic but capture fresh read-only state
        # instead of signing stale state under potentially changed inputs.
        validate_store_precondition(load_store_receipt(initial_path), stage=request.stage, platform=request.platform)
        request = replace(request, store_precondition=initial_path.with_name(f"store-precondition-{secrets.token_hex(16)}.json"))
    receipt_path = _run_store_lane(config=config, release=release, request=request)
    if not receipt_path.is_file():
        raise StoreOperationError(
            "Store preparation did not produce authoritative readback at "
            "MOBILE_RELEASE_STORE_RECEIPT_PATH"
        )
    raw = load_store_receipt(receipt_path)
    return validate_store_precondition(raw, stage=request.stage, platform=request.platform)


def execute_store_operation(
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    request: StoreRequest,
    operation_intent: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if not request.execute or request.prepare:
        raise StoreOperationError("Store execution requires execute-only mode")
    if operation_intent is None:
        raise StoreOperationError("Store execution requires an authenticated operation intent")
    validate_operation_intent(operation_intent)
    if request.operation_intent is None:
        raise StoreOperationError("Store execution requires the original operation-intent file")
    intent_path = _repository_path(config, request.operation_intent, "operation intent path")
    if load_operation_intent(intent_path) != operation_intent:
        raise StoreOperationError("operation-intent file differs from the validated authorization")
    receipt_path = request.store_receipt or Path(
        os.environ.get(
            "MOBILE_RELEASE_STORE_RECEIPT_PATH", request.output_dir / "raw-store-receipt.json"
        )
    )
    receipt_path = _repository_path(config, receipt_path, "Store receipt path")
    if not receipt_path.exists():
        try:
            _run_store_lane(config=config, release=release, request=request)
        except StoreOperationError as error:
            # Never echo Fastlane stderr: it may contain private API bodies.
            # A strictly validated public inventory is safe/actionable instead.
            if request.platform == "ios":
                journal = receipt_path.with_name(f"{receipt_path.stem}-apple-state.json")
                if journal.is_file() and not journal.is_symlink():
                    try:
                        diagnostic = load_store_receipt(journal)
                        history = diagnostic.get("history", [])
                        if isinstance(history, list):
                            for event in reversed(history[-256:]):
                                if isinstance(event, dict) and "createRetryInventory" in event:
                                    inventory = validate_create_retry_inventory(event["createRetryInventory"], operation_intent=operation_intent)
                                    confirmation = f"retry-ios-operation-creates:{operation_intent['integrity']['sha256']}:{canonical_sha256(inventory)}"
                                    raise StoreOperationError(
                                        "Apple create outcome is ambiguous. Retain the original intent/artifacts; "
                                        "independently resolve whether prior requests were accepted, then use a NEW "
                                        "protected first-attempt recovery dispatch with --recovery-run-id "
                                        f"{operation_intent['authorizedBy']['runId']} --recovery-confirmation {confirmation}. "
                                        "Repeated absence alone is not proof of rejection."
                                    ) from error
                    except ValidationError:
                        pass
            raise
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise StoreOperationError(
            "Store operation did not produce authoritative readback at "
            "MOBILE_RELEASE_STORE_RECEIPT_PATH"
        )
    raw = load_store_receipt(receipt_path)
    return validate_store_receipt(
        raw,
        config=config,
        release=release,
        stage=request.stage,
        platform=request.platform,
        operation_intent=operation_intent,
        recovery_run_id=request.recovery_run_id,
    )


def online_preflight_findings(
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    platforms: tuple[str, ...],
) -> list[Finding]:
    tooling_root = resolve_tooling_root()
    if tooling_root is None:
        return [
            Finding(
                "store.online.tooling",
                Status.FAIL,
                "Shared Fastlane assets are unavailable; install the complete pinned distribution "
                "or set MOBILE_RELEASE_TOOLING_ROOT.",
                category="store-access",
            )
        ]
    runner = tooling_root / "fastlane/run_lane.rb"
    gemfile = tooling_root / "Gemfile"
    if not _complete_tooling_root(tooling_root):
        return [
            Finding(
                "store.online.fastfile",
                Status.FAIL,
                "Pinned shared Fastlane/Gem bundle is incomplete.",
                category="store-access",
            )
        ]
    try:
        _require_fastlane_bundle(tooling_root)
    except StoreOperationError as error:
        return [
            Finding(
                "store.online.bundle",
                Status.FAIL,
                str(error),
                category="store-access",
            )
        ]
    findings: list[Finding] = []
    private_root = _private_app_directory(config, ".mobile-release/store")
    explicit_readback = os.environ.get("MOBILE_RELEASE_PREFLIGHT_READBACK_PATH")
    temporary_context = (
        tempfile.TemporaryDirectory(prefix="online-preflight-", dir=private_root)
        if not explicit_readback
        else None
    )
    temporary = temporary_context.__enter__() if temporary_context else None
    try:
        for platform in platforms:
            report_path = _repository_path(
                config,
                explicit_readback or Path(temporary or "") / f"{platform}.json",
                "Store preflight readback path",
            )
            if report_path.exists() and not report_path.is_file():
                raise StoreOperationError("Store preflight readback path must be a regular file")
            report_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                report_path.unlink(missing_ok=True)
            except OSError as error:
                raise StoreOperationError("could not clear stale Store preflight readback") from error
            source_environment = os.environ.copy()
            env = _runtime_environment(source_environment)
            env.update(
                credential_values_for_purpose(
                    config,
                    credential_values_from_environment(source_environment),
                    stage="candidate",
                    purpose="store",
                    platforms=(platform,),
                )
            )
            env.update(
                {
                    "MOBILE_RELEASE_APP_ROOT": str(config.root),
                    "MOBILE_RELEASE_CONFIG_PATH": str(config.path),
                    "MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(report_path),
                    "BUNDLE_GEMFILE": str(gemfile),
                }
            )
            lane = f"{platform}_online_preflight"
            try:
                with tempfile.TemporaryDirectory(
                    prefix="mobile-release-online-run-"
                ) as runner_temporary:
                    runner_directory = Path(runner_temporary)
                    runner_directory.chmod(0o700)
                    completed = subprocess.run(
                        ["bundle", "exec", "ruby", str(runner), lane],
                        cwd=runner_directory,
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15 * 60,
                        check=False,
                    )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                completed = None
            if completed is None or completed.returncode:
                findings.append(
                    Finding(
                        f"store.online.{platform}",
                        Status.FAIL,
                        f"Non-publishing {platform} Store preflight failed.",
                        category="store-access",
                    )
                )
                continue
            if report_path.is_symlink() or not report_path.is_file():
                findings.append(
                    Finding(
                        f"store.online.{platform}",
                        Status.FAIL,
                        f"Non-publishing {platform} Store preflight produced no safe readback.",
                        category="store-access",
                    )
                )
                continue
            try:
                raw = json.loads(
                    report_path.read_text(encoding="utf-8"),
                    object_pairs_hook=_reject_duplicate_pairs,
                )
                _validate_online_readback(raw, config=config, release=release, platform=platform)
            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                StoreOperationError,
                ValidationError,
            ) as error:
                findings.append(
                    Finding(
                        f"store.online.{platform}",
                        Status.FAIL,
                        str(error),
                        category="store-access",
                    )
                )
                continue
            findings.append(
                Finding(
                    f"store.online.{platform}",
                    Status.PASS,
                    f"Non-publishing {platform} Store access, identity, destinations, and build uniqueness are valid.",
                    category="store-access",
                )
            )
    finally:
        if temporary_context is not None:
            temporary_context.__exit__(None, None, None)
    return findings


def _validate_online_readback(
    raw: object, *, config: ReleaseConfig, release: ReleaseVersion, platform: str
) -> None:
    if not isinstance(raw, dict):
        raise StoreOperationError("Store preflight readback must be a JSON object")
    required = {
        "schemaVersion",
        "platform",
        "appIdentity",
        "buildNumber",
        "buildUnused",
        "observedAt",
    }
    platform_config = config.section(platform)
    if platform == "android":
        required.add("requiredTracks")
        if platform_config.get("externalTrack", {}).get("kind") == "closed":
            required.add("closedTesterAssignmentVerified")
    else:
        required.update({"appStoreAppId", "externalGroup"})
    missing = sorted(required - set(raw))
    if missing:
        raise StoreOperationError(f"Store preflight readback is missing: {', '.join(missing)}")
    unknown = sorted(set(raw) - required)
    if unknown:
        raise StoreOperationError(
            f"Store preflight readback has unexpected fields: {', '.join(unknown)}"
        )
    identity_key = "applicationId" if platform == "android" else "bundleId"
    if (
        type(raw["schemaVersion"]) is not int
        or raw["schemaVersion"] != 1
        or raw["platform"] != platform
        or raw["appIdentity"] != config.section(platform).get(identity_key)
        or raw["buildNumber"] != release.build
        or raw["buildUnused"] is not True
    ):
        raise StoreOperationError("Store preflight identity/build uniqueness readback is inconsistent")
    if not isinstance(raw["observedAt"], str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", raw["observedAt"]
    ):
        raise StoreOperationError("Store preflight observedAt is not second-precision UTC RFC3339")
    if platform == "android":
        expected_tracks = ["internal", platform_config["externalTrack"]["name"]]
        if raw.get("requiredTracks") != expected_tracks:
            raise StoreOperationError("Play preflight tracks do not match configured lifecycle tracks")
        closed = platform_config["externalTrack"].get("kind") == "closed"
        if closed and raw.get("closedTesterAssignmentVerified") is not True:
            raise StoreOperationError(
                "Closed Play track lacks an API-verified nonempty tester-group assignment"
            )
    else:
        ios = platform_config
        if str(raw.get("appStoreAppId")) != str(ios.get("appStoreAppId")):
            raise StoreOperationError("App Store Connect app ID does not match configuration")
        if raw.get("externalGroup") != ios.get("externalTestFlightGroup"):
            raise StoreOperationError("TestFlight external group does not match configuration")
