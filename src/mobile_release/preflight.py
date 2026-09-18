from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import json
import tempfile
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from .android import validate_aab, run_android_build
from .config import ConfigurationError, ReleaseConfig
from .credentials import (
    ALLOWED_CREDENTIAL_NAMES,
    artifact_validation_environment,
    credential_findings,
    credential_values_for_purpose,
    is_credential_capability_name,
    materialize_build_inputs,
    materialized_profile_specifier,
    resolve_credential_values,
    scrub_credential_capabilities,
    store_material_prerequisite_findings,
    _selected_store_material,
    validate_signing_material,
)
from .build_inputs import BuildInputError, InvocationCustody, invocation_custody
from .cancellation import DefaultCancellation
from .discovery import (
    discover_project,
    git_context,
    selected_android_details,
    selected_android_module,
    selected_ios_container,
    selected_ios_scheme,
)
from .errors import CredentialError, MobileReleaseError, ValidationError
from .ios import run_ios_build, validate_ipa, validate_xcarchive
from .ios_artifacts import inspect_ios_artifact_set, snapshot_ios_artifacts
from .metadata import metadata_findings
from .local_signing import SigningLease, local_signing_lease
from .owned_process import OUTPUT_LIMIT, ProcessError, run_owned
from .reporting import FAILING_STATUSES, Finding, Report, Status
from .stores import online_preflight_findings
from .toolchain_policy import XCODE_BUILD, XCODE_VERSION

ANDROID_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
IOS_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$")
FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
APP_STORE_ID_RE = re.compile(r"^[0-9]+$")


def _normalized_fingerprint(value: str | None) -> str | None:
    return value.replace(":", "") if value else None


def _xcode_toolchain_finding(*, execution_source=None, cancellation: DefaultCancellation | None = None) -> Finding:
    if sys.platform != "darwin" or not shutil.which("xcodebuild"):
        return Finding(
            "ios.xcode-toolchain",
            Status.SKIP,
            "The pinned Xcode baseline can only be checked on a macOS host with xcodebuild.",
            category="toolchain",
            remediation=f"Run iOS preflight with Xcode {XCODE_VERSION} ({XCODE_BUILD}).",
        )
    try:
        result = run_owned(
            ["xcodebuild", "-version"],
            environ=scrub_credential_capabilities(os.environ),
            capture=True,
            output_limit=OUTPUT_LIMIT,
            timeout=30,
            cancellation=cancellation,
            execution_scope=None if execution_source is None else execution_source.new_scope(),
        )
    except ProcessError as error:
        if error.fatal:
            raise
        result = None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        result = None
    expected = f"Xcode {XCODE_VERSION}\nBuild version {XCODE_BUILD}"
    observed = (result.stdout.strip() if result and result.returncode == 0 else "")
    if observed == expected:
        return Finding(
            "ios.xcode-toolchain",
            Status.PASS,
            f"Xcode {XCODE_VERSION} ({XCODE_BUILD}) matches the shared release baseline.",
            category="toolchain",
        )
    return Finding(
        "ios.xcode-toolchain",
        Status.FAIL,
        "The selected Xcode installation does not match the shared release baseline.",
        category="toolchain",
        remediation=f"Select Xcode {XCODE_VERSION} build {XCODE_BUILD} before iOS preflight.",
    )


def _identity_query_environment(config: ReleaseConfig, *, project_read_token: str | None) -> dict[str, str]:
    environment = scrub_credential_capabilities(os.environ)
    # This generated signing-routing hint is not a generic credential, but
    # identity queries must not borrow it from an unrelated signing context.
    environment.pop("MOBILE_RELEASE_IOS_PROFILE_SPECIFIER", None)
    if config.section("source").get("projectReadTokenRequired") and project_read_token:
        environment["MOBILE_RELEASE_PROJECT_READ_TOKEN"] = project_read_token
    return environment


def _effective_android_identity_finding(config: ReleaseConfig, *, project_read_token: str | None = None,
                                       execution_source=None,
                                       cancellation: DefaultCancellation | None = None) -> Finding:
    discovered = discover_project(config.root, include_git=False, cancellation=cancellation,
                                  execution_source=execution_source)
    module = selected_android_module(config, discovered)
    wrapper = config.root / "gradlew"
    if not module or wrapper.is_symlink() or not wrapper.is_file():
        return Finding(
            "android.debug-identity.effective",
            Status.BLOCKED,
            "Effective Android Debug identity cannot be queried without one selected module and wrapper.",
            category="identity",
        )
    script = """
def mobileReleaseTargetPath = '__MODULE__'
def mobileReleaseModernApi = false

gradle.beforeProject { project ->
    if (project.path == mobileReleaseTargetPath) {
        project.pluginManager.withPlugin('com.android.application') {
            def components = project.extensions.findByName('androidComponents')
            if (components != null) {
                mobileReleaseModernApi = true
                components.onVariants(components.selector().all()) { variant ->
                    if (variant.name.toString().toLowerCase().endsWith('debug')) {
                        println("MOBILE_RELEASE_EFFECTIVE_ANDROID_ID|${variant.name}|${variant.applicationId.get()}")
                    }
                }
            }
        }
    }
}

gradle.projectsEvaluated {
    if (!mobileReleaseModernApi) {
        def target = gradle.rootProject.findProject(mobileReleaseTargetPath)
        def android = target?.extensions?.findByName('android')
        def variants = android?.hasProperty('applicationVariants') ? android.applicationVariants : null
        variants?.all { variant ->
            if (variant.buildType?.name == 'debug') {
                println("MOBILE_RELEASE_EFFECTIVE_ANDROID_ID|${variant.name}|${variant.applicationId}")
            }
        }
    }
}
""".replace("__MODULE__", module)
    release = config.release_version()
    environment = _identity_query_environment(config, project_read_token=project_read_token)
    environment.update(
        {
            "MOBILE_RELEASE_VERSION_NAME": release.name,
            "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
        }
    )
    try:
        with tempfile.TemporaryDirectory(prefix="mobile-release-gradle-query-") as temporary:
            init_script = Path(temporary) / "identity.init.gradle"
            init_script.write_text(script, encoding="utf-8")
            task = f"{module}:tasks" if module != ":" else ":tasks"
            result = run_owned(
                [
                    str(wrapper),
                    "--no-daemon",
                    "--no-configuration-cache",
                    "--quiet",
                    "--init-script",
                    str(init_script),
                    task,
                ],
                cwd=config.root,
                environ=environment,
                capture=True,
                output_limit=OUTPUT_LIMIT,
                timeout=10 * 60,
                cancellation=cancellation,
                execution_scope=None if execution_source is None else execution_source.new_scope(),
            )
    except ProcessError as error:
        if error.fatal:
            raise
        result = None
    except (OSError, subprocess.TimeoutExpired, ConfigurationError):
        result = None
    identities: list[tuple[str, str]] = []
    if result and result.returncode == 0:
        for variant, identity in re.findall(
            r"(?m)^MOBILE_RELEASE_EFFECTIVE_ANDROID_ID\|([^|\r\n]+)\|([^|\r\n]+)$",
            result.stdout,
        ):
            if ANDROID_ID_RE.fullmatch(identity):
                identities.append((variant, identity))
    store_identity = config.section("android").get("applicationId")
    if not identities:
        return Finding(
            "android.debug-identity.effective",
            Status.BLOCKED,
            "Gradle did not expose an effective Debug application identity.",
            category="identity",
            remediation="Keep an Android Debug build type and ensure Gradle configuration can be queried.",
        )
    collisions = sorted(variant for variant, identity in identities if identity == store_identity)
    if collisions:
        return Finding(
            "android.debug-identity.effective",
            Status.BLOCKED,
            "At least one effective Android Debug variant uses the canonical Store identity.",
            category="identity",
            details={"collidingVariants": collisions},
            remediation="Give every Debug variant a non-Store applicationId.",
        )
    return Finding(
        "android.debug-identity.effective",
        Status.PASS,
        "Gradle proved that every effective Debug variant uses a non-Store identity.",
        category="identity",
        details={"verifiedVariants": sorted(variant for variant, _identity in identities)},
    )


def _xcode_application_identities(
    config: ReleaseConfig, *, configuration: str, project_read_token: str | None = None, execution_source=None,
    cancellation: DefaultCancellation | None = None,
) -> tuple[set[str], str | None]:
    discovered = discover_project(config.root, include_git=False, cancellation=cancellation,
                                  execution_source=execution_source)
    container = selected_ios_container(config, discovered)
    scheme = selected_ios_scheme(config, discovered)
    if not container or not scheme:
        return set(), "Xcode container or shared scheme is ambiguous"
    path = config.project_path(container[1])
    if not path.is_dir():
        return set(), "configured Xcode container is missing"
    flag = "-workspace" if container[0] == "workspace" else "-project"
    try:
        result = run_owned(
            [
                "xcodebuild",
                flag,
                str(path),
                "-scheme",
                scheme,
                "-configuration",
                configuration,
                "-showBuildSettings",
                "-json",
            ],
            cwd=config.root,
            environ=_identity_query_environment(config, project_read_token=project_read_token),
            capture=True,
            output_limit=OUTPUT_LIMIT,
            timeout=5 * 60,
            cancellation=cancellation,
            execution_scope=None if execution_source is None else execution_source.new_scope(),
        )
    except ProcessError as error:
        if error.fatal:
            raise
        return set(), "xcodebuild settings query failed or timed out"
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ConfigurationError):
        return set(), "xcodebuild settings query failed or timed out"
    if result.returncode:
        return set(), "xcodebuild settings query failed"
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return set(), "xcodebuild settings query did not return JSON"
    if not isinstance(payload, list):
        return set(), "xcodebuild settings query returned an invalid shape"
    identities: set[str] = set()
    for item in payload:
        settings = item.get("buildSettings") if isinstance(item, dict) else None
        if not isinstance(settings, dict):
            continue
        if settings.get("PRODUCT_TYPE") != "com.apple.product-type.application":
            continue
        identity = settings.get("PRODUCT_BUNDLE_IDENTIFIER")
        if isinstance(identity, str) and IOS_ID_RE.fullmatch(identity):
            identities.add(identity)
    return identities, None


def _effective_ios_identity_finding(config: ReleaseConfig, *, project_read_token: str | None = None,
                                  execution_source=None,
                                  cancellation: DefaultCancellation | None = None) -> Finding:
    if sys.platform != "darwin" or not shutil.which("xcodebuild"):
        return Finding(
            "ios.debug-identity.effective",
            Status.SKIP,
            "Effective iOS Debug/Archive identities require the pinned macOS/Xcode host.",
            category="identity",
        )
    ios = config.section("ios")
    if prepare := ios.get("prepareCommand"):
        release = config.release_version()
        environment = _identity_query_environment(config, project_read_token=project_read_token)
        environment.update(
            {
                "MOBILE_RELEASE_VERSION_NAME": release.name,
                "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
                "MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS": "1",
            }
        )
        try:
            prepared = run_owned(
                list(prepare),
                cwd=config.root,
                environ=environment,
                capture=False,
                timeout=10 * 60,
                cancellation=cancellation,
                execution_scope=None if execution_source is None else execution_source.new_scope(),
            )
        except ProcessError as error:
            if error.fatal:
                raise
            prepared = None
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ConfigurationError):
            prepared = None
        if prepared is None or prepared.returncode:
            return Finding(
                "ios.debug-identity.effective",
                Status.BLOCKED,
                "The configured Xcode preparation command failed before identity proof.",
                category="identity",
            )
    debug_ids, debug_error = _xcode_application_identities(config, configuration="Debug",
                                project_read_token=project_read_token, execution_source=execution_source,
                                cancellation=cancellation)
    archive_ids, archive_error = (set(), "Debug identity proof failed")
    if not debug_error and len(debug_ids) == 1:
        archive_ids, archive_error = _xcode_application_identities(
            config, configuration=ios.get("archiveConfiguration", "Release"),
            project_read_token=project_read_token, execution_source=execution_source,
            cancellation=cancellation,
        )
    store_identity = ios.get("bundleId")
    if debug_error or archive_error or len(debug_ids) != 1 or len(archive_ids) != 1:
        return Finding(
            "ios.debug-identity.effective",
            Status.BLOCKED,
            "Xcode could not prove exactly one application identity for Debug and Archive settings.",
            category="identity",
            remediation="Make the shared scheme expose one app target in Debug and Archive configurations.",
        )
    debug_identity = next(iter(debug_ids))
    archive_identity = next(iter(archive_ids))
    if debug_identity == store_identity or archive_identity != store_identity:
        return Finding(
            "ios.debug-identity.effective",
            Status.BLOCKED,
            "Effective Xcode Debug and Archive identities do not satisfy the Development/Store policy.",
            category="identity",
            remediation="Use a non-Store Debug Bundle ID and the canonical Store ID for Archive.",
        )
    return Finding(
        "ios.debug-identity.effective",
        Status.PASS,
        "Xcode proved distinct Debug and canonical Store Archive identities.",
        category="identity",
    )


def effective_identity_findings(
    config: ReleaseConfig, platforms: Iterable[str], *, project_read_token: str | None = None, execution_source=None,
    cancellation: DefaultCancellation | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for platform in platforms:
        if platform == "android" and config.platform_enabled("android"):
            findings.append(_effective_android_identity_finding(config, project_read_token=project_read_token,
                                                                 execution_source=execution_source, cancellation=cancellation))
        elif platform == "ios" and config.platform_enabled("ios"):
            findings.append(_effective_ios_identity_finding(config, project_read_token=project_read_token,
                                                             execution_source=execution_source, cancellation=cancellation))
        if findings and findings[-1].status in FAILING_STATUSES:
            break
    return findings


def _platform_policy_findings(config: ReleaseConfig, platform: str) -> list[Finding]:
    section = config.section(platform)
    if not config.platform_enabled(platform):
        return [
            Finding(
                f"{platform}.disabled",
                Status.NOT_APPLICABLE,
                f"{platform} release support is disabled.",
                category="configuration",
            )
        ]
    status = section.get("identityStatus", "unverified")
    findings: list[Finding] = []
    if status == "blocked":
        findings.append(
            Finding(
                f"{platform}.identity-status",
                Status.BLOCKED,
                f"{platform} Store identity is explicitly blocked.",
                category="identity",
                remediation="Select and verify an owned Store identity in a reviewed change.",
            )
        )
    elif status == "unverified":
        findings.append(
            Finding(
                f"{platform}.identity-status",
                Status.BLOCKED,
                f"{platform} Store identity has not been verified.",
                category="identity",
                remediation="Verify Store ownership online, then set identityStatus to approved.",
            )
        )
    else:
        findings.append(
            Finding(
                f"{platform}.identity-status",
                Status.PASS,
                f"{platform} Store identity is explicitly approved.",
                category="identity",
            )
        )

    if platform == "android":
        identity = section.get("applicationId")
        if not identity:
            findings.append(
                Finding(
                    "android.application-id",
                    Status.MISSING,
                    "Android configuration lacks applicationId.",
                    category="identity",
                )
            )
        elif not ANDROID_ID_RE.fullmatch(identity):
            findings.append(
                Finding(
                    "android.application-id",
                    Status.INVALID,
                    "Android applicationId is not a valid reverse-domain identifier.",
                    category="identity",
                )
            )
        track = section.get("externalTrack")
        if not isinstance(track, dict) or not track.get("name"):
            findings.append(
                Finding(
                    "android.external-track",
                    Status.MISSING,
                    "Android external testing track is not configured.",
                    category="store-policy",
                )
            )
        elif track["name"] in {"internal", "production"}:
            findings.append(
                Finding(
                    "android.external-track",
                    Status.INVALID,
                    "External testing track must not be internal or production.",
                    category="store-policy",
                )
            )
        fingerprint = _normalized_fingerprint(section.get("uploadCertificateSha256"))
        if not fingerprint:
            findings.append(
                Finding(
                    "android.upload-fingerprint",
                    Status.MISSING,
                    "Android configuration lacks the upload certificate SHA-256.",
                    category="signing-policy",
                )
            )
        elif not FINGERPRINT_RE.fullmatch(fingerprint) or set(fingerprint) == {"0"}:
            findings.append(
                Finding(
                    "android.upload-fingerprint",
                    Status.INVALID,
                    "Android upload certificate fingerprint is invalid or a placeholder.",
                    category="signing-policy",
                )
            )
    else:
        identity = section.get("bundleId")
        if not identity:
            findings.append(
                Finding(
                    "ios.bundle-id",
                    Status.MISSING,
                    "iOS configuration lacks bundleId.",
                    category="identity",
                )
            )
        elif not IOS_ID_RE.fullmatch(identity):
            findings.append(
                Finding(
                    "ios.bundle-id",
                    Status.INVALID,
                    "iOS bundleId is not a valid reverse-domain identifier.",
                    category="identity",
                )
            )
        required = {
            "appStoreAppId": APP_STORE_ID_RE,
            "teamId": TEAM_ID_RE,
            "externalTestFlightGroup": None,
        }
        for key, pattern in required.items():
            value = section.get(key)
            if not value:
                findings.append(
                    Finding(
                        f"ios.{key}",
                        Status.MISSING,
                        f"iOS configuration lacks {key}.",
                        category="store-policy",
                    )
                )
            elif pattern and not pattern.fullmatch(str(value)):
                findings.append(
                    Finding(
                        f"ios.{key}",
                        Status.INVALID,
                        f"iOS {key} has an invalid format.",
                        category="store-policy",
                    )
                )
        review = section.get("review")
        if not isinstance(review, dict) or not all(
            isinstance(review.get(key), bool)
            for key in ("usesNonExemptEncryption", "demoAccountRequired")
        ):
            findings.append(
                Finding(
                    "ios.review-policy",
                    Status.MISSING,
                    "iOS configuration lacks committed encryption/demo-account policy.",
                    category="store-policy",
                )
            )
        fingerprint = _normalized_fingerprint(section.get("distributionCertificateSha256"))
        if not fingerprint:
            findings.append(
                Finding(
                    "ios.distribution-fingerprint",
                    Status.MISSING,
                    "iOS configuration lacks the distribution certificate SHA-256.",
                    category="signing-policy",
                )
            )
        elif not FINGERPRINT_RE.fullmatch(fingerprint) or set(fingerprint) == {"0"}:
            findings.append(
                Finding(
                    "ios.distribution-fingerprint",
                    Status.INVALID,
                    "Apple distribution certificate fingerprint is invalid or a placeholder.",
                    category="signing-policy",
                )
            )
    return findings


def doctor(config: ReleaseConfig, platforms: Iterable[str] | None = None, *, execution_source=None,
           cancellation: DefaultCancellation | None = None) -> Report:
    report = Report("doctor", context={"config": str(config.path), "root": str(config.root)})
    selected = tuple(platforms if platforms is not None else config.enabled_platforms)
    try:
        release = config.release_version()
        report.context["release"] = {"marketingVersion": release.name, "buildNumber": release.build}
        report.add(
            "version.source",
            Status.PASS,
            f"Resolved committed release {release.name} ({release.build}).",
            category="version",
        )
    except ConfigurationError as error:
        report.add(
            "version.source",
            Status.FAIL,
            str(error),
            category="version",
            remediation="Fix the single committed version source before building.",
        )

    discovered = discover_project(config.root, execution_source=execution_source, cancellation=cancellation)
    report.context["discovery"] = discovered
    report.context["git"] = discovered["git"]
    if not selected:
        report.add(
            "platform.none",
            Status.FAIL,
            "At least one release platform must be enabled.",
            category="configuration",
        )
    for platform in selected:
        if platform not in {"android", "ios"} or not config.platform_enabled(platform):
            report.add(
                "platform.selection",
                Status.FAIL,
                f"Requested platform is disabled or unknown: {platform}",
                category="configuration",
            )
            continue
        report.extend(_platform_policy_findings(config, platform))

    if "android" in selected and config.platform_enabled("android"):
        module = selected_android_module(config, discovered)
        if not module:
            report.add(
                "android.module",
                Status.MISSING,
                "Android application module could not be selected deterministically.",
                category="discovery",
                remediation="Set android.module to the Gradle application module path.",
            )
        else:
            report.add(
                "android.module",
                Status.PASS,
                f"Selected Android application module {module}.",
                category="discovery",
            )
        if not (config.root / "gradlew").is_file():
            report.add(
                "android.gradle-wrapper",
                Status.MISSING,
                "Gradle wrapper is missing.",
                category="toolchain",
            )
        else:
            report.add(
                "android.gradle-wrapper", Status.PASS, "Gradle wrapper is present.", category="toolchain"
            )
        android_found = selected_android_details(config, discovered)
        suffix = android_found.get("debugApplicationIdSuffix")
        if suffix:
            report.add(
                "android.debug-identity",
                Status.CONFIGURED,
                f"A non-Store Debug applicationId suffix is declared ({suffix}); effective proof is deferred.",
                category="identity",
            )
        else:
            report.add(
                "android.debug-identity",
                Status.MANUAL,
                "Static discovery found no reliable Debug/Store identity proof.",
                category="identity",
                remediation="Run buildful preflight so Gradle can prove the effective Debug applicationId.",
            )

    if "ios" in selected and config.platform_enabled("ios"):
        container = selected_ios_container(config, discovered)
        scheme = selected_ios_scheme(config, discovered)
        if not container:
            report.add(
                "ios.container",
                Status.MISSING,
                "Xcode project/workspace could not be selected deterministically.",
                category="discovery",
            )
        else:
            container_path = config.project_path(container[1])
            if container_path.is_dir() and not container_path.is_symlink():
                report.add(
                    "ios.container",
                    Status.PASS,
                    f"Selected Xcode {container[0]} {container[1]}.",
                    category="discovery",
                )
            elif config.section("ios").get("prepareCommand"):
                report.add(
                    "ios.container",
                    Status.CONFIGURED,
                    f"Configured preparation must generate Xcode {container[0]} {container[1]}.",
                    category="discovery",
                )
            else:
                report.add(
                    "ios.container",
                    Status.MISSING,
                    f"Configured Xcode {container[0]} is missing: {container[1]}.",
                    category="discovery",
                )
        if not scheme:
            report.add(
                "ios.scheme",
                Status.MISSING,
                "Shared Xcode archive scheme could not be selected deterministically.",
                category="discovery",
            )
        else:
            report.add(
                "ios.scheme", Status.PASS, f"Selected shared Xcode scheme {scheme}.", category="discovery"
            )
        bundle_ids = discovered.get("ios", {}).get("bundleIds", [])
        store_id = config.section("ios").get("bundleId")
        debug_ids = {
            value
            for value in bundle_ids
            if value != store_id
            and (
                value in {f"{store_id}.debug", f"{store_id}.dev"}
                or value.endswith((".debug", ".dev", ".development"))
            )
        }
        if debug_ids:
            report.add(
                "ios.debug-identity",
                Status.CONFIGURED,
                "A distinct non-Store iOS identity is declared; effective proof is deferred.",
                category="identity",
            )
        else:
            report.add(
                "ios.debug-identity",
                Status.MANUAL,
                "Static discovery found no reliable Debug/Store identity proof.",
                category="identity",
                remediation="Run buildful preflight on macOS so Xcode can prove effective identities.",
            )
        report.extend([_xcode_toolchain_finding(execution_source=execution_source, cancellation=cancellation)])

    gitignore = config.root / ".gitignore"
    ignored = False
    if gitignore.is_file():
        ignored = any(
            line.strip().rstrip("/") in {".mobile-release", "/.mobile-release"}
            for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        )
    report.add(
        "workspace.private-output",
        Status.PASS if ignored else Status.MISSING,
        ".mobile-release is ignored by Git."
        if ignored
        else ".mobile-release is not explicitly ignored by Git.",
        category="security",
        remediation=None if ignored else "Add /.mobile-release/ to the project .gitignore.",
    )
    return report


def run_project_checks(
    config: ReleaseConfig,
    phase: str,
    *,
    environ: Mapping[str, str] | None = None,
    execution_source=None,
    cancellation: DefaultCancellation | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    execution_environment = (
        dict(environ)
        if environ is not None
        else scrub_credential_capabilities(os.environ)
    )
    for index, command in enumerate(config.commands(phase)):
        expanded: list[str] = []
        missing_variable: str | None = None
        for argument in command:
            value = argument
            for name in (
                "MOBILE_RELEASE_AAB_PATH",
                "MOBILE_RELEASE_IPA_PATH",
                "MOBILE_RELEASE_DSYM_PATH",
            ):
                placeholder = f"${{{name}}}"
                if placeholder in value and not execution_environment.get(name):
                    missing_variable = name
                    break
                value = value.replace(placeholder, execution_environment.get(name, placeholder))
            if missing_variable:
                break
            expanded.append(value)
        if missing_variable:
            findings.append(
                Finding(
                    f"project-check.{phase}.{index}",
                    Status.FAIL,
                    f"Project check requires unavailable artifact variable {missing_variable}.",
                    category="project-check",
                )
            )
            break
        try:
            result = run_owned(
                expanded,
                cwd=config.root,
                environ=execution_environment,
                capture=False,
                timeout=30 * 60,
                cancellation=cancellation,
                execution_scope=None if execution_source is None else execution_source.new_scope(),
            )
        except (ProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
            if isinstance(error, ProcessError) and error.fatal:
                raise
            findings.append(
                Finding(
                    f"project-check.{phase}.{index}",
                    Status.FAIL,
                    f"Project check failed or timed out: {expanded[0]}",
                    category="project-check",
                    details={"errorType": type(error).__name__},
                )
            )
            break
        findings.append(
            Finding(
                f"project-check.{phase}.{index}",
                Status.PASS if result.returncode == 0 else Status.FAIL,
                f"Project check {'passed' if result.returncode == 0 else 'failed'}: {expanded[0]}",
                category="project-check",
                details={"exitCode": result.returncode},
            )
        )
        if result.returncode:
            break
    if not findings:
        findings.append(
            Finding(
                f"project-check.{phase}",
                Status.NOT_APPLICABLE,
                f"No application-owned {phase} checks are configured.",
                category="project-check",
            )
        )
    return findings


@contextmanager
def _credential_environment(values: Mapping[str, str], *, invocation: InvocationCustody) -> Iterator[None]:
    invocation.require(root=invocation.root, cancellation=invocation.cancellation,
                       signing_lease=invocation.signing_lease)
    capability_names = {
        key for key in os.environ if is_credential_capability_name(key)
    } | ALLOWED_CREDENTIAL_NAMES | {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"}
    updates: dict[str, str | None] = {key: None for key in capability_names}
    updates.update({key: value for key, value in values.items() if key in ALLOWED_CREDENTIAL_NAMES})
    profile = materialized_profile_specifier(values, invocation=invocation)
    if profile is not None:
        updates["MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"] = profile
    with invocation.environment(updates):
        yield


def _online_query_blockers(
    config: ReleaseConfig,
    platforms: tuple[str, ...],
    credential_checks: Iterable[Finding],
) -> list[str]:
    blockers: list[str] = []
    for finding in credential_checks:
        if finding.status in FAILING_STATUSES:
            blockers.append(finding.code)
    for platform in platforms:
        if not config.platform_enabled(platform):
            blockers.append(f"{platform}.disabled")
            continue
        section = config.section(platform)
        if section.get("identityStatus") == "blocked":
            blockers.append(f"{platform}.identity-status")
        if platform == "android":
            track = section.get("externalTrack")
            if not isinstance(track, dict) or not track.get("name") or not track.get("kind"):
                blockers.append("android.external-track")
        else:
            for key in ("appStoreAppId", "externalTestFlightGroup"):
                if not section.get(key):
                    blockers.append(f"ios.{key}")
    return sorted(set(blockers))


def preflight(
    config: ReleaseConfig,
    *,
    mode: str,
    platforms: Iterable[str],
    run_builds: bool,
    artifacts: Mapping[str, Path] | None = None,
    credentials_file: Path | None = None,
    credentials_from_env: bool = False,
    require_tools: bool = False,
) -> Report:
    selected = tuple(platforms)
    if mode not in {"offline", "signing", "online"}:
        raise ValidationError(f"unsupported preflight mode: {mode}")
    arguments = dict(mode=mode, platforms=selected, run_builds=run_builds, artifacts=artifacts,
                     credentials_file=credentials_file, credentials_from_env=credentials_from_env,
                     require_tools=require_tools)
    try:
        # Reserve process-global environment before credential snapshots, then
        # account (when applicable), then continuous project admission. Even
        # --skip-builds may run application checks and must hold that project.
        with invocation_custody(config.root, mode="online" if mode == "online" else "build") as invocation:
            if mode == "online":
                return _preflight(config, **arguments, invocation=invocation)
            if mode == "signing" and run_builds and "ios" in selected and config.platform_enabled("ios"):
                with local_signing_lease(cancellation=invocation.cancellation) as lease:
                    with invocation.project(signing_lease=lease):
                        return _preflight(config, **arguments, signing_lease=lease, invocation=invocation)
            with invocation.project(signing_lease=None):
                return _preflight(config, **arguments, invocation=invocation)
    except ProcessError as error:
        report = Report(command=f"preflight --{mode}")
        report.add("preflight.process-lifetime", Status.FAIL,
                   "A command did not complete safely or its resource cleanup could not be confirmed.",
                   category="lifecycle",
                   remediation="End this invocation and establish that its exact workers/resources are idle before retrying. "
                   "If local-signing status reports pending ownership, follow the original session recovery guide; "
                   "an early command failure does not create a recoverable signing session.")
        return _stop_preflight(report, "Further commands, private validation and builds were not executed.")
    except BuildInputError as error:
        report = Report(command=f"preflight --{mode}")
        report.add("preflight.build-input-ownership", Status.FAIL, str(error), category="lifecycle",
                   remediation="Wait for the original invocation or inspect build-inputs status for this project.")
        return _stop_preflight(report, "Further application, credential and Store work was not executed.")
    except CredentialError as error:
        if mode != "signing" or not run_builds or "ios" not in selected or not config.platform_enabled("ios"):
            raise
        report = Report(command="preflight --signing")
        report.add("ios.local-signing-lease", Status.FAIL, str(error), category="signing",
                   remediation="Wait for the account owner, or use mobile-release local-signing status and the recovery guide.")
        return report


def _stop_preflight(report: Report, message: str) -> Report:
    report.add("preflight.early-exit", Status.SKIP, message, category="lifecycle")
    return report


def _preflight(
    config: ReleaseConfig,
    *,
    mode: str,
    platforms: Iterable[str],
    run_builds: bool,
    artifacts: Mapping[str, Path] | None = None,
    credentials_file: Path | None = None,
    credentials_from_env: bool = False,
    require_tools: bool = False,
    signing_lease: SigningLease | None = None,
    invocation: InvocationCustody,
) -> Report:
    if mode not in {"offline", "signing", "online"}:
        raise ValidationError(f"unsupported preflight mode: {mode}")
    selected = tuple(platforms)
    execution_source = None if signing_lease is None else signing_lease.execution_source()
    cancellation = invocation.cancellation
    invocation.require(root=config.root, cancellation=cancellation, signing_lease=signing_lease)
    report = doctor(config, selected, execution_source=execution_source, cancellation=cancellation)
    report.command = f"preflight --{mode}"
    invalid = set(selected) - set(config.enabled_platforms)
    if invalid:
        report.add(
            "platform.selection",
            Status.FAIL,
            f"Requested disabled platform(s): {', '.join(sorted(invalid))}",
            category="configuration",
        )
    report.extend(metadata_findings(config, platforms=selected))
    if (invalid or not selected) and mode == "online":
        report.add("store.online.gate", Status.SKIP,
                   "Non-publishing Store API checks were skipped because the platform selection is invalid.",
                   category="store-access")
        return report
    if not report.ok and mode != "online":
        return _stop_preflight(report, "Application checks, credentials and builds were skipped because initial checks failed.")
    credential_values = resolve_credential_values(
        config,
        credentials_file=credentials_file,
        credentials_from_env=credentials_from_env,
        cancellation=cancellation,
    )
    build_credential_values = credential_values_for_purpose(
        config,
        credential_values,
        stage="candidate",
        purpose="signing",
        platforms=selected,
    )
    store_credential_values = credential_values_for_purpose(
        config,
        credential_values,
        stage="candidate",
        purpose="store",
        platforms=selected,
    )
    project_check_environment = scrub_credential_capabilities(os.environ)
    if config.section("source").get("projectReadTokenRequired") and credential_values.get(
        "MOBILE_RELEASE_PROJECT_READ_TOKEN"
    ):
        project_check_environment["MOBILE_RELEASE_PROJECT_READ_TOKEN"] = credential_values[
            "MOBILE_RELEASE_PROJECT_READ_TOKEN"
        ]
    try:
        release = config.release_version()
    except ConfigurationError:
        release = None
    if release is not None:
        project_check_environment.update(
            {
                "MOBILE_RELEASE_VERSION_NAME": release.name,
                "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
            }
        )
    if mode == "online":
        report.add(
            "project-check.preflight.online",
            Status.NOT_APPLICABLE,
            "Non-publishing online preflight never executes application-owned commands.",
            category="project-check",
        )
    else:
        report.extend(
            run_project_checks(config, "preflight", environ=project_check_environment,
                               execution_source=execution_source, cancellation=cancellation)
        )
    if (
        mode != "online"
        and run_builds
        and config.section("source").get("projectReadTokenRequired")
        and not credential_values.get("MOBILE_RELEASE_PROJECT_READ_TOKEN")
    ):
        report.add(
            "build.project-read-token",
            Status.MISSING,
            "Release builds require MOBILE_RELEASE_PROJECT_READ_TOKEN for private dependencies.",
            category="credentials",
            remediation=(
                "Provide the read-only token through an explicit credentials file or protected "
                "candidate environment; static checks remain credential-free."
            ),
        )
    if not report.ok and mode != "online":
        return _stop_preflight(report, "Private validation and builds were skipped because preflight checks failed.")
    credential_checks: list[Finding] = []
    if mode in {"signing", "online"}:
        credential_checks.extend(
            credential_findings(
                config,
                stage="candidate",
                credentials_from_env=True,
                environ=credential_values,
                purpose="signing" if mode == "signing" else "store",
                platforms=selected,
                cancellation=cancellation,
            )
        )
        report.extend(credential_checks)
    if not report.ok and mode != "online":
        return _stop_preflight(report, "Private validation and builds were skipped because credential prerequisites failed.")
    if mode == "online":
        # Nonfatal signing/build/metadata diagnostics are independent of a
        # read-only ownership query. Query credentials/identity/version are not.
        prerequisites = store_material_prerequisite_findings(values=store_credential_values, platforms=selected)
        credential_checks.extend(prerequisites)
        report.extend(prerequisites)
        blockers = _online_query_blockers(config, selected, credential_checks)
        if release is None:
            blockers.append("version.source")
        if blockers:
            report.add("store.online.gate", Status.SKIP,
                       "Non-publishing Store API checks were skipped because prerequisites are incomplete: "
                       + ", ".join(sorted(set(blockers))), category="store-access")
            return report
    if mode == "signing":
        material_checks = validate_signing_material(
            config, values=build_credential_values, platforms=selected, execution_source=execution_source, cancellation=cancellation,
        )
        credential_checks.extend(material_checks)
        report.extend(material_checks)
    if release is None:
        return report
    if mode == "online":
        try:
            # The same immutable selection spans native validation, the gate,
            # environment and actual adapters; originals are never reopened.
            with _selected_store_material(config, values=store_credential_values,
                    platforms=selected, invocation=invocation, cancellation=cancellation) as material:
                material_checks = material.validate()
                credential_checks.extend(material_checks)
                report.extend(material_checks)
                blockers = _online_query_blockers(config, selected, credential_checks)
                if blockers:
                    report.add("store.online.gate", Status.SKIP,
                        "Non-publishing Store API checks were skipped because prerequisites are incomplete: "
                        + ", ".join(blockers), category="store-access")
                    return report
                with _credential_environment(material.lane_environment(), invocation=invocation):
                    report.extend(online_preflight_findings(config=config, release=release, platforms=selected,
                                                           material=material, invocation=invocation))
        except ProcessError:
            raise
        except CredentialError as error:
            report.add("store.online.materialization", Status.FAIL, str(error), category="store-access")
        return report
    if report.ok and run_builds:
        project_read_token = (build_credential_values.get("MOBILE_RELEASE_PROJECT_READ_TOKEN")
                             if config.section("source").get("projectReadTokenRequired") else None)
        identity_values = ({"MOBILE_RELEASE_PROJECT_READ_TOKEN": project_read_token} if project_read_token else {})
        with _credential_environment(identity_values, invocation=invocation):
            report.extend(effective_identity_findings(config, selected, project_read_token=project_read_token,
                                                      execution_source=execution_source,
                                                      cancellation=cancellation))
    if not report.ok:
        report.add(
            "preflight.early-exit",
            Status.SKIP,
            "Build and artifact checks were skipped because cheaper checks failed.",
            category="lifecycle",
        )
        return report

    collected = dict(artifacts or {})
    allowed_artifacts = {
        "android-aab",
        "android-mapping",
        "android-native-symbols",
        "ios-ipa",
        "ios-archive",
        "ios-dsyms",
    }
    for name, path in collected.items():
        if name not in allowed_artifacts:
            report.add(
                "artifact.name",
                Status.INVALID,
                f"Unsupported preflight artifact name: {name}",
                category="artifact",
            )
        elif path.is_symlink() or not path.exists():
            report.add(
                f"artifact.{name}",
                Status.INVALID,
                f"Supplied artifact is missing or unsafe: {name}",
                category="artifact",
            )
    if not report.ok:
        report.add(
            "preflight.artifact-input-exit",
            Status.SKIP,
            "Builds were skipped because supplied artifact inputs are invalid.",
            category="lifecycle",
        )
        return report
    if run_builds:
        for platform in selected:
            platform_values = credential_values_for_purpose(
                config,
                credential_values,
                stage="candidate",
                purpose="signing",
                platforms=(platform,),
            )
            try:
                with _credential_environment({}, invocation=invocation):
                    child_context = (invocation.materialization(signing_lease=signing_lease)
                                     if mode == "signing" else nullcontext(None))
                    with child_context as build_inputs:
                        material_context = (
                            materialize_build_inputs(
                                config, values=platform_values, platforms=(platform,),
                                prepare_ios_signing=platform == "ios", signing_lease=signing_lease,
                                cancellation=cancellation, build_inputs=build_inputs,
                            ) if mode == "signing" else nullcontext({
                                name: value for name, value in platform_values.items()
                                if name == "MOBILE_RELEASE_PROJECT_READ_TOKEN"
                            })
                        )
                        with material_context as materialized_environment, _credential_environment(
                            materialized_environment, invocation=invocation
                        ):
                            if platform == "android":
                                collected.update(run_android_build(
                                    config, signed=mode == "signing", execution_source=execution_source,
                                    cancellation=cancellation, build_inputs=build_inputs,
                                ))
                            else:
                                collected.update(run_ios_build(
                                    config, signed=mode == "signing",
                                    signing_session=signing_lease.active if signing_lease is not None else None,
                                    execution_source=execution_source, cancellation=cancellation,
                                ))
            except ProcessError as error:
                if error.fatal:
                    raise
                report.add(f"{platform}.build", Status.FAIL, str(error), category="build")
                return _stop_preflight(report, "Remaining platforms and artifact checks were skipped after a build or cleanup failure; completed outputs are retained but not validated.")
            except (MobileReleaseError, OSError) as error:
                report.add(
                    f"{platform}.build",
                    Status.FAIL,
                    str(error),
                    category="build",
                )
                return _stop_preflight(report, "Remaining platforms and artifact checks were skipped after a build or cleanup failure; completed outputs are retained but not validated.")

    if "android" in selected and "android-aab" in collected:
        android = config.section("android")
        report.extend(
            validate_aab(
                collected["android-aab"],
                expected_application_id=android["applicationId"],
                release=release,
                expected_fingerprint=android.get("uploadCertificateSha256"),
                require_tools=require_tools or mode == "signing",
                check_signer=mode == "signing",
                cancellation=cancellation,
            )
        )
        artifact_environment = artifact_validation_environment(os.environ)
        artifact_environment.update(
            {
                "MOBILE_RELEASE_AAB_PATH": str(collected["android-aab"]),
                "MOBILE_RELEASE_VERSION_NAME": release.name,
                "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
            }
        )
        report.extend(
            run_project_checks(config, "androidArtifact", environ=artifact_environment,
                               execution_source=execution_source, cancellation=cancellation)
        )
    elif "android" in selected and not run_builds:
        report.add(
            "android.artifact",
            Status.SKIP,
            "Android artifact validation was not requested.",
            category="android-artifact",
        )

    if "ios" in selected:
        ios = config.section("ios")
        symbols_policy = ios.get("symbols", {}).get("policy", "disabled")
        archive = collected.get("ios-archive")
        ipa = collected.get("ios-ipa")
        if archive and not ipa:
            archive_findings = validate_xcarchive(
                archive,
                expected_bundle_id=ios["bundleId"],
                release=release,
                symbols_policy=symbols_policy,
                require_tools=require_tools or mode == "signing",
                cancellation=cancellation,
            )
            report.extend(archive_findings)
            if mode == "signing" and symbols_policy == "required":
                report.add(
                    "ios.symbols.upload",
                    Status.BLOCKED,
                    "Automatic symbol upload is not available in validation-only local preflight.",
                    category="ios-artifact",
                    remediation=(
                        "Use symbols.policy=retain, or add a separately guarded candidate-stage "
                        "symbol upload before activating this project."
                    ),
                )
        elif not archive and mode == "signing" and (ipa or symbols_policy in {"retain", "required"}):
            report.add(
                "ios.archive.symbols",
                Status.FAIL,
                "Signed IPA validation requires its retained xcarchive, regardless of symbol policy.",
                category="ios-artifact",
            )
        if ipa:
            try:
                with snapshot_ios_artifacts(collected, cancellation=cancellation) as snapshot:
                    if archive:
                        inspect_ios_artifact_set(snapshot, expected_bundle_id=ios["bundleId"],
                                                 release=release, symbols_policy=symbols_policy)
                    else:
                        report.add("ios.artifacts.correspondence", Status.FAIL if mode == "signing" else Status.SKIP,
                                   "IPA-only inspection cannot establish retained archive/symbol correspondence.", category="ios-artifact")
                    snapshot.deadline.check()
                    report.extend(validate_ipa(
                        snapshot.paths["ios-ipa"], expected_bundle_id=ios["bundleId"],
                        expected_team_id=ios["teamId"], expected_fingerprint=ios.get("distributionCertificateSha256"),
                        release=release, require_tools=require_tools or mode == "signing",
                        deadline=snapshot.deadline,
                        cancellation=snapshot.cancellation,
                    ))
                    snapshot.deadline.check()
                    artifact_environment = artifact_validation_environment(os.environ)
                    artifact_environment.update({
                        "MOBILE_RELEASE_IPA_PATH": str(ipa),
                        "MOBILE_RELEASE_VERSION_NAME": release.name,
                        "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
                    })
                    if archive:
                        symbol_archive = archive if archive.is_dir() else snapshot.unpack("ios-archive")
                        artifact_environment["MOBILE_RELEASE_DSYM_PATH"] = str(symbol_archive / "dSYMs")
                    if report.ok:
                        snapshot.deadline.check()
                        report.extend(run_project_checks(config, "iosArtifact", environ=artifact_environment,
                                                         execution_source=execution_source,
                                                         cancellation=cancellation))
                    snapshot.assert_unchanged()
                    if archive:
                        report.add("ios.artifacts.correspondence", Status.PASS,
                                   "IPA/archive native images and resources correspond; retained dSYMs satisfy the configured symbol-inventory policy.",
                                   category="ios-artifact")
            except ValidationError as error:
                if isinstance(error, ProcessError) and error.fatal:
                    raise
                report.add("ios.artifacts.correspondence", Status.FAIL, str(error), category="ios-artifact")
            if mode == "signing" and symbols_policy == "required":
                report.add("ios.symbols.upload", Status.BLOCKED,
                           "Automatic symbol upload is not available in validation-only local preflight.", category="ios-artifact",
                           remediation="Use symbols.policy=retain, or add a separately guarded candidate-stage symbol upload before activation.")
        elif mode == "signing" and run_builds:
            report.add(
                "ios.ipa",
                Status.FAIL,
                "Signed iOS preflight did not produce an IPA.",
                category="ios-artifact",
            )
        elif not run_builds:
            report.add(
                "ios.artifact",
                Status.SKIP,
                "iOS artifact validation was not requested.",
                category="ios-artifact",
            )

    return report
