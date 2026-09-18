"""Passive, supplied-draft environment guidance; never discover or run tools.

The existing CLI doctor and build/validation modules are deliberately not part
of this import graph. A requirement is neither a tool observation nor readiness.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal, cast

from ..config import ReleaseConfig, parse_config_text
from ..errors import ConfigurationError
from ..toolchain_policy import (BUNDLETOOL_MAX_BYTES, BUNDLETOOL_SHA256,
                                BUNDLETOOL_VERSION, XCODE_BUILD, XCODE_VERSION)
from ._json import bounded_json_text
from .contracts import (ApiError, EnvironmentBaseline, EnvironmentHelp,
                        EnvironmentOperation, EnvironmentPlatform,
                        EnvironmentRequirement, EnvironmentRequirementsResult,
                        EnvironmentRole, assurance)

REQUEST_ERROR = "The environment request is invalid."
DRAFT_ERROR = "Review the project configuration before loading environment requirements."
UNAVAILABLE_ERROR = "Environment requirements could not be loaded. Check the core connection and try again."
# Leave ample room for the fixed protocol envelope and its bounded request ID.
_RESULT_LIMIT = 60 * 1024


def _help(label: str, what: str, why: str, where: str, format: str, failure: str,
          *, when: str = "") -> EnvironmentHelp:
    return {"label": label, "requiredness": "conditional" if when else "required",
            "requiredWhen": when or "For the selected activity.", "what": what, "why": why, "where": where,
            "format": format, "failure": failure}


_HELP: dict[EnvironmentRole, EnvironmentHelp] = {
    "android-jdk": _help(
        "Java Development Kit (JDK)",
        "Java runs your Android build and the toolkit's AAB inspection and signature tools.",
        "A JDK provides java, keytool and jarsigner; the project build must support its chosen Java version.",
        "Use the JDK documented by your Android project or its Android Studio configuration.",
        "A project-compatible JDK. Reusable GitHub workflows use Temurin Java 21 as a reference, not a universal local compatibility rule.",
        "An incompatible or missing JDK can prevent builds or final AAB validation. No Java installation or version was checked."),
    "android-gradle-wrapper": _help(
        "Project Gradle wrapper",
        "The build launcher committed with your Android project.",
        "The toolkit uses the project's gradlew and its configured Gradle version, rather than a global Gradle installation.",
        "Your project root, normally created by Android Studio or the project's build setup.",
        "The existing project Gradle wrapper and its companion configuration. This screen does not read or execute them.",
        "A missing or incompatible wrapper blocks the Android build. Ask the project's maintainer to restore its reviewed build setup."),
    "android-sdk": _help(
        "Android SDK and build tools",
        "Android platform libraries and build tools required by your project.",
        "Gradle needs the SDK packages selected by the project's Android build configuration.",
        "Android Studio's SDK Manager and your project's documented SDK requirements.",
        "Install the SDK platform and build-tool packages required by your project. No universal SDK version is inferred here.",
        "Missing or incompatible packages can stop the build. This screen has not inspected your SDK or project scripts."),
    "android-bundletool": _help(
        "Bundletool release helper",
        "The helper used to inspect the final Android App Bundle (AAB) manifest.",
        "The toolkit accepts only its pinned helper bytes before reading the bundle's release identity.",
        "The standalone Desktop distribution must supply this non-SDK helper. This development milestone does not establish that packaging is complete.",
        "The exact expected version, SHA-256 and byte limit shown below. These are policy values, not an inspected file.",
        "A missing or different helper prevents complete AAB validation. Do not replace it with an arbitrary downloaded JAR."),
    "apple-macos": _help(
        "macOS host",
        "The Apple operating system required for native iOS operations.",
        "iOS archive/export and native signature/profile checks depend on Apple platform facilities.",
        "A suitable local Mac or an appropriately configured GitHub Actions macOS runner.",
        "An eligible macOS host for the later native operation. The current release target is not proof of your host platform.",
        "Linux or Windows cannot perform these native iOS steps locally. No macOS tools or permissions have been checked."),
    "apple-xcode": _help(
        "Xcode release baseline",
        "Apple's iOS build and archive/export toolchain.",
        "The existing release preflight compares the selected Xcode version and build with the shared exact baseline.",
        "Apple Developer downloads or the Xcode installation maintained for your release runner.",
        "The expected Xcode version and build shown below. A version label alone is not proof that this toolchain is selected or usable.",
        "An absent or different selected Xcode blocks the pinned release preflight. No xcodebuild command was run here."),
    "apple-signing-tools": _help(
        "macOS signing and keychain tools",
        "The platform tools used by an owned local signing session.",
        "Signed archives need controlled keychain and signing setup, separate from the private certificate and provisioning-profile inputs.",
        "The macOS release host's system signing tools; configure private signing inputs through the dedicated Credentials flow when available.",
        "Platform signing support with a reviewed signing-session owner. Do not put passwords or private keys in project settings.",
        "Unavailable signing tools or unsettled signing ownership block a signed build. This screen checks neither tools nor signing identities.",
        when="Building a signed iOS archive or export."),
    "apple-codesign": _help(
        "Apple code-signature tools",
        "The macOS codesign facility for inspecting and verifying application signatures.",
        "Final IPA validation checks signed content, nested code and signing identity instead of trusting a filename.",
        "The macOS host used for native iOS validation.",
        "The platform codesign tool needed by the existing core validation path. No version or presence is inferred.",
        "Missing or unsuccessful signature checks prevent native artifact validation. No signature or artifact was checked here."),
    "apple-openssl": _help(
        "macOS OpenSSL support",
        "The certificate and CMS inspection support used by the native iOS validators.",
        "The core examines certificate fingerprints, validity dates and authenticated provisioning-profile content.",
        "The approved macOS validation environment, including its system OpenSSL path for authenticated-profile checks.",
        "OpenSSL functionality compatible with the existing native core path; this screen invents no additional version pin.",
        "Missing or incompatible native certificate/CMS support prevents complete validation. No executable was selected or probed."),
    "apple-security-framework": _help(
        "Apple Security and CoreFoundation frameworks",
        "macOS framework support for authenticated provisioning-profile trust checks.",
        "The core uses explicit Apple trust policy and retained trust anchors, not merely a decoded profile.",
        "The macOS operating system on the native validation host.",
        "The platform Security and CoreFoundation framework APIs required by the core. Their presence and behavior remain unverified here.",
        "Unavailable framework or profile-trust checks block authenticated profile validation. No framework has been loaded by this screen."),
}

_KINDS: dict[EnvironmentRole, Literal["external-toolchain", "project-file", "bundled-helper", "native-os"]] = {
    "android-jdk": "external-toolchain", "android-gradle-wrapper": "project-file",
    "android-sdk": "external-toolchain", "android-bundletool": "bundled-helper",
    "apple-macos": "native-os", "apple-xcode": "external-toolchain",
    "apple-signing-tools": "native-os", "apple-codesign": "native-os",
    "apple-openssl": "native-os", "apple-security-framework": "native-os",
}
_ROLES: dict[tuple[EnvironmentPlatform, EnvironmentOperation], tuple[EnvironmentRole, ...]] = {
    ("android", "build"): ("android-jdk", "android-gradle-wrapper", "android-sdk"),
    ("android", "artifact-validation"): ("android-jdk", "android-bundletool"),
    ("ios", "build"): ("apple-macos", "apple-xcode", "apple-signing-tools"),
    ("ios", "artifact-validation"): ("apple-macos", "apple-codesign", "apple-openssl", "apple-security-framework"),
}


def _baseline(role: EnvironmentRole) -> EnvironmentBaseline:
    value: EnvironmentBaseline = {"kind": "platform-defined", "version": None,
                                  "build": None, "sha256": None, "maxBytes": None}
    if role == "android-jdk":
        # Current reusable-preflight/candidate workflow reference only. This is
        # not a new local JDK minimum or a project compatibility assertion.
        value.update(kind="workflow-reference", version="21")
    elif role in ("android-gradle-wrapper", "android-sdk"):
        value["kind"] = "project-defined"
    elif role == "android-bundletool":
        value.update(kind="exact-pin", version=BUNDLETOOL_VERSION,
                     sha256=BUNDLETOOL_SHA256, maxBytes=BUNDLETOOL_MAX_BYTES)
    elif role == "apple-xcode":
        value.update(kind="exact-pin", version=XCODE_VERSION, build=XCODE_BUILD)
    return value


def environment_requirements(params: object) -> EnvironmentRequirementsResult:
    if (type(params) is not dict or len(params) != 3 or any(type(key) is not str for key in params)
            or set(params) != {"draft", "platform", "operation"}
            or type(params["draft"]) is not dict
            or type(params["platform"]) is not str or params["platform"] not in ("android", "ios")
            or type(params["operation"]) is not str or params["operation"] not in ("build", "artifact-validation")):
        raise ApiError("environment_request_invalid", REQUEST_ERROR)
    try:
        data = parse_config_text(bounded_json_text(params["draft"]))
    except ConfigurationError:
        raise ApiError("environment_draft_invalid", DRAFT_ERROR) from None
    platform = cast(EnvironmentPlatform, params["platform"])
    operation = cast(EnvironmentOperation, params["operation"])
    # These are inert value-wrapper paths. No filesystem method is called.
    config = ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data=data)
    enabled = config.platform_enabled(platform)
    rows: list[EnvironmentRequirement] = [
        {"id": role, "kind": _KINDS[role], "presence": "unknown", "versionState": "unknown",
         "inspection": "not-run", "baseline": _baseline(role), "help": dict(_HELP[role])}
        for role in (_ROLES[(platform, operation)] if enabled else ())
    ]
    host = ("linux" if sys.platform.startswith("linux") else "macos" if sys.platform == "darwin"
            else "windows" if sys.platform == "win32" else "other")
    result: EnvironmentRequirementsResult = {
        "schemaVersion": 1, "policyVersion": "environment-requirements-v1", "hostPlatform": host,
        "context": {"platform": platform, "operation": operation}, "platformEnabled": enabled,
        "state": "requirements-only" if enabled else "platform-disabled",
        "coverage": "toolchain-prerequisites-only", "nativeInspection": "unavailable",
        "dependencyCompleteness": "unknown", "requirements": rows,
        "help": {
            "platform": _help("Release platform", "The release target whose requirements you want to understand.",
                              "Android and iOS need different toolchains, even when they share a project.",
                              "Choose a target enabled in your current Project settings draft.", "Android or iOS; this is not the host operating system.",
                              "A disabled target has no applicable requirements here. This choice does not enable a build."),
            "operation": _help("Activity", "The kind of prerequisites to display.",
                               "Building a project and validating an existing artifact need different tools.",
                               "Choose the activity you are preparing for; no command will run.", "Build/archive prerequisites or artifact-validation prerequisites.",
                               "Build guidance is not a complete signed release checklist. Final artifact checks, credentials and release gates remain separate."),
        },
        "limitations": [
            "Only known toolkit prerequisites are described. Custom preparation commands and project dependencies have not been inspected.",
            "All tool presence, versions and native behavior remain unknown. Expected baselines are policy, not observations.",
            "Build/archive prerequisites do not include every final artifact, credential, account, network or release-lifecycle check.",
            "iOS native operations require local or hosted macOS. Android Windows native execution remains separately unqualified.",
            "This screen neither installs nor selects tools. Native doctor, builds and release operations remain unavailable.",
            "Bundled-runtime and non-SDK helper delivery are separate requirements; normal Desktop use must not require a manual Python, Rust or CLI setup.",
        ],
        "assurance": assurance("schema-policy"),
    }
    # This fixed DATA remains comfortably below the whole-envelope 64-KiB cap.
    # Refuse accidental future help growth, rather than silently truncating it.
    try:
        bounded_json_text(result, max_bytes=_RESULT_LIMIT)
    except ConfigurationError:
        raise ApiError("environment_unavailable", UNAVAILABLE_ERROR) from None
    return result
