"""Shared, passive setup guidance from the existing project snapshot.

This is deliberately not a weaker release validator. It runs no discovery,
tools, scripts, credential reads or Store requests, and grants no operation.
Both Desktop and its saved CLI observation may project this same result.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import (ANDROID_ID_RE, IOS_ID_RE, MAX_CONFIG_BYTES, ReleaseConfig,
                      _validate_relative_path, validate_config_data)
from ..discovery import (selected_android_details, selected_android_module,
                         selected_ios_container, selected_ios_scheme)
from ..errors import ConfigurationError
from ._json import bounded_json_text
from .contracts import ApiError, assurance

MAX_RESULT_BYTES = 16 * 1024
MAX_REQUIREMENTS = 32
STAGES = ("local", "signing", "store", "automation")
STATES = ("configured", "detected", "needs-input", "ambiguous", "unverified",
          "unsupported", "blocked", "deferred", "not-checked")
REQUIREMENT_IDS = (
    "project-layout", "release-settings", "version-source",
    "android-identity", "android-module", "android-variant", "android-tools",
    "android-signing", "android-store", "android-testing",
    "ios-identity", "ios-container", "ios-scheme", "ios-configuration", "ios-tools",
    "ios-signing", "ios-store", "ios-testing", "store-metadata", "github-automation",
)
LIMITATIONS = (
    "This is setup guidance, not a passed preflight, build, signing check or release approval.",
    "Static hints do not prove the effective Gradle variant, Xcode target or application identity.",
    "Native Android/iOS and conventional KMP/CMP platform layouts are covered; framework identity is not inferred from nested build files.",
    "The separate unsigned Android build and unsigned iOS archive do not require Store account setup; their own tool, input and safety checks still apply.",
    "Full release preflight has additional Store-policy requirements; local setup or local project checks do not replace it.",
    "No tool, credential, Store account, metadata file or release version value was inspected by this analysis.",
)


def _invalid() -> ApiError:
    return ApiError("setup_analysis_invalid", "The supplied setup observation is invalid or exceeds its bound.")


def _text(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 512
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _reference(value: object) -> str | None:
    if not _text(value) or len(value.encode("utf-8")) > 512:
        return None
    try:
        _validate_relative_path(value, "setup.reference")
    except ConfigurationError:
        return None
    return value


def _admit_hints(hints: object) -> dict[str, Any]:
    # The real snapshot's finite parser produces exactly these public hints.
    # Strings are never interpreted as commands or native path authority.
    if type(hints) is not dict or set(hints) - {
        "android", "ios", "versionSource", "versionNameKey", "versionBuildKey"
    }:
        raise _invalid()
    try:
        bounded_json_text(hints, max_bytes=512 * 1024, max_nodes=8192, max_depth=8)
    except ConfigurationError:
        raise _invalid() from None
    for key in ("versionSource", "versionNameKey", "versionBuildKey"):
        if key in hints and not _text(hints[key]):
            raise _invalid()
    android = hints.get("android")
    if "android" in hints:
        if type(android) is not dict:
            raise _invalid()
        if "ambiguous" in android:
            if (set(android) - {"ambiguous", "candidates"} or android["ambiguous"] is not True
                    or type(android.get("candidates", [])) is not list or len(android.get("candidates", [])) > 128):
                raise _invalid()
            # A partial snapshot may have omitted every candidate, but must
            # retain the ambiguity instead of selecting an arbitrary survivor.
            candidates = android.get("candidates", [])
        else:
            candidates = [android]
        for candidate in candidates:
            if type(candidate) is not dict or set(candidate) - {
                "module", "buildFile", "applicationId", "namespace", "debugApplicationIdSuffix"
            } or any(value is not None and not _text(value) for value in candidate.values()):
                raise _invalid()
    ios = hints.get("ios")
    if "ios" in hints:
        lists = {"projects", "workspaces", "schemes", "bundleIds", "generatedProjectSources"}
        if type(ios) is not dict or set(ios) - (lists | {"bundleId", "project", "workspace", "scheme"}):
            raise _invalid()
        for key, value in ios.items():
            if key in lists:
                if type(value) is not list or len(value) > 128 or not all(_text(item) for item in value):
                    raise _invalid()
            elif not _text(value):
                raise _invalid()
    return hints


def analyze_setup(configuration_state: object, data: object, hints: object, *, partial: object) -> dict[str, Any]:
    """Project local requirements before later signing/Store/automation stages.

    ``configuration_state`` and ``data`` come from the SAME config observation;
    ``hints`` and ``partial`` come from its existing discovery. These remain
    input assertions, not freshness or filesystem authority. No defaults are
    saved, examples invented, identities approved, or missing tools installed.
    """
    if (type(configuration_state) is not str
            or configuration_state not in {"missing", "invalid", "format-valid", "unavailable"}
            or type(partial) is not bool):
        raise _invalid()
    config: ReleaseConfig | None = None
    if configuration_state == "format-valid":
        try:
            bounded_json_text(data, max_bytes=MAX_CONFIG_BYTES)
            validate_config_data(data)
        except ConfigurationError:
            raise _invalid() from None
        # Inert value wrapper for the actual shared selectors. No Path IO.
        config = ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data=data)
    elif data is not None:
        raise _invalid()
    found = _admit_hints(hints)
    platforms = [platform for platform in ("android", "ios") if (
        config.platform_enabled(platform) if config is not None else bool(found.get(platform)))]
    rows: list[dict[str, Any]] = []

    def row(identifier: str, stage: str, state: str, summary: str,
            field: str | None = None, reference: object = None) -> None:
        rows.append({"id": identifier, "stage": stage, "state": state,
                     "field": field, "reference": _reference(reference), "summary": summary})

    absent = "unverified" if partial else "needs-input"
    android_hints = found.get("android", {})
    ios_hints = found.get("ios", {})
    layout_detected = (
        "android" in platforms and bool(android_hints.get("buildFile") or any(
            candidate.get("buildFile") for candidate in android_hints.get("candidates", [])))
        or "ios" in platforms and any(ios_hints.get(key) for key in ("projects", "workspaces", "generatedProjectSources"))
    )
    row("project-layout", "local", "detected" if layout_detected else absent,
        "Android or Xcode layout hints can guide local setup; confirm the intended app target."
        if layout_detected else "No supported app target was detected in this read. A saved platform setting is not a discovered layout. Choose the Android app module or Xcode project and shared scheme; dynamic/generated layouts are not guessed.")
    row("release-settings", "local",
        {"format-valid": "configured", "missing": "needs-input", "invalid": "needs-input", "unavailable": "unverified"}[configuration_state],
        {"format-valid": "Saved settings are format-valid. An unverified identity may be used to prepare a local unsigned build; this does not approve Store ownership.",
         "missing": "Create and review the local release settings. Keep identity unverified until ownership is checked; Store IDs and testing tracks can wait.",
         "invalid": "Correct the saved settings. Local guidance does not excuse invalid supplied Store fields or relax the configuration schema.",
         "unavailable": "Saved settings could not be read. Preserve existing files and refresh before deciding that anything is missing."}[configuration_state],
        reference="release/mobile-release.json")
    version_source = config.section("version").get("source") if config else found.get("versionSource")
    row("version-source", "local", "configured" if config else "detected" if _reference(version_source) else absent,
        "Choose one version source and read its name/build values before building. This analysis only sees the source setting or hint, not those values.",
        "version.source", version_source)

    if "android" in platforms:
        android = config.section("android") if config else {}
        # Reuse actual selector semantics, including explicit selection among
        # multiple app modules; never silently choose the first candidate.
        value_config = config or ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data={})
        details = selected_android_details(value_config, found)
        module = selected_android_module(value_config, found)
        identity = android.get("applicationId") or details.get("applicationId")
        static_android = found.get("android", {})
        ambiguous = bool(static_android.get("ambiguous")) and not android.get("module")
        row("android-identity", "local", "configured" if android.get("applicationId") else
            "detected" if type(identity) is str and ANDROID_ID_RE.fullmatch(identity) else "ambiguous" if ambiguous else absent,
            "Use the actual Application ID, not namespace. Dynamic IDs and multiple variants need explicit review; no source package is renamed.",
            "android.applicationId", details.get("buildFile"))
        row("android-module", "local", "configured" if android.get("module") else "detected" if module else "ambiguous" if ambiguous else absent,
            "Save the explicit Gradle application module before the Desktop build. A static hint does not prove the effective variant or execute Gradle.",
            "android.module", details.get("buildFile"))
        row("android-variant", "local", "configured" if android.get("variant") else "not-checked",
            "Choose the intended variant. The build owner's release default is a default, not an observed project variant.", "android.variant")
        row("android-tools", "local", "not-checked",
            "Check a project-compatible JDK, the project Gradle wrapper and required Android SDK components. Reuse compatible installations; none were probed here.")
        row("android-signing", "signing", "not-checked",
            "For a signed build, reuse the app's existing upload key and verify its certificate. Vault presence and a configured fingerprint are not a signing check.",
            "android.uploadCertificateSha256")
        row("android-store", "store", "blocked" if android.get("identityStatus") == "blocked" else "deferred",
            "This identity is explicitly blocked for Store use; do not publish or silently change it."
            if android.get("identityStatus") == "blocked" else
            "Before Google Play operations, verify app ownership and the authorized account. Local unsigned builds do not require this Store setup.", "android.identityStatus")
        row("android-testing", "store", "configured" if android.get("externalTrack") else "deferred",
            "Configure the intended Play testing track when preparing testing delivery. This setting neither creates a track nor verifies access.", "android.externalTrack")

    if "ios" in platforms:
        ios = config.section("ios") if config else {}
        ios_found = found.get("ios", {})
        value_config = config or ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data={})
        container = selected_ios_container(value_config, found)
        scheme = selected_ios_scheme(value_config, found)
        identity = ios.get("bundleId") or ios_found.get("bundleId")
        generated_only = bool(ios_found.get("generatedProjectSources")) and not container
        containers = ios_found.get("workspaces", []) or ios_found.get("projects", [])
        row("ios-identity", "local", "configured" if ios.get("bundleId") else
            "detected" if type(identity) is str and IOS_ID_RE.fullmatch(identity) else
            "ambiguous" if len(ios_found.get("bundleIds", [])) > 1 else absent,
            "Choose the actual app Bundle ID. Extension targets and generated or dynamic settings need separate supported-target review.", "ios.bundleId")
        row("ios-container", "local", "configured" if ios.get("project") or ios.get("workspace") else
            "detected" if container else "unverified" if generated_only and partial else "unsupported" if generated_only else "ambiguous" if len(containers) > 1 else absent,
            "A generator definition was seen, but this read is incomplete. Refresh or select an existing supported project; an omitted Xcode container is not proven absent."
            if generated_only and partial else
            "Only a generator definition was found. Produce and select a supported Xcode project using its reviewed setup; this guide never executes the generator."
            if generated_only else "Select the actual Xcode project or workspace. Multiple containers are not chosen automatically; a static path is not proof it is usable.",
            "ios.workspace" if container and container[0] == "workspace" else "ios.project",
            container[1] if container else (ios_found.get("generatedProjectSources") or [None])[0])
        row("ios-scheme", "local", "configured" if ios.get("scheme") else "detected" if scheme else
            "ambiguous" if len(ios_found.get("schemes", [])) > 1 else absent,
            "Save the app's shared archive scheme before the Desktop archive. Scheme and target compatibility are checked by the separate native operation.", "ios.scheme")
        row("ios-configuration", "local", "configured" if ios.get("archiveConfiguration") else "not-checked",
            "Choose the archive configuration. Release is the existing default, not an observed or validated Xcode configuration.", "ios.archiveConfiguration")
        row("ios-tools", "local", "not-checked",
            "Use macOS with a compatible, admitted Xcode installation. Check existing installations before setup; no Xcode version or platform was inspected here.")
        row("ios-signing", "signing", "not-checked",
            "A signed archive/export needs the correct team, reusable certificate/private key and matching provisioning profiles. An unsigned archive needs no Store account.", "ios.teamId")
        row("ios-store", "store", "blocked" if ios.get("identityStatus") == "blocked" else "deferred",
            "This identity is explicitly blocked for Store use; do not publish or silently change it."
            if ios.get("identityStatus") == "blocked" else
            "Before TestFlight/App Store operations, verify ownership, the App Store app identifier and authorized account. These are later than local unsigned setup.", "ios.appStoreAppId")
        row("ios-testing", "store", "configured" if ios.get("externalTestFlightGroup") else "deferred",
            "Set the TestFlight group, review information and encryption policy when preparing Store delivery. No group or provider permission was checked.", "ios.externalTestFlightGroup")

    if platforms:
        row("store-metadata", "store", "deferred",
            "Prepare localized Store text, images and required policies before delivery. A metadata folder setting does not prove its files are complete.",
            "metadata.root", config.section("metadata").get("root") if config else None)
    row("github-automation", "automation", "deferred",
        "GitHub automation is optional for local setup. Later, select the account/repository and preview workflow changes; no connection or repository change happened here.")
    result = {"schemaVersion": 1, "scope": "local-setup-guidance",
              "configurationState": configuration_state, "discoveryPartial": partial,
              "platforms": platforms, "requirements": rows, "limitations": list(LIMITATIONS),
              "assurance": assurance("static-text")}
    if len(rows) > MAX_REQUIREMENTS:
        raise _invalid()
    try:
        bounded_json_text(result, max_bytes=MAX_RESULT_BYTES, max_nodes=2048, max_depth=8)
    except ConfigurationError:
        raise _invalid() from None
    return result
