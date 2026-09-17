"""Core-owned help and requirement descriptors, never credential values."""
from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from ..config import ReleaseConfig
from ..credential_requirements import ENVIRONMENT_NAMES, requirements
from ..metadata import (ALLOWED_SUFFIXES, ANDROID_NOTE_LIMIT, MAX_ARCHIVE_SIZE,
                        MAX_FILE_COUNT, MAX_FILE_SIZE, REQUIRED_LOCALE_TEXT, TEXT_LIMITS)
from .contracts import ApiError, CatalogResult, CredentialHelp, RequirementDescriptor, assurance

_RESOURCE_LIMIT = 256 * 1024


def _resource(name: str) -> Any:
    # Names are fixed trusted code, never request fields or $schema URLs. The
    # engine's selected package origin selects these resources. Source/installed
    # callers use the same shipped bytes, not MOBILE_RELEASE_TOOLING_ROOT.
    if name not in {"field-help.json", "project.schema.json"}:
        raise ApiError("resource_unavailable", "Unknown bundled catalogue resource")
    try:
        with files("mobile_release.api").joinpath("data", name).open("rb") as source:
            raw = source.read(_RESOURCE_LIMIT + 1)
        if len(raw) > _RESOURCE_LIMIT:
            raise ValueError("resource bound")
        return json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        raise ApiError("resource_unavailable", "The bundled core catalogue is unavailable or invalid; no alternate resource was used") from error


def requirement_descriptors(data: dict[str, Any]) -> list[RequirementDescriptor]:
    # ReleaseConfig is only a typed data wrapper here. None of its filesystem
    # methods (project_path/release_version) is invoked.
    config = ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data=data)
    return [
        {"name": item.name, "kind": item.kind, "stage": item.stage, "platform": item.platform,
         "environment": ENVIRONMENT_NAMES[item.stage], "alternatives": list(item.alternatives),
         "reason": item.reason, "state": "unknown"}
        for item in requirements(config)
    ]


# This is presentation help, not material-validation policy. Actual requiredness
# and stage/platform selection above come exclusively from the shared core.
_CREDENTIAL_GUIDES = {
    "ANDROID_KEYSTORE_BASE64": (
        "Android candidate signing.", "Your existing upload-key keystore; use the future native asset importer.",
        "A supported keystore containing the intended private upload key; path/base64 are core alternatives, not proof of validity.",
    ),
    "ANDROID_KEYSTORE_PASSWORD": (
        "Android candidate signing.", "The password chosen when creating the upload keystore.",
        "A nonempty private keystore password, entered only through the future secure credential flow.",
    ),
    "ANDROID_KEY_ALIAS": (
        "Android candidate signing.", "The private-key entry alias in your upload keystore.",
        "1–255 letters, digits, underscores, dots or hyphens; native validation must confirm the entry.",
    ),
    "ANDROID_KEY_PASSWORD": (
        "Android candidate signing.", "The password for the selected private-key entry, which may differ from the store password.",
        "A nonempty private-key password; never put it in project configuration or command arguments.",
    ),
    "ANDROID_GOOGLE_SERVICES_JSON_BASE64": (
        "Android candidate builds when services.androidFirebase is required.",
        "Download google-services.json for this Android application from Firebase Project Settings.",
        "The original Firebase client JSON; later checks must bind its application identity. Import is not yet implemented.",
    ),
    "GOOGLE_WIF_PROVIDER": (
        "Each selected Android Store stage.", "The administrator-created Google workload identity provider bound to the protected GitHub workflow.",
        "projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER; never a service-account private key.",
    ),
    "GOOGLE_SERVICE_ACCOUNT": (
        "Each selected Android Store stage.", "The least-privileged Google service account granted the intended Play roles and federation access.",
        "A service-account email ending in .iam.gserviceaccount.com. IAM/Store access remains unverified.",
    ),
    "APPLE_DISTRIBUTION_P12_BASE64": (
        "iOS candidate signing.", "Export the approved Apple Distribution identity and private key from its existing secure owner.",
        "A PKCS#12 (.p12) file containing the distribution certificate and private key; future secure import keeps it outside the repository.",
    ),
    "APPLE_DISTRIBUTION_P12_PASSWORD": (
        "iOS candidate signing.", "The private password used when exporting the distribution P12.",
        "A nonempty private P12 password, not the Apple account password.",
    ),
    "APPLE_PROVISIONING_PROFILE_BASE64": (
        "iOS candidate signing.", "The App Store distribution provisioning profile for the approved app/team/certificate.",
        "The original .mobileprovision bytes; native profile authenticity and entitlement checks are separate.",
    ),
    "IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": (
        "iOS candidate builds when services.iosFirebase is required.",
        "Download GoogleService-Info.plist for the intended iOS app from Firebase Project Settings.",
        "The original Firebase client plist; its bundle identity must later be validated.",
    ),
    "ASC_PRIVATE_KEY_P8_BASE64": (
        "Each selected iOS Store stage.", "The existing App Store Connect API key downloaded by its authorized owner.",
        "The original private .p8 key, distinct from the distribution P12/profile. Future import must protect it outside project storage.",
    ),
    "ASC_KEY_ID": (
        "Each selected iOS Store stage.", "The Key ID shown for the selected App Store Connect API key.",
        "Exactly 10 uppercase letters or digits; not a private key or developer Team ID.",
    ),
    "ASC_ISSUER_ID": (
        "Each selected iOS Store stage.", "The Issuer ID for the selected App Store Connect API credentials.",
        "A UUID in 8-4-4-4-12 hexadecimal form; service access must still be checked.",
    ),
    "APPLE_REVIEW_CONTACT_FIRST_NAME": (
        "iOS external-testing and production review.", "An authorized private review contact reachable by Apple.",
        "The contact's nonempty first name; private review information, not public metadata.",
    ),
    "APPLE_REVIEW_CONTACT_LAST_NAME": (
        "iOS external-testing and production review.", "An authorized private review contact reachable by Apple.",
        "The contact's nonempty last name; private review information, not public metadata.",
    ),
    "APPLE_REVIEW_CONTACT_EMAIL": (
        "iOS external-testing and production review.", "An authorized private review contact reachable by Apple.",
        "A valid review-contact email address; keep the value in protected credential storage.",
    ),
    "APPLE_REVIEW_CONTACT_PHONE": (
        "iOS external-testing and production review.", "An authorized private review contact reachable by Apple.",
        "A nonempty reachable review-contact telephone number; it is private review data.",
    ),
    "OPERATION_COMMITMENT_KEY_BASE64": (
        "iOS external-testing and production recovery commitments.", "A dedicated secure key generated and retained by the release owner, not derived from the P8 key.",
        "Canonical base64 decoding to exactly 32 bytes. Preserve the original key while incomplete operations can need recovery.",
    ),
    "OPERATION_COMMITMENT_KEY_VERSION": (
        "iOS external-testing and production recovery commitments.", "The retained version label for the matching private-state commitment key.",
        "1–64 letters, digits, underscores, dots or hyphens; preserve the key/version pairing.",
    ),
    "APPLE_DEMO_ACCOUNT_USERNAME": (
        "iOS external-testing and production when review.demoAccountRequired is true.",
        "A dedicated functioning account for App Review, supplied by the app owner.",
        "A nonempty private demo username; do not put it in public release notes or metadata.",
    ),
    "APPLE_DEMO_ACCOUNT_PASSWORD": (
        "iOS external-testing and production when review.demoAccountRequired is true.",
        "The password for the dedicated reviewer demo account.",
        "A nonempty private demo password; never place it in project configuration.",
    ),
    "PROJECT_READ_TOKEN": (
        "Candidate builds when source.projectReadTokenRequired is true.",
        "An explicitly authorized read-only token restricted to required private project dependencies.",
        "A private narrowly scoped token, never Store or general administrator authority.",
    ),
}


def _credential_catalog() -> list[CredentialHelp]:
    # Enumerate every policy branch using an in-memory selection description,
    # not a project, credential reader or claim that these inputs are configured.
    all_branches = {
        "android": {"enabled": True},
        "ios": {"enabled": True, "review": {"demoAccountRequired": True}},
        "services": {"androidFirebase": "required", "iosFirebase": "required"},
        "source": {"projectReadTokenRequired": True},
    }
    grouped: dict[str, CredentialHelp] = {}
    for descriptor in requirement_descriptors(all_branches):
        name = descriptor["name"]
        if name in grouped:
            grouped[name]["stages"].append(descriptor["stage"])
            continue
        guide = _CREDENTIAL_GUIDES.get(name.removeprefix("MOBILE_RELEASE_"))
        if guide is None:
            raise ApiError("resource_unavailable", "Bundled credential guidance is incomplete")
        when, where, format_help = guide
        grouped[name] = {
            "name": name, "kind": descriptor["kind"], "platform": descriptor["platform"],
            "stages": [descriptor["stage"]], "alternatives": descriptor["alternatives"],
            "requiredness": "conditional", "requiredWhen": when,
            "what": descriptor["reason"], "why": "Selected material is restricted by platform, stage and purpose; presence is never verification.",
            "where": where, "format": format_help,
            "failure": "Missing or invalid selected material blocks the applicable later flow. No values are collected, read or checked here.",
        }
    return list(grouped.values())


def catalog() -> CatalogResult:
    schema, fields = _resource("project.schema.json"), _resource("field-help.json")
    if not isinstance(schema, dict) or schema.get("$id") != "urn:mobile-release-kit:schema:project:1" or not isinstance(fields, list):
        raise ApiError("resource_unavailable", "The bundled core catalogue has an incompatible shape")
    return {
        "schemaVersion": 1, "schema": schema, "fields": fields,
        "credentials": _credential_catalog(),
        "metadata": {
            "requiredLocaleText": {platform: list(names) for platform, names in REQUIRED_LOCALE_TEXT.items()},
            "textLimits": dict(TEXT_LIMITS), "androidReleaseNoteLimit": ANDROID_NOTE_LIMIT,
            "maxFileBytes": MAX_FILE_SIZE, "maxFiles": MAX_FILE_COUNT,
            "maxArchiveBytes": MAX_ARCHIVE_SIZE, "supportedSuffixes": sorted(ALLOWED_SUFFIXES),
            "assurance": "format-rules-only",
        },
        "assurance": assurance("schema-policy"),
    }
