"""Pure credential requirement descriptions; never reads material or probes services.

The release core and desktop catalogue share this policy. Importing this module
must not import process, native-signing, filesystem-custody or credential readers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .config import ReleaseConfig
from .errors import CredentialError

STAGES = ("candidate", "external-testing", "production")
ENVIRONMENT_NAMES = {
    "candidate": "mobile-candidate",
    "external-testing": "mobile-external-testing",
    "production": "mobile-production",
}


# Canonical remote input classifications. The existing requirements below
# derive their type from this same map; it does not decide applicability or
# authorize a read/write. Local *_PATH alternatives and arbitrary names are not
# GitHub environment fields.
ENVIRONMENT_INPUT_TYPES = {
    "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64": "secret",
    "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": "secret",
    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "secret",
    "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "variable",
    "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "secret",
    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD": "secret",
    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME": "secret",
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": "secret",
    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "secret",
    "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": "secret",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL": "secret",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME": "secret",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME": "secret",
    "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE": "secret",
    "MOBILE_RELEASE_ASC_ISSUER_ID": "variable",
    "MOBILE_RELEASE_ASC_KEY_ID": "variable",
    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "secret",
    "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT": "variable",
    "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER": "variable",
    "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": "secret",
    "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64": "secret",
    "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION": "variable",
    "MOBILE_RELEASE_PROJECT_READ_TOKEN": "secret",
}


@dataclass(frozen=True)
class Requirement:
    name: str
    kind: str  # secret, variable, file, or manual
    stage: str
    platform: str
    alternatives: tuple[str, ...] = ()
    reason: str = ""


def requirements(
    config: ReleaseConfig,
    stage: str = "all",
    *,
    purpose: str = "full",
    platforms: Iterable[str] | None = None,
) -> list[Requirement]:
    if stage != "all" and stage not in STAGES:
        raise CredentialError(f"unknown credential stage: {stage}")
    if purpose not in {"full", "signing", "store"}:
        raise CredentialError(f"unknown credential purpose: {purpose}")
    stages = STAGES if stage == "all" else (stage,)
    selected = set(platforms if platforms is not None else config.enabled_platforms)
    values: list[Requirement] = []
    for current in stages:
        if config.platform_enabled("android") and "android" in selected:
            if current == "candidate" and purpose in {"full", "signing"}:
                values.extend(
                    [
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64"],
                            current,
                            "android",
                            alternatives=("MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",),
                            reason="Android release signing key",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"],
                            current,
                            "android",
                            reason="Android keystore password",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ANDROID_KEY_ALIAS"],
                            current,
                            "android",
                            reason="Android private-key alias",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ANDROID_KEY_PASSWORD"],
                            current,
                            "android",
                            reason="Android private-key password",
                        ),
                    ]
                )
                if config.section("services").get("androidFirebase") == "required":
                    values.append(
                        Requirement(
                            "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64"],
                            current,
                            "android",
                            alternatives=("MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",),
                            reason="Android Firebase client configuration",
                        )
                    )
            if purpose in {"full", "store"}:
                values.extend(_google_requirements(current))

        if config.platform_enabled("ios") and "ios" in selected:
            if current == "candidate" and purpose in {"full", "signing"}:
                values.extend(
                    [
                        Requirement(
                            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64"],
                            current,
                            "ios",
                            alternatives=("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH",),
                            reason="Apple distribution certificate and private key",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD"],
                            current,
                            "ios",
                            reason="Apple P12 password",
                        ),
                        Requirement(
                            "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64"],
                            current,
                            "ios",
                            alternatives=("MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH",),
                            reason="App Store provisioning profile",
                        ),
                    ]
                )
                if config.section("services").get("iosFirebase") == "required":
                    values.append(
                        Requirement(
                            "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64",
                            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64"],
                            current,
                            "ios",
                            alternatives=("MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH",),
                            reason="iOS Firebase client configuration",
                        )
                    )
            if purpose in {"full", "store"}:
                values.extend(_apple_api_requirements(current))
            if purpose in {"full", "store"} and current in {"external-testing", "production"}:
                values.extend(_apple_review_requirements(current, config))

        if (
            current == "candidate"
            and purpose in {"full", "signing"}
            and config.section("source").get("projectReadTokenRequired")
        ):
            values.append(
                Requirement(
                    "MOBILE_RELEASE_PROJECT_READ_TOKEN",
                    ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_PROJECT_READ_TOKEN"],
                    current,
                    "project",
                    reason="Read-only project dependency access",
                )
            )
    return values


def _google_requirements(stage: str) -> list[Requirement]:
    return [
        Requirement(
            "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER",
            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_GOOGLE_WIF_PROVIDER"],
            stage,
            "android",
            reason="Google Workload Identity provider",
        ),
        Requirement(
            "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT",
            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT"],
            stage,
            "android",
            reason="Least-privileged Google service-account email",
        ),
    ]


def _apple_api_requirements(stage: str) -> list[Requirement]:
    return [
        Requirement(
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"],
            stage,
            "ios",
            alternatives=("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH",),
            reason="App Store Connect API private key",
        ),
        Requirement(
            "MOBILE_RELEASE_ASC_KEY_ID",
            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ASC_KEY_ID"],
            stage,
            "ios",
            reason="App Store Connect API key ID",
        ),
        Requirement(
            "MOBILE_RELEASE_ASC_ISSUER_ID",
            ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_ASC_ISSUER_ID"],
            stage,
            "ios",
            reason="App Store Connect API issuer ID",
        ),
    ]


def _apple_review_requirements(stage: str, config: ReleaseConfig) -> list[Requirement]:
    requirements = [
        Requirement(
            name,
            ENVIRONMENT_INPUT_TYPES[name],
            stage,
            "ios",
            reason="Private App Review contact information",
        )
        for name in (
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME",
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_LAST_NAME",
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL",
            "MOBILE_RELEASE_APPLE_REVIEW_CONTACT_PHONE",
        )
    ]
    requirements.extend(
        [
            Requirement(
                "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64",
                ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64"],
                stage,
                "ios",
                reason="HMAC key binding private Apple review state to recoverable operations",
            ),
            Requirement(
                "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION",
                ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION"],
                stage,
                "ios",
                reason="Version of the retained private-state commitment key",
            ),
        ]
    )
    if config.section("ios").get("review", {}).get("demoAccountRequired"):
        requirements.extend(
            [
                Requirement(
                    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME",
                    ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME"],
                    stage,
                    "ios",
                    reason="Private App Review demo-account username",
                ),
                Requirement(
                    "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD",
                    ENVIRONMENT_INPUT_TYPES["MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD"],
                    stage,
                    "ios",
                    reason="Private App Review demo-account password",
                ),
            ]
        )
    return requirements


def local_requirements(
    config: ReleaseConfig,
    stage: str = "all",
    *,
    purpose: str = "full",
    platforms: Iterable[str] | None = None,
) -> list[Requirement]:
    """The existing local Store policy uses ADC, not the pre-auth WIF pair."""
    requested = requirements(config, stage, purpose=purpose, platforms=platforms)
    if purpose != "store":
        return requested
    wif = {"MOBILE_RELEASE_GOOGLE_WIF_PROVIDER", "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT"}
    google_stages = {item.stage for item in requested if item.platform == "android" and item.name in wif}
    requested = [item for item in requested if not (item.platform == "android" and item.name in wif)]
    requested.extend(
        Requirement(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "file",
            current_stage,
            "android",
            reason="Local read-only Google Application Default Credentials file",
        )
        for current_stage in sorted(google_stages)
    )
    return requested
