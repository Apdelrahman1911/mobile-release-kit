from __future__ import annotations

import json
from pathlib import Path


def android_config(*, status: str = "approved", fingerprint: str = "a" * 64) -> dict:
    android = {
        "enabled": True,
        "applicationId": "com.example.reader",
        "identityStatus": status,
        "module": ":app",
        "variant": "release",
    }
    if status == "approved":
        android.update(
            {
                "externalTrack": {"name": "closed-testing", "kind": "closed"},
                "uploadCertificateSha256": fingerprint,
            }
        )
    return {
        "$schema": "https://example.invalid/project.schema.json",
        "schemaVersion": 1,
        "version": {
            "source": "release/version.properties",
            "nameKey": "VERSION_NAME",
            "buildKey": "BUILD_NUMBER",
        },
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": android,
        "ios": {"enabled": False},
        "metadata": {
            "root": "release/store",
            "androidLocales": ["en-US"],
            "iosLocales": [],
        },
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def ios_config(*, demo: bool = False) -> dict:
    value = android_config()
    value["android"] = {"enabled": False}
    value["ios"] = {
        "enabled": True,
        "bundleId": "com.example.reader",
        "identityStatus": "approved",
        "appStoreAppId": "1234567890",
        "teamId": "ABCDE12345",
        "project": "iosApp/Reader.xcodeproj",
        "scheme": "Reader",
        "archiveConfiguration": "Release",
        "externalTestFlightGroup": "External Testers",
        "distributionCertificateSha256": "b" * 64,
        "symbols": {"policy": "retain"},
        "review": {"usesNonExemptEncryption": False, "demoAccountRequired": demo},
    }
    value["metadata"]["androidLocales"] = []
    value["metadata"]["iosLocales"] = ["en-US"]
    return value


def write_project(root: Path, value: dict, *, platform: str = "android") -> Path:
    (root / ".git").mkdir(parents=True)
    (root / ".gitignore").write_text("/.mobile-release/\n", encoding="utf-8")
    (root / "release").mkdir(parents=True)
    (root / "release/version.properties").write_text(
        "VERSION_NAME=1.2.3\nBUILD_NUMBER=42\n", encoding="utf-8"
    )
    metadata = root / f"release/store/{platform}/en-US"
    metadata.mkdir(parents=True)
    required_text = {
        "android": {
            "title.txt": "Reader",
            "short_description.txt": "Read safely on every device.",
            "full_description.txt": "A real application description.",
            "changelogs/default.txt": "Reliability improvements.",
        },
        "ios": {
            "description.txt": "A real application description.",
            "keywords.txt": "reader,books,library",
            "privacy_url.txt": "https://example.test/privacy",
            "support_url.txt": "https://example.test/support",
            "release_notes.txt": "Reliability improvements.",
        },
    }
    for name, content in required_text[platform].items():
        (metadata / name).parent.mkdir(parents=True, exist_ok=True)
        (metadata / name).write_text(content + "\n", encoding="utf-8")
    if platform == "ios":
        review = root / "release/store/review"
        testflight = root / "release/store/testflight"
        review.mkdir(parents=True)
        testflight.mkdir(parents=True)
        (review / "ios-beta-notes.txt").write_text(
            "Use the main reader flow and report regressions.\n", encoding="utf-8"
        )
        (review / "ios-notes.txt").write_text(
            "No special review instructions are required.\n", encoding="utf-8"
        )
        (testflight / "what-to-test.txt").write_text(
            "Verify sign-in, library browsing, and offline reading.\n", encoding="utf-8"
        )
    if platform == "android":
        (root / "app").mkdir()
        (root / "app/build.gradle.kts").write_text(
            'plugins { id("com.android.application") }\n'
            'android { namespace = "com.example.reader"; defaultConfig { applicationId = "com.example.reader" }; '
            'buildTypes { debug { applicationIdSuffix = ".debug" } } }\n',
            encoding="utf-8",
        )
        (root / "gradlew").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    else:
        project = root / "iosApp/Reader.xcodeproj"
        project.mkdir(parents=True)
        (project / "project.pbxproj").write_text(
            "PRODUCT_BUNDLE_IDENTIFIER = com.example.reader;\n"
            "PRODUCT_BUNDLE_IDENTIFIER = com.example.reader.debug;\n",
            encoding="utf-8",
        )
        scheme = project / "xcshareddata/xcschemes/Reader.xcscheme"
        scheme.parent.mkdir(parents=True)
        scheme.write_text("<Scheme/>", encoding="utf-8")
    path = root / "release/mobile-release.json"
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path
