"""Pure initialization layout shared by CLI and Desktop preparation.

This module grants no filesystem, transaction, overwrite or recovery authority.
The existing workflow/configuration/ignore byte policies live in their shared
payload modules; only the metadata skeleton policy is defined here.
"""
from __future__ import annotations

from typing import Any, Mapping

from .errors import ValidationError


def metadata_skeleton(
    configuration: Mapping[str, Any], *, max_paths: int | None = None
) -> tuple[str, ...]:
    """Return the shared relative skeleton; no files are observed or created.

    Configuration admission and complete target/parent/byte quotas belong to the
    caller. The optional count limit refuses before materializing locale paths.
    Omitting it preserves the CLI initialization policy, including its ordering.
    """
    metadata = configuration.get("metadata", {})
    if max_paths is not None:
        if type(max_paths) is not int or max_paths < 0:
            raise ValidationError("metadata skeleton path limit must be a nonnegative integer")
        count = 0
        if configuration.get("android", {}).get("enabled"):
            count += 4 * len(metadata.get("androidLocales", []))
        if configuration.get("ios", {}).get("enabled"):
            count += 5 * len(metadata.get("iosLocales", [])) + 3
        if count > max_paths:
            raise ValidationError("metadata skeleton exceeds the permitted path count")
    root = str(metadata.get("root", "release/store")).rstrip("/")
    paths: list[str] = []
    if configuration.get("android", {}).get("enabled"):
        for locale in metadata.get("androidLocales", []):
            paths.extend(
                f"{root}/android/{locale}/{name}"
                for name in (
                    "title.txt", "short_description.txt", "full_description.txt", "changelogs/default.txt"
                )
            )
    if configuration.get("ios", {}).get("enabled"):
        for locale in metadata.get("iosLocales", []):
            paths.extend(
                f"{root}/ios/{locale}/{name}"
                for name in (
                    "description.txt",
                    "keywords.txt",
                    "privacy_url.txt",
                    "support_url.txt",
                    "release_notes.txt",
                )
            )
        paths.extend(
            (
                f"{root}/review/ios-beta-notes.txt",
                f"{root}/review/ios-notes.txt",
                f"{root}/testflight/what-to-test.txt",
            )
        )
    return tuple(sorted(paths))
