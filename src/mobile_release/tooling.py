from __future__ import annotations

import os
import shutil
import sysconfig
from pathlib import Path
from typing import Iterable, Mapping

from .config import ConfigurationError, ReleaseConfig
from .errors import ValidationError

REQUIRED_TOOLING_FILES = (
    "Gemfile",
    "Gemfile.lock",
    "fastlane/Fastfile",
    "fastlane/play_store.rb",
    "fastlane/apple_store.rb",
    "fastlane/apple_production.rb",
    "fastlane/apple_asset_upload.rb",
    "fastlane/apple_create_retry.rb",
    "fastlane/ios_upload_validation.rb",
    "fastlane/android_upload_validation.rb",
    "fastlane/native_upload_validation.rb",
    "fastlane/release_support.rb",
    "fastlane/run_lane.rb",
    "schemas/candidate.schema.json",
    "schemas/project.schema.json",
    "schemas/receipt.schema.json",
    "schemas/store-operation-intent.schema.json",
    "templates/mobile-release.json",
    "templates/workflows/mobile-candidate.yml",
    "templates/workflows/mobile-external-testing.yml",
    "templates/workflows/mobile-preflight.yml",
    "templates/workflows/mobile-production-submit.yml",
)


def canonical_external_path(path: Path, *, label: str) -> Path:
    """Resolve an external path while rejecting user-controlled symlink traversal.

    macOS exposes ``/var`` and ``/tmp`` as root-owned aliases into ``/private``.
    Those two exact aliases are safe and unavoidable for paths returned by the
    platform temporary-directory APIs. Any lower symlink component remains a
    hard failure.
    """

    absolute = Path(os.path.abspath(path.expanduser()))
    permitted_system_aliases = {
        candidate
        for candidate in (Path("/var"), Path("/tmp"))
        if candidate.is_symlink()
        and candidate.resolve() in {Path("/private/var"), Path("/private/tmp")}
    }
    lexical = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        lexical /= part
        if lexical.is_symlink() and lexical not in permitted_system_aliases:
            raise ValidationError(f"{label} must not traverse a symbolic link")
    return absolute.resolve(strict=True)


def _complete_tooling_root(path: Path) -> bool:
    if path.is_symlink() or not path.is_dir():
        return False
    for relative in REQUIRED_TOOLING_FILES:
        current = path
        parts = Path(relative).parts
        for index, part in enumerate(parts):
            current /= part
            if current.is_symlink():
                return False
            if index < len(parts) - 1 and (not current.is_dir()):
                return False
        if not current.is_file():
            return False
    return True


def resolve_tooling_root(
    *,
    environ: Mapping[str, str] | None = None,
    candidates: Iterable[Path] | None = None,
) -> Path | None:
    """Locate one pinned source checkout or the wheel-installed shared assets."""

    env = environ if environ is not None else os.environ
    if configured := env.get("MOBILE_RELEASE_TOOLING_ROOT"):
        try:
            resolved = Path(configured).expanduser().resolve(strict=True)
        except OSError:
            return None
        return resolved if _complete_tooling_root(resolved) else None
    search = candidates
    if search is None:
        search = (
            Path(__file__).resolve().parents[2],
            Path(sysconfig.get_path("data")) / "share/mobile-release-kit",
        )
    for candidate in search:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if _complete_tooling_root(resolved):
            return resolved
    return None


def recreate_private_build_directory(config: ReleaseConfig, platform: str) -> Path:
    """Recreate only one tool-owned build directory after rejecting symlink traversal."""

    if platform not in {"android", "ios"}:
        raise ValidationError(f"unsupported private build platform: {platform}")
    relative = f".mobile-release/build/{platform}"
    try:
        target = config.project_path(relative)
    except ConfigurationError as error:
        raise ValidationError(
            f"private build directory must not traverse a symbolic link: {relative}"
        ) from error
    root = config.root.resolve()
    lexical = root
    for part in Path(relative).parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise ValidationError(
                f"private build directory must not traverse a symbolic link: {relative}"
            )
        if lexical.exists() and not lexical.is_dir():
            raise ValidationError(f"private build path is not a directory: {relative}")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=False)
    return target
