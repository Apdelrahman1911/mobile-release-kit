from __future__ import annotations

import os
import shutil
import stat
import sysconfig
from contextlib import contextmanager
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
    "fastlane/native_process_spawn.rb",
    "fastlane/native_upload_process.rb",
    "fastlane/store_document.rb",
    "fastlane/store_lane_lifetime.rb",
    "fastlane/store_lane_resources.rb",
    "fastlane/store_lane_runtime.rb",
    "fastlane/store_lane_fastlane_bridges.rb",
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


def canonical_external_path(path: Path, *, label: str, cancellation=None) -> Path:
    """Observe a safe public-tool path for diagnostics, NEVER to authorize reuse.

    Consumers must use checked bytes or a live selected snapshot instead of
    reopening this returned path. The shared reader implements the same exact
    system-alias policy for public tools and explicitly private input kinds.
    """
    from .checked_files import inspect_external_path
    from .owned_process import ProcessError

    try:
        return inspect_external_path(path, kind="public-tool", project_root=None,
                                     cancellation=cancellation)
    except ProcessError:
        raise  # Descriptor/handler uncertainty is never an ordinary path error.
    except ValidationError:
        raise ValidationError(f"{label} must be a regular file without unsafe symbolic-link components") from None


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
        module = Path(__file__).resolve()
        source_root = module.parents[2]
        # The executing module selects one origin. An incomplete wheel must not
        # borrow checkout-like assets placed next to site-packages, and an
        # incomplete checkout must not silently borrow another installed release.
        search = (
            (source_root,)
            if module == source_root / "src/mobile_release/tooling.py"
            else (Path(sysconfig.get_path("data")) / "share/mobile-release-kit",)
        )
    for candidate in search:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if _complete_tooling_root(resolved):
            return resolved
    return None


@contextmanager
def private_build_directory(config: ReleaseConfig, platform: str, *, cancellation=None):
    """Reset one admitted original build target and retain custody across use.

    Keep the original target inode. Removing/reopening the top-level pathname
    would make an intervening replacement look like the output we admitted.
    Old tool-owned contents are cleared relative to the retained target fd;
    namespace admission itself grants no deletion rights to any other caller.
    """
    from .build_inputs import _app_private_directory, _directory, _file, _names

    if platform not in {"android", "ios"}:
        raise ValidationError(f"unsupported private build platform: {platform}")
    relative = f".mobile-release/build/{platform}"
    try:
        config.project_path(relative)
    except ConfigurationError as error:
        raise ValidationError(
            f"private build directory must not traverse a symbolic link: {relative}"
        ) from error
    root = config.root
    with _app_private_directory(root / relative, app_root=root, cancellation=cancellation) as namespace:
        assert namespace is not None
        parent = namespace.fd
        # Inspect every direct old child before the first destructive effect.
        # Nested generated archive directories are not required to be0700;
        # their private enclosing original target is the fixed rebuild scope.
        original = {}
        for name in _names(parent):
            observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not (stat.S_ISDIR(observed.st_mode) or stat.S_ISREG(observed.st_mode)):
                raise ValidationError("private build output contains an unsafe direct entry; preserve it")
            original[name] = observed
        namespace.check()
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValidationError("private build reset requires descriptor-relative directory removal")
        for name, before in original.items():
            namespace.cancellation.check()
            namespace.check()
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            observe = _directory if stat.S_ISDIR(before.st_mode) else _file
            if observe(current) != observe(before):
                raise ValidationError("private build output changed before reset; preserve it")
            if stat.S_ISDIR(before.st_mode):
                shutil.rmtree(name, dir_fd=parent)
            else:
                os.unlink(name, dir_fd=parent)
        if _names(parent):
            raise ValidationError("private build output changed during reset; preserve it")
        os.fsync(parent)
        namespace.check()
        namespace.cancellation.check()
        yield namespace
        namespace.check()


def recreate_private_build_directory(config: ReleaseConfig, platform: str, *, cancellation=None) -> Path:
    """Compatibility point-in-time reset; returned location is NOT live custody.

    Actual library builds use private_build_directory over reset, command and
    normalization. Other callers must independently reacquire before any use.
    """
    with private_build_directory(config, platform, cancellation=cancellation) as namespace:
        return namespace.path
