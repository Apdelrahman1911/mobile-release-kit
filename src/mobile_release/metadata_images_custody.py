"""Original configuration-bound image targets for the existing rooted writer.

This module adds a closed target descriptor, not another writer or lock owner.
The selected bytes and detached policy objects alone grant no filesystem
authority. Only the original InitRootLease may bind one descriptor inside its
first locked capture. Recovery has a separate inspected capability.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .config_edit import _PrivateAuthority
from .init_transaction import (IMAGE_STATE_NAMES, MAX_FILES, MAX_TOTAL_BYTES, InitConflict, InitWorkspace,
                               ObservedFile, TypedEditProfile, validate_paths)
from .metadata_images import (DEPENDENCY_LIMITS, DEPENDENCY_PATHS, MAX_IMAGE_BYTES,
                              MAX_SIBLINGS, MetadataImagesInputError, PublicImageSelection,
                              SelectedImage, admit_selected_images, content_digest,
                              name_key, protected_project_sources, public_image_selection,
                              safe_name, target_names)

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease

def _failure(reason: str):
    from .init_workspace_custody import _failure as failure
    return failure(reason)


@dataclass(frozen=True, slots=True)
class _FolderEntry:
    name: str
    kind: int
    device: int
    inode: int
    mode: int
    uid: int
    gid: int

    def data(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "device": self.device,
                "inode": self.inode, "mode": self.mode, "uid": self.uid, "gid": self.gid}


def _folder_entries(workspace: InitWorkspace, selection: PublicImageSelection,
                    *, planning: bool) -> tuple[_FolderEntry, ...]:
    """Inspect a complete finite local roster through the original owner.

    A synthetic leaf is only used to borrow its parent descriptor. It is never
    opened, created or an authority. Existing InitWorkspace owns all traversed
    directory descriptors and applies its no-follow/portable-name checks.
    """
    result = []
    with workspace._parent(selection.folder + "/.mrk-image-inventory", planning=planning) as folder:
        if folder is None:
            return ()
        # The existing directory primitive already has its global hard bound;
        # the image domain applies its much smaller complete-roster bound too.
        names = workspace._list(folder)
        if len(names) > MAX_SIBLINGS or len({name_key(name) for name in names}) != len(names):
            raise _failure("invalid_params")
        for name in sorted(names):
            workspace._checkpoint()
            try:
                if (not name or len(name.encode("utf-8")) > 255
                        or any(ord(c) < 32 or ord(c) == 127 for c in name)):
                    raise _failure("invalid_params")
            except UnicodeError:
                raise _failure("invalid_params") from None
            value = os.stat(name, dir_fd=folder, follow_symlinks=False)
            result.append(_FolderEntry(name, stat.S_IFMT(value.st_mode), value.st_dev,
                                       value.st_ino, stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid))
        if sorted(workspace._list(folder)) != sorted(names):
            raise InitConflict("image folder changed during complete inventory")
    return tuple(result)


def _relevant(selection: PublicImageSelection, entries: tuple[_FolderEntry, ...]) -> tuple[str, ...]:
    if selection.asset_type.singleton:
        names = tuple(entry.name for entry in entries
                      if entry.name.rsplit(".", 1)[0].casefold() == selection.asset_type.identity.casefold())
    else:
        names = tuple(entry.name for entry in entries)
    selected = set(names)
    if (any(not safe_name(name) for name in names)
            or any(entry.kind != stat.S_IFREG for entry in entries if entry.name in selected)):
        raise _failure("invalid_params")
    return names


class ImageTargets(_PrivateAuthority):
    """Immutable selected write roster and all read-only sibling observations."""

    __slots__ = ("_identity", "_lease", "_capture_workspace", "_selection", "_names",
                 "_dependencies", "_dependency_observations", "_raw", "_parents", "_parent_facts",
                 "_inventory", "_relevant_names", "_protected_sources", "_protected_objects")

    def __repr__(self) -> str:
        return "<ImageTargets>"

    @property
    def selection(self) -> PublicImageSelection:
        return self._selection

    @property
    def names(self) -> tuple[str, ...]:
        return self._names

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(self._selection.relative_path(name) for name in self._names)

    @property
    def directories(self) -> tuple[str, ...]:
        parts = self._selection.folder.split("/")
        return tuple("/".join(parts[:depth]) for depth in range(1, len(parts) + 1))

    @property
    def dependency_paths(self) -> tuple[str, ...]:
        return tuple(row[0] for row in self._dependencies)

    @property
    def dependency_limits(self) -> tuple[int, ...]:
        return (*DEPENDENCY_LIMITS, *((MAX_IMAGE_BYTES,) * (len(self._dependencies) - 2)))

    @property
    def payload_limits(self) -> tuple[int, ...]:
        return (MAX_IMAGE_BYTES,) * len(self.paths)

    @property
    def observation_paths(self) -> tuple[str, ...]:
        return (*self.dependency_paths, *self.paths)

    @property
    def observation_limits(self) -> tuple[int, ...]:
        return (*self.dependency_limits, *self.payload_limits)

    @property
    def dependency_observations(self) -> tuple[ObservedFile, ...]:
        # These are original objects retained inside the capture scope. They
        # are not reconstructed from renderer values or disk journal data.
        return self._dependency_observations

    @property
    def protected_sources(self) -> tuple[str, ...]:
        return self._protected_sources

    @property
    def dependency_only_parents(self) -> dict[str, dict[str, int] | None]:
        return {path: dict(value) if value is not None else None for path, value in self._parents
                if path not in self.directories}

    def _check_workspace(self, workspace: InitWorkspace) -> None:
        from .init_workspace_custody import LockedInitScope
        if (type(self) is not ImageTargets or self._identity is not self
                or type(workspace) is not InitWorkspace
                or workspace._typed_profile is not TypedEditProfile.METADATA_IMAGES
                or workspace._image_targets is not self
                or type(workspace._scope) is not LockedInitScope
                or workspace._scope is not self._lease._active
                or workspace._scope.lease is not self._lease
                or workspace._scope.workspace is not workspace
                or self._lease._image_targets is not self):
            raise _failure("invalid_params")

    def check_roster(self, workspace: InitWorkspace, *, initial: bool = False,
                     changing: str | None = None) -> None:
        """Permit only the current transaction's own target-name transitions."""
        self._check_workspace(workspace)
        if changing is not None and (self.selection.folder == changing
                                     or self.selection.folder.startswith(changing + "/")):
            # Only the existing writer's narrow failed-native-move restoration
            # check has a transient parent spelling. It must be an originally
            # absent, now owned transaction directory, never an existing image
            # folder or a generic caller-requested stale suppression.
            revision = self._lease._revision
            if (initial or revision is None or changing not in self.directories
                    or dict(revision._parents).get(changing, "unobserved") is not None
                    or self._inventory):
                raise InitConflict("image directory transition is not an original empty creation")
            return
        current = _folder_entries(workspace, self.selection, planning=False)
        if initial:
            unchanged = current == self._inventory
        else:
            selected = set(self.names)
            original_other = tuple(row for row in self._inventory if row.name not in selected)
            current_other = tuple(row for row in current if row.name not in selected)
            unchanged = original_other == current_other
        if not unchanged:
            raise InitConflict("selected image set or unrelated sibling names changed")

    def relevant_contents(self, originals: tuple[ObservedFile, ...]) -> tuple[tuple[str, bytes], ...]:
        combined = {row.path: row for row in (*self.dependency_observations, *originals)}
        rows = []
        for name in self._relevant_names:
            value = combined.get(self.selection.relative_path(name))
            if type(value) is not ObservedFile or value.before is None or type(value.data) is not bytes:
                raise _failure("custody_unknown")
            rows.append((name, value.data))
        return tuple(rows)

    def protected_target_paths(self, originals: tuple[ObservedFile, ...]) -> tuple[str, ...]:
        """Compare private original exclusions to the actual captured roster.

        All relevant siblings participate, but only already-derived target
        names are returned. Neither selected absolute paths nor object numbers
        enter the public preview or supply filesystem authority.
        """
        protected = {name_key(path) for path in self.protected_sources}
        objects = set(self._protected_objects)
        for item in (*self.dependency_observations, *originals):
            if item.before is not None and (item.before["device"], item.before["inode"]) in objects:
                protected.add(name_key(item.path))
        return tuple(path for path in self.paths if name_key(path) in protected)

    def check_payloads(self, changes: list[tuple[ObservedFile, bytes | None]]) -> None:
        protected = {name_key(path) for path in self.protected_sources}
        objects = set(self._protected_objects)
        if any(payload is not None and (name_key(item.path) in protected
                or item.before is not None and (item.before["device"], item.before["inode"]) in objects)
                for item, payload in changes):
            raise _failure("invalid_params")
        dependencies = sum(len(raw) for _, _, raw in self._dependencies)
        if dependencies + sum((item.before or {}).get("size", 0) + len(payload or b"")
                              for item, payload in changes) > MAX_TOTAL_BYTES:
            raise _failure("invalid_params")

    def journal_context(self) -> dict[str, Any]:
        """Closed image context needed for a separately inspected restoration.

        This persisted DATA is not enough to recover: restart admission also
        checks the complete plan, current files/staging/controls and root lock.
        """
        config, ignore = self._dependencies[:2]
        return {"policy": "metadata-images-v1", "platform": self.selection.platform,
                "locale": self.selection.locale, "assetType": self.selection.asset_type.identity,
                "metadataRoot": self.selection.metadata_root,
                "config": content_digest(config[2]), "ignore": content_digest(ignore[2]),
                "inventory": [row.data() for row in self._inventory],
                "siblings": [{"path": path, "binding": dict(binding)}
                             for path, binding, _ in self._dependencies[2:]]}


def bind_image_targets(lease: InitRootLease, workspace: InitWorkspace,
                       dependencies: tuple[ObservedFile, ...], platform: object, locale: object,
                       asset_type: object, images: tuple[SelectedImage, ...],
                       protected_sources: tuple[str, ...],
                       protected_objects: tuple[tuple[int, int], ...]) -> ImageTargets:
    """Called only by the original lease's closed image-domain method."""
    from .config_payloads import sufficient_ignore_rules
    from .init_transaction import IGNORE_LINES
    from .init_workspace_custody import InitRootLease
    from .metadata import check_metadata_text

    if type(lease) is not InitRootLease:
        raise _failure("invalid_params")
    lease.check()
    scope = lease._active
    if (lease.profile is not TypedEditProfile.METADATA_IMAGES or scope is None
            or scope.workspace is not workspace or type(workspace) is not InitWorkspace
            or workspace._typed_profile is not lease.profile or lease._revision is not None
            or lease._image_targets is not None or workspace._image_targets is not None
            or type(dependencies) is not tuple or len(dependencies) != 2
            or any(type(item) is not ObservedFile or item.path != path
                   or workspace._captured.get(path) is not item
                   for item, path in zip(dependencies, DEPENDENCY_PATHS))
            or set(workspace._captured) != set(DEPENDENCY_PATHS)
            or set(workspace._raw_observations) != set(DEPENDENCY_PATHS)
            or set(workspace.parents) != {"release"} or set(workspace._parent_facts) != {"release"}):
        raise _failure("invalid_params")
    try:
        admit_selected_images(images)
        admitted_sources = protected_project_sources(list(protected_sources))
        if (type(protected_objects) is not tuple or len(protected_objects) != len(images)
                or any(type(pair) is not tuple or len(pair) != 2
                       or any(type(value) is not int or not 0 <= value < 2**64 for value in pair)
                       for pair in protected_objects)
                or len(set(protected_objects)) != len(protected_objects)):
            raise MetadataImagesInputError()
    except (MetadataImagesInputError, TypeError):
        raise _failure("invalid_params") from None
    config, ignore = dependencies
    if config.before is None or type(config.data) is not bytes or not 0 < len(config.data) <= DEPENDENCY_LIMITS[0]:
        raise _failure("invalid_config")
    try:
        config_text = config.data.decode("utf-8")
        if any(code == "metadata.secret-pattern" for code, _ in check_metadata_text("mobile-release.json", config_text).issues):
            raise _failure("invalid_config")
        selection = public_image_selection(config_text, platform, locale, asset_type)
    except UnicodeError:
        raise _failure("invalid_config") from None
    except MetadataImagesInputError as error:
        raise _failure("invalid_params" if error.reason in {"invalid_params", "unsupported_type"} else "invalid_config") from None
    if (ignore.before is None or type(ignore.data) is not bytes or len(ignore.data) > DEPENDENCY_LIMITS[1]
            or not sufficient_ignore_rules(ignore.data, IGNORE_LINES)):
        raise _failure("ignore_conflict")
    workspace.require_clean()
    inventory = _folder_entries(workspace, selection, planning=True)
    relevant = _relevant(selection, inventory)
    try:
        names = target_names(selection, images, tuple(row.name for row in inventory))
    except MetadataImagesInputError:
        raise _failure("invalid_params") from None
    readonly = tuple(selection.relative_path(name) for name in relevant if name not in names)
    paths = tuple(selection.relative_path(name) for name in names)
    if len(DEPENDENCY_PATHS) + len(readonly) + len(paths) > MAX_FILES:
        raise _failure("invalid_params")
    validate_paths([*DEPENDENCY_PATHS, *readonly, *paths])
    sibling_observations = tuple(workspace.observe(path, limit=MAX_IMAGE_BYTES) for path in readonly)
    if any(row.before is None or type(row.data) is not bytes for row in sibling_observations):
        raise InitConflict("original image sibling disappeared during capture")
    all_dependencies = (*dependencies, *sibling_observations)
    dependency_directories = {"/".join(item.path.split("/")[:depth])
                              for item in all_dependencies for depth in range(1, len(item.path.split("/")))}
    targets = object.__new__(ImageTargets)
    for name, value in (
        ("_identity", targets), ("_lease", lease), ("_capture_workspace", workspace),
        ("_selection", selection), ("_names", names), ("_inventory", inventory),
        ("_relevant_names", relevant), ("_protected_sources", admitted_sources),
        ("_protected_objects", protected_objects),
        ("_dependency_observations", all_dependencies),
        ("_dependencies", tuple((item.path, tuple(sorted(item.before.items())), item.data) for item in all_dependencies)),
        ("_raw", tuple(sorted(workspace._raw_observations.items()))),
        ("_parents", tuple((path, tuple(sorted(value.items())) if value is not None else None)
                           for path, value in sorted(workspace.parents.items()) if path in dependency_directories)),
        ("_parent_facts", tuple((path, value) for path, value in sorted(workspace._parent_facts.items())
                                if path in dependency_directories)),
    ):
        object.__setattr__(targets, name, value)
    lease._image_targets = workspace._image_targets = targets
    targets.check_roster(workspace, initial=True)
    return targets
