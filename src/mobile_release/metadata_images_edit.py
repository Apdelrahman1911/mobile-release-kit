"""One-shot public-image preview/import through the existing native edit owner.

No selected source pathname is a destination. The original lease derives the
closed target set from saved configuration and preserves complete sibling
observations; only the typed InitWorkspace writer publishes files. Renderer
projections contain image metadata, never pixels, base64 or absolute paths.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from . import config_edit as _shared
from .api._json import bounded_json_text
from .config_edit import ConfigEditFailure, CoreEditOutcome
from .init_transaction import TypedEditProfile
from .metadata_images import (DEPENDENCY_LIMITS, DEPENDENCY_PATHS, MAX_IMAGE_BYTES,
                              MAX_PREPARED_BYTES, MetadataImagesInputError,
                              PublicImageSelection, SelectedImage, admit_baseline,
                              admit_selected_images, baseline, import_view,
                              protected_project_sources, protected_source_objects, replacement_choices)

if TYPE_CHECKING:
    from .init_workspace_custody import InitRootLease, RootedRevision
    from .metadata_images_custody import ImageTargets


class MetadataImagesCheckout(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_lease", "_revision", "_revision_token", "_targets",
                 "_dependencies", "_files", "_images", "_observed", "_baseline_json",
                 "_view_json", "_state", "_prepared", "_protected_paths")
    _lease: InitRootLease
    _revision: RootedRevision
    _targets: ImageTargets
    _images: tuple[SelectedImage, ...]

    def __repr__(self) -> str:
        return "<MetadataImagesCheckout>"

    @property
    def intent(self) -> str:
        return "import"

    @property
    def revision(self) -> str:
        return self._revision_token

    @property
    def baseline(self) -> dict[str, Any]:
        return json.loads(self._baseline_json)

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


class PreparedMetadataImagesEdit(_shared._PrivateAuthority):
    __slots__ = ("_identity", "_checkout", "_token", "_payloads", "_view_json", "_state")
    _checkout: MetadataImagesCheckout

    def __repr__(self) -> str:
        return "<PreparedMetadataImagesEdit>"

    @property
    def intent(self) -> str:
        return "import"

    @property
    def token(self) -> str:
        return self._token

    @property
    def revision(self) -> str:
        return self._checkout.revision

    @property
    def view(self) -> dict[str, Any]:
        return json.loads(self._view_json)


def _authentic_checkout(value: object) -> bool:
    return type(value) is MetadataImagesCheckout and getattr(value, "_identity", None) is value


def _authentic_plan(value: object) -> bool:
    return (type(value) is PreparedMetadataImagesEdit and getattr(value, "_identity", None) is value
            and _authentic_checkout(getattr(value, "_checkout", None))
            and getattr(value._checkout, "_prepared", None) is value)


def _lease_matches(native: _shared._NativeContract, lease: object) -> bool:
    return type(lease) is native.lease and getattr(lease, "profile", None) is TypedEditProfile.METADATA_IMAGES


def _admit_revision(native: _shared._NativeContract, revision: object, targets: object) -> None:
    from .metadata_images_custody import ImageTargets
    if (type(revision) is not native.revision or revision.profile is not TypedEditProfile.METADATA_IMAGES
            or type(revision.token) is not str or _shared._TOKEN.fullmatch(revision.token) is None
            or type(targets) is not ImageTargets or getattr(targets, "_identity", None) is not targets
            or getattr(revision, "_image_targets", None) is not targets
            or type(targets.selection) is not PublicImageSelection):
        raise _shared._ContractViolation()


def _encode_view(value: dict[str, Any]) -> bytes:
    return bounded_json_text(value, max_bytes=MAX_PREPARED_BYTES, max_nodes=16384,
                             max_depth=16).encode("utf-8")


def capture_metadata_images_edit(lease: InitRootLease, platform: object, locale: object,
                                 asset_type: object, images: tuple[SelectedImage, ...],
                                 protected_sources: object, protected_objects: object) -> MetadataImagesCheckout:
    """The caller is the private native protocol after one-use batch transfer."""
    try:
        images = admit_selected_images(images)
        protected = protected_project_sources(protected_sources)
        objects = protected_source_objects(protected_objects, len(images))
    except MetadataImagesInputError:
        _shared._reject("invalid_params")
    try:
        native = _shared._native_contract()
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None
    if not _lease_matches(native, lease):
        _shared._reject("invalid_params")
    try:
        with lease.workspace_scope() as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            dependencies = tuple(workspace.observe(path, limit=limit)
                                 for path, limit in zip(DEPENDENCY_PATHS, DEPENDENCY_LIMITS))
            targets = lease.bind_image_targets(workspace, dependencies, platform, locale,
                                                asset_type, images, protected, objects)
            originals = tuple(workspace.observe(path, limit=MAX_IMAGE_BYTES) for path in targets.paths)
            targets.check_roster(workspace, initial=True)
            revision = lease.bind_revision(workspace, (*targets.dependency_observations, *originals))
    except BaseException as error:
        raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
    try:
        _admit_revision(native, revision, targets)
        captured_dependencies = tuple(_shared._snapshot(item, path, limit) for item, path, limit in
                                      zip(targets.dependency_observations, targets.dependency_paths,
                                          targets.dependency_limits))
        files = tuple(_shared._snapshot(item, path, MAX_IMAGE_BYTES)
                      for item, path in zip(originals, targets.paths))
        if len(files) != len(images) or len(captured_dependencies) != len(targets.dependency_paths):
            raise _shared._ContractViolation()
        config, ignore = captured_dependencies[0].data, captured_dependencies[1].data
        if type(config) is not bytes or type(ignore) is not bytes:
            raise _shared._ContractViolation()
        observed = targets.relevant_contents(originals)
        protected_paths = targets.protected_target_paths(originals)
        view, _ = import_view(targets.selection, images, targets.names, observed,
                              (False,) * len(images), dependency_bytes=len(config) + len(ignore),
                              protected_sources=protected_paths)
        baseline_json = bounded_json_text(baseline(config, ignore, targets.selection, targets.names,
                                                   observed, images), max_bytes=8192, max_nodes=256,
                                          max_depth=8).encode("utf-8")
        view_json = _encode_view(view)
        checkout = object.__new__(MetadataImagesCheckout)
        for name, value in (("_identity", checkout), ("_lease", lease), ("_revision", revision),
                            ("_revision_token", revision.token), ("_targets", targets),
                            ("_dependencies", captured_dependencies), ("_files", files),
                            ("_images", images), ("_observed", observed), ("_baseline_json", baseline_json),
                            ("_protected_paths", protected_paths),
                            ("_view_json", view_json), ("_state", _shared._CAPTURED), ("_prepared", None)):
            object.__setattr__(checkout, name, value)
        return checkout
    except ConfigEditFailure:
        raise
    except (AttributeError, _shared._ContractViolation):
        raise ConfigEditFailure(_shared._uncertain()) from None
    except BaseException as error:
        raise ConfigEditFailure(_shared._pure_failure(error)) from None


def prepare_metadata_images_edit(lease: InitRootLease, checkout: MetadataImagesCheckout,
                                 expected_revision: str, expected_baseline: object,
                                 choices: object) -> PreparedMetadataImagesEdit:
    if not _authentic_checkout(checkout) or getattr(checkout, "_state", None) != _shared._CAPTURED:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._PREPARING)
    try:
        if lease is not checkout._lease:
            _shared._reject("invalid_params")
        if type(expected_revision) is not str or _shared._TOKEN.fullmatch(expected_revision) is None:
            _shared._reject("invalid_params")
        if expected_revision != checkout.revision:
            _shared._reject("stale_revision")
        try:
            expected = admit_baseline(expected_baseline)
            replacements = replacement_choices(choices, checkout._images)
        except MetadataImagesInputError:
            _shared._reject("invalid_params")
        if expected != checkout.baseline:
            _shared._reject("stale_revision")
        native = _shared._native_contract()
        if not _lease_matches(native, lease):
            _shared._reject("invalid_params")
        targets = checkout._targets
        _admit_revision(native, checkout._revision, targets)
        config, ignore = checkout._dependencies[0].data, checkout._dependencies[1].data
        view, payloads = import_view(targets.selection, checkout._images, targets.names, checkout._observed,
                                     replacements, dependency_bytes=len(config) + len(ignore),
                                     protected_sources=checkout._protected_paths)
        if view["valid"] is not True:
            _shared._reject("invalid_params")
        view_json = _encode_view(view)
        try:
            with lease.workspace_scope(checkout._revision) as workspace:
                if type(workspace) is not native.workspace:
                    raise _shared._ContractViolation()
        except BaseException as error:
            raise ConfigEditFailure(_shared._settled_failure(native, error)) from None
        token = _shared.uuid.uuid4().hex
        if type(token) is not str or _shared._TOKEN.fullmatch(token) is None or token == checkout.revision:
            _shared._reject("custody_unknown")
        prepared = object.__new__(PreparedMetadataImagesEdit)
        for name, value in (("_identity", prepared), ("_checkout", checkout), ("_token", token),
                            ("_payloads", payloads), ("_view_json", view_json), ("_state", _shared._PREPARED)):
            object.__setattr__(prepared, name, value)
        object.__setattr__(checkout, "_prepared", prepared)
        object.__setattr__(checkout, "_state", _shared._PREPARED)
        return prepared
    except ConfigEditFailure:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        raise
    except BaseException as error:
        object.__setattr__(checkout, "_state", _shared._RETIRED)
        raise ConfigEditFailure(_shared._pure_failure(error)) from None


def apply_metadata_images_edit(lease: InitRootLease, plan: PreparedMetadataImagesEdit) -> CoreEditOutcome:
    if (not _authentic_plan(plan) or getattr(plan, "_state", None) != _shared._PREPARED
            or plan._checkout._state != _shared._PREPARED):
        return _shared._not_started("invalid_params")
    object.__setattr__(plan, "_state", _shared._RETIRED)
    checkout = plan._checkout
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    if lease is not checkout._lease:
        return _shared._not_started("invalid_params")
    try:
        native = _shared._native_contract()
    except BaseException as error:
        return _shared._pure_failure(error)
    if not _lease_matches(native, lease):
        return _shared._not_started("invalid_params")
    native_result = None
    try:
        _admit_revision(native, checkout._revision, checkout._targets)
        with lease.workspace_scope(checkout._revision) as workspace:
            if type(workspace) is not native.workspace:
                raise _shared._ContractViolation()
            changes = [(file.observed(), payload) for file, payload in zip(checkout._files, plan._payloads)]
            native_result = workspace.apply_metadata_images_typed(changes)
    except BaseException as error:
        try:
            provisional = _shared._native_outcome(native, native_result)
        except _shared._ContractViolation:
            provisional = None
        return _shared._settled_failure(native, error, provisional)
    try:
        provisional = _shared._native_outcome(native, native_result)
    except _shared._ContractViolation:
        return _shared._uncertain()
    if provisional.reason == "none":
        expected = ("unchanged", "not_created") if all(payload is None for payload in plan._payloads) else ("committed", "clean")
        if (provisional.effect, provisional.journal) != expected:
            return _shared._uncertain(provisional)
    return provisional


def discard_metadata_images_edit(authority: MetadataImagesCheckout | PreparedMetadataImagesEdit) -> None:
    if _authentic_checkout(authority):
        checkout = authority
    elif _authentic_plan(authority):
        checkout = authority._checkout
    else:
        _shared._reject("invalid_params")
    object.__setattr__(checkout, "_state", _shared._RETIRED)
    object.__setattr__(checkout, "_images", ())
    if checkout._prepared is not None:
        object.__setattr__(checkout._prepared, "_state", _shared._RETIRED)
        object.__setattr__(checkout._prepared, "_payloads", ())
