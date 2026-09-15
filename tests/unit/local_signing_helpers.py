"""Fictional signing effects through the real bounded command owner.

This account-test adapter reuses the persisted target/FIFO bridge; it never
constructs a command receipt or writes a custodian fence. It is consequently NOT
a shared-host-safe unit selector. Pure account tests patch the separate profile
caller boundary and do not claim profile authentication/lifetime coverage.
"""
from __future__ import annotations

import copy
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .local_signing_persistent import PersistentSigningModel, write_json


@contextmanager
def completed_case_directory(*, prefix: str):
    """Delete only a successfully checked case; failures retain native evidence."""
    root = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    owner, before = os.getpid(), root.lstat()
    if not stat.S_ISDIR(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o700:
        raise AssertionError("task case directory is not private")
    yield root
    after = root.lstat()
    if os.getpid() != owner or (after.st_dev, after.st_ino, after.st_mode, after.st_uid) != (
        before.st_dev, before.st_ino, before.st_mode, before.st_uid
    ):
        raise AssertionError("task case directory identity changed; preserve it")
    shutil.rmtree(root)


class NativeSigningModel:
    def __init__(self, home: Path):
        if home.name != "home" or not home.is_dir():
            raise AssertionError("the persisted signing fixture requires its task-owned <root>/home")
        self.home = home
        root = home.parent
        observed = root / "observed-native.json"
        if not observed.exists():
            original = {"default": str(home / "fictional login.keychain-db"),
                        "search": [str(home / "fictional login.keychain-db"),
                                   str(home / "f\\ictional أرشيف.keychain-db")]}
            write_json(observed, {"original": original, "preferences": copy.deepcopy(original),
                                  "keychain": None, "revisions": 0, "calls": []})
            write_json(root / "independent-owner.json",
                       {"sentinels": {}, "native": {}, "profile": {}, "foreignChanges": {}})
        self._model = PersistentSigningModel(root)
        self.calls: list[list[str]] = []
        self.before = self.after = self.result_policy = None

    @property
    def original(self):
        return self._model.state["original"]

    @property
    def preferences(self):
        return self._model.state["preferences"]

    @preferences.setter
    def preferences(self, value):
        self._model.state["preferences"] = copy.deepcopy(value)

    @property
    def keychain(self):
        value = self._model.state["keychain"]
        return None if value is None else Path(value)

    @keychain.setter
    def keychain(self, value):
        self._model.state["keychain"] = None if value is None else str(value)

    @property
    def revisions(self):
        return self._model.state["revisions"]

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.before is not None:
            self.before(argv, kwargs)
        self._model.save()  # Explicit test-owner preference edits precede W.
        policy = None if self.result_policy is None else self.result_policy(argv)
        result = self._model(argv, result_policy=policy, **kwargs)
        original_result = (result.returncode, result.stdout, result.stderr)
        if self.after is not None:
            replacement = self.after(argv, kwargs, result)
            if replacement is not None and replacement is not result:
                raise AssertionError("test callback replaced the original command result")
            if (result.returncode, result.stdout, result.stderr) != original_result:
                raise AssertionError("test callback altered the original command result")
        return result


def model_result(*, returncode=0, perform_effect=True, stdout=None, stderr=""):
    """Finite data for the target's actual exit/streams, never a wait receipt."""
    return {"returncode": returncode, "perform_effect": perform_effect,
            "stdout": stdout, "stderr": stderr}


def fictional_signing_profile(path: Path, *, cancellation, payload: dict | None = None):
    """Account-resource-only seam; dedicated composition tests do not use it."""
    from mobile_release.ios_profiles import read_profile_bytes
    from .ios_entitlement_helpers import profile

    cancellation.check()
    assert payload is None or type(payload) is dict, "fictional profile metadata must be explicit data"
    return read_profile_bytes(path, cancellation=cancellation), profile() if payload is None else copy.deepcopy(payload)
