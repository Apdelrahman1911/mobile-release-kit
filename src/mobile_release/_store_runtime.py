"""Owned bundled-tool selection for read-only Store access, not release authority.

The native caller must retain its complete installed Store runtime loan for the
whole child invocation. This object does not authenticate arbitrary paths or
replace that signed-inventory owner. No renderer/environment deserializer exists.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path

from .build_inputs import FiniteScratch, InvocationCustody
from .errors import StoreOperationError
from ._profile_callers import first_primary_context


@dataclass(frozen=True)
class StoreRuntimeContext:
    runtime_root: Path
    _invocation: InvocationCustody = field(repr=False)
    _home: FiniteScratch = field(repr=False)

    @classmethod
    def installed(cls, runtime_root: Path, *, invocation: InvocationCustody,
                  private_home: FiniteScratch) -> StoreRuntimeContext:
        if (not isinstance(runtime_root, Path) or not runtime_root.is_absolute()
                or any(part in (".", "..") for part in runtime_root.parts)
                or any(ord(c) < 32 or ord(c) == 127 or c == ":" for c in str(runtime_root))
                or runtime_root.resolve(strict=True) != runtime_root):
            raise StoreOperationError("Selected Store runtime path is not canonical")
        result = cls(runtime_root, invocation, private_home)
        result.check()
        return result

    @property
    def tooling_root(self) -> Path:
        return self.runtime_root / "store/tooling"

    @property
    def private_directory(self) -> Path:
        self.check()
        return self._home._path

    def require(self, *, root: Path, invocation: InvocationCustody) -> None:
        if invocation is not self._invocation or root != self._invocation.root:
            raise StoreOperationError("Selected Store runtime belongs to another invocation")
        self.check()

    def check(self) -> None:
        if (type(self._invocation) is not InvocationCustody or self._invocation.mode != "online"
                or type(self._home) is not FiniteScratch or self._home.layout != "online-runner"
                or self._home.cancellation is not self._invocation.cancellation):
            raise StoreOperationError("Selected Store runtime requires its original online owners")
        self._invocation.require(root=self._invocation.root, cancellation=self._invocation.cancellation)
        self._home._owner()
        self._home._check()
        for name in ("ruby", "bundle"):
            path = self.runtime_root / "store/bin" / name
            if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
                raise StoreOperationError("Selected Store interpreter is unavailable")

    def environment(self) -> dict[str, str]:
        self.check()
        store = self.runtime_root / "store"
        # Fresh values only: no os.environ, user's HOME, ambient gem config,
        # credential discovery, Ruby injection or GitHub identity inheritance.
        # The signed bundle wrapper supplies its own space-safe setup shim.
        return {"PATH": str(store / "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(self._home._path), "TMPDIR": str(self._home._path),
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                "GEM_HOME": str(store / "lib/ruby/gems/3.3.0"),
                "GEM_PATH": str(store / "lib/ruby/gems/3.3.0"),
                "BUNDLE_PATH": str(store / "bundle"), "BUNDLE_DEPLOYMENT": "true",
                "SSL_CERT_FILE": str(store / "ca.pem")}

    @contextmanager
    def _checked(self):
        self.check()
        try:
            yield
        finally:
            self.check()

    def checked(self):
        # Reuse existing first-primary/cancellation arbitration; this wrapper
        # owns no process, new clock, descriptor or cleanup permission.
        return first_primary_context(self._checked(), cancellation=self._invocation.cancellation)

    @contextmanager
    def command(self, argv, *, capture: bool):
        # Existing CLI/context callers retain their original checked scope.
        # Only the exact Desktop source additionally admits its fixed six roles.
        source = self._invocation.cancellation._store_preflight_source
        if source is None:
            with self.checked():
                yield
            return
        operation = source.require_operation()
        with first_primary_context(operation.command(self, argv, capture=capture),
                                   cancellation=self._invocation.cancellation):
            with self.checked():
                yield
