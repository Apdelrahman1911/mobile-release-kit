"""One fixed saved-preflight admission ledger, not a filesystem/process runner.

Only the original PreflightInput/DefaultCancellation service can bind this
domain. CLI callers without that domain keep their existing policy. Charges
precede effects/retention and never refund; unknown original closes stay rooted.
These are application-managed limits, not a sandbox or an exact RSS bound.
"""
from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from .build_inputs import InvocationCustody
    from .cancellation import DefaultCancellation
    from ._desktop_preflight_control import PreflightInput


class PreflightBudgetError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("Saved offline preflight exceeded a fixed admission limit")


class _Iterator:
    """Prearmed original scandir acquisition and exactly one close attempt."""
    def __init__(self, budget: OfflinePreflightBudget) -> None:
        self.budget, self.value = budget, None
        self.state, self.close_state = "new", "new"

    def acquire(self, fd: int) -> None:
        self.budget.check()
        self.state = "attempted"
        try:
            self.value = os.scandir(fd)
            self.state = "open"
        except BaseException as error:
            # Do not infer no acquisition from an exception/absent return.
            self.state = "unknown"
            self.budget.guard._abort(error)
            raise

    def __iter__(self):
        return self

    def __next__(self):
        self.budget.charge("advances", 1, 50_000)
        if self.state != "open" or self.close_state != "new" or self.value is None:
            raise RuntimeError("Original directory iterator is unavailable")
        entry = next(self.value)
        self.budget.check()
        return entry

    def close(self) -> None:
        self.budget.owner()
        if self.close_state == "closed":
            return
        if self.close_state != "new" or self.state in {"attempted", "unknown"}:
            error = RuntimeError("Original directory iterator close is unknown")
            self.budget.guard._abort(error)
            raise error
        self.close_state = "attempted"
        try:
            with self.budget.guard.deferred(check_on_exit=False):
                if self.value is not None:
                    self.value.close()
                self.close_state = "closed"
        except BaseException as error:
            self.close_state = "unknown"
            self.budget.guard._abort(error)
            raise


class _List(list):
    def __init__(self, budget: OfflinePreflightBudget, kind: str) -> None:
        super().__init__()
        self.budget, self.kind = budget, kind

    def append(self, value) -> None:
        if self.kind == "path":
            self.budget.path(value)
        elif self.kind == "finding":
            self.budget.finding(value)
        else:
            self.budget.retain(value)
        super().append(value)

    def extend(self, values) -> None:
        for value in values:
            self.append(value)

    def insert(self, index, value) -> None:
        if self.kind == "path":
            self.budget.path(value)
        elif self.kind == "finding":
            self.budget.finding(value)
        else:
            self.budget.retain(value)
        super().insert(index, value)

    def __iadd__(self, values):
        self.extend(values)
        return self


class OfflinePreflightBudget:
    def __init__(self, root: Path, guard: DefaultCancellation, source: PreflightInput) -> None:
        from .cancellation import DefaultCancellation
        from ._desktop_preflight_control import PreflightInput
        if (type(guard) is not DefaultCancellation or type(source) is not PreflightInput
                or guard._preflight_source is not source or source.guard is not guard
                or source.budget is not None or threading.current_thread() is not threading.main_thread()):
            raise ValueError("Offline preflight budget has no original input owner")
        self.root, self.guard, self.source = root, guard, source
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.invocation: InvocationCustody | None = None
        self.counters: dict[str, int] = {}
        self.iterators: list[_Iterator] = []
        self.slots = []
        self.open_iterators = 0
        self.findings: dict[int, object] = {}
        self.failure: str | None = None
        self.close_claimed = self.closed = False
        source.budget = self

    def owner(self) -> None:
        if (self.pid != os.getpid() or self.thread is not threading.current_thread()
                or self.source.guard is not self.guard or self.source.budget is not self):
            raise ValueError("Offline preflight budget owner changed")
        self.guard._check_owner()

    def check(self) -> None:
        self.owner()
        if self.failure is not None:
            raise PreflightBudgetError(self.failure)
        if self.close_claimed:
            raise ValueError("Offline preflight budget is retired")
        self.guard.check()

    def bind(self, invocation: InvocationCustody) -> None:
        from .build_inputs import InvocationCustody
        self.check()
        if (type(invocation) is not InvocationCustody or self.invocation is not None
                or invocation.root != self.root or invocation.cancellation is not self.guard
                or invocation.mode != "build" or invocation.signing_lease is not None):
            raise ValueError("Offline preflight invocation binding differs")
        self.invocation = invocation

    def checkpoint(self) -> None:
        self.check()
        if self.invocation is None:
            raise ValueError("Offline preflight has no original project invocation")
        self.invocation.require(root=self.root, cancellation=self.guard, signing_lease=None)

    def fail(self, reason: str = "input-limit") -> None:
        self.owner()
        if self.failure is None:
            self.failure = reason
            self.source.failure_observed()
        raise PreflightBudgetError(self.failure)

    def charge(self, name: str, amount: int, limit: int, *, result: bool = False) -> None:
        self.check()
        old = self.counters.get(name, 0)
        if type(amount) is not int or amount < 0 or old > limit - amount:
            self.fail("result-limit" if result else "input-limit")
        self.counters[name] = old + amount

    def relative(self, path: Path) -> str:
        self.check()
        try:
            relative = path.relative_to(self.root).as_posix()
            parts = () if relative == "." else relative.split("/")
            raw = relative.encode("utf-8")
            # At most 32 directory components and one file leaf. Directory
            # consumers additionally check depth before retaining/opening it.
            if (len(raw) > 2048 or len(parts) > 33 or any(
                    part in {"", ".", ".."} or len(part.encode("utf-8")) > 255
                    or any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                    for part in parts)):
                self.fail()
            return relative
        except (ValueError, UnicodeError):
            self.fail()
        raise AssertionError("unreachable")

    def path(self, path: Path) -> None:
        relative = self.relative(path)
        self.charge("paths", 1, 4096)
        self.charge("path-bytes", len(relative.encode("utf-8")), 2 * 1024 * 1024)

    def list(self, kind: str = "value") -> list:
        self.charge("nodes", 1, 65_536, result=True)
        return _List(self, kind)

    def mapping(self) -> dict:
        self.charge("nodes", 1, 65_536, result=True)
        return {}

    def retain(self, value, *, depth: int = 0) -> None:
        """Precharge result promotion, never serialize a Report for inspection."""
        self.charge("nodes", 1, 65_536, result=True)
        if depth > 32:
            self.fail("result-limit")
        if isinstance(value, (str, bytes)):
            try:
                size = len(value.encode("utf-8")) if isinstance(value, str) else len(value)
            except UnicodeError:
                self.fail("result-limit")
            if size > 16 * 1024:
                self.fail("result-limit")
            self.charge("result-bytes", size, 8 * 1024 * 1024, result=True)
        elif type(value) is dict:
            for key, item in value.items():
                self.retain(key, depth=depth + 1)
                self.retain(item, depth=depth + 1)
        elif isinstance(value, (tuple, list, set)):
            for item in value:
                self.retain(item, depth=depth + 1)
        elif value is not None and type(value) not in {bool, int, float}:
            self.fail("result-limit")

    def put(self, target: dict, key, value) -> None:
        self.retain(key)
        self.retain(value)
        target[key] = value

    def add(self, target: set, value) -> None:
        self.check()
        if value not in target:
            self.retain(value)
            target.add(value)

    def finding(self, finding) -> None:
        from .reporting import Finding
        self.check()
        if type(finding) is not Finding:
            self.fail("result-limit")
        if id(finding) in self.findings:
            return
        self.charge("findings", 1, 4096, result=True)
        self.retain((finding.code, finding.status.value, finding.message,
                     finding.category, finding.remediation, finding.details))
        self.findings[id(finding)] = finding  # Bounded, identity cannot be recycled.

    def file_admission(self, path: Path, limit: int) -> int:
        self.relative(path)
        self.charge("files", 1, 512)  # Before stat/open, including missing attempts.
        if type(limit) is not int or limit <= 0:
            self.fail()
        return min(limit, 10 * 1024 * 1024)

    def read_request(self, amount: int) -> None:
        if not 0 < amount <= 64 * 1024:
            self.fail()
        self.charge("reads", amount, 64 * 1024 * 1024)

    def capture(self, limit: int) -> int:
        selected = min(limit, 1024 * 1024)
        self.charge("capture", selected, 8 * 1024 * 1024)
        return selected

    def open_fd(self, name, flags: int, *, parent: int) -> int:
        from .build_inputs import _FD
        self.check()
        slot = _FD(self.guard)
        self.slots.append(slot)  # Original record exists before acquisition.
        return slot.open(name, flags, dir_fd=parent)

    def close_fd(self, number: int) -> None:
        self.owner()
        slot = next((slot for slot in self.slots if slot.number == number), None)
        if slot is None:
            error = RuntimeError("Offline preflight descriptor has no original record")
            self.guard._abort(error)
            raise error
        slot.close()

    @contextmanager
    def entries(self, fd: int) -> Iterator[_Iterator]:
        self.charge("iterators", 1, 4096)
        if self.open_iterators >= 33:
            self.fail()
        original = _Iterator(self)
        self.iterators.append(original)
        self.open_iterators += 1
        try:
            original.acquire(fd)
            yield original
        finally:
            try:
                original.close()
            finally:
                if original.close_state == "closed":
                    self.open_iterators -= 1

    def read(self, path: Path, *, limit: int, binary: bool = False,
             errors: str = "strict") -> str | bytes | None:
        from .api._snapshot import borrowed_preflight_reads, _ReadProblem
        self.checkpoint()
        relative = self.relative(path)
        try:
            with borrowed_preflight_reads(self) as reader:
                raw = reader.read(relative, limit=limit, binary=True)
        except _ReadProblem as error:
            if error.code in {"snapshot.deadline", "snapshot.entry-limit", "snapshot.file-limit", "snapshot.byte-limit"}:
                self.fail()
            if error.code == "snapshot.file-size" and relative != "release/mobile-release.json":
                self.fail()
            raise
        self.checkpoint()
        if raw is None or binary:
            return raw
        # Match ordinary Path.read_text's universal-newline semantics. Callers
        # needing exact config/note bytes explicitly use binary=True.
        return raw.decode("utf-8", errors=errors).replace("\r\n", "\n").replace("\r", "\n")

    def walk(self, root: Path, *, discovery: bool = False) -> list[Path]:
        """Incremental original-fd traversal; policy filtering stays in callers."""
        from .api._snapshot import borrowed_preflight_reads, _named_identity
        from .discovery import _ignored_path
        self.checkpoint()
        relative = self.relative(root)
        values = self.list("path")

        def visit(fd: int, parent: Path, depth: int, reader) -> None:
            self.check()
            if depth > 32:
                self.fail()
            with self.entries(fd) as entries:
                for entry in entries:
                    path = parent / entry.name
                    self.relative(path)
                    if discovery and _ignored_path(self.root, path):
                        continue
                    before = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(before.st_mode) and depth >= 32:
                        self.fail()  # Before retaining/opening a deeper directory.
                    values.append(path)
                    if not stat.S_ISDIR(before.st_mode):
                        continue  # Never follow a symlink directory.
                    reader._admit(before, directory=True)
                    child = self.open_fd(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                         | os.O_NONBLOCK, parent=fd)
                    try:
                        expected = _named_identity(before)
                        if _named_identity(os.fstat(child)) != expected:
                            raise RuntimeError("Original traversal parent changed")
                        visit(child, path, depth + 1, reader)
                        if (_named_identity(os.fstat(child)) != expected
                                or _named_identity(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) != expected):
                            raise RuntimeError("Original traversal parent changed")
                    finally:
                        self.close_fd(child)

        with borrowed_preflight_reads(self) as reader:
            fd = reader.directory(relative)
            visit(fd, root, 0 if relative == "." else len(relative.split("/")), reader)
        self.checkpoint()
        return values

    def close(self) -> None:
        self.owner()
        if self.close_claimed:
            if not self.closed:
                raise RuntimeError("Offline preflight resource closure is unknown")
            return
        self.close_claimed = True
        first = None
        for group in (self.iterators, self.slots):
            for resource in reversed(group):
                try:
                    resource.close()
                except BaseException as error:
                    self.guard._abort(error)
                    if first is None:
                        first = error
        if first is not None:
            raise first
        self.closed = True


def budget_for(cancellation: DefaultCancellation | None) -> OfflinePreflightBudget | None:
    """No imports or input acquisitions for ordinary callers without this domain."""
    if cancellation is None:
        return None
    source = getattr(cancellation, "_preflight_source", None)
    if source is None or source.budget is None:
        return None
    budget = source.budget
    if type(budget) is not OfflinePreflightBudget or budget.guard is not cancellation:
        raise ValueError("Offline preflight budget binding differs")
    budget.check()
    return budget
