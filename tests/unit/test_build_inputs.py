"""QA-004 draft regression source. Execute only through the reviewed owner.

These cases use exclusively synthetic task-owned files/environment values and
do not execute an application or Store client. Modeled aliases are not native
evidence; the real Darwin scratch-alias case requires the reviewed native owner.
"""
from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import signal
import stat
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import build_inputs as inputs
from mobile_release.owned_process import ProcessError


class _TTY(io.StringIO):
    def isatty(self):
        return True


class _AcquisitionLock:
    """Fixture owns the real lock result when its injected handoff does not return."""
    def __init__(self):
        self.original = threading.Lock()
        self.callback = None
        self.held, self.releases = False, 0

    def acquire(self, *, blocking):
        result = self.original.acquire(blocking=blocking)
        if result:
            self.held = True
            if self.callback is not None:
                self.callback()
        return result

    def release(self):
        self.releases += 1
        self.original.release()
        self.held = False

    def dispose_fixture(self):
        # Not production recovery: this wrapper retained its own positive native
        # result and never transferred it when callback publication failed.
        if self.held:
            self.original.release()
            self.held = False


@contextmanager
def _environment_facility():
    # Test-local bookkeeping, not a production recovery/reset operation.
    with patch.multiple(inputs, _ENV_LOCK=threading.Lock(), _ENV_OWNER=None,
                        _ENV_TAINTED=False, _ENV_PID=os.getpid()):
        yield


@contextmanager
def _scratch_guard():
    from .test_checked_files import no_signal_setters
    with no_signal_setters():
        guard = inputs.DefaultCancellation(inputs.ProcessCleanupError, "scratch fixture cleanup")
        try:
            guard.install()
            guard.activate()
            yield guard
        finally:
            guard.restore()


@contextmanager
def _scratch_topology(*, platform="darwin"):
    """Directory-policy model only; no synthetic FD can reach a real OS call."""
    def node(inode, mode, uid=0):
        return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=0,
                               st_nlink=1, st_size=11, st_mtime_ns=1, st_ctime_ns=1)
    root = node(1, stat.S_IFDIR | 0o755)
    private = node(2, stat.S_IFDIR | 0o755)
    tmp, var = node(3, stat.S_IFDIR | 0o1777), node(4, stat.S_IFDIR | 0o755)
    entries = {(1, "private"): private, (1, "Private"): private,
               (2, "tmp"): tmp, (2, "Tmp"): tmp, (2, "var"): var, (2, "Var"): var,
               (3, "work"): node(5, stat.S_IFDIR | 0o700, os.geteuid()),
               (4, "work"): node(6, stat.S_IFDIR | 0o700, os.geteuid()),
               (1, "tmp"): node(7, stat.S_IFLNK | 0o777),
               (1, "var"): node(8, stat.S_IFLNK | 0o777)}
    model = SimpleNamespace(root=root, entries=entries, targets={"tmp": "private/tmp", "var": "private/var"},
                            handles={}, opened=[], closed=[], made=[], removed=[], serial=500)
    def stating(name, *, dir_fd=None, follow_symlinks=False):
        assert follow_symlinks is False
        return root if name == "/" and dir_fd is None else entries[model.handles[dir_fd].st_ino, name]
    def opening(name, flags, mode=0o600, *, dir_fd=None):
        assert flags & (os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC) == (
            os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        observed = stating(name, dir_fd=dir_fd)
        assert stat.S_ISDIR(observed.st_mode), "model must not open any alias"
        model.serial += 1
        model.handles[model.serial] = observed
        model.opened.append((model.serial, dir_fd, name))
        return model.serial
    def closing(number):
        del model.handles[number]
        model.closed.append(number)
    def readlink(name, *, dir_fd):
        assert model.handles[dir_fd] is root
        return model.targets[name]
    def mkdir(name, mode, *, dir_fd):
        key = model.handles[dir_fd].st_ino, name
        assert key not in entries and mode == 0o700
        entries[key] = node(9, stat.S_IFDIR | mode, os.geteuid())
        model.made.append(key)
    def listdir(number):
        inode = model.handles[number].st_ino
        return [name for parent, name in entries if parent == inode]
    def remove(name, *, dir_fd):
        model.removed.append((dir_fd, name))
        raise AssertionError("uncertain ancestry must not authorize removal")
    with patch.object(inputs.sys, "platform", platform), patch.multiple(
            inputs.os, open=opening, close=closing, stat=stating, fstat=model.handles.__getitem__,
            readlink=readlink, mkdir=mkdir, listdir=listdir, unlink=remove, rmdir=remove,
            fsync=lambda number: model.handles[number]):
        yield model


class ScratchParentTests(unittest.TestCase):
    def test_default_scratch_freezes_task_tmpdir_and_uses_real_native_tmp_alias(self):
        with tempfile.TemporaryDirectory(prefix="mrk-scratch-parent-") as temporary:
            root = Path(temporary).resolve(strict=True)  # Canonicalize only this test-owned fixture.
            selected, later = root / "selected", root / "later"
            selected.mkdir(mode=0o700)
            later.mkdir(mode=0o700)
            spellings = [selected]
            if inputs.sys.platform == "darwin":
                self.assertTrue(selected.is_relative_to(Path("/private/tmp")),
                                "reviewed native source/wheel scratch must stay inside its /private/tmp work root")
                spellings.append(Path("/tmp") / selected.relative_to("/private/tmp"))
            original_acquire = inputs._Directory.acquire
            for spelling in spellings:
                with self.subTest(spelling=spelling), _scratch_guard() as guard:
                    def acquire(parent):
                        self.assertEqual(parent.lexical_path, spelling)
                        os.environ["TMPDIR"] = str(later)  # After construction, before the actual walk.
                        return original_acquire(parent)
                    before = inputs._directory(selected.stat())
                    with patch.object(inputs.os, "environ", {"TMPDIR": str(spelling), "TMP": str(later), "TEMP": str(later)}), \
                         patch.object(tempfile, "tempdir", str(later)), patch.object(inputs._Directory, "acquire", acquire):
                        with inputs.finite_scratch(layout="store-selection", cancellation=guard) as scratch:
                            self.assertIs(scratch.cancellation, guard)
                            self.assertEqual(scratch.parent.path, selected)
                            self.assertEqual(inputs._directory(os.fstat(scratch.parent.fd)), before)
                            self.assertEqual(inputs._directory(scratch._path.lstat()), scratch.identity)
                            self.assertEqual(scratch.identity["mode"], 0o700)
                            material = scratch.put("asc-p8", b"synthetic-selected-input")
                            path = scratch.require(material)
                            self.assertEqual(path.read_bytes(), b"synthetic-selected-input")
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                            self.assertEqual({entry.name for entry in scratch._path.iterdir()}, {"AuthKey.p8"})
                            slots = [*scratch.parent.slots, scratch.slot, *scratch.writer_slots]
                    self.assertTrue(all(slot.guard is guard and slot.number is None and slot.close_state == "CLOSED"
                                        for slot in slots))
                    self.assertFalse(path.parent.exists())
                    self.assertEqual(inputs._directory(selected.stat()), before)
                    self.assertEqual(list(selected.iterdir()), [])
                    self.assertEqual(list(later.iterdir()), [])
                    if spelling != selected:
                        # The same genuine root alias is not admitted for an explicit parent.
                        with self.assertRaises(OSError):
                            with inputs.finite_scratch(layout="online-runner", cancellation=guard, parent=spelling):
                                self.fail("explicit parent followed a system alias")
                        self.assertEqual(list(selected.iterdir()), [])

    def test_parent_selection_is_bounded_frozen_and_explicit_without_fallback_acquisition(self):
        cases = (("linux", None, None, "/tmp"), ("linux", "", None, "/tmp"),
                 ("darwin", None, None, "/private/tmp"), ("darwin", "", None, "/private/tmp"),
                 ("linux", "/task/selected", None, "/task/selected"),
                 ("darwin", "/var/folders/task", None, "/var/folders/task"),
                 ("darwin", "invalid/../configured", Path("/task/explicit"), "/task/explicit"))
        with _scratch_guard() as guard, patch.object(inputs.os, "open", side_effect=AssertionError("unexpected open")) as opened, \
             patch.object(inputs.os, "mkdir", side_effect=AssertionError("unexpected mkdir")) as made:
            for platform, value, explicit, expected in cases:
                environment = {"TMP": "/not-authority", "TEMP": "/not-authority"}
                if value is not None:
                    environment["TMPDIR"] = value
                with self.subTest(platform=platform, value=value), patch.object(inputs.sys, "platform", platform), \
                     patch.object(inputs.os, "environ", environment), patch.object(tempfile, "tempdir", "/cached-not-authority"):
                    owner = inputs.FiniteScratch("online-runner", guard, explicit)
                    environment["TMPDIR"] = "/later"
                    self.assertEqual(owner.parent.lexical_path, Path(expected))
                    self.assertEqual(owner.parent.path, Path(expected))
                    self.assertIs(owner.parent.system_root_aliases, explicit is None)
                    owner.cleanup()
            invalid = ("relative", "~/.tmp", "//server/work", "/tmp/link/../work", "/tmp/nul\x00work",
                       "/" + "/".join(["x"] * 128), "/" + "x" * 4096, "/tmp/\ud800")
            for index, value in enumerate(invalid):
                with self.subTest(invalid=index), patch.object(inputs.os, "environ", {"TMPDIR": value}), \
                     self.assertRaisesRegex(inputs.BuildInputError, "bounded absolute lexical path") as caught:
                    inputs.FiniteScratch("online-runner", guard, None)
                self.assertLess(len(str(caught.exception)), 100)
            opened.assert_not_called()
            made.assert_not_called()

    def test_default_and_explicit_lower_links_never_create_children_or_lose_original_handles(self):
        with tempfile.TemporaryDirectory(prefix="mrk-scratch-link-") as temporary:
            root = Path(temporary).resolve(strict=True)
            target, link = root / "target", root / "link"
            target.mkdir(mode=0o700)
            link.symlink_to(target, target_is_directory=True)
            original = target.stat().st_ino
            for explicit in (None, link):
                with self.subTest(explicit=explicit is not None), _scratch_guard() as guard, \
                     patch.object(inputs.os, "environ", {"TMPDIR": str(link)}), \
                     patch.object(inputs, "_mkdir_private", side_effect=AssertionError("child creation reached")) as made:
                    owner = inputs.FiniteScratch("online-runner", guard, explicit)
                    with self.assertRaises(OSError), inputs._scope(owner, guard, False):
                        self.fail("lower symbolic link admitted")
                    made.assert_not_called()
                    self.assertTrue(all(slot.number is None and slot.close_state == "CLOSED" for slot in owner.parent.slots))
                    self.assertFalse(owner.created)
            self.assertEqual(target.stat().st_ino, original)
            self.assertEqual(list(target.iterdir()), [])
            self.assertEqual(os.readlink(link), str(target))

    def test_default_aliases_bind_exact_original_root_and_protected_physical_entries(self):
        for name in ("tmp", "var"):
            for target in ("private/" + name, "/private/" + name):
                with self.subTest(name=name, target=target), _scratch_guard() as guard, _scratch_topology() as model:
                    model.targets[name] = target
                    directory = inputs._Directory(Path("/") / name / "work", guard, system_root_aliases=True)
                    try:
                        directory.acquire()
                        self.assertEqual(directory.path, Path("/private") / name / "work")
                        self.assertEqual(directory.lexical_path, Path("/") / name / "work")
                        self.assertEqual([entry[2] for entry in model.opened], ["/", "private", name, "work"])
                        self.assertEqual(directory.alias[0::2], (name, target))
                        directory.check()
                    finally:
                        directory.close()
                    self.assertEqual(model.closed, [number for number, _, _ in reversed(model.opened)])
                    self.assertFalse(model.handles)

    def test_alias_policy_and_physical_identity_refuse_unsupported_or_unprotected_ancestry(self):
        # Reuse the checked-reader policy vectors at the actual directory owner.
        cases = (("darwin", "tmp", "/private/var", None, None),
                 ("darwin", "var", "/private/tmp", None, None),
                 ("darwin", "tmp", "/private/other/../tmp", None, None),
                 ("linux", "tmp", "private/tmp", None, None),
                 ("darwin", "tmp", "private/tmp", "alias-owner", None),
                 ("darwin", "Private/Tmp", None, "root", 0o777),
                 ("darwin", "Private/Tmp", None, "private", 0o777),
                 ("darwin", "Private/Tmp", None, "tmp", 0o777),
                 ("darwin", "Private/Var", None, "var", 0o777),
                 ("darwin", "Private/Tmp", None, "tmp-owner", None))
        for platform, spelling, target, change, mode in cases:
            with self.subTest(platform=platform, spelling=spelling, change=change), _scratch_guard() as guard, \
                 _scratch_topology(platform=platform) as model:
                if target is not None:
                    model.targets[spelling] = target
                if change == "alias-owner":
                    model.entries[1, spelling].st_uid = 501
                elif change == "tmp-owner":
                    model.entries[2, "tmp"].st_uid = 501
                elif change is not None:
                    observed = model.root if change == "root" else model.entries[1 if change == "private" else 2, change]
                    observed.st_mode = stat.S_IFDIR | mode
                directory = inputs._Directory(Path("/") / spelling / "work", guard, system_root_aliases=True)
                try:
                    with self.assertRaises(inputs.BuildInputError):
                        directory.acquire()
                finally:
                    directory.close()
                self.assertFalse(model.handles)
                self.assertFalse(model.made)
        with _scratch_guard() as guard, _scratch_topology() as model:
            directory = inputs._Directory(Path("/Private/Tmp/work"), guard, system_root_aliases=True)
            try:
                directory.acquire()
                self.assertEqual(directory.path, Path("/private/tmp/work"))
                self.assertEqual([name for _, _, name, _ in directory.physical_bindings], ["private", "tmp"])
                # Caller spelling still points to its original directory; the
                # exact entry which identified the physical role must also hold.
                model.entries[2, "tmp"] = SimpleNamespace(**dict(vars(model.entries[2, "tmp"]), st_ino=40))
                with self.assertRaisesRegex(inputs.BuildInputError, "physical system directory ancestry changed"):
                    directory.check()
            finally:
                directory.close()
            self.assertFalse(model.handles)

    def test_alias_drift_blocks_acquisition_or_disposal_but_retires_original_descriptors(self):
        for timing in ("acquisition", "disposal"):
            for change in ("metadata", "target"):
                with self.subTest(timing=timing, change=change), _scratch_guard() as guard, _scratch_topology() as model, \
                     patch.object(inputs.os, "environ", {"TMPDIR": "/tmp/work"}):
                    owner = inputs.FiniteScratch("online-runner", guard, None, _name="scratch")
                    def drift():
                        if change == "metadata":
                            model.entries[1, "tmp"].st_uid = 501
                        else:
                            model.targets["tmp"] = "/private/var"
                    original_check = owner.parent.check
                    def check():
                        if timing == "acquisition":
                            drift()
                        return original_check()
                    expected = inputs.BuildInputError if timing == "acquisition" else ProcessError
                    with self.assertRaises(expected), patch.object(owner.parent, "check", check):
                        with inputs._scope(owner, guard, False):
                            self.assertEqual(owner.parent.path, Path("/private/tmp/work"))
                            drift()
                    self.assertEqual(len(model.made), int(timing == "disposal"))
                    self.assertEqual(owner.parent.path, Path("/tmp/work") if timing == "acquisition" else Path("/private/tmp/work"))
                    if timing == "disposal":
                        self.assertIn((5, "scratch"), model.entries)
                        self.assertTrue(guard.lifetime_ledger.fatal)
                    self.assertFalse(model.removed)
                    self.assertFalse(model.handles)
                    self.assertEqual(model.closed, [number for number, _, _ in reversed(model.opened)])
                    self.assertTrue(all(slot.number is None and slot.close_state == "CLOSED"
                                        for slot in [*owner.parent.slots, owner.slot]))


class BuildInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-build-input-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / ".gitignore").write_text(".mobile-release/\n", encoding="utf-8")
        self.facility = _environment_facility()
        self.facility.__enter__()
        self.addCleanup(self.facility.__exit__, None, None, None)

    def replacement(self, role="android-services", content=b"synthetic-new"):
        name = "google-services.json" if role == "android-services" else "GoogleService-Info.plist"
        return inputs.TargetReplacement(role, PurePosixPath(name), content)

    @contextmanager
    def materialization(self):
        with inputs.invocation_custody(self.root, mode="build") as invocation:
            with invocation.project(signing_lease=None):
                with invocation.materialization(signing_lease=None) as owner:
                    yield invocation, owner

    def pending(self):
        state = inputs.build_inputs_status(self.root)
        self.assertEqual(state["status"], "pending")
        return state["session"]

    def recover(self, session, **kwargs):
        return inputs.recover_build_inputs(self.root, session=session,
            confirm="project-build-inputs-are-idle-and-restore-owned-state", **kwargs)

    def test_environment_reserves_before_snapshots_and_borrows_only_explicit_frames(self):
        key = "MRK_SYNTHETIC_INPUT_TEST"
        with patch.dict(os.environ, {key: "original"}):
            with inputs.invocation_custody(self.root, mode="online") as invocation:
                with invocation.environment({key: None}):
                    self.assertNotIn(key, os.environ)
                    with self.assertRaises(inputs.BuildInputError):
                        with inputs.invocation_custody(self.root, mode="online"):
                            self.fail("second invocation acquired identical absence")
                    self.assertFalse(inputs._ENV_TAINTED)
                    with invocation.environment({key: "selected"}):
                        self.assertEqual(os.environ[key], "selected")
                    self.assertNotIn(key, os.environ)
                self.assertEqual(os.environ[key], "original")
                with self.assertRaises(inputs.BuildInputError):
                    with invocation.project(signing_lease=None):
                        self.fail("online invocation acquired project resources")
            self.assertEqual(os.environ[key], "original")

    def test_environment_conflict_preserves_foreign_value_and_restores_independent_entry(self):
        first, second = "MRK_SYNTHETIC_FIRST", "MRK_SYNTHETIC_SECOND"
        with patch.dict(os.environ, {first: "old-a", second: "old-b"}):
            with self.assertRaises(ProcessError):
                with inputs.invocation_custody(self.root, mode="online") as invocation:
                    with invocation.environment({first: "selected-a", second: "selected-b"}):
                        os.environ[first] = "foreign"
            self.assertEqual(os.environ[first], "foreign")
            self.assertEqual(os.environ[second], "old-b")
            self.assertTrue(inputs._ENV_TAINTED)
            with self.assertRaises(inputs.BuildInputError):
                with inputs.invocation_custody(self.root, mode="online"):
                    self.fail("unresolved facility was reused")

    def test_default_cancellation_at_lock_handoff_settles_the_exact_original_reservation(self):
        lock, primaries, depths = _AcquisitionLock(), [], []
        self.addCleanup(lock.dispose_fixture)
        with patch.object(inputs, "_ENV_LOCK", lock):
            with self.assertRaises(KeyboardInterrupt) as caught:
                with inputs.finite_scratch(layout="online-runner", parent=self.root) as scratch:
                    guard = scratch.cancellation
                    actual_check = guard.check
                    def check():
                        try:
                            actual_check()
                        except KeyboardInterrupt as error:
                            if not primaries:
                                primaries.append(error)
                            raise
                    def cancel():
                        depths.append(guard.depth)
                        guard.interrupt(signal.SIGINT, None)  # Default-handler callback oracle, not an OS signal.
                    lock.callback = cancel
                    with patch.object(guard, "check", side_effect=check):
                        with inputs.invocation_custody(self.root, mode="online", cancellation=guard):
                            self.fail("cancelled acquire published a usable invocation")
            self.assertEqual(depths, [1])
            self.assertIs(caught.exception, primaries[0])
            self.assertEqual((lock.releases, lock.held, inputs._ENV_TAINTED), (1, False, False))
            lock.callback = None
            with inputs.invocation_custody(self.root, mode="online"):
                pass
            self.assertEqual(lock.releases, 2)

    def test_unobserved_lock_handoff_is_tainted_without_releasing_a_guessed_owner(self):
        lock = _AcquisitionLock()
        self.addCleanup(lock.dispose_fixture)
        original = KeyboardInterrupt("synthetic-unobserved-lock-result")
        def interrupt():
            raise original
        lock.callback = interrupt
        with patch.object(inputs, "_ENV_LOCK", lock):
            with self.assertRaises(KeyboardInterrupt) as caught:
                with inputs.finite_scratch(layout="online-runner", parent=self.root) as scratch:
                    try:
                        with inputs.invocation_custody(self.root, mode="online", cancellation=scratch.cancellation):
                            self.fail("unknown acquire entered consumers")
                    except KeyboardInterrupt:
                        self.assertTrue(scratch.cancellation.lifetime_ledger.fatal)
                        raise
            self.assertIs(caught.exception, original)
            self.assertEqual((lock.releases, lock.held, inputs._ENV_TAINTED), (0, True, True))
            with self.assertRaises(inputs.BuildInputError):
                with inputs.invocation_custody(self.root, mode="online"):
                    self.fail("unknown environment facility was reused")

    def test_nested_environment_failure_still_restores_independent_outer_keys_once(self):
        a, b, common = "MRK_SYNTHETIC_OUTER", "MRK_SYNTHETIC_INNER", "MRK_SYNTHETIC_OVERLAP"
        actual_set = type(os.environ).__setitem__
        for overlap in (False, True):
            frames, writes = [], []
            def record_set(mapping, key, value):
                if key in (a, b, common):
                    writes.append((key, value))
                return actual_set(mapping, key, value)
            with self.subTest(overlap=overlap), _environment_facility(), patch.dict(
                    os.environ, {a: "old-a", b: "old-b", common: "old-common"}), patch.object(
                    type(os.environ), "__setitem__", record_set):
                with self.assertRaises(ProcessError):
                    with inputs.invocation_custody(self.root, mode="online") as invocation:
                        with invocation.environment({a: "outer-a", common: "outer-common"}):
                            frames.append(invocation.frames[-1])
                            updates = {b: "inner-b", **({common: "inner-common"} if overlap else {})}
                            with invocation.environment(updates):
                                frames.append(invocation.frames[-1])
                                os.environ[b] = "foreign-b"
                                if overlap:
                                    os.environ[common] = "foreign-common"
                self.assertEqual(os.environ[a], "old-a")
                self.assertEqual(os.environ[b], "foreign-b")
                self.assertEqual(os.environ[common], "foreign-common" if overlap else "old-common")
                self.assertEqual(invocation.frames, [])
                self.assertTrue(inputs._ENV_TAINTED)
                self.assertEqual(writes.count((a, "old-a")), 1)
                self.assertEqual(writes.count((common, "old-common")), 0 if overlap else 1)
                before = list(writes)
                for frame in frames:
                    frame.cleanup()
                self.assertEqual(writes, before, "consumed setters were retried")

    def test_wrong_thread_cannot_borrow_or_restore_parent_environment(self):
        observations = []
        with inputs.invocation_custody(self.root, mode="online") as invocation:
            def contender():
                for operation in (lambda: invocation.require(root=self.root,
                        cancellation=invocation.cancellation), invocation.cleanup):
                    try:
                        operation()
                    except inputs.BuildInputError:
                        observations.append("refused")
            worker = threading.Thread(target=contender)
            worker.start()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(observations, ["refused", "refused"])
            self.assertFalse(invocation.claimed)
            self.assertFalse(inputs._ENV_TAINTED)

    def test_snapshot_cannot_be_forged_and_changed_input_is_not_silently_accepted(self):
        path = None
        with self.assertRaises(ProcessError):
            with inputs.finite_scratch(layout="store-selection", parent=self.root) as scratch:
                selected = scratch.put("asc-p8", b"fictional-private-bytes")
                path = scratch.require(selected)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                forged = inputs.InputSnapshot(selected.size, selected.sha256, scratch, "asc-p8", object())
                with self.assertRaises(inputs.BuildInputError):
                    scratch.require(forged)
                path.write_bytes(b"intervening-bytes")
                with self.assertRaises(inputs.BuildInputError):
                    scratch.require(selected)
        self.assertIsNotNone(path)
        self.assertEqual(path.read_bytes(), b"intervening-bytes")

    def test_scratch_unknown_entry_is_preserved_without_recursive_cleanup(self):
        retained = None
        with self.assertRaises(ProcessError):
            with inputs.finite_scratch(layout="store-selection", parent=self.root) as scratch:
                selected = scratch.put("asc-p8", b"fictional")
                retained = scratch.require(selected).parent / "foreign"
                retained.write_bytes(b"not-owned-by-scratch")
        self.assertEqual(retained.read_bytes(), b"not-owned-by-scratch")

    def test_private_snapshot_hardlink_is_not_accepted_or_deleted_as_owned(self):
        with self.assertRaises(ProcessError):
            with inputs.finite_scratch(layout="store-selection", parent=self.root) as scratch:
                selected = scratch.put("asc-p8", b"fictional-private-bytes")
                path = scratch.require(selected)
                alias = self.root / "foreign-link"
                os.link(path, alias)
                with self.assertRaises(inputs.BuildInputError):
                    scratch.require(selected)
        self.assertEqual(path.read_bytes(), b"fictional-private-bytes")
        self.assertEqual(alias.stat().st_ino, path.stat().st_ino)

    def test_stream_copy_borrows_source_fd_and_rejects_unpinned_parameters(self):
        data = b"synthetic-pinned-tool"
        source = self.root / "public-tool"
        source.write_bytes(data)
        descriptor = os.open(source, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        digest = hashlib.sha256(data).hexdigest()
        layout = {"bundletool": {"bundletool": inputs._ScratchSpec("bundletool.jar", len(data))}}
        # This is an inert streaming/authority oracle, not evidence for the real JAR.
        with patch.multiple(inputs, _BUNDLETOOL_BYTES=len(data), _BUNDLETOOL_SHA256=digest, _LAYOUTS=layout):
            with inputs.finite_scratch(layout="bundletool", parent=self.root) as scratch:
                with self.assertRaises(inputs.BuildInputError):
                    scratch.copy_from_fd("bundletool", descriptor, maximum_bytes=len(data) + 1,
                                         expected_sha256=digest)
                selected = scratch.copy_from_fd("bundletool", descriptor, maximum_bytes=len(data),
                                                expected_sha256=digest)
                path = scratch.require(selected)
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual((selected.size, selected.sha256), (len(data), digest))
                self.assertEqual(os.fstat(descriptor).st_ino, source.stat().st_ino)
            self.assertFalse(path.exists())
        self.assertEqual(source.read_bytes(), data)

    def test_output_without_original_writer_binding_is_closed_before_creation(self):
        with inputs.finite_scratch(layout="online-readback", parent=self.root) as scratch:
            with self.assertRaises(inputs.BuildInputError):
                scratch.output_path("android")
            with self.assertRaises(inputs.BuildInputError):
                scratch.read_output("android")
            self.assertEqual(list(scratch._path.iterdir()), [])

    def test_reserved_aliases_refuse_targets_and_early_project_admission(self):
        for component in (".GIT", ".MOBILE-RELEASE", *[name.upper() for name in inputs.INIT_STATES]):
            with self.subTest(component=component), self.assertRaises(inputs.BuildInputError):
                inputs._target_path("android-services", component + "/google-services.json")
        self.assertEqual(inputs._target_path("android-services", "src/google-services.json"),
                         PurePosixPath("src/google-services.json"))
        # Linux exercises canonical-name policy only. Actual case-insensitive
        # filesystem behavior still requires the later native macOS fixture.
        aliases = ((".MOBILE-RELEASE",), (next(iter(inputs.INIT_STATES)).upper(),),
                   (".mobile-release", "BUILD-INPUTS"),
                   (".mobile-release", "BUILD-INPUTS-COMPLETE.JSON"))
        for index, parts in enumerate(aliases):
            root = self.root / f"alias-{index}"
            root.mkdir()
            entry = root
            for part in parts:
                entry /= part
                entry.mkdir(mode=0o700)
            before = entry.stat().st_ino
            with self.subTest(parts=parts), inputs.invocation_custody(root, mode="build") as invocation:
                with self.assertRaises(inputs.BuildInputError):
                    with invocation.project(signing_lease=None):
                        self.fail("aliased pending namespace admitted early consumers")
            self.assertEqual(entry.stat().st_ino, before)
            self.assertEqual(list(entry.iterdir()), [])

    def test_ignore_proof_respects_rule_order_without_rewriting_patterns(self):
        cases = (
            (b"!keep.txt\n.mobile-release/\n", True),
            (b"!keep.txt\n/.mobile-release/\n*.apk\n", True),
            (b".mobile-release/\n!.mobile-release/\n", False),
            (b".mobile-release/\n!ambiguous\n/.mobile-release/\n", True),
            (b"*.apk\n", False),
            (b" .mobile-release/\n", False),
            (b"not-a-newline\v.mobile-release/\n", False),
            (b"/.mobile-release/\r\n# !comment\r\n", True),
        )
        for content, expected in cases:
            with self.subTest(content=content):
                self.assertIs(inputs._private_is_ignored(content), expected)

    def test_target_batch_restores_original_inodes_modes_and_absence(self):
        android = self.root / "google-services.json"
        ios = self.root / "GoogleService-Info.plist"
        android.write_bytes(b"")
        android.chmod(0o640)
        before = android.stat()
        with self.materialization() as (_, owner):
            owner.replace_all((self.replacement(), self.replacement("ios-services")))
            self.assertEqual(android.read_bytes(), b"synthetic-new")
            self.assertEqual(ios.read_bytes(), b"synthetic-new")
            self.assertNotEqual(android.stat().st_ino, before.st_ino)
        after = android.stat()
        self.assertEqual(android.read_bytes(), b"")
        self.assertEqual((after.st_dev, after.st_ino, stat.S_IMODE(after.st_mode)),
                         (before.st_dev, before.st_ino, 0o640))
        self.assertFalse(ios.exists())
        self.assertEqual(inputs.build_inputs_status(self.root), {"status": "idle"})

    def test_zero_mode_is_not_replaced_by_truthiness_fallback(self):
        binding = dict(device=1, inode=2, uid=3, gid=3, mode=0, links=1,
                       size=0, mtime=0, ctime=0, sha256=hashlib.sha256(b"").hexdigest())
        self.assertTrue(inputs._valid_binding(binding))
        observed = dict(binding)
        observed["mode"] = 0o600
        self.assertFalse(inputs._same_object(observed, binding))
        target = self.root / "google-services.json"
        target.write_bytes(b"old")
        target.chmod(0)
        try:
            if os.geteuid() == 0:
                with self.materialization() as (_, owner):
                    owner.replace_all((self.replacement(),))
            else:
                with self.assertRaises((PermissionError, ProcessError)):
                    with self.materialization() as (_, owner):
                        owner.replace_all((self.replacement(),))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0)
        finally:
            target.chmod(0o600)  # Exact test-owned original, after the assertion.

    def test_all_target_parents_are_inspected_before_any_publication(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"original")
        before = target.stat().st_ino
        bad = inputs.TargetReplacement("ios-services", PurePosixPath("missing/GoogleService-Info.plist"), b"new")
        with self.assertRaises((FileNotFoundError, ProcessError)):
            with self.materialization() as (_, owner):
                owner.replace_all((self.replacement(), bad))
        self.assertEqual((target.read_bytes(), target.stat().st_ino), (b"original", before))
        self.assertFalse((self.root / "missing").exists())

    def test_no_replace_capability_failure_never_moves_an_application_original(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"original")
        before = target.stat().st_ino
        fired = []
        with self.assertRaises(ProcessError):
            with self.materialization() as (_, owner):
                original = owner.project.rename
                def rename(source_fd, source, destination_fd, destination):
                    if source == "probe-a" and destination == "probe-b":
                        fired.append(True)
                        return None  # Invalid filesystem contract, before target work.
                    return original(source_fd, source, destination_fd, destination)
                owner.project.rename = rename
                owner.replace_all((self.replacement(),))
        self.assertEqual(fired, [True])
        self.assertEqual((target.read_bytes(), target.stat().st_ino), (b"original", before))

    def test_foreign_target_is_preserved_and_other_target_restores_independently(self):
        android, ios = self.root / "google-services.json", self.root / "GoogleService-Info.plist"
        android.write_bytes(b"old-android")
        ios.write_bytes(b"old-ios")
        with self.assertRaises(ProcessError):
            with self.materialization() as (_, owner):
                owner.replace_all((self.replacement(), self.replacement("ios-services")))
                ios.write_bytes(b"foreign-change")
        self.assertEqual(ios.read_bytes(), b"foreign-change")
        self.assertEqual(android.read_bytes(), b"old-android")
        session = self.pending()
        journal = self.root / inputs._PRIVATE / inputs._PENDING
        control_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                          "st_size", "st_mtime_ns", "st_ctime_ns")

        def control_state(name):
            path = journal / name
            details = path.stat()
            return tuple(getattr(details, field) for field in control_fields), path.read_bytes()

        previous_controls = {name: control_state(name) for name in owner.controls}
        observed = []
        actual_checkpoint = inputs.BuildInputs._checkpoint

        def checkpoint(recovery):
            if recovery.invocation is not None:
                return actual_checkpoint(recovery)
            guard = recovery.cancellation
            ledger = guard.lifetime_ledger
            sequence = recovery.seq + 1
            record = dict(owner=recovery, guard=guard, ledger=ledger, fatal=ledger.fatal,
                          depth=guard.depth, sequence=sequence, previous=recovery.previous,
                          name=f"checkpoint-{sequence:03}.json", returned=False)
            observed.append(record)
            result = actual_checkpoint(recovery)
            record.update(returned=True, actual_sequence=recovery.seq, digest=recovery.previous,
                          control_digest=recovery.controls[record["name"]]["sha256"])
            return result

        with patch.object(inputs.BuildInputs, "_checkpoint", checkpoint), self.assertRaises(ProcessError) as caught:
            self.recover(session)
        self.assertTrue(caught.exception.fatal)
        # The independent target checkpoint and the failed-action checkpoint
        # both use the same original recovery owner. Assertions stay outside
        # callbacks whose failures the product must retain as secondary errors.
        self.assertEqual(len(observed), 2)
        recovery, guard = observed[0]["owner"], observed[0]["guard"]
        self.assertIsNot(recovery, owner)
        self.assertIsNone(recovery.invocation)
        self.assertEqual((recovery.token, recovery.project.root), (session, self.root))
        self.assertIs(guard, recovery.cancellation)
        self.assertIs(guard, recovery.project.guard)
        self.assertIsNot(guard, owner.cancellation)
        for record in observed:
            self.assertIs(record["owner"], recovery)
            self.assertIs(record["guard"], guard)
            self.assertIs(record["ledger"], guard.lifetime_ledger)
            self.assertTrue(record["fatal"])
            self.assertGreater(record["depth"], 0)
            self.assertTrue(record["returned"])
            self.assertEqual(record["actual_sequence"], record["sequence"])
            content = (journal / record["name"]).read_bytes()
            payload = json.loads(content)
            self.assertEqual((payload["session"], payload["sequence"], payload["previous"]),
                             (session, record["sequence"], record["previous"]))
            digest = hashlib.sha256(content).hexdigest()
            self.assertEqual((record["digest"], record["control_digest"]), (digest, digest))
        self.assertEqual((recovery.seq, recovery.previous),
                         (observed[-1]["sequence"], observed[-1]["digest"]))
        self.assertTrue(guard.lifetime_ledger.fatal)
        self.assertEqual(guard.handler_state, "RESTORED")
        self.assertTrue(all(slot.number is None and slot.close_state == "CLOSED"
                            for slot in (recovery.slot, *recovery.control_slots)))
        self.assertEqual({name: control_state(name) for name in previous_controls}, previous_controls)
        self.assertFalse(any(path.name.endswith(".stage") for path in journal.iterdir()))
        self.assertEqual(self.pending(), session)
        self.assertEqual(ios.read_bytes(), b"foreign-change")
        self.assertEqual(android.read_bytes(), b"old-android")
        # Exact fixture-owned preservation outside the reserved transaction namespace.
        saved = self.root / "saved-foreign"
        ios.rename(saved)
        self.assertEqual(self.recover(session)["status"], "recovered")
        self.assertEqual(ios.read_bytes(), b"old-ios")
        self.assertEqual(saved.read_bytes(), b"foreign-change")

    def test_original_interruption_survives_independent_cleanup_failure(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"old")
        original = KeyboardInterrupt("original-test-interruption")
        caught = None
        try:
            with self.materialization() as (_, owner):
                owner.replace_all((self.replacement(),))
                target.write_bytes(b"foreign")
                raise original
        except KeyboardInterrupt as error:
            caught = error
        self.assertIs(caught, original)
        self.assertEqual(target.read_bytes(), b"foreign")
        self.pending()

    def test_after_effect_move_error_is_retained_as_failure_without_losing_original(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"old")
        before = target.stat().st_ino
        fired = []
        with self.assertRaises(OSError):
            with self.materialization() as (_, owner):
                rename = owner.project.rename
                def after_effect(source_fd, source, destination_fd, destination):
                    result = rename(source_fd, source, destination_fd, destination)
                    if source == "stage-0" and destination == target.name and not fired:
                        fired.append(True)
                        raise OSError("synthetic after-effect report")
                    return result
                owner.project.rename = after_effect
                owner.replace_all((self.replacement(),))
        self.assertEqual(fired, [True])
        self.assertEqual((target.read_bytes(), target.stat().st_ino), (b"old", before))
        self.assertEqual(inputs.build_inputs_status(self.root), {"status": "idle"})

    def test_terminal_recovery_never_reopens_or_recompares_changed_application_targets(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"original")
        with self.assertRaises(ProcessError):
            with patch.object(inputs, "_retire_terminal", side_effect=OSError("stop after terminal publication")):
                with self.materialization() as (_, owner):
                    owner.replace_all((self.replacement(),))
        state = inputs.build_inputs_status(self.root)
        self.assertEqual(state["status"], "cleanup-only")
        target.write_bytes(b"legitimate-later-edit")
        actual_read = inputs._read_file
        def read(fd, name, *args, **kwargs):
            self.assertNotEqual(name, target.name, "terminal recovery inspected a historical target")
            return actual_read(fd, name, *args, **kwargs)
        with patch.object(inputs, "_read_file", side_effect=read):
            self.assertEqual(self.recover(state["session"])["status"], "recovered")
        self.assertEqual(target.read_bytes(), b"legitimate-later-edit")
        self.assertEqual(self.recover(state["session"])["status"], "absent")

    def test_move_interruption_is_not_replaced_by_later_reconciliation_failure(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"original")
        before = target.stat().st_ino
        original = KeyboardInterrupt("original-move-interruption")
        events = []
        caught = None
        try:
            with self.materialization() as (_, owner):
                rename, settle = owner.project.rename, owner._settle_move
                def after_effect(source_fd, source, destination_fd, destination):
                    rename(source_fd, source, destination_fd, destination)
                    if source == "stage-0" and destination == target.name and not events:
                        events.append("interrupted")
                        raise original
                def reconcile(row):
                    if events == ["interrupted"]:
                        events.append("observation-failed")
                        raise OSError("synthetic later observation failure")
                    return settle(row)
                owner.project.rename, owner._settle_move = after_effect, reconcile
                owner.replace_all((self.replacement(),))
        except KeyboardInterrupt as error:
            caught = error
        self.assertIs(caught, original)
        self.assertEqual(events, ["interrupted", "observation-failed"])
        self.assertEqual((target.read_bytes(), target.stat().st_ino), (b"original", before))

    def test_unknown_original_consumer_requires_new_manual_fact_not_lock_absence(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"original")
        with self.assertRaises(ProcessError):
            with self.materialization() as (invocation, owner):
                owner.replace_all((self.replacement(),))
                invocation.cancellation.lifetime_ledger._bind_command(object())
                # Inert pending-record oracle only; no process/containment evidence.
        session = self.pending()
        with self.assertRaises(inputs.BuildInputError):
            self.recover(session)
        self.assertEqual(target.read_bytes(), b"synthetic-new")
        with self.assertRaises(inputs.BuildInputError):
            self.recover(session, manual=True, input_stream=_TTY("wrong\n"), output_stream=_TTY())
        self.assertEqual(target.read_bytes(), b"synthetic-new")
        incoming = _TTY(f"recheck {session} original-workers-are-idle\n")
        self.assertEqual(self.recover(session, manual=True, input_stream=incoming,
                                     output_stream=_TTY())["status"], "recovered")
        self.assertEqual(target.read_bytes(), b"original")

    def test_retired_fd_slot_is_not_retried_after_a_close_error(self):
        with self.assertRaises(ProcessError), inputs.finite_scratch(layout="online-runner", parent=self.root) as scratch:
            slot = inputs._FD(scratch.cancellation)
            descriptor = slot.open(self.root / "owned-fd", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            closed = []
            original_close = os.close
            def close(number):
                closed.append(number)
                original_close(number)
                raise OSError("synthetic close-after-effect")
            with patch.object(inputs.os, "close", side_effect=close):
                with self.assertRaises(ProcessError):
                    slot.close()
                with self.assertRaises(ProcessError):
                    slot.close()
            self.assertIsNone(slot.number)
            self.assertEqual(closed, [descriptor])
            # The surrounding owner remains fatal; it cannot publish a clean result.

    def test_pending_inspection_settles_descriptors_without_automatic_recovery(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"original")
        with self.assertRaises(ProcessError):
            with self.materialization() as (invocation, owner):
                owner.replace_all((self.replacement(),))
                invocation.cancellation.lifetime_ledger._bind_command(object())
        session = self.pending()
        pending = self.root / inputs._PRIVATE / inputs._PENDING
        before = (pending.stat().st_ino, sorted(p.name for p in pending.iterdir()))
        actual_load, actual_close = inputs._load_pending, inputs._FD.close
        for action, cut in (("status", "load-return"), ("recover", "load-return"), ("status", "close")):
            observed, closes = {}, []
            original = KeyboardInterrupt("synthetic-inspection-handoff")
            def load(owner):
                actual_load(owner)
                slots = [owner.slot, owner.scratch.slot, *owner.scratch.parent.slots,
                         *[slot for parent in owner.parents.values() for slot in parent.slots]]
                observed.update(owner=owner, slots=slots)
                if cut == "load-return":
                    raise original
            def close(slot):
                ours = slot in observed.get("slots", ()) and slot.number is not None
                if ours:
                    closes.append(slot)
                    if cut == "close" and slot is observed["owner"].slot:
                        self.assertGreater(slot.guard.depth, 0)
                        slot.guard.interrupt(signal.SIGINT, None)
                result = actual_close(slot)
                if ours and cut == "load-return" and slot is observed["owner"].scratch.slot:
                    raise OSError("synthetic later inspection-close error")
                return result
            with self.subTest(action=action, cut=cut), patch.object(inputs, "_load_pending", load), patch.object(
                    inputs._FD, "close", close), patch.object(inputs.BuildInputs, "_finish") as finish:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    inputs.build_inputs_status(self.root) if action == "status" else self.recover(session)
                finish.assert_not_called()
            if cut == "load-return":
                self.assertIs(caught.exception, original)
                self.assertTrue(observed["owner"].cancellation.lifetime_ledger.fatal)
            self.assertCountEqual(closes, observed["slots"])
            self.assertTrue(all(slot.number is None and slot.close_state == "CLOSED"
                                for slot in observed["slots"]))
            self.assertEqual(target.read_bytes(), b"synthetic-new")
            self.assertEqual((pending.stat().st_ino, sorted(p.name for p in pending.iterdir())), before)

    def test_reader_cleanup_dispatch_and_numeric_retirement_cover_default_cancellation(self):
        source = self.root / "reader-source"
        source.write_bytes(b"synthetic-reader-content")
        actual_open, actual_close, primitive_close = inputs._FD.open, inputs._FD.close, os.close
        for cut in ("dispatch", "retired"):
            observed, calls = {}, []
            def open_slot(slot, name, *args, **kwargs):
                result = actual_open(slot, name, *args, **kwargs)
                if name == source.name:
                    observed.update(slot=slot, number=result, attempted=False)
                return result
            def close_slot(slot):
                if cut == "dispatch" and slot is observed.get("slot") and not calls:
                    self.assertGreater(slot.guard.depth, 0)
                    calls.append("cut")
                    slot.guard.interrupt(signal.SIGINT, None)
                return actual_close(slot)
            def close_primitive(number):
                if number == observed.get("number") and not observed["attempted"]:
                    if cut == "retired":
                        slot = observed["slot"]
                        self.assertIsNone(slot.number)
                        self.assertEqual(slot.close_state, "ATTEMPTED")
                        self.assertGreater(slot.guard.depth, 0)
                        calls.append("cut")
                        slot.guard.interrupt(signal.SIGINT, None)
                    observed["attempted"] = True
                    calls.append("close")
                return primitive_close(number)
            try:
                with self.subTest(cut=cut), self.assertRaises(KeyboardInterrupt), patch.object(
                        inputs._FD, "open", open_slot), patch.object(inputs._FD, "close", close_slot), patch.object(
                        inputs.os, "close", close_primitive):
                    with inputs.finite_scratch(layout="online-runner", parent=self.root) as scratch:
                        inputs._read_file(scratch.parent.fd, source.name, scratch.cancellation, 1024)
                        self.fail("cancelled reader published its result")
                self.assertEqual(calls, ["cut", "close"])
                self.assertEqual(observed["slot"].close_state, "CLOSED")
                self.assertEqual(source.read_bytes(), b"synthetic-reader-content")
            finally:
                # The fault wrapper can prove the exact returned test FD never
                # entered close. Never retry a possibly entered close primitive.
                if observed and not observed["attempted"]:
                    primitive_close(observed["number"])

    def test_direct_acquisition_refusals_are_distinct_from_wrapped_lost_results(self):
        with inputs.finite_scratch(layout="online-runner", parent=self.root) as scratch:
            slot = inputs._FD(scratch.cancellation)
            with self.assertRaises(FileNotFoundError):
                slot.open(self.root / "absent-file", os.O_RDONLY)
            self.assertEqual(slot.open_state, "NO_EFFECT")
            slot.close()
            record = {"state": "NEW"}
            (self.root / "already-present").mkdir()
            with self.assertRaises(FileExistsError):
                inputs._mkdir_private("already-present", scratch.parent.fd, scratch.cancellation, record)
            self.assertEqual(record, {"state": "NO_EFFECT"})
            self.assertFalse(scratch.cancellation.lifetime_ledger.fatal)

        source = self.root / "known-source"
        source.write_bytes(b"synthetic")
        actual_open, actual_close = os.open, os.close
        for after_effect in (False, True):
            retained = []
            def open_fault(name, *args, **kwargs):
                if name == source:
                    if after_effect:
                        retained.append(actual_open(name, *args, **kwargs))
                    raise FileNotFoundError(errno.ENOENT, "synthetic wrapper lost its result")
                return actual_open(name, *args, **kwargs)
            try:
                with self.subTest(after_effect=after_effect), self.assertRaises(ProcessError):
                    with inputs.finite_scratch(layout="online-runner", parent=self.root) as scratch:
                        slot = inputs._FD(scratch.cancellation)
                        with patch.object(inputs.os, "open", open_fault), self.assertRaises(FileNotFoundError):
                            slot.open(source, os.O_RDONLY)
                        self.assertEqual(slot.open_state, "UNKNOWN")
                        self.assertIsNone(slot.number)
                        self.assertTrue(scratch.cancellation.lifetime_ledger.fatal)
                        with self.assertRaises(ProcessError):
                            scratch.cancellation.check()
                        with self.assertRaises(ProcessError):
                            slot.close()
                for number in retained:
                    self.assertEqual(os.fstat(number).st_ino, source.stat().st_ino)
            finally:
                # The wrapper, not the helper, retained these positive results.
                for number in retained:
                    actual_close(number)

    def test_unobserved_private_directory_creation_is_retained_and_fatal(self):
        actual_mkdir = os.mkdir
        for name in (inputs._PRIVATE, inputs._PENDING, "scratch"):
            root = self.root / ("mkdir-" + name.lstrip("."))
            root.mkdir()
            (root / ".gitignore").write_text(".mobile-release/\n", encoding="utf-8")
            original = KeyboardInterrupt("synthetic-directory-return-lost")
            cuts = []
            def mkdir_fault(target, *args, **kwargs):
                actual_mkdir(target, *args, **kwargs)
                if target == name:
                    cuts.append(target)
                    raise original
            with self.subTest(name=name), self.assertRaises(KeyboardInterrupt) as caught:
                with inputs.invocation_custody(root, mode="build") as invocation:
                    with invocation.project(signing_lease=None):
                        with patch.object(inputs.os, "mkdir", mkdir_fault):
                            with invocation.materialization(signing_lease=None):
                                self.fail("unobserved creation entered consumers")
            self.assertIs(caught.exception, original)
            self.assertEqual(cuts, [name])
            self.assertTrue(invocation.cancellation.lifetime_ledger.fatal)
            retained = root / inputs._PRIVATE
            if name != inputs._PRIVATE:
                retained /= inputs._PENDING
            if name == "scratch":
                retained /= "scratch"
            self.assertTrue(retained.is_dir())
            self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
