"""Checked-input policy, real filesystem races and inert lifetime fault seams.

The model alias tests are not macOS evidence. The final class exercises genuine
Darwin aliases only on the reviewed native runner. No test launches a command,
changes OS aliases or uses an external credential. Fault-only descriptors below
are inert numbers with every open/close mocked, never foreign host descriptors.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import checked_files as checked
from mobile_release.cancellation import DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError, ProcessError


@contextmanager
def no_signal_setters():
    # A genuine zero-handler guard is supported. Replace only observation for
    # these inert/source tests; any attempted signal installation is a failure.
    callback = lambda _signal, _frame: None
    with patch("mobile_release.cancellation.signal.getsignal", return_value=callback), \
         patch("mobile_release.cancellation.signal.signal", side_effect=AssertionError("unexpected signal setter")):
        yield


@contextmanager
def files(*, directory=None):
    root = Path(tempfile.mkdtemp(prefix="mrk-checked-input-", dir=directory))
    if directory is None:
        root = root.resolve()
    project, external = root / "project", root / "external"
    project.mkdir(mode=0o700)
    external.mkdir(mode=0o700)
    try:
        yield root, project, external
    except BaseException:
        # An unexpected failure is evidence, not permission for fallback cleanup.
        raise
    else:
        shutil.rmtree(root)


def write_private(path, content=b"selected private bytes"):
    path.write_bytes(content)
    path.chmod(0o600)
    return path


class CheckedFilesPolicyTests(unittest.TestCase):
    def test_exact_darwin_alias_pairs_and_physical_protection(self):
        link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        with patch.object(checked.sys, "platform", "darwin"):
            for name in ("tmp", "var"):
                for target in ("private/" + name, "/private/" + name):
                    self.assertEqual(checked._alias_parts(name, link, target), ("private", name))
            bad = [("tmp", link, "/private/var"), ("var", link, "/private/tmp"),
                   ("tmp", link, "/private/other/../tmp"), ("other", link, "/private/tmp"),
                   ("tmp", SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=501), "/private/tmp")]
            for name, observed, target in bad:
                with self.subTest(name=name, target=target), self.assertRaises(ValidationError):
                    checked._alias_parts(name, observed, target)
            protected = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            for path in ("/", "/private", "/private/var"):
                checked._protect_directory(Path(path), protected)
                with self.subTest(path=path), self.assertRaises(ValidationError):
                    checked._protect_directory(Path(path), SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0))
            checked._protect_directory(Path("/private/tmp"), SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0))
            for mode, uid in ((0o777, 0), (0o1777, 501), (0o755, 501)):
                with self.subTest(mode=mode, uid=uid), self.assertRaises(ValidationError):
                    checked._protect_directory(Path("/private/tmp"), SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid))

            # Inert equivalent-spelling identities exercise the actual walker,
            # not a casefold oracle. No descriptor below reaches a real OS call.
            cases = (
                (("Private",), "private", 0o777, 0, "system protected"),
                (("Private",), "private", 0o755, 501, "system protected"),
                (("Private", "Var"), "var", 0o777, 0, "system protected"),
                (("Private", "Tmp"), "tmp", 0o777, 0, "sticky protection"),
                (("Private", "Tmp"), "tmp", 0o1777, 501, "sticky protection"),
                (("Private", "Tmp"), None, 0, 0, None),
            )
            for parts, changed, mode, uid, message in cases:
                with self.subTest(parts=parts, changed=changed, mode=mode, uid=uid):
                    metadata = {
                        name: SimpleNamespace(st_dev=1, st_ino=inode, st_mode=stat.S_IFDIR | permissions,
                                              st_uid=0, st_gid=0)
                        for name, inode, permissions in (("private", 2, 0o755), ("var", 3, 0o755), ("tmp", 4, 0o1777))
                    }
                    if changed is not None:
                        metadata[changed].st_mode, metadata[changed].st_uid = stat.S_IFDIR | mode, uid
                    entries = {(501, "private"): metadata["private"], (501, "Private"): metadata["private"],
                               (502, "var"): metadata["var"], (502, "Var"): metadata["var"],
                               (502, "tmp"): metadata["tmp"], (502, "Tmp"): metadata["tmp"]}
                    pinned = {500 + value.st_ino: value for value in metadata.values()}
                    reader = checked._Reader(SimpleNamespace(check=lambda: None))
                    reader.root = checked._Descriptor(501, "OWNED")

                    def lookup(parent, name):
                        return entries[parent.number, name]

                    def open_directory(name, *, parent, directory):
                        self.assertTrue(directory)
                        return checked._Descriptor(500 + lookup(parent, name).st_ino, "OWNED")

                    with patch.object(reader, "_stat", side_effect=lookup), \
                         patch.object(reader, "_open", side_effect=open_directory), \
                         patch.object(checked.os, "fstat", side_effect=pinned.__getitem__), \
                         patch.object(checked.os, "open", side_effect=AssertionError("inert directory open reached OS")), \
                         patch.object(checked.os, "close", side_effect=AssertionError("inert directory close reached OS")):
                        if message is not None:
                            with self.assertRaisesRegex(ValidationError, message):
                                reader._directories(parts)
                        else:
                            _slot, diagnostic = reader._directories(parts)
                            self.assertEqual(diagnostic, Path("/Private/Tmp"))
                            self.assertEqual([node.name for node in reader.nodes], ["Private", "private", "Tmp", "tmp"])
                            reader.terminal()
                            # The caller-spelled entry still matches. Losing the
                            # exact entry that selected its role must also reject.
                            entries[502, "tmp"] = SimpleNamespace(**dict(vars(metadata["tmp"]), st_ino=40))
                            with self.assertRaisesRegex(ValidationError, "ancestry changed"):
                                reader.terminal()
        with patch.object(checked.sys, "platform", "linux"):
            with self.assertRaises(ValidationError):
                checked._alias_parts("tmp", link, "/private/tmp")
            # A real Linux directory is not subject to an Apple alias exception.
            checked._protect_directory(Path("/private/tmp"), SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000))

    def test_private_absolute_and_public_relative_policies_reject_hidden_parent_traversal(self):
        with self.assertRaisesRegex(ValidationError, "absolute"):
            checked._absolute(Path("key"), private=True)
        with patch.object(checked.Path, "cwd", return_value=Path("/observed/cwd")):
            self.assertEqual(checked._absolute(Path("tool.jar"), private=False), Path("/observed/cwd/tool.jar"))
        with patch.object(checked.os, "open", side_effect=AssertionError("acquisition reached")) as opened:
            for path in (Path("/tmp/link/../key"), Path("relative/../tool.jar")):
                with self.subTest(path=path), self.assertRaisesRegex(ValidationError, "parent traversal"):
                    checked.inspect_external_path(path, kind="public-tool", project_root=None)
            opened.assert_not_called()

    def test_pinned_bundletool_arguments_are_not_caller_overrides(self):
        with patch.object(checked, "_consume", side_effect=AssertionError("input acquisition reached")) as consumed:
            for maximum, digest in ((checked.BUNDLETOOL_MAX_BYTES + 1, checked.BUNDLETOOL_SHA256),
                                    (True, checked.BUNDLETOOL_SHA256),
                                    (checked.BUNDLETOOL_MAX_BYTES, "0" * 64)):
                with self.subTest(maximum=maximum), self.assertRaisesRegex(ValidationError, "pinned"):
                    checked.copy_bundletool(Path("/fictional/tool.jar"), scratch=object(),
                                            maximum_bytes=maximum, expected_sha256=digest)
            consumed.assert_not_called()
        self.assertEqual(checked.BUNDLETOOL_MAX_BYTES, 32_520_401)

    def test_terminal_alias_metadata_or_direct_target_drift_prevents_publication(self):
        metadata = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFLNK | 0o777, st_uid=0,
                        st_gid=0, st_nlink=1, st_size=11, st_mtime_ns=1, st_ctime_ns=1)
        observed = SimpleNamespace(**metadata)
        with no_signal_setters():
            guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
            guard.install()
            guard.activate()
            reader = checked._Reader(guard)
            reader.root = checked._Descriptor(504, "OWNED")  # Inert; never passed to a real OS call.
            reader.aliases.append(checked._Alias("tmp", observed, "private/tmp"))
            try:
                for current, target in ((SimpleNamespace(**dict(metadata, st_uid=501)), "private/tmp"),
                                        (observed, "private/var")):
                    with patch.object(reader, "_stat", return_value=current), \
                         patch.object(checked.os, "readlink", return_value=target), \
                         self.assertRaisesRegex(ValidationError, "alias changed"):
                        reader.terminal()
            finally:
                guard.restore()


class CheckedFilesFilesystemTests(unittest.TestCase):
    def test_private_bytes_bounds_modes_outside_project_and_original_preservation(self):
        with no_signal_setters(), files() as (_root, project, external):
            source = write_private(external / "material")
            original = source.read_bytes()
            # Hardlink exclusion is deliberately not claimed by this policy.
            os.link(source, project / "same-object")
            self.assertEqual(checked.read_external_bytes(source, kind="private-small", project_root=project), original)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ValidationError, "outside"):
                checked.read_external_bytes(project / "same-object", kind="private-small", project_root=project)
            (project / "nested").mkdir(mode=0o700)
            inside = write_private(project / "nested/material", b"inside the project")
            spelling = project.with_name("PROJECT")
            original_directories = checked._Reader._directories

            def equivalent_directory(reader, parts):
                prefix = spelling.parts[1:]
                if parts[:len(prefix)] == prefix:
                    suffix = parts[len(prefix):]
                    pinned, _canonical = original_directories(reader, (*project.parts[1:], *suffix))
                    return pinned, spelling.joinpath(*suffix)
                return original_directories(reader, parts)

            # Model a spelling disagreement while retaining real owned project
            # descriptors. This is not native case-insensitive-filesystem proof.
            with patch.object(checked._Reader, "_directories", new=equivalent_directory), \
                 self.assertRaisesRegex(ValidationError, "outside"):
                checked.read_external_bytes(spelling / inside.relative_to(project), kind="private-small", project_root=project)
            self.assertEqual(inside.read_bytes(), b"inside the project")
            if sys.platform.startswith("linux"):
                # On an ordinary Linux filesystem this is a genuinely different
                # sibling, not permission to casefold project containment.
                spelling.mkdir(mode=0o700)
                distinct = write_private(spelling / "material", b"distinct external directory")
                self.assertNotEqual((spelling.stat().st_dev, spelling.stat().st_ino),
                                    (project.stat().st_dev, project.stat().st_ino))
                self.assertEqual(checked.read_external_bytes(distinct, kind="private-small", project_root=project),
                                 b"distinct external directory")
            source.chmod(0o644)
            with self.assertRaisesRegex(ValidationError, "group or others"):
                checked.read_external_bytes(source, kind="private-small", project_root=project)
            self.assertEqual(checked.inspect_external_path(source, kind="public-tool", project_root=None), source)
            source.chmod(0o600)
            source.write_bytes(b"")
            self.assertEqual(checked.read_external_bytes(source, kind="credentials-file", project_root=project), b"")
            with self.assertRaisesRegex(ValidationError, "empty"):
                checked.read_external_bytes(source, kind="private-small", project_root=project)
            with source.open("wb") as handle:
                handle.truncate(checked.CREDENTIALS_FILE_MAX_BYTES + 1)
            with self.assertRaisesRegex(ValidationError, "size limit"):
                checked.read_external_bytes(source, kind="credentials-file", project_root=project)
            self.assertEqual(source.stat().st_size, checked.CREDENTIALS_FILE_MAX_BYTES + 1)

    def test_leaf_and_lower_links_reject_without_changing_their_targets(self):
        with no_signal_setters(), files() as (root, project, external):
            source = write_private(external / "material")
            (external / "leaf-link").symlink_to(source)
            (root / "lower-link").symlink_to(external, target_is_directory=True)
            for path in (external / "leaf-link", root / "lower-link/material"):
                with self.subTest(path=path.name), self.assertRaisesRegex(ValidationError, "symbolic"):
                    checked.read_external_bytes(path, kind="private-small", project_root=project)
            self.assertEqual(source.read_bytes(), b"selected private bytes")
            self.assertTrue((external / "leaf-link").is_symlink())

    def test_source_or_original_parent_replacement_and_same_inode_edit_fail_terminal_checks(self):
        for change in ("replace-leaf", "edit-inode", "replace-parent"):
            with self.subTest(change=change), no_signal_setters(), files() as (root, project, external):
                source = write_private(external / "material")
                original_read, fired = os.read, []

                def changing_read(number, amount):
                    content = original_read(number, amount)
                    if content and not fired:
                        fired.append(change)
                        if change == "replace-leaf":
                            source.rename(external / "original")
                            write_private(source, b"replacement bytes")
                        elif change == "edit-inode":
                            before = source.stat()
                            source.write_bytes(b"different private byte")
                            os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
                        else:
                            external.rename(root / "original-parent")
                            external.mkdir(mode=0o700)
                            write_private(source, b"replacement bytes")
                    return content

                with patch.object(checked.os, "read", side_effect=changing_read), self.assertRaises(ValidationError):
                    checked.read_external_bytes(source, kind="private-small", project_root=project)
                self.assertEqual(fired, [change])
                self.assertTrue(source.is_file())

    def test_sibling_activity_does_not_invalidate_directory_custody(self):
        with no_signal_setters(), files() as (_root, project, external):
            source = write_private(external / "material")
            original_read, fired = os.read, []

            def sibling_read(number, amount):
                content = original_read(number, amount)
                if content and not fired:
                    fired.append(True)
                    (external / "new-sibling-directory").mkdir()
                return content

            with patch.object(checked.os, "read", side_effect=sibling_read):
                self.assertEqual(checked.read_external_bytes(source, kind="private-small", project_root=project),
                                 b"selected private bytes")
            self.assertEqual(fired, [True])

    def test_short_or_growing_read_rejects_even_when_file_metadata_is_unchanged(self):
        with no_signal_setters(), files() as (_root, project, external):
            source = write_private(external / "material")
            for chunks, message in (((b"short", b""), "shortened"),
                                    ((b"x" * (source.stat().st_size + 1),), "grew")):
                with self.subTest(message=message), patch.object(checked.os, "read", side_effect=chunks), \
                     self.assertRaisesRegex(ValidationError, message):
                    checked.read_external_bytes(source, kind="private-small", project_root=project)
            self.assertEqual(source.read_bytes(), b"selected private bytes")

    def test_bundletool_stream_borrows_one_original_fd_and_publishes_after_its_close(self):
        # Model only the separately tested finite scratch implementation. This
        # proves reader routing/custody, NOT real pinned-JAR authentication.
        from mobile_release import build_inputs

        with no_signal_setters(), files() as (_root, _project, external):
            source = write_private(external / "tool.jar", b"synthetic tool bytes")
            guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
            guard.install()
            guard.activate()
            closed, calls = [], []
            original_close = os.close

            class ScratchContract:
                cancellation = guard

                def copy_from_fd(self, role, number, *, maximum_bytes, expected_sha256):
                    calls.append((role, number, maximum_bytes, expected_sha256, os.read(number, 4096)))
                    return SimpleNamespace(size=len(calls[-1][-1]), sha256=expected_sha256)

                def require(self, snapshot):
                    self.asserted = True
                    if calls[0][1] not in closed:
                        raise AssertionError("snapshot published before original close")
                    return Path("/fictional/selected-snapshot")

            def close(number):
                original_close(number)
                closed.append(number)

            scratch = ScratchContract()
            try:
                with patch.object(build_inputs, "FiniteScratch", ScratchContract), patch.object(checked.os, "close", side_effect=close):
                    snapshot = checked.copy_bundletool(source, scratch=scratch,
                        maximum_bytes=checked.BUNDLETOOL_MAX_BYTES, expected_sha256=checked.BUNDLETOOL_SHA256)
                self.assertEqual(len(calls), 1)
                role, number, maximum, digest, content = calls[0]
                self.assertEqual((role, maximum, digest, content),
                                 ("bundletool", checked.BUNDLETOOL_MAX_BYTES, checked.BUNDLETOOL_SHA256, b"synthetic tool bytes"))
                self.assertEqual(closed.count(number), 1)
                self.assertEqual(snapshot.size, len(content))
                self.assertTrue(scratch.asserted)
                self.assertEqual(source.read_bytes(), content)
            finally:
                guard.restore()


class CheckedFilesLifetimeContractTests(unittest.TestCase):
    def test_inherited_reader_closes_only_known_child_copies_once_without_parent_guard(self):
        with no_signal_setters():
            guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
            reader = checked._Reader(guard)
            reader.descriptors = [checked._Descriptor(505, "OWNED"), checked._Descriptor(None, "CLOSING")]
            with patch.object(checked.os, "getpid", return_value=reader.pid + 1), \
                 patch.object(checked.os, "close") as close, \
                 patch.object(checked, "_mark_fork_unsafe") as unsafe, \
                 patch.object(guard, "_abort", side_effect=AssertionError("parent ledger reached")):
                reader.after_fork_child()
                reader.after_fork_child()
                close.assert_called_once_with(505)
                self.assertTrue(unsafe.called)
                with self.assertRaisesRegex(ProcessCleanupError, "inherited"):
                    reader._origin()
            self.assertIsNone(reader.descriptors[0].number)
            self.assertEqual(reader.descriptors[1].state, "INHERITED_UNKNOWN")

    def test_failed_close_retires_its_number_and_still_closes_independent_descriptors(self):
        with no_signal_setters():
            guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
            guard.install()
            guard.activate()
            reader = checked._Reader(guard)
            reader.descriptors = [checked._Descriptor(501, "OWNED"), checked._Descriptor(502, "OWNED")]
            calls = []

            def close(number):
                self.assertTrue(all(slot.number != number for slot in reader.descriptors))
                calls.append(number)
                if number == 502:
                    raise OSError("fictional close return loss")

            try:
                with patch.object(checked.os, "close", side_effect=close):
                    with self.assertRaises(ProcessCleanupError):
                        reader.close()
                    with self.assertRaises(ProcessCleanupError):
                        reader.close()
                self.assertEqual(calls, [502, 501])
                self.assertEqual([slot.state for slot in reader.descriptors], ["CLOSED", "UNKNOWN"])
                self.assertTrue(guard.lifetime_ledger.fatal)
            finally:
                guard.restore()

    def test_open_return_loss_is_prearmed_and_cannot_be_retried_as_an_unknown_number(self):
        with no_signal_setters():
            guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
            guard.install()
            guard.activate()
            reader = checked._Reader(guard)
            primary = KeyboardInterrupt()

            def lost_open(*_args, **_kwargs):
                self.assertEqual(reader.descriptors[-1].state, "ACQUIRING")
                self.assertIsNone(reader.descriptors[-1].number)
                raise primary

            try:
                with patch.object(checked.os, "open", side_effect=lost_open), \
                     patch.object(checked.os, "close", side_effect=AssertionError("no known descriptor")) as close:
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        reader._open("/fictional", parent=None, directory=True)
                    self.assertIs(raised.exception, primary)
                    with self.assertRaises(ProcessCleanupError):
                        reader.close()
                    close.assert_not_called()
                self.assertEqual(reader.descriptors[0].state, "UNKNOWN")
                self.assertTrue(guard.lifetime_ledger.fatal)
            finally:
                guard.restore()

    def test_cleanup_failure_blocks_publication_and_keeps_first_interruption_and_actual_guard(self):
        for primary in (None, ValidationError("fictional body rejection"), KeyboardInterrupt(), SystemExit(73)):
            with self.subTest(primary=type(primary).__name__), no_signal_setters():
                guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
                guard.install()
                guard.activate()
                reached = []

                def acquire(reader, _path, _policy, _project):
                    self.assertIs(reader.cancellation, guard)
                    reader.descriptors.append(checked._Descriptor(503, "OWNED"))
                    reached.append(reader)
                    return object()

                def read(_reader, _node):
                    if primary is not None:
                        raise primary
                    return b"must not escape failed cleanup"

                try:
                    with patch.object(checked._Reader, "acquire", new=acquire), \
                         patch.object(checked._Reader, "read", new=read), \
                         patch.object(checked._Reader, "terminal", return_value=None), \
                         patch.object(checked.os, "close", side_effect=OSError("fictional close failure")) as close:
                        expected = type(primary) if isinstance(primary, (KeyboardInterrupt, SystemExit)) else ProcessError
                        with self.assertRaises(expected) as raised:
                            checked.read_external_bytes(Path("/fictional/material"), kind="private-small",
                                                        project_root=Path("/fictional/project"), cancellation=guard)
                    if isinstance(primary, (KeyboardInterrupt, SystemExit)):
                        self.assertIs(raised.exception, primary)
                    else:
                        self.assertTrue(raised.exception.fatal)
                    self.assertEqual(close.call_count, 1)
                    self.assertEqual(len(reached), 1)
                    self.assertTrue(guard.lifetime_ledger.fatal)
                    self.assertEqual(guard.handler_state, "ACTIVE", "borrower restored its owner's handlers")
                finally:
                    guard.restore()

    def test_cancellation_during_settled_borrowed_cleanup_still_prevents_byte_publication(self):
        with no_signal_setters():
            guard = DefaultCancellation(ProcessCleanupError, "fixture cleanup")
            guard.install()
            guard.activate()

            def acquire(reader, _path, _policy, _project):
                reader.descriptors.append(checked._Descriptor(506, "OWNED"))
                return object()

            def close(_number):
                guard.cancelled = True

            try:
                with patch.object(checked._Reader, "acquire", new=acquire), \
                     patch.object(checked._Reader, "read", return_value=b"not publishable"), \
                     patch.object(checked._Reader, "terminal", return_value=None), \
                     patch.object(checked.os, "close", side_effect=close) as closed, \
                     self.assertRaises(KeyboardInterrupt):
                    checked.read_external_bytes(Path("/fictional/material"), kind="private-small",
                                                project_root=Path("/fictional/project"), cancellation=guard)
                closed.assert_called_once_with(506)
                self.assertFalse(guard.lifetime_ledger.fatal, "settled cancellation became UNKNOWN")
                self.assertEqual(guard.handler_state, "ACTIVE")
            finally:
                guard.restore()


class NativeCheckedFilesTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "requires actual macOS system alias topology")
    def test_actual_tmp_var_folders_and_physical_spellings_select_identical_private_bytes(self):
        # The reviewed controller publishes only these two finite readonly
        # fixtures. Neither HOME, per-user confstr nor TMPDIR grants a reader.
        # ROOT is the original tests tree for both source and installed wheel.
        session_root = Path(__file__).resolve().parents[3]
        self.assertEqual(session_root.parent, Path("/private/tmp"))
        self.assertEqual(os.getuid(), os.geteuid())
        self.assertTrue(60000 <= os.getuid() < 65000)
        roots = (Path("/tmp") / session_root.name / "fixture-controls/checked-files",
                 Path("/var/folders") / (session_root.name + "-checked-files"))
        for root in roots:
            with self.subTest(alias=root.parts[1]):
                project, external = root / "project", root / "external"
                source, inside = external / "material", project / "nested/inside-material"
                originals = {path: path.lstat() for path in (source, inside)}
                physical_source, physical_project = source.resolve(strict=True), project.resolve(strict=True)
                self.assertNotEqual(source, physical_source)
                self.assertEqual(physical_source.parts[:2], ("/", "private"))
                self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
                self.assertEqual(source.stat().st_uid, os.getuid())
                for directory in (root, external, project, project / "nested"):
                    observed = directory.lstat()
                    self.assertTrue(stat.S_ISDIR(observed.st_mode))
                    self.assertEqual((observed.st_uid, stat.S_IMODE(observed.st_mode)), (0, 0o555))
                # UID-owned leaves alone are not readonly. This actual denial
                # proves that the ordinary outside-work sandbox still applies.
                with self.assertRaises(PermissionError):
                    descriptor = os.open(source, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                    try:
                        self.fail("ordinary native reader gained outside-work write access")
                    finally:
                        os.close(descriptor)
                spellings = (source, physical_source,
                             Path("/", "Private", *physical_source.parts[2:]),
                             Path("/", "private", physical_source.parts[2].capitalize(), *physical_source.parts[3:]))
                for spelling in spellings:
                    with self.subTest(physical_spelling=spelling.parts[1:3]):
                        self.assertEqual((spelling.stat().st_dev, spelling.stat().st_ino),
                                         (source.stat().st_dev, source.stat().st_ino),
                                         "native fixture requires genuine equivalent physical spellings")
                        self.assertEqual(checked.read_external_bytes(spelling, kind="private-small",
                                                                    project_root=physical_project),
                                         b"selected private bytes")
                case_project = project.with_name("PROJECT")
                self.assertEqual((case_project.stat().st_dev, case_project.stat().st_ino),
                                 (project.stat().st_dev, project.stat().st_ino),
                                 "native fixture requires a genuine case-alias project directory")
                for selected in (inside, case_project / inside.relative_to(project), inside.resolve(strict=True)):
                    with self.assertRaisesRegex(ValidationError, "outside"):
                        checked.read_external_bytes(selected, kind="private-small", project_root=physical_project)
                lower_link = root / "lower-link"
                link_info = lower_link.lstat()
                self.assertTrue(stat.S_ISLNK(link_info.st_mode))
                self.assertEqual((link_info.st_uid, link_info.st_gid, stat.S_IMODE(link_info.st_mode)), (0, 0, 0o777))
                with self.assertRaises(ValidationError):
                    checked.read_external_bytes(root / "lower-link/material", kind="private-small", project_root=physical_project)
                self.assertEqual(os.readlink(lower_link), "external")
                for path, content in ((source, b"selected private bytes"), (inside, b"inside the project")):
                    self.assertEqual(path.read_bytes(), content)
                    after, before = path.lstat(), originals[path]
                    for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
                                  "st_mtime_ns", "st_ctime_ns"):
                        self.assertEqual(getattr(after, field), getattr(before, field), field)
