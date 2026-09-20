"""Inert SOURCE tests; not executed/admitted and not native filesystem evidence.

Only task-owned bytes and fixed-seam fakes are used. No real descriptor, project,
directory, process, tool, handler, installer or network fixture is acquired.
Constructed owner/closure DATA below tests predicates, never qualification.
"""
from __future__ import annotations

import errno
import io
import os
import stat
import threading
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from mobile_release import _desktop_android_build_files as subject
from mobile_release.android_build_operation import AndroidBuildOperation
from mobile_release.owned_process import ProcessCleanupError


def observed(*, inode=17, directory=False, size=7, links=1):
    return types.SimpleNamespace(
        st_dev=1, st_ino=inode, st_uid=os.geteuid(), st_gid=os.getegid(),
        st_mode=(stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600),
        st_nlink=links, st_size=size, st_mtime_ns=11, st_ctime_ns=13,
    )


class Ledger:
    def __init__(self):
        self.fatal = False
        self.complete = self.contained = True
        self.errors = []

    def _remember(self, error):
        self.errors.append(error)

    def verdict(self):
        return types.SimpleNamespace(
            complete=self.complete, contained=self.contained, fatal=self.fatal,
            command_dispatched=False, profile_dispatched=False,
        )


class Guard:
    def __init__(self):
        self.pid = os.getpid()
        self.depth = 0
        self.lifetime_ledger = Ledger()

    def _check_owner(self):
        return None

    def _abort(self, error):
        self.lifetime_ledger.fatal = True
        self.lifetime_ledger._remember(error)

    @contextmanager
    def deferred(self, *, check_on_exit=False):
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1


class Slot:
    def __init__(self, number):
        self.number = number
        self.open_state = "OPEN"
        self.close_state = "NOT_ATTEMPTED"
        self.calls = 0

    def close(self):
        self.calls += 1
        self.number = None
        self.close_state = "CLOSED"


class Entries:
    def __init__(self, names):
        self.values = iter(types.SimpleNamespace(name=name) for name in names)
        self.advances = self.closes = 0

    def __next__(self):
        self.advances += 1
        return next(self.values)

    def close(self):
        self.closes += 1


def inert_files():
    # Exact operation type only as inert DATA. There is no source, invocation,
    # project or native admission, and all IO tests patch the relevant syscalls.
    operation = object.__new__(AndroidBuildOperation)
    operation.guard = Guard()
    operation.source = types.SimpleNamespace(guard=operation.guard, operation=operation)
    operation.root = Path("/inert/project")
    operation.pid, operation.thread = os.getpid(), threading.current_thread()
    operation.operation_id = "a" * 32
    operation.close_claimed = False
    operation.invocation = None
    operation.files = None
    operation.counters = {}
    operation.cleanup_checkpoint = Mock(return_value=None)

    def fail(reason):
        raise subject.AndroidFileError(reason)

    def charge(name, amount, limit):
        previous = operation.counters.get(name, 0)
        if previous > limit - amount:
            fail("input-limit")
        operation.counters[name] = previous + amount

    operation.fail, operation.charge = fail, charge
    files = subject.AndroidBuildFiles(operation)
    operation.files = files
    return files


def add_slot(files, number):
    slot = Slot(number)
    files.slots.append(slot)
    files._numbers[number] = slot
    return slot


def inert_artifact(files, size=7):
    # These patched metadata predicates are explicitly NOT original custody.
    artifact = object.__new__(subject.OriginalAndroidArtifact)
    artifact.files = files
    artifact.size, artifact.sha256 = size, "0" * 64
    artifact._snapshot = subject._FileRecord(10, "app-release.aab", add_slot(files, 5))
    artifact._reader, artifact._native, artifact._borrows = None, False, []
    artifact.check = Mock(return_value=None)
    files.artifact = files._original_artifact = artifact
    return artifact


class OriginalFileAdmissionTests(unittest.TestCase):
    def test_foreign_constructor_rejects_before_io(self):
        with patch.object(subject.os, "open") as opened, patch.object(subject.os, "scandir") as scanned:
            with self.assertRaises(subject.AndroidFileError):
                subject.AndroidBuildFiles(types.SimpleNamespace())
        opened.assert_not_called()
        scanned.assert_not_called()

    def test_foreign_thread_cannot_enumerate(self):
        files = inert_files()
        files.thread = object()
        with patch.object(subject.os, "scandir") as scanned:
            with self.assertRaises(subject.AndroidFileError):
                files.names(10)
        scanned.assert_not_called()

    def test_names_are_bounded_alias_checked_and_original_iterator_closed(self):
        for values, limit, valid in ((["a", "b"], 2, True), (["Readme", "README"], 2, False), (["x"], 0, False)):
            with self.subTest(values=values):
                files = inert_files()
                add_slot(files, 10)
                entries = Entries(values)
                with patch.object(subject.os, "scandir", return_value=entries), \
                        patch.object(subject.os, "fstat", return_value=observed(directory=True)):
                    if valid:
                        self.assertEqual(files.names(10, limit), set(values))
                    else:
                        with self.assertRaises(subject.AndroidFileError):
                            files.names(10, limit)
                self.assertEqual(entries.closes, 1)
                self.assertEqual(files.iterators[0].close_state, "CLOSED")

    def test_iterator_advance_is_charged_before_next(self):
        files = inert_files()
        add_slot(files, 10)
        files.operation.counters["file-iterator-advances"] = 400_000
        entries = Entries(["x"])
        with patch.object(subject.os, "scandir", return_value=entries), \
                patch.object(subject.os, "fstat", return_value=observed(directory=True)):
            with self.assertRaises(subject.AndroidFileError):
                files.names(10)
        self.assertEqual((entries.advances, entries.closes), (0, 1))

    def test_lost_scandir_return_stays_rooted_unknown(self):
        files = inert_files()
        add_slot(files, 10)
        with patch.object(subject.os, "scandir", side_effect=OSError(errno.EACCES, "PRIVATE")), \
                patch.object(subject.os, "fstat", return_value=observed(directory=True)):
            with self.assertRaises(ProcessCleanupError):
                files.names(10)
        # A wrapper's familiar errno is not the direct builtin's no-effect receipt.
        self.assertEqual(files.iterators[0].state, "UNKNOWN")
        self.assertTrue(files.guard.lifetime_ledger.fatal)
        self.assertFalse(files.closed())

    def test_invalid_scandir_return_is_not_inferred_no_acquisition(self):
        files = inert_files()
        add_slot(files, 10)
        with patch.object(subject.os, "scandir", return_value=None), \
                patch.object(subject.os, "fstat", return_value=observed(directory=True)):
            with self.assertRaises(ProcessCleanupError):
                files.names(10)
        self.assertEqual(files.iterators[0].state, "UNKNOWN")
        self.assertFalse(files.closed())

    def test_iterator_unknown_close_is_not_retried(self):
        files = inert_files()
        add_slot(files, 10)
        entries = Entries([])
        entries.close = Mock(side_effect=OSError(errno.EIO, "PRIVATE"))
        with patch.object(subject.os, "scandir", return_value=entries), \
                patch.object(subject.os, "fstat", return_value=observed(directory=True)):
            with self.assertRaises(ProcessCleanupError):
                files.names(10)
        with self.assertRaises(ProcessCleanupError):
            files.iterators[0].close()
        self.assertEqual(entries.close.call_count, 1)
        self.assertEqual(files.iterators[0].close_state, "UNKNOWN")

    def test_read_budget_precedes_os_read(self):
        files = inert_files()
        add_slot(files, 5)
        files.operation.counters["file-read-bytes"] = subject.MAX_READ_BYTES
        with patch.object(subject.os, "read") as read:
            with self.assertRaises(subject.AndroidFileError):
                files._read(5, 1)
        read.assert_not_called()

    def test_named_replacement_cannot_become_original_descriptor(self):
        files = inert_files()
        original = observed()
        record = subject._FileRecord(10, "input", add_slot(files, 5), subject._file(original))
        with patch.object(subject.os, "fstat", return_value=original), \
                patch.object(subject.os, "stat", return_value=observed(inode=18)), \
                patch.object(subject.os, "open") as opened:
            with self.assertRaises(subject.AndroidFileError):
                files._check_record(record)
        opened.assert_not_called()

    def test_cached_overlap_returns_original_bytes_without_reopening(self):
        files = inert_files()
        raw = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=4\n"
        files.inputs["gradle.properties"] = subject._InputRecord(
            "gradle.properties", 4096, complete=True, raw=raw)
        with patch.object(files, "_borrow_root", return_value=10), \
                patch.object(files, "_input_check") as checked, \
                patch.object(subject.os, "open") as opened:
            self.assertIs(files.read_input("gradle.properties", 4096, optional=True), raw)
            with self.assertRaises(subject.AndroidFileError):
                files.read_input("gradle.properties", 1, optional=True)
        self.assertEqual(checked.call_count, 2)
        opened.assert_not_called()

    def test_absent_component_is_rechecked_not_reopened(self):
        files = inert_files()
        record = subject._InputRecord("release/version.properties", 10, parent=10,
                                      name="release", absent=True, complete=True)
        with patch.object(files, "_root_metadata"), \
                patch.object(files, "names", return_value={"release"}), \
                patch.object(subject.os, "open") as opened:
            with self.assertRaises(subject.AndroidFileError):
                files._input_check(record)
        opened.assert_not_called()

    def test_invalid_output_components_refuse_before_namespace_or_file_work(self):
        for module, variant in ((":app::foreign", "release"), (":app", "..")):
            files = inert_files()
            files.operation.capture_ready = Mock(return_value=None)
            with patch.object(subject.os, "open") as opened, patch.object(subject.os, "scandir") as scanned:
                with self.assertRaises(subject.AndroidFileError):
                    files.capture_aab(module, variant)
            opened.assert_not_called()
            scanned.assert_not_called()

    def test_output_scope_drift_is_not_a_second_discovery(self):
        files = inert_files()
        files._output_scope = subject._DirectoryRecord(1, "release", add_slot(files, 10))
        files._output_epoch = (0, 0)
        with patch.object(files, "_check_record"), \
                patch.object(subject.os, "fstat", return_value=observed(directory=True)), \
                patch.object(subject.os, "scandir") as scanned:
            with self.assertRaises(subject.AndroidFileError):
                files._check_output_scope()
        scanned.assert_not_called()


class BorrowedArtifactTests(unittest.TestCase):
    def test_reader_chunks_logical_seeks_and_retires_without_fd_close(self):
        files = inert_files()
        raw = b"x" * (subject.READ_CHUNK * 2 + 3)
        artifact = inert_artifact(files, len(raw))
        reader = subject._BorrowedReader(artifact)
        artifact._reader = reader
        memory = io.BytesIO(raw)
        with patch.object(subject.os, "read", side_effect=lambda fd, n: memory.read(n)) as read, \
                patch.object(subject.os, "lseek", side_effect=lambda fd, offset, whence: memory.seek(offset, whence)), \
                patch.object(subject.os, "close") as closed:
            self.assertEqual(reader.read(subject.READ_CHUNK + 1), raw[:subject.READ_CHUNK + 1])
            self.assertEqual(reader.tell(), subject.READ_CHUNK + 1)
            self.assertEqual(reader.seek(-3, 2), len(raw) - 3)
            self.assertEqual(reader.read(), b"xxx")
            self.assertEqual(reader.read(1), b"")
            reader.closed = True
            with self.assertRaises(subject.AndroidFileError):
                reader.tell()
        self.assertTrue(all(0 < call.args[1] <= subject.READ_CHUNK for call in read.call_args_list))
        closed.assert_not_called()

    def test_reader_refuses_unbounded_result_before_seek_or_read(self):
        files = inert_files()
        artifact = inert_artifact(files, subject.MAX_READ_RESULT + 1)
        reader = subject._BorrowedReader(artifact)
        artifact._reader = reader
        with patch.object(subject.os, "read") as read, patch.object(subject.os, "lseek") as seek:
            with self.assertRaises(subject.AndroidFileError):
                reader.read()
        read.assert_not_called()
        seek.assert_not_called()

    def test_chunk_identity_failure_never_returns_partial_observation(self):
        files = inert_files()
        artifact = inert_artifact(files, subject.READ_CHUNK + 1)
        reader = subject._BorrowedReader(artifact)
        artifact._reader = reader
        artifact.check.side_effect = [None, None, subject.AndroidFileError("artifact-changed")]
        with patch.object(subject.os, "read", return_value=b"x" * subject.READ_CHUNK) as read, \
                patch.object(subject.os, "lseek", return_value=0):
            with self.assertRaises(subject.AndroidFileError):
                reader.read(subject.READ_CHUNK + 1)
        self.assertEqual(read.call_count, 1)

    def test_reader_body_primary_survives_failed_final_metadata_check(self):
        files = inert_files()
        artifact = inert_artifact(files)
        artifact.check.side_effect = [None, subject.AndroidFileError("artifact-changed")]
        primary = ValueError("inert original primary")
        with self.assertRaises(ValueError) as raised:
            with artifact.reader() as reader:
                raise primary
        self.assertIs(raised.exception, primary)
        self.assertTrue(reader.closed)
        self.assertIsNone(artifact._reader)

    def test_native_borrow_checks_bytes_on_both_sides_and_known_failure_retires_borrow(self):
        files = inert_files()
        files.namespace = types.SimpleNamespace(path=Path("/inert/namespace"))
        artifact = inert_artifact(files)
        artifact.verify_bytes = Mock(side_effect=[None, subject.AndroidFileError("artifact-changed")])
        with self.assertRaises(subject.AndroidFileError):
            with artifact.native_input() as path:
                self.assertEqual(path, Path("/inert/namespace/artifacts/app-release.aab"))
                self.assertTrue(artifact._native)
        self.assertEqual(artifact.verify_bytes.call_count, 2)
        self.assertFalse(artifact._native)

    def test_unknown_native_consumer_keeps_original_borrow(self):
        files = inert_files()
        files.namespace = types.SimpleNamespace(path=Path("/inert/namespace"))
        artifact = inert_artifact(files)
        artifact.verify_bytes = Mock(return_value=None)
        with self.assertRaises(ProcessCleanupError):
            with artifact.native_input():
                files.guard.lifetime_ledger.complete = False
                files.guard.lifetime_ledger.contained = False
        self.assertTrue(artifact._native)
        self.assertTrue(files.guard.lifetime_ledger.fatal)

    def test_operation_close_blocks_new_borrow_before_byte_read(self):
        files = inert_files()
        artifact = inert_artifact(files)
        artifact.verify_bytes = Mock(return_value=None)
        files.operation.close_claimed = True
        with self.assertRaises(subject.AndroidFileError):
            with artifact.native_input():
                self.fail("retired operation yielded a native borrow")
        artifact.verify_bytes.assert_not_called()


class DisposalAndClosureTests(unittest.TestCase):
    def test_work_name_limit_cannot_spend_namespace_close_name_budget(self):
        files = inert_files()
        files._cleanup_counts["work-name-bytes"] = subject.MAX_NAME_BYTES
        with self.assertRaises(subject._RetainWork):
            files._name("cache", cleanup=True, work=True)
        self.assertEqual(files._name("artifacts", cleanup=True), "artifacts")

    def test_delete_unknown_is_prearmed_rooted_and_never_retried(self):
        files = inert_files()
        original = subject._FileRecord(10, "cache", add_slot(files, 5), subject._file(observed()))
        record = subject._DeleteRecord(files, original, False)
        files.deletions.append(record)
        with patch.object(files, "_check_record"), \
                patch.object(subject.os, "unlink", side_effect=OSError(errno.EACCES, "PRIVATE")) as unlink:
            with self.assertRaises(ProcessCleanupError):
                record.remove()
            with self.assertRaises(ProcessCleanupError):
                record.remove()
        self.assertEqual(unlink.call_count, 1)
        self.assertEqual(record.state, "UNKNOWN")
        self.assertEqual(files.disposition()["work"], "unknown")

    def test_classified_no_effect_retains_work_without_claiming_unknown(self):
        files = inert_files()
        original = subject._FileRecord(10, "cache", add_slot(files, 5), subject._file(observed()))
        record = subject._DeleteRecord(files, original, False)
        # Predicate stub only: this is NOT a native direct-builtin receipt.
        with patch.object(files, "_check_record"), patch.object(subject, "_direct_refusal", return_value=True), \
                patch.object(subject.os, "unlink", side_effect=OSError(errno.EACCES, "PRIVATE")):
            with self.assertRaises(subject._RetainWork):
                record.remove()
        self.assertEqual(record.state, "NO_EFFECT")
        self.assertFalse(files.guard.lifetime_ledger.fatal)

    def test_positive_delete_uses_original_inode_receipt_not_new_path(self):
        files = inert_files()
        original = subject._FileRecord(10, "cache", add_slot(files, 5), subject._file(observed()))
        record = subject._DeleteRecord(files, original, False)
        with patch.object(files, "_check_record"), patch.object(subject.os, "unlink", return_value=None) as unlink, \
                patch.object(subject.os, "fstat", return_value=observed(links=0)), \
                patch.object(subject.os, "stat", side_effect=FileNotFoundError), \
                patch.object(subject.os, "open") as opened:
            record.remove()
        unlink.assert_called_once_with("cache", dir_fd=10)
        opened.assert_not_called()
        self.assertTrue(original.deleted)
        self.assertEqual(record.state, "DELETED")

    def test_post_delete_failure_cannot_be_reclassified_as_no_effect(self):
        for failed_check in ("fstat", "named-stat", "return-value"):
            with self.subTest(failed_check=failed_check):
                files = inert_files()
                original = subject._FileRecord(10, "cache", add_slot(files, 5), subject._file(observed()))
                record = subject._DeleteRecord(files, original, False)
                files.deletions.append(record)
                # Predicate would accept a direct EACCES if wrongly consulted
                # after the consuming call returned. No real deletion occurs.
                with patch.object(files, "_check_record"), \
                        patch.object(subject, "_direct_refusal", return_value=True) as classify, \
                        patch.object(subject.os, "unlink", return_value=1 if failed_check == "return-value" else None) as unlink, \
                        patch.object(subject.os, "fstat", return_value=observed(links=0),
                                     side_effect=OSError(errno.EACCES, "PRIVATE") if failed_check == "fstat" else None), \
                        patch.object(subject.os, "stat", side_effect=OSError(errno.EACCES, "PRIVATE")):
                    with self.assertRaises(ProcessCleanupError):
                        record.remove()
                    with self.assertRaises(ProcessCleanupError):
                        record.remove()
                classify.assert_not_called()
                unlink.assert_called_once_with("cache", dir_fd=10)
                self.assertEqual(record.state, "UNKNOWN")
                self.assertFalse(original.deleted)
                self.assertEqual(files.disposition()["work"], "unknown")

    def test_pending_consumer_blocks_even_first_work_walk(self):
        files = inert_files()
        files._work = subject._DirectoryRecord(1, "work", add_slot(files, 10),
            subject._directory(observed(directory=True)), creation={"state": "CREATED"})
        files.guard.lifetime_ledger.complete = False
        with patch.object(subject.os, "scandir") as scanned, patch.object(subject.os, "unlink") as unlink:
            with self.assertRaises(ProcessCleanupError):
                files.finish_work()
        scanned.assert_not_called()
        unlink.assert_not_called()
        self.assertFalse(files.closed())

    def test_known_retained_work_can_have_closed_original_handles(self):
        files = inert_files()
        files._work = subject._DirectoryRecord(1, "work", add_slot(files, 10),
            subject._directory(observed(directory=True)), creation={"state": "CREATED"})
        files.directories.append(files._work)
        files.close()
        self.assertTrue(files.closed())  # Constructed closure DATA, no actual directory.
        self.assertEqual(files.disposition(), {"work": "retained-work", "artifacts": "not-created"})

    def test_incomplete_mkdir_identity_cannot_claim_closed(self):
        files = inert_files()
        files._work = subject._DirectoryRecord(1, "work", add_slot(files, 10), creation={"state": "CREATED"})
        files.directories.append(files._work)
        with self.assertRaises(Exception):
            files.close()
        self.assertFalse(files.closed())
        self.assertEqual(files.disposition()["work"], "unknown")

    def test_artifact_retention_never_manufactures_result_acceptance(self):
        files = inert_files()
        files._artifacts = subject._DirectoryRecord(1, "artifacts", add_slot(files, 11),
            subject._directory(observed(directory=True)), creation={"state": "CREATED"})
        self.assertEqual(files.disposition()["artifacts"], "retained-incomplete")


if __name__ == "__main__":
    unittest.main()


# Append-only orchestration coverage. The focused unittest discovery command
# imports this module; the earlier reviewed direct-script entry stays unchanged.
@contextmanager
def inert_file_orchestration():
    """Two tiny fixed DATA trees, not a reusable filesystem/native fixture.

    Keep capture/walk, record checks, enumeration, copying, digest verification
    and deletion orchestration real. Replace original admission and every OS
    effect before calling them. Descriptor numbers below were never acquired.
    """
    files = inert_files()
    state = types.SimpleNamespace(files=files, events=[], scans=[], writes=0,
        write_fault=None, mutate_source=False, delete_fault=None, classified_refusal=False)
    state.names = {
        10: {"app": 11}, 11: {"build": 12}, 12: {"outputs": 13},
        13: {"bundle": 14}, 14: {"release": 15},
        15: {"app.aab": 16, "readme.txt": 17, "nested": 18},
        18: {"ignored.aab": 19}, 20: {"work": 21, "artifacts": 22},
        21: {"cache": 23, "tail": 25}, 22: {}, 23: {"leaf": 24},
    }
    state.data = {16: bytearray(b"original-aab"), 17: bytearray(b"note"),
                  19: bytearray(b"not-selected"), 24: bytearray(b"cache"), 25: bytearray(b"tail")}
    state.nodes = {number: observed(inode=1000 + number, directory=True)
                   for number in state.names}
    state.nodes.update({number: observed(inode=1000 + number, size=len(raw))
                        for number, raw in state.data.items()})
    positions = {number: 0 for number in state.data}
    for number in (10, 20, 21, 22):
        add_slot(files, number)
    files._work = subject._DirectoryRecord(20, "work", files._numbers[21],
        subject._directory(state.nodes[21]), creation={"state": "CREATED"})
    files._artifacts = subject._DirectoryRecord(20, "artifacts", files._numbers[22],
        subject._directory(state.nodes[22]), creation={"state": "CREATED"})
    files.directories.extend((files._work, files._artifacts))
    files.operation.capture_ready = Mock(return_value=None)

    def forbidden(*args, **kwargs):
        raise AssertionError("orchestration reached an unselected OS effect")

    def slot_factory(guard):
        assert guard is files.guard
        slot = Slot(None)
        slot.open_state = "NEW"

        def open_name(name, flags, *, dir_fd):
            assert slot.number is None and slot.open_state == "NEW"
            assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
            if flags & os.O_CREAT:
                assert (dir_fd, name) == (22, "app-release.aab")
                assert flags & os.O_EXCL and flags & os.O_RDWR and name not in state.names[22]
                assert files._snapshot.slot is slot and files._snapshot in files.file_records
                number = 30
                state.names[22][name] = number
                state.data[number], positions[number] = bytearray(), 0
                state.nodes[number] = observed(inode=1030, size=0)
            else:
                number = state.names[dir_fd][name]
            state.events.append(("open", dir_fd, name, number))
            slot.number, slot.open_state = number, "OPEN"
            return number

        slot.open = open_name
        return slot

    def named(name, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False and type(name) is str
        state.events.append(("stat", dir_fd, name))
        if name not in state.names[dir_fd]:
            raise FileNotFoundError(errno.ENOENT, "inert absent name")
        return state.nodes[state.names[dir_fd][name]]

    def scan(number):
        entries = Entries(tuple(state.names[number]))
        state.scans.append((number, entries))
        state.events.append(("scan", number))
        original_close = entries.close

        def close():
            state.events.append(("iterator-close", number))
            original_close()

        entries.close = close
        return entries

    def read(number, amount):
        assert number in (16, 30) and 0 < amount <= 4
        start = positions[number]
        result = bytes(state.data[number][start:start + amount])
        positions[number] += len(result)
        state.events.append(("read", number, start, amount, result))
        return result

    def write(number, view):
        assert number == 30 and 0 < len(view) <= 4
        state.writes += 1
        state.events.append(("write", number, bytes(view)))
        if state.writes == 2 and state.write_fault == "disk":
            raise OSError(errno.ENOSPC, "inert write refusal")
        if state.writes == 2 and state.write_fault == "zero":
            return 0
        count = min(2, len(view))  # Exercise the actual partial-write loop.
        state.data[number].extend(view[:count])
        positions[number] += count
        state.nodes[number].st_size = len(state.data[number])
        state.nodes[number].st_mtime_ns += 1
        state.nodes[number].st_ctime_ns += 1
        if state.mutate_source and state.writes == 1:
            state.nodes[16].st_mtime_ns += 1  # Same inode/length, changed original observation.
        return count

    def seek(number, offset, whence):
        assert number == 30 and offset == 0 and whence == os.SEEK_SET
        state.events.append(("seek", number, offset))
        positions[number] = offset
        return offset

    def sync(number):
        assert number in (22, 30)
        state.events.append(("fsync", number))

    def remove(name, *, dir_fd, directory):
        number = state.names[dir_fd][name]
        assert number in (21, 23, 24, 25)  # Never project, artifact or other tree.
        assert directory is stat.S_ISDIR(state.nodes[number].st_mode)
        state.events.append(("rmdir" if directory else "unlink", dir_fd, name))
        if directory:
            assert not state.names[number], "parent removal before its children"
        if name == "tail" and state.delete_fault == "known":
            raise OSError(errno.EACCES, "inert classified refusal")
        del state.names[dir_fd][name]
        state.nodes[number].st_nlink = 0
        state.nodes[number].st_ctime_ns += 1
        if name == "tail" and state.delete_fault == "unknown":
            raise OSError(errno.EIO, "inert lost consuming return")

    # Admission and OS results are fabricated, not orchestration. Do not mock capture_aab,
    # finish_work, names, _check_record, _read, _digest or _work_delete.
    with patch.object(files, "_namespace_metadata"), patch.object(files, "_borrow_root", return_value=10), \
         patch.object(subject, "_FD", side_effect=slot_factory), patch.object(subject, "READ_CHUNK", 4), \
         patch.object(subject.os, "open", side_effect=forbidden), patch.object(subject.os, "close", side_effect=forbidden), \
         patch.object(subject.os, "mkdir", side_effect=forbidden), patch.object(subject.os, "fstat", side_effect=lambda n: state.nodes[n]), \
         patch.object(subject.os, "stat", side_effect=named), patch.object(subject.os, "scandir", side_effect=scan), \
         patch.object(subject.os, "read", side_effect=read), patch.object(subject.os, "write", side_effect=write), \
         patch.object(subject.os, "lseek", side_effect=seek), patch.object(subject.os, "fsync", side_effect=sync), \
         patch.object(subject.os, "unlink", side_effect=lambda name, *, dir_fd: remove(name, dir_fd=dir_fd, directory=False)), \
         patch.object(subject.os, "rmdir", side_effect=lambda name, *, dir_fd: remove(name, dir_fd=dir_fd, directory=True)), \
         patch.object(subject, "_direct_refusal", side_effect=lambda *args: state.classified_refusal):
        yield state


class CaptureAndWorkOrchestrationTests(unittest.TestCase):
    def test_capture_copies_partial_writes_and_hashes_the_same_selected_snapshot(self):
        with inert_file_orchestration() as state:
            files = state.files
            artifact = files.capture_aab(":app", "release")
            raw = bytes(state.data[16])
            self.assertIs(artifact, files.artifact)
            self.assertIs(artifact, files._original_artifact)
            self.assertIs(artifact._snapshot, files._snapshot)
            self.assertIs(artifact._source, next(record for record in files.file_records if record.name == "app.aab"))
            self.assertEqual((artifact.size, artifact.sha256), (len(raw), subject.hashlib.sha256(raw).hexdigest()))
            self.assertEqual(bytes(state.data[30]), raw)
            self.assertGreater(state.writes, len(raw) // 4)
            source_reads = [event for event in state.events if event[:2] == ("read", 16)]
            snapshot_reads = [event for event in state.events if event[:2] == ("read", 30)]
            self.assertEqual(b"".join(event[4] for event in source_reads), raw)
            self.assertEqual(b"".join(event[4] for event in snapshot_reads), raw)
            self.assertEqual(source_reads[-1][4], b"")
            self.assertEqual(snapshot_reads[-1][4], b"")
            self.assertEqual([event for event in state.events if event[0] == "fsync"], [("fsync", 30), ("fsync", 22)])
            self.assertEqual([number for number, _ in state.scans], [10, 11, 12, 13, 14, 15, 22])
            self.assertTrue(all(entries.closes == 1 for _, entries in state.scans))
            self.assertEqual(files.operation.counters["captured-aab-bytes"], len(raw))
            self.assertEqual(files.operation.counters["output-candidates"], 1)
            self.assertEqual(files.disposition()["artifacts"], "retained-incomplete")
            files.operation.capture_ready.assert_called_once_with(":app", "release")

    def test_capture_missing_ambiguous_and_entry_limit_never_create_a_snapshot(self):
        for case, reason in (("missing-directory", "artifact-missing"), ("missing-aab", "artifact-missing"),
                             ("ambiguous", "artifact-ambiguous"), ("entry-limit", "input-limit")):
            with self.subTest(case=case), inert_file_orchestration() as state:
                files = state.files
                if case == "missing-directory":
                    state.names[14].clear()
                elif case == "missing-aab":
                    del state.names[15]["app.aab"]
                elif case == "ambiguous":
                    state.names[15]["second.aab"] = state.names[15].pop("readme.txt")
                else:
                    files.operation.counters["output-entries"] = subject.MAX_OUTPUT_ENTRIES
                with self.assertRaises(subject.AndroidFileError) as raised:
                    files.capture_aab(":app", "release")
                self.assertEqual(raised.exception.reason, reason)
                self.assertIsNone(files._snapshot)
                self.assertIsNone(files.artifact)
                self.assertEqual(state.names[22], {})
                self.assertEqual(state.writes, 0)
                before = list(state.events)
                with self.assertRaises(subject.AndroidFileError):
                    files.capture_aab(":app", "release")
                self.assertEqual(state.events, before)
                self.assertTrue(all(entries.closes == 1 for _, entries in state.scans))

    def test_capture_mutated_input_and_partial_copy_failures_retain_original_without_retry(self):
        for case in ("mutation", "zero", "disk"):
            with self.subTest(case=case), inert_file_orchestration() as state:
                files = state.files
                state.mutate_source = case == "mutation"
                state.write_fault = case
                with self.assertRaises(OSError if case == "disk" else subject.AndroidFileError) as raised:
                    files.capture_aab(":app", "release")
                if case == "disk":
                    self.assertEqual(raised.exception.errno, errno.ENOSPC)
                else:
                    self.assertEqual(raised.exception.reason, "artifact-changed")
                self.assertIsNotNone(files._snapshot.identity)
                self.assertIs(files._numbers[30], files._snapshot.slot)
                self.assertTrue(0 < len(state.data[30]) < len(state.data[16]))
                self.assertEqual(bytes(state.data[30]), bytes(state.data[16][:len(state.data[30])]))
                self.assertIsNone(files.artifact)
                self.assertFalse(any(event[0] == "fsync" for event in state.events))
                self.assertEqual(files.disposition()["artifacts"], "retained-incomplete")
                before = list(state.events)
                with self.assertRaises(subject.AndroidFileError):
                    files.capture_aab(":app", "release")
                self.assertEqual(state.events, before)
                self.assertEqual(sum(event[:2] == ("open", 22) for event in state.events), 1)

    def test_finish_work_deletes_children_before_parents_and_never_walks_artifacts(self):
        with inert_file_orchestration() as state:
            files = state.files
            files.finish_work()
            deletes = [event for event in state.events if event[0] in {"unlink", "rmdir"}]
            self.assertEqual(deletes, [("unlink", 23, "leaf"), ("rmdir", 21, "cache"),
                                      ("unlink", 21, "tail"), ("rmdir", 20, "work")])
            self.assertLess(state.events.index(("iterator-close", 23)), state.events.index(("rmdir", 21, "cache")))
            self.assertLess(state.events.index(("iterator-close", 21)), state.events.index(("rmdir", 20, "work")))
            self.assertEqual([number for number, _ in state.scans], [21, 23])
            self.assertTrue(all(entries.closes == 1 for _, entries in state.scans))
            self.assertTrue(all(record.state == "DELETED" and record.original.slot.number is None
                                for record in files.deletions))
            self.assertEqual(files.disposition(), {"work": "removed", "artifacts": "retained-incomplete"})
            self.assertEqual(state.names[20], {"artifacts": 22})
            self.assertEqual(files._cleanup_counts["work-entries"], 3)
            self.assertEqual(files._cleanup_counts["work-deletions"], 4)

    def test_finish_work_unsafe_entry_or_precharged_limit_keeps_bounded_partial_progress(self):
        for case in ("unsafe-entry", "entry-limit"):
            with self.subTest(case=case), inert_file_orchestration() as state:
                files = state.files
                if case == "unsafe-entry":
                    state.names[23]["mystery"] = 18
                    state.nodes[18].st_mode = stat.S_IFLNK | 0o600
                else:
                    files._cleanup_counts["work-entries"] = subject.MAX_WORK_ENTRIES - 2
                with self.assertRaises(subject.AndroidFileError) as raised:
                    files.finish_work()
                self.assertEqual(raised.exception.reason, "work-retained")
                self.assertFalse(files.guard.lifetime_ledger.fatal)
                self.assertEqual(files.disposition()["work"], "retained-work")
                deletes = [event for event in state.events if event[0] in {"unlink", "rmdir"}]
                expected = [("unlink", 23, "leaf")]
                if case == "entry-limit":
                    expected.append(("rmdir", 21, "cache"))
                    self.assertNotIn(("stat", 21, "tail"), state.events)
                self.assertEqual(deletes, expected)
                self.assertTrue(all(entries.closes == 1 for _, entries in state.scans))
                before = list(state.events)
                with self.assertRaises(subject.AndroidFileError):
                    files.finish_work()
                self.assertEqual(state.events, before)
                self.assertEqual(state.names[20], {"work": 21, "artifacts": 22})

    def test_finish_work_known_refusal_and_unknown_consuming_return_do_not_replay_the_walk(self):
        for case in ("known", "unknown"):
            with self.subTest(case=case), inert_file_orchestration() as state:
                files = state.files
                state.delete_fault = case
                state.classified_refusal = case == "known"  # Stub classification DATA, not a native errno receipt.
                with self.assertRaises(subject.AndroidFileError if case == "known" else ProcessCleanupError):
                    files.finish_work()
                self.assertEqual([record.original.name for record in files.deletions], ["leaf", "cache", "tail"])
                self.assertEqual([record.state for record in files.deletions],
                                 ["DELETED", "DELETED", "NO_EFFECT" if case == "known" else "UNKNOWN"])
                self.assertEqual(files.guard.lifetime_ledger.fatal, case == "unknown")
                self.assertEqual(files.disposition()["work"], "retained-work" if case == "known" else "unknown")
                self.assertIsNotNone(files.deletions[-1].original.slot.number)
                self.assertFalse(files.closed())
                self.assertTrue(all(entries.closes == 1 for _, entries in state.scans))
                self.assertNotIn(("rmdir", 20, "work"), state.events)
                before = list(state.events)
                with self.assertRaises(subject.AndroidFileError):
                    files.finish_work()
                self.assertEqual(state.events, before)
                self.assertEqual(sum(event == ("unlink", 21, "tail") for event in state.events), 1)
