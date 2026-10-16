"""Real private disk records and HMAC; no native checkpoint or Store claims."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import local_release_journal as J

KEY = b"K" * 32  # Synthetic test-only key.
PROJECT = "11111111-1111-4111-8111-111111111111"
KEY_ID = "22222222-2222-4222-8222-222222222222"
OP = "33333333-3333-4333-8333-333333333333"
ENROLLMENT = dict(projectLocator="a"*64, projectBinding="b"*64,
                  projectId=PROJECT, keyId=KEY_ID, keyRevision=1)
GENESIS = {"rootIdentity": dict(device=1, inode=9, uid=65534, gid=65534, mode=0o700)}
INPUTS = dict(sourceCommit="c"*40, sourceTree="d"*40, configurationSha256="e"*64, versionSha256="f"*64)


class LocalReleaseJournalTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, "Run filesystem ownership tests nonroot")
        self.assertEqual(len(KEY), 32)
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.home = Path(self.temp.name)
        self.books = []

    def tearDown(self):
        for book in self.books:
            if not book.closed:
                try:
                    book.close()
                except J.JournalError:
                    self.assertTrue(book.failed)
            self.assertFalse(book.ancestors)
            self.assertEqual(book._key, bytes(32))
        self.temp.cleanup()

    def book(self, *, key=KEY, enrollment=None):
        book = J.LocalReleaseJournal(str(self.home), end=time.monotonic()+20,
                                    enrollment=enrollment or ENROLLMENT, key=key)
        self.books.append(book)
        try:
            book.open()
        except BaseException:
            try:
                book.close()
            except J.JournalError:
                self.assertTrue(book.failed)
            raise
        return book

    def append(self, book, phase, payload, operation=OP):
        return book._append(expected_head=book.head(), operation_id=operation, phase=phase, payload=payload)

    def genesis(self, book):
        return self.append(book, 'genesis', GENESIS, None)

    def path(self, sequence):
        return self.home / '.local/share/mobile-release-kit/local-releases' / ENROLLMENT['projectLocator'] / f'{sequence:04d}.json'

    def test_real_complete_lifecycle_closed_reload_and_detached_payload(self):
        book = self.book(); self.genesis(book)
        initial = copy.deepcopy(INPUTS)
        self.append(book, 'inputs-pending', initial)
        initial['sourceCommit'] = '0'*40
        self.append(book, 'inputs-ready', dict(candidateSha256='1'*64))
        self.append(book, 'prepare-pending', dict(candidateSha256='1'*64, confirmationSha256='2'*64))
        self.append(book, 'prepared', dict(candidateSha256='1'*64, intentSha256='3'*64, storePreconditionSha256='4'*64))
        self.append(book, 'execute-pending', dict(intentSha256='3'*64, confirmationSha256='5'*64,
                                                authorizationId=KEY_ID, assignmentRevision=1))
        head = self.append(book, 'settled-success', dict(intentSha256='3'*64, receiptSha256='6'*64))
        self.assertEqual(head['sequence'], 7)
        self.assertEqual(head['sha256'], hashlib.sha256(self.path(7).read_bytes()).hexdigest())
        self.assertEqual(book._rows[1][0]['payload']['sourceCommit'], INPUTS['sourceCommit'])
        for n in range(1, 8): self.assertEqual(self.path(n).stat().st_mode & 0o777, 0o400)
        book.close()
        reloaded = self.book()
        self.assertEqual(reloaded.head(), head)
        self.assertEqual(set(head), {'sequence', 'sha256'})  # No GO/checkpoint/Store success authority.

    def test_wrong_key_and_expected_enrollment_refused_without_adoption(self):
        book = self.book(); self.genesis(book); book.close()
        for field in ('key', 'projectBinding', 'projectId', 'keyId', 'keyRevision'):
            with self.subTest(field=field):
                expected = dict(ENROLLMENT)
                key = KEY
                if field == 'key': key = b'x'*32
                elif field in ('projectId', 'keyId'): expected[field] = OP
                elif field == 'keyRevision': expected[field] = 2
                else: expected[field] = '0'*64
                with self.assertRaises(J.JournalError): self.book(key=key, enrollment=expected)
        self.assertTrue(self.path(1).exists())

    def test_tamper_and_missing_middle_are_preserved(self):
        book = self.book(); self.genesis(book); self.append(book, 'inputs-pending', INPUTS)
        self.append(book, 'inputs-ready', dict(candidateSha256='1'*64)); book.close()
        original = self.path(2).read_bytes()
        self.path(2).chmod(0o600)
        self.path(2).write_bytes(original.replace(b'"inputs-pending"', b'"inputs-changed"'))
        self.path(2).chmod(0o400)
        with self.assertRaises(J.JournalError): self.book()
        self.path(2).unlink()  # Only this test's own synthetic row; production never deletes.
        with self.assertRaises(J.JournalError): self.book()
        self.assertTrue(self.path(3).exists())

    def test_valid_prefix_can_reload_and_is_not_native_rollback_evidence(self):
        book = self.book(); head = self.genesis(book)
        self.append(book, 'inputs-pending', INPUTS); book.close()
        self.path(2).unlink()  # Demonstrate required external successor-anchor check.
        self.assertEqual(self.book().head(), head)

    def test_reconciliation_is_absorbing_and_blocks_new_operation(self):
        book = self.book(); self.genesis(book); self.append(book, 'inputs-pending', INPUTS)
        self.append(book, 'reconciliation-required', dict(phase='inputs-pending', reason='checkpoint-unknown'))
        book.close(); book = self.book()
        with self.assertRaises(J.JournalError): self.append(book, 'inputs-pending', INPUTS, KEY_ID)
        self.assertTrue(book.failed)
        self.assertEqual(len(book._rows), 3)

    def test_illegal_transition_and_changed_candidate_fail_before_write(self):
        for fault in ('skip', 'changed-candidate', 'replay', 'unknown-field', 'stale-head'):
            with self.subTest(fault=fault):
                subhome = self.home / fault; subhome.mkdir(mode=0o700)
                book = J.LocalReleaseJournal(str(subhome), end=time.monotonic()+20, enrollment=ENROLLMENT, key=KEY)
                self.books.append(book); book.open(); old = self.genesis(book)
                self.append(book, 'inputs-pending', INPUTS)
                if fault == 'changed-candidate': self.append(book, 'inputs-ready', dict(candidateSha256='1'*64))
                count = len(book.leaves)
                with self.assertRaises(J.JournalError):
                    if fault == 'skip': self.append(book, 'settled-success', dict(intentSha256='1'*64, receiptSha256='2'*64))
                    elif fault == 'changed-candidate': self.append(book, 'prepare-pending', dict(candidateSha256='2'*64, confirmationSha256='3'*64))
                    elif fault == 'replay': self.append(book, 'inputs-pending', INPUTS)
                    elif fault == 'unknown-field': self.append(book, 'inputs-ready', dict(candidateSha256='1'*64, command='forbidden'))
                    else: book._append(expected_head=old, operation_id=OP, phase='inputs-ready', payload=dict(candidateSha256='1'*64))
                self.assertEqual(len(book.leaves), count)
                self.assertTrue(book.failed)

    def test_write_failure_preserves_partial_and_latches_no_later_append(self):
        book = self.book(); self.genesis(book)
        with patch('os.write', side_effect=OSError('synthetic')):
            with self.assertRaises(OSError): self.append(book, 'inputs-pending', INPUTS)
        self.assertTrue(self.path(2).exists())
        self.assertEqual(self.path(2).stat().st_size, 0)
        with self.assertRaises(J.JournalError): self.append(book, 'inputs-pending', INPUTS)

    def test_consuming_close_error_never_advances_memory_head(self):
        book = self.book(); self.genesis(book)
        original = J._Custodian._close
        def close_then_fail(owner, fd):
            original(owner, fd)
            raise OSError('synthetic lost close acknowledgement')
        with patch.object(J._Custodian, '_close', close_then_fail):
            with self.assertRaises(OSError): self.append(book, 'inputs-pending', INPUTS)
        self.assertEqual(len(book._rows), 1)
        self.assertTrue(self.path(2).exists())
        with self.assertRaises(J.JournalError): book.head()

    def test_finite_operation_capacity_and_foreign_inventory(self):
        book = self.book(); self.genesis(book)
        for n in range(J.MAX_OPERATIONS):
            operation = f'{n+1:08x}-3333-4333-8333-333333333333'
            self.append(book, 'inputs-pending', INPUTS, operation)
            self.append(book, 'settled-failure', dict(phase='inputs-pending', reason='validation'), operation)
        with self.assertRaises(J.JournalError): self.append(book, 'inputs-pending', INPUTS, KEY_ID)
        book.close()
        foreign = self.path(1).parent / 'unrelated.txt'; foreign.write_bytes(b'preserve')
        with self.assertRaises(J.JournalError): self.book()
        self.assertEqual(foreign.read_bytes(), b'preserve')

    def test_complete_suffix_bounds_before_any_filesystem_effect(self):
        for home in ('/' + '/'.join(['a'] * 124), '/' + 'a' * (J.MAX_PATH_BYTES - 81)):
            with self.subTest(length=len(home)), patch('os.open', side_effect=AssertionError('no open')):
                with self.assertRaises(J.JournalError):
                    J.LocalReleaseJournal(home, end=time.monotonic()+20, enrollment=ENROLLMENT, key=KEY)
        book = J.LocalReleaseJournal('/' + '/'.join(['a'] * 123), end=time.monotonic()+20,
                                     enrollment=ENROLLMENT, key=KEY)
        self.books.append(book)
        self.assertEqual(len(book.parts) + len(book.suffix), J.MAX_PATH_COMPONENTS)

    def test_interrupt_during_close_drains_other_originals_without_retry(self):
        book = self.book(); self.genesis(book)
        expected = [entry[0] for entry in reversed(book.ancestors)]
        original, attempted = J._Custodian._close, []
        def interrupt_once(owner, fd):
            attempted.append(fd)
            original(owner, fd)
            if len(attempted) == 1: raise KeyboardInterrupt()
        with patch.object(J._Custodian, '_close', interrupt_once):
            with self.assertRaises(KeyboardInterrupt): book.close()
        self.assertEqual(attempted, expected)
        self.assertFalse(book.ancestors)
        self.assertIsNone(book.root)
        self.assertEqual(book._key, bytes(32))
        with self.assertRaises(J.JournalError): book.close()
        self.assertEqual(attempted, expected)

    def test_bad_operation_id_refused_before_serialization_or_publication(self):
        book = self.book(); self.genesis(book)
        head = book.head()
        with patch.object(J, 'canonical', side_effect=AssertionError('no serialization')):
            with self.assertRaises(J.JournalError):
                book._append(expected_head=head, operation_id='x' * 10000,
                             phase='inputs-pending', payload=INPUTS)
        self.assertEqual(len(book.leaves), 1)
