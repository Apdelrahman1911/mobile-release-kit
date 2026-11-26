"""Retained ZIP allocation/custody seams only; no Mac, network, or RSS proof."""
import ast
import builtins
from contextlib import contextmanager
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from desktop.tools import macos_candidate_consumer as C
from desktop.tools import macos_e2_native_fixture as F
from desktop.tools import macos_fixed_carrier_resume as R
from tests.desktop.test_macos_candidate_carrier import archive, retained_fixture
from tests.desktop.test_macos_candidate_consumer import mounted_fixture, retained_instance


RESERVE = (16 << 20) + (512 << 20) + (1 << 30)
FAILED_AVAILABLE = 3179905024
FAILED_REQUIRED = 3396405392


def owner_for(selection):
    owner = retained_instance(selection)
    owner.sources, owner.child_bootstrap = [], ''
    owner.work, owner.private, owner.parent = Path('/inert'), {}, {'fd': -911}
    owner.clock, owner.host = R.Deadline(now=lambda: 1), object()
    owner.command = mock.Mock(return_value=SimpleNamespace(stdout=b'', stderr=b'', returncode=0))
    owner._resource_inputs = (0, 17)
    return owner


@contextmanager
def capacity(available=1 << 40, disk=1 << 40):
    with mock.patch.dict(R.STATE), \
            mock.patch.object(R, 'host_memory_data', return_value=(16384, 1 << 40)), \
            mock.patch.object(R, 'memory_data', side_effect=lambda *a, **k: {
                'availableEstimateBytes': available() if callable(available) else available}), \
            mock.patch.object(C.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=disk, f_frsize=1)):
        yield


def large_fixture():
    selection, entries, *_ = retained_fixture()
    entries[-2] = (entries[-2][0], b'O' * (2 * 65536 + 123))
    entries[-1] = (entries[-1][0], b'M' * (65536 + 17))
    body, origin = archive(selection['origin'], entries)
    return dict(selection, origin=origin,
                members=[dict(name=name, bytes=len(value)) for name, value in entries]), entries, body


class RetainedResourceAdmissionTests(unittest.TestCase):
    def test_failed_observation_has_separate_peaks_not_changed_reserves_or_disk(self):
        selection = R.decode((C.ROOT / C.RETAINED_OBSERVER_SELECTION_PATH).read_bytes())
        a = selection['origin']['artifactBytes']
        i = next(v['bytes'] for v in selection['members'] if v['name'] == C.candidate.RETAINED_OBSERVER_IMAGE)
        # Historical source amount, not a prediction of this edited program's RSS.
        retained = FAILED_REQUIRED - 6 * a - RESERVE
        owner = owner_for(selection)
        ordinary = C.candidate_resource_requirements(selection['origin'], retained, 17)
        self.assertEqual(ordinary['acquisitionMemory'], FAILED_REQUIRED)
        self.assertGreater(FAILED_REQUIRED, FAILED_AVAILABLE)
        with capacity(FAILED_AVAILABLE):
            owner.admit_resources(retained, 17)
            self.assertEqual(owner.memory_base, retained + RESERVE + 3 * a)
            self.assertEqual(owner.required_disk, ordinary['requiredDisk'])
            owner.admit_resources(retained, 17, image_bytes=i, acquiring=True)
            self.assertEqual(owner.memory_base, retained + RESERVE + 2 * a + 3 * i)
            full = C.candidate_resource_requirements(selection['origin'], retained, 17, image_bytes=i)
            self.assertEqual(owner.required_disk, full['requiredDisk'])
            owner.admit_resources(retained, 17, image_bytes=i)
            self.assertEqual(owner.memory_base, full['postAcquisitionMemory'])
            self.assertEqual(owner.memory_base, retained + RESERVE + 6 * i)
            self.assertFalse(R.STATE['resourceAdmission']['osMemoryReservation'])
            self.assertFalse(R.STATE['resourceAdmission']['peakRssQualified'])
        self.assertEqual(owner.command.call_args_list,
                         [mock.call('memory', ['/usr/bin/vm_stat'], 10)] * 3)
        # The ordinary candidate still requires its original larger quote.
        with mock.patch.object(R.Resume, '__init__', return_value=None):
            other = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                      nomination=selection['origin'])
        for key in ('sources', 'child_bootstrap', 'parent', 'clock', 'host', 'command'):
            setattr(other, key, getattr(owner, key))
        with capacity(FAILED_AVAILABLE), self.assertRaisesRegex(R.Refused, 'candidate-resource-admission'):
            other.admit_resources(retained, 17)

    def test_initial_refusal_cannot_enter_acquisition_install_or_add_a_retry(self):
        selection, *_ = retained_fixture()
        for disk_short in (False, True):
            owner = owner_for(selection)
            owner._CandidateResume__source_loaded = True
            owner.quota = SimpleNamespace(reserved=76, finish=mock.Mock(return_value=True))
            owner.acquire_candidate, owner.install_image = mock.Mock(), mock.Mock()
            demand = C.candidate.retained_observer_memory_requirement(selection, 0)
            with self.subTest(disk_short=disk_short), capacity(
                    1 << 40 if disk_short else demand - 1, 0 if disk_short else 1 << 40):
                try:
                    owner.consume(0, 17)
                except R.Refused as error:
                    self.assertEqual(error.args, ('candidate-resource-admission',))
                    # Inspect the actual traceback before unittest clears it.
                    facts = C.failure_data(error)['resourceAdmission']
                else:
                    self.fail('original resource admission must refuse')
                self.assertEqual(facts['requiredMemoryBytes'], demand)
                self.assertEqual(facts['memorySufficient'], disk_short)
                self.assertEqual(facts['diskSufficient'], not disk_short)
            owner.acquire_candidate.assert_not_called()
            owner.install_image.assert_not_called()
            owner.command.assert_called_once_with('memory', ['/usr/bin/vm_stat'], 10)
            owner.quota.finish.assert_called_once_with()
            self.assertEqual(owner.quota.reserved, 76)
            self.assertEqual(owner.clock.deadline - owner.clock.started, 600_000_000_000)
            self.assertEqual(owner.clock.deadline - owner.clock.work, 60_000_000_000)
            self.assertFalse(owner.clock.finality)

    def test_unselected_size_cannot_request_a_smaller_decode_quote(self):
        selection, entries, *_ = retained_fixture()
        owner = owner_for(selection)
        image_size = len(entries[-1][1])
        for size in (image_size - 1, image_size + 1, sum(len(v) for _, v in entries), True, 0):
            with self.subTest(size=size), capacity(), self.assertRaises(R.Refused):
                owner.admit_resources(0, 17, image_bytes=size, acquiring=True)
        owner.command.assert_not_called()

    def test_decode_and_exact_original_post_share_one_leaf_and_keep_full_decode_quote(self):
        selection, entries, body = large_fixture()
        a, i = len(body), len(entries[-1][1])
        faults = (None, 'pin', 'capacity', 'post-bytes', 'post-short', 'post-grew',
                  'post-before', 'post-after', 'post-unknown', 'post-deadline')
        for fault in faults:
            owner, events, reads, now = owner_for(selection), [], [], [1]
            owner.clock = R.Deadline(now=lambda: now[0])
            original_error = RuntimeError('inert original post uncertainty')
            entry = {'fd': -922, 'identity': (1, 2, stat.S_IFREG | 0o600, 501, 20, 1, a, 1, 1)}
            book = SimpleNamespace(entries=[], directories={owner.work: owner.parent})
            def original(path, limit, *, modes):
                events.append('file')
                self.assertEqual(owner.memory_base, RESERVE + 3 * a)
                self.assertEqual((path, limit, modes), (owner.work / 'arm64-retained-observer.zip', a, (0o600,)))
                book.entries.append(entry)
                return entry, (b'!' + body[1:] if fault == 'pin' else body)
            book.file = mock.Mock(side_effect=original)
            book.read = mock.Mock(side_effect=AssertionError('full ZIP reread forbidden'))
            def identity(held):
                self.assertIs(held, entry)
                self.assertEqual(owner.memory_base, RESERVE + 2 * a + 3 * i)
                events.append('identity')
                if fault == 'post-before' and events.count('identity') == 1 or \
                        fault == 'post-after' and events.count('identity') == 2:
                    raise original_error
            book.check_one = mock.Mock(side_effect=identity)
            owner.quota = R.OriginalQuota()
            owner.outer = owner.quota.book(lambda: book)
            owner.quota.reserve(76)  # Inert already-funded source/parent prefix.
            def pread(fd, count, offset):
                self.assertEqual(fd, entry['fd'])
                self.assertLessEqual(count, 65536)
                self.assertEqual(owner.memory_base, RESERVE + 2 * a + 3 * i)
                reads.append((fd, count, offset))
                if fault == 'post-unknown': raise original_error
                data = body[offset:offset + count]
                if fault == 'post-bytes' and offset == 0: return b'!' + data[1:]
                if fault == 'post-short' and offset == 0: return data[:-1]
                if fault == 'post-grew' and offset == a: return b'!'
                if fault == 'post-deadline': now[0] = owner.clock.work
                return data
            samples = []
            def available():
                samples.append('sample')
                return 0 if fault == 'capacity' and len(samples) == 2 else 1 << 40
            with self.subTest(fault=fault), capacity(available), mock.patch.object(R.os, 'pread', side_effect=pread):
                owner.admit_resources(0, 17)
                if fault is None:
                    result = owner.read_candidate_zip()
                    self.assertEqual(result, {C.candidate.RETAINED_OBSERVER_IMAGE: entries[-1][1]})
                    self.assertEqual(R.decode(owner._CandidateResume__members_document),
                        [dict(name=n, bytes=len(v), sha256=R.sha(v)) for n, v in entries])
                    self.assertEqual(R.decode(owner._CandidateResume__image_document),
                        dict(name=entries[-1][0], bytes=i, sha256=R.sha(entries[-1][1])))
                    self.assertEqual(reads, [(entry['fd'], min(65536, a - offset), offset)
                                            for offset in range(0, a, 65536)] + [(entry['fd'], 1, a)])
                    self.assertTrue(owner._CandidateResume__artifact_admitted)
                    owner.admit_resources(0, 17, image_bytes=i)
                    self.assertEqual(owner.memory_base, RESERVE + 6 * i)
                else:
                    with self.assertRaises((R.Refused, RuntimeError)) as caught: owner.read_candidate_zip()
                    if fault in ('post-before', 'post-after', 'post-unknown'):
                        self.assertIs(caught.exception, original_error)
                    self.assertFalse(owner._CandidateResume__artifact_admitted)
                    self.assertIsNone(owner._CandidateResume__image_document)
                    self.assertFalse(hasattr(owner, '_CandidateResume__members_document'))
                    if fault in ('pin', 'capacity'): self.assertEqual(reads, [])
            self.assertEqual(owner.quota.reserved, 77)
            self.assertEqual(book.entries, [entry])
            book.file.assert_called_once()
            book.read.assert_not_called()
            self.assertEqual(len(samples), 3 if fault is None else 1 if fault == 'pin' else 2)
            self.assertEqual(owner.private['arm64-retained-observer.zip'], entry['identity'])

    def test_late_package_and_codec_demands_are_not_discounted_or_skipped(self):
        selection, entries, *_ = retained_fixture()
        image = entries[-1][1]
        for fault in (None, 'read', 'before', 'after'):
            owner = owner_for(selection)
            originals, row, stage = mounted_fixture(owner.target)
            owner._CandidateResume__artifact_admitted = True
            owner._CandidateResume__members_document = R.canonical(row['members'])
            owner.selection = stage.source_build_selection(owner.target)
            stage.PRODUCER_DESCRIPTOR_BYTES, stage.PRODUCER_SIGNATURE_BYTES = 16384, 512
            owner.stager, owner.signing_identity, owner.point = stage, row['signingIdentity'], mock.Mock()
            package, calls = len(originals['Install.pkg'][0]), []
            before = RESERVE + len(image) + 6 * package + 2 * 65536
            after = RESERVE + len(image) + package + 2 * 65536
            def read(book, method, path, *args, **kwargs):
                self.assertEqual(owner.memory_base, before)
                calls.append(path.name)
                if fault == 'read' and path.name == 'producer.sig': raise OSError('inert read')
                return {}, originals[path.name][0]
            owner.quota = SimpleNamespace(call=read)
            def parse(*args, **kwargs):
                self.assertEqual(calls, list(originals))
                self.assertEqual(owner.memory_base, after)
                self.assertEqual(kwargs['allocation_budget'], owner.allocation_budget)
                return {}, b'inventory'
            samples = []
            def available():
                samples.append('sample')
                return 0 if (fault == 'before' and len(samples) == 1 or
                             fault == 'after' and len(samples) == 2) else 1 << 40
            with self.subTest(fault=fault), capacity(available), \
                    mock.patch.object(C.os, 'stat', side_effect=lambda name, **kw: SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o444, st_size=len(originals[name][0]),
                        st_uid=C.os.getuid(), st_gid=C.os.getgid())), \
                    mock.patch.object(R, 'mounted_data', side_effect=parse) as parser:
                if fault is None:
                    owner.read_mounted(object(), {'fd': -933}, Path('/inert'), image, None)
                    self.assertEqual(owner.memory_base, after)
                    parser.assert_called_once()
                else:
                    with self.assertRaises((R.Refused, OSError)):
                        owner.read_mounted(object(), {'fd': -933}, Path('/inert'), image, None)
                    parser.assert_not_called()
                    self.assertIsNone(owner._CandidateResume__binding)
            if fault is None:
                # Deliberately large synthetic codec demand still fails its
                # actual late guard; it is NOT a claim about retained P sizes.
                live, packed, output = 320 << 20, 160 << 20, 400 << 20
                required = after + live + 3 * packed + 2 * (output + 1) + (16 << 20)
                self.assertGreater(required, FAILED_AVAILABLE)
                with capacity(FAILED_AVAILABLE), self.assertRaisesRegex(R.Refused, 'resume-resource-memory-admission'):
                    try: owner.allocation_budget('scripts', live, packed, output)
                    finally:
                        self.assertEqual(R.STATE['resourceAdmission']['requiredMemoryBytes'], required)
                        self.assertFalse(R.STATE['resourceAdmission']['memorySufficient'])
                self.assertEqual(owner.memory_base, after)
                self.assertEqual(owner.allocation_samples, 1)

    def test_original_reader_has_one_growable_and_one_final_copy(self):
        # Actual donor method, inert pread/check ports. Allocation sizes here
        # check the source model only; no native allocator/RSS qualification.
        for size in (22, 65535, 65536, 65537, 3 * 65536 + 31, (2 << 20) + 1):
            body, growth, conversions, reads = b'A' * size, [], [], []
            class Buffer(bytearray):
                def extend(self, block):
                    before = self.__alloc__()
                    super().extend(block)
                    growth.append(before + self.__alloc__() + len(block))
            def freeze(value):
                self.assertIsInstance(value, Buffer)
                conversions.append(value.__alloc__() + len(value) + 65536)
                return builtins.bytes(value)
            def pread(fd, count, offset):
                self.assertEqual(fd, -944)
                reads.append((count, offset))
                return body[offset:offset + count]
            book = SimpleNamespace(check_one=mock.Mock())
            entry = {'fd': -944, 'identity': (1, 2, 3, 4, 5, 6, size)}
            with self.subTest(size=size), mock.patch.object(F, 'bytearray', Buffer, create=True), \
                    mock.patch.object(F, 'bytes', freeze, create=True), mock.patch.object(F.os, 'pread', side_effect=pread):
                self.assertEqual(F.Originals.read(book, entry), body)
            self.assertEqual(len(conversions), 1)
            self.assertTrue(all(peak <= 3 * size + (16 << 20) for peak in growth + conversions))
            self.assertTrue(all(0 < count <= 65536 for count, _ in reads))
            self.assertEqual(reads[-1], (1, size))
            self.assertEqual(book.check_one.call_args_list, [mock.call(entry), mock.call(entry)])

    def test_held_consumer_source_cap_is_unchanged(self):
        body = Path(C.__file__).read_bytes()
        calls = [node for node in ast.walk(ast.parse(body)) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'source'
                 and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == 'CONSUMER_PATH']
        self.assertEqual([ast.dump(node.args[1]) for node in calls],
                         [ast.dump(ast.parse('96 << 10', mode='eval').body)])
        self.assertLessEqual(len(body), 96 << 10)


if __name__ == '__main__':
    unittest.main()
