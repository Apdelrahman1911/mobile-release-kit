"""Retained first-detach DATA/owner-port tests; no Mac, network or native proof."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest
from unittest import mock

from desktop.tools import macos_candidate_consumer as C
from desktop.tools import macos_fixed_carrier_resume as R


DEVICE = '/dev/disk7s1'
DETACH = ['/usr/bin/hdiutil', 'detach', DEVICE]
WALL = 1_798_200_000_123_456_789
MONO = 1_000_000_000


def event(message, **extra):
    return dict(subsystem=C.DA_SUBSYSTEM, category='default', eventMessage=message, **extra)


def failure_event(device=DEVICE, code='00000010'):
    return event(f'unable to unmount {device} (status code 0x{code}).',
                 processID=99887766, processImagePath='/PRIVATE/PATH')


def api_event():
    return event('  dispatched response, id = AABBCCDDEEFF0011:1122334455667788, '
                 f'kind = disk unmount approval, disk = {DEVICE}, dissented, status = 0xF8DA0002.')


class Book:
    """Inert donor shape; OriginalQuota itself performs real admission arithmetic."""
    def __init__(self):
        self.entries, self.directories, self.errors = [], {}, []

    def directory(self, path):
        if path not in self.directories:
            if path != Path('/'): self.directory(path.parent)
            row = {'path': path, 'kind': 'directory', 'fd': -1, 'closed': False}
            self.entries.append(row); self.directories[path] = row
        return self.directories[path]

    def file(self, path, *args, **kwargs):
        self.directory(path.parent)
        row = {'path': path, 'kind': 'file', 'fd': -1, 'closed': False}
        self.entries.append(row)
        return row, b'INERT TOOL BYTES'

    def check(self): pass


@contextmanager
def owner_port(*, code=16, log_code=0, log_stdout=None, log_stderr=b'', fault=None, reserved=95,
               retained=True, readback=True, clock_bad=False):
    C._RETAINED_DETACH = None
    with mock.patch.object(R.Resume, '__init__', return_value=None):
        owner = C.CandidateResume(C.HELPER_ROOT, C.CANDIDATE_ROOT, Path('/inert'), None, None,
                                  retained_observer=retained)
    owner._CandidateResume__installation_entered = True
    owner.installer_entered = owner.installer_zero = True
    owner.readback_known = readback
    owner.installation = {'inert': True}
    owner.work, owner.parent = Path('/inert'), {'fd': -123}
    owner.environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/runner', 'TZ': 'UTC'}
    owner.calls = []
    now = [MONO]
    owner.clock = R.Deadline(now=lambda: now[0]); owner.clock.finality = True
    owner.quota = R.OriginalQuota()
    owner.outer = owner.quota.book(Book); owner.outer.directory(Path('/usr/bin'))
    owner.quota.reserve(reserved)
    calls, originals = [], []
    failure = RuntimeError('PRIVATE ORIGINAL FAILURE')
    # Even affirmative exception attributes are not normal original return.
    failure.contained = failure.cleanup_complete = True
    def native(argv, **kwargs):
        calls.append((list(argv), kwargs))
        now[0] += 100_000_000
        if argv[0] == '/usr/bin/hdiutil':
            if fault == 'detach-unknown': raise failure
            result = subprocess.CompletedProcess(argv, code, b'', b'PRIVATE DETACH CAPTURE')
            originals.append(result)
            return result
        if fault == 'log-unknown': raise failure
        result = subprocess.CompletedProcess(argv, log_code,
            R.canonical([failure_event()]) if log_stdout is None else log_stdout, log_stderr)
        if fault == 'bad-contract': result.stdout = 'not bytes'
        return result
    owner.owner = SimpleNamespace(run_owned=mock.Mock(side_effect=native))
    def no_logrc(name, **kwargs):
        if name != '.logrc' or kwargs != {'dir_fd': -123, 'follow_symlinks': False}:
            raise AssertionError('Unexpected filesystem observation')
        if fault == 'logrc': return object()
        raise FileNotFoundError(name)
    def wall():
        if clock_bad: raise OSError('INERT CLOCK FAILURE')
        return WALL + now[0] - MONO
    with mock.patch.object(C.time, 'time_ns', side_effect=wall), \
         mock.patch.object(C.time, 'monotonic_ns', side_effect=lambda: now[0]), \
         mock.patch.object(C.os, 'getuid', return_value=501), \
         mock.patch.object(C.os, 'geteuid', return_value=501), \
         mock.patch.object(C.os, 'stat', side_effect=no_logrc), \
         mock.patch.object(C.os, 'open', side_effect=AssertionError('No real FD in owner-port tests')):
        yield owner, calls, originals, failure, now


class RetainedDetachDiagnosticTests(unittest.TestCase):
    def tearDown(self): C._RETAINED_DETACH = None

    def test_two_exact_apple_grammars_only_with_finite_codes(self):
        body = R.canonical([failure_event(), api_event(), failure_event(),
            failure_event('/dev/disk7s10'), event('holder PRIVATE name <private>')])
        value = C.retained_detach_log_codes(body, b'', 0, DEVICE)
        self.assertEqual(value, {'codes': [dict(kind='api-dissent-log', code=0xF8DA0002),
                                        dict(kind='unmount-failure-log', code=16)]})
        public = R.canonical(value)
        for private in (b'PRIVATE', b'99887766', b'AABBCCDDEEFF0011', b'/dev/disk'):
            self.assertNotIn(private, public)
        for message in ('unable to unmount <private> (status code 0x00000010).',
                        f'unable to unmount {DEVICE} (status code 0x000000100).',
                        f'unable to unmount {DEVICE} (status code 0x0000010).',
                        f'unable to unmount {DEVICE} (status code -16).',
                        f'  dispatched response, kind = disk unmount approval, disk = {DEVICE}, dissented, status = 0x00000010.'):
            self.assertEqual(C.retained_detach_log_codes(R.canonical([event(message)]), b'', 0, DEVICE), {'codes': []})

    def test_data_bounds_and_unavailable_results_never_become_attribution(self):
        self.assertIsNone(C.retained_detach_log_codes(b'[]', b'PRIVATE WARNING', 0, DEVICE))
        self.assertIsNone(C.retained_detach_log_codes(b'[]', b'', 1, DEVICE))
        for body in (b'', b'{}', b'[{"category":"default","category":"default"}]',
                     b'[NaN]', R.canonical([failure_event()] * 65),
                     R.canonical([event('x' * 513)]), R.canonical([dict(failure_event(), subsystem='foreign')]),
                     b'x' * (C.DETACH_LOG_LIMIT + 1)):
            with self.subTest(body=body[:40]), self.assertRaises((R.Refused, ValueError)):
                C.retained_detach_log_codes(body, b'', 0, DEVICE)
        many = [failure_event(code=f'{code:08X}') for code in range(9)]
        with self.assertRaises(R.Refused): C.retained_detach_log_codes(R.canonical(many), b'', 0, DEVICE)
        for code in (True, 1.0, '0'):
            with self.assertRaises(R.Refused): C.retained_detach_log_codes(b'[]', b'', code, DEVICE)

    def test_clock_and_predicate_use_only_the_sampled_original_window(self):
        before, after = (WALL, MONO), (WALL + 100_000_000, MONO + 100_000_000)
        argv = C.retained_detach_log_argv(DEVICE, before, after)
        self.assertEqual(argv[:4], ['/usr/bin/log', 'show', '--style', 'json'])
        self.assertEqual(argv[8:11], ['--timezone', 'UTC', '--no-pager'])
        self.assertIn('process == "diskarbitrationd"', argv[-1])
        self.assertIn('category == "default"', argv[-1])
        self.assertIn('unmount /dev/disk7s1 (status code ', argv[-1])
        self.assertIn('disk = /dev/disk7s1, dissented, status = ', argv[-1])
        self.assertNotIn('--info', argv); self.assertNotIn('--debug', argv)
        for device in ('/dev/disk7s1" OR TRUE', '/dev/rdisk7', '/Volumes/private', '/dev/disk123456'):
            with self.assertRaises(R.Refused): C.retained_detach_log_argv(device, before, after)
        for bad in (None, (True, MONO), (WALL - 1, MONO + 1),
                    (WALL + 3_000_000_000, MONO + 1), (WALL + 31_000_000_000, MONO + 31_000_000_000)):
            with self.assertRaises(R.Refused): C.retained_detach_log_argv(DEVICE, before, bad)

    def test_one_original16_one_same_owner_log_and_no_roster_mutation(self):
        with owner_port() as (owner, calls, originals, _, _now):
            result = owner.command('detach', DETACH, 30)
            self.assertIs(result, originals[0]); self.assertEqual(result.returncode, 16)
            self.assertEqual([row['role'] for row in owner.calls], ['detach'])
            self.assertEqual(owner.quota.reserved, 96)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0], DETACH)
            self.assertEqual(calls[0][1]['timeout'], 30)
            self.assertEqual(calls[0][1]['output_limit'], 65536)
            self.assertEqual(calls[0][1]['environ'], owner.environment)
            self.assertEqual(calls[1][0][0], '/usr/bin/log')
            self.assertEqual(calls[1][1], dict(environ=dict(owner.environment, HOME='/inert'), cwd=owner.work,
                timeout=10, capture=True, text=False, output_limit=16384, cleanup=True))
            self.assertEqual(R.STATE['lastRole'], 'detach')
            report = C.failure_data(R.Refused('resume-original-detach'))['retainedDetachObservation']
            self.assertEqual(report['state'], 'observed')
            self.assertEqual(report['codes'], [dict(kind='unmount-failure-log', code=16)])
            self.assertTrue(report['settled']); self.assertFalse(report['resourceUnknown'])
            for key in ('rawOutputExported', 'absenceEstablished', 'requestAttributionEstablished',
                        'holderAuthentication', 'systemServiceExitClaimed'):
                self.assertIs(report[key], False)
            self.assertNotIn(b'PRIVATE', R.canonical(report))
            owner.observe_retained_detach(result, 0, None, None)
            self.assertEqual(len(calls), 2)
            with self.assertRaises(R.Refused): owner.command('detach', DETACH, 30)
            self.assertEqual(len(calls), 2)

    def test_nonfailure_unknown_nonretained_and_failed_prerequisites_do_not_query(self):
        for options in ({'code': 0}, {'code': 1}, {'retained': False}, {'readback': False}, {'clock_bad': True}, {'reserved': 96}):
            with self.subTest(options=options), owner_port(**options) as (owner, calls, originals, _, _now):
                self.assertIs(owner.command('detach', DETACH, 30), originals[0])
                self.assertEqual(len(calls), 1)
                self.assertEqual(owner.quota.reserved, options.get('reserved', 95))
                if C._RETAINED_DETACH is not None:
                    value = C.retained_detach_diagnostic_data(C._RETAINED_DETACH)
                    self.assertEqual(value['state'], 'unavailable'); self.assertEqual(value['codes'], [])
        with owner_port(fault='detach-unknown') as (owner, calls, _, original, _now):
            with self.assertRaises(RuntimeError) as caught: owner.command('detach', DETACH, 30)
            self.assertIs(caught.exception, original)
            self.assertEqual(len(calls), 1); self.assertEqual(owner.quota.reserved, 95)
            self.assertFalse(owner.calls[0]['returned']); self.assertIsNone(C._RETAINED_DETACH)

    def test_every_diagnostic_failure_preserves_identical16_and_custody_uncertainty(self):
        for fault in ('log-unknown', 'bad-contract', 'logrc', 'tool-unknown', 'parse-unknown'):
            with self.subTest(fault=fault), owner_port(fault=fault) as (owner, calls, originals, original, _now):
                if fault == 'tool-unknown':
                    owner.outer.file = mock.Mock(side_effect=original)
                parser = mock.Mock(side_effect=original) if fault == 'parse-unknown' else C.retained_detach_log_codes
                with mock.patch.object(C, 'retained_detach_log_codes', parser):
                    result = owner.command('detach', DETACH, 30)
                self.assertIs(result, originals[0]); self.assertEqual(result.returncode, 16)
                self.assertEqual(owner.quota.reserved, 96)
                value = C.retained_detach_diagnostic_data(C._RETAINED_DETACH)
                self.assertEqual(value['state'], 'unavailable'); self.assertEqual(value['codes'], [])
                self.assertEqual(value['resourceUnknown'], fault in ('log-unknown', 'bad-contract', 'tool-unknown'))
                self.assertEqual(value['settled'], fault == 'parse-unknown')
                self.assertLessEqual(len(calls), 2)

    def test_empty_redacted_nonzero_and_warning_outputs_are_plain_unavailable(self):
        for options in ({'log_stdout': b'[]'}, {'log_stdout': R.canonical([event('<private>')])},
                        {'log_code': 1}, {'log_stderr': b'PRIVATE WARNING'}, {'log_stdout': b'not json'}):
            with self.subTest(options=options), owner_port(**options) as (owner, _, originals, _, _now):
                self.assertIs(owner.command('detach', DETACH, 30), originals[0])
                value = C.retained_detach_diagnostic_data(C._RETAINED_DETACH)
                self.assertEqual(value['state'], 'unavailable'); self.assertEqual(value['codes'], [])
                self.assertTrue(value['returned']); self.assertTrue(value['settled'])
                self.assertFalse(value['resourceUnknown'])

    def test_deadline_reserve_no_parent_or_nonroot_admission_cannot_add_a_query(self):
        for fault in ('deadline', 'parent', 'root'):
            with self.subTest(fault=fault), owner_port() as (owner, calls, originals, _, now):
                if fault == 'deadline': now[0] = owner.clock.deadline - 15_500_000_000
                if fault == 'parent': owner.outer.directories.pop(Path('/usr/bin'))
                with mock.patch.object(C.os, 'geteuid', return_value=0 if fault == 'root' else 501):
                    if fault == 'deadline':
                        # The original shared command itself cannot borrow its reserved15s.
                        with self.assertRaises(R.Refused): owner.command('detach', DETACH, 30)
                        self.assertEqual(calls, [])
                    else:
                        self.assertIs(owner.command('detach', DETACH, 30), originals[0])
                        self.assertEqual(len(calls), 1)
                self.assertEqual(owner.quota.reserved, 95)

    def test_projector_never_exports_unknown_fields_or_malformed_codes(self):
        with owner_port() as (owner, *_):
            owner.command('detach', DETACH, 30)
            raw = dict(C._RETAINED_DETACH, private='PRIVATE', codes=[{'kind': 'PRIVATE', 'code': 123}])
            value = C.retained_detach_diagnostic_data(raw)
            self.assertEqual(value['state'], 'unavailable'); self.assertEqual(value['codes'], [])
            self.assertNotIn(b'PRIVATE', R.canonical(value))
            for codes in ([{'kind': 'unmount-failure-log', 'code': True}],
                          [{'kind': 'unmount-failure-log', 'code': 1 << 32}],
                          [{'kind': 'unmount-failure-log', 'code': 16, 'raw': 'PRIVATE'}]):
                self.assertEqual(C.retained_detach_diagnostic_data(dict(raw, codes=codes))['codes'], [])

    def test_actual_whole_plan_has_one_failure_only_cell_without_refunds_or_source_growth(self):
        quota = R.OriginalQuota(); quota.reserve(2)
        outer = quota.book(Book)
        work = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/resume-carrier')
        quota.call(outer, 'directory', work)
        for name in (*C.HELPER_SOURCE_INPUTS, C.RETAINED_OBSERVER_SELECTION_PATH, C.CONSUMER_PATH,
                     C.LEGACY_PATH, C.PARSER_PATH, R.SIGNING_CERTIFICATE[0], R.TLS_CA_PATH):
            quota.call(outer, 'file', C.HELPER_ROOT / name, 1)
        for name in (C.STAGER_PATH, *(name for name, _ in C.CANDIDATE_SOURCE_INPUTS)):
            quota.call(outer, 'file', C.CANDIDATE_ROOT / name, 1)
        host = work.parent / 'host-python'
        quota.call(outer, 'file', host / 'host-binding.json', 1)
        for name in R.HOST_DIRS: quota.call(outer, 'directory', host / name)
        for name in (*R.HOST_FILES, R.HOST_OPTIONAL): quota.call(outer, 'file', host / name, 1)
        for name in ('git', 'hdiutil', 'vm_stat', 'openssl', 'codesign'):
            quota.call(outer, 'file', Path('/usr/bin') / name, 1)
        quota.call(outer, 'file', Path('/usr/sbin/installer'), 1); quota.reserve(4)
        self.assertEqual(quota.reserved, 76)
        quota.reserve(3); quota.call(outer, 'file', work / 'arm64-retained-observer.zip', 1)
        quota.reserve(1); quota.call(outer, 'file', work / 'arm64.dmg', 1)
        quota.call(outer, 'directory', Path('/Volumes'))
        mounted = quota.book(Book)
        mounted.directories.update({p: e for p, e in outer.directories.items() if p in (Path('/'), Path('/Volumes'))})
        mount = Path('/Volumes/inert'); quota.call(mounted, 'directory', mount)
        for name in ('Install.pkg', 'producer.json', 'producer.sig'): quota.call(mounted, 'file', mount / name, 1)
        for name in ('producer-key.pem', 'producer-message.bin', 'producer-message.bin'):
            quota.call(outer, 'file', work / name, 1)
        quota.call(outer, 'directory', work / 'input')
        quota.call(outer, 'file', work / 'input/install-inventory.json', 1)
        quota.call(outer, 'file', work / 'installer-output.status', 1)
        quota.reserve(2)  # Only pre-attach/attached iterators have been entered.
        self.assertEqual(quota.reserved, 95)
        quota.call(outer, 'file', Path('/usr/bin/log'), 64 << 20, uid=0, modes=(0o555, 0o755))
        self.assertEqual(quota.reserved, R.MAX_ORIGINALS)
        with self.assertRaises(R.Refused): quota.reserve(1)  # No success POST or second leaf after16.
        self.assertEqual(R.MAX_ORIGINALS, 96)
        clock = R.Deadline(now=lambda: MONO)
        self.assertEqual(clock.deadline - clock.started, 600_000_000_000)
        self.assertEqual(clock.deadline - clock.work, 60_000_000_000)
        self.assertLessEqual(Path(C.__file__).stat().st_size, 96 << 10)


if __name__ == '__main__': unittest.main()
