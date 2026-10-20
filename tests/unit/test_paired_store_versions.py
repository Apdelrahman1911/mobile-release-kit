"""Inert provider/HTTP/ACK DATA; only own temporary source/Init files are real.

No native material receipt, installed process, external edit or credential runs.
"""
from contextlib import contextmanager
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import paired_store_versions as pair
from mobile_release import android_store_versions as android
from mobile_release import ios_store_versions as ios
from mobile_release import version_allocation as allocation
from mobile_release import version_allocation_state as state
from mobile_release import version_allocation_source as source
from mobile_release import version_policy as policy
from mobile_release import desktop_store_preflight as store
from mobile_release import _desktop_store_preflight_protocol as wire
from mobile_release import _desktop_version_allocation_protocol as dialogue
from mobile_release._desktop_store_preflight_control import StorePreflightInput, PREFIX, SUFFIX, parse_header
from mobile_release.build_inputs import finite_scratch
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config import default_config_data, ReleaseVersion
from mobile_release.owned_process import ProcessCleanupError
from . import test_desktop_store_preflight as fixture
from . import test_ios_store_versions as ios_raw
from . import test_android_store_versions as play_raw
from . import test_version_allocation as original
import test_reserved_version_edit as edit_fixture
from test_version_allocation_state import LOCAL_PROJECT, NativePortFixture

NOW, IDENTITY, CONTEXT = original.NOW, original.IDENTITY, '9' * 64


def request(increment='build', **kwargs):
    return original.request('00000000-0000-4000-8000-000000000007', increment,
        enabled_platforms=pair.PLATFORMS, store_context_revision=CONTEXT,
        version_policy=policy.VersionPolicy('automatic', (policy.RefRule('refs/heads/main', increment),),
                                           store_scope=pair.POLICY_SCOPE), **kwargs)


def observations(android_build=7, ios_build=6, marketing='1.2.3'):
    return (android.CurrentInventory(IDENTITY, CONTEXT, 'a'*64, NOW, android_build, (0, 0, 0, 0, int(android_build > 0))),
            ios.CurrentInventory(IDENTITY, CONTEXT, 'b'*64, NOW, ios_build, marketing,
                                 (int(ios_build > 0), 0, int(marketing is not None))))


class PairedPolicyTests(unittest.TestCase):
    def test_v4_mixed_immutable_replay_retains_each_old_row_domain_and_envelope(self):
        ledger, authority = original.initial()
        versions = original.CurrentInventoryLedgerTests()
        stages = [ledger.append(original.request(), original.observations(), now=NOW)]
        stages.append(stages[-1].append(versions.selected(), versions.observed(), now=NOW))
        stages.append(stages[-1].append(play_raw.selected(), play_raw.inventory(20), now=NOW))
        frozen = [v.to_bytes() for v in stages]
        joined = stages[-1].append(request(), observations(30, 25, '2.0.0'), now=NOW)
        self.assertEqual(joined.last_version, ReleaseVersion('2.0.0', 31))
        self.assertEqual((joined.value()['schemaVersion'], joined.value()['protocol']), (4, allocation.PROTOCOL_V4))
        for n, old in enumerate(frozen, 1):
            self.assertEqual(allocation.Ledger(joined.genesis, joined.reservations[:n]).to_bytes(), old)
        self.assertEqual(allocation.Ledger.parse(joined.to_bytes(), authority), joined)
        for schema, protocol in ((1, allocation.PROTOCOL), (2, allocation.PROTOCOL_V2), (3, allocation.PROTOCOL_V3)):
            invalid = joined.value(); invalid.update(schemaVersion=schema, protocol=protocol)
            with self.assertRaises(ValueError): allocation.Ledger.parse(policy.canonical(invalid)+b'\n', authority)
        self.assertEqual(policy.VersionPolicy().value()['mode'], 'manual')

    def test_intersection_bound_marketing_only_and_all_increments(self):
        empty, _ = original.initial()
        for increment, expected in [('build','2.0.0'), ('patch','2.0.1'), ('minor','2.1.0'), ('major','3.0.0')]:
            result = empty.append(request(increment), observations(9, 0, '2.0.0'), now=NOW)
            self.assertEqual(result.last_version, ReleaseVersion(expected, 10))
        with self.assertRaises(policy.VersionPolicyError) as error:
            empty.append(request(), observations(9999), now=NOW)
        self.assertEqual(error.exception.reason, 'ios-integer-build-exhausted')
        # The pre-existing manual range is not narrowed by this optional policy.
        self.assertEqual(policy.version(ReleaseVersion('1.2.3', 10000), pair.PLATFORMS).build, 10000)

    def test_exact_order_same_earliest_clock_context_and_both_complete_required(self):
        empty, _ = original.initial(); good = observations()
        bad = [(), good[:1], good[::-1], (good[0], good[0]),
               (good[0], replace(good[1], observed_at=NOW-1)),
               (replace(good[0], context_revision='f'*64), good[1]),
               tuple(replace(x, observed_at=NOW-901) for x in good)]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError): empty.append(request(), value, now=NOW)
        for platforms in (('ios',), ('android',)):
            with self.assertRaises(ValueError): replace(request(), enabled_platforms=platforms)
        encoded = [x.value() for x in good]
        self.assertEqual(allocation.parse_observations(request(), encoded), good)
        with self.assertRaises(ValueError): allocation.parse_observations(request(), encoded[::-1])

    def test_lost_ack_retains_pair_and_same_candidate_never_renumbers(self):
        empty, authority = original.initial()
        remote = original.Repository(empty, authority)
        journal = original.Journal(authority, allocation.Checkpoint(0, empty.head_sha256, original.COMMIT))
        remote.write_mode = 'timeout-after'
        result = allocation.allocate_version(request(), authority, remote, journal, observations=observations(), clock=lambda:NOW)
        self.assertEqual(result.status, 'recovery-required')
        pending = allocation.PendingAllocation.parse(journal.pending[request().candidate_id])
        self.assertEqual(pending.value()['schemaVersion'], 4)
        remote.write_mode = 'normal'
        recovered = allocation.allocate_version(request(), authority, remote, journal.restarted(), observations=observations(90), clock=lambda:NOW)
        self.assertEqual(recovered.reservation, pending.reservation)
        self.assertEqual(len(remote.writes), 1)
        with self.assertRaises(policy.VersionPolicyError):
            pair.check_reserved(recovered.reservation.version, request().version_policy, enabled=pair.PLATFORMS,
                identity_revision=IDENTITY, context_revision=CONTEXT, observations=observations(90), now=NOW)

    def test_pair_summary_is_exact_current_only_and_partial_is_not_observed(self):
        good = {'android': play_raw.observe(play_raw.frame(apks=[{'versionCode':7}])),
                'ios': ios_raw.observe(ios_raw.frame(versions=[ios_raw.version('1.2.3')]))}
        self.assertTrue(pair.observed(good))
        value = pair.project_result([], good)
        wire.validate_result(value, platform='both', query=pair.QUERY)
        for platform in ('android','ios'):
            with self.assertRaises(ValueError): wire.validate_result(value, platform=platform, query=pair.QUERY)
        partial = copy.deepcopy(good); partial['android'] = android.unavailable('temporary-edit-unconfirmed', temporary_edit='unconfirmed')
        self.assertFalse(pair.observed(partial)); self.assertTrue(pair.valid_summary(partial))
        for bad in ([], {}, True):
            value['findings'] = [{'check':bad, 'status':'PASS'}]
            self.assertFalse(pair.valid_result(value))


class PairedStoreOwnerTests(unittest.TestCase):
    @contextmanager
    def original(self):
        # Same genuine source/input/cancellation/run and finite scratch classes as
        # the single-platform fixture; only the closed input frame is different.
        with fixture.DesktopStorePreflightTests().files(platform='ios') as (base, root, runtime):
            data = default_config_data({'android':{'applicationId':play_raw.PACKAGE}, 'ios':{'bundleId':ios_raw.BUNDLE}})
            data['ios']['appStoreAppId'] = ios_raw.APP
            (root/'release/mobile-release.json').write_bytes(policy.canonical(data)+b'\n')
            selected = fixture.request(root, runtime)
            selected['context'].update(platform='both', query=pair.QUERY, iosRecord={'recordId':'d'*32,'recordRevision':3})
            parts = (fixture.encode(fixture.account()), *fixture.apple_material())
            frame = PREFIX + fixture.encode({'schemaVersion':1,'files':[{'role':role,'bytes':len(raw)}
                for role,raw in zip(('google-service-account','asc-p8','asc-key-id','asc-issuer-id'),parts)]}) + b''.join(parts) + SUFFIX
            saved = os.dup(0); reader, writer = os.pipe(); os.dup2(reader,0); os.close(reader)
            os.write(writer, fixture.encode(selected)+frame)
            guard = DefaultCancellation(ProcessCleanupError, 'inert paired Store owner')
            original = StorePreflightInput(time.monotonic()); operation = None
            cwd=Path.cwd(); os.chdir(runtime)
            def cleanup():
                if operation is not None: operation.close()
                original.close()
            scope=CleanupScope(guard,cleanup,owns_cancellation=True,first_primary=True)
            def scratch(**kwargs):
                if kwargs.get('parent')==Path('/private/tmp'): kwargs['parent']=base
                return finite_scratch(**kwargs)
            try:
                with patch.object(store,'sys',SimpleNamespace(platform='darwin')), patch.object(store,'finite_scratch',side_effect=scratch), \
                     patch.object(subprocess,'Popen',side_effect=AssertionError('no real process')), patch.dict(os.environ,{'TMPDIR':str(base)},clear=True):
                    try:
                        with scope:
                            guard.install(); original.acquire(); guard._install_store_preflight_source(original); guard.activate()
                            operation=store.StorePreflightRun(original.request(),guard,original)
                            yield root,runtime,original,operation
                    finally: scope.__exit__(*sys.exc_info())
            finally:
                os.chdir(cwd); os.close(writer); os.dup2(saved,0); os.close(saved)

    def commands(self, operation, *, first_fails=False, delete_fails=False, drift=False):
        calls=[]; probes=('3.3.12','4.0.16','','MRK_RUNTIME_3.3.12_FIDDLE_1.1.2','MRK_RUNTIME_3.3.12_FIDDLE_1.1.2')
        end=operation.source.work_end
        def call(argv, **kwargs):
            n=len(calls); calls.append(tuple(argv))
            self.assertIs(kwargs['cancellation'], operation.guard)
            self.assertEqual(end,operation.source.work_end)
            self.assertLessEqual(kwargs['timeout'],60)
            if n==0: return subprocess.CompletedProcess(argv,0,stdout='',stderr='')
            if n not in (6,12): return subprocess.CompletedProcess(argv,0,stdout=probes[(n-1)%6],stderr='')
            self.assertFalse(kwargs['text']); self.assertEqual(kwargs['output_limit'],2*1024*1024)
            env=kwargs['environ']
            if n==6:
                self.assertNotIn('GOOGLE_APPLICATION_CREDENTIALS',env)
                self.assertEqual(tuple(argv),ios.fixed_argv(operation.runtime.tooling_root))
                raw=ios_raw.frame(uploads=[ios_raw.upload('6')]); raw['contextSha256']=policy.digest(operation.request.context)
                if first_fails: raw['queryFinished']=False
            else:
                self.assertNotIn('MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64',env)
                self.assertEqual(tuple(argv),android.fixed_argv(operation.runtime.tooling_root))
                raw=play_raw.frame(apks=[{'versionCode':7}]); raw['contextSha256']=policy.digest(operation.request.context)
                if delete_fails:
                    raw['temporaryEdit']['deleteConfirmed']=False; raw['pages'][-1]['response']['status']=500
                if drift:
                    path=operation.root/'release/version.properties'; path.write_bytes(path.read_bytes()+b'\n')
            return subprocess.CompletedProcess(argv,0,stdout=policy.canonical(raw),stderr=b'')
        return calls,call

    def test_same_original_four_private_roles_thirteen_commands_and_whole_pair(self):
        with self.original() as (_,_,original,operation):
            calls,call=self.commands(operation)
            with patch('mobile_release._command_process.run_command',side_effect=call): operation.run()
            self.assertEqual(len(calls),13); self.assertTrue(pair.observed(operation.report['currentVersions']))
            self.assertTrue(operation.closed()); self.assertIsNone(operation.terminal()['result'])
            self.assertNotIn('client_email',json.dumps(operation.report))
            self.assertNotIn('PRIVATE KEY',json.dumps(operation.report))
        self.assertTrue(original.material_closed())

    def test_first_reader_failure_never_opens_play_edit_and_failed_delete_never_pair(self):
        for first in (True,False):
            with self.original() as (_,_,_,operation):
                calls,call=self.commands(operation,first_fails=first,delete_fails=not first)
                with patch('mobile_release._command_process.run_command',side_effect=call): operation.run()
                self.assertEqual(len(calls),7 if first else 13)
                self.assertFalse(pair.observed(operation.report['currentVersions']))
                self.assertEqual(operation.report['currentVersions']['android']['observation'],
                                 'not-checked' if first else 'temporary-edit-unconfirmed')

    def test_source_drift_after_second_reader_vetoes_pair(self):
        with self.original() as (_,_,_,operation):
            calls,call=self.commands(operation,drift=True)
            with patch('mobile_release._command_process.run_command',side_effect=call), self.assertRaises(store._Refused): operation.run()
            self.assertEqual(len(calls),13); self.assertIsNone(operation.report)

    def test_pair_context_and_four_role_parser_do_not_widen_delivery_or_single_access(self):
        with self.original() as (_,_,_,operation):
            for options in ({},{'apple_access':True},{'bundle_query':True}):
                with self.assertRaises(ValueError): wire.context(operation.request.context,**options)
            for change in ({'query':android.QUERY},{'platform':'ios'},{'iosRecord':None}):
                invalid={**operation.request.context,**change}
                with self.assertRaises(ValueError): wire.context(invalid,apple_access=True,bundle_query=True)
        header={'schemaVersion':1,'files':[{'role':r,'bytes':n} for r,n in
            [('google-service-account',16384),('asc-p8',16384),('asc-key-id',10),('asc-issuer-id',36)]]}
        self.assertEqual(parse_header(fixture.encode(header),platform='both'),(16384,16384,10,36))
        for bad in ('android','ios'):
            with self.assertRaises(ValueError): parse_header(fixture.encode(header),platform=bad)
        header['files'][1]['bytes']=16385
        with self.assertRaises(ValueError): parse_header(fixture.encode(header),platform='both')


class PairEditFixture(edit_fixture.EditFixture):
    def __init__(self, root):
        super().__init__(root)
        self.data=default_config_data({'android':{'applicationId':'com.example.inert'},'ios':{'bundleId':'com.example.inert'}})
        self.data['source']['localStoreEnabled']=False; self.data['ios']['appStoreAppId']='17'; self.save()
        self.selected=request(source=self.binding())
        self.native=NativePortFixture(); self.native_journal=state.NativeAllocationJournal(self.native,local_project_id=LOCAL_PROJECT)
        self.native_journal.enroll_authority(self.authority,allocation.Checkpoint(0,self.ledger.head_sha256,original.COMMIT))
        self.native_journal.select_candidate(self.authority,self.selected)
        self.pair=observations()
    def _write(self,fd,raw):
        prior=len(self.frames); result=super()._write(fd,raw)
        if len(self.frames)>prior and 'ready' in self.frames[-1]:
            go=dialogue.frame(bytes(self.incoming),dialogue.GO_LIMIT)
            go['go']['observations']=[v.value() for v in self.pair]
            self.incoming[:]=dialogue.encoded(go,dialogue.GO_LIMIT)
        return result
    def handoff(self):
        row=super().handoff(); row['observation']=[v.value() for v in self.pair]; return row


class PairedReserveEditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='mrk-paired-reserved-edit-inert-')
        root=Path(self.tmp.name)/'project';root.mkdir();self.f=PairEditFixture(root);self.retained=len(source._RETAINED)
    def tearDown(self):
        del source._RETAINED[self.retained:];self.tmp.cleanup()
    def test_pair_reserve_real_preview_apply_and_restart_same_candidate_one_put(self):
        edit_fixture.ReservedVersionEditTests.test_reserve_real_preview_apply_and_retry_retains_exact_candidate_without_another_put(self)
        self.assertEqual(self.f.checkout.enabled_platforms,pair.PLATFORMS)
        self.assertEqual(self.f.fin['outcome']['reservation']['request']['policy']['schemaVersion'],4)
        self.assertEqual(len(self.f.fin['outcome']['reservation']['storeObservations']),2)
    def test_stale_either_inventory_refuses_before_put_without_single_platform_fallback(self):
        for index in (0,1):
            with self.subTest(index=index):
                root=Path(self.tmp.name)/str(index);root.mkdir();f=PairEditFixture(root)
                rows=list(f.pair);rows[index]=replace(rows[index],context_revision='f'*64);f.pair=tuple(rows)
                f.run();self.assertEqual(len(f.repository.writes),0)
                self.assertNotEqual(f.fin['outcome']['status'],'reserved')
                # Each fixture represents a separate original process lifetime;
                # remove only its settled synthetic retained call before next.
                del source._RETAINED[self.retained:]


if __name__=='__main__':unittest.main()
