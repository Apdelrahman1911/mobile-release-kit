"""Synthetic raw provider DATA only: no credentials, HTTP or native receipts."""
import base64
import copy
import unittest
from dataclasses import replace
from unittest.mock import patch

from mobile_release import android_store_versions as v
from mobile_release import ios_store_versions as ios
from mobile_release import version_allocation as a
from mobile_release import version_policy as p
from mobile_release.config import ReleaseVersion
from . import test_version_allocation as original

PACKAGE, CONTEXT, IDENTITY = 'com.example.version', '9' * 64, original.IDENTITY
EDIT = 'synthetic-edit-1'


def page(step, body, *, status=None, failure=None):
    raw = body if type(body) is bytes else p.canonical(body)
    return {'step': step, 'request': v.request(step, PACKAGE, None if step == 'insert' else EDIT),
            'response': {'status': (204 if step == 'delete' else 200) if status is None else status,
                         'bodyBase64': base64.b64encode(raw).decode(), 'failure': failure}}


def frame(*, tracks=(), bundles=(), apks=()):
    return {'schemaVersion': 1, 'scope': v.SCOPE, 'contextSha256': CONTEXT, 'packageName': PACKAGE,
        'pages': [page('insert', {'id': EDIT, 'expiryTimeSeconds': '99999'}),
                  page('tracks', {'tracks': list(tracks)}), page('bundles', {'bundles': list(bundles)}),
                  page('apks', {'apks': list(apks)}), page('delete', b'')],
        'queryFinished': True, 'temporaryEdit': {'insertAttempted': True, 'editId': EDIT,
                                               'deleteAttempted': True, 'deleteConfirmed': True}}


def observe(value):
    raw = value if type(value) is bytes else p.canonical(value)
    return v.summary_from_frame(raw, context_sha256=CONTEXT, package_name=PACKAGE)


def selected(increment='build', candidate='00000000-0000-4000-8000-000000000006'):
    return original.request(candidate, increment, store_context_revision=CONTEXT,
        version_policy=p.VersionPolicy('automatic', (p.RefRule('refs/heads/main', increment),), store_scope=v.POLICY_SCOPE))


def inventory(build=10, counts=(1, 1, 1, 0, 0)):
    return (v.CurrentInventory(IDENTITY, CONTEXT, 'a' * 64, original.NOW, build, counts),)


class CurrentPlayInventoryTests(unittest.TestCase):
    def test_ruby_frame_terminator_keeps_capture_limit_and_edit_uncertainty(self):
        raw = p.canonical(frame(apks=[{'versionCode': 21}]))
        expected = observe(raw)
        self.assertEqual((expected['observation'], expected['maxBuild'], expected['temporaryEdit']),
                         ('observed', 21, 'deleted'))
        self.assertEqual(observe(raw + b'\n'), expected)
        unknown = v.unavailable('temporary-edit-unconfirmed', temporary_edit='unconfirmed')
        for changed in (raw + b'\n\n', raw + b'\r\n', raw + b' \n', raw + b'\n ',
                        raw + b'\n' + raw + b'\n', b'\n' + raw + b'\n', b'\n'):
            with self.subTest(raw=changed[-12:]):
                self.assertEqual(observe(changed), unknown)
        with patch.object(v, 'FRAME_LIMIT', len(raw)):
            self.assertEqual(observe(raw), expected)
            self.assertEqual(observe(raw + b'\n'), unknown)
        with patch.object(v, 'FRAME_LIMIT', len(raw) + 1):
            self.assertEqual(observe(raw + b'\n'), expected)
        with self.assertRaises(ValueError):
            v._json(b'{}\n')  # Only the fixed reader's framing changed.

    def test_all_tracks_all_statuses_apks_bundles_and_repeated_codes_count(self):
        tracks = [{'track': status, 'releases': [{'name': '9999.9.9 IS NOT A VERSION', 'status': status,
                    'versionCodes': ['10', str(index + 1)]}]} for index, status in enumerate(('draft', 'inProgress', 'halted', 'completed'))]
        result = observe(frame(tracks=tracks, bundles=[{'versionCode': 15}], apks=[{'versionCode': 21}]))
        self.assertEqual((result['observation'], result['maxBuild'], result['marketingVersion']), ('observed', 21, None))
        self.assertEqual(result['counts'], dict(tracks=4, releases=4, versionCodes=8, bundles=1, apks=1))
        self.assertEqual(result['temporaryEdit'], 'deleted')
        self.assertEqual(result['historicalUniqueness'], 'not-established')
        self.assertTrue(v.valid_summary(result))

    def test_real_empty_omitted_repeated_fields_and_apk_only_are_supported(self):
        value = frame()
        for i, name in enumerate(v.COLLECTIONS, 1): value['pages'][i] = page(name, {})
        self.assertEqual(observe(value)['maxBuild'], 0)
        self.assertEqual(observe(frame(apks=[{'versionCode': 11}]))['maxBuild'], 11)
        value['pages'].pop(2)
        self.assertNotEqual(observe(value)['observation'], 'observed')

    def test_incomplete_or_unknown_pagination_never_becomes_empty(self):
        for bad in ({'tracks': [], 'nextPageToken': 'second'}, {'tracks': None}, {'unexpected': []}):
            value = frame(); value['pages'][1] = page('tracks', bad)
            result = observe(value)
            self.assertEqual((result['observation'], result['temporaryEdit']), ('inconclusive', 'deleted'))
            self.assertIsNone(result['maxBuild'])
        value = frame(); value['queryFinished'] = False
        self.assertEqual(observe(value)['observation'], 'inconclusive')

    def test_all_lists_capped_and_noncanonical_dotted_out_of_range_codes_refuse(self):
        for collection in v.COLLECTIONS:
            value = frame()
            value['pages'][1 + v.COLLECTIONS.index(collection)] = page(collection, {collection: [{}] * 401})
            self.assertEqual(observe(value)['observation'], 'too-many')
        for code in ('01', '0', '1.2', '2147483647', 1, True):
            value = frame(tracks=[{'track': 'internal', 'releases': [{'status': 'draft', 'versionCodes': [code]}]}])
            self.assertEqual(observe(value)['observation'], 'unsupported-format')
        value = frame(bundles=[{'versionCode': True}])
        self.assertEqual(observe(value)['observation'], 'unsupported-format')

    def test_unconfirmed_insert_or_delete_keeps_external_uncertainty_not_a_floor(self):
        for status, body in ((500, b'PRIVATE_PROVIDER_ERROR'), (200, b''), (204, b'not-empty')):
            value = frame(); value['pages'][-1] = page('delete', body, status=status)
            value['temporaryEdit']['deleteConfirmed'] = False
            result = observe(value)
            self.assertEqual(result['observation'], 'temporary-edit-unconfirmed')
            self.assertEqual(result['temporaryEdit'], 'unconfirmed')
            self.assertIsNone(result['revision'])
            self.assertNotIn('PRIVATE_PROVIDER_ERROR', str(result))
        value = frame(); value['pages'] = [page('insert', b'partial response', status=500)]
        value['queryFinished'] = False
        value['temporaryEdit'].update(editId=None, deleteAttempted=False, deleteConfirmed=False)
        self.assertEqual(observe(value)['observation'], 'temporary-edit-unconfirmed')

    def test_confirmed_zero_byte_delete_and_late_known_id_cleanup_is_not_success(self):
        value = frame(); value['pages'] = [value['pages'][0], value['pages'][-1]]; value['queryFinished'] = False
        result = observe(value)
        self.assertEqual((result['observation'], result['temporaryEdit']), ('inconclusive', 'deleted'))
        value = frame(); value['pages'][1] = page('tracks', {'error': 'PRIVATE'}, status=403)
        value['pages'] = value['pages'][:2] + value['pages'][-1:]; value['queryFinished'] = False
        self.assertEqual(observe(value)['observation'], 'not-permitted')
        value = frame(); value['pages'][-1]['request']['path'] += 'foreign'
        self.assertEqual(observe(value)['observation'], 'temporary-edit-unconfirmed')

    def test_raw_and_frame_bounds_duplicates_reject_without_echo(self):
        value = frame(); value['pages'][2] = page('bundles', b'{"bundles":[],"bundles":[]}')
        self.assertEqual(observe(value)['observation'], 'inconclusive')
        value['pages'][2] = page('bundles', b' ' * (v.RAW_LIMIT + 1))
        self.assertNotEqual(observe(value)['observation'], 'observed')
        value = frame(); value['contextSha256'] = 'b' * 64
        self.assertNotEqual(observe(value)['observation'], 'observed')


class CurrentPlayAllocationTests(unittest.TestCase):
    def test_schema3_is_explicit_android_only_and_old_envelope_hashes_are_unchanged(self):
        empty, authority = original.initial()
        legacy = empty.append(original.request(), original.observations(), now=original.NOW)
        old = original.CurrentInventoryLedgerTests()
        mixed2 = legacy.append(old.selected(), old.observed(), now=original.NOW)
        v1_bytes, v2_bytes = legacy.to_bytes(), mixed2.to_bytes()
        before = [r.value() for r in mixed2.reservations]
        mixed3 = mixed2.append(selected(), inventory(21), now=original.NOW)
        self.assertEqual(mixed3.value()['protocol'], a.PROTOCOL_V3)
        self.assertEqual(mixed3.value()['schemaVersion'], 3)
        self.assertEqual(mixed3.last_version, ReleaseVersion('1.4.0', 22))
        self.assertEqual([r.value() for r in mixed3.reservations[:2]], before)
        self.assertEqual(a.Ledger(mixed3.genesis, mixed3.reservations[:1]).to_bytes(), v1_bytes)
        self.assertEqual(a.Ledger(mixed3.genesis, mixed3.reservations[:2]).to_bytes(), v2_bytes)
        self.assertEqual(a.Ledger.parse(mixed3.to_bytes(), authority), mixed3)
        for schema, protocol in ((1, a.PROTOCOL), (2, a.PROTOCOL_V2)):
            bad = mixed3.value(); bad.update(schemaVersion=schema, protocol=protocol)
            with self.assertRaises(a.VersionAllocationError): a.Ledger.parse(p.canonical(bad) + b'\n', authority)
        for platforms in (('ios',), ('android', 'ios')):
            with self.assertRaises(a.VersionAllocationError): replace(selected(), enabled_platforms=platforms)
        for schema in (1, 2):
            bad = selected().version_policy.value(); bad['schemaVersion'] = schema
            with self.assertRaises(p.VersionPolicyError): p.VersionPolicy.parse(bad)
        self.assertEqual(p.VersionPolicy().schema_version, 1)

    def test_same_candidate_lost_ack_reconciles_once_and_new_floor_never_renumbers(self):
        empty, authority = original.initial()
        journal = original.Journal(authority, a.Checkpoint(0, empty.head_sha256, original.COMMIT))
        remote = original.Repository(empty, authority)
        remote.write_mode = "timeout-after"
        result = a.allocate_version(selected(), authority, remote, journal, observations=inventory(), clock=lambda: original.NOW)
        self.assertEqual(result.status, 'recovery-required')
        pending = a.PendingAllocation.parse(journal.pending[selected().candidate_id])
        self.assertEqual(pending.value()['schemaVersion'], 3)
        remote.write_mode = "normal"
        recovered = a.allocate_version(selected(), authority, remote, journal.restarted(), observations=inventory(99), clock=lambda: original.NOW)
        self.assertEqual(recovered.status, 'reserved')
        self.assertEqual(recovered.reservation, pending.reservation)
        self.assertEqual(len(remote.writes), 1)
        with self.assertRaises(p.VersionPolicyError) as raised:
            v.check_reserved(recovered.reservation.version, selected().version_policy, enabled=('android',),
                identity_revision=IDENTITY, context_revision=CONTEXT, observations=inventory(99), now=original.NOW)
        self.assertEqual(raised.exception.reason, 'reservation-consumed')

    def test_build_range_all_increments_freshness_and_exact_material_context(self):
        empty, _ = original.initial()
        for increment, name in (('build', '1.2.3'), ('patch', '1.2.4'), ('minor', '1.3.0'), ('major', '2.0.0')):
            result = empty.append(selected(increment), inventory(10_001), now=original.NOW)
            self.assertEqual(result.last_version, ReleaseVersion(name, 10_002))
        for observed in (inventory(p.MAX_BUILD), (replace(inventory()[0], context_revision='b' * 64),),
                         (replace(inventory()[0], observed_at=original.NOW - 901),),
                         (ios.CurrentInventory(IDENTITY, CONTEXT, 'a' * 64, original.NOW, 11, '1.0.0', (1, 0, 0)),)):
            with self.assertRaises((p.VersionPolicyError, a.VersionAllocationError)):
                empty.append(selected(), observed, now=original.NOW)


if __name__ == '__main__': unittest.main()
