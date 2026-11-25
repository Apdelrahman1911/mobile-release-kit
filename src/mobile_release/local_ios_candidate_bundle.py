"""Closed retained iOS candidate DATA; not build, file, or Store authority."""
from __future__ import annotations
import hashlib
import json
import re
from .local_candidate_bundle import CandidateBundleError, MANIFEST_BYTES, _pairs, _sha, need
from .local_release_journal import canonical, _enrollment, _uuid
from ._desktop_ios_archive_protocol import content, saved_version, integer, _text
from ._desktop_android_build_protocol import _VERSION_TEXT

SCOPE = 'local-ios-candidate-inputs'
ARCHIVE_DOMAIN = b'mrk-local-ios-archive-inventory/1\0'
from .config import IOS_ID_RE


def bundle_id(value):
    return type(value) is str and len(value) <= 255 and IOS_ID_RE.fullmatch(value) is not None


def archive_digest(inventory):
    """Consume the actual shared _tree inventory, no native validity assertion."""
    from .ios_artifacts import _File
    need(type(inventory) is dict and 0 < len(inventory) <= 100_000)
    digest = hashlib.sha256(ARCHIVE_DOMAIN)
    for name, value in sorted(inventory.items(), key=lambda row: row[0].encode('utf-8')):
        need(type(name) is str and name and not name.startswith('/') and '\\' not in name
             and all(part not in {'', '.', '..'} for part in name.split('/')))
        row = {'path': name, 'kind': 'directory' if value is None else 'file'}
        if value is not None:
            need(type(value) is _File and type(value.size) is int and value.size >= 0 and _sha(value.sha256))
            row.update(bytes=value.size, sha256=value.sha256)
        digest.update(canonical(row) + b'\n')
    return digest.hexdigest()


def file_rows(value):
    need(type(value) is list and len(value) == 3)
    ipa = value[0].get('fileName') if type(value[0]) is dict else None
    need(type(ipa) is str and ipa.startswith('export/') and ipa.endswith('.ipa'))
    leaf = ipa[7:]
    need(0 < len(leaf.encode('utf-8')) <= 255 and leaf not in {'.', '..'}
         and not any(ord(c) < 32 or ord(c) == 127 or c in '/\\:' for c in leaf))
    for row, (name, maximum) in zip(value, ((ipa, 4 << 30), ('store-metadata.zip', 512 << 20),
                                           ('validation-report.json', 65536))):
        need(type(row) is dict and set(row) == {'fileName', 'bytes', 'sha256'}
             and row['fileName'] == name and type(row['bytes']) is int
             and 0 < row['bytes'] <= maximum and _sha(row['sha256']))
    return value


def archive_data(value):
    need(type(value) is dict and set(value) == {'directory', 'entries', 'bytes', 'sha256'}
         and value['directory'] == 'archive.xcarchive'
         and type(value['entries']) is int and 0 < value['entries'] <= 100_000
         and type(value['bytes']) is int and 0 < value['bytes'] <= 8 << 30 and _sha(value['sha256']))
    return value


def summary_data(value):
    need(type(value) is dict and set(value) == {'operationId', 'candidateSha256', 'sourceCommit', 'sourceTree',
         'bundleId', 'version', 'files', 'archive', 'observation', 'priorCreateFinality'}
         and _uuid(value['operationId']) and _sha(value['candidateSha256'])
         and _sha(value['sourceCommit'], 40) and _sha(value['sourceTree'], 40)
         and bundle_id(value['bundleId'])
         and value['observation'] == 'current-bundle-only' and value['priorCreateFinality'] == 'not-established')
    version = value['version']
    need(type(version) is dict and set(version) == {'name', 'build'})
    need(_text(version["name"], _VERSION_TEXT) and integer(version["build"], 2_100_000_000, 1))
    file_rows(value['files']); archive_data(value['archive'])
    return value


def signing_data(value):
    from .ios import PROFILE_UUID_RE
    from .provenance import _validate_timestamp
    need(type(value) is dict and set(value) == {'platform', 'kind', 'certificateSha256',
         'teamId', 'profileUuid', 'profileExpiresAt'} and value['platform'] == 'ios'
         and value['kind'] == 'apple-distribution' and _sha(value['certificateSha256'])
         and type(value['teamId']) is str and re.fullmatch(r'[A-Z0-9]{10}', value['teamId']) is not None
         and type(value['profileUuid']) is str and PROFILE_UUID_RE.fullmatch(value['profileUuid']) is not None
         and type(value['profileExpiresAt']) is str
         and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value['profileExpiresAt']) is not None)
    _validate_timestamp(value['profileExpiresAt'], 'candidate.signing.profileExpiresAt')
    return value


def manifest_data(raw, *, operation_id, enrollment, pending):
    need(type(raw) is bytes and 0 < len(raw) <= MANIFEST_BYTES and _uuid(operation_id))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: need(False))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CandidateBundleError() from None
    need(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'operationId', 'enrollment',
         'sourceCommit', 'sourceTree', 'savedConfig', 'savedVersion', 'bundleId', 'signing', 'files', 'archive'}
         and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
         and value['scope'] == SCOPE and value['operationId'] == operation_id
         and value['enrollment'] == _enrollment(enrollment) and canonical(value) + b'\n' == raw
         and _sha(value['sourceCommit'], 40) and _sha(value['sourceTree'], 40)
         and bundle_id(value['bundleId']))
    signing_data(value['signing'])
    config = content(value['savedConfig']); version = saved_version(value['savedVersion'])
    need(type(pending) is dict and set(pending) == {'configurationSha256', 'versionSha256', 'sourceCommit', 'sourceTree'}
         and config['sha256'] == pending['configurationSha256'] and version['sha256'] == pending['versionSha256']
         and value['sourceCommit'] == pending['sourceCommit'] and value['sourceTree'] == pending['sourceTree'])
    file_rows(value['files']); archive_data(value['archive'])
    return value
