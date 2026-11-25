"""Closed iOS Create DATA/phase framing; original native authority is separate."""
from __future__ import annotations
from uuid import UUID
from . import _desktop_ios_archive_protocol as ios
from . import _desktop_local_history_protocol as history
from .local_candidate_create_protocol import PHASES, CLOSES, REASONS, head
from .local_candidate_bundle import _sha
from .local_ios_candidate_bundle import SCOPE, summary_data


def native_history(value):
    ios._keys(value, {'home', 'leaseFd', 'nonce', 'clock'})
    ios._path(value['home'])
    ios.require(ios.integer(value['leaseFd'], 255, 3) and ios._text(value['nonce'], ios._TOKEN)
                and value['nonce'] != '0' * 32)
    clock = ios._keys(value['clock'], {'workEndNs', 'cleanupEndNs', 'hardEndNs'})
    for n in clock.values():
        ios.require(type(n) is str and 1 <= len(n) <= 20 and n.isascii() and n.isdigit()
                    and not n.startswith('0') and 0 < int(n) < 1 << 64)
    work, cleanup, hard = (int(clock[k]) for k in ('workEndNs', 'cleanupEndNs', 'hardEndNs'))
    ios.require(work <= cleanup <= hard and cleanup - work <= 120_000_000_000
                and hard - cleanup <= 10_000_000_000)
    return {**value, 'clock': dict(clock)}


def reply(raw, request, kind, step):
    value = history.decode(raw, 2048)
    ios._keys(value, {'protocol', 'operationId', 'ownerGeneration', 'nonce', 'requestSha256', 'kind', 'step', 'payload'})
    ios.require(value['protocol'] == ios.CANDIDATE_PROTOCOL and value['operationId'] == request.operation_id
                and value['ownerGeneration'] == request.owner_generation
                and value['nonce'] == request.native['candidateHistory']['nonce']
                and value['requestSha256'] == request.digest and value['kind'] == kind
                and ios.integer(value['step'], 4, 1) and value['step'] == step)
    if step == 1:
        ios.require(kind == 'key-material')
        return history._enrollment(value['payload'])
    ios.require(kind == 'checkpoint-settled' and value['payload'] == {})
    return None


def result_data(value, request):
    ios._keys(value, {'schemaVersion', 'scope', 'headSequence', 'candidateInputs', 'build'})
    ios.require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                and value['scope'] == SCOPE and ios.integer(value['headSequence'], 513, 3))
    selected = summary_data(value['candidateInputs']); build = value['build']
    ios.require(selected['operationId'] == str(UUID(hex=request.operation_id))
                and selected['version'] == {k: request.context['savedVersion'][k] for k in ('name', 'build')}
                and type(build) is dict
                and build.get('archive') == f'.mobile-release/desktop-ios-archive/{request.operation_id}/archive.xcarchive'
                and build.get('ipa') == f'.mobile-release/desktop-ios-archive/{request.operation_id}/' + selected['files'][0]['fileName']
                and build.get('ipaBytes') == selected['files'][0]['bytes']
                and build.get('entries') == selected['archive']['entries']
                and build.get('bytes') == selected['archive']['bytes'])


def terminal(value, request):
    ios.require(ios.candidate_create(request.context))
    ios._validate_terminal(value, request, candidate=True)
    if value['outcome'] == 'complete':
        ios.require(value['result']['candidateInputs']['bundleId'] == value['activity']['selection']['bundleId'])


class IOSCandidateFrames:
    def __init__(self, request):
        ios.require(ios.candidate_create(request.context) and _sha(request.digest))
        self.request = request
        self.binding = ios._encode(ios._request_binding(request))
        self.count = self.total = self.phase = 0
        self.stage = -1
        self.finished = self.failed = False
        self.previous_head = None

    def response(self, kind, payload):
        try:
            ios.require(not self.failed and not self.finished and self.count < 17
                        and ios._encode(ios._request_binding(self.request)) == self.binding)
            if self.count == 0:
                ios.require(kind == 'accepted' and payload == {'schemaVersion': 1, 'context': self.request.context})
            elif kind == 'progress':
                ios._keys(payload, {'schemaVersion', 'stage'})
                ios.require(type(payload['schemaVersion']) is int and payload['schemaVersion'] == 1
                            and payload['stage'] in ios.SIGNED_STAGES)
                stage = ios.SIGNED_STAGES.index(payload['stage'])
                ios.require(stage > self.stage and (stage == 0 or self.phase >= 3))
                self.stage = stage
            elif kind in PHASES:
                ios.require(self.phase < 4 and kind == PHASES[self.phase] and self.stage >= 0)
                if self.phase == 0:
                    ios.require(payload == {})
                else:
                    current = head(payload)
                    if self.phase == 1:
                        ios.require(current['sequence'] <= 511)
                    else:
                        ios.require(self.previous_head is not None
                                    and current['sequence'] == self.previous_head['sequence'] + 1)
                    self.previous_head = current
                if kind == 'inputs-ready':
                    ios.require(self.stage == len(ios.SIGNED_STAGES) - 1)
                self.phase += 1
            elif kind == 'terminal':
                terminal(payload, self.request)
                if payload['outcome'] == 'complete':
                    ios.require(self.phase == 4 and self.stage == len(ios.SIGNED_STAGES) - 1
                                and payload['result']['headSequence'] == self.previous_head['sequence'])
                self.finished = True
            else:
                ios.require(False)
            raw = ios._encode({'protocol': ios.CANDIDATE_PROTOCOL, 'operationId': self.request.operation_id,
                'ownerGeneration': self.request.owner_generation, 'nonce': self.request.native['candidateHistory']['nonce'],
                'requestSha256': self.request.digest, 'sequence': self.count, 'kind': kind, 'payload': payload})
            ios.require(len(raw) <= (65536 if kind == 'terminal' else 4096) and self.total + len(raw) <= 65536)
            self.count += 1; self.total += len(raw)
            return raw
        except BaseException:
            self.failed = True
            raise
