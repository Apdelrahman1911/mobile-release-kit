"""One local stored-key comparison on the original Apple run and writer.

Native validates the full immutable recovery relation before INITIAL. Python
checks that projection's exact linkage, never eligibility from a digest alone.
No provider/generator/journal writer, new clock or stored receipt lives here.
"""
from __future__ import annotations

import base64
import json

from . import _desktop_apple_key_protocol as key
from . import _desktop_apple_provisioning_protocol as common
from . import apple_provisioning_api as api
from ._desktop_apple_profile_protocol import _reply_envelope, key_ref
from ._desktop_preflight_protocol import _keys, integer
from .build_inputs import FiniteScratch

need = common.require


def effective_pending(native, account):
    """Private policy adapter; raw pending rows/status remain unchanged."""
    rows = common.pending(native["pending"], account)
    relations = native.get("keyRecoveries", [])
    need(type(relations) is list and len(rows) + len(relations) <= 32)
    old, operations = set(), {row.operation_id for row in rows}
    for relation in relations:
        relation = _keys(relation, {"accountRef", "operationId", "ownerGeneration", "originalOperationId",
            "originalOwnerGeneration", "originalRowSha256", "recordSha256"})
        need(relation["accountRef"] == account and all(common.token(relation[name]) for name in
            ("operationId", "ownerGeneration", "originalOperationId", "originalOwnerGeneration"))
            and all(common.sha(relation[name]) for name in ("originalRowSha256", "recordSha256"))
            and relation["operationId"] not in operations and relation["originalOperationId"] not in old)
        matching = [row for row in rows if row.operation_id == relation["originalOperationId"]]
        need(len(matching) == 1 and matching[0].kind == "key_prepare"
            and matching[0].status == "unknown" and matching[0].native_settlement == "pending")
        operations.add(relation["operationId"])
        old.add(relation["originalOperationId"])
    return tuple(row for row in rows if row.operation_id not in old)


def selection(value):
    value = _keys(value, {"reference", "rowSha256", "nativeSettlement", "output", "recovery"})
    key.reference(value["reference"])
    key.output_metadata(value["output"])
    need(common.sha(value["rowSha256"]) and value["nativeSettlement"] in {"pending", "known"})
    if value["recovery"] is not None:
        recovery = _keys(value["recovery"], {"reference", "sha256"})
        need(value["nativeSettlement"] == "pending" and common.sha(recovery["sha256"])
            and key.reference(recovery["reference"]) != value["reference"])
    return value


def validate_native(context, native):
    scope = _keys(native["key"], {"sourceP8", "sourceKey", "destination", "entitlements", "review", "vaultInventory", "recovery"})
    source, p8 = key_ref(scope["sourceKey"]), key_ref(scope["sourceP8"])
    need(context["mode"] == "key-recover" and source.record_id == context["keyRecordId"]
        and source.revision_counter == context["keyRecordRevision"]
        and p8.record_id == context["recordId"] and p8.revision_counter == context["recordRevision"]
        and source.vault_id == p8.vault_id and source.generation_id == p8.generation_id and source.record_id != p8.record_id
        and scope["vaultInventory"] is None and scope["destination"] is None and scope["review"] is None
        and scope["entitlements"] == {} and native["reviewedAt"] is None and native["prior"] is None
        and native["target"]["appIdPrefix"] == native["target"]["teamId"])
    selected = selection(scope["recovery"])
    old = [row for row in common.pending(native["pending"], native["provisioning"]["accountRef"])
           if row.operation_id == selected["reference"]["operationId"]]
    need(len(old) == 1 and old[0].kind == "key_prepare" and old[0].native_settlement == selected["nativeSettlement"])
    relations = [row for row in native.get("keyRecoveries", []) if row["originalOperationId"] == old[0].operation_id]
    if selected["recovery"] is None:
        need(not relations)
    else:
        need(len(relations) == 1 and relations[0]["originalOwnerGeneration"] == selected["reference"]["ownerGeneration"]
            and relations[0]["originalRowSha256"] == selected["rowSha256"]
            and relations[0]["recordSha256"] == selected["recovery"]["sha256"]
            and {name: relations[0][name] for name in ("operationId", "ownerGeneration")} == selected["recovery"]["reference"])


def context(value):
    need(type(value) is dict and value.get("mode") == "key-recover" and value.get("reference") is None
        and value.get("newApplication") is False and common.token(value.get("keyRecordId"))
        and integer(value.get("keyRecordRevision"), 2**32 - 2, 1))
    base = {name: item for name, item in value.items() if name not in {"keyRecordId", "keyRecordRevision"}}
    base.update(mode="review", reference=None)
    common.context(base)
    return dict(value)


def payload(request, csr, spki, output):
    need(request.context["mode"] == "key-recover")
    value = {"sourceKey": request.native["key"]["sourceKey"], "csrPem": csr.decode("ascii"),
        "publicKeySpkiDer": base64.b64encode(spki).decode("ascii"), "output": output}
    validate_event(request, value, 1)
    return value


def validate_event(request, value, sequence):
    need(request.context["mode"] == "key-recover" and sequence == 1)
    value = _keys(value, {"sourceKey", "csrPem", "publicKeySpkiDer", "output"})
    need(value["sourceKey"] == request.native["key"]["sourceKey"]
        and key.output_metadata(value["output"]) == request.native["key"]["recovery"]["output"]
        and type(value["csrPem"]) is str and value["csrPem"].isascii() and 0 < len(value["csrPem"]) <= 4096
        and value["csrPem"].startswith("-----BEGIN CERTIFICATE REQUEST-----\n")
        and value["csrPem"].endswith("-----END CERTIFICATE REQUEST-----\n")
        and type(value["publicKeySpkiDer"]) is str and 0 < len(value["publicKeySpkiDer"]) <= 1368)
    spki = base64.b64decode(value["publicKeySpkiDer"], validate=True)
    need(0 < len(spki) <= 1024 and base64.b64encode(spki).decode("ascii") == value["publicKeySpkiDer"]
        and api.digest(spki) == value["output"]["publicKeySha256"]
        and api.digest(value["csrPem"].encode("ascii")) == value["output"]["csrSha256"]
        and len(api.canonical(value)) <= common.EVENT_LIMIT)


def reply(raw, request, value):
    envelope = _reply_envelope(raw, request, 1, "key-compared-ack")
    result = _keys(envelope["payload"], {"comparisonSha256", "originalRowSha256"})
    need(result["comparisonSha256"] == api.digest(api.canonical(value))
        and result["originalRowSha256"] == request.native["key"]["recovery"]["rowSha256"])
    return result


class KeyRecoverySteps:
    def __init__(self, operation):
        from .desktop_apple_provisioning import AppleProvisioningRun
        need(type(operation) is AppleProvisioningRun and operation.source.require_operation() is operation
            and operation.request.context["mode"] == "key-recover" and operation._key_recovery is None)
        self.operation, self.compared, self.ack = operation, None, None
        self.claimed = False
        operation._key_recovery = self

    def _bound(self):
        op = self.operation
        need(op._key_recovery is self and op.source.require_operation() is op and op.request.context["mode"] == "key-recover")
        return op

    def bind_scratch(self, scratch):
        op = self._bound()
        need(type(scratch) is FiniteScratch and scratch.layout == "apple-distribution-key" and len(op.scratches) == 3
            and scratch.cancellation is op.guard and not scratch.active and not scratch.claimed
            and scratch.journal is None and scratch._lane_binding is None and op._next_command == 6
            and op._distribution_key is not None and op.invocation is not None)
        op.scratches.append(scratch)
        op._distribution_key.bind_scratch(scratch)

    def exchange(self):
        op = self._bound()
        source = op.source
        op.checkpoint()
        need(not self.claimed and self.compared is not None and source.reply_step == 0 and op._next_command == 7
            and not source.reading and not source.material_receiving and not source.material_pending
            and not source.buffer and source.engine is not None)
        self.claimed = True
        source.reply_step = 1
        source.reading = source.material_receiving = source.material_pending = True
        source.read_remaining = 1
        original = api.canonical(self.compared)
        line = bytearray()
        try:
            source.engine.provisioning_event("key-compared", self.compared)
            while not line.endswith(b"\n"):
                need(len(line) < common.ACK_LIMIT)
                line.extend(source._take(1, audit=False))
            need(not source.buffer and api.canonical(self.compared) == original)
            result = reply(bytes(line), op.request, self.compared)
            source.reading = source.material_receiving = source.material_pending = False
            op.checkpoint()
            self.ack = result
        except BaseException as error:
            op.remember(error)
            raise
        finally:
            line[:] = b"\0" * len(line)
            source.reading = source.material_receiving = False
            source.read_remaining = 0

    def run(self):
        from ._desktop_apple_distribution_key import AppleDistributionKeyWork
        op = self._bound()
        op.check(op.context)
        need(op._next_command == 6)
        child = AppleDistributionKeyWork(op).run()
        csr, spki = child.verified_public_parts(op)
        self.compared = payload(op.request, csr, spki, child.recovery_metadata(op))
        self.exchange()
        op.check(op.context)
        need(self.ack is not None)
        op.report = {"schemaVersion": 1, "scope": "local-ios-distribution-key", "mode": "key-recover",
            "decision": "compared", "reason": "stored-key-checked", "saved": False,
            "certificateRequested": False, "credentialReady": False}
        key.validate_result(op.report, op.request)
        # This result is provisional. Only native source/worker/Asset joins,
        # sole CAS and NativeUse/private retirement may publish final success.
