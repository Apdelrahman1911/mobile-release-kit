"""P2 phase/journal DATA regression; original OS/TLS finality is a native gate."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from mobile_release import _desktop_github_preflight_engine as engine
from mobile_release import _github_connection_transport as transport
from mobile_release import _github_preflight_journal as journal
from mobile_release import github_environment_inputs as policy
from mobile_release._github_action_family import Family
from test_github_environment_inputs import (TIME, LATER, SOURCE, PRIVATE, Reader, action,
                                            bodies, prepared, sealed_body, target)


def frame(value):
    return policy.canonical(value) + b"\n"


def initial(kind="apply"):
    chosen = None if kind == "pending" else action(kind)
    scope = {key: target().value()[key] for key in
             ("projectBinding", "repository", "accountId", "repositoryId")}
    return {"protocol": policy.PROTOCOL, "id": "input-original-1",
            "action": None if chosen is None else chosen.value(),
            "pendingScope": scope if chosen is None else None,
            "home": None if kind == "prepare" else "/home/mrk"}


def request(kind="apply"):
    return engine.parse_initial(frame(initial(kind)), family=Family.INPUT_GROUP)


def read_frame(chosen):
    return frame({"protocol": policy.PROTOCOL, "id": chosen.id,
                  "read": {"requestSha256": chosen.digest, "token": None if chosen.kind == "pending" else PRIVATE}})


def go_frame(chosen, snapshot_digest, intent_digest, body=None):
    return frame({"protocol": policy.PROTOCOL, "id": chosen.id, "go": {
        "requestSha256": chosen.digest, "snapshotSha256": snapshot_digest, "intentSha256": intent_digest,
        "putBodyBase64": base64.b64encode(sealed_body() if body is None else body).decode()}})


class MemoryJournal:
    def __init__(self, events, *, fail_intent=False, fail_outcome=False):
        self.events = events
        self.fail_intent, self.fail_outcome = fail_intent, fail_outcome
        self.original = self.digest = self.write = None
        self.bind_count = 0

    def create_intent(self, selected):
        self.events.append("intent")
        if self.fail_intent:
            raise journal.JournalError("Synthetic original intent failure")
        self.original = selected
        self.digest = hashlib.sha256(journal.intent_bytes(selected, family=Family.INPUT_GROUP)).hexdigest()
        return self.digest

    def bind_outcome(self, selected, write):
        self.bind_count += 1
        self.events.append("journal-outcome")
        if self.fail_outcome:
            raise journal.JournalError("Synthetic outcome failure")
        if selected != self.original:
            raise AssertionError("Recheck replaced original intent")
        self.write = dict(write)

    def input_record(self, selected):
        return policy.record_value(selected, {"state": "attempted-outcome-unknown"}, policy.intent_digest(selected))


class ApplyReader(Reader):
    def __init__(self, chosen, values, events, *, close_failure=False):
        super().__init__(chosen, values)
        self.events, self.close_failure = events, close_failure

    def read(self, step, reference=None):
        self.events.append("get:" + step)
        return super().read(step, reference)

    def put(self, body, observer):
        self.calls.append(self.schedule.claim_write(body))
        self.events.append("put")
        budget = transport._Budget(100.0, monotonic=lambda: 100.0,
                                    _profile=transport._ExchangeProfile.INPUT_GROUP)
        response = transport._ResponseBody(io.BytesIO(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
                                           budget, _role=transport._ResponseRole.INPUT_GROUP_WRITE)
        result = transport._input_write_result(response, budget)
        transport._publish_input_write(result, observer)
        events, should_fail = self.events, self.close_failure

        class Original:
            def __init__(self, name): self.name = name
            def close(self):
                events.append("close:" + self.name)
                if should_fail and self.name == "response":
                    raise OSError("Synthetic original close")

        transport._settle_originals((Original("response"), Original("connection")), [False], result)
        return result


def run_apply(*, change_go=None, fail_intent=False, fail_outcome=False, close_failure=False):
    chosen = request()
    events, output = [], []
    owner = MemoryJournal(events, fail_intent=fail_intent, fail_outcome=fail_outcome)
    reader = ApplyReader(chosen.action, bodies(), events, close_failure=close_failure)
    writer = engine._InputOutput(chosen, 91)
    reads = 0

    def supplied(_fd, _end, _maximum, *, eof):
        nonlocal reads
        reads += 1
        if reads == 1:
            if eof: raise AssertionError("Apply READ must retain original stdin")
            return read_frame(chosen)
        if reads != 2 or not eof:
            raise AssertionError("Final GO must be the sole EOF phase")
        rechecked = json.loads(output[-1])["rechecked"]
        value = json.loads(go_frame(chosen, rechecked["snapshotSha256"], rechecked["intentSha256"]))
        if change_go is not None:
            change_go(value)
        return frame(value)

    def emitted(_fd, raw):
        envelope = json.loads(raw)
        phase = next(key for key in ("ready", "rechecked", "outcome", "result") if key in envelope)
        events.append("emit:" + phase)
        output.append(raw)

    with patch.object(engine, "_read_input_phase", side_effect=supplied), \
         patch.object(engine, "_write_response", side_effect=emitted), \
         patch.object(engine.time, "monotonic", return_value=100.0), \
         patch.object(policy, "_make_live_reader", return_value=reader):
        result = engine._run_input_group(chosen, 90, writer, owner, started=100.0, runtime_dir="/unused")
    return chosen, result, events, output, owner, reader, writer


class GitHubInputGroupFrameTests(unittest.TestCase):
    def test_distinct_read_and_final_go_bind_original_initial_snapshot_and_intent(self):
        chosen = request()
        self.assertEqual(chosen.digest, hashlib.sha256(frame(initial())).hexdigest())
        ready = json.loads(engine.input_ready_frame(chosen))
        self.assertEqual(ready["ready"], {"requestSha256": chosen.digest, "phase": "observe", "journal": "opened"})
        self.assertEqual(engine.parse_input_read(read_frame(chosen), chosen), PRIVATE)
        original = chosen.action.prepared
        snapshot = original.value()
        snapshot["observedAt"] = snapshot["metadata"]["observedAt"] = LATER
        fresh = policy.Prepared.parse(snapshot)
        intent = hashlib.sha256(journal.intent_bytes(original, family=Family.INPUT_GROUP)).hexdigest()
        raw, digest = engine.input_rechecked_frame(chosen, fresh, intent)
        self.assertEqual(digest, hashlib.sha256(policy.canonical(snapshot)).hexdigest())
        self.assertEqual(json.loads(raw)["rechecked"]["intentSha256"], intent)
        final = go_frame(chosen, digest, intent)
        self.assertEqual(engine.parse_input_go(final, chosen, digest, intent), sealed_body())
        for invalid in (read_frame(chosen), final + final, final[:-1], final + b" ",
                        final.replace(digest.encode(), b"f" * 64),
                        final.replace(intent.encode(), b"a" * 64)):
            with self.assertRaises(ValueError):
                engine.parse_input_go(invalid, chosen, digest, intent)
        with self.assertRaises(ValueError):
            engine.parse_input_read(final, chosen)
        with self.assertRaises(ValueError):
            engine.parse_go(read_frame(chosen), chosen)

    def test_initial_read_final_go_are_incremental_and_final_eof_is_required(self):
        chosen = request()
        raw = go_frame(chosen, "e" * 64, "f" * 64)
        for cut in (1, 2, len(raw) // 2, len(raw) - 1):
            with patch.object(engine.os, "read", side_effect=[raw[:cut], raw[cut:], b""]), \
                 patch.object(engine.time, "monotonic", return_value=100.0):
                self.assertEqual(engine._read_input_phase(90, 110.0, engine.MAX_INPUT_GO_BYTES, eof=True), raw)
        for values in ([raw[:-1], b""], [raw + raw, b""], [b""]):
            with patch.object(engine.os, "read", side_effect=values), \
                 patch.object(engine.time, "monotonic", return_value=100.0), self.assertRaises(ValueError):
                engine._read_input_phase(90, 110.0, engine.MAX_INPUT_GO_BYTES, eof=True)
        with patch.object(engine.os, "read", return_value=read_frame(chosen)), \
             patch.object(engine.time, "monotonic", side_effect=[100.0, 110.0]), self.assertRaises(ValueError):
            engine._read_input_phase(90, 110.0, engine.MAX_INPUT_READ_BYTES, eof=False)
        with patch.object(engine.os, "read", return_value=read_frame(chosen) + raw), \
             patch.object(engine.time, "monotonic", return_value=100.0), self.assertRaises(ValueError):
            engine._read_input_phase(90, 110.0, engine.MAX_INPUT_READ_BYTES, eof=False)

    def test_apply_chronology_has_ten_reads_then_original_intent_one_put_outcome_before_cleanup(self):
        chosen, result, events, output, owner, reader, writer = run_apply()
        self.assertEqual(result["record"]["write"], {"state": "acknowledged-updated", "statusCode": 204})
        self.assertEqual(result["reason"], "none")
        self.assertEqual(reader.schedule.steps, list(policy._READ_STEPS))
        self.assertEqual([call.method for call in reader.calls], ["GET"] * 10 + ["PUT"])
        self.assertLess(events.index("get:repository-after"), events.index("intent"))
        self.assertLess(events.index("intent"), events.index("emit:rechecked"))
        self.assertLess(events.index("emit:rechecked"), events.index("put"))
        self.assertLess(events.index("emit:outcome"), events.index("close:response"))
        self.assertLess(events.index("emit:outcome"), events.index("close:connection"))
        self.assertLess(events.index("close:connection"), events.index("journal-outcome"))
        self.assertEqual(owner.original, chosen.action.prepared)
        self.assertEqual(owner.bind_count, 1)
        self.assertEqual(len(output), 3)  # No extra ACK request or replacement reader.
        result["journal"] = "confirmed"  # This test's synthetic owner, not OS evidence.
        terminal = engine.encode_result(chosen, result)
        with patch.object(engine, "_write_response") as emitted:
            writer.emit("result", terminal)
            emitted.assert_called_once_with(91, terminal)
        self.assertEqual(len((output[-1] + terminal).splitlines()), 2)
        self.assertNotIn(PRIVATE.encode(), b"".join(output) + terminal)

    def test_early_durability_or_go_refusal_never_attempts_a_put_and_ack_survives_late_failures(self):
        chosen, result, events, output, owner, reader, _ = run_apply(fail_intent=True)
        self.assertEqual(result["reason"], "journal-incomplete")
        self.assertNotIn("put", events)
        self.assertEqual(len(output), 1)
        self.assertEqual(owner.bind_count, 0)
        _, result, events, _, owner, _, _ = run_apply(change_go=lambda value: value["go"].update(intentSha256="0" * 64))
        self.assertNotIn("put", events)
        self.assertEqual(owner.write, {"state": "not-attempted"})
        for arguments, reason in (({"fail_outcome": True}, "journal-incomplete"), ({"close_failure": True}, "response-invalid")):
            _, result, events, _, owner, _, _ = run_apply(**arguments)
            self.assertEqual(result["reason"], reason)
            self.assertEqual(result["record"]["write"]["state"], "acknowledged-updated")
            self.assertEqual(owner.bind_count, 1)
            self.assertEqual(events.count("put"), 1)
            self.assertEqual(events.count("close:response"), 1)
            self.assertEqual(events.count("close:connection"), 1)
            self.assertLess(events.index("emit:outcome"), events.index("journal-outcome"))

    def test_optional_outcome_has_strict_phase_and_never_waits_for_an_ack(self):
        chosen = request()
        writer = engine._InputOutput(chosen, 91)
        ready = engine.input_ready_frame(chosen)
        checked, digest = engine.input_rechecked_frame(chosen, chosen.action.prepared, policy.intent_digest(chosen.action.prepared))
        outcome = engine.input_outcome_frame(chosen, digest, "e" * 64,
                    {"state": "acknowledged-created", "statusCode": 201}, transport._control())
        with patch.object(engine, "_write_response"):
            writer.emit("ready", ready)
            with self.assertRaises(ValueError): writer.emit("outcome", outcome)
            writer.emit("rechecked", checked)
            with self.assertRaises(ValueError): writer.emit("outcome", outcome)
            writer.go_accepted = True
            writer.emit("outcome", outcome)
            with self.assertRaises(ValueError): writer.emit("outcome", outcome)
        broken = engine._InputOutput(chosen, 91)
        with patch.object(engine, "_write_response", side_effect=OSError("Synthetic pipe failure")):
            with self.assertRaises(OSError): broken.emit("ready", ready)
        with patch.object(engine, "_write_response") as retry:
            with self.assertRaises(ValueError): broken.emit("ready", ready)
            retry.assert_not_called()

    def test_pending_uses_null_action_and_null_token_without_network_client(self):
        chosen = request("pending")
        self.assertEqual(json.loads(engine.input_ready_frame(chosen))["ready"]["journal"], "loaded")
        with patch.object(engine, "_read_input_phase", return_value=read_frame(chosen)), \
             patch.object(engine, "_write_response"), patch.object(policy, "_make_live_reader") as network:
            result = engine._run_input_group(chosen, 90, engine._InputOutput(chosen, 91), None,
                                             started=100.0, runtime_dir="/unused")
        self.assertIsNone(result)
        network.assert_not_called()
        self.assertIsNone(engine.parse_input_read(read_frame(chosen), chosen))
        bad = json.loads(read_frame(chosen)); bad["read"]["token"] = PRIVATE
        with self.assertRaises(ValueError): engine.parse_input_read(frame(bad), chosen)
        records = []
        for index in range(64):
            value = prepared().value(); value["target"]["marker"] = format(index, "032x")
            selected = policy.Prepared.parse(value)
            records.append(policy.record_value(selected,
                {"state": "attempted-outcome-unknown"}, policy.intent_digest(selected)))
        encoded = engine.encode_result(chosen, None, records)
        self.assertLessEqual(len(encoded), engine.MAX_RESULT_BYTES)
        self.assertNotIn(b'"finality"', encoded)
        with self.assertRaises(ValueError): engine.encode_result(chosen, None, records + records[:1])
        with self.assertRaises(ValueError): engine.encode_result(chosen, None, [records[0], records[0]])

    def test_immutable_outcome_family_and_restart_uncertainty_never_create_workflow_run_ids(self):
        original = prepared()
        raw = journal.intent_bytes(original, family=Family.INPUT_GROUP)
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(journal.parse_intent(raw, family=Family.INPUT_GROUP), original)
        outcome = journal.outcome_bytes(digest, {"state": "acknowledged-created", "statusCode": 201})
        self.assertEqual(journal.parse_outcome(outcome, digest)["statusCode"], 201)
        for operation in (lambda: journal.parse_intent(raw), lambda: journal.parse_run(outcome, digest),
                          lambda: journal.parse_outcome(outcome, "f" * 64),
                          lambda: journal.parse_outcome(outcome[:-1], digest)):
            with self.assertRaises(ValueError): operation()
        owner = journal.Journal("/home/mrk", end=110.0, family=Family.INPUT_GROUP)
        owner.records[original.target.marker] = original, None, digest
        with patch.object(owner, "_post"):
            record = owner.input_record(original)
        self.assertEqual(record["write"], {"state": "attempted-outcome-unknown"})
        self.assertNotIn("cleanup", record)
        self.assertNotIn("finality", record)
        self.assertIsNone(owner.leaf_pattern.fullmatch(original.target.marker + ".run.json"))
        self.assertIsNotNone(owner.leaf_pattern.fullmatch(original.target.marker + ".outcome.json"))
        owner.records[original.target.marker] = original, {"state": "acknowledged-created", "statusCode": 201}, digest
        with patch.object(owner, "_post"), patch.object(owner, "_create") as create:
            owner.bind_outcome(original, {"state": "acknowledged-created", "statusCode": 201})
            create.assert_not_called()
            with self.assertRaises(journal.JournalError):
                owner.bind_outcome(original, {"state": "acknowledged-updated", "statusCode": 204})
            with self.assertRaises(journal.JournalError):
                owner.admit_input_intent(original)


if __name__ == "__main__":
    unittest.main()
