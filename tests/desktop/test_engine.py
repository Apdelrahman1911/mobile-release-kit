"""In-memory transport checks. No child creation, descriptor tricks or services.

Real supervisor/channel/finality checks belong on disposable hosted runners.
"""

import json
import unittest

from mobile_release import _desktop_engine as engine


def frame(**changes):
    value = {"protocol": 1, "id": "test-1", "method": "capabilities", "params": {}}
    value.update(changes)
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"


class EngineContractTests(unittest.TestCase):
    def test_closed_envelope_and_identity(self):
        request = engine.parse_request(frame())
        self.assertEqual((request.id, request.method, request.params), ("test-1", "capabilities", {}))
        environment = engine.parse_request(frame(method="environment.requirements", params={"draft": {}, "platform": "ios", "operation": "build"}))
        self.assertEqual(environment.method, "environment.requirements")
        version = engine.parse_request(frame(method="release.version.observe", params={"root": "/selected/project"}))
        self.assertEqual((version.method, version.params), ("release.version.observe", {"root": "/selected/project"}))
        for changes in (
            {"protocol": True}, {"protocol": 2}, {"id": "../other"}, {"id": ""},
            {"id": "x" * 65}, {"method": "run"}, {"method": []}, {"params": []},
            {"extra": False},
        ):
            with self.subTest(changes=changes), self.assertRaises(engine.ProtocolError):
                engine.parse_request(frame(**changes))

    def test_strict_framing_duplicate_unicode_and_nonfinite(self):
        good = frame()
        for raw in (
            good[:-1], good + good, good + b"\n", b" " + good, b"[]\n", b"\xff\n",
            good.replace(b'"protocol":1', b'"protocol":1,"protocol":1'),
            good.replace(b'"params":{}', b'"params":{"x":NaN}'),
            good.replace(b'"params":{}', b'"params":{"x":1e999}'),
            good.replace(b'"params":{}', b'"params":{"x":"\\ud800"}'),
            good.replace(b'"params":{}', b'"params":{"x":1,"x":2}'),
        ):
            with self.subTest(raw=raw[:90]), self.assertRaises(engine.ProtocolError):
                engine.parse_request(raw)

    def test_depth_values_and_read_bounds(self):
        for raw in (
            frame(params={"x": "x" * engine.MAX_REQUEST_BYTES}),
            b'{"protocol":1,"id":"a","method":"catalog","params":{"x":'
            + b"[" * 33 + b"0" + b"]" * 33 + b"}}\n",
            frame(params={"x": [0] * engine.MAX_VALUES}),
        ):
            with self.assertRaises(engine.ProtocolError):
                engine.parse_request(raw)
        # Quoted brackets and escaped quotes are data, not structure.
        self.assertEqual(engine.parse_request(frame(params={"x": '[{\\"' * 100})).params["x"], '[{\\"' * 100)

    def test_results_and_errors_are_correlated_not_stringified(self):
        request = engine.parse_request(frame())
        result = json.loads(engine.encode_response(request, result={"state": "unknown"}))
        self.assertEqual(result, {"protocol": 1, "id": "test-1", "ok": True, "result": {"state": "unknown"}})
        error = {"code": "UNAVAILABLE", "message": "Not implemented", "retryable": False}
        self.assertEqual(json.loads(engine.encode_response(request, error=error))["error"], error)
        for invalid in (
            {**error, "retryable": True}, {**error, "detail": "private"},
            {**error, "message": "x" * 1601}, {**error, "message": "é" * 801},
            {**error, "message": "line\nbreak"}, {**error, "code": "../invalid"},
        ):
            with self.assertRaises(engine.ProtocolError):
                engine.encode_response(request, error=invalid)
        for value in (object(), float("inf"), {1: "not a string key"}, "x" * engine.MAX_RESPONSE_BYTES):
            with self.assertRaises(engine.ProtocolError):
                engine.encode_response(request, result=value)
        # Include the result envelope in the shared 32-container limit. An
        # empty final container must not evade the scalar-depth check.
        nested = {}
        for _ in range(engine.MAX_DEPTH - 2):
            nested = [nested]
        engine.encode_response(request, result=nested)
        with self.assertRaises(engine.ProtocolError):
            engine.encode_response(request, result=[nested])


if __name__ == "__main__":
    unittest.main()
