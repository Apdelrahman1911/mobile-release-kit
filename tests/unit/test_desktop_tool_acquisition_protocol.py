"""Synthetic fixed DATA/ownership refusals only; no inherited FD/process/network."""
import base64
import copy
import hashlib
import json
import stat
import time
import unittest

from mobile_release import _desktop_tool_acquisition_protocol as wire
from mobile_release._desktop_tool_acquisition_control import ToolAcquisitionInput
from mobile_release._desktop_tool_acquisition_engine import _Engine
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release._tool_acquisition_spec import canonical
from mobile_release.cancellation import DefaultCancellation
from mobile_release.desktop_tool_acquisition import ToolAcquisitionRun
from mobile_release.tool_requirements import observe_tool_requirements


def directory():
    return {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o700, "uid": 501, "gid": 20}


def footprint():
    return {"module": ":app", "buildFile": "app/build.gradle", "sourcesSha256": "b" * 64,
        "directories": [{"relative": "release", "identity": directory()}],
        "missing": sorted(["app", "gradle", "build.gradle", "build.gradle.kts", "gradle.properties", "settings.gradle", "settings.gradle.kts"]),
        "files": [{"relative": wire.CONFIG, "identity": {**directory(), "mode": stat.S_IFREG | 0o600,
            "bytes": 2, "links": 1, "mtimeNs": "1", "ctimeNs": "1"}, "sha256": "a" * 64}]}


def request(acquire=False):
    value = {"protocol": wire.PROTOCOL, "operationId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "synthetic-project", "draftRevision": 1, "baselineGeneration": 2,
            "savedConfig": {"bytes": 2, "sha256": "a" * 64}, "action": "inspect", "review": None},
        "native": {"profile": "macos-arm64", "projectRoot": "/synthetic-unopened-project", "rootIdentity": directory(),
            "cwd": "/synthetic-unopened-installed-runtime", "manifestBase64": None, "caBase64": None, "cache": None}}
    if acquire:
        value["context"]["action"] = "acquire"
        value["context"]["review"] = {"operationId": "c" * 32, "ownerGeneration": "d" * 32, "requirementsSha256": "b" * 64}
        native = value["native"]
        native["manifestBase64"] = base64.b64encode(b"{}").decode("ascii")
        native["caBase64"] = base64.b64encode(b"synthetic-non-certificate").decode("ascii")
        cache = {"root": "/synthetic-unopened-cache", "rootIdentity": directory(), "generation": 1, "contextSha256": "c" * 64,
            "referenceSha256": "d" * 64, "projectionSha256": hashlib.sha256(b"{}").hexdigest(),
            "missing": [part.value for part in wire.COMPONENTS], "compatible": [], "origins": [], "footprint": footprint()}
        intent = canonical({"schemaVersion": 1, "operationId": value["operationId"], "contextSha256": cache["contextSha256"],
            "profile": native["profile"], "referenceSha256": cache["referenceSha256"], "projectionSha256": cache["projectionSha256"],
            "cacheGeneration": 1, "components": cache["missing"]})
        cache["intentBase64"] = base64.b64encode(intent).decode("ascii")
        native["cache"] = cache
    return value


def parse(value):
    return wire.parse_request(json.dumps(value, separators=(",", ":")).encode() + b"\n")


class ToolWireTests(unittest.TestCase):
    def test_closed_request_does_not_lend_execution_or_cross_domain_ownership(self):
        for acquire in (False, True):
            parsed = parse(request(acquire))
            self.assertEqual(parsed.context["action"], "acquire" if acquire else "inspect")
            self.assertEqual(json.loads(wire.response(parsed, "accepted", {"schemaVersion": 1, "context": parsed.context}))["sequence"], 0)
        source = ToolAcquisitionInput(time.monotonic())
        self.assertEqual(source_domain(source), SavedCommandDomain.ToolAcquisition)
        with self.assertRaises(wire.ProtocolError):
            source.command_limits(30, True, 4096)  # No generic child role.
        engine = _Engine(time.monotonic())
        self.assertIs(type(engine.input), ToolAcquisitionInput)
        with self.assertRaises(wire.ProtocolError):
            ToolAcquisitionRun(parse(request()), engine.guard, engine.input)  # No actual held pipe/guard binding.
        self.assertIsNone(engine.input.operation)
        class Subclass(ToolAcquisitionInput):
            pass
        with self.assertRaises(ValueError):
            source_domain(Subclass(time.monotonic()))
        with self.assertRaises(ValueError):
            DefaultCancellation(RuntimeError, "synthetic")._install_tool_acquisition_source(object())

    def test_request_rejects_arbitrary_native_path_profiles_urls_and_implicit_acquire(self):
        for path, replacement in [(('native', 'profile'), "linux-x86_64"), (('native', 'projectRoot'), "/a/../b"),
            (('context', 'review'), {}), (('context', 'action'), "install"), (('native', 'cache'), {}),
            (('context', 'draftRevision'), True)]:
            value = request()
            value[path[0]][path[1]] = replacement
            with self.subTest(path=path), self.assertRaises(wire.ProtocolError):
                parse(value)
        for name in ("url", "argv", "env", "sourceSnapshot", "credential", "authorization"):
            value = request()
            value["native"][name] = "unused"
            with self.subTest(name=name), self.assertRaises(wire.ProtocolError):
                parse(value)

    def test_duplicate_lines_limits_and_noncanonical_base64_refuse_before_service(self):
        raw = json.dumps(request()).encode() + b"\n"
        for damaged in (raw + b"\n", raw[:-1], raw.replace(b'"protocol":', b'"protocol":0,"protocol":', 1),
                        b" " * (wire.REQUEST_LIMIT + 1)):
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(damaged)
        for manifest in ("!", "e30=\n", "e30", base64.b64encode(b"changed").decode()):
            value = request(True)
            value["native"]["manifestBase64"] = manifest
            with self.assertRaises(wire.ProtocolError):
                parse(value)

    def test_complete_fixed_footprint_required_and_traversal_refuses(self):
        self.assertEqual(wire.footprint(footprint())["module"], ":app")
        cases = []
        for field, replacement in (("module", ":.."), ("buildFile", "elsewhere/build.gradle"), ("missing", [])):
            value = footprint()
            value[field] = replacement
            cases.append(value)
        value = footprint()
        value["directories"] = []
        cases.append(value)
        value = footprint()
        value["missing"] += ["gradle/wrapper"]
        cases.append(value)
        value = footprint()
        value["files"][0]["identity"]["mode"] = stat.S_IFLNK | 0o777
        cases.append(value)
        for value in cases:
            with self.assertRaises(wire.ProtocolError):
                wire.footprint(value)

    def test_native_intent_exact_components_and_same_origin_fences(self):
        for modify in (lambda c: c.update(missing=["gradle"]), lambda c: c.update(compatible=["jdk"]),
            lambda c: c.update(generation=2), lambda c: c.update(contextSha256="f" * 64),
            lambda c: c["footprint"].update(sourcesSha256="e" * 64),
            lambda c: c["footprint"]["files"][0].update(sha256="e" * 64),
            lambda c: c["footprint"]["files"][0]["identity"].update(bytes=3),
            lambda c: c.update(origins=[{"operationId": "a" * 32, "intentSha256": "d" * 64}]),
            lambda c: c.update(origins=[{"operationId": "e" * 32, "intentSha256": "d" * 64}] * 2)):
            value = request(True)
            modify(value["native"]["cache"])
            with self.assertRaises(wire.ProtocolError):
                parse(value)

    def test_no_success_from_positive_result_without_full_child_lifetime(self):
        parsed = parse(request())
        hints = observe_tool_requirements({}, platform="android", android_build_file="app/build.gradle", complete=True)
        fp = footprint()
        fp["sourcesSha256"] = hints["sourcesSha256"]
        life = {"complete": True, "fatal": False, "contained": True, "commandDispatched": False,
            "commands": 0, "profileCalls": 0, "inputClosed": True, "handlersRestored": True, "resourcesClosed": True, "stopObserved": "none"}
        terminal = {"schemaVersion": 1, "context": parsed.context, "outcome": "complete", "reason": "none",
            "result": {"kind": "tool-requirements-observation", "requirements": hints, "footprint": fp}, "lifetime": life}
        self.assertEqual(json.loads(wire.response(parsed, "terminal", terminal))["sequence"], 1)
        for field, replacement in (("fatal", True), ("resourcesClosed", False), ("inputClosed", False),
            ("handlersRestored", False), ("commands", 1), ("profileCalls", 1), ("commandDispatched", None)):
            value = copy.deepcopy(terminal)
            value["lifetime"][field] = replacement
            with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, parsed)
        value = copy.deepcopy(terminal)
        value["result"]["requirements"]["projectCodeExecuted"] = True
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, parsed)

        # A complete-looking footprint cannot replace the exact saved native
        # configuration observation that admitted this child.
        for field, replacement in (("sha256", "f" * 64), ("bytes", 3)):
            value = copy.deepcopy(terminal)
            row = value["result"]["footprint"]["files"][0]
            (row["identity"] if field == "bytes" else row)[field] = replacement
            with self.subTest(saved_config=field), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, parsed)


if __name__ == "__main__":
    unittest.main()
