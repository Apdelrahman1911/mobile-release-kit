"""Finite Xcode failure categories; no native runner import or process calls."""
import ast
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "desktop/tools/macos_normal_ui_runner.py"


def reducers():
    tree = ast.parse(RUNNER.read_bytes())
    names = {"Refused", "need", "sha", "encoded", "failure_base", "normal_failure_diagnostics"}
    nodes = [node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    assert {node.name for node in nodes} == names and len(nodes) == len(names)
    namespace = dict(hashlib=hashlib, json=json, re=re, subprocess=subprocess)
    constants = {"NORMAL_SELECTIONS", "OUTPUT_DATA_RESULT", "IOS_UNSIGNED_RESULT"}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in constants:
                namespace[target.id] = ast.literal_eval(node.value)
    assert constants <= namespace.keys()
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNNER), "exec"), namespace)
    return namespace


def admission_reducers():
    """Genuine finite DATA only; no native runner/core import or owner command."""
    names = {"Refused", "need", "pairs", "document", "encoded", "normal_admission_failure",
        "classify_normal_admission_failure", "admit_output_data_result_post", "LOADER", "TOOLCHAIN_QUERIES",
        "ADMISSION_STAGES", "ADMISSION_EXCEPTION_TYPES", "ADMISSION_EXCEPTION_LABELS", "ADMISSION_SOURCE_FILES",
        "ADMISSION_COMMAND_ROLES", "ADMISSION_OWNER_REASONS"}
    nodes, found = [], set()
    for node in ast.parse(RUNNER.read_bytes()).body:
        name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in names:
            nodes.append(node); found.add(name)
    assert found == names and len(nodes) == len(names)
    namespace = dict(json=json, re=re, Path=Path, __file__=str(RUNNER))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNNER), "exec"), namespace)
    class Owner:
        class ProcessError(Exception):
            def __init__(self, message, mask=None):
                super().__init__(message)
                self.owner_failure_mask = mask
                self.dispatched = self.contained = self.cleanup_complete = True
            def __str__(self):
                raise AssertionError("exception-text-must-not-be-read")
        class ProcessCleanupError(ProcessError):
            pass
        class ProcessOutcomeUnknown(ProcessError):
            pass
        class ProcessInterrupted(KeyboardInterrupt):
            pass
    return namespace, Owner


def build_settings_reducers(*, main=False):
    """Actual DATA, phase/clock and caller with inert ports; no owner import."""
    names = {"Refused", "need", "pairs", "encoded", "sha", "original_command", "PhaseClock", "NormalPhase",
        "normal_target_data", "normal_build_arguments", "normal_build_settings_arguments", "normal_build_settings_data",
        "publish_normal_build_settings", "ARM_TARGET", "INTEL_TARGET", "TARGET", "PROJECT",
        "NORMAL_BUILD_SETTINGS", "NORMAL_BUILD_ARCHITECTURES", "NORMAL_BUILD_PLATFORMS", "DESTINATION_REJECTIONS"}
    if main:
        names.update(("main", "NativeQueryFailure", "ENGINEERING_MODES"))
    nodes, found = [], set()
    for node in ast.parse(RUNNER.read_bytes()).body:
        name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in names:
            nodes.append(node); found.add(name)
    assert found == names and len(nodes) == len(names)
    namespace = dict(hashlib=hashlib, json=json, re=re, Path=Path,
        subprocess=SimpleNamespace(CompletedProcess=subprocess.CompletedProcess))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNNER), "exec"), namespace)
    return namespace


def settings_body(settings=None, **extra):
    return json.dumps([{"target": "MRKNormalAppUITests", "buildSettings": {} if settings is None else settings,
                        **extra}]).encode()


class NormalBuildFailureDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = reducers()

    def observe(self, out=b"", err=b"", **kwargs):
        original = subprocess.CompletedProcess([], 70, out, err)
        observed = self.data["normal_failure_diagnostics"]("build", None, original, **kwargs)
        self.assertEqual(observed["originalReturncode"], 70)
        self.assertEqual(observed["stdoutSha256"], hashlib.sha256(out).hexdigest())
        self.assertEqual(observed["stderrSha256"], hashlib.sha256(err).hexdigest())
        self.assertLessEqual(len(self.data["encoded"](observed)) + 1, 4096)
        return observed

    def test_exact_categories_keep_original_and_never_export_names(self):
        first = b"xcodebuild: error: Unable to find a destination matching the provided destination specifier:"
        second = b"xcodebuild: error: Found no destinations for the scheme 'PRIVATE-SENTINEL' and action build."
        observed = self.observe(first + b"\n" + second + b"\r\n", first + b"\r\n" + second + b"\n")
        self.assertEqual(observed["buildFailureReasons"], [
            {"stream": stream, "code": code}
            for stream in ("stdout", "stderr")
            for code in ("destination-not-found", "no-eligible-destination")])
        self.assertEqual(observed["status"], "classified")
        self.assertNotIn(b"PRIVATE-SENTINEL", self.data["encoded"](observed))
        self.assertEqual(len(self.observe((first + b"\n") * 20)["buildFailureReasons"]), 1)

    def test_partial_unknown_oversized_and_injected_records_are_not_categories(self):
        first = b"xcodebuild: error: Unable to find a destination matching the provided destination specifier:"
        second = b"xcodebuild: error: Found no destinations for the scheme 'name' and action build."
        for raw in (first, second, b"prefix " + first + b"\n", first + b"suffix\n",
                    first.lower() + b"\n", first + b"\x00\n", b"unknown error\n",
                    second.replace(b"name", b"x" * 257) + b"\n",
                    second.replace(b"name", b"private\x01name") + b"\n",
                    second.replace(b"build", b"x" * 33) + b"\n",
                    second + b" " * 4096 + b"\n"):
            with self.subTest(length=len(raw)):
                observed = self.observe(err=raw)
                self.assertEqual(observed["buildFailureReasons"], [])
                self.assertEqual(observed["status"], "unclassified")

    def test_other_phases_and_fallback_do_not_gain_build_authority(self):
        original = subprocess.CompletedProcess([], 70, b"", b"xcodebuild: error: Unable to find a destination matching the provided destination specifier:\n")
        for phase, selection, engineering in (("query", None, False), ("build", None, True),
                                               ("test", "test.xcresult", False)):
            value = self.data["normal_failure_diagnostics"](phase, selection, original, engineering=engineering)
            self.assertNotIn("buildFailureReasons", value)
        fallback = self.data["failure_base"]("build", None, original)
        self.assertEqual(fallback["status"], "unavailable")
        self.assertEqual(fallback["buildFailureReasons"], [])

    def test_old_compiler_diagnostics_and_output_budget_remain(self):
        raw = b"xcodebuild: error: Unable to find a destination matching the provided destination specifier:\n"
        raw += b"NormalAppUITests.swift:17:9: error: cannot convert PRIVATE-SENTINEL\n"
        observed = self.observe(err=raw)
        self.assertEqual(observed["compilerDiagnostics"], [{"stream": "stderr", "source": "NormalAppUITests.swift",
            "line": 17, "column": 9, "severity": "error", "reasonCodes": ["type-mismatch"]}])
        self.assertNotIn(b"PRIVATE-SENTINEL", self.data["encoded"](observed))
        dense = raw
        for n in range(8):
            dense += ("Error Domain=NSCocoaErrorDomain Code=" + str(n) + "\n").encode()
        for n in range(4):
            dense += ("NormalAppUITests.swift:" + str(n + 18) + ":9: error: cannot convert private\n").encode()
        self.observe(dense, dense)

    def test_destination_sections_architectures_and_private_values(self):
        available = b'\tAvailable destinations for the "MRKNormalAppUI" scheme:\r\n'
        ineligible = b'  Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
        rows = (b' { platform:macOS, arch:x86_64, id:PRIVATE-SENTINEL, name:Private Mac }\r\n'
                b' { platform:macOS, arch:arm64, name:Private Mac }\n'
                b' { platform:macOS, name:Any Mac arch:arm64, error:PRIVATE-SENTINEL arch:x86_64 }\n')
        observed = self.observe(available + rows, ineligible + b' { platform:macOS, name:Any Mac }\n')
        self.assertEqual(observed["destinationTable"], {"state": "observed", "unknownRowObserved": False,
            "malformedRowObserved": False, "rowsTruncated": False, "rows": [
                {"stream": "stdout", "section": "available", "platform": "macos", "architecture": arch,
                 "errorPresent": error} for arch, error in (("x86_64", False), ("arm64", False), (None, True))] + [
                {"stream": "stderr", "section": "ineligible", "platform": "macos", "architecture": None,
                 "errorPresent": False}]})
        self.assertEqual(observed["status"], "unclassified")  # Table rows are not a cause or success predicate.
        for private in (b"PRIVATE-SENTINEL", b"Private Mac", b"Any Mac", b"MRKNormalAppUI"):
            self.assertNotIn(private, self.data["encoded"](observed))

    def test_destination_scope_boundaries_and_absence_are_not_empty_eligibility(self):
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        row = b'{ platform:macOS, name:Any Mac }\n'
        for prefix in (b"", header.replace(b"MRKNormalAppUI", b"OTHER"), b"prefix " + header,
                       b" " * 33 + header, header.rstrip(b"\n")):
            with self.subTest(prefix=prefix):
                value = self.observe(prefix + row)["destinationTable"]
                self.assertEqual(value["state"], "absent")
                self.assertEqual(value["rows"], [])
        self.assertEqual(self.observe(header)["destinationTable"]["state"], "observed")
        self.assertEqual(self.observe(header, row)["destinationTable"]["rows"], [])
        self.assertEqual(self.observe(header + b"not a row\n" + row)["destinationTable"]["rows"], [])
        self.assertEqual(len(self.observe(header + b" \t\n" + row)["destinationTable"]["rows"]), 1)
        original = subprocess.CompletedProcess([], 70, header + row, b"")
        for phase, selection, engineering in (("query", None, False), ("build", None, True),
                                               ("test", "test.xcresult", False)):
            value = self.data["normal_failure_diagnostics"](phase, selection, original, engineering=engineering)
            self.assertNotIn("destinationTable", value)
        self.assertEqual(self.data["failure_base"]("build", None, original)["destinationTable"], {
            "state": "unavailable", "unknownRowObserved": False, "malformedRowObserved": False,
            "rowsTruncated": False, "rows": []})

    def test_destination_malformed_and_unsupported_rows_remain_distinct(self):
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        good = b'{ platform:macOS, arch:x86_64, name:Any Mac }\n'
        malformed = (b'{ platform:macOS, platform:macOS, name:Any Mac }\n', b'{ platform:macOS }\n',
            b'{ platform:macOS; name:Any Mac }\n', b'{ platform:macOS, name:Any Mac, }\n',
            b'{ platform:macOS, name:Any\tMac }\n', b'{ platform:macOS, name:Any\x00Mac }\n',
            b'{ platform:macOS, name:Any\xffMac }\n', b'{ platform:macOS, name:{Any Mac} }\n',
            b'{ platform:macOS, name:' + b'x' * 1025 + b' }\n', b' ' * 33 + good,
            b'{ platform:macOS, name:Any Mac, id:x, arch:arm64, error:x, extra:x }\n')
        unknown = (b'{ platform:iOS, name:Any Mac }\n', b'{ platform:macOS, arch:i386, name:Any Mac }\n',
                   b'{ platform:macOS, name:Any Mac, OS:26.0 }\n',
                   b'{ platform:macOS, name:Any Mac, variant:unknown }\n')
        for flag, cases in (("malformedRowObserved", malformed), ("unknownRowObserved", unknown)):
            for raw in cases:
                with self.subTest(flag=flag, raw=raw):
                    table = self.observe(header + raw + good)["destinationTable"]
                    self.assertEqual(table["state"], "observed")
                    self.assertIs(table[flag], True)
                    self.assertIs(table["unknownRowObserved" if flag == "malformedRowObserved" else "malformedRowObserved"], False)
                    self.assertIs(table["rowsTruncated"], False)
                    self.assertEqual(len(table["rows"]), 1)  # Partial observations are retained, never padded.

    def test_destination_partial_oversized_and_ninth_rows_are_truncated_not_classified(self):
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        row = b'{ platform:macOS, name:Any Mac }\n'
        for raw in (row.rstrip(b"\n"), b'{ platform:macOS, name:' + b'x' * 4096 + b' }\n'):
            observed = self.observe(header + raw)
            self.assertEqual(observed["destinationTable"]["rows"], [])
            self.assertIs(observed["destinationTable"]["rowsTruncated"], True)
            self.assertIs(observed["destinationTable"]["malformedRowObserved"], False)
            self.assertIs(observed["findingsTruncated"], True)
        observed = self.observe(header + row * 9)
        self.assertEqual(len(observed["destinationTable"]["rows"]), 8)
        self.assertIs(observed["destinationTable"]["rowsTruncated"], True)
        self.assertIs(observed["findingsTruncated"], True)

    def test_destination_dense_output_retains_all_observations_within_budget(self):
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        row = b'{ platform:macOS, arch:x86_64, name:PRIVATE-SENTINEL, error:PRIVATE-SENTINEL }\n'
        reasons = (b'xcodebuild: error: Unable to find a destination matching the provided destination specifier:\n'
                   b'xcodebuild: error: Found no destinations for the scheme PRIVATE-SENTINEL and action build.\n')
        dense = reasons
        for n in range(8):
            dense += ('Error Domain=IDETestOperationsObserverErrorDomain Code=' + str(-2147483648 + n) + '\n').encode()
        for n in range(4):
            dense += ('NormalAppUITests.swift:' + str(65535 - n) + ':4096: error: ambiguous missing argument actor-isolated\n').encode()
            dense += b'MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=containingSameStaticText;matches=5;exceedsFour=1;nonAtomic=1\n'
        observed = self.observe(dense + header + row * 8, reasons)
        baseline = self.observe(dense + header.replace(b'Available', b'Xvailable') + row * 8, reasons)
        for key in ("errorCodes", "compilerDiagnostics", "buildFailureReasons", "queryObservations", "markers", "status"):
            self.assertEqual(observed[key], baseline[key], key)
        self.assertEqual(len(observed["compilerDiagnostics"]), 4)
        self.assertEqual(len(observed["errorCodes"]), 8)
        self.assertEqual(len(observed["queryObservations"]), 4)
        self.assertEqual(len(observed["buildFailureReasons"]), 4)
        self.assertIs(observed["findingsTruncated"], False)
        self.assertEqual(len(observed["destinationTable"]["rows"]), 8)
        self.assertNotIn(b'PRIVATE-SENTINEL', self.data["encoded"](observed))

    def test_admission_exact_owner_reasons_masks_and_unknowns_are_passive(self):
        data, owner = admission_reducers()
        encode, write = data["encoded"], data["normal_admission_failure"]
        self.assertEqual(len(data["ADMISSION_OWNER_REASONS"]), 10)
        for kind in (owner.ProcessError, owner.ProcessCleanupError, owner.ProcessOutcomeUnknown):
            for reason, label in data["ADMISSION_OWNER_REASONS"].items():
                error = kind(reason, 63)
                before = dict(error.__dict__)
                raw = write("execute", error, owner, [])
                value = data["classify_normal_admission_failure"](encode(raw))
                self.assertEqual(value["ownerDiagnostic"], {"reason": label, "failureMask": 63})
                self.assertEqual(value["exceptionClass"], "ProcessError")
                self.assertEqual(error.__dict__, before)
                self.assertEqual(BaseException.args.__get__(error), (reason,))
                self.assertIs(value["nativeSuccessInferred"], False)
        for mask in (32, *range(48, 64), None, True, False, -1, 0, 1, 31, 33, 47, 64, "63"):
            raw = write("execute", owner.ProcessError("owned command produced incomplete output", mask), owner, [])
            expected = mask if type(mask) is int and (mask == 32 or 48 <= mask <= 63) else None
            self.assertEqual(raw["ownerDiagnostic"], {"reason": "incomplete-output", "failureMask": expected})
        class PrivateString(str):
            def __hash__(self):
                raise AssertionError("custom-message-must-not-be-hashed")
        for args in ((), ("PRIVATE-SENTINEL",), ("x" * 129,), (PrivateString("private"),),
                     (object(),), ("owned command produced incomplete output", "PRIVATE-SENTINEL")):
            error = owner.ProcessError("unused")
            error.args = args
            del error.owner_failure_mask
            raw = write("execute", error, owner, [])
            self.assertEqual(raw["ownerDiagnostic"], {"reason": "unknown", "failureMask": None})
            self.assertNotIn(b"PRIVATE-SENTINEL", encode(raw))
        class OtherOwnerError(owner.ProcessError):
            @property
            def args(self):
                raise AssertionError("subclass-args-must-not-be-read")
        for error in (OtherOwnerError("owned command produced incomplete output", 63),
                      ValueError("PRIVATE-SENTINEL"), owner.ProcessInterrupted()):
            self.assertIsNone(write("execute", error, owner, [])["ownerDiagnostic"])
        self.assertIsNone(write("loader", ValueError("PRIVATE-SENTINEL"), None, [])["ownerDiagnostic"])

    def test_admission_tracebacks_retain_first_and_last_three_with_bounded_scan(self):
        data, owner = admission_reducers()
        files = [str(ROOT / name) for name in data["ADMISSION_SOURCE_FILES"]]
        def observe(locations):
            error = owner.ProcessError("owned command produced incomplete output", 48)
            following = None
            for filename, line in reversed(locations):
                namespace = {"following": following, "error": error}
                body = "    raise error\n" if following is None else "    return following()\n"
                exec(compile("\n" * (line - 2) + "def invoke():\n" + body, filename, "exec"), namespace)
                following = namespace["invoke"]
            try:
                following()
            except owner.ProcessError as caught:
                return data["normal_admission_failure"]("execute", caught, owner, [])
            self.fail("synthetic-exception-not-observed")
        locations = [(files[0], 10), (files[0], 20), (files[0], 30), (files[1], 40),
                     (files[2], 50), (files[3], 60)]
        raw = observe(locations)
        self.assertEqual(raw["sourceFrames"], [{"source": Path(path).name, "line": line}
            for path, line in [locations[0], *locations[-3:]]])
        self.assertIs(raw["sourceFramesTruncated"], True)
        for kept in (locations[:1], locations[:4]):
            raw = observe([*kept, ("/PRIVATE-SENTINEL/not-allowed.py", 70)])
            self.assertEqual(raw["sourceFrames"], [{"source": Path(path).name, "line": line} for path, line in kept])
            self.assertIs(raw["sourceFramesTruncated"], False)
            self.assertNotIn(b"PRIVATE-SENTINEL", data["encoded"](raw))
        raw = observe([(files[0], 100 + index) for index in range(70)] + [(files[3], 999999)])
        self.assertEqual(len(raw["sourceFrames"]), 4)
        self.assertEqual(raw["sourceFrames"][0], {"source": Path(files[0]).name, "line": 100})
        self.assertTrue(all(frame["line"] != 999999 for frame in raw["sourceFrames"]))
        self.assertIs(raw["sourceFramesTruncated"], True)  # Last observed is not claimed globally deepest.

    def test_admission_optional_fields_preserve_dense_old_facts_and_refuse_bad_data(self):
        data, owner = admission_reducers()
        encode, classify = data["encoded"], data["classify_normal_admission_failure"]
        command = {"role": max(data["ADMISSION_COMMAND_ROLES"], key=len), "returncode": 255,
            "timeoutSeconds": 720, "roleCapSeconds": 720, "outputLimitBytes": 1048576,
            "argvSha256": "1" * 64, "stdoutBytes": 1048576, "stdoutSha256": "2" * 64,
            "stderrBytes": 0, "stderrSha256": "3" * 64}
        raw = data["normal_admission_failure"]("publication",
            owner.ProcessError("owned command failed, timed out, or produced incomplete output", 63),
            owner, [dict(command) for _ in range(16)])
        source = max((Path(path).name for path in data["ADMISSION_SOURCE_FILES"]), key=len)
        raw["sourceFrames"] = [{"source": source, "line": 1000000} for _ in range(4)]
        raw["sourceFramesTruncated"] = True
        raw["ownerFailure"] = dict(dispatched=False, contained=False, cleanupComplete=False)
        for with_post in (False, True):
            dense = json.loads(encode(raw))
            if with_post:
                dense.update(stage="execute", exceptionClass="Refused", ownerDiagnostic=None,
                    resultPost={"schemaVersion": 1, "query": "summary", "originalReturncode": 0,
                        "heldVsPre": [True] * 9, "namedVsPre": [True] * 9, "heldVsNamed": [False] * 9})
                dense["commands"][-1].update(role="normal-ui-summary", returncode=0)
            old = {key: value for key, value in dense.items() if key not in ("ownerDiagnostic", "sourceFramesTruncated")}
            baseline, observed = classify(encode(old)), classify(encode(dense))
            self.assertEqual(baseline["status"], "observed-exception-only")
            self.assertEqual(observed["status"], "observed-exception-only")
            self.assertEqual({key: value for key, value in observed.items()
                              if key not in ("ownerDiagnostic", "sourceFramesTruncated")}, baseline)
            self.assertLessEqual(len(encode(observed)) + 1, 4096)  # Actual encoder, no fabricated byte pressure.
            self.assertEqual(len(observed["commands"]), 16)
            self.assertEqual(len(observed["sourceFrames"]), 4)
            self.assertIs(observed["nativeSuccessInferred"], False)
        good = {"reason": "incomplete-output", "failureMask": 63}
        for bad in ({}, True, [], {**good, "message": "PRIVATE-SENTINEL"}, {**good, "reason": "PRIVATE-SENTINEL"},
                    *({**good, "failureMask": mask} for mask in (True, 0, 31, 33, 47, 64, "63"))):
            broken = {**raw, "ownerDiagnostic": bad}
            self.assertEqual(classify(encode(broken))["status"], "unavailable")
        for broken in ({**raw, "sourceFramesTruncated": 1}, {**raw, "sourceFramesTruncated": None},
                       {**raw, "exceptionClass": "Refused"}, {**raw, "extra": "PRIVATE-SENTINEL"}):
            self.assertEqual(classify(encode(broken))["status"], "unavailable")

    def test_current_dependency_preparation_pins_actual_runner(self):
        body = RUNNER.read_bytes()
        tree = ast.parse((ROOT / "desktop/tools/macos_android_dependency_preparation.py").read_bytes())
        assignments = {node.targets[0].id: node.value for node in tree.body
                       if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name)}
        expected = [len(body), hashlib.sha256(body).hexdigest()]
        self.assertEqual(ast.literal_eval(assignments["PINS"])["desktop/tools/macos_normal_ui_runner.py"], expected)
        self.assertEqual(ast.literal_eval(assignments["UI_NORMAL_PIN"]), expected)


    def test_build_settings_selected_values_are_closed_and_private(self):
        data = build_settings_reducers(); parse = data["normal_build_settings_data"]
        raw = {"ARCHS": "arm64 arm64e x86_64 x86_64h i386", "VALID_ARCHS": "x86_64", "EXCLUDED_ARCHS": "",
            "NATIVE_ARCH_ACTUAL": "x86_64h", "NATIVE_ARCH_64_BIT": "x86_64", "SUPPORTED_PLATFORMS": "macosx",
            "ONLY_ACTIVE_ARCH": "NO", "MACOSX_DEPLOYMENT_TARGET": "26.0", "SDK_VERSION": "26.1.2",
            "PRIVATE_SENTINEL": "/private/setting/value"}
        result = parse(settings_body(raw, private="PRIVATE_SENTINEL"))
        self.assertEqual(tuple(result), data["NORMAL_BUILD_SETTINGS"])
        self.assertEqual(result["ARCHS"], {"state": "observed", "value": raw["ARCHS"].split()})
        self.assertEqual(result["EXCLUDED_ARCHS"], {"state": "observed", "value": []})
        self.assertEqual(result["ONLY_ACTIVE_ARCH"], {"state": "observed", "value": False})
        for name in ("NATIVE_ARCH_ACTUAL", "NATIVE_ARCH_64_BIT", "MACOSX_DEPLOYMENT_TARGET", "SDK_VERSION"):
            self.assertEqual(result[name], {"state": "observed", "value": raw[name]})
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))
        self.assertTrue(all(row == {"state": "absent", "value": None} for row in parse(settings_body()).values()))
        for name, values in (("ARCHS", ("x86_64 PRIVATE_SENTINEL", "x86_64 x86_64", "x86_64\tarm64", True)),
                ("SUPPORTED_PLATFORMS", ("macosx PRIVATE_SENTINEL", "macosx macosx")),
                ("NATIVE_ARCH_ACTUAL", ("", "i386", "PRIVATE_SENTINEL", 64)),
                ("ONLY_ACTIVE_ARCH", ("", "yes", True, "PRIVATE_SENTINEL")),
                ("SDK_VERSION", ("26.1.2.3", "1000", "26/PRIVATE_SENTINEL", None))):
            for value in values:
                with self.subTest(setting=name, value=value):
                    self.assertEqual(parse(settings_body({name: value}))[name], {"state": "unsupported", "value": None})
        self.assertEqual(parse(settings_body({"ONLY_ACTIVE_ARCH": "YES"}))["ONLY_ACTIVE_ARCH"]["value"], True)

    def test_build_settings_json_bounds_and_target_selection(self):
        data = build_settings_reducers(); parse = data["normal_build_settings_data"]
        valid = settings_body({"ARCHS": "x86_64"})
        self.assertEqual(parse(valid + b" " * (262144 - len(valid)))["ARCHS"]["value"], ["x86_64"])
        for body in (b"", valid + b" " * (262145 - len(valid)), b"\xff", valid[:-1],
                b'[{"target":"MRKNormalAppUITests","target":"MRKNormalAppUITests","buildSettings":{}}]',
                settings_body(extra=1.5), settings_body(extra=float("nan")), settings_body(extra=2147483648),
                settings_body(extra=-2147483649), settings_body(extra="x" * 16385),
                settings_body(extra=[0] * 2049), settings_body(extra={str(n): 0 for n in range(2049)}),
                settings_body(extra=[[0] * 2048 for _ in range(6)]),
                b"[" * 9 + b"0" + b"]" * 9, b"[]", b"{}",
                json.dumps([{"target": "other", "buildSettings": {}}]).encode(),
                json.dumps([{"target": "MRKNormalAppUITests", "buildSettings": {}}] * 2).encode(),
                json.dumps([{"target": "other", "buildSettings": {}}] * 9).encode(),
                settings_body().decode()):
            with self.subTest(kind=type(body).__name__, size=len(body)), self.assertRaises((data["Refused"], ValueError)):
                parse(body)
        rows = [{"target": "other", "buildSettings": {"ARCHS": "arm64"}},
                {"target": "MRKNormalAppUITests", "buildSettings": {"ARCHS": "x86_64"}}]
        self.assertEqual(parse(json.dumps(rows).encode())["ARCHS"]["value"], ["x86_64"])
        # Braces/escapes within a private JSON string do not change lexical depth.
        self.assertEqual(parse(settings_body(private='[{}]"\\'))["ARCHS"]["state"], "absent")

    def test_build_settings_same_phase_arguments_and_original_capture(self):
        data = build_settings_reducers(); now = [0]; calls = []; writes = []
        environment = {"PRIVATE_SENTINEL": "not exported"}; root = Path("/inert/repo")
        request = {"phase": "build", "target": data["INTEL_TARGET"], "derived": Path("/inert/normal-ui/DerivedData")}
        body = settings_body({"ARCHS": "x86_64"})
        def run(argv, **kwargs):
            calls.append((argv, kwargs)); now[0] += 1_000_000_000
            return subprocess.CompletedProcess(argv, 0, body, b"PRIVATE_SENTINEL")
        owner = SimpleNamespace(run_owned=run)
        clock = data["PhaseClock"](450, now=lambda: now[0])
        phase = data["NormalPhase"](owner, environment, root, clock)
        data["exclusive_output"] = lambda *args: writes.append(args)
        original = subprocess.CompletedProcess([], 70, b"failed-build-out", b"failed-build-err")
        observed = data["publish_normal_build_settings"](phase, request, "1" * 40, original, "26.0.1")
        expected = ["/usr/bin/xcodebuild", "-showBuildSettings", "-json", "-project", data["PROJECT"],
            "-scheme", "MRKNormalAppUI", "-configuration", "Debug", "-derivedDataPath", str(request["derived"]),
            "-jobs", "2", "-disableAutomaticPackageResolution", "ARCHS=x86_64", "COMPILER_INDEX_STORE_ENABLE=NO", "build-for-testing"]
        self.assertEqual(calls[0][0], expected); self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][1]["environ"], environment); self.assertIs(calls[0][1]["cwd"], root)
        self.assertEqual(calls[0][1], dict(environ=environment, cwd=root, timeout=15, capture=True, text=False, output_limit=262144))
        self.assertIs(phase.owner, owner); self.assertIs(phase.clock, clock); self.assertEqual(clock.deadline, 450_000_000_000)
        self.assertFalse(clock.finalized); self.assertFalse(clock.failed)
        self.assertEqual(phase.records[0]["role"], "normal-build-settings")
        self.assertEqual(observed["stdoutSha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(observed["originalBuildStderrSha256"], hashlib.sha256(original.stderr).hexdigest())
        self.assertEqual(observed["settingsState"], "observed"); self.assertEqual(observed["hostVersion"], "26.0.1")
        self.assertEqual(writes[0][0], request["derived"].parent / "build.settings-diagnostics.json")
        self.assertEqual(writes[0][2], 4096); self.assertEqual(json.loads(writes[0][1]), observed)
        self.assertNotIn(b"PRIVATE_SENTINEL", writes[0][1]); self.assertLessEqual(len(writes[0][1]), 4096)
        build = data["normal_build_arguments"](request["derived"], target=data["INTEL_TARGET"])
        self.assertIn("build-for-testing", build); self.assertIn("platform=macOS,arch=x86_64", build)
        self.assertIn("-destination-timeout", build); self.assertNotIn("-showBuildSettings", build)
        self.assertNotIn("-destination", expected)

    def test_build_settings_unknown_nonzero_malformed_and_publication_failures(self):
        for outcome in ("nonzero", "malformed", "owner-error", "bad-original", "expired", "write-error"):
            with self.subTest(outcome=outcome):
                data = build_settings_reducers(); now = [0]; calls = []; writes = []
                clock = data["PhaseClock"](450, now=lambda: now[0])
                def run(argv, **kwargs):
                    calls.append(argv)
                    if outcome == "owner-error": raise RuntimeError("PRIVATE_SENTINEL")
                    if outcome == "bad-original": return None
                    return subprocess.CompletedProcess(argv, 9 if outcome == "nonzero" else 0,
                        b"" if outcome == "malformed" else settings_body(), b"")
                phase = data["NormalPhase"](SimpleNamespace(run_owned=run), {}, Path("/inert"), clock)
                def write(*args):
                    writes.append(args)
                    if outcome == "write-error": raise OSError("PRIVATE_SENTINEL")
                data["exclusive_output"] = write
                if outcome == "expired": now[0] = clock.deadline
                request = dict(phase="build", target=data["INTEL_TARGET"], derived=Path("/inert/normal-ui/DerivedData"))
                original = subprocess.CompletedProcess([], 70, b"a", b"b")
                if outcome in ("owner-error", "bad-original", "expired"):
                    with self.assertRaises((RuntimeError, data["Refused"])):
                        data["publish_normal_build_settings"](phase, request, "1" * 40, original, "PRIVATE_SENTINEL")
                    value = json.loads(writes[0][1]); self.assertTrue(clock.failed)
                    self.assertEqual(value["queryState"], "not-returned")
                    self.assertTrue(all(value[k] is None for k in ("queryReturncode", "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256")))
                else:
                    value = data["publish_normal_build_settings"](phase, request, "1" * 40, original, "PRIVATE_SENTINEL")
                    self.assertEqual(value["settingsState"], {"nonzero": "nonzero", "malformed": "malformed", "write-error": "observed"}[outcome])
                self.assertIsNone(value["hostVersion"]); self.assertEqual(original.returncode, 70)
                self.assertEqual(len(calls), 0 if outcome == "expired" else 1)
                self.assertIs(value["nativeSuccessInferred"], False); self.assertEqual(value["phaseFinality"], "not-asserted")

    def _settings_main(self, scenario, *, target="x86_64-apple-darwin", code=70, phase_name="build", engineering=False):
        data = build_settings_reducers(main=True); events = []; captures = []; phases = []; clock_value = [0]
        request = dict(phase=phase_name, phaseSeconds=450, target=target, derived=Path("/inert/normal-ui/DerivedData"))
        original = subprocess.CompletedProcess(["build"], code, b"original-out", b"original-err")
        class Stream:
            def __init__(self, name): self.name = name; self.buffer = self
            def write(self, body):
                events.append(self.name + "-write")
                if scenario == "stream-error": raise OSError("PRIVATE_SENTINEL")
            def flush(self): events.append(self.name + "-flush")
        data["sys"] = SimpleNamespace(argv=["runner", "--engineering-main-build" if engineering else "--normal-build"],
            stdout=Stream("stdout"), stderr=Stream("stderr"))
        data["os"] = SimpleNamespace(environ={}); data["time"] = SimpleNamespace(monotonic_ns=lambda: clock_value[0])
        data["normal_request"] = data["engineering_request"] = lambda *_: request
        def context(req, **kwargs):
            events.append("context"); self.assertIs(req, request)
            self.assertEqual(set(kwargs), {"diagnostics"} if target == data["INTEL_TARGET"] and phase_name == "build" and not engineering else set())
            if kwargs: kwargs["diagnostics"]["hostVersion"] = "26.0"
            return Path("/inert/repo"), "1" * 40, {"inert": "environment"}, 123
        data["normal_context"] = data["engineering_context"] = context
        def run(argv, **kwargs):
            events.append("settings-query")
            self.assertEqual(events[-6:-1], ["build-diagnostic", "stdout-write", "stderr-write", "stdout-flush", "stderr-flush"])
            self.assertEqual(kwargs["timeout"], 15); self.assertEqual(kwargs["output_limit"], 262144)
            if scenario == "query-error": raise RuntimeError("PRIVATE_SENTINEL")
            return subprocess.CompletedProcess(argv, 9 if scenario == "query-nonzero" else 0,
                b"" if scenario == "parse-error" else settings_body(), b"")
        owner = SimpleNamespace(run_owned=run); data["load_normal_owner"] = lambda root: owner
        def execute(phase, req, source, file_limit):
            phases.append(phase); events.append("execute")
            if scenario == "toolchain-error": raise data["NativeQueryFailure"](original)
            if scenario == "execute-error": raise RuntimeError("PRIVATE_SENTINEL")
            if scenario == "expired": clock_value[0] = phase.clock.deadline
            return original
        data["execute_normal_phase"] = data["execute_engineering_phase"] = execute
        def diagnostic(*args, **kwargs):
            events.append("build-diagnostic")
            if scenario == "diagnostic-error": raise OSError("PRIVATE_SENTINEL")
        data["publish_failure_diagnostics"] = data["publish_engineering_failure"] = diagnostic
        data["engineering_native_failure"] = lambda *args, **kwargs: {}
        data["normal_admission_failure"] = lambda *args, **kwargs: {"stage": args[0]}
        def publish(path, body, limit):
            captures.append(json.loads(body)); events.append("settings-publication")
            if scenario == "write-error": raise OSError("PRIVATE_SENTINEL")
            if scenario == "finish-error": clock_value[0] = phases[0].clock.deadline
        data["exclusive_output"] = publish
        result = data["main"]()
        return result, events, captures, phases, original

    def test_build_settings_main_preserves_build70_and_publication_order(self):
        for scenario in ("ok", "query-nonzero", "query-error", "parse-error", "write-error", "finish-error",
                         "expired", "diagnostic-error", "stream-error"):
            with self.subTest(scenario=scenario):
                result, events, captures, phases, original = self._settings_main(scenario)
                self.assertEqual(result, 70); self.assertEqual(original.returncode, 70)
                self.assertEqual(events.count("execute"), 1)
                queried = scenario not in ("expired", "diagnostic-error", "stream-error")
                self.assertEqual(events.count("settings-query"), int(queried))
                if scenario not in ("diagnostic-error", "stream-error"):
                    self.assertEqual(len(captures), 1)
                    self.assertEqual(captures[0]["originalBuildStdoutSha256"], hashlib.sha256(original.stdout).hexdigest())
                    self.assertEqual(captures[0]["originalBuildStderrSha256"], hashlib.sha256(original.stderr).hexdigest())
                if scenario in ("query-error", "finish-error", "expired", "diagnostic-error", "stream-error"):
                    self.assertTrue(phases[0].clock.failed)

    def test_build_settings_main_never_queries_other_routes(self):
        for scenario, kwargs, expected in (("ok", {"target": "aarch64-apple-darwin"}, 70),
                ("ok", {"code": 0}, 0), ("ok", {"phase_name": "test"}, 70),
                ("ok", {"engineering": True}, 70), ("toolchain-error", {}, 70), ("execute-error", {}, 1)):
            with self.subTest(scenario=scenario, kwargs=kwargs):
                result, events, captures, _, _ = self._settings_main(scenario, **kwargs)
                self.assertEqual(result, expected); self.assertNotIn("settings-query", events); self.assertEqual(captures, [])

    def test_build_settings_context_reuses_single_admitted_host_observation(self):
        tree = ast.parse(RUNNER.read_bytes())
        context = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "normal_context")
        calls = [node for node in ast.walk(context) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                 and node.func.value.id == "platform" and node.func.attr == "mac_ver"]
        self.assertEqual(len(calls), 1)
        assignments = [node for node in ast.walk(context) if isinstance(node, ast.NamedExpr)
                       and isinstance(node.target, ast.Name) and node.target.id == "host_version"]
        self.assertEqual(len(assignments), 1)
        self.assertIn(calls[0], list(ast.walk(assignments[0])))
        self.assertEqual(context.args.kwonlyargs[0].arg, "diagnostics")
        self.assertEqual(ast.literal_eval(context.args.kw_defaults[0]), None)
        source = ast.get_source_segment(RUNNER.read_text(), context)
        self.assertIn('if diagnostics is not None:\n        diagnostics["hostVersion"] = host_version', source)
        self.assertLess(source.index('"normal-clean-environment"'), source.index('diagnostics["hostVersion"] = host_version'))

    def test_destination_rejection_details_cover_each_branch_and_cap(self):
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        rows = (("non-ascii-or-control", b'{ platform:macOS, name:private\x01name }\n'),
            ("row-envelope", b'{ platform:macOS, name:private\n'),
            ("field-count", b'{ platform:macOS, name:a, id:b, arch:arm64, error:c, extra:d }\n'),
            ("field-format", b'{ platform:macOS, name:a, broken }\n'),
            ("duplicate-key", b'{ platform:macOS, name:a, name:b }\n'),
            ("missing-required-field", b'{ platform:macOS }\n'))
        for reason, raw in rows:
            value = self.observe(header + raw + raw)["destinationTable"]
            self.assertEqual(value["rejections"], [{"stream": "stdout", "section": "available", "reason": reason}])
            self.assertFalse(value["rejectionDetailsTruncated"])
        value = self.observe(header + b"".join(row for _, row in rows), header + b"".join(row for _, row in rows))
        self.assertEqual(len(value["destinationTable"]["rejections"]), 8)
        self.assertTrue(value["destinationTable"]["rejectionDetailsTruncated"])
        self.assertEqual(value["destinationTable"]["rows"], [])
        self.assertNotIn(b"private", self.data["encoded"](value))


    def test_destination_opaque_printable_utf8_preserves_only_finite_fields(self):
        opaque = "OPAQUE_PRIVATE_名_“diagnostic”"
        row = ("{ platform:macOS, arch:x86_64, id:" + opaque + ", name:" + opaque + ", error:" + opaque + " }\n").encode()
        for section in ("available", "ineligible"):
            header = (section.title() + ' destinations for the "MRKNormalAppUI" scheme:\n').encode()
            for stream in ("stdout", "stderr"):
                with self.subTest(section=section, stream=stream):
                    raw = header + row
                    value = self.observe(raw if stream == "stdout" else b"", raw if stream == "stderr" else b"")
                    table = value["destinationTable"]
                    self.assertEqual(table["rows"], [{"stream": stream, "section": section,
                        "platform": "macos", "architecture": "x86_64", "errorPresent": True}])
                    self.assertFalse(table["malformedRowObserved"]); self.assertFalse(table["unknownRowObserved"])
                    self.assertNotIn("rejections", table)
                    self.assertNotIn("OPAQUE_PRIVATE", json.dumps(value))
        header = b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
        invalid = (b"\xff", b"bad\x00value", b"bad\x7fvalue", "bad\u0085value".encode(),
            "bad\u202evalue".encode(), "bad\u200bvalue".encode(), "bad\u2028value".encode(),
            "bad\u00a0value".encode(), b"comma,value", b"brace{value}", "名".encode() * 342)
        for value in invalid:
            table = self.observe(header + b"{ platform:macOS, name:" + value + b" }\n")["destinationTable"]
            self.assertTrue(table["malformedRowObserved"]); self.assertEqual(table["rows"], [])
        for row in ("{ platform:macOS, 名:value, name:a }\n", "{ platform:macOS名, name:a }\n",
                    "{ platform:macOS, arch:x86_64名, name:a }\n", "{ platform:macOS, name:名, name:名 }\n"):
            table = self.observe(header + row.encode())["destinationTable"]
            self.assertTrue(table["malformedRowObserved"]); self.assertEqual(table["rows"], [])
        good = ("{ platform:macOS, name:" + opaque + " }\n").encode()
        for raw in (good.rstrip(b"\n"), b"{ platform:macOS, name:" + "名".encode() * 1400 + b" }\n"):
            value = self.observe(header + raw)
            self.assertTrue(value["destinationTable"]["rowsTruncated"])
            self.assertTrue(value["findingsTruncated"]); self.assertEqual(value["destinationTable"]["rows"], [])


if __name__ == "__main__":
    unittest.main()
