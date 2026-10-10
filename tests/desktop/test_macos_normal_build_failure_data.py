"""Finite Xcode failure categories; no native runner import or process calls."""
import ast
import hashlib
import json
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

    def test_current_dependency_preparation_pins_actual_runner(self):
        body = RUNNER.read_bytes()
        tree = ast.parse((ROOT / "desktop/tools/macos_android_dependency_preparation.py").read_bytes())
        assignments = {node.targets[0].id: node.value for node in tree.body
                       if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name)}
        expected = [len(body), hashlib.sha256(body).hexdigest()]
        self.assertEqual(ast.literal_eval(assignments["PINS"])["desktop/tools/macos_normal_ui_runner.py"], expected)
        self.assertEqual(ast.literal_eval(assignments["UI_NORMAL_PIN"]), expected)


if __name__ == "__main__":
    unittest.main()
