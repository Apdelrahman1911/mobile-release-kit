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
