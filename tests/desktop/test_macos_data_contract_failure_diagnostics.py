"""Finite DATA from genuine inline reducers; never run the native owner/child."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "desktop/tools/macos_installed_data_contracts.sh"
SENTINEL = "PRIVATE_SENTINEL_/outside/file_token_and_traceback"


def reducers():
    shell = SCRIPT.read_text()
    source = shell.split("<<'PY_DATA_CONTRACTS'\n", 1)[1].rsplit("\nPY_DATA_CONTRACTS", 1)[0]
    tree = ast.parse(source)
    wanted = {"DATA_FAILURE_GUARDS", "data_failure_guard", "data_failure_json", "data_failure_python",
              "data_failure_cargo", "data_failure_rust_panic", "data_failure_document"}
    nodes, found = [], set()
    for node in tree.body:
        name = node.name if isinstance(node, ast.FunctionDef) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in wanted:
            nodes.append(node); found.add(name)
    if found != wanted:
        raise AssertionError("exact inline failure DATA closure required")
    assignments = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    names = ast.literal_eval(assignments["names"])
    child = ast.literal_eval(assignments["child_code"].right)
    functions = [node for node in ast.parse(child).body if isinstance(node, ast.FunctionDef) and node.name == "data_failed_test_rows"]
    if len(functions) != 1:
        raise AssertionError("genuine child failure-ID reducer required")
    namespace = {"json": json, "hashlib": hashlib, "re": re}
    exec(compile(ast.Module(body=nodes + functions, type_ignores=[]), str(SCRIPT), "exec"), namespace)
    return namespace, names, source, child


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def failure_entry(name):
    return (SimpleNamespace(id=lambda: name), SENTINEL)


def facts(data, names, failures=(), errors=()):
    return dict(testsRun=84, failures=len(failures), errors=len(errors), skipped=0,
        expectedFailures=0, unexpectedSuccesses=0, testIds=names, actualHostBeforeAndAfter=True,
        **data["data_failed_test_rows"](failures, errors, names))


def cargo_message(code="E0123", filename="src/bin/macos_install.rs", *, manifest=True):
    row = {"reason": "compiler-message", "message": {"level": "error", "message": SENTINEL,
        "rendered": SENTINEL, "code": {"code": code, "explanation": SENTINEL}, "spans": [
            {"is_primary": True, "file_name": filename, "line_start": 12, "column_start": 7, "text": [SENTINEL]}]}}
    if manifest:
        row["manifest_path"] = "/public/checkout/desktop/src-tauri/Cargo.toml"
    return row


class MacDataContractFailureDiagnostics(unittest.TestCase):
    def test_actual_child_ids_keep_exact_roster_and_unknown_entries_separate(self):
        data, names, _, _ = reducers()
        self.assertEqual(len(names), 84)
        self.assertEqual(hashlib.sha256(encoded(names)).hexdigest(), "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94")
        failed = [failure_entry(names[1]), failure_entry(names[1]), failure_entry(names[0] + " (private=" + SENTINEL + ")")]
        errors = [failure_entry(names[0]), failure_entry(SENTINEL)]
        value = facts(data, names, failed, errors)
        self.assertEqual(value["failureTests"], [{"kind": "error", "id": names[0]}, {"kind": "failure", "id": names[1]}])
        self.assertEqual((value["classifiedTestCount"], value["omittedTestCount"], value["unclassifiedTestCount"]), (2, 0, 2))
        result = data["data_failure_python"](encoded(value), names)
        self.assertEqual((result["failures"], result["errors"]), (3, 2))
        self.assertNotIn(SENTINEL, json.dumps(result))

    def test_combined_sixteen_rows_have_distinct_omission_not_raw_entry_counts(self):
        data, names, _, _ = reducers()
        value = facts(data, names, [failure_entry(name) for name in names], [failure_entry(name) for name in names])
        self.assertEqual((len(value["failureTests"]), value["classifiedTestCount"], value["omittedTestCount"]), (16, 168, 152))
        result = data["data_failure_python"](encoded(value), names)
        self.assertIsNotNone(result)
        self.assertEqual(result["failureTests"][-1], {"kind": "error", "id": names[7]})

    def test_python_typed_closed_schema_never_accepts_prose_or_partial_facts(self):
        data, names, _, _ = reducers()
        base = facts(data, names, [failure_entry(names[0])])
        mutations = {"testsRun": True, "failures": -1, "errors": 65536, "skipped": None,
            "actualHostBeforeAndAfter": 1, "testIds": names[:-1], "classifiedTestCount": True,
            "omittedTestCount": 1, "unclassifiedTestCount": 1, "failureTests": [{"kind": "failure", "id": SENTINEL}]}
        for key, value in mutations.items():
            broken = dict(base, **{key: value})
            with self.subTest(key=key):
                self.assertIsNone(data["data_failure_python"](encoded(broken), names))
        for body in (encoded({**base, "traceback": SENTINEL}), encoded(base)[:-1], b'{"x":1,"x":2}', b'[]', SENTINEL.encode()):
            self.assertIsNone(data["data_failure_python"](body, names))
        self.assertIsNone(data["data_failure_python"](encoded({**base, "failureTests": base["failureTests"] * 2}), names))

    def test_json_preflight_bounds_depth_nodes_bytes_and_ignores_quoted_structure(self):
        data, _, _, _ = reducers(); parse = data["data_failure_json"]
        self.assertEqual(parse(encoded({"escaped": '\\"[{},:]' * 100})), {"escaped": '\\"[{},:]' * 100})
        expected = 0
        for _ in range(32): expected = [expected]
        self.assertEqual(parse(b"[" * 32 + b"0" + b"]" * 32), expected)
        for body in (b"[" * 33 + b"0" + b"]" * 33, b"[" + b"0," * 8192 + b"0]", b" " * 65537,
                     b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":1e9999}', b'"unterminated', b"{]", b"\xff"):
            with self.subTest(size=len(body)), self.assertRaises((ValueError, UnicodeError)):
                parse(body)

    def test_cargo_codes_use_actual_manifest_not_process_cwd_for_relative_sources(self):
        data, _, _, _ = reducers(); parse = data["data_failure_cargo"]
        paths = {"desktop/src-tauri/src/bin/macos_install.rs": {}}
        value = cargo_message()
        result = parse(encoded(value), paths, "/public/checkout")
        self.assertEqual(result, {"errors": [{"code": "E0123", "source": next(iter(paths)), "line": 12, "column": 7}],
                                  "unclassifiedErrors": 0, "omittedErrors": 0})
        for filename in (next(iter(paths)), "/public/checkout/" + next(iter(paths))):
            value = cargo_message(filename=filename, manifest=False)
            self.assertEqual(parse(encoded(value), paths, "/public/checkout")["errors"][0]["source"], next(iter(paths)))
        for value in (cargo_message(manifest=False), {**cargo_message(), "manifest_path": SENTINEL}, cargo_message(filename=SENTINEL)):
            row = parse(encoded(value), paths, "/public/checkout")["errors"][0]
            self.assertEqual(row, dict(code="E0123", source=None, line=None, column=None))
            self.assertNotIn(SENTINEL, json.dumps(row))
        value = cargo_message(); value["message"]["spans"][0]["line_start"] = True
        self.assertIsNone(parse(encoded(value), paths, "/public/checkout")["errors"][0]["source"])

    def test_cargo_finite_errors_omission_and_unknowns_are_not_rendered_messages(self):
        data, _, _, _ = reducers(); parse = data["data_failure_cargo"]
        rows = [cargo_message(code="E%04d" % index) for index in range(10)]
        rows += [rows[0], cargo_message(code=SENTINEL)]
        warning = cargo_message(); warning["message"]["level"] = "warning"; rows.append(warning)
        result = parse(b"\n".join(encoded(row) for row in rows), {}, "/public/checkout")
        self.assertEqual((len(result["errors"]), result["omittedErrors"], result["unclassifiedErrors"]), (8, 2, 1))
        self.assertNotIn(SENTINEL, json.dumps(result))
        for body in (b'{"a":1,"a":2}', b"[" * 33 + b"0" + b"]" * 33, b"{}\n" * 4097,
                     b" " * 65537, encoded(rows[0]) + b"\ntruncated", b"[]", b"x" * (4 * 1024 * 1024 + 1)):
            self.assertIsNone(parse(body, {}, "/public/checkout"))

    def test_rust_panic_location_uses_only_closed_inventory_site(self):
        data, _, _, _ = reducers(); parse = data["data_failure_rust_panic"]
        site = "desktop/src-tauri/src/shell/installed_observation.rs"
        observer = "desktop/src-tauri/tests/installed_shell_observation.rs"
        paths = {site: {}, observer: {}}
        def capture(path=site, coordinates="12:7", thread="'main' (123)"):
            return ("\nthread " + thread + " panicked at " + path + ":" + coordinates + ":\n" + SENTINEL + "\n").encode()
        expected = {"source": site, "line": 12, "column": 7}
        for path in (site, "/public/checkout/" + site, "tests/../src/shell/installed_observation.rs",
                     "desktop/src-tauri/tests/../src/shell/installed_observation.rs",
                     "/public/checkout/desktop/src-tauri/tests/../src/shell/installed_observation.rs"):
            for thread in ("'main'", "'main' (123)", "'<unnamed>' (1)"):
                with self.subTest(path=path, thread=thread):
                    self.assertEqual(parse(capture(path, thread=thread), paths, "/public/checkout"), expected)
        self.assertEqual(parse(capture("tests/installed_shell_observation.rs"), paths, "/public/checkout"),
                         {"source": observer, "line": 12, "column": 7})
        self.assertEqual(parse(capture(coordinates="1000000:1000000"), paths, "/public/checkout"),
                         {"source": site, "line": 1000000, "column": 1000000})
        self.assertNotIn(SENTINEL, json.dumps(parse(capture(), paths, "/public/checkout")))
        self.assertIsNone(parse(capture(), {}, "/public/checkout"))
        for path in ("/foreign/" + site, "src/shell/installed_observation.rs", "tests/../src/../shell.rs",
                     "desktop/src-tauri/src/./shell.rs", "desktop/src-tauri/src//shell.rs",
                     site + "/../other.rs", "desktop/src-tauri/src/file name.rs", site + "\x1b", site + "é",
                     "desktop/src-tauri/tests/../../src/shell.rs", "tests/../src/.hidden/../shell.rs"):
            with self.subTest(path=path):
                self.assertIsNone(parse(capture(path), paths, "/public/checkout"))
        for coordinates in ("0:1", "1:0", "1000001:1", "1:1000001", "True:7", "-1:7", "1:7:8"):
            self.assertIsNone(parse(capture(coordinates=coordinates), paths, "/public/checkout"))
        header = capture().split(b"\n")[1]
        for raw in (b"", b"\xff", header[:-1], header + b" inline payload", capture() + header + b"\n",
                    capture(thread="'" + "x" * 129 + "'"), capture(thread="'ma\tin'"), b"x" * 1025,
                    b"unrelated first line\n" + header, header.replace(b"thread", b"\xffthread", 1)):
            self.assertIsNone(parse(raw, paths, "/public/checkout"))
        exact = header + b"\n" + b"x" * (65536 - len(header) - 1)
        self.assertEqual(parse(exact, paths, "/public/checkout"), expected)
        self.assertIsNone(parse(exact + b"x", paths, "/public/checkout"))
        lines = header + b"\n" + b"x\n" * 254
        self.assertEqual(len(lines.split(b"\n")), 256)
        self.assertEqual(parse(lines, paths, "/public/checkout"), expected)
        self.assertIsNone(parse(lines + b"x\n", paths, "/public/checkout"))
        # Payload bytes are not decoded or copied, even if they are not UTF-8.
        self.assertEqual(parse(header + b"\n\xff", paths, "/public/checkout"), expected)

    def test_guard_mapping_uses_only_current_exact_builtin_errors(self):
        data, _, source, _ = reducers()
        guard = data["data_failure_guard"]
        for phase in ("mount", "apfs", "build", "rust", "python"):
            self.assertEqual(guard(ValueError("original fixed command did not completely pass: " + phase)), "command-not-complete")
        self.assertEqual(guard(ValueError("exact native Python original counts required")), "python-counts")
        for error in (RuntimeError("exact native Python original counts required"), ValueError(SENTINEL),
                      ValueError("source-post"), ValueError("x", "y"), ValueError()):
            self.assertEqual(guard(error), "unclassified")
        owner = source.split("# Optional failure DATA only;", 1)[0] + source.split('if (sys.platform != "darwin"', 1)[1]
        for literal in data["DATA_FAILURE_GUARDS"]:
            if literal.startswith("original fixed command did not completely pass:"):
                continue
            self.assertIn(repr(literal).replace("'", '"'), owner)

    def test_document_retains_original_capture_flags_and_never_promotes_zero(self):
        data, names, _, _ = reducers()
        context = dict(source="a" * 40, workflowSource="a" * 40, runId="123", runAttempt="1", target="aarch64-apple-darwin")
        command = dict(phase="python", originalReturned=True, returnCode=1, outputComplete=True,
                       captureClosed=True, timedOut=False, outputOverflow=False)
        output = dict(stdout=encoded(facts(data, names, [failure_entry(names[0])])), stderr=SENTINEL.encode())
        call = lambda c, guard="command-not-complete": json.loads(data["data_failure_document"](c, output, guard, context, names, {}, "/public/checkout"))
        result = call(command)
        self.assertEqual(result["python"]["failureTests"], [{"kind": "failure", "id": names[0]}])
        self.assertEqual(result["stderrSha256"], hashlib.sha256(output["stderr"]).hexdigest())
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assertTrue(result["diagnosticOnly"]); self.assertFalse(result["productReady"])
        for flag in ("originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow"):
            changed = dict(command); changed[flag] = not changed[flag]
            row = call(changed)
            self.assertIsNone(row["python"]); self.assertIsNone(row["cargo"])
            self.assertEqual(row[flag], changed[flag])
        for phase in ("mount", "apfs", "rust"):
            row = call(dict(command, phase=phase)); self.assertIsNone(row["python"]); self.assertIsNone(row["cargo"])
        row = call(dict(command, returnCode=0), "source-post")
        self.assertEqual(row["originalReturncode"], 0); self.assertFalse(row["productReady"])
        self.assertLessEqual(len(encoded(row)), 16384)
        site = "desktop/src-tauri/src/shell/installed_observation.rs"
        stderr = ("thread 'main' panicked at tests/../src/shell/installed_observation.rs:12:7:\n" + SENTINEL).encode()
        rust = dict(command, phase="rust", returnCode=101)
        rust_call = lambda c: json.loads(data["data_failure_document"](c, {"stdout": b"", "stderr": stderr},
            "command-not-complete", context, names, {site}, "/public/checkout"))
        self.assertEqual(rust_call(rust)["rustPanic"], {"source": site, "line": 12, "column": 7})
        self.assertIsNone(result["rustPanic"])
        for flag in ("originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow"):
            changed = dict(rust); changed[flag] = not changed[flag]
            self.assertIsNone(rust_call(changed)["rustPanic"])
        for phase in ("mount", "apfs", "build", "python"):
            self.assertIsNone(rust_call(dict(rust, phase=phase))["rustPanic"])
        for code in (0, 1, -9, None):
            self.assertIsNone(rust_call(dict(rust, returnCode=code))["rustPanic"])
        self.assertNotIn(SENTINEL, json.dumps(rust_call(rust)))
        with self.assertRaises(ValueError):
            data["data_failure_document"](dict(command, returnCode=True), output, "source-post", context, names, {}, "/public/checkout")

    def test_source_wiring_keeps_existing_owner_and_failure_exit(self):
        _, names, source, child = reducers()
        self.assertEqual(source.count('subprocess.Popen('), 1)
        self.assertEqual(source.count('for phase in ("mount", "apfs", "build", "rust", "python"):'), 1)
        self.assertEqual(source.count('put("failure-diagnostics.json", supplement)'), 1)
        self.assertIn('rustPanic=data_failure_rust_panic(captures["stderr"], source_paths, checkout) if classified and phase == "rust" and code == 101 else None', source)
        self.assertIn('if failure is not None and diagnostic_output is not None:', source)
        self.assertIn('        except BaseException:\n            pass\n    put("result.json",', source)
        self.assertIn('if failure is not None: raise SystemExit(1)', source)
        self.assertIn('facts.update(data_failed_test_rows(result.failures, result.errors, NAMES))', child)
        self.assertIn("try:\n    facts.update(data_failed_test_rows(result.failures, result.errors, NAMES))\nexcept BaseException:\n    pass\n", child)
        self.assertIn('raise SystemExit(0 if result.wasSuccessful() and facts["testsRun"] == 84', child)
        self.assertIn('"testsRun": result.testsRun, "failures": len(result.failures), "errors": len(result.errors)', child)
        self.assertLess(source.index('command["captureClosed"] = not close_errors'), source.index('if failure is not None and diagnostic_output is not None:'))
        self.assertLess(source.index('put("failure-diagnostics.json", supplement)'), source.index('put("result.json",'))
        tree = ast.parse(source)
        assignments = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
        self.assertEqual(len(ast.literal_eval(assignments["source_names"])), 78)
        self.assertEqual(source.count("0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94"), 2)
        owner = source.split('        capture_error = None\n', 1)[1].split('        if (capture_error', 1)[0]
        self.assertEqual(hashlib.sha256(owner.encode()).hexdigest(), "dffb34b67d4ae54155a1ad8000c82d5bcb252927f89e4a3c330dc83ffa520ad7")


if __name__ == "__main__":
    unittest.main()
