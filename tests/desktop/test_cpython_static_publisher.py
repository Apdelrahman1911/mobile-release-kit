"""Inert source-authored publisher tests; select only after separate review.

No record()/native linker call, shell recipe, build, compiler, candidate import,
real ELF image, installed runtime, subprocess, host filesystem link or fixture
execution. Tiny ordinary text files and in-memory GNU ar framing are test data.
This file and the authored helpers have NOT been run as part of source authoring.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

_SOURCE = Path(__file__).resolve().parents[2]


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, _SOURCE / path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inputs = _load("mrk_static_inputs_test", "desktop/tools/cpython_static_inputs.py")
link = _load("mrk_static_link_test", "desktop/tools/cpython_static_link.py")
payload = _load("mrk_static_payload_test", "desktop/tools/prepare_cpython_static_payload.py")
preparation = _load("mrk_static_existing_preparer_test", "desktop/tools/prepare_runtime.py")

_STAGE = {
    "bin/python3.14": b"INERT final-link bytes; NOT a program.\n",
    "bin/python3.14-config": b"INERT omitted SDK script; NEVER run.\n",
    "lib/python3.14/LICENSE.txt": b"INERT original-license fixture, not a public notice.\n",
    "lib/python3.14/os.py": b"# inert stdlib text; never imported\n",
    "lib/python3.14/encodings/__init__.py": b"# inert encodings text; never imported\n",
    "lib/python3.14/json/__init__.py": b"# conservatively retained text; never imported\n",
    "lib/python3.14/asyncio/__init__.py": b"# retained source is NOT a supported-feature claim\n",
    "lib/python3.14/_sysconfigdata__linux_x86_64-linux-gnu.py": b"# inert generated data; never imported\n",
    "lib/python3.14/_sysconfig_vars__linux_x86_64-linux-gnu.json": b'{"inert": true}\n',
    "lib/python3.14/build-details.json": b'{"inert": true, "notExecutionEvidence": true}\n',
    "lib/python3.14/test/inert.py": b"# excluded test source; never imported\n",
    "lib/python3.14/__pycache__/os.cpython-314.pyc": b"INERT text, not bytecode.\n",
    "include/python3.14/inert.h": b"INERT omitted SDK header; never compiled.\n",
}
_NOTICES = {"LICENSE.fixture.txt": b"INERT notice fixture, no legal clearance.\n",
            "PYTHON-CHANGES.txt": b"INERT direct-build profile/pruning/mapping/landmark change-summary fixture.\n"}
_LOCK_SHA = "1" * 64  # Only a fixture label, never an admitted/sealed production lock.


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _rec(path: str, raw: bytes) -> dict:
    return {"path": path, "size": len(raw), "sha256": _sha(raw)}


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _snapshot(root: Path) -> dict[str, bytes]:
    # Only the test's owned, ordinary temporary directory, not a custody scan.
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _shape_fixture() -> dict:
    """Initial lock-shape fixture ONLY; its empty builder is not a valid lock."""
    sources = []
    for name, (version, size, sha, url) in sorted(inputs.SOURCE_PINS.items()):
        sources.append({"id": name, "version": version, "root": str(inputs.SOURCE_ROOT / name), "patches": [],
            "archive": {"url": url, "file": {"path": "/inert/" + name + ".archive", "size": size, "sha256": sha},
                        "receipt": {"path": "/inert/" + name + ".receipt", "size": 1, "sha256": "2" * 64}},
            "inventory": {"path": "/inert/" + name + ".json", "size": 1, "sha256": "3" * 64}})
    return {"schemaVersion": 1, "state": "sealed", "target": dict(inputs.TARGET), "builder": {},
        "packages": [], "tools": [], "sources": sources, "recipeFiles": [], "coreSourceFiles": [],
        "environment": {**inputs.FIXED_ENV, "SOURCE_DATE_EPOCH": "0"},
        "configuration": {"profile": inputs.PROFILE, "cpythonCommit": inputs.CPYTHON_COMMIT,
            "staticModules": list(inputs.STATIC_MODULES), "disabledModules": list(inputs.DISABLED_MODULES),
            "pythonConfigure": list(inputs.PYTHON_CONFIGURE), "zlibConfigure": list(inputs.ZLIB_CONFIGURE),
            "libffiConfigure": list(inputs.FFI_CONFIGURE), "makePhases": list(inputs.PHASES),
            "coreProfile": {"path": "/inert/profile.json", "size": 17456, "sha256": inputs.CORE_PROFILE_SHA256}}}


def _ar(*members: tuple[str, bytes]) -> bytes:
    result = bytearray(b"!<arch>\n")
    for name, content in members:
        label = name if name.startswith("/") else name + "/"
        header = f"{label:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(content):<10}`\n".encode("ascii")
        assert len(header) == 60
        result.extend(header + content + (b"\n" if len(content) % 2 else b""))
    return bytes(result)


def _fixture(base: Path, *, stage_files=None, notices=None):
    stage_files = dict(_STAGE if stage_files is None else stage_files)
    notices = dict(_NOTICES if notices is None else notices)
    stage, receipt_root, notice_root, host_root = (base / name for name in ("stage", "receipts", "notices", "host"))
    for root in (stage, receipt_root, notice_root, host_root):
        root.mkdir(parents=True)
    for name, raw in stage_files.items():
        _write(stage / name, raw)
    # A listed empty installed directory is omitted, never shipped as an extra.
    (stage / "lib/python3.14/site-packages").mkdir(parents=True, exist_ok=True)
    for name, raw in notices.items():
        _write(notice_root / name, raw)
    host_bytes = {"python": b"INERT host identity data, not an executable.\n",
                  "stdlib-and-zlib.fixture.txt": b"INERT host closure data.\n"}
    host_records = []
    for name, raw in host_bytes.items():
        _write(host_root / name, raw)
        host_records.append(_rec(str(host_root / name), raw))
    host_document = {"schemaVersion": 1, "hostPython": _rec(str(host_root / "python"), host_bytes["python"]),
                     "files": sorted(host_records, key=lambda value: value["path"])}
    host_raw = payload._canonical(host_document)
    host_path = base / "host-inputs.json"
    host_path.write_bytes(host_raw)
    notice_document = {"schemaVersion": 1, "profile": payload.PROFILE, "pythonChangeSummary": "PYTHON-CHANGES.txt",
                       "files": [_rec(name, raw) for name, raw in sorted(notices.items())]}
    notice_raw = payload._canonical(notice_document)
    notice_path = base / "notice-inventory.json"
    notice_path.write_bytes(notice_raw)

    evidence = {}
    def retained(raw: bytes) -> dict:
        key = "objects/" + _sha(raw)
        evidence[key] = raw
        return {"object": key, "size": len(raw), "sha256": _sha(raw)}
    def artifact(raw: bytes, *, output: bool = False) -> dict:
        value = {"available": True, "size": len(raw), "sha256": _sha(raw), "retained": retained(raw)}
        if output:
            value["observation"] = "successful-original-link-output"
        return value
    link_id = "link-000000"
    argv = b"-o\0python\0inert-input.o\0"
    effective = argv + b"-Map=/inert/map\0--cref\0-t\0-t\0--dependency-file=/inert/deps\0"
    environment = payload._canonical({"PYTHONSTRICTEXTENSIONBUILD": "1"})
    map_raw, deps_raw = b"INERT map text, not native evidence.\n", b"python: inert-input.o\n"
    stdout_raw, stderr_raw = b"inert-input.o\n", b""
    receipt = {"schemaVersion": 1, "inputLockSha256": _LOCK_SHA, "linkId": link_id, "phase": "python-build",
        "kind": "linked", "originalResult": {"kind": "exit", "code": 0}, "originalArgvSha256": _sha(argv),
        "effectiveArgvSha256": _sha(effective), "expandedArgvSha256": _sha(argv),
        "cwd": "/work/build/cpython", "environmentSha256": _sha(environment), "responseFiles": [],
        "linkerSha256": "4" * 64, "stdout": retained(stdout_raw), "stderr": retained(stderr_raw),
        "analysisComplete": True, "artifacts": {"map": artifact(map_raw),
            "deps": artifact(deps_raw), "output": artifact(stage_files["bin/python3.14"], output=True)},
        "inputs": [{"path": "/work/build/cpython/inert-input.o", "role": "linker-script-or-argument-data",
            "observedRead": True, "origin": {"kind": "source-build", "id": "cpython", "inputLockSha256": _LOCK_SHA},
            "retained": retained(b"INERT object text, NOT ELF.\n"), "selectedMembers": []}],
        "processFiles": [], "outputPath": "/work/build/cpython/python",
        "beforeLinkOutput": {"available": False, "reason": "absent-before-link"}}
    evidence.update({link_id + "/original.argv": argv, link_id + "/expanded.argv": argv,
        link_id + "/effective.argv": effective, link_id + "/environment.json": environment,
        link_id + "/stdout": stdout_raw, link_id + "/stderr": stderr_raw,
        link_id + "/map": map_raw, link_id + "/deps": deps_raw,
        link_id + "/original-result.json": payload._canonical({"linkId": link_id, "result": {"kind": "exit", "code": 0}}),
        link_id + "/receipt.json": payload._canonical(receipt),
        "review/linked-input-closure.txt": b"INERT closure review fixture; NOT a linked SBOM.\n",
        "review/dynamic-closure.txt": b"INERT fixture; no ELF was observed or executed.\n"})
    for phase in payload._PHASES:
        log = b"INERT phase log, NOT proof that a program ran.\n"
        evidence[phase + ".log"] = log
        evidence[phase + ".json"] = payload._canonical({"schemaVersion": 1, "inputLockSha256": _LOCK_SHA,
            "phase": phase, "originalExitCode": 0, "logSha256": _sha(log), "ignoredInstallError": False,
            "captureFailure": False, "incompleteLinkCaptures": []})
        if phase in {"python-configure", "python-build", "python-install"}:
            evidence[phase + "-configuration.json"] = payload._canonical({"inertFixture": True,
                "notARuntimeBuiltinObservation": True})
    for name, raw in evidence.items():
        _write(receipt_root / name, raw)
    document = {"schemaVersion": 1, "profile": payload.PROFILE, "target": payload.TARGET,
        "inputLockSha256": _LOCK_SHA, "hostInputsSha256": _sha(host_raw),
        "stage": {"sourcePrefix": "/work/stage/opt/mrk-python",
            "files": [_rec(name, raw) for name, raw in sorted(stage_files.items())],
            "directories": sorted(p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_dir())},
        "finalInterpreter": {"stagePath": "bin/python3.14", "linkId": link_id,
            "receiptSha256": _sha(evidence[link_id + "/receipt.json"]),
            "size": len(stage_files["bin/python3.14"]), "sha256": _sha(stage_files["bin/python3.14"])}}
    provenance = {"schemaVersion": 1, "profile": payload.PROFILE, "inputLockSha256": _LOCK_SHA,
        "noticeInventorySha256": _sha(notice_raw), "files": [_rec(name, raw) for name, raw in sorted(evidence.items())],
        "linkedInputClosure": _rec("review/linked-input-closure.txt", evidence["review/linked-input-closure.txt"]),
        "dynamicClosure": _rec("review/dynamic-closure.txt", evidence["review/dynamic-closure.txt"])}
    result = SimpleNamespace(base=base, stage=stage, receipts=receipt_root, notices=notice_root,
        host_inputs=host_path, notice_inventory=notice_path, output_inventory=base / "output-inventory.json",
        provenance=base / "provenance.json", output=base / "output", report=base / "copy-report.json",
        document=document, provenance_document=provenance, stage_bytes=stage_files)
    _rebind(result)
    return result


def _rebind(fixture) -> None:
    # Rebinding is private inert-fixture construction, NOT a production bypass.
    evidence = _snapshot(fixture.receipts)
    fixture.provenance_document["files"] = [_rec(name, raw) for name, raw in sorted(evidence.items())]
    link_id = fixture.document["finalInterpreter"]["linkId"]
    fixture.document["finalInterpreter"]["receiptSha256"] = _sha(evidence[link_id + "/receipt.json"])
    out_raw = payload._canonical(fixture.document)
    provenance_raw = payload._canonical(fixture.provenance_document)
    fixture.output_inventory.write_bytes(out_raw)
    fixture.provenance.write_bytes(provenance_raw)
    fixture.policy = payload._Policy(_sha(out_raw), _sha(provenance_raw), _sha(fixture.notice_inventory.read_bytes()),
                                    len(_STAGE[payload._LICENSE_SOURCE]), _sha(_STAGE[payload._LICENSE_SOURCE]))


def _run(fixture, *, output=None, report=None):
    return payload._prepare_with_policy(fixture.stage, fixture.output_inventory, fixture.receipts, fixture.provenance,
        fixture.notices, fixture.notice_inventory, fixture.host_inputs, output or fixture.output,
        report or fixture.report, fixture.policy)


class CPythonStaticPublisherTests(unittest.TestCase):
    def setUp(self):
        # Guards remain active for every inert test. In particular no test calls
        # record(), even with a stubbed linker: genuine native evidence is not simulated.
        guard = patch.object(link.subprocess, "run", side_effect=AssertionError("Native execution is forbidden in inert tests"))
        guard.start()
        self.addCleanup(guard.stop)

    def assert_refused_without_output(self, fixture):
        before = _snapshot(fixture.base)
        with self.assertRaises((payload.PayloadError, OSError)):
            _run(fixture)
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.report.exists())
        self.assertEqual(_snapshot(fixture.base), before)

    def test_production_copy_is_closed_before_reads_and_has_no_cli_override(self):
        for name in ("APPROVED_OUTPUT_INVENTORY_SHA256", "APPROVED_STATIC_LINK_PROVENANCE_SHA256",
                     "APPROVED_NOTICE_INVENTORY_SHA256"):
            self.assertIsNone(getattr(payload, name))
        self.assertEqual(tuple(inspect.signature(payload.prepare).parameters),
                         ("stage", "output_inventory", "receipts", "provenance", "notices", "notice_inventory",
                          "host_inputs", "output", "report"))
        with patch.object(payload, "_read_checked") as read, patch.object(payload, "_directory") as directory, \
                patch.object(payload, "_write_payload") as write:
            with self.assertRaises(payload.PayloadError):
                payload.prepare(*(Path("/inert/not-read") for _ in range(9)))
            read.assert_not_called()
            directory.assert_not_called()
            write.assert_not_called()
        parser = payload._parser()
        arguments = [word for name in ("stage", "output-inventory", "receipts", "provenance", "notices",
                      "notice-inventory", "host-inputs", "output", "report") for word in ("--" + name, "/inert")]
        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args([*arguments, "--approve"])

    def test_ambiguous_json_never_gets_a_second_interpretation(self):
        for raw in (b'{"state":"UNSEALED","state":"sealed"}\n', b'{"size":NaN}\n'):
            with self.assertRaises(inputs.InputError):
                inputs.decode(raw)
            with self.assertRaises(payload.PayloadError):
                payload._decode(raw)

    def test_lock_refuses_unsealed_and_drift_in_real_profile_inputs(self):
        initial = _shape_fixture()
        for mutate in (lambda value: value.update(state="UNSEALED"),
                       lambda value: value["sources"][0]["archive"]["file"].update(sha256="0" * 64),
                       lambda value: value["configuration"]["staticModules"].append("_ssl"),
                       lambda value: value["environment"].update(PYTHONSTRICTEXTENSIONBUILD="0")):
            value = copy.deepcopy(initial)
            mutate(value)
            with self.assertRaises(inputs.InputError):
                inputs.validate_shape(value)
        with patch.object(inputs, "read_file", return_value=inputs.canonical(initial)), \
                patch.object(inputs, "decode") as decode:
            with self.assertRaises(inputs.InputError):
                inputs.load_lock(Path("/inert/lock.json"), "0" * 64)
            decode.assert_not_called()  # Caller lock identity cannot skip byte matching.

    def test_generated_module_roster_is_names_not_checker_count(self):
        names = inputs.BOOTSTRAP_MODULES + inputs.INTRINSIC_MODULES + inputs.STATIC_MODULES
        self.assertEqual(len(set(names)), 56)
        config = ("struct _inittab _PyImport_Inittab[] = {\n" +
                  "".join('{"' + name + '", PyInit_fixture},\n' for name in names) + "{0, 0}\n};\n").encode("ascii")
        makefile = ("MODBUILT_NAMES= " + " ".join(inputs.BOOTSTRAP_MODULES + inputs.STATIC_MODULES) +
                    "\nMODSHARED_NAMES=\nMODDISABLED_NAMES= " + " ".join(inputs.DISABLED_MODULES) + "\n").encode("ascii")
        self.assertEqual(inputs.configuration_names(config, makefile), sorted(names))
        with self.assertRaises(inputs.InputError):
            inputs.configuration_names(config.replace(b'"_contextvars"', b'"_unknown"'), makefile)
        with self.assertRaises(inputs.InputError):
            inputs.configuration_names(config, makefile.replace(b"MODSHARED_NAMES=", b"MODSHARED_NAMES= _ssl"))

    def test_negative_link_result_is_not_capture_failure_or_a_new_output(self):
        self.assertEqual(link.original_result(1), {"kind": "exit", "code": 1})
        self.assertEqual(link.original_result(-9), {"kind": "signal", "signal": 9})
        self.assertEqual(link.artifact(None, failed=True), {"available": False, "reason": "original-link-failed"})
        self.assertEqual(link.artifact(None, failed=False, query=True)["reason"], "not-a-link")
        with self.assertRaises(link.I.InputError):
            link.artifact(None, failed=False)
        self.assertEqual(link.output_observation(b"old", b"old", 1), "unchanged-preexisting-after-failure")
        self.assertNotEqual(link.output_observation(b"partial", None, -9), "successful-original-link-output")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link.capture_failure(root, "link-000007", link.original_result(-9))
            original = (root / "CAPTURE-FAILED.json").read_bytes()
            link.capture_failure(root, "unregistered", None)
            self.assertEqual((root / "CAPTURE-FAILED.json").read_bytes(), original)
            self.assertEqual(json.loads(original)["originalResult"], {"kind": "signal", "signal": 9})

    def test_phase_checks_catch_lost_receipts_even_without_a_failure_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "zlib-configure.log").write_bytes(b"inert successful outer phase log\n")
            (root / "link-000000").mkdir()  # Deliberate incomplete data, not an executed link.
            with patch.object(inputs, "RECEIPTS", root), patch.object(inputs, "load_lock", return_value={}):
                with self.assertRaises(inputs.InputError):
                    inputs.phase_record(Path("/inert/lock"), _LOCK_SHA, "zlib-configure", 0)
            value = json.loads((root / "zlib-configure.json").read_bytes())
            self.assertEqual(value["originalExitCode"], 0)
            self.assertTrue(value["captureFailure"])
            self.assertEqual(value["incompleteLinkCaptures"], ["link-000000"])

    def test_gnu_archive_member_hash_offsets_long_names_and_ambiguity(self):
        first, second = b"inert member A\n", b"inert member B\n"
        raw = _ar(("one.o", first), ("two.o", second))
        member = link.selected_members(raw, {"two.o"})[0]
        self.assertEqual((member["ordinal"], member["headerOffset"]), (1, 8 + 60 + len(first) + len(first) % 2))
        self.assertEqual((member["size"], member["sha256"], member["content"]), (len(second), _sha(second), second))
        name = "a-long-fixture-member-name.o"
        long = _ar(("//", (name + "/\n").encode("ascii")), ("/0", first))
        self.assertEqual(link.selected_members(long, {name})[0]["ordinal"], 1)
        for bad, wanted in ((_ar(("same.o", first), ("same.o", second)), {"same.o"}),
                            (raw, {"missing.o"}), (b"!<thin>\n", {"one.o"})):
            with self.assertRaises(link.I.InputError):
                link.selected_members(bad, wanted)

    def test_map_trace_and_dependency_reconciliation_rejects_missing_evidence(self):
        cwd, output = Path("/inert/build"), Path("/inert/build/python")
        mapping = b"Linker script and memory map\nlibfixture.a(member.o)\n"
        dependency = b"python: main.o libfixture.a\nmain.o:\nlibfixture.a:\n"
        trace = b"main.o\nlibfixture.a\n(libfixture.a)member.o\n"
        paths, selected = link.reconcile(mapping, dependency, trace, output, cwd)
        self.assertEqual(paths, {cwd / "main.o", cwd / "libfixture.a"})
        self.assertEqual(selected, {(cwd / "libfixture.a", "member.o")})
        for bad_map, bad_deps, bad_trace in ((b"map with no member\n", dependency, trace),
            (mapping, b"python: main.o\n", trace), (mapping, dependency, b"main.o\n")):
            with self.assertRaises(link.I.InputError):
                link.reconcile(bad_map, bad_deps, bad_trace, output, cwd)
        with self.assertRaises(link.I.InputError):
            link.dep_inputs(b"python: path\\ with\\ spaces.o\n")
        with self.assertRaises(link.I.InputError):
            link.dep_inputs(b"python: colon:input.o\n")

    def test_response_bytes_are_preserved_with_gnu_not_shell_escape_rules(self):
        self.assertEqual(link.response_tokens(b'"a\\q" \'b\\c\' "quoted value" #literal'),
                         ["aq", "bc", "quoted value", "#literal"])
        for raw in (b'"unterminated', b"trailing\\", b"nul\0value"):
            with self.assertRaises(link.I.InputError):
                link.response_tokens(raw)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "objects").mkdir(mode=0o700)
            raw = b'-o "python" @second.rsp\n'
            (root / "first.rsp").write_bytes(raw)
            (root / "second.rsp").write_bytes(b"inert.o\n")
            retained = []
            self.assertEqual(link.expand_arguments(["@first.rsp"], root, root, retained), ["-o", "python", "inert.o"])
            self.assertEqual((root / retained[0]["object"]).read_bytes(), raw)
            self.assertEqual(retained[0]["sha256"], _sha(raw))
        with self.assertRaises(link.I.InputError):
            link.output_path(["-omagic", "inert.o"], Path("/inert"))

    def test_plugin_paths_and_argument_only_data_do_not_become_member_provenance(self):
        plugins = link.plugin_paths(["-plugin", "/inert/liblto_plugin.so", "-plugin-opt=/inert/lto-wrapper",
                                     "-plugin-opt=-pass-through=-lgcc"], Path("/inert"))
        self.assertEqual(plugins[Path("/inert/liblto_plugin.so")], "linker-plugin")
        self.assertEqual(plugins[Path("/inert/lto-wrapper")], "plugin-option-path-not-execution-proof")
        fake_lock = {"_origins": {}, "_digest": _LOCK_SHA, "_tools": {"cc": "/inert/cc"}}
        with self.assertRaises(link.I.InputError):
            link.origin(Path("/inert/unknown.o"), b"inert", fake_lock)
        data = link.origin(Path("/inert/unknown.o"), b"inert", fake_lock, argument_only=True)
        self.assertTrue(data["notEvidenceOfReadOrIncorporation"])

    def test_copy_preserves_bytes_metadata_and_ships_notices_before_generic_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            before = (_snapshot(fixture.stage), _snapshot(fixture.receipts), _snapshot(fixture.notices))
            result = _run(fixture)
            after = _snapshot(fixture.output)
            self.assertEqual(result["evidenceKind"], "inert-algorithm-test")
            self.assertEqual(set(p.name for p in fixture.output.iterdir()), {"python"})
            self.assertEqual(after["python/bin/python3"], _STAGE["bin/python3.14"])
            self.assertEqual(after["python/LICENSE.txt"], _STAGE[payload._LICENSE_SOURCE])
            self.assertEqual(after["python/" + payload._SYSCONFIG_JSON], _STAGE[payload._SYSCONFIG_JSON])
            self.assertIn("python/lib/python3.14/asyncio/__init__.py", after)
            for name, raw in _NOTICES.items():
                self.assertEqual(after["python/licenses/" + name], raw)
            for name, raw, _ in payload._GENERATED:
                self.assertEqual(after[name], raw)
            self.assertEqual(len(after["python/lib/python314.zip"]), 22)
            self.assertFalse(any(name.endswith((".pyc", ".h")) or "/test/" in name for name in after))
            self.assertFalse(any(name in after for name in (*payload.RESERVED_PAYLOAD_FILES, "manifest.json", "INCOMPLETE")))
            self.assertEqual(before, (_snapshot(fixture.stage), _snapshot(fixture.receipts), _snapshot(fixture.notices)))
            for name in after:
                self.assertEqual(stat.S_IMODE((fixture.output / name).stat().st_mode),
                                 0o755 if name == "python/bin/python3" else 0o644)
                self.assertEqual((fixture.output / name).stat().st_nlink, 1)
            report = json.loads(fixture.report.read_bytes())
            self.assertTrue(report["notACompletionOrHandoffReceipt"])
            self.assertEqual(report["evidenceKind"], "inert-algorithm-test")
            self.assertEqual(report["profile"], "not-a-production-profile")
            copied_policy = payload._Policy(*payload._PRODUCTION_POLICY)
            self.assertEqual(json.loads(payload._report(copied_policy, fixture.document, [], []))["evidenceKind"],
                             "inert-algorithm-test")
            self.assertIn("lib/python3.14/test/inert.py", {item["path"] for item in report["omissions"]})
            second = _run(fixture, output=fixture.base / "second", report=fixture.base / "second-report.json")
            self.assertEqual(second["reportSha256"], result["reportSha256"])
            self.assertEqual(_snapshot(fixture.base / "second"), after)

    def test_changed_stage_or_original_object_bytes_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary) / "stage-change")
            (fixture.stage / "bin/python3.14").write_bytes(b"Changed INERT bytes\n")
            self.assert_refused_without_output(fixture)
            fixture = _fixture(Path(temporary) / "receipt-change")
            object_path = next((fixture.receipts / "objects").iterdir())
            object_path.write_bytes(b"Changed original object fixture\n")
            self.assert_refused_without_output(fixture)

    def test_a_rebound_stage_hash_cannot_replace_original_final_link_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            replacement = b"Different INERT output, not the original final link.\n"
            (fixture.stage / "bin/python3.14").write_bytes(replacement)
            fixture.document["stage"]["files"] = [_rec(name, replacement if name == "bin/python3.14" else raw)
                                                   for name, raw in sorted(fixture.stage_bytes.items())]
            fixture.document["finalInterpreter"].update(size=len(replacement), sha256=_sha(replacement))
            _rebind(fixture)
            self.assert_refused_without_output(fixture)

    def test_failed_original_phase_and_sticky_capture_are_not_accepted_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary) / "phase")
            path = fixture.receipts / "python-install.json"
            value = json.loads(path.read_bytes())
            value["ignoredInstallError"] = True
            path.write_bytes(payload._canonical(value))
            _rebind(fixture)
            self.assert_refused_without_output(fixture)
            fixture = _fixture(Path(temporary) / "sticky")
            (fixture.receipts / "CAPTURE-FAILED.json").write_bytes(b"INERT failed capture marker\n")
            _rebind(fixture)
            self.assert_refused_without_output(fixture)

    def test_missing_summary_extra_directory_and_shared_output_are_not_silently_pruned(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary) / "summary", notices={"LICENSE.fixture.txt": _NOTICES["LICENSE.fixture.txt"]})
            self.assert_refused_without_output(fixture)
            fixture = _fixture(Path(temporary) / "directory")
            (fixture.stage / "unlisted-empty").mkdir()
            self.assert_refused_without_output(fixture)
            files = {**_STAGE, "lib/python3.14/lib-dynload/unexpected.so": b"INERT text; NOT a shared library.\n"}
            fixture = _fixture(Path(temporary) / "shared", stage_files=files)
            self.assert_refused_without_output(fixture)
            missing = {name: raw for name, raw in _STAGE.items() if name != payload._SYSCONFIG_JSON}
            fixture = _fixture(Path(temporary) / "missing-metadata", stage_files=missing)
            self.assert_refused_without_output(fixture)

    def test_limits_reserve_both_bootstraps_core_and_manifest_without_loosening(self):
        for name in ("MAX_FILES", "MAX_ENTRIES", "MAX_PATH_PARTS", "MAX_FILE_BYTES", "MAX_TOTAL_BYTES"):
            self.assertEqual(getattr(payload, name), getattr(preparation, name))
        self.assertEqual(set(payload.RESERVED_PAYLOAD_FILES),
                         {"core.zip", preparation.GITHUB_CA_NAME, *preparation.BOOTSTRAPS})
        self.assertEqual(len(payload.RESERVED_PAYLOAD_FILES), 8)
        self.assertEqual(payload.RESERVED_ENTRIES, 9)
        self.assertEqual(payload.RESOURCE_BYTE_HEADROOM, 64 * 1024 * 1024)
        self.assertGreater(payload.RESOURCE_BYTE_HEADROOM,
                           preparation.MAX_CORE_BYTES + len(preparation.BOOTSTRAPS) * preparation.MAX_BOOTSTRAP_BYTES
                           + preparation.MAX_GITHUB_CA_BYTES + payload.MAX_MANIFEST_BYTES)
        item = payload._Item("python/fixture.py", b"# inert\n", {})
        inventory = payload._inventory([item]) + [
            {"path": name, "size": payload.RESOURCE_BYTE_HEADROOM, "sha256": "0" * 64}
            for name in payload.RESERVED_PAYLOAD_FILES]
        limits = {
            "MAX_FILES": 1 + len(payload.RESERVED_PAYLOAD_FILES),
            "MAX_ENTRIES": 2 + payload.RESERVED_ENTRIES,
            "MAX_TOTAL_BYTES": payload.RESOURCE_BYTE_HEADROOM + len(item.content),
            "MAX_FILE_BYTES": len(item.content),
            "MAX_MANIFEST_BYTES": len(payload._canonical(inventory)) + payload.MANIFEST_METADATA_HEADROOM,
            "MAX_MANIFEST_NODES": 7 * len(inventory) + 32,
        }
        for key, exact in limits.items():
            with self.subTest(bound=key):
                with patch.object(payload, key, exact):
                    self.assertEqual(payload._preflight_items([item]), {"python"})
                with patch.object(payload, key, exact - 1), self.assertRaises(payload.PayloadError):
                    payload._preflight_items([item])
        with self.assertRaises(payload.PayloadError):
            payload._preflight_items([item, payload._Item("python/FIXTURE.py", b"inert", {})])

    def test_nonordinary_files_are_refused_without_creating_host_links(self):
        ordinary = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_nlink=1, st_file_attributes=0)
        hardlinked = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_nlink=2, st_file_attributes=0)
        symlink = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_nlink=1, st_file_attributes=0)
        with patch.object(Path, "lstat", return_value=ordinary):
            self.assertIs(payload._ordinary(Path("/inert/file")), ordinary)
        for metadata in (hardlinked, symlink):
            with patch.object(Path, "lstat", return_value=metadata), self.assertRaises(payload.PayloadError):
                payload._ordinary(Path("/inert/file"))

    def test_partial_output_keeps_sentinel_and_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            with patch.object(payload, "_verify_output", side_effect=payload.PayloadError("inert verification failure")):
                with self.assertRaises(payload.PayloadError):
                    _run(fixture)
            self.assertEqual((fixture.output / "INCOMPLETE").read_bytes(), payload._SENTINEL)
            self.assertFalse(fixture.report.exists())
            before = _snapshot(fixture.output)
            with self.assertRaises(payload.PayloadError):
                _run(fixture)
            self.assertEqual(_snapshot(fixture.output), before)


if __name__ == "__main__":
    unittest.main()
