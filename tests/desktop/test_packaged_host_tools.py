"""Pure H1 DATA contracts; never run the observer, tools, workflow or cleanup.

Filesystem/process APIs exercised below are fake objects with invented identities.
Reading this checkout's source/readset is not installed-input or native evidence.
"""
from copy import deepcopy
import base64
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import posixpath
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib


SOURCE = Path(__file__).resolve().parents[2]
TOOLS = SOURCE / "desktop/tools"


def module(name):
    spec = importlib.util.spec_from_file_location("h1_contract_" + name, TOOLS / (name + ".py"))
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


helper = module("packaged_host_tools")
returned = module("packaged_host_tools_return")
DATASET_BYTES = (TOOLS / "packaged_host_tools_readset.json").read_bytes()
DATASET = json.loads(DATASET_BYTES)
POLICY = deepcopy(DATASET["policy"])
POLICY["sourceDatasetSha256"] = hashlib.sha256(DATASET_BYTES).hexdigest()


def fake_stat(*, mode=stat.S_IFREG | 0o755, inode=7, size=4, uid=0):
    return SimpleNamespace(st_dev=2049, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=0,
        st_nlink=1, st_size=size, st_blocks=8, st_mtime_ns=11, st_ctime_ns=12)


def object_row(path="/usr/bin/python3.12", identity=None):
    return {"path": path, "kind": "regular", "stat": helper.ident(identity or fake_stat()),
            "sha256": "a" * 64, "aliasTarget": None}


def public_values():
    """Invented shapes for return-gate tests, not purported host observations."""
    values = {name: dict.fromkeys(keys) for name, keys in returned.SHAPES.items()}
    for name, value in values.items():
        value.update(scope="candidate-only", state="UNSEALED", nativeQualification="not-established",
                     profile=helper.PROFILE, schema="mrk-h1-" + name.removesuffix(".json") + "-1")
    values["host-facts.json"]["policySha256"] = helper.POLICY_SHA256
    values["fit-gaps.json"]["storageBoundary"] = "bounded-observer-scratch-not-build-admission"
    values["host-candidate-files.json"].update(sourceDatasetSha256=helper.DATASET_SHA256,
        policySha256=helper.POLICY_SHA256, objects=[None] * 3460,
        roles=dict.fromkeys(str(i) for i in range(13)), providerDeclarations=dict.fromkeys(str(i) for i in range(42)))
    return values


class PackagedHostToolsContract(unittest.TestCase):
    def setUp(self):
        self.globals = patch.multiple(helper, P=deepcopy(POLICY), BODY=0, META=0, SUPPORT=0,
                                      CACHE={}, ORIGINALS={}, GAPS={})
        self.globals.start()
        self.addCleanup(self.globals.stop)

    def test_policy_is_exact_complete_frozen_data(self):
        self.assertEqual(hashlib.sha256(DATASET_BYTES).hexdigest(), helper.DATASET_SHA256)
        raw = helper.canonical(POLICY)
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (helper.POLICY_BYTES, helper.POLICY_SHA256))
        self.assertEqual(tuple(sorted(POLICY["roles"])), helper.ROLE_NAMES)
        self.assertEqual(len(POLICY["paths"]), 3460)
        self.assertEqual(len(POLICY["providers"]), 42)
        self.assertEqual(len(POLICY["cacheIndices"]), 568)
        self.assertEqual(len(POLICY["absenceIndices"]), 63)
        self.assertEqual(len(POLICY["mapFileIndices"]), 156)
        self.assertEqual(POLICY["roles"]["perl"]["package"], "perl-base")
        self.assertEqual(len(POLICY["aliases"]), 29)
        self.assertEqual(len(POLICY["directoryIndices"]), 12)
        records = {row["path"]: row for row in DATASET["records"]}
        map_paths = {POLICY["paths"][i] for i in POLICY["mapFileIndices"]}
        directories = {POLICY["paths"][i] for i in POLICY["directoryIndices"]}
        # Retained member-index symlinks use type/target, unlike the old census.
        # Observe the lexical alias AND its exact canonical body/directory.
        aliases = (
            ("/usr/lib/x86_64-linux-gnu/libgdbm.so.6", "/usr/lib/x86_64-linux-gnu/libgdbm.so.6.0.0", "libgdbm6t64"),
            ("/usr/lib/x86_64-linux-gnu/libgdbm_compat.so.4", "/usr/lib/x86_64-linux-gnu/libgdbm_compat.so.4.0.0", "libgdbm-compat4t64"),
            ("/usr/lib/x86_64-linux-gnu/perl/5.38", "/usr/lib/x86_64-linux-gnu/perl/5.38.2", "libperl5.38t64"),
            ("/usr/share/perl/5.38", "/usr/share/perl/5.38.2", "perl-modules-5.38"),
        )
        for alias, target, package in aliases:
            self.assertEqual(POLICY["aliases"][alias], target)
            self.assertIn("fixed-alias", records[alias]["reasons"])
            self.assertEqual(records[alias]["sourceMembers"], [{"kind": "alias", "bytes": 0,
                "mode": 0o777, "package": package, "sha256": None, "target": target.rsplit("/", 1)[1]}])
        for target, size, digest, package in (
            ("/usr/lib/x86_64-linux-gnu/libgdbm.so.6.0.0", 71864,
             "9d4eee22c3cdfc96d92d1dd56e09114c74203a6208b98ebd724b434047e4e070", "libgdbm6t64"),
            ("/usr/lib/x86_64-linux-gnu/libgdbm_compat.so.4.0.0", 14328,
             "e0f14a7aa92607093b25e1401837a83a756799acc7d6f99af61581d8b618f14c", "libgdbm-compat4t64"),
        ):
            self.assertIn(target, map_paths)
            self.assertEqual(records[target]["sourceMembers"], [{"kind": "regular", "bytes": size,
                "mode": 0o644, "package": package, "sha256": digest, "target": None}])
        for target, package in (("/usr/lib/x86_64-linux-gnu/perl/5.38.2", "libperl5.38t64"),
                                ("/usr/share/perl/5.38.2", "perl-modules-5.38")):
            self.assertIn(target, directories)
            self.assertEqual(records[target]["sourceMembers"], [{"kind": "directory", "bytes": 0,
                "mode": 0o755, "package": package, "sha256": None, "target": None}])
        helper.validate_policy(POLICY)
        for change in (lambda p: p["paths"].append("/outside/declared/input"),
                       lambda p: p["roles"].pop("perl"),
                       lambda p: p["providers"][0].update(version="different")):
            altered = deepcopy(POLICY)
            change(altered)
            with self.assertRaises(helper.Refused):
                helper.validate_policy(altered)
        with self.assertRaises(helper.Refused):
            helper.unique([("same", 1), ("same", 2)])

    def test_workflow_embeds_exact_sources_and_bounded_policy(self):
        workflow = (SOURCE / ".github/workflows/desktop-builder-host-observation.yml").read_text()
        embedded, tail = workflow.split("          MRK_H1_PROGRAM: |-\n", 1)[1].split("          MRK_H1_POLICY_B85: ", 1)
        program = "".join(line[12:] for line in embedded.splitlines(keepends=True))
        self.assertEqual(program, (TOOLS / "packaged_host_tools.py").read_text())
        self.assertLessEqual(len(program.encode()), 48 * 1024)
        self.assertEqual(hashlib.sha256(program.encode()).hexdigest(), returned.COLLECTOR_SHA256)
        encoded = json.loads(tail.splitlines()[0])
        self.assertNotIn("${{", encoded)
        self.assertNotIn("${{", program)
        self.assertEqual(helper.load_policy(encoded), POLICY)
        self.assertEqual(zlib.decompress(base64.b85decode(encoded)), helper.canonical(POLICY))
        for value in (None, "", encoded + "0", ("0" if encoded[0] != "0" else "1") + encoded[1:]):
            with self.assertRaises(helper.Refused):
                helper.load_policy(value)
        blocks = workflow.split("        run: |\n")
        self.assertEqual(len(blocks), 3)
        run = "".join(line[10:] for line in blocks[1].split("      - name:", 1)[0].splitlines(keepends=True))
        finalizer = "".join(line[10:] for line in blocks[2].splitlines(keepends=True))
        self.assertEqual(run, (TOOLS / "packaged_host_tools_run.sh").read_text())
        self.assertEqual(finalizer, (TOOLS / "packaged_host_tools_return.sh").read_text())
        self.assertLessEqual(len(run.encode()), 21000)
        self.assertLessEqual(len(finalizer.encode()), 21000)
        self.assertIn("${#MRK_H1_PROGRAM} -eq " + str(len(program.encode()) - 1), run)
        for marker, filename in (("MRK_H1_RETURN", "packaged_host_tools_return.py"),
                                 ("MRK_H1_CLEANUP", "packaged_host_tools_cleanup.py")):
            embedded = finalizer.split("<<'" + marker + "'\n", 1)[1].split("\n" + marker + "\n", 1)[0] + "\n"
            self.assertEqual(embedded, (TOOLS / filename).read_text())
        self.assertNotIn("uses:", workflow)
        self.assertIn("branches: [verify/desktop-packaged-host-tools]", workflow)
        self.assertIn("timeout-minutes: 8", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("steps.observer.outcome == 'success'", workflow)
        self.assertIn("--kill-after=5s 180s", run)
        self.assertLess(finalizer.index("FINALIZER-WAIT"), finalizer.index("MRK_H1_CLEANUP'"))
        self.assertIn('exit "$rc"', finalizer.split("MRK_H1_CLEANUP'", 1)[0])

    def test_provider_declarations_close_missing_duplicate_invalid_and_different(self):
        providers = [{"package": "example", "version": "1.2-3", "architecture": "amd64"}]
        raw = b"Package: example\nStatus: install ok installed\nVersion: 1.2-3\nArchitecture: amd64\nDescription: ordinary\n continuation\n"
        self.assertEqual(helper.provider_status(raw, providers)["example"]["state"], "matches-declaration")
        cases = ((None, "unavailable"), (b"", "missing"), (raw + b"\n" + raw, "duplicate"),
                 (raw.replace(b"1.2-3", b"1.2-4"), "different"), (raw + b"Version: 1.2-3\n", "invalid"),
                 (raw + b"version: 1.2-3\n", "invalid"), (raw + b"broken-field\n", "invalid"),
                 (raw.replace(b"Version: 1.2-3\n", b"Version: 1.2-3\n continuation\n"), "invalid"),
                 (b"\xff", "invalid"), (raw.replace(b"\n", b"\r\n"), "invalid"))
        for data, state in cases:
            with self.subTest(state=state, size=len(data) if data is not None else None):
                self.assertEqual(helper.provider_status(data, providers)["example"]["state"], state)

    def test_provider_members_never_authorize_extra_reads_or_authenticate_bytes(self):
        allowed = {"/usr/bin/example": 0}
        members = helper.declared_members(b"/bin/example\n/private/not-allowed\n", allowed, {"/bin": "/usr/bin"})
        self.assertEqual(members, {0})
        self.assertIsNone(helper.declared_members(b"/bin/example\n/usr/bin/example\n", allowed, {"/bin": "/usr/bin"}))
        expected = {"index": 0, "package": "example", "bytes": 4, "mode": 0o755, "sha256": "a" * 64}
        row = object_row("/usr/bin/example")
        observed = helper.role_observation(expected, row, {"example": members})
        self.assertEqual(observed["body"], "matches-retained-member")
        row["sha256"] = "b" * 64
        self.assertEqual(helper.role_observation(expected, row, {"example": members})["body"], "different-or-unavailable")
        observed = helper.role_observation(expected, object_row(), {"example": None, "other": {0}})
        self.assertFalse(observed["expectedProviderDeclared"])
        self.assertEqual(observed["declaredProviders"], ["other"])
        self.assertEqual(observed["scope"], "fixed-provider-declarations-not-global-ownership")

    def test_maps_join_only_allowed_original_identities_without_path_or_address_output(self):
        rows = [object_row(), object_row("/usr/lib/loader", fake_stat(inode=8))]
        raw = (b"00400000-00401000 r-xp 00000000 08:01 7 /usr/bin/python3.12\n"
               b"00500000-00501000 r--p 00000000 08:01 8 /lib/loader\n"
               b"00600000-00601000 rw-p 00000000 00:00 0\n"
               b"00700000-00701000 r-xp 00000000 00:00 0 [vdso]\n")
        observed = helper.normalized_maps(raw, rows, [0, 1], {"/lib": "/usr/lib"}, 0)
        self.assertEqual(observed, {"mappedIndices": [0, 1], "anonymousMappings": 1, "kernelMappings": 1, "gaps": {}})
        for altered, code in ((raw.replace(b"/usr/bin/python3.12", b"/private/unknown"), "MAP_UNKNOWN"),
                              (raw.replace(b"python3.12\n", b"python3.12 (deleted)\n"), "MAP_DELETED"),
                              (raw.replace(b"08:01 7", b"08:01 9"), "MAP_CHANGED"),
                              (raw.replace(b"08:01 7", b"08:02 7"), "MAP_CHANGED"),
                              (raw.replace(b"00401000", b"00300000"), "MAP_INVALID"),
                              (raw[:-1], "MAP_INVALID"), (b"\xff\n", "MAP_INVALID"),
                              (b"x" * (256 * 1024 + 1), "MAP_INVALID")):
            with self.subTest(code=code):
                result = helper.normalized_maps(altered, rows, [0, 1], {"/lib": "/usr/lib"}, 0)
                self.assertIn(code, result["gaps"])
                encoded = json.dumps(result)
                for undisclosed in ("/private", "/usr/bin", "/lib/loader", "00400000", "00300000"):
                    self.assertNotIn(undisclosed, encoded)

    def test_readlink_reserves_and_charges_every_original_and_recheck(self):
        fake = SimpleNamespace(readlink=Mock(return_value="/usr/bin/python3.12"), fsencode=lambda value: value.encode())
        with patch.object(helper, "os", fake):
            helper.link_body(41, "exe")
            helper.link_body(41, "exe")
            total = 2 * len(b"/usr/bin/python3.12")
            self.assertEqual((helper.META, helper.BODY), (total, total))
            helper.META = 8 * 2**20 - 4095
            with self.assertRaises(helper.Refused):
                helper.link_body(41, "exe")
        self.assertEqual(fake.readlink.call_count, 2)

    def test_alias_change_and_original_absence_recheck_fail_closed(self):
        original = fake_stat(mode=stat.S_IFLNK | 0o777, size=8)
        fake = SimpleNamespace(readlink=Mock(return_value="/usr/lib"), fsencode=lambda value: value.encode(),
                               path=posixpath, close=Mock())
        with patch.object(helper, "os", fake), patch.object(helper, "parent", return_value=(41, "lib")), \
                patch.object(helper, "at", side_effect=[original, original]):
            row = helper.measure("/lib")
        self.assertEqual(row["aliasTarget"], "/usr/lib")
        self.assertEqual(fake.close.call_args_list[0].args, (41,))
        changed = fake_stat(mode=original.st_mode, inode=99, size=8)
        with patch.object(helper, "os", fake), patch.object(helper, "parent", return_value=(41, "lib")), \
                patch.object(helper, "at", side_effect=[original, changed]):
            with self.assertRaises(helper.Refused):
                helper.measure("/lib")
        helper.ORIGINALS = {"/absent": errno.ENOENT}
        with patch.object(helper, "at", side_effect=FileNotFoundError(errno.ENOENT, "fake")):
            helper.recheck_originals()
        with patch.object(helper, "at", return_value=fake_stat()):
            with self.assertRaises(helper.Refused):
                helper.recheck_originals()

    def test_original_reader_closes_both_once_and_cleanup_failure_dominates_read_error(self):
        s = fake_stat()
        for read_error, close_error in ((False, False), (True, False), (True, True)):
            with self.subTest(read_error=read_error, close_error=close_error):
                helper.CACHE = {}
                fake = SimpleNamespace(stat=Mock(return_value=s), open=Mock(return_value=42),
                    fstat=Mock(return_value=s), read=Mock(side_effect=OSError(errno.EIO, "fake") if read_error else [b"data"]),
                    close=Mock(side_effect=[OSError(errno.EIO, "fake"), None] if close_error else None))
                with patch.object(helper, "os", fake), patch.object(helper, "parent", return_value=(41, "example")), \
                        patch.object(helper, "at", return_value=s):
                    if read_error:
                        with self.assertRaises(helper.CleanupUnknown if close_error else OSError):
                            helper.body("/fixed/example", 4, metadata=True)
                    else:
                        row, raw = helper.body("/fixed/example", 4, metadata=True)
                        self.assertEqual((raw, row["sha256"]), (b"data", hashlib.sha256(b"data").hexdigest()))
                self.assertEqual([call.args for call in fake.close.call_args_list], [(42,), (41,)])

    def test_body_reservation_and_final_identity_precede_success(self):
        s = fake_stat()
        for full, changed in ((True, False), (False, True)):
            helper.BODY = 3 * 2**30 if full else 0
            helper.CACHE = {}
            fake = SimpleNamespace(stat=Mock(return_value=s), open=Mock(return_value=42), fstat=Mock(return_value=s),
                                   read=Mock(return_value=b"data"), close=Mock())
            with patch.object(helper, "os", fake), patch.object(helper, "parent", return_value=(41, "example")), \
                    patch.object(helper, "at", return_value=fake_stat(inode=99) if changed else s):
                with self.assertRaises(helper.Refused):
                    helper.body("/fixed/example", 4)
            self.assertEqual(fake.read.call_count, 0 if full else 1)
            self.assertEqual([call.args for call in fake.close.call_args_list], [(42,), (41,)])

    def test_selected_roster_never_becomes_sealed_and_output_has_fixed_ceiling(self):
        def unavailable(path, metadata=False):
            return {"path": path, "kind": "unavailable", "stat": None, "sha256": None, "aliasTarget": None}
        with patch.object(helper, "measure", side_effect=unavailable) as measure, \
                patch.object(helper, "self_observation", return_value={"scope": "invented-test-data"}), \
                patch.object(helper, "recheck_originals"):
            result = helper.candidates()
        self.assertEqual([call.args[0] for call in measure.call_args_list], POLICY["paths"])
        self.assertEqual((result["state"], result["scope"], result["nativeQualification"]),
                         ("UNSEALED", "candidate-only", "not-established"))
        self.assertEqual(len(result["objects"]), 3460)
        self.assertEqual(helper.GAPS["ROLE_BODY_DIFFERENT"], 13)
        self.assertEqual(helper.GAPS["ROLE_DECLARATION_MISSING"], 13)
        helper.bounded_outputs({"data": result})
        with self.assertRaises(helper.Refused):
            helper.bounded_outputs({"data": "x" * (2 * 2**20)})

    def test_return_gate_refuses_scope_upgrade_old_schema_and_changed_roster(self):
        returned.validate_values(public_values())
        for key, value in (("scope", "sealed"), ("state", "SEALED"), ("nativeQualification", "passed"),
                           ("profile", "old-profile"), ("schema", "mrk-h0-host-facts-1"), ("extra", "not-allowed")):
            values = public_values()
            values["host-facts.json"][key] = value
            with self.assertRaises(ValueError):
                returned.validate_values(values)
        for change in (lambda values: values["host-candidate-files.json"]["objects"].pop(),
                       lambda values: values["host-candidate-files.json"].update(sourceDatasetSha256="0" * 64),
                       lambda values: values["ci-shape.json"].update({"return": {"already": "returned"}})):
            values = public_values()
            change(values)
            with self.assertRaises(ValueError):
                returned.validate_values(values)

    def test_original_return_read_requires_eof_identity_and_successful_close(self):
        s = fake_stat(mode=stat.S_IFREG | 0o600, uid=1001)
        for extra, changed, close_error in ((False, False, False), (True, False, False), (False, True, False), (False, False, True)):
            fake = SimpleNamespace(stat=Mock(return_value=s), getuid=lambda: 1001, open=Mock(return_value=42),
                fstat=Mock(side_effect=[s, fake_stat(mode=s.st_mode, inode=99, uid=1001) if changed else s]),
                read=Mock(side_effect=[b"data", b"x" if extra else b""]),
                close=Mock(side_effect=OSError(errno.EIO, "fake") if close_error else None))
            with patch.object(returned, "os", fake), patch.object(returned, "ROOT", 41):
                if extra or changed or close_error:
                    with self.assertRaises(OSError if close_error else ValueError):
                        returned.read("fixed.json", 4)
                else:
                    self.assertEqual(returned.read("fixed.json", 4)[0], b"data")
            self.assertEqual([call.args for call in fake.close.call_args_list], [(42,)])


if __name__ == "__main__":
    unittest.main()
