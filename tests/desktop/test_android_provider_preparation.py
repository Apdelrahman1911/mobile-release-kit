"""Inert Android provider/loader DATA tests. No program body is ever executed."""
from copy import deepcopy
import hashlib
import importlib.util
import io
from pathlib import Path
import os
import stat
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

SOURCE = Path(__file__).resolve().parents[2]


def fixture_module(name):
    spec = importlib.util.spec_from_file_location("_provider_fixture_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


F = fixture_module("test_android_material_preparation")
M = F.M


def elf(*needed, soname=None, rpath=None, runpath=None):
    return {"interpreter": None, "needed": list(needed), "soname": soname, "rpath": rpath, "runpath": runpath,
            "versionNeeds": {}, "versionDefinitions": []}


def context_data():
    """Tiny invented loader contexts, not a supplier/runtime profile."""
    tools = {"jdk/bin/java": elf("libjli.so", rpath="$ORIGIN/../lib"),
             "jdk/lib/libjli.so": elf("libchild.so", soname="libjli.so"),
             "jdk/lib/libchild.so": elf(soname="libchild.so"),
             "jdk/lib/server/libjvm.so": elf(soname="libjvm.so")}
    return {"toolObjects": {path: {"elf": row} for path, row in tools.items()}, "osLibraries": {}, "nestedObjects": [],
            "programs": {}, "launches": ["jdk/bin/java"], "java": "jdk/bin/java", "jvm": "jdk/lib/server/libjvm.so",
            "postJliModules": [], "expectedGlobalAbsences": ["libtinfo.so.5"]}


def loader_data():
    """Parser fixtures only; identities below do not bind any actual OS file."""
    _, readers = M._provider_readers()
    control = {"osLibraries": {"libc.so.6": {"file": {"selectedPath": "/usr/lib/x86_64-linux-gnu/libc.so.6"}}},
               "expectedGlobalAbsences": ["libtinfo.so.5"], "packages": {"libc-bin": {"version": "2.39-inert"}}}
    original = {"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "identity": [0] * 9, "size": 1, "sha256": "a" * 64}
    state = {"bindings": {original["path"]: original}, "alternatives": {"/etc/ld.so.preload": {"absent": True}}}
    alternatives = state["alternatives"]
    for directory in readers["DEFAULT_LIBRARY_DIRS"]:
        alternatives[directory] = {"directory": [0] * 5}
        for tier in readers["HWCAPS"]:
            alternatives[directory + "/glibc-hwcaps/" + tier] = {"absent": True}
        for name in ("libc.so.6", "libtinfo.so.5"):
            alternatives[directory + "/" + name] = (deepcopy(original) if name == "libc.so.6" and directory.endswith("x86_64-linux-gnu")
                                                    else {"absent": True})
    rows = ['dl_dst_lib="lib/x86_64-linux-gnu"', 'dso.ld="ld-linux-x86-64.so.2"', 'dso.libc="libc.so.6"',
            'path.rtld="/lib64/ld-linux-x86-64.so.2"', 'version.version="2.39"', 'dl_hwcaps_subdirs_active=0x7',
            'dl_hwcaps_subdirs="' + ":".join(readers["HWCAPS"]) + '"']
    rows += ['path.system_dirs[0x' + format(index, "x") + ']="' + directory + '/"'
             for index, directory in enumerate(readers["DEFAULT_LIBRARY_DIRS"])]
    diagnostics = ("\n".join(rows) + "\n").encode()
    cache = b"1 libs found in cache `/etc/ld.so.cache'\n\tlibc.so.6 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libc.so.6\n"
    return control, state, diagnostics, cache


def provider_stage(folder, fault=None):
    compiler, root = Path(folder) / "compiler", Path(folder) / "material"
    compiler.mkdir(mode=0o700); root.mkdir(mode=0o700)
    owner = (os.getuid(), os.getgid())
    directories = {".": M._private(root, owner, directory=True, mode=0o700)[:5]}
    for name in ("private", "home", "tmp"):
        M._staging_mkdir(root, name, directories, owner)
    control, state, diagnostics, cache = loader_data()
    outputs = {"android-provider-diagnostics": diagnostics, "android-provider-cache": cache}
    check = SimpleNamespace(root=compiler, end=time.monotonic() + 30, failed=False, private_roots={}, calls=[])

    def command(label, argv, env, cwd, *, timeout, limit):
        check.calls.append((label, argv, env, cwd, timeout, limit))
        capture = compiler / "private-material"
        if not capture.exists():
            capture.mkdir(mode=0o700)
            check.private_roots["material"] = M._private(capture, owner, directory=True, mode=0o700)[:5]
        stdout, stderr = outputs[label], b""
        if fault == "stderr": stderr = b"inert error"
        if fault == "partial": stdout = stdout.splitlines()[0] + b"\n"
        if fault == "private-output": M.D.write(root / "tmp/unexpected", b"preserve", 0o400)
        request = {"phase": label, "argv": argv if fault != "request" else ["/inert/other"], "timeoutSeconds": timeout}
        captures = {}
        for suffix, raw in (("stdout", stdout), ("stderr", stderr)):
            pin = M.D.write(capture / (label + "." + suffix), raw)
            captures[suffix] = {key: pin[key] for key in ("size", "sha256")}
        M.D.write(capture / (label + ".request.json"), M.D.canonical(request))
        M.D.write(capture / (label + ".result.json"), M.D.canonical({**request, "exitCode": 0,
                  "ordinaryOwnerReturned": fault != "owner", "captures": captures}))
        return SimpleNamespace(args=argv, returncode=0, stdout=stdout, stderr=stderr)

    check.private_command = command
    return check, root, owner, directories, control, state


class AndroidProviderDataTests(unittest.TestCase):
    def test_complete_fixed_source_walk_keeps_phases_abi5_and_native_obligations_separate(self):
        value = M.policy(); control = M._provider_control(value)
        files = {row["path"]: row for row in M._control(value, "layout.json.gz")["files"]}
        for name, row in control["toolObjects"].items(): self.assertEqual(row["file"], files[name])
        graph = M._provider_graph(control, files)
        self.assertEqual(len(graph["contexts"]), 119)
        self.assertEqual(len(graph["globalNames"]), 40)
        self.assertFalse(graph["nativeSelectionProven"]); self.assertFalse(graph["symbolBindingProven"])
        self.assertEqual(control["nativeSelectorObligations"],
                         ["jansi-selected-origin", "fileevents-gnu-selected-origin", "same-vm-native-member-and-helper-finality"])
        misses = [row for row in graph["edges"] if row["via"] == "expected-global-miss"]
        self.assertEqual(len(misses), 1)
        self.assertIn("ncurses5", misses[0]["requester"]); self.assertEqual(misses[0]["name"], "libtinfo.so.5")
        self.assertTrue(any(row["name"] == "libtinfo.so.5" and row["selected"] == "sdk/build-tools/35.0.0/lib64/libtinfo.so.5"
                            for row in graph["edges"]))
        self.assertTrue(any(row["name"] == "libjvm.so" and row["via"] == "loaded" and row["phase"] == "jdk-module"
                            for row in graph["edges"]))
        self.assertFalse(any(row["name"] == "libjvm.so" and row["phase"] == "startup" for row in graph["edges"]))
        jna = [row for row in control["nestedObjects"] if "jna-5.6.0.jar" in row["jar"]["path"]]
        self.assertEqual(jna[0]["elf"]["soname"], "../build/libjnidispatch.so")

    def test_rpath_is_inherited_but_runpath_is_direct_and_overrides_rpath(self):
        control = context_data(); tools = control["toolObjects"]
        self.assertTrue(M._provider_graph(control, tools)["edges"])
        tools["jdk/bin/java"]["elf"].update(rpath="$ORIGIN/unused", runpath="$ORIGIN/../lib")
        with self.assertRaisesRegex(M.D.Refused, "no admitted provider"): M._provider_graph(control, tools)
        tools["jdk/lib/libjli.so"]["elf"]["rpath"] = "$ORIGIN"
        self.assertTrue(M._provider_graph(control, tools)["edges"])
        for tag in ("", ".", "$LIB", "$ORIGIN/../../../outside", "$ORIGIN:$PLATFORM", "/tmp"):
            tools["jdk/lib/libjli.so"]["elf"]["rpath"] = tag
            with self.subTest(tag=tag), self.assertRaises(M.D.Refused): M._provider_graph(control, tools)

    def test_loaded_jvm_and_optional_objects_never_leak_to_other_roots_or_modules(self):
        control = context_data(); tools = control["toolObjects"]
        tools["jdk/lib/module.so"] = {"elf": elf("libjvm.so")}
        control["postJliModules"] = ["jdk/lib/module.so"]
        self.assertTrue(M._provider_graph(control, tools)["contexts"])
        tools["sdk/bin/inert"] = {"elf": elf("libjvm.so")}; control["launches"].append("sdk/bin/inert")
        with self.assertRaisesRegex(M.D.Refused, "no admitted provider"): M._provider_graph(control, tools)
        del tools["sdk/bin/inert"]; control["launches"].pop()
        tools["sdk/private/liboptional.so"] = {"elf": elf(soname="liboptional.so")}
        control["postJliModules"].insert(0, "sdk/private/liboptional.so")
        tools["jdk/lib/module.so"]["elf"]["needed"].append("liboptional.so")
        with self.assertRaisesRegex(M.D.Refused, "no admitted provider"): M._provider_graph(control, tools)

    def test_missing_version_unparsed_and_ambiguous_private_candidates_refuse(self):
        for fault in ("version", "unparsed", "ambiguous"):
            control = context_data(); tools = control["toolObjects"]; inventory = list(tools)
            if fault == "version": tools["jdk/bin/java"]["elf"]["versionNeeds"] = {"libjli.so": ["MISSING_1"]}
            else:
                path = "jdk/lib/glibc-hwcaps/x86-64-v3/libjli.so"; inventory.append(path)
                if fault == "ambiguous": tools[path] = {"elf": elf(soname="libjli.so")}
            with self.subTest(fault=fault), self.assertRaises(M.D.Refused): M._provider_graph(control, inventory)

    def test_android_elf_data_mode_does_not_widen_old_callers_or_allow_other_platforms(self):
        fixture = fixture_module("test_ubuntu_publication_ci")
        parse, _ = M._provider_readers()
        for tag in (15, 29):
            raw = fixture.elf_data(tag)
            observed = parse(raw, android_data=True)
            self.assertEqual(observed["rpath" if tag == 15 else "runpath"], "libc.so.6")
            for options in ({}, {"shell": True}, {"android_data": True, "shell": True},
                            {"android_data": True, "runtime_path": "python/bin/python3"}):
                with self.subTest(tag=tag, options=options), self.assertRaises(ValueError): parse(raw, **options)
        for tag in (0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff):
            with self.assertRaises(ValueError): parse(fixture.elf_data(tag), android_data=True)
        other = bytearray(fixture.elf_data()); other[7] = 9  # FreeBSD OSABI, not a GNU/Linux module.
        with self.assertRaises(ValueError): parse(bytes(other), android_data=True)
        nodeflib = bytearray(fixture.elf_data(0x6ffffffb))
        struct.pack_into("<Q", nodeflib, 640 + 5 * 16 + 8, 0x800)
        with self.assertRaisesRegex(ValueError, "unsupported loader search flag"): parse(bytes(nodeflib), android_data=True)

    def test_exact_nested_aapt2_routes_reuse_the_original_body_and_archive_inventory(self):
        value = M.policy(); files = M._control(value, "layout.json.gz")["files"]
        suppliers = M._control(value, "suppliers.json")["files"]; indexes = M._control(value, "archives.json.gz")["archives"]
        routes = M._archive_routes(files, suppliers, indexes)
        self.assertEqual({row["path"] for row in routes["body-010"]["aapt2"]},
                         {"gradle/native/aapt2/aapt2", "gradle/aapt2/8.9.2-12782657-linux/aapt2"})
        for fault in ("wrong-jar", "different-body", "source-mode"):
            changed = deepcopy(files); row = next(row for row in changed if row["path"] == "gradle/native/aapt2/aapt2")
            if fault == "wrong-jar": row["source"]["jar"] = "bundletool/bundletool.jar"
            elif fault == "different-body": row["source"]["id"] = "body-011"
            else: row["sourceMode"] = 0o644
            with self.subTest(fault=fault), self.assertRaises(M.D.Refused): M._archive_routes(changed, suppliers, indexes)

    def test_both_routes_use_existing_bounded_writer_without_running_a_decoder(self):
        raw = b"inert archive DATA, not a native program"
        buffer = io.BytesIO()
        info = zipfile.ZipInfo("aapt2"); info.external_attr = (stat.S_IFREG | 0o755) << 16
        with zipfile.ZipFile(buffer, "w") as archive: archive.writestr(info, raw)
        with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive: info = archive.getinfo("aapt2")
        member = {"path": "aapt2", "type": "regular", "size": len(raw), "mode": 0o755, "sha256": hashlib.sha256(raw).hexdigest(),
                  "externalAttr": info.external_attr, "creatorSystem": info.create_system, "compression": info.compress_type,
                  "flags": info.flag_bits, "compressedBytes": info.compress_size, "crc32": info.CRC, "headerOffset": info.header_offset}
        index = {"id": "body-010", "format": "zip", "members": [member], "logicalMembers": 1}
        rows = [{"path": path, "size": len(raw), "sha256": member["sha256"], "mode": 0o555, "sourceMode": 0o755}
                for path in ("gradle/native/aapt2/aapt2", "gradle/aapt2/8.9.2-12782657-linux/aapt2")]
        with tempfile.TemporaryDirectory(prefix="mrk-provider-zip-inert-") as folder:
            root = Path(folder); owner = (os.getuid(), os.getgid()); originals = {}
            directories = {".": M._private(root, owner, directory=True, mode=0o700)[:5]}
            for name in ("bodies", "tools", *["tools/" + name for name in M._parents([row["path"] for row in rows])]):
                M._staging_mkdir(root, name, directories, owner)
            M.D.write(root / "bodies/body-010", buffer.getvalue(), 0o400)
            check = SimpleNamespace(end=time.monotonic() + 30, private_command=Mock(side_effect=AssertionError("no decoder")))
            M._archive(check, root, index, {"aapt2": rows}, owner, directories, originals)
            tree = M._tree(root, rows, owner, check.end, directories=directories, originals=originals)
            self.assertEqual(len(tree["files"]), 2); check.private_command.assert_not_called()
            self.assertTrue(all(row["identity"][2] == stat.S_IFREG | 0o500 for row in tree["files"]))

    def test_complete_generated_and_os_union_refuses_before_creation_or_acquisition(self):
        value = M.policy(); context = F.inert_context(); end = time.monotonic() + 30
        original = {"runnerUid": 123, "runnerGid": 456, "source": "/source", "root": "/inert/compiler", "deadline": str(end)}
        check = SimpleNamespace(root=Path(original["root"]), end=end, failed=False, private_command=Mock())
        generated = {role: {"size": size, "sha256": "a" * 64} for role, size in (("javaTrustStore", 1 << 20), ("sdkLicense", 41))}
        contract = F.inert_os(); contract["files"] *= 2
        contract["files"] = [{**row, "path": "/usr/lib/inert" + str(index) + ".so", "size": 40 << 20}
                             for index, row in enumerate(contract["files"])]
        with patch.object(M, "_context", return_value=original), patch.object(M.os, "getuid", return_value=123), \
             patch.object(M.os, "getgid", return_value=456), patch.object(M, "_host_state", return_value=(contract, generated)), \
             patch.object(M.Path, "mkdir") as mkdir, patch.object(M, "_space") as capacity, patch.object(M, "_download") as acquire:
            with self.assertRaisesRegex(M.D.Refused, r"tool\+OS byte bound"):
                M.prepare(check, Path("/source"), Path("/inert/mrk-android-material-17-2"), context=context, host={})
        mkdir.assert_not_called(); capacity.assert_not_called(); acquire.assert_not_called(); check.private_command.assert_not_called()
        self.assertTrue(check.failed)
        files = M._control(value, "layout.json.gz")["files"]
        prospective = M._prospective_files(value, files, generated)
        self.assertEqual(sum(row["size"] for row in prospective), 993914038 + (1 << 20) + 41 + 35514)

    def test_actual_material_parser_requires_original_writers_and_exact_jar_members(self):
        fixture = fixture_module("test_ubuntu_publication_ci")
        raw = fixture.elf_data(); parse, _ = M._provider_readers(); parsed = parse(raw, android_data=True)
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, "w") as archive: archive.writestr("linux-x86-64/inert.so", raw)
        contents = {"jdk/bin/java": raw, "gradle/lib/inert.jar": packed.getvalue()}
        files = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                  "mode": 0o555 if name == "jdk/bin/java" else 0o444} for name, body in contents.items()]
        control = {"toolObjects": {files[0]["path"]: {"file": files[0], "elf": parsed}},
                   "nestedObjects": [{"jar": files[1], "member": "linux-x86-64/inert.so", "size": len(raw),
                                      "sha256": files[0]["sha256"], "elf": parsed}]}
        with tempfile.TemporaryDirectory(prefix="mrk-provider-material-inert-") as folder:
            root = Path(folder); owner = (os.getuid(), os.getgid()); originals = {}; end = time.monotonic() + 30
            directories = {".": M._private(root, owner, directory=True, mode=0o700)[:5]}
            for name in ("tools", *["tools/" + name for name in M._parents(contents)]):
                M._staging_mkdir(root, name, directories, owner)
            for row in files:
                M._member_output(io.BytesIO(contents[row["path"]]), root, [{**row, "sourceMode": row["mode"]}], row, end,
                                 directories=directories, originals=originals, owner=owner)
            inventory = M._tree(root, files, owner, end, directories=directories, originals=originals)
            with patch.object(M, "_provider_control", return_value=control), patch.object(M, "_provider_graph", return_value={}) as graph:
                proof = M._provider_material_graph({}, root, owner, inventory, end)
                self.assertEqual(len(proof["materialOriginalsSha256"]), 64)
                graph.assert_called_once_with(control, originals)
                control["nestedObjects"][0]["sha256"] = "0" * 64
                with self.assertRaisesRegex(M.D.Refused, "actual JNI source member differs"):
                    M._provider_material_graph({}, root, owner, inventory, end)
                control["nestedObjects"][0]["sha256"] = files[0]["sha256"]
                path = root / "tools/jdk/bin/java"; path.rename(path.with_name("original")); M.D.write(path, raw, 0o500)
                with self.assertRaisesRegex(M.D.Refused, "original staging writer"):
                    M._provider_material_graph({}, root, owner, inventory, end)

    def test_provider_state_includes_complete_original_loader_configuration(self):
        value = M.policy(); control = M._provider_control(value)
        files = {row["file"]["selectedPath"]: deepcopy(row["file"])
                 for row in (*control["osLibraries"].values(), *control["programs"].values())}
        files.update({row["selectedPath"]: deepcopy(row) for row in (control["loader"], control["ldconfig"])})
        for path in ("/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d/libc.conf"):
            files[path] = {"path": path, "size": 1, "sha256": "a" * 64, "mode": 0o644}
        value["hostPolicy"] = {"inputs": {"files": ["/etc/ld.so.conf", "/etc/ld.so.conf.d/libc.conf"],
                                          "directories": {"/etc/ld.so.conf.d": ["libc.conf"]}, "absences": []}}
        host = {"bindings": {"files": files, "androidDirectories": {"/etc/ld.so.conf.d": {"inert": "directory"}},
                             "androidLoader": {"/etc/ld.so.preload": {"absent": True}}}}
        with patch.object(M, "_protected_binding", side_effect=lambda row, _: {key: row[key] for key in ("path", "size", "sha256", "mode")}), \
             patch.object(M, "_protected_namespace") as namespace, patch.object(M, "_provider_boundary") as boundary:
            state = M._provider_state(value, host, time.monotonic() + 30)
            self.assertTrue({"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d/libc.conf"} <= set(state["osFiles"]))
            namespace.assert_called_once_with({"inert": "directory"}, "/etc/ld.so.conf.d", children=["libc.conf"])
            boundary.side_effect = M.D.Refused("original alternative changed")
            with self.assertRaisesRegex(M.D.Refused, "original alternative changed"):
                M._provider_state(value, host, time.monotonic() + 30)
            value["hostPolicy"]["inputs"]["files"].remove("/etc/ld.so.conf.d/libc.conf")
            with self.assertRaisesRegex(M.D.Refused, "configuration roster is incomplete"):
                M._provider_state(value, host, time.monotonic() + 30)

    def test_cache_alias_and_expected_global_absence_cannot_admit_alternatives(self):
        control, state, diagnostics, cache = loader_data()
        self.assertTrue(M._provider_loader_proof(control, state, diagnostics, cache)["candidates"])
        for fault in ("alias", "missing-original", "global-abi5", "cache-location", "extra-original"):
            changed, capture = deepcopy(state), cache
            if fault == "alias": changed["alternatives"]["/lib/x86_64-linux-gnu/libc.so.6"]["identity"][1] = 5
            elif fault == "missing-original": del changed["alternatives"]["/lib/x86_64-linux-gnu/libc.so.6"]
            elif fault == "global-abi5": changed["alternatives"]["/lib/x86_64-linux-gnu/libtinfo.so.5"] = {"path": "/sdk/private/libtinfo.so.5"}
            elif fault == "cache-location": capture = cache.replace(b"/usr/lib/x86_64-linux-gnu/libc.so.6", b"/unbound/libc.so.6")
            else: changed["alternatives"]["/other/libc.so.6"] = {"absent": True}
            with self.subTest(fault=fault), self.assertRaises(ValueError): M._provider_loader_proof(control, changed, diagnostics, capture)

    def test_fixed_consumers_settle_originals_and_readback_does_not_launch(self):
        with tempfile.TemporaryDirectory(prefix="mrk-provider-owner-inert-") as folder:
            check, root, owner, directories, control, state = provider_stage(folder)
            with patch.object(M, "_provider_state", return_value=state), patch.object(M, "_provider_control", return_value=control), \
                 patch.object(M, "_provider_material_graph", return_value={"inert": "graph"}) as graph:
                proof = M._provider_consumers(check, {}, {}, root, owner, directories)
                proof["graph"] = {"inert": "graph"}
                M._provider_readback({}, {}, root, owner, directories, check.root, {}, proof, check.end)
                self.assertEqual(len(check.calls), 2); graph.assert_called_once(); self.assertFalse(check.failed)
                for _, _, env, cwd, timeout, limit in check.calls:
                    self.assertEqual(set(env), {"PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR"})
                    self.assertEqual(cwd, root); self.assertEqual(timeout, 15); self.assertLessEqual(limit, 512 << 10)
                path = root / "private/provider-cache.stdout"; raw = path.read_bytes()
                path.rename(path.with_name("retained-original")); M.D.write(path, raw, 0o400)
                with self.assertRaisesRegex(M.D.Refused, "original provider output changed"):
                    M._provider_readback({}, {}, root, owner, directories, check.root, {}, proof, check.end)
                self.assertEqual(len(check.calls), 2)

    def test_first_consumer_error_changed_inputs_or_late_return_latches_before_successor(self):
        for fault in ("stderr", "partial", "private-output", "request", "owner", "changed-input", "late"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-provider-failure-inert-") as folder:
                check, root, owner, directories, control, state = provider_stage(folder, fault)
                clock, reads = [time.monotonic()], []
                def current(*args):
                    reads.append(None)
                    return {**state, "changed": True} if fault == "changed-input" and len(reads) > 1 else state
                original = check.private_command
                def command(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if fault == "late": clock[0] = check.end + 1
                    return result
                check.private_command = command
                with patch.object(M, "_provider_state", side_effect=current), patch.object(M, "_provider_control", return_value=control), \
                     patch.object(M.time, "monotonic", side_effect=lambda: clock[0]):
                    with self.assertRaises(ValueError): M._provider_consumers(check, {}, {}, root, owner, directories)
                    self.assertTrue(check.failed); self.assertEqual(len(check.calls), 1)
                    with self.assertRaisesRegex(M.D.Refused, "failure is latched"):
                        M._provider_consumers(check, {}, {}, root, owner, directories)
                    self.assertEqual(len(check.calls), 1)
                self.assertTrue((check.root / "private-material/android-provider-diagnostics.stdout").exists())
                if fault == "private-output": self.assertEqual((root / "tmp/unexpected").read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
