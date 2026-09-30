"""Focused DATA/workflow regressions; never start a Windows original on Linux."""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
import re
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("mrk_retained_fixture_ci", ROOT / "desktop/tools/windows_installer_fixture_ci.py")
assert SPEC is not None and SPEC.loader is not None
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


# Reuse the original DATA fixture factory and the real foundation module.
# No graph reader is extracted, and no declaration validator is replaced.
FOUNDATION_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "mrk_retained_fixture_foundation_contract", ROOT / "tests/desktop/test_ci_foundation_contract.py")
assert FOUNDATION_CONTRACT_SPEC is not None and FOUNDATION_CONTRACT_SPEC.loader is not None
foundation_contract = importlib.util.module_from_spec(FOUNDATION_CONTRACT_SPEC)
FOUNDATION_CONTRACT_SPEC.loader.exec_module(foundation_contract)
foundation = foundation_contract.helper

# Independent SOURCE-derived declaration and role DATA, not a catalog copied
# from either reader under test. Lock surplus is not active compiler permission.
INSTALLER_NATIVE_DECLARATIONS = {
    "runtime-publication": [],
    "installer-acquisition": ["dep:sha2"],
    "installer-selection": ["installer-acquisition", "runtime-publication",
        "windows-sys/Win32_System_Com_StructuredStorage", "windows-sys/Wdk_System_Registry"],
    "installer-selection-fixture": ["installer-selection", "installer-protected-fixture"],
    "installer-protected-fixture": ["installer-acquisition", "runtime-publication", "qualification-result"],
    "qualification-result": [],
    "image-writer": [],
    "image-stdio": ["image-writer"],
    "desktop-ui": ["dep:windows", "dep:webview2-com", "dep:windows-core"],
    "desktop-ui-dialogs": ["desktop-ui"],
    "windows-installed-observation": ["desktop-ui-dialogs"],
}
INSTALLER_NATIVE_SHA2_DECLARATION = {
    "name": "sha2", "source": "registry+https://github.com/rust-lang/crates.io-index",
    "req": "=0.10.9", "kind": None, "rename": None, "optional": True,
    "uses_default_features": True, "features": [],
    "target": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))',
    "registry": None,
}
INSTALLER_NATIVE_PACKAGES = {
    "mrk-windows-installed-native": "0.1.0", "windows-sys": "0.61.2", "windows-link": "0.2.1",
    "sha2": "0.10.9", "cfg-if": "1.0.5", "cpufeatures": "0.2.17", "digest": "0.10.7",
    "block-buffer": "0.10.4", "crypto-common": "0.1.7", "generic-array": "0.14.7",
    "typenum": "1.20.1", "version_check": "0.9.5",
}
INSTALLER_NATIVE_EDGES = {
    "mrk-windows-installed-native": ("sha2", "windows-sys"), "windows-sys": ("windows-link",),
    "windows-link": (), "sha2": ("cfg-if", "cpufeatures", "digest"), "cfg-if": (),
    "cpufeatures": (), "digest": ("block-buffer", "crypto-common"),
    "block-buffer": ("generic-array",), "crypto-common": ("generic-array", "typenum"),
    "generic-array": ("typenum", "version_check"), "typenum": (), "version_check": (),
}
INSTALLER_GRAPH_FEATURES = {
    "windows-installer-retained-shell-v1": {
        "native": ["installer-acquisition", "installer-protected-fixture", "qualification-result", "runtime-publication"],
        "app": ["windows-installer-acquisition", "windows-installer-profile", "windows-installer-protected-fixture"],
    },
    "windows-installer-selection-v1": {
        "native": ["installer-acquisition", "installer-protected-fixture", "installer-selection",
                   "installer-selection-fixture", "qualification-result", "runtime-publication"],
        "app": ["windows-installer-acquisition", "windows-installer-profile", "windows-installer-protected-fixture",
                "windows-installer-selection", "windows-installer-selection-fixture"],
    },
}
INSTALLER_APP_DECLARATIONS = {
    "windows-installer-acquisition": ["mrk-windows-installed-native/installer-acquisition"],
    "windows-installer-profile": ["windows-installer-acquisition", "mrk-windows-installed-native/runtime-publication"],
    "windows-installer-protected-fixture": ["windows-installer-profile", "mrk-windows-installed-native/installer-protected-fixture"],
    "windows-installer-selection": ["windows-installer-profile", "mrk-windows-installed-native/installer-selection"],
    "windows-installer-selection-fixture": ["windows-installer-selection", "windows-installer-protected-fixture",
                                          "mrk-windows-installed-native/installer-selection-fixture"],
}

# Complete native Cargo.lock DATA (34 packages), including inactive libc/UI.
# Source bytes SHA256: 3c142042bf67eeeb221c16607246d2cda7dfea5144d541bd051120d2d67bdebf
INSTALLER_NATIVE_LOCK34 = json.loads(r'''{
  "package": [
    {
      "checksum": "3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71",
      "dependencies": [
        "generic-array"
      ],
      "name": "block-buffer",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.10.4"
    },
    {
      "checksum": "4e7648175b45a9a48536d676f68d918270699102aa8dab5496df06904c914600",
      "name": "cfg-if",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "1.0.5"
    },
    {
      "checksum": "59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280",
      "dependencies": [
        "libc"
      ],
      "name": "cpufeatures",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.2.17"
    },
    {
      "checksum": "78c8292055d1c1df0cce5d180393dc8cce0abec0a7102adb6c7b1eef6016d60a",
      "dependencies": [
        "generic-array",
        "typenum"
      ],
      "name": "crypto-common",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.1.7"
    },
    {
      "checksum": "9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292",
      "dependencies": [
        "block-buffer",
        "crypto-common"
      ],
      "name": "digest",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.10.7"
    },
    {
      "checksum": "85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a",
      "dependencies": [
        "typenum",
        "version_check"
      ],
      "name": "generic-array",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.14.7"
    },
    {
      "checksum": "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2",
      "name": "libc",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.2.189"
    },
    {
      "dependencies": [
        "sha2",
        "webview2-com",
        "windows",
        "windows-core",
        "windows-sys"
      ],
      "name": "mrk-windows-installed-native",
      "version": "0.1.0"
    },
    {
      "checksum": "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9",
      "dependencies": [
        "unicode-ident"
      ],
      "name": "proc-macro2",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "1.0.107"
    },
    {
      "checksum": "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001",
      "dependencies": [
        "proc-macro2"
      ],
      "name": "quote",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "1.0.47"
    },
    {
      "checksum": "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283",
      "dependencies": [
        "cfg-if",
        "cpufeatures",
        "digest"
      ],
      "name": "sha2",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.10.9"
    },
    {
      "checksum": "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297",
      "dependencies": [
        "proc-macro2",
        "quote",
        "unicode-ident"
      ],
      "name": "syn",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "2.0.119"
    },
    {
      "checksum": "8593e8e72159ed2257d083c7a454a85cbf854f37a0966d8d483aff8c8a3ebcee",
      "dependencies": [
        "proc-macro2",
        "quote",
        "unicode-ident"
      ],
      "name": "syn",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "3.0.6"
    },
    {
      "checksum": "ec86235f5fcc2a73650310756d2ac5b138a5780bbbdfae3eeccec992c435ba4f",
      "dependencies": [
        "thiserror-impl"
      ],
      "name": "thiserror",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "2.0.20"
    },
    {
      "checksum": "bc04cd3e1236dd4a98afca4569f2deb3f120e5422a4023be2cb683f8486292af",
      "dependencies": [
        "proc-macro2",
        "quote",
        "syn 3.0.6"
      ],
      "name": "thiserror-impl",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "2.0.20"
    },
    {
      "checksum": "b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20",
      "name": "typenum",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "1.20.1"
    },
    {
      "checksum": "ab72a15cf68d77cb0987d3684aa8a45c5ef827e8cb49ee2f30bfd7ba2feb519f",
      "name": "unicode-ident",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "1.0.25"
    },
    {
      "checksum": "0b928f33d975fc6ad9f86c8f283853ad26bdd5b10b7f1542aa2fa15e2289105a",
      "name": "version_check",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.9.5"
    },
    {
      "checksum": "7130243a7a5b33c54a444e54842e6a9e133de08b5ad7b5861cd8ed9a6a5bc96a",
      "dependencies": [
        "webview2-com-macros",
        "webview2-com-sys",
        "windows",
        "windows-core",
        "windows-implement",
        "windows-interface"
      ],
      "name": "webview2-com",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.38.2"
    },
    {
      "checksum": "67a921c1b6914c367b2b823cd4cde6f96beec77d30a939c8199bb377cf9b9b54",
      "dependencies": [
        "proc-macro2",
        "quote",
        "syn 2.0.119"
      ],
      "name": "webview2-com-macros",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.8.1"
    },
    {
      "checksum": "381336cfffd772377d291702245447a5251a2ffa5bad679c99e61bc48bacbf9c",
      "dependencies": [
        "thiserror",
        "windows",
        "windows-core"
      ],
      "name": "webview2-com-sys",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.38.2"
    },
    {
      "checksum": "9babd3a767a4c1aef6900409f85f5d53ce2544ccdfaa86dad48c91782c6d6893",
      "dependencies": [
        "windows-collections",
        "windows-core",
        "windows-future",
        "windows-link 0.1.3",
        "windows-numerics"
      ],
      "name": "windows",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.61.3"
    },
    {
      "checksum": "3beeceb5e5cfd9eb1d76b381630e82c4241ccd0d27f1a39ed41b2760b255c5e8",
      "dependencies": [
        "windows-core"
      ],
      "name": "windows-collections",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.2.0"
    },
    {
      "checksum": "c0fdd3ddb90610c7638aa2b3a3ab2904fb9e5cdbecc643ddb3647212781c4ae3",
      "dependencies": [
        "windows-implement",
        "windows-interface",
        "windows-link 0.1.3",
        "windows-result",
        "windows-strings"
      ],
      "name": "windows-core",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.61.2"
    },
    {
      "checksum": "fc6a41e98427b19fe4b73c550f060b59fa592d7d686537eebf9385621bfbad8e",
      "dependencies": [
        "windows-core",
        "windows-link 0.1.3",
        "windows-threading"
      ],
      "name": "windows-future",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.2.1"
    },
    {
      "checksum": "053e2e040ab57b9dc951b72c264860db7eb3b0200ba345b4e4c3b14f67855ddf",
      "dependencies": [
        "proc-macro2",
        "quote",
        "syn 2.0.119"
      ],
      "name": "windows-implement",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.60.2"
    },
    {
      "checksum": "3f316c4a2570ba26bbec722032c4099d8c8bc095efccdc15688708623367e358",
      "dependencies": [
        "proc-macro2",
        "quote",
        "syn 2.0.119"
      ],
      "name": "windows-interface",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.59.3"
    },
    {
      "checksum": "5e6ad25900d524eaabdbbb96d20b4311e1e7ae1699af4fb28c17ae66c80d798a",
      "name": "windows-link",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.1.3"
    },
    {
      "checksum": "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5",
      "name": "windows-link",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.2.1"
    },
    {
      "checksum": "9150af68066c4c5c07ddc0ce30421554771e528bde427614c61038bc2c92c2b1",
      "dependencies": [
        "windows-core",
        "windows-link 0.1.3"
      ],
      "name": "windows-numerics",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.2.0"
    },
    {
      "checksum": "56f42bd332cc6c8eac5af113fc0c1fd6a8fd2aa08a0119358686e5160d0586c6",
      "dependencies": [
        "windows-link 0.1.3"
      ],
      "name": "windows-result",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.3.4"
    },
    {
      "checksum": "56e6c93f3a0c3b36176cb1327a4958a0353d5d166c2a35cb268ace15e91d3b57",
      "dependencies": [
        "windows-link 0.1.3"
      ],
      "name": "windows-strings",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.4.2"
    },
    {
      "checksum": "ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc",
      "dependencies": [
        "windows-link 0.2.1"
      ],
      "name": "windows-sys",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.61.2"
    },
    {
      "checksum": "b66463ad2e0ea3bbf808b7f1d371311c80e115c0b71d60efc142cafbcfb057a6",
      "dependencies": [
        "windows-link 0.1.3"
      ],
      "name": "windows-threading",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "version": "0.1.0"
    }
  ],
  "version": 4
}
''')


def installer_native_graph_data(qualification_profile, *, source=None, root=None):
    """Independent native12 Windows DATA; never invoke a validator to build it."""
    source = Path("/checkout") if source is None else source
    root = Path("/owned") if root is None else root
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    ids = {name: name + "@" + version for name, version in INSTALLER_NATIVE_PACKAGES.items()}
    packages, nodes = [], []
    for name, version in INSTALLER_NATIVE_PACKAGES.items():
        local = name == "mrk-windows-installed-native"
        manifest = (source / "desktop/native/windows-installed-native/Cargo.toml" if local else
                    root / "cargo/registry/src/fixed" / (name + "-" + version) / "Cargo.toml")
        declarations = [{
            "name": "windows-sys", "source": registry, "req": "=0.61.2", "kind": None,
            "rename": None, "optional": False, "uses_default_features": True, "features": [],
            "target": INSTALLER_NATIVE_SHA2_DECLARATION["target"], "registry": None,
        }, copy.deepcopy(INSTALLER_NATIVE_SHA2_DECLARATION)] if local else []
        packages.append({"id": ids[name], "name": name, "version": version, "source": None if local else registry,
            "manifest_path": str(manifest), "features": copy.deepcopy(INSTALLER_NATIVE_DECLARATIONS) if local else {},
            "dependencies": declarations,
            "targets": [{"name": name.replace("-", "_"), "kind": ["lib"], "crate_types": ["lib"],
                         "src_path": str(manifest.parent / "src/lib.rs")}]})
        children = INSTALLER_NATIVE_EDGES[name]
        nodes.append({"id": ids[name],
            "features": list(INSTALLER_GRAPH_FEATURES[qualification_profile]["native"]) if local else [],
            "dependencies": [ids[child] for child in children],
            "deps": [{"pkg": ids[child], "name": child.replace("-", "_"), "dep_kinds": [{
                "kind": "build" if name == "generic-array" and child == "version_check" else None,
                "target": INSTALLER_NATIVE_SHA2_DECLARATION["target"] if local else None,
            }]} for child in children]})
    native = ids["mrk-windows-installed-native"]
    value = {"version": 1, "packages": packages, "resolve": {"root": native, "nodes": nodes},
             "workspace_root": str(source / "desktop/native/windows-installed-native"),
             "workspace_members": [native], "workspace_default_members": [native],
             "target_directory": str(root / "target")}
    return value, copy.deepcopy(INSTALLER_NATIVE_LOCK34), source, root


def installer_app_graph_data(qualification_profile):
    """Select installer roles in the original core app DATA factory, not a stub."""
    value, lock, c = foundation_contract.WindowsReaderGateTests.graph_data(publication=False, normal_units=False)
    source, root = Path(c["source"]), Path(c["root"])
    native_value, native_lock, _, _ = installer_native_graph_data(qualification_profile, source=source, root=root)
    # Preserve the original native package's declarations, including its exact
    # optional SHA2 row. Only the installer resolve closure gains the SHA2 edge.
    packages = {row["id"]: row for row in value["packages"]}
    for row in native_value["packages"]:
        if row["id"] not in packages:
            value["packages"].append(copy.deepcopy(row))
    nodes = {row["id"]: row for row in value["resolve"]["nodes"]}
    for row in native_value["resolve"]["nodes"]:
        if row["id"] in nodes:
            nodes[row["id"]].update(copy.deepcopy(row))
        else:
            value["resolve"]["nodes"].append(copy.deepcopy(row))
    app = value["resolve"]["root"]
    packages[app]["features"].update(copy.deepcopy(INSTALLER_APP_DECLARATIONS))
    nodes[app]["features"] = list(INSTALLER_GRAPH_FEATURES[qualification_profile]["app"])
    # Keep the app's independent direct SHA2 edge and complete native lock
    # surplus. Inactive lock rows do not become metadata packages or nodes.
    locked = {(row["name"], row["version"], row.get("source")) for row in lock["package"]}
    for row in native_lock["package"]:
        key = (row["name"], row["version"], row.get("source"))
        if key not in locked:
            lock["package"].append(copy.deepcopy(row))
            locked.add(key)
    return value, lock, source, root


def installer_native_package(value):
    return next(row for row in value["packages"] if row["name"] == "mrk-windows-installed-native")


def context():
    return {"qualificationProfile": ci.PROFILE, "ref": ci.REF, "attempt": 1, "event": "workflow_dispatch",
            "scope": "windows-installed-native-v1", "sourceSha": "a"*40, "sourceTree": "b"*40, "runId": "19"}


def test_output(extra=""):
    return ("running 1 test\n" + extra
            + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.05s\n").encode()


def profile():
    return {"inputs": [{"size": 64, "sha256": "d"*64} for _ in range(54)]}


class RetainedFixtureDataTests(unittest.TestCase):
    def test_fixed_order_keeps_last_corruption_and_all_sixteen_originals(self):
        self.assertEqual(len(ci.CHAIN), 16)
        self.assertEqual(ci.CHAIN[:3], (("fresh", "stage"), ("fresh", "app"), ("fresh", "observe")))
        self.assertEqual(ci.CHAIN[-4:], (("bad-manifest", "stage"), ("bad-manifest", "corrupt"),
                                         ("bad-manifest", "app"), ("bad-manifest", "observe")))
        self.assertEqual(len({ci.selector(*pair) for pair in ci.CHAIN}), 16)
        with self.assertRaises(ci.FixtureError):
            ci.selector("fresh", "corrupt")
        with self.assertRaises(ci.FixtureError):
            ci.selector("bad-manifest", "repair")

    def test_route_does_not_accept_legacy_wrong_attempt_or_shipping_scope(self):
        expected = ci.binding(context())
        self.assertEqual(expected["profile"], ci.PROFILE)
        for key, value in (("qualificationProfile", "windows-installed-passive-v1"),
                           ("ref", "refs/heads/main"), ("attempt", 2), ("event", "push"), ("scope", "foundation")):
            bad = {**context(), key: value}
            with self.subTest(key=key), self.assertRaises(ci.FixtureError):
                ci.binding(bad)

    def test_outcomes_require_actual_all_success_and_reject_duplicate_or_extra_records(self):
        names = tuple(case+"-"+role for case, role in ci.CHAIN)
        good = dict.fromkeys(names, "success")
        self.assertEqual(ci.outcomes(json.dumps(good), names), good)
        for state in ("failure", "cancelled", "skipped", "queued", ""):
            with self.subTest(state=state), self.assertRaises(ci.FixtureError):
                ci.outcomes(json.dumps({**good, names[4]: state}), names)
        for bad in ({**good, "repair": "success"}, {k: v for k, v in good.items() if k != names[0]}):
            with self.assertRaises(ci.FixtureError):
                ci.outcomes(json.dumps(bad), names)
        with self.assertRaises(ci.FixtureError):
            ci.outcomes('{"fresh-stage":"success","fresh-stage":"success"}', ("fresh-stage",))

    def test_closed_wire_refuses_reordering_duplicates_cr_and_trailing_lines(self):
        raw = ci.encoded_wire("FRAME", ("a", "b"), {"a": "one", "b": "two"})
        self.assertEqual(ci.wire(raw, "FRAME", ("a", "b")), {"a": "one", "b": "two"})
        for bad in (b"FRAME\nb=two\na=one\n", b"FRAME\na=one\na=two\n", raw+b"\n",
                    raw.replace(b"\n", b"\r\n"), raw[:-1], raw.replace(b"one", b"one=two")):
            with self.subTest(raw=bad), self.assertRaises(ci.FixtureError):
                ci.wire(bad, "FRAME", ("a", "b"))

    def test_original_exit_binds_actual_bytes_selector_and_closure(self):
        c = context()
        pre = {"appArtifact": r"C:\owned\mobile_release_desktop-aaaaaaaaaaaaaaaa.exe",
               "appArtifactSha256": "d"*64}
        raw_result = test_output()
        values = {**ci.binding(c), "role": "fresh-app", "artifactSha256": "d"*64,
            "precheckSha256": "e"*64, "commandSha256": ci.command_sha(pre["appArtifact"], "fresh", "app"),
            "resultBytes": str(len(raw_result)), "resultSha256": ci.sha(raw_result),
            "originalWaitReturned": "true", "exitCode": "0", "writerCloseGate": "original-owner-closed-output"}
        encoded = ci.encoded_wire(ci.EXIT_HEADER, ci.EXIT_KEYS, values)
        self.assertEqual(ci.exit_record(encoded, c, pre, "e"*64, "fresh", "app", raw_result), values)
        for key, value in (("role", "reuse-app"), ("originalWaitReturned", "false"), ("exitCode", "1"),
                           ("writerCloseGate", "claimed"), ("commandSha256", "f"*64), ("resultBytes", "1")):
            bad = ci.encoded_wire(ci.EXIT_HEADER, ci.EXIT_KEYS, {**values, key: value})
            with self.subTest(key=key), self.assertRaises(ci.FixtureError):
                ci.exit_record(bad, c, pre, "e"*64, "fresh", "app", raw_result)

    def test_zero_tests_and_duplicate_success_are_not_behavioral_evidence(self):
        ci.libtest(test_output())
        for raw in (test_output().replace(b"1 test", b"0 tests"), test_output()*2,
                    test_output().replace(b"1 passed", b"0 passed"), b"x"*65537):
            with self.assertRaises(ci.FixtureError):
                ci.libtest(raw)

    def test_app_lifecycle_requires_real_counts_no_failed_activation_and_watchdog_join(self):
        p = profile()
        proof = {"case": "fresh", "rows": "54", "sourceRead": str(64*54), "confirmedWritten": str(64*54),
                 "readbackRead": str(64*54), "prerequisite": "already-present", "runtime": "published-new",
                 "activation": "true", "roles": "63", "transitions": "63",
                 "originalWatchdogJoined": "true", "nativeSettled": "true"}
        def render(value):
            return test_output(ci.APP_PREFIX + ";".join(key+"="+value[key] for key in ci.APP_KEYS))
        self.assertEqual(ci.app_record(render(proof), "fresh", p), proof)
        for key, value in (("sourceRead", "0"), ("nativeSettled", "false"), ("originalWatchdogJoined", "false"),
                           ("activation", "false"), ("transitions", "56"), ("runtime", "reused-existing")):
            with self.subTest(key=key), self.assertRaises(ci.FixtureError):
                ci.app_record(render({**proof, key: value}), "fresh", p)
        stopped = {**proof, "case": "stop-copy", "rows": "0", "sourceRead": "129", "confirmedWritten": "1",
                   "readbackRead": "0", "prerequisite": "not-started", "runtime": "not-started",
                   "activation": "false", "roles": "0", "transitions": "0"}
        ci.app_record(render(stopped), "stop-copy", p)
        with self.assertRaises(ci.FixtureError):
            ci.app_record(render({**stopped, "confirmedWritten": "0"}), "stop-copy", p)

    def test_probe_refusals_are_never_behavioral_acceptance(self):
        c = context()
        for name in ci.PROBES:
            value = ci.probe_value(c, name, "d"*64)
            self.assertFalse(value["behavioralAcceptance"])
            self.assertTrue(value["bothEof"] and value["readersClosed"] and value["writersClosed"] and value["processClosed"])
            self.assertEqual(value["exitCode"], 0)
        overflow = ci.probe_value(c, "overflow", "d"*64)
        self.assertEqual(overflow["stdoutObserved"], 81920)
        self.assertEqual(overflow["stdoutBytes"], 65536)
        self.assertEqual(overflow["errors"], ["aggregate-overflow", "stdout-overflow"])
        writer = ci.probe_value(c, "writer-fault", "d"*64)
        self.assertEqual(writer["stdoutObserved"], 30720)
        self.assertEqual(writer["stdoutBytes"], 0)
        self.assertEqual(writer["stderrBytes"], 30720)
        self.assertEqual(writer["errors"], ["stdout-write"])

    def test_compile_argv_has_only_closed_features_and_never_executes_native(self):
        f = SimpleNamespace(WINDOWS_INSTALLED_CRATE="desktop/native/windows-installed-native", WINDOWS_INSTALLED_APP="desktop/src-tauri")
        c = {**context(), "source": str(ROOT), "root": str(ROOT / "unused-data-only-root")}
        for role, feature in ci.SELECTED_FEATURES.items():
            argv = ci.compile_argv(f, c, "cargo", role)
            self.assertIn("--no-run", argv)
            self.assertIn("--offline", argv)
            self.assertEqual(argv[argv.index("--features")+1], feature)
            self.assertEqual(argv[argv.index("--jobs")+1], "1")
            self.assertNotIn("--ignored", argv)
            self.assertNotIn("desktop-shell", ",".join(argv))
        with self.assertRaises(ci.FixtureError):
            ci.compile_argv(f, c, "cargo", "publisher")
        with self.assertRaises(ci.FixtureError):
            ci.metadata_argv(f, c, "cargo", "publisher")

    def test_snapshot_rosters_cover_retained_old_image_partial_and_final_manifest(self):
        profiles = dict.fromkeys(ci.CASES, profile())
        fresh = ci.snapshot_members("fresh", "observe", profiles)
        reuse = ci.snapshot_members("reuse", "observe", profiles)
        self.assertEqual(len(fresh), 110)
        self.assertEqual(reuse[:len(fresh)], fresh)
        self.assertEqual(len(reuse), 171)
        self.assertEqual(len(ci.snapshot_members("stop-copy", "observe", profiles)), 8)
        self.assertEqual(ci.snapshot_members("bad-manifest", "corrupt", profiles)[0][0], "d/f/7")
        self.assertEqual(ci.snapshot_members("bad-manifest", "observe", profiles)[-1][0], "d/f/7")


    def test_native_graph_rejects_unreviewed_features_dependencies_sources_and_units(self):
        f = foundation
        value, lock, source, root = installer_native_graph_data(ci.PROFILE)
        self.assertEqual(len(ci.native_graph(f, value, lock, source=source, root=root)["nodes"]), 12)
        for mutate in (
            lambda bad: bad["resolve"]["nodes"][0]["features"].append("desktop-ui"),
            lambda bad: bad["resolve"]["nodes"][0]["dependencies"].clear(),
            lambda bad: bad["packages"][1].update(source="git+https://unreviewed.invalid/source"),
            lambda bad: bad["packages"][0]["targets"].append({"name": "unexpected", "kind": ["bin"], "crate_types": ["bin"], "src_path": str(source / "elsewhere.rs")}),
            lambda bad: bad["packages"].append(copy.deepcopy(bad["packages"][1])),
        ):
            bad = copy.deepcopy(value)
            mutate(bad)
            with self.assertRaises(ci.FixtureError):
                ci.native_graph(f, bad, lock, source=source, root=root)

    def test_installer_graph_profiles_keep_sha2_and_full_native_lock_surplus(self):
        self.assertEqual(foundation.WINDOWS_NATIVE_DECLARED_FEATURES, INSTALLER_NATIVE_DECLARATIONS)
        self.assertEqual(ci.declared_native_features(foundation), INSTALLER_NATIVE_DECLARATIONS)
        self.assertIsNot(ci.declared_native_features(foundation), foundation.WINDOWS_NATIVE_DECLARED_FEATURES)
        self.assertEqual(ci.NATIVE_PACKAGES, INSTALLER_NATIVE_PACKAGES)
        self.assertEqual(ci.NATIVE_EDGES, {name: set(children) for name, children in INSTALLER_NATIVE_EDGES.items()})
        self.assertNotIn("sha2", INSTALLER_NATIVE_DECLARATIONS)
        for qualification_profile, features in INSTALLER_GRAPH_FEATURES.items():
            for role, factory, reader in (
                ("native", installer_native_graph_data, ci.native_graph),
                ("app", installer_app_graph_data, ci.app_graph),
            ):
                with self.subTest(profile=qualification_profile, role=role):
                    value, lock, source, root = factory(qualification_profile)
                    native_package = installer_native_package(value)
                    self.assertIs(foundation.windows_native_declarations_valid(native_package), True)
                    self.assertEqual(native_package["features"], INSTALLER_NATIVE_DECLARATIONS)
                    self.assertEqual([row for row in native_package["dependencies"] if row["name"] == "sha2"],
                                     [INSTALLER_NATIVE_SHA2_DECLARATION])
                    graph = reader(foundation, value, lock, source=source, root=root, profile=qualification_profile)
                    native = native_package["id"]
                    self.assertEqual(graph["nodes"][native]["features"], features["native"])
                    self.assertEqual({(graph["packages"][key]["name"], graph["packages"][key]["version"])
                                      for key in graph["nodes"][native]["dependencies"]},
                                     {("sha2", "0.10.9"), ("windows-sys", "0.61.2")})
                    self.assertFalse(set(features["native"]) & {
                        "sha2", "image-writer", "image-stdio", "desktop-ui", "desktop-ui-dialogs",
                        "windows-installed-observation"})
                    self.assertNotIn("libc", {row["name"] for row in graph["packages"].values()})
                    if role == "native":
                        locked = {(row["name"], row["version"]) for row in lock["package"]}
                        active = {(row["name"], row["version"]) for row in graph["packages"].values()}
                        self.assertEqual(len(lock["package"]), 34)
                        self.assertEqual(len(locked), 34)
                        self.assertEqual(len(graph["nodes"]), 12)
                        self.assertEqual(active, set(INSTALLER_NATIVE_PACKAGES.items()))
                        self.assertEqual(len(locked - active), 22)
                        self.assertIn(("libc", "0.2.189"), locked)
                        cpu = next(row for row in lock["package"] if row["name"] == "cpufeatures")
                        self.assertEqual(cpu["dependencies"], ["libc"])
                        self.assertEqual(graph["nodes"]["cpufeatures@0.2.17"]["dependencies"], [])
                    else:
                        app = graph["appId"]
                        self.assertEqual(graph["nodes"][app]["features"], features["app"])
                        sha2 = next(key for key, row in graph["packages"].items() if row["name"] == "sha2")
                        self.assertIn(sha2, graph["nodes"][app]["dependencies"])
                        self.assertIn(sha2, graph["nodes"][native]["dependencies"])

    def test_installer_graphs_refuse_native_optional_sha2_declaration_drift(self):
        mutations = [
            ("missing-dependencies", lambda package: package.pop("dependencies")),
            ("null-dependencies", lambda package: package.update(dependencies=None)),
            ("map-dependencies", lambda package: package.update(dependencies={})),
            ("empty-dependencies", lambda package: package.update(dependencies=[])),
            ("non-map-dependency", lambda package: package["dependencies"].append(None)),
            ("non-string-name", lambda package: package["dependencies"].append({"name": True})),
            ("oversized-dependencies", lambda package: package["dependencies"].extend({"name": "unused"} for _ in range(255))),
            ("missing-sha2", lambda package: package.update(dependencies=[
                row for row in package["dependencies"] if row["name"] != "sha2"])),
            ("duplicate-sha2", lambda package: package["dependencies"].append(copy.deepcopy(INSTALLER_NATIVE_SHA2_DECLARATION))),
            ("renamed-sha2-collision", lambda package: package["dependencies"].append({
                **copy.deepcopy(INSTALLER_NATIVE_SHA2_DECLARATION), "name": "other-digest", "rename": "sha2"})),
            ("missing-acquisition", lambda package: package["features"].pop("installer-acquisition")),
            ("empty-acquisition-overlay", lambda package: package["features"].update({"installer-acquisition": []})),
            ("implicit-sha2-feature", lambda package: package["features"].update({"sha2": ["dep:sha2"]})),
            ("extra-default-feature", lambda package: package["features"].update({"default": []})),
            ("image-acquires-sha2", lambda package: package["features"].update({"image-writer": ["dep:sha2"]})),
        ]
        for field, replacement in (
            ("name", "not-sha2"), ("source", None), ("source", "git+https://unreviewed.invalid/sha2"),
            ("req", "^0.10.9"), ("req", "=0.10.8"), ("kind", "build"), ("kind", "dev"),
            ("rename", "digest_alias"), ("optional", False), ("optional", 1),
            ("uses_default_features", False), ("uses_default_features", 1),
            ("features", ["std"]), ("target", None), ("target", 'cfg(target_os = "windows")'),
            ("target", 'cfg(target_os = "linux")'), ("registry", "unreviewed"), ("path", "/other/sha2"),
        ):
            def change(package, field=field, replacement=replacement):
                row = next(row for row in package["dependencies"] if row["name"] == "sha2")
                row[field] = copy.deepcopy(replacement)
            mutations.append((field + "=" + repr(replacement), change))
        for field in INSTALLER_NATIVE_SHA2_DECLARATION:
            def remove(package, field=field):
                row = next(row for row in package["dependencies"] if row["name"] == "sha2")
                row.pop(field)
            mutations.append(("missing-sha2-field-" + field, remove))
        for qualification_profile in INSTALLER_GRAPH_FEATURES:
            for role, factory, reader in (
                ("native", installer_native_graph_data, ci.native_graph),
                ("app", installer_app_graph_data, ci.app_graph),
            ):
                value, lock, source, root = factory(qualification_profile)
                reader(foundation, value, lock, source=source, root=root, profile=qualification_profile)
                for label, mutate in mutations:
                    bad = copy.deepcopy(value)
                    package = installer_native_package(bad)
                    mutate(package)
                    with self.subTest(profile=qualification_profile, role=role, mutation=label):
                        self.assertIs(foundation.windows_native_declarations_valid(package), False)
                        with self.assertRaises(ci.FixtureError):
                            reader(foundation, bad, lock, source=source, root=root, profile=qualification_profile)

    def test_installer_graphs_keep_native_and_app_sha2_edges_independent(self):
        for qualification_profile in INSTALLER_GRAPH_FEATURES:
            for role, factory, reader in (
                ("native", installer_native_graph_data, ci.native_graph),
                ("app", installer_app_graph_data, ci.app_graph),
            ):
                value, lock, source, root = factory(qualification_profile)
                reader(foundation, value, lock, source=source, root=root, profile=qualification_profile)
                native = installer_native_package(value)["id"]
                sha2 = next(row["id"] for row in value["packages"] if row["name"] == "sha2")
                nodes = {row["id"]: row for row in value["resolve"]["nodes"]}
                bad = copy.deepcopy(value)
                native_node = next(row for row in bad["resolve"]["nodes"] if row["id"] == native)
                native_node["dependencies"].remove(sha2)
                native_node["deps"] = [edge for edge in native_node["deps"] if edge["pkg"] != sha2]
                reason = "Native resolved edges differ" if role == "native" else "Windows app native dependency differs"
                with self.subTest(profile=qualification_profile, role=role, missing="native-sha2"):
                    if role == "app":
                        app = value["resolve"]["root"]
                        self.assertIn(sha2, nodes[app]["dependencies"])
                        # All metadata remains reachable from app-own SHA2: the
                        # refusal must be the native role, not disconnected DATA.
                        changed = {row["id"]: row for row in bad["resolve"]["nodes"]}
                        seen, pending = set(), [app]
                        while pending:
                            current = pending.pop()
                            if current not in seen:
                                seen.add(current)
                                pending.extend(changed[current]["dependencies"])
                        self.assertEqual(seen, set(changed))
                    with self.assertRaisesRegex(ci.FixtureError, reason):
                        reader(foundation, bad, lock, source=source, root=root, profile=qualification_profile)
                if role == "app":
                    # Conversely, native SHA2 cannot satisfy the app's own
                    # independent direct dependency contract.
                    bad = copy.deepcopy(value)
                    app_node = next(row for row in bad["resolve"]["nodes"] if row["id"] == value["resolve"]["root"])
                    app_node["dependencies"].remove(sha2)
                    app_node["deps"] = [edge for edge in app_node["deps"] if edge["pkg"] != sha2]
                    self.assertIn(sha2, nodes[native]["dependencies"])
                    with self.subTest(profile=qualification_profile, role=role, missing="app-sha2"), \
                            self.assertRaisesRegex(ci.FixtureError, "Windows app selected direct dependencies differ"):
                        reader(foundation, bad, lock, source=source, root=root, profile=qualification_profile)

    def test_installer_graph_profiles_refuse_ui_image_activation_and_native_lock_surplus(self):
        for qualification_profile in INSTALLER_GRAPH_FEATURES:
            for role, factory, reader in (
                ("native", installer_native_graph_data, ci.native_graph),
                ("app", installer_app_graph_data, ci.app_graph),
            ):
                value, lock, source, root = factory(qualification_profile)
                for feature in ("image-writer", "image-stdio", "desktop-ui", "desktop-ui-dialogs",
                                "windows-installed-observation"):
                    bad = copy.deepcopy(value)
                    native = installer_native_package(bad)["id"]
                    node = next(row for row in bad["resolve"]["nodes"] if row["id"] == native)
                    node["features"] = sorted([*node["features"], feature])
                    with self.subTest(profile=qualification_profile, role=role, feature=feature), \
                            self.assertRaises(ci.FixtureError):
                        reader(foundation, bad, lock, source=source, root=root, profile=qualification_profile)
                if role == "native":
                    for name, version in (("libc", "0.2.189"), ("windows", "0.61.3"),
                                          ("windows-link", "0.1.3"), ("webview2-com", "0.38.2")):
                        bad = copy.deepcopy(value)
                        row = next(row for row in lock["package"] if (row["name"], row["version"]) == (name, version))
                        package_id = name + "@" + version
                        manifest = root / "cargo/registry/src/fixed" / (package_id.replace("@", "-")) / "Cargo.toml"
                        bad["packages"].append({"id": package_id, "name": name, "version": version,
                            "source": row["source"], "manifest_path": str(manifest), "features": {},
                            "targets": [{"kind": ["lib"], "crate_types": ["lib"],
                                         "src_path": str(manifest.parent / "src/lib.rs")}]})
                        bad["resolve"]["nodes"].append({"id": package_id, "features": [], "dependencies": [], "deps": []})
                        with self.subTest(profile=qualification_profile, surplus=package_id), \
                                self.assertRaisesRegex(ci.FixtureError, "Fixture native package inventory differs"):
                            ci.native_graph(foundation, bad, lock, source=source, root=root, profile=qualification_profile)

    def test_native_test_path_defers_executable_admission_until_complete_stream(self):
        def stream(*rows):
            return b"".join((row if type(row) is bytes else json.dumps(row, sort_keys=True).encode("utf-8"))
                            + b"\n" for row in rows)

        for qualification_profile in INSTALLER_GRAPH_FEATURES:
            value, lock, source, root = installer_native_graph_data(qualification_profile)
            # Minimal platform DATA for the real unit-feature reader. The older
            # graph-only fixture does not need this map; do not stub the reader.
            platform = next(row for row in value["packages"] if row["name"] == "windows-sys")
            platform["features"] = {
                "default": [], "Win32_System_Com_StructuredStorage": [], "Wdk_System_Registry": [],
            }
            platform_node = next(row for row in value["resolve"]["nodes"] if row["id"] == platform["id"])
            platform_node["features"] = (["default"] if qualification_profile == ci.PROFILE
                                         else sorted(platform["features"]))
            graph = ci.native_graph(foundation, value, lock, source=source, root=root,
                                    profile=qualification_profile)
            native = graph["nativeId"]
            package = graph["packages"][native]
            admitted_path = root / "target" / "x86_64-pc-windows-msvc/debug/deps/native-fixture.exe"
            artifact = {
                "reason": "compiler-artifact", "package_id": native,
                "target": copy.deepcopy(package["targets"][0]),
                "profile": {"test": True, "debug_assertions": True},
                "features": list(INSTALLER_GRAPH_FEATURES[qualification_profile]["native"]),
                "manifest_path": package["manifest_path"], "fresh": False, "executable": str(admitted_path),
            }
            diagnostic = {"reason": "compiler-message", "package_id": native,
                          "target": copy.deepcopy(package["targets"][0])}
            terminal = {"reason": "build-finished", "success": True}
            accepted = stream(artifact, diagnostic, terminal)
            trace = mock.Mock()
            with self.subTest(profile=qualification_profile, case="complete-success"):
                with mock.patch.object(foundation, "bounded_json", wraps=foundation.bounded_json) as parsed, \
                        mock.patch.object(foundation, "ordinary_windows_executable",
                                          return_value=admitted_path) as admission:
                    trace.attach_mock(parsed, "parse")
                    trace.attach_mock(admission, "admit")
                    self.assertIs(ci.native_test_path(foundation, accepted, graph, root=root, source=source),
                                  admitted_path)
                admission.assert_called_once_with(str(admitted_path), target_root=root / "target")
                self.assertEqual(trace.mock_calls,
                                 [mock.call.parse(line, 2 << 20) for line in accepted.splitlines()]
                                 + [mock.call.admit(str(admitted_path), target_root=root / "target")])

            refused = [
                ("missing-terminal", stream(artifact, diagnostic), ci.FixtureError,
                 "No complete successful native compiler artifact"),
                ("failed-terminal", stream(artifact, diagnostic, {"reason": "build-finished", "success": False}),
                 ci.FixtureError, "Original compiler failed"),
                ("missing-success", stream(artifact, {"reason": "build-finished"}),
                 ci.FixtureError, "Original compiler failed"),
                ("nonboolean-success", stream(artifact, {"reason": "build-finished", "success": 1}),
                 ci.FixtureError, "Original compiler failed"),
                ("duplicate-candidate", stream(artifact, copy.deepcopy(artifact), terminal),
                 ci.FixtureError, "Wrong original native executable"),
                ("forbidden-unit", stream(artifact, {**artifact, "package_id": "libc@0.2.189"}, terminal),
                 ci.FixtureError, "Compiler unit is not in fixed native graph"),
                ("late-feature-drift", stream(artifact, {**artifact, "executable": None,
                                                        "features": ["desktop-ui"]}, terminal),
                 ci.FixtureError, "Native compiler unit features/source differ"),
                ("late-target-drift", stream(artifact, {**artifact, "target": {
                    **artifact["target"], "kind": ["bin"]}}, terminal),
                 ci.FixtureError, "Native compiler target differs"),
                ("malformed-record", stream(artifact, [], terminal),
                 ci.FixtureError, "Compiler message differs"),
                ("unknown-reason", stream(artifact, {"reason": "unreviewed"}, terminal),
                 ci.FixtureError, "Compiler message differs"),
                ("malformed-json", stream(artifact, b'{"reason":', terminal),
                 foundation.CheckFailure, "Invalid fixed JSON encoding"),
                ("duplicate-json-key", stream(artifact,
                    b'{"reason":"build-finished","reason":"build-finished","success":true}'),
                 foundation.CheckFailure, "Invalid fixed JSON encoding"),
                ("post-terminal-artifact", stream(artifact, terminal, artifact),
                 ci.FixtureError, "Native compiler output follows final result"),
                ("duplicate-terminal", stream(artifact, terminal, terminal),
                 ci.FixtureError, "Native compiler output follows final result"),
                ("trailing-malformed-data", stream(artifact, terminal, b"not JSON"),
                 ci.FixtureError, "Native compiler output follows final result"),
                ("trailing-blank-line", stream(artifact, terminal) + b"\n",
                 ci.FixtureError, "Native compiler output follows final result"),
            ]
            for label, raw, error, reason in refused:
                with self.subTest(profile=qualification_profile, case=label):
                    with mock.patch.object(foundation, "ordinary_windows_executable",
                                           return_value=admitted_path) as admission:
                        with self.assertRaisesRegex(error, reason):
                            ci.native_test_path(foundation, raw, graph, root=root, source=source)
                    admission.assert_not_called()


class RetainedOwnerSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner = (ROOT / "desktop/tools/windows_installer_fixture_owner.ps1").read_text()
        cls.workflow = (ROOT / ".github/workflows/desktop-foundation.yml").read_text()
        cls.foundation = (ROOT / "desktop/tools/ci_foundation.py").read_text()

    def test_module_compiler_labels_complete_the_foundation_allowlist(self):
        wanted = {
            "acquire": "retained-compiler-acquire",
            "native-metadata": "retained-native-locked-metadata",
            "app-metadata": "retained-app-locked-metadata",
            "native-compile": "retained-native-compile-only",
            "app-compile": "retained-app-compile-only",
        }
        self.assertEqual(ci.COMPILER_CHECKS, wanted)
        foundation = ast.parse(self.foundation)
        assignments = {target.id: node.value for node in foundation.body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
        labels = assignments["WINDOWS_RETAINED_TOOL_CHECKS"]
        self.assertIsInstance(labels, ast.Call)
        self.assertEqual(ast.unparse(labels.func), "frozenset")
        self.assertEqual(ast.literal_eval(labels.args[0]), set(wanted.values()))
        self.assertIsInstance(assignments["TOOL_CHECKS"], ast.BinOp)
        self.assertIsInstance(assignments["TOOL_CHECKS"].op, ast.BitOr)
        self.assertEqual(ast.unparse(assignments["TOOL_CHECKS"].right), "WINDOWS_RETAINED_TOOL_CHECKS")
        source = (ROOT / "desktop/tools/windows_installer_fixture_ci.py").read_text()
        module = ast.parse(source)
        calls = [node for node in ast.walk(module) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                 and node.func.value.id == "f" and node.func.attr == "run"]
        self.assertEqual(len(calls), 3)
        checks = {ast.unparse(next(keyword.value for keyword in call.keywords if keyword.arg == "check"))
                  for call in calls}
        self.assertEqual(checks, {"COMPILER_CHECKS['acquire']", "COMPILER_CHECKS[role + '-metadata']",
                                 "COMPILER_CHECKS[role + '-compile']"})
        for name in ("acquire", "compile_only"):
            function = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name)
            roles = [node for node in function.body if isinstance(node, ast.For)
                     and isinstance(node.target, ast.Name) and node.target.id == "role"]
            self.assertEqual(len(roles), 1)
            self.assertEqual(ast.literal_eval(roles[0].iter), ("native", "app"))

    def test_actual_owner_has_one_original_and_two_finite_raw_slots(self):
        owner = self.owner
        self.assertEqual(owner.count("$process.Start()"), 1)
        self.assertEqual(owner.count("$process.WaitForExit()"), 1)
        self.assertEqual(owner.count("Buffer=[byte[]]::new(4096)"), 2)
        self.assertIn("[Threading.Tasks.Task]::WaitAny", owner)
        self.assertIn("$slot.Task.GetAwaiter().GetResult()", owner)
        self.assertIn("$slot.Task = $null", owner)
        self.assertIn("$info.Environment.Clear()", owner)
        for forbidden in (".ReadLine(", ".ReadToEnd(", ".BeginOutputReadLine(", "Start-Process", ".Kill(", "Get-Process", "2>&1"):
            self.assertNotIn(forbidden, owner)
        charge = owner.index("$slot.Retained += $keep; $aggregate += $keep")
        self.assertLess(charge, owner.index("$slot.Writer.Write($slot.Buffer, 0, $keep)"))
        self.assertIn("$script:OriginalCustody = @{ Process=$process; Slots=$slots; Errors=$errors }", owner)
        self.assertIn("$script:OriginalUnknown = $true", owner)
        self.assertEqual(owner.count("FinalityUnknown=$true; Errors=$errors"), 3)
        self.assertIn("ReaderCloseAttempted=$false", owner)
        self.assertIn("WriterCloseAttempted=$false", owner)
        self.assertIn("$slot.Reader.Dispose(); $slot.ReaderClosed = $true", owner)
        self.assertIn("$slot.Writer.Dispose(); $slot.WriterClosed = $true", owner)
        self.assertIn("if ($script:InputCloseAttempted) { return }", owner)
        self.assertIn("$slot.Reader.Dispose()", owner)
        self.assertIn("$slot.Writer.Flush($true)", owner)
        self.assertIn("$slot.Writer.Dispose()", owner)
        self.assertIn("$process.Dispose()", owner)
        self.assertLess(owner.index("Close-RetainedInputs\n  Require-Retained"), owner.index("Write-RetainedReceipt $receiptPath $receipt"))

    def test_real_writer_fault_uses_original_sink_and_common_drain_not_fake_receipt(self):
        owner = self.owner
        injection = owner.index("$Role -ceq 'probe-writer-fault'")
        write = owner.index("$slot.Writer.Write($slot.Buffer, 0, $keep)")
        self.assertLess(owner.index("$slot.Writer.Dispose()", injection), write)
        self.assertIn("$errors[$slot.Name + '-write'] = $true", owner)
        self.assertIn("$slot.Reader.BaseStream.ReadAsync($slot.Buffer, 0, 4096)", owner[write:])
        self.assertIn("$r.Slots[0].Eof -and $r.Slots[1].Eof", owner)
        self.assertIn("$r.Started -and $r.WaitReturned -and $r.ExitCode -eq 0 -and $r.ProcessClosed", owner)

    def test_workflow_serial_finality_and_profile_isolation(self):
        steps = self.workflow.split("\n      - name: ")
        by_id = {}
        for step in steps:
            for line in step.splitlines():
                if line.startswith("        id: retained-"):
                    by_id[line.strip().removeprefix("id: ")] = step
        previous = "retained-precheck"
        for case, role in ci.CHAIN:
            identity = "retained-"+case+"-"+role
            step = by_id[identity]
            self.assertIn("timeout-minutes: 3", step)
            self.assertIn("success() && inputs.scope == 'windows-installer-retained-shell'", step)
            self.assertIn("steps."+previous+".outcome == 'success'", step)
            self.assertIn("MRK_RETAINED_PREVIOUS_OUTCOME: $"+"{{ steps."+previous+".outcome }}", step)
            self.assertIn("-Role '"+case+"-"+role+"'", step)
            self.assertNotIn("always()", step)
            self.assertNotIn("continue-on-error", step)
            previous = identity
        self.assertIn("inputs.scope == 'windows-installer-retained-shell' && 65", self.workflow)
        self.assertIn("inputs.scope != 'windows-installer-retained-shell'", self.workflow)
        self.assertIn("/public/retained-shell-summary.json", self.workflow)
        self.assertIn("WINDOWS_RETAINED_DATA_PHASES", self.foundation)
        self.assertIn("No retained-shell phase can fall through to another fixture or legacy native route", self.foundation)



def selection_context():
    return {**context(), "qualificationProfile": ci.SELECTION_PROFILE}


def selection_account(case, *, recovery="1"*32):
    """Independent finite fixture DATA, never an OS/native receipt."""
    previews = ci.SELECTION_CASE_CONFIG[case][4]
    old = case in ("select-reuse", "remove-reuse", "stop-old", "stop-new", "recover-current", "remove-damaged")
    new = case in ("select-fresh", "select-reuse", "repair-reuse", "recover-previous", "stop-new", "recover-current")
    commit = case in ("select-fresh", "select-reuse", "remove-reuse", "repair-reuse",
                     "recover-previous", "recover-current", "remove-damaged")
    stop = case in ("stop-old", "stop-new")
    conflict = case == "registry-conflict"
    masks = {"select-fresh": 121, "select-reuse": 127, "remove-reuse": 103, "repair-reuse": 121,
             "stop-old": 3, "recover-previous": 121, "stop-new": 15, "recover-current": 127, "remove-damaged": 103}
    mask = masks.get(case, 0)
    readonly = (previews and ci.SELECTION_CASE_CONFIG[case][1] in (
        "verify-and-restore-launch-entries", "recover-previous-launch-selection", "recover-current-launch-selection")) \
        or (commit and case not in ("remove-reuse", "remove-damaged")) or stop or case == "verify-reuse"
    head = {"version": "1", **ci.binding(selection_context()), "case": case,
        "previewObservationSha256": "-" if case == "refuse-foreign-selector" else "e"*64,
        "recoveryRun": recovery if commit or stop or conflict else "-",
        "inputs": "54" if readonly else "0", "runtime": "47" if readonly else "0",
        "readonlyClosed": "true", "conflictStaged": str(conflict).lower(),
        "conflictReturned": str(conflict).lower(), "competitorClosed": "true", "competitorPresent": str(conflict).lower()}
    failed = stop or conflict or case in ("refuse-stale-repair", "refuse-foreign-selector")
    main = {"mode": ci.SELECTION_CASE_CONFIG[case][1], "stage": "Closed" if commit else "Observed",
        "disposition": "Partial" if stop else "LaunchEntriesRemoved" if case in ("remove-reuse", "remove-damaged")
            else "Selected" if commit or case == "verify-reuse" else "Unchanged",
        "firstFailure": "fixture-refusal" if failed else "-",
        "oldMoveEntered": str(old).lower(), "newMoveEntered": str(new).lower(),
        "registryCommitEntered": str(commit).lower(), "registryCommitted": str(commit).lower(),
        "nativeClosed": "true", "oldMoveNative": "1,0" if old else "-", "newMoveNative": "1,0" if new else "-",
        "registryNative": "1,0" if commit else "-", "flushedRecords": str(mask.bit_count()),
        "closedRecords": str(mask.bit_count()), "phaseMask": str(mask), "writeCountUnknown": "false",
        "charged": "256" if commit or stop else "0", "confirmed": "256" if commit or stop else "0",
        "retainedBytes": "-", "controllerFinalityRequired": "true", "shippingInstallerEnabled": "false", "outputs": "0"}
    root = "selection/recovery/" + recovery
    rows = ([{"kind": "CreatedDirectory", "path": root, "destination": "-", "native": "1,0"}] if conflict else [])
    if old:
        rows.append({"kind": "Rename", "path": "selector", "destination": root+"/previous.lnk", "native": "1,0"})
    if new:
        rows.append({"kind": "Rename", "path": root+"/incoming.lnk", "destination": "selector", "native": "1,0"})
    main["outputRows"] = rows
    competitor = None
    if conflict:
        competitor = {**main, "stage": "RegistryStaged", "firstFailure": "-", "nativeClosed": "false",
                      "charged": "128", "confirmed": "128", "outputRows": []}
    return {"fields": head, "main": main, "competitor": competitor}


def accounting_wire(value):
    rows = [(key, value["fields"][key]) for key in ci.SELECTION_ACCOUNT_HEAD]
    for prefix in ("main", "competitor"):
        report = value[prefix]
        if report is None:
            continue
        report = {**report, "outputs": str(len(report["outputRows"]))}
        rows.extend((prefix+"."+key, report[key]) for key in ci.SELECTION_ACCOUNT_REPORT)
        for i, item in enumerate(report["outputRows"]):
            rows.extend((f"{prefix}.o{i}.{key}", item[key]) for key in ("kind", "path", "destination", "native"))
    return ";".join(key+"="+str(value) for key, value in rows)


def selection_preview_data(case="preview-fresh"):
    return dict(zip(ci.SELECTION_PREVIEW_KEYS, (
        1, ci.SELECTION_CASE_CONFIG[case][1], None, "d"*64, "c"*64, "1.0.0",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Mobile Release Kit.lnk",
        ci.SELECTION_REGISTRATION, "e"*64,
        [r"C:\Program Files\Mobile Release Kit"+"\\"+name
         for name in ("installer-input", "runtime-input", "versions", "selection")],
        None, ci.SELECTION_WARNING), strict=True))


class SelectionFixtureDataTests(unittest.TestCase):
    def test_exact54_dependency_chain_and_finite_original_budgets(self):
        self.assertEqual(len(ci.SELECTION_CHAIN), 54)
        self.assertEqual(len(ci.SELECTION_CASE_CONFIG), 24)
        self.assertEqual(len(ci.SELECTION_NATIVE_OPEN_BUDGET), 30)
        self.assertEqual(len(set(ci.SELECTION_ROLES)), 54)
        self.assertEqual(ci.SELECTION_ROLES[:3], ("stage-fresh", "preview-fresh", "preview-fresh-observe"))
        self.assertEqual(ci.SELECTION_ROLES[-3:], ("stage-owned-foreign-selector",
                                                  "refuse-foreign-selector", "refuse-foreign-selector-observe"))
        self.assertEqual(ci.SELECTION_NATIVE_OPEN_BUDGET["damage-owned-shell"], 804)
        self.assertEqual(ci.SELECTION_NATIVE_OPEN_BUDGET["stage-bad-manifest"], 753)
        self.assertEqual(ci.SELECTION_NATIVE_OPEN_BUDGET["stage-owned-foreign-selector"], 756)
        self.assertEqual(ci.SELECTION_NATIVE_OPEN_BUDGET["refuse-foreign-selector-observe"], 748)
        for role, kind, _ in ci.SELECTION_CHAIN:
            if kind == "app":
                index = ci.SELECTION_ROLES.index(role)
                self.assertEqual(ci.SELECTION_ROLES[index+1], role+"-observe")
            self.assertEqual(ci.selection_route(role), (kind, next(r[2] for r in ci.SELECTION_CHAIN if r[0] == role)))
        for role in ("fresh-app", "arbitrary-command", "stage-stop-copy"):
            with self.assertRaises(ci.FixtureError):
                ci.selection_route(role)
        with self.assertRaises(ci.FixtureError):
            ci.outcomes(json.dumps(dict.fromkeys(ci.SELECTION_ROLES[:-1], "success")), ci.SELECTION_ROLES)

    def test_accounting_nullable_order_duplicates_unknowns_and_origin_returns_are_closed(self):
        case = "preview-fresh"
        value = selection_account(case)
        raw = accounting_wire(value)
        actual = ci.selection_accounting(raw, case, selection_context())
        self.assertEqual(actual["main"]["oldMoveNative"], "-")
        self.assertEqual(actual["main"]["retainedBytes"], "-")
        mutations = (
            raw.replace("main.oldMoveNative=-;", ""),
            raw.replace("main.retainedBytes=-", "main.retainedBytes="),
            raw.replace("version=1;profile=", "profile=windows-installer-selection-v1;version=1;profile="),
            raw+";extra=1", raw+";main.outputs=0", raw+"\n", raw.replace("readonlyClosed=true", "readonlyClosed=false"),
            raw.replace("main.writeCountUnknown=false", "main.writeCountUnknown=true"),
            raw.replace("main.controllerFinalityRequired=true", "main.controllerFinalityRequired=false"),
            raw.replace("sourceTree="+"b"*40, "sourceTree="+"a"*40),
        )
        for bad in mutations:
            with self.subTest(raw=bad[:80]), self.assertRaises(ci.FixtureError):
                ci.selection_accounting(bad, case, selection_context())
        with self.assertRaises(ci.FixtureError):
            ci.selection_accounting(raw, case, context())

    def test_stop_masks_real_native_returns_and_exact_rename_order(self):
        for case, mask, count in (("stop-old", 3, 2), ("stop-new", 15, 4)):
            value = selection_account(case)
            ci.selection_accounting(accounting_wire(value), case, selection_context())
            self.assertEqual(value["main"]["phaseMask"], str(mask))
            self.assertEqual(value["main"]["closedRecords"], str(count))
            for key, replacement in (("phaseMask", "7"), ("closedRecords", "1"), ("oldMoveNative", "0,5"),
                                     ("nativeClosed", "false"), ("charged", "255")):
                bad = copy.deepcopy(value); bad["main"][key] = replacement
                with self.subTest(case=case, key=key), self.assertRaises(ci.FixtureError):
                    ci.selection_accounting(accounting_wire(bad), case, selection_context())
        value = selection_account("stop-new")
        for changes in ("reverse", "duplicate", "return"):
            bad = copy.deepcopy(value)
            if changes == "reverse":
                bad["main"]["outputRows"].reverse()
            elif changes == "duplicate":
                bad["main"]["outputRows"] += copy.deepcopy(bad["main"]["outputRows"])
            else:
                bad["main"]["outputRows"][0]["native"] = "0,5"
            with self.subTest(change=changes), self.assertRaises(ci.FixtureError):
                ci.selection_accounting(accounting_wire(bad), "stop-new", selection_context())

    def test_genuine_conflict_accounts_for_created_directory_and_original_competitor_report(self):
        value = selection_account("registry-conflict")
        result = ci.selection_accounting(accounting_wire(value), "registry-conflict", selection_context())
        self.assertEqual(result["main"]["disposition"], "Unchanged")
        self.assertEqual(len(result["main"]["outputRows"]), 1)
        self.assertEqual(result["competitor"]["nativeClosed"], "false")
        self.assertEqual(result["fields"]["competitorClosed"], "true")
        for mutation in ("omit-directory", "pretend-competitor-final", "unsettled", "omit-run", "extra-file"):
            bad = copy.deepcopy(value)
            if mutation == "omit-directory":
                bad["main"]["outputRows"] = []
            elif mutation == "pretend-competitor-final":
                bad["competitor"]["nativeClosed"] = "true"
            elif mutation == "unsettled":
                bad["fields"]["competitorClosed"] = "false"
            elif mutation == "omit-run":
                bad["fields"]["recoveryRun"] = "-"
            else:
                bad["competitor"]["outputRows"] = [{"kind": "CreatedFile", "path": "selector", "destination": "-", "native": "1,0"}]
            with self.subTest(mutation=mutation), self.assertRaises(ci.FixtureError):
                ci.selection_accounting(accounting_wire(bad), "registry-conflict", selection_context())

    def test_preview_preserves_original_canonical_null_bytes_and_refuses_unknown_fields(self):
        value = selection_preview_data()
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(ci.selection_preview(raw, "preview-fresh"), value)
        self.assertIn('"beforeImage":null', raw)
        for bad in (json.dumps(value), json.dumps(value, sort_keys=True, separators=(",", ":")),
                    raw.replace('"beforeImage":null,', ""), raw.replace('"version":1', '"version":true'),
                    raw.replace('"version":1', '"version":1,"arbitraryCommand":true'), raw+"\n"):
            with self.subTest(raw=bad[:100]), self.assertRaises(ci.FixtureError):
                ci.selection_preview(bad, "preview-fresh")
        with self.assertRaises(ci.FixtureError):
            ci.selection_preview(raw, "preview-remove-reuse")

    def test_selection_compile_roles_remain_distinct_from_both_historical_and_shipping(self):
        f = SimpleNamespace(WINDOWS_INSTALLED_CRATE="desktop/native/windows-installed-native",
                            WINDOWS_INSTALLED_APP="desktop/src-tauri")
        for current, features in ((context(), ci.SELECTED_FEATURES), (selection_context(), ci.SELECTION_SELECTED_FEATURES)):
            c = {**current, "source": str(ROOT), "root": str(ROOT/"unused-selection-data-only-root")}
            for role, feature in features.items():
                for fn in (ci.compile_argv, ci.metadata_argv):
                    argv = fn(f, c, "/fixed-cargo", role)
                    self.assertEqual(argv[argv.index("--features")+1], feature)
                    for wrong in ("image-stdio", "desktop-shell", "windows-runtime-publisher", "--ignored"):
                        self.assertNotIn(wrong, argv)
        declarations = {"unexpected": ["must-not-be-silently-repaired"]}
        self.assertEqual(ci.declared_native_features(SimpleNamespace(WINDOWS_NATIVE_DECLARED_FEATURES=declarations)), declarations)

    def test_selection_output_inventory_enforces_aggregate_not_per_stream_only(self):
        files = ci.selection_behavior_files()
        # Each raw endpoint permits64KiB individually, but stdout+stderr share
        # exactly one64KiB original budget. The finalizer must enforce both.
        self.assertEqual(sum(files.values()) - 54*65536, 5_947_392)
        self.assertEqual(ci.SELECTION_OUTPUT_BUDGET, 5_947_392)
        self.assertEqual(len(files), 54*3 + 30)
        self.assertNotIn("retained-fresh-app.private.txt", files)
        self.assertNotIn("retained-shell-precheck.private.txt", files)
        for role, kind, _ in ci.SELECTION_CHAIN:
            self.assertEqual(files["retained-"+role+"-exit.private.txt"], 8192)
            self.assertEqual(files["retained-"+role+".private.txt"], 65536)
            self.assertEqual(files["retained-"+role+".stderr.private.bin"], 65536)


    def test_complete_output_origin_census_survives_later_selector_rename(self):
        profiles = {name: {"case": name, **profile()} for name in ci.CASES}
        proofs = {name: selection_account(name, recovery=str(index)*32)
                  for index, name in enumerate(("preview-fresh", "select-fresh", "preview-reuse", "select-reuse"), 1)}
        def created(path, directory=False):
            return {"kind": "CreatedDirectory" if directory else "CreatedFile", "path": path, "destination": "-", "native": "1,0"}
        for name, image, first in (("select-fresh", "fresh", True), ("select-reuse", "reuse", False)):
            report = proofs[name]["main"]
            provenance = "selection/"+ci.TARGET+"/"+ci.sha(ci.canonical(profiles[image]))
            recovery = "selection/recovery/"+proofs[name]["fields"]["recoveryRun"]
            rows = [created(path, True) for path in ("selection", "selection/"+ci.TARGET, "selection/recovery")] if first else []
            rows += [created(provenance, True), created(provenance+"/profile.json"), created(provenance+"/launch.lnk"),
                     created(recovery, True), created(recovery+"/incoming.lnk")]
            rows += [created(f"{recovery}/record-{index:02}.bin") for index in range(7) if int(report["phaseMask"]) & (1<<index)]
            report["outputRows"] = rows + report["outputRows"]
        actual = ci.selection_state("select-reuse-observe", proofs, profiles)
        first_origin = "selection/recovery/"+"2"*32+"/incoming.lnk"
        self.assertEqual(actual["objects"]["selection/recovery/"+"4"*32+"/previous.lnk"], (False, "select-fresh", first_origin))
        self.assertEqual(actual["objects"]["selector"][1], "select-reuse")
        self.assertEqual(actual["images"], ["fresh", "reuse"])
        for mutation in ("duplicate", "omit-record", "extra-output", "unowned-rename"):
            bad = copy.deepcopy(proofs)
            if mutation == "duplicate":
                bad["select-reuse"]["main"]["outputRows"].insert(0, created("selection", True))
            elif mutation == "omit-record":
                bad["select-fresh"]["main"]["outputRows"] = [r for r in bad["select-fresh"]["main"]["outputRows"] if not r["path"].endswith("/record-00.bin")]
            elif mutation == "extra-output":
                bad["select-reuse"]["main"]["outputRows"].insert(0, created("selection/recovery/"+"9"*32, True))
            else:
                bad["select-reuse"]["main"]["outputRows"][-2]["path"] = "selection/recovery/"+"9"*32+"/incoming.lnk"
            with self.subTest(mutation=mutation), self.assertRaises(ci.FixtureError):
                ci.selection_state("select-reuse-observe", bad, profiles)

    def test_selection_finalizer_never_falls_back_or_creates_fake_success_on_incomplete_route(self):
        # Rejection occurs before source reads/imports or any compiler/native call.
        from unittest import mock
        for c, phase in ((selection_context(), "windows-retained-finalize"),
                         (context(), "windows-selection-finalize"),
                         (selection_context(), "windows-installed-native")):
            with mock.patch.object(ci, "source_pins", side_effect=AssertionError("must fail before source dispatch")):
                with self.assertRaises(ci.FixtureError):
                    ci.phase(object(), c, phase, 0.0)

    def test_selection_workflow_all54_actual_outcomes_and_old_episode_are_separate(self):
        workflow = (ROOT/".github/workflows/desktop-foundation.yml").read_text()
        blocks = workflow.split("\n      - name: ")
        by_id = {}
        for block in blocks:
            match = re.search(r"^        id: ([a-z0-9-]+)$", block, re.MULTILINE)
            if match:
                by_id[match[1]] = block
        previous = "retained-precheck"
        for role, kind, _ in ci.SELECTION_CHAIN:
            identity = "selection-"+role
            block = by_id[identity]
            self.assertIn("success() && inputs.scope == 'windows-installer-selection'", block)
            self.assertIn("steps."+previous+".outcome == 'success'", block)
            self.assertIn("MRK_RETAINED_PREVIOUS_OUTCOME: $"+"{{ steps."+previous+".outcome }}", block)
            self.assertIn("timeout-minutes: "+("11" if kind == "app" else "3"), block)
            self.assertIn("-Role '"+role+"'", block)
            self.assertNotIn("continue-on-error", block)
            self.assertNotIn("always()", block)
            previous = identity
        final = by_id["selection-finalize"]
        self.assertIn("MRK_SELECTION_OUTCOMES:", final)
        for role in ci.SELECTION_ROLES:
            self.assertIn('"'+role+'":"$'+"{{ steps.selection-"+role+'.outcome }}"', final)
        for identity in ("ordinary-preflight", "ordinary-owner", "runtime-data", "retain"):
            self.assertIn("inputs.scope != 'windows-installer-selection'", by_id[identity])
        for identity in ("retained-probe-balanced", "retained-probe-overflow", "retained-probe-writer-fault",
                         "retained-probes-finalize", "retained-precheck"):
            self.assertIn("inputs.scope == 'windows-installer-selection'", by_id[identity])
        self.assertIn("windows-selection-finalize", final)
        self.assertNotIn("ci_foundation.py windows-retained-finalize", final)
        self.assertIn("MRK_SELECTION_FINALIZE_OUTCOME:", by_id["selection-retain"])
        self.assertIn("/public/selection-summary.json", workflow)
        self.assertNotIn("MRK_RETAINED_OUTCOMES:", final)


if __name__ == "__main__":
    unittest.main()
