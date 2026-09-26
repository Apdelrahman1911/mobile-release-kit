"""Public fixture DATA only; no native Java, crypto validation or host capture."""
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load("stock_trust_correspondence")
S = load("observe_hosted_android")
POLICY = (ROOT / "desktop/tools" / T.POLICY_FILE).read_bytes()
ROWS = json.loads(POLICY)["certificates"]
PEM = (ROOT / "tests/fixtures/ubuntu-stock-ca-certificates.pem.data").read_bytes()
BLOCKS = re.findall(rb"-----BEGIN CERTIFICATE-----\n(.*?)-----END CERTIFICATE-----\n", PEM, re.S)
DER = [base64.b64decode(block.replace(b"\n", b""), validate=True) for block in BLOCKS]
CONFIG = ("# Exact authenticated public package selections\n" + "\n".join(row["name"] for row in ROWS) + "\n").encode()
CUSTOM = {"status": "empty", "customBodiesRead": False, "customNamesExported": False}


def utf(value):
    raw = value.encode("utf-8") if type(value) is str else value
    return struct.pack(">H", len(raw)) + raw


def checksum(body):
    return body + hashlib.sha1("changeit".encode("utf-16be") + b"Mighty Aphrodite" + body).digest()


def jks(records=None, *, tag=2, version=2, count=121, timestamp=0, certificate_type="X.509"):
    # Synthetic JKS framing of real public certificate bytes, NOT native output.
    if records is None:
        records = [(row["jksAlias"], der) for row, der in zip(ROWS, DER)]
    body = struct.pack(">III", 0xFEEDFEED, version, count)
    for alias, der in records:
        body += (struct.pack(">I", tag) + utf(alias) + struct.pack(">Q", timestamp)
                 + utf(certificate_type) + struct.pack(">I", len(der)) + der)
    return checksum(body)


JKS = jks()


class StockTrustContracts(unittest.TestCase):
    def setUp(self):
        self.policy = T.Policy(POLICY)

    def test_exact_public_fixture_and_both_orders_correspond_without_producer_claim(self):
        self.assertEqual(len(DER), 121)
        self.assertEqual(len(PEM), 182140)
        self.assertEqual(hashlib.sha256(PEM).hexdigest(),
                         "9481fcd95f41b221f02f14d896535fe500bec539bc563c4cdca1acee483a8bdd")
        for row, der in zip(ROWS, DER):
            self.assertEqual((len(der), hashlib.sha256(der).hexdigest()), (row["derBytes"], row["derSha256"]))
        parts = {"pem": self.policy.pem(PEM, lambda: None), "jks": self.policy.jks(JKS, lambda: None),
                 "config": self.policy.config(CONFIG, lambda: None)}
        self.assertEqual(self.policy.complete(parts, CUSTOM), self.policy.summary("complete"))
        # Ordering/timestamp differences alone cannot change certificate authority.
        reversed_pem = b"".join(b"-----BEGIN CERTIFICATE-----\n" + block + b"-----END CERTIFICATE-----\n"
                                for block in reversed(BLOCKS))
        self.assertEqual(self.policy.pem(reversed_pem, lambda: None), parts["pem"])
        pairs = list(reversed([(row["jksAlias"], der) for row, der in zip(ROWS, DER)]))
        self.assertEqual(self.policy.jks(jks(pairs, timestamp=2**64-1), lambda: None), parts["jks"])
        self.assertIs(parts["jks"]["producerExecutionProven"], False)

    def test_policy_authentication_precedes_parsing(self):
        for raw in (b"{}", POLICY + b" ", POLICY.replace(b'"certificateCount": 121', b'"certificateCount": 120'),
                    b"x" * (T.POLICY_LIMIT + 1)):
            with self.subTest(size=len(raw)), self.assertRaisesRegex(T.Refused, "stock-policy"):
                T.Policy(raw)

    def test_pem_incomplete_duplicate_extra_and_unknown_anchor_refuse(self):
        blocks = [b"-----BEGIN CERTIFICATE-----\n" + block + b"-----END CERTIFICATE-----\n" for block in BLOCKS]
        unknown = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"not a real certificate") + b"\n-----END CERTIFICATE-----\n"
        for raw in (b"".join(blocks[:-1]), b"".join([blocks[0], *blocks[:-1]]), PEM + blocks[0],
                    unknown + b"".join(blocks[1:])):
            with self.subTest(size=len(raw)), self.assertRaises(T.Refused):
                self.policy.pem(raw, lambda: None)

    def test_pem_strict_complete_framing_and_bounds(self):
        for raw in (b"private text\n" + PEM, PEM + b"trailing", PEM.replace(b"-----END", b"-----BAD", 1),
                    PEM.replace(b"\nMII", b"\n!II", 1), b"-----BEGIN CERTIFICATE-----\n",
                    b"x" * (T.PEM_LIMIT + 1), PEM.replace(b"-----END CERTIFICATE-----", b"-----BEGIN CERTIFICATE-----", 1)):
            with self.subTest(size=len(raw)), self.assertRaises(T.Refused):
                self.policy.pem(raw, lambda: None)

    def test_jks_rejects_key_entries_wrong_type_version_counts_tails_and_checksum(self):
        for raw in (jks(tag=1), jks(tag=3), jks(version=1), jks(count=120), jks(count=122),
                    jks(certificate_type="PKCS12"), checksum(JKS[:-20] + b"tail"),
                    JKS[:-1] + bytes([JKS[-1] ^ 1]), JKS[:31], b"x" * (T.JKS_LIMIT + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(T.Refused):
                self.policy.jks(raw, lambda: None)

    def test_jks_alias_must_bind_its_own_certificate_and_not_collapse(self):
        original = [(row["jksAlias"], der) for row, der in zip(ROWS, DER)]
        for first in ((original[0][0].upper(), original[0][1]), (original[1][0], original[0][1]),
                      (original[0][0], original[1][1]), ("debian:unknown.pem", original[0][1])):
            with self.subTest(alias=first[0]), self.assertRaises(T.Refused):
                self.policy.jks(jks([first, *original[1:]]), lambda: None)

    def test_fixed_netlock_modified_utf_subset_not_general_unicode(self):
        index = next(i for i, row in enumerate(ROWS) if "NetLock" in row["name"])
        alias = ROWS[index]["jksAlias"]
        self.assertEqual(alias, "debian:netlock_arany_=class_gold=_főtanúsítvány.pem")
        self.policy.jks(JKS, lambda: None)
        self.policy.config(CONFIG, lambda: None)
        originals = [(row["jksAlias"], der) for row, der in zip(ROWS, DER)]
        for changed in (alias.replace("ő", "o\u030b"), alias.replace("ő", "Ő"), alias + "\0",
                        b"debian:\xc0\x80.pem", b"debian:\xed\xa0\x80.pem", b"debian:\xf0\x9f\x98\x80.pem",
                        b"debian:\xff.pem"):
            pairs = list(originals)
            pairs[index] = changed, pairs[index][1]
            with self.subTest(alias=repr(changed)), self.assertRaises(T.Refused):
                self.policy.jks(jks(pairs), lambda: None)
        for replacement in ("FŐtanúsítvány", "Fo\u030btanúsítvány"):
            raw = CONFIG.replace("Főtanúsítvány".encode(), replacement.encode())
            with self.assertRaises(T.Refused):
                self.policy.config(raw, lambda: None)

    def test_config_must_select_the_complete_exact_set_without_private_exports(self):
        first = (ROWS[0]["name"] + "\n").encode()
        for raw in (CONFIG + first, CONFIG.replace(first, b"", 1), CONFIG.replace(first, b"!" + first, 1),
                    CONFIG + b"mozilla/private-customer.crt\n", b"\xef\xbb\xbf" + CONFIG,
                    CONFIG + b"# comment\0private\n", CONFIG + b"# \xff\n", CONFIG.replace(b"\n", b"\r\n"),
                    CONFIG + b"#" + b"x" * 2048, b"x" * (T.CONFIG_LIMIT + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(T.Refused):
                self.policy.config(raw, lambda: None)

    def test_declared_lengths_cannot_read_past_jks_body(self):
        for raw in (checksum(JKS[:12] + struct.pack(">IH", 2, 65535)),
                    checksum(JKS[:12] + struct.pack(">I", 2) + utf(ROWS[0]["jksAlias"]) + b"\0" * 8
                             + utf("X.509") + struct.pack(">I", 0xFFFFFFFF)),
                    checksum(JKS[:-21])):
            with self.assertRaises(T.Refused):
                self.policy.jks(raw, lambda: None)

    def test_all_parsers_preserve_aggregate_cancellation(self):
        class Stop(Exception):
            pass
        for method, raw in ((self.policy.pem, PEM), (self.policy.jks, JKS), (self.policy.config, CONFIG)):
            point = Mock(side_effect=[None, None, Stop("owned aggregate deadline")])
            with self.assertRaises(Stop):
                method(raw, point)
            self.assertEqual(point.call_count, 3)

    def test_summary_needs_all_original_projections_and_genuinely_empty_custom_directory(self):
        parts = {kind: self.policy.summary(kind) for kind in ("pem", "jks", "config")}
        for custom in ({"status": "absent"}, {**CUSTOM, "status": "nonempty"},
                       {**CUSTOM, "customBodiesRead": True}, {"status": "empty"}):
            with self.assertRaisesRegex(T.Refused, "stock-custom-inputs"):
                self.policy.complete(parts, custom)
        for changed in ({"pem": parts["pem"]}, {**parts, "jks": parts["pem"]},
                        {**parts, "jks": {**parts["jks"], "policySha256": "0" * 64}}):
            with self.assertRaisesRegex(T.Refused, "stock-correspondence"):
                self.policy.complete(changed, CUSTOM)


class CollectorStockTrustContracts(unittest.TestCase):
    def collect(self, *, changed=None, custom=None, policy=POLICY, stopped=False):
        bodies = dict(zip((row[0] for row in S.TRUST_INPUTS), (PEM, JKS, CONFIG)))
        calls = []
        class Reader(S.Reader):
            def file(self, name, limit, parse=None):
                if name in bodies:
                    return super().file(name, limit, parse)
                return {"status": "observed", "file": {"path": name, "selectedPath": name,
                                                          "size": 1, "sha256": "a" * 64}}

            def _record(self, name, bound):
                calls.append((name, "record"))
                raw = bodies[name]
                digest = hashlib.sha256(raw).hexdigest()
                if changed == name and calls.count((name, "record")) == 2:
                    digest = "0" * 64
                return {"path": name, "selectedPath": name, "size": len(raw), "sha256": digest}, len(raw)

            def _body(self, name, bound):
                calls.append((name, "body"))
                if stopped:
                    raise S.Stopped("deadline")
                return bodies[name], len(bodies[name])

            def directory(self, name, *, custom=False):
                self.point()
                return CUSTOM if directory is None else directory

        directory = custom
        def source_read(path, bound):
            self.assertEqual(path, S.TOOLS / T.POLICY_FILE)
            self.assertEqual(bound, T.POLICY_LIMIT)
            return policy
        publisher = SimpleNamespace(D=SimpleNamespace(same=lambda a, b: a == b, read=source_read,
            canonical=lambda value: (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()))
        github = {"qualified": False, "runtimeSelfAdmission": False, "nftExecuted": False, "dnsQueryIssued": False}
        with patch.object(S, "Reader", Reader), patch.object(S.time, "monotonic", return_value=0), \
             patch.object(S, "supplier_cas", side_effect=S.Refused("supplier-directory-permissions")), \
             patch.object(S, "github_materials", return_value=github) as shared:
            value = S.collect(publisher, {}, 10)
        return value, calls, shared.call_count

    def test_collector_uses_original_callbacks_rebinds_and_charged_source_data(self):
        result, calls, shared = self.collect()
        rows = result["observations"]
        self.assertEqual(rows["stockTrustCorrespondence"], {"status": "observed", "data": T.Policy(POLICY).summary("complete")})
        self.assertEqual(calls, [(name, phase) for name, _, _ in S.TRUST_INPUTS for phase in ("record", "body", "record")])
        self.assertEqual(result["androidChargedReadBytes"], 3 * (len(PEM) + len(JKS) + len(CONFIG)) + len(POLICY))
        self.assertEqual(rows["supplierCaInputs"]["refusal"], "supplier-directory-permissions")
        self.assertEqual(shared, 1)
        for flag in ("runtimeAdmission", "nativeQualification", "producerOriginProven", "collectionComplete", "newConsent"):
            self.assertIs(result[flag], False)
        self.assertNotIn("BEGIN CERTIFICATE", json.dumps(result))
        self.assertNotIn("NetLock", json.dumps(result))
        self.assertIn("stock_trust_correspondence.py", S.SOURCE_FILES)
        self.assertIn(T.POLICY_FILE, S.SOURCE_FILES)

    def test_changed_original_or_unobserved_custom_input_never_publishes_complete(self):
        for changed, custom in ((S.TRUST_INPUTS[0][0], None), (S.TRUST_INPUTS[1][0], None),
                                (None, {"status": "absent"}), (None, {**CUSTOM, "status": "nonempty"})):
            with self.subTest(changed=changed, custom=custom):
                result, _, shared = self.collect(changed=changed, custom=custom)
                self.assertEqual(result["observations"]["stockTrustCorrespondence"]["status"], "unavailable")
                if changed:
                    self.assertEqual(result["observations"][changed]["refusal"], "parsed-original-changed")
                self.assertEqual(shared, 1)

    def test_policy_substitution_does_not_block_independent_work_but_global_stop_does(self):
        result, _, shared = self.collect(policy=b"private replacement policy")
        self.assertIsNone(result["stopped"])
        self.assertEqual(shared, 1)
        self.assertEqual(result["observations"]["stockTrustCorrespondence"]["refusal"], "stock-policy-unavailable")
        self.assertNotIn("private replacement", json.dumps(result))
        result, calls, shared = self.collect(stopped=True)
        self.assertEqual(result["stopped"], "deadline")
        self.assertEqual(shared, 0)
        self.assertEqual(calls, [(S.TRUST_INPUTS[0][0], phase) for phase in ("record", "body")])

    def test_helper_has_no_command_network_native_or_filesystem_capability(self):
        tree = ast.parse((ROOT / "desktop/tools/stock_trust_correspondence.py").read_bytes())
        imports = {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
        self.assertEqual(imports, {"base64", "binascii", "hashlib", "hmac", "json", "struct"})
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        self.assertNotIn("open", calls)
        self.assertNotIn("exec", calls)


if __name__ == "__main__":
    unittest.main()
