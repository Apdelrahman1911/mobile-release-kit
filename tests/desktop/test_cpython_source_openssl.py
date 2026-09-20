"""Inert OpenSSL generated-DATA regressions: no native tools or filesystem writes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("_mrk_openssl_data_tests", ROOT / "desktop/tools/cpython_static_inputs.py")
I = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(I)

DISABLED = {"acvp-tests": "default", "autoload-config": "option", "dso": "option",
            "dynamic-engine": "cascade", "engine": "option", "legacy": "option", "module": "option"}


def configdata(disabled=DISABLED):
    # Exact simple-scalar format from pinned OpenSSL Util.pm dump_data/quotify1:
    # sorted four-space rows, comma/newline separators, no final comma.
    rows = [f'    "{key}" => "{value}"' for key, value in sorted(disabled.items())]
    return ('our %config = ();\nour %disabled = (\n' + ',\n'.join(rows) + '\n);\nour %withargs = ();\n').encode()


def generated():
    return {"configdata.pm": configdata(), "Makefile": b"MODULES=\nINSTALL_MODULES=\n",
            "include/openssl/configuration.h": b"# define OPENSSL_NO_DSO\n# define OPENSSL_NO_ENGINE\n# define OPENSSL_NO_AUTOLOAD_CONFIG\n",
            "include/openssl/opensslv.h": b'# define OPENSSL_VERSION_STR "3.5.8"\n'}


class OpenSSLConfigurationTests(unittest.TestCase):
    def test_generated_controls_do_not_require_nonexistent_macros(self):
        files = generated()
        self.assertNotIn(b"OPENSSL_NO_MODULE", files["include/openssl/configuration.h"])
        self.assertNotIn(b"OPENSSL_NO_LEGACY", files["include/openssl/configuration.h"])
        I.source_openssl_configuration({k: files[k] for k in ("Makefile", "configdata.pm")}, headers=False)
        I.source_openssl_configuration(files, headers=True)

    def test_disabled_controls_and_unique_scalar_table_are_required(self):
        files = generated()
        for key in ("module", "dso", "engine", "autoload-config", "legacy"):
            for settings in ({k: v for k, v in DISABLED.items() if k != key}, {**DISABLED, key: "default"}):
                with self.subTest(key=key, settings=settings), self.assertRaises(I.InputError):
                    I.source_openssl_configuration({**files, "configdata.pm": configdata(settings)}, headers=False)
        raw = files["configdata.pm"]
        for invalid in (b"our %withargs = ();\n", raw + raw,
                        raw.replace(b'    "module" => "option"', b'    "module" => "option",\n    "module" => "option"'),
                        raw.replace(b'    "module" => "option"', b'    "module" => "option",'),
                        raw.replace(b'    "module" => "option"', b'    "module" => ["option"]'),
                        raw.replace(b'    "module" => "option"', b'    "module" => "option\\n"'),
                        raw.replace(b'    "acvp-tests" => "default",\n', b'').replace(b'    "module"', b'    "acvp-tests" => "default",\n    "module"')):
            with self.subTest(invalid=invalid), self.assertRaises(I.InputError):
                I.source_openssl_configuration({**files, "configdata.pm": invalid}, headers=False)

    def test_module_targets_real_headers_and_version_remain_checked(self):
        files = generated()
        for key in ("MODULES", "INSTALL_MODULES"):
            row = (key + "=\n").encode()
            for invalid in (files["Makefile"].replace(row, b""), files["Makefile"] + row,
                            files["Makefile"].replace(row, (key + "=providers/example.so\n").encode())):
                with self.subTest(key=key, invalid=invalid), self.assertRaises(I.InputError):
                    I.source_openssl_configuration({**files, "Makefile": invalid}, headers=False)
        for macro in ("DSO", "ENGINE", "AUTOLOAD_CONFIG"):
            header = files["include/openssl/configuration.h"].replace(("# define OPENSSL_NO_" + macro + "\n").encode(), b"")
            with self.subTest(macro=macro), self.assertRaises(I.InputError):
                I.source_openssl_configuration({**files, "include/openssl/configuration.h": header}, headers=True)
        with self.assertRaisesRegex(I.InputError, "OpenSSL version differs"):
            I.source_openssl_configuration({**files, "include/openssl/opensslv.h": b'# define OPENSSL_VERSION_STR "3.5.7"\n'}, headers=True)

    def test_capture_checks_configure_before_headers_and_rechecks_later_phases(self):
        files, root = generated(), I.WORK / "build/openssl"
        def read(path, limit):
            return files[path.relative_to(root).as_posix()]
        def write(path, raw):
            return {"path": str(path), "size": len(raw), "sha256": I.digest(raw)}
        with patch.object(I, "source_read", side_effect=read) as reads, patch.object(I, "source_write", side_effect=write):
            for phase, names in (("openssl-configure", ("Makefile", "configdata.pm")),
                                 ("openssl-build", I.SOURCE_OPENSSL_FILES), ("openssl-install", I.SOURCE_OPENSSL_FILES)):
                reads.reset_mock()
                records = I.source_capture_configuration(phase)
                self.assertEqual([call.args[0] for call in reads.call_args_list], [root / name for name in names])
                self.assertEqual(len(records), len(names))
                self.assertEqual([r["sha256"] for r in records], [I.digest(files[name]) for name in names])
            files["configdata.pm"] = configdata({k: v for k, v in DISABLED.items() if k != "module"})
            with self.assertRaisesRegex(I.InputError, "explicit no-module"):
                I.source_capture_configuration("openssl-configure")


if __name__ == "__main__":
    unittest.main()
