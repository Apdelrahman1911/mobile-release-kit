"""Inert checks of the fixed edit bootstrap's Mac workflow admission.

The actual bootstrap definition is loaded as source, then called with isolated
sys/path DATA and a stub engine module. No real edit engine, native custody,
transaction, subprocess, credentials or product traffic is admitted by these
checks. They do not qualify installed execution or filesystem durability.
"""
from __future__ import annotations

import posixpath
import runpy
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch


BOOTSTRAP = Path(__file__).resolve().parents[2] / "desktop" / "config_edit_bootstrap.py"
DOMAINS = ("github_workflows", "metadata_text", "release_version", "metadata_images")


class MacWorkflowBootstrapAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # run_name is not __main__: the dedicated engine never starts here.
        cls.bootstrap = staticmethod(runpy.run_path(str(BOOTSTRAP), run_name="inert_bootstrap_source")["main"])

    def invoke(self, platform="darwin", domain="github_workflows", **changes):
        argv = ["config_edit_bootstrap.py", "/inert/core.zip"]
        if domain is not None:
            argv.append(domain)
        data = SimpleNamespace(argv=argv, platform=platform,
                               flags=SimpleNamespace(isolated=1, no_site=1),
                               dont_write_bytecode=True, version_info=(3, 14, 0),
                               path=["/inert/bootstrap-directory"])
        for name, value in changes.items():
            setattr(data, name, value)
        package = ModuleType("mobile_release")
        package.__path__ = []
        engine = ModuleType("mobile_release._desktop_edit_engine")
        engine.main = Mock(return_value=23)
        package._desktop_edit_engine = engine
        with patch.dict(sys.modules, {package.__name__: package, engine.__name__: engine}), \
                patch.dict(self.bootstrap.__globals__, {
                    "sys": data, "os": SimpleNamespace(path=posixpath),
                    "time": SimpleNamespace(monotonic=lambda: 17.0)}):
            code = self.bootstrap()
        return code, engine.main, data

    def assert_admission(self, platform, domain, admitted):
        code, engine, data = self.invoke(platform, domain)
        if admitted:
            self.assertEqual(code, 23)
            engine.assert_called_once_with(started=17.0, domain="configuration" if domain is None else domain)
            self.assertEqual(data.path, ["/inert/core.zip", "/inert/bootstrap-directory"])
        else:
            self.assertEqual(code, 78)
            engine.assert_not_called()
            self.assertEqual(data.path, ["/inert/bootstrap-directory"])

    def test_darwin_edit_domains_share_fixed_engine_but_images_stay_closed(self):
        for domain in (None, *DOMAINS):
            with self.subTest(domain=domain):
                self.assert_admission("darwin", domain, domain != "metadata_images")

    def test_existing_linux_domains_and_unsupported_platforms_keep_their_boundary(self):
        for domain in (None, *DOMAINS):
            with self.subTest(platform="linux", domain=domain):
                self.assert_admission("linux", domain, True)
            with self.subTest(platform="linux2", domain=domain):
                self.assert_admission("linux2", domain, domain is None)
            for platform in ("win32", "freebsd", "Darwin", ""):
                with self.subTest(platform=platform, domain=domain):
                    self.assert_admission(platform, domain, False)

    def test_invalid_flags_arguments_and_domains_cannot_enter_the_engine(self):
        invalid = (
            {"flags": SimpleNamespace(isolated=0, no_site=1)},
            {"flags": SimpleNamespace(isolated=1, no_site=0)},
            {"dont_write_bytecode": False},
            {"version_info": (3, 10, 99)},
            {"argv": ["config_edit_bootstrap.py"]},
            {"argv": ["config_edit_bootstrap.py", "relative/core.zip", "github_workflows"]},
            {"argv": ["config_edit_bootstrap.py", "/inert/core.zip", "configuration"]},
            {"argv": ["config_edit_bootstrap.py", "/inert/core.zip", "github_workflows", "extra"]},
        )
        for changes in invalid:
            with self.subTest(changes=changes):
                code, engine, data = self.invoke(**changes)
                self.assertEqual(code, 78)
                engine.assert_not_called()
                self.assertEqual(data.path, ["/inert/bootstrap-directory"])
        for domain in ("github-workflows", "GitHub_Workflows", "github_workflows ", "unknown", ""):
            with self.subTest(domain=domain):
                self.assert_admission("darwin", domain, False)


if __name__ == "__main__":
    unittest.main()
