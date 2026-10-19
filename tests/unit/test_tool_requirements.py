"""Synthetic source DATA only; no filesystem discovery, process or download."""
import unittest

from mobile_release.tool_requirements import FILE_LIMIT, RequirementsInputError, observe_tool_requirements
from mobile_release.toolchain_policy import XCODE_BUILD, XCODE_VERSION


class ToolRequirementsTests(unittest.TestCase):
    def sources(self):
        return {
            "app/build.gradle.kts": 'plugins { id("com.android.application") }\nandroid {\n compileSdk = 35\n buildToolsVersion = "35.0.0"\n}\nkotlin { jvmToolchain(17) }',
            "build.gradle.kts": 'plugins { id("com.android.application") version "8.9.2" apply false }',
            "gradle/wrapper/gradle-wrapper.properties": 'distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.5-bin.zip\ndistributionSha256Sum=' + "a" * 64,
        }

    def observe(self, sources=None, **kwargs):
        return observe_tool_requirements(self.sources() if sources is None else sources, platform="android", android_build_file="app/build.gradle.kts", complete=kwargs.get("complete", True))

    def test_conventional_literal_requirements_are_hints_not_effective_model(self):
        result = self.observe()
        self.assertEqual(result["basis"], "unverified-static-source-hints")
        self.assertFalse(result["projectCodeExecuted"])
        for key, expected in (("jdk", "17"), ("agp", "8.9.2"), ("sdkPlatform", "android-35"), ("sdkBuildTools", "35.0.0")):
            self.assertEqual(result["android"][key], {"state": "literal", "value": expected})
        self.assertEqual(result["android"]["gradle"]["version"], "8.14.5")
        self.assertEqual(result["xcode"], {"version": XCODE_VERSION, "build": XCODE_BUILD})

    def test_actual_applied_catalog_plugin_and_unset_optional_constraints(self):
        sources = self.sources()
        sources["app/build.gradle.kts"] = 'plugins { alias(libs.plugins.android.application) }\nandroid { compileSdk = 35 }'
        sources["gradle/libs.versions.toml"] = '[versions]\nagp = "8.9.2"\n[plugins]\nandroid-application = { id = "com.android.application", version.ref = "agp" }'
        result = self.observe(sources)["android"]
        self.assertEqual(result["agp"]["value"], "8.9.2")
        self.assertEqual(result["jdk"]["state"], "unspecified")
        self.assertEqual(result["sdkBuildTools"]["state"], "unspecified")
        sources["app/build.gradle.kts"] = 'plugins { id("com.android.library") }\nandroid { compileSdk = 35 }'
        self.assertEqual(self.observe(sources)["android"]["sdkPlatform"]["state"], "unknown")

    def test_dynamic_duplicate_comments_strings_and_unknown_scopes_never_supply_literal(self):
        for replacement in ("compileSdk = libs.versions.sdk.get().toInt()", "compileSdk = 35 + extra", "compileSdk = 34\ncompileSdk = 35"):
            sources = self.sources()
            sources["app/build.gradle.kts"] = sources["app/build.gradle.kts"].replace("compileSdk = 35", replacement)
            self.assertEqual(self.observe(sources)["android"]["sdkPlatform"]["state"], "unknown", replacement)
        sources = self.sources()
        sources["app/build.gradle.kts"] = 'plugins { id("com.android.application") }\n// android { compileSdk = 35 }\nval example = "compileSdk = 35"\n'
        self.assertEqual(self.observe(sources)["android"]["sdkPlatform"]["state"], "unknown")
        sources["app/build.gradle.kts"] += 'afterEvaluate { compileSdk = 35 }'
        self.assertEqual(self.observe(sources)["android"]["sdkPlatform"]["state"], "unknown")

    def test_checksum_url_duplicates_and_partial_census_do_not_authorize_acquisition(self):
        for wrapper in ("distributionUrl=https://example.invalid/gradle-8.14.5-bin.zip", "distributionUrl=https://services.gradle.org/distributions/gradle-8.14.5-bin.zip?token=test", "distributionUrl=x\ndistributionUrl=x"):
            sources = self.sources()
            sources["gradle/wrapper/gradle-wrapper.properties"] = wrapper
            self.assertEqual(self.observe(sources)["android"]["gradle"]["state"], "unknown")
        sources = self.sources()
        sources["gradle/wrapper/gradle-wrapper.properties"] = 'distributionUrl=https://services.gradle.org/distributions/gradle-8.14.5-bin.zip'
        self.assertIsNone(self.observe(sources)["android"]["gradle"]["sha256"])
        self.assertEqual(self.observe(complete=False)["android"]["agp"]["state"], "unknown")

    def test_source_fingerprint_binds_missing_inputs_selection_and_exact_bytes(self):
        first = self.observe()
        sources = self.sources()
        sources["settings.gradle.kts"] = ""
        self.assertNotEqual(first["sourcesSha256"], self.observe(sources)["sourcesSha256"])
        sources = self.sources()
        sources["app/build.gradle.kts"] += "\n// harmless but new source\n"
        self.assertNotEqual(first["sourcesSha256"], self.observe(sources)["sourcesSha256"])
        self.assertNotEqual(first["sourcesSha256"], self.observe(complete=False)["sourcesSha256"])

    def test_java_language_toolchain_and_composite_build_refusal(self):
        sources = self.sources()
        sources["app/build.gradle.kts"] = sources["app/build.gradle.kts"].replace('kotlin { jvmToolchain(17) }', 'java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }')
        self.assertEqual(self.observe(sources)["android"]["jdk"]["value"], "17")
        sources["settings.gradle.kts"] = 'includeBuild("build-logic")'
        self.assertEqual(self.observe(sources)["android"]["jdk"]["state"], "unknown")

    def test_declared_but_not_applied_plugin_and_ambiguous_catalog_do_not_select_app(self):
        for declaration in ('id("com.android.application") apply false',
                            'id("com.android.application") version "8.9.2" apply false',
                            'id("com.android.application") version "8.9.2" apply false + other',
                            'alias(libs.plugins.android.application) apply false',
                            'alias(android.application)'):
            sources = self.sources()
            sources["app/build.gradle.kts"] = 'plugins { ' + declaration + ' }\nandroid { compileSdk = 35 }'
            sources["gradle/libs.versions.toml"] = '[plugins]\nandroid-application = { id = "com.android.application", version = "8.9.2" }'
            self.assertEqual(self.observe(sources)["android"]["agp"]["state"], "unknown", declaration)
        sources["app/build.gradle.kts"] = 'plugins { alias(libs.plugins.android.application) }\nandroid { compileSdk = 35 }'
        sources["gradle/libs.versions.toml"] += '\nandroid_application = { id = "com.android.application", version = "8.9.2" }'
        self.assertEqual(self.observe(sources)["android"]["agp"]["state"], "unknown")

    def test_script_siblings_and_external_build_logic_stay_unresolved(self):
        for name, content in (("app/build.gradle", ""), ("settings.gradle", "")):
            sources = self.sources()
            sources["settings.gradle.kts"] = ""
            first = self.observe(sources)
            sources[name] = content
            observed = self.observe(sources)
            self.assertNotEqual(first["sourcesSha256"], observed["sourcesSha256"])
            self.assertEqual(observed["android"]["agp"]["state"], "unknown")
            self.assertEqual(observed["android"]["gradle"]["state"], "unknown")
        for logic in ('apply from: "tool-overrides.gradle"', 'afterEvaluate { configureTools() }'):
            sources = self.sources()
            sources["app/build.gradle.kts"] += "\n" + logic
            self.assertEqual(self.observe(sources)["android"]["agp"]["state"], "unknown")
            self.assertEqual(self.observe(sources)["android"]["gradle"]["state"], "unknown")

    def test_bounds_and_invalid_paths_are_closed_and_errors_do_not_echo_input(self):
        for sources in ({"secrets.json": "not-read"}, {"app/build.gradle.kts": "x" * (FILE_LIMIT + 1)}, {"app/build.gradle.kts": "\0"}):
            with self.assertRaises(RequirementsInputError) as caught:
                self.observe(sources)
            self.assertNotIn("not-read", str(caught.exception))
        with self.assertRaises(RequirementsInputError):
            observe_tool_requirements({}, platform="android", android_build_file="../build.gradle.kts", complete=True)
        ios = observe_tool_requirements({}, platform="ios", complete=True)
        self.assertIsNone(ios["android"])
        self.assertEqual(ios["xcode"]["version"], XCODE_VERSION)


if __name__ == "__main__":
    unittest.main()
