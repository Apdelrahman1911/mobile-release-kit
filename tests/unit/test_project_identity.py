"""Synthetic source fixtures only: no build, provider, native owner or credentials."""
from __future__ import annotations

import json
import plistlib
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from mobile_release import project_identity as identity
from .helpers import android_config

OLD, NEW = "com.example.reader", "com.example.another"
ANDROID = identity.IdentitySelection("android", ":app", continuity="unknown")
IOS = identity.IdentitySelection("ios", "Reader", "iosApp/Reader.xcodeproj", "unknown")
PBX = "iosApp/Reader.xcodeproj/project.pbxproj"
SCHEME = "iosApp/Reader.xcodeproj/xcshareddata/xcschemes/Reader.xcscheme"
IDS = {name: f"{index:024X}" for index, name in enumerate((
    "project", "main", "app", "projectlist", "projectdebug", "projectrelease",
    "applist", "appdebug", "apprelease", "other", "otherlist", "otherdebug",
    "otherrelease", "config", "alias", "group", "shell"), 1)}


def config(platform="android", **changes):
    value = android_config(status="unverified")
    if platform == "ios":
        value["android"] = {"enabled": False}
        value["ios"] = {"enabled": True, "bundleId": OLD, "identityStatus": "unverified",
                        "project": IOS.project, "scheme": "Reader", "archiveConfiguration": "Release"}
        value["metadata"].update(androidLocales=[], iosLocales=["en-US"])
    value[platform].update(changes)
    return json.dumps(value, indent=2).encode() + b"\n"


def android(source=None, **extra):
    return {identity.CONFIG_PATH: config(), "settings.gradle.kts": b'include(":app", ":shared")\n',
            "app/build.gradle.kts": (source or (
                'plugins { id("com.android.application") }\n'
                'android {\n namespace = "com.example.source"\n defaultConfig {\n'
                f'  applicationId = "{OLD}"\n  versionCode = 1\n }}\n'
                ' buildTypes { debug { applicationIdSuffix = ".debug" } }\n}\n')).encode(), **extra}


def pbx(*, app_settings=None, other=False, base=None, other_base=None, refs="", main_children="",
        project_settings="", info="GENERATE_INFOPLIST_FILE = YES;"):
    s = f"PRODUCT_BUNDLE_IDENTIFIER = {OLD};" if app_settings is None else app_settings
    base = f"baseConfigurationReference = {base};" if base else ""
    other_base = f"baseConfigurationReference = {other_base};" if other_base else ""
    data = f"""// !$*UTF8*$!
{{ archiveVersion = 1; objectVersion = 56; objects = {{
{IDS['project']} = {{ isa = PBXProject; mainGroup = {IDS['main']};
 buildConfigurationList = {IDS['projectlist']}; targets = ({IDS['app']}, {IDS['other'] + ',' if other else ''}); }};
{IDS['main']} = {{ isa = PBXGroup; sourceTree = "<group>"; children = ({main_children}); }};
{IDS['projectlist']} = {{ isa = XCConfigurationList; buildConfigurations = ({IDS['projectdebug']}, {IDS['projectrelease']}); }};
{IDS['projectdebug']} = {{ isa = XCBuildConfiguration; name = Debug; buildSettings = {{ {project_settings} }}; }};
{IDS['projectrelease']} = {{ isa = XCBuildConfiguration; name = Release; buildSettings = {{ {project_settings} }}; }};
{IDS['app']} = {{ isa = PBXNativeTarget; name = Reader; productType = "com.apple.product-type.application";
 buildConfigurationList = {IDS['applist']}; }};
{IDS['applist']} = {{ isa = XCConfigurationList; buildConfigurations = ({IDS['appdebug']}, {IDS['apprelease']}); }};
{IDS['appdebug']} = {{ isa = XCBuildConfiguration; name = Debug; {base} buildSettings = {{ {s} {info} }}; }};
{IDS['apprelease']} = {{ isa = XCBuildConfiguration; name = Release; {base} buildSettings = {{ {s} {info} }}; }};
{IDS['shell']} = {{ isa = PBXShellScriptBuildPhase; shellScript = "echo DO-NOT-EXPORT-THIS-SCRIPT"; }};
{refs}
"""
    if other:
        data += f"""
{IDS['other']} = {{ isa = PBXNativeTarget; name = ReaderTests; productType = "com.apple.product-type.bundle.unit-test";
 buildConfigurationList = {IDS['otherlist']}; }};
{IDS['otherlist']} = {{ isa = XCConfigurationList; buildConfigurations = ({IDS['otherdebug']}, {IDS['otherrelease']}); }};
{IDS['otherdebug']} = {{ isa = XCBuildConfiguration; name = Debug; {other_base} buildSettings = {{ {'PRODUCT_BUNDLE_IDENTIFIER = com.example.tests;' if not other_base else ''} }}; }};
{IDS['otherrelease']} = {{ isa = XCBuildConfiguration; name = Release; {other_base} buildSettings = {{ {'PRODUCT_BUNDLE_IDENTIFIER = com.example.tests;' if not other_base else ''} }}; }};
"""
    data += f"}}; rootObject = {IDS['project']}; }}\n"
    return data.encode()


def scheme():
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme version="1.3">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES">
  <BuildActionEntries><BuildActionEntry buildForArchiving="YES" buildForRunning="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{IDS['app']}"
    ReferencedContainer="container:Reader.xcodeproj" BlueprintName="Reader" BuildableName="Reader.app"/>
  </BuildActionEntry></BuildActionEntries>
 </BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
'''.encode()


def ios(**kwargs):
    return {identity.CONFIG_PATH: config("ios"), PBX: pbx(**kwargs), SCHEME: scheme()}


class ProjectIdentityTests(unittest.TestCase):
    def analyze(self, sources, selection=ANDROID, **kwargs):
        with ExitStack() as stack:
            for target in ("subprocess.Popen", "os.system", "pathlib.Path.open",
                           "mobile_release.discovery.run_owned"):
                stack.enter_context(patch(target, side_effect=AssertionError("Passive analysis executed/opened a source")))
            return identity.analyze_project_identity(sources, selection, **kwargs)

    def prepared(self, sources, selection=ANDROID):
        found = self.analyze(sources, selection)
        self.assertTrue(found.supported, found.view)
        return identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")

    def refused(self, sources, code, selection=ANDROID, **kwargs):
        found = self.analyze(sources, selection, **kwargs)
        self.assertFalse(found.supported)
        self.assertEqual(found.diagnostics[0].code, code, found.view)
        self.assertGreaterEqual(found.diagnostics[0].line, 1)
        return found.diagnostics[0]

    def test_android_literal_changes_only_application_and_saved_ids_not_namespace(self):
        sources = android()
        prepared = self.prepared(sources)
        self.assertEqual(set(dict(prepared._payloads)), {identity.CONFIG_PATH, "app/build.gradle.kts"})
        self.assertEqual(dict(prepared._payloads)["app/build.gradle.kts"],
                         sources["app/build.gradle.kts"].replace(OLD.encode(), NEW.encode()))
        self.assertIn(b'namespace = "com.example.source"', dict(prepared._payloads)["app/build.gradle.kts"])
        self.assertTrue(prepared.view["retainVersionReservations"])
        self.assertTrue(prepared.view["buildVerificationRequired"])

    def test_groovy_old_apply_and_exact_crlf_comments_quotes_and_no_final_newline(self):
        raw = ("apply plugin: 'com.android.application'\r\n// café source comment\r\n"
               "android { namespace 'com.example.source'; defaultConfig { applicationId '" + OLD + "' } }")
        sources = android()
        del sources["app/build.gradle.kts"]
        sources["app/build.gradle"] = raw.encode()
        self.assertEqual(dict(self.prepared(sources)._payloads)["app/build.gradle"], raw.replace(OLD, NEW).encode())

    def test_legacy_plugin_apply_cannot_target_another_project_or_have_extra_controls(self):
        for plugin in ('other.apply(plugin = "com.android.application")',
                       'other.\napply(plugin = "com.android.application")',
                       'apply plugin: "com.android.application", to: otherProject',
                       'apply(plugin = "com.android.application", to = otherProject)'):
            self.refused(android(plugin + f'\nandroid {{ defaultConfig {{ applicationId = "{OLD}" }} }}'),
                         "imported-control")
        for statement in (f'other.\napplicationId = "{OLD}"', f'return; applicationId = "{OLD}"'):
            found = self.analyze(android('plugins { id("com.android.application") }\n'
                                        f'android {{ defaultConfig {{ {statement} }} }}'))
            self.assertFalse(found.supported)

    def test_comments_and_strings_never_select_a_fake_identity(self):
        raw = ('plugins { id("com.android.application") }\n'
               'val fake = "android { defaultConfig { applicationId = \\\"com.example.fake\\\" } }"\n'
               '/* applicationId = "com.example.comment" /* nested */ */\n'
               'android { namespace = "com.example.source"; defaultConfig { applicationId = "' + OLD + '" } }')
        prepared = self.prepared(android(raw))
        after = dict(prepared._payloads)["app/build.gradle.kts"]
        self.assertIn(b"com.example.fake", after)
        self.assertIn(b"com.example.comment", after)

    def test_kmp_catalog_chooses_actual_application_not_shared_library(self):
        sources = android('plugins { alias(libs.plugins.android.application); alias(libs.plugins.kotlin.multiplatform) }\n'
                          f'android {{ defaultConfig {{ applicationId = "{OLD}" }} }}')
        sources["gradle/libs.versions.toml"] = (b'[plugins]\nandroid-application = { id = "com.android.application", version = "8.9.0" }\n'
            b'kotlin-multiplatform = { id = "org.jetbrains.kotlin.multiplatform", version = "2.1.0" }\n')
        sources["shared/build.gradle.kts"] = b'plugins { id("com.android.library") }\nandroid { namespace = "com.example.shared" }'
        self.assertTrue(self.analyze(sources).supported)
        sources[identity.CONFIG_PATH] = config(module=":shared")
        self.refused(sources, "ambiguous-target", identity.IdentitySelection("android", ":shared", continuity="unknown"))

    def test_apply_false_does_not_make_a_library_an_application(self):
        sources = android(f'plugins {{ id("com.android.application")\n apply false }}\nandroid {{ defaultConfig {{ applicationId = "{OLD}" }} }}')
        self.refused(sources, "ambiguous-target")

    def test_dynamic_expression_and_wrong_context_refuse_with_exact_location(self):
        for value in ('providers.gradleProperty("APP_ID").get()', '"' + OLD + '" + ".changed"', '"${appId}"'):
            sources = android('plugins { id("com.android.application") }\nandroid {\n defaultConfig {\n applicationId = ' + value + '\n }\n}')
            diagnostic = self.refused(sources, "dynamic-identity")
            self.assertEqual((diagnostic.path, diagnostic.line), ("app/build.gradle.kts", 4))
        self.refused(android('plugins { id("com.android.application") }\n'
            f'fun sample() {{ applicationId = "{OLD}" }}\nandroid {{ defaultConfig {{ }} }}'), "dynamic-identity")

    def test_flavors_release_suffixes_and_late_mutators_refuse(self):
        for suffix, code in (('productFlavors { create("free") {} }', "variant-identity"),
                             ('buildTypes { release { applicationIdSuffix = ".release" } }', "variant-identity"),
                             ('afterEvaluate { }', "dynamic-identity"),
                             ('defaultConfig.applicationId = "com.example.other"', "dynamic-identity")):
            self.refused(android(f'plugins {{ id("com.android.application") }}\nandroid {{ defaultConfig {{ applicationId = "{OLD}" }}\n{suffix}\n}}'), code)

    def test_build_type_init_with_refuses_inherited_debug_suffix(self):
        for path, build_types in (
                ("app/build.gradle.kts",
                 '  getByName("debug") { applicationIdSuffix = ".debug" }\n'
                 '  getByName("release") {\n   initWith(getByName("debug"))\n  }\n'),
                ("app/build.gradle",
                 '  debug { applicationIdSuffix ".debug" }\n'
                 '  release {\n   initWith debug\n  }\n')):
            with self.subTest(path=path):
                raw = ('plugins { id("com.android.application") }\n'
                       'android {\n namespace = "com.example.source"\n'
                       f' defaultConfig {{ applicationId = "{OLD}" }}\n'
                       ' buildTypes {\n' + build_types + ' }\n}\n')
                sources = android()
                del sources["app/build.gradle.kts"]
                sources[path] = raw.encode()
                diagnostic = self.refused(sources, "dynamic-identity")
                self.assertEqual((diagnostic.path, diagnostic.line, diagnostic.column), (path, 8, 4))

    def test_init_with_comments_and_strings_keep_literal_identity_supported(self):
        for path, declaration, debug in (
                ("app/build.gradle.kts", "val", 'getByName("debug") { applicationIdSuffix = ".debug" }'),
                ("app/build.gradle", "def", 'debug { applicationIdSuffix ".debug" }')):
            with self.subTest(path=path):
                raw = ('plugins { id("com.android.application") }\n'
                       f'{declaration} note = "initWith(debug)"\n'
                       '// initWith(debug)\n/* initWith debug */\n'
                       'android {\n namespace = "com.example.source"\n'
                       f' defaultConfig {{ applicationId = "{OLD}" }}\n'
                       ' buildTypes { ' + debug + ' }\n}\n')
                sources = android()
                del sources["app/build.gradle.kts"]
                sources[path] = raw.encode()
                prepared = self.prepared(sources)
                self.assertEqual(set(dict(prepared._payloads)), {identity.CONFIG_PATH, path})
                self.assertEqual(dict(prepared._payloads)[path], raw.replace(OLD, NEW).encode())

    def test_root_and_settings_controls_or_buildsrc_cannot_be_silently_ignored(self):
        for path, source in (("build.gradle.kts", 'subprojects { android { } }'),
                             ("settings.gradle.kts", 'includeBuild("build-logic")'),
                             ("app/build.gradle.kts", 'apply(from = "identity.gradle")')):
            sources = android()
            sources[path] = source.encode()
            self.refused(sources, "imported-control")
        self.refused(android(), "unsupported-plugin", directories=("buildSrc",))

    def test_unknown_plugin_does_not_claim_a_controlling_literal(self):
        self.refused(android('plugins { id("company.application") }\n'
            f'android {{ defaultConfig {{ applicationId = "{OLD}" }} }}'), "unsupported-plugin")

    def test_applied_provider_plugin_blocks_identity_change_even_if_mrk_service_is_disabled(self):
        for declaration in ('plugins { id("com.google.gms.google-services") }',
                            'plugins { id("com.google.firebase.crashlytics") }',
                            'apply plugin: "com.google.gms.google-services"',
                            'plugins { alias(libs.plugins.google.services) }'):
            source = f'apply plugin: "com.android.application"\n{declaration}\nandroid {{ defaultConfig {{ applicationId = "{OLD}" }} }}'
            sources = android(source)
            sources["gradle/libs.versions.toml"] = b'[plugins]\ngoogle-services = { id = "com.google.gms.google-services", version = "4.4.2" }\n'
            found = self.analyze(sources)
            self.assertTrue(found.supported, found.view)
            self.assertFalse(identity.prepare_project_identity(found, OLD, expected_revision=found.revision, intent="preserve").changed)
            with self.assertRaises(identity.IdentityInputError) as error:
                identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")
            self.assertEqual((error.exception.diagnostic.code, error.exception.diagnostic.path,
                              error.exception.diagnostic.line), ("dependent-service", "app/build.gradle.kts", 2))
        sources = android(f'plugins {{ id("com.android.application"); id("com.google.gms.google-services") apply false }}\n'
                          f'android {{ defaultConfig {{ applicationId = "{OLD}" }} }}')
        self.assertTrue(self.prepared(sources).changed)

    def test_root_and_settings_convention_or_resolution_control_are_not_ignored(self):
        for path, source, code in (
                ("build.gradle.kts", 'plugins { id("company.root") }', "unsupported-plugin"),
                ("settings.gradle.kts", 'plugins { id("company.settings") }\ninclude(":app")', "unsupported-plugin"),
                ("settings.gradle.kts", 'pluginManagement { plugins { id("company.android") } }\ninclude(":app")', "unsupported-plugin"),
                ("settings.gradle.kts", 'pluginManagement { resolutionStrategy {} }\ninclude(":app")', "imported-control"),
                ("settings.gradle.kts", 'dependencyResolutionManagement { versionCatalogs {} }\ninclude(":app")', "imported-control"),
                ("build.gradle.kts", 'plugins.withId("com.android.application") {}', "unsupported-plugin")):
            sources = android()
            sources[path] = source.encode()
            diagnostic = self.refused(sources, code)
            self.assertEqual(diagnostic.path, path)

    def test_android_saved_module_and_literal_settings_include_must_agree(self):
        for settings, code in ((b'include(":shared")', "target-mismatch"),
                               (b'if (enabled) { include(":app") }', "conditional-config"),
                               (b'include(module)', "imported-control"),
                               (b'include(":app"); project(":app").name = "renamed"', "imported-control"),
                               (b'include(":app"); rootProject.buildFileName = "custom.gradle"', "imported-control")):
            sources = android()
            sources["settings.gradle.kts"] = settings
            self.refused(sources, code)
        sources = android()
        del sources["settings.gradle.kts"]
        sources["settings.gradle"] = b"rootProject.name = 'Reader'\ninclude ':app', ':shared'\n"
        self.assertTrue(self.analyze(sources).supported)
        data = json.loads(sources[identity.CONFIG_PATH])
        del data["android"]["module"]
        sources[identity.CONFIG_PATH] = json.dumps(data).encode()
        self.refused(sources, "target-mismatch")

    def test_saved_identity_must_agree_with_source_before_preparation(self):
        sources = android()
        sources[identity.CONFIG_PATH] = config(applicationId="com.example.different")
        self.refused(sources, "identity-mismatch")

    def test_existing_or_approved_identity_cannot_be_changed_using_new_toggle(self):
        sources = android()
        for selection in (identity.IdentitySelection("android", ":app"), ANDROID):
            if selection is ANDROID:
                sources[identity.CONFIG_PATH] = json.dumps(android_config(status="approved")).encode()
            found = self.analyze(sources, selection)
            self.assertTrue(found.supported, found.view)
            with self.assertRaises(identity.IdentityInputError) as error:
                identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")
            self.assertEqual(error.exception.diagnostic.code, "existing-application")
            same = identity.prepare_project_identity(found, OLD, expected_revision=found.revision, intent="preserve")
            self.assertFalse(same.changed)

    def test_unknown_requires_explicit_new_and_never_asserts_store_nonexistence(self):
        found = self.analyze(android())
        with self.assertRaises(identity.IdentityInputError) as error:
            identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="preserve")
        self.assertEqual(error.exception.diagnostic.code, "new-intent-required")
        prepared = identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")
        self.assertIn("not been checked", prepared.view["warnings"][0])

    def test_stale_revision_invalid_identifiers_and_dependent_provider_are_not_adopted(self):
        found = self.analyze(android())
        for value, revision in ((NEW, "f" * 32), ("new", found.revision), ("com.example.bad-id", found.revision),
                                ("com.example.id\n", found.revision)):
            with self.assertRaises(identity.IdentityInputError):
                identity.prepare_project_identity(found, value, expected_revision=revision, intent="new-application")
        sources = android()
        data = json.loads(sources[identity.CONFIG_PATH])
        data["services"]["androidFirebase"] = "required"
        sources[identity.CONFIG_PATH] = json.dumps(data).encode()
        found = self.analyze(sources)
        with self.assertRaises(identity.IdentityInputError) as error:
            identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")
        self.assertEqual(error.exception.diagnostic.code, "dependent-service")

    def test_source_inventory_bounds_and_private_or_alias_paths_refuse(self):
        for name in ("../app/build.gradle", "release/private/build.gradle", ".git/build.gradle", "APP/build.gradle.kts"):
            sources = android()
            sources[name] = sources["app/build.gradle.kts"]
            with self.assertRaises(identity.IdentityInputError):
                self.analyze(sources)
        sources = android()
        sources["app/build.gradle.kts"] = b"x" * (identity.MAX_FILE_BYTES + 1)
        with self.assertRaises(identity.IdentityInputError):
            self.analyze(sources)

    def test_ios_selected_application_configs_not_tests_or_unrelated_text(self):
        sources = ios(other=True)
        prepared = self.prepared(sources, IOS)
        after = dict(prepared._payloads)[PBX]
        self.assertEqual(after, sources[PBX].replace(OLD.encode(), NEW.encode()))
        self.assertIn(b"com.example.tests", after)
        self.assertIn(b"DO-NOT-EXPORT-THIS-SCRIPT", after)
        self.assertEqual(prepared.analysis.configurations, ("Debug", "Release"))

    def test_ios_higher_target_setting_overrides_project_setting_without_touching_it(self):
        sources = ios(project_settings="PRODUCT_BUNDLE_IDENTIFIER = com.example.project;")
        prepared = self.prepared(sources, IOS)
        self.assertIn(b"com.example.project", dict(prepared._payloads)[PBX])

    def test_ios_target_kind_or_saved_container_mismatch_refuses(self):
        self.refused(ios(other=True), "ambiguous-target",
                     identity.IdentitySelection("ios", "ReaderTests", IOS.project, "unknown"))
        sources = ios()
        data = json.loads(sources[identity.CONFIG_PATH])
        del data["ios"]["project"]
        data["ios"]["workspace"] = "Reader.xcworkspace"
        sources[identity.CONFIG_PATH] = json.dumps(data).encode()
        self.refused(sources, "target-mismatch", IOS)

    def test_ios_debug_release_disagreement_and_dynamic_variables_refuse(self):
        sources = ios()
        sources[PBX] = sources[PBX].replace(OLD.encode(), b"com.example.different", 1)
        self.refused(sources, "ambiguous-identity", IOS)
        self.refused(ios(app_settings='PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_ID).reader";'), "dynamic-identity", IOS)

    def test_xcconfig_unconditional_include_edits_only_the_actual_controlling_file(self):
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; path = Config/Release.xcconfig; sourceTree = SOURCE_ROOT; }};'
        sources = ios(app_settings="", base=IDS["config"], refs=refs)
        sources["iosApp/Config/Release.xcconfig"] = b'#include "../Shared/Identity.xcconfig"\nOTHER = keep\n'
        sources["iosApp/Shared/Identity.xcconfig"] = f'// keep\r\n PRODUCT_BUNDLE_IDENTIFIER = {OLD}\r\n'.encode()
        prepared = self.prepared(sources, IOS)
        self.assertNotIn(PBX, dict(prepared._payloads))
        self.assertEqual(dict(prepared._payloads)["iosApp/Shared/Identity.xcconfig"],
                         sources["iosApp/Shared/Identity.xcconfig"].replace(OLD.encode(), NEW.encode()))
        self.assertEqual(len(prepared.view["changes"]), 2)

    def test_xcconfig_line_continuation_cannot_hide_inherited_bundle_id_control(self):
        path = "iosApp/Identity.xcconfig"
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; path = Identity.xcconfig; sourceTree = SOURCE_ROOT; }};'
        for newline in ("\n", "\r\n"):
            for ending in ("\\", "\\ \t; \t"):
                with self.subTest(newline=newline, ending=ending):
                    sources = ios(app_settings="", base=IDS["config"], refs=refs,
                                  project_settings=f"PRODUCT_BUNDLE_IDENTIFIER = {OLD};")
                    sources[path] = newline.join(("// keep context", "IGNORED_NOTE = keep " + ending,
                                                  f"PRODUCT_BUNDLE_IDENTIFIER = {OLD}", "")).encode()
                    diagnostic = self.refused(sources, "unsupported-syntax", IOS)
                    self.assertEqual((diagnostic.path, diagnostic.line, diagnostic.column), (path, 2, 21))

    def test_xcconfig_comment_and_closed_string_backslashes_keep_literal_identity_supported(self):
        path = "iosApp/Identity.xcconfig"
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; path = Identity.xcconfig; sourceTree = SOURCE_ROOT; }};'
        for newline in ("\n", "\r\n"):
            for quote in ("", '"'):
                with self.subTest(newline=newline, quote=quote):
                    sources = ios(app_settings="", base=IDS["config"], refs=refs)
                    raw = newline.join((r"// kept \ comment text", r"/* kept \ block comment */",
                                        r'OTHER = "closed \\ string"',
                                        f"PRODUCT_BUNDLE_IDENTIFIER = {quote}{OLD}{quote}", "")).encode()
                    sources[path] = raw
                    prepared = self.prepared(sources, IOS)
                    self.assertEqual(set(dict(prepared._payloads)), {identity.CONFIG_PATH, path})
                    self.assertEqual(dict(prepared._payloads)[path], raw.replace(OLD.encode(), NEW.encode()))

    def test_shared_scheme_binds_selected_application_and_remains_read_only(self):
        sources = ios()
        prepared = self.prepared(sources, IOS)
        self.assertNotIn(SCHEME, dict(prepared._payloads))
        self.assertEqual(sources[SCHEME], scheme())
        value = json.loads(sources[identity.CONFIG_PATH])
        value["ios"]["archiveConfiguration"] = "Missing"
        sources[identity.CONFIG_PATH] = json.dumps(value, indent=2).encode()
        diagnostic = self.refused(sources, "scheme-selection", IOS)
        self.assertEqual(diagnostic.path, identity.CONFIG_PATH)
        self.assertGreater(diagnostic.line, 1)

    def test_wrong_or_custom_archive_scheme_refuses_without_guessing_target_names(self):
        extra = (b'<BuildActionEntry buildForArchiving="YES"><BuildableReference BuildableIdentifier="primary" '
                 b'BlueprintIdentifier="OTHER" ReferencedContainer="container:Reader.xcodeproj"/></BuildActionEntry>')
        for value in (scheme().replace(IDS["app"].encode(), IDS["other"].encode()),
                      scheme().replace(b"container:Reader.xcodeproj", b"container:Another.xcodeproj"),
                      scheme().replace(b'buildConfiguration="Release"', b'buildConfiguration="Debug"'),
                      scheme().replace(b"</BuildActionEntries>", extra + b"</BuildActionEntries>"),
                      scheme().replace(b'buildForArchiving="YES"', b'buildForArchiving="NO"'),
                      scheme().replace(b"</BuildAction>", b'<PreActions><ExecutionAction ActionType="script"/></PreActions></BuildAction>'),
                      scheme().replace(b"<Scheme version", b'<!DOCTYPE Scheme [<!ENTITY synthetic "PRIVATE_VALUE">]><Scheme version')):
            sources = ios()
            sources[SCHEME] = value
            diagnostic = self.refused(sources, "scheme-selection", IOS)
            self.assertEqual(diagnostic.path, SCHEME)
            self.assertNotIn("PRIVATE_VALUE", json.dumps(diagnostic.as_dict()))
        sources = ios()
        del sources[SCHEME]
        diagnostic = self.refused(sources, "missing-control", IOS)
        self.assertEqual(diagnostic.path, SCHEME)

    def test_missing_saved_scheme_is_passive_setup_only_and_same_identity_noop(self):
        sources = ios()
        value = json.loads(sources[identity.CONFIG_PATH])
        del value["ios"]["scheme"]
        sources[identity.CONFIG_PATH] = json.dumps(value).encode()
        found = self.analyze(sources, IOS)
        self.assertTrue(found.supported, found.view)
        self.assertIn("Save a shared Xcode scheme", found.view["nextStep"])
        self.assertFalse(identity.prepare_project_identity(found, OLD, expected_revision=found.revision, intent="preserve").changed)
        with self.assertRaises(identity.IdentityInputError) as error:
            identity.prepare_project_identity(found, NEW, expected_revision=found.revision, intent="new-application")
        self.assertEqual(error.exception.diagnostic.code, "scheme-required")

    def test_xcconfig_conditionals_cycles_missing_and_duplicate_controls_refuse(self):
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; path = Config/Release.xcconfig; sourceTree = SOURCE_ROOT; }};'
        for content, code in ((f'PRODUCT_BUNDLE_IDENTIFIER[sdk=iphoneos*] = {OLD}', "conditional-config"),
                              ('#include? "Absent.xcconfig"', "conditional-config"),
                              ('#include "Release.xcconfig"', "include-cycle"),
                              ('#include "Absent.xcconfig"', "missing-control"),
                              (f'PRODUCT_BUNDLE_IDENTIFIER = {OLD}\nPRODUCT_BUNDLE_IDENTIFIER = {OLD}', "ambiguous-identity")):
            sources = ios(app_settings="", base=IDS["config"], refs=refs)
            sources["iosApp/Config/Release.xcconfig"] = content.encode()
            self.refused(sources, code, IOS)

    def test_xcconfig_shared_through_group_alias_is_not_exclusive_to_selected_app(self):
        refs = f'''{IDS['config']} = {{ isa = PBXFileReference; path = Config/Shared.xcconfig; sourceTree = SOURCE_ROOT; }};
{IDS['alias']} = {{ isa = PBXFileReference; path = Shared.xcconfig; sourceTree = "<group>"; }};
{IDS['group']} = {{ isa = PBXGroup; path = Config; sourceTree = "<group>"; children = ({IDS['alias']}); }};'''
        sources = ios(app_settings="", base=IDS["config"], other=True, other_base=IDS["alias"], refs=refs,
                      main_children=IDS["group"])
        sources["iosApp/Config/Shared.xcconfig"] = f'PRODUCT_BUNDLE_IDENTIFIER = {OLD}\n'.encode()
        self.refused(sources, "shared-control", IOS)

    def test_xcconfig_shared_by_another_xcode_project_or_inherited_target_is_not_exclusive(self):
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; path = Shared.xcconfig; sourceTree = SOURCE_ROOT; }};'
        sources = ios(app_settings="", base=IDS["config"], refs=refs)
        sources["iosApp/Shared.xcconfig"] = f'PRODUCT_BUNDLE_IDENTIFIER = {OLD}\n'.encode()
        sources["iosApp/Second.xcodeproj/project.pbxproj"] = pbx(app_settings="", base=IDS["config"], refs=refs)
        self.refused(sources, "shared-control", IOS)
        del sources["iosApp/Second.xcodeproj/project.pbxproj"]
        sources[PBX] = pbx(app_settings="", base=IDS["config"], other=True, other_base=IDS["config"], refs=refs)
        for name in ("otherdebug", "otherrelease"):
            key = f'{IDS[name]} = {{ isa = XCBuildConfiguration;'
            start = sources[PBX].index(key.encode())
            index = sources[PBX].index(b'buildSettings = { ', start) + len(b'buildSettings = { ')
            sources[PBX] = sources[PBX][:index] + b'PRODUCT_BUNDLE_IDENTIFIER = "$(inherited).tests"; ' + sources[PBX][index:]
        self.refused(sources, "shared-control", IOS)

    def test_xcconfig_bad_include_reports_include_file_and_exact_line(self):
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; path = Shared.xcconfig; sourceTree = SOURCE_ROOT; }};'
        sources = ios(app_settings="", base=IDS["config"], refs=refs)
        sources["iosApp/Shared.xcconfig"] = b'// context\n// context\n#include "../../outside.xcconfig"\n'
        diagnostic = self.refused(sources, "imported-control", IOS)
        self.assertEqual((diagnostic.path, diagnostic.line), ("iosApp/Shared.xcconfig", 3))

    def test_info_plist_must_use_the_setting_not_an_independent_literal_id(self):
        sources = ios(info='INFOPLIST_FILE = Reader/Info.plist;')
        path = "iosApp/Reader/Info.plist"
        sources[path] = plistlib.dumps({"CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)"})
        self.assertTrue(self.analyze(sources, IOS).supported)
        sources[path] = plistlib.dumps({"CFBundleIdentifier": OLD})
        self.refused(sources, "unsupported-plist", IOS)
        sources[path] = (b'<?xml version="1.0"?><plist version="1.0"><dict>'
                         b'<key>CFBundleIdentifier</key><string>com.example.other</string>'
                         b'<key>CFBundleIdentifier</key><string>$(PRODUCT_BUNDLE_IDENTIFIER)</string></dict></plist>')
        self.refused(sources, "unsupported-plist", IOS)
        self.refused(ios(info="CODE_SIGN_ENTITLEMENTS = Reader/Reader.entitlements; GENERATE_INFOPLIST_FILE = YES;"),
                     "imported-control", IOS)

    def test_generated_and_explicit_plists_refuse_identity_overrides_and_preprocessing(self):
        for setting in (f"INFOPLIST_KEY_CFBundleIdentifier = {OLD};", "INFOPLIST_PREPROCESS = YES;",
                        'INFOPLIST_PREPROCESS = "$(CUSTOM_PREPROCESS)";', "INFOPLIST_PREFIX_HEADER = Identity.h;",
                        'INFOPLIST_PREPROCESSOR_DEFINITIONS = "APP_ID=PRIVATE_VALUE";',
                        'INFOPLIST_OTHER_PREPROCESSOR_FLAGS = "-include Identity.h";',
                        "INFOPLIST_EXPAND_BUILD_SETTINGS = NO;"):
            diagnostic = self.refused(ios(info="GENERATE_INFOPLIST_FILE = YES; " + setting), "plist-override", IOS)
            self.assertEqual(diagnostic.path, PBX)
            self.assertNotIn("PRIVATE_VALUE", json.dumps(diagnostic.as_dict()))
        self.assertTrue(self.analyze(ios(info="GENERATE_INFOPLIST_FILE = YES; INFOPLIST_PREPROCESS = NO; "
                                             "INFOPLIST_EXPAND_BUILD_SETTINGS = YES;"), IOS).supported)
        path = "iosApp/Identity.xcconfig"
        refs = f'{IDS["config"]} = {{ isa = PBXFileReference; sourceTree = SOURCE_ROOT; path = Identity.xcconfig; }};'
        sources = ios(base=IDS["config"], refs=refs)
        sources[path] = b"// captured override\nINFOPLIST_KEY_CFBundleIdentifier = com.example.other\n"
        diagnostic = self.refused(sources, "plist-override", IOS)
        self.assertEqual((diagnostic.path, diagnostic.line), (path, 2))

    def test_generated_projects_refuse_generator_location(self):
        sources = ios()
        sources["project.yml"] = b"name: Synthetic\n"
        diagnostic = self.refused(sources, "generated-project", IOS)
        self.assertEqual(diagnostic.path, "project.yml")

    def test_malformed_sources_have_closed_redacted_diagnostics_not_parser_errors(self):
        for raw in ('plugins {', 'plugins { id }', 'plugins { alias() }',
                    'plugins { id("com.android.application") version }',
                    'plugins { id("com.android.application") apply }', '{ )', '/* unfinished'):
            found = self.analyze(android(raw))
            self.assertFalse(found.supported)
            self.assertEqual(found.diagnostics[0].path, "app/build.gradle.kts")
            self.assertNotIn(raw, str(found.view))
        for raw in (b'{', b'{ objects = { x = ', b'"unterminated', b'{ objects = (); rootObject = x; }'):
            sources = ios()
            sources[PBX] = raw
            self.assertFalse(self.analyze(sources, IOS).supported)
        for target in (":..:app", ":app:.", ":private:app"):
            with self.assertRaises(identity.IdentityInputError):
                self.analyze(android(), identity.IdentitySelection("android", target, continuity="unknown"))

    def test_public_views_never_export_build_files_or_unrelated_values(self):
        prepared = self.prepared(ios(), IOS)
        public = json.dumps([prepared.analysis.view, prepared.view])
        self.assertNotIn("DO-NOT-EXPORT-THIS-SCRIPT", public)
        self.assertNotIn("shellScript", public)
        self.assertNotIn("payloads", public)
        self.assertNotIn("sha256", public)
        self.assertIn("recognized-literal-source-only", public)
        sources = ios()
        sources[PBX] = sources[PBX].replace(b"name = Debug;", b'name = "' + b"PRIVATE_NOT_A_CONFIGURATION" * 100 + b'";')
        found = self.analyze(sources, IOS)
        self.assertFalse(found.supported)
        self.assertNotIn("PRIVATE_NOT_A_CONFIGURATION", json.dumps(found.view))


if __name__ == "__main__":
    unittest.main()
