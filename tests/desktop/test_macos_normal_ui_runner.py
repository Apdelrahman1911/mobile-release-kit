"""Inert DATA/source regressions, NOT XCTest, native API or app evidence."""
from __future__ import annotations

import importlib.util
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile
import sys
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
SPEC = importlib.util.spec_from_file_location("mrk_normal_ui_runner_data", ROOT / "desktop/tools/macos_normal_ui_runner.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SWIFT = ROOT / "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"


# Exact regional SOURCE inverse for the separately reviewed positive/private
# addition. No existing ordinary-owner or historical whole-source hash is relaxed.
ANDROID_POSITIVE_SWIFT_INVERSE = ((70,
  71,
  '18d47688246d2599562ecbd80520613298438449478bcd019b61580c1760e8e5',
  '        init(seconds: TimeInterval) throws {\n'),
 (72,
  73,
  '90dc136b10da6a35858e66557a61d99462dcc242cc995e75c5b147d84c193909',
  '            guard now.isFinite, now >= 0, seconds == 60 || seconds == 300,\n'),
 (366,
  367,
  'b42389798fd9f698dbb02bdfba8d28cad7da3a646fc8303cf46303291909c364',
  '    @MainActor private func beginCase(seconds: TimeInterval) throws {\n'),
 (368,
  369,
  'dfc5996fc7856f951a5b859e0107475a7414a7afa54d08bde50285169cecf622',
  '        let clock = try CaseClock(seconds: seconds)\n'),
 (1056,
  1057,
  '53609dc044126f2020ad5eba2bc00dbce2d9dbdf257630ab0bdea8a720ca3dde',
  '        enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal, '
  'savedVersionRecovery }\n'),
 (1122, 1123, 'ee6ff2553dbc2086998719aa34f1e6d7490f586e97597e3e6714ba3a95e88e03', ''),
 (1148, 1179, 'dfec62301b87370dbba26f83e97d5b71e2ea981616fc1c6c0ff3f3c7448d586a', ''),
 (1244, 1598, 'e7ad67290bdf488bf83f6d914fd9f0a54b0b1889e5ab3f359a5a054ef574d749', ''),
 (1716,
  1717,
  'd87ff8a55c8b4c0a6e25ccf9ab145f62a9d80b38f845ad0e355fe69eed6ecf3e',
  '        // Fixed positive Android output custody. No current Profile enters it.\n'),
 (1797,
  1799,
  '6b52423d9031f297094cfd7ac7804f4600b926ede04e6cf8b668f9108d482de9',
  '            try Self.need(androidOutput == nil && acceptedStages.isEmpty,\n'),
 (2088,
  2089,
  '1a7e02c89ffac69c14e9b959b07d02f6412b54ab6e992b7acc0e7fef9c27a5d7',
  '                let cleanupFacts: StatFacts? = rootNamed == 0 ? StatFacts(createdRoot) : nil\n'),
 (2172,
  2179,
  '6cc28f4048a9ba7524c8ad428d856ca3c1a76d6b72997fd86104812c79bfdfc6',
  '                    catch Refusal.condition(let message) { observed = message == "fixture: " + reason }\n'),
 (2183,
  2193,
  '69ab0671ac44cc263a23bdfab0de21f66c78c214dd5b36101be90745c0867ef7',
  '                    guard let initialRoot = cleanupFacts else { throw Refusal.condition("fixture: Android DATA '
  'created root facts absent") }\n'
  '                    try need(initialRoot.mode & 0o7777 == 0o700 && initialRoot.uid == getuid()\n'
  '                        && initialRoot.gid == getgid() && initialRoot.flags == 0\n'
  '                        && initialRoot.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)\n'
  '                        && initialRoot == facts(cleanupRoot) && initialRoot == named(temporary, rootName),\n'
  '                        "Android output DATA private original root differs")\n'),
 (2362,
  2366,
  '8ee7a52613fd69c28a82a3bcf3f796cf5b75c525a1f9fbadfdb6d771280037b0',
  '                if let primary { throw primary }\n'),
 (2549,
  2551,
  '53e07f82570af9005a9512df66fea819c81413d6eb19eda20bdda68ec624e363',
  '            let resourceName = projectData ? "normal-project-v1" : "normal-persistence-v1"\n'),
 (2577, 2582, 'f843744260a518c433e5249e14de36aeecefc75b6aa14c52a287b2e79d395c88', ''),
 (2583,
  2584,
  '846b4564aff220f9be648fe74fd4f7578743414f272cc87ecd86c615fd43607b',
  '            let stagePaths: [String: Set<String>] = projectData ? [\n'),
 (2587,
  2588,
  '768924e1546bba885fa35244665c03e830a5d34dbafd24bc6f521115c402781d',
  '            let expectedOriginals = projectData ? Self.originals : Self.persistenceOriginals\n'),
 (2590,
  2591,
  '292e59ef36b3ab8683b2eadbe6daad8901a7e016b96ae82135397e6934dee655',
  '                && (projectData ? spec.templateDataSHA256?.count == 64 : spec.templateDataSHA256 == nil),\n'),
 (2603, 2610, '2062c0e8796cbbe10fc9fb0fc0ce260a5258e06bc905993b31881b2758b05960', ''),
 (2703,
  2704,
  '5348ad9f129c9675f97a29b18dc87ee3c35c33ce56a3acd87e9a7d16b20544ae',
  '            let root = try adoptDirectory(openat(temporary.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | '
  'O_CLOEXEC),\n'),
 (2705,
  2710,
  '1c512d2679edae9eb9f4db1127ae42eeb3f4e259c2d8e688275718569035c807',
  '            directories[""] = root\n'),
 (2742,
  2743,
  '683c9580e49ee032acc891b3accf807fdb313b618a444bae5cb76faa012fe78e',
  '                let saved = try read(path)\n'),
 (2891, 2897, '47fcb4f08a6315201fbe7551174aff00cf554aeeae5ea7ffb80537605aa2755e', ''),
 (2899,
  2901,
  '330373cd0cb8ea89fc9f5eb6d0c41674e20da54dad89fa27c985c74b0432cb01',
  '                let old = current[path]!, observed = try read(path)\n'),
 (2921,
  2922,
  '92d403fa15562aab3c92fe0e5d78a9893a1f7dd0f440dd6a8614dc2548c60e31',
  '                let observed = try read(path)\n'),
 (2981, 2982, 'd044507984e3652c3ae6eda02752f307ceb65e38a6a8b5f81b3cf40440d6d6df', ''),
 (4698, 4980, 'e6c45d863e0f73cacaff298621176cc7b6ba90026d01f2a6acd536323396f824', ''),
 (5002, 5012, '1370af131a521e62e1f81d1a2a8ecc3e595711ec9bd8c754b6d9ad212d982dbc', ''))

IOS_UNSIGNED_SWIFT_INVERSE = [(70, 71, '9bac829257dc5bfc3a439aac882d2dd08d941c3f649245b3d7a768774a240fb6', '        init(seconds: TimeInterval, androidPositive: Bool = false) throws {\n'), (72, 73, '66f825502f9177249fae4721b875432bc67fb64cb82913b6316d1774c5a49dfd', '            guard now.isFinite, now >= 0, (androidPositive ? seconds == 900 : (seconds == 60 || seconds == 300)),\n'), (213, 214, '6cd754f487e73847150b083af7e63e879a8dbac5ad665697097f9ec96855aa0e', '        func healthy() throws {\n'), (216, 218, '6a92da92d5532c709c9f3120362f8254966396700c0466f327c01b0ab76b5dfa', '            _ = try clock.remaining(1)\n'), (367, 368, 'fd8a6b3740680e236e8d1b7230c780d1b2047a08811daf14f32e2a626a9bbca2', '    @MainActor private func beginCase(seconds: TimeInterval, androidPositive: Bool = false) throws {\n'), (369, 370, '3e8ede215cecb56df70dc3f608cc5f1cee333b9789c9dc3c9dad5490f8a90700', '        let clock = try CaseClock(seconds: seconds, androidPositive: androidPositive)\n'), (1057, 1058, 'fe1a506227717451d1ea704c49f67707355cf944c26b23254692342734be093f', '        enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal, savedVersionRecovery, androidSignedBuild }\n'), (1717, 1815, '8207c234f1e8514a6fc76d5ce60326720330a45af6f3d21a939a9c241306c9fc', ''), (2169, 2172, 'dcf34ab30490e5e6f7018fc3909338186a496fd715c7f6dcc02f3b100cbbb33e', '                             "symlink", "hardlink", "depth", "mode", "input", "wrong-result", "identity", "repeated-start"] {\n'), (2299, 2386, 'b6ebcf146b2dff8f0aad636bf67b3dda1162b9a7dd958e017a298ee8b7610e59', ''), (2511, 2512, '24e72c6479ac7bc1e357f0db0edc814203f1521b12a87159a84c81f83cd3e3b0', ''), (2517, 2518, '206f1b83b020317dd90a1fe16c65d22dc46b4f99d00d66327b63ec35596f83d2', ''), (2719, 2720, 'df6605ab7490f24679c4a978e7c5b13f93f85210ea6444e2e2e9efcfcae013d6', '                let expected = Set(leafPaths.union(expectedDirectories).compactMap { item -> String? in\n'), (2724, 2727, 'c960cb683f36e92409c4c587c97282b29c14f0ae014559e7ee26c650e4b95da0', ''), (2743, 2745, 'b73ca4989daede170caf6b6b1a0998e75ea6ebba25d2f8d1a6fe0156cdd7d1ae', '            let resourceName = androidPositive ? "normal-android-positive-v1" : projectData ? "normal-project-v1" : "normal-persistence-v1"\n'), (2776, 2782, '1107bb850d890130bbb52690bf0a0cb605709f74d8472036002b6a5a015cc10c', ''), (2783, 2784, 'ea2d11d0ac471ad6c10e11edf0f41fed2d107ed6d1e06de7711e25de619a9398', '            let stagePaths: [String: Set<String>] = projectData && !androidPositive ? [\n'), (2787, 2788, '2498cc74fb404e00c579acc48e5cfdd4a0960767e13892af10381bc785c3fbc5', '            let expectedOriginals = androidPositive ? Self.androidPositivePaths : projectData ? Self.originals : Self.persistenceOriginals\n'), (2790, 2791, '1a888d6908be38a47f83ceeb92e6a3bf14a2a1a3aeb4652e02395e1b491f385b', '                && (projectData && !androidPositive ? spec.templateDataSHA256?.count == 64 : spec.templateDataSHA256 == nil),\n'), (2803, 2809, '49b024bd18a645445fbd6b19e3fe2cbad35bf22b7bc08bcde6f5579952779f55', ''), (3149, 3150, '419b3fec90b5f9f9cab66658f88de15a911c551aeb16763ab01e151d74198a49', ''), (3157, 3158, '6849ff7af4e41318c8523669ea36515c7f32c00a1e67b3ef51f7f9e9a490a51e', ''), (3183, 3185, '649cb7eca7a5aa1accb59bfe7e5ae11533ec19478cee237ef8c4c35cb2e98be4', '    // Explicit DATA-only native selection; not an Android-positive application case.\n'), (4951, 5171, 'daf86c7067443724d660940776c521e0d1655f9cc3701f3579faa2c0fbecd1b7', '')]


# Progressive Unicode-character coordinates, each independently SHA-bound to
# the reviewed V2 then V1 removal-only inverse. Historical iOS/Android tables stay exact.
REMOVAL_UI_SWIFT_INVERSE = ((80622,
  81151,
  '769d6f8133da98a9246545d016242bcfe97b677112d9015e9139746eb9eeb633',
  '            try click(renderer.buttons.matching(identifier: "Project settings"), "post-removal-Cancel '
  'settings unavailable")\n'
  '            try click(renderer.buttons.matching(identifier: "Dashboard"), "post-removal-Cancel Dashboard '
  'unavailable")\n'),
 (79308,
  79699,
  '24df5c9b2cc0d3504c70a04403eeb8493ffdd05dea796849a52ef35618061476',
  '        let renderer = try unique(window.webViews, "removal renderer unavailable or ambiguous")\n'),
 (403769,
  404160,
  '2c34411fe7d2fa2b70b5dda3868e01e7f4060cd223d19aab495b0d1d7f943f8a',
  '        // Independent private consuming close after any partial setup or unknown\n'),
 (402192,
  402751,
  '7767c4fd2d151d42c5d0b2ecdbaaacf6fbca0d622b388f52d65eaec4c2957811',
  '                if let owner = originalLaunch { try owner.tearDown(normalQuit: normalQuitObserved) }\n'),
 (63333,
  81939,
  '5b73f478c9711d94ad91041699c4942556b0b0b1153ffb770432a5408333d1f9',
  '    // Finite synthetic files only. No existing project, .git, credential, tool\n'),
 (19944,
  20064,
  'a9a620ff5278b840264427dd203fe578639f3bbd8cebcbb195f8c1cfa2ca72b5',
  '        try require(originalLaunch == nil && entryGateObservation == nil && !normalQuitObserved\n'),
 (18886,
  19544,
  '579a5e4b6046df5507eabaa7cfa730d38f0e3a9e6cd58d1a5b2bd35d4db430b8',
  '    @MainActor private func beginCase(seconds: TimeInterval, androidPositive: Bool = false, iosUnsigned: '
  'Bool = false) throws {\n'
  '        try require(caseClock == nil && journeyDeadline == nil && originalLaunch == nil, "case deadline '
  'cannot be reset")\n'),
 (2557,
  2725,
  '4c449e08120eadbecd8936b8ebbe53a5a1b2674fda21f943728e165599946cf7',
  '    @MainActor private var normalQuitObserved = false\n'))


# Closed progressive UTF8-byte inverse; historical assertions retain their exact original source.
RELEASE_EVIDENCE_SOURCE_INVERSE = ((84244,
  74,
  'ca802d395d94fe8f4e95d598eae6af302f685430f6c2a44c58e0bcacf5636fce',
  'workflowRefusal, savedVersionRecovery, androidSignedBuild'),
 (86055,
  15900,
  '120e7e450ed499d1fb7ee976fced3d494494ebd3e18773d4185372d111305568',
  '        // Extra selection-only DATA belongs only to the ordinary project-field case.\n'),
 (105714,
  117,
  '741bed4c8e5237ce18636d45d36f26e761efcec66d164a23673db0e0bbc0cc51',
  '        var projectPath: String { rootPath + "/project" }'),
 (226077,
  1322,
  '386213f3bb5a42ed262cbc368ea1141492188759ffffd0e7510b04c748780e92',
  '            if profile == .projectFields {\n                try Self.need(Set(originals.keys)'),
 (237724,
  344,
  'afa3317976c40008d856a0ad4dbbf1be3ace0186118641a599b32a1b213f3c07',
  '            if profile == .workflowRefusal {\n                try Self.need(current.count'),
 (341352,
  10403,
  'b7e0e6930ae4301d528d0525a63344f16ca195b00691e3adb743621dc4bb100c',
  '    @MainActor func testSyntheticProjectManagedWorkflowRefusal() throws {\n'))

# Exact current engineering wait/Status amendments only; preserve every prior
# owner/hash assertion by undoing these four uniquely identified regions first.
ENGINEERING_WAIT_STATUS_REGIONS = (('            throw Refusal.condition("missing or ambiguous expected control in " + journeyStage)\n',
  '            if engineeringRequireDiagnosticActive {\n'
  '                try require(false, "missing or ambiguous expected control in " + journeyStage, line: '
  'line)\n'
  '            }\n'
  '            throw Refusal.condition("missing or ambiguous expected control in " + journeyStage)\n'),
 ('            throw Refusal.condition("terminal UI refusal in " + journeyStage)\n',
  '            if engineeringRequireDiagnosticActive {\n'
  '                try require(false, "terminal UI refusal in " + journeyStage, line: line)\n'
  '            }\n'
  '            throw Refusal.condition("terminal UI refusal in " + journeyStage)\n'),
 ('                                       failures: [String] = []) throws -> XCUIElement {\n',
  '                                       failures: [String] = [], line: UInt = #line) throws -> XCUIElement '
  '{\n'),
 ('        try require(window.sheets.count == 0, "reference navigation opened an unexpected native '
  'operation")\n'
  '\n'
  '        let first = try quitSheet(app, window)\n',
  '        try require(window.sheets.count == 0, "reference navigation opened an unexpected native '
  'operation")\n'
  '\n'
  '        // Fresh native document only: a heading or event relay alone is not\n'
  '        // Status invocation admission. An invoke failure remains visible until\n'
  '        // a successful explicit checkStatus; equal-revision display is not a\n'
  '        // separately correlated receipt for this button click.\n'
  '        try click(renderer.buttons.matching(identifier: "Artifacts"), "engineering Artifacts navigation '
  'unavailable")\n'
  '        _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Inspect '
  'selected artifact bytes")), in: renderer)\n'
  '        let artifactStatusQuery = renderer.buttons.matching(identifier: "Check original artifact '
  'status")\n'
  '        let artifactStatus = try waitElement(artifactStatusQuery, in: renderer, enabled: true,\n'
  '                                             failures: ["No new artifact outcome confirmed"])\n'
  '        try reveal(artifactStatus, in: renderer)\n'
  '        try require(artifactStatus.isEnabled && artifactStatus.isHittable,\n'
  '                    "engineering artifact Status read unavailable")\n'
  '        artifactStatus.click() // Actual production bridge command; no fixture result.\n'
  '        _ = try waitElement(artifactStatusQuery, in: renderer, enabled: true,\n'
  '                            failures: ["No new artifact outcome confirmed"])\n'
  '        let artifactAvailability = renderer.staticTexts.matching(NSPredicate(format: "title IN %@", [\n'
  '            "This native document supports reviewing selected artifact bytes. Actual originals and '
  'runtime are rechecked before inspection.",\n'
  '            "The required bundled runtime is not qualified for this document. Missing optional '
  'verification tools are a separate unavailable check."\n'
  '        ]))\n'
  '        _ = try waitElement(artifactAvailability, in: renderer,\n'
  '                            failures: ["No new artifact outcome confirmed"])\n'
  '        try require(renderer.staticTexts.matching(identifier: "No new artifact outcome confirmed").count '
  '== 0,\n'
  '                    "engineering artifact Status invocation did not settle successfully")\n'
  '        let chooseArtifact = try unique(renderer.buttons.matching(identifier: "Choose AAB"),\n'
  '                                        "engineering artifact input control differs")\n'
  '        let reviewArtifact = try unique(renderer.buttons.matching(identifier: "Review artifact '
  'inspection"),\n'
  '                                        "engineering artifact review control differs")\n'
  '        try require(!chooseArtifact.isEnabled && !reviewArtifact.isEnabled,\n'
  '                    "engineering Status observation must not admit a project or inspection")\n'
  '        try engineeringNoFallback(renderer)\n'
  '        try require(window.sheets.count == 0, "engineering Status read opened an unexpected native '
  'operation")\n'
  '        // This proves only a validated native Status in this fresh application,\n'
  '        // not artifact inspection, every ACL entry, or signed/runtime readiness.\n'
  '\n'
  '        let first = try quitSheet(app, window)\n'))

ARTIFACT_WAIT_DIAGNOSTIC_BEGIN = '        // Fixed pre-wait diagnostic only: seven availability texts plus waiting/error.\n'
ARTIFACT_WAIT_DIAGNOSTIC_END = '        // End fixed artifact pre-wait diagnostic; original wait remains authoritative.\n'
ARTIFACT_WAIT_DIAGNOSTIC_SHA256 = '8f6eb5e3fd9beab058345e951d81998496d2c0f8fd538cfebc018e948c001b2b'

def without_artifact_wait_diagnostic_source(source):
    # Exact current-runtime handoff line only; historical SOURCE hashes stay fixed.
    saved_marker = 'raw["sourceInputsSha256"] as? String'
    saved_prior = '                  raw["sourceInputsSha256"] as? String == "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0",\n'
    saved_current = '                  raw["sourceInputsSha256"] as? String == "58f6d68d2db29100ed15fd8c4f8d893b3a0a3dbe1d8cd37b385690c36b9cfa3d",\n'
    if saved_marker in source:
        if (source.count(saved_marker) != 1
                or source.count(saved_prior) + source.count(saved_current) != 1):
            raise AssertionError('saved-version current SOURCE handoff differs')
        source = source.replace(saved_current, saved_prior, 1)
    if 'MRK_MACOS_ENGINEERING_ARTIFACT_QUERY' not in source:
        return source  # Historical intermediate source remains valid for old inverses.
    if (source.count(ARTIFACT_WAIT_DIAGNOSTIC_BEGIN) != 1 or source.count(ARTIFACT_WAIT_DIAGNOSTIC_END) != 1
            or source.count('MRK_MACOS_ENGINEERING_ARTIFACT_QUERY') != 1):
        raise AssertionError('artifact wait diagnostic source markers differ')
    start = source.index(ARTIFACT_WAIT_DIAGNOSTIC_BEGIN)
    end = source.index(ARTIFACT_WAIT_DIAGNOSTIC_END, start) + len(ARTIFACT_WAIT_DIAGNOSTIC_END)
    if hashlib.sha256(source[start:end].encode()).hexdigest() != ARTIFACT_WAIT_DIAGNOSTIC_SHA256:
        raise AssertionError('artifact wait diagnostic exact SOURCE differs')
    return source[:start] + source[end:]

# Exact semantic status scope only; old diagnostic/owner/historical bytes are unchanged.
ARTIFACT_STATUS_GROUP_PRIOR = '        let artifactAvailability = renderer.staticTexts.matching(NSPredicate(format: "title IN %@", [\n'
ARTIFACT_STATUS_GROUP_CURRENT = '        let artifactStatusGroup = try waitElement(named(renderer, "Original artifact inspection status"),\n                                                  in: renderer, failures: ["No new artifact outcome confirmed"])\n        let artifactAvailability = artifactStatusGroup.staticTexts.matching(NSPredicate(format: "value IN %@", [\n'

def without_artifact_status_group_source(source):
    if source.count(ARTIFACT_STATUS_GROUP_CURRENT) != 1:
        raise AssertionError('artifact status group exact SOURCE differs')
    return source.replace(ARTIFACT_STATUS_GROUP_CURRENT, ARTIFACT_STATUS_GROUP_PRIOR, 1)

# First-failure diagnostics undo exactly before every unchanged historical inverse.
ENGINEERING_FIRST_FAILURE_REGIONS = (('        private(set) var firstFailure: String?\n'
  '        init(seconds: TimeInterval, androidPositive: Bool = false, iosUnsigned: Bool = false) throws {\n',
  '        private(set) var firstFailure: String?\n'
  '        enum EngineeringPhase: String {\n'
  '            case admission, launch, catalogue, guideSelection, artifactStatus, artifactSample\n'
  '            case artifactValue, quitCancel, postCancel, quitConfirm, termination, terminal\n'
  '        }\n'
  '        private let engineeringDiagnostic: Bool\n'
  '        private var engineeringPhase: EngineeringPhase = .admission\n'
  '        func recordEngineeringPhase(_ phase: EngineeringPhase) {\n'
  '            // Last ENTERED fixed step only; never completion or a new observation.\n'
  '            if engineeringDiagnostic && firstFailure == nil { engineeringPhase = phase }\n'
  '        }\n'
  '        init(seconds: TimeInterval, androidPositive: Bool = false, iosUnsigned: Bool = false,\n'
  '             engineeringDiagnostic: Bool = false) throws {\n'),
 ('            last = now\n            deadline = now + seconds\n',
  '            last = now\n'
  '            deadline = now + seconds\n'
  '            self.engineeringDiagnostic = engineeringDiagnostic\n'),
 ('        func fail(_ reason: String) -> Refusal {\n'
  '            if firstFailure == nil { firstFailure = reason }\n'
  '            return .condition(firstFailure!)\n'
  '        }\n',
  '        func fail(_ reason: String, line: UInt = #line) -> Refusal {\n'
  '            if firstFailure == nil {\n'
  '                firstFailure = reason\n'
  '                if engineeringDiagnostic && line >= 1 && line <= 65535 {\n'
  '                    '
  'print("MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line=\\(line);phase=\\(engineeringPhase.rawValue)")\n'
  '                }\n'
  '            }\n'
  '            return .condition(firstFailure!)\n'
  '        }\n'),
 ('                                      removal: Bool = false) throws {\n',
  '                                      removal: Bool = false, engineeringDiagnostic: Bool = false) throws '
  '{\n'),
 ('        let clock = try CaseClock(seconds: seconds, androidPositive: androidPositive, iosUnsigned: '
  'iosUnsigned)\n',
  '        let clock = try CaseClock(seconds: seconds, androidPositive: androidPositive, iosUnsigned: '
  'iosUnsigned,\n'
  '                                  engineeringDiagnostic: engineeringDiagnostic)\n'),
 ('            let refusal = caseClock?.fail(reason) ?? Refusal.condition(reason)\n',
  '            let refusal = caseClock?.fail(reason, line: line) ?? Refusal.condition(reason)\n'),
 ('        try beginCase(seconds: 60) // Includes original host/source/input admission.\n',
  '        try beginCase(seconds: 60, engineeringDiagnostic: true) // Includes original host/source/input '
  'admission.\n'),
 ('        let app = try launchEngineeringMain(work: work)\n',
  '        caseClock?.recordEngineeringPhase(.launch)\n'
  '        let app = try launchEngineeringMain(work: work)\n'),
 ('        // Wait on actual current-core guide data below, not a static UI heading.\n',
  '        caseClock?.recordEngineeringPhase(.catalogue)\n'
  '        // Wait on actual current-core guide data below, not a static UI heading.\n'),
 ('        apple.click() // Reference-only selection: no credential import or operation.\n',
  '        caseClock?.recordEngineeringPhase(.guideSelection)\n'
  '        apple.click() // Reference-only selection: no credential import or operation.\n'),
 ('        try click(renderer.buttons.matching(identifier: "Artifacts"), "engineering Artifacts navigation '
  'unavailable")\n',
  '        caseClock?.recordEngineeringPhase(.artifactStatus)\n'
  '        try click(renderer.buttons.matching(identifier: "Artifacts"), "engineering Artifacts navigation '
  'unavailable")\n'),
 ('        // Fixed pre-wait diagnostic only: seven availability texts plus waiting/error.\n',
  '        caseClock?.recordEngineeringPhase(.artifactSample)\n'
  '        // Fixed pre-wait diagnostic only: seven availability texts plus waiting/error.\n'),
 ('        _ = try waitElement(artifactAvailability, in: renderer,\n',
  '        caseClock?.recordEngineeringPhase(.artifactValue)\n'
  '        _ = try waitElement(artifactAvailability, in: renderer,\n'),
 ('        let first = try quitSheet(app, window)\n'
  '        try click(first.buttons.matching(identifier: "Cancel"), "engineering normal Quit Cancel '
  'unavailable")\n',
  '        caseClock?.recordEngineeringPhase(.quitCancel)\n'
  '        let first = try quitSheet(app, window)\n'
  '        try click(first.buttons.matching(identifier: "Cancel"), "engineering normal Quit Cancel '
  'unavailable")\n'),
 ('        try click(renderer.buttons.matching(identifier: "Dashboard"), "engineering post-Cancel navigation '
  'unavailable")\n',
  '        caseClock?.recordEngineeringPhase(.postCancel)\n'
  '        try click(renderer.buttons.matching(identifier: "Dashboard"), "engineering post-Cancel navigation '
  'unavailable")\n'),
 ('        let second = try quitSheet(app, window)\n'
  '        try click(second.buttons.matching(identifier: "Quit"), "engineering normal Quit confirmation '
  'unavailable")\n',
  '        caseClock?.recordEngineeringPhase(.quitConfirm)\n'
  '        let second = try quitSheet(app, window)\n'
  '        try click(second.buttons.matching(identifier: "Quit"), "engineering normal Quit confirmation '
  'unavailable")\n'),
 ('        let end = try clock.end(within: 10)\n'
  '        try require(app.wait(for: .notRunning, timeout: try clock.remaining(10, before: end)), '
  '"engineering normal Quit did not stop UI")\n',
  '        caseClock?.recordEngineeringPhase(.termination)\n'
  '        let end = try clock.end(within: 10)\n'
  '        try require(app.wait(for: .notRunning, timeout: try clock.remaining(10, before: end)), '
  '"engineering normal Quit did not stop UI")\n'),
 ('        try owner.acceptTerminal()\n'
  '        normalQuitObserved = true // Existing teardown still rechecks this SAME original.\n',
  '        caseClock?.recordEngineeringPhase(.terminal)\n'
  '        try owner.acceptTerminal()\n'
  '        normalQuitObserved = true // Existing teardown still rechecks this SAME original.\n'))

def without_engineering_first_failure_source(source):
    for previous, current in reversed(ENGINEERING_FIRST_FAILURE_REGIONS):
        if source.count(current) != 1:
            raise AssertionError("engineering first-failure exact SOURCE differs")
        source = source.replace(current, previous, 1)
    return source

def without_engineering_wait_status_source(source):
    if "MRK_MACOS_ENGINEERING_FIRST_FAILURE" in source:
        source = without_engineering_first_failure_source(source)
    if "artifactStatusGroup" in source or "Original artifact inspection status" in source:
        source = without_artifact_status_group_source(source)
    source = without_artifact_wait_diagnostic_source(source)
    if not any(current in source for _, current in ENGINEERING_WAIT_STATUS_REGIONS):
        return source
    for previous, current in ENGINEERING_WAIT_STATUS_REGIONS:
        if source.count(current) != 1:
            raise AssertionError("engineering wait/Status exact source region differs")
        source = source.replace(current, previous, 1)
    return source

def without_release_evidence_source(source):
    source = without_engineering_wait_status_source(source)
    if 'static let releaseEvidenceDocuments:' not in source:
        if 'testSyntheticProjectSavedReleaseEvidence' in source: raise AssertionError("partial release_evidence_source source")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(RELEASE_EVIDENCE_SOURCE_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("release_evidence_source exact source region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != 'da621652977a2f09a32f670fe5ddefc0d135d1753b4fdfce792995872076dae8':
        raise AssertionError("release_evidence_source predecessor source differs")
    return value.decode()

def without_removal_ui_source(source):
    source = without_release_evidence_source(source)
    for start, end, expected, original in REMOVAL_UI_SWIFT_INVERSE:
        observed = source[start:end]
        if hashlib.sha256(observed.encode()).hexdigest() != expected:
            raise AssertionError('removal UI exact SOURCE region differs')
        source = source[:start] + original + source[end:]
    if hashlib.sha256(source.encode()).hexdigest() != '03c9285e0ed83a3b2d019cfa75ddd5e309c60dbc48ac162964755122279842b8':
        raise AssertionError('removal UI inverse changed prior SOURCE')
    return source


def without_ios_unsigned_source(source):
    source = without_removal_ui_source(source)
    rows = source.splitlines(keepends=True)
    for start, end, expected, original in reversed(IOS_UNSIGNED_SWIFT_INVERSE):
        observed = ''.join(rows[start:end])
        if hashlib.sha256(observed.encode()).hexdigest() != expected:
            raise AssertionError('unsigned iOS exact SOURCE region differs')
        rows[start:end] = original.splitlines(keepends=True)
    value = ''.join(rows)
    if hashlib.sha256(value.encode()).hexdigest() != 'baa5731b9a25910affe6019ace6db58cccb35267a028a7034e70997ed96156eb':
        raise AssertionError('unsigned iOS inverse changed prior SOURCE')
    return value


def without_positive_android_source(source):
    source = without_ios_unsigned_source(source)
    rows = source.splitlines(keepends=True)
    for start, end, expected, original in reversed(ANDROID_POSITIVE_SWIFT_INVERSE):
        observed = ''.join(rows[start:end])
        if hashlib.sha256(observed.encode()).hexdigest() != expected:
            raise AssertionError('positive Android exact SOURCE region differs')
        rows[start:end] = original.splitlines(keepends=True)
    value = ''.join(rows)
    if hashlib.sha256(value.encode()).hexdigest() != '32e2bd4223c6219eaeed0e9b9cfa78f3fd9b7c8fd05fb1e2cf903395038d78c4':
        raise AssertionError('positive Android inverse changed ordinary SOURCE')
    return value

def target():
    return {"BlueprintName": MODULE.TARGET, "IsUITestBundle": True,
        "TestHostPath": "__TESTROOT__/" + MODULE.RUNNER,
        "TestBundlePath": "__TESTHOST__/Contents/PlugIns/MRKNormalAppUITests.xctest",
        "TestHostBundleIdentifier": "dev.mobile-release-kit.normal-ui-tests.xctrunner"}


def manifest():
    return plistlib.dumps({"__xctestrun_metadata__": {"FormatVersion": 2},
        "TestConfigurations": [{"IsEnabled": True, "TestTargets": [target()]}]})


def result_data():
    selected = "-[MRKNormalAppUITests.NormalAppUITests testPackagedEntryLaunchCancelAndQuit]"
    output = "\n".join(("Test Case '" + selected + "' started.", MODULE.ORIGINAL_MARKER,
        MODULE.ENTRY_MARKER, MODULE.UI_MARKER, "Test Case '" + selected + "' passed (1.000 seconds).", "")).encode()
    summary = json.dumps({"totalTestCount": 1, "passedTests": 1, "failedTests": 0,
                          "skippedTests": 0, "expectedFailures": 0}).encode()
    tree = json.dumps({"testNodes": [{"name": MODULE.TARGET, "nodeType": "Unit test bundle", "children": [
        {"name": "NormalAppUITests", "nodeType": "Test Suite", "children": [
            {"name": "testPackagedEntryLaunchCancelAndQuit()", "nodeType": "Test Case",
             "nodeIdentifier": "NormalAppUITests/testPackagedEntryLaunchCancelAndQuit()", "result": "Passed"}]}]}]}).encode()
    return output, summary, tree


def normal_arguments(result="test.xcresult"):
    methods, allowance, _ = MODULE.NORMAL_SELECTIONS[result]
    root = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui")
    return ["test-without-building", "-project", MODULE.PROJECT, "-scheme", "MRKNormalAppUI",
        "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64",
        "-destination-timeout", "15", "-derivedDataPath", str(root / "DerivedData"),
        "-resultBundlePath", str(root / result), *["-only-testing:" + MODULE.CLASS + method for method in methods],
        "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
        "-default-test-execution-time-allowance", str(allowance),
        "-maximum-test-execution-time-allowance", str(allowance), "-disableAutomaticPackageResolution"]


def normal_project_output():
    # Literal independent roster/markers: never generated from the helper's table.
    methods = ("testSyntheticProjectLocalEditsAndImages", "testSyntheticProjectPathFields")
    markers = (
        ("MRK_MACOS_NORMAL_PROJECT_UI=project-config-workflows-text-version-images;cleanExitStatus=unavailable;allWorkerFinality=unavailable",),
        ("MRK_MACOS_NORMAL_PROJECT_FIELDS_UI=ordinary-four-field-browse-two-cancels-draft-only-invalid-pair-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
         "MRK_MACOS_NORMAL_ANDROID_SOURCE_UI=ordinary-jdk-sdk-gradle-native-cancel-jdk-reselect-backend-source-refused-selection-only;cleanExitStatus=unavailable;allWorkerFinality=unavailable"),
    )
    lines = []
    for method, case_markers in zip(methods, markers):
        selected = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
        lines.extend(("Test Case '" + selected + "' started.", MODULE.ORIGINAL_MARKER, *case_markers,
                      "Test Case '" + selected + "' passed (1.000 seconds)."))
    return ("\n".join(lines) + "\n").encode()


def normal_workflow_refusal_output():
    # Independent literal returned-output fixture; no native command is run.
    selected = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectManagedWorkflowRefusal]"
    return ("\n".join(("Test Case '" + selected + "' started.", MODULE.ORIGINAL_MARKER,
        "MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI=ordinary-preview-customized-candidate-whole-bundle-refused-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable",
        "Test Case '" + selected + "' passed (1.000 seconds).", ""))).encode()


class RunnerAdmissionDataTests(unittest.TestCase):
    def test_only_strict_absent_or_false_entitlement_is_admitted(self):
        self.assertEqual(MODULE.sandbox_entitlement(plistlib.dumps({})), "absent")
        self.assertEqual(MODULE.sandbox_entitlement(plistlib.dumps({
            "com.apple.security.app-sandbox": False, "com.apple.security.get-task-allow": True})), "false")
        for body in (b"", b"not a plist", plistlib.dumps([]), *[
            plistlib.dumps({"com.apple.security.app-sandbox": value}) for value in (True, 0, 1, "false", b"false")]):
            with self.subTest(body=body[:40]), self.assertRaises(MODULE.Refused):
                MODULE.sandbox_entitlement(body)
        duplicate = (b'<?xml version="1.0"?><plist version="1.0"><dict>'
            b'<key>com.apple.security.app-sandbox</key><true/>'
            b'<key>com.apple.security.app-sandbox</key><false/></dict></plist>')
        with self.assertRaisesRegex(MODULE.Refused, "duplicate-plist-key"):
            MODULE.sandbox_entitlement(duplicate)

    def test_android_verification_resource_is_fixed_without_widening_normal_fixture_limits(self):
        # Actual public SOURCE/DATA only; this does not execute the Swift reader.
        import base64
        import xml.etree.ElementTree as ET
        native = ROOT / "desktop/native/macos-normal-ui"
        fixtures = native / "MRKNormalAppUITests/Fixtures"
        name = "android-positive-verification-v1.xml"
        xml = (fixtures / name).read_bytes()
        digest = "5d00856c785363da964e00da72ad38571cfd088da915ebe86cf20640bb1c7545"
        self.assertEqual((len(xml), hashlib.sha256(xml).hexdigest()), (90045, digest))
        self.assertGreater(len(xml), 32 * 1024)
        self.assertEqual(len(base64.b64encode(xml)), 120060)
        self.assertGreater(len(base64.b64encode(xml)), 64 * 1024)
        self.assertNotIn(b"<!DOCTYPE", xml)
        self.assertNotIn(b"<!ENTITY", xml)
        tree = ET.fromstring(xml)
        ns = "{https://schema.gradle.org/dependency-verification}"
        self.assertEqual(tree.tag, ns + "verification-metadata")
        self.assertEqual(tree.findtext(ns + "configuration/" + ns + "verify-metadata"), "true")
        components = tree.findall(ns + "components/" + ns + "component")
        self.assertEqual(len(components), 234)
        artifacts = [artifact for component in components for artifact in component.findall(ns + "artifact")]
        self.assertEqual(len(artifacts), 386)
        self.assertTrue(all(len(artifact.findall(ns + "sha256")) == 1
                            and re.fullmatch(r"[0-9a-f]{64}", artifact.find(ns + "sha256").get("value", ""))
                            for artifact in artifacts))
        # Both old bundled JSON fixtures are unchanged, not repackaged with a
        # larger decoder or a base64 copy of this XML.
        for filename, length, expected in (
            ("normal-project-v1.json", 19560, "ea9b004f0026c053bc1a12607cc70bd0a6f7e07afe9f33cf2a17506de62d512c"),
            ("normal-persistence-v1.json", 10690, "99965739ae4dedf7de4dbc4c20d519eeea31e7a7eaab59484c5969f8cb03cce4"),
        ):
            with self.subTest(fixture=filename):
                raw = (fixtures / filename).read_bytes()
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (length, expected))
                self.assertLessEqual(len(raw), 64 * 1024)
                spec = json.loads(raw)
                values = [*spec["files"].values(), *[value for stage in spec["stages"].values() for value in stage.values()]]
                decoded = [base64.b64decode(value, validate=True) for value in values]
                self.assertTrue(all(len(value) <= 32 * 1024 for value in decoded))
                self.assertLessEqual(sum(map(len, decoded)), 256 * 1024)
                self.assertNotIn("project/gradle/verification-metadata.xml", spec["files"])

        project = (native / "MRKNormalAppUI.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        # Standard architectures is a one-line project baseline successor.
        # Restore only that current line before preserving all older hashes.
        current_archs = '\t\t\t\tARCHS = "$(ARCHS_STANDARD)";\n'
        prior_archs = '\t\t\t\tARCHS = arm64;\n'
        self.assertEqual(project.count(current_archs), 1)
        self.assertNotIn(prior_archs, project)
        project = project.replace(current_archs, prior_archs, 1)
        # The later unsigned-iOS resource is an exact reviewed successor of
        # the Android project. Undo only its four SOURCE additions FIRST so
        # the existing Android inverse and original XML-only hash stay strict.
        self.assertEqual(hashlib.sha256(project.encode()).hexdigest(),
                         '18903dd03df852e0d6b8ca8c1f545553c4440468c3b067ead5b92cd76b5c5514')
        for added, original in (
            ('\t\tA10000000000000000000018 = {isa = PBXBuildFile; fileRef = A10000000000000000000019; };\n', ''),
            ('\t\tA10000000000000000000019 = {isa = PBXFileReference; lastKnownFileType = text.json; path = "Fixtures/normal-ios-unsigned-v1.json"; sourceTree = "<group>"; };\n', ''),
            (', A10000000000000000000019);', ');'),
            (', A10000000000000000000018);', ');'),
        ):
            self.assertEqual(project.count(added), 1)
            project = project.replace(added, original, 1)
        self.assertEqual(hashlib.sha256(project.encode()).hexdigest(),
                         '3b4f8f2f22ba6540b402b8738f880a9c81bfb216337eed6a7bfdd817896f6469')
        for added in ('\t\tA10000000000000000000016 = {isa = PBXBuildFile; fileRef = A10000000000000000000017; };\n',
                      '\t\tA10000000000000000000017 = {isa = PBXFileReference; lastKnownFileType = text.json; path = "Fixtures/normal-android-positive-v1.json"; sourceTree = "<group>"; };\n'):
            self.assertEqual(project.count(added), 1)
            project = project.replace(added, '', 1)
        project = project.replace(', A10000000000000000000017);', ');', 1).replace(', A10000000000000000000016);', ');', 1)
        self.assertEqual(hashlib.sha256(project.encode()).hexdigest(), '7a2f623a3bbc2ad23ed7f04d6f373fdfaffa0cef83752bc3133c0e4fbf75f382')
        build = "A10000000000000000000014 = {isa = PBXBuildFile; fileRef = A10000000000000000000015; };"
        reference = ('A10000000000000000000015 = {isa = PBXFileReference; lastKnownFileType = text.xml; '
                     'path = "Fixtures/' + name + '"; sourceTree = "<group>"; };')
        self.assertEqual(project.count(build), 1)
        self.assertEqual(project.count(reference), 1)
        resources = re.findall(r"isa = PBXResourcesBuildPhase;[^\n]*files = \(([^)]*)\)", project)
        self.assertEqual(resources, ["A10000000000000000000010, A10000000000000000000012, A10000000000000000000014"])
        self.assertIn('children = (A10000000000000000000002, A10000000000000000000011, '
                      'A10000000000000000000013, A10000000000000000000015); path = MRKNormalAppUITests;', project)
        self.assertEqual(project.count("isa = PBXNativeTarget;"), 1)
        self.assertNotIn("PBXShellScriptBuildPhase", project)

        source = without_positive_android_source(SWIFT.read_text(encoding="utf-8"))
        begin = "        // Fixed public XML prerequisite only."
        end = "        private func children(_ directory: Directory) throws -> Set<String> {"
        self.assertEqual(source.count(begin), 1)
        added = source.split(begin, 1)[1].split(end, 1)[0]
        resource = added.split("private func androidVerificationResource() throws -> Data {", 1)[1].split(
            "private func readAndroidVerificationOriginal() throws -> File {", 1)[0]
        readback = added.split("private func readAndroidVerificationOriginal() throws -> File {", 1)[1]
        self.assertIn('private static let androidVerificationResourceName = "android-positive-verification-v1"', added)
        self.assertIn('private static let androidVerificationPath = "project/gradle/verification-metadata.xml"', added)
        self.assertIn("private static let androidVerificationLength = 90_045", added)
        self.assertIn('private static let androidVerificationSHA256 = "' + digest + '"', added)
        for required in (
            "Bundle(for: NormalAppUITests.self)", "parentURL = bundle.resourceURL",
            'bundle.url(forResource: Self.androidVerificationResourceName, withExtension: "xml")',
            "url.deletingLastPathComponent().path == parentURL.path",
            "open(parentURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)",
            "openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)",
            "resource = fd", "parentBefore == StatFacts(parentNamedBefore)",
            "parentBefore.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)",
            "before.mode & mode_t(S_IFMT) == mode_t(S_IFREG) && before.links == 1",
            "before.bytes == Self.androidVerificationLength", "body.count + count <= Self.androidVerificationLength",
            "body.count == Self.androidVerificationLength", "if count == 0 { break }",
            "SHA256.hash(data: body)", "before == Self.facts(fd)",
            "parentBefore == Self.facts(parent) && parentBefore == StatFacts(parentNamedAfter)",
        ):
            self.assertIn(required, resource)
        self.assertEqual(resource.count("before == Self.named(parent, name)"), 2)
        self.assertIn("lstat(parentURL.path, &parentNamedBefore) == 0", resource)
        self.assertIn("lstat(parentURL.path, &parentNamedAfter) == 0", resource)
        self.assertLess(resource.index("resource = fd"), resource.index("let before = try Self.facts(fd)"))
        failure, success = resource.split("} catch {", 1)[1].split(
            '\n            if let fd = resource, Darwin.close(fd)', 1)
        self.assertLess(failure.index("Darwin.close(fd)"), failure.index("Darwin.close(parent)"))
        self.assertLess(failure.index("Darwin.close(parent)"), failure.index("throw error"))
        self.assertIn('closeErrors.append("android-xml-resource-close")', success)
        self.assertLess(success.index("Darwin.close(parent)"), success.index("closeErrors.isEmpty"))
        self.assertLess(success.index("closeErrors.isEmpty"), success.index("return data"))
        self.assertEqual(resource.count("Darwin.close(fd)"), 2)
        self.assertEqual(resource.count("Darwin.close(parent)"), 2)
        self.assertIn("originals[Self.androidVerificationPath]", readback)
        self.assertIn('directories["project/gradle"]', readback)
        self.assertIn("expected.count == Self.androidVerificationLength", readback)
        self.assertIn("SHA256.hash(data: expected)", readback)
        self.assertIn('readLeaf(original, name: "verification-metadata.xml", privateOnly: true,', readback)
        self.assertIn("limit: Self.androidVerificationLength)", readback)
        self.assertIn("observed.bytes == expected", readback)
        self.assertLess(readback.index("let observed = try readLeaf"), readback.index('closeErrors.isEmpty, "Android XML original'))
        self.assertLess(readback.index("try checkDirectory(original)"), readback.index("return observed"))
        # These are dormant fixed prerequisite readers, not an implicit larger
        # limit in any current profile or an added Android-positive selection.
        self.assertEqual(source.count("androidVerificationResource("), 2)
        self.assertEqual(source.count("readAndroidVerificationOriginal("), 3)
        self.assertIn("enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal, savedVersionRecovery }", source)
        generic = source.split("private func read(_ path: String) throws -> File {", 1)[1].split("private func readLeaf(", 1)[0]
        self.assertIn("return try readLeaf(original, name: name)", generic)
        self.assertNotIn("androidVerification", generic)
        self.assertIn("privateOnly: Bool = false, limit: Int = 32 * 1024)", source)
        prepare = source.split("func prepare(_ profile: Profile = .projectEdits) throws {", 1)[1].split("func admitDefaultVault()", 1)[0]
        self.assertIn("before.bytes <= 64 * 1024", prepare)
        self.assertIn("body.count + count <= 64 * 1024", prepare)
        self.assertIn("bytes.count <= 32 * 1024", prepare)
        self.assertIn("<= 256 * 1024", prepare)
        self.assertNotIn("androidVerification", prepare)

        # Public positive PROJECT only: genuine A9 + B2 locks + five normal
        # user/locale sentinels. No supplier, private key or runtime handoff is
        # part of this bundled DATA; current generic preparation is unchanged.
        positive_raw = (fixtures / "normal-android-positive-v1.json").read_bytes()
        self.assertEqual((len(positive_raw), hashlib.sha256(positive_raw).hexdigest()),
                         (15695, "f0936a01330d095da8863571d78c1580e037d6d2a69d26c19a31814ffa251f4e"))
        self.assertLessEqual(len(positive_raw), 64 * 1024)
        positive = json.loads(positive_raw)
        self.assertEqual(set(positive), {"schemaVersion", "files", "stages"})
        self.assertIs(type(positive["schemaVersion"]), int)
        self.assertEqual(positive["schemaVersion"], 1)
        self.assertEqual(positive["stages"], {})
        self.assertEqual((json.dumps(positive, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(),
                         positive_raw)
        expected_positive = {
            'project/.github/workflows/keep-user.yml': (76, '365244a6298332816ce5faeca4c2d8445fb29d887f981b0666ea32da005d742a'),
            'project/.gitignore': (48, 'b4babbcd85071657df35045a4bc38c465e1720a96ffe4a07c4c2d6504e1d2cc8'),
            'project/README-user.txt': (56, '3a6675d287793428f05e033457dbb6ca839a008fc6f70423f67ebddab9cb58f5'),
            'project/app/build.gradle': (915, 'b78bad2b96b50b6613ed6c55c34be35a8b49842b595d447ad2a8c59fd1455f35'),
            'project/app/gradle.lockfile': (326, 'b8ca8e27e9b203531b6bd0d08c8d9a906ba8fecf63a7797fbbb64cd34e316ec4'),
            'project/app/src/main/AndroidManifest.xml': (306, 'dba12a22f84ec6f275f99979263344b25ba8c45131520648e1a8adb86695eb8d'),
            'project/app/src/main/java/org/example/saved/MainActivity.java': (93, '8177c62171176ac7756a85bff7180eeb10f56d02465adc8c3e6ef979d3f96f96'),
            'project/build.gradle': (674, '94666f4e4fe591e43c78929a5765c38c4b1553665f49834121f872f811232759'),
            'project/buildscript-gradle.lockfile': (6566, 'ff53ec4b7427f2da997ed040dd338b0086c856564fe7001a0d030583c778ac85'),
            'project/gradle/wrapper/gradle-wrapper.properties': (168, 'ef6da5202b4ca5bc4564e427bfcff6c2f761cbf761367f9ea561bf5141e33628'),
            'project/release/mobile-release.json': (733, 'a64b904e27dac9df06377c7ad5d1f79988df3eec6295f689d2a5ead7c4d52144'),
            'project/release/store/android/en-US/full_description.txt': (79, '61a57bfd859d0fd1fded8756580f38f51dc66c19e8ca6163588c1840aaf0584b'),
            'project/release/store/android/en-US/short_description.txt': (49, '66f1806ac841eb119d3e3a9cfcb7218ab76d88c6120f7e7db43929933dbdea5c'),
            'project/release/store/android/en-US/title.txt': (15, '8f06c2070f1e3f84db731b2a1ff568a06f18916dd7f24e75aa6e8a6359b629b3'),
            'project/release/version.properties': (34, 'a811da0677c243236101fb4aa93319d28b731f963f8a295c1028b8aee136386b'),
            'project/settings.gradle': (991, '0238825f1dccf203000d3cc80f5a4d1987b0456835f9c745efe25767f66901ea'),
        }
        self.assertEqual(set(positive["files"]), set(expected_positive))
        positive_files = {path: base64.b64decode(value, validate=True)
                          for path, value in positive["files"].items()}
        self.assertEqual(len(positive_files), 16)
        for path, (length, expected_sha) in expected_positive.items():
            with self.subTest(positive_file=path):
                raw = positive_files[path]
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (length, expected_sha))
                self.assertEqual(base64.b64encode(raw).decode("ascii"), positive["files"][path])
                self.assertGreater(len(raw), 0)
                self.assertLessEqual(len(raw), 32 * 1024)
        positive_directories = {"/".join(path.split("/")[:depth]) for path in positive_files
                                for depth in range(1, len(path.split("/")))}
        self.assertEqual(len(positive_directories), 16)
        self.assertEqual(sum(map(len, positive_files.values())), 11129)
        self.assertEqual(max(map(len, positive_files.values())), 6566)
        self.assertNotIn("project/gradle/verification-metadata.xml", positive_files)
        self.assertEqual(sum(map(len, positive_files.values())) + len(xml), 101174)
        self.assertLessEqual(sum(map(len, positive_files.values())) + len(xml), 256 * 1024)

        positive_config = json.loads(positive_files["project/release/mobile-release.json"])
        self.assertEqual(positive_config["version"], {"source": "release/version.properties",
                         "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"})
        self.assertEqual(positive_config["android"], {"enabled": True, "module": ":app", "variant": "release",
                         "applicationId": "org.example.saved", "identityStatus": "unverified"})
        self.assertEqual(positive_config["ios"], {"enabled": False})
        self.assertEqual(positive_config["source"], {"candidateBranch": "main", "productionBranch": "main"})
        self.assertEqual(positive_config["services"], {"androidFirebase": "disabled", "iosFirebase": "disabled"})
        self.assertEqual(positive_config["projectChecks"], {"preflight": [], "androidArtifact": [], "iosArtifact": []})
        self.assertEqual(positive_config["metadata"], {"root": "release/store", "androidLocales": ["en-US"],
                         "iosLocales": []})
        self.assertEqual(positive_files["project/release/version.properties"], b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n")
        # The public starting config intentionally lacks the same-job signer
        # fingerprint. The later ordinary UI must save the real public cert;
        # this fixture cannot fabricate signing approval or a private asset.
        self.assertNotIn("uploadCertificateSha256", positive_config["android"])
        self.assertNotIn("signing", positive_config)
        positive_app = positive_files["project/app/build.gradle"].decode("utf-8")
        for required in (
            "namespace 'org.example.saved'", "applicationId 'org.example.saved'",
            "compileSdk 35", "buildToolsVersion '35.0.0'", "minSdk 23", "targetSdk 35",
            "versionCode Integer.parseInt(System.getenv('MOBILE_RELEASE_BUILD_NUMBER'))",
            "versionName System.getenv('MOBILE_RELEASE_VERSION_NAME')", "debuggable false",
        ):
            self.assertIn(required, positive_app)
        self.assertNotIn("signingConfig", positive_app)
        positive_manifest = ET.fromstring(positive_files["project/app/src/main/AndroidManifest.xml"])
        self.assertEqual(positive_manifest.tag, "manifest")
        positive_application = positive_manifest.find("application")
        self.assertIsNotNone(positive_application)
        android_ns = "{http://schemas.android.com/apk/res/android}"
        self.assertNotIn(android_ns + "debuggable", positive_application.attrib)
        self.assertEqual(positive_application.get(android_ns + "testOnly"), "false")
        self.assertEqual(positive_application.find("activity").get(android_ns + "name"), ".MainActivity")
        self.assertEqual(positive_files["project/app/src/main/java/org/example/saved/MainActivity.java"],
                         b"package org.example.saved;\n\npublic final class MainActivity extends android.app.Activity {\n}\n")
        positive_settings = positive_files["project/settings.gradle"].decode("utf-8")
        positive_build = positive_files["project/build.gradle"].decode("utf-8")
        for required in ("DependencyVerificationMode.STRICT", "file('gradle/verification-metadata.xml').isFile()",
                         "rootProject.name = 'MacAndroidSignedBuildFixture'", "include(':app')"):
            self.assertIn(required, positive_settings)
        for required in ("classpath 'com.android.tools.build:gradle:8.9.2'",
                         "resolutionStrategy.activateDependencyLocking()", "lockAllConfigurations()",
                         "lockMode = LockMode.STRICT"):
            self.assertIn(required, positive_build)
        for forbidden in ("--write-locks", "--write-verification-metadata", "failOnNonReproducibleResolution"):
            self.assertNotIn(forbidden, positive_settings + positive_build + positive_app)
        self.assertEqual(positive_files["project/gradle/wrapper/gradle-wrapper.properties"].decode("ascii").splitlines(), [
            r"distributionUrl=https\://services.gradle.org/distributions/gradle-8.14.5-bin.zip",
            "distributionSha256Sum=6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854",
        ])
        self.assertEqual(positive_files["project/.gitignore"], b"/.mobile-release/\n/.gradle/\n/build/\n/app/build/\n")

        lock_header = ["# This is a Gradle generated file for dependency locking.",
                       "# Manual edits can break the build and are not advised.",
                       "# This file is expected to be part of source control."]
        root_lock = positive_files["project/buildscript-gradle.lockfile"].decode("ascii").splitlines()
        app_lock = positive_files["project/app/gradle.lockfile"].decode("ascii").splitlines()
        self.assertEqual(root_lock[:3], lock_header)
        self.assertEqual(root_lock[-1], "empty=")
        root_locked = root_lock[3:-1]
        self.assertEqual(len(root_locked), 123)
        self.assertEqual(root_locked, sorted(set(root_locked)))
        self.assertTrue(all(row.endswith("=classpath") and row.count("=") == 1 for row in root_locked))
        self.assertIn("com.android.tools.build:gradle:8.9.2=classpath", root_locked)
        xml_coordinates = {(row.get("group"), row.get("name"), row.get("version")) for row in components}
        self.assertTrue(all(tuple(row.removesuffix("=classpath").split(":")) in xml_coordinates for row in root_locked))
        self.assertEqual(app_lock, lock_header + [
            "empty=androidApis,androidJdkImage,lintChecks,releaseAnnotationProcessorClasspath,"
            "releaseCompileClasspath,releaseReverseMetadataValues,releaseRuntimeClasspath"
        ])
        self.assertEqual(len(app_lock[3].removeprefix("empty=").split(",")), 7)
        normal_public = json.loads((fixtures / "normal-project-v1.json").read_bytes())
        for path in ("project/README-user.txt", "project/.github/workflows/keep-user.yml",
                     "project/release/store/android/en-US/title.txt",
                     "project/release/store/android/en-US/short_description.txt",
                     "project/release/store/android/en-US/full_description.txt"):
            self.assertEqual(positive_files[path], base64.b64decode(normal_public["files"][path], validate=True))
        for name, limit in (("title", 30), ("short_description", 80), ("full_description", 4000)):
            text = positive_files[f"project/release/store/android/en-US/{name}.txt"].decode("utf-8")
            self.assertTrue(text.strip())
            self.assertLessEqual(len(text.rstrip("\n")), limit)

    def test_android_output_custody_is_bounded_without_activating_a_profile(self):
        # SOURCE assertions are not the separately selected native DATA test.
        # In particular they never duplicate/execute a Python version of the DFS.
        source = without_positive_android_source(SWIFT.read_text(encoding="utf-8"))
        begin = "        // Fixed positive Android output custody. No current Profile enters it."
        end = "        // A one-case transfer of observation custody, never a product lease."
        self.assertEqual(source.count(begin), 1)
        block = begin + source.split(begin, 1)[1].split(end, 1)[0]
        production, data_test = block.split("        // Native DATA-only regression of the same scanner;", 1)
        for literal in (
            'private static let androidOutputRoots = ["project/app/build", "project/.mobile-release", "project/build"]',
            'private static let androidReport = "project/build/reports/problems/problems-report.html"',
            'private static let androidEntryLimit = 100_000', 'private static let androidNameLimit = 2 * 1024 * 1024',
            'private static let androidRelativeLimit = 2048', 'private static let androidDepthLimit = 32',
            'private static let androidAABLimit: Int64 = 64 * 1024 * 1024',
            'private static let androidModuleLimit: Int64 = 1024 * 1024 * 1024',
            'private static let androidLogicalLimit: Int64 = 2 * 1024 * 1024 * 1024',
            'private static let androidReportLimit: Int64 = 16 * 1024 * 1024',
            'case reviewed, running, complete', 'state.identity == identity',
            'current[Self.androidVerificationPath] != nil', 'current["project/buildscript-gradle.lockfile"] != nil',
            'current["project/app/gradle.lockfile"] != nil', 'if path == Self.androidVerificationPath',
            'observed = try readAndroidVerificationOriginal()', 'outputsMayExist: false',
            'actual.subtracting(admittedOutputs) == expected', 'readAndroidVerificationOriginal()',
            'let bytes = withUnsafePointer(to: &entry.pointee.d_name)', 'String(bytes: bytes, encoding: .utf8)',
            'canonical.insert(key).inserted', 'census.identities.insert(originalKey).inserted',
            'O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC', 'O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC',
            'before.links == 1 && before.bytes >= 0', 'before.uid == getuid() && before.gid == getgid()',
            'before.device == parent.facts.device && before.mode & 0o7022 == 0',
            'names == [identity.operationID]', 'names == ["artifacts"]', 'names == ["app-release.aab"]',
            'names == ["desktop-android-build"]', 'names == ["reports"]', 'names == ["problems"]',
            'names == ["problems-report.html"]', 'before.mode & 0o7777 == 0o600',
            'before.mode & 0o7777 == 0o700', 'count: 64 * 1024', 'if count == 0 { break }',
            'total == size', 'before == Self.facts(fd) && before == Self.androidOutputNamed(parent.fd, name)',
            'try androidOutputDirectoryPost(parent); try check()', 'census.projectAAB = true',
            'result.artifactBytes == artifactBytes && result.artifactSHA256 == artifactSHA256',
            'scanAndroidOutputs(identity, check: check) == summary', 'androidClosing = true',
            'do { try closeOriginals() } catch { if primary == nil { primary = error } }',
        ):
            with self.subTest(required=literal):
                self.assertIn(literal, production)
        for forbidden in ('FileManager', 'removeItem', 'unlinkat(', 'mkdirat(', 'Process(', 'shell', 'glob(',
                          'try?', 'Data(contentsOf:', 'project/.gradle', 'sdkmanager', 'chmod('):
            self.assertNotIn(forbidden, production)
        walk = production.split('private func androidOutputWalk(', 1)[1].split('private func scanAndroidOutputs(', 1)[0]
        failure, success = walk.split('} catch {', 1)[1].split('\n            if Darwin.close(fd)', 1)
        self.assertLess(failure.index('Darwin.close(fd)'), failure.index('throw error'))
        self.assertLess(success.index('closeErrors.append'), success.index('closeErrors.isEmpty'))
        self.assertNotIn('Self.named(', walk)
        self.assertNotIn('checkDirectory(', walk)
        enumeration = production.split('private func androidOutputNames(', 1)[1].split('private func androidOutputWalk(', 1)[0]
        self.assertNotIn('checkDirectory(', enumeration)
        self.assertIn('androidOutputDirectoryPost(directory)', enumeration)
        fixed_named = production.split('private static func androidOutputNamed(', 1)[1].split('private func androidOutputDirectoryPost(', 1)[0]
        self.assertIn('"Android output named binding unavailable"', fixed_named)
        self.assertNotIn('+ name', fixed_named)
        close = production.split('func closeAndroidOriginals(', 1)[1]
        self.assertLess(close.index('try closeOriginals()'), close.index('do { try check() }'))
        self.assertLess(close.index('do { try check() }'), close.index('androidOutput = nil; androidClosing = false'))
        self.assertIn('do { try check() } catch { if primary == nil { primary = error } }', close)
        self.assertIn('initialRoot == facts(cleanupRoot) && initialRoot == named(temporary, rootName)', data_test)
        self.assertIn('fixture.directories[""]!.facts == initialRoot', data_test)
        self.assertNotIn('cleanupFacts = try facts(', data_test)
        self.assertIn('Android DATA closed deadline refusal', data_test)
        self.assertIn('Android DATA primary closure failure was masked or state retained', data_test)
        self.assertIn('private-name-not-for-diagnostics', data_test)
        self.assertIn('fixture.androidOutputDirectoryPost(moved)', data_test)
        scan = production.split('private func scanAndroidOutputs(', 1)[1].split('func finishAndroidOutputObservation(', 1)[0]
        self.assertEqual(scan.count('try androidInputPost(check)'), 2)
        self.assertEqual(scan.count('try androidInputRoster(outputsMayExist: true)'), 2)
        finish = production.split('func finishAndroidOutputObservation(', 1)[1].split('func assertAndroidOutputClosure(', 1)[0]
        self.assertLess(finish.index('let result = try scanAndroidOutputs'), finish.index('state.stage = .complete'))
        self.assertLess(finish.index('result.artifactSHA256 == artifactSHA256'), finish.index('state.stage = .complete'))
        for label in ('"valid"', '"late-close"', '"extra-operation"', '"work"', '"journal"', '"project-cache"',
                      '"extra-artifact"', '"symlink"', '"hardlink"', '"depth"', '"mode"', '"input"',
                      '"wrong-result"', '"identity"', '"repeated-start"'):
            self.assertIn(label, data_test)
        for required in ('entryLimit: census.entries,', 'entryLimit: census.entries - 1,',
                         'message == "fixture: " + reason', 'created.reversed()', 'AT_REMOVEDIR',
                         'fixture.closeAndroidOriginals(identity, check: check)',
                         'Android DATA production close deleted output', 'now - started < 30',
                         'if primary == nil { primary = error }', 'if let primary { throw primary }'):
            self.assertIn(required, data_test)
        self.assertNotIn('FileManager', data_test)
        self.assertNotIn('XCUIApplication', data_test)
        native = """    // Explicit DATA-only native selection; not an Android-positive application case.
    func testPositiveAndroidOutputCustodyData() throws {
        try LocalFixture.exerciseAndroidOutputCustodyData()
    }

"""
        self.assertEqual(source.count(native), 1)
        identity_begin = "    // Read only the ordinary parsed-current Build details within the caller's"
        identity = identity_begin + source.split(identity_begin, 1)[1].split(native, 1)[0]
        self.assertIn('container.descendants(matching: .group).matching(identifier: "Build details")', identity)
        self.assertIn('["Build operation ID: ", "Build owner generation: "]', identity)
        self.assertIn('field.isHittable && label.hasPrefix(prefix)', identity)
        self.assertIn('^[0-9a-f]{32}$', identity)
        self.assertIn('LocalFixture.AndroidBuildIdentity(operationID: values[0], ownerGeneration: values[1])', identity)
        restored = source.replace(block, '', 1).replace(identity, '', 1).replace(native, '', 1)
        restored = restored.replace('            let missingAndroidClosure = androidOutput != nil && !androidClosing\n', '', 1)
        restored = restored.replace('            try Self.need(!missingAndroidClosure, "Android final output observation was not joined before close")\n', '', 1)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),
                         "2c2f47ace92b094365ac93a661b6e944d54b25a363a7d53f0b8350d420b9d93b")
        # The explicit native DATA route is now reviewed; ordinary application
        # selections must still exclude it. No Android-positive UI profile is enabled.
        self.assertEqual(MODULE.OUTPUT_DATA_METHOD, MODULE.CLASS + 'testPositiveAndroidOutputCustodyData')
        self.assertNotIn(MODULE.OUTPUT_DATA_RESULT, MODULE.NORMAL_SELECTIONS)
        for methods, _, _ in MODULE.NORMAL_SELECTIONS.values():
            self.assertNotIn('testPositiveAndroidOutputCustodyData', methods)
        # Actual native filesystem DATA remains a separate fixed selector. This
        # local group verifies SOURCE and exact historical inverses, not an
        # independently reimplemented archive scanner or a native pass.
        import base64
        current = without_release_evidence_source(SWIFT.read_text(encoding="utf-8"))
        removal_before = without_removal_ui_source(current)
        self.assertEqual((len(removal_before.encode()), hashlib.sha256(removal_before.encode()).hexdigest()),
                         (385349, '03c9285e0ed83a3b2d019cfa75ddd5e309c60dbc48ac162964755122279842b8'))
        with self.assertRaisesRegex(AssertionError, 'removal UI exact SOURCE region differs'):
            without_removal_ui_source(current.replace('MRK_MACOS_REMOVAL_UI=v1;', 'MRK_MACOS_REMOVAL_UI=v2;', 1))
        with self.assertRaisesRegex(AssertionError, 'removal UI inverse changed prior SOURCE'):
            without_removal_ui_source(current + '\n')
        self.assertEqual(hashlib.sha256(without_ios_unsigned_source(current).encode()).hexdigest(),
                         "baa5731b9a25910affe6019ace6db58cccb35267a028a7034e70997ed96156eb")
        with self.assertRaises(AssertionError):
            without_ios_unsigned_source(current.replace("iOS original identity shape", "changed iOS identity shape", 1))
        ios_begin = "        // One ordinary unsigned archive's post-terminal namespace observation."
        ios = current.split(ios_begin, 1)[1].split("        // Fixed positive Android output custody;", 1)[0]
        for literal in ('struct IOSArchiveIdentity: Equatable', '^[0-9a-f]{32}$', 'iosIdentity == identity',
                        'iosDirectories.count == 4', '[Set(["desktop-ios-archive"]), Set([identity.operationID]), Set(["archive.xcarchive"])]',
                        'children(iosDirectories[index]) == names',
                        'original.facts.uid == getuid()', 'original.facts.device == device',
                        'original.facts.mode & 0o7777 == 0o700', 'original.facts.mode & 0o7022 == 0',
                        'O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC',
                        'iosDirectories.append(original)', 'iosClosing = true', 'try assertUnchanged()',
                        'do { try closeOriginals() } catch { if primary == nil { primary = error } }',
                        'do { try check() } catch { if primary == nil { primary = error } }'):
            self.assertIn(literal, ios)
        self.assertLess(ios.index('try adoptDirectory(openat('), ios.index('iosDirectories.append(original)'))
        self.assertLess(ios.index('iosDirectories.append(original)'), ios.index('original.facts.uid == getuid()'))
        self.assertEqual(ios.count('children(iosDirectories['), 1)
        self.assertNotIn('children(iosDirectories[3])', ios)
        for forbidden in ('FileManager', 'removeItem', 'unlinkat(', 'mkdirat(', 'Data(contentsOf:',
                          'androidOutputWalk(', 'fchmod(', 'Process(', 'readdir('):
            self.assertNotIn(forbidden, ios)
        self.assertIn('if path == "project" && iosUnsignedProfile && iosCompleted && iosIdentity != nil && iosDirectories.count == 4', current)
        for name in ('ios-valid', 'ios-work', 'ios-extra-operation', 'ios-foreign-output', 'ios-symlink',
                     'ios-replacement', 'ios-partial-open', 'ios-late-close', 'ios-input'):
            self.assertIn('"' + name + '"', current)
        for literal in ('fixture.iosDirectories.count == 3', 'fixture.descriptors.count == 12',
                        'fixture.iosDirectories.count == 4', 'fixture.descriptors.count == 13',
                        '"/opaque-data"', '"retained-archive"', 'iOS DATA production observation deleted archive',
                        'iOS DATA consuming close and late refusal'):
            self.assertIn(literal, current)
        journey = current.split('    @MainActor func testSyntheticProjectUnsignedIOSArchive()', 1)[1].split(
            '    @MainActor func testSyntheticProjectAndroidSignedBuild()', 1)[0]
        self.assertEqual(journey.count('"Create unsigned archive"'), 1)
        for literal in ('beginCase(seconds: 900, iosUnsigned: true)', 'clock.deadline - 150',
                        'journeyDeadline = successCutoff', 'successBeforeCutoff = true',
                        'fixture.beginIOSArchiveObservation(pair)', 'fixture.confirmIOSArchiveStart(pair)',
                        'fixture.finishIOSArchiveObservation(pair)', 'fixture.closeIOSArchiveOriginals(pair)',
                        'try completeNormalQuit(app)', 'try acceptFinalScenario()', 'MRK_MACOS_IOS_UNSIGNED_ARCHIVE_UI=',
                        'signed": false', 'ipaExported": false', 'releaseQualified": false'):
            self.assertIn(literal, journey)
        settling = current.split('    @MainActor private func settleFailedIOSArchive(', 1)[1].split(
            '    @MainActor func testSyntheticProjectUnsignedIOSArchive()', 1)[0]
        self.assertIn('clock.firstFailure != nil', settling)
        self.assertIn('owner.healthy(cleanup: true)', settling)
        self.assertIn('cancelRequested = true', settling)
        self.assertNotIn('"Create unsigned archive"', settling)
        self.assertNotIn('normalQuitObserved = true', settling)
        self.assertNotIn('CaseClock(', settling)
        fixture_path = SWIFT.parent / "Fixtures/normal-ios-unsigned-v1.json"
        body = fixture_path.read_bytes()
        self.assertEqual((len(body), hashlib.sha256(body).hexdigest()),
                         (10237, "999a48f946b2a26164d250086d5ece7588f3ff9b2b88824e596168b82faa8daf"))
        fixture = json.loads(body)
        self.assertEqual(set(fixture), {"schemaVersion", "files", "stages"})
        self.assertEqual(fixture["stages"], {})
        decoded = {key: base64.b64decode(value, validate=True) for key, value in fixture["files"].items()}
        self.assertEqual((len(decoded), sum(map(len, decoded.values())), max(map(len, decoded.values()))), (9, 7264, 3903))
        self.assertEqual(set(decoded), {"project/.gitignore", "project/keep.txt", "project/release/mobile-release.json",
            "project/release/version.properties", "project/ios/MRKObserved.xcodeproj/project.pbxproj",
            "project/ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme",
            "project/ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
            "project/ios/MRKObserved/main.m", "project/ios/MRKObserved/Info.plist"})
        pbx = (SWIFT.parent.parent / "MRKNormalAppUI.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        self.assertEqual(pbx.count('path = "Fixtures/normal-ios-unsigned-v1.json"'), 1)
        self.assertIn('A10000000000000000000018 = {isa = PBXBuildFile; fileRef = A10000000000000000000019;', pbx)
        self.assertIn('A10000000000000000000017, A10000000000000000000019); path = MRKNormalAppUITests;', pbx)
        self.assertIn('A10000000000000000000016, A10000000000000000000018); runOnlyForDeploymentPostprocessing = 0;', pbx)
        self.assertIn('SWIFT_STRICT_CONCURRENCY = complete;', pbx)
        self.assertNotIn(MODULE.IOS_UNSIGNED_RESULT, MODULE.NORMAL_SELECTIONS)

    def test_ui_target_requests_boolean_false_sandbox_at_build_time(self):
        # Source intent only; the actual generated signature is admitted separately.
        project_root = ROOT / "desktop/native/macos-normal-ui"
        project = (project_root / "MRKNormalAppUI.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        target_marker = "\t\tA10000000000000000000008 = {\n"
        self.assertEqual(project.count("isa = PBXNativeTarget;"), 1)
        self.assertEqual(project.count(target_marker), 1)
        target = project.split(target_marker, 1)[1].split("\n\t\t};", 1)[0]
        self.assertIn("name = MRKNormalAppUITests;", target)
        self.assertIn('productType = "com.apple.product-type.bundle.ui-testing";', target)
        self.assertIn("buildConfigurationList = A1000000000000000000000E;", target)
        self.assertIn("A1000000000000000000000E = {isa = XCConfigurationList; "
                      "buildConfigurations = (A1000000000000000000000F);", project)
        config_marker = "\t\tA1000000000000000000000F = {\n"
        self.assertEqual(project.count(config_marker), 1)
        config = project.split(config_marker, 1)[1].split("\n\t\t};", 1)[0]
        self.assertEqual(project.count("CODE_SIGN_ENTITLEMENTS"), 1)
        self.assertIn("CODE_SIGN_ENTITLEMENTS = MRKNormalAppUITests.entitlements;", config)
        for preserved in ('CODE_SIGN_IDENTITY = "-";', "CODE_SIGN_STYLE = Manual;",
                          'DEVELOPMENT_TEAM = "";', "ENABLE_APP_SANDBOX = NO;",
                          "ENABLE_HARDENED_RUNTIME = NO;", "name = Debug;"):
            self.assertIn(preserved, config)
        body = (project_root / "MRKNormalAppUITests.entitlements").read_bytes()
        value = MODULE.plist(body)  # Strict dictionary/duplicate-key parsing.
        self.assertEqual(set(value), {"com.apple.security.app-sandbox"})
        self.assertIs(value["com.apple.security.app-sandbox"], False)

    def test_manifest_is_exact_one_generated_runner_not_an_app_target(self):
        products = Path("/fresh/DerivedData/Build/Products")
        self.assertEqual(MODULE.target_from_xctestrun(manifest(), products)["BlueprintName"], MODULE.TARGET)
        for change in (
            {"TestHostPath": "__TESTROOT__/Debug/Other.app"},
            {"TestBundlePath": "__TESTROOT__/../Elsewhere.xctest"},
            {"UITargetAppPath": "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app"},
            {"TestHostBundleIdentifier": "dev.mobile-release-kit.desktop"},
            {"IsUITestBundle": False}):
            value = plistlib.loads(manifest())
            value["TestConfigurations"][0]["TestTargets"][0].update(change)
            with self.subTest(change=change), self.assertRaises(MODULE.Refused):
                MODULE.target_from_xctestrun(plistlib.dumps(value), products)
        for key in ("TestTargets", "configuration"):
            value = plistlib.loads(manifest())
            if key == "TestTargets":
                value["TestConfigurations"][0]["TestTargets"].append(target())
            else:
                value["TestConfigurations"].append(value["TestConfigurations"][0])
            with self.assertRaises(MODULE.Refused):
                MODULE.target_from_xctestrun(plistlib.dumps(value), products)

    def test_normal_cli_preserves_every_old_selection_and_rejects_reuse_switch(self):
        for result in MODULE.NORMAL_SELECTIONS:
            derived, selected, methods, allowance, timeout = MODULE.normal_cli_arguments(normal_arguments(result))
            self.assertEqual(selected.name, result)
            self.assertEqual(derived.name, "DerivedData")
            self.assertNotIn(MODULE.PACKAGED_METHOD, methods)
            self.assertIn(allowance, (60, 300))
            self.assertEqual(timeout, MODULE.NORMAL_SELECTIONS[result][2])
        for mutate in (
            lambda args: args + ["-retry-tests-on-failure"],
            lambda args: [value.replace("testLaunchCancelAndQuit", "testPackagedEntryLaunchCancelAndQuit") for value in args],
            lambda args: [value.replace("Debug", "Release") for value in args],
            lambda args: [value.replace("platform=macOS,arch=arm64", "platform=macOS") for value in args]):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_cli_arguments(mutate(normal_arguments()))
        for allowance in (True, 300, 600):
            with self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments("/fixed.xctestrun", "/fresh.xcresult", (MODULE.PACKAGED_METHOD,), allowance)
        # One separately selected unsigned iOS original; it is not part of the
        # seven ordinary groups and cannot borrow an arbitrary 900s allowance.
        temporary = "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        normal = Path(temporary).parent
        selected = MODULE.CLASS + "testSyntheticProjectUnsignedIOSArchive"
        self.assertEqual(MODULE.IOS_UNSIGNED_METHOD, "testSyntheticProjectUnsignedIOSArchive")
        self.assertNotIn(MODULE.IOS_UNSIGNED_RESULT, MODULE.NORMAL_SELECTIONS)
        self.assertEqual(len(MODULE.NORMAL_SELECTIONS), 8)
        for target, machine in ((MODULE.ARM_TARGET, "arm64"), (MODULE.INTEL_TARGET, "x86_64")):
            request = MODULE.normal_request(["--target", target, "--normal-ios-unsigned-archive-test"], temporary)
            self.assertEqual(request, dict(phase="test", derived=normal / "DerivedData",
                result=normal / "ios-unsigned-archive-test.xcresult", methods=(selected,), allowance=900,
                timeout=1020, phaseSeconds=1245, iosUnsigned=True, target=target))
            summary = MODULE.normal_request(["--target", target, "--normal-ios-unsigned-archive-summary"], temporary)
            self.assertEqual(summary, dict(request, phase="summary", methods=(), allowance=None,
                                           timeout=30, phaseSeconds=90))
            command = MODULE.xcode_test_arguments(Path("fixed.xctestrun"), request["result"],
                                                  (selected,), 900, target=target, ios_unsigned=True)
            self.assertEqual(command, ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", "fixed.xctestrun",
                "-destination", "platform=macOS,arch=" + machine, "-destination-timeout", "15",
                "-resultBundlePath", str(request["result"]), "-only-testing:" + selected,
                "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
                "-default-test-execution-time-allowance", "900", "-maximum-test-execution-time-allowance", "900",
                "-disableAutomaticPackageResolution"])
        for arguments in (["--normal-ios-unsigned-archive-test", "extra"],
                          ["--normal-ios-unsigned-archive-summary", "ios-unsigned-archive-test.xcresult"],
                          ["--normal-ios-unsigned-archive-test", "--retry"],
                          ["--normal-ios-unsigned-archive-test", "--target", MODULE.ARM_TARGET]):
            with self.subTest(ios_arguments=arguments), self.assertRaises(MODULE.Refused):
                MODULE.normal_request(arguments, temporary)
        for changed in (dict(ios_unsigned=False), dict(ios_unsigned=1), dict(engineering=True),
                        dict(output_data=True), dict(android_positive=True), dict(allowance=300),
                        dict(allowance=True), dict(methods=(MODULE.OUTPUT_DATA_METHOD,)),
                        dict(methods=(selected, selected)), dict(result=normal / "test.xcresult")):
            values = dict(methods=(selected,), allowance=900, result=normal / MODULE.IOS_UNSIGNED_RESULT,
                          ios_unsigned=True)
            values.update(changed)
            with self.subTest(ios_arguments=changed), self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments(Path("fixed.xctestrun"), **values)
        for changed in (dict(ios_unsigned=1), dict(engineering=True), dict(output_data=True),
                        dict(android_positive=True), dict(allowance=300), dict(timeout=900),
                        dict(methods=(MODULE.OUTPUT_DATA_METHOD,)), dict(result=normal / "test.xcresult")):
            values = dict(methods=(selected,), allowance=900, timeout=1020, result=normal / MODULE.IOS_UNSIGNED_RESULT,
                          ios_unsigned=True)
            values.update(changed)
            with self.subTest(ios_owner=changed), patch.object(MODULE, "RunnerProducts") as unopened:
                with self.assertRaises(MODULE.Refused):
                    MODULE.run_admitted_test(lambda *_: self.fail("invalid iOS original dispatched"),
                                             normal / "DerivedData", **values)
                unopened.assert_not_called()

        # Removal remains a separate closed in-process owner, never an ordinary CLI selector.
        for case in ("ordinary", "abrupt"):
            method, result_name = MODULE.removal_selection(case)
            values = dict(methods=(method,), allowance=300, result=normal / result_name, removal_case=case)
            command = MODULE.xcode_test_arguments(Path("fixed.xctestrun"), **values)
            self.assertEqual([v for v in command if v.startswith("-only-testing:")], ["-only-testing:" + method])
            self.assertNotIn(result_name, MODULE.NORMAL_SELECTIONS)
            for changed in (dict(removal_case=None), dict(removal_case=True), dict(removal_case="unknown"),
                            dict(target=MODULE.INTEL_TARGET), dict(engineering=True), dict(output_data=True),
                            dict(android_positive=True), dict(ios_unsigned=True), dict(allowance=60),
                            dict(methods=(method, method)), dict(result=normal / "test.xcresult")):
                with self.subTest(removal=case, changed=changed), self.assertRaises(MODULE.Refused):
                    MODULE.xcode_test_arguments(Path("fixed.xctestrun"), **dict(values, **changed))
            with patch.object(MODULE, "RunnerProducts") as unopened:
                for timeout in (True, 419, 421):
                    with self.assertRaises(MODULE.Refused):
                        MODULE.run_admitted_test(lambda *_: self.fail("invalid removal dispatched"),
                            normal / "DerivedData", timeout=timeout, **values)
                unopened.assert_not_called()
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_request(["--normal-summary", result_name], temporary)


    def test_project_batch_is_exactly_two_methods_with_existing_finite_deadlines(self):
        expected = ("testSyntheticProjectLocalEditsAndImages", "testSyntheticProjectPathFields")
        self.assertEqual(MODULE.NORMAL_SELECTIONS["project-test.xcresult"], (expected, 300, 720))
        arguments = normal_arguments("project-test.xcresult")
        derived, result, methods, allowance, timeout = MODULE.normal_cli_arguments(arguments)
        self.assertEqual(methods, tuple(MODULE.CLASS + method for method in expected))
        temporary = str(derived.parent / "tmp") + "/"
        self.assertEqual(MODULE.normal_request(arguments, temporary)["phaseSeconds"], 885)
        fixed = MODULE.xcode_test_arguments("/fixed.xctestrun", result, methods, allowance)
        self.assertEqual([item for item in fixed if item.startswith("-only-testing:")],
                         ["-only-testing:" + method for method in methods])
        for changed in (arguments[:15] + arguments[16:], arguments[:16] + arguments[17:],
                        arguments[:16] + arguments[15:16] + arguments[16:],
                        [item.replace("testSyntheticProjectPathFields", "testSyntheticProjectLocalEdits")
                         for item in arguments],
                        arguments[:15] + list(reversed(arguments[15:17])) + arguments[17:]):
            with self.subTest(selection=changed[15:18]), self.assertRaises(MODULE.Refused):
                MODULE.normal_cli_arguments(changed)

    def test_project_output_requires_both_originals_exact_attempts_and_terminal_markers(self):
        output = normal_project_output()
        self.assertIs(MODULE.normal_project_markers(output), True)
        original = MODULE.ORIGINAL_MARKER.encode() + b"\n"
        markers = [line + b"\n" for line in output.splitlines()
                   if line.startswith((b"MRK_MACOS_NORMAL_PROJECT", b"MRK_MACOS_NORMAL_ANDROID_SOURCE_UI="))]
        self.assertEqual(len(markers), 3)
        started = [line + b"\n" for line in output.splitlines() if line.endswith(b"' started.")]
        passed = [line + b"\n" for line in output.splitlines() if b"' passed (" in line]
        bad = [b"", b"x" * (1024 * 1024 + 1), output.replace(original, b"", 1), output + original,
               output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
               output.replace(b"completion=1", b"completion=0", 1),
               output.replace(b"testSyntheticProjectPathFields", b"testUnexpectedProjectMethod"),
               output.replace(b"MRKNormalAppUITests.NormalAppUITests", b"OtherTests.OtherClass"),
               output.replace(b"passed (1.000 seconds).", b"failed (1.000 seconds).", 1),
               output.replace(b"passed (1.000 seconds).", b"passed (... seconds).", 1),
               output.replace(b"backend-source-refused-selection-only", b"cancelled-selection-only")]
        for row in markers + started + passed:
            bad.extend((output.replace(row, b"", 1), output + row))
        for body in bad:
            with self.subTest(bytes=len(body)), self.assertRaises(MODULE.Refused):
                MODULE.normal_project_markers(body)
        for body in (None, "not bytes", bytearray(output)):
            with self.assertRaises(MODULE.Refused): MODULE.normal_project_markers(body)
        with self.assertRaises(UnicodeDecodeError): MODULE.normal_project_markers(output + b"\xff")

    def test_project_marker_admission_gates_zero_only_and_preserves_original_nonzero(self):
        arguments = normal_arguments("project-test.xcresult")
        request = MODULE.normal_request(arguments, str(Path(arguments[12]).parent / "tmp") + "/")
        clock = SimpleNamespace(before_publication=lambda: {}, check=lambda: None)
        phase = SimpleNamespace(call=lambda *args: self.fail("no native execution"), records=[], clock=clock)
        for status, output in ((0, normal_project_output()), (0, b"missing original markers"), (65, b"native failed")):
            original = subprocess.CompletedProcess([], status, output, b"")
            with self.subTest(status=status, bytes=len(output)), \
                    patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                    patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                    patch.object(MODULE, "exclusive_output") as publish, \
                    patch.object(MODULE, "normal_project_markers", wraps=MODULE.normal_project_markers) as parse:
                if status == 0 and output != normal_project_output():
                    with self.assertRaises(MODULE.Refused):
                        MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    publish.assert_not_called()
                    continue
                self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                receipt = json.loads(publish.call_args.args[1])
                self.assertEqual(receipt["originalTestReturncode"], status)
                if status == 0:
                    self.assertIs(receipt["projectFieldAndEditMarkersObserved"], True)
                    self.assertIs(receipt["androidToolSourceBrowseMarkerObserved"], True)
                    parse.assert_called_once_with(output)
                else:
                    self.assertNotIn("projectFieldAndEditMarkersObserved", receipt)
                    self.assertNotIn("androidToolSourceBrowseMarkerObserved", receipt)
                    parse.assert_not_called()

    def test_workflow_refusal_selection_is_opt_in_and_preserves_all_old_budgets(self):
        old = {
            "test.xcresult": (("testLaunchCancelAndQuit",), 60, 180),
            "project-test.xcresult": (("testSyntheticProjectLocalEditsAndImages",
                                      "testSyntheticProjectPathFields"), 300, 720),
            "persistence-test.xcresult": (("testSyntheticPersistentCredentials",), 300, 420),
            "diagnostics-test.xcresult": (("testSyntheticProjectBuildToolDiagnostics",), 300, 420),
            "saved-checks-test.xcresult": (("testSyntheticProjectSavedOfflineChecks",
                                          "testSyntheticProjectEmptyBuildInputInspection"), 300, 720),
        }
        result_name = "workflow-refusal-test.xcresult"
        self.assertEqual({name: value for name, value in MODULE.NORMAL_SELECTIONS.items() if name not in (result_name, "saved-version-recovery-test.xcresult", "release-evidence-test.xcresult")}, old)
        self.assertEqual(MODULE.NORMAL_SELECTIONS[result_name],
                         (("testSyntheticProjectManagedWorkflowRefusal",), 300, 420))
        arguments = normal_arguments(result_name)
        derived, result, methods, allowance, timeout = MODULE.normal_cli_arguments(arguments)
        self.assertEqual((methods, allowance, timeout),
                         ((MODULE.CLASS + "testSyntheticProjectManagedWorkflowRefusal",), 300, 420))
        temporary = str(derived.parent / "tmp") + "/"
        self.assertEqual(MODULE.normal_request(arguments, temporary)["phaseSeconds"], 585)
        summary = MODULE.normal_request(["--normal-summary", result_name], temporary)
        self.assertEqual((summary["phase"], summary["result"], summary["timeout"], summary["phaseSeconds"]),
                         ("summary", result, 30, 90))
        self.assertEqual(MODULE.SUMMARY_STEMS[result_name], "workflow-refusal-summary")
        fixed = MODULE.xcode_test_arguments("/fixed.xctestrun", result, methods, allowance)
        self.assertEqual([arg for arg in fixed if arg.startswith("-only-testing:")],
                         ["-only-testing:" + MODULE.CLASS + "testSyntheticProjectManagedWorkflowRefusal"])
        for changed in (
            arguments[:15] + arguments[16:],
            arguments[:16] + arguments[15:16] + arguments[16:],
            arguments + ["-retry-tests-on-failure"],
            [arg.replace("testSyntheticProjectManagedWorkflowRefusal", "testSyntheticProjectLocalEditsAndImages")
             for arg in arguments],
            [arg.replace("workflow-refusal-test.xcresult", "project-test.xcresult") for arg in arguments],
            ["60" if arg == "300" else arg for arg in arguments],
        ):
            with self.subTest(selection=changed[15:18]), self.assertRaises(MODULE.Refused):
                MODULE.normal_cli_arguments(changed)

        # Current recovery SOURCE is the genuine configured runtime nomination,
        # not an arbitrary replacement digest or a claim of native qualification.
        expected_source = '58f6d68d2db29100ed15fd8c4f8d893b3a0a3dbe1d8cd37b385690c36b9cfa3d'
        nomination = json.loads((ROOT / "desktop/macos-installed-inputs/python-signed-runtime-binding.json").read_bytes())
        self.assertEqual(set(nomination["targets"]), {MODULE.ARM_TARGET, MODULE.INTEL_TARGET})
        for target in (MODULE.ARM_TARGET, MODULE.INTEL_TARGET):
            self.assertEqual(nomination["targets"][target]["state"], "configured")
            self.assertEqual(nomination["targets"][target]["sourceInputsSha256"], expected_source)
        self.assertEqual(MODULE.SAVED_VERSION_SOURCE, expected_source)
        profile = "desktop/packaging/macos-history-provider.profile"
        self.assertEqual(hashlib.sha256((ROOT / profile).read_bytes()).hexdigest(),
                         "76ce1597468fd1d4d420b1453194ea6ab89c1556de6bba5664c79637754c2e4b")
        runner_source = (ROOT / "desktop/tools/macos_normal_ui_runner.py").read_text(encoding="utf-8")
        self.assertEqual(runner_source.count("    def _sources(self):\n"), 1)
        fixed_source = runner_source.split("    def _sources(self):\n", 1)[1].split("        selected =", 1)[0]
        self.assertEqual(fixed_source,
                         '        fixed = {"desktop/" + name for name in SAVED_VERSION_BOOTSTRAPS}\n'
                         '        fixed.update(("desktop/cpython-source-inputs/github-ca.pem", "desktop/tools/prepare_runtime.py",\n'
                         '                      "desktop/packaging/macos-history-provider.profile"))\n')
        self.assertEqual(len(MODULE.SAVED_VERSION_BOOTSTRAPS), 13)
        self.assertEqual(len(set(MODULE.SAVED_VERSION_BOOTSTRAPS)), 13)
        swift = SWIFT.read_text(encoding="utf-8")
        current_line = '                  raw["sourceInputsSha256"] as? String == "58f6d68d2db29100ed15fd8c4f8d893b3a0a3dbe1d8cd37b385690c36b9cfa3d",\n'
        prior_line = '                  raw["sourceInputsSha256"] as? String == "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0",\n'
        self.assertEqual(swift.count(current_line), 1)
        self.assertNotIn(prior_line, swift)
        normalized = without_artifact_wait_diagnostic_source(swift)
        self.assertEqual(normalized.count(prior_line), 1)
        self.assertEqual(without_artifact_wait_diagnostic_source(swift.replace(current_line, prior_line, 1)), normalized)
        self.assertEqual(without_artifact_wait_diagnostic_source(normalized), normalized)
        self.assertEqual(without_artifact_wait_diagnostic_source("historical pre-recovery source\n"),
                         "historical pre-recovery source\n")
        for malformed in (current_line.replace(expected_source, "0" * 64), current_line.replace(" == ", " != "),
                          current_line.rstrip("\n"), current_line + current_line, current_line + prior_line):
            with self.subTest(saved_source_line=malformed[-80:]), self.assertRaises(AssertionError):
                without_artifact_wait_diagnostic_source(swift.replace(current_line, malformed, 1))

        # The new singleton adds no budget to or extra method in any old call.
        selected = "saved-version-recovery-test.xcresult"
        self.assertEqual(MODULE.NORMAL_SELECTIONS[selected], (("testSyntheticProjectSavedVersionRecovery",), 300, 420))
        self.assertEqual(MODULE.SUMMARY_STEMS[selected], "saved-version-recovery-summary")
        args = normal_arguments(selected)
        request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
        self.assertEqual((request["methods"], request["allowance"], request["timeout"], request["phaseSeconds"]),
                         ((MODULE.CLASS + "testSyntheticProjectSavedVersionRecovery",), 300, 420, 585))
        for changed in (args + ["-retry-tests-on-failure"], args + [args[15]],
                        [v.replace("SavedVersionRecovery", "SavedOfflineChecks") for v in args]):
            with self.assertRaises(MODULE.Refused): MODULE.normal_cli_arguments(changed)
        case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedVersionRecovery]"
        marker = ("MRK_MACOS_NORMAL_SAVED_VERSION_RECOVERY_UI=original-core-interrupt86-fresh-ui-inspect-close-reinspect-confirm-rollback-reload;"
                  "interruptedGuiSave=not-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
        output = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, marker,
                            "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
        self.assertIs(MODULE.normal_saved_version_markers(output), True)
        for wrong in (output + output, output.replace(marker.encode(), b"wrong"), output[:-1],
                      output.replace(b"passed (", b"failed ("), output.replace(b"SavedVersionRecovery", b"SavedOfflineChecks"),
                      output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
                      b"\n".join((output.splitlines()[0], marker.encode(), MODULE.ORIGINAL_MARKER.encode(), output.splitlines()[3], b""))):
            with self.assertRaises(MODULE.Refused): MODULE.normal_saved_version_markers(wrong)
        frames = [dict(protocol="mrk-release-version/1", session="0123456789abcdef0123456789abcdef", seq=i,
                       kind=kind, result=dict(scopeResources="settled", **result))
                  for i, (kind, result) in enumerate((("opened", {"source": "release/version.properties", "values": {"name": "1.2.3", "build": "7"}}),
                                                       ("prepared", {"view": {"synthetic": True}})))]
        body = b"".join(json.dumps(row).encode() + b"\n" for row in frames)
        self.assertEqual(MODULE.saved_version_producer_frames(body), hashlib.sha256(body).hexdigest())
        for wrong in (body + b'{}\n', body.replace(b'"seq": 1', b'"seq": true'), body.replace(b'"prepared"', b'"terminal"'),
                      body.replace(b'"settled"', b'"unknown"', 1), body.replace(b'"1.2.3"', b'"2.3.4"'), body[:-1]):
            with self.assertRaises(MODULE.Refused): MODULE.saved_version_producer_frames(wrong)

        # A separate saved-document singleton; never changes ordinary-seven or recovery.
        result_name = "release-evidence-test.xcresult"
        self.assertEqual(MODULE.NORMAL_SELECTIONS[result_name], (("testSyntheticProjectSavedReleaseEvidence",), 300, 420))
        self.assertEqual(MODULE.SUMMARY_STEMS[result_name], "release-evidence-summary")
        args = normal_arguments(result_name)
        request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
        self.assertEqual((request["methods"], request["allowance"], request["timeout"], request["phaseSeconds"]),
                         ((MODULE.CLASS + "testSyntheticProjectSavedReleaseEvidence",), 300, 420, 585))
        summary = MODULE.normal_request(["--normal-summary", result_name], str(Path(args[12]).parent / "tmp") + "/")
        self.assertEqual((summary["timeout"], summary["phaseSeconds"]), (30, 90))
        for changed in (args + ["-retry-tests-on-failure"], args + [args[15]],
                        [v.replace("SavedReleaseEvidence", "ManagedWorkflowRefusal") for v in args],
                        [v.replace("release-evidence-test", "saved-checks-test") for v in args],
                        ["900" if v == "300" else v for v in args]):
            with self.assertRaises(MODULE.Refused): MODULE.normal_cli_arguments(changed)

    def test_workflow_refusal_output_requires_one_original_exact_final_case_and_scope(self):
        output = normal_workflow_refusal_output()
        self.assertIs(MODULE.normal_workflow_refusal_markers(output), True)
        rows = output.splitlines(keepends=True)
        self.assertEqual(len(rows), 4)
        bad = [b"", b"x" * (1024 * 1024 + 1), output[:-1],
               output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
               output.replace(b"completion=1", b"completion=0", 1),
               output.replace(b"testSyntheticProjectManagedWorkflowRefusal", b"testUnexpectedMethod"),
               output.replace(b"MRKNormalAppUITests.NormalAppUITests", b"OtherTests.OtherClass"),
               output.replace(b"passed (1.000 seconds).", b"failed (1.000 seconds)."),
               output.replace(b"passed (1.000 seconds).", b"passed (... seconds)."),
               output.replace(b"whole-bundle-refused-originals-preserved", b"preview-only"),
               output + b"Test Case 'unselected' failed (1.000 seconds).\n",
               output + b"Test Case 'unselected' started\n",
               rows[3] + b"".join(rows[:3]),
               rows[0] + rows[2] + rows[1] + rows[3]]
        for row in rows:
            bad.extend((output.replace(row, b"", 1), output + row))
        for prefix in (b"MRK_MACOS_UI_ORIGINAL=", b"MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI="):
            bad.append(output + prefix + b"wrong-extra-value\n")
        for body in bad:
            with self.subTest(bytes=len(body)), self.assertRaises(MODULE.Refused):
                MODULE.normal_workflow_refusal_markers(body)
        for body in (None, "not bytes", bytearray(output)):
            with self.assertRaises(MODULE.Refused): MODULE.normal_workflow_refusal_markers(body)
        with self.assertRaises(UnicodeDecodeError):
            MODULE.normal_workflow_refusal_markers(output + b"\xff\n")
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_workflow_refusal_markers(normal_project_output())
        self.assertIs(MODULE.normal_project_markers(normal_project_output()), True)

        case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedReleaseEvidence]"
        marker = 'MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted'
        output = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, marker,
                             "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
        self.assertIs(MODULE.normal_release_evidence_markers(output), True)
        rows = output.splitlines(keepends=True)
        for bad in (b"", output[:-1], output + output, b"x" * (1024 * 1024 + 1),
                    output.replace(b"passed (", b"failed ("), output.replace(b"SavedReleaseEvidence", b"ManagedWorkflowRefusal"),
                    output.replace(b"documents-only", b"store-authenticated"),
                    output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
                    rows[0] + rows[2] + rows[1] + rows[3], normal_workflow_refusal_output()):
            with self.assertRaises(MODULE.Refused): MODULE.normal_release_evidence_markers(bad)
        for row in rows:
            for bad in (output + row, output.replace(row, b"", 1)):
                with self.assertRaises(MODULE.Refused): MODULE.normal_release_evidence_markers(bad)
        with self.assertRaises(MODULE.Refused): MODULE.normal_workflow_refusal_markers(output)

    def test_workflow_refusal_marker_gate_is_only_new_selection_original_zero(self):
        clock = SimpleNamespace(before_publication=lambda: {}, check=lambda: None)
        phase = SimpleNamespace(call=lambda *args: self.fail("no native execution"), records=[], clock=clock)
        selected = "workflow-refusal-test.xcresult"
        for name, status, output in (
            (selected, 0, normal_workflow_refusal_output()), (selected, 0, b"missing original markers"),
            (selected, 65, b"native failed"),
            ("project-test.xcresult", 0, normal_project_output()),
            ("diagnostics-test.xcresult", 0, b"not a workflow-refusal case"),
        ):
            arguments = normal_arguments(name)
            request = MODULE.normal_request(arguments, str(Path(arguments[12]).parent / "tmp") + "/")
            original = subprocess.CompletedProcess([], status, output, b"")
            with self.subTest(selection=name, status=status, bytes=len(output)), \
                    patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                    patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                    patch.object(MODULE, "exclusive_output") as publish, \
                    patch.object(MODULE, "normal_workflow_refusal_markers",
                                 wraps=MODULE.normal_workflow_refusal_markers) as parse:
                if name == selected and status == 0 and output != normal_workflow_refusal_output():
                    with self.assertRaises(MODULE.Refused):
                        MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    parse.assert_called_once_with(output)
                    publish.assert_not_called()
                    continue
                self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                receipt = json.loads(publish.call_args.args[1])
                self.assertEqual(receipt["originalTestReturncode"], status)
                if name == selected and status == 0:
                    self.assertIs(receipt["managedWorkflowRefusalMarkerObserved"], True)
                    parse.assert_called_once_with(output)
                    self.assertNotIn("projectFieldAndEditMarkersObserved", receipt)
                else:
                    self.assertNotIn("managedWorkflowRefusalMarkerObserved", receipt)
                    parse.assert_not_called()

        case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedReleaseEvidence]"
        marker = 'MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted'
        output = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, marker,
                             "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
        for name, status, body in (("release-evidence-test.xcresult", 0, output),
                                   ("release-evidence-test.xcresult", 0, b"missing markers"),
                                   ("release-evidence-test.xcresult", 65, b"failure"),
                                   ("workflow-refusal-test.xcresult", 0, normal_workflow_refusal_output())):
            args = normal_arguments(name)
            request = MODULE.normal_request(args, str(Path(args[12]).parent / "tmp") + "/")
            original = subprocess.CompletedProcess([], status, body, b"")
            with patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}), \
                 patch.object(MODULE, "run_admitted_test", return_value=(original, {})), \
                 patch.object(MODULE, "exclusive_output") as publish, \
                 patch.object(MODULE, "normal_release_evidence_markers", wraps=MODULE.normal_release_evidence_markers) as parser:
                if name == "release-evidence-test.xcresult" and status == 0 and body != output:
                    with self.assertRaises(MODULE.Refused): MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2)
                    parser.assert_called_once_with(body); publish.assert_not_called()
                    continue
                self.assertIs(MODULE.execute_normal_phase(phase, request, "a" * 40, (1024**3,) * 2), original)
                receipt = json.loads(publish.call_args.args[1])
                if name == "release-evidence-test.xcresult" and status == 0:
                    self.assertIs(receipt["savedReleaseEvidenceMarkerObserved"], True)
                    parser.assert_called_once_with(body)
                else:
                    self.assertNotIn("savedReleaseEvidenceMarkerObserved", receipt); parser.assert_not_called()

    def test_workflow_refusal_source_derives_originals_before_creation_and_never_applies(self):
        source = without_positive_android_source(SWIFT.read_text())
        prepare = source.split("func prepare(_ profile: Profile = .projectEdits) throws {", 1)[1].split(
            "func admitDefaultVault()", 1)[0]
        self.assertIn("case projectEdits, projectFields, persistentCredentials, workflowRefusal", source)
        self.assertLess(prepare.index('changes[stage] = try decode(values)'),
                        prepare.index("if profile == .workflowRefusal"))
        self.assertLess(prepare.index("if profile == .workflowRefusal"),
                        prepare.index('let slash = try adoptDirectory(open("/",'))
        for fragment in (
            'changes["workflows"]?[preflight]', 'changes["workflows"]?[candidate]',
            'Data("# MRK synthetic user customization; preserve exactly.\\n".utf8)',
            "let customized = candidateTemplate + suffix", "suffix.count == 54",
            "originals[preflight] = canonical", "originals[candidate] = customized",
            "originals.count == 15 && Self.ancestors(Set(originals.keys)).count == 10",
            "originalBytes == 5232 && stageBytes == 12137 && originalBytes + stageBytes == 17369",
            "current.count == 15 && directories.count == 10 && anchors.count == 3",
            "descriptors.count == 13",
            "cb50a58a62167a9e25da9eeb42a2c2d448f47445515e9fc291d3a23543762933",
        ):
            self.assertIn(fragment, prepare)
        journey = source.split("@MainActor func testSyntheticProjectManagedWorkflowRefusal() throws {", 1)[1].split(
            "    // Ordinary saved offline checks", 1)[0]
        for fragment in (
            "try beginCase(seconds: 300)", "try launchForJourney()", "try fixture.prepare(.workflowRefusal)",
            'try goToFolder(sheet, path: fixture.projectPath)', 'try nativeOpen(sheet)',
            'with: "Example/mobile-release-kit"', 'with: String(repeating: "a", count: 40)',
            'equals: fixture.text(path, stage: "workflows")',
            'Self.workflowFailures.filter { $0 != "Local workflow bundle refused" }',
            'Observed differing callers · no Apply token', '"existing_workflow_differs"',
            '"candidate", "2,368 observed bytes"', '"Independent native workflow outcome facts"',
            '["Transaction effect", "not_started", "Journal", "not_created",',
            '"Core resources", "settled", "Native finality", "settled"]',
            '"Review unchanged confirmation"', '"Confirm unchanged plan"', '"Confirm four unchanged callers?"',
        ):
            self.assertIn(fragment, journey)
        self.assertEqual(journey.count('try press(review, "Review local workflow files"'), 1)
        self.assertEqual(journey.count("try fixture.assertUnchanged()"), 5)
        for forbidden in ("fixture.accept(", "confirmedDialog(", "controller.", "evaluateJavaScript",
                          'try press(review, "Confirm', 'try press(review, "Apply', "fixture.prepare()"):
            self.assertNotIn(forbidden, journey)
        ending = journey.split('try stage("workflow-refusal-readback-and-quit") {', 1)[1]
        order = ("try refusedOutcome()", "try fixture.assertUnchanged()", "try quitSheet(app, window)",
                 "try completeNormalQuit(app)", "try fixture.closeOriginals()", "ownedFixture = nil",
                 "try acceptFinalScenario()", 'print("MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI=')
        self.assertEqual([ending.index(fragment) for fragment in order], sorted(ending.index(fragment) for fragment in order))
        after_quit = ending.split("try completeNormalQuit(app)", 1)[1]
        self.assertLess(after_quit.index("try fixture.assertUnchanged()"), after_quit.index("try fixture.closeOriginals()"))
        failures = source.split("private static let workflowFailures = [", 1)[1].split("\n    ]", 1)[0]
        self.assertIn('"Local workflow bundle refused"', failures)  # Never remove it globally.

        import base64
        current = SWIFT.read_text()
        rows = current.split("static let releaseEvidenceDocuments: [(String, String, Int, String)] = [", 1)[1].split("\n        ]", 1)[0]
        additions = re.findall(r'\("([^"]+)", "([A-Za-z0-9+/=]+)", ([0-9]+), "([0-9a-f]{64})"\)', rows)
        expected = {
            "evidence/candidate-manifest.json": "candidate-valid.json",
            "evidence/candidate-receipt.json": "receipt-candidate-valid.json",
            "evidence/operation/candidate-operation-intent.json": "intent-candidate-valid.json",
        }
        self.assertEqual(len(additions), 3); self.assertEqual({r[0] for r in additions}, set(expected))
        total = 0
        for path, encoded, size, digest in additions:
            observed = base64.b64decode(encoded, validate=True)
            actual = (ROOT / "tests/fixtures" / expected[path]).read_bytes()
            self.assertEqual(observed, actual)
            self.assertEqual((len(observed), hashlib.sha256(observed).hexdigest()), (int(size), digest))
            self.assertLessEqual(len(observed), 4096); total += len(observed)
        self.assertEqual(total, 11366)
        prepare = current.split("func prepare(_ profile: Profile = .projectEdits) throws {", 1)[1].split("func admitDefaultVault()", 1)[0]
        for token in ("originals.count == 16", "Self.ancestors(Set(originals.keys)).count == 12", "== 12740",
                      "current.count == 16 && directories.count == 12 && anchors.count == 3", "descriptors.count == 15"):
            self.assertIn(token, prepare)
        self.assertLess(prepare.index("if profile == .releaseEvidence"), prepare.index('let slash = try adoptDirectory(open("/",'))
        journey = current.split("@MainActor func testSyntheticProjectSavedReleaseEvidence() throws {", 1)[1].split("@MainActor func testSyntheticProjectManagedWorkflowRefusal()", 1)[0]
        for token in ("try beginCase(seconds: 300)", "try launchForJourney()", "try fixture.prepare(.releaseEvidence)",
                      'title: "Choose a release evidence folder"', "fixture.evidencePath", 'try nativeOpen(sheet)',
                      '"Documents agree"', '"Documents only"', '"com.example.reader"', '"evidence · Candidate"', 'guidance)',
                      '"External testing · reuse candidate"', '"Android · Google Play"', '!prepare.isEnabled',
                      '!inspect.isEnabled', 'input.value as? String == ""', 'try click(sheet.buttons.matching(identifier: "Cancel")',
                      'Original operation cancelled and settled. No new result was accepted.', 'try staleDocuments()',
                      'Previous guidance · stale · evidence', 'All six assurance flags remain false.'):
            self.assertIn(token, journey)
        self.assertEqual(journey.count('try press(renderer, "Inspect documents"'), 1)
        for forbidden in ('try press(renderer, "Prepare', 'try press(renderer, "Dispatch', 'fixture.accept(', 'controller.', 'evaluateJavaScript', 'Confirm unchanged'):
            self.assertNotIn(forbidden, journey)
        self.assertEqual(journey.count('try press(renderer, "Choose evidence folder"'), 2)
        final = journey.split('try stage("evidence-readback-and-quit") {', 1)[1]
        order = ['try fixture.assertUnchanged()', 'let sheet = try quitSheet(app, window)',
                 'try click(sheet.buttons.matching(identifier: "Quit"),', 'try completeNormalQuit(app)',
                 'try fixture.closeOriginals()', 'ownedFixture = nil', 'try acceptFinalScenario()', 'print("MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=']
        self.assertEqual([final.index(t) for t in order], sorted(final.index(t) for t in order))
        self.assertLess(final.index('try completeNormalQuit(app)'), final.rindex('try fixture.assertUnchanged()'))
        self.assertEqual(hashlib.sha256(without_release_evidence_source(current).encode()).hexdigest(),
                         "da621652977a2f09a32f670fe5ddefc0d135d1753b4fdfce792995872076dae8")
        for token in ('"Documents agree"', 'releaseEvidenceDocuments:', 'try fixture.prepare(.releaseEvidence)', 'descriptors.count == 15'):
            with self.assertRaises(AssertionError): without_release_evidence_source(current.replace(token, token + "changed", 1))

    def test_project_field_fixture_and_normal_workflow_keep_draft_only_scope(self):
        source = without_positive_android_source(SWIFT.read_text())
        prepare = source.split("func prepare(_ profile: Profile = .projectEdits) throws {", 1)[1].split(
            "func admitDefaultVault()", 1)[0]
        self.assertIn("let projectData = profile != .persistentCredentials", prepare)
        self.assertNotIn("profile == .projectEdits", prepare)
        for fragment in ('projectData ? "normal-project-v1" : "normal-persistence-v1"',
                         "let stagePaths: [String: Set<String>] = projectData ?",
                         "let expectedOriginals = projectData ? Self.originals : Self.persistenceOriginals",
                         "(projectData ? spec.templateDataSHA256?.count == 64 : spec.templateDataSHA256 == nil)",
                         'projectData && path.hasPrefix("sources/")'):
            self.assertIn(fragment, prepare)
        ordered = ("originals = try decode(spec.files)", "if profile == .projectFields",
                   "Set(originals.keys).isDisjoint(with: Self.projectFieldAdditions.keys)",
                   "originals[path] = bytes", "whole fixture DATA limit",
                   "for path in Self.ancestors(Set(originals.keys)) where !path.isEmpty {", "for path in originals.keys.sorted()",
                   "current[path] = saved", "try checkRoster()")
        self.assertEqual([prepare.index(item) for item in ordered], sorted(prepare.index(item) for item in ordered))
        additions = source.split("static let projectFieldAdditions: [String: Data] = [", 1)[1].split("\n        ]", 1)[0]
        self.assertEqual(set(re.findall(r'^\s+"([^"]+)": Data\(', additions, re.M)), {
            "project/inputs/VERSION", "project/ios/Example.xcodeproj/project.pbxproj",
            "project/ios/Example.xcworkspace/contents.xcworkspacedata", "project/metadata/README.txt"})
        journey = source.split("@MainActor func testSyntheticProjectPathFields() throws {", 1)[1].split(
            "@MainActor func testSyntheticProjectLocalEdits()", 1)[0]
        selected = journey.split("@MainActor func selected(_ label: String, relative: String) throws {", 1)[1].split(
            "@MainActor func browse(", 1)[0]
        self.assertEqual(selected.count("timeout: 48"), 2)
        self.assertIn('matching(NSPredicate(format: "value == %@", relative)), in: renderer, timeout: 48)', selected)
        self.assertIn("in: renderer, enabled: true, timeout: 48)", selected)
        for required in ("try beginCase(seconds: 300)", "try launchForJourney()", "try fixture.prepare(.projectFields)",
                         'try browse("Committed version file"', 'try browse("Xcode project"',
                         'try browse("Xcode workspace"', 'try browse("Store metadata folder"',
                         'relative: "inputs/VERSION", file: true, cancel: true',
                         'relative: "metadata", cancel: true', '"Review draft changes"',
                         '"Current draft · retained baseline"', '"Format validation needs attention"'):
            self.assertIn(required, journey)
        self.assertGreaterEqual(journey.count('try selected("Xcode project", relative: "ios/Example.xcodeproj")'), 2)
        for forbidden in ('"Prepare save review"', '"Unset field"', '"Unset all ', "savePrivate(", "assertStage(", "evaluateJavaScript"):
            self.assertNotIn(forbidden, journey)
        final = ("try completeNormalQuit(app)", "try fixture.assertUnchanged()", "try fixture.closeOriginals()",
                 "ownedFixture = nil", "try acceptFinalScenario()", 'print("MRK_MACOS_NORMAL_PROJECT_FIELDS_UI=')
        quit_body = journey.split('try stage("quit") {', 1)[1]
        self.assertEqual([quit_body.index(item) for item in final], sorted(quit_body.index(item) for item in final))
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        block = workflow.split("id: normal_project_ui_test", 1)[1].split("id: normal_persistence_ui_test", 1)[0]
        self.assertIn("timeout-minutes: 16", block)
        self.assertEqual(re.findall(r"-only-testing:([^\s]+)", block),
                         ["MRKNormalAppUITests/NormalAppUITests/" + method for method in
                          ("testSyntheticProjectLocalEditsAndImages", "testSyntheticProjectPathFields")])
        self.assertIn('expected = {"totalTestCount": 2, "passedTests": 2, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}', block)
        self.assertIn('"project-test.xcresult", 885,', block)
        self.assertIn('("one-admitted-ui-test", 720, 1048576)', block)
        self.assertIn('runner.get("projectFieldAndEditMarkersObserved") is not True', block)
        self.assertIn('"projectRelativeFieldBrowseUI": "passed"', block)
        runtime = (ROOT / "desktop/src-tauri/src/runtime.rs").read_text()
        self.assertIn("const INSTALLED_MAC_PROJECT_FIELDS_QUALIFIED: bool = true;", runtime)
        self.assertIn("const INSTALLED_MAC_ANDROID_SOURCE_SELECTION_QUALIFIED: bool = true;", runtime)
        self._assert_android_source_browse_bindings(source, prepare, journey, workflow, runtime)

    def _assert_android_source_browse_bindings(self, source, prepare, journey, workflow, runtime):
        # SOURCE/literal DATA inside the existing selected test. The independent
        # Rust16-cell test and actual native journeys remain separately required.
        rust = ROOT / "desktop/src-tauri/src"
        sources = (rust / "android_tool_sources.rs").read_text()
        status_helper = sources.split("pub(crate) fn status_availability(", 1)[1].split("pub(crate) fn unavailable()", 1)[0]
        self.assertEqual(" ".join(status_helper.split()),
                         "gate: Availability, source_selection_available: bool) -> Availability { "
                         "match (gate, source_selection_available) { "
                         "(Availability::Available, false) => Availability::RuntimeUnqualified, _ => gate, } }")
        oracle = [
            ("Available", "RuntimeUnqualified", "Available"),
            ("Busy", "Busy", "Busy"), ("Shutdown", "Shutdown", "Shutdown"),
            ("CleanupUnknown", "CleanupUnknown", "CleanupUnknown"),
            ("DocumentLost", "DocumentLost", "DocumentLost"),
            ("UnsupportedPlatform", "UnsupportedPlatform", "UnsupportedPlatform"),
            ("RuntimeUnqualified", "RuntimeUnqualified", "RuntimeUnqualified"),
            ("ToolchainUnqualified", "ToolchainUnqualified", "ToolchainUnqualified"),
        ]
        table = sources.split("let cases = [", 1)[1].split("];", 1)[0]
        self.assertEqual(re.findall(r"^\s+\(([A-Za-z]+), ([A-Za-z]+), ([A-Za-z]+)\),$", table, re.M), oracle)
        for literal in ("assert_eq!(status_availability(gate, false), unqualified);",
                        "assert_eq!(status_availability(gate, true), qualified);"):
            self.assertIn(literal, sources)
        protocol = (rust / "android_build_protocol.rs").read_text()
        variants = protocol.split("pub(crate) enum Availability {", 1)[1].split("}", 1)[0]
        self.assertEqual([name.strip() for name in variants.split(",")], [row[0] for row in oracle])

        document = (rust / "asset_session.rs").read_text()
        status = document.split("pub(crate) fn android_tool_sources_status(", 1)[1].split(
            "pub(crate) fn cancel_android_tool_source(", 1)[0]
        ordered = ("publisher.is_none() && !self.inner.android_registration_control.is_unknown()",
                   "crate::android_build_protocol::Availability::Busy",
                   "} else { self.android_build_gate(&state) };",
                   "let gate = crate::android_tool_sources::status_availability(",
                   "gate, self.inner.bridge.installed_android_source_selection_available());",
                   "self.inner.bridge.android_build.sources_status(gate)")
        self.assertEqual([status.index(item) for item in ordered], sorted(status.index(item) for item in ordered))
        self.assertEqual(status.count("status_availability("), 1)
        self.assertEqual(status.count("installed_android_source_selection_available()"), 1)
        self.assertEqual(status.count("sources_status(gate)"), 1)
        self.assertNotIn(".availability =", status)
        choose = document.split("pub(crate) fn choose_android_tool_source(", 1)[1].split("pub(crate) fn choose_project_path(", 1)[0]
        self.assertIn("if gate != crate::android_build_protocol::Availability::Available\n"
                      "                || !self.inner.bridge.installed_android_source_selection_available()", choose)
        self.assertNotIn("status_availability(", choose)
        cancel = document.split("pub(crate) fn cancel_android_tool_source(", 1)[1].split("fn observe_android_source_slot(", 1)[0]
        self.assertIn("cancel_source(input, self.android_build_gate(&state))?", cancel)
        self.assertNotIn("installed_android_source_selection_available", cancel)
        self.assertNotIn("status_availability", cancel)
        bridge = (rust / "bridge.rs").read_text()
        self.assertEqual(bridge.count("let installed_android_source_selection_available = runtime.android_source_selection_profile_available();"), 1)
        self.assertIn("pub(crate) fn installed_android_source_selection_available(&self) -> bool { self.installed_android_source_selection_available }", bridge)
        profile = runtime.split("pub(crate) fn android_source_selection_profile_available(", 1)[1].split(
            "pub(crate) fn evidence_selection_profile_available(", 1)[0]
        self.assertIn("INSTALLED_MAC_ANDROID_SOURCE_SELECTION_QUALIFIED && self.project_selection_profile_available()", profile)
        self.assertIn('#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]\n'
                      '        { INSTALLED_MAC_ANDROID_SOURCE_SELECTION_QUALIFIED && self.project_selection_profile_available()\n'
                      '            && crate::android_build_protocol::Profile::current().is_some_and(crate::android_toolchain_macos_policy::native_catalog_supports) }', profile)
        self.assertIn('#[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]\n        { false }', profile)
        ui = (ROOT / "desktop/src/components/AndroidBuild.tsx").read_text()
        self.assertIn("const sourceRoles: AndroidToolSourceRole[] = ['jdk', 'sdk', 'gradle'];", ui)
        self.assertEqual(ui.count("role=\"group\" aria-label={`${help.label} source folder`}"), 1)
        controller = (ROOT / "desktop/src/androidBuild.ts").read_text()
        self.assertIn("if (this.state.toolSources.availability !== 'available') return androidBuildAvailabilityText[this.state.toolSources.availability];", controller)

        deep = "sources/tool-refused/" + "/".join(["d"] * 123)
        expected_paths = {"sources/tool-jdk.jdk/README.txt", "sources/tool-sdk/README.txt", "sources/tool-gradle/README.txt",
                          "sources/tool-jdk-replacement.jdk/README.txt", deep + "/README.txt"}
        additions = source.split("static let androidSourceAdditions: [String: Data] = [", 1)[1].split("\n        ]", 1)[0]
        rows = re.findall(r'^\s+"([^"]+)": Data\(("(?:\\.|[^"\\])*")\.utf8\)', additions, re.M)
        self.assertEqual(len(rows), 5)
        self.assertEqual({path for path, _ in rows}, expected_paths)
        self.assertEqual([json.loads(value) for _, value in rows], ["MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n"] * 5)
        self.assertEqual([len(json.loads(value).encode()) for _, value in rows], [41] * 5)
        actual_deep = json.loads(source.split("static let androidRefusedDirectory = ", 1)[1].splitlines()[0])
        self.assertEqual(actual_deep, deep)
        absolute = "/private/tmp/mrk-normal-project-XXXXXX/" + deep
        self.assertEqual((len(deep.split("/")), len([part for part in absolute.split("/") if part]), len(absolute.encode())), (125, 128, 305))
        fixture = json.loads((SWIFT.parent / "Fixtures/normal-project-v1.json").read_bytes())
        field_paths = {"project/inputs/VERSION", "project/ios/Example.xcodeproj/project.pbxproj",
                       "project/ios/Example.xcworkspace/contents.xcworkspacedata", "project/metadata/README.txt"}
        leaves = set(fixture["files"]) | field_paths | expected_paths
        directories = {""}
        for path in leaves:
            parts = path.split("/")
            directories.update("/".join(parts[:count]) for count in range(1, len(parts)))
        self.assertEqual((len(leaves), len(directories), len(directories) + 3, len(directories) + 4), (22, 143, 146, 147))
        names = (leaves | directories) - {""}
        fanouts = [sum(name.startswith(prefix) and "/" not in name[len(prefix):] for name in names)
                   for prefix in (path + "/" if path else "" for path in directories)]
        self.assertEqual((max(fanouts), len(names), len(names) + 3 * len(directories)), (7, 164, 593))
        for fragment in ("Self.androidSourceAdditions.count == 5", "$0.count == 41",
                         "Set(originals.keys).isDisjoint(with: Self.androidSourceAdditions.keys)",
                         "originals.count == 22 && Self.ancestors(Set(originals.keys)).count == 143",
                         'Self.androidRefusedDirectory.split(separator: "/").count == 125',
                         'refusedPath.split(separator: "/").count == 128 && refusedPath.utf8.count == 305',
                         "current.count == 22 && directories.count == 143 && anchors.count == 3", "descriptors.count == 146"):
            self.assertIn(fragment, prepare)
        self.assertLess(prepare.index("originals.count == 22"), prepare.index('adoptDirectory(open("/"'))
        self.assertLess(prepare.index("try checkRoster()"), prepare.index("descriptors.count == 146"))
        for fragment in ("result.count < 64", "bytes.count <= 32 * 1024", "<= 256 * 1024"):
            self.assertIn(fragment, source)
        for forbidden in ("getrlimit(", "setrlimit(", "RLIMIT_NOFILE"):
            self.assertNotIn(forbidden, prepare)

        android = journey.split("// Six ordinary native source actions", 1)[1].split("@MainActor func settings(", 1)[0]
        self.assertLess(journey.index('try stage("project-open")'), journey.index("// Six ordinary native source actions"))
        self.assertLess(journey.index('try stage("android-source-refused")'), journey.index('try stage("field-version")'))
        self.assertEqual(re.findall(r'try stage\("android-source-([^"]+)"\)', android), ["jdk", "sdk", "gradle", "cancel", "reselect", "refused"])
        self.assertEqual(re.findall(r'try androidBrowse\("([^"]+)"', android), ["jdk", "sdk", "gradle", "jdk", "jdk", "jdk"])
        for fragment in ('"jdk": "Java development kit (JDK)"', '"sdk": "Android SDK"', '"gradle": "Gradle distribution"',
                         'controls(renderer, [.group], label: label + " source folder")',
                         'try nativeSheet(window, title: title)', 'try nativeOpen(sheet)',
                         'try goToFolder(sheet, path: fixture.rootPath + "/" + relative)',
                         'try click(sheet.buttons.matching(identifier: "Cancel")',
                         'relative: "sources/tool-jdk.jdk", cancel: true',
                         'relative: "sources/tool-sdk"', 'relative: "sources/tool-gradle"',
                         'relative: "sources/tool-jdk-replacement.jdk"',
                         "relative: LocalFixture.androidRefusedDirectory, refused: true",
                         'try androidStatus("Folder selection cancelled."',
                         'reason: "The native folder dialog was closed without selecting a folder."',
                         'try androidStatus("Folder selection could not be used."',
                         'reason: "Choose a real, readable local folder, not an alias or archive. This check does not inspect the tools inside it."',
                         'try androidStatus("Original folder selection retained."',
                         'reason: "Folder selection alone is not supplier inspection or a protected copy. Check the separate original registration Status."',
                         "try androidRetained()\n            try fixture.assertUnchanged()",
                         'in: group, enabled: true, timeout: 48)', 'in: renderer, timeout: 48, failures: failures)'):
            self.assertIn(fragment, android)
        self.assertEqual(android.count("androidSelections[role] = String(name)"), 1)
        for branch in (android.split("if refused {", 1)[1].split("} else {", 1)[0],
                       android.split("if cancel {", 1)[1].split("} else {", 1)[0]):
            self.assertNotIn("androidSelections[role] = String(name)", branch)
        for forbidden in ("firstMatch", "element(boundBy:", "evaluateJavaScript", "setValue(", "try?", "catch",
                          "inspectToolSources(", "registerTools(", "checkAndroidToolService(", "requestAndroidToolServiceRegistration("):
            self.assertNotIn(forbidden, android)
        marker = "MRK_MACOS_NORMAL_ANDROID_SOURCE_UI=ordinary-jdk-sdk-gradle-native-cancel-jdk-reselect-backend-source-refused-selection-only;cleanExitStatus=unavailable;allWorkerFinality=unavailable"
        self.assertEqual(journey.count('print("' + marker + '")'), 1)
        self.assertLess(journey.index("try acceptFinalScenario()"), journey.index('print("' + marker + '")'))

        # Unchanged real directory-refusal route, not a synthetic returned DTO.
        shared_source = (rust / "asset_source.rs").read_text()
        mac_source = (rust / "asset_source_macos.rs").read_text()
        self.assertIn("const COMPONENT_LIMIT: usize = 128;", shared_source)
        self.assertIn("pub(crate) const PATH_LIMIT: usize = 4096;", shared_source)
        parts = mac_source.split("fn parts(path: &Path)", 1)[1].split("fn source_extra(", 1)[0]
        self.assertIn("components.len() >= COMPONENT_LIMIT - 1 { return Err(Reason::SourceRefused); }", parts)
        probe = mac_source.split("pub(crate) fn probe_project_excluding_vault(", 1)[1].split("pub(crate) fn probe_vault_exclusion(", 1)[0]
        self.assertLess(probe.index("let project_parts = parts(&path)?;"), probe.index("book.begin("))
        job = document.split("Job::AndroidSource { app, binding } => {", 1)[1].split("Job::ProjectPath {", 1)[0]
        self.assertIn("DialogChoice::AndroidToolSource(binding.role)", job)
        self.assertIn("ChildJob::Probe { path, origins: Vec::new(), vault: None }", job)
        self.assertIn("book.not_started() || book.settled()", document)
        self.assertIn('runner.get("androidToolSourceBrowseMarkerObserved") is not True', workflow)
        self.assertIn('"androidToolSourceBrowseUI": "passed"', workflow)
        self.assertIn('"androidToolSourceBrowseScope": "selection-only-three-roles-native-cancel-reselect-backend-source-refused"', workflow)
        self.assertIn('"supplierInspectionQualified": False, "protectedToolCopyQualified": False, "androidBuildQualified": False', workflow)

    def test_closed_result_requires_every_original_terminal_fact(self):
        original = result_data()
        accepted = MODULE.packaged_ui_result(*original)
        self.assertIsNone(accepted["cleanExitStatus"])
        for key in ("sameBuildQualified", "fullUIQualified", "fullM2Qualified", "productReady"):
            self.assertIs(accepted[key], False)
        output = original[0]
        for body in (
            output.replace(b"completion=1", b"completion=2"),
            output.replace(b"body=1", b"body=0"),
            output.replace(b"handoff=1", b"handoff=2"),
            output.replace(b"payloadIdentity=1", b"payloadIdentity=0"),
            output.replace(b"originalTerminated=1", b"originalTerminated=0"),
            output.replace(b"gateFree=1", b"gateFree=0"),
            output.replace(b"gateClosed=1", b"gateClosed=0"),
            output.replace(b"caseDeadlineMet=1", b"caseDeadlineMet=0"),
            output.replace(b"failureCleanup=0", b"failureCleanup=1"),
            output + MODULE.ORIGINAL_MARKER.encode() + b"\n",
            output + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
            output.replace(MODULE.ORIGINAL_MARKER.encode() + b"\n", b"")):
            with self.subTest(body=body[-60:]), self.assertRaises(MODULE.Refused):
                MODULE.packaged_ui_result(body, original[1], original[2])

    def test_count_selection_and_retry_cannot_be_repaired_by_a_marker(self):
        output, summary, tree = result_data()
        for key, value in (("totalTestCount", 0), ("passedTests", True), ("failedTests", 1),
                           ("skippedTests", 1), ("expectedFailures", 1)):
            altered = json.loads(summary); altered[key] = value
            with self.assertRaises(MODULE.Refused):
                MODULE.packaged_ui_result(output, json.dumps(altered).encode(), tree)
        for selected in (tree.replace(b"testPackagedEntryLaunchCancelAndQuit", b"testLaunchCancelAndQuit"),
                         tree.replace(b'"Passed"', b'"Skipped"'), b'{"testNodes":[]}'):
            with self.assertRaises(MODULE.Refused):
                MODULE.packaged_ui_result(output, summary, selected)
        with self.assertRaises(MODULE.Refused):
            MODULE.packaged_ui_result(output.splitlines(keepends=True)[0] + output, summary, tree)
        with self.assertRaises(MODULE.Refused):
            MODULE.packaged_ui_result(output, summary[:-1] + b',"passedTests":1}', tree)

    def test_source_has_one_fixed_request_and_only_original_cleanup_receivers(self):
        source = without_positive_android_source(SWIFT.read_text())
        self.assertEqual(source.count("NSWorkspace.shared.openApplication(at: requestURL"), 1)
        self.assertEqual(source.count("let app = try launchOrdinaryApplication()"), 2)
        self.assertEqual(source.count("original.terminate()"), 1)
        self.assertEqual(source.count("original.forceTerminate()"), 1)
        for forbidden in ("app.launch()", "app.activate()", "app.terminate()", "monitor.launch(",
                          "monitor.activate(", "monitor.terminate(", "processIdentifier", "kill(", "Process()"):
            self.assertNotIn(forbidden, source)
        for required in ("configuration.createsNewApplicationInstance = true",
                         "configuration.allowsRunningApplicationSubstitution = false",
                         "configuration.arguments = []", "private let lock = NSLock()",
                         "entries = min(2, entries + 1)", "bodies = min(2, bodies + 1)",
                         "handoffs = min(2, handoffs + 1)", "late original is cleanup-only",
                         "if ticket == 1", "if original == nil { original = value.first }",
                         "DispatchQueue.main.async { self.handoff() }"):
            self.assertIn(required, source)
        launch = source.split("private func launchOrdinaryApplication()", 1)[1].split("private func completeNormalQuit(", 1)[0]
        for earlier, later in (("outer.state == .notRunning && monitor.state == .notRunning", "entryGateObservation = gate"),
                               ("try gate.probe(busy: false)", "originalLaunch = owner"),
                               ("originalLaunch = owner", "try owner.requestAndAwait()"),
                               ("try owner.requestAndAwait()", "try gate.probe(busy: true)")):
            self.assertLess(launch.index(earlier), launch.index(later))
        self.assertIn("original.bundleURL?.path == Self.payloadURL.path", source)
        self.assertIn('original.bundleIdentifier == "dev.mobile-release-kit.desktop"', source)

        # One shared original request, not one request per launch profile.
        self.assertEqual(source.count("NSWorkspace.shared.openApplication("), 1)
        route = source.split("let requestURL: URL", 1)[1].split("requested = true", 1)[0]
        ordinary, engineering = route.split("case .engineeringMain(let work):", 1)
        self.assertIn("case .ordinary:", ordinary)
        self.assertIn("requestURL = Self.outerURL", ordinary)
        self.assertNotIn("configuration.environment", ordinary)
        self.assertIn('requestURL = work.appendingPathComponent("Mobile Release Kit.app", isDirectory: true)', engineering)
        self.assertIn('"MRK_DESKTOP_DEV_PYTHON": work.appendingPathComponent("runtime/python/bin/python3").path', engineering)
        self.assertIn('"MRK_DESKTOP_DEV_CORE": work.appendingPathComponent("runtime/core.zip").path', engineering)
        launch = source.split("private func launchEngineeringMain(work:", 1)[1].split("private func engineeringDashboard", 1)[0]
        self.assertEqual(source.count("runningApplications"), 2)
        self.assertEqual(launch.count("runningApplications"), 2)
        self.assertIn('NSRunningApplication.runningApplications(withBundleIdentifier: "dev.mobile-release-kit.engineering-ui").isEmpty', launch)
        self.assertIn('!NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.path == url.path })', launch)
        self.assertLess(launch.index("monitor.state == .notRunning"), launch.index("originalLaunch = owner"))
        for forbidden in ("original =", ".terminate(", ".forceTerminate(", "processIdentifier", "adopt"):
            # The fixed refusal/comment may describe adoption; no expression does it.
            if forbidden != "adopt": self.assertNotIn(forbidden, launch)
        self.assertIn('ProcessInfo.processInfo.environment["MRK_ENGINEERING_UI_WORK"] == nil', source)

    def test_first_callback_custody_survives_reordered_main_handoffs(self):
        source = without_positive_android_source(SWIFT.read_text())
        reply = source.split("private final class LaunchReply:", 1)[1].split(
            "@MainActor private final class OrdinaryLaunch", 1)[0]
        body = reply.split("func body(", 1)[1].split("func snapshot()", 1)[0]
        handoff = source.split("private func handoff()", 1)[1].split(
            "private func callbackHealthy(", 1)[0]
        self.assertIn("if ticket == 1 {\n                first = application", body)
        self.assertLess(body.index("first = application"), body.index("bodies = min("))
        self.assertIn("first = application // Retain before ANY fallible validation.\n                error = failed", body)
        healthy = source.split("private func callbackHealthy(", 1)[1].split("func healthy()", 1)[0]
        self.assertIn("!value.error, original != nil", healthy)
        self.assertIn("guard let launchEnd, !workClosed else", handoff)
        self.assertEqual(handoff.count("if original == nil { original = value.first }"), 1)
        self.assertLess(handoff.index("original = value.first"), handoff.index("try callbackHealthy()"))
        self.assertNotIn("if handoffs == 1 { original", source)
        self.assertIn('workClosed = true\n                _ = clock.fail("launch completion refused")', handoff)

        # Deterministic inert schedule oracle bound to the literal custody
        # statements above. This does NOT execute Swift, a callback thread,
        # AppKit, or a native cleanup receiver and is not native UI evidence.
        def fresh_state():
            return dict(entries=0, bodies=0, handoffs=0, first=None, error=False,
                        original=None, failed=False, work_closed=False)
        state = fresh_state()
        def enter():
            state["entries"] = min(2, state["entries"] + 1)
            return state["entries"]
        def complete(ticket, value, error=False):
            if ticket == 1:
                state["first"] = value
                state["error"] = error
            state["bodies"] = min(2, state["bodies"] + 1)
        def handoff_only():
            state["handoffs"] = min(2, state["handoffs"] + 1)
            if state["original"] is None:
                state["original"] = state["first"]
            duplicate = any(state[key] > 1 for key in ("entries", "bodies", "handoffs"))
            bad_first = state["handoffs"] == 1 and (
                state["entries"] != 1 or state["bodies"] != 1 or
                state["error"] or state["original"] is None)
            if state["work_closed"] or duplicate or bad_first:
                state["failed"] = state["work_closed"] = True  # Sticky.

        first, second = object(), object()
        ticket1 = enter()               # First callback pauses before its body.
        ticket2 = enter()
        self.assertEqual((ticket1, ticket2), (1, 2))
        complete(ticket2, second)
        handoff_only()                  # Second callback reaches main first.
        self.assertTrue(state["failed"])
        self.assertIsNone(state["first"])
        self.assertIsNone(state["original"])
        complete(ticket1, first)
        handoff_only()                  # Late ticket1 restores custody, NOT work.
        self.assertIs(state["first"], first)
        self.assertIs(state["original"], first)
        self.assertTrue(state["failed"])
        complete(ticket2, second)
        handoff_only()
        self.assertIs(state["original"], first)
        self.assertIsNot(state["original"], second)
        self.assertTrue(state["failed"])
        self.assertEqual(tuple(state[key] for key in ("entries", "bodies", "handoffs")), (2, 2, 2))
        cleanup_receivers = [state["original"]]  # Record identity only, no call.
        self.assertEqual(cleanup_receivers, [first])
        self.assertTrue(state["work_closed"])

        # First nil may NEVER be repaired by a nonnil second callback. Exercise
        # both normal and reversed main/body arrival; no real receiver is used.
        for reordered in (False, True):
            with self.subTest(first="nil", reordered=reordered):
                state = fresh_state()
                ticket1 = enter()
                if reordered:
                    ticket2 = enter()
                    complete(ticket2, second)
                    handoff_only()
                    self.assertIsNone(state["original"])
                complete(ticket1, None)
                handoff_only()
                self.assertIsNone(state["original"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                if not reordered:
                    ticket2 = enter()
                complete(ticket2, second)
                handoff_only()
                self.assertIsNone(state["first"])
                self.assertIsNone(state["original"])
                self.assertFalse(state["error"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                cleanup_receivers = [] if state["original"] is None else [state["original"]]
                self.assertEqual(cleanup_receivers, [])

        # Error+nonnull first is retained for cleanup ONLY. A later callback
        # without error cannot clear first's error, reopen work or replace it.
        for reordered in (False, True):
            with self.subTest(first="error-and-original", reordered=reordered):
                state = fresh_state()
                ticket1 = enter()
                if reordered:
                    ticket2 = enter()
                    complete(ticket2, second)
                    handoff_only()
                    self.assertIsNone(state["original"])
                complete(ticket1, first, error=True)
                handoff_only()
                self.assertIs(state["original"], first)
                self.assertTrue(state["error"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                if not reordered:
                    ticket2 = enter()
                complete(ticket2, second, error=False)
                handoff_only()
                self.assertIs(state["first"], first)
                self.assertIs(state["original"], first)
                self.assertIsNot(state["original"], second)
                self.assertTrue(state["error"])
                self.assertTrue(state["failed"])
                self.assertTrue(state["work_closed"])
                cleanup_receivers = [state["original"]]  # Identity only, no call.
                self.assertEqual(cleanup_receivers, [first])

        engineering = source.split("private func launchEngineeringMain(work:", 1)[1].split("private func engineeringDashboard", 1)[0]
        self.assertIn("let owner = OrdinaryLaunch(clock: clock, profile: .engineeringMain(work: work))", engineering)
        self.assertLess(engineering.index("originalLaunch = owner"), engineering.index("try owner.requestAndAwait()"))
        self.assertLess(engineering.index("try owner.requestAndAwait()"), engineering.index("try owner.healthy()"))
        self.assertIn("init(clock: CaseClock, profile: LaunchProfile = .ordinary)", source)
        self.assertEqual(source.count("private let reply = LaunchReply()"), 1)
        self.assertNotIn("LaunchReply()", engineering)
        self.assertNotIn("DispatchQueue", engineering)
        self.assertNotIn("GateObservation(", engineering)

    def test_source_packaged_require_site_is_forwarded_and_first_failure_only(self):
        # Current raw diagnostic sites are validated before historical inverses.
        first_source = SWIFT.read_text()
        first_original = without_engineering_first_failure_source(first_source)
        self.assertEqual(hashlib.sha256(first_original.encode()).hexdigest(),
                         '76cf81ab6ebcc4f576528405fc784461837619628b0144db27e1db31a0d15ea8')
        # Missing/duplicated/changed first-failure regions cannot pass a historical pin.
        for previous, current in reversed(ENGINEERING_FIRST_FAILURE_REGIONS):
            for replacement in (previous, current + current, current.replace('engineering', 'foreign', 1)):
                if replacement == current:
                    continue
                bad_first = first_source.replace(current, replacement, 1)
                self.assertNotEqual(bad_first, first_source)
                with self.assertRaises(AssertionError):
                    without_engineering_first_failure_source(bad_first)
        first_clock = first_source.split('private final class CaseClock {', 1)[1].split('private final class', 1)[0]
        first_fail = first_clock.split('func fail(', 1)[1].split('private func now()', 1)[0]
        self.assertEqual(first_fail.count('MRK_MACOS_ENGINEERING_FIRST_FAILURE'), 1)
        self.assertLess(first_fail.index('if firstFailure == nil'), first_fail.index('firstFailure = reason'))
        self.assertLess(first_fail.index('firstFailure = reason'), first_fail.index('print('))
        self.assertIn('engineeringDiagnostic && line >= 1 && line <= 65535', first_fail)
        self.assertNotIn('systemUptime', first_fail)
        self.assertNotIn('\\(reason)', first_fail)
        self.assertEqual(first_source.count('engineeringDiagnostic: true'), 1)
        self.assertIn('caseClock?.fail(reason, line: line)', first_source)
        first_case = first_source.split('func testEngineeringMainCatalogueAndQuit() throws {', 1)[1].split(
            '// End engineering main fixture', 1)[0]
        phases = ('launch', 'catalogue', 'guideSelection', 'artifactStatus', 'artifactSample', 'artifactValue',
                  'quitCancel', 'postCancel', 'quitConfirm', 'termination', 'terminal')
        phase_sites = ['caseClock?.recordEngineeringPhase(.' + phase + ')' for phase in phases]
        self.assertEqual(first_source.count('caseClock?.recordEngineeringPhase('), len(phases))
        self.assertEqual([first_case.index(site) for site in phase_sites], sorted(first_case.index(site) for site in phase_sites))
        raw_status = first_original
        # Current scope cannot be a global duplicate refusal paragraph. These
        # exact inverses preserve all earlier ordinary/native-owner source pins.
        self.assertEqual(raw_status.count(ARTIFACT_STATUS_GROUP_CURRENT), 1)
        self.assertEqual(hashlib.sha256(without_artifact_status_group_source(raw_status).encode()).hexdigest(),
                         'bfb649ba2c5c7e8309c09cd97d1dc549aead1d3df3fe8eed7d62423ab2db5405')
        for changed_group in (
                '',
                ARTIFACT_STATUS_GROUP_CURRENT * 2,
                ARTIFACT_STATUS_GROUP_CURRENT.replace('Original artifact inspection status', 'Other status'),
                ARTIFACT_STATUS_GROUP_CURRENT.replace('artifactStatusGroup.staticTexts', 'renderer.staticTexts'),
                ARTIFACT_STATUS_GROUP_CURRENT.replace('value IN %@', 'title IN %@')):
            bad_status = raw_status.replace(ARTIFACT_STATUS_GROUP_CURRENT, changed_group, 1)
            self.assertNotEqual(bad_status, raw_status)
            with self.assertRaises(AssertionError):
                without_artifact_status_group_source(bad_status)
        raw_wait = without_artifact_wait_diagnostic_source(without_artifact_status_group_source(raw_status))
        for previous, current in ENGINEERING_WAIT_STATUS_REGIONS:
            self.assertEqual(raw_wait.count(current), 1)
        for previous, current in ENGINEERING_WAIT_STATUS_REGIONS:
            for bad in (raw_wait.replace(current, previous, 1),
                        raw_wait.replace(current, current + current, 1)):
                with self.assertRaises(AssertionError):
                    without_engineering_wait_status_source(bad)
        self.assertEqual(MODULE.LOADER_SHA,
                         hashlib.sha256((ROOT / "desktop/tools/macos_aqua_qualification.py").read_bytes()).hexdigest())
        source = without_positive_android_source(SWIFT.read_text())
        self.assertEqual(source.count("line: UInt = #line"), 3)
        self.assertIn("private enum RequireCheck: String { case condition, singleton, actionable }", source)
        self.assertEqual(source.count("packagedRequireDiagnosticActive = true"), 1)
        self.assertEqual(source.count("packagedRequireDiagnosticActive = false"), 2)  # Initial + scoped defer.
        self.assertEqual(source.count("packagedRequireDiagnosticEmitted = false"), 1)
        self.assertEqual(source.count("packagedRequireDiagnosticEmitted = true"), 1)
        selected = source.split("func testPackagedEntryLaunchCancelAndQuit() throws {", 1)[1].split(
            "\n    @MainActor private func launchCancelAndQuit", 1)[0]
        self.assertIn("try launchCancelAndQuit(profile: .packagedEntry)", selected)
        self.assertNotIn("packagedRequireDiagnosticActive", selected)
        shared = source.split("@MainActor private func launchCancelAndQuit(profile: SourceProfile) throws {", 1)[1]
        order = ("packagedRequireDiagnosticActive = true", "defer { packagedRequireDiagnosticActive = false }",
                 "try beginCase(seconds: 60)", "try admittedJourneyApplication(profile: profile)")
        self.assertEqual([shared.index(item) for item in order], sorted(shared.index(item) for item in order))
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .sameBuild)"), 1)
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .packagedEntry)"), 1)
        self.assertEqual(MODULE.NORMAL_SELECTIONS["test.xcresult"][0], ("testLaunchCancelAndQuit",))
        self.assertFalse(any("testPackagedEntryLaunchCancelAndQuit" in methods
                             for methods, _, _ in MODULE.NORMAL_SELECTIONS.values()))
        require = source.split("private func require(", 1)[1].split("private func unique(", 1)[0]
        false_guard = require.split("guard value else {", 1)[1].split("\n        try checkOriginalOwners()", 1)[0]
        ordered = ("let originalFailureAbsent = caseClock?.firstFailure == nil",
                   "let refusal = caseClock?.fail(reason) ?? Refusal.condition(reason)",
                   "if packagedRequireDiagnosticActive && originalFailureAbsent && !packagedRequireDiagnosticEmitted",
                   "&& line >= 1 && line <= 65535", "packagedRequireDiagnosticEmitted = true",
                   'print("MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=\\(line);check=\\(check.rawValue)")',
                   "if let (sample, waiter) = dashboard, (1...4).contains(sample.ordinal), waiter != .completed",
                   "MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;", "throw refusal")
        positions = [false_guard.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(source.count("MRK_MACOS_PACKAGED_REQUIRE_FAILURE="), 1)
        self.assertEqual(require.count("caseClock?.fail(reason) ?? Refusal.condition(reason)"), 1)
        for forbidden in ("XCTFail", "recordIssue", "waitFor", "remaining(", "systemUptime", "owner.", "checkOriginalOwners(",
                          "catch", "try?", "isEnabled", "isHittable", "renderer.", "firstMatch", "XCUIElement"):
            self.assertNotIn(forbidden, false_guard)
        self.assertEqual(require.count("try checkOriginalOwners()"), 1)
        # A false guard still throws; true values retain BOTH original gates.
        self.assertIn("throw refusal\n        }\n        try checkOriginalOwners()\n"
                      "        if let clock = caseClock { _ = try clock.remaining(1, before: journeyDeadline) }", require)
        unique = source.split("private func unique(", 1)[1].split("private func click(", 1)[0]
        click = source.split("private func click(", 1)[1].split("private func dashboard(", 1)[0]
        self.assertIn("try require(query.count == 1, reason, line: line, check: .singleton)", unique)
        self.assertIn("return query.element(boundBy: 0)", unique)
        self.assertIn("let element = try unique(query, reason, line: line)", click)
        self.assertIn("try require(element.isEnabled && element.isHittable, reason, line: line, check: .actionable)", click)
        self.assertLess(click.index("try unique(query, reason, line: line)"), click.index("try require("))
        self.assertLess(click.index("try require("), click.index("element.click()"))
        self.assertEqual(source.count("MRK_MACOS_PACKAGED_DASHBOARD_FAILURE="), 1)
        self.assertIn("dashboard: (DashboardSnapshot, DashboardWaiter)? = nil", require)
        self.assertIn(";sample=pre-wait;nonAtomic=1", false_guard)
        snapshot_type = source.split("private struct DashboardSnapshot {", 1)[1].split("\n    }", 1)[0]
        self.assertEqual(snapshot_type.count("let "), 4)
        self.assertNotIn("var ", snapshot_type)
        dashboard = source.split("private func dashboard(", 1)[1].split("private func quitSheet(", 1)[0]
        self.assertIn("diagnosticOrdinal: UInt8? = nil", dashboard)
        sample = dashboard.split("let snapshot: DashboardSnapshot?", 1)[1].split("        let ready =", 1)[0]
        order = ("if packagedRequireDiagnosticActive, let ordinal = diagnosticOrdinal, (1...4).contains(ordinal)",
                 "try checkOriginalOwners()", "_ = try remaining(5)",
                 "let enabled = open.isEnabled", "let hittable = open.isHittable",
                 "if !enabled || !hittable {", "for (titles, reason) in reasons")
        self.assertEqual([sample.index(item) for item in order], sorted(sample.index(item) for item in order))
        # Entry, each group, and exit use the original owner/case end; no new wait or lease.
        self.assertEqual(sample.count("try checkOriginalOwners()"), 3)
        self.assertEqual(sample.count("try remaining(5)"), 3)
        self.assertEqual(sample.count("open.isEnabled"), 1)
        self.assertEqual(sample.count("open.isHittable"), 1)
        self.assertNotIn(".firstMatch", sample)
        self.assertEqual(sample.count("let reasons: [([String], DashboardReason)] = ["), 1)
        self.assertEqual(sample.count("                ([\n"), 15)
        self.assertEqual(sample.count("for (titles, reason) in reasons"), 1)
        self.assertEqual(sample.count("renderer.staticTexts."), 1)
        self.assertEqual(sample.count(".count"), 1)
        self.assertEqual(source.count("private enum DashboardReason: String {"), 1)
        self.assertIn("    private enum DashboardReason: String {\n        case loading, notLoaded = \"not-loaded\", bridgeUnavailable = \"bridge-unavailable\"\n        case selectionUnavailable = \"selection-unavailable\", selectionInProgress = \"selection-in-progress\"\n        case shuttingDown = \"shutting-down\"\n        case ownerOfflinePreflight = \"owner-offline-preflight\", ownerAndroidBuild = \"owner-android-build\"\n        case ownerIOSArchive = \"owner-ios-archive\", ownerProjectRecovery = \"owner-project-recovery\"\n        case ownerGitHubPreflight = \"owner-github-preflight\", ownerGitHubRelease = \"owner-github-release\"\n        case ownerProjectPath = \"owner-project-path\", ownerSavedVersionEdit = \"owner-saved-version-edit\"\n        case ownerMetadataImages = \"owner-metadata-images\"\n        case otherOrUnobserved = \"other-or-unobserved\", ambiguous\n    }\n", source)
        groups = (
            ("loading", "loading", (
                "Application capabilities are being loaded.",
            )),
            ("notLoaded", "not-loaded", (
                "Application capabilities have not been loaded.",
            )),
            ("bridgeUnavailable", "bridge-unavailable", (
                "The native desktop bridge is unavailable.",
            )),
            ("selectionUnavailable", "selection-unavailable", (
                "Project selection is not available in the current desktop runtime profile.",
            )),
            ("selectionInProgress", "selection-in-progress", (
                "Finish the original project selection first.",
            )),
            ("shuttingDown", "shutting-down", (
                "The application is shutting down.",
            )),
            ("ownerOfflinePreflight", "owner-offline-preflight", (
                "Offline-check ownership or finality is unverified. Keep the original status; conflicting work is disabled.",
                "Saved offline checks hold the original intent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original offline-check status is unverified. Check retained status before conflicting work.",
            )),
            ("ownerAndroidBuild", "owner-android-build", (
                "Android-build ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.",
                "The original Android service action is active or unconfirmed. Keep its Status and Cancel; do not repeat registration.",
                "The original Android source inspection or protected registration is active or unconfirmed. Keep its Status and Cancel; do not repeat copy.",
                "An original source review is retained. Register that exact review or explicitly discard it before conflicting work.",
                "The original Android tool picker or folder check is active or unconfirmed. Keep tool-selection Status and Cancel before conflicting work.",
                "The original Android tool catalog is still reading, stopping or unconfirmed. Keep catalog Status and Cancel before conflicting work.",
                "The Android build holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original Android-build status is unverified. Check retained Status before conflicting work.",
            )),
            ("ownerIOSArchive", "owner-ios-archive", (
                "iOS-archive ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.",
                "The iOS archive holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original iOS-archive status is unverified. Check retained Status before conflicting work.",
            )),
            ("ownerProjectRecovery", "owner-project-recovery", (
                "Project-recovery ownership or finality is unverified. Keep the original status; conflicting work is disabled.",
                "Project build-input recovery holds the original intent or execution slot. Cancel or settle that original operation before conflicting work.",
                "The original project-recovery status is unverified. Check retained status before conflicting work.",
            )),
            ("ownerGitHubPreflight", "owner-github-preflight", (
                "The original GitHub preflight action is running or unverified. Read its local Status before starting another operation.",
            )),
            ("ownerGitHubRelease", "owner-github-release", (
                "The original protected release workflow action is running or unverified. Read its local Status before starting another operation.",
            )),
            ("ownerProjectPath", "owner-project-path", (
                "The original project-path outcome or cleanup is unverified. Conflicting native operations remain blocked.",
                "Finish the original project-path selection. Changing drafts or projects does not cancel it.",
            )),
            ("ownerSavedVersionEdit", "owner-saved-version-edit", (
                "Saved-version edit ownership is unverified. Keep its original operation and do not retry.",
                "A saved-version edit is still owned. Close or finish that original session before another operation.",
                "This project needs separately authorized saved-version recovery. No other edit can clear that journal.",
            )),
            ("ownerMetadataImages", "owner-metadata-images", (
                "Original image ownership or cleanup is unverified. Observe that original operation; do not start a competing one.",
                "An original image selection or local-copy review is retained. Finish or stop that operation first.",
                "This project needs a separate image recovery inspection. Another edit cannot bypass its journal.",
            )),
        )
        self.assertEqual(len(groups), 15)
        literals = [title for _, _, titles in groups for title in titles]
        self.assertEqual(len(literals), 33)
        self.assertEqual(len(set(literals)), 33)
        self.assertEqual(len({label for _, label, _ in groups}), 15)
        expected_table = "            let reasons: [([String], DashboardReason)] = [\n"
        for name, _, titles in groups:
            expected_table += "                ([\n"
            expected_table += "".join("                    " + json.dumps(title) + ",\n" for title in titles)
            expected_table += "                ], ." + name + "),\n"
        expected_table += "            ]\n"
        self.assertIn(expected_table, sample)
        expected_scan = "            var selected: DashboardReason?\n            var ambiguous = false\n            // Already-ready samples need no refusal queries; the real wait below is still required.\n            if !enabled || !hittable {\n                for (titles, reason) in reasons {\n                    try checkOriginalOwners()\n                    _ = try remaining(5)\n                    let matches = renderer.staticTexts.matching(NSPredicate(\n                        format: \"identifier IN %@ OR label IN %@ OR title IN %@\",\n                        argumentArray: [titles, titles, titles])).count\n                    if matches > 1 || (matches == 1 && selected != nil) {\n                        ambiguous = true\n                        break // No further diagnostic observation can repair ambiguity.\n                    }\n                    if matches == 1 { selected = reason }\n                }\n            }\n            try checkOriginalOwners()\n            _ = try remaining(5)\n"
        self.assertIn(expected_scan, sample)
        # Inert count DATA only, paired with the exact Swift reducer above.
        # This does not execute XCTest queries or prove native AX exposure.
        def reduce_counts(counts, *, enabled=False, hittable=False):
            self.assertEqual(len(counts), 15)
            selected, ambiguous, observations = None, False, 0
            if not enabled or not hittable:
                for index, matches in enumerate(counts):
                    observations += 1
                    if matches > 1 or (matches == 1 and selected is not None):
                        ambiguous = True
                        break
                    if matches == 1:
                        selected = groups[index][1]
            return ("ambiguous" if ambiguous else selected or "other-or-unobserved"), observations

        # Both mixed samples still classify. Ready samples consume no queries,
        # even when the unused count data contains matching or ambiguous reasons.
        for enabled, hittable in ((False, False), (False, True), (True, False), (True, True)):
            for counts, not_ready in (
                    ([0] * 15, ("other-or-unobserved", 15)),
                    ([1] + [0] * 14, ("loading", 15)),
                    ([2] + [0] * 14, ("ambiguous", 1)),
                    ([1, 1] + [0] * 13, ("ambiguous", 2))):
                with self.subTest(enabled=enabled, hittable=hittable, counts=counts):
                    self.assertEqual(
                        reduce_counts(counts, enabled=enabled, hittable=hittable),
                        ("other-or-unobserved", 0) if enabled and hittable else not_ready)

        self.assertEqual(reduce_counts([0] * 15), ("other-or-unobserved", 15))
        for index, (_, label, _) in enumerate(groups):
            counts = [0] * 15
            counts[index] = 1
            self.assertEqual(reduce_counts(counts), (label, 15))
            for duplicate_count in (2, 5):
                counts[index] = duplicate_count
                self.assertEqual(reduce_counts(counts), ("ambiguous", index + 1))
            for second in range(index + 1, 15):
                conflicting = [0] * 15
                conflicting[index] = conflicting[second] = 1
                self.assertEqual(reduce_counts(conflicting), ("ambiguous", second + 1))
        self.assertIn("reason: ambiguous ? .ambiguous : selected ?? .otherOrUnobserved)", sample)
        for forbidden in ("print(", ".label", ".value", "debugDescription", "screenshot",
                          "while ", "sleep(", "waitFor", "XCTWaiter", "catch", "try?", "Date(", "systemUptime"):
            self.assertNotIn(forbidden, sample)
        self.assertEqual(dashboard.count('NSPredicate(format: "enabled == true AND hittable == true"), object: open'), 1)
        self.assertEqual(dashboard.count("XCTWaiter.wait(for: [ready], timeout: try remaining(5))"), 1)
        self.assertIn("let returned = XCTWaiter.wait(for: [ready], timeout: try remaining(5))\n"
                      "        let readiness = snapshot.map { ($0, DashboardWaiter(returned)) }\n"
                      '        try require(returned == .completed, "ordinary project control is not usable", dashboard: readiness)', dashboard)
        self.assertEqual(source.count("diagnosticOrdinal:"), 5)  # Default plus only four shared-case callers.
        case_body = shared.split("    // Finite synthetic files only.", 1)[0]
        for ordinal in range(1, 5):
            self.assertEqual(case_body.count(f"try dashboard(renderer, diagnosticOrdinal: {ordinal})"), 1)
        clock = source.split("func fail(_ reason: String) -> Refusal {", 1)[1].split("private func now()", 1)[0]
        self.assertIn("if firstFailure == nil { firstFailure = reason }\n            return .condition(firstFailure!)", clock)
        # The engineering fixture owns a distinct first-site marker, not a new
        # launch/ordinary selection or a second observation after a failure.
        self.assertEqual(source.count("engineeringRequireDiagnosticActive = true"), 1)
        self.assertEqual(source.count("engineeringRequireDiagnosticActive = false"), 2)
        self.assertEqual(source.count("engineeringRequireDiagnosticEmitted = false"), 1)
        self.assertEqual(source.count("engineeringRequireDiagnosticEmitted = true"), 1)
        self.assertEqual(source.count("MRK_MACOS_ENGINEERING_REQUIRE_FAILURE="), 1)
        engineering = source.split("func testEngineeringMainCatalogueAndQuit() throws {", 1)[1].split(
            "    // End engineering main fixture", 1)[0]
        activation = ("engineeringRequireDiagnosticActive = true",
                      "defer { engineeringRequireDiagnosticActive = false }", "try beginCase(seconds: 60)")
        self.assertEqual([engineering.index(item) for item in activation],
                         sorted(engineering.index(item) for item in activation))
        engineering_guard = false_guard.split("if engineeringRequireDiagnosticActive", 1)[1].split("throw refusal", 1)[0]
        ordering = ("originalFailureAbsent && !engineeringRequireDiagnosticEmitted", "line >= 1 && line <= 65535",
                    "engineeringRequireDiagnosticEmitted = true",
                    'print("MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=\\(line);check=\\(check.rawValue)")')
        self.assertEqual([engineering_guard.index(item) for item in ordering],
                         sorted(engineering_guard.index(item) for item in ordering))
        self.assertLess(false_guard.index("let refusal = caseClock?.fail(reason)"),
                        false_guard.index("if engineeringRequireDiagnosticActive"))
        self.assertNotIn("reason", engineering_guard)
        self.assertNotIn("engineeringRequireDiagnosticActive", shared)
        self.assertNotIn("testEngineeringMainCatalogueAndQuit",
                         tuple(method for methods, _, _ in MODULE.NORMAL_SELECTIONS.values() for method in methods))

    def test_source_uses_nonrenewable_case_clock_and_all_terminal_gates(self):
        source = without_positive_android_source(SWIFT.read_text())
        custody = source.split("    private final class GateObservation {", 1)[0]
        self.assertEqual(source.count("try beginCase(seconds: 60)"), 2)
        self.assertEqual(source.count("try beginCase(seconds: 300)"), 8)
        self.assertEqual(source.count("try completeNormalQuit(app)"), 9)
        self.assertEqual(source.count("try completeNormalQuit(restartedApp)"), 1)
        self.assertEqual(source.count("try acceptFinalScenario()"), 8)
        self.assertEqual(source.count("try acceptPersistenceRestart()"), 1)
        self.assertEqual(source.count("normalQuitObserved = true"), 2)
        for required in ("let deadline: TimeInterval", "value.isFinite, value >= last",
                         "if firstFailure == nil", "caseClock == nil && journeyDeadline == nil",
                         "journeyDeadline = clock.deadline", "min(deadline, start + maximum)",
                         "min(deadline, end ?? deadline) - (try now())", "return min(maximum, left)",
                         "try clock.end(within: 15)", "clock.progress(until:",
                         "if cleanupEnd == nil", "clock.end(within: 5, cleanup: true)",
                         "try clock.remaining(10, before: end)", "SAME ten seconds"):
            self.assertTrue(required in source, "missing case-clock gate: " + required)
        for forbidden in ("journeyDeadline = ProcessInfo.processInfo.systemUptime +",
                          "else { return requested }", "timeout: 5)", "timeout: 10)"):
            section = custody if forbidden == "timeout: 10)" else source
            self.assertFalse(forbidden in section, "unbounded case-clock token: " + forbidden)
        # Literal ten seconds is a maximum only on the clamped press helper route.
        for line in source.splitlines():
            if "timeout: 10)" in line:
                self.assertTrue(line.lstrip().startswith("try press("), "raw ten-second wait outside custody")
        for name, route in (
            ("press", ("try waitElement(", "timeout: timeout")),
            ("waitElement", ("XCTWaiter.wait(for: [expected], timeout: try remaining(timeout))",)),
            ("remaining", ("return try clock.remaining(requested, before: deadline)",)),
        ):
            helper = source.split("private func " + name + "(", 1)[1].split("\n    @MainActor ", 1)[0]
            for required in route:
                self.assertTrue(required in helper, "missing original-clock clamp in " + name)
        terminal = source.split("private func completeNormalQuit(", 1)[1].split("private func acceptFinalScenario()", 1)[0]
        self.assertLess(terminal.index("owner.observeNormalTermination"), terminal.index("gate.probe(busy: false)"))
        self.assertLess(terminal.index("gate.closeOriginal()"), terminal.index("normalQuitObserved = true"))
        teardown = source.split("override func tearDown() async throws", 1)[1]
        for required in ("owner.tearDown(normalQuit: normalQuitObserved)", "entryGateObservation?.closeOriginal()",
                         "fixture.closeOriginals()", "super.tearDown()", "if cleanupFailure == nil"):
            self.assertTrue(required in teardown, "missing terminal cleanup gate: " + required)

        engineering = source.split("func testEngineeringMainCatalogueAndQuit() throws {", 1)[1].split(
            "// End engineering main fixture;", 1)[0]
        self.assertEqual(engineering.count("try beginCase(seconds: 60)"), 1)
        self.assertEqual(engineering.count("try clock.end(within: 10)"), 1)
        self.assertIn("timeout: try clock.remaining(10, before: end)", engineering)
        self.assertIn("try owner.observeNormalTermination(until: end)", engineering)
        ordered = ("try beginCase(seconds: 60)", "let work = try engineeringWork()", "let app = try launchEngineeringMain(work: work)",
                   "try owner.observeNormalTermination(until: end)", "try owner.acceptTerminal()", "normalQuitObserved = true",
                   'print("MRK_MACOS_ENGINEERING_MAIN_UI=')
        positions = [engineering.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        for forbidden in ("gate.probe(", "GateObservation(", "original.terminate()", "forceTerminate", "try?", "catch", "beginCase(seconds: 300)"):
            self.assertNotIn(forbidden, engineering)

        recovery = source.split("func testSyntheticProjectSavedVersionRecovery() throws {", 1)[1].split(
            "    @MainActor func testSyntheticProjectManagedWorkflowRefusal()", 1)[0]
        for token in ("try beginCase(seconds: 300)", "try completeNormalQuit(app)", "try acceptFinalScenario()"):
            self.assertEqual(recovery.count(token), 1)
        self.assertLess(recovery.index("try completeNormalQuit(app)"), recovery.index("try fixture.closeOriginals()"))
        self.assertLess(recovery.index("try fixture.closeOriginals()"), recovery.index("try acceptFinalScenario()"))

    def test_native_panels_display_fixed_purpose_without_relaxing_sheet_identity(self):
        native = (ROOT / "desktop/native/macos-installed-native/src/native.m").read_text()
        start = native.split("static int mrk_panel_start_inner(", 1)[1]
        title = "[panel setTitle:title];"
        message = "[panel setMessage:title];"
        self.assertEqual(native.count(message), 1)
        self.assertEqual(start.count(title), 1)
        self.assertIn('NSString *title = kind == 1 ? @"Choose a mobile project folder"', start)
        self.assertLess(start.index(title), start.index(message))
        self.assertLess(start.index(message), start.index("[panel setCanChooseFiles:"))
        self.assertLess(start.index(message), start.index("beginSheetModalForWindow:s->parent"))
        # A visible purpose is not permission to accept an arbitrary native sheet.
        sheet = without_positive_android_source(SWIFT.read_text()).split("private func nativeSheet(", 1)[1].split(
            "private func goToFolder(", 1)[0]
        self.assertIn("let sheet = try waitElement(window.sheets, in: window)", sheet)
        self.assertIn("if sheet.label != title && sheet.staticTexts.matching(identifier: title).count != 1 {", sheet)
        self.assertIn('throw Refusal.condition("unexpected original native sheet title in " + journeyStage)', sheet)

    def test_reuse_profile_cannot_relax_the_existing_same_build_cases(self):
        source = without_positive_android_source(SWIFT.read_text())
        self.assertIn('#if !os(macOS) || !(arch(arm64) || arch(x86_64))\n#error(', source)
        compiled = ('        #if arch(arm64)\n'
                    '        let hostedJob = "github-hosted-macos26-arm64"\n'
                    '        #elseif arch(x86_64)\n'
                    '        let hostedJob = "github-hosted-macos26-x86_64"\n'
                    '        #endif\n')
        admission = source.split('private func admitHostedAccount(', 1)[1].split('let nonroot = getuid() != 0', 1)[0]
        self.assertIn(compiled, admission)
        self.assertIn('try require(context["MRK_NORMAL_UI_HOSTED_JOB"] == hostedJob,', admission)
        self.assertEqual(source.count('let hostedJob = '), 2)
        self.assertEqual(source.count('#if arch(arm64)'), 1)
        self.assertEqual(source.count('#elseif arch(x86_64)'), 1)
        project = (ROOT / MODULE.PROJECT / 'project.pbxproj').read_text()
        self.assertEqual(project.count('ARCHS = "$(ARCHS_STANDARD)";'), 1)
        self.assertEqual(project.count('ONLY_ACTIVE_ARCH = YES;'), 1)
        runner = (ROOT / 'desktop/tools/macos_normal_ui_runner.py').read_text()
        self.assertIn('(["ARCHS=x86_64"] if target == INTEL_TARGET else [])', runner)
        self.assertIn('"ARCHS=x86_64", "COMPILER_INDEX_STORE_ENABLE=NO", "build-for-testing"]', runner)
        self.assertEqual(runner.count('ARCHS='), 2)
        self.assertEqual(source.count("try launchCancelAndQuit(profile: .packagedEntry)"), 1)
        self.assertIn("try launchCancelAndQuit(profile: .sameBuild)", source)
        self.assertIn("private func admittedJourneyApplication(profile: SourceProfile = .sameBuild)", source)
        profile = source.split("case .sameBuild:", 1)[1].split("case .packagedEntry:", 1)[0]
        self.assertIn("applicationSource == harnessSource", profile)
        basic = source.split("private func launchCancelAndQuit(profile:", 1)[1].split("private struct FixtureSpec", 1)[0]
        for required in ("try beginCase(seconds: 60)", "try admittedJourneyApplication(profile: profile)",
                         'title: "Choose a mobile project folder"', '"normal Quit Cancel is unavailable"',
                         '"post-Cancel navigation is unavailable"', '"normal affirmative Quit is unavailable"'):
            self.assertIn(required, basic)
        self.assertLess(basic.index("try beginCase(seconds: 60)"), basic.index("try admittedJourneyApplication"))


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "pread"), "POSIX inert original-file DATA")
class GeneratedProductOriginalTests(unittest.TestCase):
    def fixture(self, root):
        derived = Path(root) / "DerivedData"
        products = derived / "Build/Products"
        bodies = {MODULE.RUNNER_EXECUTABLE: b"INERT RUNNER DATA; NEVER EXECUTED\n",
            MODULE.TEST_EXECUTABLE: b"INERT TEST DATA; NEVER EXECUTED\n",
            MODULE.RUNNER_INFO: plistlib.dumps({"CFBundleIdentifier": "dev.mobile-release-kit.normal-ui-tests.xctrunner",
                                               "CFBundleExecutable": "MRKNormalAppUITests-Runner"}),
            MODULE.TEST_INFO: plistlib.dumps({"CFBundleIdentifier": "dev.mobile-release-kit.normal-ui-tests",
                                             "CFBundleExecutable": "MRKNormalAppUITests"}),
            "MRKNormalAppUI_macosx26.0-arm64.xctestrun": manifest()}
        for name, body in bodies.items():
            path = products / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(body)
            path.chmod(0o700 if name in (MODULE.RUNNER_EXECUTABLE, MODULE.TEST_EXECUTABLE) else 0o600)
        return derived, products

    def test_retained_product_originals_close_and_mutations_fail(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
            derived, products = self.fixture(root)
            with MODULE.RunnerProducts(derived) as originals:
                self.assertEqual(set(originals.held), originals.keep)
                originals.check()
                (products / MODULE.RUNNER_EXECUTABLE).write_bytes(b"CHANGED INERT DATA\n")
                with self.assertRaisesRegex(MODULE.Refused, "pre-post"):
                    originals.check()
            self.assertEqual(originals.held, {})
            self.assertIsNone(originals.fd)
            self.assertTrue(originals.closed)

    def test_sandbox_refusal_never_reaches_the_test_invocation(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
            derived, _ = self.fixture(root)
            calls = []
            def call(role, argv, timeout):
                calls.append(role)
                body = plistlib.dumps({"com.apple.security.app-sandbox": True}) if role.endswith("entitlements") else b""
                return subprocess.CompletedProcess(argv, 0, body, b"")
            with self.assertRaisesRegex(MODULE.Refused, "sandboxed-or-unknown"):
                MODULE.run_admitted_test(call, derived, Path(root) / "test.xcresult",
                                         (MODULE.PACKAGED_METHOD,), 60, 180)
            self.assertEqual(calls, ["verify-generated-runner", "generated-runner-entitlements"])

    def test_external_or_cyclic_build_product_links_refuse_before_native_commands(self):
        for target in ("/tmp", "../../outside", "link"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
                derived, products = self.fixture(root)
                os.symlink(target, products / "Debug/link")
                with self.assertRaises(MODULE.Refused):
                    with MODULE.RunnerProducts(derived):
                        self.fail("bad product link was admitted")

    def test_unknown_close_is_consuming_and_other_originals_still_close(self):
        with tempfile.TemporaryDirectory(prefix="mrk-ui-inert-products-") as root:
            derived, _ = self.fixture(root)
            originals = MODULE.RunnerProducts(derived).__enter__()
            selected = next(iter(originals.held.values()))
            expected = set(originals.held.values()) | {originals.fd}
            actual_close = os.close
            closed = []
            def close(fd):
                closed.append(fd)
                actual_close(fd)
                if fd == selected:
                    raise OSError("synthetic unknown close, never retried")
            with patch.object(MODULE.os, "close", close):
                with self.assertRaises(OSError):
                    originals.close()
                originals.close()
            self.assertEqual(set(closed), expected)
            self.assertEqual(len(closed), len(expected))
            self.assertEqual(originals.held, {})
            self.assertIsNone(originals.fd)


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "pread"), "POSIX inert normal-phase DATA")
class NormalPhaseDataTests(unittest.TestCase):
    def test_android_private_input_schema_current_run_and_public_projection(self):
        # Inert closed DATA; no key generation, source registration or UI call.
        import copy
        source, run, attempt = 'a' * 40, '42', '1'
        normal = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui')
        root = normal / 'android-inputs'
        facts = ['0'] * 10
        commands = [dict(role=role, returncode=0, timeoutSeconds=30, roleCapSeconds=30,
            outputLimitBytes=2097152, argvSha256='b'*64, stdoutBytes=0, stdoutSha256=hashlib.sha256(b'').hexdigest(),
            stderrBytes=0, stderrSha256=hashlib.sha256(b'').hexdigest())
            for role in ('android-ui-disposable-jks', 'android-ui-public-certificate')]
        value = dict(schemaVersion=1, scope='one-owned-android-ui-inputs', sourceCommit=source,
            target=MODULE.ARM_TARGET, runId=run, runAttempt=attempt, workflow=MODULE.ANDROID_WORKFLOW,
            ref=MODULE.ANDROID_REF, root=str(root), rootFacts=facts, credentialDirectoryFacts=facts,
            sourceCatalogueSha256=MODULE.ANDROID_CATALOGUE, sourceRosterSha256='c'*64,
            publicCertificateSha256='d'*64,
            roots={k: dict(relative=v, facts=facts) for k,v in MODULE.ANDROID_ROOTS.items()},
            files={k: dict(relative='credentials/'+k, facts=facts, sha256='e'*64) for k in MODULE.ANDROID_PRIVATE_FILES},
            keyCommands=commands, parentReturncodeRequired=0,
            phaseClock=dict(startNs='1', deadlineNs=str(1+1200*10**9), beforePublicationNs='2', postCloseDeadlineRequired=True))
        def admit(item):
            return MODULE.android_input_document(MODULE.encoded(item)+b'\n', source=source, run=run, attempt=attempt, root=root)
        self.assertEqual(admit(value), value)
        for key, replacement in [('runId','41'),('runAttempt','2'),('sourceCommit','b'*40),('target',MODULE.INTEL_TARGET),
            ('root',str(root/'elsewhere')),('schemaVersion',True),('parentReturncodeRequired',False),
            ('sourceCatalogueSha256','0'*64),('unknown','private message')]:
            bad=copy.deepcopy(value);bad[key]=replacement
            with self.subTest(key=key),self.assertRaises(MODULE.Refused): admit(bad)
        for mutation in ('command-bool','command-extra','command-order','clock','path','facts','digest'):
            bad=copy.deepcopy(value)
            if mutation=='command-bool': bad['keyCommands'][0]['returncode']=False
            elif mutation=='command-extra': bad['keyCommands'][0]['stderr']='private'
            elif mutation=='command-order': bad['keyCommands'].reverse()
            elif mutation=='clock': bad['phaseClock']['deadlineNs']=str(1200*10**9)
            elif mutation=='path': bad['files']['upload.jks']['relative']='../upload.jks'
            elif mutation=='facts': bad['rootFacts']=[0]*10
            elif mutation=='digest': bad['publicCertificateSha256']='F'*64
            with self.subTest(mutation=mutation),self.assertRaises(MODULE.Refused): admit(bad)
        raw=MODULE.encoded(value)+b'\n'
        for bad in (raw[:-1], raw+b' ', b'{"schemaVersion":1,'+raw[1:], b'x'*16385):
            with self.assertRaises((MODULE.Refused,ValueError)):
                MODULE.android_input_document(bad,source=source,run=run,attempt=attempt,root=root)
        scalars=dict(alias='mrk-disposable-android-ui',storePassword='1'*48,keyPassword='2'*48)
        self.assertEqual(MODULE.android_input_scalars(MODULE.encoded(scalars)+b'\n'),scalars)
        for key,badvalue in [('alias','other'),('storePassword','1'*49),('keyPassword',None)]:
            bad=dict(scalars);bad[key]=badvalue
            with self.assertRaises(MODULE.Refused): MODULE.android_input_scalars(MODULE.encoded(bad)+b'\n')
        public=dict(schemaVersion=1,scope=MODULE.ANDROID_FACTS_SCOPE,sourceCommit=source,target=MODULE.ARM_TARGET,
            runId=run,runAttempt=attempt,sourceRegistrationObserved=False,nativeSigningVerified=True,
            privateOriginalsClosed=True,memorySessionDiscarded=True,outputPostMatched=True,normalQuitObserved=True,
            releaseQualified=False,parentReturncodeRequired=0,operationId='3'*32,ownerGeneration='4'*32,
            publicCertificateSha256='d'*64,artifactSha256='5'*64,artifactBytes=3,outputEntries=20,
            outputNameBytes=1000,outputLogicalBytes=12,moduleLogicalBytes=9,outputCensusSha256='6'*64)
        self.assertEqual(MODULE.android_signed_facts(public,source=source,run=run,attempt=attempt),public)
        for field, invalid in [('source','private/path'),('source',True),('run','0'),('run','secret'),('attempt','01'),('attempt',1)]:
            context=dict(source=source,run=run,attempt=attempt);context[field]=invalid
            bad=dict(public);bad[{'source':'sourceCommit','run':'runId','attempt':'runAttempt'}[field]]=invalid
            with self.subTest(public_context=field,value=invalid),self.assertRaisesRegex(MODULE.Refused,'android-signed-public-context'):
                MODULE.android_signed_facts(bad,**context)
        selected=b'-[MRKNormalAppUITests.NormalAppUITests '+MODULE.ANDROID_METHOD.encode()+b']'
        stdout=b'\n'.join([b"Test Case '"+selected+b"' started.",MODULE.ORIGINAL_MARKER.encode(),
            MODULE.ANDROID_FACTS_PREFIX+MODULE.encoded(public),b"Test Case '"+selected+b"' passed (2.000 seconds)."])+b'\n'
        self.assertEqual(MODULE.android_signed_marker(stdout,source=source,run=run,attempt=attempt,certificate='d'*64),public)
        for key,badvalue in [('runId','2'),('privateOriginalsClosed',False),('sourceRegistrationObserved',True),
            ('parentReturncodeRequired',False),('operationId','private/path'),('artifactBytes',True),
            ('moduleLogicalBytes',13),('privateKeySha256','e'*64)]:
            bad=dict(public);bad[key]=badvalue
            with self.subTest(public=key),self.assertRaises(MODULE.Refused):
                MODULE.android_signed_facts(bad,source=source,run=run,attempt=attempt)
        for bad in (stdout+MODULE.ANDROID_FACTS_PREFIX+MODULE.encoded(public)+b'\n',
                    stdout.replace(b' passed (',b' failed ('),stdout+b'MRK_MACOS_UI_FAILURE_CLEANUP=unknown\n',b'x'*1048577):
            with self.assertRaises(MODULE.Refused): MODULE.android_signed_marker(bad,source=source,run=run,attempt=attempt,certificate='d'*64)
        request=MODULE.normal_request(['--normal-android-signed-build-test'],str(normal/'tmp')+'/')
        self.assertEqual((request['methods'],request['allowance'],request['timeout'],request['phaseSeconds']),
            ((MODULE.CLASS+MODULE.ANDROID_METHOD,),900,1020,1245))
        self.assertEqual(MODULE.normal_request(['--normal-android-signed-build-summary'],str(normal/'tmp')+'/')['phaseSeconds'],90)
        self.assertNotIn(MODULE.ANDROID_RESULT,MODULE.NORMAL_SELECTIONS)
        for args in (['--target',MODULE.INTEL_TARGET,'--normal-android-signed-build-test'],
                     ['--normal-android-signed-build-test','--work','/tmp/private']):
            with self.assertRaises(MODULE.Refused): MODULE.normal_request(args,str(normal/'tmp')+'/')

        # Exercise the ACTUAL new normal_context with the exact Metadata
        # clean environment. Only host/account observations are inert adapters;
        # there is no caller private path, no target env and no native command.
        import resource
        import pwd
        checkout=Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
        env=dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin',HOME='/Users/runner',USER='runner',LOGNAME='runner',
            TMPDIR=str(normal/'tmp')+'/',LANG='en_US.UTF-8',LC_ALL='en_US.UTF-8',TZ='UTC',
            DEVELOPER_DIR=MODULE.DEVELOPER,TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB='github-hosted-macos26-arm64',
            TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=source,TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=source,
            GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit',GITHUB_EVENT_NAME='push',GITHUB_REF=MODULE.ANDROID_REF,
            GITHUB_SHA=source,GITHUB_WORKFLOW_SHA=source,
            GITHUB_WORKFLOW_REF='Apdelrahman1911/mobile-release-kit/'+MODULE.ANDROID_WORKFLOW+'@'+MODULE.ANDROID_REF,
            GITHUB_WORKSPACE=str(checkout),GITHUB_RUN_ID=run,GITHUB_RUN_ATTEMPT=attempt,
            RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='macOS',RUNNER_ARCH='ARM64')
        with ExitStack() as stack:
            stack.enter_context(patch.object(MODULE,'__file__',str(checkout/'desktop/tools/macos_normal_ui_runner.py')))
            stack.enter_context(patch.object(MODULE.sys,'platform','darwin'))
            stack.enter_context(patch.object(MODULE.sys,'version_info',(3,14,7)))
            stack.enter_context(patch.object(MODULE.sys,'flags',SimpleNamespace(isolated=1,no_site=1)))
            stack.enter_context(patch.object(MODULE.sys,'dont_write_bytecode',True))
            stack.enter_context(patch.object(MODULE.platform,'machine',return_value='arm64'))
            stack.enter_context(patch.object(MODULE.platform,'mac_ver',return_value=('26.6.2',(),'')))
            stack.enter_context(patch.object(resource,'getrlimit',return_value=(1024**3,1024**3)))
            stack.enter_context(patch.object(pwd,'getpwuid',return_value=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_name='runner',pw_dir='/Users/runner')))
            for function in ('getuid','geteuid','getgid','getegid'):
                stack.enter_context(patch.object(MODULE.os,function,return_value=1000))
            stack.enter_context(patch.object(MODULE.os,'stat',return_value=SimpleNamespace(st_uid=1000)))
            stack.enter_context(patch.object(MODULE.Path,'cwd',return_value=checkout))
            with patch.dict(MODULE.os.environ,env,clear=True):
                admitted,actual,forwarded,limit=MODULE.normal_context(request)
            self.assertEqual((admitted,actual,limit),(checkout,source,(1024**3,1024**3)))
            self.assertEqual(forwarded[MODULE.ANDROID_INPUT_ENV],str(normal/'android-input-fixture.json'))
            self.assertEqual((forwarded[MODULE.ANDROID_RUN_ENV],forwarded[MODULE.ANDROID_ATTEMPT_ENV]),(run,attempt))
            self.assertNotIn('MRK_MACOS_TARGET',forwarded)
            self.assertNotIn('GITHUB_SHA',forwarded)
            for key,badvalue in [('GITHUB_RUN_ID','0'),('GITHUB_RUN_ATTEMPT','secret'),('GITHUB_SHA','b'*40),
                ('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_REF','refs/heads/other'),('RUNNER_ARCH','X64')]:
                altered=dict(env);altered[key]=badvalue
                with self.subTest(context=key),patch.dict(MODULE.os.environ,altered,clear=True),self.assertRaisesRegex(MODULE.Refused,'android-signed-fixed-installed-context'):
                    MODULE.normal_context(request)

    def test_android_private_reader_real_originals_post_and_consuming_close(self):
        # Real tiny files and FD bindings, with only the fixed Mac root mapped to
        # an isolated private test directory. No actual credential/vendor bytes.
        native=Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui')
        real_open,real_close,real_stat=os.open,os.close,os.stat
        for fault in (None,'ancestor','leaf','fifo','hardlink','close','primary-close','post-close-clock'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                scratch=Path(temporary);normal=scratch/str(native).lstrip('/');normal.mkdir(parents=True,mode=0o700)
                for parent in normal.parents:
                    if parent==scratch: break
                    parent.chmod(0o700)
                root=normal/'android-inputs';credentials=root/'credentials';credentials.mkdir(parents=True,mode=0o700);root.chmod(0o700);credentials.chmod(0o700)
                tools=root/'tools';tools.mkdir(mode=0o700);(tools/'jdk').mkdir(mode=0o755);(tools/'jdk').chmod(0o755)
                for relative in MODULE.ANDROID_ROOTS.values():
                    (root/relative).mkdir(mode=0o755);(root/relative).chmod(0o755)
                data={'upload.jks':b'inert-not-a-key','upload.der':b'inert-not-a-certificate',
                    'scalars.json':MODULE.encoded(dict(alias='mrk-disposable-android-ui',storePassword='1'*48,keyPassword='2'*48))+b'\n'}
                for name,body in data.items():
                    path=credentials/name;path.write_bytes(body);path.chmod(0o600)
                wire=lambda path:MODULE.decimal(MODULE.saved_version_facts(real_stat(path,follow_symlinks=False)))
                commands=[dict(role=role,returncode=0,timeoutSeconds=30,roleCapSeconds=30,outputLimitBytes=2097152,
                    argvSha256='b'*64,stdoutBytes=0,stdoutSha256=hashlib.sha256(b'').hexdigest(),
                    stderrBytes=0,stderrSha256=hashlib.sha256(b'').hexdigest())
                    for role in ('android-ui-disposable-jks','android-ui-public-certificate')]
                doc=dict(schemaVersion=1,scope='one-owned-android-ui-inputs',sourceCommit='a'*40,target=MODULE.ARM_TARGET,
                    runId='42',runAttempt='1',workflow=MODULE.ANDROID_WORKFLOW,ref=MODULE.ANDROID_REF,
                    root=str(native/'android-inputs'),rootFacts=wire(root),credentialDirectoryFacts=wire(credentials),
                    sourceCatalogueSha256=MODULE.ANDROID_CATALOGUE,sourceRosterSha256='c'*64,
                    publicCertificateSha256=hashlib.sha256(data['upload.der']).hexdigest(),
                    roots={k:dict(relative=v,facts=wire(root/v))for k,v in MODULE.ANDROID_ROOTS.items()},
                    files={k:dict(relative='credentials/'+k,facts=wire(credentials/k),sha256=hashlib.sha256(v).hexdigest())for k,v in data.items()},
                    keyCommands=commands,parentReturncodeRequired=0,
                    phaseClock=dict(startNs='1',deadlineNs=str(1+1200*10**9),beforePublicationNs='2',postCloseDeadlineRequired=True))
                handoff=normal/'android-input-fixture.json';handoff.write_bytes(MODULE.encoded(doc)+b'\n');handoff.chmod(0o600)
                if fault=='fifo':
                    (credentials/'upload.jks').unlink();os.mkfifo(credentials/'upload.jks',0o600)
                    doc['credentialDirectoryFacts']=wire(credentials)
                    handoff.write_bytes(MODULE.encoded(doc)+b'\n')
                if fault=='hardlink': os.link(credentials/'upload.jks',scratch/'linked')
                opened,closed,flags=[],[],[]
                sentinel=ValueError('synthetic primary remains private')
                def opening(path,mode,*args,**kwargs):
                    actual=scratch if path=='/' else path
                    fd=real_open(actual,mode,*args,**kwargs);opened.append(fd);flags.append((path,mode));return fd
                def stating(path,*args,**kwargs): return real_stat(scratch if path=='/' else path,*args,**kwargs)
                def closing(fd):
                    closed.append(fd);real_close(fd)
                    if fault in ('close','primary-close'): raise OSError('synthetic consuming close')
                reader=None
                def check():
                    if fault=='post-close-clock' and reader is not None and reader.closed: raise ValueError('clock')
                phase=SimpleNamespace(clock=SimpleNamespace(check=check),environment={MODULE.ANDROID_RUN_ENV:'42',MODULE.ANDROID_ATTEMPT_ENV:'1'})
                reader=MODULE.AndroidPrivateInputs(phase,'a'*40,native)
                failure=None
                with patch.object(MODULE.os,'open',opening),patch.object(MODULE.os,'stat',stating),patch.object(MODULE.os,'close',closing):
                    try:
                        with reader:
                            self.assertEqual((len(reader.fds),len(reader.files)),(18,4))
                            self.assertEqual(reader.public_certificate,doc['publicCertificateSha256'])
                            if fault=='ancestor':
                                (scratch/'Users/runner/work').rename(scratch/'Users/runner/old-work')
                                (scratch/'Users/runner/work').mkdir(mode=0o700)
                            elif fault=='leaf':
                                leaf=credentials/'upload.jks';leaf.write_bytes(b'x'*len(data['upload.jks']))
                            elif fault=='primary-close': raise sentinel
                    except BaseException as error: failure=error
                    finally:
                        # Safety precedes assertions, including failed __enter__.
                        reader.close(primary=True)
                self.assertTrue(reader.closed)
                self.assertEqual(len(opened),len(closed))
                self.assertEqual(len(closed),len(set(closed)))
                self.assertFalse(reader.fds or reader.files or reader.directories)
                self.assertTrue(all(mode&os.O_NONBLOCK for path,mode in flags if path in ('android-input-fixture.json',*MODULE.ANDROID_PRIVATE_FILES)))
                if fault is None: self.assertIsNone(failure)
                elif fault=='primary-close': self.assertIs(failure,sentinel)
                else:
                    expected={'ancestor':'android-input-ancestor-post','leaf':'android-input-private-post',
                        'fifo':'android-input-private-file','hardlink':'android-input-private-file',
                        'close':'android-input-close-or-clock','post-close-clock':'android-input-close-or-clock'}[fault]
                    self.assertIsInstance(failure,MODULE.Refused)
                    self.assertEqual(str(failure),expected)

    def test_android_positive_source_uses_closed_private_role_and_ordinary_ui(self):
        # Actual new Swift source, not an executable Python model of its reader.
        source=SWIFT.read_bytes().decode('utf-8')
        restored=without_positive_android_source(source)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), '32e2bd4223c6219eaeed0e9b9cfa78f3fd9b7c8fd05fb1e2cf903395038d78c4')
        private=source.split('        final class AndroidInputs {',1)[1].split('        // Fixed public XML prerequisite only.',1)[0]
        for token in ('O_NONBLOCK','descriptors.count == 18','held.count == 14','leaves.count == 4',
                      'try directoryPost(directory, full: true)','while let fd = descriptors.popLast()',
                      'scalars.removeAll()','do { try check() } catch { if primary == nil { primary = error } }'):
            self.assertIn(token,private)
        for forbidden in ('Process(', 'removeItem', 'unlinkat(', 'chmod(', 'try?'):
            self.assertNotIn(forbidden,private)
        journey=source.split('    @MainActor func testSyntheticProjectAndroidSignedBuild() throws {',1)[1].split('    override func tearDown()',1)[0]
        for token in ('beginCase(seconds: 900, androidPositive: true)','fixture.prepare(.androidSignedBuild)',
                      'fixture.accept("android-public-certificate")','!register.isEnabled',
                      '"Discard this source review"','"Recover (full verification)"','"Choose this tool copy"',
                      '"Start session — keep inputs in memory"','"Keep for this session"','"Assign to this context"',
                      '"Build, sign and validate"','"retained-local-result','finishAndroidOutputObservation',
                      '"MRK_MACOS_ANDROID_SIGNED_BUILD_UI="'):
            # Disposition phrase has its surrounding fixed text.
            self.assertIn(token if token!='"retained-local-result' else 'Local artifacts: retained-local-result.',journey)
        self.assertEqual(journey.count('try press(review, "Build, sign and validate"'),1)
        # Swift argument labels still follow the unchanged declaration order.
        signature=source.split('    @MainActor private func press(',1)[1].split(') throws {',1)[0]
        self.assertIn('failures: [String] = [], timeout: TimeInterval = 5',signature)
        self.assertEqual(journey.count('try press(review, "Apply reviewed save", renderer: renderer, failures: Self.configurationFailures, timeout: 48)'),1)
        self.assertNotIn('try press(review, "Apply reviewed save", renderer: renderer, timeout: 48, failures: Self.configurationFailures)',journey)
        self.assertNotIn('license.click()',journey)
        for forbidden in ('"Open encrypted vault"','"Create encrypted vault"','"Register protected tool copy", renderer:',
                          '"Request system registration"','"Open System Settings"'):
            self.assertNotIn(forbidden,journey)
        self.assertLess(journey.index('initialInputs.finish'),journey.index('"Discard session copies"'))
        self.assertLess(journey.index('"Discard session copies"'),journey.index('finishAndroidOutputObservation'))
        self.assertLess(journey.index('closeAndroidOriginals'),journey.index('MRK_MACOS_ANDROID_SIGNED_BUILD_UI='))
        self.assertNotIn('testSyntheticProjectAndroidSignedBuild',str(MODULE.NORMAL_SELECTIONS))

    def test_normal_loader_registers_real_dataclasses_and_preserves_original_custody(self):
        name = MODULE.LOADER_MODULE
        self.assertNotIn(name, sys.modules)
        for collision in (None, object()):
            sys.modules[name] = collision
            try:
                with patch.object(MODULE.os, "open", side_effect=AssertionError("collision must precede open")):
                    with self.assertRaisesRegex(MODULE.Refused, "loader-collision"):
                        MODULE.load_normal_owner(ROOT)
                self.assertIs(sys.modules[name], collision)
            finally:
                if name in sys.modules and sys.modules[name] is collision:
                    del sys.modules[name]
        original_spec = MODULE.importlib.util.spec_from_file_location
        original_open, original_close, original_body = os.open, os.close, MODULE.original_body
        for fault in (None, "execution", "registry-before-core", "registry-after-core",
                      "source-before-core", "source-after-core", "close", "primary-and-close"):
            with self.subTest(fault=fault), ExitStack() as stack:
                opened, closed, modules, calls = [], [], [], []
                foreign, sentinel = object(), object()
                first_failure = ValueError("private synthetic loader failure")
                close_failure = OSError("private synthetic close failure")
                reads = 0

                def opening(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if Path(path) == ROOT / MODULE.LOADER:
                        opened.append(fd)
                    return fd

                def closing(fd):
                    if fd in opened:
                        closed.append(fd)
                    original_close(fd)
                    if fd in opened and fault in ("close", "primary-and-close"):
                        raise close_failure

                def reading(fd, limit, collect=False):
                    nonlocal reads
                    value = original_body(fd, limit, collect)
                    reads += 1
                    if (fault == "source-before-core" and reads == 3
                            or fault == "source-after-core" and reads == 4):
                        return value[:2] + ("0" * 64,)
                    return value

                def spec_for(module_name, path):
                    self.assertEqual((module_name, Path(path)), (name, ROOT / MODULE.LOADER))
                    spec = original_spec(module_name, path)
                    actual = spec.loader

                    class DefinitionLoader:
                        def create_module(self, _spec):
                            return None

                        def exec_module(self, module):
                            modules.append(module)
                            self_registered = sys.modules.get(name)
                            if self_registered is not module:
                                raise AssertionError("real definitions require original registration")
                            actual.exec_module(module)  # Actual helper/dataclasses, NOT core/native execution.
                            if not dataclasses.is_dataclass(module.Binding):
                                raise AssertionError("real Binding dataclass was not loaded")

                            def no_core(root):
                                calls.append(root)
                                if fault == "registry-after-core":
                                    sys.modules[name] = foreign
                                return sentinel

                            module.load_owner = no_core  # Stub only before the first possible core entry.
                            if fault in ("execution", "primary-and-close"):
                                raise first_failure
                            if fault == "registry-before-core":
                                sys.modules[name] = foreign

                    spec.loader = DefinitionLoader()
                    return spec

                stack.enter_context(patch.object(MODULE.importlib.util, "spec_from_file_location", spec_for))
                stack.enter_context(patch.object(MODULE.os, "open", opening))
                stack.enter_context(patch.object(MODULE.os, "close", closing))
                stack.enter_context(patch.object(MODULE, "original_body", reading))
                try:
                    if fault is None:
                        self.assertIs(MODULE.load_normal_owner(ROOT), sentinel)
                        self.assertIs(sys.modules[name], modules[0])
                    else:
                        with self.assertRaises((MODULE.Refused, ValueError, OSError)) as raised:
                            MODULE.load_normal_owner(ROOT)
                        if fault in ("execution", "primary-and-close"):
                            self.assertIs(raised.exception, first_failure)
                        elif fault == "close":
                            self.assertIs(raised.exception, close_failure)
                        if fault.startswith("registry-"):
                            self.assertIs(sys.modules[name], foreign)
                        else:
                            self.assertNotIn(name, sys.modules)
                    self.assertEqual(len(opened), 1)
                    self.assertEqual(closed, opened)
                    self.assertEqual(len(calls), 0 if fault in (
                        "execution", "primary-and-close", "registry-before-core", "source-before-core") else 1)
                finally:
                    # Only these fixture-owned entries are retired; no blanket registry restore.
                    if name in sys.modules and (sys.modules[name] is foreign
                            or any(sys.modules[name] is item for item in modules)):
                        del sys.modules[name]

    def test_admission_exception_projection_is_closed_and_preserves_main_failure(self):
        private = "private-synthetic-credential-or-path"
        try:
            MODULE.need(False, private)
        except MODULE.Refused as error:
            value = MODULE.normal_admission_failure("loader", error, None, [])
        self.assertEqual(value["exceptionClass"], "Refused")
        self.assertEqual(value["sourceFrames"][0]["source"], "macos_normal_ui_runner.py")
        self.assertNotIn(private.encode(), MODULE.encoded(value))
        projected = MODULE.classify_normal_admission_failure(MODULE.encoded(value) + b"\n")
        self.assertEqual(projected["status"], "observed-exception-only")
        self.assertFalse(projected["nativeSuccessInferred"])
        self.assertIs(projected["ownerFailure"]["cleanupComplete"], None)
        foreign_frame = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(
            co_filename="/private/macos_normal_ui_runner.py")), tb_lineno=12, tb_next=None)
        fake_error = SimpleNamespace(__traceback__=foreign_frame)
        self.assertEqual(MODULE.normal_admission_failure("loader", fake_error, None, [])["sourceFrames"], [])
        command = {"role": "normal-ui-build", "returncode": 65, "timeoutSeconds": 120, "roleCapSeconds": 240,
            "outputLimitBytes": 1048576, "stdoutBytes": 32, "stderrBytes": 12,
            "argvSha256": "a" * 64, "stdoutSha256": "b" * 64, "stderrSha256": "c" * 64}
        with_commands = dict(value, commands=[command])
        selected = MODULE.classify_normal_admission_failure(MODULE.encoded(with_commands))
        self.assertEqual(selected["commands"], [{"role": "normal-ui-build", "returncode": 65, "stdoutBytes": 32, "stderrBytes": 12}])
        mutations = []
        for key, bad in (("schemaVersion", True), ("productReady", True), ("stage", "private-stage"),
                         ("exceptionClass", private), ("sourceFrames", [{"source": "/private/macos_normal_ui_runner.py", "line": 1}]),
                         ("sourceFrames", [{"source": "macos_normal_ui_runner.py", "line": True}]),
                         ("ownerFailure", {"dispatched": 1, "contained": True, "cleanupComplete": None}),
                         ("commands", [{"private": private}])):
            mutations.append(MODULE.encoded(dict(value, **{key: bad})))
        mutations += [b"", b"x" * 65537, MODULE.encoded(value) + b"\nprivate native output\n",
            MODULE.encoded(value) + MODULE.encoded(value), b'{"schemaVersion":1,"schemaVersion":1}',
            b'{"schemaVersion":NaN}', MODULE.encoded(dict(value, extra=private))]
        mutations += [MODULE.encoded(dict(value, commands=[dict(command, **{key: bad})]))
                      for key, bad in (("role", private), ("returncode", True), ("stderrBytes", 1048576),
                                       ("argvSha256", private), ("timeoutSeconds", 241))]
        for body in mutations:
            self.assertEqual(MODULE.classify_normal_admission_failure(body)["status"], "unavailable")
        # Main returns1 even for an early loader exception; no owner/native call.
        normal = "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        with patch.object(MODULE.sys, "argv", ["helper", "--normal-build"]), \
                patch.object(MODULE.os, "environ", {"TMPDIR": normal}), \
                patch.object(MODULE.time, "monotonic_ns", return_value=0), \
                patch.object(MODULE, "normal_context", return_value=(ROOT, "a" * 40, {}, (32 * 1024**3,) * 2)), \
                patch.object(MODULE, "load_normal_owner", side_effect=AttributeError(private)), \
                patch.object(MODULE, "execute_normal_phase", side_effect=AssertionError("must not execute")), \
                patch.object(MODULE.sys, "stderr", io.StringIO()) as errors:
            self.assertEqual(MODULE.main(), 1)
        classified = MODULE.classify_normal_admission_failure(errors.getvalue().encode())
        self.assertEqual((classified["stage"], classified["exceptionClass"]), ("loader", "AttributeError"))
        self.assertNotIn(private, errors.getvalue())
        # Real result-query guard with inert original/FD doubles only. There is
        # no xcresult bundle, native command, filesystem access or new owner.
        base = (11, 22, stat.S_IFDIR | 0o700, 1001, 1002, 2, 4096, 700, 800)
        names = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        mask_keys = ("heldVsPre", "namedVsPre", "heldVsNamed")
        request = dict(target=MODULE.ARM_TARGET, methods=(MODULE.OUTPUT_DATA_METHOD,), allowance=60,
            timeout=120, phaseSeconds=345, derived=Path("/inert/normal-ui/DerivedData"),
            result=Path("/inert/normal-ui/output-data-test.xcresult"))
        mutable = base[:5] + tuple(value + 1 for value in base[5:])
        def exercise(held, named, *, query_kind="summary", nonzero=False, annotation_fault=False,
                     close_fault=False, clock_fault=False, first_query_metadata=False):
            events, records, published = [], [], []
            guard_error = MODULE.Refused("output-data-result-post")
            original = subprocess.CompletedProcess(["inert-xctest"], 0, b"inert-original", b"")
            real_need = MODULE.need
            def need_original(condition, reason):
                if not condition and reason == "output-data-result-post": raise guard_error
                return real_need(condition, reason)
            def current(values):
                changed_at = 1 if query_kind == "summary" else 2
                if len(records) >= changed_at: return values
                return mutable if first_query_metadata and len(records) == 1 else base
            def fd_stat(fd):
                self.assertEqual(fd, 77); events.append("fstat")
                return SimpleNamespace(**dict(zip(names, current(held))))
            def named_stat(path, *, follow_symlinks):
                self.assertEqual(path, request["result"]); self.assertFalse(follow_symlinks); events.append("stat")
                return SimpleNamespace(**dict(zip(names, current(named))))
            def consume(fd):
                self.assertEqual(fd, 77); events.append("close")
                if close_fault: raise OSError("inert-consuming-close")
            def clock_check():
                events.append("clock")
                if clock_fault: raise TimeoutError("inert-result-deadline")
            def source_state(*args): events.append("source"); return ()
            def query(role, argv, cap, limit):
                self.assertEqual((cap, limit), (30, 262144)); events.append(role)
                code = 17 if nonzero and argv[4] == query_kind else 0
                records.append(dict(command, role=role, returncode=code, timeoutSeconds=30, roleCapSeconds=30,
                    outputLimitBytes=262144, stdoutBytes=1, stderrBytes=0))
                return subprocess.CompletedProcess(argv, code, b"x", b"")
            def parse(*args): events.append("parse"); return {"inert": True}
            def capture(*args): events.append("write"); published.append(args)
            def annotate_failure(*args): raise KeyboardInterrupt("inert-annotation-interruption")
            phase = SimpleNamespace(call=query, records=records,
                clock=SimpleNamespace(check=clock_check, before_publication=lambda: {}))
            returned = caught = None
            with ExitStack() as stack:
                for name, replacement in (("normal_source_state", source_state),
                        ("output_data_read_build", lambda *args: "a" * 64),
                        ("run_admitted_test", lambda *args, **kwargs: (original, {})),
                        ("open_directory", lambda *args: 77), ("need", need_original),
                        ("os", SimpleNamespace(fstat=fd_stat, stat=named_stat, close=consume,
                                               getuid=lambda: base[3], getgid=lambda: base[4])),
                        ("output_data_result", parse), ("exclusive_output", capture)):
                    stack.enter_context(patch.object(MODULE, name, replacement))
                if annotation_fault:
                    stack.enter_context(patch.object(MODULE, "output_data_result_post_masks", annotate_failure))
                try: returned = MODULE.execute_output_data_phase(phase, request, "a" * 40, (1024**3,) * 2)
                except BaseException as error: caught = error
            self.assertEqual(events.count("close"), 1)
            self.assertEqual(events.count("clock"), 2 if caught is None and returned.returncode == 0 else 1)
            return returned, caught, guard_error, records, events, published

        # Original object/type/permissions stay fixed across both queries.
        # Layout metadata is allowed to change only with a matching live name.
        for index in range(5):
            altered = tuple(value + (slot == index) for slot, value in enumerate(base))
            with self.subTest(result_post_component=index):
                returned, caught, expected, records, events, published = exercise(altered, altered)
                self.assertIsNone(returned); self.assertIs(caught, expected)
                self.assertEqual(events, ["source", "fstat", "stat", "normal-ui-summary", "fstat", "stat", "close", "clock"])
                self.assertEqual(published, [])
                result = MODULE.normal_admission_failure("execute", caught, None, records)
                observation = result["resultPost"]
                self.assertEqual(observation, dict(schemaVersion=1, query="summary", originalReturncode=0,
                    heldVsPre=[slot == index for slot in range(9)], namedVsPre=[slot == index for slot in range(9)],
                    heldVsNamed=[False] * 9))
                projected = MODULE.classify_normal_admission_failure(MODULE.encoded(result))
                self.assertEqual(projected["resultPost"], observation)
                self.assertEqual(projected["status"], "observed-exception-only")
                self.assertFalse(projected["nativeSuccessInferred"])
                self.assertLessEqual(len(MODULE.encoded(projected)) + 1, 4096)
        # Reproduce all four observed mutable fields, independently and together,
        # at either query. Both queries, semantic parsing and SOURCE POST still run.
        for index in (5, 6, 7, 8, None):
            altered = mutable if index is None else tuple(value + (slot == index) for slot, value in enumerate(base))
            for kind in ("summary", "tests"):
                with self.subTest(mutable_component=index, query=kind):
                    returned, caught, _, observed_records, events, published = exercise(altered, altered, query_kind=kind)
                    self.assertIsNone(caught); self.assertEqual(returned.returncode, 0)
                    self.assertEqual([row["role"] for row in observed_records], ["normal-ui-summary", "normal-ui-test-tree"])
                    self.assertEqual(events.count("source"), 2); self.assertEqual(events.count("parse"), 1)
                    self.assertEqual(len(published), 1)
            # Mutable is not an exemption for disagreement between the held
            # original and its name: even timestamp-only disagreement refuses.
            returned, caught, expected, _, events, published = exercise(base, altered)
            self.assertIsNone(returned); self.assertIs(caught, expected)
            self.assertNotIn("parse", events); self.assertEqual(published, [])
        # A successful mutable first query never adopts a new identity baseline.
        changed_owner = mutable[:4] + (base[4] + 1,) + mutable[5:]
        for held, named in ((changed_owner, changed_owner), (mutable, changed_owner)):
            returned, caught, expected, observed_records, events, published = exercise(
                held, named, query_kind="tests", first_query_metadata=True)
            self.assertIsNone(returned); self.assertIs(caught, expected)
            self.assertEqual(len(observed_records), 2); self.assertNotIn("parse", events)
            self.assertEqual(events.count("source"), 1); self.assertEqual(published, [])
        # Successful queries cannot outrun a consuming close or phase deadline.
        for flags, error_type in (({"close_fault": True}, OSError), ({"clock_fault": True}, TimeoutError)):
            returned, caught, _, _, events, published = exercise(mutable, mutable, **flags)
            self.assertIsNone(returned); self.assertIsInstance(caught, error_type)
            self.assertNotIn("parse", events); self.assertEqual(published, [])
        replacement = tuple(value + (index == 1) for index, value in enumerate(base))
        returned, caught, expected, records, events, published = exercise(base, replacement, query_kind="tests")
        self.assertIs(caught, expected); self.assertIsNone(returned); self.assertEqual(published, [])
        self.assertEqual([x for x in events if x.startswith("normal-ui-")], ["normal-ui-summary", "normal-ui-test-tree"])
        self.assertNotIn("parse", events); self.assertNotIn("write", events); self.assertEqual(events.count("source"), 1)
        valid = MODULE.normal_admission_failure("execute", caught, None, records)
        self.assertEqual(valid["resultPost"]["heldVsPre"], [False] * 9)
        self.assertEqual(valid["resultPost"]["namedVsPre"], [index == 1 for index in range(9)])
        self.assertEqual(valid["resultPost"]["heldVsNamed"], valid["resultPost"]["namedVsPre"])
        other = tuple(value + 2 * (index == 1) for index, value in enumerate(base))
        triple = MODULE.output_data_result_post_masks("tests", base, replacement, other)
        self.assertEqual(MODULE.admit_output_data_result_post(triple, records), triple)
        for flags in ((True, False), (False, True)):
            returned, caught, expected, observed_records, events, published = exercise(replacement, replacement,
                annotation_fault=flags[0], close_fault=flags[1])
            self.assertIs(caught, expected); self.assertIsNone(returned); self.assertEqual(published, [])
            self.assertEqual(events[-2:], ["close", "clock"])
            value = MODULE.normal_admission_failure("execute", caught, None, observed_records)
            self.assertEqual("resultPost" in value, not flags[0])
        for kind in ("summary", "tests"):
            returned, caught, _, observed_records, events, published = exercise(replacement, replacement, query_kind=kind, nonzero=True)
            self.assertIsNone(caught); self.assertEqual(returned.returncode, 17); self.assertEqual(published, [])
            self.assertNotIn("parse", events); self.assertNotIn("write", events)
            self.assertEqual(events.count("source"), 1)
            self.assertEqual(len(observed_records), 1 if kind == "summary" else 2)
        returned, caught, _, records_ok, events, published = exercise(base, base)
        self.assertIsNone(caught); self.assertEqual(returned.returncode, 0); self.assertEqual(len(published), 1)
        self.assertEqual(events.count("source"), 2); self.assertEqual(events.count("parse"), 1)

        # Closed decoder: no raw stats/names/paths, impossible equality triples,
        # absent guard failure, wrong query original, or later command is accepted.
        bad_observations = [dict(valid["resultPost"], **change) for change in (
            {"schemaVersion": True}, {"query": "private-query"}, {"originalReturncode": True},
            {"extra": private}, {"heldVsPre": [False] * 8}, {"heldVsPre": [0] * 9},
            {"heldVsPre": [False] * 9, "namedVsPre": [False] * 9, "heldVsNamed": [False] * 9})]
        for index in range(3):
            impossible = dict(valid["resultPost"], **{key: [False] * 9 for key in mask_keys})
            impossible[mask_keys[index]][0] = True
            bad_observations.append(impossible)
        invalid_records = [dict(valid, resultPost=entry) for entry in bad_observations]
        invalid_records += [dict(valid, **change) for change in (
            {"stage": "loader"}, {"exceptionClass": "OSError"},
            {"commands": [dict(valid["commands"][-1], returncode=1)]},
            {"commands": [dict(valid["commands"][-1], role="normal-ui-summary")]},
            {"commands": valid["commands"] + [dict(command, role="normal-ui-source-roster", returncode=0)]})]
        for invalid in invalid_records:
            self.assertEqual(MODULE.classify_normal_admission_failure(MODULE.encoded(invalid))["status"], "unavailable")
        for stage, error in (("loader", expected), ("execute", MODULE.Refused("different-refusal")),
                             ("execute", ValueError("output-data-result-post"))):
            error._output_data_result_post = valid["resultPost"]
            self.assertNotIn("resultPost", MODULE.normal_admission_failure(stage, error, None, valid["commands"]))
        with patch.object(MODULE, "admit_output_data_result_post", side_effect=KeyboardInterrupt(private)):
            expected._output_data_result_post = valid["resultPost"]
            self.assertNotIn("resultPost", MODULE.normal_admission_failure("execute", expected, None, valid["commands"]))


    def test_normal_runner_build_is_early_but_ui_stays_after_installation(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        label = "      - name: Build only the external normal-app XCTest runner, not an instrumented app\n"
        self.assertEqual(workflow.count(label), 1)
        source_end = workflow.index("          PY_SOURCE\n")
        start = workflow.index(label)
        between = workflow[source_end + len("          PY_SOURCE\n"):start]
        self.assertEqual([line[len("      - name: "):] for line in between.splitlines()
                          if line.startswith("      - name: ")], ['Admit the fixed image Rust tools without installing a distribution', 'Admit only a fresh independently pinned Python transport destination', 'Download the independently accepted fresh Python transport', 'Project the pinned fresh Python transport without executing it', 'Download only the configured signed Python capsule', 'Project the configured capsule as DATA without executing it', 'Prepare the current payload from the independently accepted fresh Python supplier'])
        self.assertLess(source_end, start)
        self.assertLess(start, workflow.index("      - name: Acquire and verify the two fixed Android support archives as DATA"))
        build = workflow.split(label, 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: github.ref == 'refs/heads/verify/desktop-macos-preview'", build)
        self.assertNotIn("steps.preview_upload", build)
        self.assertEqual(build.count(" --normal-build "), 1)
        self.assertIn("classify_normal_admission_failure", build)
        self.assertIn('exit "$build_status"', build)
        self.assertIn('original_body(fd, 65536, collect=True)', build)
        self.assertIn('exclusive_output(normal / "build.admission-diagnostics.json"', build)
        action = workflow.split("      - name: Launch the exact ordinary app, Cancel its real Quit sheet, then Quit normally\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("steps.normal_ui_build.outcome == 'success' && steps.preview_upload.outcome == 'success'", action)
        install = workflow.index("macos_android_helper_package.py package-install")
        saved_original = workflow.index('"$package_status_saved" == 0', install)
        preview = workflow.index("stage_macos_installed.py preview", saved_original)
        upload = workflow.index("      - name: Upload only the normal user preview package and guide", preview)
        launch = workflow.index("      - name: Launch the exact ordinary app,", upload)
        self.assertLess(install, saved_original)
        self.assertLess(saved_original, preview)
        self.assertLess(preview, upload)
        self.assertLess(upload, launch)
        self.assertIn('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" --normal-build', build)
        self.assertIn('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building', action)
        artifact = workflow.split("        id: evidence\n", 1)[1]
        self.assertIn("/normal-ui/build.admission-diagnostics.json", artifact)
        self.assertNotIn("/normal-ui/build.log", artifact.split("      # Do not start", 1)[0])

    """Only fake original owners and private synthetic files, never Apple tools."""

    def test_fixed_normal_modes_environment_and_returned_original_contract(self):
        normal = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui")
        temporary = str(normal / "tmp") + "/"
        build = MODULE.normal_request(["--normal-build"], temporary)
        self.assertEqual((build["phase"], build["derived"], build["result"], build["phaseSeconds"]),
                         ("build", normal / "DerivedData", None, 450))
        self.assertEqual(MODULE.normal_build_arguments(build["derived"]), [
            "/usr/bin/xcodebuild", "build-for-testing", "-project", MODULE.PROJECT, "-scheme", "MRKNormalAppUI",
            "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
            "-derivedDataPath", str(normal / "DerivedData"), "-jobs", "2", "-disableAutomaticPackageResolution",
            "COMPILER_INDEX_STORE_ENABLE=NO"])
        self.assertEqual(build["target"], "aarch64-apple-darwin")
        arm_build = MODULE.normal_build_arguments(build["derived"])
        targets = (("aarch64-apple-darwin", "arm64", "github-hosted-macos26-arm64"),
                   ("x86_64-apple-darwin", "x86_64", "github-hosted-macos26-x86_64"))
        requests = {}
        for target_value, machine, marker in targets:
            self.assertEqual(MODULE.normal_target_data(target_value), (machine, marker))
            selected_build = MODULE.normal_request(["--target", target_value, "--normal-build"], temporary)
            expected_build = list(arm_build)
            expected_build[expected_build.index("-destination") + 1] = ("platform=macOS" if machine == "x86_64"
                else "platform=macOS,arch=" + machine)
            if machine == "x86_64": expected_build.append("ARCHS=x86_64")
            self.assertEqual(MODULE.normal_build_arguments(build["derived"], target=target_value), expected_build)
            self.assertEqual(selected_build, dict(build, target=target_value))
            for name, (_, allowance, cap) in MODULE.NORMAL_SELECTIONS.items():
                arguments = normal_arguments(name)
                arguments[8] = "platform=macOS,arch=" + machine
                selected_test = MODULE.normal_request(["--target", target_value, *arguments], temporary)
                selected_summary = MODULE.normal_request(["--target", target_value, "--normal-summary", name], temporary)
                self.assertEqual(selected_test["target"], target_value)
                self.assertEqual((selected_test["allowance"], selected_test["timeout"], selected_test["phaseSeconds"]),
                                 (allowance, cap, {180: 345, 420: 585, 720: 885}[cap]))
                self.assertEqual((selected_summary["target"], selected_summary["timeout"], selected_summary["phaseSeconds"]),
                                 (target_value, 30, 90))
                command = MODULE.xcode_test_arguments("/fixed.xctestrun", normal / name,
                    selected_test["methods"], allowance, target=target_value)
                self.assertEqual(command[command.index("-destination") + 1],
                                 "platform=macOS" if machine == "x86_64" else arguments[8])
                self.assertFalse(any(value.startswith("ARCHS=") for value in command))
                other = "x86_64-apple-darwin" if machine == "arm64" else "aarch64-apple-darwin"
                with self.assertRaises(MODULE.Refused):
                    MODULE.normal_request(["--target", other, *arguments], temporary)
                if name == "test.xcresult": requests[target_value] = (selected_build, selected_test, selected_summary)
        for invalid in (None, True, "arm64", "x86_64", "X86_64-apple-darwin", "x86_64-apple-darwin "):
            with self.subTest(target=invalid), self.assertRaises(MODULE.Refused):
                MODULE.normal_build_arguments(build["derived"], target=invalid)
        for arguments in (["--target"], ["--target", "x86_64-apple-darwin"],
                          ["--target", "other", "--normal-build"],
                          ["--target", "x86_64-apple-darwin", "--target", "x86_64-apple-darwin", "--normal-build"],
                          ["--normal-build", "--target", "x86_64-apple-darwin"],
                          ["--target=x86_64-apple-darwin", "--normal-build"],
                          ["--target", "x86_64-apple-darwin", *normal_arguments()]):
            with self.subTest(arguments=arguments), self.assertRaises(MODULE.Refused):
                MODULE.normal_request(arguments, temporary)
        with self.assertRaises(MODULE.Refused):
            MODULE.xcode_test_arguments("/fixed.xctestrun", "/fresh.xcresult", (MODULE.PACKAGED_METHOD,),
                                       60, target="x86_64-apple-darwin")
        with patch.object(MODULE, "RunnerProducts") as unopened:
            with self.assertRaises(MODULE.Refused):
                MODULE.run_admitted_test(lambda *args: self.fail("no dispatch"), build["derived"], normal / "test.xcresult",
                                         (MODULE.PACKAGED_METHOD,), 60, 180, target="x86_64-apple-darwin")
            unopened.assert_not_called()
        for name, (_, allowance, cap) in MODULE.NORMAL_SELECTIONS.items():
            summary = MODULE.normal_request(["--normal-summary", name], temporary)
            test = MODULE.normal_request(normal_arguments(name), temporary)
            self.assertEqual((summary["phase"], summary["result"], summary["timeout"], summary["phaseSeconds"]),
                             ("summary", normal / name, 30, 90))
            self.assertEqual((test["result"], test["allowance"], test["timeout"]), (normal / name, allowance, cap))
            self.assertEqual(test["phaseSeconds"], {180: 345, 420: 585, 720: 885}[cap])
        for arguments in ([], ["--normal-build", "extra"], ["--normal-summary"],
                          ["--normal-summary", "../test.xcresult"], ["--normal-summary", "other.xcresult"],
                          ["--normal-summary", "test.xcresult", "extra"]):
            with self.subTest(arguments=arguments), self.assertRaises(MODULE.Refused):
                MODULE.normal_request(arguments, temporary)
        for temporary_value in ("", temporary + "/", temporary.replace("/normal-ui/", "/elsewhere/")):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_request(["--normal-build"], temporary_value)
        tools = {"xcode": b"Xcode 26.0\nBuild version 17A324\n", "sdkVersion": b"26.0\n",
                 "sdkBuild": b"25A352\n", "sdkPath": b"/Applications/Xcode_26.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n"}
        self.assertEqual(MODULE.normal_toolchain(tools)["sdkVersion"], "26.0")
        MODULE.normal_toolchain(dict(tools, sdkPath=tools["sdkPath"].replace(b"Xcode_26.0.app", b"Xcode.app").replace(b"MacOSX26.0.sdk", b"MacOSX.sdk")))
        for key, value in (("xcode", b"Xcode 25.0\nBuild version 1A\n"), ("sdkVersion", b"26.0\nextra"),
                           ("sdkBuild", b"private value"), ("sdkPath", tools["sdkPath"].replace(b"SDKs/", b"SDKs/../SDKs/")),
                           ("sdkPath", b"/private/arbitrary/SDK.sdk\n"), ("xcode", b"x" * 513)):
            with self.subTest(tool=key), self.assertRaises((MODULE.Refused, UnicodeError)):
                MODULE.normal_toolchain(dict(tools, **{key: value}))
        source = "a" * 40
        environment = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", USER="runner", LOGNAME="runner",
            TMPDIR=temporary, LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8", TZ="UTC", DEVELOPER_DIR=MODULE.DEVELOPER,
            TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB="github-hosted-macos26-arm64",
            TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=source, TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=source)
        account = SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="runner", pw_dir="/Users/runner")
        root = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        with ExitStack() as stack:
            for context in (
                patch.dict(sys.modules, {"resource": SimpleNamespace(RLIMIT_FSIZE=1, getrlimit=lambda _: (32 * 1024**3,) * 2),
                                         "pwd": SimpleNamespace(getpwuid=lambda _: account)}),
                patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.platform, "machine", return_value="arm64"),
                patch.object(MODULE.platform, "mac_ver", return_value=("26.0", (), "arm64")),
                patch.object(MODULE, "__file__", str(root / "desktop/tools/macos_normal_ui_runner.py")),
                patch.object(MODULE.Path, "cwd", return_value=root), patch.object(MODULE.os, "environ", dict(environment)),
                patch.object(MODULE.os, "getuid", return_value=501), patch.object(MODULE.os, "geteuid", return_value=501),
                patch.object(MODULE.os, "getgid", return_value=20), patch.object(MODULE.os, "getegid", return_value=20),
                patch.object(MODULE.os, "stat", return_value=SimpleNamespace(st_uid=501)),
            ):
                stack.enter_context(context)
            self.assertEqual(MODULE.normal_context(build), (root, source, environment, (32 * 1024**3,) * 2))
            for target_value, machine, marker in targets:
                selected_environment = dict(environment, TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=marker)
                with patch.object(MODULE.platform, "machine", return_value=machine), \
                        patch.dict(MODULE.os.environ, selected_environment, clear=True):
                    for request in requests[target_value]:
                        limit = 32 * 1024**3 if request["phase"] == "build" else 1024**3
                        with patch.object(sys.modules["resource"], "getrlimit", return_value=(limit, limit)):
                            self.assertEqual(MODULE.normal_context(request),
                                             (root, source, selected_environment, (limit, limit)))
                            other_machine = "x86_64" if machine == "arm64" else "arm64"
                            with patch.object(MODULE.platform, "machine", return_value=other_machine), self.assertRaises(MODULE.Refused):
                                MODULE.normal_context(request)
                            with patch.dict(MODULE.os.environ, {"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-" + other_machine}), \
                                    self.assertRaises(MODULE.Refused):
                                MODULE.normal_context(request)
                            with self.assertRaises(MODULE.Refused):
                                MODULE.normal_context(dict(request, target="unsupported"))
            for key in ("PATH", "HOME", "LANG", "DEVELOPER_DIR", "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB",
                        "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE"):
                with self.subTest(environment=key), patch.dict(MODULE.os.environ, {key: "not-admitted"}), self.assertRaises(MODULE.Refused):
                    MODULE.normal_context(build)
            with patch.object(MODULE.os, "geteuid", return_value=502), self.assertRaises(MODULE.Refused):
                MODULE.normal_context(build)
        # Actual Python handoffs, with only inert original/IO doubles. This is
        # target propagation and first-return DATA, never native/UI evidence.
        for target_value, machine, _ in targets:
            for request in requests[target_value]:
                for status in (0, 65):
                    returned = []
                    def fixed_call(role, arguments, timeout, output_limit=1024 * 1024):
                        body = tools[role[len("normal-toolchain-"):]] if role.startswith("normal-toolchain-") else b"inert original"
                        value = subprocess.CompletedProcess(arguments, 0 if role.startswith("normal-toolchain-") else status, body, b"")
                        returned.append((role, value, timeout, output_limit))
                        return value
                    phase = SimpleNamespace(call=fixed_call, records=[],
                        clock=SimpleNamespace(check=lambda: None, before_publication=lambda: {}))
                    with self.subTest(target=target_value, phase=request["phase"], status=status), \
                            patch.object(MODULE, "normal_source_state", return_value={"inert": "source"}) as source_check, \
                            patch.object(MODULE, "exclusive_output") as publication, \
                            patch.object(MODULE.os.path, "lexists", return_value=False), \
                            patch.object(MODULE.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=501)), \
                            patch.object(MODULE.os, "getuid", return_value=501), \
                            patch.object(MODULE, "RunnerProducts") as products_type:
                        products = products_type.return_value.__enter__.return_value
                        products_type.return_value.__exit__.return_value = False
                        products.products = build["derived"] / "Build/Products"
                        products.manifest = "fixed.xctestrun"
                        products.admit.return_value = {"scope": "inert-products-not-native-authority"}
                        limit = 32 * 1024**3 if request["phase"] == "build" else 1024**3
                        actual = MODULE.execute_normal_phase(phase, request, source, (limit, limit))
                        self.assertIs(actual, returned[-1][1])
                        self.assertEqual(actual.returncode, status)
                        facts = json.loads(publication.call_args.args[1])
                        self.assertEqual(facts["target"], target_value)
                        self.assertEqual(source_check.call_count, 2)
                        if request["phase"] == "build":
                            expected = list(arm_build)
                            expected[expected.index("-destination") + 1] = ("platform=macOS" if machine == "x86_64"
                                else "platform=macOS,arch=" + machine)
                            if machine == "x86_64": expected.append("ARCHS=x86_64")
                            self.assertEqual(actual.args, expected)
                            self.assertEqual(returned[-1][2], 240)
                            products_type.assert_not_called()
                        elif request["phase"] == "summary":
                            self.assertEqual(actual.args, ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary",
                                "--path", str(normal / "test.xcresult"), "--compact"])
                            self.assertEqual(returned[-1][2:], (30, 262144))
                            products_type.assert_not_called()
                        else:
                            self.assertEqual(actual.args, ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun",
                                str(products.products / products.manifest), "-destination", "platform=macOS,arch=" + machine,
                                "-destination-timeout", "15", "-resultBundlePath", str(normal / "test.xcresult"),
                                "-only-testing:" + MODULE.CLASS + "testLaunchCancelAndQuit", "-parallel-testing-enabled", "NO",
                                "-test-timeouts-enabled", "YES", "-default-test-execution-time-allowance", "60",
                                "-maximum-test-execution-time-allowance", "60", "-disableAutomaticPackageResolution"])
                            self.assertEqual(returned[-1][2], 180)
                            products.admit.assert_called_once_with(fixed_call)
                            self.assertEqual(products.check.call_count, 2)
                            products_type.return_value.__exit__.assert_called_once_with(None, None, None)
        argv = ["/usr/bin/xcodebuild", "-version"]
        original = subprocess.CompletedProcess(argv, 65, b"ordinary original", b"ordinary stderr")
        self.assertIs(MODULE.original_command(original, argv, 4096), original)
        for changed in (SimpleNamespace(args=argv, returncode=0, stdout=b"", stderr=b""),
                        subprocess.CompletedProcess(tuple(argv), 0, b"", b""),
                        subprocess.CompletedProcess(argv, True, b"", b""),
                        subprocess.CompletedProcess(argv, -1, b"", b""),
                        subprocess.CompletedProcess(argv, 0, "text", b""),
                        subprocess.CompletedProcess(argv, 0, b"x" * 4096, b"x")):
            with self.assertRaises(MODULE.Refused):
                MODULE.original_command(changed, argv, 4096)
        calls = []
        def fake_owned(arguments, **kwargs):
            calls.append((arguments, kwargs))
            return original
        phase = MODULE.NormalPhase(SimpleNamespace(run_owned=fake_owned), environment, root,
                                   MODULE.PhaseClock(90, now=lambda: 0))
        self.assertIs(phase.call("normal-toolchain-xcode", argv, 15, 4096), original)
        self.assertEqual(calls, [(argv, dict(environ=environment, cwd=root, timeout=15, capture=True, text=False, output_limit=4096))])
        self.assertEqual(phase.records[0]["argvSha256"], MODULE.sha(MODULE.encoded(argv)))

        # Closed engineering profile DATA only. Ordinary/packaged routing is
        # still exercised above; no test here launches an app or compiler.
        engineering_work = Path("/Users/runner/work/_temp/mrk-macos-engineering-ui.ABCDef12")
        engineering_tmp = str(engineering_work / "normal-ui/tmp") + "/"
        engineering_requests = {}
        for mode, seconds, cap in (("build", 450, 240), ("test", 345, 180), ("summary", 90, 30)):
            arguments = ["--engineering-main-" + mode, "--work", str(engineering_work)]
            request = MODULE.engineering_request(arguments, engineering_tmp)
            engineering_requests[mode] = request
            self.assertEqual((request["phase"], request["phaseSeconds"], request["timeout"], request["target"]),
                             (mode, seconds, cap, "aarch64-apple-darwin"))
            self.assertEqual(request["work"], engineering_work)
            self.assertEqual(request["derived"], engineering_work / "normal-ui/DerivedData")
            self.assertEqual(request["methods"], (MODULE.ENGINEERING_METHOD,) if mode == "test" else ())
            with self.assertRaises(MODULE.Refused): MODULE.normal_request(arguments, engineering_tmp)
            for changed in (arguments[1:], arguments + ["extra"], ["--target", MODULE.INTEL_TARGET] + arguments,
                            [arguments[0], "--work", str(engineering_work) + "/"],
                            [arguments[0], "--work", str(engineering_work).replace("engineering-ui.", "installed.")],
                            ["--normal-" + mode, *arguments[1:]]):
                with self.subTest(engineering_arguments=changed), self.assertRaises(MODULE.Refused):
                    MODULE.engineering_request(changed, engineering_tmp)
            with self.assertRaises(MODULE.Refused): MODULE.engineering_request(arguments, temporary)
        selected_method = "MRKNormalAppUITests/NormalAppUITests/testEngineeringMainCatalogueAndQuit"
        self.assertEqual(MODULE.ENGINEERING_METHOD, selected_method)
        self.assertEqual(MODULE.ENGINEERING_MAIN_BYTES, 256 * 1024 * 1024)
        expected_arguments = ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", "fixed.xctestrun",
            "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15", "-resultBundlePath", "fixed.xcresult",
            "-only-testing:" + selected_method, "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
            "-default-test-execution-time-allowance", "60", "-maximum-test-execution-time-allowance", "60",
            "-disableAutomaticPackageResolution"]
        self.assertEqual(MODULE.xcode_test_arguments(Path("fixed.xctestrun"), Path("fixed.xcresult"),
                         (selected_method,), 60, engineering=True), expected_arguments)
        for selected, allowance, target_value, enabled in (((MODULE.PACKAGED_METHOD,), 60, MODULE.ARM_TARGET, True),
                ((selected_method,), 300, MODULE.ARM_TARGET, True), ((selected_method,), 60, MODULE.INTEL_TARGET, True),
                ((selected_method,), 60, MODULE.ARM_TARGET, False), ((selected_method,), 60, MODULE.ARM_TARGET, 1)):
            with self.assertRaises(MODULE.Refused):
                MODULE.xcode_test_arguments(Path("fixed.xctestrun"), Path("fixed.xcresult"), selected,
                                            allowance, target=target_value, engineering=enabled)
        with patch.object(MODULE, "RunnerProducts") as products_type:
            with self.assertRaises(MODULE.Refused):
                MODULE.run_admitted_test(lambda *_: self.fail("mixed scope dispatched"), Path("inert"), Path("inert-result"),
                                         (selected_method,), 60, 180, target=MODULE.INTEL_TARGET, engineering=True)
            products_type.assert_not_called()

        binding = dict(sourceSha="a" * 40, sourceTree="b" * 40,
            workflowPath=".github/workflows/desktop-macos-engineering-ui.yml", workflowSha="a" * 40,
            workflowRef="mobile-release-kit/mobile-release-kit/.github/workflows/desktop-macos-engineering-ui.yml@refs/heads/verify/desktop-macos-engineering-ui",
            workflowSha256="c" * 64, runId="123", attempt="1", engineeringWork=str(engineering_work))
        rust = dict(release="1.98.1", commitHash="48a229ceaefd4985c50990b14116b6d856af0985", target="aarch64-apple-darwin")
        compiled = dict(relativePath="target/engineering-main/mobile-release-kit-desktop", bytes=17, sha256="d" * 64)
        checks = {"acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
                  "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only")}
        for mode in ("acquire", "compile"):
            receipt = dict(schemaVersion=1, scope="desktop-macos-engineering-ui-compile-only-v1", phase=mode,
                status="passed", **binding, platform="macos", rust=rust, node="v24.20.0",
                checks=[dict(check=name, exitCode=0) for name in checks[mode]])
            if mode == "compile": receipt["compiledMain"] = compiled
            MODULE.engineering_compile_receipt(receipt, binding, mode, compiled=compiled if mode == "compile" else None)
            for key, changed_value in (("schemaVersion", True), ("status", "failed"), ("sourceTree", "e" * 40),
                    ("engineeringWork", str(engineering_work) + "-foreign"), ("checks", receipt["checks"][:-1]),
                    ("checks", [*receipt["checks"], receipt["checks"][0]]), ("node", "v0.0.0"),
                    ("rust", dict(rust, target="x86_64-apple-darwin"))):
                with self.subTest(engineering_receipt=(mode, key)), self.assertRaises(MODULE.Refused):
                    MODULE.engineering_compile_receipt(dict(receipt, **{key: changed_value}), binding, mode,
                                                       compiled=compiled if mode == "compile" else None)
            for key in tuple(receipt):
                changed = dict(receipt); del changed[key]
                with self.assertRaises(MODULE.Refused):
                    MODULE.engineering_compile_receipt(changed, binding, mode, compiled=compiled if mode == "compile" else None)
            with self.assertRaises(MODULE.Refused):
                MODULE.engineering_compile_receipt(dict(receipt, productReady=True), binding, mode,
                                                   compiled=compiled if mode == "compile" else None)
            if mode == "compile":
                for key, value in (("bytes", True), ("bytes", 0), ("bytes", 256 * 1024 * 1024 + 1),
                        ("relativePath", "target/aarch64-apple-darwin/debug/mobile-release-kit-desktop"),
                        ("sha256", "not-a-digest")):
                    wrong = dict(compiled, **{key: value})
                    with self.assertRaises(MODULE.Refused):
                        MODULE.engineering_compile_receipt(dict(receipt, compiledMain=wrong), binding, mode, compiled=wrong)

        marker = ("MRK_MACOS_ENGINEERING_MAIN_UI=mainRequest=1;completion=1;body=1;handoff=1;mainIdentity=1;catalogueGuide=1;"
                  "projectSelected=0;editCapability=unavailable;originalTerminated=1;failureCleanup=0;caseDeadlineMet=1;"
                  "cleanExitStatus=unavailable;allWorkerFinality=unavailable")
        case = "-[MRKNormalAppUITests.NormalAppUITests testEngineeringMainCatalogueAndQuit]"
        output = ("Test Case '" + case + "' started.\n" + marker + "\nTest Case '" + case + "' passed (1.000 seconds).\n").encode()
        summary = dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0)
        value = MODULE.engineering_ui_result(output, json.dumps(summary).encode())
        self.assertEqual(value["testIdentifier"], selected_method)
        self.assertEqual(value["testCounts"], summary)
        self.assertIs(value["sameOriginalNormalQuitObserved"], True)
        self.assertIsNone(value["cleanExitStatus"])
        self.assertEqual(value["allWorkerFinality"], "not-established")
        self.assertFalse(value["fullUIQualified"])
        self.assertFalse(value["productReady"])
        for changed in (b"", output + output, output.replace(marker.encode(), b""),
                output.replace(b"catalogueGuide=1", b"catalogueGuide=0"), output.replace(b"originalTerminated=1", b"originalTerminated=0"),
                output.replace(b"testEngineeringMainCatalogueAndQuit", b"testLaunchCancelAndQuit"),
                output.replace(b" passed ", b" failed "), output.replace(b"failureCleanup=0", b"failureCleanup=1"),
                output.replace(marker.encode(), marker.encode() + b"\n" + marker.encode()),
                (marker + "\n").encode() + output.replace((marker + "\n").encode(), b""),
                output + b"MRK_MACOS_UI_FAILURE_CLEANUP=attempted\n", output + b"MRK_MACOS_NORMAL_UI=not-authority\n"):
            with self.assertRaises(MODULE.Refused): MODULE.engineering_ui_result(changed, json.dumps(summary).encode())
        for key in summary:
            for invalid in (True, summary[key] + 1):
                with self.assertRaises(MODULE.Refused):
                    MODULE.engineering_ui_result(output, json.dumps(dict(summary, **{key: invalid})).encode())
        with self.assertRaises(MODULE.Refused):
            MODULE.engineering_ui_result(output, b'{"totalTestCount":1,"passedTests":1,"passedTests":1}')

        # Exercise actual engineering_context with inert directory originals;
        # only this module's os binding is replaced, never a real syscall here.
        compiler_root = Path("/Users/runner/work/_temp/mrk-desktop-foundation-ABCDef12")
        engine_environment = dict(environment, TMPDIR=engineering_tmp,
            GITHUB_SHA=source, GITHUB_WORKSPACE=str(root), GITHUB_REPOSITORY="mobile-release-kit/mobile-release-kit",
            GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/verify/desktop-macos-engineering-ui", GITHUB_WORKFLOW_SHA=source,
            GITHUB_WORKFLOW_REF=binding["workflowRef"], GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
            MRK_MACOS_WORK=str(engineering_work), MRK_DESKTOP_CI_ROOT=str(compiler_root),
            MUST_NOT_INHERIT="inert private environment sentinel")
        observed = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700, st_uid=501, st_gid=20,
                                   st_nlink=2, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        closed_directories = []
        inert_os = SimpleNamespace(environ=engine_environment, getuid=lambda: 501, geteuid=lambda: 501,
            getgid=lambda: 20, getegid=lambda: 20, stat=lambda *_a, **_k: observed,
            fstat=lambda _fd: observed, close=closed_directories.append)
        with ExitStack() as stack:
            for context in (patch.dict(sys.modules, {"resource": SimpleNamespace(RLIMIT_FSIZE=1, getrlimit=lambda _: (32 * 1024**3,) * 2),
                                                     "pwd": SimpleNamespace(getpwuid=lambda _: account)}),
                    patch.object(MODULE, "os", inert_os), patch.object(MODULE.sys, "platform", "darwin"),
                    patch.object(MODULE.platform, "machine", return_value="arm64"),
                    patch.object(MODULE.platform, "mac_ver", return_value=("26.0", (), "arm64")),
                    patch.object(MODULE, "__file__", str(root / "desktop/tools/macos_normal_ui_runner.py")),
                    patch.object(MODULE.Path, "cwd", return_value=root), patch.object(MODULE, "open_directory", return_value=77)):
                stack.enter_context(context)
            request = dict(engineering_requests["build"])
            actual_root, actual_source, clean, limits = MODULE.engineering_context(request)
            self.assertEqual((actual_root, actual_source, limits), (root, source, (32 * 1024**3,) * 2))
            self.assertEqual(request["compiler"], compiler_root)
            self.assertEqual(clean, dict(environment, TMPDIR=engineering_tmp, TEST_RUNNER_MRK_ENGINEERING_UI_WORK=str(engineering_work)))
            self.assertEqual(closed_directories, [77, 77])
            for key in ("GITHUB_SHA", "GITHUB_WORKSPACE", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
                        "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "MRK_MACOS_WORK", "MRK_DESKTOP_CI_ROOT", "PATH"):
                original_value = engine_environment[key]
                try:
                    engine_environment[key] = "not-admitted"
                    with self.subTest(engineering_context=key), self.assertRaises(MODULE.Refused):
                        MODULE.engineering_context(dict(engineering_requests["build"]))
                finally:
                    engine_environment[key] = original_value
            with patch.object(MODULE.platform, "machine", return_value="x86_64"), self.assertRaises(MODULE.Refused):
                MODULE.engineering_context(dict(engineering_requests["build"]))
            with self.assertRaises(MODULE.Refused):
                MODULE.engineering_context(dict(engineering_requests["build"], target=MODULE.INTEL_TARGET))

        # Main publishes only existing closed exception/command facts, including
        # context refusals after a parsed fixed CLI. Native output stays PRIVATE.
        private = b"PRIVATE-engineering-diagnostic-sentinel"
        for fault in (None, "context", "loader", "exception", "native", "query", "malformed"):
            with self.subTest(engineering_main_failure=fault), ExitStack() as stack:
                published, output, errors = [], io.BytesIO(), io.BytesIO()
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                native = subprocess.CompletedProcess(["fixed-original"], 65 if fault in ("native", "query") else 0, private, b"private stderr")
                owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError,
                                        run_owned=lambda *_a, **_k: native)
                def execute(phase, _request, _source, _limits):
                    if fault == "exception": raise TypeError(private.decode())
                    original = phase.call("one-admitted-ui-test", ["fixed-original"], 180)
                    if fault == "query": raise MODULE.NativeQueryFailure(original)
                    return original
                arguments = ["helper", "--engineering-main-build", "--work", str(engineering_work)]
                if fault == "malformed": arguments.append("extra")
                for context in (
                    patch.object(MODULE.sys, "argv", arguments),
                    patch.object(MODULE.os, "environ", {"TMPDIR": engineering_tmp}),
                    patch.object(MODULE.time, "monotonic_ns", return_value=0),
                    patch.object(MODULE, "engineering_context", side_effect=ValueError(private.decode()) if fault == "context" else None,
                                 return_value=(Path("/inert"), "a" * 40, {}, (32 * 1024**3,) * 2)),
                    patch.object(MODULE, "load_normal_owner", side_effect=OSError(private.decode()) if fault == "loader" else None, return_value=owner),
                    patch.object(MODULE, "execute_engineering_phase", side_effect=execute),
                    patch.object(MODULE, "publish_engineering_failure", side_effect=lambda request, value: published.append((request, value))),
                    patch.object(MODULE, "execute_normal_phase", side_effect=AssertionError("ordinary route selected")),
                    patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors)),
                ): stack.enter_context(context)
                self.assertEqual(MODULE.main(), 0 if fault is None else 65 if fault in ("native", "query") else 1)
                if fault in (None, "malformed"):
                    self.assertEqual(published, [])
                else:
                    self.assertEqual(len(published), 1)
                    request, failure = published[0]
                    self.assertEqual(request["work"], engineering_work)
                    expected_fields = {"schemaVersion", "scope", "productReady", "error", "stage", "exceptionClass",
                                       "sourceFrames", "commands", "ownerFailure", "unknownStateRetained"}
                    if fault in ("native", "query"):
                        expected_fields.add("nativeDiagnostics")
                    self.assertEqual(set(failure), expected_fields)
                    self.assertEqual(failure["scope"], "generated-ui-runner-refused")
                    self.assertFalse(failure["productReady"])
                    self.assertTrue(failure["unknownStateRetained"])
                    self.assertNotIn(private, MODULE.encoded(failure))
                    self.assertNotIn(b"private stderr", MODULE.encoded(failure))
                    if fault in ("native", "query"):
                        self.assertEqual(len(failure["commands"]), 1)
                        self.assertEqual(failure["commands"][0]["returncode"], 65)
                        self.assertEqual(failure["commands"][0]["stdoutSha256"], hashlib.sha256(private).hexdigest())
                        native_diagnostic = failure["nativeDiagnostics"]
                        self.assertEqual(native_diagnostic["scope"], "engineering-main-ui-failure-diagnostic-only")
                        self.assertEqual(native_diagnostic["phase"], "query" if fault == "query" else "build")
                        self.assertEqual(native_diagnostic["originalReturncode"], 65)
                        self.assertFalse(native_diagnostic["markers"]["selectedCaseStarted"])
                        self.assertEqual(output.getvalue(), private)
                    else:
                        self.assertEqual(failure["commands"], [])
                        self.assertEqual(failure["stage"], "context" if fault == "context" else "loader" if fault == "loader" else "execute")
        # Fixed unsigned iOS result grammar. These are inert original-return
        # DATA tests, not a native archive, and do not reimplement core inspection.
        ios_source = "a" * 40
        ios_facts = dict(schemaVersion=1, scope="one-ordinary-local-unsigned-ios-archive", sourceCommit=ios_source,
            operationId="b" * 32, ownerGeneration="c" * 32, savedVersion="1.2.3", savedBuild=7,
            originalEntries=3, originalBytes=1024, inputFiles=9, inputBytes=7264, topLevelDirectories=4,
            archiveDescendantsObserved=False, nativeResultDisplayed=True, outputPostMatched=True,
            originalsClosed=True, normalQuitObserved=True, successBeforeCutoff=True, signed=False,
            ipaExported=False, releaseQualified=False, parentReturncodeRequired=0)
        ios_case = b"-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectUnsignedIOSArchive]"
        def ios_stdout(value):
            return (b"Test Case '" + ios_case + b"' started.\n" + MODULE.ORIGINAL_MARKER.encode() + b"\n"
                    + MODULE.IOS_UNSIGNED_PREFIX + MODULE.encoded(value) + b"\nTest Case '" + ios_case
                    + b"' passed (12.000 seconds).\n")
        ios_output = ios_stdout(ios_facts)
        self.assertIs(MODULE.ios_unsigned_facts(ios_facts, source=ios_source), ios_facts)
        self.assertEqual(MODULE.ios_unsigned_marker(ios_output, source=ios_source), ios_facts)
        for key, value in ios_facts.items():
            bad = dict(ios_facts)
            del bad[key]
            with self.subTest(ios_missing=key), self.assertRaises(MODULE.Refused):
                MODULE.ios_unsigned_facts(bad, source=ios_source)
            bad[key] = not value if type(value) is bool else True if type(value) is int else "wrong"
            with self.subTest(ios_changed=key), self.assertRaises(MODULE.Refused):
                MODULE.ios_unsigned_facts(bad, source=ios_source)
        for changed in (dict(ios_facts, extra=True), dict(ios_facts, originalEntries=0),
                        dict(ios_facts, originalEntries=100001), dict(ios_facts, originalBytes=0),
                        dict(ios_facts, originalBytes=(8 << 30) + 1)):
            with self.assertRaises(MODULE.Refused): MODULE.ios_unsigned_facts(changed, source=ios_source)
        self.assertEqual(MODULE.ios_unsigned_facts(dict(ios_facts, originalEntries=100000, originalBytes=8 << 30),
                                                  source=ios_source)["originalBytes"], 8 << 30)
        for changed in (b"", b"x" * 1048577, ios_output + ios_output,
                ios_output.replace(MODULE.ORIGINAL_MARKER.encode(), b""),
                ios_output.replace(MODULE.IOS_UNSIGNED_PREFIX, b"not-the-marker="),
                ios_output.replace(b" passed ", b" failed "),
                ios_output.replace(ios_case, b"-[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit]"),
                ios_output.replace(MODULE.encoded(ios_facts), json.dumps(ios_facts).encode()),
                ios_output.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                ios_output + b"MRK_MACOS_UI_ORIGINAL=unqualified\n",
                ios_output + b"MRK_MACOS_UI_FAILURE_CLEANUP=attempted\n",
                MODULE.IOS_UNSIGNED_PREFIX + MODULE.encoded(ios_facts) + b"\n" + ios_output.replace(
                    MODULE.IOS_UNSIGNED_PREFIX + MODULE.encoded(ios_facts) + b"\n", b"")):
            with self.assertRaises(MODULE.Refused): MODULE.ios_unsigned_marker(changed, source=ios_source)
        with self.assertRaises(MODULE.Refused): MODULE.ios_unsigned_marker(ios_output, source="d" * 40)
        ios_counts = dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0)
        self.assertEqual(MODULE.ios_unsigned_summary(MODULE.encoded(ios_counts)), ios_counts)
        for key, value in ios_counts.items():
            for wrong in (True, value + 1):
                with self.assertRaises(MODULE.Refused):
                    MODULE.ios_unsigned_summary(MODULE.encoded(dict(ios_counts, **{key: wrong})))
        with self.assertRaises(MODULE.Refused):
            MODULE.ios_unsigned_summary(b'{"totalTestCount":1,"passedTests":1,"passedTests":1}')

        ios_temporary = "/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/tmp/"
        ios_requests = {name: MODULE.normal_request(["--normal-ios-unsigned-archive-" + name], ios_temporary)
                        for name in ("test", "summary")}
        ios_limits = (1024**3,) * 2
        ios_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=501)
        ios_inert_os = SimpleNamespace(path=SimpleNamespace(lexists=lambda _: False),
                                      stat=lambda *_a, **_k: ios_stat, getuid=lambda: 501)
        # The actual NormalPhase/run_admitted_test/executor run against a finite
        # generated-product adapter and inert original owner. No filesystem or
        # process is used; every adapted product close is still observed.
        for mode, code, fault in (("test", 0, None), ("summary", 0, None), ("test", 65, None),
                ("summary", 75, None), ("test", 0, "marker"), ("summary", 0, "counts"),
                ("test", 0, "post"), ("test", 0, "close"), ("test", 65, "close"),
                ("test", 0, "source"), ("test", 0, "publication")):
            with self.subTest(ios_execute=(mode, code, fault)), ExitStack() as stack:
                events, originals, publications = [], [], []
                request = ios_requests[mode]
                class IOSProducts:
                    def __init__(self, derived):
                        self.products, self.manifest = Path("/inert-products"), "fixed.xctestrun"
                        self.checks = 0
                    def __enter__(self): events.append("entered"); return self
                    def admit(self, _call): events.append("admitted"); return {"generatedRunner": True}
                    def check(self):
                        self.checks += 1; events.append("post")
                        if fault == "post" and self.checks == 2: raise OSError("inert product POST refusal")
                    def __exit__(self, _kind, _error, _tb):
                        events.append("closed")
                        if fault == "close": raise OSError("inert consuming product close refusal")
                        return False
                def ios_owned(arguments, **kwargs):
                    body = ios_output if mode == "test" else MODULE.encoded(ios_counts)
                    if fault in ("marker", "counts"): body = b"{}"
                    value = subprocess.CompletedProcess(list(arguments), code, body, b"")
                    originals.append((value, kwargs)); return value
                def ios_source_state(_phase, _source):
                    events.append("source")
                    return {"source": "changed" if fault == "source" and events.count("source") == 2 else ios_source}
                def ios_publish(path, body, limit):
                    if fault == "publication": raise OSError("inert receipt consuming close refusal")
                    publications.append((path, MODULE.document(body), limit))
                for context in (patch.object(MODULE, "os", ios_inert_os), patch.object(MODULE, "RunnerProducts", IOSProducts),
                        patch.object(MODULE, "normal_source_state", side_effect=ios_source_state),
                        patch.object(MODULE, "exclusive_output", side_effect=ios_publish)):
                    stack.enter_context(context)
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=ios_owned), {}, Path("/inert-source"),
                    MODULE.PhaseClock(request["phaseSeconds"], now=lambda: 0), retain_nonzero=True)
                if fault is not None:
                    with self.assertRaises((MODULE.Refused, OSError)):
                        MODULE.execute_normal_phase(phase, request, ios_source, ios_limits)
                    self.assertEqual(publications, [])
                else:
                    original = MODULE.execute_normal_phase(phase, request, ios_source, ios_limits)
                    self.assertIs(original, originals[0][0])
                    self.assertEqual(len(publications), 2 if mode == "test" and code == 0 else 1)
                    receipt = publications[0][1]
                    self.assertTrue(receipt["sourcePrePostMatched"])
                    self.assertEqual(receipt["commands"][0]["returncode"], code)
                    self.assertEqual(receipt["fileLimitBytes"], list(ios_limits))
                    if mode == "test" and code == 0:
                        self.assertEqual(receipt["iosUnsignedObservation"], ios_facts)
                        self.assertTrue(receipt["originalProductsPrePostMatched"])
                        self.assertTrue(receipt["originalClosesCompleted"])
                        self.assertEqual(publications[1], (request["derived"].parent / "ios-unsigned-archive.facts.json", ios_facts, 16384))
                    elif mode == "summary" and code == 0:
                        self.assertEqual(receipt["iosUnsignedTestCounts"], ios_counts)
                    else:
                        self.assertNotIn("iosUnsignedObservation", receipt)
                        self.assertNotIn("iosUnsignedTestCounts", receipt)
                self.assertEqual(len(originals), 1)
                self.assertEqual((originals[0][1]["timeout"], originals[0][1]["output_limit"]),
                                 (1020, 1048576) if mode == "test" else (30, 262144))
                self.assertEqual(events.count("closed"), 1 if mode == "test" else 0)
                self.assertIs(phase.first_nonzero, originals[0][0] if code else None)

        # Real main + real executor + real NormalPhase retain the FIRST admitted
        # return before a late clock, receipt-close, or interrupted diagnostic.
        # Both standard streams are scoped and restored; no private text escapes.
        actual_execute = MODULE.execute_normal_phase
        for mode, code, fault in (("test", 0, None), ("summary", 0, None), ("test", 65, None),
                ("test", 0, "late"), ("test", 65, "late"), ("test", 0, "close"), ("test", 65, "close"),
                ("test", 65, "diagnostic-interrupt"), ("test", 65, "diagnostic-exit"),
                ("summary", 75, "diagnostic-interrupt"), ("test", 0, "context")):
            with self.subTest(ios_main=(mode, code, fault)), ExitStack() as stack:
                tick, phases, originals, published, events = [0], [], [], [], []
                output, errors = io.BytesIO(), io.BytesIO()
                request = ios_requests[mode]
                class IOSMainProducts:
                    def __init__(self, _derived): self.products, self.manifest = Path("/inert-products"), "fixed.xctestrun"
                    def __enter__(self): return self
                    def admit(self, _call): return {"generatedRunner": True}
                    def check(self): pass
                    def __exit__(self, _kind, _error, _tb): events.append("closed"); return False
                def ios_main_owned(arguments, **kwargs):
                    body = ios_output if mode == "test" else MODULE.encoded(ios_counts)
                    value = subprocess.CompletedProcess(list(arguments), code, body, b"private inert diagnostic")
                    originals.append(value)
                    if fault == "late": tick[0] = request["phaseSeconds"] * 10**9
                    return value
                def ios_main_execute(phase, *args): phases.append(phase); return actual_execute(phase, *args)
                def ios_main_publish(path, body, limit):
                    if fault == "close" and path.name.endswith("admission.json"):
                        raise OSError("inert consuming publication close refusal")
                    published.append((path, MODULE.document(body), limit))
                def ios_main_diagnostic(*_a, **_k):
                    if fault == "diagnostic-interrupt": raise KeyboardInterrupt()
                    if fault == "diagnostic-exit": raise SystemExit(99)
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                owner = SimpleNamespace(run_owned=ios_main_owned, ProcessError=OSError, ProcessInterrupted=InterruptedError)
                main_os = SimpleNamespace(environ={"TMPDIR": ios_temporary}, path=ios_inert_os.path,
                                          stat=ios_inert_os.stat, getuid=ios_inert_os.getuid)
                for context in (patch.object(MODULE.sys, "argv", ["helper", "--normal-ios-unsigned-archive-" + mode]),
                        patch.object(MODULE, "os", main_os), patch.object(MODULE.time, "monotonic_ns", side_effect=lambda: tick[0]),
                        patch.object(MODULE, "normal_context", side_effect=MODULE.Refused("inert context refusal") if fault == "context" else None,
                                     return_value=(Path("/inert-source"), ios_source, {}, ios_limits)),
                        patch.object(MODULE, "load_normal_owner", return_value=owner),
                        patch.object(MODULE, "RunnerProducts", IOSMainProducts),
                        patch.object(MODULE, "normal_source_state", return_value={"source": ios_source}),
                        patch.object(MODULE, "execute_normal_phase", side_effect=ios_main_execute),
                        patch.object(MODULE, "exclusive_output", side_effect=ios_main_publish),
                        patch.object(MODULE, "publish_failure_diagnostics", side_effect=ios_main_diagnostic),
                        patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors))):
                    stack.enter_context(context)
                self.assertEqual(MODULE.main(), code if code else 0 if fault is None else 1)
                if fault == "context":
                    self.assertEqual((originals, phases, published, events), ([], [], [], []))
                    continue
                self.assertEqual(len(originals), 1)
                self.assertIs(phases[0].first_nonzero, originals[0] if code else None)
                self.assertEqual(events.count("closed"), 1 if mode == "test" else 0)
                if fault is not None:
                    self.assertTrue(phases[0].clock.failed)
                    self.assertFalse(any(path.name == "ios-unsigned-archive.facts.json" for path, _, _ in published))
                    self.assertTrue(all(b"private inert diagnostic" not in MODULE.encoded(value) for _, value, _ in published))

    def test_removal_ui_clock_observation_and_finality(self):
        tick = [0]
        clock = MODULE.RemovalPhaseClock(500 * 10**9, now=lambda: tick[0])
        self.assertEqual(clock.deadline, 500 * 10**9)
        self.assertEqual(MODULE.RemovalPhaseClock(900 * 10**9, now=lambda: 0).deadline, 585 * 10**9)
        tick[0] = 499 * 10**9
        with self.assertRaises(MODULE.Refused): clock.allowance(420)
        tick[0] = 0
        with self.assertRaises(MODULE.Refused): clock.check()
        for endpoint in (True, 0, -1, 1.5):
            with self.assertRaises(MODULE.Refused): MODULE.RemovalPhaseClock(endpoint, now=lambda: 0)

        def output(case):
            method = MODULE.REMOVAL_METHODS[case]
            selected = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
            marker = ("MRK_MACOS_REMOVAL_UI=v1;case=" + case + ";cancelObserved="
                      + ("1" if case == "ordinary" else "0")
                      + ";continueObserved=1;originalTerminated=1;gateClosed=1;gateFree=unqualified;normalQuit=0;channelClosed=1")
            stdout = ("Test Case '" + selected + "' started.\n" + marker
                      + "\nTest Case '" + selected + "' passed (1.0 seconds).\n").encode()
            summary = MODULE.encoded(dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0))
            tests = MODULE.encoded(dict(testNodes=[dict(name=MODULE.TARGET, nodeType="Test Suite", children=[
                dict(name=method + "()", nodeType="Test Case", nodeIdentifier="NormalAppUITests/" + method + "()", result="Passed")])]))
            return stdout, summary, tests

        for case in ("ordinary", "abrupt"):
            stdout, summary, tests = output(case)
            facts = MODULE.removal_ui_result(stdout, summary, tests, case)
            self.assertIs(facts["normalQuit"], False)
            self.assertEqual(facts["gateFree"], "unqualified")
            self.assertIs(facts["productReady"], False)
            for body in (stdout + stdout, stdout.replace(b"originalTerminated=1", b"originalTerminated=0"),
                         stdout.replace(b"gateFree=unqualified", b"gateFree=1"),
                         stdout.replace(b"normalQuit=0", b"normalQuit=1"),
                         stdout.replace(b"channelClosed=1", b"channelClosed=0"),
                         stdout + MODULE.ORIGINAL_MARKER.encode(), stdout.replace(b" passed ", b" skipped ")):
                with self.assertRaises(MODULE.Refused): MODULE.removal_ui_result(body, summary, tests, case)
            for key in ("totalTestCount", "passedTests", "skippedTests"):
                bad = json.loads(summary); bad[key] += 1
                with self.assertRaises(MODULE.Refused):
                    MODULE.removal_ui_result(stdout, MODULE.encoded(bad), tests, case)
            with self.assertRaises(MODULE.Refused):
                MODULE.removal_ui_result(stdout, summary, tests, "abrupt" if case == "ordinary" else "ordinary")

        # Explicit context admission reads only supplied environment and actual (mocked) native facts.
        derived = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui/DerivedData")
        channel = derived.parent.parent / ("removal-ui-v1/r-" + "a" * 32)
        source, limit = "a" * 40, (1024**3,) * 2
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner",
            "LOGNAME": "runner", "TMPDIR": str(derived.parent / "tmp") + "/", "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8", "TZ": "UTC", "DEVELOPER_DIR": MODULE.DEVELOPER,
            "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
            "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": source,
            "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": source, MODULE.REMOVAL_CHANNEL_ENV: str(channel)}
        def make_phase(root, env=None, now=lambda: 0):
            return MODULE.NormalPhase(SimpleNamespace(), dict(environment if env is None else env), root,
                MODULE.RemovalPhaseClock(600 * 10**9, now=now), retain_nonzero=True)
        root = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        resource = SimpleNamespace(RLIMIT_FSIZE=1, getrlimit=lambda _: limit)
        with patch.object(MODULE.sys, "platform", "darwin"), patch.object(MODULE.platform, "machine", return_value="arm64"), \
             patch.object(MODULE.platform, "mac_ver", return_value=("26.6", (), "")), patch.object(MODULE, "_removal_resource", resource):
            phase = make_phase(root)
            kwargs = dict(case="ordinary", derived=derived, channel=channel, source=source, file_limit=limit, target=MODULE.ARM_TARGET)
            self.assertEqual(MODULE.removal_phase_context(phase, **kwargs)[1].name, "removal-ordinary-test.xcresult")
            for mutation in (dict(channel=channel.parent / ("r-" + "0" * 32)), dict(channel=Path("/foreign/r-" + "a" * 32)),
                             dict(source="b" * 40), dict(target=MODULE.INTEL_TARGET), dict(file_limit=(-1, -1))):
                with self.assertRaises(MODULE.Refused): MODULE.removal_phase_context(phase, **dict(kwargs, **mutation))
            for mutation in (dict(PATH="/foreign"), dict(UNEXPECTED="value"), {MODULE.REMOVAL_CHANNEL_ENV: str(channel) + "/other"}):
                with self.assertRaises(MODULE.Refused):
                    MODULE.removal_phase_context(make_phase(root, dict(environment, **mutation)), **kwargs)

        # Actual result/receipt descriptors in disposable files; all native calls remain inert.
        for fault in (None, "native-nonzero", "query-nonzero", "result-replaced", "source-changed",
                      "bad-marker", "result-close", "receipt-close", "late-receipt"):
            with self.subTest(removal_finality=fault), tempfile.TemporaryDirectory(prefix="mrk-removal-ui-data-") as temporary:
                normal = Path(temporary); derived = normal / "DerivedData"
                result = normal / "removal-ordinary-test.xcresult"; result.mkdir(mode=0o700)
                stdout, summary, tests = output("ordinary")
                if fault == "bad-marker": stdout = stdout.replace(b"gateClosed=1", b"gateClosed=0")
                original = subprocess.CompletedProcess(["inert-test"], 65 if fault == "native-nonzero" else 0, stdout, b"")
                tick, result_fd, receipt_fd, closed = [0], [None], [None], []
                phase = make_phase(normal, now=lambda: tick[0])
                def query(role, argv, seconds, cap):
                    if fault == "result-replaced" and role == "normal-ui-summary":
                        result.rename(normal / "old-result"); result.mkdir(mode=0o700)
                    return subprocess.CompletedProcess(argv, 66 if fault == "query-nonzero" else 0,
                        summary if role == "normal-ui-summary" else tests, b"")
                phase.call = query
                original_open, original_close = MODULE.os.open, MODULE.os.close
                def opened(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if str(path).endswith(".runner-admission.json"): receipt_fd[0] = fd
                    return fd
                def directory(path):
                    fd = original_open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    result_fd[0] = fd; return fd
                def close(fd):
                    original_close(fd); closed.append(fd)
                    if fault == "result-close" and receipt_fd[0] is None and fd == result_fd[0]: raise OSError("synthetic consumed result close")
                    if receipt_fd[0] is not None and fd == receipt_fd[0]:
                        if fault == "receipt-close": raise OSError("synthetic consumed receipt close")
                        if fault == "late-receipt": tick[0] = 585 * 10**9
                before = {"inert-source": ["fixed"]}
                post = {} if fault == "source-changed" else before
                with patch.object(MODULE, "removal_phase_context", return_value=(MODULE.CLASS + MODULE.REMOVAL_METHODS["ordinary"], result)), \
                     patch.object(MODULE, "normal_source_state", side_effect=[before, post]), \
                     patch.object(MODULE, "output_data_read_build", return_value="b" * 64), \
                     patch.object(MODULE, "run_admitted_test", return_value=(original, {"originalClosesCompleted": True})), \
                     patch.object(MODULE, "open_directory", side_effect=directory), \
                     patch.object(MODULE, "_removal_resource", resource), \
                     patch.object(MODULE.os, "open", side_effect=opened), patch.object(MODULE.os, "close", side_effect=close):
                    kwargs = dict(case="ordinary", derived=derived, channel=channel, source=source, file_limit=limit)
                    if fault is None:
                        returned, facts = MODULE.execute_removal_ui_phase(phase, **kwargs)
                        self.assertIs(returned, original)
                        self.assertEqual(facts["workerJoin"], "pending-caller-original-join")
                        self.assertTrue(phase.clock.finalized)
                    else:
                        with self.assertRaises((MODULE.Refused, MODULE.NativeQueryFailure, OSError)):
                            MODULE.execute_removal_ui_phase(phase, **kwargs)
                        self.assertTrue(phase.clock.failed)
                    with self.assertRaises(MODULE.Refused): MODULE.execute_removal_ui_phase(phase, **kwargs)
                if result_fd[0] is not None:
                    with self.assertRaises(OSError): os.fstat(result_fd[0])
                receipt = result.with_suffix(".runner-admission.json")
                if fault not in (None, "receipt-close", "late-receipt"): self.assertFalse(receipt.exists())
                if fault is None:
                    self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
                    self.assertEqual(json.loads(receipt.read_bytes())["observation"]["gateFree"], "unqualified")


    def test_normal_phase_deadlines_file_limits_source_and_receipt_finality(self):
        for phase, limit in (("build", 32 * 1024**3), ("test", 1024**3), ("summary", 1024**3)):
            self.assertEqual(MODULE.normal_file_limit(phase, (limit, limit)), (limit, limit))
            for actual in ((-1, -1), (limit, -1), [limit, limit], (True, limit), (limit - 1, limit - 1)):
                with self.subTest(phase=phase, actual=actual), self.assertRaises(MODULE.Refused):
                    MODULE.normal_file_limit(phase, actual)
        tick = [0]
        clock = MODULE.PhaseClock(90, now=lambda: tick[0])
        tick[0] = 70 * 1_000_000_000
        self.assertEqual(clock.allowance(30), 7)  # remaining20 - owner3 - publication10
        self.assertEqual(clock.deadline, 90 * 1_000_000_000)
        tick[0] = 77 * 1_000_000_000
        with self.assertRaisesRegex(MODULE.Refused, "no-command-budget"):
            clock.allowance(30)
        tick[0] = 0
        with self.assertRaisesRegex(MODULE.Refused, "terminal"):
            clock.allowance(30)
        for invalid in (-1, True, 0.5, 90 * 1_000_000_000):
            tick = [1]
            clock = MODULE.PhaseClock(90, now=lambda: tick[0], started=0)
            tick[0] = invalid
            with self.assertRaises(MODULE.Refused): clock.check()
            self.assertTrue(clock.failed)
        finished = MODULE.PhaseClock(90, now=lambda: 0)
        finished.finish()
        with self.assertRaisesRegex(MODULE.Refused, "terminal"): finished.allowance(15)
        calls = []
        tick = [0]
        def late_original(argv, **_):
            calls.append(argv); tick[0] = 90 * 1_000_000_000
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        phase = MODULE.NormalPhase(SimpleNamespace(run_owned=late_original), {}, Path("/inert"),
                                   MODULE.PhaseClock(90, now=lambda: tick[0]))
        for _ in range(2):
            with self.assertRaises(MODULE.Refused): phase.call("normal-ui-summary", ["fixed"], 30, 262144)
        self.assertEqual(calls, [["fixed"]])
        # Real SOURCE readers/receipt originals; fake owner returns inert bytes only.
        for fault in (None, "native-nonzero", "query-nonzero", "source-changed", "late-command", "close", "late-close"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-normal-phase-data-") as temporary:
                root = Path(temporary)
                normal = root / "normal-ui"; normal.mkdir(mode=0o700)
                relative_names = ("desktop/tools/macos_normal_ui_runner.py",
                    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift")
                source_rows = []
                for relative in relative_names:
                    path = root / relative; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    body = b"inert source fixture, never imported or compiled\n"; path.write_bytes(body)
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    source_rows.append(b"100644 blob " + blob.encode() + b"\t" + relative.encode() + b"\0")
                tool_values = (b"Xcode 26.0\nBuild version 17A324\n",
                    b"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n",
                    b"26.0\n", b"25A352\n")
                query_values = {tuple(query[2]): body for query, body in zip(MODULE.TOOLCHAIN_QUERIES, tool_values)}
                tick, owned = [0], []
                def owned_fake(argv, **kwargs):
                    owned.append((argv, kwargs))
                    if argv[0] == "/usr/bin/git":
                        return subprocess.CompletedProcess(argv, 0, b"".join(source_rows), b"")
                    if tuple(argv) in query_values:
                        return subprocess.CompletedProcess(argv, 66 if fault == "query-nonzero" else 0, query_values[tuple(argv)], b"")
                    if argv[1] == "build-for-testing":
                        if fault == "source-changed": (root / relative_names[0]).write_bytes(b"changed inert SOURCE\n")
                        if fault == "late-command": tick[0] = 450 * 1_000_000_000
                        return subprocess.CompletedProcess(argv, 65 if fault == "native-nonzero" else 0, b"inert build original\n", b"")
                    self.fail("unexpected fake original route")
                request = MODULE.normal_request(["--normal-build"], str(normal / "tmp") + "/")
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(450, now=lambda: tick[0]))
                receipt_fd, closed = [None], []
                original_open, original_close = os.open, os.close
                def open_original(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if str(path).endswith("/build.command-admission.json"): receipt_fd[0] = fd
                    return fd
                def close_original(fd):
                    original_close(fd)
                    if fd == receipt_fd[0]:
                        closed.append(fd)
                        if fault == "close": raise OSError("synthetic consuming close failure")
                        if fault == "late-close": tick[0] = 450 * 1_000_000_000
                with patch.object(MODULE.os, "open", open_original), patch.object(MODULE.os, "close", close_original):
                    if fault in (None, "native-nonzero"):
                        original = MODULE.execute_normal_phase(phase, request, "a" * 40, (32 * 1024**3,) * 2)
                        self.assertEqual(original.returncode, 65 if fault else 0)
                    else:
                        with self.assertRaises((MODULE.Refused, MODULE.NativeQueryFailure, OSError)):
                            MODULE.execute_normal_phase(phase, request, "a" * 40, (32 * 1024**3,) * 2)
                if fault in ("query-nonzero", "source-changed", "late-command"):
                    self.assertFalse((normal / "build.command-admission.json").exists())
                if fault == "query-nonzero": self.assertEqual(len(owned), 2)
                if fault in (None, "native-nonzero", "close", "late-close"):
                    self.assertEqual(len(closed), 1)
                if fault is None:
                    facts = json.loads((normal / "build.command-admission.json").read_bytes())
                    self.assertEqual([row["role"] for row in facts["commands"]], ["normal-ui-source-roster",
                        "normal-toolchain-xcode", "normal-toolchain-sdkPath", "normal-toolchain-sdkVersion",
                        "normal-toolchain-sdkBuild", "normal-ui-build", "normal-ui-source-roster"])
                    self.assertTrue(facts["sourcePrePostMatched"])
                    self.assertTrue(facts["phaseClock"]["postCloseDeadlineRequired"])
                    self.assertEqual(stat.S_IMODE((normal / "build.command-admission.json").stat().st_mode), 0o600)
                    with self.assertRaises(OSError): MODULE.exclusive_output(normal / "build.command-admission.json", b"no overwrite\n", 32768)
                    # Same checked original source route for the fixed summary, no Apple command.
                    (normal / "test.xcresult").mkdir(mode=0o700)
                    def summary_fake(argv, **kwargs):
                        owned.append((argv, kwargs))
                        return subprocess.CompletedProcess(argv, 0, b"".join(source_rows) if argv[0] == "/usr/bin/git" else b'{"totalTestCount":1}\n', b"")
                    summary = MODULE.normal_request(["--normal-summary", "test.xcresult"], str(normal / "tmp") + "/")
                    summary_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=summary_fake), {}, root, MODULE.PhaseClock(90, now=lambda: 0))
                    MODULE.execute_normal_phase(summary_phase, summary, "a" * 40, (1024**3,) * 2)
                    self.assertEqual(owned[-2][0], ["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(normal / "test.xcresult"), "--compact"])
                    self.assertEqual(owned[-2][1]["timeout"], 30)
                    self.assertEqual(owned[-2][1]["output_limit"], 262144)
                    self.assertEqual(json.loads((normal / "summary.command-admission.json").read_bytes())["resultBundle"], "test.xcresult")

        # The SAME real-filesystem group also exercises the fixed engineering
        # assembly/input/receipt path. Small synthetic bytes only: no archive,
        # interpreter, signer, Xcode, or application is executed by this test.
        for fault in (None, "runtime-changed", "source-changed", "native-nonzero", "late-test",
                      "input-close", "receipt-close", "summary-nonzero", "late-summary-close",
                      "resources-missing", "resources-symlink", "resources-nonempty"):
            with self.subTest(engineering_original=fault), tempfile.TemporaryDirectory(prefix="mrk-engineering-main-data-") as temporary:
                base = Path(temporary)
                root, compiler, work = (base / name for name in ("source", "compiler", "work"))
                for directory in (root, compiler, work): directory.mkdir(mode=0o700)
                normal = work / "normal-ui"; normal.mkdir(mode=0o700)
                (normal / "tmp").mkdir(mode=0o700)
                def put(path, body, mode=0o600):
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(body); path.chmod(mode)
                relative_names = ("desktop/tools/macos_normal_ui_runner.py",
                    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift")
                source_rows = []
                for relative in relative_names:
                    body = b"synthetic SOURCE only, never imported or compiled\n"
                    put(root / relative, body)
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    source_rows.append(b"100644 blob " + blob.encode() + b"\t" + relative.encode() + b"\0")
                workflow_name = ".github/workflows/desktop-macos-engineering-ui.yml"
                workflow_body = b"synthetic fixed workflow SOURCE, never executed\n"
                put(root / workflow_name, workflow_body)
                bootstrap = b"synthetic bootstrap SOURCE, never executed\n"
                protocol = b"synthetic core protocol SOURCE, never imported\n"
                put(root / "desktop/engine_bootstrap.py", bootstrap)
                put(root / "src/mobile_release/_desktop_engine.py", protocol)
                plist_body = plistlib.dumps(dict(CFBundleIdentifier="dev.mobile-release-kit.engineering-ui",
                    CFBundleExecutable="mobile-release-kit-desktop", CFBundleName="Mobile Release Kit", CFBundlePackageType="APPL"))
                put(root / "desktop/native/macos-normal-ui/engineering-main-app.plist", plist_body)
                binary = b"synthetic original main, not an executable format\n"
                put(compiler / "target/engineering-main/mobile-release-kit-desktop", binary, 0o700)
                binding = dict(sourceSha="a" * 40, sourceTree="b" * 40, workflowPath=workflow_name,
                    workflowSha="a" * 40, workflowSha256=hashlib.sha256(workflow_body).hexdigest(),
                    workflowRef="mobile-release-kit/mobile-release-kit/" + workflow_name + "@refs/heads/verify/desktop-macos-engineering-ui",
                    runId="123", attempt="1", engineeringWork=str(work))
                context = dict(binding, root=str(compiler), source=str(root), platform="macos", executionScope="macos-engineering-ui-compile-v1")
                public = dict(binding, platform="macos", scope="desktop-macos-engineering-ui-compile-only-v1",
                              bootstrapSha256=hashlib.sha256(bootstrap).hexdigest())
                put(compiler / "context.json", json.dumps(context).encode())
                put(compiler / "public-bindings.json", json.dumps(public).encode())
                rust = dict(release="1.98.1", commitHash="48a229ceaefd4985c50990b14116b6d856af0985", target="aarch64-apple-darwin")
                check_names = {"acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
                    "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only")}
                for mode in ("acquire", "compile"):
                    receipt = dict(schemaVersion=1, scope="desktop-macos-engineering-ui-compile-only-v1", phase=mode,
                        status="passed", **binding, platform="macos", rust=rust, node="v24.20.0",
                        checks=[dict(check=name, exitCode=0) for name in check_names[mode]])
                    if mode == "compile":
                        receipt["compiledMain"] = dict(relativePath="target/engineering-main/mobile-release-kit-desktop",
                            bytes=len(binary), sha256=hashlib.sha256(binary).hexdigest())
                    put(compiler / (mode + "-checks.json"), json.dumps(receipt).encode())
                runtime = work / "runtime"
                runtime_inputs = {"core.zip": b"synthetic core bytes, not parsed as a ZIP\n",
                                  "engine_bootstrap.py": bootstrap, "python/bin/python3": b"synthetic interpreter, never executed\n"}
                rows = []
                for name, body in sorted(runtime_inputs.items()):
                    put(runtime / name, body, 0o555 if name == "python/bin/python3" else 0o444)
                    rows.append(dict(path=name, size=len(body), sha256=hashlib.sha256(body).hexdigest()))
                manifest = dict(schemaVersion=1, protocol=1, coreVersion="fixture", target="aarch64-apple-darwin",
                    coreSha256=hashlib.sha256(runtime_inputs["core.zip"]).hexdigest(),
                    protocolSha256=hashlib.sha256(protocol).hexdigest(),
                    inventorySha256=hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
                    files=rows)
                manifest_body = json.dumps(manifest).encode()
                put(runtime / "manifest.json", manifest_body, 0o444)
                for directory in sorted((p for p in runtime.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                    directory.chmod(0o555)
                runtime.chmod(0o555)
                description = dict(qualification="current-source-description-only-not-build-or-install-authority", target="aarch64-apple-darwin",
                    supplierOrigin="fresh-public-source", supplierReceiptSha256="2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d",
                    supplierProfile="mrk-macos-cpython-source-supplier-v1", pythonVersion="3.14.7", gil=True,
                    successorManifestSha256=hashlib.sha256(manifest_body).hexdigest(),
                    **{key: manifest[key] for key in ("inventorySha256", "coreSha256", "protocolSha256")})
                put(work / "runtime-description.json", json.dumps(description).encode())
                put(work / "runtime-result.json", json.dumps(dict(description, qualification="current-source-staged-no-native-execution")).encode())
                tool_values = (b"Xcode 26.0\nBuild version 17A324\n",
                    b"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.0.sdk\n",
                    b"26.0\n", b"25A352\n")
                query_values = {tuple(query[2]): body for query, body in zip(MODULE.TOOLCHAIN_QUERIES, tool_values)}
                marker = ("MRK_MACOS_ENGINEERING_MAIN_UI=mainRequest=1;completion=1;body=1;handoff=1;mainIdentity=1;catalogueGuide=1;"
                    "projectSelected=0;editCapability=unavailable;originalTerminated=1;failureCleanup=0;caseDeadlineMet=1;"
                    "cleanExitStatus=unavailable;allWorkerFinality=unavailable")
                case = "-[MRKNormalAppUITests.NormalAppUITests testEngineeringMainCatalogueAndQuit]"
                ui_stdout = ("Test Case '" + case + "' started.\n" + marker + "\nTest Case '" + case + "' passed (1.000 seconds).\n").encode()
                summary_body = b'{"totalTestCount":1,"passedTests":1,"failedTests":0,"skippedTests":0,"expectedFailures":0}\n'
                tick, owned, current_mode = [0], [], ["build"]
                def owned_fake(argv, **kwargs):
                    owned.append((argv, kwargs))
                    if argv[0] == "/usr/bin/git":
                        body = ((binding["sourceSha"] + "\n" + binding["sourceTree"] + "\n").encode() if "rev-parse" in argv
                                else b"" if "diff" in argv else b"".join(source_rows))
                        return subprocess.CompletedProcess(argv, 0, body, b"")
                    if tuple(argv) in query_values:
                        return subprocess.CompletedProcess(argv, 0, query_values[tuple(argv)], b"")
                    if argv[0] == "/usr/bin/codesign":
                        if "--sign" in argv:
                            app = work / "Mobile Release Kit.app"
                            resources = app / "Contents/Resources"
                            self.assertTrue(stat.S_ISDIR(resources.lstat().st_mode))
                            self.assertEqual(stat.S_IMODE(resources.lstat().st_mode), 0o700)
                            self.assertEqual(list(resources.iterdir()), [])
                            put(app / "Contents/_CodeSignature/CodeResources", b"synthetic signature envelope\n")
                            put(app / "Contents/MacOS/mobile-release-kit-desktop", binary + b"synthetic ad-hoc mutation\n", 0o700)
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[1] == "build-for-testing":
                        (normal / "DerivedData").mkdir(mode=0o700)
                        return subprocess.CompletedProcess(argv, 0, b"synthetic build original\n", b"")
                    if argv[1] == "test-without-building":
                        (normal / "engineering-test.xcresult").mkdir(mode=0o700)
                        if fault == "runtime-changed":
                            path = runtime / "core.zip"; path.chmod(0o644); path.write_bytes(b"changed runtime"); path.chmod(0o444)
                        if fault == "source-changed": (root / relative_names[0]).write_bytes(b"changed source\n")
                        if fault == "late-test": tick[0] = 345 * 1_000_000_000
                        return subprocess.CompletedProcess(argv, 65 if fault == "native-nonzero" else 0,
                                                           b"" if fault == "native-nonzero" else ui_stdout, b"")
                    if argv[:4] == ["/usr/bin/xcrun", "xcresulttool", "get", "test-results"]:
                        return subprocess.CompletedProcess(argv, 66 if fault == "summary-nonzero" else 0, summary_body, b"")
                    self.fail("unexpected engineering fake original route")
                original_open, original_close = os.open, os.close
                original_enter = MODULE.EngineeringInputs.__enter__
                close_target, close_failures = [None], []
                def remember_inputs(instance):
                    returned = original_enter(instance)
                    if current_mode[0] == "test" and fault == "input-close":
                        close_target[0] = instance.held[runtime / "core.zip"][0]
                    return returned
                def open_original(path, flags, *args, **kwargs):
                    fd = original_open(path, flags, *args, **kwargs)
                    if flags & os.O_CREAT and str(path).endswith("/engineering-test.runner-admission.json") and fault == "receipt-close":
                        close_target[0] = fd
                    if flags & os.O_CREAT and str(path).endswith("/engineering-summary.command-admission.json") and fault == "late-summary-close":
                        close_target[0] = fd
                    return fd
                def close_original(fd):
                    original_close(fd)
                    if fd == close_target[0]:
                        close_target[0] = None; close_failures.append(fd)
                        if fault == "late-summary-close": tick[0] = 90 * 1_000_000_000
                        else: raise OSError("synthetic consuming original close failure")
                request = dict(engineering=True, phase="build", target="aarch64-apple-darwin", work=work, compiler=compiler,
                    binding={key: value for key, value in binding.items() if key not in ("sourceTree", "workflowSha256")},
                    derived=normal / "DerivedData", result=None, methods=(), allowance=None, timeout=240, phaseSeconds=450)
                result = normal / "engineering-smoke.json"
                try:
                    with patch.object(MODULE.os, "open", open_original), patch.object(MODULE.os, "close", close_original), \
                            patch.object(MODULE.EngineeringInputs, "__enter__", remember_inputs), patch.object(MODULE, "RunnerProducts") as products_type:
                        products = products_type.return_value.__enter__.return_value
                        products_type.return_value.__exit__.return_value = False
                        products.products = normal / "DerivedData/Build/Products"
                        products.manifest = "fixed.xctestrun"
                        products.admit.side_effect = lambda _call: {"scope": "inert-products-not-native-authority"}
                        build_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(450, now=lambda: tick[0]))
                        built = MODULE.execute_engineering_phase(build_phase, request, binding["sourceSha"], (32 * 1024**3,) * 2)
                        self.assertEqual(built.returncode, 0)
                        self.assertFalse(result.exists())
                        self.assertEqual((compiler / "target/engineering-main/mobile-release-kit-desktop").read_bytes(), binary)
                        self.assertEqual((work / "Mobile Release Kit.app/Contents/Info.plist").read_bytes(), plist_body)
                        self.assertEqual((work / "Mobile Release Kit.app/Contents/MacOS/mobile-release-kit-desktop").read_bytes(), binary + b"synthetic ad-hoc mutation\n")
                        build_facts = json.loads((normal / "engineering-build.command-admission.json").read_bytes())
                        self.assertEqual(build_facts["compilerBinarySha256"], hashlib.sha256(binary).hexdigest())
                        self.assertTrue(build_facts["inputOriginalClosesCompleted"])
                        resources = work / "Mobile Release Kit.app/Contents/Resources"
                        self.assertTrue(stat.S_ISDIR(resources.lstat().st_mode))
                        self.assertEqual(stat.S_IMODE(resources.lstat().st_mode), 0o555)
                        self.assertEqual(list(resources.iterdir()), [])
                        # Real strict path resolution matches Tauri's macOS
                        # resource_dir requirement; no Tauri/native call is faked.
                        self.assertEqual((work / "Mobile Release Kit.app/Contents/MacOS/../Resources").resolve(strict=True),
                                         resources.resolve(strict=True))
                        if fault in ("resources-missing", "resources-symlink"):
                            resources.parent.chmod(0o700)
                            resources.rmdir()
                            if fault == "resources-symlink":
                                resources.symlink_to(normal / "tmp", target_is_directory=True)
                            resources.parent.chmod(0o555)
                        elif fault == "resources-nonempty":
                            resources.chmod(0o700)
                            put(resources / "unexpected", b"not a runtime input\n", 0o444)
                            resources.chmod(0o555)
                        current_mode[0] = "test"
                        tested_request = dict(request, phase="test", result=normal / "engineering-test.xcresult",
                            methods=(MODULE.ENGINEERING_METHOD,), allowance=60, timeout=180, phaseSeconds=345)
                        test_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(345, now=lambda: tick[0]))
                        before_test_calls = len(owned)
                        if fault in ("runtime-changed", "source-changed", "late-test", "input-close", "receipt-close",
                                     "resources-missing", "resources-symlink", "resources-nonempty"):
                            with self.assertRaises((MODULE.Refused, OSError)):
                                MODULE.execute_engineering_phase(test_phase, tested_request, binding["sourceSha"], (1024**3,) * 2)
                        else:
                            tested = MODULE.execute_engineering_phase(test_phase, tested_request, binding["sourceSha"], (1024**3,) * 2)
                            self.assertEqual(tested.returncode, 65 if fault == "native-nonzero" else 0)
                            test_facts = json.loads((normal / "engineering-test.runner-admission.json").read_bytes())
                            self.assertEqual(test_facts["sameOriginalNormalQuitObserved"], fault != "native-nonzero")
                            self.assertTrue(test_facts["generatedRunnerOriginalClosesCompleted"])
                            original_stdout = b"" if fault == "native-nonzero" else ui_stdout
                            self.assertEqual(test_facts["testStdoutSha256"], hashlib.sha256(original_stdout).hexdigest())
                            self.assertEqual((normal / "engineering-test.stdout").read_bytes(), original_stdout)
                            self.assertEqual((normal / "engineering-test.stderr").read_bytes(), b"")
                            current_mode[0] = "summary"
                            summarized = dict(tested_request, phase="summary", timeout=30, phaseSeconds=90, methods=(), allowance=None)
                            summary_phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), {}, root, MODULE.PhaseClock(90, now=lambda: tick[0]))
                            if fault in ("native-nonzero", "late-summary-close"):
                                with self.assertRaises(MODULE.Refused):
                                    MODULE.execute_engineering_phase(summary_phase, summarized, binding["sourceSha"], (1024**3,) * 2)
                            else:
                                returned = MODULE.execute_engineering_phase(summary_phase, summarized, binding["sourceSha"], (1024**3,) * 2)
                                self.assertEqual(returned.returncode, 66 if fault == "summary-nonzero" else 0)
                        if fault is None:
                            facts = json.loads(result.read_bytes())
                            self.assertEqual(set(facts), {"schemaVersion", "scope", "status", "sourceSha", "sourceTree", "workflowPath",
                                "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "engineeringWork", "compilerRoot", "target",
                                "compilerReceiptSha256", "runtimeResultSha256", "runtimeManifestSha256", "runtimeRosterSha256", "applicationRosterSha256",
                                "compilerBinarySha256", "testAdmissionSha256", "testIdentifier", "testCounts", "nativeSummarySha256",
                                "sameOriginalNormalQuitObserved", "cleanExitStatus", "allWorkerFinality", "fullUIQualified", "productReady",
                                "sourcePrePostMatched", "inputPrePostMatched", "inputOriginalClosesCompleted", "generatedRunnerOriginalClosesCompleted",
                                "originalCommandsReturned", "summaryAdmissionSha256", "originalWrapperZeroRequired"})
                            self.assertEqual(facts["scope"], "engineering-main-ui-smoke-only")
                            self.assertEqual(facts["status"], "passed")
                            self.assertEqual(facts["testCounts"], dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0, expectedFailures=0))
                            self.assertEqual(facts["compilerReceiptSha256"], hashlib.sha256((compiler / "compile-checks.json").read_bytes()).hexdigest())
                            self.assertEqual(facts["summaryAdmissionSha256"], hashlib.sha256((normal / "engineering-summary.command-admission.json").read_bytes()).hexdigest())
                            self.assertEqual(facts["testAdmissionSha256"], hashlib.sha256((normal / "engineering-test.runner-admission.json").read_bytes()).hexdigest())
                            self.assertEqual(facts["nativeSummarySha256"], hashlib.sha256(summary_body).hexdigest())
                            for key in ("sameOriginalNormalQuitObserved", "sourcePrePostMatched", "inputPrePostMatched",
                                        "inputOriginalClosesCompleted", "generatedRunnerOriginalClosesCompleted", "originalCommandsReturned", "originalWrapperZeroRequired"):
                                self.assertIs(facts[key], True)
                            self.assertIsNone(facts["cleanExitStatus"])
                            self.assertEqual(facts["allWorkerFinality"], "not-established")
                            self.assertFalse(facts["fullUIQualified"]); self.assertFalse(facts["productReady"])
                            self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
                            # Published JSON alone is NOT the external wrapper's original return.
                            self.assertFalse((normal / "engineering-summary.status").exists())
                            with self.assertRaises(OSError): MODULE.exclusive_output(result, b"do not overwrite\n", 16384)
                            with self.assertRaises(MODULE.Refused): MODULE.exclusive_output(normal / "empty-receipt.json", b"", 16384)
                            with self.assertRaises(MODULE.Refused): MODULE.exclusive_output(normal / "empty-receipt.json", b"", 16384, allow_empty=1)
                            self.assertFalse((normal / "empty-receipt.json").exists())
                        else:
                            self.assertFalse(result.exists())
                        if fault in ("input-close", "receipt-close", "late-summary-close"):
                            self.assertEqual(len(close_failures), 1)
                        if fault in ("runtime-changed", "source-changed", "late-test", "input-close",
                                     "resources-missing", "resources-symlink", "resources-nonempty"):
                            self.assertFalse((normal / "engineering-test.runner-admission.json").exists())
                        if fault == "native-nonzero":
                            self.assertFalse(any(argv[:4] == ["/usr/bin/xcrun", "xcresulttool", "get", "test-results"] for argv, _ in owned))
                        if fault in ("resources-missing", "resources-symlink", "resources-nonempty"):
                            self.assertEqual(len(owned), before_test_calls)
                            products_type.assert_not_called()
                            products.admit.assert_not_called()
                            products.check.assert_not_called()
                            products_type.return_value.__exit__.assert_not_called()
                            self.assertFalse(any(argv[1:2] == ["test-without-building"] for argv, _ in owned))
                        else:
                            products.admit.assert_called_once()
                            self.assertEqual(products.check.call_count, 2 if fault != "late-test" else 1)
                            products_type.return_value.__exit__.assert_called_once()
                            self.assertEqual(sum(argv[1:2] == ["test-without-building"] for argv, _ in owned), 1)
                finally:
                    # Remove only this fixture's explicit symlink before the
                    # existing readonly-tree cleanup; never follow it for chmod.
                    resources_link = work / "Mobile Release Kit.app/Contents/Resources"
                    if resources_link.is_symlink():
                        resources_link.parent.chmod(0o700)
                        resources_link.unlink()
                    # Only this test's known temporary tree, including deliberate
                    # readonly fixture inputs, is made removable for its owner.
                    for directory in [base, *(p for p in base.rglob("*") if p.is_dir())]:
                        directory.chmod(0o700)

        # The fixed diagnostic destination also uses real private directory/file
        # originals. Its publication can never overwrite, retry, or imply success.
        with tempfile.TemporaryDirectory(prefix="mrk-engineering-diagnostic-data-") as temporary:
            work = Path(temporary); work.chmod(0o700)
            normal = work / "normal-ui"; normal.mkdir(mode=0o700)
            request = dict(engineering=True, phase="build", work=work, derived=normal / "DerivedData")
            failure = MODULE.normal_admission_failure("context", ValueError("PRIVATE-diagnostic-value"), None, [])
            expected = MODULE.encoded(failure) + b"\n"
            for mode in ("build", "test", "summary"):
                selected = dict(request, phase=mode)
                path = normal / ("engineering-" + mode + ".failure-diagnostics.json")
                MODULE.publish_engineering_failure(selected, failure)
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(b"PRIVATE", path.read_bytes())
                with patch.object(MODULE.sys, "stderr", io.StringIO()) as errors:
                    MODULE.publish_engineering_failure(selected, dict(failure, stage="loader"))
                    self.assertEqual(errors.getvalue(), "engineering-failure-diagnostic-publication-failed\n")
                self.assertEqual(path.read_bytes(), expected)
                path.unlink()
            for invalid in (dict(request, engineering=False), dict(request, phase="../foreign"),
                            dict(request, derived=work / "foreign/DerivedData")):
                with patch.object(MODULE.sys, "stderr", io.StringIO()):
                    MODULE.publish_engineering_failure(invalid, failure)
                self.assertEqual(list(normal.iterdir()), [])
            for directory in (work, normal):
                directory.chmod(0o755)
                try:
                    with patch.object(MODULE.sys, "stderr", io.StringIO()):
                        MODULE.publish_engineering_failure(request, failure)
                    self.assertEqual(list(normal.iterdir()), [])
                finally:
                    directory.chmod(0o700)
            normal.rmdir()
            other = work / "foreign"; other.mkdir(mode=0o700)
            normal.symlink_to(other, target_is_directory=True)
            try:
                with patch.object(MODULE.sys, "stderr", io.StringIO()):
                    MODULE.publish_engineering_failure(request, failure)
                self.assertEqual(list(other.iterdir()), [])
            finally:
                normal.unlink(); normal.mkdir(mode=0o700)
            with patch.object(MODULE.sys, "stderr", io.StringIO()):
                MODULE.publish_engineering_failure(request, dict(failure, commands=["x" * 16384]))
            self.assertEqual(list(normal.iterdir()), [])
            actual_open, actual_close = os.open, os.close
            selected_fd, consumed = [None], []
            def diagnostic_open(path, flags, *args, **kwargs):
                fd = actual_open(path, flags, *args, **kwargs)
                if flags & os.O_CREAT: selected_fd[0] = fd
                return fd
            def diagnostic_close(fd):
                actual_close(fd)
                if fd == selected_fd[0]:
                    selected_fd[0] = None; consumed.append(fd)
                    raise OSError("PRIVATE-consuming-close")
            with patch.object(MODULE.os, "open", diagnostic_open), patch.object(MODULE.os, "close", diagnostic_close), \
                    patch.object(MODULE.sys, "stderr", io.StringIO()) as errors:
                MODULE.publish_engineering_failure(request, failure)
                self.assertEqual(errors.getvalue(), "engineering-failure-diagnostic-publication-failed\n")
            self.assertEqual(len(consumed), 1)
            self.assertEqual((normal / "engineering-build.failure-diagnostics.json").read_bytes(), expected)
            self.assertFalse((normal / "engineering-smoke.json").exists())

        # One additional fixture in this EXISTING real-FS group. The fake owner
        # returns only inert frames and makes named fixture renames below; no
        # producer, interpreter, signer, Xcode or application is executed here.
        # Actual core interruption remains the unchanged joined-child test/native prerequisite.
        fixture_data = (ROOT / MODULE.SAVED_VERSION_DATA).read_bytes()
        source_faults = {"profile-missing", "profile-bytes", "runtime-old-s", "runtime-count", "runtime-target", "runtime-qualification"}
        for fault in (None, "producer-zero", "original-unknown", "seed-facts", "source-bytes", "consuming-close",
                      "interrupt-named", "restored-facts", "profile-missing", "profile-bytes", "profile-post",
                      "runtime-old-s", "runtime-count", "runtime-target", "runtime-qualification"):
            with self.subTest(saved_version_custody=fault), tempfile.TemporaryDirectory(prefix="mrk-saved-version-handoff-data-") as temporary:
                base = Path(temporary)
                source_root, work, parent = (base / value for value in ("source", "work", "temporary"))
                for directory in (source_root, work, parent): directory.mkdir(mode=0o700)
                normal = work / "normal-ui"; normal.mkdir(mode=0o700)
                fixed = {"desktop/" + name for name in MODULE.SAVED_VERSION_BOOTSTRAPS}
                profile = "desktop/packaging/macos-history-provider.profile"
                fixed.update(("desktop/cpython-source-inputs/github-ca.pem", "desktop/tools/prepare_runtime.py",
                              profile, "src/mobile_release/__init__.py"))
                bodies = {name: b"inert admitted SOURCE, never imported or executed\n" for name in fixed | {MODULE.SAVED_VERSION_PRODUCER}}
                bodies[MODULE.SAVED_VERSION_DATA] = fixture_data
                rows, git_rows = [], []
                for name, body in sorted(bodies.items()):
                    path = source_root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(body); path.chmod(0o600)
                    if name in fixed: rows.append(dict(path=name, size=len(body), sha256=hashlib.sha256(body).hexdigest()))
                    blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                    git_rows.append(b"100644 blob " + blob.encode() + b"\t" + name.encode() + b"\0")
                source_s = hashlib.sha256(MODULE.encoded(rows)).hexdigest()
                # Keep the admitted expected S fixed even for a coherent changed
                # profile+Git blob. A new Git row is not runtime-source authority.
                if fault == "profile-missing":
                    git_rows = [row for row in git_rows if not row.endswith(b"\t" + profile.encode() + b"\0")]
                elif fault == "profile-bytes":
                    changed = b"different inert profile, never imported or executed\n"
                    (source_root / profile).write_bytes(changed)
                    blob = hashlib.sha1(b"blob " + str(len(changed)).encode() + b"\0" + changed).hexdigest()
                    git_rows = [(b"100644 blob " + blob.encode() + b"\t" + profile.encode() + b"\0")
                                if row.endswith(b"\t" + profile.encode() + b"\0") else row for row in git_rows]
                runtime = dict(sourceInputsSha256=source_s, sourceInputCount=len(rows), target=MODULE.ARM_TARGET,
                               qualification="current-source-staged-no-native-execution", successorManifestSha256="b" * 64)
                if fault == "runtime-old-s": runtime["sourceInputsSha256"] = 'fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0'
                if fault == "runtime-count": runtime["sourceInputCount"] -= 1
                if fault == "runtime-target": runtime["target"] = MODULE.INTEL_TARGET
                if fault == "runtime-qualification": runtime["qualification"] = "native-qualified"
                (work / "runtime-result.json").write_bytes(json.dumps(runtime).encode())
                owned, envs = [], []
                fixture = None
                case = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedVersionRecovery]"
                ui_stdout = ("\n".join(("Test Case '" + case + "' started.", MODULE.ORIGINAL_MARKER, MODULE.SAVED_VERSION_MARKER,
                                       "Test Case '" + case + "' passed (1.000 seconds).", ""))).encode()
                def owned_fake(argv, **kwargs):
                    owned.append(argv); envs.append(kwargs["environ"])
                    if argv[0] == "/usr/bin/git": return subprocess.CompletedProcess(argv, 0, b"".join(git_rows), b"")
                    if argv[0] == "/inert/python":
                        self.assertEqual(argv, ["/inert/python", "-I", "-S", "-B", str(source_root / MODULE.SAVED_VERSION_PRODUCER),
                                                "--restart-child", str(fixture.root / "project"), "release_version", "interrupt"])
                        self.assertEqual((kwargs["timeout"], kwargs["output_limit"]), (20, 65536))
                        self.assertNotIn(MODULE.SAVED_VERSION_ENV, kwargs["environ"])
                        if fault == "original-unknown": raise MODULE.Refused("synthetic unreturned original")
                        journal = fixture.root / MODULE.SAVED_VERSION_JOURNAL; journal.mkdir(mode=0o700)
                        controls = {"header.json": {"schemaVersion": 2, "domain": "release_version", "transactionId": "d" * 32},
                                    "plan.json": {"transactionId": "d" * 32, "files": [{"path": "release/version.properties"}]},
                                    "commit.pending": {}, "rollback.pending": {}}
                        for name, value in controls.items():
                            path = journal / name; path.write_bytes(json.dumps(value).encode()); path.chmod(0o600)
                        (journal / "new-0").write_bytes(fixture.after); (journal / "new-0").chmod(0o600)
                        os.rename(fixture.root / MODULE.SAVED_VERSION_PATH, journal / "old-0")
                        for directory in (journal, fixture.root / "project/release"):
                            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                            try: os.fsync(fd)
                            finally: os.close(fd)
                        if fault == "interrupt-named":
                            path = fixture.root / "project/README-user.txt"
                            replacement = path.with_name("replacement-fixture-only")
                            replacement.write_bytes(fixture.files["project/README-user.txt"]); replacement.chmod(0o600)
                            os.replace(replacement, path)  # Same bytes/mode, different named original.
                        frames = [dict(protocol="mrk-release-version/1", session="0123456789abcdef0123456789abcdef", seq=i,
                            kind=kind, result=dict(scopeResources="settled", **value)) for i, (kind, value) in enumerate((
                                ("opened", {"source": "release/version.properties", "values": {"name": "1.2.3", "build": "7"}}),
                                ("prepared", {"view": {"synthetic": True}})))]
                        return subprocess.CompletedProcess(argv, 0 if fault == "producer-zero" else 86,
                            b"".join(json.dumps(row).encode() + b"\n" for row in frames), b"")
                    self.assertEqual(argv, ["/inert/xcodebuild"])
                    self.assertEqual(kwargs["environ"][MODULE.SAVED_VERSION_ENV], str(fixture.handoff))
                    journal = fixture.root / MODULE.SAVED_VERSION_JOURNAL
                    os.rename(journal / "old-0", fixture.root / MODULE.SAVED_VERSION_PATH)
                    for path in journal.iterdir(): path.unlink()
                    journal.rmdir()
                    if fault == "restored-facts":
                        path = fixture.root / "project/README-user.txt"; previous = path.stat()
                        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000))
                    return subprocess.CompletedProcess(argv, 0, ui_stdout, b"")
                original_environment = {"PATH": "/inert", "HOME": "/inert"}
                phase = MODULE.NormalPhase(SimpleNamespace(run_owned=owned_fake), original_environment, source_root,
                                           MODULE.PhaseClock(585, now=lambda: 0))
                fake_sys = SimpleNamespace(flags=SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1), executable="/inert/python")
                with patch.object(MODULE, "sys", fake_sys), patch.object(MODULE, "SAVED_VERSION_TEMPORARY", parent), \
                        patch.object(MODULE, "SAVED_VERSION_SOURCE", source_s):
                    fixture = MODULE.SavedVersionFixture(phase, "a" * 40, normal)
                    try:
                        if fault in source_faults:
                            reason = "saved-version-current-s" if fault.startswith("profile-") else "saved-version-runtime-source-binding"
                            with self.assertRaisesRegex(MODULE.Refused, "^" + reason + "$"):
                                fixture.interrupt(MODULE.ARM_TARGET)
                            self.assertIsNone(fixture.root)
                            self.assertFalse(fixture.handoff.exists())
                            self.assertEqual(len(owned), 1)
                            self.assertEqual([row["role"] for row in phase.records], ["saved-version-source-roster"])
                            self.assertIs(phase.environment, original_environment)
                            self.assertLessEqual(len(fixture.fds), 28)
                            continue
                        if fault in ("producer-zero", "original-unknown", "interrupt-named"):
                            with self.assertRaises(MODULE.Refused): fixture.interrupt(MODULE.ARM_TARGET)
                            self.assertFalse(fixture.handoff.exists())
                            self.assertEqual(len(owned), 2)
                            self.assertLessEqual(len(fixture.fds), 59)
                            continue
                        fixture.interrupt(MODULE.ARM_TARGET)
                        # Synthetic census:19SOURCE (13 bootstraps+profile)+7parents+
                        # 2runtime+1tmp+11fixture dirs+13public+6journal+2handoff=61;
                        # one restored version adds a retained original later.
                        # Local controls also budget stdio/transients separately.
                        self.assertEqual(len(fixture.fds), 61)
                        self.assertEqual(len(set(fixture.fds)), 61)
                        self.assertIn(profile, fixture.sources)
                        for path in fixture.originals.keys() - {MODULE.SAVED_VERSION_PATH}:
                            self.assertIs(fixture.seed[path], fixture.originals[path])
                        self.assertEqual([row["role"] for row in phase.records], ["saved-version-source-roster", "saved-version-core-interrupt"])
                        self.assertEqual(phase.records[1]["returncode"], 86)
                        self.assertEqual(stat.S_IMODE(fixture.handoff.stat().st_mode), 0o600)
                        self.assertLessEqual(fixture.handoff.stat().st_size, 16384)
                        handoff = json.loads(fixture.handoff.read_bytes())
                        self.assertEqual((len(handoff["files"]), len(fixture.originals)), (18, 13))
                        self.assertFalse((fixture.root / MODULE.SAVED_VERSION_PATH).exists())
                        self.assertEqual(fixture.files["project/.gitignore"], MODULE.saved_version_payload(fixture_data)[0]["project/.gitignore"])
                        fixture.check_seed()
                        if fault == "seed-facts":
                            path = fixture.root / "project/README-user.txt"; old = path.stat()
                            os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1_000_000))
                        elif fault == "source-bytes":
                            (source_root / MODULE.SAVED_VERSION_PRODUCER).write_bytes(b"changed original source\n")
                        elif fault == "profile-post":
                            (source_root / profile).write_bytes(b"changed original history profile\n")
                        if fault in ("seed-facts", "source-bytes", "profile-post"):
                            with self.assertRaises(MODULE.Refused): fixture.ui_call("one-admitted-ui-test", ["/inert/xcodebuild"], 420)
                            self.assertEqual(len(owned), 2)
                            self.assertIs(phase.environment, original_environment)
                            continue
                        fixture.original = fixture.ui_call("one-admitted-ui-test", ["/inert/xcodebuild"], 420)
                        self.assertIs(phase.environment, original_environment)
                        if fault == "restored-facts":
                            with self.assertRaises(MODULE.Refused): fixture.restored()
                            self.assertNotIn("originalFixtureRestored", fixture.receipt)
                            self.assertLessEqual(len(fixture.fds), 62)
                            continue
                        result = fixture.restored()
                        self.assertEqual(len(fixture.fds), 62)
                        self.assertEqual(len(set(fixture.fds)), 62)
                        self.assertTrue(all(result[k] for k in ("originalFixtureRestored", "unrelatedOriginalsUnchanged", "readyJournalRemoved",
                                                               "sourcePrePostMatched", "uiOriginalMarkersObserved")))
                        self.assertFalse(result["interruptedGuiSaveObserved"])
                        self.assertEqual((fixture.root / MODULE.SAVED_VERSION_PATH).read_bytes(), fixture.files[MODULE.SAVED_VERSION_PATH])
                        self.assertFalse((fixture.root / MODULE.SAVED_VERSION_JOURNAL).exists())
                        if fault == "consuming-close":
                            close, first, closed = os.close, fixture.fds[-1], []
                            def consuming(fd):
                                close(fd); closed.append(fd)
                                if fd == first: raise OSError("synthetic consumed recovery original close")
                            owned_fds = set(fixture.fds)
                            with patch.object(MODULE.os, "close", consuming), self.assertRaises(OSError): fixture.close()
                            self.assertEqual(set(closed), owned_fds)
                            self.assertEqual(len(closed), len(owned_fds))
                    finally:
                        held = tuple(fixture.fds)
                        fixture.close()
                        self.assertLessEqual(len(held), 62)
                        self.assertEqual(fixture.fds, [])
                        for fd in held:
                            with self.assertRaises(OSError): os.fstat(fd)

    def test_closed_normal_failure_diagnostics_preserve_original_nonzero_and_privacy(self):
        selected = "testLaunchCancelAndQuit"
        query = b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=title;matches=2;exceedsFour=0;nonAtomic=1\n"
        secret = b"PRIVATE-SYNTHETIC-NOT-FOR-PUBLIC-output"
        body = (b"/Users/private/" + secret + b" Error Domain=NSCocoaErrorDomain Code=-4 description=" + secret + b"\n"
            b"NormalAppUITests.swift:123:9: error: -[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit] : private reason\n"
            b"Test Case '-[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit]' started.\n" + query + query)
        original = subprocess.CompletedProcess(["fixed-original"], 65, body, b"** TEST EXECUTE FAILED **\n")
        value = MODULE.normal_failure_diagnostics("test", "test.xcresult", original)
        self.assertEqual(value["errorCodes"], [{"stream": "stdout", "domain": "NSCocoaErrorDomain", "code": -4}])
        self.assertEqual(value["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift", "method": selected, "line": 123, "column": 9}])
        self.assertEqual(len(value["queryObservations"]), 2)  # Preserve repeats, never substitute the last as authority.
        self.assertEqual(value["requireObservations"], [])
        # Same-original diagnostic DATA, never a new test selection or success.
        marker = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=123;check=condition\n"
        for line, check, ending in ((1, "condition", b"\n"), (123, "singleton", b"\n"),
                                    (65535, "actionable", b"\r\n")):
            fixed = f"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line={line};check={check}".encode() + ending
            observed = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                subprocess.CompletedProcess([], 65, fixed, b""))
            self.assertEqual(observed["requireObservations"],
                [{"source": "NormalAppUITests.swift", "line": line, "check": check}])
            self.assertEqual(observed["status"], "classified")
            self.assertEqual(observed["originalReturncode"], 65)
        malformed = (marker[:-1], marker.replace(b"123", b"0"), marker.replace(b"123", b"01"),
            marker.replace(b"123", b"+1"), marker.replace(b"123", b"-1"), marker.replace(b"123", b"65536"),
            marker.replace(b"v1", b"v2"), marker.replace(b"condition", b"PRIVATE"),
            b"prefix " + marker, marker[:-1] + b";private=" + secret + b"\n", marker + marker,
            marker + marker.replace(b"123", b"124"), marker + marker[:-1],
            marker + marker.replace(b"condition", b"PRIVATE"))
        for raw in malformed:
            with self.subTest(require_marker=raw[:100]):
                observed = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                    subprocess.CompletedProcess([], 65, query + raw, b""))
                self.assertEqual(observed["requireObservations"], [])
                self.assertEqual(observed["status"], "unavailable")
                self.assertEqual(len(observed["queryObservations"]), 1)  # Retain unrelated finite observations.
                self.assertEqual(observed["originalReturncode"], 65)
                self.assertNotIn(secret, MODULE.encoded(observed))
                self.assertNotIn(b"PRIVATE", MODULE.encoded(observed))
        other = next(name for name in MODULE.NORMAL_SELECTIONS if name != "test.xcresult")
        for phase, selection, stdout, stderr in (("test", "test.xcresult", b"", marker),
                ("test", other, marker, b""), ("summary", "test.xcresult", marker, b""),
                ("build", None, marker, b""), ("query", None, marker, b"")):
            observed = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, stdout, stderr))
            self.assertEqual(observed["requireObservations"], [])
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_failure_diagnostics("test", "packaged-entry.xcresult",
                subprocess.CompletedProcess([], 65, marker, b""))
        self.assertTrue(value["markers"]["selectedCaseStarted"] and value["markers"]["testExecuteFailed"])
        self.assertEqual(value["stdoutSha256"], hashlib.sha256(body).hexdigest())
        for private in (secret, b"/Users/private", b"private reason", b"description="):
            self.assertNotIn(private, MODULE.encoded(value))
        invalid = (query.rstrip(b"\n") + b" invalid\n" + query.rstrip(b"\n") + b"\nextra=private\n" +
            b"Error Domain=NSCocoaErrorDomain Code=-0\nError Domain=NSCocoaErrorDomain Code=2147483648\n" +
            b"Error Domain=PrivateDomain Code=1\nNormalAppUITests.swift:65536:9: error: -[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit] : bad\n")
        invalid_value = MODULE.normal_failure_diagnostics("test", "test.xcresult", subprocess.CompletedProcess([], 65, invalid, b""))
        self.assertEqual(invalid_value["errorCodes"], [])
        self.assertEqual(invalid_value["sourceFailures"], [])
        incomplete = MODULE.normal_failure_diagnostics("test", "test.xcresult", subprocess.CompletedProcess([], 65, query[:-1], b""))
        self.assertEqual(incomplete["queryObservations"], [])
        many = MODULE.normal_failure_diagnostics("test", "test.xcresult", subprocess.CompletedProcess([], 65, query * 5, b""))
        self.assertEqual(len(many["queryObservations"]), 4)
        self.assertTrue(many["findingsTruncated"])
        self.assertLessEqual(len(MODULE.encoded(many)) + 1, 4096)
        long_body = b"x" * 65537 + b"\nError Domain=NSPOSIXErrorDomain Code=2\n"
        complete = MODULE.normal_failure_diagnostics("build", None, subprocess.CompletedProcess([], 65, long_body, b""))
        self.assertEqual(complete["errorCodes"][0]["code"], 2)  # Not a truncated64-KiB tail/prefix.
        for phase, selection, cap in (("build", None, 1048576), ("test", "test.xcresult", 1048576),
                                      ("summary", "test.xcresult", 262144), ("query", None, 4096)):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics(phase, selection, subprocess.CompletedProcess([], 65, b"x" * (cap + 1), b""))
        for bad in (subprocess.CompletedProcess([], 0, b"", b""), subprocess.CompletedProcess([], True, b"", b""),
                    SimpleNamespace(returncode=65, stdout=secret, stderr=b"")):
            with self.assertRaises(MODULE.Refused): MODULE.normal_failure_diagnostics("build", None, bad)
        normal = Path("/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui")
        request = MODULE.normal_request(["--normal-build"], str(normal / "tmp") + "/")
        # Main's formatter/output failures preserve a genuine COMPLETE original failure.
        # Context/owner are inert fakes here, not actual runtime/native admission.
        for fault in ("formatter", "oversize", "publication", "query"):
            with self.subTest(fault=fault), ExitStack() as stack:
                published = []
                output, errors = io.BytesIO(), io.BytesIO()
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                native = subprocess.CompletedProcess(["fixed-original"], 66 if fault == "query" else 65, secret, b"private stderr")
                for context in (
                    patch.object(MODULE.sys, "argv", ["helper", "--normal-build"]),
                    patch.object(MODULE.os, "environ", {"TMPDIR": str(normal / "tmp") + "/"}),
                    patch.object(MODULE.time, "monotonic_ns", return_value=0),
                    patch.object(MODULE, "normal_context", return_value=(Path("/inert"), "a" * 40, {}, (32 * 1024**3,) * 2)),
                    patch.object(MODULE, "load_normal_owner", return_value=SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError)),
                    patch.object(MODULE, "execute_normal_phase", side_effect=MODULE.NativeQueryFailure(native) if fault == "query" else None, return_value=native),
                    patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors)),
                ): stack.enter_context(context)
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                def publish(path, data, cap):
                    published.append((path, data, cap))
                    if fault == "publication": raise OSError("synthetic original close failure")
                stack.enter_context(patch.object(MODULE, "exclusive_output", publish))
                self.assertEqual(MODULE.main(), native.returncode)
                self.assertEqual(len(published), 1)
                self.assertNotIn(secret, published[0][1])
                self.assertLessEqual(len(published[0][1]), 4096)
                diagnostic = json.loads(published[0][1])
                self.assertEqual(diagnostic["originalReturncode"], native.returncode)
                if fault in ("formatter", "oversize"): self.assertEqual(diagnostic["status"], "unavailable")
                if fault == "query":
                    self.assertEqual(published[0][0].name, "toolchain.failure-diagnostics.json")
                    self.assertEqual(output.getvalue(), b"")
                if fault == "publication": self.assertIn(b"normal-failure-diagnostic-publication-failed\n", errors.getvalue())

        engineering_selection = "engineering-test.xcresult"
        engineering_method = "testEngineeringMainCatalogueAndQuit"
        engineering_marker = b"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=821;check=condition\n"
        engineering_case = "-[MRKNormalAppUITests.NormalAppUITests " + engineering_method + "]"
        engineering_body = (f"Test Case '{engineering_case}' started.\n"
            f"NormalAppUITests.swift:821:7: error: {engineering_case} : ".encode() + secret + b"\n" + engineering_marker +
            f"Test Case '{engineering_case}' failed (1.234 seconds).\n".encode())
        native_error = b"Error Domain=FBSOpenApplicationServiceErrorDomain Code=1 description=" + secret + b"\n** TEST EXECUTE FAILED **\n"
        engineering_original = subprocess.CompletedProcess(["fixed-original"], 65, engineering_body, native_error)
        observed = MODULE.normal_failure_diagnostics("test", engineering_selection, engineering_original, engineering=True)
        self.assertEqual(observed["scope"], "engineering-main-ui-failure-diagnostic-only")
        self.assertEqual(observed["selection"], engineering_selection)
        self.assertEqual(observed["originalReturncode"], 65)
        self.assertTrue(observed["markers"]["selectedCaseStarted"] and observed["markers"]["selectedCaseFailed"])
        self.assertEqual(observed["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift",
            "method": engineering_method, "line": 821, "column": 7}])
        self.assertEqual(observed["requireObservations"], [{"source": "NormalAppUITests.swift", "line": 821, "check": "condition"}])
        self.assertEqual(observed["errorCodes"], [{"stream": "stderr", "domain": "FBSOpenApplicationServiceErrorDomain", "code": 1}])
        self.assertEqual(observed["queryObservations"], [])
        self.assertIsNone(observed["dashboardReadiness"])
        self.assertNotIn(secret, MODULE.encoded(observed))
        framework_only = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, b"", native_error), engineering=True)
        self.assertFalse(framework_only["markers"]["selectedCaseStarted"])
        self.assertFalse(framework_only["markers"]["selectedCaseFailed"])
        self.assertEqual(framework_only["requireObservations"], [])  # Unobserved is not proof of nonexecution.
        for line, check, end in ((1, "condition", b"\n"), (42, "singleton", b"\r\n"), (65535, "actionable", b"\n")):
            mark = f"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line={line};check={check}".encode() + end
            one = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, mark, b""), engineering=True)
            self.assertEqual(one["requireObservations"], [{"source": "NormalAppUITests.swift", "line": line, "check": check}])
        invalid_engineering = (engineering_marker[:-1], engineering_marker.replace(b"821", b"0"),
            engineering_marker.replace(b"821", b"0821"), engineering_marker.replace(b"821", b"65536"),
            engineering_marker.replace(b"condition", secret), b"prefix " + engineering_marker,
            engineering_marker + engineering_marker, engineering_marker + engineering_marker[:-1],
            engineering_marker + b"MRK_MACOS_ENGINEERING_REQUIRE", engineering_marker.replace(b"v1", b"v2"),
            engineering_marker[:-1] + b";private=" + secret + b"\n")
        for raw in invalid_engineering:
            bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, raw, b""), engineering=True)
            self.assertEqual(bad["requireObservations"], [])
            self.assertEqual(bad["status"], "unavailable")
            self.assertNotIn(secret, MODULE.encoded(bad))
        for stdout, stderr in ((b"", engineering_marker), (engineering_marker, engineering_marker)):
            bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, stdout, stderr), engineering=True)
            self.assertEqual(bad["requireObservations"], [])
            self.assertEqual(bad["status"], "unavailable")
        foreign = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, body + marker, b""), engineering=True)
        self.assertFalse(foreign["markers"]["selectedCaseStarted"])
        self.assertEqual(foreign["sourceFailures"], [])
        self.assertEqual(foreign["requireObservations"], [])
        self.assertEqual(foreign["queryObservations"], [])
        ordinary = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, engineering_body, b""))
        self.assertEqual(ordinary["requireObservations"], [])
        self.assertEqual(ordinary["sourceFailures"], [])
        self.assertFalse(ordinary["markers"]["selectedCaseStarted"])
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, engineering_marker, b""), engineering=True)
            self.assertEqual(outside["requireObservations"], [])
        for engineering, selection in ((False, engineering_selection), (True, "test.xcresult"),
                (True, "packaged-entry.xcresult"), (True, "foreign.xcresult"), (1, engineering_selection)):
            with self.subTest(engineering=engineering, selection=selection), self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics("test", selection, engineering_original, engineering=engineering)
        for code in (0, True):
            with self.assertRaises(MODULE.Refused):
                MODULE.normal_failure_diagnostics("test", engineering_selection,
                    subprocess.CompletedProcess([], code, b"", b""), engineering=True)
        with self.assertRaises(MODULE.Refused):
            MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, b"x" * (1048576 + 1), b""), engineering=True)

        # First failure is captured by the original CaseClock itself, including
        # teardown; phase is only the last ENTERED fixed step, never completion.
        first_phases = ("admission", "launch", "catalogue", "guideSelection", "artifactStatus", "artifactSample",
                        "artifactValue", "quitCancel", "postCancel", "quitConfirm", "termination", "terminal")
        first_marker = b"MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line=103;phase=artifactValue\n"
        self.assertIsNone(observed["engineeringFirstFailure"])
        for index, first_phase in enumerate(first_phases):
            line = (1, 103, 65535)[index % 3]
            ending = b"\r\n" if index % 2 else b"\n"
            fixed = f"MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line={line};phase={first_phase}".encode() + ending
            one_first = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, fixed, b""), engineering=True)
            self.assertEqual(one_first["engineeringFirstFailure"], {"line": line, "phase": first_phase})
            self.assertEqual(one_first["status"], "classified")
            self.assertEqual(one_first["originalReturncode"], 65)
            self.assertEqual(one_first["requireObservations"], [])
        malformed_first = (first_marker[:-1], first_marker.replace(b"103", b"0"),
            first_marker.replace(b"103", b"0103"), first_marker.replace(b"103", b"+1"),
            first_marker.replace(b"103", b"-1"), first_marker.replace(b"103", b"65536"),
            first_marker.replace(b"v1", b"v2"), first_marker.replace(b"artifactValue", b"unknown"),
            first_marker.replace(b"artifactValue", secret), b"prefix " + first_marker,
            first_marker[:-1] + b";private=" + secret + b"\n", first_marker + first_marker,
            first_marker + first_marker.replace(b"103", b"104"), first_marker + first_marker[:-1],
            b"MRK_MACOS_ENGINEERING_FIRST_", b"tail MRK_MACOS_ENGINEERING_FIRST_",
            first_marker[:-1] + engineering_marker)
        for raw in malformed_first:
            for whole in (raw, first_marker + raw, raw + first_marker):
                first_bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                    subprocess.CompletedProcess([], 65, whole, native_error), engineering=True)
                self.assertIsNone(first_bad["engineeringFirstFailure"])
                self.assertEqual(first_bad["status"], "unavailable")
                self.assertEqual(first_bad["originalReturncode"], 65)
                self.assertEqual(first_bad["errorCodes"], observed["errorCodes"])
                self.assertNotIn(secret, MODULE.encoded(first_bad))
        for stdout, stderr in ((b"", first_marker), (first_marker, first_marker),
                               (first_marker, first_marker[:-1])):
            first_bad = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, stdout, stderr), engineering=True)
            self.assertIsNone(first_bad["engineeringFirstFailure"])
            self.assertEqual(first_bad["status"], "unavailable")
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            first_outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, first_marker, b""), engineering=True)
            self.assertNotIn("engineeringFirstFailure", first_outside)
            self.assertEqual(first_outside["status"], "unavailable")
        first_ordinary = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, query * 5 + first_marker, b""))
        for key in many:
            if key not in ("stdoutBytes", "stdoutSha256"):
                self.assertEqual(first_ordinary[key], many[key])
        self.assertNotIn("engineeringFirstFailure", first_ordinary)

        # Six finite samples describe the SAME fixed guide, not a selector or
        # atomic catalogue result. A prefix remains a prefix, never six zero rows.
        guide_tuples = tuple((prop, kind) for prop in ("label", "title") for kind in ("any", "button", "checkBox"))
        guide_rows = [(f"MRK_MACOS_ENGINEERING_GUIDE_QUERY=v1;property={prop};type={kind};matches={index};"
                       f"exceedsFour={int(index == 5)};nonAtomic=1").encode() + (b"\r\n" if index % 2 else b"\n")
                      for index, (prop, kind) in enumerate(guide_tuples)]
        guide_expected = [{"stream": "stdout", "kind": "guide", "property": prop, "elementType": kind,
                           "matches": index, "exceedsFour": index == 5, "nonAtomic": True}
                          for index, (prop, kind) in enumerate(guide_tuples)]
        for length in range(7):
            raw = b"".join(guide_rows[:length])
            partial = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess(["fixed-original"], 65, raw, b""), engineering=True)
            self.assertEqual(partial["queryObservations"], guide_expected[:length])
            self.assertEqual(partial["status"], "classified" if length else "unclassified")
            self.assertEqual(partial["requireObservations"], [])
            self.assertIsNone(partial["dashboardReadiness"])
            self.assertFalse(any(partial["markers"].values()))
            self.assertFalse(partial["findingsTruncated"])
            self.assertEqual(partial["originalReturncode"], 65)
        reverse = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess(["fixed-original"], 65, b"".join(reversed(guide_rows)), b""), engineering=True)
        self.assertEqual(reverse["queryObservations"], list(reversed(guide_expected)))

        guide_row = guide_rows[0]
        invalid_guides = (
            guide_row[:-1], guide_row.replace(b"v1", b"v2"), guide_row.replace(b"label", b"value"),
            guide_row.replace(b"type=any", b"type=window"), guide_row.replace(b"type=any", b"type=checkbox"),
            *(guide_row.replace(b"matches=0", b"matches=" + token) for token in (b"-1", b"01", b"+1", b"6", b"true")),
            guide_row.replace(b"exceedsFour=0", b"exceedsFour=1"),
            guide_rows[5].replace(b"exceedsFour=1", b"exceedsFour=0"),
            guide_row.replace(b"exceedsFour=0", b"exceedsFour=true"),
            guide_row.replace(b"nonAtomic=1", b"nonAtomic=0"),
            guide_row.replace(b"nonAtomic=1", b"nonAtomic=true"),
            b"prefix " + guide_row, b" " + guide_row, guide_row[:-1] + b" \n",
            guide_row[:-1] + b";private=" + secret + b"\n", guide_row.replace(b";type=", b"\n;type="),
            guide_row + guide_row, guide_row + guide_row.replace(b"matches=0", b"matches=2"),
            guide_row + guide_row[:-1], b"MRK_MACOS_ENGINEERING_GUIDE", b"MRK_MACOS_ENGINEERING_",
            b"noise\ntrailing MRK_MACOS_ENGINEERING_GUIDE_",
        )
        for raw in invalid_guides:
            for surrounding in (b"".join(guide_rows) + raw, raw + b"".join(guide_rows)):
                with self.subTest(guide_marker=raw[:100]):
                    rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                        subprocess.CompletedProcess(["fixed-original"], 65, surrounding, native_error), engineering=True)
                    self.assertEqual(rejected["queryObservations"], [])  # No valid-neighbor salvage/deduplication.
                    self.assertEqual(rejected["status"], "unavailable")
                    self.assertEqual(rejected["errorCodes"], observed["errorCodes"])
                    self.assertFalse(rejected["findingsTruncated"])
                    self.assertEqual(rejected["originalReturncode"], 65)
                    self.assertNotIn(secret, MODULE.encoded(rejected))
        for stdout, stderr in ((b"", guide_row), (b"".join(guide_rows), guide_row),
                               (guide_row, guide_row[:-1]), (guide_row, b"MRK_MACOS_ENGINEERING_GUIDE")):
            rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess(["fixed-original"], 65, stdout, stderr), engineering=True)
            self.assertEqual(rejected["queryObservations"], [])
            self.assertEqual(rejected["status"], "unavailable")
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess(["fixed-original"], 65, guide_row, b""), engineering=True)
            self.assertEqual(outside["queryObservations"], [])
            self.assertEqual(outside["status"], "unavailable")
        # New engineering namespace cannot change ordinary four-row retention,
        # including its deliberate repeat preservation and truncation signal.
        ordinary_guides = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess(["fixed-original"], 65, query * 5 + b"".join(guide_rows), b""))
        for key in many:
            if key not in ("stdoutBytes", "stdoutSha256"):
                self.assertEqual(ordinary_guides[key], many[key])

        # Fill every engineering category to its retained maximum, with longest
        # fixed public scalars, without borrowing the ordinary four-row budget.
        guide_maximum = b"".join((f"MRK_MACOS_ENGINEERING_GUIDE_QUERY=v1;property={prop};type={kind};"
                                 "matches=4;exceedsFour=0;nonAtomic=1\n").encode() for prop, kind in guide_tuples)
        codes_maximum = b"".join(f"Error Domain=FBSOpenApplicationServiceErrorDomain Code={-2147483648 + i}\n".encode()
                                 for i in range(8))
        sites_maximum = b"".join(f"NormalAppUITests.swift:{line}:4096: error: {engineering_case} : PRIVATE\n".encode()
                                 for line in range(65532, 65536))
        require_maximum = b"MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=65535;check=actionable\n"
        first_maximum = b"MRK_MACOS_ENGINEERING_FIRST_FAILURE=v1;line=65535;phase=guideSelection\n"
        maximum = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess(["fixed-original"], 65,
                guide_maximum + codes_maximum + sites_maximum + require_maximum + first_maximum, b""), engineering=True)
        self.assertEqual([len(maximum[key]) for key in ("errorCodes", "sourceFailures", "queryObservations", "requireObservations")],
                         [8, 4, 6, 1])
        self.assertEqual(maximum["queryObservations"], [dict(row, matches=4, exceedsFour=False) for row in guide_expected])
        self.assertEqual(maximum["requireObservations"], [{"source": "NormalAppUITests.swift", "line": 65535, "check": "actionable"}])
        self.assertEqual(maximum["engineeringFirstFailure"], {"line": 65535, "phase": "guideSelection"})
        self.assertEqual(maximum["status"], "classified")
        self.assertFalse(maximum["findingsTruncated"])
        self.assertLessEqual(len(MODULE.encoded(maximum)) + 1, 4096)
        self.assertNotIn(b"PRIVATE", MODULE.encoded(maximum))

        # Same failed original, closed nine-text roster, three properties only.
        # Zero means no exact match in this one sample; missing rows stay unknown.
        artifact_states = ("available", "runtime-unqualified", "busy", "shutdown", "cleanup-unknown",
                           "document-lost", "unsupported-platform", "waiting", "error")
        artifact_rows = [(f"MRK_MACOS_ENGINEERING_ARTIFACT_QUERY=v1;property={prop};type=staticText;"
                          "counts=0,1,2,3,4,5,0,1,2;sample=pre-wait;nonAtomic=1").encode()
                         + (b"\r\n" if index % 2 else b"\n")
                         for index, prop in enumerate(("label", "title", "value"))]
        artifact_expected = [{"stream": "stdout", "kind": "artifactAvailability", "property": prop,
            "elementType": "staticText", "counts": dict(zip(artifact_states, (0, 1, 2, 3, 4, 5, 0, 1, 2))),
            "sample": "pre-wait", "nonAtomic": True} for prop in ("label", "title", "value")]
        for length in range(4):
            partial = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess(["fixed-original"], 65, b"".join(artifact_rows[:length]), b""), engineering=True)
            self.assertEqual(partial["queryObservations"], artifact_expected[:length])
            self.assertEqual(partial["status"], "classified" if length else "unclassified")
            self.assertEqual(partial["originalReturncode"], 65)
            self.assertEqual(partial["requireObservations"], [])
            self.assertFalse(any(partial["markers"].values()))
            self.assertIsNone(partial["dashboardReadiness"])
        reversed_rows = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, b"".join(reversed(artifact_rows)), b""), engineering=True)
        self.assertEqual(reversed_rows["queryObservations"], list(reversed(artifact_expected)))
        for artifact_count in range(6):
            row = artifact_rows[0].replace(b"0,1,2,3,4,5,0,1,2", b",".join([str(artifact_count).encode()] * 9))
            admitted = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, row, b""), engineering=True)
            self.assertEqual(admitted["queryObservations"][0]["counts"], dict.fromkeys(artifact_states, artifact_count))
        artifact_row = artifact_rows[0]
        invalid_artifacts = (
            artifact_row[:-1], artifact_row.replace(b"v1", b"v2"), artifact_row.replace(b"label", b"identifier"),
            artifact_row.replace(b"staticText", b"any"), artifact_row.replace(b"staticText", b"staticTexts"),
            *(artifact_row.replace(b"0,1,2,3,4,5,0,1,2", token) for token in (
                b"", b"0,1,2,3,4,5,0,1", b"0,1,2,3,4,5,0,1,2,3", b"6,1,2,3,4,5,0,1,2",
                b"-1,1,2,3,4,5,0,1,2", b"01,1,2,3,4,5,0,1,2", b"+1,1,2,3,4,5,0,1,2",
                b"true,1,2,3,4,5,0,1,2", b"0, 1,2,3,4,5,0,1,2")),
            artifact_row.replace(b"pre-wait", b"after-wait"), artifact_row.replace(b"nonAtomic=1", b"nonAtomic=0"),
            b"prefix " + artifact_row, artifact_row[:-1] + b";private=" + secret + b"\n",
            artifact_row + artifact_row, artifact_row + artifact_row[:-1],
            b"MRK_MACOS_ENGINEERING_ARTIFACT", b"noise\ntrailing MRK_MACOS_ENGINEERING_ARTIFACT_",
        )
        for raw in invalid_artifacts:
            for supplied in (raw + b"".join(artifact_rows), b"".join(artifact_rows) + raw):
                rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                    subprocess.CompletedProcess([], 65, guide_maximum + require_maximum + supplied, native_error), engineering=True)
                self.assertEqual(rejected["queryObservations"], maximum["queryObservations"])
                self.assertEqual(rejected["requireObservations"], maximum["requireObservations"])
                self.assertEqual(rejected["errorCodes"], observed["errorCodes"])
                self.assertEqual(rejected["status"], "unavailable")
                self.assertEqual(rejected["originalReturncode"], 65)
                self.assertNotIn(secret, MODULE.encoded(rejected))
        for stdout, stderr in ((b"", artifact_row), (artifact_row, artifact_row),
                               (artifact_row, artifact_row[:-1])):
            rejected = MODULE.normal_failure_diagnostics("test", engineering_selection,
                subprocess.CompletedProcess([], 65, stdout, stderr), engineering=True)
            self.assertEqual(rejected["queryObservations"], [])
            self.assertEqual(rejected["status"], "unavailable")
        for phase, selection in (("build", None), ("query", None), ("summary", engineering_selection)):
            rejected = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, artifact_row, b""), engineering=True)
            self.assertEqual(rejected["queryObservations"], [])
            self.assertEqual(rejected["status"], "unavailable")
        ordinary_artifacts = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, query * 5 + b"".join(artifact_rows), b""))
        for key in many:
            if key not in ("stdoutBytes", "stdoutSha256"):
                self.assertEqual(ordinary_artifacts[key], many[key])
        full = MODULE.normal_failure_diagnostics("test", engineering_selection,
            subprocess.CompletedProcess([], 65, guide_maximum + codes_maximum + sites_maximum + require_maximum
                                        + first_maximum + b"".join(artifact_rows), b""), engineering=True)
        for key in maximum:
            if key not in ("stdoutBytes", "stdoutSha256", "queryObservations"):
                self.assertEqual(full[key], maximum[key])
        self.assertEqual(full["queryObservations"], maximum["queryObservations"] + artifact_expected)
        self.assertLessEqual(len(MODULE.encoded(full)) + 1, 4096)
        self.assertFalse(full["findingsTruncated"])
        self.assertNotIn(b"PRIVATE", MODULE.encoded(full))

        engineering_work = Path("/Users/runner/work/_temp/mrk-macos-engineering-ui.ABCDef12")
        engineering_tmp = str(engineering_work / "normal-ui/tmp") + "/"
        request = MODULE.engineering_request(["--engineering-main-test", "--work", str(engineering_work)], engineering_tmp)
        owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError)
        original_generic = MODULE.normal_admission_failure("diagnostic", MODULE.NativeQueryFailure(engineering_original), owner, [])
        enhanced = MODULE.engineering_native_failure(request, engineering_original, owner, [])
        self.assertEqual({key: value for key, value in enhanced.items() if key != "nativeDiagnostics"}, original_generic)
        self.assertEqual(enhanced["nativeDiagnostics"], observed)
        for fault in ("base", "format", "oversize"):
            with self.subTest(engineering_formatter=fault), ExitStack() as stack:
                if fault == "base": stack.enter_context(patch.object(MODULE, "failure_base", side_effect=ValueError(secret.decode())))
                elif fault == "format": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                else: stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                failed = MODULE.engineering_native_failure(request, engineering_original, owner, [])
                if fault == "base": self.assertEqual(failed, original_generic)
                else: self.assertEqual(failed["nativeDiagnostics"]["status"], "unavailable")
                self.assertNotIn(secret, MODULE.encoded(failed))
        # NativeQueryFailure can carry a verify-app result larger than the4KiB
        # diagnostic query cap. It remains the same original65, not main's1.
        large_query = subprocess.CompletedProcess(["fixed-original"], 65, b"x" * 4097, b"")
        large_generic = MODULE.normal_admission_failure("diagnostic", MODULE.NativeQueryFailure(large_query), owner, [])
        self.assertEqual(MODULE.engineering_native_failure(request, large_query, owner, [], query=True), large_generic)
        record = {"role": "one-admitted-ui-test", "argvSha256": "a" * 64, "returncode": 65,
            "stdoutBytes": len(engineering_body), "stdoutSha256": hashlib.sha256(engineering_body).hexdigest(),
            "stderrBytes": len(native_error), "stderrSha256": hashlib.sha256(native_error).hexdigest(),
            "timeoutSeconds": 180, "roleCapSeconds": 180, "outputLimitBytes": 1048576}
        outer_bound_exercised = False
        for count in range(1, 65):
            records = [record] * count
            generic = MODULE.normal_admission_failure("diagnostic", MODULE.NativeQueryFailure(engineering_original), owner, records)
            if len(MODULE.encoded(generic)) + 1 <= 16384 < len(MODULE.encoded({**generic, "nativeDiagnostics": observed})) + 1:
                self.assertEqual(MODULE.engineering_native_failure(request, engineering_original, owner, records), generic)
                outer_bound_exercised = True
                break
        self.assertTrue(outer_bound_exercised)

        # Real main and existing failure publisher; only original native command,
        # directory observations and exclusive write are inert DATA doubles.
        for fault in ("none", "query-over-cap", "formatter", "oversize", "publication"):
            with self.subTest(engineering_main_diagnostic=fault), ExitStack() as stack:
                native = large_query if fault == "query-over-cap" else engineering_original
                calls, published, closes = [], [], []
                output, errors = io.BytesIO(), io.BytesIO()
                stream = lambda buffer: SimpleNamespace(buffer=buffer, write=lambda value: buffer.write(value.encode()), flush=lambda: None)
                observed_dir = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700,
                    st_uid=501, st_gid=20, st_nlink=2, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
                fake_os = SimpleNamespace(environ={"TMPDIR": engineering_tmp}, getuid=lambda: 501, getgid=lambda: 20,
                    fstat=lambda _fd: observed_dir, stat=lambda *_a, **_k: observed_dir,
                    open=lambda *_a, **_k: 78, close=closes.append,
                    O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=os.O_CLOEXEC)
                def native_call(*_args, **_kwargs):
                    calls.append(1)
                    return native
                fake_owner = SimpleNamespace(ProcessError=OSError, ProcessInterrupted=InterruptedError, run_owned=native_call)
                def execute(phase, _request, _source, _limits):
                    result = phase.call("one-admitted-ui-test", ["fixed-original"], 180)
                    if fault == "query-over-cap": raise MODULE.NativeQueryFailure(result)
                    return result
                def publish(path, data, cap):
                    published.append((path, data, cap))
                    if fault == "publication": raise OSError(secret.decode())
                for context in (
                    patch.object(MODULE.sys, "argv", ["helper", "--engineering-main-test", "--work", str(engineering_work)]),
                    patch.object(MODULE, "os", fake_os), patch.object(MODULE.time, "monotonic_ns", return_value=0),
                    patch.object(MODULE, "engineering_context", return_value=(Path("/inert"), "a" * 40, {}, (1024**3,) * 2)),
                    patch.object(MODULE, "load_normal_owner", return_value=fake_owner),
                    patch.object(MODULE, "execute_engineering_phase", side_effect=execute),
                    patch.object(MODULE, "execute_normal_phase", side_effect=AssertionError("ordinary route selected")),
                    patch.object(MODULE, "open_directory", return_value=77), patch.object(MODULE, "exclusive_output", side_effect=publish),
                    patch.object(MODULE.sys, "stdout", stream(output)), patch.object(MODULE.sys, "stderr", stream(errors)),
                ): stack.enter_context(context)
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                self.assertEqual(MODULE.main(), 65)
                self.assertEqual(calls, [1])
                self.assertEqual(closes, [78, 77])
                self.assertEqual(output.getvalue(), native.stdout)
                self.assertTrue(errors.getvalue().endswith(native.stderr))
                self.assertEqual(len(published), 1)
                self.assertEqual(published[0][0].name, "engineering-test.failure-diagnostics.json")
                self.assertEqual(published[0][2], 16384)
                self.assertLessEqual(len(published[0][1]), 16384)
                self.assertNotIn(secret, published[0][1])
                diagnostic = json.loads(published[0][1])
                self.assertEqual(diagnostic["commands"][0]["returncode"], 65)
                if fault == "query-over-cap": self.assertNotIn("nativeDiagnostics", diagnostic)
                else:
                    self.assertEqual(diagnostic["nativeDiagnostics"]["originalReturncode"], 65)
                    if fault in ("formatter", "oversize"):
                        self.assertEqual(diagnostic["nativeDiagnostics"]["status"], "unavailable")
                if fault == "publication": self.assertIn(b"engineering-failure-diagnostic-publication-failed\n", errors.getvalue())

        # Fixed Android DATA failure supplement: source literals only, never raw
        # XCTest/private paths. It cannot turn the original65 into a test pass.
        data_method = "testPositiveAndroidOutputCustodyData"
        data_case = "-[MRKNormalAppUITests.NormalAppUITests " + data_method + "]"
        data_namespace = b"MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE"
        data_scenarios = ('valid', 'late-close', 'extra-operation', 'work', 'journal', 'project-cache', 'extra-artifact', 'symlink', 'hardlink', 'depth', 'mode', 'input', 'wrong-result', 'identity', 'repeated-start',
            'ios-valid', 'ios-work', 'ios-extra-operation', 'ios-foreign-output', 'ios-symlink', 'ios-replacement', 'ios-partial-open', 'ios-late-close', 'ios-input')
        data_reasons = (
            (b'fixture: Android AAB byte bound', 'r001'),
            (b'fixture: Android AAB exact EOF', 'r002'),
            (b'fixture: Android AAB original read', 'r003'),
            (b'fixture: Android AAB read bound', 'r004'),
            (b'fixture: Android DATA adopted root is not the original', 'r005'),
            (b'fixture: Android DATA census accounting', 'r006'),
            (b'fixture: Android DATA cleanup original differs', 'r007'),
            (b'fixture: Android DATA cleanup root close', 'r008'),
            (b'fixture: Android DATA cleanup root replaced', 'r009'),
            (b'fixture: Android DATA cleanup row absent', 'r010'),
            (b'fixture: Android DATA closed deadline refusal', 'r011'),
            (b'fixture: Android DATA created root facts absent', 'r012'),
            (b'fixture: Android DATA exact entry limit', 'r013'),
            (b'fixture: Android DATA fixed original removal', 'r014'),
            (b'fixture: Android DATA hardlink setup', 'r015'),
            (b'fixture: Android DATA input parent missing', 'r016'),
            (b'fixture: Android DATA late close did not clear state and refuse', 'r017'),
            (b'fixture: Android DATA later close refusal', 'r018'),
            (b'fixture: Android DATA mode mutation', 'r019'),
            (b'fixture: Android DATA original parent replaced', 'r020'),
            (b'fixture: Android DATA original parent row absent', 'r021'),
            (b'fixture: Android DATA primary closure failure was masked or state retained', 'r022'),
            (b'fixture: Android DATA private root retirement', 'r023'),
            (b'fixture: Android DATA production close deleted output', 'r024'),
            (b'fixture: Android DATA scenario unmapped', 'r025'),
            (b'fixture: Android DATA symlink setup', 'r026'),
            (b'fixture: Android DATA temporary close', 'r027'),
            (b'fixture: Android DATA unopened cleanup root differs', 'r028'),
            (b'fixture: Android DATA unopened private root retirement', 'r029'),
            (b'fixture: Android XML original consuming close failed', 'r030'),
            (b'fixture: Android XML original content differs', 'r031'),
            (b'fixture: Android XML resource consuming close failed', 'r032'),
            (b'fixture: Android XML resource content or original changed', 'r033'),
            (b'fixture: Android XML resource open failed', 'r034'),
            (b'fixture: Android XML resource parent changed', 'r035'),
            (b'fixture: Android XML resource parent open failed', 'r036'),
            (b'fixture: Android XML resource parent shape or binding', 'r037'),
            (b'fixture: Android XML resource read failed', 'r038'),
            (b'fixture: Android XML resource read limit', 'r039'),
            (b'fixture: Android XML resource shape, binding or exact length', 'r040'),
            (b'fixture: Android captured AAB mode', 'r041'),
            (b'fixture: Android census enumeration conversion', 'r042'),
            (b'fixture: Android census enumeration failed', 'r043'),
            (b'fixture: Android census enumeration open', 'r044'),
            (b'fixture: Android census limit selection', 'r045'),
            (b'fixture: Android current build identity shape', 'r046'),
            (b'fixture: Android current terminal artifact differs', 'r047'),
            (b'fixture: Android earlier consuming close failed', 'r048'),
            (b'fixture: Android final output observation was not joined before close', 'r049'),
            (b'fixture: Android immutable input changed', 'r050'),
            (b'fixture: Android input consuming close failed', 'r051'),
            (b'fixture: Android input directory roster', 'r052'),
            (b'fixture: Android input parent absent', 'r053'),
            (b'fixture: Android input roster consuming close failed', 'r054'),
            (b'fixture: Android module output byte bound', 'r055'),
            (b'fixture: Android operation output roster', 'r056'),
            (b'fixture: Android original Start identity or state differs', 'r057'),
            (b'fixture: Android output DATA case deadline', 'r058'),
            (b'fixture: Android output DATA cleanup original', 'r059'),
            (b'fixture: Android output DATA cleanup parent', 'r060'),
            (b'fixture: Android output DATA create leaf', 'r061'),
            (b'fixture: Android output DATA creation consuming close', 'r062'),
            (b'fixture: Android output DATA exact refusal missing', 'r063'),
            (b'fixture: Android output DATA leaf write', 'r064'),
            (b'fixture: Android output DATA mkdir', 'r065'),
            (b'fixture: Android output DATA private root creation', 'r067'),
            (b'fixture: Android output DATA temporary consuming close', 'r068'),
            (b'fixture: Android output DATA temporary original', 'r069'),
            (b'fixture: Android output canonical duplicate', 'r070'),
            (b'fixture: Android output census name or entry bound', 'r071'),
            (b'fixture: Android output closure is not terminal', 'r072'),
            (b'fixture: Android output consuming close failed', 'r073'),
            (b'fixture: Android output depth bound', 'r074'),
            (b'fixture: Android output enumeration consuming close failed', 'r075'),
            (b'fixture: Android output existed before review', 'r076'),
            (b'fixture: Android output name encoding', 'r077'),
            (b'fixture: Android output name length', 'r078'),
            (b'fixture: Android output named binding unavailable', 'r079'),
            (b'fixture: Android output named directory changed', 'r080'),
            (b'fixture: Android output observation repeated or mixed with Save', 'r081'),
            (b'fixture: Android output original POST', 'r082'),
            (b'fixture: Android output original alias', 'r083'),
            (b'fixture: Android output original directory changed', 'r084'),
            (b'fixture: Android output original open', 'r085'),
            (b'fixture: Android output parent absent', 'r086'),
            (b'fixture: Android output regular leaf shape', 'r087'),
            (b'fixture: Android output root absent or type', 'r088'),
            (b'fixture: Android output roster changed', 'r089'),
            (b'fixture: Android output total byte bound', 'r090'),
            (b'fixture: Android output type owner mode or binding', 'r091'),
            (b'fixture: Android parsed terminal artifact shape', 'r092'),
            (b'fixture: Android positive input prerequisites absent', 'r093'),
            (b'fixture: Android private output directory mode', 'r094'),
            (b'fixture: Android private root output roster', 'r095'),
            (b'fixture: Android project AAB candidate roster', 'r096'),
            (b'fixture: Android report byte bound', 'r097'),
            (b'fixture: Android report output roster', 'r098'),
            (b'fixture: Android report parent roster', 'r099'),
            (b'fixture: Android required AAB observations absent', 'r100'),
            (b'fixture: Android retained artifact roster', 'r101'),
            (b'fixture: Android retained output changed', 'r102'),
            (b'fixture: Android root build output roster', 'r103'),
            (b'fixture: Android root census bound', 'r104'),
            (b'fixture: Android running original identity differs', 'r105'),
            (b'fixture: Android terminal original identity differs', 'r106'),
            (b'fixture: Android unexpected input-adjacent output', 'r107'),
            (b'fixture: Android unrecognized output directory', 'r108'),
            (b'fixture: Android unrecognized output leaf', 'r109'),
            (b'fixture: Android work or journal remains', 'r110'),
            (b'fixture: admitted Android XML pin differs', 'r111'),
            (b'fixture: an earlier consuming close failed', 'r112'),
            (b'fixture: directory binding changed', 'r113'),
            (b'fixture: directory entry changed', 'r114'),
            (b'fixture: directory open failed', 'r115'),
            (b'fixture: directory original changed', 'r116'),
            (b'fixture: fixed Android XML original was not admitted', 'r117'),
            (b'fixture: fixed Android XML resource absent or misplaced', 'r118'),
            (b'fixture: fixed leaf changed during observation', 'r119'),
            (b'fixture: fixed leaf open failed', 'r120'),
            (b'fixture: fixed leaf read failed', 'r121'),
            (b'fixture: fixed leaf read limit', 'r122'),
            (b'fixture: leaf shape/mode/limit', 'r123'),
            (b'fixture: missing fixed parent', 'r124'),
            (b'fixture: not an original directory', 'r125'),
            (b'fixture: original descriptor stat failed', 'r126'),
            (b'fixture: owned roster changed during enumeration', 'r127'),
            (b'fixture: owned roster conversion failed', 'r128'),
            (b'fixture: owned roster limit/duplicate', 'r129'),
            (b'fixture: owned roster open failed', 'r130'),
            (b'fixture: owned roster read failed', 'r131'),
            (b'fixture: Android output DATA private original root mode differs', 'r132'),
            (b'fixture: Android output DATA private original root uid differs', 'r133'),
            (b'fixture: Android output DATA private original root gid differs', 'r134'),
            (b'fixture: Android output DATA private original root flags differ', 'r135'),
            (b'fixture: Android output DATA private original root kind differs', 'r136'),
            (b'fixture: Android output DATA private original root descriptor differs', 'r137'),
            (b'fixture: Android output DATA private original root entry differs', 'r138'),
            (b'fixture: new private root initialization precondition', 'r139'),
            (b'fixture: new private root group initialization failed', 'r140'),
            (b'fixture: new private root initialization transition differs', 'r141'),
        )
        self.assertEqual(len(data_reasons), 140)
        self.assertEqual([code for _, code in data_reasons], [f"r{i:03d}" for i in range(1, 142) if i != 66])
        self.assertEqual(len({literal for literal, _ in data_reasons}), 140)
        swift = SWIFT.read_text(encoding="utf-8")
        data_swift = swift.split("        static func exerciseAndroidOutputCustodyData() throws {", 1)[1].split(
            "        // A one-case transfer of observation custody", 1)[0]
        closure = swift.split("        private static func facts(", 1)[1].split(
            "        // A one-case transfer of observation custody", 1)[0]
        self.assertEqual(swift.count("    private final class LocalFixture {"), 1)
        local_fixture = swift.split("    private final class LocalFixture {", 1)[1]
        closure += local_fixture.split("        func closeOriginals() throws {", 1)[1].split("\n        }", 1)[0]
        for literal, _ in data_reasons:
            raw = literal.decode("ascii")
            self.assertTrue(('"' + raw + '"') in closure or ('"' + raw.removeprefix("fixture: ") + '"') in closure, raw)
        self.assertNotIn(b"fixture: named stat failed: ", dict(data_reasons))
        self.assertNotIn(b"fixture: original close errors: ", dict(data_reasons))
        scenario_source = re.search(r"for scenario in \[(.*?)\] \{", data_swift, re.S).group(1)
        self.assertEqual(tuple(re.findall(r'"([a-z-]+)"', scenario_source)), data_scenarios)
        marker_source = ('                if let primary {\n'
            '                    print("MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE=v1;scenario=\\(scenario);sample=after-cleanup-attempt;originalFailurePreserved=1")\n'
            '                    throw primary\n'
            '                }\n'
            '                try check()')
        self.assertEqual(swift.count(data_namespace.decode() + "="), 1)
        self.assertIn(marker_source, data_swift)
        self.assertLess(data_swift.index('if Darwin.close(temporary) != 0 && primary == nil'), data_swift.index(marker_source))
        refused_source = data_swift.split('                func refused(', 1)[1].split('\n                }\n                do {', 1)[0]
        self.assertIn('catch let failure as Refusal {', refused_source)
        self.assertIn('guard message == "fixture: " + reason else { throw failure }\n                            observed = true', refused_source)
        self.assertIn('try need(observed, "Android output DATA exact refusal missing")', refused_source)
        self.assertNotIn('throw Refusal.condition', refused_source)
        self.assertNotIn('String(describing:', refused_source)
        # The first failed original root clause is observable; every predicate,
        # order and live stat call remains the original short-circuit contract.
        expected_root_guards = '                    try need(initialRoot.mode & 0o7777 == 0o700, "Android output DATA private original root mode differs")\n                    try need(initialRoot.uid == getuid(), "Android output DATA private original root uid differs")\n                    try need(initialRoot.gid == getgid(), "Android output DATA private original root gid differs")\n                    try need(initialRoot.flags == 0, "Android output DATA private original root flags differ")\n                    try need(initialRoot.mode & mode_t(S_IFMT) == mode_t(S_IFDIR), "Android output DATA private original root kind differs")\n                    try need(initialRoot == facts(cleanupRoot), "Android output DATA private original root descriptor differs")\n                    try need(initialRoot == named(temporary, rootName), "Android output DATA private original root entry differs")'
        self.assertEqual(data_swift.count(expected_root_guards), 1)
        self.assertNotIn('"Android output DATA private original root differs"', data_swift)
        self.assertNotIn("r066", [code for _, code in data_reasons])

        # The real Darwin creation fix retains the final policy rather than
        # accepting an inherited group. This is SOURCE coverage, not syscall execution.
        initialize = swift.split("        private static func initializeNewPrivateRootGroup(", 1)[1].split("\n        }\n", 1)[0]
        self.assertEqual(swift.count("initializeNewPrivateRootGroup("), 3)  # One private definition, two fresh roots.
        self.assertEqual(swift.count("Darwin.fchown("), 1)
        self.assertEqual(initialize.count("Darwin.fchown(fd, uid_t.max, group) == 0"), 1)
        before = initialize.split("            let group = getgid()", 1)[0]
        for required in ("fd >= 0", "created.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)",
                         "created.uid == getuid()", "created.mode & 0o7777 == 0o700", "created.flags == 0",
                         "created == facts(fd)", "created == named(parent, name)"):
            self.assertIn(required, before)
        self.assertIn("let changed = created.gid != group\n            if changed {", initialize)
        self.assertLess(initialize.index("new private root initialization precondition"), initialize.index("Darwin.fchown("))
        self.assertLess(initialize.index("Darwin.fchown("), initialize.index("let after = try facts(fd)"))
        self.assertEqual(re.findall(r"created\.(\w+) == after\.(\w+)", initialize),
            [(field, field) for field in ("device", "inode", "mode", "uid", "flags", "links", "bytes",
                                         "modifiedSeconds", "modifiedNanoseconds")])
        self.assertIn("transition = created == after", initialize)
        self.assertIn("transition && after.gid == group && after == facts(fd) && after == named(parent, name)", initialize)
        self.assertLess(initialize.index("new private root initialization transition differs"), initialize.index("return after"))
        for forbidden in ("created.changedSeconds", "created.changedNanoseconds", "open(", "openat(", "Darwin.close(", "fchmod(", "chown(parent", "while ", "try?", "catch"):
            self.assertNotIn(forbidden, initialize)
        self.assertIn("var cleanupFacts: StatFacts? = rootNamed == 0 ? StatFacts(createdRoot) : nil", data_swift)
        data_initialize = "let initialRoot = try initializeNewPrivateRootGroup(cleanupRoot, parent: temporary, name: rootName, created: createdFacts)"
        self.assertLess(data_swift.index("let cleanupRoot = openat("), data_swift.index(data_initialize))
        self.assertLess(data_swift.index(data_initialize), data_swift.index("cleanupFacts = initialRoot"))
        self.assertLess(data_swift.index("cleanupFacts = initialRoot"), data_swift.index(expected_root_guards))
        self.assertLess(data_swift.index(expected_root_guards), data_swift.index('for path in ["project", "project/app"'))
        self.assertIn("expected.sameDirectory(facts(cleanupRoot)) && expected.sameDirectory(named(temporary, rootName))", data_swift)
        prepare = swift.split("        func prepare(", 1)[1].split("        // Read-only admission BEFORE app launch.", 1)[0]
        saved_early_return = "if profile == .savedVersionRecovery {\n                try adoptSavedVersion(data, temporary: temporary)\n                return\n            }"
        self.assertLess(prepare.index(saved_early_return), prepare.index("mkdtemp("))
        self.assertLess(prepare.index("mkdtemp("), prepare.index("let createdRoot = try adoptDirectory("))
        self.assertLess(prepare.index('directories[""] = createdRoot'), prepare.index("try Self.initializeNewPrivateRootGroup("))
        self.assertLess(prepare.index("try Self.initializeNewPrivateRootGroup("), prepare.index("let root = Directory(fd: createdRoot.fd"))
        self.assertIn("parent: createdRoot.parent, name: createdRoot.name, facts: initialized", prepare)
        self.assertLess(prepare.index('directories[""] = root'), prepare.index("root.facts.uid == getuid() && root.facts.gid == getgid() && root.facts.mode & 0o7777 == 0o700"))
        self.assertLess(prepare.index("temporary parent policy refused"), prepare.index("for path in Self.ancestors("))
        self.assertIn("directory.facts.gid == getgid()", prepare)

        def data_marker(scenario="valid", ending=b"\n"):
            return (b"MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE=v1;scenario=" + scenario.encode()
                + b";sample=after-cleanup-attempt;originalFailurePreserved=1" + ending)

        def data_error(literal, quote=b'"', ending=b"\n", line=1969, column=9):
            site = f"NormalAppUITests.swift:{line}" + (f":{column}" if column is not None else "")
            return (b"/Users/private/" + secret + b"/" + site.encode() + b": error: " + data_case.encode()
                + b" : private XCTest wrapper " + secret + b" condition(" + quote + literal + quote
                + b") private suffix " + secret + ending)

        def data_diagnostic(stdout, stderr=b""):
            return MODULE.normal_failure_diagnostics("test", MODULE.OUTPUT_DATA_RESULT,
                subprocess.CompletedProcess(["fixed-original"], 65, stdout, stderr))

        self.assertNotIn("outputDataFailure", value)
        self.assertIsNone(MODULE.failure_base("test", MODULE.OUTPUT_DATA_RESULT,
            subprocess.CompletedProcess([], 65, b"", b""))["outputDataFailure"])
        expected_code = "r063"  # Only the no-error path now yields exact-refusal-missing.
        known_literal = b"fixture: Android output DATA exact refusal missing"
        for ordinal, (literal, code) in enumerate(data_reasons):
            for quote, ending in ((b'"', b"\n"), (b'\\"', b"\r\n")):
                with self.subTest(output_data_code=code, escaped=(quote != b'"')):
                    scenario = data_scenarios[ordinal % len(data_scenarios)]
                    raw = data_marker(scenario, ending) + data_error(literal, quote, ending)
                    observed = data_diagnostic(raw)
                    self.assertEqual(observed["outputDataFailure"], {"scenario": scenario, "reasonCode": code,
                        "source": "NormalAppUITests.swift", "method": data_method, "line": 1969, "column": 9,
                        "sample": "after-cleanup-attempt"})
                    self.assertEqual(observed["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift",
                        "method": data_method, "line": 1969, "column": 9}])
                    self.assertEqual(observed["status"], "classified")
                    self.assertEqual(observed["originalReturncode"], 65)
                    self.assertEqual(observed["stdoutBytes"], len(raw))
                    self.assertEqual(observed["stdoutSha256"], hashlib.sha256(raw).hexdigest())
                    self.assertNotIn(secret, MODULE.encoded(observed))
                    self.assertNotIn(literal, MODULE.encoded(observed))
                    self.assertNotIn(b"/Users/private", MODULE.encoded(observed))
                    self.assertLessEqual(len(MODULE.encoded(observed)) + 1, 4096)
        data_good_marker, data_good_error = data_marker(), data_error(known_literal)
        marker_only = data_diagnostic(data_good_marker)["outputDataFailure"]
        self.assertEqual(marker_only, {"scenario": "valid", "reasonCode": None, "source": "NormalAppUITests.swift",
            "method": data_method, "line": None, "column": None, "sample": "after-cleanup-attempt"})
        reason_only = data_diagnostic(data_good_error)["outputDataFailure"]
        self.assertEqual(reason_only, dict(marker_only, scenario=None, reasonCode=expected_code, line=1969, column=9, sample=None))
        for unknown in (secret, b"fixture: named stat failed: PRIVATE", b"fixture: original close errors: PRIVATE",
                        known_literal + b" PRIVATE", b"fixture: not a fixed source literal"):
            observed = data_diagnostic(data_good_marker + data_error(unknown))
            self.assertEqual(observed["outputDataFailure"], dict(marker_only, line=1969, column=9))
            self.assertIsNone(data_diagnostic(data_error(unknown))["outputDataFailure"])
            self.assertNotIn(unknown, MODULE.encoded(observed))
        for line, column in ((1, None), (65535, 4096)):
            observed = data_diagnostic(data_good_marker + data_error(known_literal, line=line, column=column))
            self.assertEqual((observed["outputDataFailure"]["line"], observed["outputDataFailure"]["column"]), (line, column))
        bad_markers = (data_good_marker[:-1], data_good_marker.replace(b"v1", b"v2"),
            data_good_marker.replace(b"scenario=valid", b"scenario=PRIVATE"),
            data_good_marker.replace(b"after-cleanup-attempt", b"cleanup-complete"),
            data_good_marker.replace(b"Preserved=1", b"Preserved=0"),
            b"prefix " + data_good_marker, b" " + data_good_marker, data_good_marker[:-1] + b" \n",
            data_good_marker[:-1] + b";private=" + secret + b"\n",
            data_good_marker.replace(b";sample=", b"\n;sample="), data_namespace, data_namespace[:-3],
            b"trailing " + data_namespace[:-3], data_good_marker + data_good_marker,
            data_good_marker + data_marker("identity"), data_good_marker + data_good_marker[:-1])
        for raw in bad_markers:
            for stdout in (data_good_error + data_good_marker + raw, raw + data_good_marker + data_good_error):
                with self.subTest(output_data_bad_marker=raw[:80]):
                    observed = data_diagnostic(stdout)
                    self.assertIsNone(observed["outputDataFailure"])
                    self.assertEqual(observed["status"], "unavailable")
                    self.assertEqual(observed["originalReturncode"], 65)
                    self.assertNotIn(secret, MODULE.encoded(observed))
        malformed_errors = (data_good_error[:-1],
            data_error(known_literal, line=0), data_error(known_literal, line=65536),
            data_error(known_literal, line="01"), data_error(known_literal, column=4097),
            data_error(known_literal, column=0), data_error(known_literal, column="01"),
            data_good_error.replace(data_case.encode(), data_case[:-1].encode()),
            data_good_error.replace(b'condition("', b'condition(\\"', 1),
            data_good_error.replace(b'") private suffix', b'" private suffix'),
            data_error(b"x" * 129), data_error(b"fixture: private\x00token"),
            data_good_error[:-1] + b' condition("fixture: Android DATA mode mutation")\n',
            data_good_error + data_good_error, data_good_error + data_error(b"fixture: Android DATA mode mutation"),
            data_good_error + data_good_error[:-1],
            data_good_error.rstrip(b"\n") + b" " + data_good_error)
        for raw in malformed_errors:
            with self.subTest(output_data_bad_site=raw[:80]):
                observed = data_diagnostic(data_good_marker + raw)
                self.assertIsNone(observed["outputDataFailure"])
                self.assertEqual(observed["status"], "unavailable")
                self.assertEqual(observed["originalReturncode"], 65)
                self.assertNotIn(secret, MODULE.encoded(observed))
        for stdout, stderr in ((b"", data_good_marker + data_good_error), (data_good_marker, data_good_error),
                               (data_good_error, data_good_marker), (data_good_marker + data_good_error, data_good_marker),
                               (data_good_marker + data_good_error, data_good_error), (data_good_marker, data_namespace[:-2])):
            observed = data_diagnostic(stdout, stderr)
            self.assertIsNone(observed["outputDataFailure"])
            self.assertEqual(observed["status"], "unavailable")
        for phase, selection, engineering in (("build", None, False), ("query", None, False),
                ("summary", MODULE.OUTPUT_DATA_RESULT, False), ("test", "test.xcresult", False),
                ("test", "engineering-test.xcresult", True)):
            outside = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, data_good_marker + data_good_error, b""), engineering=engineering)
            self.assertNotIn("outputDataFailure", outside)
        wrong_method = data_good_error.replace(data_method.encode(), b"testLaunchCancelAndQuit")
        self.assertIsNone(data_diagnostic(wrong_method)["outputDataFailure"])
        self.assertEqual(data_diagnostic(data_good_marker + wrong_method)["outputDataFailure"], marker_only)
        capped = data_good_marker + data_good_error
        capped += b"x" * (1048576 - len(capped))
        self.assertEqual(data_diagnostic(capped)["outputDataFailure"]["reasonCode"], expected_code)
        with self.assertRaises(MODULE.Refused): data_diagnostic(capped + b"x")
        # Existing finite findings survive a refused supplement, never repaired
        # by a valid neighbor, a marker on stderr, or an incomplete tail.
        unrelated = data_diagnostic(data_good_error + data_good_marker + data_good_marker,
            b"Error Domain=NSPOSIXErrorDomain Code=2\n")
        self.assertEqual(len(unrelated["sourceFailures"]), 1)
        self.assertEqual(unrelated["errorCodes"], [{"stream": "stderr", "domain": "NSPOSIXErrorDomain", "code": 2}])
        self.assertIsNone(unrelated["outputDataFailure"])
        self.assertEqual(unrelated["status"], "unavailable")
        data_request = {"phase": "test", "result": Path("/inert/output-data-test.xcresult"),
            "derived": Path("/inert/DerivedData"), "outputData": True}
        data_original = subprocess.CompletedProcess(["fixed-original"], 65, data_good_marker + data_good_error, b"")
        for fault in ("none", "formatter", "oversize", "publication"):
            with self.subTest(output_data_publisher=fault), ExitStack() as stack:
                published = []
                def publish_data(path, raw, cap):
                    published.append((path, raw, cap))
                    if fault == "publication": raise OSError(secret.decode())
                stack.enter_context(patch.object(MODULE, "exclusive_output", side_effect=publish_data))
                stack.enter_context(patch.object(MODULE.sys, "stderr", io.StringIO()))
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                if fault == "oversize": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", return_value={"private": "x" * 5000}))
                MODULE.publish_failure_diagnostics(data_request, data_original, role="one-admitted-ui-test")
                self.assertEqual(data_original.returncode, 65)
                self.assertEqual(len(published), 1)
                self.assertEqual(published[0][0].name, "output-data-test.failure-diagnostics.json")
                self.assertEqual(published[0][2], 4096)
                self.assertLessEqual(len(published[0][1]), 4096)
                self.assertNotIn(secret, published[0][1])
                diagnostic = json.loads(published[0][1])
                self.assertEqual(diagnostic["originalReturncode"], 65)
                self.assertEqual(diagnostic["originalCommandRole"], "one-admitted-ui-test")
                if fault in ("formatter", "oversize"):
                    self.assertEqual(diagnostic["status"], "unavailable")
                    self.assertIsNone(diagnostic["outputDataFailure"])
                else: self.assertEqual(diagnostic["outputDataFailure"]["reasonCode"], expected_code)


        # Standard Swift compiler diagnostics do not contain XCTest method text.
        # Exercise the actual parser/publisher, never another compiler/CLI owner.
        compiler_prefix = b"/Users/runner/work/mobile-release-kit/mobile-release-kit/desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"
        def compiler_line(message, *, line=321, column=17, severity=b"error", path=compiler_prefix, ending=b"\n"):
            return path + f":{line}:{column}: ".encode() + severity + b": " + message + ending
        def compiler_diagnostic(stdout, stderr=b"", **kwargs):
            return MODULE.normal_failure_diagnostics("build", None,
                subprocess.CompletedProcess(["fixed-build"], 65, stdout, stderr), **kwargs)
        compile_error = compiler_line(b"cannot convert value of type '" + secret + b"' to expected argument type 'Int'")
        compile_note = compiler_line(b"PRIVATE unexpected note " + secret, line=322, severity=b"note",
            path=b"NormalAppUITests.swift", ending=b"\r\n")
        observed = compiler_diagnostic(compile_error, compile_note + b"** BUILD FAILED **\n")
        self.assertEqual(observed["compilerDiagnostics"], [
            {"stream": "stdout", "source": "NormalAppUITests.swift", "line": 321, "column": 17,
             "severity": "error", "reasonCodes": ["type-mismatch"]},
            {"stream": "stderr", "source": "NormalAppUITests.swift", "line": 322, "column": 17,
             "severity": "note", "reasonCodes": []}])
        self.assertTrue(observed["markers"]["buildFailed"])
        self.assertEqual(observed["status"], "classified")
        self.assertEqual(observed["sourceFailures"], [])
        self.assertEqual(observed["originalReturncode"], 65)
        self.assertEqual(observed["stdoutSha256"], hashlib.sha256(compile_error).hexdigest())
        for hidden in (secret, b"/Users/runner", b"unexpected note", b"expected argument type"):
            self.assertNotIn(hidden, MODULE.encoded(observed))
        for message, code in ((b"value has no member 'PRIVATE'", "missing-member"),
                (b"cannot find 'PRIVATE' in scope", "missing-name"),
                (b"'PRIVATE' is inaccessible due to 'private' protection level", "inaccessible"),
                (b"missing argument for parameter 'PRIVATE' in call", "missing-argument"),
                (b"extra argument 'PRIVATE' in call", "extra-argument"),
                (b"generic parameter 'PRIVATE' could not be inferred", "inference"),
                (b"ambiguous use of 'PRIVATE'", "ambiguous-overload"),
                (b"variable 'PRIVATE' used before being initialized", "initialization"),
                (b"call can throw but is not marked with 'try'", "throwing"),
                (b"call to main actor-isolated method 'PRIVATE'", "actor-isolation"),
                (b"capture of 'PRIVATE' with non-sendable type", "sendability"),
                (b"expected expression after 'PRIVATE'", "syntax"),
                (b"invalid redeclaration of 'PRIVATE'", "redeclaration")):
            with self.subTest(compiler_category=code):
                item = compiler_diagnostic(compiler_line(message))["compilerDiagnostics"][0]
                self.assertIn(code, item["reasonCodes"])
                self.assertNotIn(b"PRIVATE", MODULE.encoded(item))
        unknown = compiler_diagnostic(compiler_line(secret))
        self.assertEqual(unknown["compilerDiagnostics"][0]["reasonCodes"], [])
        self.assertEqual(unknown["status"], "classified")  # A usable public SOURCE site, not a cause claim.
        for raw in (compile_error[:-1], compiler_line(b"x" * 4096),
                compiler_line(secret, line=0), compiler_line(secret, line=65536), compiler_line(secret, line="01"),
                compiler_line(secret, column=0), compiler_line(secret, column=4097), compiler_line(secret, column="01"),
                compiler_line(secret, severity=b"warning"), compiler_line(secret, path=b"Private.swift"),
                compiler_line(secret, path=b"/Users/private/NormalAppUITests.swift"),
                compiler_line(secret, path=compiler_prefix + b".bak"),
                b"prefix " + compile_error, compiler_line(secret + b"\x00suffix")):
            with self.subTest(compiler_bad_site=raw[:80]):
                item = compiler_diagnostic(raw)
                self.assertEqual(item["compilerDiagnostics"], [])
                self.assertNotIn(secret, MODULE.encoded(item))
        self.assertTrue(compiler_diagnostic(compile_error[:-1])["findingsTruncated"])
        self.assertTrue(compiler_diagnostic(compiler_line(b"x" * 4096))["findingsTruncated"])
        for path in (b"NormalAppUITests.swift", compiler_prefix,
                b"desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"):
            item = compiler_diagnostic(compiler_line(b"unknown", line=65535, column=4096, path=path))
            self.assertEqual((item["compilerDiagnostics"][0]["line"], item["compilerDiagnostics"][0]["column"]), (65535, 4096))
        crowded = b"".join(compiler_line(b"unknown", line=n, severity=b"note") for n in range(1, 9)) + compile_error
        item = compiler_diagnostic(crowded, b"Error Domain=NSPOSIXErrorDomain Code=2\n")
        self.assertEqual(len(item["compilerDiagnostics"]), 4)
        self.assertEqual(item["compilerDiagnostics"][0]["severity"], "error")
        self.assertTrue(item["findingsTruncated"])
        self.assertEqual(item["errorCodes"], [{"stream": "stderr", "domain": "NSPOSIXErrorDomain", "code": 2}])
        self.assertLessEqual(len(MODULE.encoded(item)) + 1, 4096)
        # Stress optional-row trimming without weakening the existing final cap.
        actual_base = MODULE.failure_base
        def nearly_full_base(*args, **kwargs):
            value = actual_base(*args, **kwargs)
            value["legacyPadding"] = "x" * (3900 - len(MODULE.encoded(value)))
            return value
        with patch.object(MODULE, "failure_base", side_effect=nearly_full_base):
            item = compiler_diagnostic(crowded)
        self.assertTrue(item["findingsTruncated"])
        self.assertLessEqual(len(item["compilerDiagnostics"]), 1)
        self.assertIn("legacyPadding", item)
        self.assertLessEqual(len(MODULE.encoded(item)) + 1, 4096)
        exact = compile_error + b"x" * (1048576 - len(compile_error))
        self.assertEqual(len(compiler_diagnostic(exact)["compilerDiagnostics"]), 1)
        with self.assertRaises(MODULE.Refused): compiler_diagnostic(exact + b"x")
        for phase, selection, engineering in (("query", None, False), ("summary", "test.xcresult", False),
                ("test", "test.xcresult", False), ("build", None, True)):
            value = MODULE.normal_failure_diagnostics(phase, selection,
                subprocess.CompletedProcess([], 65, compile_error, b""), engineering=engineering)
            self.assertNotIn("compilerDiagnostics", value)
            self.assertNotIn("buildFailed", value["markers"])
        build_request = {"phase": "build", "result": None, "derived": Path("/inert/DerivedData")}
        build_original = subprocess.CompletedProcess(["fixed-build"], 65, compile_error, b"")
        for fault in ("none", "formatter", "publication"):
            with self.subTest(compiler_publication=fault), ExitStack() as stack:
                captured = []
                def publish_build(path, raw, cap):
                    captured.append((path, raw, cap))
                    if fault == "publication": raise OSError(secret.decode())
                stack.enter_context(patch.object(MODULE, "exclusive_output", side_effect=publish_build))
                stack.enter_context(patch.object(MODULE.sys, "stderr", io.StringIO()))
                if fault == "formatter": stack.enter_context(patch.object(MODULE, "normal_failure_diagnostics", side_effect=ValueError(secret.decode())))
                MODULE.publish_failure_diagnostics(build_request, build_original)
                self.assertEqual(build_original.returncode, 65)
                self.assertEqual(len(captured), 1)
                self.assertEqual((captured[0][0].name, captured[0][2]), ("build.failure-diagnostics.json", 4096))
                self.assertLessEqual(len(captured[0][1]), 4096)
                self.assertNotIn(secret, captured[0][1])
                self.assertEqual(json.loads(captured[0][1])["originalReturncode"], 65)

    def test_dashboard_failure_diagnostics_preserve_finite_prewait_data(self):
        reasons = (
            "loading", "not-loaded", "bridge-unavailable", "selection-unavailable",
            "selection-in-progress", "shutting-down", "owner-offline-preflight",
            "owner-android-build", "owner-ios-archive", "owner-project-recovery",
            "owner-github-preflight", "owner-github-release", "owner-project-path",
            "owner-saved-version-edit", "owner-metadata-images", "other-or-unobserved", "ambiguous",
        )
        waiters = ("timed-out", "incorrect-order", "inverted-fulfillment", "interrupted", "unknown")
        self.assertEqual(len(set(reasons)), 17)
        for index, reason in enumerate(reasons):
            ordinal, line = index % 4 + 1, 1 if index % 2 == 0 else 65535
            waiter, enabled, hittable = waiters[index % 5], bool(index % 2), bool(index // 2 % 2)
            ending = b"\n" if index % 2 == 0 else b"\r\n"
            require = f"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line={line};check=condition".encode()
            row = (f"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line={line};ordinal={ordinal};waiter={waiter}"
                   f";enabled={int(enabled)};hittable={int(hittable)};reason={reason};sample=pre-wait;nonAtomic=1").encode()
            with self.subTest(reason=reason, ordinal=ordinal, waiter=waiter):
                value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                    subprocess.CompletedProcess([], 65, require + ending + row + ending, b""))
                self.assertEqual(value["requireObservations"],
                    [{"source": "NormalAppUITests.swift", "line": line, "check": "condition"}])
                self.assertEqual(value["dashboardReadiness"], {
                    "stream": "stdout", "line": line, "ordinal": ordinal, "waiter": waiter,
                    "enabled": enabled, "hittable": hittable, "reason": reason,
                    "sample": "pre-wait", "nonAtomic": True})
                self.assertEqual(value["originalReturncode"], 65)
                self.assertEqual(value["status"], "classified")
                self.assertFalse(any(value["markers"].values()))  # Not a XCTest outcome or final UI state.

        require = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=65535;check=condition\n"
        row = (b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=65535;ordinal=4;waiter=inverted-fulfillment;"
               b"enabled=0;hittable=0;reason=owner-saved-version-edit;sample=pre-wait;nonAtomic=1\n")
        for phase, selection in (
                ("build", None), ("query", None), ("summary", "test.xcresult"),
                *(("test", name) for name in MODULE.NORMAL_SELECTIONS if name != "test.xcresult")):
            with self.subTest(phase=phase, selection=selection):
                value = MODULE.normal_failure_diagnostics(phase, selection,
                    subprocess.CompletedProcess([], 65, require + row, b""))
                self.assertIsNone(value["dashboardReadiness"])
                self.assertEqual(value["requireObservations"], [])
                self.assertEqual(value["originalReturncode"], 65)
        stderr_only = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, b"", require + row))
        self.assertIsNone(stderr_only["dashboardReadiness"])  # Existing normal REQUIRE remains stdout-only.
        self.assertEqual(stderr_only["requireObservations"], [])

        # Fill every existing retained category with widest public scalar values.
        query = (b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=containingSameStaticText;"
                 b"matches=4;exceedsFour=0;nonAtomic=1\n")
        codes = b"".join(f"Error Domain=IDETestOperationsObserverErrorDomain Code={-2147483648 + i}\n".encode()
                         for i in range(8))
        sites = b"".join(b"NormalAppUITests.swift:" + str(line).encode() + b":4096: error: "
            b"-[MRKNormalAppUITests.NormalAppUITests testLaunchCancelAndQuit] : fixture-secret\n"
            for line in range(65532, 65536))
        value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
            subprocess.CompletedProcess([], 65, require + row + codes + sites + query * 4, b""))
        self.assertEqual([len(value[key]) for key in ("errorCodes", "sourceFailures", "queryObservations")],
                         [8, 4, 4])
        self.assertEqual(value["dashboardReadiness"]["waiter"], "inverted-fulfillment")
        self.assertEqual(value["dashboardReadiness"]["reason"], "owner-saved-version-edit")
        self.assertFalse(value["findingsTruncated"])
        self.assertEqual(value["originalReturncode"], 65)
        self.assertLessEqual(len(MODULE.encoded(value)) + 1, 4096)
        self.assertNotIn(b"fixture-secret", MODULE.encoded(value))

    def test_dashboard_failure_diagnostics_reject_ambiguous_or_malformed_data(self):
        require = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=508;check=condition\n"
        row = (b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=508;ordinal=1;waiter=timed-out;"
               b"enabled=0;hittable=0;reason=loading;sample=pre-wait;nonAtomic=1\n")
        site = {"source": "NormalAppUITests.swift", "line": 508, "check": "condition"}
        for stdout, stderr, expected in (
                (row, b"", []), (require, b"", [site]), (require, row, [site]), (row, require, []),
                (require.replace(b"line=508", b"line=509") + row, b"", [dict(site, line=509)]),
                (require.replace(b"condition", b"singleton") + row, b"", [dict(site, check="singleton")]),
                (require + require + row, b"", []), (require + row, require, [site]),
                (require + row + row, b"", [site]), (require + row, row, [site]),
                (require + row + row.replace(b"ordinal=1", b"ordinal=2"), b"", [site]),
                (require + row + require[:-1] + b";private=MRK_MACOS_PACKAGED_DASHBOARD_FAILURE\n", b"", [])):
            with self.subTest(stdout_bytes=len(stdout), stderr_bytes=len(stderr), expected=expected):
                value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                    subprocess.CompletedProcess([], 65, stdout, stderr))
                self.assertIsNone(value["dashboardReadiness"])
                self.assertEqual(value["requireObservations"], expected)
                self.assertEqual(value["originalReturncode"], 65)
                self.assertNotIn(b"private", MODULE.encoded(value))

        namespace = b"MRK_MACOS_PACKAGED_DASHBOARD_FAILURE"
        malformed = [row.replace(old, new, 1) for old, new in (
            (b"v1;", b"v2;"), (b"line=508", b"line=0"), (b"line=508", b"line=0508"),
            (b"line=508", b"line=65536"), (b"ordinal=1", b"ordinal=0"), (b"ordinal=1", b"ordinal=5"),
            (b"ordinal=1", b"ordinal=01"), (b"timed-out", b"completed"), (b"timed-out", b"fixture-secret"),
            (b"enabled=0", b"enabled=true"), (b"hittable=0", b"hittable=2"),
            (b"reason=loading", b"reason=fixture-secret"), (b"sample=pre-wait", b"sample=post-wait"),
            (b"reason=loading", b"reason=owner-native"), (b"reason=loading", b"reason=owner-Android-build"),
            (b"reason=loading", b"reason=owner-offline-preflight-extra"),
            (b"reason=loading", b"reason=owner-metadata-images;detail=fixture-secret"),
            (b"nonAtomic=1", b"nonAtomic=0"))]
        malformed += [row[:-1], namespace[:-1], b"fixture-secret " + namespace[:-1],
                      b"fixture-secret " + row, row[:-1] + b";extra=fixture-secret\n",
                      row[:-1] + b"\r\r\n", row.replace(namespace, namespace + b"_EXTRA")]
        for bad in malformed:
            for observations in (bad, row + bad, bad + row):
                with self.subTest(bad_bytes=len(bad), observations=len(observations)):
                    value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                        subprocess.CompletedProcess([], 65, require + observations, b""))
                    self.assertIsNone(value["dashboardReadiness"])
                    self.assertEqual(value["requireObservations"], [site])
                    self.assertEqual(value["status"], "classified")
                    self.assertEqual(value["originalReturncode"], 65)
                    self.assertNotIn(b"fixture-secret", MODULE.encoded(value))
        for bad in (namespace[:-1], row[:-1] + b";extra=fixture-secret\n"):
            value = MODULE.normal_failure_diagnostics("test", "test.xcresult",
                subprocess.CompletedProcess([], 65, require + row, bad))
            self.assertIsNone(value["dashboardReadiness"])
            self.assertEqual(value["requireObservations"], [site])
            self.assertEqual(value["status"], "classified")
            self.assertEqual(value["originalReturncode"], 65)
            self.assertNotIn(b"fixture-secret", MODULE.encoded(value))

    def test_acl_complete_source_inventory_reads_originals_at_current_native_size(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        begin = "          # Fixed complete ACL SOURCE reader; logs retain their separate 128-KiB bound.\n"
        end = "          # End fixed complete ACL SOURCE reader.\n"
        self.assertEqual(workflow.count(begin), 1); self.assertEqual(workflow.count(end), 1)
        source = workflow.split(begin, 1)[1].split(end, 1)[0]
        self.assertTrue(all(not line.strip() or line.startswith("          ") for line in source.splitlines()))
        source = "\n".join(line[10:] for line in source.splitlines()) + "\n"
        namespace = dict(hashlib=hashlib, json=json, os=os, re=re, stat=stat)
        exec(compile(source, "<fixed ACL source reader only>", "exec"), namespace)
        read_sources = namespace["acl_source_hashes"]
        paths = ("desktop/native/macos-installed-native/src/native.m", "desktop/native/macos-installed-native/tests/acl_probe.m")
        current_length = len((ROOT / paths[0]).read_bytes())
        self.assertGreater(current_length, 131072); self.assertLessEqual(current_length, 262144)
        for length in (current_length, 262144):
            with self.subTest(length=length), tempfile.TemporaryDirectory(prefix="mrk-acl-source-data-") as temporary:
                root = Path(temporary)
                rows = []
                for name, size in zip(paths, (length, 73)):
                    body = b"x" * size
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(body); path.chmod(0o644)
                    rows.append({"path": name, "gitMode": "100644", "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                                 "blob": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()})
                original = dict(source="a" * 40, tree="b" * 40, files=rows)
                inventory = root / "source-inventory.json"
                def save(value):
                    inventory.write_text(json.dumps(value)); inventory.chmod(0o600)
                save(original)
                expected = {row["path"]: row["sha256"] for row in rows}
                self.assertEqual(read_sources(str(root), str(inventory), "a" * 40, "a" * 40), expected)
                for key, bad in (("sha256", "0" * 64), ("blob", "0" * 40), ("size", length - 1),
                                 ("size", True), ("size", 262145), ("gitMode", "100755")):
                    changed = dict(original, files=[dict(rows[0], **{key: bad}), rows[1]])
                    save(changed)
                    with self.subTest(row=key), self.assertRaises(ValueError):
                        read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                save(dict(original, files=rows + [rows[0]]))
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                inventory.write_text(json.dumps(original)[:-1] + ',"source":"' + "a" * 40 + '"}')
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                save(original)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "c" * 40)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "c" * 40, "c" * 40)
                native = root / paths[0]
                native.chmod(0o744)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                native.chmod(0o644)
                link = root / "task-hardlink"; os.link(native, link)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                link.unlink()
                native.unlink(); os.symlink(root / paths[1], native)
                with self.assertRaises(OSError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                native.unlink(); native.write_bytes(b"x" * (262144 + 1)); native.chmod(0o644)
                with self.assertRaises(ValueError): read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                native.write_bytes(b"x" * length)
                actual_open, actual_read, actual_close = os.open, os.read, os.close
                for fault in ("early-eof", "changed", "close"):
                    selected, closed, changed = [None], [], [False]
                    def opened(path, flags, *args, **kwargs):
                        fd = actual_open(path, flags, *args, **kwargs)
                        if str(path) == str(native):
                            self.assertTrue(flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK)
                            selected[0] = fd
                        return fd
                    def reading(fd, size):
                        if fd == selected[0] and fault == "early-eof": return b""
                        data = actual_read(fd, size)
                        if fd == selected[0] and fault == "changed" and not changed[0]:
                            changed[0] = True
                            with native.open("ab") as output: output.write(b"!")
                        return data
                    def closing(fd):
                        actual_close(fd)
                        if fd == selected[0]:
                            closed.append(fd)
                            if fault == "close": raise OSError("synthetic consuming source close failure")
                    with patch.object(os, "open", opened), patch.object(os, "read", reading), patch.object(os, "close", closing):
                        with self.assertRaises((ValueError, OSError)):
                            read_sources(str(root), str(inventory), "a" * 40, "a" * 40)
                    self.assertEqual(len(closed), 1)
                    native.write_bytes(b"x" * length)


if __name__ == "__main__":
    unittest.main()
