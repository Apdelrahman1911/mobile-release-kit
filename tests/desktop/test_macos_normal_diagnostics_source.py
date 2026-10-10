"""SOURCE-only bindings for ordinary Mac diagnostics, saved offline checks and Idle inspection.

These methods read first-party bytes and AST/literals only. They do not launch
XCTest, import product code, qualify native resources, or stand in for the
original future XCTest result. The four fixed negative mutations are applied
by the separately authorized local verification route, never by native retry.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import unittest
from pathlib import Path

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

# Restore only this exact separately reviewed, disabled unsigned iOS route.
# This preserves every earlier complete workflow assertion without normalizing
# unknown source or expanding any default native selection.
IOS_UNSIGNED_WORKFLOW_INVERSE = ((22,
  24,
  '25d5e48ce6a5b9ed6623aa8e2d641dd2b5283c38ae7e0c87aee2601100bec0c4',
  '    # Timed-step union421min; SOURCE scopes select disjoint UI work.\n'
  '    # Preview345 / recovery339 / installed210 / dormant ARM Android267, plus5 overhead.\n'),
 (25, 26, '2efcc97e0a7ee7aa819e1a814e036cef0751b966ed949162de93c0e86f2626f3', ''),
 (62, 64, '13af455f3ba85ffe5bfb6df297fd2b77955327e7afdd7092122a611a68c02c3b', ''),
 (93, 100, '217f658c360f5de5cb6fe7bac982b124d62f2a0b97c20c65820a6118e9909424', ''),
 (607,
  608,
  'b4c270696a678ce3d435c88f10530e83d756f2f103b1305e733416e526f7838a',
  "        if: github.ref == 'refs/heads/verify/desktop-macos-preview' || (github.ref == "
  "'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' && "
  "env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build')\n"),
 (1986, 2062, '42a622c64f52492d93cdbe83abe96113a21539f2d81cd5acf80ae0745bdb3d7b', ''),
 (3865, 3872, '7d7de67e8395eda8fa407f0be71c16173855972af274c03bca09c465e0f9d562', ''))


# Later fixed-remover packaging wiring only; recover the exact pre-wiring
# workflow before applying the unchanged iOS inverse and its old whole pin.
REMOVE_PACKAGE_WORKFLOW_INVERSE = ((73519, 1623, '77826b06c51c25de52bc2f44acf44886e64d2cc894dd821deb15b882dffec294', ''),
 (80606, 690, '91d5cae889e0e34d2420e279840145199b3bec4b71fd32e84f4c12e53699e0af', ''),
 (81786, 312, '8f535e5014c5e559a5ba869d8ba04bd6bc60be306060e8ee7935e2aa98946dcc', ''),
 (85351, 91, 'af795ceaa3d69b9d62dae7408df6ea452734b13405243f36576d42a596b8f966', ''),
 (303397, 159, '386c2bc8bde635a7272a9f46bc584558ef40248cfc665ae6f3321e6857199c7d', ''),
 (314552,
  185,
  'de92f8700678e9723fc66ee7c45cf110feaef2a1bbb1c19ef67c71ba87494f43',
  '          for path in (root / "cargo-target", root / "vault-helper-target", root / "npm-cache", workspace '
  '/ "desktop/node_modules", workspace / "desktop/dist",\n'))


# Exact independent shipping-compile job only. All prior installed/source
# assertions receive their unchanged bytes; a partial or altered job refuses.
SHIPPING_COMPILE_WORKFLOW_INVERSE = ((146, 80, 'e788721c52ce2b2a196b69441bd9469503e9ee123a8758ed99662bcae273e12c', '      - verify/desktop-macos-preview\n'), (20759, 47, '44222096a313a399009b17793d392fec11cb7a20988cd4e0bc36023dad3a6c5f', '        run: |\n'), (24134, 42, '4e4810b6121d5c821d53c96394a4a5a3149338f9703c5e31ab3dc60526b5a144', '        run: |\n'), (326387, 74208, '4a74a4d98e113504d89eed6aaf0e979f7d232ef1026c3a8673f1e19c8bb521b0', ''))


# Ordinary Install presentation only. Preserve both historical whole-workflow
# inverse stacks byte-for-byte; a partial/altered product region is not ignored.
INSTALL_PRODUCT_WORKFLOW_INVERSE = ((108130, 217, '8b87b9b0b3e8ac89ee8e9b1a7220391eb723c318c97ac2456e4df9383b6cb2af', '          /bin/mkdir -m 700 "$MRK_MACOS_WORK/package-unsigned"\n          [[ ! -e "$MRK_MACOS_WORK/package-unsigned/MobileReleaseKit.pkg" && ! -L "$MRK_MACOS_WORK/package-unsigned/MobileReleaseKit.pkg" ]] || exit 1\n'), (108515, 92, '4a2d1b9cb0b5f33ec56d16c48bf394c817eb903617c909b1ab7e756396edca87', '              /usr/bin/xar -c -f "$MRK_MACOS_WORK/package-unsigned/MobileReleaseKit.pkg" \\\n'), (108845, 173, 'e22272f841ce8a1d0103144f86b07a6f1135464eb7eee018d42184c3333c4a5e', '          # This completed unsigned XAR is not final P; the next fixed phase signs and notarizes it.\n'), (109104, 115, '24ebdf18c54cfa3c91d92f0ee23a44cfbb60d6ffa6aea5f4b837135bb18a2d0e', '      - name: Sign and notarize the completed scripts-only Installer package before final P\n'), (109846, 260, 'ac6b48901eabbef4f5e3c0ac970c51f45c100405432d1fa383eced046e839b2b', '          # A separate Installer identity signs the completed Scripts XAR.\n'))


# Closed SOURCE-only singleton successor; all old workflow assertions see the exact predecessor.
GITHUB_REFUSAL_WORKFLOW_INVERSE = ((4363,
  87,
  'd50265e789e53873f15ab75cff4803877dbde8b95b4192d7a7585cfbfcaa786f',
  '      # Default seven cases and the singleton are distinct native obligations.\n'),
 (8791,
  128,
  'e096c708a3ee6d790a39600a9150f94036ab3e712d88451865ccff1d30df0a2b',
  '            saved-version-recovery) [[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-preview ]] || exit 1 ;;'),
 (313704,
  409,
  '7761de9aa25b4e7dea114b692869124fc38ef49bd67c3126d920ff4ef94f904b',
  '          print("One ordinary saved-version recovery passed after original core interrupt86; interrupted GUI Save, '
  'other domains and all-worker finality remain unproved.")\n'),
 (313371,
  146,
  'aac6598ec0d08a4d34bed289b631f6ade12eac7b7db0b737655da1342dc1b10a',
  '          fd = os.open(root / "normal-ui/saved-version-recovery-result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL '
  '| os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)\n'),
 (312040,
  388,
  '9e7b1f655813a122369fb1917f629d63adee88c6791db4cb8c66384923c642d0',
  '              "testIdentifier": "MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedVersionRecovery", '
  '"testCounts": counts,\n'
  '              "nativeSummarySha256": digest(summary_bytes), "savedVersionRecoveryUI": "passed", '
  '"savedVersionRecovery": recovery,\n'
  '              "selectedSavedFileScope": "saved-version-recovery", "savedOfflineAndEmptyBuildInputCohortObserved": '
  'False,\n'
  '              "coreOutcomeObserved": {"effect": "rolled_back", "journal": "clean", "resources": "settled", '
  '"reason": "none"},\n'
  '              "nativeProjectionObserved": {"finality": "settled", "reason": "none"}, "freshSavedVersionObserved": '
  '{"name": "1.2.3", "build": "7"},\n'
  '              "inspectionClosedWithoutApply": True, "explicitFreshRecoveryConfirmation": True, '
  '"interruptedGuiSaveObserved": False,\n'
  '              "configurationTextImagesRecoveryObserved": False, "applicationStateAfterNormalQuit": "notRunning", '
  '"originalReferenceAndGateTerminalObserved": True,\n'),
 (309757,
  3441,
  '9094f214d7de5d0e897d2e9609d2a3cf03355b2d2f482145751e996db413dee2',
  '          recovery = runner.get("savedVersionRecovery")\n'
  '          digests = ("sourceInputsSha256", "runtimeManifestSha256", "runtimeResultSha256", "sourceClosureSha256", '
  '"fixtureDataSha256", "producerSha256", "producerFramesSha256", "handoffSha256")\n'
  '          positives = ("originalFixtureRestored", "unrelatedOriginalsUnchanged", "readyJournalRemoved", '
  '"sourcePrePostMatched", "uiOriginalMarkersObserved", "originalClosesCompleted")\n'
  '          need(type(recovery) is dict and set(recovery) == set(digests) | set(positives) | {"producerReturncode", '
  '"publicOriginalCount", "readyJournalFileCount", "interruptedGuiSaveObserved"}\n'
  '               and all(hex64(recovery[k]) for k in digests) and all(recovery[k] is True for k in positives)\n'
  '               and recovery["interruptedGuiSaveObserved"] is False\n'
  '               and all(type(recovery[k]) is int and recovery[k] == n for k, n in (("producerReturncode", 86), '
  '("publicOriginalCount", 13), ("readyJournalFileCount", 6)))\n'
  '               and recovery["sourceInputsSha256"] == os.environ["MRK_BUNDLED_RUNTIME_SOURCE_SHA256"]\n'
  '               and recovery["runtimeManifestSha256"] == preview["runtimeManifestSha256"]\n'
  '               and recovery["runtimeResultSha256"] == digest(read("runtime-result.json", 65536))\n'
  '               and recovery["producerFramesSha256"] == runner["commands"][2]["stdoutSha256"]\n'
  '               and runner["commands"][2]["stderrBytes"] == 0 and runner["commands"][2]["stderrSha256"] == '
  'digest(b""))\n'
  '          result = {"schemaVersion": 1, "scope": '
  '"ordinary-ui-observed-original-saved-version-rollback-and-fresh-load",\n'),
 (309252,
  82,
  '9f74bc560a8262b224ff4b68c5b01314439b2d9e8ae3dd3c0852451f507f839b',
  '          summary_bytes = read("normal-ui/saved-version-recovery-summary.raw.json", 262144)\n'),
 (308123,
  839,
  '93dc97b6ab8b18aa28d3a341e71fa1c17acd5a16bb50394dd726719f78737c09',
  '          runner, runner_bytes = admitted("saved-version-recovery-test.runner-admission.json", "test", 585,\n'
  '              [roster, ("saved-version-source-roster", 15, 65536, 0), ("saved-version-core-interrupt", 20, 65536, '
  '86),\n'
  '               ("verify-generated-runner", 30, 1048576, 0), ("generated-runner-entitlements", 30, 1048576, 0),\n'
  '               ("one-admitted-ui-test", 420, 1048576, 0), roster])\n'
  '          summary_owner, summary_owner_bytes = admitted("saved-version-recovery-summary.command-admission.json", '
  '"summary", 90,\n'),
 (305682,
  150,
  '1ea836eb80a7f4e54a6c682a19cd5ec65369e488399eb253a910f4b80f3d46d7',
  '                   and value.get("sourceCommit") == source and value.get("target") == target and '
  'value.get("resultBundle") == "saved-version-recovery-test.xcresult"\n'),
 (305030,
  95,
  '5cbd6d7290ea5cb8bf28f89492dca8f64b2e4b9c903fb84914dc3b933625c094',
  '          for name in ("build", "saved-version-recovery-test-file-limit", "saved-version-recovery-test", '
  '"saved-version-recovery-summary"):\n'),
 (303941,
  0,
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  '          need(os.environ["MRK_MACOS_SAVED_FILE_UI_SCOPE"] == "saved-version-recovery")\n'),
 (301673,
  547,
  '6047762ee9d6c02c50fc06a4d584b637d351bc948d8f0da012f26183d0d3e8fe',
  '              if not value: raise ValueError("original saved-version recovery binding refused")\n'),
 (301576,
  66,
  'c8d99524a0b36aa40ed5750b4c3e81fdc55dbdbd7c34ac0afeb78aa77ebc9e32',
  '              raise ValueError("saved-version result SOURCE differs")\n'),
 (301011,
  100,
  'ffa8efa5bb9f0ff59745bb37853951dcfb628705fe2881928758fd58d81d95a0',
  '          printf \'%s\\n\' "$summary_status" > "$MRK_MACOS_WORK/normal-ui/saved-version-recovery-summary.status"\n'),
 (300655,
  283,
  'bc08e127ca87f1bf7ec187847f0894fbb3abce38442e8dcb8fa83ef681429264',
  '            "$MRK_PYTHON" -I -S -B desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" '
  '--normal-summary saved-version-recovery-test.xcresult \\\n'
  '            > "$MRK_MACOS_WORK/normal-ui/saved-version-recovery-summary.raw.json" 2> '
  '"$MRK_MACOS_WORK/normal-ui/saved-version-recovery-summary.stderr"\n'),
 (300067, 343, 'c1c9eb9ab87521f518a7c63a9056201d9f7ff37ada9480a7ed377b38e336f6e2', ''),
 (299648,
  262,
  '3a759c0048ae101b0c371faaf79c5d8dce1e5dc06fb9f9f967bc40a39af5b4c3',
  "        if: github.ref == 'refs/heads/verify/desktop-macos-preview' && "
  "steps.normal_saved_version_recovery_ui_test.outcome == 'success' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == "
  "'saved-version-recovery'\n"),
 (299491,
  104,
  'a295c36879b006e35c9536afb9eecca98c104b83e71d96cf5d3f710a66b44b76',
  '      - name: Bind the singleton saved-version recovery to original XCTest and the same ordinary package\n'),
 (299328,
  94,
  '11a05e29dac5b101a4cebd4aa1380ea58a0a41b2475eaf0ae378fd10e46373a9',
  '          printf \'%s\\n\' "$test_status" > "$MRK_MACOS_WORK/normal-ui/saved-version-recovery-test.status"\n'),
 (299207,
  69,
  '236043dc2e3c74d2681c2cbfbb4cc6c6728b4d040ba5c584fd03c2ad9d63bfd2',
  '            > "$MRK_MACOS_WORK/normal-ui/saved-version-recovery-test.log" 2>&1\n'),
 (298785,
  172,
  'a93e5ac7e4d414096982e8bd2a1be26c6a58833b131fb5dc3bcffd284a7d9c7d',
  '            -resultBundlePath "$MRK_MACOS_WORK/normal-ui/saved-version-recovery-test.xcresult" \\\n'
  '            -only-testing:MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedVersionRecovery \\\n'),
 (298244,
  114,
  '90b4fd64a09a64d4d8a8c0bc6024d82aa22cf90169e6242f1f5c6f8d2f5b341d',
  '          # One 300s recovery journey; unchanged420s command/585s phase, including the fixed20s producer.\n'),
 (297261,
  122,
  'd093a0380bc51bcc7672693f969af8d24cf13103755e3c52f32a8c11f7307a4c',
  '          printf \'%s\\n\' "$file_limit_status" > '
  '"$MRK_MACOS_WORK/normal-ui/saved-version-recovery-test-file-limit.status" || exit $?\n'),
 (297072, 343, 'c1c9eb9ab87521f518a7c63a9056201d9f7ff37ada9480a7ed377b38e336f6e2', ''),
 (296661,
  253,
  'b42009f70fc9ea61fa34b4e53f6823c4dc7a6dc607536bb442581fd7a8e59947',
  "        if: github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome "
  "== 'success' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery'\n"),
 (296518,
  105,
  '9ed585b466ec2361e34aa42774b5a4e88a5b2e7d3b1a4a05c61e57a349fb7259',
  '      - name: Recover one real interrupted saved-version journal through the ordinary Mac UI\n'),
 (322009, 527, '208640236d3e7a4695ae9af7177327bc538d348918e1564d5b94b841647ef4f5', ''),
 (336370,
  195,
  '455beda55ca0c1eef5420f6805c675e56da566eea999c21884ebb342f37244c6',
  "(env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery' && "
  "steps.normal_saved_version_recovery_ui_result.outcome == 'success'))"),
 (338706,
  91,
  '9a4e77caf8e16f2cac57280b59a58433cebe0384e59e48e0ee2af1763c79373c',
  '          if scope not in ("ordinary-seven", "saved-version-recovery"):'),
 (338866,
  238,
  '1a2441af766022dd62d9db6c67bcc1aa7db31db24a4ea865745d3d7fabd911b8',
  '          test_stem, summary_stem = (("saved-checks-test", "saved-checks-summary") if scope == "ordinary-seven"\n'
  '                                    else ("saved-version-recovery-test", "saved-version-recovery-summary"))'))


# Closed progressive UTF8-byte inverse; historical assertions retain their exact original source.
RELEASE_EVIDENCE_WORKFLOW_INVERSE = ((8803,
  60,
  '5021b1db991227ff34a62cd91b75377e330b451af458a7c186a3c1c99a94a5da',
  'saved-version-recovery|workflow-refusal) [['),
 (296549,
  106,
  'c15797119e4c5c4d40061259978c01d0fe5eea5d56a60119abae694cdd8995aa',
  'Exercise one selected saved-version recovery or GitHub refusal through the ordinary Mac UI'),
 (296706,
  312,
  'fef86b009d1000d8d15b5cd6f6188e746b414b43e1d2d6e8903e4ce7dd19f4e0',
  "        if: github.ref == 'refs/heads/verify/desktop-macos-preview' && "
  "steps.normal_diagnostics_ui_result.outcome == 'success' && (env.MRK_MACOS_SAVED_FILE_UI_SCOPE == "
  "'saved-version-recovery' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'workflow-refusal')\n"),
 (300102,
  321,
  '3c6c8b1e45aa11c123fdedd499e7e628c7de06b6adc4acc7a4f594c5ed7f371b',
  "        if: github.ref == 'refs/heads/verify/desktop-macos-preview' && "
  "steps.normal_saved_version_recovery_ui_test.outcome == 'success' && (env.MRK_MACOS_SAVED_FILE_UI_SCOPE == "
  "'saved-version-recovery' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'workflow-refusal')\n"),
 (336112,
  748,
  '4835fe322b6fedaac2ee6dbe0e531981bc2a4edd6534c9ee905e46882f1f85f9',
  "        if: always() && steps.preview_upload.outcome == 'success' && steps.normal_ui_result.outcome == "
  "'success' && steps.normal_persistence_ui_result.outcome == 'success' && "
  "steps.normal_project_ui_result.outcome == 'success' && steps.normal_diagnostics_ui_result.outcome == "
  "'success' && ((env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven' && "
  "steps.normal_saved_checks_ui_result.outcome == 'success') || ((env.MRK_MACOS_SAVED_FILE_UI_SCOPE == "
  "'saved-version-recovery' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'workflow-refusal') && "
  "steps.normal_saved_version_recovery_ui_result.outcome == 'success')) && steps.data_contracts.outcome == "
  "'success' && steps.evidence.outcome == 'success'\n"),
 (297419,
  376,
  '05cb73facc88c77c7edab74ade310ff76ed02bc811b5871a58989b615fae7de4',
  '            workflow-refusal) singleton=workflow-refusal; '
  'singleton_method=testSyntheticProjectManagedWorkflowRefusal ;;\n'
  '            *) exit 1 ;;\n'
  '          esac\n'
  '          # Finite per-file logical size only; not RAM, total disk, service limits or finality.\n'),
 (300942,
  369,
  '8541a9c29269af604b8a23e4799bdd619790d9e8696286e6e4b8d6e7cb0b630f',
  '            workflow-refusal) singleton=workflow-refusal; '
  'singleton_method=testSyntheticProjectManagedWorkflowRefusal ;;\n'
  '            *) exit 1 ;;\n'
  '          esac\n'
  '          # Each summary has its own finite one-GiB file limit and original owner phase.\n'),
 (302920,
  392,
  '5c769c7f77ed5691579d1080b404493224c4d2d537efd681f86a4976680fa28b',
  '              need(type(scope) is str and scope in ("saved-version-recovery", "workflow-refusal"))\n'
  '              return (scope, "testSyntheticProjectSavedVersionRecovery" if scope == '
  '"saved-version-recovery"\n'
  '                      else "testSyntheticProjectManagedWorkflowRefusal")'),
 (311714,
  1472,
  '16fab05e49ad7a17c1c53c91e03336e45bb818972eb5028559f708c689c5e22c',
  '              if scope == "workflow-refusal":\n'
  '                  need(runner.get("managedWorkflowRefusalMarkerObserved") is True\n'
  '                       and "savedVersionRecovery" not in runner and runtime_digest is None)'),
 (323763,
  1054,
  'afbe17f96cacd20de62251b3c52fd8a7688dda934edd56ff6d2d0e54f5dd1e7e',
  '            {0}/normal-ui/workflow-refusal-test-file-limit.status\n'
  '            {0}/normal-ui/workflow-refusal-test.status\n'
  '            {0}/normal-ui/workflow-refusal-test.runner-admission.json\n'
  '            {0}/normal-ui/workflow-refusal-test.failure-diagnostics.json\n'
  '            {0}/normal-ui/workflow-refusal-summary.status\n'
  '            {0}/normal-ui/workflow-refusal-summary.command-admission.json\n'
  '            {0}/normal-ui/workflow-refusal-summary.failure-diagnostics.json\n'
  '            {0}/normal-ui/workflow-refusal-result.json\n'),
 (341056,
  101,
  '6386ee92ac46e7842c6bb28401376d32771724d3393456d53daad8e3b7d7bf13',
  'if scope not in ("ordinary-seven", "saved-version-recovery", "workflow-refusal"):'),
 (341330,
  104,
  '900e8a281f11cd3bddc346a58e380328531165c5ed02394c620a2bbff46dd0b8',
  '                  "workflow-refusal": "workflow-refusal"}[scope]'))

APP_SIGNATURE_WORKFLOW_INVERSE = ((273, 43, '7fce308b4a7080ff7750eac96f2d9b4cffbb3783b4122ba8cba542498acb5bfd', ''), (711, 65, '41559436d557d14e00f7d258f8c4e12dbe18d63c9fa21299122ea4ef10cecc72', ''), (1535, 196, '19f9ce6b7d1ec6a940317d1ab55b2a8098cd4c1dc4888103cf0534954547c57f', 'timeout-minutes: 350'), (8496, 346, '007ec8dc2b6263d463042cde185b2b11532cd97452239be023a87962e7dec487', ') ]] || exit 1'), (22387, 392, '140f1114a37be725631dc52ff0d6e6d7bc70c25a2643c3ede69bcadaa9f7435d', ''), (28064, 404, 'f02b9ddfefd341e9b719b357cfefbd9e153c83ca836d04b6e334969e895d37ce', ''), (6090, 106, 'e2d105aeb112cfd2bd59cf0647c033334694eb6acce215f761c44f7138231cc7', ''), (12337, 106, 'd50f52c13a8a19f68b2c33b50d5b25e6dd20d369fe17756888f8b9bbdc25d5b2', ''), (12803, 106, '7ee78366225f739c169111fbefed37f411bcbbd3cc2690ce927f99a229829b0a', ''), (16823, 106, '7ee78366225f739c169111fbefed37f411bcbbd3cc2690ce927f99a229829b0a', ''), (17177, 106, '7ee78366225f739c169111fbefed37f411bcbbd3cc2690ce927f99a229829b0a', ''), (25310, 106, 'd50f52c13a8a19f68b2c33b50d5b25e6dd20d369fe17756888f8b9bbdc25d5b2', ''), (46887, 22, '7c17228c1639da37cc0cb9c729e8fa369e145457f66dbca110e45efa0b5b819a', ''), (47906, 24, '4bd7d18a6ab921647f28b9f705afce990e7be141983b0261a1bd78a2027b46cd', ''), (49834, 569, '0cb195b9032334ab1fde6250bd5a506aa55210401354052606487836d0941e5d', "== 'refs/heads/verify/desktop-macos-removal-lifecycle' || github.ref == 'refs/heads/verify/desktop-macos-preview' || (github.ref == 'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build') || (github.ref == 'refs/heads/verify/desktop-macos-installed' && env.MRK_MACOS_IOS_UI_SCOPE == 'ios-unsigned-archive' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'disabled' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven'"), (56371, 74, 'f866c0025f1d76e1354383cae0e5b786337ee91bc1feb88d224c96904116adbc', ''), (59904, 113, 'f5a33c75c6ce8fc9ab4318b9ff1c9c73431c21443fda21b6e7c5c4dd7aec9064', "== 'refs/heads/verify/desktop-macos-installed'"), (73979, 26, '597f8c7b070b180f75b720d5e0ed56c9d8516121f2362472835a8d2ca9f62a3f', ''), (77317, 22, '1ff00fb090aa18879ebc52e6139b586ab4df0a1f8ae2bf554349f760fd5d4971', ''), (81724, 22, '26477eb4b9b1e9f4e33d895f3a8078a3c0dd77bf259f688adef6a71076ccc3d6', ''), (86995, 25, '77ab554b279f18d90fa1e1c00e32cc72ccd74339ab1691df1db5c4813a45c27f', ''), (91240, 111, '3724c9e86afa31131d048471eac2cbf9e34d37ffd9ceaad11df2f9454396a35c', "== 'refs/heads/verify/desktop-macos-preview'"), (91584, 25, '5cc48d8e6d98662ab3c2aab2df255eae1e5ec11f1feda55fd65b35debb50f20d', ''), (99092, 74, 'f866c0025f1d76e1354383cae0e5b786337ee91bc1feb88d224c96904116adbc', ''), (101598, 113, 'f5a33c75c6ce8fc9ab4318b9ff1c9c73431c21443fda21b6e7c5c4dd7aec9064', "== 'refs/heads/verify/desktop-macos-installed'"), (109317, 85, '2644bb6d6cdfe3a94764f272420ae678b46e191a59addb024a0e7bb20d1991f0', "removal-lifecycle'"), (113961, 85, '2644bb6d6cdfe3a94764f272420ae678b46e191a59addb024a0e7bb20d1991f0', "removal-lifecycle'"), (116948, 85, '2644bb6d6cdfe3a94764f272420ae678b46e191a59addb024a0e7bb20d1991f0', "removal-lifecycle'"), (117883, 74, 'f866c0025f1d76e1354383cae0e5b786337ee91bc1feb88d224c96904116adbc', ''), (122676, 74, 'f866c0025f1d76e1354383cae0e5b786337ee91bc1feb88d224c96904116adbc', ''), (125088, 74, 'bad463f354b2a866e9cf26c7a6d2e05a0a489eec8c9f6e744e83f2a8efb2b615', ''), (127216, 308, 'ab9cdf74283bafd177c5d7f4f3f00fecc8d0e2e1afd617e17e6dec40263465c8', "== 'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build' && steps.normal_ui_build.outcome == 'success' && steps.package_install.outcome == 'success'"), (130098, 314, 'ed4d8df25865bb2efa1affa1aae5e6735d5fdcc45207f0f28dd32b27e8979442', "== 'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build' && steps.normal_android_inputs.outcome == 'success' && steps.package_install.outcome == 'success'"), (132865, 315, 'c7db2067611ed9836dea7e55cd0efdbcdca216304f6aef8d00395619e34bf015', "== 'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build' && steps.normal_android_ui_test.outcome == 'success' && steps.package_install.outcome == 'success'"), (157373, 366, 'eea4d991941793cc3ff538b64e95b890df2522d3461df258b3bccc68b244918f', "== 'refs/heads/verify/desktop-macos-installed' && env.MRK_MACOS_IOS_UI_SCOPE == 'ios-unsigned-archive' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'disabled' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven' && steps.normal_ui_build.outcome == 'success' && steps.package_install.outcome == 'success'"), (160117, 415, 'b91605221b6e03330e1de20fec73ff21c41bf31c8851e403dc87eaec309db3d6', "== 'refs/heads/verify/desktop-macos-installed' && env.MRK_MACOS_IOS_UI_SCOPE == 'ios-unsigned-archive' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'disabled' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven' && steps.normal_ios_ui_test.outcome == 'success' && steps.normal_ui_build.outcome == 'success' && steps.package_install.outcome == 'success'"), (162951, 111, '3724c9e86afa31131d048471eac2cbf9e34d37ffd9ceaad11df2f9454396a35c', "== 'refs/heads/verify/desktop-macos-preview'"), (164606, 180, '8c4abdb5c61de686aec61b6587e7bcf2c5111317be45104dfcd69d973594f235', "== 'refs/heads/verify/desktop-macos-preview' || github.ref == 'refs/heads/verify/desktop-macos-removal-lifecycle'"), (168336, 180, '8c4abdb5c61de686aec61b6587e7bcf2c5111317be45104dfcd69d973594f235', "== 'refs/heads/verify/desktop-macos-preview' || github.ref == 'refs/heads/verify/desktop-macos-removal-lifecycle'"), (170714, 180, '8c4abdb5c61de686aec61b6587e7bcf2c5111317be45104dfcd69d973594f235', "== 'refs/heads/verify/desktop-macos-preview' || github.ref == 'refs/heads/verify/desktop-macos-removal-lifecycle'"), (172776, 213, '43ed53d5845b014b6ed81e99151694b3ecd71ce09e89d25f19f2aa373b92db13', "== 'refs/heads/verify/desktop-macos-removal-lifecycle' && steps.removal_package.outcome == 'success' && steps.normal_ui_build.outcome == 'success'"), (175646, 215, 'f90633631773d375f84c5b8e75e7e2f4a4a0125844ec4e11a37514f56b489aeb', "== 'refs/heads/verify/desktop-macos-removal-lifecycle' && steps.removal_observers.outcome == 'success' && steps.normal_ui_build.outcome == 'success'"), (177434, 111, '3724c9e86afa31131d048471eac2cbf9e34d37ffd9ceaad11df2f9454396a35c', "== 'refs/heads/verify/desktop-macos-preview'"), (179130, 111, '3724c9e86afa31131d048471eac2cbf9e34d37ffd9ceaad11df2f9454396a35c', "== 'refs/heads/verify/desktop-macos-preview'"), (180189, 149, 'c9f8c1b898ebe47511fc19a92d4779c383cf0fd9bdd3add2fe114ea267529845', "== 'refs/heads/verify/desktop-macos-preview' && steps.preview.outcome == 'success'"), (181255, 202, '80a104c2c0efbbebaecb3357f952d702096bd2ec9274733a50e9889e055086bc', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_build.outcome == 'success' && steps.preview_upload.outcome == 'success'"), (185986, 156, '04803e48fbef0bb42a74922ce1f3f1d52ed0d93229d52140c613b22c3aa02bbd', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_test.outcome == 'success'"), (200721, 158, '22a1be5e5346d3f9463dbcbec338a30f1612bae9eb3aab8ed6f9347c44767cee', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_result.outcome == 'success'"), (205582, 164, 'ec40c206029f6e512ed2542530214ccd1c2b27ae228b6eb636c4a5edb22d50aa', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_project_ui_test.outcome == 'success'"), (221342, 158, '22a1be5e5346d3f9463dbcbec338a30f1612bae9eb3aab8ed6f9347c44767cee', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_result.outcome == 'success'"), (229607, 168, 'e84aa7b7c1c39bcca3049d9454603cbdb2f1329bec45cc9c04d7a74bdbb41aab', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_persistence_ui_test.outcome == 'success'"), (248219, 170, 'd1cf60824d1d2edbaada6b17cc0cb4b260eaa273653bd503a4b1ea9b8827f85f', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_persistence_ui_result.outcome == 'success'"), (256538, 168, '04d55d596e2237f5bb1673b6f5eca44367d66a3a05b8595d55d127d7f5a2b3f2', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_test.outcome == 'success'"), (275763, 227, 'af714bbb5dd50503c6e50c46cad8b225faa61d5b41d5009163553cfe33a05429', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome == 'success' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven'"), (284537, 169, '8a205d64a41a2fb50e9668e96d3f1dc3cf06cfd29505d360f916c4781c664ce7', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_saved_checks_ui_test.outcome == 'success'"), (306585, 354, '98d0f1fff12aee1fdc4d912ff203420fb5ecbaaba63381407e1992308e8fe322', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome == 'success' && (env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'workflow-refusal' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'release-evidence'"), (310167, 363, 'b77a50fe6b42263b79e7c5c58bbcc09478e6af96e7f7acc5158cc2d0e6942dfb', "== 'refs/heads/verify/desktop-macos-preview' && steps.normal_saved_version_recovery_ui_test.outcome == 'success' && (env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'workflow-refusal' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'release-evidence'"), (328621, 108, '5c417bb5e050744e16fefbeb795e9f68f08a699c1f2e2e4245c922c3e43f96f8', "always() && steps.work.outputs.root != ''"), (348311, 802, '4a646c829e8f95a14c43b2abf5d5ad076e9284d64a7a10f1f330002887c0482c', "always() && steps.preview_upload.outcome == 'success' && steps.normal_ui_result.outcome == 'success' && steps.normal_persistence_ui_result.outcome == 'success' && steps.normal_project_ui_result.outcome == 'success' && steps.normal_diagnostics_ui_result.outcome == 'success' && ((env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven' && steps.normal_saved_checks_ui_result.outcome == 'success') || ((env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'workflow-refusal' || env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'release-evidence') && steps.normal_saved_version_recovery_ui_result.outcome == 'success')) && steps.data_contracts.outcome == 'success' && steps.evidence.outcome == 'success'"), (99000, 6360, '1fd61cebe258aef7e40106cf2093ea57d052bf385053c294bbd41d23ef25faac', ''))

# Exact recent SOURCE deltas only; the historical tables and their final
# predecessor hashes below remain authoritative for every other byte.
RECENT_APP_SIGNATURE_WORKFLOW_INVERSE = (('prebuild',
  ('Check fixed optional-array argv before native preparation',
   'tests/desktop/test_macos_optional_arrays.py',
   '# App-signature:82 timed preparation +14 bounded setup'),
  (('    # App-signature:82 timed preparation +14 bounded setup +7 summary/cleanup/upload;7 overhead.\n',
    '    # App-signature:82 timed preparation +13 bounded setup +7 summary/cleanup/upload;8 overhead.\n'),
   ('      - name: Check fixed optional-array argv before native preparation\n'
    '        timeout-minutes: 1\n'
    '        shell: bash\n'
    '        run: |\n'
    '          set -euo pipefail\n'
    '          /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$MRK_PYTHON" -I -S -B \\\n'
    '            tests/desktop/test_macos_optional_arrays.py \\\n'
    '            MacOSOptionalArraysTests.test_optional_arrays_preserve_empty_and_quoted_argv_under_nounset '
    '-v\n',
    ''))),
 ('optional arrays',
  ('${history_provider_arguments[@]+', '${removal_arguments[@]+', '${github_seal_arguments[@]+'),
  (('            --target "$MRK_MACOS_TARGET" '
    '${history_provider_arguments[@]+"${history_provider_arguments[@]}"} \\\n',
    '            --target "$MRK_MACOS_TARGET" "${history_provider_arguments[@]}" \\\n'),
   ('          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py app --target "$MRK_MACOS_TARGET" '
    '${removal_arguments[@]+"${removal_arguments[@]}"} '
    '${github_seal_arguments[@]+"${github_seal_arguments[@]}"} \\\n',
    '          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py app --target "$MRK_MACOS_TARGET" '
    '"${removal_arguments[@]}" "${github_seal_arguments[@]}" \\\n'),
   ('          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py remove-scripts --target '
    '"$MRK_MACOS_TARGET" ${removal_arguments[@]+"${removal_arguments[@]}"} \\\n',
    '          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py remove-scripts --target '
    '"$MRK_MACOS_TARGET" "${removal_arguments[@]}" \\\n'),
   ('          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py prepare-remove-package --target '
    '"$MRK_MACOS_TARGET" ${removal_arguments[@]+"${removal_arguments[@]}"} --expected-remover '
    '"$MRK_MACOS_REMOVER_SHA256" \\\n',
    '          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py prepare-remove-package --target '
    '"$MRK_MACOS_TARGET" "${removal_arguments[@]}" --expected-remover "$MRK_MACOS_REMOVER_SHA256" \\\n'))),
 ('confidential diagnostics',
  ('confidential_compiler',
   'macos_resident_confidential_capture.py',
   'Encrypt only the settled failed ARM compiler captures',
   'Retain ciphertext and finite transport receipt only',
   'confidential-resident-compiler-'),
  (('      # TEMPORARY verification-only diagnostic. Never copy to product workflows.\n'
    '      - name: Encrypt only the settled failed ARM compiler captures\n'
    '        id: confidential_compiler\n'
    "        if: failure() && github.ref == 'refs/heads/verify/desktop-macos-app-signature' && matrix.target "
    "== 'aarch64-apple-darwin' && steps.work.outcome == 'success' && steps.android_helper.outcome == "
    "'failure'\n"
    '        timeout-minutes: 2\n'
    '        shell: bash\n'
    '        env:\n'
    '          RUNNER_ENVIRONMENT: ${{ runner.environment }}\n'
    '        run: |\n'
    '          set +x\n'
    '          set -euo pipefail\n'
    '          umask 077\n'
    '          ulimit -c 0\n'
    '          "$MRK_PYTHON" -I -S -B desktop/tools/macos_resident_confidential_capture.py\n'
    '      - name: Retain ciphertext and finite transport receipt only\n'
    "        if: always() && github.ref == 'refs/heads/verify/desktop-macos-app-signature' && matrix.target == "
    "'aarch64-apple-darwin' && steps.confidential_compiler.outcome == 'success'\n"
    '        timeout-minutes: 2\n'
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: confidential-resident-compiler-${{ github.sha }}-${{ github.run_id }}-${{ '
    'github.run_attempt }}\n'
    '          path: |\n'
    '            ${{ steps.work.outputs.root }}/resident-compiler-confidential/cargo-capture.cms\n'
    '            ${{ steps.work.outputs.root }}/resident-compiler-confidential/receipt.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 1\n'
    '          compression-level: 0\n',
    ''),)))


# Exact public-evidence/export-only successor. Never refresh the historical
# workflow hashes or treat reconstructed private capture paths as upload policy.
PUBLIC_VERIFICATION_WORKFLOW_INVERSE = (('.github/workflows/desktop-macos-installed.yml',
  'name: Desktop Mac normal package and limited early preview (Aqua gate separate)\n',
  'f6a2aae527c8daceb01621195f127d83fdb5e33a0de59e1d27744d79462bd071',
  (('            /usr/bin/tail -c 16384 "$MRK_MACOS_WORK/vault-helper-build.stderr" >&2\n'
    '            /usr/bin/tail -c 32768 "$MRK_MACOS_WORK/vault-helper-build.jsonl" >&2\n',
    "            printf 'Fixed vault helper compiler failed with original status %s; originals remain local.\\n' "
    '"$status" >&2 || :\n'),
   ('          if [[ "$remover_status" != 0 ]]; then\n'
    '            # Optional diagnostics cannot replace the original compiler status.\n'
    '            set +e\n'
    "            printf 'Fixed remover compiler failed with original status %s; bounded diagnostics are "
    'retained.\\n\' "$remover_status" >&2\n'
    '            /usr/bin/tail -c 16384 "$MRK_MACOS_WORK/remover-build.stderr" >&2\n'
    '            exit "$remover_status"\n'
    '          fi\n',
    '          if [[ "$remover_status" != 0 ]]; then\n'
    '            # Optional diagnostics cannot replace the original compiler status.\n'
    '            set +e\n'
    "            printf 'Fixed remover compiler failed with original status %s; bounded diagnostics are "
    'retained.\\n\' "$remover_status" >&2\n'
    '            exit "$remover_status"\n'
    '          fi\n'),
   ('            "$@" 2>&1 | /usr/bin/tee /dev/stderr | /usr/bin/tail -c 131072 > "$MRK_MACOS_WORK/$label.log"\n',
    '            "$@" 2>&1 | /usr/bin/tee /dev/null | /usr/bin/tail -c 131072 > "$MRK_MACOS_WORK/$label.log"\n'),
   ('      - name: Preserve bounded originals; upload success is never GUI/native acceptance\n',
    '      - name: Project closed public verification facts without raw originals\n'
    '        id: public_evidence\n'
    "        if: github.ref != 'refs/heads/verify/desktop-macos-app-signature' && (always() && "
    "steps.work.outputs.root != '')\n"
    '        timeout-minutes: 1\n'
    '        shell: bash\n'
    '        run: |\n'
    '          set -euo pipefail\n'
    '          umask 077\n'
    '          /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \\\n'
    '            "$MRK_PYTHON" -I -S -B desktop/tools/macos_public_verification_evidence.py \\\n'
    '            --profile installed --work "$MRK_MACOS_WORK" --target "$MRK_MACOS_TARGET" \\\n'
    '            --source "$GITHUB_SHA" --workflow-source "$GITHUB_WORKFLOW_SHA" \\\n'
    '            --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"\n'
    '      - name: Preserve bounded originals; upload success is never GUI/native acceptance\n'),
   ('      - name: Preserve bounded originals; upload success is never GUI/native acceptance\n'
    '        id: evidence\n'
    "        if: github.ref != 'refs/heads/verify/desktop-macos-app-signature' && (always() && "
    "steps.work.outputs.root != '')\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-installed-${{ matrix.target }}${{ matrix.removal_case && '
    "format('-removal-{0}', matrix.removal_case) || '' }}-${{ github.sha }}-${{ github.run_id }}-${{ "
    'github.run_attempt }}\n'
    '          path: |\n'
    "            ${{ format('{0}/source-binding.json\n"
    '            {0}/removal-observer-build.status\n'
    '            {0}/removal-observers.status\n'
    '            {0}/android-helper-prepare-removal-observers.json\n'
    '            {0}/package-removal-fixture.status\n'
    '            {0}/android-helper-package-removal-fixture.json\n'
    '            {0}/normal-ui/removal-ordinary-test.runner-admission.json\n'
    '            {0}/normal-ui/removal-abrupt-test.runner-admission.json\n'
    '            {0}/normal-ui/android-inputs.status\n'
    '            {0}/normal-ui/android-input-status.json\n'
    '            {0}/prepare-ui-inputs-failure.json\n'
    '            {0}/normal-ui/android-signed-build-test.status\n'
    '            {0}/normal-ui/android-signed-build-summary.status\n'
    '            {0}/normal-ui/android-signed-build-result.status\n'
    '            {0}/normal-ui/android-signed-build.facts.json\n'
    '            {0}/normal-ui/android-signed-build-result.json\n'
    '            {0}/normal-ui/ios-unsigned-archive-test.status\n'
    '            {0}/normal-ui/ios-unsigned-archive-summary.status\n'
    '            {0}/normal-ui/ios-unsigned-archive.facts.json\n'
    '            {0}/normal-ui/ios-unsigned-archive-test.runner-admission.json\n'
    '            {0}/normal-ui/ios-unsigned-archive-summary.command-admission.json\n'
    '            {0}/normal-ui/ios-unsigned-archive-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/ios-unsigned-archive-summary.failure-diagnostics.json\n'
    '            {0}/effective-rust-toolchain.json\n'
    '            {0}/source-inventory.json\n'
    '            {0}/data-contracts/mount.stdout\n'
    '            {0}/data-contracts/mount.stderr\n'
    '            {0}/data-contracts/mount.status\n'
    '            {0}/data-contracts/apfs.stdout\n'
    '            {0}/data-contracts/apfs.stderr\n'
    '            {0}/data-contracts/apfs.status\n'
    '            {0}/data-contracts/build.stdout\n'
    '            {0}/data-contracts/build.stderr\n'
    '            {0}/data-contracts/build.status\n'
    '            {0}/data-contracts/rust.stdout\n'
    '            {0}/data-contracts/rust.stderr\n'
    '            {0}/data-contracts/rust.status\n'
    '            {0}/data-contracts/python.stdout\n'
    '            {0}/data-contracts/python.stderr\n'
    '            {0}/data-contracts/python.status\n'
    '            {0}/data-contracts/result.json\n'
    '            {0}/normal-build.jsonl\n'
    '            {0}/normal-build.status\n'
    '            {0}/normal-build.stderr.tail.txt\n'
    '            {0}/preview-result.json\n'
    '            {0}/normal-ui/build-file-limit.status\n'
    '            {0}/normal-ui/build-file-budget.status\n'
    '            {0}/normal-ui/build-file-budget.json\n'
    '            {0}/normal-ui/test-file-limit.status\n'
    '            {0}/normal-ui/test-file-budget.status\n'
    '            {0}/normal-ui/test-file-budget.json\n'
    '            {0}/normal-ui/project-test-file-limit.status\n'
    '            {0}/normal-ui/project-test-file-budget.status\n'
    '            {0}/normal-ui/project-test-file-budget.json\n'
    '            {0}/normal-ui/persistence-test-file-limit.status\n'
    '            {0}/normal-ui/persistence-test-file-budget.status\n'
    '            {0}/normal-ui/persistence-test-file-budget.json\n'
    '            {0}/normal-ui/toolchain.failure-diagnostics.json\n'
    '            {0}/normal-ui/build.failure-diagnostics.json\n'
    '            {0}/normal-ui/build.admission-diagnostics.json\n'
    '            {0}/normal-ui/build.command-admission.json\n'
    '            {0}/normal-ui/test.failure-diagnostics.json\n'
    '            {0}/normal-ui/summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/summary.command-admission.json\n'
    '            {0}/normal-ui/project-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/project-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/project-summary.command-admission.json\n'
    '            {0}/normal-ui/persistence-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/persistence-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/persistence-summary.command-admission.json\n'
    '            {0}/normal-ui/diagnostics-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/diagnostics-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/diagnostics-summary.command-admission.json\n'
    '            {0}/normal-ui/saved-checks-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/saved-checks-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/saved-checks-summary.command-admission.json\n'
    '            {0}/normal-ui/saved-version-recovery-test-file-limit.status\n'
    '            {0}/normal-ui/saved-version-recovery-test.status\n'
    '            {0}/normal-ui/saved-version-recovery-test.runner-admission.json\n'
    '            {0}/normal-ui/saved-version-recovery-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/saved-version-recovery-summary.status\n'
    '            {0}/normal-ui/saved-version-recovery-summary.command-admission.json\n'
    '            {0}/normal-ui/saved-version-recovery-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/saved-version-recovery-result.json\n'
    '            {0}/normal-ui/workflow-refusal-test-file-limit.status\n'
    '            {0}/normal-ui/workflow-refusal-test.status\n'
    '            {0}/normal-ui/workflow-refusal-test.runner-admission.json\n'
    '            {0}/normal-ui/workflow-refusal-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/workflow-refusal-summary.status\n'
    '            {0}/normal-ui/workflow-refusal-summary.command-admission.json\n'
    '            {0}/normal-ui/workflow-refusal-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/workflow-refusal-result.json\n'
    '            {0}/normal-ui/release-evidence-test-file-limit.status\n'
    '            {0}/normal-ui/release-evidence-test.status\n'
    '            {0}/normal-ui/release-evidence-test.runner-admission.json\n'
    '            {0}/normal-ui/release-evidence-test.failure-diagnostics.json\n'
    '            {0}/normal-ui/release-evidence-summary.status\n'
    '            {0}/normal-ui/release-evidence-summary.command-admission.json\n'
    '            {0}/normal-ui/release-evidence-summary.failure-diagnostics.json\n'
    '            {0}/normal-ui/release-evidence-result.json\n'
    '            {0}/normal-ui/build.status\n'
    '            {0}/normal-ui/test.status\n'
    '            {0}/normal-ui/test.runner-admission.json\n'
    '            {0}/normal-ui/summary.status\n'
    '            {0}/normal-ui/xcode-version.txt\n'
    '            {0}/normal-ui/sdk-path.txt\n'
    '            {0}/normal-ui/sdk-version.txt\n'
    '            {0}/normal-ui/sdk-build.txt\n'
    '            {0}/normal-ui/result.json\n'
    '            {0}/normal-ui/persistence-test.status\n'
    '            {0}/normal-ui/persistence-test.runner-admission.json\n'
    '            {0}/normal-ui/persistence-diagnostics.json\n'
    '            {0}/normal-ui/persistence-summary.status\n'
    '            {0}/normal-ui/persistence-result.json\n'
    '            {0}/normal-ui/project-test.status\n'
    '            {0}/normal-ui/project-test.runner-admission.json\n'
    '            {0}/normal-ui/project-summary.status\n'
    '            {0}/normal-ui/project-result.json\n'
    '            {0}/normal-ui/diagnostics-test-file-limit.status\n'
    '            {0}/normal-ui/diagnostics-test-file-budget.status\n'
    '            {0}/normal-ui/diagnostics-test-file-budget.json\n'
    '            {0}/normal-ui/diagnostics-test.status\n'
    '            {0}/normal-ui/diagnostics-test.runner-admission.json\n'
    '            {0}/normal-ui/diagnostics-safe-facts.json\n'
    '            {0}/normal-ui/diagnostics-summary.status\n'
    '            {0}/normal-ui/diagnostics-result.json\n'
    '            {0}/normal-ui/saved-checks-test-file-limit.status\n'
    '            {0}/normal-ui/saved-checks-test-file-budget.status\n'
    '            {0}/normal-ui/saved-checks-test-file-budget.json\n'
    '            {0}/normal-ui/saved-checks-test.status\n'
    '            {0}/normal-ui/saved-checks-test.runner-admission.json\n'
    '            {0}/normal-ui/saved-checks-safe-facts.json\n'
    '            {0}/normal-ui/saved-checks-summary.status\n'
    '            {0}/normal-ui/saved-checks-result.json\n'
    '            {0}/package-format-input.json\n'
    '            {0}/PackageFormat-original.pkg\n'
    '            {0}/package-format-prepare.json\n'
    '            {0}/package-format-tar.status\n'
    '            {0}/package-format-xar.status\n'
    '            {0}/package-format-audit.json\n'
    '            {0}/package-format-final/PackageFormat.pkg\n'
    '            {0}/native-acl-compile.log\n'
    '            {0}/native-acl-compile.status\n'
    '            {0}/native-acl-probe.log\n'
    '            {0}/native-acl-probe.status\n'
    '            {0}/native-acl-cleanup.status\n'
    '            {0}/native-acl-probe-result.json\n'
    '            {0}/runtime-result.json\n'
    '            {0}/fresh-python-transport-result.json\n'
    '            {0}/android-support-result.json\n'
    '            {0}/vault-helper-build.status\n'
    '            {0}/vault-helper-build.jsonl\n'
    '            {0}/vault-helper-build.stderr\n'
    '            {0}/vault-helper-signing.json\n'
    '            {0}/android-helper-prepare.json\n'
    '            {0}/android-helper-build.jsonl\n'
    '            {0}/android-helper-build.stderr\n'
    '            {0}/android-helper-build.status\n'
    '            {0}/android-helper-resident-image-sign.stdout\n'
    '            {0}/android-helper-resident-image-sign.stderr\n'
    '            {0}/android-helper-resident-image-sign.status\n'
    '            {0}/android-helper-resident-image-verify-signed.stdout\n'
    '            {0}/android-helper-resident-image-verify-signed.stderr\n'
    '            {0}/android-helper-resident-image-verify-signed.status\n'
    '            {0}/android-helper-entry-build.stdout\n'
    '            {0}/android-helper-entry-build.stderr\n'
    '            {0}/android-helper-entry-build.status\n'
    '            {0}/android-helper-desktop-facade-build.stdout\n'
    '            {0}/android-helper-desktop-facade-build.stderr\n'
    '            {0}/android-helper-desktop-facade-build.status\n'
    '            {0}/android-helper-resident-facade-build.stdout\n'
    '            {0}/android-helper-resident-facade-build.stderr\n'
    '            {0}/android-helper-resident-facade-build.status\n'
    '            {0}/android-helper-verify-before-resident-image.stdout\n'
    '            {0}/android-helper-verify-before-resident-image.stderr\n'
    '            {0}/android-helper-verify-before-resident-image.status\n'
    '            {0}/android-helper-verify-after-resident-image.stdout\n'
    '            {0}/android-helper-verify-after-resident-image.stderr\n'
    '            {0}/android-helper-verify-after-resident-image.status\n'
    '            {0}/android-helper-sign.stdout\n'
    '            {0}/android-helper-sign.stderr\n'
    '            {0}/android-helper-sign.status\n'
    '            {0}/android-helper-verify-signed.stdout\n'
    '            {0}/android-helper-verify-signed.stderr\n'
    '            {0}/android-helper-verify-signed.status\n'
    '            {0}/android-helper-verify-before.stdout\n'
    '            {0}/android-helper-verify-before.stderr\n'
    '            {0}/android-helper-verify-before.status\n'
    '            {0}/android-helper-verify-after.stdout\n'
    '            {0}/android-helper-verify-after.stderr\n'
    '            {0}/android-helper-verify-after.status\n'
    '            {0}/android-helper-verify-before.json\n'
    '            {0}/android-helper-verify-after.json\n'
    '            {0}/android-helper-sign-vault-helper.json\n'
    '            {0}/android-helper-sign-desktop-image.json\n'
    '            {0}/android-helper-sign-desktop-payload.json\n'
    '            {0}/android-helper-sign-root-app.json\n'
    '            {0}/android-helper-sign-root-installer.json\n'
    '            {0}/remover-build.jsonl\n'
    '            {0}/remover-build.stderr\n'
    '            {0}/remover-build.status\n'
    '            {0}/android-helper-sign-remover.json\n'
    '            {0}/app-result.json\n'
    '            {0}/input-result.json\n'
    '            {0}/dialog-regressions.log\n'
    '            {0}/dialog-regressions.status\n'
    '            {0}/installer-finalizer-regression.log\n'
    '            {0}/installer-finalizer-regression.status\n'
    '            {0}/native-abi-regression.log\n'
    '            {0}/native-abi-regression.status\n'
    '            {0}/focused-regressions.json\n'
    '            {0}/scripts-fixture-result.json\n'
    '            {0}/package-fixture-audit.json\n'
    '            {0}/installer-fixture-output.txt\n'
    '            {0}/installer-fixture-output.status\n'
    '            {0}/installer-fixture-log-cursor.json\n'
    '            {0}/installer-fixture-log-cursor.status\n'
    '            {0}/installer-fixture-log-capture.json\n'
    '            {0}/installer-fixture-log-capture.status\n'
    '            {0}/installer-fixture-log-selected.txt\n'
    '            {0}/installer-fixture-observation.json\n'
    '            {0}/MobileReleaseKit-InstallerFixture-original.pkg\n'
    '            {0}/package-fixture-prepare.json\n'
    '            {0}/package-fixture-tar.status\n'
    '            {0}/package-fixture-xar.status\n'
    '            {0}/package-fixture-final/MobileReleaseKit-InstallerFixture.pkg\n'
    '            {0}/scripts-result.json\n'
    '            {0}/package-audit.json\n'
    '            {0}/installation-observation.json\n'
    '            {0}/installer-output.txt\n'
    '            {0}/installer-output.status\n'
    '            {0}/installer-log-cursor.json\n'
    '            {0}/installer-log-cursor.status\n'
    '            {0}/installer-log-capture.json\n'
    '            {0}/installer-log-capture.status\n'
    '            {0}/installer-log-selected.txt\n'
    '            {0}/MobileReleaseKit-original.pkg\n'
    '            {0}/package-prepare.json\n'
    '            {0}/package-tar.status\n'
    '            {0}/package-xar.status\n'
    '            {0}/package-final/MobileReleaseKit.pkg\n'
    '            {0}/packaging-selection.json\n'
    '            {0}/producer-root/Install.pkg\n'
    '            {0}/producer-root/producer.json\n'
    '            {0}/producer-root/producer.sig\n'
    '            {0}/distribution/MobileReleaseKit.dmg\n'
    '            {0}/distribution/MobileReleaseKit-Observation.dmg\n'
    '            {0}/package-request-id.txt\n'
    '            {0}/android-helper-package-install.json\n'
    '            {0}/remove-scripts-result.json\n'
    '            {0}/remove-package-prepare.json\n'
    '            {0}/remove-package-tar.status\n'
    '            {0}/remove-package-xar.status\n'
    '            {0}/remove-package-finalization.status\n'
    '            {0}/package-remove.status\n'
    '            {0}/remove-image-finalization.status\n'
    '            {0}/android-helper-finalize-remove-package.json\n'
    '            {0}/android-helper-package-remove.json\n'
    '            {0}/android-helper-finalize-remove-image.json\n'
    '            {0}/remove-preview-result.json\n'
    '            {0}/android-helper-notarize-payload.json\n'
    '            {0}/android-helper-finalize-package.json\n'
    '            {0}/package-finalization.status\n'
    '            {0}/image-finalization.status\n'
    '            {0}/image-finalization.stdout\n'
    '            {0}/image-finalization.stderr\n'
    '            {0}/android-helper-finalize-image.json\n'
    '            {0}/android-helper-final-image-resolve-notarytool.stdout\n'
    '            {0}/android-helper-final-image-resolve-notarytool.stderr\n'
    '            {0}/android-helper-final-image-resolve-notarytool.status\n'
    '            {0}/android-helper-final-image-resolve-stapler.stdout\n'
    '            {0}/android-helper-final-image-resolve-stapler.stderr\n'
    '            {0}/android-helper-final-image-resolve-stapler.status\n'
    '            {0}/android-helper-final-image-signature-before.stdout\n'
    '            {0}/android-helper-final-image-signature-before.stderr\n'
    '            {0}/android-helper-final-image-signature-before.status\n'
    '            {0}/android-helper-final-image-submit.stdout\n'
    '            {0}/android-helper-final-image-submit.stderr\n'
    '            {0}/android-helper-final-image-submit.status\n'
    '            {0}/android-helper-final-image-log.stdout\n'
    '            {0}/android-helper-final-image-log.stderr\n'
    '            {0}/android-helper-final-image-log.status\n'
    '            {0}/android-helper-final-image-staple.stdout\n'
    '            {0}/android-helper-final-image-staple.stderr\n'
    '            {0}/android-helper-final-image-staple.status\n'
    '            {0}/android-helper-final-image-validate.stdout\n'
    '            {0}/android-helper-final-image-validate.stderr\n'
    '            {0}/android-helper-final-image-validate.status\n'
    '            {0}/android-helper-final-image-signature-after.stdout\n'
    '            {0}/android-helper-final-image-signature-after.stderr\n'
    '            {0}/android-helper-final-image-signature-after.status\n'
    '            {0}/android-helper-final-image-verify.stdout\n'
    '            {0}/android-helper-final-image-verify.stderr\n'
    '            {0}/android-helper-final-image-verify.status\n'
    '            {0}/android-helper-final-image-attach.stdout\n'
    '            {0}/android-helper-final-image-attach.stderr\n'
    '            {0}/android-helper-final-image-attach.status\n'
    '            {0}/android-helper-final-image-detach.stdout\n'
    '            {0}/android-helper-final-image-detach.stderr\n'
    '            {0}/android-helper-final-image-detach.status\n'
    '            {0}/package-install.stdout\n'
    '            {0}/package-install.stderr\n'
    '            {0}/package-install.status\n'
    '            {0}/android-helper-producer-build.stdout\n'
    '            {0}/android-helper-producer-build.stderr\n'
    '            {0}/android-helper-producer-build.status\n'
    '            {0}/android-helper-producer-emitter.stdout\n'
    '            {0}/android-helper-producer-emitter.stderr\n'
    '            {0}/android-helper-producer-emitter.status\n'
    '            {0}/android-helper-distribution-create.stdout\n'
    '            {0}/android-helper-distribution-create.stderr\n'
    '            {0}/android-helper-distribution-create.status\n'
    '            {0}/android-helper-distribution-sign.stdout\n'
    '            {0}/android-helper-distribution-sign.stderr\n'
    '            {0}/android-helper-distribution-sign.status\n'
    '            {0}/android-helper-distribution-verify-signature.stdout\n'
    '            {0}/android-helper-distribution-verify-signature.stderr\n'
    '            {0}/android-helper-distribution-verify-signature.status\n'
    '            {0}/android-helper-distribution-verify-image.stdout\n'
    '            {0}/android-helper-distribution-verify-image.stderr\n'
    '            {0}/android-helper-distribution-verify-image.status\n'
    '            {0}/android-helper-observation-create.stdout\n'
    '            {0}/android-helper-observation-create.stderr\n'
    '            {0}/android-helper-observation-create.status\n'
    '            {0}/android-helper-observation-sign.stdout\n'
    '            {0}/android-helper-observation-sign.stderr\n'
    '            {0}/android-helper-observation-sign.status\n'
    '            {0}/android-helper-observation-verify-signature.stdout\n'
    '            {0}/android-helper-observation-verify-signature.stderr\n'
    '            {0}/android-helper-observation-verify-signature.status\n'
    '            {0}/android-helper-observation-verify-image.stdout\n'
    '            {0}/android-helper-observation-verify-image.stderr\n'
    '            {0}/android-helper-observation-verify-image.status\n'
    '            {0}/android-helper-distribution-attach.stdout\n'
    '            {0}/android-helper-distribution-attach.stderr\n'
    '            {0}/android-helper-distribution-attach.status\n'
    '            {0}/android-helper-installer-log-cursor.stdout\n'
    '            {0}/android-helper-installer-log-cursor.stderr\n'
    '            {0}/android-helper-installer-log-cursor.status\n'
    '            {0}/android-helper-installer.stdout\n'
    '            {0}/android-helper-installer.stderr\n'
    '            {0}/android-helper-installer.status\n'
    '            {0}/android-helper-installer-log-capture.stdout\n'
    '            {0}/android-helper-installer-log-capture.stderr\n'
    '            {0}/android-helper-installer-log-capture.status\n'
    '            {0}/android-helper-distribution-detach.stdout\n'
    '            {0}/android-helper-distribution-detach.stderr\n'
    "            {0}/android-helper-distribution-detach.status', steps.work.outputs.root) }}\n"
    '          if-no-files-found: error\n'
    '          retention-days: 14\n'
    '          compression-level: 0\n'
    '      # Do not start a payload build, host scan, notice-only task, service,\n'
    '      # publication of a release, Store workflow, or synthetic GUI success here.\n'
    '      # The focused real Aqua/Save procedure and separate command/result gates\n'
    '      # are in desktop/packaging/macos-installed.md.\n',
    '      - name: Preserve bounded originals; upload success is never GUI/native acceptance\n'
    '        id: evidence\n'
    "        if: github.ref != 'refs/heads/verify/desktop-macos-app-signature' && (always() && "
    "steps.work.outputs.root != '') && steps.public_evidence.outcome == 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-installed-${{ matrix.target }}${{ matrix.removal_case && '
    "format('-removal-{0}', matrix.removal_case) || '' }}-${{ github.sha }}-${{ github.run_id }}-${{ "
    'github.run_attempt }}\n'
    '          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 14\n'
    '          compression-level: 0\n'
    '      # Do not start a payload build, host scan, notice-only task, service,\n'
    '      # publication of a release, Store workflow, or synthetic GUI success here.\n'
    '      # The focused real Aqua/Save procedure and separate command/result gates\n'
    '      # are in desktop/packaging/macos-installed.md.\n'))),
 ('.github/workflows/desktop-macos-aqua.yml',
  'name: Desktop macOS genuine Aqua engineering verification\n',
  '3ada5fb2ddacbc22ab11e039e9028cc729e7383cb3467f19977ddf17a1d4f258',
  (('            /usr/bin/tail -c 16384 "$MRK_MACOS_WORK/vault-helper-build.stderr" >&2\n'
    '            /usr/bin/tail -c 32768 "$MRK_MACOS_WORK/vault-helper-build.jsonl" >&2\n',
    "            printf 'Fixed vault helper compiler failed with original status %s; originals remain local.\\n' "
    '"$status" >&2 || :\n'),
   ('          if [[ "$remover_status" != 0 ]]; then\n'
    '            # Optional diagnostics cannot replace the original compiler status.\n'
    '            set +e\n'
    "            printf 'Fixed remover compiler failed with original status %s; bounded diagnostics are "
    'retained.\\n\' "$remover_status" >&2\n'
    '            /usr/bin/tail -c 16384 "$MRK_MACOS_WORK/remover-build.stderr" >&2\n'
    '            exit "$remover_status"\n'
    '          fi\n',
    '          if [[ "$remover_status" != 0 ]]; then\n'
    '            # Optional diagnostics cannot replace the original compiler status.\n'
    '            set +e\n'
    "            printf 'Fixed remover compiler failed with original status %s; bounded diagnostics are "
    'retained.\\n\' "$remover_status" >&2\n'
    '            exit "$remover_status"\n'
    '          fi\n'),
   ('      - name: Preserve bounded original evidence; upload alone is not an Aqua pass\n',
    '      - name: Project closed public verification facts without raw originals\n'
    '        id: public_evidence\n'
    "        if: always() && steps.work.outputs.root != ''\n"
    '        timeout-minutes: 1\n'
    '        shell: bash\n'
    '        run: |\n'
    '          set -euo pipefail\n'
    '          umask 077\n'
    '          /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC \\\n'
    '            "$MRK_PYTHON" -I -S -B desktop/tools/macos_public_verification_evidence.py \\\n'
    '            --profile aqua --work "$MRK_MACOS_WORK" --target "$MRK_MACOS_TARGET" \\\n'
    '            --source "$GITHUB_SHA" --workflow-source "$GITHUB_WORKFLOW_SHA" \\\n'
    '            --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"\n'
    '      - name: Preserve bounded original evidence; upload alone is not an Aqua pass\n'),
   ('      - name: Preserve bounded original evidence; upload alone is not an Aqua pass\n'
    "        if: always() && steps.work.outputs.root != '' && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || "
    "env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || "
    "env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs' || env.MRK_MACOS_AQUA_SCOPE == "
    "'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'installation-inspection' || env.MRK_MACOS_AQUA_SCOPE "
    "== 'vault-helper-shipping-installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending' "
    "|| env.MRK_MACOS_AQUA_SCOPE == 'ios-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' || "
    "env.MRK_MACOS_AQUA_SCOPE == 'local-edits3')\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ '
    'env.MRK_MACOS_AQUA_SCOPE }}-${{ matrix.target }}\n'
    '          path: |\n'
    '            ${{ steps.work.outputs.root }}/source-binding.json\n'
    '            ${{ steps.work.outputs.root }}/package-format-input.json\n'
    '            ${{ steps.work.outputs.root }}/PackageFormat-original.pkg\n'
    '            ${{ steps.work.outputs.root }}/package-format-prepare.json\n'
    '            ${{ steps.work.outputs.root }}/package-format-tar.status\n'
    '            ${{ steps.work.outputs.root }}/package-format-xar.status\n'
    '            ${{ steps.work.outputs.root }}/package-format-audit.json\n'
    '            ${{ steps.work.outputs.root }}/package-format-final/PackageFormat.pkg\n'
    '            ${{ steps.work.outputs.root }}/source-inventory.json\n'
    '            ${{ steps.work.outputs.root }}/xcode-host-preparation-intent.json\n'
    '            ${{ steps.work.outputs.root }}/xcode-host-preparation-result.json\n'
    '            ${{ steps.work.outputs.root }}/runtime-result.json\n'
    '            ${{ steps.work.outputs.root }}/fresh-python-transport-result.json\n'
    '            ${{ steps.work.outputs.root }}/android-support-result.json\n'
    '            ${{ steps.work.outputs.root }}/headless-build.admitted.jsonl\n'
    '            ${{ steps.work.outputs.root }}/headless-build.stderr.tail.txt\n'
    '            ${{ steps.work.outputs.root }}/headless-build.status\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.stdout\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.stderr\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.status\n'
    '            ${{ steps.work.outputs.root }}/headless-catalogue-tests.stdout\n'
    '            ${{ steps.work.outputs.root }}/headless-catalogue-tests.stderr\n'
    '            ${{ steps.work.outputs.root }}/headless-catalogue-tests.status\n'
    '            ${{ steps.work.outputs.root }}/headless-native-tests.stdout\n'
    '            ${{ steps.work.outputs.root }}/headless-native-tests.stderr\n'
    '            ${{ steps.work.outputs.root }}/headless-native-tests.status\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/shipping-gate-control.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/shipping-gate-control.status\n'
    '            ${{ steps.work.outputs.root }}/shipping-capacity-data.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/shipping-capacity-data.status\n'
    '            ${{ steps.work.outputs.root }}/frontend-data.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/frontend-data-tests.stdout\n'
    '            ${{ steps.work.outputs.root }}/frontend-data-tests.stderr\n'
    '            ${{ steps.work.outputs.root }}/observer-build.admitted.jsonl\n'
    '            ${{ steps.work.outputs.root }}/observer-build.stderr.tail.txt\n'
    '            ${{ steps.work.outputs.root }}/bounded-diagnostics.json\n'
    '            ${{ steps.work.outputs.root }}/observer-build.status\n'
    '            ${{ steps.work.outputs.root }}/vault-helper-build.status\n'
    '            ${{ steps.work.outputs.root }}/vault-helper-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/vault-helper-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/vault-helper-signing.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-prepare.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/android-helper-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-build.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-image-sign.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-image-sign.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-image-sign.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-image-verify-signed.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-image-verify-signed.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-image-verify-signed.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-entry-build.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-entry-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-entry-build.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-desktop-facade-build.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-desktop-facade-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-desktop-facade-build.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-facade-build.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-facade-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-resident-facade-build.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before-resident-image.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before-resident-image.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before-resident-image.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after-resident-image.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after-resident-image.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after-resident-image.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-signed.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-signed.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-signed.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-before.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-verify-after.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign-vault-helper.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign-desktop-payload.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign-root-app.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign-root-installer.json\n'
    '            ${{ steps.work.outputs.root }}/remover-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/remover-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/remover-build.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-sign-remover.json\n'
    '            ${{ steps.work.outputs.root }}/app-result.json\n'
    '            ${{ steps.work.outputs.root }}/input-result.json\n'
    '            ${{ steps.work.outputs.root }}/scripts-result.json\n'
    '            ${{ steps.work.outputs.root }}/package-audit.json\n'
    '            ${{ steps.work.outputs.root }}/installation-observation.json\n'
    '            ${{ steps.work.outputs.root }}/installer-output.tail.txt\n'
    '            ${{ steps.work.outputs.root }}/installer-output.status\n'
    '            ${{ steps.work.outputs.root }}/installer-log-cursor.json\n'
    '            ${{ steps.work.outputs.root }}/installer-log-cursor.status\n'
    '            ${{ steps.work.outputs.root }}/installer-log-capture.json\n'
    '            ${{ steps.work.outputs.root }}/installer-log-capture.status\n'
    '            ${{ steps.work.outputs.root }}/installer-log-selected.txt\n'
    '            ${{ steps.work.outputs.root }}/MobileReleaseKit-original.pkg\n'
    '            ${{ steps.work.outputs.root }}/package-prepare.json\n'
    '            ${{ steps.work.outputs.root }}/package-tar.status\n'
    '            ${{ steps.work.outputs.root }}/package-xar.status\n'
    '            ${{ steps.work.outputs.root }}/package-final/MobileReleaseKit.pkg\n'
    '            ${{ steps.work.outputs.root }}/packaging-selection.json\n'
    '            ${{ steps.work.outputs.root }}/producer-root/Install.pkg\n'
    '            ${{ steps.work.outputs.root }}/producer-root/producer.json\n'
    '            ${{ steps.work.outputs.root }}/producer-root/producer.sig\n'
    '            ${{ steps.work.outputs.root }}/distribution/MobileReleaseKit.dmg\n'
    '            ${{ steps.work.outputs.root }}/distribution/MobileReleaseKit-Observation.dmg\n'
    '            ${{ steps.work.outputs.root }}/package-request-id.txt\n'
    '            ${{ steps.work.outputs.root }}/android-helper-package-install.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-notarize-payload.json\n'
    '            ${{ steps.work.outputs.root }}/android-helper-finalize-package.json\n'
    '            ${{ steps.work.outputs.root }}/package-finalization.status\n'
    '            ${{ steps.work.outputs.root }}/package-install.stdout\n'
    '            ${{ steps.work.outputs.root }}/package-install.stderr\n'
    '            ${{ steps.work.outputs.root }}/package-install.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-producer-build.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-producer-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-producer-build.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-producer-emitter.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-producer-emitter.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-producer-emitter.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-create.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-create.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-create.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-sign.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-sign.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-sign.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-verify-signature.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-verify-signature.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-verify-signature.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-verify-image.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-verify-image.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-verify-image.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-create.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-create.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-create.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-sign.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-sign.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-sign.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-verify-signature.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-verify-signature.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-verify-signature.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-verify-image.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-verify-image.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-observation-verify-image.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-attach.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-attach.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-attach.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer-log-cursor.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer-log-cursor.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer-log-cursor.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer-log-capture.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer-log-capture.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-installer-log-capture.status\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-detach.stdout\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-detach.stderr\n'
    '            ${{ steps.work.outputs.root }}/android-helper-distribution-detach.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-project-fields-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-project-fields-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-project-fields.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-android-inputs-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-android-inputs-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-android-inputs.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-local-edits3-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-local-edits3-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-local-edits3.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-doctor-preflight2-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-doctor-preflight2-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-doctor-preflight2.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-vault-helper-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-vault-helper-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-vault-helper.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-installation-inspection-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-installation-inspection-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-installation-inspection.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-project-recovery-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-project-recovery-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-project-recovery.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-ios-account-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-ios-account-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-ios-account.status\n'
    '            ${{ steps.work.outputs.root }}/aqua-results.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua-failure.jsonl\n'
    '            ${{ steps.work.outputs.root }}/aqua.status\n'
    '          if-no-files-found: error\n'
    '          retention-days: 14\n'
    '          compression-level: 0\n'
    '      # Instrumented engineering evidence only. No release, Store mutation,\n'
    '      # shipping-binary equivalence, notarization or physical-device claim.\n'
    '      # On uncertainty retain originals; runner disposal is not observed here.\n',
    '      - name: Preserve bounded original evidence; upload alone is not an Aqua pass\n'
    "        if: always() && steps.work.outputs.root != '' && (env.MRK_MACOS_AQUA_SCOPE == 'project-fields' || "
    "env.MRK_MACOS_AQUA_SCOPE == 'ios-current-synthetic' || env.MRK_MACOS_AQUA_SCOPE == 'android-inputs' || "
    "env.MRK_MACOS_AQUA_SCOPE == 'project-fields-android-inputs' || env.MRK_MACOS_AQUA_SCOPE == "
    "'vault-helper-shipping' || env.MRK_MACOS_AQUA_SCOPE == 'installation-inspection' || env.MRK_MACOS_AQUA_SCOPE "
    "== 'vault-helper-shipping-installation-inspection' || env.MRK_MACOS_AQUA_SCOPE == 'project-recovery-pending' "
    "|| env.MRK_MACOS_AQUA_SCOPE == 'ios-recovery-pending' || env.MRK_MACOS_AQUA_SCOPE == 'doctor-preflight2' || "
    "env.MRK_MACOS_AQUA_SCOPE == 'local-edits3') && steps.public_evidence.outcome == 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}-${{ '
    'env.MRK_MACOS_AQUA_SCOPE }}-${{ matrix.target }}\n'
    '          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 14\n'
    '          compression-level: 0\n'
    '      # Instrumented engineering evidence only. No release, Store mutation,\n'
    '      # shipping-binary equivalence, notarization or physical-device claim.\n'
    '      # On uncertainty retain originals; runner disposal is not observed here.\n'),
   ('      - name: Preserve bounded Android lifecycle results and original workflow exit evidence\n'
    "        if: always() && env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle' && steps.source.outcome "
    "== 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
    '}}-android-registration-lifecycle\n'
    '          path: |\n'
    '            ${{ steps.work.outputs.root }}/source-inventory.json\n'
    '            ${{ steps.work.outputs.root }}/headless-build.admitted.jsonl\n'
    '            ${{ steps.work.outputs.root }}/headless-build.stderr.tail.txt\n'
    '            ${{ steps.work.outputs.root }}/headless-build.status\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.stdout\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.stderr\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.status\n'
    '            ${{ steps.work.outputs.root }}/headless-native-tests.stdout\n'
    '            ${{ steps.work.outputs.root }}/headless-native-tests.stderr\n'
    '            ${{ steps.work.outputs.root }}/headless-native-tests.status\n'
    '            ${{ steps.work.outputs.root }}/headless-tests.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/bounded-diagnostics.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 14\n',
    '      - name: Preserve bounded Android lifecycle results and original workflow exit evidence\n'
    "        if: always() && env.MRK_MACOS_AQUA_SCOPE == 'android-registration-lifecycle' && steps.source.outcome "
    "== 'success' && steps.public_evidence.outcome == 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
    '}}-android-registration-lifecycle\n'
    '          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 14\n'),
   ('      - name: Preserve bounded classification DATA and original workflow exit evidence\n'
    "        if: always() && env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification' && steps.source.outcome "
    "== 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
    '}}-xcode-installed-classification\n'
    '          path: |\n'
    '            ${{ steps.work.outputs.root }}/source-inventory.json\n'
    '            ${{ steps.work.outputs.root }}/xcode-installed-classification-result.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 7\n',
    '      - name: Preserve bounded classification DATA and original workflow exit evidence\n'
    "        if: always() && env.MRK_MACOS_AQUA_SCOPE == 'xcode-installed-classification' && steps.source.outcome "
    "== 'success' && steps.public_evidence.outcome == 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
    '}}-xcode-installed-classification\n'
    '          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 7\n'),
   ('      - name: Preserve bounded private-cohort public facts and compiler-only diagnostics\n'
    "        if: always() && env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private' && steps.source.outcome == "
    "'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
    '}}-wrapping-keychain-private\n'
    '          path: |\n'
    '            ${{ steps.work.outputs.root }}/source-inventory.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-native.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-native.report.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-before-add.report.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-before-lookup.report.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-creator.report.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-reader.report.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-pair.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-codec.receipt.json\n'
    '            ${{ steps.work.outputs.root }}/wrapping-codec-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/wrapping-codec-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/wrapping-codec-build.status\n'
    '            ${{ steps.work.outputs.root }}/wrapping-normal-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/wrapping-normal-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/wrapping-normal-build.status\n'
    '            ${{ steps.work.outputs.root }}/wrapping-observer-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/wrapping-observer-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/wrapping-observer-build.status\n'
    '            ${{ steps.work.outputs.root }}/wrapping-qualification-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/wrapping-qualification-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/wrapping-qualification-build.status\n'
    '            ${{ steps.work.outputs.root }}/wrapping-reader-build.jsonl\n'
    '            ${{ steps.work.outputs.root }}/wrapping-reader-build.stderr\n'
    '            ${{ steps.work.outputs.root }}/wrapping-reader-build.status\n'
    '          if-no-files-found: error\n'
    '          retention-days: 7\n'
    '          compression-level: 0\n'
    '      # Never upload native stdout/stderr, a private Keychain, task-root contents\n'
    '      # or a diagnostic filesystem sweep. Uncertainty has no fixture cleanup.\n',
    '      - name: Preserve bounded private-cohort public facts and compiler-only diagnostics\n'
    "        if: always() && env.MRK_MACOS_AQUA_SCOPE == 'wrapping-keychain-private' && steps.source.outcome == "
    "'success' && steps.public_evidence.outcome == 'success'\n"
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n'
    '        with:\n'
    '          name: desktop-macos-aqua-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt '
    '}}-wrapping-keychain-private\n'
    '          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json\n'
    '          if-no-files-found: error\n'
    '          retention-days: 7\n'
    '          compression-level: 0\n'
    '      # Never upload native stdout/stderr, a private Keychain, task-root contents\n'
    '      # or a diagnostic filesystem sweep. Uncertainty has no fixture cleanup.\n'))))
PUBLIC_VERIFICATION_WORKFLOW_MARKERS = ('public_evidence',
 'public-verification-evidence.json',
 'macos_public_verification_evidence.py',
 'Fixed vault helper compiler failed with original status',
 '          if [[ "$remover_status" != 0 ]]; then\n'
 '            # Optional diagnostics cannot replace the original compiler status.\n'
 '            set +e\n'
 "            printf 'Fixed remover compiler failed with original status %s; bounded diagnostics are "
 'retained.\\n\' "$remover_status" >&2\n'
 '            exit "$remover_status"\n'
 '          fi\n',
 '            "$@" 2>&1 | /usr/bin/tee /dev/null | /usr/bin/tail -c 131072 > "$MRK_MACOS_WORK/$label.log"\n')


# Exact Intel-only app-build allocation, before every historical workflow layer.
# Marker-free old intermediates stay unchanged; whole-predecessor hashes remain authoritative.
INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE = (('    # Raw timed-step union535min; disjoint scopes retain the350min hard job cap.\n'
  '    # Pre-Remove baseline preview345 / recovery339 / installed210, plus5 overhead.\n'
  '    # Remove preview adds90 nominal step maxima; this sum establishes no fit.\n'
  '    # Dormant Android272 / iOS248 include5 overhead; no native qualification claimed.\n'
  '    # Fixed removal uses its own two fresh ARM rows, the same350min ceiling,\n'
  '    # separate baseline Install/UI-build preparation, O3 work1740/hard1800,\n'
  '    # then one removal owner990 (fixed segment sum963); no budget restart.\n'
  '    # App-signature:82 timed preparation +14 bounded setup +7 summary/cleanup/upload;7 overhead.\n',
  '    # Raw timed-step union535min (ARM) /559min (Intel); no job fit is established.\n'
  '    # Historical pre-Remove baselines: preview345 / recovery339 / installed210, plus5 overhead.\n'
  '    # Remove preview adds90 nominal step maxima; Intel app-build adds24 to the old allocation.\n'
  '    # Dormant Android272 / iOS248 include5 overhead; historical baselines, not fit proofs.\n'
  '    # Fixed removal uses its own two fresh ARM rows, the same350min ceiling,\n'
  '    # separate baseline Install/UI-build preparation, O3 work1740/hard1800,\n'
  '    # then one removal owner990 (fixed segment sum963); no budget restart.\n'
  '    # App-signature: ARM82 / Intel106 timed preparation +14 bounded setup\n'
  '    # +7 summary/cleanup/upload;7 overhead. Independent110 hard cap takes precedence.\n'),
 ('        id: app_build\n        timeout-minutes: 24\n',
  '        id: app_build\n'
  "        timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 48 || 24 }}\n"),
 ('          # Same24-minute app-build budget; no independent timeout entitlement.\n',
  '          # Same architecture-selected app-build budget; no independent timeout entitlement.\n'))
INTEL_APP_BUILD_BUDGET_WORKFLOW_MARKERS = ('Raw timed-step union535min (ARM) /559min (Intel)', "matrix.target == 'x86_64-apple-darwin' && 48 || 24", 'Same architecture-selected app-build budget')


def without_intel_app_build_budget_workflow(source):
    if not isinstance(source, str) or len(source.encode()) > 512 * 1024:
        raise AssertionError("Intel app-build budget workflow source bound differs")
    if not any(marker in source for marker in INTEL_APP_BUILD_BUDGET_WORKFLOW_MARKERS):
        return source
    if not source.startswith("name: Desktop Mac normal package and limited early preview (Aqua gate separate)\n"):
        raise AssertionError("Intel app-build budget workflow route differs")
    for previous, current in INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE:
        if source.count(current) != 1 or source.count("\n" + current) != 1 or previous in source:
            raise AssertionError("Intel app-build budget workflow exact delta differs")
    for previous, current in reversed(INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE):
        source = source.replace("\n" + current, "\n" + previous, 1)
    if any(marker in source for marker in INTEL_APP_BUILD_BUDGET_WORKFLOW_MARKERS):
        raise AssertionError("Intel app-build budget workflow partial delta remains")
    return source


# One exact optional removal-case CLI suffix, before the original privacy inverse.
# This is SOURCE normalization only, never removal or original-finality evidence.
REMOVAL_PUBLIC_VERIFICATION_WORKFLOW_INVERSE = ('            --profile installed --work "$MRK_MACOS_WORK" --target "$MRK_MACOS_TARGET" \\\n            --source "$GITHUB_SHA" --workflow-source "$GITHUB_WORKFLOW_SHA" \\\n            --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"\n', '            --profile installed --work "$MRK_MACOS_WORK" --target "$MRK_MACOS_TARGET" \\\n            --source "$GITHUB_SHA" --workflow-source "$GITHUB_WORKFLOW_SHA" \\\n            --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" \\\n            --removal-case "$MRK_MACOS_REMOVAL_CASE"\n')


def without_removal_public_verification_workflow(source):
    if not isinstance(source, str) or len(source.encode()) > 512 * 1024:
        raise AssertionError("removal public verification workflow source bound differs")
    source = without_intel_app_build_budget_workflow(source)
    # Retire the independent outer shipping-privacy delta before historical hashes.
    source = without_shipping_compile_privacy_workflow(source)
    installed = "name: Desktop Mac normal package and limited early preview (Aqua gate separate)\n"
    if "desktop/tools/macos_public_verification_evidence.py" not in source or not source.startswith(installed):
        if "--removal-case" in source:
            raise AssertionError("removal public verification workflow route differs")
        return source
    previous, current = REMOVAL_PUBLIC_VERIFICATION_WORKFLOW_INVERSE
    anchor = '--profile installed --work "$MRK_MACOS_WORK" --target "$MRK_MACOS_TARGET"'
    if source.count(anchor) != 1:
        raise AssertionError("removal public verification workflow anchor differs")
    if source.count(previous) == 1 and source.count("\n" + previous) == 1 and "--removal-case" not in source:
        return source
    if (source.count(current) != 1 or source.count("\n" + current) != 1
            or previous in source or source.count("--removal-case") != 1):
        raise AssertionError("removal public verification workflow exact delta differs")
    return source.replace("\n" + current, "\n" + previous, 1)


def without_public_verification_workflow(source):
    source = without_removal_public_verification_workflow(source)
    if not isinstance(source, str) or len(source.encode()) > 512 * 1024:
        raise AssertionError("public verification workflow source bound differs")
    if not any(marker in source for marker in PUBLIC_VERIFICATION_WORKFLOW_MARKERS):
        return source
    selected = [rows for path, header, prior_hash, rows in PUBLIC_VERIFICATION_WORKFLOW_INVERSE
                if source.startswith(header)]
    if len(selected) != 1:
        raise AssertionError("public verification workflow exact route differs")
    for previous, current in reversed(selected[0]):
        if source.count(current) != 1 or source.count("\n" + current) != 1:
            raise AssertionError("public verification workflow exact delta differs")
        source = source.replace("\n" + current, "\n" + previous, 1)
    if any(marker in source for marker in PUBLIC_VERIFICATION_WORKFLOW_MARKERS):
        raise AssertionError("public verification workflow partial delta remains")
    return source


def without_recent_app_signature_workflow(source):
    source = without_public_verification_workflow(source)
    if not isinstance(source, str) or len(source.encode()) > 512 * 1024:
        raise AssertionError("recent app signature workflow source bound differs")
    for label, markers, replacements in RECENT_APP_SIGNATURE_WORKFLOW_INVERSE:
        if not any(marker in source for marker in markers):
            continue
        if any(source.count(current) != 1 or source.count("\n" + current) != 1
               or (previous and previous in source) for current, previous in replacements):
            raise AssertionError("recent app signature workflow " + label + " exact delta differs")
        for current, previous in replacements:
            source = source.replace("\n" + current, "\n" + previous, 1)
        if any(marker in source for marker in markers):
            raise AssertionError("recent app signature workflow " + label + " partial delta remains")
    return source


def without_enrolled_runtime_source_pin(source):
    # The configured gh profile adds one real SOURCE row. Undo only the
    # installed workflow's new two-site pin before its exact app-scope inverse.
    # Unchanged Aqua still uses the old 177-row pin and bypasses this layer.
    enrolled = "58f6d68d2db29100ed15fd8c4f8d893b3a0a3dbe1d8cd37b385690c36b9cfa3d"
    preceding = "f35a69f6a0e4baf2b365fc28662152d529564107738da9f477363dcc2ea6cdc2"
    if enrolled in source:
        configured = "      MRK_BUNDLED_RUNTIME_SOURCE_SHA256: " + enrolled + "\n"
        guard = '          [[ "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256" =~ ^[0-9a-f]{64}$ && "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256" == ' + enrolled + ' ]] || exit 1\n'
        if (source.count(enrolled) != 2 or preceding in source
                or source.count("\n" + configured) != 1 or source.count("\n" + guard) != 1):
            raise AssertionError("current runtime source pin exact two-site delta differs")
        for line in (configured, guard):
            source = source.replace("\n" + line, "\n" + line.replace(enrolled, preceding), 1)
    return source


def without_app_signature_workflow(source):
    source = without_recent_app_signature_workflow(source)
    source = without_enrolled_runtime_source_pin(source)
    if "verify/desktop-macos-app-signature" not in source:
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(APP_SIGNATURE_WORKFLOW_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("app signature workflow region changed")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "fdbe8fcc6595ce90cb5cab397b4050cf53c164132198252d6b6ada4be4b83081":
        raise AssertionError("app signature workflow inverse changed predecessor")
    return value.decode()


# This exact current two-site pin delta is independent of the historical
# workflow additions below. Preserve their complete predecessor hash checks.
def without_current_runtime_source_pin(source):
    source = without_app_signature_workflow(source)
    current = "f35a69f6a0e4baf2b365fc28662152d529564107738da9f477363dcc2ea6cdc2"
    previous = "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0"
    if current not in source:
        return source
    configured = "      MRK_BUNDLED_RUNTIME_SOURCE_SHA256: " + current + "\n"
    guard = '[[ "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256" =~ ^[0-9a-f]{64}$ && "$MRK_BUNDLED_RUNTIME_SOURCE_SHA256" == ' + current + ' ]] || exit 1\n'
    # Only the already-reviewed installed and Aqua admission indentations.
    guards = [indent + guard for indent in ("          ", "            ")
              if "\n" + indent + guard in source]
    if (source.count(current) != 2 or previous in source
            or source.count("\n" + configured) != 1 or len(guards) != 1
            or source.count("\n" + guards[0]) != 1):
        raise AssertionError("current runtime source pin exact two-site delta differs")
    for line in (configured, guards[0]):
        source = source.replace("\n" + line, "\n" + line.replace(current, previous), 1)
    return source


TOOL_ENROLLMENT_WORKFLOW_INVERSE = ((41577, 4155, 'e1ad3768ba7ed53f8217824d1348ca502b9bcf88b0562ce82ca66de2efd9cdfe', ''), (45965, 244, 'dec34c68710ed49677a78116d21f6c9a1eb3e13bc0c2bb83b26b78babeb76523', ''), (46419, 78, '251bd1dc99a992dba08e5aba35b0d7b67765f79b4da5679606da413e18ee08dd', '            --target "$MRK_MACOS_TARGET" \\\n'), (90916, 363, '4bec18b0387d401a0cb993bf2d1396cce3fe8ca432abcd966e1eef12317d3eab', ''), (91329, 163, '98ec04098231bc33c3a4fa0614ef46cbdd6057e9f58af89fa9e3bf332dd4258d', '          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py app --target "$MRK_MACOS_TARGET" "${removal_arguments[@]}" \\\n'), (95390, 368, '31da7f0d6c48b8dc93d41545e63747b4a170a208737daac4630c58b1e7cb105b', ''))

def without_tool_enrollment_workflow(source):
    source = without_current_runtime_source_pin(source)
    if "      - name: Select only SOURCE-enrolled current signed GitHub tools" not in source:
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(TOOL_ENROLLMENT_WORKFLOW_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("tool enrollment workflow region changed")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "c68a194c08d209e19f6f7028a590a6d39619c6b2f276a24a2dc334ad49dfba00":
        raise AssertionError("tool enrollment workflow inverse changed original")
    return value.decode()


def without_release_evidence_workflow(source):
    source = without_current_runtime_source_pin(source)
    source = without_tool_enrollment_workflow(source)
    if '"savedReleaseEvidenceUI": "passed"' not in source:
        if 'release-evidence) singleton=' in source: raise AssertionError("partial release_evidence_workflow source")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(RELEASE_EVIDENCE_WORKFLOW_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("release_evidence_workflow exact source region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != '80998a0d9633a7a3bae47407ecb06f2d2b748ebb0e96fa068c7bfc42149a7626':
        raise AssertionError("release_evidence_workflow predecessor source differs")
    return value.decode()

def without_github_refusal_workflow(source):
    source = without_release_evidence_workflow(source)
    marker = "      - name: Exercise one selected saved-version recovery or GitHub refusal through the ordinary Mac UI\n"
    if marker not in source:
        if "singleton_method=" in source or "singleton_case_data" in source:
            raise AssertionError("partial GitHub refusal workflow")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(GITHUB_REFUSAL_WORKFLOW_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("GitHub refusal workflow fixed region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "611783adbc1d6961c905005037fcf15605401e7b819eeff3f544a779d2bf18b0":
        raise AssertionError("GitHub refusal workflow inverse changed prior source")
    return value.decode()


REMOVAL_LIFECYCLE_WORKFLOW_INVERSE = ((226, 47, 'a704747a4193562a5e58ae053eb9e1589916783e7b1522be2abde7179fb0957a', ''), (599, 69, '69f7174b3cd9ca531aeaf62491a0f1f3bc571a41a29916fb314f8a5155a08133', ''), (753, 79, '84369e0f4fd0a31f33781995dc1c75b89cd6ac7cc388c3524de894dd9871c949', ''), (1279, 1984, 'b649ec4cfe89d2c6978bc4021317eed27fcaaa8bf62d21cb76168e4e3cc79023', "include:\n          - target: aarch64-apple-darwin\n            runner: macos-26\n            machine: arm64\n            hosted_job: github-hosted-macos26-arm64\n            supplier_receipt: '2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d'\n            supplier_tar: 'ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695'\n            supplier_source: '158cdff422e3837f7ab5e6192af76a578faf6fab'\n            supplier_run: '37467019389'\n            supplier_attempt: '1'\n            supplier_artifact: '11415902210'\n          - target: x86_64-apple-darwin\n            runner: macos-26-intel\n            machine: x86_64\n            hosted_job: github-hosted-macos26-x86_64\n            supplier_receipt: 'a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b'\n            supplier_tar: '739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd'\n            supplier_source: '079ab2a2c8fef88f01bf909e7669c685f07e1375'\n            supplier_run: '37476532238'\n            supplier_attempt: '1'\n            supplier_artifact: '11419502465'"), (3730, 71, 'f9fefa3718ae898b78132aa38bdc5b3e362b73f0ecfa4a3db2baa1293dc10b6e', ''), (1195, 228, 'f38b1fc17d9d827d5e6807e506d4779c25910080aae3082d6b22ee39b48f0ac1', ''), (8134, 566, 'cebc4460add0cd6b3fdea1e916574147cd7cf02e02e1a568955bc58579ca9803', ') ]] || exit 1'), (22064, 1047, '2b394548ebccdb868edb041d7749ce405aef1a0cda862c499c793eb5bb58937c', ''), (43300, 69, '64b629967c59bc65a8424104f6d690f0a25b2db134ac45d7644a790d9620b685', ''), (99397, 78, '6801bd4de84db1e9812849b0af46cadd0ec2164ad823acfda2667a533993d1f7', ''), (103974, 78, '6801bd4de84db1e9812849b0af46cadd0ec2164ad823acfda2667a533993d1f7', ''), (106894, 78, '6801bd4de84db1e9812849b0af46cadd0ec2164ad823acfda2667a533993d1f7', ''), (76697, 3356, 'fd410e2faf1fdc677b84e0efacee8268056f61cf722f925eb0517a3371f9bed8', '# Same24-minute app-build budget; no independent timeout entitlement.\n          # This current SOURCE role cannot embed its not-yet-created inventory.\n          set +e\n          PATH="/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/rustc" RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" RUSTUP_AUTO_INSTALL=0 CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup CARGO_TARGET_DIR="$MRK_MACOS_WORK/remover-target" /usr/bin/env -u MRK_MACOS_INSTALL_INVENTORY_SHA256 "/Users/runner/.rustup/toolchains/stable-$MRK_MACOS_TARGET/bin/cargo" build \\\n            --locked --offline --release --jobs 1 --no-default-features --features macos-installed-remover --bin mrk-macos-remove \\\n            --target "$MRK_MACOS_TARGET" --message-format=json-render-diagnostics \\\n            > "$MRK_MACOS_WORK/remover-build.jsonl" 2> "$MRK_MACOS_WORK/remover-build.stderr"\n          remover_status=$?\n          printf \'%s\\n\' "$remover_status" > "$MRK_MACOS_WORK/remover-build.status"\n          remover_status_saved=$?\n          set -e\n          if [[ "$remover_status" != 0 ]]; then\n            # Optional diagnostics cannot replace the original compiler status.\n            set +e\n            printf \'Fixed remover compiler failed with original status %s; bounded diagnostics are retained.\\n\' "$remover_status" >&2\n            /usr/bin/tail -c 16384 "$MRK_MACOS_WORK/remover-build.stderr" >&2\n            exit "$remover_status"\n          fi\n          [[ "$remover_status_saved" == 0 ]] || exit "$remover_status_saved"'), (86218, 401, '1437bb8f8e16e877d01975a568c24b027924764f80b086da4072da8f1f538ea0', '/bin/mkdir -m 700 "$MRK_MACOS_WORK/app"\n          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py app --target "$MRK_MACOS_TARGET'), (155958, 1430, '9115ca359f000551d59ba2793087d14a1f3983b078d39ce8bb8993ac0f64cfec', '\n        timeout-minutes: 8\n        shell: bash\n        run: |\n          set -euo pipefail\n          set -o noclobber\n          umask 077\n          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py remove-scripts --target "$MRK_MACOS_TARGET" \\\n            --remover "$MRK_MACOS_WORK/input/app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-macos-remove" \\\n            --expected-remover "$MRK_MACOS_REMOVER_SHA256" --output "$MRK_MACOS_WORK/remove-scripts" \\\n            > "$MRK_MACOS_WORK/remove-scripts-result.json"\n          [[ ! -e "$MRK_MACOS_WORK/Remove-original.pkg" && ! -L "$MRK_MACOS_WORK/Remove-original.pkg" ]] || exit 1\n          /usr/bin/pkgbuild --nopayload --scripts "$MRK_MACOS_WORK/remove-scripts" \\\n            --identifier dev.mobile-release-kit.desktop.remove --version "$MRK_MACOS_SOURCE_PACKAGE_VERSION" \\\n            --install-location / --ownership recommended "$MRK_MACOS_WORK/Remove-original.pkg"\n          "$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py prepare-remove-package --target "$MRK_MACOS_TARGET'), (159621, 69, '69f7174b3cd9ca531aeaf62491a0f1f3bc571a41a29916fb314f8a5155a08133', ''), (161932, 97, '7c00a5aa8e446b1d4a35ca3a04cb8b148f559ea23aa1ccd49b4a52fed6a73967', ''), (163757, 4562, 'e23beb1ed1963fc3f92eab36981a8584c15020cd82b7e77cc310ea89a92ef124', ''), (314219, 599, '1fef83695b6cca6a40261680a661b4be77daf98802d55dd5e55704919220379f', "-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}\n          path: |\n            ${{ format('{0}/source-binding"))


def without_removal_lifecycle_workflow(source):
    source = without_github_refusal_workflow(source)
    marker = "      - name: Prepare three source-bound readonly observation carriers without removal\n"
    if marker not in source:
        if any(token in source for token in ("verify/desktop-macos-removal-lifecycle", "package-removal-fixture --target", "prepare-removal-observers --target")):
            raise AssertionError("partial removal lifecycle workflow")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(REMOVAL_LIFECYCLE_WORKFLOW_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("removal lifecycle workflow fixed region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "d89f5e09a105d2dc485d4c35db80f7ed7fefe4fd77d1b000a6939326af114238":
        raise AssertionError("removal lifecycle workflow inverse changed prior source")
    return value.decode()


def without_install_product_workflow(source):
    source = without_removal_lifecycle_workflow(source)
    marker = "      - name: Build fixed Installer presentation then sign and notarize the completed outer package before final P\n"
    if marker not in source:
        if "package-component" in source or "SOURCE ReadMe envelope" in source:
            raise AssertionError("partial Install product workflow")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(INSTALL_PRODUCT_WORKFLOW_INVERSE):
        if hashlib.sha256(value[start:start + length]).hexdigest() != expected:
            raise AssertionError("Install product workflow fixed region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "659016d8b299a5497ab895162695d3927b55e4dda96750cd3e5f9a742467bd00":
        raise AssertionError("Install product workflow inverse changed prior source")
    return value.decode()


SHIPPING_COMPILE_PRIVACY_INVERSE = (('          prep_start = time.monotonic()\n', '          def compile_public_data(value, source, run_id, run_attempt):\n              """Closed prior compile observations, never receipt-publication authority."""\n              def check(ok):\n                  need(ok, \'compile-public-data\')\n\n              def digest(item):\n                  check(type(item) is str and re.fullmatch(r\'[0-9a-f]{64}\', item) is not None)\n                  return item\n\n              def integer(item, low, high):\n                  check(type(item) is int and low <= item <= high)\n                  return item\n\n              def nullable_bool(item):\n                  check(item is None or type(item) is bool)\n                  return item\n\n              roles = (\'node-version\', \'npm-version\', \'rustc-version\', \'cargo-version\',\n                       \'npm-ci\', \'frontend-build\', \'shipping-image-build\')\n              fact_names = (\'originalPending\', \'sourcePost\', \'toolsPost\', \'frontendGenerated\',\n                            \'facadeArtifactVerified\', \'inputOriginalsKnown\', \'toolOriginalsClosed\',\n                            \'generatedOutputsRetired\', \'shippingGraphCompiled\', \'installedQualified\',\n                            \'runtimeQualified\', \'launched\', \'signed\', \'pythonControllerPrepared\',\n                            \'pythonControllerPost\', \'pythonControllerRetired\')\n              conditions = (\'controller-record\', \'controller-base\', \'controller-row\', \'controller-roster\',\n                            \'controller-file\', \'controller-config\', \'controller-runtime\', \'controller-original-changed\',\n                            \'controller-total\', \'controller-directory\', \'controller-short-read\', \'controller-deadline\',\n                            \'controller-unexpected-process\', \'controller-work-root\', \'controller-template\',\n                            \'controller-publication\', \'controller-source-copy\', \'controller-operation\',\n                            \'cargo-output-bound\', \'cargo-line-bound\', \'cargo-document\', \'cargo-finished\',\n                            \'cargo-facade-count\', \'cargo-target-shape\', \'cargo-real-facade\', \'cargo-app-count\',\n                            \'cargo-shipping-feature\', \'compile-artifact-file\', \'compile-artifact-short\', \'compile-artifact-post\')\n              owner_reasons = (\'incomplete-output\', \'output-bound\', \'protocol-or-ownership\',\n                               \'command-failed-or-incomplete\', \'cleanup-unconfirmed\', \'exec-rejected\',\n                               \'stopped-before-exec\', \'parent-ended\', \'observer-ended\', \'fence-collision\', \'unknown\')\n              check(type(value) is dict and type(source) is str and re.fullmatch(r\'[0-9a-f]{40}\', source)\n                    and source != \'0\' * 40 and all(type(item) is str and re.fullmatch(r\'[1-9][0-9]{0,19}\', item)\n                                                 for item in (run_id, run_attempt)))\n              fixed = dict(schemaVersion=1, scope=\'fixed-arm-shipping-image-compile-only\', source=source,\n                           workflowSource=source, runId=run_id, runAttempt=run_attempt, target=\'aarch64-apple-darwin\')\n              check(type(value.get(\'schemaVersion\')) is int and all(value.get(key) == item for key, item in fixed.items()))\n              facts = {}\n              for name in fact_names:\n                  check(name not in value or type(value[name]) is bool)\n                  facts[name] = value.get(name)\n              check(type(facts[\'shippingGraphCompiled\']) is bool\n                    and all(facts[name] is False for name in (\'installedQualified\', \'runtimeQualified\', \'launched\', \'signed\')))\n              rows = value.get(\'commands\')\n              check(type(rows) is list and len(rows) <= len(roles))\n              commands = []\n              for index, row in enumerate(rows):\n                  check(type(row) is dict and row.get(\'role\') == roles[index]\n                        and type(row.get(\'returned\')) is bool and type(row.get(\'capturesSettled\')) is bool)\n                  out = integer(row.get(\'stdoutBytes\'), 0, 4096 if index < 4 else 4 * 1024 * 1024)\n                  err = integer(row.get(\'stderrBytes\'), 0, 4096 if index < 4 else 4 * 1024 * 1024)\n                  check(out + err <= (4096 if index < 4 else 4 * 1024 * 1024))\n                  commands.append(dict(role=roles[index], returned=row[\'returned\'], capturesSettled=row[\'capturesSettled\'],\n                                       returncode=integer(row.get(\'returncode\'), -(2**31), 2**31 - 1),\n                                       stdoutBytes=out, stderrBytes=err,\n                                       stdoutSha256=digest(row.get(\'stdoutSha256\')), stderrSha256=digest(row.get(\'stderrSha256\'))))\n              inventory = None\n              if \'sourceInventoryBytes\' in value or \'sourceInventorySha256\' in value:\n                  inventory = dict(bytes=integer(value.get(\'sourceInventoryBytes\'), 1, 2 * 1024 * 1024),\n                                   sha256=digest(value.get(\'sourceInventorySha256\')))\n              facade = None\n              if \'facadeArtifact\' in value:\n                  item = value[\'facadeArtifact\']\n                  check(type(item) is dict)\n                  facade = dict(bytes=integer(item.get(\'bytes\'), 1, 256 * 1024 * 1024), sha256=digest(item.get(\'sha256\')))\n              failure = None\n              if value.get(\'failure\') is not None:\n                  item = value[\'failure\']\n                  check(type(item) is dict)\n                  stages = (\'python-base\', \'python-create\', \'python-census\', \'python-publication\', \'admission\',\n                            \'source-tool-post\', \'generated-cleanup\', \'tool-close\', \'public-capture\') + roles\n                  stage, condition = item.get(\'stage\'), item.get(\'condition\')\n                  check(type(stage) is str and (condition is None or type(condition) is str))\n                  failure = dict(stage=stage if stage in stages else \'other\',\n                                 condition=condition if condition in conditions else None if condition is None else \'unclassified\',\n                                 ownerDiagnostic=None)\n                  if \'ownerDiagnostic\' in item:\n                      observed = item[\'ownerDiagnostic\']\n                      check(type(observed) is dict and type(observed.get(\'available\')) is bool)\n                      typed = observed.get(\'typedFacts\', [])\n                      check(type(typed) is list and len(typed) <= 16\n                            and (observed[\'available\'] or not typed))\n                      projected = []\n                      for row in typed:\n                          check(type(row) is dict and type(row.get(\'kind\')) is str and row[\'kind\'] in (\'process-error\', \'interrupted\')\n                                and type(row.get(\'reason\')) is str and row[\'reason\'] in owner_reasons)\n                          mask = row.get(\'ownerFailureMask\')\n                          check(mask is None or type(mask) is int and 1 <= mask <= 63)\n                          projected.append(dict(kind=row[\'kind\'], reason=row[\'reason\'], ownerFailureMask=mask,\n                                                **{key: nullable_bool(row.get(key)) for key in (\'dispatched\', \'contained\', \'cleanupComplete\')}))\n                      failure[\'ownerDiagnostic\'] = dict(available=observed[\'available\'], typedFacts=projected,\n                                                        chainTruncated=nullable_bool(observed.get(\'chainTruncated\')))\n              if facts[\'shippingGraphCompiled\']:\n                  check(len(commands) == len(roles) and all(row[\'returned\'] and row[\'capturesSettled\'] and row[\'returncode\'] == 0 for row in commands)\n                        and facts[\'originalPending\'] is False and failure is None and inventory is not None and facade is not None\n                        and all(facts[name] is True for name in (\'sourcePost\', \'toolsPost\', \'frontendGenerated\', \'facadeArtifactVerified\',\n                            \'inputOriginalsKnown\', \'toolOriginalsClosed\', \'generatedOutputsRetired\', \'pythonControllerPrepared\',\n                            \'pythonControllerPost\', \'pythonControllerRetired\')))\n              result = dict(kind=\'mrk-public-shipping-compile-evidence-v1\', **fixed, facts=facts,\n                            commands=commands, sourceInventory=inventory, facadeArtifact=facade, failure=failure)\n              check(len((json.dumps(result, sort_keys=True, separators=(\',\', \':\'), allow_nan=False) + \'\\n\').encode(\'ascii\')) <= 16384)\n              return result\n\n\n          prep_start = time.monotonic()\n'), ("          TARGET = 'aarch64-apple-darwin'\n          RUST_RELEASE = '1.98.1'\n", '          def compile_public_data(value, source, run_id, run_attempt):\n              """Closed prior compile observations, never receipt-publication authority."""\n              def check(ok):\n                  need(ok, \'compile-public-data\')\n\n              def digest(item):\n                  check(type(item) is str and re.fullmatch(r\'[0-9a-f]{64}\', item) is not None)\n                  return item\n\n              def integer(item, low, high):\n                  check(type(item) is int and low <= item <= high)\n                  return item\n\n              def nullable_bool(item):\n                  check(item is None or type(item) is bool)\n                  return item\n\n              roles = (\'node-version\', \'npm-version\', \'rustc-version\', \'cargo-version\',\n                       \'npm-ci\', \'frontend-build\', \'shipping-image-build\')\n              fact_names = (\'originalPending\', \'sourcePost\', \'toolsPost\', \'frontendGenerated\',\n                            \'facadeArtifactVerified\', \'inputOriginalsKnown\', \'toolOriginalsClosed\',\n                            \'generatedOutputsRetired\', \'shippingGraphCompiled\', \'installedQualified\',\n                            \'runtimeQualified\', \'launched\', \'signed\', \'pythonControllerPrepared\',\n                            \'pythonControllerPost\', \'pythonControllerRetired\')\n              conditions = (\'controller-record\', \'controller-base\', \'controller-row\', \'controller-roster\',\n                            \'controller-file\', \'controller-config\', \'controller-runtime\', \'controller-original-changed\',\n                            \'controller-total\', \'controller-directory\', \'controller-short-read\', \'controller-deadline\',\n                            \'controller-unexpected-process\', \'controller-work-root\', \'controller-template\',\n                            \'controller-publication\', \'controller-source-copy\', \'controller-operation\',\n                            \'cargo-output-bound\', \'cargo-line-bound\', \'cargo-document\', \'cargo-finished\',\n                            \'cargo-facade-count\', \'cargo-target-shape\', \'cargo-real-facade\', \'cargo-app-count\',\n                            \'cargo-shipping-feature\', \'compile-artifact-file\', \'compile-artifact-short\', \'compile-artifact-post\')\n              owner_reasons = (\'incomplete-output\', \'output-bound\', \'protocol-or-ownership\',\n                               \'command-failed-or-incomplete\', \'cleanup-unconfirmed\', \'exec-rejected\',\n                               \'stopped-before-exec\', \'parent-ended\', \'observer-ended\', \'fence-collision\', \'unknown\')\n              check(type(value) is dict and type(source) is str and re.fullmatch(r\'[0-9a-f]{40}\', source)\n                    and source != \'0\' * 40 and all(type(item) is str and re.fullmatch(r\'[1-9][0-9]{0,19}\', item)\n                                                 for item in (run_id, run_attempt)))\n              fixed = dict(schemaVersion=1, scope=\'fixed-arm-shipping-image-compile-only\', source=source,\n                           workflowSource=source, runId=run_id, runAttempt=run_attempt, target=\'aarch64-apple-darwin\')\n              check(type(value.get(\'schemaVersion\')) is int and all(value.get(key) == item for key, item in fixed.items()))\n              facts = {}\n              for name in fact_names:\n                  check(name not in value or type(value[name]) is bool)\n                  facts[name] = value.get(name)\n              check(type(facts[\'shippingGraphCompiled\']) is bool\n                    and all(facts[name] is False for name in (\'installedQualified\', \'runtimeQualified\', \'launched\', \'signed\')))\n              rows = value.get(\'commands\')\n              check(type(rows) is list and len(rows) <= len(roles))\n              commands = []\n              for index, row in enumerate(rows):\n                  check(type(row) is dict and row.get(\'role\') == roles[index]\n                        and type(row.get(\'returned\')) is bool and type(row.get(\'capturesSettled\')) is bool)\n                  out = integer(row.get(\'stdoutBytes\'), 0, 4096 if index < 4 else 4 * 1024 * 1024)\n                  err = integer(row.get(\'stderrBytes\'), 0, 4096 if index < 4 else 4 * 1024 * 1024)\n                  check(out + err <= (4096 if index < 4 else 4 * 1024 * 1024))\n                  commands.append(dict(role=roles[index], returned=row[\'returned\'], capturesSettled=row[\'capturesSettled\'],\n                                       returncode=integer(row.get(\'returncode\'), -(2**31), 2**31 - 1),\n                                       stdoutBytes=out, stderrBytes=err,\n                                       stdoutSha256=digest(row.get(\'stdoutSha256\')), stderrSha256=digest(row.get(\'stderrSha256\'))))\n              inventory = None\n              if \'sourceInventoryBytes\' in value or \'sourceInventorySha256\' in value:\n                  inventory = dict(bytes=integer(value.get(\'sourceInventoryBytes\'), 1, 2 * 1024 * 1024),\n                                   sha256=digest(value.get(\'sourceInventorySha256\')))\n              facade = None\n              if \'facadeArtifact\' in value:\n                  item = value[\'facadeArtifact\']\n                  check(type(item) is dict)\n                  facade = dict(bytes=integer(item.get(\'bytes\'), 1, 256 * 1024 * 1024), sha256=digest(item.get(\'sha256\')))\n              failure = None\n              if value.get(\'failure\') is not None:\n                  item = value[\'failure\']\n                  check(type(item) is dict)\n                  stages = (\'python-base\', \'python-create\', \'python-census\', \'python-publication\', \'admission\',\n                            \'source-tool-post\', \'generated-cleanup\', \'tool-close\', \'public-capture\') + roles\n                  stage, condition = item.get(\'stage\'), item.get(\'condition\')\n                  check(type(stage) is str and (condition is None or type(condition) is str))\n                  failure = dict(stage=stage if stage in stages else \'other\',\n                                 condition=condition if condition in conditions else None if condition is None else \'unclassified\',\n                                 ownerDiagnostic=None)\n                  if \'ownerDiagnostic\' in item:\n                      observed = item[\'ownerDiagnostic\']\n                      check(type(observed) is dict and type(observed.get(\'available\')) is bool)\n                      typed = observed.get(\'typedFacts\', [])\n                      check(type(typed) is list and len(typed) <= 16\n                            and (observed[\'available\'] or not typed))\n                      projected = []\n                      for row in typed:\n                          check(type(row) is dict and type(row.get(\'kind\')) is str and row[\'kind\'] in (\'process-error\', \'interrupted\')\n                                and type(row.get(\'reason\')) is str and row[\'reason\'] in owner_reasons)\n                          mask = row.get(\'ownerFailureMask\')\n                          check(mask is None or type(mask) is int and 1 <= mask <= 63)\n                          projected.append(dict(kind=row[\'kind\'], reason=row[\'reason\'], ownerFailureMask=mask,\n                                                **{key: nullable_bool(row.get(key)) for key in (\'dispatched\', \'contained\', \'cleanupComplete\')}))\n                      failure[\'ownerDiagnostic\'] = dict(available=observed[\'available\'], typedFacts=projected,\n                                                        chainTruncated=nullable_bool(observed.get(\'chainTruncated\')))\n              if facts[\'shippingGraphCompiled\']:\n                  check(len(commands) == len(roles) and all(row[\'returned\'] and row[\'capturesSettled\'] and row[\'returncode\'] == 0 for row in commands)\n                        and facts[\'originalPending\'] is False and failure is None and inventory is not None and facade is not None\n                        and all(facts[name] is True for name in (\'sourcePost\', \'toolsPost\', \'frontendGenerated\', \'facadeArtifactVerified\',\n                            \'inputOriginalsKnown\', \'toolOriginalsClosed\', \'generatedOutputsRetired\', \'pythonControllerPrepared\',\n                            \'pythonControllerPost\', \'pythonControllerRetired\')))\n              result = dict(kind=\'mrk-public-shipping-compile-evidence-v1\', **fixed, facts=facts,\n                            commands=commands, sourceInventory=inventory, facadeArtifact=facade, failure=failure)\n              check(len((json.dumps(result, sort_keys=True, separators=(\',\', \':\'), allow_nan=False) + \'\\n\').encode(\'ascii\')) <= 16384)\n              return result\n\n\n          TARGET = \'aarch64-apple-darwin\'\n          RUST_RELEASE = \'1.98.1\'\n'), ("publish_preparation('compile-receipt.json', failure, cleanup=True)", "publish_preparation('compile-receipt.json', compile_public_data(failure, source, os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']), cleanup=True)"), ("publish('compile-receipt.json', (json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\\n').encode('ascii'), 65536)", "publish('compile-receipt.json', (json.dumps(compile_public_data(receipt, source, os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']), sort_keys=True, separators=(',', ':'), allow_nan=False) + '\\n').encode('ascii'), 65536)"), ('                  # Public fixed-source compiler output only; no binary/cache/runtime/signing upload.\n', '                  # Local captured compiler originals only; never included in the artifact.\n'), ('            ${{ steps.compile_work.outputs.root }}/source-inventory.json\n            ${{ steps.compile_work.outputs.root }}/compile-receipt.json\n            ${{ steps.compile_work.outputs.root }}/npm-ci.stdout\n            ${{ steps.compile_work.outputs.root }}/npm-ci.stderr\n            ${{ steps.compile_work.outputs.root }}/frontend-build.stdout\n            ${{ steps.compile_work.outputs.root }}/frontend-build.stderr\n            ${{ steps.compile_work.outputs.root }}/shipping-image-build.stdout\n            ${{ steps.compile_work.outputs.root }}/shipping-image-build.stderr\n', '            ${{ steps.compile_work.outputs.root }}/compile-receipt.json\n'))


def without_shipping_compile_privacy_workflow(source):
    marker = "  shipping-image-compile:\n"
    if marker not in source:
        if "compile_public_data(" in source:
            raise AssertionError("partial shipping privacy workflow")
        return source
    states = []
    for before, after in SHIPPING_COMPILE_PRIVACY_INVERSE:
        if source.count(after) == 1 and source.count(before) == after.count(before):
            states.append("new")
        elif source.count(before) == 1 and source.count(after) == before.count(after):
            states.append("old")
        else:
            raise AssertionError("shipping privacy region differs")
    if states == ["old"] * len(states):
        if "compile_public_data(" in source:
            raise AssertionError("partial shipping privacy workflow")
        return source
    if states != ["new"] * len(states) or source.count("compile_public_data(") != 4:
        raise AssertionError("mixed shipping privacy workflow")
    for before, after in reversed(SHIPPING_COMPILE_PRIVACY_INVERSE):
        if source.count(after) != 1:
            raise AssertionError("duplicate shipping privacy workflow")
        source = source.replace(after, before, 1)
    if "compile_public_data(" in source:
        raise AssertionError("unretired shipping privacy workflow")
    return source


def without_shipping_compile_workflow(source):
    source = without_shipping_compile_privacy_workflow(source)
    source = without_install_product_workflow(source)
    marker = "  shipping-image-compile:\n"
    if marker not in source:
        if any(value in source for value in ("verify/desktop-macos-image-compile", "mrk_installed_source_inventory", "mrk_installed_direct_rust")):
            raise AssertionError("partial shipping compile workflow")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(SHIPPING_COMPILE_WORKFLOW_INVERSE):
        actual = value[start:start + length]
        if hashlib.sha256(actual).hexdigest() != expected:
            raise AssertionError("shipping compile workflow fixed region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "03f8546fb009e0f9bc316da6e4b58ff7d851884a364af0caaaf05043602ca11d":
        raise AssertionError("shipping compile workflow inverse changed prior source")
    return value.decode()


# Exact Remove-output successor only. No original Install/instrumented workflow
# safety assertion is weakened by the independent, fixed preview-only route.
REMOVE_OUTPUT_WORKFLOW_INVERSE = ((629, 328, '11cd9e875296bd66a7fe4932b8774e3152110f531eec148ab376851c3f918b67', '    # Timed-step union445min; SOURCE scopes select disjoint UI work.\n    # Preview345 / recovery339 / installed210 / dormant ARM Android267 / dormant iOS243, plus5 overhead.\n    # Android adds build9 + preparation22 + test23 + summary3;272 <=350.\n    # iOS installed-only adds build9 + test22 + summary2;248 <=350, never preview+24.\n'), (150120, 9028, '9d50426024c5a0b7935ae93ee5c06be69221dce04aff47f27c4b8a4b610cada1', ''), (159699, 296, '757619f49bf177bc5404bec36b927f406b9ca1ddc8bbc79609c4ad7981e8105d', ''), (160791, 225, 'adbb7994c243addb230dcff883b114ded25035ee8931a15b6bb6aca2238a89fd', ''), (315226, 521, 'b37eab9482c0d97fa90e1f37e948849a9b3f7d8cfc3bda939e630b8bb07a0726', ''))


def without_remove_output_workflow(source):
    source = without_shipping_compile_workflow(source)
    marker = "      - name: Prepare the fixed two-file removal package without executing it\n"
    if marker not in source:
        if "finalize-remove-package --target" in source or "finalize-remove-image --target" in source or "package-remove --target" in source:
            raise AssertionError("partial Remove output workflow")
        return source
    value = source.encode()
    for start, length, expected, prior in reversed(REMOVE_OUTPUT_WORKFLOW_INVERSE):
        actual = value[start:start + length]
        if hashlib.sha256(actual).hexdigest() != expected:
            raise AssertionError("Remove output workflow fixed region differs")
        value = value[:start] + prior.encode() + value[start + length:]
    if hashlib.sha256(value).hexdigest() != "dd0ca6b4e80d05f276a129049b9600a9e9eccbc26a881b515accceefadcafcca":
        raise AssertionError("Remove output workflow inverse changed prior source")
    return value.decode()


def without_ios_unsigned_workflow(source):
    original = without_remove_output_workflow(source).encode()
    for start, length, expected, prior in reversed(REMOVE_PACKAGE_WORKFLOW_INVERSE):
        observed = original[start:start + length]
        if hashlib.sha256(observed).hexdigest() != expected:
            raise AssertionError('unsigned iOS workflow remover region differs')
        original = original[:start] + prior.encode() + original[start + length:]
    if hashlib.sha256(original).hexdigest() != 'ec46e521444b1c350cee7d31dddcd3afe4fd8e8ec0775dd95be0d4423749b99d':
        raise AssertionError('unsigned iOS workflow remover inverse changed prior SOURCE')
    rows = original.decode().splitlines(keepends=True)
    for start, end, expected, original in reversed(IOS_UNSIGNED_WORKFLOW_INVERSE):
        observed = ''.join(rows[start:end])
        if hashlib.sha256(observed.encode()).hexdigest() != expected:
            raise AssertionError('unsigned iOS workflow exact region differs')
        rows[start:end] = original.splitlines(keepends=True)
    value = ''.join(rows)
    if hashlib.sha256(value.encode()).hexdigest() != 'd7199d46c3292bca3f7f04a932a4cdde05513f91bbff5d2c859bee9451fcf8bb':
        raise AssertionError('unsigned iOS workflow inverse changed prior SOURCE')
    return value


ROOT = Path(__file__).absolute().parents[2]
SWIFT = "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift"
FIXTURE = "desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json"
METHOD = "testSyntheticProjectBuildToolDiagnostics"
SCOPE = "ordinary-ui-observed-original-diagnostics-report-and-settled-projection"
SOURCE_METHODS = ['test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_observes_original_complete_report_and_settled_projection',
 'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_workflow_has_one_bounded_original_result']
# Exact two-lifetime/dashboard, draft-only fields and selection-only Android baseline.
# Only the explicitly checked heading/readiness/diagnostic blocks below are
# restored or removed; original-owner and restart paths remain bound.
ORIGINAL_SWIFT_SHA256 = "ff4f7c461fb48e2c71f720ba9facebcb0716bb81e50a37f0dc4c0e9f167e9d98"
DIAGNOSTICS_INSERTION_SHA256 = "d6c1730aa9c3b82467a5f6f15b549a463746e0901556174fc52a602d903b798d"
DASHBOARD_QUERY_BEGIN = '        // Fixed dashboard query diagnostics only; observations are non-atomic.\n'
DASHBOARD_QUERY_END = '        // End fixed dashboard query diagnostics.\n'
DASHBOARD_QUERY_ORIGINAL = '        _ = try unique(heading, "dashboard heading is ambiguous")\n'
DASHBOARD_QUERY_DIAGNOSTICS_SHA256 = "4a0f78d6468535805756ea785f0cdf5fbcede31c38d276635485a476b9fb6ad6"
# Authored h1/h2/h3 singleton queries only; no badge, native-sheet or
# existence-only selector is normalized. Every complete line and multiplicity
# is independently enumerated, then the unchanged whole-source pins apply.
SEMANTIC_HEADING_PREFIX = 'staticTexts.matching(NSPredicate(format: "title == %@", '
SEMANTIC_HEADING_LINES = (
    ('        let heading = renderer.staticTexts.matching(identifier: "Good releases start here.")\n',
     '        let heading = renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Good releases start here."))\n', 1),
    ('        _ = try waitElement(review.staticTexts.matching(identifier: title), in: storage, failures: Self.privateInputFailures)\n',
     '        _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", title)), in: storage, failures: Self.privateInputFailures)\n', 1),
    ('        _ = try waitElement(storage.staticTexts.matching(identifier: "Supplied-input assessment"), in: storage,\n',
     '        _ = try waitElement(storage.staticTexts.matching(NSPredicate(format: "title == %@", "Supplied-input assessment")), in: storage,\n', 1),
    ('            _ = try waitElement(renderer.staticTexts.matching(identifier: "Let’s get project ready."), in: renderer,\n',
     '            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,\n', 7),
    ('            _ = try waitElement(renderer.staticTexts.matching(identifier: "Format validation complete"), in: renderer,\n',
     '            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Format validation complete")), in: renderer,\n', 1),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Submitted configuration saved"), in: review,\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Submitted configuration saved")), in: review,\n', 1),
    ('            _ = try waitElement(proposal.staticTexts.matching(identifier: "Four read-only workflow previews"), in: proposal)\n',
     '            _ = try waitElement(proposal.staticTexts.matching(NSPredicate(format: "title == %@", "Four read-only workflow previews")), in: proposal)\n', 2),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Reviewed local workflow bundle installed"), in: review,\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Reviewed local workflow bundle installed")), in: review,\n', 1),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Text saved"), in: review, timeout: 48, failures: Self.textFailures)\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Text saved")), in: review, timeout: 48, failures: Self.textFailures)\n', 1),
    ('                _ = try waitElement(renderer.staticTexts.matching(identifier: "Original image selection cancelled"), in: renderer,\n',
     '                _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Original image selection cancelled")), in: renderer,\n', 1),
    ('                _ = try unique(review.staticTexts.matching(identifier: "Final lexical Store input order"), "final image order was not displayed")\n',
     '                _ = try unique(review.staticTexts.matching(NSPredicate(format: "title == %@", "Final lexical Store input order")), "final image order was not displayed")\n', 1),
    ('                _ = try waitElement(review.staticTexts.matching(identifier: "Reviewed public images copied locally"), in: review,\n',
     '                _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Reviewed public images copied locally")), in: review,\n', 1),
    ('            _ = try unique(report.staticTexts.matching(identifier: "Returned offline-check report"), "returned offline report heading is missing")\n',
     '            _ = try unique(report.staticTexts.matching(NSPredicate(format: "title == %@", "Returned offline-check report")), "returned offline report heading is missing")\n', 1),
    ('            _ = try unique(panel.staticTexts.matching(identifier: "No pending build-input record observed"),\n',
     '            _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", "No pending build-input record observed")),\n', 2),
    ('            let fresh = panel.staticTexts.matching(identifier: "Tool observations from this run")\n',
     '            let fresh = panel.staticTexts.matching(NSPredicate(format: "title == %@", "Tool observations from this run"))\n', 1),
    ('                _ = try unique(panel.staticTexts.matching(identifier: label), "fixed Android diagnostics card is missing or repeated")\n',
     '                _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", label)), "fixed Android diagnostics card is missing or repeated")\n', 1),
    ('            _ = try waitElement(renderer.staticTexts.matching(identifier: "Format validation needs attention"),\n',
     '            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Format validation needs attention")),\n', 1),
    ('            _ = try unique(review.staticTexts.matching(identifier: "Local workflow bundle refused"),\n',
     '            _ = try unique(review.staticTexts.matching(NSPredicate(format: "title == %@", "Local workflow bundle refused")),\n', 1),
    ('            _ = try waitElement(review.staticTexts.matching(identifier: "Local workflow bundle refused"),\n',
     '            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Local workflow bundle refused")),\n', 1),
    ('            _ = try waitElement(restartedRenderer.staticTexts.matching(identifier: "Let’s get project ready."), in: restartedRenderer,\n',
     '            _ = try waitElement(restartedRenderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: restartedRenderer,\n', 1),
)
RENDERER_QUERY_BEGIN = '        // Fixed renderer singleton diagnostic; no additional query or wait.\n'
RENDERER_QUERY_END = '        // End fixed renderer singleton diagnostic.\n'
RENDERER_QUERY_ORIGINAL = '        let renderer = try unique(window.webViews, "ordinary first-party renderer is missing or ambiguous")\n'
RENDERER_QUERY_DIAGNOSTICS_SHA256 = 'dea59830e6aef376217856dc9779acffb9634aa5fd2d260847db0b876cb7a0c4'
RENDERER_READINESS_BEGIN = '        // Bounded initial renderer readiness; observed ambiguity remains terminal.\n'
RENDERER_READINESS_END = '        // End bounded initial renderer readiness.\n'
RENDERER_READINESS_SHA256 = '9f8936dd612d12ae8dc10c561181686359171a3ce98021603c12c17a486c2a8a'
ORIGINAL_ROSTER_SHA256 = "293426d49f6bb226563ea325527858b894aa98ac2e72dea6b70875157cfd58e4"
SAVED_CHECKS_ROSTER_SHA256 = "1cf265f8c97381708d68c1dedc8bc61ebcaf182c104d3021bda8b8211f016d65"
ROSTER_SHA256 = "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94"
# The normal result also binds M2-A entry identity without claiming full M2/maintenance readiness.
BLOCK_PINS = {'normal_ui_result': '10624295dc658af933e3abbaf4bc0dd512d558dcb8776ee38d93f06148300527',
 'normal_project_ui_test': '8610371ad9fbc357cac42d8b6796275799a0c1ed436c8331416455974f2c99b5',
 'normal_project_ui_result': 'b0c6b67f2f0914e1e69cd5182b20e04043ce95a7c9299d5115225a1f62f9acf2',
 'normal_persistence_ui_test': '9cc77c35a6fe15ae7cc52155f2b5def9dedd72f9a266f031698fdb7c1e295635',
 'normal_persistence_ui_result': 'e5a27529527fc9c3f79eea85071b14da1b5930337518a8618cd7f57f058b3430',
 'normal_diagnostics_ui_test': '433ccae8e525cea7eb90ce2946e2fe74d6fd1723027135ee05cedf0c1ff9583a',
 'normal_diagnostics_ui_result': '42c762abee679550f043efaefdf0a5f0031e0c46d90adc7da5f1fe1263696cf3',
 'normal_saved_checks_ui_test': '8604b52879c59a82655ba8e92ff0c7c07f57e8611f0380aad54a5127bfb8cdb0',
 'normal_saved_checks_ui_result': '90ad440589ee026a98635883f63e2878295b80da87e34b4d8a74617b46d96105'}
# One added source regression covers the two deliberately separate GUI scopes.
# This is method82 after the unchanged original81; two already-reviewed Android
# caller/source checks follow it in the current fixed84 workflow selection.
SAVED_CHECKS_SOURCE_METHOD = 'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_saved_offline_and_empty_recovery_use_original_gui_only'
SAVED_CHECKS_BEGIN = "    // Ordinary saved offline checks and empty project-recovery inspection only.\n"
SAVED_CHECKS_END = "    // End ordinary saved offline and empty recovery journeys.\n\n"
SAVED_CHECKS_INSERTION_SHA256 = "f51d6f4576db08022016938624571f0b05781fdff8b66a060cc927801696e391"
SAVED_CHECKS_SOURCE_REFS = [
    'desktop/src/components/OfflinePreflight.tsx',
    'desktop/src/components/ProjectRecovery.tsx',
    'desktop/src/components/Common.tsx',
    'desktop/src/offlinePreflight.ts',
    'desktop/src/projectRecoveryController.ts',
    'desktop/src/offlinePreflightProtocol.ts',
    'desktop/src/projectRecoveryProtocol.ts',
    'src/mobile_release/desktop_preflight.py',
    'src/mobile_release/desktop_project_recovery.py',
    'src/mobile_release/build_inputs.py',
    'src/mobile_release/discovery.py',
]

SOURCE_REFS = ['tests/desktop/test_macos_normal_diagnostics_source.py',
 'desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift',
 'desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json',
 'desktop/src/components/EnvironmentDiagnostics.tsx',
 'desktop/src/environmentDiagnosticsController.ts',
 'desktop/src-tauri/src/environment_diagnostics_owner.rs']
EVIDENCE_LEAVES = ['diagnostics-test-file-limit.status',
 'diagnostics-test-file-budget.status',
 'diagnostics-test-file-budget.json',
 'diagnostics-test.status',
 'diagnostics-safe-facts.json',
 'diagnostics-summary.status',
 'diagnostics-result.json']


# Closed engineering-only inverse: unchanged ordinary semantic/owner hashes below
# remain authoritative after exactly these reviewed source regions are removed.
# Exact context-bound inverse of the accepted engineering failure diagnostics.
ENGINEERING_DIAGNOSTIC_REGIONS = (('    @MainActor private var packagedRequireDiagnosticEmitted = false\n'
  '    @MainActor private var originalLaunch: OrdinaryLaunch?\n',
  '    @MainActor private var packagedRequireDiagnosticEmitted = false\n'
  '    @MainActor private var engineeringRequireDiagnosticActive = false\n'
  '    @MainActor private var engineeringRequireDiagnosticEmitted = false\n'
  '    @MainActor private var originalLaunch: OrdinaryLaunch?\n'),
 ('                    '
  'print("MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=\\(line);ordinal=\\(sample.ordinal);waiter=\\(waiter.rawValue);enabled=\\(sample.enabled '
  '? 1 : 0);hittable=\\(sample.hittable ? 1 : '
  '0);reason=\\(sample.reason.rawValue);sample=pre-wait;nonAtomic=1")\n'
  '                }\n'
  '            }\n'
  '            throw refusal\n',
  '                    '
  'print("MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=\\(line);ordinal=\\(sample.ordinal);waiter=\\(waiter.rawValue);enabled=\\(sample.enabled '
  '? 1 : 0);hittable=\\(sample.hittable ? 1 : '
  '0);reason=\\(sample.reason.rawValue);sample=pre-wait;nonAtomic=1")\n'
  '                }\n'
  '            }\n'
  '            if engineeringRequireDiagnosticActive && originalFailureAbsent && '
  '!engineeringRequireDiagnosticEmitted\n'
  '                && line >= 1 && line <= 65535 {\n'
  '                engineeringRequireDiagnosticEmitted = true\n'
  '                print("MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=\\(line);check=\\(check.rawValue)")\n'
  '            }\n'
  '            throw refusal\n'))
ENGINEERING_MAIN_BEGIN = '    // Engineering main only: actual embedded UI and current-core reference data.\n'
ENGINEERING_MAIN_END = '    // End engineering main fixture; ordinary installed cases below are unchanged.\n\n'
ENGINEERING_MAIN_SHA256 = '5e3cec325b490f149d2967aeebe01d017b72f16660ac88280420c33713f2527d'
ENGINEERING_BEFORE_SWIFT_SHA256 = 'c463302b56cee2da043d1cbb9ce87f03f1d92118759cf3c3127ed25dc48f0dad'
ENGINEERING_CORE_GUIDE_SHA256 = '7f9828720684a1b6d071df2a34d415feb8ff4552c89d8d6d42b19970d838d478'
ENGINEERING_SHARED_REGIONS = (('        private let clock: CaseClock\n        private let reply = LaunchReply()',
  '        private let clock: CaseClock\n'
  '        private let profile: LaunchProfile\n'
  '        private let reply = LaunchReply()'),
 ('        init(clock: CaseClock) { self.clock = clock }',
  '        init(clock: CaseClock, profile: LaunchProfile = .ordinary) {\n'
  '            self.clock = clock\n'
  '            self.profile = profile\n'
  '        }'),
 ('        private func payloadIdentity() throws -> NSRunningApplication {\n'
  '            guard let original,\n'
  '                  original.bundleURL?.path == Self.payloadURL.path,\n'
  '                  original.executableURL?.path == '
  'Self.payloadURL.appendingPathComponent("Contents/MacOS/mobile-release-kit-desktop").path,\n'
  '                  original.bundleIdentifier == "dev.mobile-release-kit.desktop" else {\n'
  '                throw clock.fail("original running reference is not the fixed payload")\n'
  '            }\n'
  '            return original\n'
  '        }\n',
  '        private func payloadIdentity() throws -> NSRunningApplication {\n'
  '            switch profile {\n'
  '            case .ordinary:\n'
  '                guard let original,\n'
  '                      original.bundleURL?.path == Self.payloadURL.path,\n'
  '                      original.executableURL?.path == '
  'Self.payloadURL.appendingPathComponent("Contents/MacOS/mobile-release-kit-desktop").path,\n'
  '                      original.bundleIdentifier == "dev.mobile-release-kit.desktop" else {\n'
  '                    throw clock.fail("original running reference is not the fixed payload")\n'
  '                }\n'
  '                return original\n'
  '            case .engineeringMain(let work):\n'
  '                let app = work.appendingPathComponent("Mobile Release Kit.app", isDirectory: true)\n'
  '                guard let original, original.bundleURL?.path == app.path,\n'
  '                      original.executableURL?.path == '
  'app.appendingPathComponent("Contents/MacOS/mobile-release-kit-desktop").path,\n'
  '                      original.bundleIdentifier == "dev.mobile-release-kit.engineering-ui" else {\n'
  '                    throw clock.fail("original running reference is not the fixed engineering main")\n'
  '                }\n'
  '                return original\n'
  '            }\n'
  '        }\n'),
 ('            // No environment override: the unchanged ordinary entry derives its\n'
  '            // own eight-entry environment and inherits the original gate once.\n'
  '            requested = true\n'
  '            let mailbox = reply\n'
  '            NSWorkspace.shared.openApplication(at: Self.outerURL, configuration: configuration) { [self, '
  'mailbox] application, error in\n',
  '            let requestURL: URL\n'
  '            switch profile {\n'
  '            case .ordinary:\n'
  '                // No environment override: the unchanged ordinary entry derives its\n'
  '                // own eight-entry environment and inherits the original gate once.\n'
  '                requestURL = Self.outerURL\n'
  '            case .engineeringMain(let work):\n'
  '                requestURL = work.appendingPathComponent("Mobile Release Kit.app", isDirectory: true)\n'
  '                configuration.environment = [\n'
  '                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner", '
  '"LOGNAME": "runner",\n'
  '                    "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",\n'
  '                    "TMPDIR": work.appendingPathComponent("normal-ui/tmp", isDirectory: true).path + "/",\n'
  '                    "MRK_DESKTOP_DEV_PYTHON": work.appendingPathComponent("runtime/python/bin/python3").path,\n'
  '                    "MRK_DESKTOP_DEV_CORE": work.appendingPathComponent("runtime/core.zip").path,\n'
  '                ]\n'
  '            }\n'
  '            requested = true\n'
  '            let mailbox = reply\n'
  '            NSWorkspace.shared.openApplication(at: requestURL, configuration: configuration) { [self, mailbox] '
  'application, error in\n'),
 ('        try require(originalLaunch == nil && entryGateObservation == nil && !normalQuitObserved,\n'
  '                    "a new ordinary launch requires empty active custody")',
  '        try require(originalLaunch == nil && entryGateObservation == nil && !normalQuitObserved\n'
  '                    && ProcessInfo.processInfo.environment["MRK_ENGINEERING_UI_WORK"] == nil,\n'
  '                    "a new ordinary launch requires empty active custody and no engineering profile")'))


# Exact new recovery regions only; all original source pins remain below.
SAVED_VERSION_SWIFT_INSERTIONS = (('        // A one-case transfer of observation custody, never a product lease. The\n',
  '        private func checkRoster() throws {',
  '9439e8d33ab2ed2b14da38c9d5b214318d1a3baa74b29e2171ce255ebc976906'),
 ("    // One real interrupted core process, then a fresh ordinary app's registered\n",
  '    @MainActor func testSyntheticProjectManagedWorkflowRefusal() throws {',
  '6042c9890e09977521ea14f7462a0c792e019417d40256b9c0ada6f23bc57c26'))
SAVED_VERSION_SWIFT_REGIONS = (('        enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal }\n',
  '        enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal, '
  'savedVersionRecovery }\n'),
 ('        private func readLeaf(_ original: Directory, name: String, privateOnly: Bool = false) throws -> File {\n',
  '        private func readLeaf(_ original: Directory, name: String, privateOnly: Bool = false, limit: Int = 32 * '
  '1024) throws -> File {\n'),
 ('                && before.uid == getuid() && before.gid == getgid() && before.bytes >= 0 && before.bytes <= 32 * '
  '1024\n',
  '                && before.uid == getuid() && before.gid == getgid() && before.bytes >= 0 && before.bytes <= '
  'limit\n'),
 ('                try Self.need(bytes.count + count <= 32 * 1024, "fixed leaf read limit")\n',
  '                try Self.need(bytes.count + count <= limit, "fixed leaf read limit")\n'),
 ('', '                if savedVersionPending && name == ".mobile-release-version" { continue }\n'),
 ('',
  '            if profile == .savedVersionRecovery {\n'
  '                guard let ignore = changes["config"]?["project/.gitignore"] else { throw '
  'Refusal.condition("fixture: fixed recovery ignore DATA absent") }\n'
  '                originals["project/.gitignore"] = ignore // Only before original admission; never after a '
  'snapshot.\n'
  '            }\n'),
 ('',
  '            if profile == .savedVersionRecovery {\n'
  '                try adoptSavedVersion(data, temporary: temporary)\n'
  '                return\n'
  '            }\n'))
SAVED_VERSION_BEFORE_SWIFT = 'a6d66a9b2de69c5f0a9b5ede463268272f8aeeee2dca1d554149ff59f37f3774'
SAVED_VERSION_WORKFLOW_BLOCKS = (('normal_saved_version_recovery_ui_test', 'e63e1155efa9166c917507e26ada153771290a7adf1ee34306bba9dbf89b96a7'),
 ('normal_saved_version_recovery_ui_result', 'ed519589f83d26474c8ccd5821c327aa0d0ed16a0e9ac785f589d885c4c5b42a'))
SAVED_VERSION_WORKFLOW_REGIONS = (('    # Timed steps total359min, but the two refs are mutually exclusive:\n'
  '    # preview345 / installed210, cleanup included in both, plus5min overhead.\n',
  '    # Closed SOURCE selection, not additive UI work: default preview345,\n'
  '    # recovery preview339 / installed210, cleanup included, plus5min overhead.\n'),
 ('',
  '      # A separate reviewed SOURCE change selects the targeted recovery run.\n'
  '      # Default seven cases and the singleton are distinct native obligations.\n'
  '      MRK_MACOS_SAVED_FILE_UI_SCOPE: ordinary-seven\n'),
 ('',
  '          case "$MRK_MACOS_SAVED_FILE_UI_SCOPE" in\n'
  '            ordinary-seven) ;;\n'
  '            saved-version-recovery) [[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-preview ]] || exit 1 ;;\n'
  '            *) exit 1 ;;\n'
  '          esac\n'),
 ("        if: github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome "
  "== 'success'\n",
  "        if: github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome "
  "== 'success' && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven'\n"),
 ('',
  '            {0}/normal-ui/saved-version-recovery-test-file-limit.status\n'
  '            {0}/normal-ui/saved-version-recovery-test.status\n'
  '            {0}/normal-ui/saved-version-recovery-test.runner-admission.json\n'
  '            {0}/normal-ui/saved-version-recovery-test.failure-diagnostics.json\n'
  '            {0}/normal-ui/saved-version-recovery-summary.status\n'
  '            {0}/normal-ui/saved-version-recovery-summary.command-admission.json\n'
  '            {0}/normal-ui/saved-version-recovery-summary.failure-diagnostics.json\n'
  '            {0}/normal-ui/saved-version-recovery-result.json\n'),
 ("        if: always() && steps.preview_upload.outcome == 'success' && steps.normal_ui_result.outcome == 'success' "
  "&& steps.normal_persistence_ui_result.outcome == 'success' && steps.normal_project_ui_result.outcome == 'success' "
  "&& steps.normal_diagnostics_ui_result.outcome == 'success' && steps.normal_saved_checks_ui_result.outcome == "
  "'success' && steps.data_contracts.outcome == 'success' && steps.evidence.outcome == 'success'\n",
  "        if: always() && steps.preview_upload.outcome == 'success' && steps.normal_ui_result.outcome == 'success' "
  "&& steps.normal_persistence_ui_result.outcome == 'success' && steps.normal_project_ui_result.outcome == 'success' "
  "&& steps.normal_diagnostics_ui_result.outcome == 'success' && ((env.MRK_MACOS_SAVED_FILE_UI_SCOPE == "
  "'ordinary-seven' && steps.normal_saved_checks_ui_result.outcome == 'success') || "
  "(env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery' && "
  "steps.normal_saved_version_recovery_ui_result.outcome == 'success')) && steps.data_contracts.outcome == 'success' "
  "&& steps.evidence.outcome == 'success'\n"),
 ('',
  '          scope = os.environ["MRK_MACOS_SAVED_FILE_UI_SCOPE"]\n'
  '          if scope not in ("ordinary-seven", "saved-version-recovery"):\n'
  '              raise ValueError("task cleanup SOURCE scope refused")\n'
  '          test_stem, summary_stem = (("saved-checks-test", "saved-checks-summary") if scope == "ordinary-seven"\n'
  '                                    else ("saved-version-recovery-test", "saved-version-recovery-summary"))\n'
  '          # The skipped cohort supplies no finality or cleanup authority.\n'
  '          saved_directory = root / ("normal-ui/" + test_stem + ".xcresult")\n'
  '          saved_logs = (test_stem + ".log", summary_stem + ".raw.json", summary_stem + ".stderr")\n'),
 ('                       root / "normal-ui/DerivedData", root / "normal-ui/test.xcresult", root / '
  '"normal-ui/persistence-test.xcresult", root / "normal-ui/project-test.xcresult", root / '
  '"normal-ui/diagnostics-test.xcresult", root / "normal-ui/saved-checks-test.xcresult", root / "normal-ui/tmp",\n',
  '                       root / "normal-ui/DerivedData", root / "normal-ui/test.xcresult", root / '
  '"normal-ui/persistence-test.xcresult", root / "normal-ui/project-test.xcresult", root / '
  '"normal-ui/diagnostics-test.xcresult", saved_directory, root / "normal-ui/tmp",\n'),
 ('                       "saved-checks-test.log", "saved-checks-summary.raw.json", '
  '"saved-checks-summary.stderr"):\n',
  '                       *saved_logs):\n'))
SAVED_VERSION_BEFORE_WORKFLOW = '47c8ef03bd6de39acd1e10cb91aefdf046b6b5466355b622857a95e7e1dbad9c'
SAVED_VERSION_EVIDENCE = ('saved-version-recovery-test-file-limit.status',
 'saved-version-recovery-test.status',
 'saved-version-recovery-test.runner-admission.json',
 'saved-version-recovery-test.failure-diagnostics.json',
 'saved-version-recovery-summary.status',
 'saved-version-recovery-summary.command-admission.json',
 'saved-version-recovery-summary.failure-diagnostics.json',
 'saved-version-recovery-result.json')


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def steps(workflow: str) -> tuple[list[str | None], dict[str, str]]:
    blocks = re.findall(r"(?ms)^      - name: .*?(?=^      - name: |\Z)", workflow)
    ids: list[str | None] = []
    mapped = {}
    for block in blocks:
        found = re.search(r"(?m)^        id: ([a-z0-9_]+)$", block)
        ident = found[1] if found else None
        ids.append(ident)
        if ident is not None:
            if ident in mapped:
                raise ValueError("duplicate workflow step identifier")
            mapped[ident] = block
    return ids, mapped


def inline_python(block: str, marker: str) -> str:
    head = "          \"$MRK_PYTHON\" -I -S -B - <<'" + marker + "'\n"
    if block.count(head) != 1:
        raise ValueError("missing original inline Python boundary")
    value = block.split(head, 1)[1].split("          " + marker + "\n", 1)[0]
    lines = value.splitlines(keepends=True)
    if not all(not line.strip() or line.startswith("          ") for line in lines):
        raise ValueError("inline Python indentation changed")
    source = "".join(line[10:] if line.strip() else line for line in lines)
    ast.parse(source)
    return source


class NormalDiagnosticsSourceTests(unittest.TestCase):
    def test_current_intel_app_build_budget_precedes_historical_projection(self):
        # Current SOURCE only: a larger finite allocation is not native completion.
        root = Path(__file__).absolute().parents[2]
        with (root / ".github/workflows/desktop-macos-installed.yml").open("rb") as stream:
            body = stream.read(512 * 1024 + 1)
        self.assertLessEqual(len(body), 512 * 1024)
        source = body.decode("utf-8", "strict")
        for previous, current in INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE:
            self.assertEqual(source.count(current), 1)
            self.assertNotIn(previous, source)
        expression = "${{ matrix.target == 'x86_64-apple-darwin' && 48 || 24 }}"
        name = "      - name: Build the ordinary selected-target desktop image and embedded frontend\n"
        self.assertEqual(source.count(name), 1)
        app = source.split(name, 1)[1].split("      - name:", 1)[0]
        self.assertEqual(re.findall(r"^        timeout-minutes: (.+)$", app, re.M), [expression])
        self.assertEqual(source.count(expression), 1)
        containing = "    timeout-minutes: ${{ github.ref == 'refs/heads/verify/desktop-macos-app-signature' && 110 || 350 }}\n"
        self.assertEqual(source.count(containing), 1)
        self.assertIn("        id: shipping_compile\n        timeout-minutes: 24\n",
                      source.split("  shipping-image-compile:\n", 1)[1])
        matrix = re.findall(r"^        include: (.+)$", source, re.M)
        self.assertEqual(len(matrix), 1)
        self.assertIn("github.ref == 'refs/heads/verify/desktop-macos-removal-lifecycle'", matrix[0])
        branches = re.findall(r"'(\[\{.*?\}\])'", matrix[0])
        self.assertEqual(len(branches), 2)
        self.assertEqual([(row["target"], row["removal_case"]) for row in json.loads(branches[0])],
                         [("aarch64-apple-darwin", "ordinary"), ("aarch64-apple-darwin", "abrupt")])
        self.assertEqual([(row["target"], row["runner"]) for row in json.loads(branches[1])],
                         [("aarch64-apple-darwin", "macos-26"), ("x86_64-apple-darwin", "macos-26-intel")])
        prior = without_intel_app_build_budget_workflow(source)
        self.assertEqual(len(prior.encode()), 434739)
        self.assertEqual(hashlib.sha256(prior.encode()).hexdigest(),
                         "1dc04737ea6298f34196adb7f71e4fb0f6b25b50dde30b4c95292d29efec4514")
        self.assertEqual(without_intel_app_build_budget_workflow(prior), prior)
        self.assertEqual(matrix, re.findall(r"^        include: (.+)$", prior, re.M))
        old_app = prior.split(name, 1)[1].split("      - name:", 1)[0]
        for previous, current in INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE[1:]:
            app = app.replace(current, previous, 1)
        self.assertEqual(app, old_app)  # Commands, environment and original status writes are unchanged.
        self.assertEqual(without_app_signature_workflow(source), without_app_signature_workflow(prior))
        for previous, current in INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE:
            for altered in ("", previous, current + current, previous + current,
                            current[:-1], current.replace(" ", "  ", 1)):
                with self.subTest(altered=altered), self.assertRaises(AssertionError):
                    without_intel_app_build_budget_workflow(source.replace(current, altered, 1))
        for altered in (expression.replace("48", "49"), expression.replace("24", "25"),
                        expression.replace("x86_64-apple-darwin", "aarch64-apple-darwin")):
            with self.assertRaises(AssertionError):
                without_intel_app_build_budget_workflow(source.replace(expression, altered, 1))
        for old in ("unchanged historical DATA\n", "name: Historical Aqua qualification\n"):
            self.assertEqual(without_intel_app_build_budget_workflow(old), old)
        unrelated = source + "# unrelated mutation\n"
        self.assertEqual(without_intel_app_build_budget_workflow(unrelated), prior + "# unrelated mutation\n")
        with self.assertRaises(AssertionError):
            without_app_signature_workflow(unrelated)
        # Erasing all new markers cannot bypass the unchanged whole-workflow hash.
        erased = source
        for previous, current in INTEL_APP_BUILD_BUDGET_WORKFLOW_INVERSE:
            erased = erased.replace(current, "", 1)
        with self.assertRaises(AssertionError):
            without_app_signature_workflow(erased)
        for invalid in (None, b"DATA", "x" * (512 * 1024 + 1),
                        source.replace(source.splitlines()[0], "name: Historical Aqua qualification", 1)):
            with self.assertRaises(AssertionError):
                without_intel_app_build_budget_workflow(invalid)

    def test_removal_public_evidence_case_is_current_before_historical_projection(self):
        # Read actual current SOURCE, not the inverse view or a raw artifact.
        root = Path(__file__).absolute().parents[2]
        with (root / ".github/workflows/desktop-macos-installed.yml").open("rb") as stream:
            body = stream.read(512 * 1024 + 1)
        self.assertLessEqual(len(body), 512 * 1024)
        source = body.decode("utf-8", "strict")
        previous, current = REMOVAL_PUBLIC_VERIFICATION_WORKFLOW_INVERSE
        self.assertEqual(source.count(current), 1)
        self.assertNotIn(previous, source)
        self.assertEqual(source.count('--removal-case "$MRK_MACOS_REMOVAL_CASE"'), 1)
        prior = without_removal_public_verification_workflow(source)
        self.assertEqual(hashlib.sha256(prior.encode()).hexdigest(),
                         "70f45b237ad1fee9466dafa427e661df2c8cd5bb96f513820eeacd5145c2bf32")
        self.assertEqual(without_removal_public_verification_workflow(prior), prior)
        self.assertEqual(without_public_verification_workflow(source), without_public_verification_workflow(prior))
        self.assertEqual(without_app_signature_workflow(source), without_app_signature_workflow(prior))
        for altered in ("", current + current, previous + current, current[:-1],
                        current.replace("--removal-case", "--removal-case disabled", 1),
                        current.replace("MRK_MACOS_REMOVAL_CASE", "MRK_OTHER_CASE", 1),
                        current.replace('            --removal-case', '          --removal-case', 1),
                        current.split('            --removal-case', 1)[0],
                        current.replace("--profile installed", "--profile aqua", 1)):
            damaged = source.replace(current, altered, 1)
            self.assertNotEqual(damaged, source)
            with self.subTest(altered=altered), self.assertRaises(AssertionError):
                without_removal_public_verification_workflow(damaged)
            with self.assertRaises(AssertionError):
                without_public_verification_workflow(damaged)
        self.assertEqual(without_removal_public_verification_workflow("unchanged historical DATA\n"),
                         "unchanged historical DATA\n")
        self.assertEqual(without_removal_public_verification_workflow(source + "# unrelated mutation\n"),
                         prior + "# unrelated mutation\n")
        with self.assertRaises(AssertionError):
            without_app_signature_workflow(source + "# unrelated mutation\n")
        for invalid in (None, b"DATA", "x" * (512 * 1024 + 1), "--removal-case disabled\n"):
            with self.assertRaises(AssertionError):
                without_removal_public_verification_workflow(invalid)

    def test_public_verification_exports_are_current_closed_data_before_projection(self):
        # Fixed bounded SOURCE only. No historical module/product import or child.
        root = Path(__file__).absolute().parents[2]
        for path, header, prior_hash, replacements in PUBLIC_VERIFICATION_WORKFLOW_INVERSE:
            with self.subTest(workflow=path):
                with (root / path).open("rb") as stream:
                    body = stream.read(512 * 1024 + 1)
                self.assertLessEqual(len(body), 512 * 1024)
                source = body.decode("utf-8", "strict")
                self.assertTrue(source.startswith(header))
                self.assertEqual(source.count("        id: public_evidence\n"), 1)
                self.assertEqual(source.count("desktop/tools/macos_public_verification_evidence.py"), 1)
                # Only the independently asserted current removal-case CLI suffix is projected here.
                source = without_removal_public_verification_workflow(source)
                upload_count = 0
                for previous, current in replacements:
                    self.assertEqual(source.count(current), 1)
                    if current.startswith("      - name: Preserve"):
                        upload_count += 1
                        self.assertEqual([line for line in current.splitlines() if line.startswith("          path:")],
                                         ["          path: ${{ steps.work.outputs.root }}/public-verification-evidence.json"])
                        self.assertIn("&& steps.public_evidence.outcome == 'success'\n", current)
                        self.assertNotIn("          path: |", current)
                    if current.startswith("      - name: Project closed public verification facts"):
                        projector = current.split("      - name:", 2)[1]
                        self.assertIn("        timeout-minutes: 1\n", projector)
                        self.assertIn("/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC", projector)
                        self.assertNotIn("secrets.", projector)
                        self.assertNotIn("continue-on-error", projector)
                    for altered in (current + current, current[:-1], current.replace(" ", "  ", 1)):
                        with self.assertRaises(AssertionError):
                            without_public_verification_workflow(source.replace(current, altered, 1))
                    # No partial old/new export state is accepted.
                    with self.assertRaises(AssertionError):
                        without_public_verification_workflow(source.replace(current, previous, 1))
                self.assertEqual(upload_count, 1 if "installed.yml" in path else 4)
                prior = without_public_verification_workflow(source)
                self.assertEqual(hashlib.sha256(prior.encode()).hexdigest(), prior_hash)
                self.assertEqual(without_public_verification_workflow(prior), prior)
                self.assertEqual(without_public_verification_workflow(source + "# unrelated mutation\n"),
                                 prior + "# unrelated mutation\n")
                if "installed.yml" in path:
                    # Existing historical whole-workflow hash still rejects unrelated bytes.
                    with self.assertRaises(AssertionError):
                        without_app_signature_workflow(source + "# unrelated mutation\n")
                    delivery_name = "      - name: Upload only the normal user preview package and guide\n"
                    delivery = source.split(delivery_name, 1)[1].split("      - name:", 1)[0]
                    old_delivery = prior.split(delivery_name, 1)[1].split("      - name:", 1)[0]
                    self.assertEqual(delivery, old_delivery)
                    self.assertEqual([line.strip() for line in delivery.splitlines()
                                      if line.startswith("            ${{ steps.work.outputs.root }}/")],
                                     ["${{ steps.work.outputs.root }}/" + leaf for leaf in
                                      ("preview/MobileReleaseKit.dmg", "preview/README.md", "preview/PREVIEW.json",
                                       "remove-preview/MobileReleaseKit-Remove.dmg", "remove-preview/REMOVE.md", "remove-preview/REMOVAL.json")])
        self.assertEqual(without_public_verification_workflow("unchanged historical DATA\n"),
                         "unchanged historical DATA\n")

    def test_exact_recent_app_workflow_projection_preserves_historical_hashes(self):
        # Bounded SOURCE DATA only; never import a stager or execute a workflow.
        root = Path(__file__).absolute().parents[2]
        with (root / ".github/workflows/desktop-macos-installed.yml").open("rb") as stream:
            body = stream.read(512 * 1024 + 1)
        self.assertLessEqual(len(body), 512 * 1024)
        source = body.decode("utf-8", "strict")
        source = without_intel_app_build_budget_workflow(source)
        projected = without_recent_app_signature_workflow(source)
        # Exact e1e4b36 bytes, not a refreshed historical app-predecessor hash.
        self.assertEqual(hashlib.sha256(projected.encode()).hexdigest(),
                         "22ce8c9e9f53b9e5e7fd25c0cb11dc305c3780c204305cc326ec4df07b68033b")
        self.assertEqual(without_recent_app_signature_workflow(projected), projected)
        self.assertEqual(without_recent_app_signature_workflow("unchanged historical DATA\n"),
                         "unchanged historical DATA\n")
        app_prior = without_app_signature_workflow(source)
        self.assertEqual(hashlib.sha256(app_prior.encode()).hexdigest(),
                         "fdbe8fcc6595ce90cb5cab397b4050cf53c164132198252d6b6ada4be4b83081")
        self.assertEqual(without_app_signature_workflow(app_prior), app_prior)
        self.assertEqual(without_current_runtime_source_pin(source), app_prior.replace(
            "f35a69f6a0e4baf2b365fc28662152d529564107738da9f477363dcc2ea6cdc2",
            "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0"))
        for label, markers, replacements in RECENT_APP_SIGNATURE_WORKFLOW_INVERSE:
            with self.subTest(delta=label):
                self.assertTrue(any(marker in source for marker in markers))
                for current, previous in replacements:
                    self.assertEqual(source.count(current), 1)
                    # Keep recognized text while breaking a complete line/block.
                    for altered in (current + current, current[:-1], current.replace(" ", "  ", 1)):
                        broken = source.replace(current, altered, 1)
                        with self.assertRaises(AssertionError):
                            without_recent_app_signature_workflow(broken)
                    if len(replacements) > 1:
                        with self.assertRaises(AssertionError):
                            without_recent_app_signature_workflow(source.replace(current, previous, 1))
                # Exact older intermediate groups remain admissible, not partial groups.
                intermediate = source
                for current, previous in replacements:
                    intermediate = intermediate.replace(current, previous, 1)
                self.assertEqual(without_recent_app_signature_workflow(intermediate), projected)
        enrolled = "58f6d68d2db29100ed15fd8c4f8d893b3a0a3dbe1d8cd37b385690c36b9cfa3d"
        preceding = "f35a69f6a0e4baf2b365fc28662152d529564107738da9f477363dcc2ea6cdc2"
        for broken in (source.replace(enrolled, preceding, 1),
                       preceding.join(source.rsplit(enrolled, 1))):
            for normalize in (without_app_signature_workflow, without_current_runtime_source_pin):
                with self.assertRaisesRegex(AssertionError, "^current runtime source pin exact two-site delta differs$"):
                    normalize(broken)
        # An unrelated change survives companion projection and the old hash refuses it.
        unrelated = source + "# unrelated mutation\n"
        self.assertEqual(without_recent_app_signature_workflow(unrelated), projected + "# unrelated mutation\n")
        with self.assertRaises(AssertionError):
            without_app_signature_workflow(unrelated)

    def restored_android_output_and_xml(self, swift: str) -> str:
        # Exact reviewed insertions only; never broaden historical owner hashes.
        # The separate existing native DATA case exercises the real Swift DFS.
        for begin, end, expected in (('        // Fixed positive Android output custody. No current Profile enters it.', '        // A one-case transfer of observation custody, never a product lease.', '72deebe04548ac88948e562d51e3c45e74da2c417746e77000e05609a74e0008'), ("    // Read only the ordinary parsed-current Build details within the caller's", '    @MainActor private var ownedFixture: LocalFixture?', '23e0e04b5416b60dcdddb44d6c0013ae5b52f6e0d690da8da4bcf6603d40e567')):
            self.assertEqual(swift.count(begin), 1)
            self.assertEqual(swift.count(end), 1)
            start, finish = swift.index(begin), swift.index(end, swift.index(begin))
            self.assertEqual(digest(swift[start:finish].encode()), expected)
            swift = swift[:start] + swift[finish:]
        for line in ('            let missingAndroidClosure = androidOutput != nil && !androidClosing\n', '            try Self.need(!missingAndroidClosure, "Android final output observation was not joined before close")\n'):
            self.assertEqual(swift.count(line), 1)
            swift = swift.replace(line, "", 1)
        self.assertEqual(digest(swift.encode()), "2c2f47ace92b094365ac93a661b6e944d54b25a363a7d53f0b8350d420b9d93b")
        begin, end, expected = ('        // Fixed public XML prerequisite only.', '        private func children(_ directory: Directory) throws -> Set<String> {', '12ae200158270a950eb25af3272ac798631e846e2e82c5b7a482987e39b09a7b')
        self.assertEqual(swift.count(begin), 1)
        self.assertEqual(swift.count(end), 1)
        start, finish = swift.index(begin), swift.index(end, swift.index(begin))
        self.assertEqual(digest(swift[start:finish].encode()), expected)
        swift = swift[:start] + swift[finish:]
        self.assertEqual(digest(swift.encode()), "dd1c74e980a587b848b8a8965c1883f746374526a523cafbc7386769e198ab4a")
        return swift

    def restored_engineering_main(self, swift: str) -> str:
        swift = self.restored_android_output_and_xml(swift)
        for begin, end, expected_hash in SAVED_VERSION_SWIFT_INSERTIONS:
            self.assertEqual(swift.count(begin), 1)
            self.assertEqual(swift.count(end), 1)
            start, finish = swift.index(begin), swift.index(end, swift.index(begin))
            self.assertEqual(digest(swift[start:finish].encode()), expected_hash)
            swift = swift[:start] + swift[finish:]
        for old, new in reversed(SAVED_VERSION_SWIFT_REGIONS):
            self.assertEqual(swift.count(new), 1)
            swift = swift.replace(new, old, 1)
        self.assertEqual(digest(swift.encode()), SAVED_VERSION_BEFORE_SWIFT)
        self.assertEqual(swift.count(ENGINEERING_MAIN_BEGIN), 1)
        self.assertEqual(swift.count(ENGINEERING_MAIN_END), 1)
        begin = swift.index(ENGINEERING_MAIN_BEGIN)
        end = swift.index(ENGINEERING_MAIN_END) + len(ENGINEERING_MAIN_END)
        self.assertLess(begin, end)
        self.assertEqual(digest(swift[begin:end].encode()), ENGINEERING_MAIN_SHA256)
        swift = swift[:begin] + swift[end:]
        for original, current in reversed(ENGINEERING_DIAGNOSTIC_REGIONS):
            self.assertEqual(swift.count(current), 1)
            swift = swift.replace(current, original, 1)
        for original, current in reversed(ENGINEERING_SHARED_REGIONS):
            self.assertEqual(swift.count(current), 1)
            swift = swift.replace(current, original, 1)
        self.assertEqual(digest(swift.encode()), ENGINEERING_BEFORE_SWIFT_SHA256)
        return swift

    def restored_initial_renderer_readiness(self, swift: str) -> str:
        # This one reviewed readiness allowance is not a general normalization:
        # the other launch site and every byte outside this block remain bound.
        self.assertEqual(swift.count(RENDERER_READINESS_BEGIN), 1)
        self.assertEqual(swift.count(RENDERER_READINESS_END), 1)
        begin = swift.index(RENDERER_READINESS_BEGIN)
        end = swift.index(RENDERER_READINESS_END) + len(RENDERER_READINESS_END)
        self.assertLess(begin, end)
        block = swift[begin:end]
        launch = swift.split('private func launchCancelAndQuit(profile:', 1)[1].split(
            '    private struct FixtureSpec', 1)[0]
        self.assertEqual(launch.count(block), 1)
        self.assertEqual(digest(block.encode()), RENDERER_READINESS_SHA256)
        ordered = (
            'let rendererQuery = window.webViews',
            'let rendererCount = rendererQuery.count',
            'if rendererCount != 1 {',
            'try require(rendererCount <= 1, "ordinary first-party renderer is ambiguous")',
            'var observedReadyCount = rendererCount',
            'if rendererCount == 0 {',
            'try require(rendererQuery.element(boundBy: 0).waitForExistence(timeout: try remaining(5)),',
            'observedReadyCount = rendererQuery.count',
            'try require(observedReadyCount == 1, "ordinary first-party renderer is missing or ambiguous")',
            'let renderer = rendererQuery.element(boundBy: 0)',
        )
        positions = []
        for token in ordered:
            self.assertEqual(block.count(token), 1, token)
            positions.append(block.index(token))
        self.assertEqual(positions, sorted(positions))
        self.assertIn('if rendererCount == 0 {\n'
                      '            try require(rendererQuery.element(boundBy: 0).waitForExistence(timeout: try remaining(5)),\n'
                      '                        "ordinary first-party renderer did not appear")\n'
                      '            observedReadyCount = rendererQuery.count\n'
                      '        }\n', block)
        for token, count in (('window.webViews', 1), ('.count', 2), ('.element(', 2),
                             ('waitForExistence(', 1), ('remaining(5)', 1), ('print(', 1)):
            self.assertEqual(block.count(token), count, token)
        for forbidden in ('firstMatch', 'matching(', 'allElements', 'descendants(', 'children(',
                          'snapshot(', 'debugDescription', 'sleep(', 'while ', 'return',
                          'try?', 'catch', '.click(', 'evaluateJavaScript', 'app.', 'Process()',
                          'FileManager', 'write(', 'beginCase(', 'journeyDeadline ='):
            self.assertNotIn(forbidden, block, forbidden)
        strict = swift.split('private func launchForJourney() throws -> (XCUIApplication, XCUIElement, XCUIElement) {', 1)[1].split(
            '    private enum PrivateInput: String {', 1)[0]
        self.assertEqual(strict.count(RENDERER_QUERY_BEGIN), 1)
        self.assertEqual(strict.count(RENDERER_QUERY_END), 1)
        original = strict[strict.index(RENDERER_QUERY_BEGIN):strict.index(RENDERER_QUERY_END) + len(RENDERER_QUERY_END)]
        self.assertEqual(len(original.encode()), 576)
        self.assertEqual(digest(original.encode()), RENDERER_QUERY_DIAGNOSTICS_SHA256)
        return swift[:begin] + original + swift[end:]

    def restored_renderer_queries(self, swift: str) -> str:
        swift = self.restored_initial_renderer_readiness(swift)
        # After that exact allowance, bind the same original query/count/refusal
        # at exactly the two existing launch sites without other changes.
        self.assertEqual(swift.count(RENDERER_QUERY_BEGIN), 2)
        self.assertEqual(swift.count(RENDERER_QUERY_END), 2)
        self.assertEqual(swift.count(RENDERER_QUERY_ORIGINAL), 0)
        begin = swift.index(RENDERER_QUERY_BEGIN)
        end = swift.index(RENDERER_QUERY_END, begin) + len(RENDERER_QUERY_END)
        block = swift[begin:end]
        self.assertEqual(swift.count(block), 2)
        for signature, following, dashboard_call in (
            ('    @MainActor private func launchCancelAndQuit(profile: SourceProfile) throws {',
             '    // Finite synthetic files only.', '        try dashboard(renderer, diagnosticOrdinal: 1)\n'),
            ('    @MainActor private func launchForJourney() throws -> (XCUIApplication, XCUIElement, XCUIElement) {',
             '    private enum PrivateInput: String {', '        try dashboard(renderer)\n'),
        ):
            self.assertEqual(swift.count(signature), 1)
            self.assertEqual(swift.count(following), 1)
            caller = swift.split(signature, 1)[1].split(following, 1)[0]
            self.assertEqual(caller.count(block), 1)
            self.assertIn('try require(window.isHittable, "ordinary main window is not usable")\n' + block
                          + dashboard_call, caller)
        for fragment in (
            'let rendererQuery = window.webViews',
            'let rendererCount = rendererQuery.count',
            'if rendererCount != 1 {\n            print(',
            'min(rendererCount, 5)', 'rendererCount > 4 ? 1 : 0',
            'try require(rendererCount == 1, "ordinary first-party renderer is missing or ambiguous")',
            'let renderer = rendererQuery.element(boundBy: 0)',
        ):
            self.assertEqual(block.count(fragment), 1, fragment)
        self.assertEqual(block.count('window.webViews'), 1)
        self.assertEqual(block.count('.count'), 1)
        self.assertEqual(block.count('.element('), 1)
        self.assertEqual(block.count('print('), 1)
        self.assertEqual(block.count('MRK_MACOS_NORMAL_RENDERER_QUERY=observation=initial;matches='), 1)
        self.assertEqual(block.count(';nonAtomic=1"'), 1)
        self.assertEqual(swift.count('MRK_MACOS_NORMAL_RENDERER_QUERY='), 2)
        self.assertLess(block.index('let rendererQuery = window.webViews'), block.index('let rendererCount = rendererQuery.count'))
        self.assertLess(block.index('let rendererCount = rendererQuery.count'), block.index('if rendererCount != 1'))
        self.assertLess(block.index('if rendererCount != 1'), block.index('print('))
        self.assertIn('        }\n        try require(rendererCount == 1, "ordinary first-party renderer is missing or ambiguous")\n'
                      '        let renderer = rendererQuery.element(boundBy: 0)\n', block)
        for forbidden in ('firstMatch', 'matching(', 'allElements', 'descendants(', 'children(',
                          'snapshot(', 'debugDescription', 'waitFor', 'sleep(', 'while ', 'return',
                          'try?', 'catch', '.click(', 'evaluateJavaScript', 'app.', 'Process()',
                          'FileManager', 'write('):
            self.assertNotIn(forbidden, block, forbidden)
        self.assertEqual(digest(block.encode()), RENDERER_QUERY_DIAGNOSTICS_SHA256)
        return swift.replace(block, RENDERER_QUERY_ORIGINAL)

    def restored_semantic_heading_queries(self, swift: str) -> str:
        # Refuse a missing, duplicate, broadened or unexpected title selector
        # before restoring only the reviewed complete source lines.
        self.assertEqual(len(SEMANTIC_HEADING_LINES), 20)
        self.assertEqual(swift.count(SEMANTIC_HEADING_PREFIX), 28)
        for original, semantic, count in SEMANTIC_HEADING_LINES:
            self.assertEqual(swift.count(semantic), count, semantic)
            self.assertEqual(swift.count(original), 0, original)
        for original, semantic, _count in SEMANTIC_HEADING_LINES:
            swift = swift.replace(semantic, original)
        self.assertNotIn(SEMANTIC_HEADING_PREFIX, swift)
        return swift

    def restored_dashboard_query(self, swift: str) -> str:
        # Validate this exact diagnostic allowance before reconstructing the old
        # singleton line for the unchanged whole-original-source pin below.
        self.assertEqual(swift.count(DASHBOARD_QUERY_BEGIN), 1)
        self.assertEqual(swift.count(DASHBOARD_QUERY_END), 1)
        begin = swift.index(DASHBOARD_QUERY_BEGIN)
        end = swift.index(DASHBOARD_QUERY_END) + len(DASHBOARD_QUERY_END)
        self.assertLess(begin, end)
        block = swift[begin:end]
        dashboard = swift.split('    @MainActor private func dashboard(_ renderer: XCUIElement, diagnosticOrdinal: UInt8? = nil) throws {', 1)[1].split(
            '    @MainActor private func quitSheet(', 1)[0]
        self.assertEqual(dashboard.count(block), 1)
        for fragment in (
            'let observedCount = heading.count',
            'if observedCount != 1 {\n            print(',
            'if observedCount > 1 && observedCount <= 4 {\n                for property in [',
            'for property in ["identifier", "title", "label", "value", "placeholderValue"] {',
            'heading.matching(NSPredicate(format: "%K == %@", property, "Good releases start here.")).count',
            'heading.containing(.staticText, identifier: "Good releases start here.").count',
            'try require(observedCount == 1, "dashboard heading is ambiguous")',
        ):
            self.assertEqual(block.count(fragment), 1, fragment)
        for value in ('observedCount', 'matches', 'containing'):
            self.assertEqual(block.count('min(' + value + ', 5)'), 1)
            self.assertEqual(block.count(value + ' > 4 ? 1 : 0'), 1)
        self.assertEqual(block.count('.count'), 3)
        self.assertEqual(block.count('print('), 3)
        self.assertEqual(block.count('MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation='), 3)
        self.assertEqual(block.count(';nonAtomic=1"'), 3)
        self.assertLess(block.index('let observedCount = heading.count'), block.index('if observedCount != 1'))
        self.assertLess(block.index('observation=initial'), block.index('if observedCount > 1 && observedCount <= 4'))
        self.assertLess(block.index('if observedCount > 1 && observedCount <= 4'), block.index('heading.matching('))
        self.assertLess(block.index('heading.containing('), block.index('try require(observedCount == 1'))
        self.assertIn('            }\n        }\n        // Later diagnostic observations cannot repair the original singleton refusal.\n'
                      '        try require(observedCount == 1, "dashboard heading is ambiguous")\n', block)
        for forbidden in ('firstMatch', 'element(', 'allElements', 'snapshot(', 'debugDescription',
                          'waitFor', 'sleep(', 'while ', 'return', 'try?', 'catch', '.click(',
                          'evaluateJavaScript', 'app.', 'Process()', 'FileManager', 'write('):
            self.assertNotIn(forbidden, block, forbidden)
        self.assertEqual(digest(block.encode()), DASHBOARD_QUERY_DIAGNOSTICS_SHA256)
        return swift.replace(block, DASHBOARD_QUERY_ORIGINAL, 1)

    def checked_saved_checks_block(self, swift: str) -> str:
        # Do not broadly strip added methods or accept a self-reported boundary.
        # Both callers validate this single independently pinned closed block.
        self.assertEqual(swift.count(SAVED_CHECKS_BEGIN), 1)
        self.assertEqual(swift.count(SAVED_CHECKS_END), 1)
        begin = swift.index(SAVED_CHECKS_BEGIN)
        end = swift.index(SAVED_CHECKS_END) + len(SAVED_CHECKS_END)
        self.assertLess(begin, end)
        self.assertEqual(swift[end:end + len("    // One ordinary current diagnostics run,")],
                         "    // One ordinary current diagnostics run,")
        block = swift[begin:end]
        self.assertEqual(digest(block.encode()), SAVED_CHECKS_INSERTION_SHA256)
        self.assertEqual(re.findall(r'@MainActor func (test\w+)\(\) throws', block),
                         ['testSyntheticProjectSavedOfflineChecks', 'testSyntheticProjectEmptyBuildInputInspection'])
        for fragment, count in (
            ('executionTimeAllowance = 300', 2),
            ('try beginCase(seconds: 300)', 2),
            ('launchForJourney()', 2), ('let fixture = LocalFixture()', 2), ('try fixture.prepare()', 2),
            ('start.click()', 1), ('acknowledgement.click()', 1), ('inspect.click()', 1),
            ('let sheet = try quitSheet(app, window)', 2), ('try completeNormalQuit(app)', 2), ('try acceptFinalScenario()', 2),
            ('try fixture.closeOriginals()', 2), ('ownedFixture = nil', 2),
        ):
            self.assertEqual(block.count(fragment), count, fragment)
        for fragment in (
            '!run.isEnabled', '(acknowledgement.value as? String) == "0"',
            '(acknowledgement.value as? String) == "1"',
            'labels[start + 1] == "complete"', 'labels[start] == "Outcome: complete"',
            '"Original operation settled"', '"This invocation only"', '"Historical / stale context"',
            'panel.staticTexts.matching(identifier: unconfirmed).count == 0',
            'counts["MISSING", default: 0] >= 2 && counts["SKIP", default: 0] >= 1',
            '"Complete is not PASS or release readiness."',
            '"No pending build-input record observed"', '!review.isEnabled && panel.checkBoxes.count == 0',
            'panel.buttons.matching(identifier: "Recover reviewed build inputs").count == 0',
            'panel.buttons.matching(identifier: "Retire reviewed metadata").count == 0',
            'for label in [unconfirmed, historical, "Recorded session:",',
            'mutationRecovery=not-run;projectCleanliness=not-established',
        ):
            self.assertIn(fragment, block, fragment)
        self.assertGreaterEqual(block.count('try fixture.assertUnchanged()'), 11)
        for forbidden in ('app.launch()', 'app.terminate()', 'fixture.accept(', 'persistentCredentials',
                          'admitDefaultVault(', 'evaluateJavaScript', 'invoke(', 'Process()',
                          'FileManager', 'write(to:', 'Check original status', 'screenshot()', 'debugDescription'):
            self.assertNotIn(forbidden, block, forbidden)
        return block

    def test_normal_saved_offline_and_empty_recovery_use_original_gui_only(self):
        swift = self.restored_semantic_heading_queries(self.restored_engineering_main(without_positive_android_source((ROOT / SWIFT).read_text())))
        block = self.checked_saved_checks_block(swift)
        offline = block.split('@MainActor func testSyntheticProjectSavedOfflineChecks() throws {', 1)[1]
        offline, recovery = offline.split('@MainActor func testSyntheticProjectEmptyBuildInputInspection() throws {', 1)
        # Ten seconds is a helper maximum, not a renewed native wait.
        for name, route in (
            ("press", ("try waitElement(", "timeout: timeout")),
            ("waitElement", ("XCTWaiter.wait(for: [expected], timeout: try remaining(timeout))",)),
            ("remaining", ("return try clock.remaining(requested, before: deadline)",)),
        ):
            helper = swift.split("private func " + name + "(", 1)[1].split("\n    @MainActor ", 1)[0]
            for fragment in route:
                self.assertTrue(fragment in helper, "missing original-clock clamp in " + name)
        for journey, prefix in ((offline, 'offline'), (recovery, 'recovery-idle')):
            for stage in ('launch', 'fixture', 'project-open', 'original-report', 'readback-and-quit'):
                self.assertEqual(journey.count('stage("' + prefix + '-' + stage + '")'), 1)
            for fragment in ('try goToFolder(sheet, path: fixture.projectPath)', 'try nativeOpen(sheet)',
                             'matching(identifier: fixture.projectPath)', 'matching(identifier: "org.fixture.app")',
                             'try savedOperationComplete(panel)', 'timeout: 10, failures: failures',
                             'cleanExitStatus=unavailable;allWorkerFinality=unavailable'):
                self.assertTrue(fragment in journey, prefix + ": missing " + fragment)
        for fragment in (
            'named(renderer, "Review the saved inputs and project-code effects")\n'
            '                .containing(.button, identifier: "Refresh saved configuration observation")',
            'try press(panel, "Refresh saved configuration observation"',
            'try press(panel, "Review offline checks"', 'named(panel, "Confirm this saved offline-check intent")',
            'let savedBytes = try fixture.text(LocalFixture.config).utf8.count',
            'Saved comparison: \\(savedBytes) bytes.',
            'matching(identifier: "Awaiting explicit consent")',
            'let run = try unique(consent.buttons.matching(identifier: "Run saved offline checks")',
            'let acknowledgement = try unique(consent.checkBoxes',
            'let start = try waitElement(consent.buttons.matching(identifier: "Run saved offline checks")',
            'enabled: true, timeout: try remaining(5), failures: failures', 'timeout: 90, failures: failures',
            'let report = try unique(named(panel, "Saved offline check findings")',
            'let counts = try savedOfflineCounts(report)',
            'panel.staticTexts.matching(identifier: historical).count == 0',
            'report.staticTexts.matching(identifier: "Historical / stale context").count == 0',
            'named(panel, "Confirm this saved offline-check intent").count == 0',
            'panel.buttons.matching(identifier: "Run saved offline checks").count == 0',
            'ordinary-ui-observed-saved-offline-report-and-settled-projection',
            'releaseReadiness=not-assessed', 'this is not zero-command evidence',
        ):
            self.assertTrue(fragment in offline, "offline: missing " + fragment)
        self.assertLess(offline.index('!run.isEnabled'), offline.index('acknowledgement.click()'))
        self.assertLess(offline.index('(acknowledgement.value as? String) == "0"'), offline.index('acknowledgement.click()'))
        self.assertLess(offline.index('(acknowledgement.value as? String) == "1"'), offline.index('start.click()'))
        self.assertLess(offline.index('start.click()'), offline.index('stage("offline-original-report")'))
        self.assertEqual(offline.count('try press(panel, "Review offline checks"'), 1)
        self.assertEqual(offline.count('let failures = ["No new offline-check outcome was confirmed", "Original cleanup unknown"]'), 1)
        self.assertNotIn('unconfirmed', offline.split('let failures = ', 1)[1].split('\n', 1)[0])
        for fragment in (
            'named(renderer, "Inspect first, then review what can safely be recovered")\n'
            '                .containing(.button, identifier: "Help: Project build-input recovery")',
            'let inspect = try waitElement(panel.buttons.matching(identifier: "Inspect build-input state")',
            'timeout: 135, failures: failures',
            'This is a build-input observation only. It does not mean the whole project, a previous file edit, signing account or Store release is clean.',
            '"Reviewed build-input session recovered."', '"Reviewed terminal metadata retired."',
            '"Pending build-input session", "Only terminal recovery metadata remains"] + failures',
            'panel.staticTexts.matching(identifier: label).count == 0',
            'ordinary-ui-observed-empty-build-input-inspection-and-settled-projection',
        ):
            self.assertTrue(fragment in recovery, "recovery: missing " + fragment)
        self.assertNotIn('start.click()', recovery)
        self.assertNotIn('acknowledgement.click()', recovery)
        self.assertLess(recovery.index('!review.isEnabled'), recovery.index('inspect.click()'))
        self.assertLess(recovery.index('inspect.click()'), recovery.index('stage("recovery-idle-original-report")'))
        self.assertEqual(recovery.count('let failures = ["No new recovery outcome was confirmed", "Original cleanup unknown"]'), 1)
        self.assertNotIn('unconfirmed', recovery.split('let failures = ', 1)[1].split('\n', 1)[0])
        for fragment in ('statuses = ["PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE"]',
                         'starts.count == 1', 'start + statuses.count * 2 <= labels.count',
                         '(0...128).contains(count), value == String(count)', 'let total = counts.values.reduce(0, +)',
                         '0 omitted from that list. Counts below include every reported finding.',
                         '"Android module configuration.", "Android Gradle wrapper policy.", "Core early-exit or remaining-check policy."'):
            self.assertTrue(fragment in block, "saved-checks: missing " + fragment)

        # The original fixture is unchanged; no copied recovery journal, service
        # credentials, wrapper or configured arbitrary command is added for a pass.
        raw = (ROOT / FIXTURE).read_bytes()
        self.assertEqual(digest(raw), 'ea9b004f0026c053bc1a12607cc70bd0a6f7e07afe9f33cf2a17506de62d512c')
        fixture = json.loads(raw)
        files = {name: base64.b64decode(value, validate=True) for name, value in fixture['files'].items()}
        expected = {'project/release/mobile-release.json', 'project/release/version.properties', 'project/.gitignore',
                    'project/README-user.txt', 'project/.github/workflows/keep-user.yml', 'sources/01.png', 'sources/02.png'}
        expected.update('project/release/store/android/' + locale + '/' + name + '.txt'
                        for locale in ('en-US', 'fr-FR') for name in ('title', 'short_description', 'full_description'))
        self.assertEqual(set(files), expected)
        config = json.loads(files['project/release/mobile-release.json'])
        self.assertEqual(config['android'], {'applicationId': 'org.fixture.app', 'enabled': True, 'identityStatus': 'unverified'})
        self.assertEqual(config['ios'], {'enabled': False})
        self.assertEqual(config['services'], {'androidFirebase': 'disabled', 'iosFirebase': 'disabled'})
        self.assertEqual(config['projectChecks'], {'preflight': [], 'androidArtifact': [], 'iosArtifact': []})
        fixture_helper = swift.split('private final class LocalFixture {', 1)[1].split('@MainActor private var ownedFixture:', 1)[0]
        unchanged = fixture_helper.split('func assertUnchanged() throws {', 1)[1].split('func accept(', 1)[0]
        self.assertIn('old.bytes == observed.bytes && old.facts == observed.facts', unchanged)
        self.assertIn('try checkRoster()', unchanged)

        sources = {name: (ROOT / name).read_text() for name in SAVED_CHECKS_SOURCE_REFS}
        offline_ui = sources['desktop/src/components/OfflinePreflight.tsx']
        recovery_ui = sources['desktop/src/components/ProjectRecovery.tsx']
        for fragment in ('<section className="card offline-preflight" aria-labelledby={label}>',
                         '<h3 id={label}>Review the saved inputs and project-code effects</h3>',
                         '>Refresh saved configuration observation</button>',
                         'aria-label="Confirm this saved offline-check intent"', 'disabled={runReason !== null}',
                         "terminal: 'Original operation settled'", 'aria-label="Saved offline check findings"',
                         "historical ? 'Historical / stale context' : 'This invocation only'", 'Complete is not PASS or release readiness.'):
            self.assertIn(fragment, offline_ui)
        for fragment in ('<h3 id={label}>Inspect first, then review what can safely be recovered</h3>',
                         "label: 'Project build-input recovery'", "controller.prepare('inspect')", "controller.prepare('recover')",
                         'disabled={recoverReason !== null}', "idle: 'No pending build-input record observed'",
                         "terminal: 'Original operation settled'", 'value.status === \'idle\''):
            self.assertIn(fragment, recovery_ui)
        self.assertIn('aria-label={`Help: ${content.label}`}', sources['desktop/src/components/Common.tsx'])
        offline_controller = sources['desktop/src/offlinePreflight.ts']
        for fragment in ('savedConfig: parseSavedConfigContent(project.savedConfigContent)',
                         'attempt.identity = id(op); attempt.prepareReply = true;',
                         'attempt.startSent = true; attempt.startAfter = attempt.observer.status?.statusRevision ?? 0;',
                         'consent: null, pending: \'start\', originalUnconfirmed: true, historical: false',
                         'historical: !attempt || !matched || attempt.retired || !this.matches(attempt)',
                         'originalUnconfirmed: finished || startObserved ? false : this.state.originalUnconfirmed',
                         "sameOfflineIdentity(status.operation, attempt.identity) || status.operation.phase === 'awaiting-consent'"):
            self.assertIn(fragment, offline_controller)
        recovery_controller = sources['desktop/src/projectRecoveryController.ts']
        for fragment in ("acknowledged: action === 'inspect'", "if (action === 'inspect') await this.start(op.operationId, op.ownerGeneration);",
                         "op.phase !== 'terminal' || op.outcome !== 'complete'", 'this.state.historical',
                         "return recoveryEligible(inspected) ? null : 'The inspection has no eligible pending build-input session to recover.'"):
            self.assertIn(fragment, recovery_controller)
        self.assertIn("op.outcome === 'complete' ? !result(op.result) || !sameSavedConfig(op.result.usedConfig, op.context.savedConfig) : op.result !== null",
                      sources['desktop/src/offlinePreflightProtocol.ts'])
        self.assertIn("if (!result(op.result, op.context) || op.effect !== (op.context.action === 'inspect' ? 'inspection' : 'recovery-attempted')) return null;",
                      sources['desktop/src/projectRecoveryProtocol.ts'])
        service = sources['src/mobile_release/desktop_preflight.py']
        for fragment in ('mode="offline", platforms=("android",)', 'run_builds=False,', 'artifacts=None, credentials_file=None',
                         'credentials_from_env=False, require_tools=False', 'signing_lease=None, invocation=invocation'):
            self.assertIn(fragment, service)
        self.assertNotIn('invocation.materialization(', service)
        discovery = sources['src/mobile_release/discovery.py']
        for fragment in ('"GIT_CONFIG_NOSYSTEM": "1"', '"GIT_CONFIG_GLOBAL": os.devnull', '"GIT_OPTIONAL_LOCKS": "0"',
                         '"GIT_NO_LAZY_FETCH": "1"', '"GIT_ALLOW_PROTOCOL": ""', '"core.fsmonitor=false"',
                         '"core.hooksPath=" + os.devnull', '"protocol.allow=never"', 'timeout=10'):
            self.assertIn(fragment, discovery)
        recovery_service = sources['src/mobile_release/desktop_project_recovery.py']
        self.assertIn('_desktop_inspect_build_inputs(', recovery_service)
        inputs = sources['src/mobile_release/build_inputs.py']
        inspection = inputs.split('def _desktop_inspect_build_inputs(', 1)[1].split('def _desktop_recover_build_inputs(', 1)[0]
        self.assertIn('if project.meta.number is None or _stat(project.meta.number, _PENDING) is None:', inspection)
        self.assertIn('return _DesktopRecoveryInspection("idle")', inspection)
        self.assertNotIn('ensure_meta(', inspection)
        finish = inputs.split('    def _finish(self) -> None:', 1)[1].split('    def cleanup(self) -> None:', 1)[0]
        self.assertLess(finish.index('_consumer_idle(self.cancellation)'), finish.index('self.quiescence = "original"'))
        self.assertLess(finish.index('self.quiescence = "original"'), finish.index('self._checkpoint()'))
        self.assertNotIn('operator', block.split('@MainActor func testSyntheticProjectEmptyBuildInputInspection()', 1)[1])

        # Additional exact singleton, not a claim that idle build-input recovery
        # above covered an interrupted saved-file transaction.
        actual_swift = without_positive_android_source((ROOT / SWIFT).read_text())
        journey = actual_swift.split('    @MainActor func testSyntheticProjectSavedVersionRecovery() throws {', 1)[1].split(
            '    @MainActor func testSyntheticProjectManagedWorkflowRefusal()', 1)[0]
        for token in ('try beginCase(seconds: 300)', 'fixture.prepare(.savedVersionRecovery)', 'try launchForJourney()',
                      'try goToFolder(sheet, path: fixture.projectPath)', 'try nativeOpen(sheet)', 'let panel = try waitElement(named(editor, "Saved-version recovery inspection")',
                      'try press(panel, "Close inspection, keep drafts"', 'Native: settled; reason: discarded.',
                      'title == %@", "Roll back the interrupted save"', 'paths: ["release/version.properties"]',
                      'SHA256 " + digest', 'bytes · mode 0600', '5 inspected owned files and 0 directories.',
                      'fixture.savedVersionTransaction', 'Type RECOVER to confirm this one original plan',
                      'Original effect: rolled_back; journal: clean; core resources: settled; core reason: none. Native: settled; reason: none.',
                      'try fixture.acceptSavedVersionRollback()', 'try press(saved, "Read saved version"',
                      'matching(identifier: "1.2.3")', 'matching(identifier: "Build number 7")',
                      'try completeNormalQuit(app)', 'try fixture.closeOriginals()', 'try acceptFinalScenario()',
                      'interruptedGuiSave=not-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable'):
            self.assertIn(token, journey)
        self.assertEqual(journey.count('try inspect()'), 2)
        self.assertEqual(journey.count('try press(dialog, "Confirm recovery action"'), 1)
        ordering = ('stage("saved-version-inspect-close")', 'try press(panel, "Close inspection, keep drafts"',
                    'stage("saved-version-reinspect-confirm")', 'try replace(field(dialog, "Type RECOVER',
                    'try press(dialog, "Confirm recovery action"', 'try fixture.acceptSavedVersionRollback()',
                    'try press(saved, "Read saved version"', 'try completeNormalQuit(app)', 'try fixture.closeOriginals()', 'try acceptFinalScenario()')
        self.assertEqual([journey.index(token) for token in ordering], sorted(journey.index(token) for token in ordering))
        for token in ('try?', 'app.terminate()', 'forceTerminate', 'launchEnvironment', 'Inspect build-input state', 'Save version'):
            self.assertNotIn(token, journey)
        adoption = actual_swift.split('        private func adoptSavedVersion(', 1)[1].split('        private func checkRoster()', 1)[0]
        for token in ('MRK_NORMAL_UI_SAVED_VERSION_FIXTURE', 'source == env["MRK_NORMAL_UI_HARNESS_SOURCE"]',
                      'source == env["MRK_NORMAL_UI_APPLICATION_SOURCE"]', 'canonicalObject["schemaVersion"] = 1',
                      'limit: 16 * 1024', 'paths.count == 18', 'Set(fileFacts.keys) == paths',
                      'expectedFacts == Self.wireFacts(observed.facts)', 'handoff bundled DATA differs',
                      'Array(oldFacts.prefix(8)) == Array(backupFacts.prefix(8))', 'oldFacts[9] == backupFacts[9]',
                      'original.bytes == observed.bytes && original.facts == observed.facts',
                      'Self.sameSavedVersionMove(backup.facts, restored.facts)', 'directories.removeValue(forKey: Self.savedVersionJournal)'):
            self.assertIn(token, adoption)
        for token in ('mkdtemp', 'unlink(', 'rename(', 'FileManager', 'try?'):
            self.assertNotIn(token, adoption)
        self.assertIn('limit: Int = 32 * 1024', actual_swift) # All existing readers retain their original cap.
        self.assertIn('if savedVersionPending && name == ".mobile-release-version" { continue }', actual_swift)
        runner = (ROOT / 'desktop/tools/macos_normal_ui_runner.py').read_text()
        fixed = runner.split('class SavedVersionFixture:', 1)[1].split('class NativeQueryFailure', 1)[0]
        for token in ('"tests/desktop/test_saved_text_recovery.py"', '"-I", "-S", "-B"', '"release_version", "interrupt"], 20, 65536)',
                      'original.returncode == 86 and original.stderr == b""', 'frames_digest = saved_version_producer_frames(original.stdout)',
                      'sha(encoded([core[name] for name in sorted(core)])) == SAVED_VERSION_SOURCE',
                      '"saved-version-no-shadow-imports"', '"saved-version-source-post"', '"saved-version-runtime-post"',
                      'saved_version_same_move(self.originals[SAVED_VERSION_PATH][2], backup[2])',
                      'self._recheck_leaf(path, self.originals[path])', 'self.check_roster(paths, moved=True)',
                      'exclusive_output(self.handoff, encoded(handoff) + b"\\n", 16384)',
                      'self.phase.environment = dict(old, **{SAVED_VERSION_ENV: str(self.handoff)})',
                      'self.phase.environment = old', 'self.check_seed()', 'normal_saved_version_markers(self.original.stdout)',
                      'self.dirs.pop(SAVED_VERSION_JOURNAL)', 'fd = self.fds.pop()', 'os.close(fd)'):
            self.assertIn(token, runner)
        self.assertEqual(fixed.count('self.phase.call("saved-version-core-interrupt"'), 1)
        self.assertEqual(fixed.count('self._recheck_leaf(path, self.originals[path])'), 2)
        recheck = fixed.split('    def _recheck_leaf(', 1)[1].split('    def check_roster(', 1)[0]
        for token in ('saved_version_facts(os.fstat(fd)) == facts',
                      'os.stat(name, dir_fd=parent_fd, follow_symlinks=False)',
                      'observed == body and found == digest',
                      '"saved-version-reused-original-pre"', '"saved-version-reused-original-post"',
                      'return entry'):
            self.assertIn(token, recheck)
        self.assertNotIn('os.open(', recheck)
        for token in ('subprocess.Popen', 'os.system', 'rmtree', 'unlink(', 'os.rename('): self.assertNotIn(token, fixed)
        self.assertLess(fixed.index('original.returncode == 86'), fixed.index('exclusive_output(self.handoff'))
        self.assertLess(fixed.index('frames_digest = saved_version_producer_frames'), fixed.index('exclusive_output(self.handoff'))
        derived_ignore = base64.b64decode(fixture['stages']['config']['project/.gitignore'], validate=True)
        self.assertNotEqual(files['project/.gitignore'], derived_ignore)
        self.assertIn(".mobile-release-version/", derived_ignore.decode())
        self.assertIn('files["project/.gitignore"] = decode(spec["stages"]["config"]["project/.gitignore"])', runner)

    def checked_diagnostics_source(self) -> tuple[str, str]:
        swift = self.restored_semantic_heading_queries(self.restored_engineering_main(without_positive_android_source((ROOT / SWIFT).read_text())))
        # Require only the two accepted paired-host compile substitutions;
        # historical semantic/owner bytes remain under their original hash.
        for old, current in (('#if !os(macOS) || !arch(arm64)\n#error("This external UI scenario requires a fresh hosted ARM64 macOS 26 job.")\n', '#if !os(macOS) || !(arch(arm64) || arch(x86_64))\n#error("This external UI scenario requires a fresh hosted native64 macOS 26 job.")\n'), ('        try require(context["MRK_NORMAL_UI_HOSTED_JOB"] == "github-hosted-macos26-arm64",\n', '        #if arch(arm64)\n        let hostedJob = "github-hosted-macos26-arm64"\n        #elseif arch(x86_64)\n        let hostedJob = "github-hosted-macos26-x86_64"\n        #endif\n        try require(context["MRK_NORMAL_UI_HOSTED_JOB"] == hostedJob,\n')):
            self.assertEqual(swift.count(current), 1)
            self.assertNotIn(old, swift)
            swift = swift.replace(current, old, 1)
        swift = self.restored_renderer_queries(swift)
        swift = self.restored_dashboard_query(swift)
        added = self.checked_saved_checks_block(swift)
        swift = swift.replace(added, "", 1)
        start = "    // One ordinary current diagnostics run, not full doctor or project-code execution.\n"
        end = "    override func tearDown() async throws {\n"
        self.assertEqual(swift.count(start), 1)
        self.assertEqual(swift.count(end), 1)
        insertion = start + swift.split(start, 1)[1].split(end, 1)[0]
        self.assertEqual(digest(insertion.encode()), DIAGNOSTICS_INSERTION_SHA256)
        # Bind the reviewed current owner/deadline/menu/dashboard source and the
        # separate bounded projectFields fixture; no broad source normalization.
        self.assertEqual(digest(swift.replace(insertion, "", 1).encode()), ORIGINAL_SWIFT_SHA256)
        return swift, insertion

    def test_renderer_readiness_preserves_one_query_and_current_baseline(self):
        self.checked_diagnostics_source()
        source = self.restored_engineering_main(without_positive_android_source((ROOT / SWIFT).read_text()))
        original, semantic, count = SEMANTIC_HEADING_LINES[0]
        self.assertEqual(count, 1)
        restart_original, restart_semantic, restart_count = SEMANTIC_HEADING_LINES[-1]
        self.assertEqual(restart_count, 1)
        self.assertIn("restartedRenderer.staticTexts", restart_semantic)
        for label, changed in (
            ("broad identifier reversion", source.replace(semantic, original, 1)),
            ("duplicate dashboard heading", source.replace(semantic, semantic + semantic, 1)),
            ("looser title predicate", source.replace(
                semantic, semantic.replace("title == %@", "title CONTAINS %@", 1), 1)),
            ("broad restart heading reversion", source.replace(restart_semantic, restart_original, 1)),
        ):
            with self.subTest(semantic_heading_refusal=label):
                with self.assertRaises(AssertionError):
                    self.restored_semantic_heading_queries(changed)

        # New diagnostic is removed exactly before ALL unchanged historical pins.
        first_source = (ROOT / SWIFT).read_text()
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
        actual_artifact_source = first_original
        raw_status = actual_artifact_source
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
        self.assertEqual(actual_artifact_source.count(ARTIFACT_WAIT_DIAGNOSTIC_BEGIN), 1)
        self.assertEqual(actual_artifact_source.count(ARTIFACT_WAIT_DIAGNOSTIC_END), 1)
        sample_start = actual_artifact_source.index(ARTIFACT_WAIT_DIAGNOSTIC_BEGIN)
        sample_end = actual_artifact_source.index(ARTIFACT_WAIT_DIAGNOSTIC_END) + len(ARTIFACT_WAIT_DIAGNOSTIC_END)
        artifact_sample = actual_artifact_source[sample_start:sample_end]
        self.assertEqual(digest(artifact_sample.encode()), ARTIFACT_WAIT_DIAGNOSTIC_SHA256)
        self.assertEqual(digest(without_artifact_wait_diagnostic_source(without_artifact_status_group_source(actual_artifact_source)).encode()),
                         'f2f33688e491bd0ae4ce1a0d357b214da03102601f1b7c051fd645f372daf135')
        # Literal roster equals actual UI text; no raw AX labels or guessed states.
        protocol = (ROOT / 'desktop/src/artifactInspectionProtocol.ts').read_text()
        component = (ROOT / 'desktop/src/components/ArtifactInspection.tsx').read_text()
        table = protocol.split('export const artifactAvailabilityText={', 1)[1].split('};', 1)[0]
        availability_texts = {
            (quoted or plain): text for quoted, plain, text in
            re.findall(r"(?:'([^']+)'|([a-z]+)):'([^']*)'", table)}
        states = ('available', 'runtime-unqualified', 'busy', 'shutdown', 'cleanup-unknown',
                  'document-lost', 'unsupported-platform')
        self.assertEqual(set(availability_texts), set(states))
        texts = tuple(availability_texts[key] for key in states) + (
            'Waiting for original native status.', 'No new artifact outcome confirmed')
        actual_texts = tuple(re.findall(r'^            "([^"\n]+)"[,]?$', artifact_sample, re.MULTILINE))
        self.assertEqual(actual_texts, texts)
        for text in texts[-2:]: self.assertIn(text, component)
        self.assertIn('artifactAvailabilityText[state.status.availability]', component)
        expected_status_group = '    <div role="group" aria-label="Original artifact inspection status">\n      <p>{state.status?artifactAvailabilityText[state.status.availability]:\'Waiting for original native status.\'}</p>\n    </div>\n'
        self.assertEqual(component.count(expected_status_group), 1)
        self.assertEqual(component.count('aria-label="Original artifact inspection status"'), 1)
        self.assertEqual(component.count('artifactAvailabilityText[state.status.availability]'), 1)
        # Restoring only this element pair leaves the entire previous component.
        self.assertEqual(hashlib.sha256(component.replace(expected_status_group, "    <p>{state.status?artifactAvailabilityText[state.status.availability]:'Waiting for original native status.'}</p>\n", 1).encode()).hexdigest(),
                         'a7cd40312c41f6bb68ed42bdfb382e323bd2389c8e34e6038f72789a780d16fd')
        self.assertNotIn('prepareReason', expected_status_group)
        self.assertNotIn('pickerPending', expected_status_group)
        self.assertNotIn('reason&&', expected_status_group)
        self.assertIn('for property in ["label", "title", "value"]', artifact_sample)
        self.assertIn('for text in artifactDiagnosticTexts', artifact_sample)
        self.assertEqual(artifact_sample.count('try remaining(1)'), 1)
        self.assertLess(artifact_sample.index('try remaining(1)'), artifact_sample.index('let count = renderer.staticTexts'))
        self.assertIn('NSPredicate(format: "%K == %@", property, text)', artifact_sample)
        self.assertIn('counts.append(String(min(count, 5)))', artifact_sample)
        self.assertNotIn('.label', artifact_sample)
        self.assertNotIn('.title', artifact_sample)
        self.assertNotIn('.value', artifact_sample)
        self.assertNotIn('debugDescription', artifact_sample)
        self.assertNotIn('print(text', artifact_sample)
        self.assertTrue(actual_artifact_source[sample_end:].startswith(
            '        _ = try waitElement(artifactAvailability, in: renderer,\n'))
        for mutated in (artifact_sample.replace('"label", "title", "value"', '"identifier", "title", "value"', 1),
                        artifact_sample.replace('try remaining(1)', 'try remaining(5)', 1),
                        artifact_sample.replace('%K == %@', '%K CONTAINS %@', 1),
                        artifact_sample.replace('renderer.staticTexts', 'renderer.descendants(matching: .any)', 1),
                        artifact_sample.replace('sample=pre-wait', 'sample=after-wait', 1),
                        artifact_sample.replace('nonAtomic=1', 'nonAtomic=0', 1)):
            self.assertNotEqual(mutated, artifact_sample)
            with self.assertRaises(AssertionError):
                without_artifact_wait_diagnostic_source(actual_artifact_source.replace(artifact_sample, mutated, 1))
        with self.assertRaises(AssertionError):
            without_artifact_wait_diagnostic_source(actual_artifact_source.replace(artifact_sample, artifact_sample * 2, 1))

        # The new smoke is a separate private profile. Restore only its exact
        # reviewed regions, then retain EVERY historical ordinary-source pin
        # and negative query mutation above. These are SOURCE checks, not UI.
        engineering_source = without_positive_android_source((ROOT / SWIFT).read_text())
        begin = engineering_source.index(ENGINEERING_MAIN_BEGIN)
        end = engineering_source.index(ENGINEERING_MAIN_END) + len(ENGINEERING_MAIN_END)
        engineering = engineering_source[begin:end]
        self.assertEqual(digest(engineering.encode()), ENGINEERING_MAIN_SHA256)
        self.assertIn('private enum SourceProfile { case sameBuild, packagedEntry }', source)
        self.assertNotIn('testEngineeringMainCatalogueAndQuit', source)
        ordered = ('try beginCase(seconds: 60)', 'let work = try engineeringWork()',
                   'let app = try launchEngineeringMain(work: work)',
                   'named(renderer, "Credential and signing asset guides")',
                   'guide.descendants(matching: .checkBox).matching(NSPredicate(format: "title BEGINSWITH %@", "Android upload keystore"))',
                   'guide.descendants(matching: .checkBox).matching(NSPredicate(format: "title BEGINSWITH %@", "Apple Distribution identity"))', 'apple.click()',
                   '"Original Distribution P12"', '"Reference guide · not a result"',
                   'let first = try quitSheet(app, window)', '"Cancel"', 'try engineeringDashboard(renderer)',
                   'let second = try quitSheet(app, window)', '"Quit"',
                   'try owner.observeNormalTermination(until: end)', 'try owner.acceptTerminal()',
                   'normalQuitObserved = true', 'print("MRK_MACOS_ENGINEERING_MAIN_UI=')
        case = engineering.split('func testEngineeringMainCatalogueAndQuit() throws {', 1)[1]
        positions = [case.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(case.count('try beginCase('), 1)
        self.assertNotIn('GateObservation(', engineering)
        self.assertNotIn('fixture.prepare(', engineering)
        self.assertNotIn('app.launch(', engineering)
        self.assertIn('try require(!open.isEnabled && !choose.isEnabled,', engineering)
        self.assertIn('entryGateObservation == nil', engineering)
        for bad in (engineering_source.replace('catalogueGuide=1', 'catalogueGuide=0', 1),
                    engineering_source.replace(ENGINEERING_MAIN_BEGIN, ENGINEERING_MAIN_BEGIN * 2, 1),
                    engineering_source.replace('case .ordinary:\n                // No environment override:',
                                               'case .ordinary:\n                configuration.environment = [:]\n                // No environment override:', 1),
                    engineering_source.replace('configuration.allowsRunningApplicationSubstitution = false',
                                               'configuration.allowsRunningApplicationSubstitution = true', 1)):
            with self.assertRaises(AssertionError): self.restored_engineering_main(bad)
        for original, current in ENGINEERING_DIAGNOSTIC_REGIONS:
            for bad in (engineering_source.replace(current, original, 1),
                        engineering_source.replace(current, current + current, 1),
                        engineering_source.replace(current, current.replace('engineeringRequireDiagnostic',
                                                                          'changedEngineeringDiagnostic'), 1),
                        engineering_source.replace(current, original, 1) + current):
                with self.assertRaises(AssertionError): self.restored_engineering_main(bad)

        # Exact diagnostic-only insertion: six same-guide samples, each guarded
        # by the existing remaining()/original-owner check BEFORE its query.
        observations = '        // Six pre-check samples of this same guide, not a fallback or atomic snapshot.\n        for property in ["label", "title"] {\n            let kinds: [(String, XCUIElement.ElementType)] = [("any", .any), ("button", .button), ("checkBox", .checkBox)]\n            for (kind, type) in kinds {\n                _ = try remaining(1) // Same original owners/clock; a latched failure stops sampling.\n                let count = guide.descendants(matching: type).matching(\n                    NSPredicate(format: "%K BEGINSWITH %@", property, "Android upload keystore")).count\n                print("MRK_MACOS_ENGINEERING_GUIDE_QUERY=v1;property=\\(property);type=\\(kind);matches=\\(min(count, 5));exceedsFour=\\(count > 4 ? 1 : 0);nonAtomic=1")\n            }\n        }\n'
        self.assertEqual(case.count(observations), 1)
        self.assertLess(case.index('let guide = try waitElement('), case.index(observations))
        self.assertLess(case.index(observations), case.index('_ = try unique(guide.descendants(matching: .checkBox)'))
        # Restore only the two title selectors and remove the exact samples;
        # every earlier engineering/ordinary owner and Quit pin stays unchanged.
        restored_guide = engineering
        for previous, current in (('controls(guide, [.checkBox], label: "Android upload keystore", prefix: true)', 'guide.descendants(matching: .checkBox).matching(NSPredicate(format: "title BEGINSWITH %@", "Android upload keystore"))'), ('controls(guide, [.checkBox], label: "Apple Distribution identity", prefix: true)', 'guide.descendants(matching: .checkBox).matching(NSPredicate(format: "title BEGINSWITH %@", "Apple Distribution identity"))')):
            self.assertEqual(engineering.count(current), 1)
            self.assertNotIn(previous, engineering)
            restored_guide = restored_guide.replace(current, previous, 1)
            for changed in (current.replace('title BEGINSWITH', 'label BEGINSWITH', 1),
                            current.replace('matching: .checkBox', 'matching: .any', 1)):
                with self.assertRaises(AssertionError):
                    self.restored_engineering_main(engineering_source.replace(current, changed, 1))
        self.assertEqual(digest(restored_guide.encode()),
                         'c77731ba526d68ed2f0dea3b8a111ecbec1b9177f176458205f2a1cd65558753')
        self.assertEqual(digest(restored_guide.replace(observations, '', 1).encode()),
                         '40b7c619718364a9f901c6c2f36f82e807681ea9c64732a12c75b3b50c084d16')
        for changed in (observations.replace('"label", "title"', '"value", "title"', 1),
                        observations.replace('("checkBox", .checkBox)', '("checkBox", .button)', 1),
                        observations.replace('Android upload keystore', 'unreviewed prefix', 1),
                        observations.replace('                _ = try remaining(1)', '                // missing guard', 1),
                        observations.replace('nonAtomic=1', 'nonAtomic=0', 1)):
            self.assertNotEqual(changed, observations)
            with self.assertRaises(AssertionError):
                self.restored_engineering_main(engineering_source.replace(observations, changed, 1))
        for changed_source in (engineering_source.replace(observations, '', 1),
                               engineering_source.replace(observations, observations + observations, 1),
                               engineering_source.replace(observations, '', 1).replace('        apple.click()',
                                                                                     observations + '        apple.click()', 1)):
            with self.assertRaises(AssertionError): self.restored_engineering_main(changed_source)

        names = ('desktop/src/App.tsx', 'desktop/src/pages/Credentials.tsx', 'desktop/src/bridge.ts',
                 'desktop/src/releaseInputGuidance.ts', 'desktop/src-tauri/src/runtime.rs', 'desktop/engine_bootstrap.py',
                 'src/mobile_release/api/_catalog.py', 'src/mobile_release/api/_credential_guide.py',
                 'src/mobile_release/api/data/credential-guide-v1.json')
        reads = {name: (ROOT / name).read_text() for name in names}
        app = reads['desktop/src/App.tsx']
        for token in ('const result = await connection.catalog();', 'releaseInputs.setCatalog(result);', 'setCatalog(result);',
                      'releaseInputs.setCatalog(null);', '<Credentials catalog={catalog}', 'inputState={releaseInputState}'):
            self.assertIn(token, app)
        bridge = reads['desktop/src/bridge.ts']
        self.assertIn("const result = await call<Catalog>('catalog');", bridge)
        self.assertIn('credentialGuide: parseCatalogCredentialGuide(result)', bridge)
        guidance = reads['desktop/src/releaseInputGuidance.ts']
        self.assertIn('const admitted = parseReleaseInputHelp(raw);', guidance)
        self.assertIn("const rawGuide = data('credentialGuide'), rawCredentials = data('credentials');", guidance)
        self.assertIn('parseCredentialGuide(structuredClone(rawGuide)) : null', guidance)
        page = reads['desktop/src/pages/Credentials.tsx']
        for token in ('<AssetGuide guide={inputState.help.guide}', 'aria-label="Credential and signing asset guides"',
                      '{guide.kinds.map((entry)', 'aria-pressed={entry.id === kind.id}',
                      '{entry.label}', '<h4>{field.label}</h4>', 'Reference guide · not a result'):
            self.assertIn(token, page)
        self.assertNotIn('Original Distribution P12', page)
        self.assertNotIn('Android upload keystore', page)
        catalogue = reads['src/mobile_release/api/_catalog.py']
        self.assertIn('asset_guide = credential_guide()', catalogue)
        self.assertIn('"credentialGuide": asset_guide', catalogue)
        loader = reads['src/mobile_release/api/_credential_guide.py']
        self.assertIn('files("mobile_release.api").joinpath("data", "credential-guide-v1.json").open("rb")', loader)
        self.assertIn('return source.read(MAX_RESOURCE_BYTES + 1)', loader)
        self.assertIn('raw = _read_resource_bytes()', loader)
        guide_body = reads['src/mobile_release/api/data/credential-guide-v1.json'].encode()
        self.assertEqual(digest(guide_body), ENGINEERING_CORE_GUIDE_SHA256)
        guide = json.loads(guide_body)
        self.assertEqual([row['label'] for row in guide['kinds'] if row['id'] in ('android-keystore', 'apple-p12')],
                         ['Android upload keystore', 'Apple Distribution identity'])
        apple = next(row for row in guide['kinds'] if row['id'] == 'apple-p12')
        self.assertIn('Original Distribution P12', [row['label'] for row in apple['fields']])
        runtime = reads['desktop/src-tauri/src/runtime.rs']
        development = runtime.split('fn development(&self, end: Instant)', 1)[1].split('\n}\n', 1)[0]
        for token in ('selected("MRK_DESKTOP_DEV_PYTHON")?', 'selected("MRK_DESKTOP_DEV_CORE")?',
                      'Path::new(env!("CARGO_MANIFEST_DIR")).parent()', '.join("engine_bootstrap.py")',
                      'core.extension().is_some_and(|extension| extension == "zip")',
                      'Ok(VerifiedRuntime { python, core, cwd: bootstrap.parent()'):
            self.assertIn(token, development)
        bootstrap = reads['desktop/engine_bootstrap.py']
        self.assertIn('from mobile_release._desktop_engine import main as run_engine', bootstrap)
        self.assertIn('return run_engine()', bootstrap)
        self.assertIn('sys.path.insert(0, sys.argv[1])', bootstrap)
        self.assertIn('or not sys.flags.isolated', bootstrap)
        self.assertIn('or not sys.flags.no_site', bootstrap)
        self.assertIn('or not sys.dont_write_bytecode', bootstrap)

    def test_normal_diagnostics_observes_original_complete_report_and_settled_projection(self):
        swift, insertion = self.checked_diagnostics_source()
        self.assertEqual(insertion.count("@MainActor func " + METHOD + "() throws"), 1)
        for fragment in (
            'launchForJourney()', 'let fixture = LocalFixture()', 'ownedFixture = fixture', 'try fixture.prepare()',
            'try goToFolder(sheet, path: fixture.projectPath)', 'try nativeOpen(sheet)',
            'label: "Release platform", value: "Android"', 'label: "Activity", value: "Build / archive"',
            'named(renderer, "Observed build-tool checks")\n'
            '                .containing(.button, identifier: "Check build tools")',
            '"Tool observations from this run"',
            '"Phase: settled"', '"Outcome: complete"', '"Native finality: settled"',
            '"Android / build · draft "', '" · core host macos"',
            '" · acknowledged original Start. Receipt time is not a native deadline or a fresh probe."',
            '"macOS developer selection", "Git version", "Java runtime version", "Java compiler version"',
            '"Core resource observations — provisional, not native finality"',
            'rows[0] == "Core outcome" && rows[1] == "complete" && rows[2] == "Commands attempted"',
            '(1...4).contains(attempts), rows[3] == String(attempts)',
            '"complete": "true", "fatal": "false", "contained": "true"',
            '"commandDispatched": "true", "commands": String(attempts), "inputClosed": "true"',
            '"handlersRestored": "true", "toolDescriptorsClosed": "true", "stopObserved": "none"',
            'expected[rows[offset]] != nil && observed[rows[offset]] == nil', 'observed == expected',
            'commandsAttempted = try diagnosticsCoreReport(panel)',
            'context.element(boundBy: 0).label == originalContext',
            'for query in [fresh, phase, outcome, finality, provenance]',
            'let sheet = try quitSheet(app, window)', 'try completeNormalQuit(app)', 'try acceptFinalScenario()',
            'try fixture.closeOriginals()', 'ownedFixture = nil', SCOPE,
        ):
            self.assertIn(fragment, insertion, fragment)
        self.assertEqual(insertion.count('start.click()'), 1)
        self.assertEqual(insertion.count('matching(identifier: "Check build tools")'), 1)
        self.assertEqual(insertion.count('executionTimeAllowance = 300'), 1)
        self.assertEqual(insertion.count('try beginCase(seconds: 300)'), 1)
        self.assertEqual(insertion.count('journeyDeadline = min(wholeDeadline, try clock.end(within: 15))'), 1)
        self.assertIn('defer { journeyDeadline = wholeDeadline }', insertion)
        self.assertGreaterEqual(insertion.count('try fixture.assertUnchanged()'), 5)
        for forbidden in ('app.launch()', 'app.terminate()', 'fixture.accept(', 'evaluateJavaScript',
                          'invoke(', 'Process()', 'xcode-select', 'Run saved offline checks',
                          'Recover reviewed build inputs', 'Read native status', 'screenshot()', 'debugDescription'):
            self.assertNotIn(forbidden, insertion)
        fixture = json.loads((ROOT / FIXTURE).read_bytes())
        config = json.loads(base64.b64decode(fixture['files']['project/release/mobile-release.json'], validate=True))
        self.assertIs(config['android']['enabled'], True)
        self.assertEqual(config['android']['applicationId'], 'org.fixture.app')
        self.assertIs(config['ios']['enabled'], False)
        self.assertEqual(config['projectChecks']['preflight'], [])
        # The queried fields are actual shipped result/provenance presentation.
        component = (ROOT / 'desktop/src/components/EnvironmentDiagnostics.tsx').read_text()
        for fragment in ('const result = observation?.projection.result ?? null;', '!compact && observation && result',
                         'observation.stale ? \'Earlier / stale tool observations\' : \'Tool observations from this run\'',
                         'row.finality', 'observation.projection', "'acknowledged original Start'",
                         '<dt>Core outcome</dt><dd>{result.outcome}</dd>',
                         '<dt>Commands attempted</dt><dd>{result.commandsAttempted}</dd>', 'Object.entries(result.lifetime)'):
            self.assertIn(fragment, component)
        controller = (ROOT / 'desktop/src/environmentDiagnosticsController.ts').read_text()
        for fragment in ('sameDiagnosticsContext(row.context, attempt.binding)', 'sameRun(row, attempt.projection)',
                         'status.statusRevision > attempt.binding.nativeStatusRevision && row.runId !== attempt.binding.previousRunId',
                         'acknowledged: attempt.acknowledged || acknowledgedBinding === attempt.binding',
                         'stale: !currentAttempt || !binding || !this.matches(binding)',
                         "provenance: currentAttempt ? currentAttempt.acknowledged ? 'acknowledged-start'"):
            self.assertIn(fragment, controller)
        owner = (ROOT / 'desktop/src-tauri/src/environment_diagnostics_owner.rs').read_text()
        for fragment in ('a.projection.result = Some(terminal)', 'let Poll::Ready(result) = Pin::new(handle).poll(&mut context)',
                         'if positive && recorded', 'if !final_clock_clear(&self.inner, &r, &owner, now)',
                         'manager_joined && startup_settled && io_joined && io && protocol && installed_final(&book, &owner)',
                         'book.out_end.as_ref().is_some_and(|r| r.closed && r.eof)',
                         'book.err_end.as_ref().is_some_and(|r| r.closed && r.eof)'):
            self.assertIn(fragment, owner)
        self.assertEqual(owner.count('active.projection.phase = Phase::Settled; active.projection.finality = Finality::Settled;'), 1)

    def test_normal_diagnostics_workflow_has_one_bounded_original_result(self):
        raw = (ROOT / '.github/workflows/desktop-macos-installed.yml').read_text()
        ids, blocks = steps(raw)
        selected = blocks['normal_saved_version_recovery_ui_test']
        result = blocks['normal_saved_version_recovery_ui_result']
        self.assertIn("env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'release-evidence'", selected)
        self.assertIn('singleton_method=testSyntheticProjectSavedReleaseEvidence', selected)
        self.assertIn('"savedReleaseEvidenceMarkerObserved") is True', result)
        self.assertIn('"scope": "ordinary-ui-observed-original-saved-release-evidence-documents-only"', result)
        self.assertIn('"fullUIQualified": False', result)
        for flag in ('artifactBytesVerified', 'signingAuthenticated', 'githubAuthenticityEstablished', 'storeStateEstablished', 'releaseReadinessEstablished', 'recoverySafetyEstablished'):
            self.assertIn('"' + flag + '": False', result)
        evidence = blocks['evidence']
        self.assertIn("steps.public_evidence.outcome == 'success'", evidence)
        self.assertEqual(evidence.count('          path:'), 1)
        self.assertEqual(evidence.split('          path: ', 1)[1].split('          if-no-files-found:', 1)[0],
                         '${{ steps.work.outputs.root }}/public-verification-evidence.json\n')
        # Current privacy policy and historical evidence are separate contracts.
        historical_uploads = without_public_verification_workflow(raw)
        for name in ('test-file-limit.status', 'test.status', 'test.runner-admission.json', 'test.failure-diagnostics.json',
                     'summary.status', 'summary.command-admission.json', 'summary.failure-diagnostics.json', 'result.json'):
            self.assertEqual(raw.count('{0}/normal-ui/release-evidence-' + name), 0)
            self.assertEqual(historical_uploads.count('{0}/normal-ui/release-evidence-' + name), 1)
        self.assertIn('"release-evidence": "release-evidence"', raw.split("      - name: Remove only this completed preview build's disposable compiler outputs", 1)[1])
        # Remove only the accepted outer tool delta before historical evidence.
        tool_predecessor = without_tool_enrollment_workflow(raw)
        self.assertEqual(hashlib.sha256(tool_predecessor.encode()).hexdigest(),
                         "c68a194c08d209e19f6f7028a590a6d39619c6b2f276a24a2dc334ad49dfba00")
        self.assertEqual(without_tool_enrollment_workflow(tool_predecessor), tool_predecessor)
        self.assertEqual(without_tool_enrollment_workflow(
            without_current_runtime_source_pin(raw)), tool_predecessor)
        tool_marker = '      - name: Select only SOURCE-enrolled current signed GitHub tools'
        tool_argument = '"${history_provider_arguments[@]}"'
        self.assertEqual(raw.count(tool_marker), 1)
        self.assertEqual(raw.count(tool_argument), 1)
        for damaged in (raw.replace(tool_marker, "      - name: partial GitHub tool selection", 1),
                        raw.replace(tool_argument, tool_argument + "-changed", 1)):
            with self.assertRaises(AssertionError): without_release_evidence_workflow(damaged)
        for token in ('"savedReleaseEvidenceMarkerObserved") is True', '"releasePromotionObserved": False', 'release-evidence) singleton=release-evidence;'):
            with self.assertRaises(AssertionError): without_release_evidence_workflow(raw.replace(token, token + '-changed', 1))
            with self.assertRaises(AssertionError): without_release_evidence_workflow(tool_predecessor.replace(token, token + '-changed', 1))
        raw = without_release_evidence_workflow(raw)
        self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), '80998a0d9633a7a3bae47407ecb06f2d2b748ebb0e96fa068c7bfc42149a7626')
        ids, blocks = steps(raw)
        self.assertEqual(ids.count('normal_saved_version_recovery_ui_test'), 1)
        self.assertEqual(ids.count('normal_saved_version_recovery_ui_result'), 1)
        selected = blocks['normal_saved_version_recovery_ui_test']
        result = blocks['normal_saved_version_recovery_ui_result']
        self.assertIn('workflow-refusal) singleton=workflow-refusal; singleton_method=testSyntheticProjectManagedWorkflowRefusal ;;', selected)
        self.assertIn('-maximum-test-execution-time-allowance 300', selected)
        self.assertIn('timeout-minutes: 11', selected)
        self.assertIn('timeout-minutes: 3', result)
        self.assertIn('"managedWorkflowRefusalMarkerObserved") is True', result)
        self.assertIn('"savedVersionRecovery" not in runner', result)
        self.assertIn('"saved-version-core-interrupt", 20, 65536, 86', result)
        self.assertIn('singleton_test_roles(selected_scope)', result)
        self.assertIn('"remoteGitHubOperationObserved": False', result)
        self.assertIn('"fullUIQualified": False', result)
        prior = without_github_refusal_workflow(raw)
        self.assertEqual(hashlib.sha256(prior.encode()).hexdigest(), '611783adbc1d6961c905005037fcf15605401e7b819eeff3f544a779d2bf18b0')
        for token in ('singleton_test_roles(selected_scope)', '"savedVersionRecovery" not in runner', 'workflow-refusal) singleton=workflow-refusal;'):
            with self.subTest(token=token), self.assertRaises(AssertionError):
                without_github_refusal_workflow(raw.replace(token, token + '-changed', 1))
        workflow = without_ios_unsigned_workflow((ROOT / '.github/workflows/desktop-macos-installed.yml').read_text())
# One dormant installed-only lane; no preview baseline or legal consent
        # is fabricated. Exercise pure original-result/JSON validators, then
        # invert only these explicit additions for all existing owner assertions.
        actual_ids, actual_blocks = steps(workflow)
        positive_ids = ('normal_android_inputs', 'normal_android_ui_test', 'normal_android_ui_result')
        start = actual_ids.index('package_install')
        self.assertEqual(tuple(actual_ids[start + 1:start + 4]), positive_ids)
        positive = ("github.ref == 'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' "
                    "&& env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build'")
        preview = "github.ref == 'refs/heads/verify/desktop-macos-preview'"
        self.assertEqual(re.findall(r'^        if: (.+)$', actual_blocks['normal_ui_build'], re.M),
                         [preview + ' || (' + positive + ')'])
        self.assertEqual(workflow.count('      MRK_MACOS_ANDROID_UI_SCOPE: disabled\n'), 1)
        self.assertEqual(workflow.count('            disabled|android-signed-build) ;;\n            *) exit 1 ;;'), 1)
        self.assertIn('if [[ "$package_status" != 0 ]]; then exit "$package_status"; fi',
                      actual_blocks['package_install'])
        new_blocks = [actual_blocks[name] for name in positive_ids]
        predecessors = ('normal_ui_build', 'normal_android_inputs', 'normal_android_ui_test')
        for ident, block, predecessor, minutes in zip(positive_ids, new_blocks, predecessors, (22, 23, 3), strict=True):
            self.assertEqual(actual_ids.count(ident), 1)
            self.assertEqual(re.findall(r'^        if: (.+)$', block, re.M),
                             [positive + " && steps." + predecessor + ".outcome == 'success' && steps.package_install.outcome == 'success'"])
            self.assertEqual(re.findall(r'^        timeout-minutes: ([0-9]+)$', block, re.M), [str(minutes)])
            self.assertNotIn('continue-on-error', block)
            self.assertNotIn('always()', block)
            self.assertNotIn(preview, block)
            for fragment in ('set +x', 'set +a', 'set -o noclobber', 'umask 077', '/usr/bin/env -i',
                             '"GITHUB_RUN_ID=$GITHUB_RUN_ID"', '"GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT"'):
                self.assertIn(fragment, block)
            run_body = block.split('        run: |\n', 1)[1]
            decoded = ''.join(line[10:] if line.startswith('          ') else line for line in run_body.splitlines(keepends=True))
            self.assertLessEqual(len(decoded), 21000, ident)
        self.assertIn('Android adds build9 + preparation22 + test23 + summary3;272 <=350.', workflow)
        self.assertEqual(210 + 9 + sum((22, 23, 3)) + 5, 272)
        actual_caps = [int(n) for n in re.findall(r'^        timeout-minutes: ([0-9]+)$', workflow, re.M)]
        self.assertEqual((len(actual_caps), sum(actual_caps)), (45, 421))
        self.assertLessEqual(272, 350)
        prep, positive_test, positive_result = new_blocks
        helper_call = 'desktop/tools/macos_android_dependency_preparation.py prepare-ui-inputs'
        self.assertEqual(workflow.count(helper_call), 1)
        self.assertIn('"MRK_ANDROID_PREPARATION_WORK=$MRK_MACOS_WORK"', prep)
        self.assertNotIn('desktop/tools/macos_android_dependency_preparation.py prepare-b', ''.join(new_blocks))
        self.assertNotIn('desktop/tools/macos_android_dependency_preparation.py acquire', ''.join(new_blocks))
        for block, word, variable in ((prep, helper_call, 'inputs_status'),
             (positive_test, '--normal-android-signed-build-test', 'android_test_status'),
             (positive_result, '--normal-android-signed-build-summary', 'android_summary_status')):
            self.assertEqual(block.count(word), 1)
            self.assertEqual(block.count(variable + '=$?'), 1)
            self.assertLess(block.index(word), block.index(variable + '=$?'))
            self.assertIn('if [[ "$' + variable + '" != 0 ]]; then exit "$' + variable + '"; fi', block)
            self.assertIn('[[ "$' + variable + '_saved" == 0 ]] || exit 1', block)
        self.assertIn('[[ "$android_result_status_saved" == 0 ]] || exit 1', positive_result)
        self.assertIn('if [[ "$android_result_status" != 0 ]]; then exit "$android_result_status"; fi', positive_result)
        self.assertNotIn('steps.normal_ui_result', ''.join(new_blocks))
        for forbidden in ('-storepass ', '-keypass ', 'MRK_ANDROID_UI_KEY_PASSWORD=',
                          'security unlock-keychain', 'sudo ', 'rm -rf', 'shutil.rmtree', 'P.main('):
            self.assertNotIn(forbidden, ''.join(new_blocks))
        evidence_actual = actual_blocks['evidence']
        public_names = ('normal-ui/android-inputs.status', 'normal-ui/android-input-status.json',
                        'prepare-ui-inputs-failure.json', 'normal-ui/android-signed-build-test.status',
                        'normal-ui/android-signed-build-summary.status', 'normal-ui/android-signed-build-result.status',
                        'normal-ui/android-signed-build.facts.json', 'normal-ui/android-signed-build-result.json')
        for name in public_names:
            self.assertEqual(evidence_actual.count('{0}/' + name + '\n'), 1)
        for private in ('android-input-fixture.json', 'android-inputs/', 'android-inputs.stdout', 'android-inputs.stderr',
                        'android-signed-build-test.log', 'android-signed-build-test.xcresult',
                        'android-signed-build-test.runner-admission.json', 'android-signed-build-summary.command-admission.json',
                        'android-signed-build-summary.json', 'android-signed-build-summary.stderr', 'android-signed-build-result.log'):
            self.assertNotIn('/normal-ui/' + private, evidence_actual)
        marker = 'PY_ANDROID_INSTALLED_RESULT'
        head = '          "$MRK_PYTHON" -I -S -B - <<' + repr(marker) + ' > "$MRK_MACOS_WORK/normal-ui/android-signed-build-result.log" 2>&1\n'
        self.assertEqual(positive_result.count(head), 1)
        part = positive_result.split(head, 1)[1].split('          ' + marker + '\n', 1)[0]
        self.assertTrue(all(not line.strip() or line.startswith('          ') for line in part.splitlines()))
        code = ''.join(line[10:] if line.strip() else line for line in part.splitlines(keepends=True))
        parsed = ast.parse(code)
        functions = {node.name: node for node in parsed.body if isinstance(node, ast.FunctionDef)}
        local = {'json': json}
        exec(compile(ast.Module(body=[functions[name] for name in ('need', 'unique', 'document', 'package_originals')],
                                type_ignores=[]), '<installed-original-data>', 'exec'), local)
        self.assertEqual(local['document'](b'{"nested":{"finite":1.5},"closed":true}'),
                         {'nested': {'finite': 1.5}, 'closed': True})
        for bad in (b'[]', b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":1e9999}', b'{"outer":{"x":-1e9999}}'):
            with self.assertRaises(ValueError): local['document'](bad)
        roles = ('installer-log-cursor', 'installer', 'installer-log-capture')
        rows = [dict(role=role, entered=True, returned=True, capturesSettled=True,
                     returncode=0 if role == 'installer' else 1) for role in roles]
        local['package_originals'](rows, roles)
        for bad in (rows[:-1], list(reversed(rows)), rows + rows[:1],
                    [dict(rows[0], returned=False)] + rows[1:],
                    rows[:1] + [dict(rows[1], returncode=1)] + rows[2:],
                    rows[:1] + [dict(rows[1], returncode=None)] + rows[2:],
                    rows[:1] + [dict(rows[1], returncode=False)] + rows[2:],
                    rows[:1] + [dict(rows[1], capturesSettled=1)] + rows[2:]):
            with self.assertRaises(ValueError): local['package_originals'](bad, roles)
        credentials = [dict(role='search-before', entered=True, returned=True, settled=True, status=0)]
        local['package_originals'](credentials, ('search-before',), credentials=True)
        for change in ({'status': 1}, {'status': False}, {'returned': False}, {'settled': None}):
            with self.assertRaises(ValueError):
                local['package_originals']([dict(credentials[0], **change)], ('search-before',), credentials=True)
        for fragment in ("env[variable] for key, variable", "P.final_package_receipt(final_raw, env, TARGET",
                         "package_originals(owner.get('originalCalls'), S.PACKAGING_CALL_ROLES)",
                         "S.maintenance_result_data", "owner.get('finalPackageReceiptSha256') == sha(final_raw)",
                         "'installer-output.status'", "'normal-ui/android-inputs.status'",
                         "N.android_signed_facts(", "N.android_signed_receipts(build, test, summary, facts,",
                         "summary['commands'][1]['stdoutSha256'] == sha(summary_raw)",
                         "type(summary_data.get(key)) is int", "os.O_NOFOLLOW", "os.O_CLOEXEC",
                         "need(last <= now < deadline", "'ui-file-pre'",
                         "held.append(row)", "os.pread(", "follow_symlinks=False", "def original_post():",
                         "closing, held[:] = held[:], []", "try: os.close(row['fd'])",
                         "if primary is None: primary = error", "if primary is not None: raise primary"):
            self.assertIn(fragment, code)
        self.assertLess(code.index('N.android_signed_receipts('), code.index('N.exclusive_output('))
        self.assertIn("original_post()\n    N.exclusive_output(normal / 'android-signed-build-result.json', body, 16384)\n    original_post()", code)
        public = next(node.value for node in ast.walk(parsed) if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'value' for target in node.targets)
                      and isinstance(node.value, ast.Dict))
        public_fields = {key.value: value for key, value in zip(public.keys, public.values, strict=True)}
        self.assertEqual(set(public_fields), {'schemaVersion', 'scope', 'target', 'applicationSourceCommit',
            'harnessSourceCommit', 'sourceTree', 'workflow', 'runId', 'runAttempt', 'packageSha256', 'packageBytes',
            'runtimeManifestSha256', 'installerInventorySha256', 'originalCommandStatuses', 'testIdentifier', 'testCounts',
            'observation', 'resultOriginalReturncodeRequired', 'privateInputsPublished', 'vendorAcknowledgementAutomated',
            'newProtectedCopyRegistered', 'cleanExitStatus', 'allWorkerFinality', 'fullUIQualified', 'distributionQualified', 'productReady'})
        self.assertEqual(ast.literal_eval(public_fields['resultOriginalReturncodeRequired']), 0)
        self.assertEqual(ast.unparse(public_fields['observation']), 'facts')
        for flag in ('privateInputsPublished', 'vendorAcknowledgementAutomated', 'newProtectedCopyRegistered',
                     'fullUIQualified', 'distributionQualified', 'productReady'):
            self.assertIs(ast.literal_eval(public_fields[flag]), False)
        self.assertIs(ast.literal_eval(public_fields['cleanExitStatus']), None)
        self.assertEqual(ast.literal_eval(public_fields['allWorkerFinality']), 'not-established-by-XCTest-UI-state')
        # Precisely restore only this lane. Every old assertion below, including
        # block pins, complete step-condition budgets and preview cleanup, remains.
        for ident in positive_ids:
            self.assertEqual(workflow.count(actual_blocks[ident]), 1)
            workflow = workflow.replace(actual_blocks[ident], '', 1)
        installed_only_edits = (
            ('    # Closed SOURCE selection, not additive UI work: default preview345,\n    # recovery preview339 / installed210, cleanup included, plus5min overhead.\n',
             '    # Timed-step union421min; SOURCE scopes select disjoint UI work.\n    # Preview345 / recovery339 / installed210 / dormant ARM Android267, plus5 overhead.\n    # Android adds build9 + preparation22 + test23 + summary3;272 <=350.\n'),
            ('      MRK_MACOS_PACKAGE_ROLE: ordinary-image\n',
             '      MRK_MACOS_PACKAGE_ROLE: ordinary-image\n      # SOURCE-owned and OFF: legal/signing/current protected-copy prerequisites remain.\n      MRK_MACOS_ANDROID_UI_SCOPE: disabled\n'),
            ('          [[ "$RUNNER_ENVIRONMENT" == github-hosted && "$RUNNER_OS" == macOS ]] || exit 1\n',
             '          [[ "$RUNNER_ENVIRONMENT" == github-hosted && "$RUNNER_OS" == macOS ]] || exit 1\n          case "$MRK_MACOS_ANDROID_UI_SCOPE" in\n            disabled|android-signed-build) ;;\n            *) exit 1 ;;\n          esac\n'),
            ("        id: normal_ui_build\n        if: github.ref == 'refs/heads/verify/desktop-macos-preview'\n",
             "        id: normal_ui_build\n        if: github.ref == 'refs/heads/verify/desktop-macos-preview' || (github.ref == 'refs/heads/verify/desktop-macos-installed' && matrix.target == 'aarch64-apple-darwin' && env.MRK_MACOS_ANDROID_UI_SCOPE == 'android-signed-build')\n"),
            ('      - name: Standard Installer only is privileged; never execute the app or Python as root\n',
             '      - name: Standard Installer only is privileged; never execute the app or Python as root\n        id: package_install\n'),
            ("            ${{ format('{0}/source-binding.json\n",
             "            ${{ format('{0}/source-binding.json\n            {0}/normal-ui/android-inputs.status\n            {0}/normal-ui/android-input-status.json\n            {0}/prepare-ui-inputs-failure.json\n            {0}/normal-ui/android-signed-build-test.status\n            {0}/normal-ui/android-signed-build-summary.status\n            {0}/normal-ui/android-signed-build-result.status\n            {0}/normal-ui/android-signed-build.facts.json\n            {0}/normal-ui/android-signed-build-result.json\n"),
        )
        for old, new in reversed(installed_only_edits):
            self.assertEqual(workflow.count(new), 1)
            workflow = workflow.replace(new, old, 1)
                # Two mutually exclusive SOURCE scopes; no ninth-case additive budget,
        # no unselected-cohort success or cleanup authority. No runtime exec here.
        actual = workflow
        current_ids, current = steps(actual)
        scope_name = 'MRK_MACOS_SAVED_FILE_UI_SCOPE'
        self.assertIn('      ' + scope_name + ': ordinary-seven\n', actual)
        self.assertIn('case "$MRK_MACOS_SAVED_FILE_UI_SCOPE" in\n            ordinary-seven) ;;\n'
                      '            saved-version-recovery) [[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-preview ]] || exit 1 ;;\n'
                      '            *) exit 1 ;;\n          esac', actual)
        self.assertIn(" && env." + scope_name + " == 'ordinary-seven'\n", current['normal_saved_checks_ui_test'])
        new_test, new_result = (current[name] for name in ('normal_saved_version_recovery_ui_test', 'normal_saved_version_recovery_ui_result'))
        test_condition = ("github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome == 'success'"
                          " && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery'")
        result_condition = ("github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_saved_version_recovery_ui_test.outcome == 'success'"
                            " && env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery'")
        self.assertIn('        if: ' + test_condition + '\n', new_test)
        self.assertIn('        if: ' + result_condition + '\n', new_result)
        self.assertLess(current_ids.index('normal_diagnostics_ui_result'), current_ids.index('normal_saved_version_recovery_ui_test'))
        self.assertEqual(re.findall(r'-only-testing:MRKNormalAppUITests/NormalAppUITests/(test[A-Za-z0-9_]+)', new_test),
                         ['testSyntheticProjectSavedVersionRecovery'])
        for token in ('timeout-minutes: 11', 'ulimit -f 1048576', 'test-without-building', 'saved-version-recovery-test.xcresult',
                      '-default-test-execution-time-allowance 300 -maximum-test-execution-time-allowance 300',
                      '[[ "$test_status" == 0 ]] || exit "$test_status"'):
            self.assertIn(token, new_test)
        self.assertNotIn('TEST_RUNNER_MRK_NORMAL_UI_SAVED_VERSION_FIXTURE=', new_test) # Only original owner creates this path.
        self.assertIn('timeout-minutes: 3', new_result)
        result_source = inline_python(new_result, 'PY_SAVED_VERSION_RECOVERY_RESULT')
        for token in ('read("normal-ui/diagnostics-result.json", 65536)',
                      'ordinary-ui-observed-original-diagnostics-report-and-settled-projection',
                      'os.environ["MRK_MACOS_SAVED_FILE_UI_SCOPE"] == "saved-version-recovery"',
                      'digest(build_bytes) == prior.get("buildCommandAdmissionSha256")',
                      'runner["sourceRosterSha256"] == summary_owner["sourceRosterSha256"] == decode(build_bytes)["sourceRosterSha256"]',
                      'recovery["runtimeManifestSha256"] == preview["runtimeManifestSha256"]',
                      'recovery["runtimeResultSha256"] == digest(read("runtime-result.json", 65536))',
                      'recovery["producerFramesSha256"] == runner["commands"][2]["stdoutSha256"]',
                      '"savedOfflineAndEmptyBuildInputCohortObserved": False', '"interruptedGuiSaveObserved": False',
                      '"configurationTextImagesRecoveryObserved": False', '"independentOwnerResourceProof": False',
                      '"productReady": False', 'clock["postCloseDeadlineRequired"] is True',
                      'finally: os.close(fd)', 'os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC'):
            self.assertIn(token, result_source)
        self.assertNotIn('saved-checks-result.json', result_source)
        program = ast.parse(result_source)
        call = next(n.value for n in program.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                    and isinstance(n.value.func, ast.Name) and n.value.func.id == 'admitted' and ast.literal_eval(n.value.args[1]) == 'test')
        self.assertEqual(ast.literal_eval(call.args[2]), 585)
        self.assertEqual(ast.dump(call.args[3].elts[0]), ast.dump(ast.Name(id='roster', ctx=ast.Load())))
        self.assertEqual(ast.dump(call.args[3].elts[-1]), ast.dump(ast.Name(id='roster', ctx=ast.Load())))
        self.assertEqual([ast.literal_eval(n) for n in call.args[3].elts[1:-1]], [
            ('saved-version-source-roster', 15, 65536, 0), ('saved-version-core-interrupt', 20, 65536, 86),
            ('verify-generated-runner', 30, 1048576, 0), ('generated-runner-entitlements', 30, 1048576, 0),
            ('one-admitted-ui-test', 420, 1048576, 0)])
        self.assertIn('"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0', result_source)
        actual_cleanup = actual.split("      - name: Remove only this completed preview build's disposable compiler outputs\n", 1)[1]
        self.assertIn("((env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven' && steps.normal_saved_checks_ui_result.outcome == 'success') || "
                      "(env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'saved-version-recovery' && steps.normal_saved_version_recovery_ui_result.outcome == 'success'))", actual_cleanup)
        self.assertIn('if scope not in ("ordinary-seven", "saved-version-recovery"):', actual_cleanup)
        self.assertIn('("saved-checks-test", "saved-checks-summary") if scope == "ordinary-seven"', actual_cleanup)
        self.assertIn('else ("saved-version-recovery-test", "saved-version-recovery-summary")', actual_cleanup)
        self.assertIn('saved_directory', actual_cleanup)
        self.assertIn('*saved_logs)', actual_cleanup)
        self.assertNotIn('rmtree("/private/tmp', actual_cleanup)
        for name in SAVED_VERSION_EVIDENCE:
            self.assertEqual(current['evidence'].count('            {0}/normal-ui/' + name + '\n'), 1)
        for name in ('saved-version-recovery-fixture.json', 'saved-version-recovery-test.log', 'saved-version-recovery-test.xcresult',
                     'saved-version-recovery-summary.raw.json', 'saved-version-recovery-summary.stderr'):
            self.assertNotIn('/normal-ui/' + name, current['evidence'])
        # Verify the two new blocks completely and invert ONLY reviewed changes
        # before running every unchanged old assertion below. Scope predicates,
        # same-scope cleanup, all new admission facts are checked above, not erased.
        for name, expected_hash in SAVED_VERSION_WORKFLOW_BLOCKS:
            self.assertEqual(digest(current[name].encode()), expected_hash)
            self.assertEqual(workflow.count(current[name]), 1)
            workflow = workflow.replace(current[name], '', 1)
        for old, new in reversed(SAVED_VERSION_WORKFLOW_REGIONS):
            self.assertEqual(workflow.count(new), 1)
            workflow = workflow.replace(new, old, 1)
        self.assertEqual(digest(workflow.encode()), SAVED_VERSION_BEFORE_WORKFLOW)
        # Only these exact conditional substitutions affect the bound census.
        old_caps = [int(n) for n in re.findall(r'^        timeout-minutes: ([0-9]+)$', workflow, re.M)]
        new_caps = [int(n) for n in re.findall(r'^        timeout-minutes: ([0-9]+)$', actual, re.M)]
        self.assertEqual((len(old_caps), sum(old_caps), len(new_caps), sum(new_caps)), (40, 359, 42, 373))
        self.assertEqual((345 + 5, 345 - (17 + 3) + (11 + 3) + 5), (350, 344))
        self.assertIn('    timeout-minutes: 350\n', actual)
        ids, blocks = steps(workflow)
        order = ['normal_ui_result', 'normal_project_ui_test', 'normal_project_ui_result',
                 'normal_persistence_ui_test', 'normal_persistence_ui_result',
                 'normal_diagnostics_ui_test', 'normal_diagnostics_ui_result',
                 'normal_saved_checks_ui_test', 'normal_saved_checks_ui_result']
        begin = ids.index(order[0])
        self.assertEqual(ids[begin:begin + len(order)], order)
        for ident, pin in BLOCK_PINS.items():
            self.assertEqual(ids.count(ident), 1)
            self.assertEqual(digest(blocks[ident].encode()), pin, ident)
        test = blocks['normal_diagnostics_ui_test']
        result = blocks['normal_diagnostics_ui_result']
        self.assertIn("steps.normal_persistence_ui_result.outcome == 'success'", test)
        self.assertIn("steps.normal_diagnostics_ui_test.outcome == 'success'", result)
        self.assertEqual(test.count('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building'), 1)
        selector = '-only-testing:MRKNormalAppUITests/NormalAppUITests/' + METHOD
        self.assertEqual(workflow.count(selector), 1)
        for fragment in ('timeout-minutes: 11', 'ulimit -f 1048576', 'resource.getrlimit(resource.RLIMIT_FSIZE)',
                         'admitted = actual == (expected, expected)', '"phase": "diagnostics-test"',
                         '[[ "$file_limit_status" == 0 ]] || exit "$file_limit_status"',
                         '[[ "$file_budget_status" == 0 ]] || exit "$file_budget_status"',
                         '-derivedDataPath "$MRK_MACOS_WORK/normal-ui/DerivedData"',
                         '-resultBundlePath "$MRK_MACOS_WORK/normal-ui/diagnostics-test.xcresult"',
                         '-default-test-execution-time-allowance 300 -maximum-test-execution-time-allowance 300',
                         '"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=$MRK_MACOS_HOSTED_JOB"',
                         'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA',
                         'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA',
                         '[[ "$test_status" == 0 ]] || exit "$test_status"'):
            self.assertIn(fragment, test, fragment)
        self.assertLess(test.index('[[ "$file_budget_status" == 0 ]]'), test.index('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building'))
        budget = inline_python(test, 'PY_UI_FILE_BUDGET')
        safe = inline_python(test, 'PY_DIAGNOSTICS_SAFE_FACTS')
        result_source = inline_python(result, 'PY_DIAGNOSTICS_RESULT')
        for source in (budget, safe, result_source):
            self.assertIn('os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC', source)
            self.assertIn('os.fsync(', source)
            self.assertIn('finally: os.close(fd)', source)
        self.assertIn('"nativeSuccessInferred": False, "rawTextExported": False', safe)
        self.assertIn('if len(events) > 64:', safe)
        self.assertIn('("launch", "fixture", "project-open", "context", "original-report", "readback-and-quit")', safe)
        self.assertIn('json.loads(summary_bytes, object_pairs_hook=unique)', result_source)
        self.assertIn('"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0', result_source)
        self.assertIn('type(summary.get(key)) is not int or summary[key] != value', result_source)
        self.assertIn('MRKNormalAppUITests/NormalAppUITests/' + METHOD, result_source)
        for fragment in ('source != os.environ["MRK_EXPECTED_SHA"]', 'prior["sourceTree"] != preview["sourceTree"]',
                         'prior["signedAppBinarySha256"] != preview["signedAppBinarySha256"]',
                         'prior["runtimeManifestSha256"] != preview["runtimeManifestSha256"]',
                         'set(budget) != set(expected_budget)', 'type(budget[key]) is not type(value)',
                         '"hardBytes": 1073741824', '"safeFactsSha256": hashlib.sha256(facts_bytes).hexdigest()',
                         SCOPE, '"diagnosticsReportAndSettledProjectionUI": "passed"',
                         '"cleanExitStatus": None', '"independentOwnerResourceProof": False',
                         '"allWorkerFinality": "not-established-by-XCTest-UI-state"',
                         '"fullDoctorExecuted": False, "offlinePreflightExecuted": False, "projectRecoveryExecuted": False',
                         '"releaseReadinessEstablished": False', '"productReady": False'):
            self.assertIn(fragment, result_source, fragment)
        evidence = blocks['evidence']
        # The single format has one literal template and one fixed work-root
        # argument. Project these exact DATA rows; do not execute expressions.
        self.assertEqual(evidence.count('          path: |\n'), 1)
        self.assertEqual(evidence.count('          if-no-files-found: error\n'), 1)
        scalar_lines = evidence.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0].splitlines()
        self.assertTrue(all(line.startswith('            ') for line in scalar_lines))
        scalar = '\n'.join(line[12:] for line in scalar_lines) + '\n'
        opening, closing = "${{ format('", "', steps.work.outputs.root) }}\n"
        self.assertTrue(scalar.startswith(opening))
        self.assertTrue(scalar.endswith(closing))
        self.assertEqual(len(scalar[4:-4]), 11686)
        self.assertLess(len(scalar[4:-4]), 21000)
        self.assertEqual(scalar.count('steps.work.outputs.root'), 1)
        self.assertEqual(scalar.count('${{'), 1)
        template = scalar[len(opening):-len(closing)]
        rows = template.split('\n')
        self.assertEqual((len(rows), len(set(rows))), (287, 287))
        self.assertTrue(all(re.fullmatch(r'\{0\}/[A-Za-z0-9_./-]+', row) for row in rows))
        suffixes = [row[3:] for row in rows]
        self.assertTrue(all(part not in ('', '.', '..') for suffix in suffixes for part in suffix[1:].split('/')))
        self.assertEqual(digest(('\n'.join(suffixes) + '\n').encode('ascii')),
                         '91017a03fb36fa6424ee26ef76c11cd837bd73786004bf5e973d2b241a229b7a')
        evidence = ''.join('${{ steps.work.outputs.root }}' + suffix + '\n' for suffix in suffixes)
        for leaf in EVIDENCE_LEAVES:
            self.assertEqual(evidence.count('${{ steps.work.outputs.root }}/normal-ui/' + leaf + '\n'), 1)
        for suffix in ('diagnostics-test.log', 'diagnostics-summary.raw.json', 'diagnostics-summary.stderr',
                       'diagnostics-test.xcresult', 'diagnostics-test.tail.txt'):
            self.assertNotIn('/normal-ui/' + suffix, evidence)
        cleanup = workflow.split("      - name: Remove only this completed preview build's disposable compiler outputs\n", 1)[1]
        self.assertIn("steps.normal_diagnostics_ui_result.outcome == 'success'", cleanup.split('        run: |', 1)[0])
        self.assertIn('root / "normal-ui/diagnostics-test.xcresult"', cleanup)
        self.assertIn('"diagnostics-test.log", "diagnostics-summary.raw.json", "diagnostics-summary.stderr"', cleanup)
        data_step = blocks['data_contracts']
        self.assertEqual(data_step.split('        run: |\n', 1)[1],
                         '          builtin source ./desktop/tools/macos_installed_data_contracts.sh\n')
        data = (ROOT / 'desktop/tools/macos_installed_data_contracts.sh').read_text(encoding='utf-8')
        names = ast.literal_eval(re.search(r'\nnames = (\[\n.*?\n\])\n', data, re.S)[1])
        selected_digest = lambda values: digest(json.dumps(values, separators=(',', ':')).encode())
        self.assertEqual(len(names), 84)
        self.assertEqual(len(set(names)), 84)
        self.assertEqual(selected_digest(names[:79]), '81ca0c9325763f3aaf2a181e521d7b6adde06b7c0321eecacfc2b93a78c3c051')
        self.assertEqual(names[79:81], SOURCE_METHODS)
        self.assertEqual(selected_digest(names[:81]), ORIGINAL_ROSTER_SHA256)
        self.assertEqual(names[81:82], [SAVED_CHECKS_SOURCE_METHOD])
        self.assertEqual(selected_digest(names[:82]), SAVED_CHECKS_ROSTER_SHA256)
        self.assertEqual(names[82:], [
            'test_android_build_tools.MacToolAdmissionDataTests.test_mac_commands_use_exact_contents_home_private_environment_and_inspection_only',
            'test_android_build_tools.OwnerAndCommandDataTests.test_bundletool_requires_original_native_borrow_and_exact_snapshot',
        ])
        self.assertEqual(selected_digest(names), ROSTER_SHA256)
        self.assertEqual(data.count(ROSTER_SHA256), 3)
        opening, closing = "<<'PY_DATA_CONTRACTS'\n", "\nPY_DATA_CONTRACTS\n"
        self.assertEqual((data.count(opening), data.count(closing)), (1, 1))
        self.assertTrue(data.endswith(closing))
        data_python = data.split(opening, 1)[1].removesuffix(closing)
        ci_admissions = [node for node in ast.parse(data_python).body
                         if isinstance(node, ast.FunctionDef) and node.name == "ci_data_admission"]
        self.assertEqual(len(ci_admissions), 1)
        ci_admission = ast.get_source_segment(data_python, ci_admissions[0])
        self.assertEqual(data.count(ci_admission), 1)
        self.assertEqual(ci_admission.count(ROSTER_SHA256), 1)
        ci_selection_guard = ast.parse('selected["selectionSha256"] != "' + ROSTER_SHA256 + '"', mode="eval").body
        self.assertEqual(sum(isinstance(node, ast.Compare) and ast.dump(node) == ast.dump(ci_selection_guard)
                             for node in ast.walk(ci_admissions[0])), 1)
        self.assertEqual(data.replace(ci_admission, "", 1).count(ROSTER_SHA256), 2)
        sources = ast.literal_eval(re.search(r'\nsource_names = (\(\n.*?\n\))\n', data, re.S)[1])
        self.assertEqual(len(sources), 78)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertEqual(selected_digest(sources[:53]), "5d544a55d63d5ac1f14f341b0ba51509c6c77e762e2f7e7c964fc9f87ec44bf4")
        self.assertEqual(list(sources[53:64]), SAVED_CHECKS_SOURCE_REFS)
        self.assertEqual(list(sources[64:69]), [
            "desktop/macos-installed-inputs/build-release.json",
            "desktop/src-tauri/src/macos_build_release.rs",
            "desktop/src-tauri/src/macos_install_fixed_paths.rs",
            "desktop/src-tauri/src/macos_install_paths.rs",
            "desktop/src-tauri/tauri.conf.json",
        ])
        self.assertEqual(list(sources[69:77]), [
            "tests/desktop/test_android_build_tools.py",
            "src/mobile_release/android_build_tools.py",
            "src/mobile_release/android_build_tools_macos.py",
            "src/mobile_release/android_build_operation.py",
            "src/mobile_release/_desktop_android_build_files.py",
            "src/mobile_release/android.py", "src/mobile_release/credentials.py",
            "src/mobile_release/local_signing.py",
        ])
        self.assertEqual(list(sources[77:]), ['desktop/tools/macos_installed_data_contracts.sh'])
        self.assertTrue(set(SOURCE_REFS).issubset(sources))
        for fragment in ('len(names) != 84 or len(set(names)) != 84', 'suite.countTestCases() != 84',
                         'facts["testsRun"] == 84', 'counts.get("testsRun") != 84', '"pythonExpectedCount": 84',
                         '"githubActionCount": 22, "normalDiagnosticsSourceCount": 3',
                         '"test_macos_normal_diagnostics_source", "test_android_build_tools") or not method.startswith("test_")'):
            self.assertIn(fragment, data, fragment)



        # All native commands now use the fixed original owner; only the local
        # affected selection adds new helper tests, never the existing native84.
        self.assertIn('    timeout-minutes: 350\n', workflow)
        ceilings = [int(value) for value in re.findall(r'^        timeout-minutes: ([0-9]+)$', workflow, re.M)]
        self.assertEqual((len(ceilings), sum(ceilings)), (40, 359))
        # Full fixed step/condition census: an unknown condition cannot silently
        # disappear from this budget. Cleanup is conservatively in BOTH refs.
        expected_routes = (('Select the fixed configured signed runtime before any payload download', 1, None),
         ('Admit the fixed image Rust tools without installing a distribution', 4, None),
         ('Admit only a fresh independently pinned Python transport destination', 1, None),
         ('Download the independently accepted fresh Python transport', 3, None),
         ('Project the pinned fresh Python transport without executing it', 3, None),
         ('Download only the configured signed Python capsule', 3, None),
         ('Project the configured capsule as DATA without executing it', 3, None),
         ('Prepare the current payload from the independently accepted fresh Python supplier', 3, None),
         ('Build only the external normal-app XCTest runner, not an instrumented app',
          9,
          "github.ref == 'refs/heads/verify/desktop-macos-preview'"),
         ('Fail fast on native Scripts ownership and package format (never Installer)', 2, None),
         ('Fail fast on the selected SDK actual no-ACL and ACE-refusal primitive',
          2,
          "github.ref == 'refs/heads/verify/desktop-macos-installed'"),
         ('Acquire and verify the two fixed Android support archives as DATA', 4, None),
         ('Require the fixed SOURCE producer identity and release before ordinary signing', 1, None),
         ('Build and sign the fixed resident image and C facades', 10, None),
         ('Build and sign the separate fixed vault helper before binding the app', 8, None),
         ('Build the ordinary selected-target desktop image and embedded frontend', 24, None),
         ('Record the effective pinned compiler from the successful build context', 1, None),
         ('Compile and run only fixed native DATA contracts and exact host-Python regressions',
          28,
          "github.ref == 'refs/heads/verify/desktop-macos-preview'"),
         ('Assemble the ordinary image app and sign code inside-out (never --deep)', 3, None),
         ('Bind this completed signed app and current-source runtime into fresh Installer DATA', 32, None),
         ('Run only the five reviewed nonroot regressions (exact groups 2, 1, 2)',
          12,
          "github.ref == 'refs/heads/verify/desktop-macos-installed'"),
         ('Build the separate fixed eight-case Installer package from the same completed input', 8, None),
         ('Standard Installer runs the one fixed fixture, never root libtest or a scenario selector', 18, None),
         ('Nonroot fixture readback leaves protected0700 staging closed and unchanged', 3, None),
         ('Build the fixed one-shot root Installer and scripts-only package', 8, None),
         ('Sign and notarize the completed scripts-only Installer package before final P', 32, None),
         ('Standard Installer only is privileged; never execute the app or Python as root', 18, None),
         ('Notarize, staple and verify only the final user image',
          32,
          "github.ref == 'refs/heads/verify/desktop-macos-preview'"),
         ('Stage only the audited normal early-preview deliverables',
          3,
          "github.ref == 'refs/heads/verify/desktop-macos-preview'"),
         ('Launch the exact ordinary app, Cancel its real Quit sheet, then Quit normally',
          7,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_build.outcome == 'success' && "
          "steps.preview_upload.outcome == 'success'"),
         ('Preserve original XCTest counts and a closed UI-only result, never a clean-exit claim',
          3,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_test.outcome == 'success'"),
         ('Exercise normal project edits, images and four draft-only Browse fields',
          16,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_result.outcome == 'success'"),
         ('Verify both selected project journeys against their original XCTest result',
          3,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_project_ui_test.outcome == 'success'"),
         ('Exercise synthetic encrypted credentials through the ordinary Mac UI',
          11,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_ui_result.outcome == 'success'"),
         ('Bind the single persistence journey to original XCTest and app-helper evidence',
          3,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_persistence_ui_test.outcome == "
          "'success'"),
         ('Observe one original build-tool diagnostics report through the ordinary Mac UI',
          11,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_persistence_ui_result.outcome == "
          "'success'"),
         ('Bind the single diagnostics journey to original XCTest and the same ordinary package',
          3,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_test.outcome == "
          "'success'"),
         ('Observe saved offline checks and empty build-input inspection through the ordinary Mac UI',
          17,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_diagnostics_ui_result.outcome == "
          "'success'"),
         ('Bind both saved-check journeys to original XCTest and the same ordinary package',
          3,
          "github.ref == 'refs/heads/verify/desktop-macos-preview' && steps.normal_saved_checks_ui_test.outcome == "
          "'success'"),
         ("Remove only this completed preview build's disposable compiler outputs",
          3,
          "always() && steps.preview_upload.outcome == 'success' && steps.normal_ui_result.outcome == 'success' && "
          "steps.normal_persistence_ui_result.outcome == 'success' && steps.normal_project_ui_result.outcome == 'success' "
          "&& steps.normal_diagnostics_ui_result.outcome == 'success' && steps.normal_saved_checks_ui_result.outcome == "
          "'success' && steps.data_contracts.outcome == 'success' && steps.evidence.outcome == 'success'"))
        actual_routes = []
        for block in re.findall(r"(?ms)^      - name: .*?(?=^      - name: |\Z)", workflow):
            caps = re.findall(r"^        timeout-minutes: ([0-9]+)$", block, re.M)
            if not caps:
                continue
            self.assertEqual(len(caps), 1)
            conditions = re.findall(r"^        if: (.+)$", block, re.M)
            self.assertLessEqual(len(conditions), 1)
            actual_routes.append((block.splitlines()[0][len("      - name: "):], int(caps[0]), conditions[0] if conditions else None))
        self.assertEqual(tuple(actual_routes), expected_routes)
        preview_ref = "github.ref == 'refs/heads/verify/desktop-macos-preview'"
        installed_ref = "github.ref == 'refs/heads/verify/desktop-macos-installed'"
        cleanup_name = "Remove only this completed preview build's disposable compiler outputs"
        preview_minutes = sum(minutes for name, minutes, condition in actual_routes if condition != installed_ref)
        installed_minutes = sum(minutes for name, minutes, condition in actual_routes
                                if name == cleanup_name or condition is None or condition == installed_ref)
        self.assertTrue(all(name == cleanup_name or condition is None or condition == installed_ref
                            or condition == preview_ref or condition.startswith(preview_ref + " && steps.")
                            for name, minutes, condition in actual_routes))
        self.assertEqual((preview_minutes, installed_minutes), (345, 210))
        self.assertEqual(max(preview_minutes, installed_minutes) + 5, 350)
        self.assertLessEqual(350, 360)
        self.assertEqual(workflow.count('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" --normal-summary '), 5)
        build = blocks['normal_ui_build']
        self.assertIn('timeout-minutes: 9', build)
        self.assertIn('ulimit -f 33554432', build)
        self.assertIn('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" --normal-build', build)
        for fragment in ('"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=$MRK_MACOS_HOSTED_JOB"',
                         'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA',
                         'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA'):
            self.assertIn(fragment, build)
        for ident, stem, summary_stem, minutes in (
            ('normal_ui', 'test', 'summary', 7),
            ('normal_project_ui', 'project-test', 'project-summary', 16),
            ('normal_persistence_ui', 'persistence-test', 'persistence-summary', 11),
            ('normal_diagnostics_ui', 'diagnostics-test', 'diagnostics-summary', 11),
            ('normal_saved_checks_ui', 'saved-checks-test', 'saved-checks-summary', 17),
        ):
            original_test, original_result = blocks[ident + '_test'], blocks[ident + '_result']
            self.assertIn('timeout-minutes: ' + str(minutes), original_test)
            self.assertIn('timeout-minutes: 3', original_result)
            self.assertIn('ulimit -f 1048576', original_result)
            self.assertIn('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" --normal-summary ' + stem + '.xcresult', original_result)
            for fragment in (
                '"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=$MRK_MACOS_HOSTED_JOB"',
                'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA', 'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA',
                'checked_admission("build.command-admission.json", "build", None, 450,',
                'checked_admission("' + stem + '.runner-admission.json", "test", "' + stem + '.xcresult", ',
                'checked_admission("' + summary_stem + '.command-admission.json", "summary", "' + stem + '.xcresult", 90,',
                'runner.get("strictCodesignOriginalZero") is not True', 'runner.get("originalClosesCompleted") is not True',
                'runner.get("originalProductsPrePostMatched") is not True', 'runner.get("reSignedOrRepaired") is not False',
                'value.get("sourcePrePostMatched") is not True', 'value.get("originalCommandReturned") is not True',
                'value.get("target") != build_target', 'preview["platform"] != platforms[build_target]',
                '"target": build_target, "platform": preview["platform"]',
                'end - start != seconds * 1_000_000_000 or not start <= before_close < end',
                'clock["postCloseDeadlineRequired"] is not True',
                'build["sourceRosterSha256"] == runner["sourceRosterSha256"] == summary_admission["sourceRosterSha256"]',
                'summary_admission["commands"][1]["stdoutSha256"] != hashlib.sha256(summary_bytes).hexdigest()',
                'hashlib.sha256(raw).hexdigest() != query["stdoutSha256"]',
                '"generatedRunnerAdmissionSha256": hashlib.sha256(runner_bytes).hexdigest()',
                '"buildCommandAdmissionSha256": hashlib.sha256(build_bytes).hexdigest()',
                '"summaryCommandAdmissionSha256": hashlib.sha256(summary_admission_bytes).hexdigest()',
            ):
                self.assertIn(fragment, original_result, ident + ':' + fragment)
            self.assertLess(original_result.index('[[ "$summary_status" == 0 ]]'), original_result.index('def checked_admission('))
            for name in (stem + '.runner-admission.json', stem + '.failure-diagnostics.json',
                         summary_stem + '.command-admission.json', summary_stem + '.failure-diagnostics.json'):
                self.assertEqual(evidence.count('${{ steps.work.outputs.root }}/normal-ui/' + name + '\n'), 1)
            for suffix in (stem + '.log', stem + '.xcresult', stem + '.tail.txt',
                           summary_stem + '.stderr', summary_stem + '.stderr.tail.txt', summary_stem + '.raw.json'):
                self.assertNotIn('/normal-ui/' + suffix + '\n', evidence)
        for leaf in ('build.command-admission.json', 'build.failure-diagnostics.json', 'toolchain.failure-diagnostics.json'):
            self.assertEqual(evidence.count('${{ steps.work.outputs.root }}/normal-ui/' + leaf + '\n'), 1)
        self.assertNotIn('join(sorted(summary))', workflow)
        for name in ('build.tail.txt', 'test.tail.txt', 'project-test.tail.txt', 'summary.stderr.tail.txt', 'project-summary.stderr.tail.txt'):
            self.assertNotIn('/normal-ui/' + name, workflow)
        for fragment in ('def acl_source_hashes(', 'original(inventory_path, 2 * 1024 * 1024)',
                         'body = original(os.path.join(workspace, path), 262144)', 'row["gitMode"] != "100644"',
                         'len(body) != row["size"] or digest != row["sha256"] or blob != row["blob"]',
                         'source != workflow_source', 'inventory["source"] != source',
                         'identity(os.stat(path, follow_symlinks=False)) != before'):
            self.assertIn(fragment, workflow)
        self.assertNotIn('body = stream.read(131073)', workflow)
        self.assertIn('read("native-acl-probe.log", 131072)', workflow)
        for name in ('test_fixed_normal_modes_environment_and_returned_original_contract',
                     'test_normal_phase_deadlines_file_limits_source_and_receipt_finality',
                     'test_closed_normal_failure_diagnostics_preserve_original_nonzero_and_privacy',
                     'test_acl_complete_source_inventory_reads_originals_at_current_native_size'):
            self.assertNotIn(name, data)

        # One already-built runner invocation contains precisely these two independent journeys.
        saved_test = blocks['normal_saved_checks_ui_test']
        saved_result = blocks['normal_saved_checks_ui_result']
        saved_methods = ['testSyntheticProjectSavedOfflineChecks', 'testSyntheticProjectEmptyBuildInputInspection']
        saved_identifiers = ['MRKNormalAppUITests/NormalAppUITests/' + name for name in saved_methods]
        self.assertNotIn('/usr/bin/xcodebuild build-for-testing', workflow)
        self.assertEqual(workflow.count('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" --normal-build'), 1)
        self.assertEqual(workflow.count('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building'), 5)
        self.assertEqual(saved_test.count('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building'), 1)
        self.assertEqual(re.findall(r'-only-testing:MRKNormalAppUITests/NormalAppUITests/(test[A-Za-z0-9_]+)', saved_test), saved_methods)
        for identifier in saved_identifiers:
            self.assertEqual(workflow.count('-only-testing:' + identifier), 1)
        self.assertIn("steps.normal_diagnostics_ui_result.outcome == 'success'", saved_test)
        self.assertIn("steps.normal_saved_checks_ui_test.outcome == 'success'", saved_result)
        for fragment in ('timeout-minutes: 17', 'ulimit -f 1048576', 'resource.getrlimit(resource.RLIMIT_FSIZE)',
                         'admitted = actual == (expected, expected)', '"phase": "saved-checks-test"',
                         '[[ "$file_limit_status" == 0 ]] || exit "$file_limit_status"',
                         '[[ "$file_budget_status" == 0 ]] || exit "$file_budget_status"',
                         '-project desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj -scheme MRKNormalAppUI',
                         '-configuration Debug -destination "platform=macOS,arch=$MRK_MACOS_MACHINE" -destination-timeout 15',
                         '-derivedDataPath "$MRK_MACOS_WORK/normal-ui/DerivedData"',
                         '-resultBundlePath "$MRK_MACOS_WORK/normal-ui/saved-checks-test.xcresult"',
                         '-parallel-testing-enabled NO -test-timeouts-enabled YES',
                         '-default-test-execution-time-allowance 300 -maximum-test-execution-time-allowance 300',
                         '"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=$MRK_MACOS_HOSTED_JOB"',
                         'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA',
                         'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA',
                         '[[ "$test_status" == 0 ]] || exit "$test_status"'):
            self.assertIn(fragment, saved_test, fragment)
        self.assertLess(saved_test.index('[[ "$file_budget_status" == 0 ]]'), saved_test.index('desktop/tools/macos_normal_ui_runner.py --target "$MRK_MACOS_TARGET" test-without-building'))
        saved_budget = inline_python(saved_test, 'PY_UI_FILE_BUDGET')
        saved_safe = inline_python(saved_test, 'PY_SAVED_CHECKS_SAFE_FACTS')
        saved_result_source = inline_python(saved_result, 'PY_SAVED_CHECKS_RESULT')
        for code in (saved_budget, saved_safe, saved_result_source):
            self.assertIn('os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC', code)
            self.assertIn('os.fsync(', code)
            self.assertIn('finally: os.close(fd)', code)
        stages = next(node.value for node in ast.parse(saved_safe).body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'stages' for target in node.targets))
        self.assertEqual(ast.literal_eval(stages), {
            'offline-launch', 'offline-fixture', 'offline-project-open', 'offline-review-and-start',
            'offline-original-report', 'offline-readback-and-quit',
            'recovery-idle-launch', 'recovery-idle-fixture', 'recovery-idle-project-open', 'recovery-idle-inspect',
            'recovery-idle-original-report', 'recovery-idle-readback-and-quit'})
        for fragment in ('"nativeSuccessInferred": False, "rawTextExported": False', 'if len(events) > 64:',
                         'before.st_size <= 16 * 1024 * 1024', 'before.st_size - 262144'):
            self.assertIn(fragment, saved_safe)
        assignments = {target.id: node.value for node in ast.parse(saved_result_source).body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
        self.assertEqual(ast.literal_eval(assignments['prior_expected']),
                         {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0})
        self.assertEqual(ast.literal_eval(assignments['expected']),
                         {"totalTestCount": 2, "passedTests": 2, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0})
        fields = {key.value: value for key, value in zip(assignments['result'].keys, assignments['result'].values)}
        self.assertEqual(ast.literal_eval(fields['testIdentifiers']), saved_identifiers)
        self.assertEqual(ast.literal_eval(fields['scope']), 'ordinary-ui-observed-saved-offline-and-empty-build-input-inspection')
        journeys = ast.literal_eval(fields['journeys'])
        self.assertEqual(list(journeys), ['savedOfflineChecks', 'emptyBuildInputInspection'])
        for journey, identifier in zip(journeys.values(), saved_identifiers):
            self.assertEqual(journey['testIdentifier'], identifier)
            self.assertEqual(journey['coreOutcomeObserved'], 'complete')
            self.assertEqual(journey['nativeProjectionObserved'], {"phase": "settled", "finality": "settled"})
            self.assertEqual(journey['fixtureReadback'], 'unchanged-before-and-after-normal-quit')
            self.assertEqual(journey['applicationStateAfterNormalQuit'], 'notRunning')
        offline_result = journeys['savedOfflineChecks']
        self.assertEqual(offline_result['scope'], 'ordinary-ui-observed-saved-offline-report-and-settled-projection')
        self.assertEqual(offline_result['savedOfflineReportAndSettledProjectionUI'], 'passed')
        self.assertEqual(offline_result['negativeFindingsAssertion'],
                         {"missingAtLeast": 2, "skippedAtLeast": 1, "moduleWrapperAndEarlyExitObserved": True})
        idle_result = journeys['emptyBuildInputInspection']
        self.assertEqual(idle_result['scope'], 'ordinary-ui-observed-empty-build-input-inspection-and-settled-projection')
        self.assertEqual(idle_result['emptyBuildInputInspectionAndSettledProjectionUI'], 'passed')
        self.assertEqual(idle_result['inspectionStatusObserved'], 'idle')
        self.assertIs(idle_result['mutationRecoveryExecuted'], False)
        self.assertIs(idle_result['projectCleanlinessEstablished'], False)
        for name in ('result.json', 'project-result.json', 'persistence-result.json', 'diagnostics-result.json'):
            self.assertIn('("' + name + '", ', saved_result_source)
        # The same project producer has two cases. Its two downstream consumers
        # must select2/2 only for that fixed prior, not relax every prior to1or2.
        # This is SOURCE/AST inspection only; no inline workflow code is run.
        for code, baseline, names in (
                (result_source, 'expected',
                 ('result.json', 'project-result.json', 'persistence-result.json')),
                (saved_result_source, 'prior_expected',
                 ('result.json', 'project-result.json', 'persistence-result.json', 'diagnostics-result.json'))):
            parsed = ast.parse(code)
            bases = [node.value for node in parsed.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == baseline for target in node.targets)]
            self.assertEqual(len(bases), 1)
            self.assertEqual(ast.literal_eval(bases[0]),
                             {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0})
            loops = [node for node in parsed.body if isinstance(node, ast.For)
                     and ast.dump(node.target) == ast.dump(ast.parse('name, scope, test, passed = ()').body[0].targets[0])]
            self.assertEqual(len(loops), 1)
            prior_loop = loops[0]
            self.assertEqual(tuple(row[0] for row in ast.literal_eval(prior_loop.iter)), names)
            choice = prior_loop.body[0]
            self.assertIsInstance(choice, ast.Assign)
            self.assertEqual([ast.dump(target) for target in choice.targets],
                             [ast.dump(ast.Name(id='prior_expected_counts', ctx=ast.Store()))])
            wanted = ast.parse(
                f'dict({baseline}, totalTestCount=2, passedTests=2) if name == "project-result.json" else {baseline}',
                mode='eval').body
            self.assertEqual(ast.dump(choice.value), ast.dump(wanted))
            gates = [node for node in prior_loop.body if isinstance(node, ast.If)]
            self.assertEqual(len(gates), 2)
            self.assertEqual(ast.dump(gates[0].test), ast.dump(ast.parse(
                'type(prior) is not dict or prior.get("target") != build_target', mode='eval').body))
            self.assertEqual(ast.get_source_segment(code, gates[0].body[0]),
                             'raise ValueError("normal-prior-target")')
            gate = ast.get_source_segment(code, gates[1].test)
            self.assertIn('for key, value in prior_expected_counts.items()', gate)
            self.assertNotIn('for key, value in ' + baseline + '.items()', gate)
            if baseline == 'prior_expected':
                self.assertIn('set(prior["testCounts"]) != set(prior_expected_counts)', gate)
        for fragment in ('source != os.environ["MRK_EXPECTED_SHA"]', 'prior["sourceTree"] != preview["sourceTree"]',
                         'prior["signedAppBinarySha256"] != preview["signedAppBinarySha256"]',
                         'prior["runtimeManifestSha256"] != preview["runtimeManifestSha256"]',
                         'prior["applicationStateAfterNormalQuit"] != "notRunning"',
                         'type(prior["testCounts"][key]) is not int', 'type(summary.get(key)) is not int or summary[key] != value',
                         'json.loads(summary_bytes, object_pairs_hook=unique)',
                         'set(budget) != set(expected_budget)', 'type(budget[key]) is not type(value)', '"hardBytes": 1073741824',
                         '"safeFactsSha256": hashlib.sha256(facts_bytes).hexdigest()',
                         'normal-saved-offline-and-empty-recovery-ui-diagnostics-only'):
            self.assertIn(fragment, saved_result_source, fragment)
        self.assertIs(ast.literal_eval(fields['cleanExitStatus']), None)
        self.assertEqual(ast.literal_eval(fields['allWorkerFinality']), 'not-established-by-XCTest-UI-state')
        self.assertEqual(ast.literal_eval(fields['applicationStateAfterBothNormalQuits']), 'notRunning')
        for field in ('independentOwnerResourceProof', 'fullDoctorExecuted', 'mutationRecoveryExecuted', 'zeroCommandEvidence',
                      'networkIsolationEstablished', 'releaseReadinessEstablished', 'fullUIQualified', 'distributionQualified', 'productReady'):
            self.assertIs(ast.literal_eval(fields[field]), False, field)
        for field in ('offlinePreflightExecuted', 'projectRecoveryInspectionExecuted'):
            self.assertIs(ast.literal_eval(fields[field]), True, field)
        for leaf in ('saved-checks-test-file-limit.status', 'saved-checks-test-file-budget.status', 'saved-checks-test-file-budget.json',
                     'saved-checks-test.status', 'saved-checks-safe-facts.json', 'saved-checks-summary.status', 'saved-checks-result.json'):
            self.assertEqual(evidence.count('${{ steps.work.outputs.root }}/normal-ui/' + leaf + '\n'), 1)
        for suffix in ('saved-checks-test.log', 'saved-checks-summary.raw.json', 'saved-checks-summary.stderr',
                       'saved-checks-test.xcresult', 'saved-checks-test.tail.txt'):
            self.assertNotIn('/normal-ui/' + suffix, evidence)
        self.assertIn("steps.normal_saved_checks_ui_result.outcome == 'success'", cleanup.split('        run: |', 1)[0])
        self.assertIn('root / "normal-ui/saved-checks-test.xcresult"', cleanup)
        self.assertIn('"saved-checks-test.log", "saved-checks-summary.raw.json", "saved-checks-summary.stderr"', cleanup)

        # The unsigned iOS lane is an installed-only, SOURCE-selected addition.
        # All older workflow assertions above received the exact prior bytes;
        # this second read tests the actual new route, not its inverse view.
        ios_workflow = without_shipping_compile_workflow((ROOT / '.github/workflows/desktop-macos-installed.yml').read_text())
        ios_ids, ios_blocks = steps(ios_workflow)
        ios_names = ('normal_ios_ui_test', 'normal_ios_ui_summary')
        ios_condition = ("github.ref == 'refs/heads/verify/desktop-macos-installed' "
                         "&& env.MRK_MACOS_IOS_UI_SCOPE == 'ios-unsigned-archive' "
                         "&& env.MRK_MACOS_ANDROID_UI_SCOPE == 'disabled' "
                         "&& env.MRK_MACOS_SAVED_FILE_UI_SCOPE == 'ordinary-seven'")
        self.assertEqual(ios_workflow.count('      MRK_MACOS_IOS_UI_SCOPE: disabled\n'), 1)
        self.assertEqual(ios_workflow.count('          case "$MRK_MACOS_IOS_UI_SCOPE" in\n'), 1)
        self.assertIn('          case "$MRK_MACOS_IOS_UI_SCOPE" in\n'
                      '            disabled) ;;\n'
                      '            ios-unsigned-archive)\n'
                      '              [[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-installed && '
                      '"$MRK_MACOS_ANDROID_UI_SCOPE" == disabled && "$MRK_MACOS_SAVED_FILE_UI_SCOPE" == ordinary-seven ]] || exit 1\n'
                      '              ;;\n            *) exit 1 ;;\n          esac\n', ios_workflow)
        self.assertEqual(re.findall(r'^        if: (.+)$', ios_blocks['normal_ui_build'], re.M),
                         [preview + ' || (' + positive + ') || (' + ios_condition + ')'])
        last_android = ios_ids.index('normal_android_ui_result')
        self.assertEqual(tuple(ios_ids[last_android + 1:last_android + 3]), ios_names)
        self.assertTrue(ios_blocks['normal_ios_ui_summary'].endswith('\n\n'))
        self.assertIn(ios_blocks['normal_ios_ui_summary'] +
                      '      - name: Notarize, staple and verify only the final user image\n', ios_workflow)
        ios_steps = [ios_blocks[name] for name in ios_names]
        for (phase, minutes, block) in zip(('test', 'summary'), (22, 2), ios_steps, strict=True):
            expected_if = ios_condition
            if phase == 'summary':
                expected_if += " && steps.normal_ios_ui_test.outcome == 'success'"
            expected_if += " && steps.normal_ui_build.outcome == 'success' && steps.package_install.outcome == 'success'"
            self.assertEqual(ios_ids.count('normal_ios_ui_' + phase), 1)
            self.assertEqual(re.findall(r'^        if: (.+)$', block, re.M), [expected_if])
            self.assertEqual(re.findall(r'^        timeout-minutes: ([0-9]+)$', block, re.M), [str(minutes)])
            self.assertNotIn('always()', block)
            self.assertNotIn('continue-on-error', block)
            self.assertNotIn('refs/heads/verify/desktop-macos-preview', block)
            for fragment in ('set +x\n', 'set +a\n', 'set -euo pipefail\n', 'set -o noclobber\n',
                             'umask 077\n', 'ulimit -f 1048576\n',
                             '[[ "$GITHUB_SHA" == "$GITHUB_WORKFLOW_SHA" && "$GITHUB_SHA" == "$MRK_EXPECTED_SHA" ]] || exit 1',
                             '[[ "$MRK_MACOS_WORK" =~ ^/Users/runner/work/_temp/mrk-macos-installed\\.[A-Za-z0-9]{8}$ ]] || exit 1'):
                self.assertIn(fragment, block)
            self.assertEqual(block.count('/usr/bin/env -i '), 1)
            command = block.split('          /usr/bin/env -i ', 1)[1].split('          ios_' + phase + '_status=$?', 1)[0]
            expected_env = {'PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ', 'DEVELOPER_DIR',
                            'TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB', 'TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE',
                            'TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE'}
            environment = command.split('"$MRK_PYTHON"', 1)[0]
            self.assertEqual(set(re.findall(r'\b([A-Z][A-Z0-9_]+)=', environment)), expected_env)
            for fragment in ('PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner USER=runner LOGNAME=runner',
                             '"TMPDIR=$MRK_MACOS_WORK/normal-ui/tmp/" LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 TZ=UTC',
                             '"DEVELOPER_DIR=$DEVELOPER_DIR"',
                             '"TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=$MRK_MACOS_HOSTED_JOB"',
                             '"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA"',
                             '"TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA"'):
                self.assertIn(fragment, environment)
            invocation = ('"$MRK_PYTHON" -I -S -B desktop/tools/macos_normal_ui_runner.py '
                          '--target "$MRK_MACOS_TARGET" --normal-ios-unsigned-archive-' + phase)
            self.assertEqual(command.count(invocation), 1)
            self.assertEqual(ios_workflow.count('--normal-ios-unsigned-archive-' + phase), 1)
            self.assertNotIn('--normal-android', command)
            self.assertNotIn('--engineering', command)
            status = 'ios_' + phase + '_status'
            self.assertEqual(block.count(status + '=$?'), 1)
            self.assertLess(block.index(invocation), block.index(status + '=$?'))
            self.assertIn('printf \'%s\\n\' "$' + status + '" > "$MRK_MACOS_WORK/normal-ui/ios-unsigned-archive-' + phase + '.status"', block)
            self.assertIn(status + '_saved=$?\n          set -e\n', block)
            first_error = 'if [[ "$' + status + '" != 0 ]]; then exit "$' + status + '"; fi'
            publication = '[[ "$' + status + '_saved" == 0 ]] || exit 1'
            self.assertLess(block.index(first_error), block.index(publication))
            for forbidden in ('curl ', 'wget ', 'security ', 'sudo ', 'rm -rf', 'shutil.rmtree', 'tee ',
                              'secrets.', 'GITHUB_TOKEN=', 'MRK_ANDROID_UI_KEY_PASSWORD=', '--work ',
                              'source ./', ' -c ', '<<', '/usr/bin/xcodebuild', '--test-timeout'):
                self.assertNotIn(forbidden, block)
            body = block.split('        run: |\n', 1)[1]
            self.assertLess(len(body), 6000)
        self.assertIn('> "$MRK_MACOS_WORK/normal-ui/ios-unsigned-archive-test.log" 2>&1', ios_steps[0])
        self.assertIn('> "$MRK_MACOS_WORK/normal-ui/ios-unsigned-archive-summary.json" '
                      '2> "$MRK_MACOS_WORK/normal-ui/ios-unsigned-archive-summary.stderr"', ios_steps[1])
        self.assertIn('same original reserve', ios_steps[0])
        self.assertIn('not a replacement Start', ios_steps[0])
        self.assertIn('never IPA/signing/distribution qualification', ios_steps[1])

        # Current all-route SOURCE census includes four Remove steps (90 total).
        # Following iOS/previous-preview arithmetic uses the earlier pinned
        # projection, not entitlement to all expanded-preview step maxima.
        # The current hard job cap remains350; no expanded-route fit is claimed.
        full_caps = [int(n) for n in re.findall(r'^        timeout-minutes: ([0-9]+)$', ios_workflow, re.M)]
        self.assertEqual((len(full_caps), sum(full_caps)), (51, 535))
        ios_build_minutes = int(re.search(r'^        timeout-minutes: ([0-9]+)$', ios_blocks['normal_ui_build'], re.M)[1])
        ios_minutes = installed_minutes + ios_build_minutes + sum(
            int(re.search(r'^        timeout-minutes: ([0-9]+)$', block, re.M)[1]) for block in ios_steps)
        self.assertEqual((ios_minutes, ios_minutes + 5, preview_minutes + 5), (243, 248, 350))
        self.assertLessEqual(ios_minutes + 5, 350)
        self.assertEqual(ios_workflow.count('    timeout-minutes: 350\n'), 1)
        self.assertIn('    # Raw timed-step union535min; disjoint scopes retain the350min hard job cap.\n'
                      '    # Pre-Remove baseline preview345 / recovery339 / installed210, plus5 overhead.\n'
                      '    # Remove preview adds90 nominal step maxima; this sum establishes no fit.\n'
                      '    # Dormant Android272 / iOS248 include5 overhead; no native qualification claimed.\n', ios_workflow)
        public_ios = ('ios-unsigned-archive-test.status', 'ios-unsigned-archive-summary.status',
                      'ios-unsigned-archive.facts.json', 'ios-unsigned-archive-test.runner-admission.json',
                      'ios-unsigned-archive-summary.command-admission.json',
                      'ios-unsigned-archive-test.failure-diagnostics.json',
                      'ios-unsigned-archive-summary.failure-diagnostics.json')
        current_evidence = ios_blocks['evidence']
        self.assertEqual(tuple(re.findall(r'^            \{0\}/normal-ui/(ios-unsigned-archive[^\n]*)$',
                                         current_evidence, re.M)), public_ios)
        self.assertEqual(current_evidence.count("${{ format('"), 1)
        # The unchanged availability guard also names the root; only the
        # artifact path scalar must contain exactly one format argument.
        self.assertEqual(re.findall(r'^        if: (.+)$', current_evidence, re.M),
                         ["always() && steps.work.outputs.root != ''"])
        ios_path_scalar = current_evidence.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        self.assertEqual(ios_path_scalar.count('steps.work.outputs.root'), 1)
        for private in ('ios-unsigned-archive-test.log', 'ios-unsigned-archive-test.xcresult',
                        'ios-unsigned-archive-summary.json', 'ios-unsigned-archive-summary.stderr', 'archive.xcarchive'):
            self.assertNotIn(private, current_evidence)
        # The inverse refuses even a one-token new-scope alteration; it cannot
        # hide a future semantic delta while keeping old SOURCE tests green.
        self.assertEqual(digest(without_ios_unsigned_workflow(ios_workflow).encode()),
                         'd7199d46c3292bca3f7f04a932a4cdde05513f91bbff5d2c859bee9451fcf8bb')
        # Remove only the authenticated outer output layer before mutating the
        # historical iOS/Wiring layer; each exact intended guard must reject it.
        ios_projection = without_remove_output_workflow(ios_workflow)
        with self.assertRaisesRegex(AssertionError, 'unsigned iOS workflow'):
            without_ios_unsigned_workflow(ios_projection.replace('MRK_MACOS_IOS_UI_SCOPE: disabled',
                                                               'MRK_MACOS_IOS_UI_SCOPE: other', 1))
        with self.assertRaisesRegex(AssertionError, 'unsigned iOS workflow remover'):
            without_ios_unsigned_workflow(ios_projection.replace('sign-remover --target', 'sign-other --target', 1))


if __name__ == '__main__':
    unittest.main()
