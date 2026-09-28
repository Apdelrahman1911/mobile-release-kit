#!/usr/bin/env python3
"""Fixed, source-bound installed Mac Aqua scopes; never a general runner.

Importing this module loads only stdlib DATA/parsers. The native main alone
admits the hosted user/source, prepares exclusive synthetic fixtures, and loads
the pinned current-source run_owned. No Store, release, alternate command or cleanup
controller is provided. Unknown invocation finality preserves the fixtures.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import hashlib
from importlib.machinery import ModuleSpec
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import FunctionType, ModuleType

CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")
IOS_CASES = ("ios-toolchain-prerequisite", "ios-version-stale", "ios-unsigned-archive", "ios-cancel", "ios-finality")
IOS_SIGNED_CASES = ("ios-signed-refusal", "ios-signed-cancel")
IOS_SESSION_CASES = ("ios-signing-inputs", *IOS_SIGNED_CASES)
IOS_INPUT_IDS = {"ios-signing-inputs": (2, 4, 6, 8, 9, 10, 11),
                 "ios-signed-refusal": (2, 7), "ios-signed-cancel": (2, 7)}
FILE_NATIVE_PANELS = {case: {f"Session(Native({index}))": identifier for index, identifier in enumerate(ids)}
                      for case, ids in IOS_INPUT_IDS.items()}
IOS_CURRENT_CASES = IOS_CASES + ("ios-signing-inputs", *IOS_SIGNED_CASES, "ios-recovery-empty")
IOS_OPERATION_CASES = IOS_CASES + IOS_SIGNED_CASES + ("ios-recovery-empty",)
PROJECT_FIELDS_CASE = "project-fields"
PROJECT_FIELD_CHOICES = (
    ("version.source", "version-source", "inputs/VERSION", None),
    ("ios.project", "ios-project", "ios/Example.xcodeproj", None),
    ("ios.workspace", "ios-workspace", "ios/Example.xcworkspace", None),
    ("metadata.root", "metadata-root", "metadata", None),
    ("version.source", "version-source", None, None),
    ("metadata.root", "metadata-root", None, None),
    ("version.source", "version-source", None, "project_path_unsafe"),
    ("version.source", "version-source", None, "project_path_unsafe"),
    ("version.source", "version-source", None, "project_path_unsafe"),
    ("ios.workspace", "ios-workspace", None, "project_path_changed"),
)
PROJECT_FIELD_PANELS = {f"ProjectFields(Native({i}))": (i + 2, choice[1])
                        for i, choice in enumerate(PROJECT_FIELD_CHOICES)}
ALL_CASES = CASES + IOS_CURRENT_CASES + (PROJECT_FIELDS_CASE,)
EXECUTABLE = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/MacOS/mobile-release-kit-desktop"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-aqua"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-aqua.yml@" + REF
MARKER = b"MRK_MACOS_AQUA_RESULT="
OUTPUT_LIMIT = 2 * 1024 * 1024
JSON_LIMIT = 16383
FAILURE_CONTEXT_LIMIT = 8192
TRACEBACK_LIMIT = 64
SCOPE = "programmatic genuine controls; no Store, release, distribution or physical-device evidence"
FAILURE_STEPS = frozenset((
    "Bootstrap Environment ReadEnvironment Dashboard ChooseCancel CancelProject CancelSettled ReadCancelled "
    "ChooseProject OpenProject ProjectSettled Snapshot Settings Suggest Suggestion Adopt Draft "
    "Validate Validation Preview Previewed RequirementsPage LoadRequirements Requirements GitHubPage "
    "GitHubRepository GitHubSha GitHubPropose GitHubProposal ReturnSettings KeepReviewing KeptReview "
    "ReadbackPage Refresh Readback SavedSettings ChangeDraft ChangedDraft MutateIgnore CloseCancel "
    "QuitCancel QuitCancelled RetainedReview Close Quit Exit PickerPending Reload Lost"
).split()) | frozenset(f"{name}({number})" for name in (
    "Prepare", "Review", "OpenConfirmation", "Confirmation", "Acknowledge", "Acknowledged", "Apply", "Applied") for number in (0, 1))
FAILURE_STEPS |= frozenset(f"Ios({name})" for name in (
    "Navigate SignedMode ReadVersion VersionRead Prepare Review Acknowledge Acknowledged MutateVersion Start Running Cancel Hold ReleaseHold Final"
).split())
FAILURE_STEPS |= frozenset(f"Session({name})" for name in (
    "Navigate Platform Purpose Open Ready Archive LockPage Lock ConfirmLock Locked Done"
).split()) | frozenset(f"Session({name}({number}))" for name in (
    "Kind Choose Native Chosen Fields Prepare Prepared Keep Kept Reassess Reassessed Bind Bound"
).split() for number in range(7)) | frozenset(
    f"Session({name}({number}, {kept}))" for name in ("Discard", "Discarded")
    for number in range(7) for kept in ("true", "false"))
FAILURE_STEPS |= frozenset(f"ProjectFields({name}({i}))" for name in (
    "Navigate Section Browse Native Chosen Read").split() for i in range(10)) | frozenset(
    f"ProjectFields({name})" for name in ("PreviewPage Preview Previewed Done").split())
FAILURE_REASONS = frozenset((
    "observer-invariant observer-deadline observer-record-unavailable observer-data-check "
    "dom-dispatch-refused dom-pending-custody dom-callback-size dom-callback-json "
    "dom-callback-object dom-callback-state picker-unexpected-result "
    "native-wrong-thread native-step native-pending-custody native-original-id native-kind native-not-started "
    "native-ineligible native-action-attempted native-action-returned native-callback-returned "
    "native-response-present native-selection-present native-close-attempted native-closed "
    "native-attachment-lost native-preaction-history native-dismissed native-duplicate-action "
    "native-ax-not-trusted native-ax-trust native-default-binding native-default-input native-default-custody native-default-deadline "
    "cancel-unexpected-project cancel-duplicate-result adapter-wrong-thread adapter-book-borrow "
    "adapter-original-call adapter-original-owner adapter-original-binding adapter-missing-facts "
    "adapter-missing-panel adapter-ineligible adapter-native-observation adapter-native-action "
    "asset_invalid_request asset_closed asset_unqualified asset_unsupported_platform "
    "asset_unsupported_filesystem asset_unsupported_format asset_busy asset_source_refused "
    "asset_source_changed asset_material_limit asset_parser_limit asset_project_overlap "
    "asset_exclusion_unconfirmed asset_capacity assessment_context_stale asset_user_cancelled "
    "asset_review_expired asset_deadline asset_document_lost asset_shutdown asset_cleanup_unknown "
    "project-result-shape project-result-order project-result-path project-result-name project-result-id "
    "snapshot-request-order snapshot-request-project "
    "snapshot-error-runtime snapshot-error-protocol snapshot-error-invalid snapshot-error-shutdown "
    "snapshot-error-timeout snapshot-error-cleanup snapshot-error-busy snapshot-error-unavailable "
    "snapshot-error-project snapshot-error-limit snapshot-error-io snapshot-error-engine snapshot-error-other "
    "snapshot-value-root snapshot-value-scope snapshot-config-path snapshot-value-assurance "
    "snapshot-value-issues snapshot-hints-android snapshot-hints-version snapshot-discovery-state "
    "snapshot-config-state snapshot-config-data snapshot-config-content snapshot-config-issues "
    "snapshot-return-order snapshot-return-project "
    "project-witness-identity project-witness-response project-witness-selection project-witness-callback "
    "edit-status-schema edit-status-generation edit-status-owner edit-status-projection "
    "relay-join-contract exit-edit-status exit-finality-contract observer-report-unavailable "
    "project-result-path-app-child project-result-path-descendant project-result-path-ancestor "
    "project-result-path-sibling project-result-path-tmp-spelling project-result-path-data-spelling "
    "native-completion-custody native-completion-data native-completion-unknown native-completion-selection "
    "ios-original-witness ios-request-contract ios-status-contract ios-version-contract "
    "ios-finality-contract ios-fixture-contract ios-dom-contract "
    "session-request-contract session-result-contract session-original-contract session-dom-contract "
    "project-fields-request-contract project-fields-result-contract project-fields-original-contract "
    "project-fields-fixture-contract project-fields-dom-contract"
).split())
PROJECT_SELECTION_CUSTODY = frozenset(("bound-original-data", "unavailable-original-data", "inconsistent-original-data"))
PROJECT_SELECTION_OBJECTS = frozenset(("fixture-root-all5", "captured-app-all5", "captured-release-all5",
                                     "captured-object-metadata-changed", "different-object", "unavailable"))
PROJECT_SELECTION_LOCATIONS = frozenset(("current-project", "current-app", "current-release", "other-case",
                                       "case-cwd", "case-home", "case-tmp", "namespace-other", "outside-namespace", "unavailable"))
# Only when saved native/registry/returned paths agree can the unchanged
# lexical failure reason constrain the selected-location axis this tightly.
PROJECT_SELECTION_BOUND_LOCATIONS = {
    "project-result-path": frozenset(("other-case", "case-cwd", "case-home", "case-tmp", "namespace-other", "outside-namespace")),
    "project-result-path-app-child": frozenset(("current-app",)),
    "project-result-path-descendant": frozenset(("current-release", "namespace-other")),
    "project-result-path-ancestor": frozenset(("namespace-other", "outside-namespace")),
    "project-result-path-sibling": frozenset(("other-case", "namespace-other")),
    "project-result-path-tmp-spelling": frozenset(("outside-namespace",)),
    "project-result-path-data-spelling": frozenset(("outside-namespace",)),
}
NATIVE_STEPS = frozenset("CancelProject OpenProject QuitCancel Quit PickerPending".split())
# Closed same-origin action DATA, not a panel query or an action/finality permit.
NATIVE_ACTION_STEPS = {
    "CancelProject": ("project-cancel", "project", (1,), 1),
    "QuitCancel": ("quit-cancel", "quit", (3,), 8),
    "Quit": ("quit-confirm", "quit", (2, 4), 16),
}
# site: (original native-return error, permitted action mask, can catch ObjC).
# None denotes an exception-only site. Keep aligned with the native decoder.
NATIVE_ACTION_SITES = {
    "main-thread": ("invalid-input", 63, False), "state-pointer": ("invalid-input", 63, False),
    "action-code": ("invalid-input", 63, False), "directory-argument": ("invalid-input", 63, False),
    "original-unknown": ("io", 63, False), "not-started": ("permission-denied", 63, False),
    "window-absent": ("permission-denied", 63, False), "parent-absent": ("permission-denied", 63, False),
    "completion-absent": ("permission-denied", 63, False), "responded": ("permission-denied", 63, False),
    "callback-active": ("permission-denied", 63, False), "close-attempted": ("permission-denied", 63, False),
    "closed": ("permission-denied", 63, False), "action-attempted": ("permission-denied", 63, False),
    "panel-kind": ("permission-denied", 63, False), "attachment": ("would-block", 63, True),
    "directory-already-bound": ("permission-denied", 2, False), "directory-path": ("invalid-input", 2, False),
    "directory-text": ("invalid-input", 2, True), "directory-url": ("invalid-input", 2, True),
    "directory-set": ("none", 2, True), "directory-unbound": ("permission-denied", 4, False),
    "directory-not-returned": ("permission-denied", 4, False), "directory-ready": ("would-block", 4, True),
    "alert-buttons": (None, 24, True), "alert-absent": ("permission-denied", 24, False),
    "button-count": ("permission-denied", 24, True), "button-index": (None, 24, True),
    "button-window": ("permission-denied", 24, True), "button-enabled": ("would-block", 24, True),
    "button-hidden": ("would-block", 24, True), "project-cancel": ("none", 1, True),
    "project-open": ("none", 4, True), "quit-cancel": ("none", 8, True), "quit-confirm": ("none", 16, True),
    "file-cancel": ("none", 32, True),
}
ACCESSIBILITY_CONTROL_LIMIT_SITES = frozenset((
    "control-title-limit control-child-count-limit control-child-copy-limit control-node-limit control-depth-limit"
).split())
ACCESSIBILITY_SITES = frozenset((
    "entry application windows parent-identifier sheet topology control-projection button control-recheck "
    "initial-original-proof original-proof admission press cleanup"
).split()) | ACCESSIBILITY_CONTROL_LIMIT_SITES
ACCESSIBILITY_CONTROL_ROLES = ("not-read", "Sheet", "Group", "SplitGroup", "Button",
                               "Browser", "Table", "Outline", "ScrollArea", "opaque")
ACCESSIBILITY_ERRORS = frozenset((
    "none wrong-thread invalid-input ineligible unsupported ambiguous malformed limit deadline custody "
    "invalid-element cannot-complete ax-other changed objc-exception cleanup-unknown"
).split())
ACCESSIBILITY_BINDING_CLASSES = frozenset(("nil", "match", "different", "type-invalid"))
ACCESSIBILITY_BINDING_SITES = frozenset((
    "objects", "parent-tag", "parent-set", "parent-get", "prompt-set", "prompt-get", "complete",
    "initial-directory-url", "initial-directory-set", "initial-temporary-close",
    "file-name-set", "file-name-get",
))
ACCESSIBILITY_PANEL_CLASSES = frozenset((
    "nil", "type-invalid", "empty", "byte-limit", "nul", "encoding-invalid", "valid", "match", "different",
))
ACCESSIBILITY_PROOF_CHECKS = (
    "eligible", "attached", "directory", "parentIdentifier", "panelIdentifier", "parentSingleton",
    "noNestedSheet", "nativeChild", "nativeParent", "nativeRole", "stableIdentifier", "finalEligibility",
)
ACCESSIBILITY_PROOF_SITES = frozenset((
    "objects attachment directory parent-identifier panel-identifier parent-sheets panel-sheets "
    "panel-attached-sheet native-children native-parent native-role stable-identifier final-eligibility complete"
).split())
ACCESSIBILITY_BUTTON_CHECKS = (
    "parentBound", "sheetBound", "completeControlProjection", "uniquePromptButton",
    "enabled", "pressAdvertised", "sameOriginalControlPathRechecked",
)
SOURCE = (b'plugins { id("com.android.application") }\n'
          b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
VERSION = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
KEEP = b"MRK_MACOS_AQUA_KEEP\n"
IGNORE_PREFIX = b"# MRK Mac Aqua user ignore\nuser-output/\n"
IGNORE_RULES = (b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n"
                b".mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n"
                b".mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n"
                b".mobile-release-version-prepare/\n.mobile-release-version/\n.mobile-release-version-cleanup/\n"
                b".mobile-release-metadata-images-prepare/\n.mobile-release-metadata-images/\n.mobile-release-metadata-images-cleanup/\n")
STALE = b"# MRK Mac Aqua stale base\n"
# Literal public fixture DATA, not another core configuration serializer.
CONFIG = b'''{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''

# Fixed credential-free iOS fixture bytes, mirrored by the native observer.
IOS_CONFIG = b'''{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
IOS_CONFIG_PREREQUISITE = b'''{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "prepareCommand": [
      "/usr/bin/false"
    ],
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
IOS_CONFIG_CANCEL = b'''{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "prepareCommand": [
      "/bin/sleep",
      "30"
    ],
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
# Fixed mechanical inputs, not valid Apple signing material or trust evidence.
# Same signature-less DER structures as credential_apple.rs's reviewed fixtures.
IOS_SYNTHETIC_P12 = bytes.fromhex(
    "3030020103302b06092a864886f70d010701a01e041c"
    "707269766174652d656e76656c6f70652d6f6e6c792d63616e617279")
IOS_SYNTHETIC_PROFILE = bytes.fromhex(
    "304306092a864886f70d010702a03630340201013100302b06092a864886f70d010701a01e041c"
    "707269766174652d656e76656c6f70652d6f6e6c792d63616e6172793100")
IOS_SYNTHETIC_FIREBASE = b'''<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>BUNDLE_ID</key><string>org.example.mrk.observed</string></dict></plist>
'''
IOS_CONFIG_SIGNED = b'''{
  "android": {"enabled": false},
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "distributionCertificateSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {"policy": "retain"},
    "teamId": "INERT12345"
  },
  "metadata": {"androidLocales": [], "iosLocales": ["en-US"], "root": "release/store"},
  "projectChecks": {"androidArtifact": [], "iosArtifact": [], "preflight": []},
  "schemaVersion": 1,
  "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
  "source": {"candidateBranch": "main", "productionBranch": "main"},
  "version": {"buildKey": "BUILD_NUMBER", "nameKey": "VERSION_NAME", "source": "version.properties"}
}
'''
IOS_CONFIG_INPUTS = IOS_CONFIG_SIGNED.replace(b'"iosFirebase": "disabled"', b'"iosFirebase": "required"')

IOS_PROJECT = b'''// !$*UTF8*$!
{
 archiveVersion = 1;
 classes = {};
 objectVersion = 56;
 objects = {
  000000000000000000000001 = {isa = PBXProject; attributes = {BuildIndependentTargetsInParallel = YES; LastUpgradeCheck = 1500;}; buildConfigurationList = 000000000000000000000002; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base); mainGroup = 000000000000000000000003; productRefGroup = 000000000000000000000004; projectDirPath = ""; projectRoot = ""; targets = (000000000000000000000005);};
  000000000000000000000002 = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000006); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;};
  000000000000000000000003 = {isa = PBXGroup; children = (000000000000000000000007, 000000000000000000000004, 000000000000000000000008); sourceTree = "<group>";};
  000000000000000000000004 = {isa = PBXGroup; children = (000000000000000000000009); name = Products; sourceTree = "<group>";};
  000000000000000000000005 = {isa = PBXNativeTarget; buildConfigurationList = 00000000000000000000000A; buildPhases = (00000000000000000000000B, 00000000000000000000000C, 00000000000000000000000D); buildRules = (); dependencies = (); name = MRKObserved; productName = MRKObserved; productReference = 000000000000000000000009; productType = "com.apple.product-type.application";};
  000000000000000000000006 = {isa = XCBuildConfiguration; buildSettings = {CLANG_ENABLE_OBJC_ARC = YES; SDKROOT = iphoneos;}; name = Release;};
  000000000000000000000007 = {isa = PBXGroup; children = (00000000000000000000000E, 00000000000000000000000F); path = MRKObserved; sourceTree = "<group>";};
  000000000000000000000008 = {isa = PBXGroup; children = (000000000000000000000010); name = Frameworks; sourceTree = "<group>";};
  000000000000000000000009 = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = MRKObserved.app; sourceTree = BUILT_PRODUCTS_DIR;};
  00000000000000000000000A = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000011); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;};
  00000000000000000000000B = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000012); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000C = {isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000013); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000D = {isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000E = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = main.m; sourceTree = "<group>";};
  00000000000000000000000F = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>";};
  000000000000000000000010 = {isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = UIKit.framework; path = System/Library/Frameworks/UIKit.framework; sourceTree = SDKROOT;};
  000000000000000000000011 = {isa = XCBuildConfiguration; buildSettings = {
   ARCHS = arm64;
   CODE_SIGNING_ALLOWED = NO;
   CODE_SIGNING_REQUIRED = NO;
   DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
   GCC_GENERATE_DEBUGGING_SYMBOLS = YES;
   INFOPLIST_FILE = MRKObserved/Info.plist;
   IPHONEOS_DEPLOYMENT_TARGET = 15.0;
   PRODUCT_BUNDLE_IDENTIFIER = org.example.mrk.observed;
   PRODUCT_NAME = MRKObserved;
   SKIP_INSTALL = NO;
   STRIP_INSTALLED_PRODUCT = NO;
   SUPPORTED_PLATFORMS = iphoneos;
   TARGETED_DEVICE_FAMILY = "1,2";
  }; name = Release;};
  000000000000000000000012 = {isa = PBXBuildFile; fileRef = 00000000000000000000000E;};
  000000000000000000000013 = {isa = PBXBuildFile; fileRef = 000000000000000000000010;};
 };
 rootObject = 000000000000000000000001;
}
'''
IOS_SCHEME = b'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1500" version="1.3">
 <BuildAction parallelizeBuildables="NO" buildImplicitDependencies="NO"><BuildActionEntries>
  <BuildActionEntry buildForTesting="NO" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="000000000000000000000005" BuildableName="MRKObserved.app" BlueprintName="MRKObserved" ReferencedContainer="container:MRKObserved.xcodeproj"/>
  </BuildActionEntry>
 </BuildActionEntries></BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="NO"/>
</Scheme>
'''
IOS_MAIN = b'''#import <UIKit/UIKit.h>
@interface MRKObservedDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation MRKObservedDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UIViewController alloc] init];
    self.window.rootViewController.view.backgroundColor = UIColor.systemBackgroundColor;
    [self.window makeKeyAndVisible];
    return YES;
}
@end
int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(MRKObservedDelegate.class)); }
}
'''
IOS_PLIST = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>CFBundleDevelopmentRegion</key><string>en</string>
 <key>CFBundleExecutable</key><string>$(EXECUTABLE_NAME)</string>
 <key>CFBundleIdentifier</key><string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
 <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
 <key>CFBundleName</key><string>$(PRODUCT_NAME)</string>
 <key>CFBundlePackageType</key><string>APPL</string>
 <key>CFBundleShortVersionString</key><string>$(MARKETING_VERSION)</string>
 <key>CFBundleVersion</key><string>$(CURRENT_PROJECT_VERSION)</string>
 <key>LSRequiresIPhoneOS</key><true/>
 <key>UILaunchScreen</key><dict/>
 <key>UISupportedInterfaceOrientations</key><array><string>UIInterfaceOrientationPortrait</string></array>
</dict></plist>
'''
IOS_WORKSPACE = b'''<?xml version="1.0" encoding="UTF-8"?>
<Workspace version="1.0"><FileRef location="self:"/></Workspace>
'''

OWNER_PINS = {
    "owned_process.py": "d832b81894372f3c48b110f6e381fe00f6d71b75940f63a3d7eb5d61c1e2fad1",
    "_command_process.py": "1ea5035578ae8ba0da31367f018d02b3669529077a65e2970cf92d1cc084b1c5",
    "_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "cancellation.py": "5f469444f42b5ad6a69ecce8161a7d83e67303c92a221a31f88c079f4ff29d35",
}


class Refused(Exception):
    """A fixed public diagnostic label, never an OS/path/child transcript."""


def need(condition, label):
    if not condition:
        raise Refused(label)


def digest(body):
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Binding:
    source: str
    run: str
    attempt: str

    def checked(self):
        need(type(self.source) is str and re.fullmatch(r"[0-9a-f]{40}", self.source), "source-binding")
        need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (self.run, self.attempt)), "run-binding")
        return self

    def root(self, *, project_fields=False):
        self.checked()
        need(type(project_fields) is bool, "scope-not-supported")
        suffix = "-project-fields" if project_fields else ""
        return Path("/private/tmp") / f"mrk-macos-aqua-{self.source}-{self.run}-{self.attempt}{suffix}"

    def public(self):
        return {"sourceCommit": self.source, "runId": self.run, "runAttempt": self.attempt}


def _expected_identity_proof():
    # Literal successful DATA shape, never a substitute for a native receipt.
    return {"returned": True, "attempted": True, "checks": dict.fromkeys(ACCESSIBILITY_PROOF_CHECKS, True),
            "parent": "match", "panel": "match", "children": 1, "originals": "one", "site": "complete", "error": "none"}


def _expected_prompt_button():
    # A literal parser fixture, not observed AX counts or a native receipt.
    return {"checks": dict.fromkeys(ACCESSIBILITY_BUTTON_CHECKS, True), "calls": 48,
            "initialNodesExamined": 2, "recheckNodesExamined": 2, "lastRole": "Button", "lastDepth": 1,
            "cfSlots": 32, "cfSlotsRetired": 32, "cleanupReturned": True, "axError": 0}


def _expected_completion_selection(case):
    # Literal parser DATA only. Browsing/Press never supplies this witness.
    return {"mechanism": "original-ok-singleton-selection-v1", "case": case,
            "id": 2 if case == "first-save" else 1, "kind": "project",
            "pollReturned": True, "pollResult": "responded", "timely": True,
            "facts": {"callbackEntered": True, "urlsReadEntered": True, "urlsReadReturned": True,
                      "callbackReturned": True, "duplicate": False, "nativeUnknown": False,
                      "response": "accept", "selection": "match"}}


def selected_cases(scope=None):
    need(scope in (None, "ios-unsigned-archive", "ios-current-synthetic", PROJECT_FIELDS_CASE), "scope-not-supported")
    if scope == PROJECT_FIELDS_CASE:
        return (PROJECT_FIELDS_CASE,)
    if scope == "ios-current-synthetic":
        return IOS_CURRENT_CASES
    return IOS_CASES if scope == "ios-unsigned-archive" else CASES


def argument_scope(argv):
    # Closed scopes only; no executable/path/env/timeout passthrough.
    need(type(argv) is list and (argv == [] or argv == ["--scope", "ios-unsigned-archive"]
                               or argv == ["--scope", "ios-current-synthetic"]
                               or argv == ["--scope", PROJECT_FIELDS_CASE]), "arguments-not-supported")
    return argv[1] if argv else None


def case_timeout(case):
    need(type(case) is str and case in ALL_CASES, "case-binding")
    return 325 if case in IOS_OPERATION_CASES else 60


def ios_config(case):
    need(case in IOS_CURRENT_CASES and case != "ios-recovery-empty", "ios-case")
    if case in IOS_SIGNED_CASES:
        return IOS_CONFIG_SIGNED
    if case == "ios-signing-inputs":
        return IOS_CONFIG_INPUTS
    return IOS_CONFIG_PREREQUISITE if case == IOS_CASES[0] else IOS_CONFIG_CANCEL if case == "ios-cancel" else IOS_CONFIG


def _ios_version_observation(case):
    return {"schemaVersion": 2, "source": "version.properties", "version": {"name": "1.2.3", "build": 7},
            "observationScope": "single-request-non-atomic",
            "assurance": {"basis": "static-text", "projectCodeExecuted": False, "toolsProbed": False,
                          "credentialsRead": False, "gitObserved": False, "storeContacted": False,
                          "writesPerformed": False, "releaseReadiness": "unknown"},
            "savedConfig": {"bytes": len(ios_config(case)), "sha256": digest(ios_config(case))},
            "savedVersion": {"bytes": len(VERSION), "sha256": digest(VERSION)}}


def _expected_signing_inputs(case):
    """Literal parser-test DATA; never substitutes for original native inputs."""
    need(case in IOS_SESSION_CASES, "signing-inputs-case")
    signed = case in IOS_SIGNED_CASES
    roles = ("p12", "profile") if signed else ("p12", "profile", "firebase", "overlap", "link", "public", "cancel")
    ids = IOS_INPUT_IDS[case]
    rows = []
    for index, (role, operation) in enumerate(zip(roles, ids)):
        assessment = None if index >= 3 else {
            "state": "format-valid" if index == 2 else "configured",
            "identity": "match" if index == 2 else "not-applicable",
            "fieldScopes": (("pfx-envelope", "value-admission"), ("cms-signed-data-envelope",),
                            ("plist-document", "firebase-shape", "application-identity"))[index]}
        if assessment is not None:
            assessment["fieldScopes"] = list(assessment["fieldScopes"])
        rows.append({"role": role, "kind": "apple-profile" if index == 1 else "ios-firebase" if index == 2 else "apple-p12",
                     "operationId": operation, "nativeResponse": "decline" if index == 6 else "accept",
                     "exactNativeSelection": None if index == 6 else True,
                     "source": "captured" if index < 3 else "pending" if index == 6 else "refused",
                     "reason": "none" if index < 3 else "project-overlap" if index == 3
                         else "user-cancelled" if index == 6 else "source-refused",
                     "originalWorkerAndNativeSettled": True,
                     "openIdentityMatched": None if index == 6 else True,
                     "openInputJoined": None if index == 6 else True,
                     "assessment": assessment, "recordId": ("d" if index == 0 else "e") * 32 if signed else None,
                     "keptRevision": 1 if signed else None, "assignedContextRevision": 1 if signed else None})
    return {"schemaVersion": 2, "oneUseOriginalDocumentRegistration": True,
            "selection": "ordinary-installed-macos-session", "mode": "session",
            "context": {"platform": "ios", "stage": "candidate", "purpose": "signing"}, "rows": rows,
            "originalOperations": 12, "allOriginalsSettled": True, "memorySessionLocked": True,
            "originalProjectAndQuitSettled": True, "observationMs": 315000 if signed else 45000,
            "outerInvocationMs": 325000 if signed else 60000}


def _signing_inputs(value, case):
    need(type(value) is dict, "signing-inputs-report")
    expected = _expected_signing_inputs(case)
    if case in IOS_SIGNED_CASES:
        try:
            rows = value["rows"]
            need(type(rows) is list and len(rows) == 2, "signing-inputs-rows")
            ids = [row["recordId"] for row in rows]
            need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in ids)
                 and len(set(ids)) == 2, "signing-inputs-records")
            for expected_row, record_id in zip(expected["rows"], ids):
                expected_row["recordId"] = record_id
        except (KeyError, TypeError, AttributeError) as error:
            raise Refused("signing-inputs-shape") from error
    _exact(value, expected, ("signingInputs",))
    return value


def _signing_policy_from_inputs(value):
    return {"teamId": "INERT12345", "distributionCertificateSha256": "c" * 64,
            "assignments": [{"kind": row["kind"], "recordId": row["recordId"],
                             "recordRevision": row["keptRevision"], "contextRevision": row["assignedContextRevision"]}
                            for row in value["rows"]]}


IOS_LIMITATIONS = ["saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
                  "unsigned-archive-not-an-ipa", "signing-and-profile-not-validated", "ipa-correspondence-not-validated",
                  "source-provenance-not-authenticated", "store-operation-not-requested", "release-readiness-not-assessed",
                  "retained-location-not-current-file-authority", "core-terminal-requires-original-native-finality"]


def _expected_ios_report(case):
    """Literal parser-test DATA, never a native receipt or a success producer."""
    if case in IOS_SIGNED_CASES or case == "ios-recovery-empty":
        return _expected_ios_account_report(case)
    need(case in IOS_CASES, "ios-report-case")
    version = _ios_version_observation(case)
    stale, cancel = case == "ios-version-stale", case == "ios-cancel"
    complete = case in ("ios-unsigned-archive", "ios-finality")
    operation, generation = "a" * 32, "b" * 32
    context = {"projectId": "inert-ios-parser", "draftRevision": 1, "baselineGeneration": 1,
               "savedConfig": version["savedConfig"], "savedVersion": {"source": "version.properties", "name": "1.2.3", "build": 7,
                   **version["savedVersion"]}, "platform": "ios", "operation": "ios-unsigned-archive"}
    facts = {key: True for key in (
        "inspectionJoined acquisitionJoined attempted childWaitedSuccess stdinClosed stdoutEofClosed stderrEofClosed ioJoined "
        "coreLifetimeSettled runtimeLedgerSettled toolsLedgerSettled nativeSettlementJoined nativeIntegrity "
        "driverJoined managerJoined observerJoined watchdogJoined retiredBeforeCutoff"
    ).split()}
    facts.update(operationId=operation, ownerGeneration=generation, activeRetained=False, resourceUnknown=False,
                 workMs=300000, hardMs=310000)
    no = {"outcome": "not-dispatched", "exitCode": None}
    zero = {"outcome": "exited", "exitCode": 0}
    commands = {"xcode-version": dict(no if stale else zero), "ios-sdk": dict(no if stale else zero),
                "archive": dict(zero if complete else no),
                "prepare": dict(no) if stale else {"outcome": "not-configured", "exitCode": None} if complete
                    else {"outcome": "unknown", "exitCode": None} if cancel else {"outcome": "exited", "exitCode": 1}}
    selection = None if stale else {"containerKind": "project", "container": "ios/MRKObserved.xcodeproj",
        "scheme": "MRKObserved", "configuration": "Release", "bundleId": "org.example.mrk.observed",
        "symbolsPolicy": "required", "preparationConfigured": not complete}
    result = None if not complete else {"schemaVersion": 1, "scope": "local-unsigned-ios-archive-observation",
        "usedConfig": context["savedConfig"], "usedVersion": context["savedVersion"],
        "archive": f".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive",
        "entries": 16, "bytes": 4096, "limitations": list(IOS_LIMITATIONS)}
    terminal = {"schemaVersion": 1, "context": context,
        "outcome": "complete" if complete else "refused" if stale else "cancelled" if cancel else "failed",
        "reason": "none" if complete else "saved-version-changed" if stale else "cancelled" if cancel else "command-failed",
        "activity": {"stage": "disposing-work" if complete else "accepted" if stale else "preparing", "selection": selection,
                     "commands": commands, "findings": [{"check": "archive-identity", "status": "PASS"},
                         {"check": "archive-dsym", "status": "PASS"}] if complete else []},
        "disposition": {"snapshot": "removed" if complete else "not-created", "work": "not-created" if stale else "removed",
                        "output": "retained-local-result" if complete else "not-created" if stale else "retained-incomplete",
                        "relativeDirectory": None if stale else f".mobile-release/desktop-ios-archive/{operation}"},
        "result": result,
        "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": not stale,
                     "commands": 0 if stale else 3, "profileCalls": 0, "stopObserved": "cancelled" if cancel else "none",
                     **dict.fromkeys(("inputClosed", "handlersRestored", "invocationClosed", "snapshotClosed", "filesClosed", "namespaceClosed"), True)}}
    held_facts = {**facts, "observerJoined": False, "watchdogJoined": False, "retiredBeforeCutoff": False, "activeRetained": True}
    return {"protocol": "mrk-ios-archive/1", "savedVersionObservation": version, "context": context,
            "prepareRequestedOnce": True, "prepareReturned": True, "reviewVisible": True, "acknowledged": True,
            "startRequestedOnce": True, "startReturned": True, "statusCallsReturned": 1,
            "staleVersionWriterReturnedAndClosed": stale,
            "original": {"facts": facts, "terminal": terminal}, "finalResultVisible": True,
            "prerequisiteOnly": case == "ios-toolchain-prerequisite",
            "cancel": {"requestedOnce": True, "returned": True, "stageAtClick": "preparing",
                       "prepareOutcome": commands["prepare"], "activeCommandKillClaimed": False} if cancel else None,
            "hold": {"original": {"facts": held_facts, "terminal": terminal}, "publicSuccessHidden": True,
                     "conflictingUiBlocked": True, "environmentDiagnosticsBlocked": True, "originalReleasedOnce": True} if case == "ios-finality" else None,
            "workMs": 300000, "hardMs": 310000, "observationMs": 315000, "outerInvocationMs": 325000}


def _expected_ios_account_report(case):
    """Closed synthetic refusal/recovery DATA, not successful signing evidence."""
    expected = _expected_ios_report("ios-toolchain-prerequisite")
    recovery, cancel = case == "ios-recovery-empty", case == "ios-signed-cancel"
    expected.update(protocol="mrk-ios-archive/3" if recovery else "mrk-ios-archive/2",
                    savedVersionObservation=None if recovery else _ios_version_observation(case),
                    prerequisiteOnly=False, workMs=120000, cleanupMs=240000, hardMs=250000)
    facts = expected["original"]["facts"]
    facts.update(workMs=120000, cleanupMs=240000, hardMs=250000, materialLoanPresent=False, materialLoanRetired=True)
    context = {"projectId": "inert-ios-parser", "platform": "ios", "operation": "ios-local-recovery",
               "recovery": {"action": "inspect"}} if recovery else {
        **expected["context"], "operation": "ios-signed-export", "savedConfig": expected["savedVersionObservation"]["savedConfig"],
        "signing": _signing_policy_from_inputs(_expected_signing_inputs(case))}
    expected["context"] = context
    lifetime = {**expected["original"]["terminal"]["lifetime"], "commandDispatched": not (recovery or cancel),
                "commands": 0 if recovery or cancel else 3, "profileCalls": 0 if recovery or cancel else 1,
                "stopObserved": "cancelled" if cancel else "none",
                "signingClosed": True, "buildInputsClosed": True, "materialRetired": True}
    if recovery:
        terminal = {"schemaVersion": 1, "context": context, "outcome": "complete", "reason": "none",
                    "activity": {"stage": "disposing-work"}, "lifetime": lifetime,
                    "report": {"schemaVersion": 1, "scope": "local-ios-recovery",
                               "account": {"status": "idle", "session": None, "next": "none"},
                               "project": {"status": "idle", "session": None, "next": "none"},
                               "limitations": ["local-recovery-only", "manual-recovery-not-supported",
                                               "user-confirmation-is-not-worker-finality", "no-store-operation"]}}
        expected["recoveryActions"] = {"idleRowsVisible": True, "ordinaryButtonsDisabled": True,
                                       "foreignMutationAttempted": False, "recoveryMutationClaimed": False}
    else:
        no = {"outcome": "not-dispatched", "exitCode": None}
        zero = {"outcome": "exited", "exitCode": 0}
        terminal = {"schemaVersion": 1, "context": context,
                    "outcome": "cancelled" if cancel else "failed", "reason": "cancelled" if cancel else "signing-validation-failed",
                    "activity": {"stage": "inputs-bound" if cancel else "validating-signing",
                                 "selection": {"containerKind": "project", "container": "ios/MRKObserved.xcodeproj",
                                               "scheme": "MRKObserved", "configuration": "Release",
                                               "bundleId": "org.example.mrk.observed", "symbolsPolicy": "retain",
                                               "preparationConfigured": False},
                                 "commands": {"xcode-version": dict(no if cancel else zero), "ios-sdk": dict(no if cancel else zero),
                                              "prepare": {"outcome": "not-configured", "exitCode": None},
                                              "archive": dict(no), "export": dict(no)},
                                 "findings": [] if cancel else [{"check": "profile-material", "status": "INVALID"}]},
                    "disposition": {"snapshot": "not-created", "work": "not-created" if cancel else "removed",
                                    "output": "not-created" if cancel else "retained-incomplete",
                                    "relativeDirectory": None if cancel else f".mobile-release/desktop-ios-archive/{facts['operationId']}"},
                    "result": None, "lifetime": lifetime}
        if cancel:
            expected["cancel"] = {"requestedOnce": True, "returned": True, "stageAtClick": "inputs-bound",
                                  "trigger": "original-inputs-bound", "boundary": {"stage": "inputs-bound",
                                      "operationId": facts["operationId"], "ownerGeneration": facts["ownerGeneration"], "originalTypedFrame": True},
                                  "activeCommandKillClaimed": False}
        else:
            held = {**facts, "observerJoined": False, "watchdogJoined": False, "retiredBeforeCutoff": False,
                    "activeRetained": True, "materialLoanPresent": True, "materialLoanRetired": False}
            expected["hold"] = {"original": {"facts": held, "terminal": terminal}, "publicSuccessHidden": True,
                                "conflictingUiBlocked": True, "environmentDiagnosticsBlocked": True, "originalReleasedOnce": True}
    expected["original"]["terminal"] = terminal
    return expected


def _ios_account_facts(value, expected, case, operation, generation):
    """Admit actual bounded varying counters; never accept unknown finality."""
    terminal, out = value["original"]["terminal"], expected["original"]["terminal"]
    lifetime = terminal["lifetime"]
    recovery, cancel = case == "ios-recovery-empty", case == "ios-signed-cancel"
    count, profiles, dispatched = lifetime["commands"], lifetime["profileCalls"], lifetime["commandDispatched"]
    need(type(count) is int and 0 <= count <= (32 if recovery else 4096)
         and type(profiles) is int and 0 <= profiles <= (0 if recovery else 1024)
         and type(dispatched) is bool and (count > 0 if dispatched else count <= 1), "ios-account-command-accounting")
    if recovery:
        out["lifetime"].update(commands=count, profileCalls=profiles, commandDispatched=dispatched)
        return
    policy = value["context"]["signing"]
    need(type(policy) is dict and type(policy.get("assignments")) is list and len(policy["assignments"]) == 2,
         "ios-signing-policy")
    ids = [row["recordId"] for row in policy["assignments"]]
    need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in ids) and len(set(ids)) == 2, "ios-signing-records")
    for row, record_id in zip(expected["context"]["signing"]["assignments"], ids):
        row["recordId"] = record_id
    if cancel:
        stages = ("inputs-bound", "checking-xcode", "validating-signing")
        stage = terminal["activity"]["stage"]
        need(stage in stages, "ios-signed-cancel-stage")
        out["activity"]["stage"] = stage
        clicked = value["cancel"]["stageAtClick"]
        need(clicked in stages and stages.index(clicked) <= stages.index(stage), "ios-signed-cancel-click")
        expected["cancel"]["stageAtClick"] = clicked
        expected["cancel"]["boundary"].update(operationId=operation, ownerGeneration=generation)
        for role in ("xcode-version", "ios-sdk"):
            command = terminal["activity"]["commands"][role]
            need(type(command) is dict and set(command) == {"outcome", "exitCode"}
                 and ((command["outcome"] in ("not-dispatched", "unknown") and command["exitCode"] is None)
                      or (command["outcome"] == "exited" and type(command["exitCode"]) is int and 0 <= command["exitCode"] <= 255)),
                 "ios-signed-cancel-command")
            out["activity"]["commands"][role] = dict(command)
        output, work = terminal["disposition"]["output"], terminal["disposition"]["work"]
        need(output in ("not-created", "retained-incomplete") and work in ("not-created", "removed")
             and (output != "not-created" or work == "not-created"), "ios-signed-cancel-output")
        out["disposition"].update(output=output, work=work,
            relativeDirectory=None if output == "not-created" else f".mobile-release/desktop-ios-archive/{operation}")
        # If cancellation raced with the material checker, retain its exact
        # known-invalid synthetic-profile finding, never an artifact check.
        findings = terminal["activity"]["findings"]
        need(findings in ([], [{"check": "profile-material", "status": "INVALID"}]), "ios-signed-cancel-findings")
        no = {"outcome": "not-dispatched", "exitCode": None}
        zero = {"outcome": "exited", "exitCode": 0}
        xcode, sdk = (out["activity"]["commands"][role] for role in ("xcode-version", "ios-sdk"))
        # Actual stage progression supplies prerequisites, not exact lifetime
        # command totals. A clicked UI stage may lag, but never lead, terminal.
        need(sdk == no or xcode == zero, "ios-signed-cancel-role-order")
        if stage == "inputs-bound":
            need(xcode == sdk == no, "ios-signed-cancel-before-xcode")
        if stage != "validating-signing":
            need(profiles == 0 and not findings, "ios-signed-cancel-before-validation")
        else:
            need(xcode == sdk == zero, "ios-signed-cancel-xcode-prerequisite")
        need(not findings or profiles >= 1, "ios-signed-cancel-profile-accounting")
        out["activity"]["findings"] = findings
    else:
        need(dispatched and count >= 2 and profiles >= 1, "ios-signing-validation-accounting")
    commands = out["activity"]["commands"].values()
    need(sum(command["outcome"] == "exited" for command in commands) <= count
         and (dispatched or all(command["outcome"] in ("not-dispatched", "not-configured") for command in commands)),
         "ios-signed-command-dispatch")
    out["lifetime"].update(commands=count, profileCalls=profiles, commandDispatched=dispatched)


def _ios_report(value, case):
    """Closed independent DATA parser. Only bounded actual varying facts vary."""
    need(type(value) is dict and case in IOS_OPERATION_CASES, "ios-report")
    expected = _expected_ios_report(case)
    try:
        facts, context, terminal = value["original"]["facts"], value["context"], value["original"]["terminal"]
        operation, generation = facts["operationId"], facts["ownerGeneration"]
        need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in (operation, generation)), "ios-original-identity")
        need(type(context["projectId"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", context["projectId"]), "ios-project-identity")
        for name in (() if case == "ios-recovery-empty" else ("draftRevision", "baselineGeneration")):
            need(type(context[name]) is int and 0 <= context[name] < 2**32 - 1, "ios-context-generation")
            expected["context"][name] = context[name]
        expected["context"]["projectId"] = context["projectId"]
        for snapshot in (expected["original"], *([expected["hold"]["original"]] if expected["hold"] else [])):
            snapshot["facts"].update(operationId=operation, ownerGeneration=generation)
        need(type(value["statusCallsReturned"]) is int and 0 <= value["statusCallsReturned"] <= 64, "ios-status-calls")
        expected["statusCallsReturned"] = value["statusCallsReturned"]
        out = expected["original"]["terminal"]
        if case != "ios-recovery-empty" and out["disposition"]["relativeDirectory"] is not None:
            out["disposition"]["relativeDirectory"] = f".mobile-release/desktop-ios-archive/{operation}"
        if case in ("ios-unsigned-archive", "ios-finality"):
            result = terminal["result"]
            need(type(result["entries"]) is int and 1 <= result["entries"] <= 1024
                 and type(result["bytes"]) is int and 1 <= result["bytes"] <= 128 * 1024 * 1024, "ios-fixture-archive-budget")
            out["result"].update(archive=f".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive",
                                  entries=result["entries"], bytes=result["bytes"])
        if case == "ios-cancel":
            prepare = terminal["activity"]["commands"]["prepare"]
            # Preparing may precede dispatch. A stopped original may also settle
            # without a usable exit result: command-result Unknown is NOT native
            # lifetime/custody Unknown. All exact original finality gates remain.
            need(type(prepare) is dict and set(prepare) == {"outcome", "exitCode"}
                 and ((prepare["outcome"] in ("not-dispatched", "unknown") and prepare["exitCode"] is None)
                      or (prepare["outcome"] == "exited" and type(prepare["exitCode"]) is int
                          and 0 <= prepare["exitCode"] <= 255)), "ios-cancel-prepare")
            count = terminal["lifetime"]["commands"]
            need(type(count) is int and count in ((2, 3) if prepare["outcome"] == "not-dispatched" else (3,)), "ios-cancel-command-count")
            out["activity"]["commands"]["prepare"] = dict(prepare)
            out["lifetime"]["commands"] = count
            expected["cancel"]["prepareOutcome"] = dict(prepare)
        if case in IOS_SIGNED_CASES or case == "ios-recovery-empty":
            _ios_account_facts(value, expected, case, operation, generation)
        _exact(value, expected, ("iosArchive",))
    except (KeyError, TypeError, AttributeError) as error:
        raise Refused("ios-report-shape") from error
    return value


def _expected_project_fields():
    """Closed comparison DATA, never the producer of a qualification receipt."""
    rows = []
    for i, (field, kind, relative, error) in enumerate(PROJECT_FIELD_CHOICES):
        accepted = i not in (4, 5)
        facts = 511 | 4096 | ((512 | 1024 | (2048 if kind == "version-source" else 0)) if accepted else 0)
        rows.append({"operationId": i + 2, "field": field, "kind": kind,
            "nativeResponse": "accept" if accepted else "decline",
            "initialRootAndOptions": {"result": "ok", "facts": facts},
            "laterSyntheticNavigation": accepted, "exactNativeSelection": True if accepted else None,
            "sourceBookStarted": accepted and i != 6, "originalSourceChildGuiAndCoordinatorSettled": True,
            "relativePath": relative, "errorCode": error, "draftObserved": True})
    return {"schemaVersion": 1, "oneUseOriginalDocumentRegistration": True, "normalProfileAvailable": False,
        "selection": "original-bound-installed-macos-project-fields", "rows": rows, "originalOperations": 12,
        "allOriginalsSettled": True, "completeDraftAndBaselineMatched": True,
        "previewValidation": "invalid-retained-ios-fields", "fixtureMutationsRestored": True,
        "shippingProfileEnabledByThisReceipt": False, "panelAttachments": [True] * 10, "controlReturns": [True] * 10,
        "acceptedOpenHistories": [{"operationId": identifier,
            "kind": "project" if identifier == 1 else PROJECT_FIELD_CHOICES[identifier - 2][1],
            "originalInputSucceeded": True, "originalBarrierRetired": True,
            "originalBindingMatched": True, "originalCompletionMatched": True}
            for identifier in (1, 2, 3, 4, 5, 8, 9, 10, 11)]}


def expected_result(binding, case):
    binding.checked()
    need(case in ALL_CASES, "case-binding")
    if case in IOS_CURRENT_CASES or case == PROJECT_FIELDS_CASE:
        value = expected_result(binding, "noop-stale")
        value.update(case=case, saveSessions=[], staleMarkerWriterReturnedAndClosed=False)
        if case in IOS_OPERATION_CASES:
            value["iosArchive"] = _expected_ios_report(case)
        if case in IOS_SESSION_CASES:
            value["signingInputs"] = _expected_signing_inputs(case)
        if case == PROJECT_FIELDS_CASE:
            value["projectFields"] = _expected_project_fields()
        value["native"]["projectOpenBinding"]["case"] = case
        value["native"]["projectCompletionSelection"]["case"] = case
        return value
    first, stale, lost = case == "first-save", case == "noop-stale", case in ("picker-loss", "save-loss")
    initial_ignore, saved_ignore = len(IGNORE_PREFIX), len(IGNORE_PREFIX + IGNORE_RULES)
    plans = {
        "create": [("release/mobile-release.json", "create", None, 684), (".gitignore", "append", initial_ignore, saved_ignore)],
        "preserve": [("release/mobile-release.json", "preserve", 684, 684), (".gitignore", "preserve", saved_ignore, saved_ignore)],
        "replace": [("release/mobile-release.json", "replace", 684, 690), (".gitignore", "preserve", saved_ignore, saved_ignore)],
    }
    rows = {
        "first-save": [(1, 1, "create", 2, True, "committed", "clean", "none", "none"),
                       (1, 2, "preserve", 0, False, "not_started", "not_created", "cancelled", "shutdown")],
        "noop-stale": [(1, 1, "preserve", 1, True, "unchanged", "not_created", "none", "none"),
                       (2, 1, "replace", 1, True, "not_started", "not_created", "stale_revision", "none")],
        "picker-loss": [],
        "save-loss": [(1, 1, "create", 0, False, "not_started", "not_created", "cancelled", "window_lost")],
    }
    sessions = []
    for draft, baseline, plan, confirmations, applied, effect, journal, reason, native in rows[case]:
        sessions.append({"draftRevision": draft, "baselineGeneration": baseline,
            "files": [dict(zip(("path", "action", "beforeBytes", "afterBytes"), row)) for row in plans[plan]],
            "createReleaseDirectory": plan == "create", "reviewMatched": True, "confirmationsOpened": confirmations,
            "acknowledged": applied, "apply": applied,
            "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": reason},
            "nativeReason": native, "nativeFinality": "settled", "writerFrames": 3 if applied else 2,
            "stdoutFrames": 3, "originalsJoined": True})
    return {"schemaVersion": 1, **binding.public(), "case": case, "instrumentedEngineeringApp": True,
        "shippingBinaryQualified": False, "distributionQualified": False, "methods": "ten-passive-with-session-assessment", "actionsAvailable": False,
        "native": {"projectCancelSettled": first, "selectedPathMatched": case != "picker-loss",
            "originalWindow": {"mechanism": "passive-original-window-callback-v1", "accessorReturned": True,
                "nativeReturned": True, "result": "ok", "admitted": True,
                "state": {"applicationPresent": True, "active": True, "mainPresent": True,
                    "originalMain": True, "ordinaryWindow": True, "noAttachedSheet": True}},
            "panelAttachments": [True, True, first, first],
            "controlReturns": [first, case != "picker-loss", first, True],
            "accessibilityTrustedWithoutPrompt": True,
            "projectOpenInput": None if case == "picker-loss" else {
                "mechanism": "accessibility-preconfigured-original-press-v5", "step": "OpenProject", "id": 2 if first else 1,
                "prepared": True, "requested": True, "dispatchAttempted": True, "state": "retired",
                "bodyEntered": True, "nativeEntered": True, "bodyReturned": True, "receiptJoined": True,
                "workerRegistered": True, "workerJoined": True, "rechecksSettled": True,
                "barrierRetired": True, "expired": False, "timely": True, "custodyKnown": True,
                "attempted": True, "pressReturned": True, "triggered": True,
                "initialOriginalProof": _expected_identity_proof(), "originalProof": _expected_identity_proof(),
                "promptChecks": {"initial": True, "final": True},
                "promptButton": _expected_prompt_button(), "site": "press", "error": "none"},
            "projectOpenBinding": None if case == "picker-loss" else {
                "mechanism": "preconfigured-original-sheet-v2", "case": case, "id": 2 if first else 1, "kind": "project",
                "start": {"returned": True, "result": "ok"},
                "configuration": {"attempted": True, "parentSetterEntered": True, "parentSetterReturned": True,
                    "promptSetterEntered": True, "promptSetterReturned": True,
                    "initialDirectorySetterEntered": True, "initialDirectorySetterReturned": True,
                    "parent": "match", "prompt": "match", "site": "complete", "error": "none"},
                "binding": _expected_identity_proof()},
            "projectCompletionSelection": None if case == "picker-loss" else _expected_completion_selection(case),
            "quitCancelKeptOriginalReview": first, "originalDocumentAndQuitSettled": True},
        "saveSessions": sessions, "freshCoreReadback": first, "syntheticFileReadback": True,
        "staleMarkerWriterReturnedAndClosed": stale,
        "reload": {"requested": lost, "dispatchReturned": lost, "navigationDenied": lost, "secondStarted": False,
            "originalLossSettled": lost, "webProcessCrashTested": False},
        "originalRelayJoined": True, "actualExit": True, "scope": SCOPE}


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-result-key")
        result[key] = value
    return result


# Public schema vocabulary only. Unknown future keys lose diagnostic detail,
# never validation. Neither report values nor unexpected keys enter this set.
RESULT_LOCATION_KEYS = frozenset((
    "accessibilityTrustedWithoutPrompt accessorReturned acknowledged action actionsAvailable active actualExit admitted "
    "afterBytes applicationPresent apply attempted axError barrierRetired baselineGeneration beforeBytes binding "
    "bodyEntered bodyReturned callbackEntered callbackReturned calls case cfSlots cfSlotsRetired checks children "
    "cleanupReturned configuration confirmationsOpened controlReturns createReleaseDirectory custodyKnown "
    "dispatchAttempted dispatchReturned distributionQualified draftRevision duplicate effect error expired facts files "
    "final freshCoreReadback id initial initialDirectorySetterEntered initialDirectorySetterReturned initialNodesExamined "
    "initialOriginalProof instrumentedEngineeringApp journal kind lastDepth lastRole mainPresent mechanism methods "
    "native nativeEntered nativeFinality nativeReason nativeReturned nativeUnknown navigationDenied noAttachedSheet "
    "ordinaryWindow originalDocumentAndQuitSettled originalLossSettled originalMain originalProof originalRelayJoined "
    "originalWindow originals originalsJoined outcome panel panelAttachments parent parentSetterEntered parentSetterReturned "
    "path pollResult pollReturned prepared pressReturned projectCancelSettled projectCompletionSelection projectOpenBinding "
    "projectOpenInput prompt promptButton promptChecks promptSetterEntered promptSetterReturned quitCancelKeptOriginalReview "
    "reason receiptJoined recheckNodesExamined rechecksSettled reload requested resources response result returned reviewMatched "
    "runAttempt runId saveSessions schemaVersion scope secondStarted selectedPathMatched selection shippingBinaryQualified "
    "site sourceCommit staleMarkerWriterReturnedAndClosed start state stdoutFrames step syntheticFileReadback timely triggered "
    "urlsReadEntered urlsReadReturned webProcessCrashTested workerJoined workerRegistered writerFrames"
).split()) | frozenset(ACCESSIBILITY_PROOF_CHECKS) | frozenset(ACCESSIBILITY_BUTTON_CHECKS)
RESULT_LOCATION_KEYS |= frozenset((
    "iosArchive protocol savedVersionObservation context prepareRequestedOnce prepareReturned reviewVisible "
    "startRequestedOnce startReturned statusCallsReturned staleVersionWriterReturnedAndClosed original terminal "
    "finalResultVisible prerequisiteOnly cancel requestedOnce stageAtClick prepareOutcome activeCommandKillClaimed "
    "hold publicSuccessHidden conflictingUiBlocked environmentDiagnosticsBlocked originalReleasedOnce "
    "workMs hardMs observationMs outerInvocationMs operationId ownerGeneration inspectionJoined acquisitionJoined "
    "childWaitedSuccess stdinClosed stdoutEofClosed stderrEofClosed ioJoined coreLifetimeSettled runtimeLedgerSettled "
    "toolsLedgerSettled nativeSettlementJoined nativeIntegrity driverJoined managerJoined observerJoined watchdogJoined "
    "retiredBeforeCutoff activeRetained resourceUnknown source version name build observationScope assurance basis "
    "projectCodeExecuted toolsProbed credentialsRead gitObserved storeContacted writesPerformed releaseReadiness "
    "savedConfig savedVersion bytes sha256 projectId platform operation activity commands xcode-version ios-sdk "
    "prepare archive exitCode containerKind container scheme bundleId symbolsPolicy preparationConfigured findings "
    "check status disposition snapshot work output relativeDirectory usedConfig usedVersion entries limitations "
    "lifetime complete fatal contained commandDispatched profileCalls stopObserved inputClosed handlersRestored "
    "invocationClosed snapshotClosed filesClosed namespaceClosed"
).split())
RESULT_LOCATION_KEYS |= frozenset((
    "projectFields normalProfileAvailable field initialRootAndOptions laterSyntheticNavigation "
    "sourceBookStarted originalSourceChildGuiAndCoordinatorSettled relativePath errorCode draftObserved "
    "completeDraftAndBaselineMatched previewValidation fixtureMutationsRestored shippingProfileEnabledByThisReceipt "
    "acceptedOpenHistories originalInputSucceeded originalBarrierRetired originalBindingMatched originalCompletionMatched"
).split())
RESULT_LOCATION_KEYS |= frozenset((
    "signingInputs oneUseOriginalDocumentRegistration mode rows role nativeResponse exactNativeSelection "
    "originalWorkerAndNativeSettled openIdentityMatched openInputJoined assessment identity fieldScopes "
    "recordId keptRevision assignedContextRevision originalOperations allOriginalsSettled memorySessionLocked "
    "originalProjectAndQuitSettled signing teamId distributionCertificateSha256 assignments recordRevision "
    "contextRevision purpose cleanupMs materialLoanPresent materialLoanRetired trigger boundary originalTypedFrame "
    "signingClosed buildInputsClosed materialRetired export recovery recoveryActions idleRowsVisible "
    "ordinaryButtonsDisabled foreignMutationAttempted recoveryMutationClaimed report account project session next"
).split())


def _result_location(parts):
    if type(parts) is not tuple or not 1 <= len(parts) <= 12 or type(parts[0]) is not str:
        return None
    result = ""
    for part in parts:
        if type(part) is str and part in RESULT_LOCATION_KEYS:
            result += ("." if result else "") + part
        elif type(part) is int and 0 <= part < 64:
            result += f"[{part}]"
        else:
            return None
    return result if len(result) <= 256 else None


def _result_need(condition, label, location):
    if not condition:
        error = Refused(label)
        try:
            error.result_location = location
        except BaseException:
            pass  # Diagnostic attachment cannot replace the original refusal.
        raise error


def _exact(actual, expected, location=()):
    # Python's True == 1 (and 1.0 == 1) must not accept substituted evidence.
    _result_need(type(actual) is type(expected), "result-type", location)
    if type(expected) is dict:
        _result_need(actual.keys() == expected.keys(), "result-keys", location)
        for key in expected:
            _exact(actual[key], expected[key], location + (key,))
    elif type(expected) is list:
        _result_need(len(actual) == len(expected), "result-count", location)
        for index, (left, right) in enumerate(zip(actual, expected)):
            _exact(left, right, location + (index,))
    else:
        _result_need(actual == expected, "result-value", location)


def parse_result(stdout, stderr, binding, case):
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= OUTPUT_LIMIT, "result-capture")
    need(not any(token in stream for stream in (stdout, stderr)
                 for token in (b"MRK_MACOS_AQUA_FAILURE", b"MRK_MACOS_AQUA=")), "inner-failure-marker")
    need(stdout.count(MARKER) == 1 and MARKER not in stderr, "result-marker-count")
    lines = stdout.split(b"\n")
    records = [line[len(MARKER):] for line in lines[:-1] if line.startswith(MARKER)]
    need(len(records) == 1 and 0 < len(records[0]) <= JSON_LIMIT and b"\r" not in records[0], "result-record")
    try:
        value = json.loads(records[0].decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("result-constant")))
    except (ValueError, RecursionError, UnicodeError) as error:
        raise Refused("result-json") from error
    expected = expected_result(binding, case)
    if case in IOS_OPERATION_CASES:
        need(type(value) is dict and "iosArchive" in value, "ios-report")
        expected["iosArchive"] = _ios_report(value["iosArchive"], case)
    if case in IOS_SESSION_CASES:
        need(type(value) is dict and "signingInputs" in value, "signing-inputs-report")
        expected["signingInputs"] = _signing_inputs(value["signingInputs"], case)
        if case in IOS_SIGNED_CASES:
            _exact(value["iosArchive"]["context"]["signing"], _signing_policy_from_inputs(value["signingInputs"]),
                   ("iosArchive", "context", "signing"))
    if case != "picker-loss":
        need(type(value) is dict and type(value.get("native")) is dict, "native-object")
        identity = _accessibility_binding_context(value["native"].get("projectOpenBinding"), case)
        need(identity is not None and identity["start"]["result"] == "ok" and identity["binding"] is not None
             and identity["binding"]["attempted"] and identity["binding"]["error"] == "none",
             "project-open-binding")
        # Original preparation and exact semantic action/return/receipt are
        # separate mandatory proofs; child counts remain actual native DATA.
        expected["native"]["projectOpenBinding"] = identity
        input_data = _accessibility_context(value["native"].get("projectOpenInput"), None, None,
                                            expected_id=identity["id"])
        need(input_data is not None and _accessibility_succeeded(input_data),
             "project-open-input")
        expected["native"]["projectOpenInput"] = input_data
        # A genuine original Press is input success only. The actual original
        # OK callback must independently return one exact, ordinary-path-agreeing
        # selection before any unchanged project/Save/finality gate may pass.
        completion = _completion_selection_context(value["native"].get("projectCompletionSelection"), case)
        need(completion is not None and _completion_selection_succeeded(completion),
             "project-completion-selection")
        expected["native"]["projectCompletionSelection"] = completion
    if case in ("picker-loss", "save-loss"):
        need(type(value) is dict and type(value.get("reload")) is dict, "reload-object")
        reload = value["reload"]
        denied, started = reload.get("navigationDenied"), reload.get("secondStarted")
        need(type(denied) is bool and type(started) is bool and (denied or started), "reload-loss-route")
        expected["reload"]["navigationDenied"], expected["reload"]["secondStarted"] = denied, started
    _exact(value, expected)
    return value


def _failure_row(stdout, stderr, marker, limit):
    """One complete row; count malformed/embedded/partial candidates too."""
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > OUTPUT_LIMIT:
        return None
    if sum(stream.count(marker) for stream in (stdout, stderr)) != 1:
        return None
    prefix = marker + b"="
    stream = stdout if marker in stdout else stderr
    start = stream.index(marker)
    if (start != 0 and stream[start - 1] != 10) or not stream.startswith(prefix, start):
        return None
    start += len(prefix)
    end = stream.find(b"\n", start)
    if not 0 < end - start <= limit:
        return None
    row = stream[start:end]
    return None if b"\r" in row else row


def failure_step(stdout, stderr):
    # Finite Rust Step labels only; never publish arbitrary child log text.
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_STEP", 40)
    if row is None:
        return None
    try:
        label = row.decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_STEPS else None


def failure_reason(stdout, stderr):
    """Optional closed DATA only; malformed/partial output never grants success."""
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_REASON", 48)
    if row is None:
        return None
    try:
        label = row.decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_REASONS else None


def _file_native_panels(case):
    return FILE_NATIVE_PANELS.get(case, {}) if type(case) is str else {}


def _file_open_step(case, identifier):
    # The seventh File panel is genuine Cancel, never an armed Open original.
    return next((step for step, original in _file_native_panels(case).items()
                 if original == identifier and step != "Session(Native(6))"), None)


def _field_native_panels(case):
    return PROJECT_FIELD_PANELS if case == PROJECT_FIELDS_CASE else {}


def _field_open_step(case, identifier):
    return next((step for step, (original, _) in _field_native_panels(case).items()
                 if original == identifier and original not in (6, 7)), None)


def _open_sample_kind(case, identifier, *, allow_files=False):
    if type(case) is not str or case not in ALL_CASES or case == "picker-loss" or type(identifier) is not int:
        return None
    if identifier == (2 if case == "first-save" else 1):
        return "project"
    if allow_files and _field_open_step(case, identifier) is not None:
        return PROJECT_FIELD_CHOICES[identifier - 2][1]
    return "file" if allow_files and _file_open_step(case, identifier) is not None else None


def _native_action_context(value, native, panel, *, case=None):
    # Missing/malformed new DATA loses only this diagnostic. Never replace the
    # existing context, first error, original return or unknown-finality facts.
    if value is None:
        return None
    try:
        need(type(value) is dict and set(value) == {"step", "id", "action", "domain", "site", "error"}, "native-action-data")
        need(all(type(value[key]) is str for key in ("step", "action", "domain", "site", "error"))
             and type(value["id"]) is int, "native-action-data")
        spec = NATIVE_ACTION_STEPS.get(value["step"])
        if value["step"] == "Quit" and type(case) is str and (case in IOS_SESSION_CASES or case == PROJECT_FIELDS_CASE):
            spec = ("quit-confirm", "quit", (12,), 16)
        elif value["step"] == "Session(Native(6))" and case == "ios-signing-inputs":
            spec = ("file-cancel", "file", (11,), 32)
        elif value["step"] == "ProjectFields(Native(4))" and case == PROJECT_FIELDS_CASE:
            spec = ("file-cancel", "version-source", (6,), 32)
        elif value["step"] == "ProjectFields(Native(5))" and case == PROJECT_FIELDS_CASE:
            spec = ("project-cancel", "metadata-root", (7,), 1)
        need(spec is not None and value["action"] == spec[0] and value["id"] in spec[2], "native-action-data")
        need(native is not None and native["entered"] and native["returned"] and native["step"] == value["step"]
             and panel is not None and panel["step"] == value["step"] and panel["id"] == value["id"]
             and panel["kind"] == spec[1], "native-action-data")
        domain, site, error = value["domain"], value["site"], value["error"]
        if domain == "rust-precondition":
            need(site == "original-usability" and error == "other", "native-action-data")
        else:
            rule = NATIVE_ACTION_SITES.get(site)
            need(rule is not None and rule[1] & spec[3], "native-action-data")
            need(domain == "native-return" and error == rule[0] and error not in (None, "none", "would-block")
                 or domain == "objc-exception" and rule[2] and error == "io", "native-action-data")
        return value
    except (Refused, TypeError, ValueError):
        return None


def _accessibility_native_proof(value):
    """Validate the closed DATA copied after one actual native body return."""
    label = "accessibility-native-proof"
    need(type(value) is dict and set(value) == {
        "returned", "attempted", "checks", "parent", "panel", "children", "originals", "site", "error"}, label)
    need(value["returned"] is True and type(value["attempted"]) is bool, label)
    checks = value["checks"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_PROOF_CHECKS)
         and all(v is None or type(v) is bool for v in checks.values()), label)
    for field, allowed in (("parent", ACCESSIBILITY_BINDING_CLASSES), ("panel", ACCESSIBILITY_PANEL_CLASSES),
                           ("originals", {"zero", "one", "multiple"})):
        need(value[field] is None or type(value[field]) is str and value[field] in allowed, label)
    children, site, error = value["children"], value["site"], value["error"]
    need(children is None or type(children) is int and 0 <= children <= 17, label)
    need(type(site) is str and site in ACCESSIBILITY_PROOF_SITES
         and type(error) is str and error in ACCESSIBILITY_ERRORS, label)
    if not value["attempted"]:
        need(all(v is None for v in checks.values())
             and all(value[key] is None for key in ("parent", "panel", "children", "originals"))
             and (site, error) == ("objects", "custody"), label)
    else:
        # Preserve the earlier successful first-value observation separately
        # from the later failed stability check. Only this exact returned
        # negative frame permits a final class different from valid/match.
        stable_failure = (site == "stable-identifier" and error == "changed"
            and all(checks[key] is True for key in ACCESSIBILITY_PROOF_CHECKS[:10])
            and checks["stableIdentifier"] is False and checks["finalEligibility"] is None
            and value["panel"] in ACCESSIBILITY_PANEL_CLASSES - {"valid", "match"})
        need(checks["eligible"] is not None
             and (checks["parentIdentifier"] is not True or value["parent"] == "match")
             and (checks["panelIdentifier"] is not True or value["panel"] in ("valid", "match") or stable_failure)
             and (checks["nativeChild"] is not True or type(children) is int and 1 <= children <= 16
                  and value["originals"] == "one")
             and (checks["stableIdentifier"] is not True or value["panel"] == "match"), label)
        need((site == "complete") == (error == "none"), label)
        if error == "none":
            need(all(v is True for v in checks.values()) and value["parent"] == value["panel"] == "match"
                 and type(children) is int and 1 <= children <= 16 and value["originals"] == "one", label)
    return value


def _accessibility_prompt_button(value):
    """Bounded returned AX/CF DATA, never a title, object or action permit."""
    label = "accessibility-prompt-button"
    need(type(value) is dict and set(value) == {"checks", "calls", "initialNodesExamined", "recheckNodesExamined",
                                               "lastRole", "lastDepth", "cfSlots", "cfSlotsRetired", "cleanupReturned", "axError"}, label)
    checks = value["checks"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_BUTTON_CHECKS)
         and all(type(v) is bool for v in checks.values()), label)
    ordered = tuple(checks[key] for key in ACCESSIBILITY_BUTTON_CHECKS)
    need(all(not flag or all(ordered[:index]) for index, flag in enumerate(ordered)), label)
    for key, maximum in (("calls", 512), ("initialNodesExamined", 16), ("recheckNodesExamined", 16), ("lastDepth", 8), ("cfSlots", 256)):
        need(type(value[key]) is int and 0 <= value[key] <= maximum, label)
    need(type(value["lastRole"]) is str and value["lastRole"] in ACCESSIBILITY_CONTROL_ROLES, label)
    need(type(value["cfSlotsRetired"]) is int and 0 <= value["cfSlotsRetired"] <= value["cfSlots"]
         and type(value["cleanupReturned"]) is bool, label)
    need(not value["cleanupReturned"] or value["cfSlotsRetired"] == value["cfSlots"], label)
    need(type(value["axError"]) is int and (value["axError"] == 0 or -25214 <= value["axError"] <= -25200), label)
    need(not (any(ordered) or value["lastRole"] != "not-read") or value["calls"] > 0 and value["cfSlots"] > 0, label)
    initial, recheck, depth = value["initialNodesExamined"], value["recheckNodesExamined"], value["lastDepth"]
    need(initial == 0 or checks["parentBound"] and checks["sheetBound"], label)
    need(not checks["completeControlProjection"] or initial >= 1, label)
    need(recheck == 0 or all(ordered[:6]), label)
    need(depth <= max(initial, recheck), label)
    need(not checks["sameOriginalControlPathRechecked"] or recheck >= 1 and value["lastRole"] == "Button"
         and 1 <= depth <= min(initial, recheck), label)
    return value


def _accessibility_succeeded(value):
    # A matching receipt alone never means that its input thread has joined.
    return (all(value[key] is True for key in ("prepared", "requested", "dispatchAttempted", "bodyEntered", "nativeEntered",
             "bodyReturned", "receiptJoined", "workerRegistered", "workerJoined", "rechecksSettled", "barrierRetired",
             "timely", "custodyKnown", "attempted", "pressReturned", "triggered"))
            and value["expired"] is False and value["state"] == "retired" and value["site"] == "press" and value["error"] == "none"
            and all(value[key] is not None and value[key]["error"] == "none" for key in ("initialOriginalProof", "originalProof"))
            and all(value["promptChecks"][key] is True for key in ("initial", "final"))
            and value["promptButton"] is not None and all(value["promptButton"]["checks"].values())
            and value["promptButton"]["cleanupReturned"] is True and value["promptButton"]["axError"] == 0
            and value["promptButton"]["cfSlotsRetired"] == value["promptButton"]["cfSlots"])


def _accessibility_context(value, native, panel, *, expected_id=None, case=None):
    if value is None:
        return None
    label = "accessibility-data"
    try:
        flags = ("prepared", "requested", "dispatchAttempted", "bodyReturned", "receiptJoined", "barrierRetired", "expired",
                 "workerRegistered", "workerJoined")
        observed = ("bodyEntered", "nativeEntered", "attempted", "pressReturned", "triggered", "timely", "custodyKnown", "rechecksSettled")
        need(type(value) is dict and set(value) == {"mechanism", "step", "id", "state", "site", "error",
             "initialOriginalProof", "originalProof", "promptChecks", "promptButton", *flags, *observed}, label)
        need(value["mechanism"] == "accessibility-preconfigured-original-press-v5" and type(value["id"]) is int, label)
        # The actual File OpenInput projection retains its historical
        # OpenProject label. Only failure DATA with an exact case/ID/native
        # panel binding may describe File; Project success callers stay closed.
        file_step = _file_open_step(case, value["id"]) if expected_id is None else None
        field_step = _field_open_step(case, value["id"]) if expected_id is None else None
        need(value["step"] == (field_step or "OpenProject")
             and (value["id"] in (1, 2) or file_step is not None or field_step is not None), label)
        if expected_id is not None:
            need(value["id"] == expected_id, label)
        elif field_step is not None:
            need(native is not None and native["step"] == field_step and native["entered"] and native["returned"]
                 and panel is not None and panel["step"] == field_step and panel["id"] == value["id"]
                 and panel["kind"] == PROJECT_FIELD_PANELS[field_step][1], label)
        elif file_step is not None:
            need(native is not None and native["step"] == file_step and native["entered"] and native["returned"]
                 and panel is not None and panel["step"] == file_step and panel["kind"] == "file"
                 and panel["id"] == value["id"], label)
        else:
            need(native is not None, label)
            if native["step"] == "OpenProject":
                need(native["entered"] and native["returned"] and panel is not None and panel["step"] == "OpenProject"
                     and panel["kind"] == "project" and panel["id"] == value["id"], label)
        need(all(type(value[key]) is bool for key in flags)
             and all(value[key] is None or type(value[key]) is bool for key in observed), label)
        state, site, error = value["state"], value["site"], value["error"]
        need(type(state) is str and state in ("prepared", "requested", "queued", "entered", "returned", "joined", "retired", "unknown"), label)
        need(site is None or type(site) is str and site in ACCESSIBILITY_SITES, label)
        need(error is None or type(error) is str and error in ACCESSIBILITY_ERRORS, label)
        need((site is None) == (error is None), label)
        need(not value["requested"] or value["prepared"], label)
        need(not value["dispatchAttempted"] or value["requested"] and value["workerRegistered"], label)
        need(not value["workerJoined"] or value["workerRegistered"], label)
        need(value["bodyEntered"] is not True or value["dispatchAttempted"], label)
        need(value["nativeEntered"] is not True or value["bodyEntered"] is True, label)
        need(not value["bodyReturned"] or value["bodyEntered"] is True, label)
        need(not value["receiptJoined"] or value["bodyReturned"] and value["workerJoined"]
             and value["rechecksSettled"] is True, label)
        no_entry = (not value["dispatchAttempted"] and value["bodyEntered"] is False
                    and not value["bodyReturned"] and value["nativeEntered"] is False)
        need(not value["barrierRetired"] or value["prepared"] and (value["receiptJoined"] or no_entry)
             and value["rechecksSettled"] is not False
             and (not value["workerRegistered"] or value["workerJoined"] and value["rechecksSettled"] is True), label)
        # Phase is current custody; monotonic facts cannot be erased by Unknown.
        if state == "unknown":
            need(value["custodyKnown"] is False, label)
        elif state == "retired":
            need(value["barrierRetired"] and value["custodyKnown"] is True, label)
        else:
            need(not value["barrierRetired"], label)
            ordinal = ("prepared", "requested", "queued", "entered", "returned", "joined").index(state)
            need(value["requested"] == (ordinal >= 1) and value["dispatchAttempted"] == (ordinal >= 2)
                 and value["bodyReturned"] == (ordinal >= 4) and value["receiptJoined"] == (ordinal >= 5), label)
            need(value["bodyEntered"] is True if ordinal >= 3 else value["bodyEntered"] in (None, False), label)
            if ordinal < 4:
                need(value["custodyKnown"] is not True, label)
            elif ordinal == 4:
                need(value["custodyKnown"] is not False, label)
            else:
                need(value["custodyKnown"] is True, label)
        need(not value["expired"] or value["timely"] is not True, label)
        need(value["attempted"] is not True or value["nativeEntered"] is True and value["bodyReturned"], label)
        need(value["pressReturned"] is not True or value["attempted"] is True, label)
        need((value["triggered"] is not None) == (value["pressReturned"] is True), label)
        need(error not in ("custody", "objc-exception", "cleanup-unknown") or value["custodyKnown"] is not True, label)
        proofs = (value["initialOriginalProof"], value["originalProof"])
        prompt = value["promptChecks"]
        need(type(prompt) is dict and set(prompt) == {"initial", "final"}
             and all(item is None or type(item) is bool for item in prompt.values()), label)
        for index, (proof, name) in enumerate(zip(proofs, ("initial", "final"))):
            if proof is not None:
                need(value["bodyReturned"] and value["nativeEntered"] is True, label)
                _accessibility_native_proof(proof)
                need(index == 0 or proofs[0] is not None and proofs[0]["error"] == "none" and prompt["initial"] is True, label)
            if prompt[name] is not None:
                need(proof is not None and proof["error"] == "none", label)
        button = value["promptButton"]
        if button is not None:
            need(value["bodyReturned"] and value["nativeEntered"] is True, label)
            _accessibility_prompt_button(button)
            need(button["calls"] == 0 or proofs[0] is not None
                 and proofs[0]["error"] == "none" and prompt["initial"] is True, label)
            need(button["cleanupReturned"] or value["custodyKnown"] is not True
                 and not value["receiptJoined"] and not value["barrierRetired"], label)
        need(proofs[1] is None or button is not None and all(button["checks"].values()), label)
        ready = (all(p is not None and p["error"] == "none" for p in proofs)
                 and prompt == {"initial": True, "final": True} and button is not None and all(button["checks"].values()))
        need(value["attempted"] is not True or ready and site in ("press", "cleanup"), label)
        if value["nativeEntered"] is False:
            need(all(p is None for p in proofs) and all(p is None for p in prompt.values()) and button is None
                 and value["attempted"] is False and value["pressReturned"] is False and value["triggered"] is None, label)
        elif value["nativeEntered"] is None:
            need(all(p is None for p in proofs) and all(p is None for p in prompt.values()) and button is None
                 and value["attempted"] is None and value["pressReturned"] is None and value["triggered"] is None, label)
        else:
            need(value["bodyReturned"], label)
        if not value["bodyReturned"]:
            need(all(p is None for p in proofs) and all(p is None for p in prompt.values()) and button is None
                 and value["triggered"] is None, label)
        if value["triggered"] is False:
            need(button is not None and button["axError"] != 0 and error not in (None, "none"), label)
        elif value["triggered"] is True:
            need(button is not None and button["axError"] == 0, label)
        if error == "none":
            need(site == "press" and value["attempted"] is True and value["pressReturned"] is True
                 and value["triggered"] is True and ready and button["axError"] == 0 and button["cleanupReturned"], label)
        if error == "cannot-complete":
            need(button is not None and button["axError"] == -25204, label)
        if error == "invalid-element":
            need(button is not None and button["axError"] == -25202, label)
        if site in ("control-projection", "button", "control-recheck"):
            need(button is not None, label)
            completed = sum(button["checks"].values())
            need((site == "control-projection" and completed in (2, 3) and button["recheckNodesExamined"] == 0)
                 or (site == "button" and completed in (4, 5, 6) and button["recheckNodesExamined"] == 0)
                 or (site == "control-recheck" and completed == 6 and button["lastDepth"] <= button["recheckNodesExamined"]), label)
        if site in ACCESSIBILITY_CONTROL_LIMIT_SITES:
            # Count/Copy can fail at the root or after deeper nodes began.
            # Preserve both actual counters and current role/depth even through
            # late/Unknown cleanup; no local diagnostic can supply proof.
            need(error == "limit" and button is not None and button["axError"] == 0
                 and button["calls"] > 0 and button["cfSlots"] > 0
                 and proofs[0] is not None and proofs[0]["error"] == "none" and proofs[1] is None
                 and prompt == {"initial": True, "final": None} and value["attempted"] is False
                 and value["pressReturned"] is False and value["triggered"] is None, label)
            ordered = tuple(button["checks"][key] for key in ACCESSIBILITY_BUTTON_CHECKS)
            initial = ordered == (True, True, False, False, False, False, False)
            recheck = ordered == (True, True, True, True, True, True, False)
            need(initial and button["recheckNodesExamined"] == 0 or recheck and button["initialNodesExamined"] >= 1, label)
            examined = button["initialNodesExamined"] if initial else button["recheckNodesExamined"]
            depth, role = button["lastDepth"], button["lastRole"]
            node = 1 <= depth <= 8 and examined >= depth
            container = role in ("Group", "SplitGroup") and node
            need((site == "control-title-limit" and role == "Button" and node)
                 or (site in ("control-child-count-limit", "control-child-copy-limit")
                     and (container or role == "Sheet" and depth == 0 and examined == 0))
                 or (site == "control-node-limit" and container and depth < 8)
                 or (site == "control-depth-limit" and container and depth == 8), label)
        for name, proof in (("initial-original-proof", proofs[0]), ("original-proof", proofs[1])):
            if site == name and proof is not None and proof["error"] != "none":
                need(proof["error"] == error, label)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _accessibility_binding_context(value, case, *, allow_files=False):
    """Closed original-return DATA; never a permission, action or finality fact."""
    if value is None:
        return None
    try:
        label = "accessibility-binding-data"
        need(type(case) is str and case in ALL_CASES and case != "picker-loss", label)
        need(type(value) is dict and set(value) == {
            "mechanism", "case", "id", "kind", "start", "configuration", "binding"}, label)
        kind = _open_sample_kind(case, value["id"], allow_files=allow_files)
        need(value["mechanism"] == "preconfigured-original-sheet-v2" and value["case"] == case
             and kind is not None and value["kind"] == kind, label)
        start, configured, bound = value["start"], value["configuration"], value["binding"]
        need(type(start) is dict and set(start) == {"returned", "result"} and start["returned"] is True
             and type(start["result"]) is str
             and start["result"] in ("ok", "permission-denied", "io", "invalid-input", "already", "other"), label)
        flags = ("parentSetterEntered", "parentSetterReturned", "promptSetterEntered", "promptSetterReturned",
                 "initialDirectorySetterEntered", "initialDirectorySetterReturned")
        file_flags = ("fileNameSetterEntered", "fileNameSetterReturned") if kind == "file" else ()
        need(type(configured) is dict and set(configured) == {"attempted", *flags, *file_flags, "parent", "prompt", "site", "error"}
             and all(type(configured[key]) is bool for key in ("attempted", *flags, *file_flags)), label)
        parent, prompt, site, error = (configured[key] for key in ("parent", "prompt", "site", "error"))
        need(parent is None or type(parent) is str and parent in ACCESSIBILITY_BINDING_CLASSES, label)
        need(prompt is None or type(prompt) is str and prompt in ACCESSIBILITY_BINDING_CLASSES, label)
        need(site is None or type(site) is str and site in ACCESSIBILITY_BINDING_SITES, label)
        need(error is None or type(error) is str and error in ACCESSIBILITY_ERRORS, label)
        bits = tuple(configured[key] for key in flags)
        file_bits = tuple(configured[key] for key in file_flags)
        all_bits = bits + file_bits
        need(all(not flag or all(all_bits[:index]) for index, flag in enumerate(all_bits)), label)
        if kind == "file":
            need(configured["attempted"] and (site in ("file-name-set", "file-name-get", "complete")
                 or file_bits == (False, False)), label)
        if not configured["attempted"]:
            need(not any(bits) and parent is prompt is site is error is None and start["result"] != "ok", label)
        else:
            need(start["result"] in ("ok", "io") and site is not None and error is not None, label)
            if site in ("objects", "parent-tag"):
                need(not any(bits) and parent is prompt is None
                     and error in (("ineligible",) if site == "objects" else ("invalid-input", "objc-exception")), label)
            elif site == "parent-set":
                need(bits == (True, False, False, False, False, False) and parent is prompt is None and error == "objc-exception", label)
            elif site == "parent-get":
                need(bits == (True, True, False, False, False, False) and parent is prompt is None and error == "objc-exception", label)
            elif site == "prompt-set":
                need(bits == (True, True, True, False, False, False) and parent is not None and prompt is None and error == "objc-exception", label)
            elif site == "prompt-get":
                need(bits == (True, True, True, True, False, False) and parent is not None
                     and (prompt is None and error == "objc-exception" or prompt is not None and prompt != "match" and error == "changed"), label)
            elif site == "initial-directory-url":
                need(bits == (True, True, True, True, False, False) and parent is not None and prompt == "match"
                     and error in ("invalid-input", "objc-exception"), label)
            elif site == "initial-directory-set":
                need(bits == (True, True, True, True, True, False) and parent is not None and prompt == "match"
                     and error == "objc-exception", label)
            elif site == "initial-temporary-close":
                need(kind in ("version-source", "ios-project", "ios-workspace", "metadata-root")
                     and bits in ((True, True, True, True, False, False), (True, True, True, True, True, False),
                                  (True, True, True, True, True, True))
                     and parent is not None and prompt == "match" and error == "cleanup-unknown", label)
            elif site == "file-name-set":
                need(kind == "file" and all(bits) and file_bits == (True, False) and parent is not None
                     and prompt == "match" and error == "objc-exception", label)
            elif site == "file-name-get":
                need(kind == "file" and all(bits) and file_bits == (True, True) and parent is not None
                     and prompt == "match" and error in ("changed", "objc-exception"), label)
            else:
                need(site == "complete" and all(all_bits) and parent is not None and prompt == "match" and error == "none", label)
            if start["result"] == "ok":
                need(site == "complete" and error == "none", label)
        if bound is not None:
            need(start["result"] == "ok", label)
            _accessibility_native_proof(bound)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _completion_selection_context(value, case, *, allow_files=False):
    """Saved same-original poll DATA, including returned errors, never a join."""
    if value is None:
        return None
    try:
        label = "completion-selection-data"
        need(type(case) is str and case in ALL_CASES and case != "picker-loss", label)
        need(type(value) is dict and set(value) == {
            "mechanism", "case", "id", "kind", "pollReturned", "pollResult", "timely", "facts"}, label)
        kind = _open_sample_kind(case, value["id"], allow_files=allow_files)
        need(value["mechanism"] == "original-ok-singleton-selection-v1" and value["case"] == case
             and kind is not None and value["kind"] == kind and value["pollReturned"] is True
             and type(value["timely"]) is bool and type(value["pollResult"]) is str
             and value["pollResult"] in ("showing", "responded", "closed", "error", "invalid-return"), label)
        facts = value["facts"]
        if facts is not None:
            flags = ("callbackEntered", "urlsReadEntered", "urlsReadReturned", "callbackReturned", "duplicate", "nativeUnknown")
            need(type(facts) is dict and set(facts) == {*flags, "response", "selection"}
                 and all(type(facts[key]) is bool for key in flags), label)
            response, selection = facts["response"], facts["selection"]
            need(response is None or type(response) is str and response in ("accept", "decline", "other"), label)
            need(selection is None or type(selection) is str and selection in (
                "empty", "malformed", "multiple", "different", "ordinary-path-disagreement", "match"), label)
            if not facts["callbackEntered"]:
                need(not any(facts[key] for key in flags[:-1]) and response is selection is None, label)
            need(not facts["urlsReadEntered"] or response == "accept", label)
            need(not facts["urlsReadReturned"] or facts["urlsReadEntered"], label)
            need(selection is None or facts["urlsReadReturned"], label)
            need(not facts["duplicate"] or facts["nativeUnknown"], label)
            if not facts["nativeUnknown"]:
                need(facts["callbackEntered"] and facts["callbackReturned"] and response is not None, label)
                if response == "accept":
                    need(facts["urlsReadReturned"] and selection is not None, label)
                else:
                    need(not facts["urlsReadEntered"] and selection is None, label)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _completion_selection_succeeded(value):
    # Unknown/late/unavailable DATA may explain a failure but never resolve it.
    # This predicate receives only a closed, case/id-bound decoded sample.
    if value is None or value["pollResult"] != "responded" or value["timely"] is not True:
        return False
    facts = value["facts"]
    return (facts is not None and all(facts[key] is True for key in (
                "callbackEntered", "urlsReadEntered", "urlsReadReturned", "callbackReturned"))
            and facts["duplicate"] is False and facts["nativeUnknown"] is False
            and facts["response"] == "accept" and facts["selection"] == "match")


def _original_window_context(value):
    if value is None:
        return None  # No returned sample, not a nil/inactive native observation.
    label = "original-window-context"
    need(type(value) is dict and set(value) == {"mechanism", "accessorReturned", "nativeReturned",
                                               "result", "admitted", "state"}, label)
    need(type(value["mechanism"]) is str and value["mechanism"] == "passive-original-window-callback-v1"
         and type(value["accessorReturned"]) is bool and value["accessorReturned"]
         and type(value["nativeReturned"]) is bool and type(value["admitted"]) is bool
         and type(value["result"]) is str
         and value["result"] in ("ok", "accessor-error", "entry-refused", "native-error", "invalid-return"), label)
    need(value["nativeReturned"] == (value["result"] != "accessor-error"), label)
    state = value["state"]
    if value["result"] != "ok":
        need(state is None and not value["admitted"], label)
    else:
        need(type(state) is dict and set(state) == {"applicationPresent", "active", "mainPresent",
                                                  "originalMain", "ordinaryWindow", "noAttachedSheet"}
             and all(type(fact) is bool for fact in state.values()), label)
        need(state["applicationPresent"] or not any(state.values()), label)
        need(state["mainPresent"] or not any(state[key] for key in
             ("originalMain", "ordinaryWindow", "noAttachedSheet")), label)
        # A positive read returned after failure/expiry can be truthful DATA
        # with admitted=False; it still cannot satisfy successful case evidence.
        need(not value["admitted"] or all(state.values()), label)
    return value


def _project_selection_context(value, source, step, reason, case):
    """Saved relational DATA, never a path, fresh identity or native receipt."""
    label = "project-selection-context"
    need(type(value) is dict and set(value) == {"custody", "recordedObject", "lexicalLocation"}
         and all(type(part) is str for part in value.values()), label)
    custody, recorded, location = value["custody"], value["recordedObject"], value["lexicalLocation"]
    need(custody in PROJECT_SELECTION_CUSTODY and recorded in PROJECT_SELECTION_OBJECTS
         and location in PROJECT_SELECTION_LOCATIONS, label)
    need(source == "record" and step in ("OpenProject", "ProjectSettled")
         and reason in PROJECT_SELECTION_BOUND_LOCATIONS
         and (case is None or type(case) is str and case in ("first-save", "noop-stale", "save-loss")), label)
    if custody == "bound-original-data":
        need(recorded != "unavailable" and location in PROJECT_SELECTION_BOUND_LOCATIONS[reason], label)
    elif custody == "unavailable-original-data":
        need(recorded == "unavailable" or location == "unavailable", label)
    need(location != "current-project" or custody == "inconsistent-original-data", label)
    # Only noop-stale captured a release directory before this original return.
    need(recorded != "captured-release-all5" or case is None or case == "noop-stale", label)
    return value


def _field_preparation_context(value, case, step):
    if value is None:
        return None
    try:
        need(case == PROJECT_FIELDS_CASE and type(value) is dict
             and set(value) == {"operationId", "kind", "returned", "result", "facts"}, "project-field-preparation-data")
        identifier = value["operationId"]
        need(type(identifier) is int and 2 <= identifier <= 11
             and value["kind"] == PROJECT_FIELD_CHOICES[identifier - 2][1] and value["returned"] is True
             and step in (f"ProjectFields(Native({identifier - 2}))", f"ProjectFields(Chosen({identifier - 2}))")
             and type(value["result"]) is str and value["result"] in (
                 "ok", "permission-denied", "io", "invalid-input", "would-block", "already", "invalid-return"),
             "project-field-preparation-data")
        flags = value["facts"]
        need(flags is None or type(flags) is int and 0 <= flags <= 8191
             and (flags == 0 or flags & 257 == 257) and (not flags & 512 or flags & 511 == 511)
             and (not flags & 1024 or flags & 512) and (not flags & 2048 or flags & 1024)
             and (value["result"] != "would-block" or flags == 0), "project-field-preparation-data")
        return value
    except (Refused, KeyError, TypeError):
        return None  # Diagnostic loss cannot become success or replace failure.


def failure_context(stdout, stderr, case=None):
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_CONTEXT", FAILURE_CONTEXT_LIMIT)
    if row is None:
        return None
    try:
        value = json.loads(row.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("failure-context")))
        need(type(value) is dict and set(value) - {"accessibilityBinding", "snapshotSource", "originalWindow", "projectSelection", "completionSelection", "projectFieldPreparation"} in (
            {"pending", "nativeHandler", "lastPanel"},
            {"pending", "nativeHandler", "lastPanel", "nativeAction"},
            {"pending", "nativeHandler", "lastPanel", "nativeAction", "accessibility"}), "failure-context")
        if "snapshotSource" in value:
            need(type(value["snapshotSource"]) is str and value["snapshotSource"] in ("record", "prearm-open-progress"), "failure-context")
        if "originalWindow" in value:
            value["originalWindow"] = _original_window_context(value["originalWindow"])
        if "projectSelection" in value:
            value["projectSelection"] = _project_selection_context(value["projectSelection"], value.get("snapshotSource"),
                failure_step(stdout, stderr), failure_reason(stdout, stderr), case)
        if "completionSelection" in value:
            # Only the saved original Record can carry this post-poll sample.
            # No native handler/Press receipt is invented to fill missing DATA.
            value["completionSelection"] = (_completion_selection_context(value["completionSelection"], case, allow_files=True)
                                             if value.get("snapshotSource") == "record" else None)
        if "projectFieldPreparation" in value:
            value["projectFieldPreparation"] = _field_preparation_context(value["projectFieldPreparation"], case, failure_step(stdout, stderr))
        pending, native, panel = value["pending"], value["nativeHandler"], value["lastPanel"]
        file_panels, field_panels = _file_native_panels(case), _field_native_panels(case)
        native_steps = NATIVE_STEPS | file_panels.keys() | field_panels.keys()
        if pending is not None:
            need(type(pending) is dict and set(pending) == {"kind", "step"}
                 and type(pending["kind"]) is str, "failure-context")
            kind, step = pending["kind"], pending["step"]
            allowed = {"dom": FAILURE_STEPS, "native": native_steps,
                       "accessibility": {"OpenProject"} | {step for step, (identifier, _) in field_panels.items() if identifier not in (6, 7)},
                       "close": {"Close", "CloseCancel"}}
            need(kind in ("reload", "failure-close") and step is None
                 or kind in allowed and type(step) is str and step in allowed[kind], "failure-context")
        if native is not None:
            need(type(native) is dict and set(native) == {"step", "entered", "returned"}
                 and type(native["step"]) is str and native["step"] in native_steps
                 and type(native["entered"]) is bool and type(native["returned"]) is bool
                 and (not native["returned"] or native["entered"]), "failure-context")
        if panel is not None:
            need(type(panel) is dict and set(panel) == {"step", "id", "kind", "parentPresent", "panelPresent",
                                                      "parentReferencesPanel", "panelReferencesParent", "panelVisible"}
                 and native is not None and native["entered"] and panel["step"] == native["step"]
                 and type(panel["id"]) is int and type(panel["kind"]) is str
                 and type(panel["parentPresent"]) is bool and type(panel["panelPresent"]) is bool, "failure-context")
            if panel["kind"] in {choice[1] for choice in PROJECT_FIELD_CHOICES} or panel["step"] in field_panels:
                need(panel["step"] in field_panels and (panel["id"], panel["kind"]) == field_panels[panel["step"]], "failure-context")
            elif panel["kind"] == "file" or panel["step"] in file_panels:
                need(panel["kind"] == "file" and panel["step"] in file_panels
                     and panel["id"] == file_panels[panel["step"]], "failure-context")
            elif panel["step"] == "Quit" and type(case) is str and (case in IOS_SESSION_CASES or case == PROJECT_FIELDS_CASE):
                need(panel["kind"] == "quit" and panel["id"] == 12, "failure-context")
            else:
                need(1 <= panel["id"] <= 4 and panel["kind"] in ("project", "quit"), "failure-context")
            both = panel["parentPresent"] and panel["panelPresent"]
            need(all(type(panel[key]) is bool if both else panel[key] is None
                     for key in ("parentReferencesPanel", "panelReferencesParent"))
                 and (type(panel["panelVisible"]) is bool if panel["panelPresent"] else panel["panelVisible"] is None),
                 "failure-context")
        if "nativeAction" in value:
            value["nativeAction"] = _native_action_context(value["nativeAction"], native, panel, case=case)
        if "accessibility" in value:
            value["accessibility"] = _accessibility_context(value["accessibility"], native, panel, case=case)
        if value.get("snapshotSource") == "prearm-open-progress":
            sample = value.get("accessibility")
            field_step = _field_open_step(case, sample["id"]) if sample is not None else None
            native_step = field_step or (_file_open_step(case, sample["id"]) if sample is not None else None) or "OpenProject"
            # The fixed pre-arm original fields are historical, while only the
            # one atomic progress/expiry sample was refreshed at the deadline.
            need(pending == {"kind": "accessibility", "step": field_step or "OpenProject"}
                 and "projectSelection" not in value and "completionSelection" not in value
                 and native == {"step": native_step, "entered": True, "returned": True}
                 and sample is not None and sample["prepared"] and sample["requested"]
                 and sample["expired"] and sample["timely"] is False
                 and all(sample[key] is None for key in ("nativeEntered", "attempted", "pressReturned", "triggered",
                      "initialOriginalProof", "originalProof", "promptButton", "site", "error"))
                 and sample["promptChecks"] == {"initial": None, "final": None}, "failure-context")
        if "accessibilityBinding" in value:
            # Early start failure legitimately has no nativeHandler/lastPanel
            # or Press sample. Bind to the known case, not to invented actions.
            value["accessibilityBinding"] = _accessibility_binding_context(value["accessibilityBinding"], case, allow_files=True)
        return value
    except (Refused, ValueError, RecursionError, UnicodeError, TypeError):
        return None


def _original_exception_diagnostics(error, run_owned, case, cwd):
    """Private CI/source-pin seam: reduce only the original call's buffers.

    No import, engine method, cause traversal, outcome/finality query or raw
    output escape. Missing/changed owner contracts fail closed. The source is
    pinned by load_owner before this callable can be the original owner.
    """
    try:
        if type(case) is not str or case not in ALL_CASES:
            return None
        argv = (EXECUTABLE, case)  # Do not trust the mutable list supplied to the call.
        source = Path(__file__).absolute().parents[2] / "src" / "mobile_release"
        modules = []
        for name in ("owned_process", "_command_process"):
            module = sys.modules.get("mobile_release." + name)
            if type(module) is not ModuleType:
                return None
            namespace = vars(module)
            expected = str(source / (name + ".py"))
            spec = namespace.get("__spec__")
            if (namespace.get("__name__") != "mobile_release." + name
                    or namespace.get("__file__") != expected or type(spec) is not ModuleSpec or spec.origin != expected):
                return None
            modules.append(namespace)
        owner, command = modules
        function = command.get("run_command")
        if (type(run_owned) is not FunctionType or owner.get("run_owned") is not run_owned
                or run_owned.__globals__ is not owner or run_owned.__code__.co_filename != owner["__file__"]
                or type(function) is not FunctionType or function.__globals__ is not command
                or function.__code__.co_filename != command["__file__"]):
            return None
        original = None
        trace = error.__traceback__
        for _ in range(TRACEBACK_LIMIT):
            if trace is None:
                break
            frame = trace.tb_frame
            if frame.f_code is function.__code__:
                if frame.f_globals is not command or original is not None and frame is not original:
                    return None
                original = frame  # Re-raising can repeat this identical frame.
            trace = trace.tb_next
        if trace is not None or original is None:
            return None
        local = original.f_locals  # Python 3.14 can supply FrameLocalsProxy.
        engine = local.get("engine")
        if type(engine) is not command.get("_Outer"):
            return None
        actual = local.get("argv")
        if (type(actual) is not list or len(actual) != 2 or any(type(arg) is not str for arg in actual)
                or tuple(actual) != argv or type(local.get("cwd")) is not type(cwd) or local["cwd"] != cwd
                or type(local.get("timeout")) is not int or local["timeout"] != case_timeout(case)
                or local.get("capture") is not True or local.get("text") is not False
                or type(local.get("output_limit")) is not int or local["output_limit"] != OUTPUT_LIMIT):
            return None
        frozen = engine.frozen
        if type(frozen) is not command.get("FrozenCommand") or type(frozen.manifest) is not command.get("Manifest"):
            return None
        if (type(frozen.args) is not tuple or len(frozen.args) != 2
                or any(type(arg) is not str for arg in frozen.args) or frozen.args != argv
                or type(frozen.argv) is not tuple or len(frozen.argv) != 2 or any(type(arg) is not bytes for arg in frozen.argv)
                or frozen.argv != tuple(arg.encode("ascii") for arg in argv)
                or type(frozen.cwd) is not bytes or frozen.cwd != str(cwd).encode("ascii")
                or frozen.manifest.capture is not True or type(frozen.manifest.limit) is not int
                or frozen.manifest.limit != OUTPUT_LIMIT or engine.text is not False):
            return None
        outputs = engine.outputs
        if (type(outputs) is not list or len(outputs) != 2 or any(type(part) is not bytearray for part in outputs)
                or len(outputs[0]) + len(outputs[1]) > OUTPUT_LIMIT):
            return None
        stdout, stderr = bytes(outputs[0]), bytes(outputs[1])
        # The copies are immediately reduced; none is retained/exported by the
        # caller. Buffer availability never means EOF or original finality.
        reduced = (failure_step(stdout, stderr), failure_reason(stdout, stderr), failure_context(stdout, stderr, case))
        return reduced if any(part is not None for part in reduced) else None
    except BaseException:
        return None  # Extraction must never mask the original invocation error.


@dataclass(frozen=True)
class Node:
    # dev, inode, complete mode, uid, gid, nlink, size, mtime_ns, ctime_ns.
    identity: tuple
    sha256: str | None
    entries: tuple | None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fixture_data(case, final, *, ios_output_created=None):
    need(case in ALL_CASES and type(final) is bool, "fixture-case")
    if case in IOS_CURRENT_CASES:
        return ios_fixture_data(case, final, output_created=ios_output_created)
    need(ios_output_created is None, "fixture-output-kind")
    if case == PROJECT_FIELDS_CASE:
        return {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
            ".gitignore": IGNORE_PREFIX + IGNORE_RULES, "release/mobile-release.json": CONFIG,
            "inputs/VERSION": VERSION, "inputs/link-input": b"MRK_PROJECT_FIELD_LINK_ORIGINAL\n",
            "inputs/kind-input": b"MRK_PROJECT_FIELD_KIND_ORIGINAL\n"}, {
            ".": (0o700, (".gitignore", "app", "inputs", "ios", "keep.txt", "metadata", "release", "version.properties")),
            "app": (0o700, ("build.gradle.kts",)), "inputs": (0o700, ("VERSION", "kind-input", "link-input")),
            "ios": (0o700, ("Example.xcodeproj", "Example.xcworkspace")), "ios/Example.xcodeproj": (0o700, ()),
            "ios/Example.xcworkspace": (0o700, ()), "metadata": (0o700, ()), "release": (0o755, ("mobile-release.json",))}
    saved = case == "noop-stale" or final and case == "first-save"
    files = {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
             ".gitignore": IGNORE_PREFIX + (IGNORE_RULES if saved else b"") + (STALE if final and case == "noop-stale" else b"")}
    directories = {".": (0o700, (".gitignore", "app", "keep.txt", "version.properties")),
                   "app": (0o700, ("build.gradle.kts",))}
    if saved:
        files["release/mobile-release.json"] = CONFIG
        directories["."] = (0o700, (".gitignore", "app", "keep.txt", "release", "version.properties"))
        directories["release"] = (0o755, ("mobile-release.json",))
    return files, directories


def ios_fixture_data(case, final, *, output_created=None):
    need(case in IOS_CURRENT_CASES and type(final) is bool, "fixture-case")
    need(output_created is None or type(output_created) is bool and final and case in IOS_SIGNED_CASES,
         "fixture-output-kind")
    if case == "ios-recovery-empty":
        return {".gitignore": IGNORE_PREFIX + b".mobile-release/\n", "keep.txt": KEEP}, {
            ".": (0o700, (".gitignore", "keep.txt"))}
    if final and case in IOS_SIGNED_CASES:
        need(type(output_created) is bool, "fixture-original-disposition-required")
    files = {".gitignore": IGNORE_PREFIX + b".mobile-release/\n", "keep.txt": KEEP,
             "version.properties": b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n" if final and case == "ios-version-stale" else VERSION,
             "release/mobile-release.json": ios_config(case), "ios/MRKObserved.xcodeproj/project.pbxproj": IOS_PROJECT,
             "ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme": IOS_SCHEME,
             "ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata": IOS_WORKSPACE,
             "ios/MRKObserved/main.m": IOS_MAIN, "ios/MRKObserved/Info.plist": IOS_PLIST}
    root = (".gitignore", "ios", "keep.txt", "release", "version.properties")
    if case == "ios-signing-inputs":
        files["overlap.p12"] = IOS_SYNTHETIC_P12
        root = tuple(sorted((*root, "overlap.p12")))
    if final and (case in IOS_CASES and case != "ios-version-stale" or output_created is True):
        root = tuple(sorted((*root, ".mobile-release")))
    directories = {".": (0o700, root), "ios": (0o700, ("MRKObserved", "MRKObserved.xcodeproj")),
        "ios/MRKObserved": (0o700, ("Info.plist", "main.m")),
        "ios/MRKObserved.xcodeproj": (0o700, ("project.pbxproj", "project.xcworkspace", "xcshareddata")),
        "ios/MRKObserved.xcodeproj/project.xcworkspace": (0o700, ("contents.xcworkspacedata",)),
        "ios/MRKObserved.xcodeproj/xcshareddata": (0o700, ("xcschemes",)),
        "ios/MRKObserved.xcodeproj/xcshareddata/xcschemes": (0o700, ("MRKObserved.xcscheme",)),
        "release": (0o755, ("mobile-release.json",))}
    return files, directories


def _shape(snapshot, case, final, uid, gid, *, ios_output_created=None):
    files, directories = fixture_data(case, final, ios_output_created=ios_output_created)
    need(type(snapshot) is dict and snapshot.keys() == files.keys() | directories.keys(), "fixture-roster")
    for path, node in snapshot.items():
        need(type(node) is Node and type(node.identity) is tuple and len(node.identity) == 9
             and all(type(v) is int and v >= 0 for v in node.identity), "fixture-identity")
        facts = node.identity
        need(facts[3:5] == (uid, gid), "fixture-owner")
        if path in files:
            need(facts[2] == stat.S_IFREG | 0o600 and facts[5] == 1 and facts[6] == len(files[path])
                 and node.sha256 == digest(files[path]) and node.entries is None, "fixture-file")
        else:
            mode, entries = directories[path]
            need(facts[2] == stat.S_IFDIR | mode and node.sha256 is None and node.entries == entries, "fixture-directory")


def validate_snapshot(original, current, case, final, uid, gid, *, ios_output_created=None):
    _shape(original, case, False, uid, gid)
    _shape(current, case, final, uid, gid, ios_output_created=ios_output_created)
    for path, before in original.items():
        after = current[path]
        if before.entries is not None:
            need(after.identity[:5] == before.identity[:5], "fixture-directory-replaced")
        elif final and case == "first-save" and path == ".gitignore":
            need(after.identity[:2] != before.identity[:2], "save-ignore-not-replaced")
        elif final and case == "noop-stale" and path == ".gitignore":
            need(after.identity[:6] == before.identity[:6], "stale-ignore-replaced")
        elif final and case == "ios-version-stale" and path == "version.properties":
            need(after.identity[:7] == before.identity[:7], "stale-version-replaced")
        elif final and case == PROJECT_FIELDS_CASE and path in ("inputs/link-input", "inputs/kind-input"):
            # Exclusive rename/restoration changes original ctime, never its
            # inode, ownership, mode, size, link count, mtime or file contents.
            need(after.identity[:8] == before.identity[:8] and after.identity[8] >= before.identity[8], "project-field-original-not-restored")
        else:
            need(after.identity == before.identity, "fixture-original-changed")
    result = {"completeRoster": True, "expectedBytesAndModes": True, "originalIdentitiesMatched": True,
            "transactionResidueAbsent": True,
            "files": len(fixture_data(case, final, ios_output_created=ios_output_created)[0]),
            "configSha256": current.get("release/mobile-release.json").sha256 if "release/mobile-release.json" in current else None,
            "ignoreSha256": current[".gitignore"].sha256, "ignoreBytes": current[".gitignore"].identity[6]}
    if case == PROJECT_FIELDS_CASE:
        result["projectFieldRestoration"] = {"originalFileMetadataExceptRenameCtimeMatched": True,
            "allowedRenameCtimeChanges": [name for name in ("inputs/link-input", "inputs/kind-input")
                if current[name].identity[8] != original[name].identity[8]], "rootModeRestored": True,
            "sameDirectoryOriginals": all(before.identity[:6] == current[path].identity[:6]
                for path, before in original.items() if before.entries is not None)}
        need(result["projectFieldRestoration"]["sameDirectoryOriginals"], "project-field-original-directory-changed")
    return result


def app_environment(state, uid, username):
    need(type(uid) is int and uid > 0 and type(username) is str
         and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "native-user")
    return {"HOME": str(state / "home"), "TMPDIR": str(state / "tmp") + "/",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
            "USER": username, "LOGNAME": username, "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"}


def signing_fixture_inputs(case):
    """Closed synthetic files outside the selected project; no real credential."""
    need(case in IOS_SESSION_CASES, "signing-fixture-case")
    files = {"synthetic.p12": (IOS_SYNTHETIC_P12, 0o600),
             "synthetic.mobileprovision": (IOS_SYNTHETIC_PROFILE, 0o600)}
    if case == "ios-signing-inputs":
        files.update({"GoogleService-Info.plist": (IOS_SYNTHETIC_FIREBASE, 0o600),
                      "public.p12": (IOS_SYNTHETIC_P12, 0o644)})
    return files, {"linked.p12": "synthetic.p12"} if case == "ios-signing-inputs" else {}


class Fixtures:
    """Finite helper-owned file custody, never process/Store custody."""

    def __init__(self, binding, uid, gid, scope=None):
        self.binding, self.uid, self.gid = binding, uid, gid
        self.cases = selected_cases(scope)
        self.path = binding.root(project_fields=(scope == PROJECT_FIELDS_CASE))
        self.fds = set()
        self.close_errors = 0
        self.first_close_error = None
        self.inflight = False
        self.last_returned = False
        self.app_returncode = self.inner_failure_step = self.inner_failure_reason = None
        self.inner_failure_context = self.inner_diagnostic_source = None
        self.case = None
        self.stage = "prepare"
        self.projects, self.states, self.originals, self.input_originals, self.field_outside_originals = {}, {}, {}, {}, {}

    def _open(self, name, parent=None, *, directory=False, create=False):
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        flags |= os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, 0o600, dir_fd=parent)
        self.fds.add(fd)
        need(not os.get_inheritable(fd), "fixture-descriptor-inheritance")
        return fd

    def _close(self, fd):
        need(fd in self.fds, "fixture-close-not-original")
        self.fds.remove(fd)  # This original close is never repeated on error.
        try:
            os.close(fd)
            return True
        except BaseException as error:
            self.close_errors += 1
            if self.first_close_error is None:
                self.first_close_error = error
            return False

    @contextmanager
    def _temporary(self, fd):
        original_error = None
        try:
            yield fd
        except BaseException as error:
            original_error = error
            raise
        finally:
            closed = self._close(fd)
            if not closed and original_error is None:
                raise self.first_close_error

    def _mkdir(self, parent, name, mode=0o700):
        os.mkdir(name, 0o700, dir_fd=parent)  # Refuse occupied paths; never adopt.
        fd = self._open(name, parent, directory=True)
        original = signature(os.fstat(fd))
        need(signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original
             and original[2] == stat.S_IFDIR | 0o700 and original[3] == self.uid,
             "fixture-created-directory-custody")
        # Darwin can inherit the parent's group even without setgid. Normalize
        # only this fresh, private, caller-owned original, before widening it.
        if original[4] != self.gid:
            os.fchown(fd, -1, self.gid)
        current = signature(os.fstat(fd))
        need(current[:4] == original[:4] and current[4] == self.gid,
             "fixture-created-directory-group")
        self._named(parent, name, fd, 0o700)
        if mode != 0o700:
            os.fchmod(fd, mode)  # Only this newly and exclusively created dir.
            self._named(parent, name, fd, mode)
        return fd

    def _named(self, parent, name, fd, mode):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        info = os.fstat(fd)
        need(signature(before) == signature(info) and info.st_mode == stat.S_IFDIR | mode
             and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-directory-custody")

    def _write(self, parent, name, body, *, mode=0o600):
        need(mode in (0o600, 0o644), "fixture-write-mode")
        with self._temporary(self._open(name, parent, create=True)) as fd:
            info = os.fstat(fd)
            need(info.st_mode == stat.S_IFREG | 0o600 and info.st_nlink == 1
                 and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-created-file")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(count > 0, "fixture-write")
                offset += count
            if mode == 0o644:
                # Only this exclusively created synthetic permission-refusal
                # fixture is public. Never repair or change a supplied input.
                os.fchmod(fd, mode)
            current = os.fstat(fd)
            need(current.st_mode == stat.S_IFREG | mode
                 and signature(current) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 "fixture-write-original")

    def prepare(self):
        self.parent = self._open("/private/tmp", directory=True)
        p = os.fstat(self.parent)
        need(p.st_mode == stat.S_IFDIR | 0o1777 and p.st_uid == 0, "temporary-parent")
        self.root = self._mkdir(self.parent, self.path.name)
        self.state = self._mkdir(self.root, "state")
        for case in self.cases:
            project = self._mkdir(self.root, case)
            self.projects[case] = project
            files, directories = fixture_data(case, False)
            with ExitStack() as children:
                opened = {".": project}
                # Closed literal roster, parents before children. No selected
                # arbitrary project, pathname adoption, or source overwrite.
                for path, (mode, _) in directories.items():
                    if path == ".":
                        continue
                    parent, _, name = path.rpartition("/")
                    opened[path] = children.enter_context(self._temporary(self._mkdir(opened[parent or "."], name, mode)))
                for path, body in files.items():
                    parent, _, name = path.rpartition("/")
                    self._write(opened[parent or "."], name, body)
            state = self._mkdir(self.state, case)
            self.states[case] = state
            for child in ("home", "tmp"):
                with self._temporary(self._mkdir(state, child)):
                    pass
            if case in IOS_SESSION_CASES:
                with self._temporary(self._mkdir(state, "inputs")) as inputs:
                    external_files, links = signing_fixture_inputs(case)
                    for name, (body, mode) in external_files.items():
                        self._write(inputs, name, body, mode=mode)
                    for name, target in links.items():
                        os.symlink(target, name, dir_fd=inputs)
                self.input_originals[case] = self._capture_inputs(case)
            if case == PROJECT_FIELDS_CASE:
                with self._temporary(self._mkdir(state, "outside")) as outside:
                    self._write(outside, "VERSION", VERSION)
                self.field_outside_originals[case] = self._capture_field_outside(case)
            self.originals[case] = self._capture(case, False)
        self._namespace()

    def _namespace(self):
        need(signature(os.stat("/private/tmp", follow_symlinks=False))[:6] == signature(os.fstat(self.parent))[:6], "temporary-parent-replaced")
        self._named(self.parent, self.path.name, self.root, 0o700)
        self._named(self.root, "state", self.state, 0o700)
        self._roster(self.root, (*self.cases, "state"), "fixture-namespace-roster")
        self._roster(self.state, self.cases, "fixture-state-roster")
        for case in self.cases:
            self._named(self.root, case, self.projects[case], 0o700)
            self._named(self.state, case, self.states[case], 0o700)

    def _roster(self, fd, expected, label):
        # A fresh openat(".") description, not dup(retained_fd), gives each
        # scan its own cursor. Never depend on a supplier's iterator rewind.
        before = signature(os.fstat(fd))
        with self._temporary(self._open(".", fd, directory=True)) as reader:
            need(signature(os.fstat(reader)) == before, "fixture-roster-original")
            iterator = os.scandir(reader)
            original_error = None
            try:
                names = []
                for entry in iterator:
                    need(len(names) < len(expected), label)  # Consume at most expected+1.
                    names.append(entry.name)
                observed = tuple(sorted(names))
                need(observed == tuple(sorted(expected)), label)
                need(signature(os.fstat(reader)) == before and signature(os.fstat(fd)) == before,
                     "fixture-roster-read-race")
                return observed
            except BaseException as error:
                original_error = error
                raise
            finally:
                try:
                    iterator.close()  # One consuming close; never retry it.
                except BaseException as error:
                    self.close_errors += 1
                    if self.first_close_error is None:
                        self.first_close_error = error
                    if original_error is None:
                        raise

    def _file(self, parent, name, body, *, mode=0o600):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(before.st_mode == stat.S_IFREG | mode and before.st_nlink == 1 and before.st_size == len(body)
             and (before.st_uid, before.st_gid) == (self.uid, self.gid), "fixture-file-shape")
        with self._temporary(self._open(name, parent)) as fd:
            original = signature(before)
            need(signature(os.fstat(fd)) == original, "fixture-file-open-race")
            chunks, remaining = [], len(body) + 1
            while remaining:
                part = os.read(fd, remaining)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            actual = b"".join(chunks)
            need(actual == body and signature(os.fstat(fd)) == original
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original, "fixture-file-readback")
            return Node(original, digest(actual), None)

    def _capture_inputs(self, case):
        files, links = signing_fixture_inputs(case)
        result = {}
        with self._temporary(self._open("inputs", self.states[case], directory=True)) as inputs:
            self._named(self.states[case], "inputs", inputs, 0o700)
            original = signature(os.fstat(inputs))
            names = self._roster(inputs, (*files, *links), "signing-fixture-roster")
            result["."] = Node(original, None, names)
            for name, (body, mode) in files.items():
                result[name] = self._file(inputs, name, body, mode=mode)
            for name, target in links.items():
                before = os.stat(name, dir_fd=inputs, follow_symlinks=False)
                need(stat.S_ISLNK(before.st_mode) and before.st_nlink == 1
                     and (before.st_uid, before.st_gid) == (self.uid, self.gid)
                     and os.readlink(name, dir_fd=inputs) == target,
                     "signing-fixture-link")
                need(signature(os.stat(name, dir_fd=inputs, follow_symlinks=False)) == signature(before)
                     and os.readlink(name, dir_fd=inputs) == target, "signing-fixture-link-race")
                result[name] = Node(signature(before), digest(target.encode("ascii")), None)
            need(signature(os.fstat(inputs)) == original, "signing-fixture-directory-race")
            self._named(self.states[case], "inputs", inputs, 0o700)
        return result

    def _inputs_unchanged(self, case):
        if case in IOS_SESSION_CASES:
            need(self._capture_inputs(case) == self.input_originals[case], "signing-fixture-original-changed")
        if case == PROJECT_FIELDS_CASE:
            need(self._capture_field_outside(case) == self.field_outside_originals[case], "project-field-outside-original-changed")

    def _capture_field_outside(self, case):
        need(case == PROJECT_FIELDS_CASE and case in self.states, "project-field-outside-case")
        with self._temporary(self._open("outside", self.states[case], directory=True)) as outside:
            self._named(self.states[case], "outside", outside, 0o700)
            before = signature(os.fstat(outside))
            entries = self._roster(outside, ("VERSION",), "project-field-outside-roster")
            version = self._file(outside, "VERSION", VERSION)
            need(signature(os.fstat(outside)) == before, "project-field-outside-changed")
            self._named(self.states[case], "outside", outside, 0o700)
            return {".": Node(before, None, entries), "VERSION": version}

    def _capture(self, case, final, *, ios_output_created=None):
        files, directories = fixture_data(case, final, ios_output_created=ios_output_created)
        snapshot = {}
        project = self.projects[case]
        with ExitStack() as children:
            opened = {".": project}
            for path, (mode, entries) in directories.items():
                if path != ".":
                    parent, _, leaf = path.rpartition("/")
                    fd = children.enter_context(self._temporary(self._open(leaf, opened[parent or "."], directory=True)))
                    self._named(opened[parent or "."], leaf, fd, mode)
                    opened[path] = fd
                fd = opened[path]
                before = signature(os.fstat(fd))
                observed = self._roster(fd, entries, "fixture-directory-roster")
                for name, body in files.items():
                    parent, _, leaf = name.rpartition("/")
                    if (parent or ".") == path:
                        snapshot[name] = self._file(fd, leaf, body)
                need(signature(os.fstat(fd)) == before, "fixture-directory-read-race")
                snapshot[path] = Node(before, None, observed)
            for path, (mode, _) in directories.items():
                need(signature(os.fstat(opened[path])) == snapshot[path].identity, "fixture-directory-read-race")
                if path != ".":
                    parent, _, leaf = path.rpartition("/")
                    self._named(opened[parent or "."], leaf, opened[path], mode)
        _shape(snapshot, case, final, self.uid, self.gid, ios_output_created=ios_output_created)
        return snapshot

    def before_call(self, case):
        self.case, self.stage = case, "before-invocation"
        self._namespace()
        validate_snapshot(self.originals[case], self._capture(case, False), case, False, self.uid, self.gid)
        state = self.states[case]
        self._roster(state, ("home", "tmp", "inputs") if case in IOS_SESSION_CASES
                     else ("home", "tmp", "outside") if case == PROJECT_FIELDS_CASE else ("home", "tmp"), "fresh-state-roster")
        self._inputs_unchanged(case)
        for name in ("home", "tmp"):
            with self._temporary(self._open(name, state, directory=True)) as fd:
                self._named(state, name, fd, 0o700)
                self._roster(fd, (), "fresh-state-not-empty")

    def readback(self, case, *, ios_output_created=None):
        need(not self.inflight and self.last_returned, "readback-without-return")
        self.stage = "independent-readback"
        self._namespace()
        self._inputs_unchanged(case)
        return validate_snapshot(self.originals[case], self._capture(case, True, ios_output_created=ios_output_created),
                                 case, True, self.uid, self.gid, ios_output_created=ios_output_created)

    def readback_ios(self, case, report):
        need(case in IOS_OPERATION_CASES and case in self.cases and not self.inflight and self.last_returned, "ios-readback-order")
        # Parser DATA bounds the spelling; this independent original-project
        # descriptor supplies the filesystem authority. Never open a report path.
        _ios_report(report, case)
        if case == "ios-recovery-empty":
            return {**self.readback(case), "iosRecovery": {"emptyAccountAndProjectObserved": True, "mutationRequested": False}}
        original = report["original"]
        disposition = original["terminal"]["disposition"]
        output_created = disposition["output"] != "not-created" if case in IOS_SIGNED_CASES else None
        source = self.readback(case, ios_output_created=output_created)
        if disposition["output"] == "not-created":
            return {**source, "iosOutput": {"state": "not-created", "archiveObserved": False}}
        operation = original["facts"]["operationId"]
        project = self.projects[case]
        with self._temporary(self._open(".mobile-release", project, directory=True)) as private:
            self._named(project, ".mobile-release", private, 0o700)
            self._roster(private, ("desktop-ios-archive",), "ios-output-parent-roster")
            with self._temporary(self._open("desktop-ios-archive", private, directory=True)) as domain:
                self._named(private, "desktop-ios-archive", domain, 0o700)
                self._roster(domain, (operation,), "ios-output-domain-roster")
                with self._temporary(self._open(operation, domain, directory=True)) as output:
                    self._named(domain, operation, output, 0o700)
                    complete = disposition["output"] == "retained-local-result"
                    self._roster(output, ("archive.xcarchive",) if complete else (), "ios-output-roster")
                    observed = self._archive_readback(output, original["terminal"]["result"]) if complete else None
                    self._named(domain, operation, output, 0o700)
                self._named(private, "desktop-ios-archive", domain, 0o700)
            self._named(project, ".mobile-release", private, 0o700)
        # Source readback is repeated only after reading the newly declared
        # output so a concurrent replacement cannot license either observation.
        validate_snapshot(self.originals[case], self._capture(case, True, ios_output_created=output_created),
                          case, True, self.uid, self.gid, ios_output_created=output_created)
        self._inputs_unchanged(case)
        return {**source, "iosOutput": {"state": disposition["output"], "archiveObserved": complete,
                                        "workAbsent": True, "archive": observed}}

    def _archive_readback(self, parent, result):
        import plistlib
        import time
        end = time.monotonic() + 20
        rows, plists, total = {}, {}, 0
        root_device = os.fstat(parent).st_dev
        retained_info = {"Info.plist", "Products/Applications/MRKObserved.app/Info.plist"}

        def current():
            need(time.monotonic() < end, "ios-output-readback-deadline")

        def bound(parent_fd, name, fd, before):
            current()
            need(signature(os.fstat(fd)) == signature(before)
                 and signature(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == signature(before), "ios-output-original-changed")
            need(before.st_dev == root_device and (before.st_uid, before.st_gid) == (self.uid, self.gid)
                 and stat.S_IMODE(before.st_mode) & 0o7022 == 0
                 and (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode) and before.st_nlink == 1), "ios-output-object")

        def names(fd):
            current()
            before = signature(os.fstat(fd))
            with self._temporary(self._open(".", fd, directory=True)) as reader:
                need(signature(os.fstat(reader)) == before, "ios-output-reader-original")
                iterator = os.scandir(reader)
                error = None
                try:
                    found = []
                    for entry in iterator:
                        current()
                        need(len(rows) + len(found) < 1024 and type(entry.name) is str, "ios-output-entry-budget")
                        need(re.fullmatch(r"[A-Za-z0-9_. -]{1,255}", entry.name) is not None and entry.name not in (".", ".."), "ios-output-name")
                        found.append(entry.name)
                    need(len(found) == len(set(name.casefold() for name in found)), "ios-output-name-collision")
                    need(signature(os.fstat(reader)) == before and signature(os.fstat(fd)) == before, "ios-output-directory-changed")
                    return sorted(found)
                except BaseException as caught:
                    error = caught
                    raise
                finally:
                    try:
                        iterator.close()
                    except BaseException as caught:
                        self.close_errors += 1
                        if self.first_close_error is None:
                            self.first_close_error = caught
                        if error is None:
                            raise

        def walk(fd, relative, depth):
            nonlocal total
            current()
            need(depth <= 16, "ios-output-depth")
            before = signature(os.fstat(fd))
            for name in names(fd):
                current()
                path = f"{relative}/{name}" if relative else name
                observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                directory = stat.S_ISDIR(observed.st_mode)
                need(directory or stat.S_ISREG(observed.st_mode), "ios-output-kind")
                need(len(rows) < 1024 and path not in rows, "ios-output-entry-budget")
                with self._temporary(self._open(name, fd, directory=directory)) as child:
                    bound(fd, name, child, observed)
                    if directory:
                        rows[path] = None
                        walk(child, path, depth + 1)
                    else:
                        need(0 <= observed.st_size <= 64 * 1024 * 1024 and total + observed.st_size <= 128 * 1024 * 1024,
                             "ios-output-byte-budget")
                        if path in retained_info:
                            need(observed.st_size <= 256 * 1024, "ios-output-plist-budget")
                        count, hashed, captured = 0, hashlib.sha256(), []
                        while True:
                            current()
                            part = os.read(child, min(1024 * 1024, observed.st_size + 1 - count))
                            if not part:
                                break
                            count += len(part)
                            need(count <= observed.st_size, "ios-output-grew")
                            hashed.update(part)
                            if path in retained_info:
                                captured.append(part)
                        need(count == observed.st_size, "ios-output-short-read")
                        total += count
                        rows[path] = {"bytes": count, "sha256": hashed.hexdigest()}
                        if path in retained_info:
                            plists[path] = b"".join(captured)
                    bound(fd, name, child, observed)
            need(signature(os.fstat(fd)) == before, "ios-output-directory-changed")

        before = os.stat("archive.xcarchive", dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode), "ios-output-archive-kind")
        with self._temporary(self._open("archive.xcarchive", parent, directory=True)) as archive:
            bound(parent, "archive.xcarchive", archive, before)
            walk(archive, "", 0)
            bound(parent, "archive.xcarchive", archive, before)
        need(len(rows) == result["entries"] and total == result["bytes"], "ios-output-core-inventory-mismatch")
        binaries = ("Products/Applications/MRKObserved.app/MRKObserved", "dSYMs/MRKObserved.app.dSYM/Contents/Resources/DWARF/MRKObserved")
        need(retained_info <= plists.keys() and all(type(rows.get(name)) is dict and rows[name]["bytes"] > 0 for name in binaries)
             and not any("_CodeSignature" in name.split("/") or name.endswith(".mobileprovision") for name in rows), "ios-output-structure")
        try:
            archive_info = plistlib.loads(plists["Info.plist"])
            app_info = plistlib.loads(plists["Products/Applications/MRKObserved.app/Info.plist"])
        except (ValueError, TypeError, OverflowError) as error:
            raise Refused("ios-output-plist") from error
        need(type(archive_info) is dict and type(archive_info.get("ApplicationProperties")) is dict
             and archive_info["ApplicationProperties"].get("ApplicationPath") == "Applications/MRKObserved.app"
             and type(app_info) is dict and app_info.get("CFBundleIdentifier") == "org.example.mrk.observed"
             and app_info.get("CFBundleShortVersionString") == "1.2.3" and app_info.get("CFBundleVersion") == "7", "ios-output-identity")
        current()
        return {"entries": len(rows), "bytes": total,
                "inventorySha256": digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("ascii")),
                "savedIdentityMatched": True, "unsignedAppAndDsymPresent": True, "retainedNotDeleted": True}

    def close(self):
        need(not self.inflight, "fixture-finality-unknown")
        for fd in tuple(self.fds):
            self._close(fd)
        if self.first_close_error is not None:
            raise self.first_close_error


def run_cases(binding, fixtures, run_owned, uid, username, emit, scope=None):
    """The sole invocation seam. Inert tests supply a non-executing callable."""
    cases = selected_cases(scope)
    need(getattr(fixtures, "cases", cases) == cases, "fixture-scope")
    for case in cases:
        fixtures.before_call(case)
        state = binding.root(project_fields=(scope == PROJECT_FIELDS_CASE)) / "state" / case
        argv = [EXECUTABLE, case]
        fixtures.stage, fixtures.inflight, fixtures.last_returned = "invocation", True, False
        fixtures.app_returncode = fixtures.inner_failure_step = fixtures.inner_failure_reason = None
        fixtures.inner_failure_context = fixtures.inner_diagnostic_source = None
        # Only the original public return contract clears this flag. An
        # exception/interruption or foreign/malformed result leaves finality
        # unknown, with no readback, close or later invocation.
        try:
            result = run_owned(argv, environ=app_environment(state, uid, username), cwd=state,
                               timeout=case_timeout(case), capture=True, text=False, output_limit=OUTPUT_LIMIT)
        except BaseException as error:
            # Diagnostics only: preserve identical error, inflight, unknown
            # finality and the no-readback/no-close/no-next-call boundary.
            try:
                reduced = _original_exception_diagnostics(error, run_owned, case, state)
                if reduced is not None:
                    fixtures.inner_failure_step, fixtures.inner_failure_reason, fixtures.inner_failure_context = reduced
                    fixtures.inner_diagnostic_source = "original-exception-buffer"
            except BaseException:
                pass  # Even an unexpected diagnostic fault cannot replace this error.
            raise
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list
             and len(result.args) == 2 and all(type(arg) is str for arg in result.args) and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "owner-return-contract")
        fixtures.inflight, fixtures.last_returned, fixtures.stage = False, True, "result-validation"
        fixtures.app_returncode = result.returncode
        fixtures.inner_failure_step = failure_step(result.stdout, result.stderr)
        fixtures.inner_failure_reason = failure_reason(result.stdout, result.stderr)
        fixtures.inner_failure_context = failure_context(result.stdout, result.stderr, case)
        fixtures.inner_diagnostic_source = "completed-output"
        need(result.returncode == 0, "app-return")
        report = parse_result(result.stdout, result.stderr, binding, case)
        readback = fixtures.readback_ios(case, report["iosArchive"]) if case in IOS_OPERATION_CASES else fixtures.readback(case)
        emit({"schemaVersion": 1, "type": "macos-aqua-case", **binding.public(), "case": case,
              "originalCallReturned": True, "observer": report, "independentReadback": readback})


def admit(environment, root):
    # Platform/user APIs are evaluated only in the actual native entry.
    import platform
    import pwd
    import threading
    need(sys.platform == "darwin" and platform.machine() == "arm64" and platform.mac_ver()[0].split(".")[0] == "26", "native-platform")
    uid, gid = os.getuid(), os.getgid()
    need(uid == os.geteuid() and uid > 0 and gid == os.getegid()
         and threading.current_thread() is threading.main_thread(), "native-main-user")
    binding = Binding(environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID"), environment.get("GITHUB_RUN_ATTEMPT")).checked()
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": REF,
                "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_WORKFLOW_SHA": binding.source, "GITHUB_WORKSPACE": str(root)}
    need(all(environment.get(key) == value for key, value in required.items()), "hosted-source-route")
    # Actions' reviewed checkout is detached at this exact source. No Git
    # command/credential lookup or alternate worktree/ref parser is needed.
    head = root / ".git" / "HEAD"
    head_info = head.lstat()
    need(stat.S_ISREG(head_info.st_mode) and head_info.st_size == 41
         and head.read_bytes() == binding.source.encode("ascii") + b"\n", "checkout-source")
    username = pwd.getpwuid(uid).pw_name
    app_environment(binding.root() / "state" / CASES[0], uid, username)
    return binding, uid, gid, username


def load_owner(root):
    need(not any(name == "mobile_release" or name.startswith("mobile_release.") for name in sys.modules), "owner-already-imported")
    for name, expected in OWNER_PINS.items():
        path = root / "src" / "mobile_release" / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 256 * 1024 and digest(path.read_bytes()) == expected, "owner-source-pin")
    sys.path.insert(0, str(root / "src"))
    try:
        from mobile_release import owned_process
    finally:
        sys.path.pop(0)
    need(Path(owned_process.__file__).absolute() == root / "src" / "mobile_release" / "owned_process.py", "owner-source-route")
    return owned_process


def diagnostic(error, owner, fixtures):
    # Preserve individual typed public lifetime facts, not a synthesized pass
    # from a later exception. Missing fields remain unknown (JSON null).
    pending, seen, facts = [error], set(), []
    while pending and len(seen) < 16:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if owner is not None and isinstance(current, (owner.ProcessError, owner.ProcessInterrupted)):
            row = {"type": "interrupted" if isinstance(current, owner.ProcessInterrupted) else "process-error"}
            for source, target in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanup_complete", "cleanupComplete")):
                value = getattr(current, source, None)
                row[target] = value if type(value) is bool else None
            facts.append(row)
        pending.extend((current.__context__, current.__cause__))
    label = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "helper-or-owner-error"
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None:
        label = "helper-refused"
    result = {"schemaVersion": 1, "type": "macos-aqua-failure", "status": "failed", "reason": label,
            "case": fixtures.case if fixtures else None, "stage": fixtures.stage if fixtures else "admission-or-source",
            "originalCallReturned": fixtures.last_returned if fixtures else False,
            "appReturncode": fixtures.app_returncode if fixtures else None,
            "innerFailureStep": fixtures.inner_failure_step if fixtures else None,
            "innerFailureReason": fixtures.inner_failure_reason if fixtures else None,
            "innerFailureContext": fixtures.inner_failure_context if fixtures else None,
            "innerDiagnosticSource": fixtures.inner_diagnostic_source if fixtures else None,
            "innerDiagnosticCompleteness": "complete" if fixtures and fixtures.last_returned else "unknown",
            "invocationFinality": "unknown" if fixtures and fixtures.inflight else "no-pending-invocation",
            "innerOutput": "unavailable" if fixtures and fixtures.inflight else "not-exported",
            "typedLifetimeFacts": facts, "exceptionChainTruncated": bool(pending),
            "fixtureCloseErrors": fixtures.close_errors if fixtures else 0,
            "fixturesPreserved": True, "laterCasesStopped": True}
    try:
        location = _result_location(getattr(error, "result_location", None)) if type(error) is Refused else None
        if location is not None:
            result["resultLocation"] = location
    except BaseException:
        pass  # Keep the original refusal/lifetime facts if optional detail fails.
    return result


def emit_record(value, stream):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    need(len(data.encode("ascii")) <= 24 * 1024, "outer-result-bound")
    stream.write(data + "\n")
    stream.flush()


def main():
    fixtures = owner = binding = None
    scope = None
    original_error = None
    try:
        scope = argument_scope(sys.argv[1:])
        root = Path(__file__).absolute().parents[2]
        binding, uid, gid, username = admit(os.environ, root)
        owner = load_owner(root)  # Native main only; no module-import-time core.
        os.umask(0o077)
        fixtures = Fixtures(binding, uid, gid, scope)
        fixtures.prepare()
        run_cases(binding, fixtures, owner.run_owned, uid, username, lambda value: emit_record(value, sys.stdout), scope)
    except BaseException as error:
        original_error = error
    if fixtures is not None and not fixtures.inflight:
        try:
            fixtures.close()
        except BaseException as error:
            if original_error is None:
                original_error = error  # Never overwrite an earlier failure.
    if original_error is not None:
        # The original exception object reaches this boundary unchanged. This
        # CLI emits bounded DATA and a nonzero status, never its traceback,
        # arbitrary message, child transcript or private source/project paths.
        try:
            emit_record(diagnostic(original_error, owner, fixtures), sys.stderr)
        except BaseException:
            pass  # Output loss remains failure; there is no diagnostic retry.
        return 130 if isinstance(original_error, KeyboardInterrupt) else 1
    try:
        emit_record({"schemaVersion": 1, "type": "macos-aqua-complete", **binding.public(), "cases": list(selected_cases(scope)),
                     "allOriginalCallsReturned": True, "independentReadbacks": True, "fixtureHandlesClosed": True,
                     "instrumentedEngineeringApp": True, "shippingBinaryQualified": False, "distributionQualified": False}, sys.stdout)
    except BaseException:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
