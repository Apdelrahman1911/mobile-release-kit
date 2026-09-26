//! Finite unsigned-iOS observations inside the original installed Mac relay.
//! This module owns only comparison DATA and one final-observer hold. The real
//! document, saved-command owner, native books and invocation keep all effects.
use std::{ffi::OsStr, sync::{Arc, Mutex, OnceLock, Weak, atomic::{AtomicBool, Ordering}}, time::Instant};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use crate::{asset_session::DocumentBinding, error::BridgeError, ios_archive_owner::IOSArchiveOwner,
    ios_archive_protocol as wire};
use super::{Case as ShellCase, Observation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case { ToolchainPrerequisite, VersionStale, UnsignedArchive, Cancel, Finality }
impl Case {
    pub(super) const ALL: [Self; 5] = [Self::ToolchainPrerequisite, Self::VersionStale,
        Self::UnsignedArchive, Self::Cancel, Self::Finality];
    pub(super) fn name(self) -> &'static str { match self {
        Self::ToolchainPrerequisite => "ios-toolchain-prerequisite", Self::VersionStale => "ios-version-stale",
        Self::UnsignedArchive => "ios-unsigned-archive", Self::Cancel => "ios-cancel", Self::Finality => "ios-finality",
    } }
    pub(super) fn parse(value: &OsStr) -> Option<Self> { Self::ALL.into_iter().find(|case| value == OsStr::new(case.name())) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command { Prepare, Start, Status, Cancel }

/// One actual owner snapshot. No public/caller JSON can construct a witness.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OriginalFacts {
    pub(crate) operation_id: String, pub(crate) owner_generation: String,
    pub(crate) inspection_joined: bool, pub(crate) acquisition_joined: bool, pub(crate) attempted: bool,
    pub(crate) child_waited_success: bool, pub(crate) stdin_closed: bool, pub(crate) stdout_eof_closed: bool,
    pub(crate) stderr_eof_closed: bool, pub(crate) io_joined: bool, pub(crate) core_lifetime_settled: bool,
    pub(crate) runtime_ledger_settled: bool, pub(crate) tools_ledger_settled: bool,
    pub(crate) native_settlement_joined: bool, pub(crate) native_integrity: bool,
    pub(crate) driver_joined: bool, pub(crate) manager_joined: bool, pub(crate) observer_joined: bool,
    pub(crate) watchdog_joined: bool, pub(crate) retired_before_cutoff: bool, pub(crate) active_retained: bool,
    pub(crate) resource_unknown: bool, pub(crate) work_ms: u64, pub(crate) hard_ms: u64,
}
impl OriginalFacts {
    fn settled_body(&self) -> bool {
        crate::edit_protocol::token(&self.operation_id) && crate::edit_protocol::token(&self.owner_generation)
            && self.inspection_joined && self.acquisition_joined && self.attempted && self.child_waited_success
            && self.stdin_closed && self.stdout_eof_closed && self.stderr_eof_closed && self.io_joined
            && self.core_lifetime_settled && self.runtime_ledger_settled && self.tools_ledger_settled
            && self.native_settlement_joined && self.native_integrity && self.driver_joined && self.manager_joined
            && !self.resource_unknown && self.work_ms == 300_000 && self.hard_ms == 310_000
    }
    fn held(&self) -> bool { self.settled_body() && !self.observer_joined && !self.watchdog_joined
        && !self.retired_before_cutoff && self.active_retained }
    fn final_for(&self) -> bool { self.settled_body() && self.observer_joined && self.watchdog_joined
        && self.retired_before_cutoff && !self.active_retained }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Snapshot { pub(crate) facts: OriginalFacts, pub(crate) terminal: wire::Terminal }

// Private, non-cloneable token. Exact original identities are consumed before
// navigation/IPC, not inferred from a path, label, owner clone or environment.
pub(crate) struct Admission { control: Arc<Control>, document: Weak<()>, owner: Weak<()> }
impl Admission {
    pub(crate) fn document_matches(&self, original: &Arc<()>) -> bool {
        self.document.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
    }
    pub(crate) fn consume(self, original: &Arc<()>) -> Result<Arc<Control>, BridgeError> {
        let q = self.control.original.get().and_then(Weak::upgrade).ok_or_else(BridgeError::invalid)?;
        let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if self.document.upgrade().is_none() || !self.owner.upgrade().is_some_and(|bound| Arc::ptr_eq(&bound, original))
            || !r.attached || r.started || r.loaded || !q.timely()
            || q.case != ShellCase::Ios(self.control.case)
            || !q.ios.as_ref().is_some_and(|control| Arc::ptr_eq(control, &self.control))
            || self.control.admitted.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        drop(r); Ok(self.control)
    }
}
struct Hold {
    snapshot: Option<Snapshot>, entered: bool, released: bool,
    sender: Option<oneshot::Sender<()>>, receiver: Option<oneshot::Receiver<()>>,
}
pub(crate) struct Control {
    pub(crate) case: Case, original: OnceLock<Weak<Observation>>, document: OnceLock<Weak<()>>, owner: OnceLock<Weak<()>>,
    admitted: AtomicBool, claimed: AtomicBool, failed: AtomicBool, hold: Mutex<Hold>,
}
impl Control {
    pub(super) fn new(case: Case) -> Arc<Self> {
        // Created before any owner work; the channel carries no native custody.
        let (sender, receiver) = oneshot::channel();
        Arc::new(Self { case, original: OnceLock::new(), document: OnceLock::new(), owner: OnceLock::new(),
            admitted: AtomicBool::new(false), claimed: AtomicBool::new(false), failed: AtomicBool::new(false),
            hold: Mutex::new(Hold { snapshot: None, entered: false, released: false, sender: Some(sender), receiver: Some(receiver) }) })
    }
    pub(super) fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &DocumentBinding, owner: &IOSArchiveOwner)
        -> Result<(), BridgeError> {
        if q.case != ShellCase::Ios(self.case) || !q.timely() || std::thread::current().id() != q.main {
            return Err(BridgeError::invalid());
        }
        let (doc, bound_owner) = document.installed_ios_identities();
        let direct = owner.installed_ios_identity();
        if doc.upgrade().is_none() || !Weak::ptr_eq(&bound_owner, &direct) || direct.upgrade().is_none()
            || self.original.set(Arc::downgrade(q)).is_err() || self.document.set(doc.clone()).is_err()
            || self.owner.set(bound_owner.clone()).is_err() { return Err(BridgeError::invalid()); }
        document.admit_installed_ios(Admission { control: self.clone(), document: doc, owner: bound_owner })
    }
    pub(crate) fn permits(&self) -> bool {
        // Called while the actual owner registry may be held. Never acquire the
        // observation Record or a native/document lock on this eligibility path.
        self.admitted.load(Ordering::SeqCst) && !self.failed.load(Ordering::SeqCst)
            && self.document.get().and_then(Weak::upgrade).is_some() && self.owner.get().and_then(Weak::upgrade).is_some()
            && self.original.get().and_then(Weak::upgrade).is_some_and(|q| q.timely()
                && q.case == ShellCase::Ios(self.case)
                && q.ios.as_ref().is_some_and(|control| std::ptr::eq(control.as_ref(), self)))
    }
    pub(crate) fn claim(&self) -> Result<(), BridgeError> {
        if !self.permits() || self.claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(BridgeError::invalid());
        }
        Ok(())
    }
    pub(crate) fn unavailable_witness(&self) {
        self.failed.store(true, Ordering::SeqCst);
        if let Some(q) = self.original.get().and_then(Weak::upgrade) { q.fail_with("ios-original-witness"); }
    }
    pub(crate) fn prepare_hold(&self, snapshot: Snapshot) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if self.case != Case::Finality || !self.permits() || !self.claimed.load(Ordering::SeqCst)
            || hold.snapshot.is_some() || hold.entered || hold.released || !snapshot.facts.held()
            || snapshot.terminal.outcome != wire::Outcome::Complete || !snapshot.terminal.settled() {
            self.unavailable_witness(); return false;
        }
        hold.snapshot = Some(snapshot); true
    }
    pub(crate) async fn hold_observer(&self, end: Instant) -> bool {
        let receiver = {
            let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
            if !self.permits() || Instant::now() >= end || hold.snapshot.is_none() || hold.entered || hold.released {
                self.unavailable_witness(); return false;
            }
            hold.entered = true; hold.receiver.take()
        };
        let Some(receiver) = receiver else { self.unavailable_witness(); return false; };
        // Same registered final observer; no new worker and no guard over await.
        // The receiver is DATA only. Dropping this future neither closes native
        // resources nor detaches another task; owner STOP still shortens its cut.
        let passed = matches!(tokio::time::timeout_at(end.into(), receiver).await, Ok(Ok(())))
            && Instant::now() < end && self.permits();
        if !passed { self.unavailable_witness(); } passed
    }
    fn held_snapshot(&self) -> Option<Snapshot> {
        let hold = self.hold.try_lock().ok()?;
        (hold.entered && !hold.released && self.permits()).then(|| hold.snapshot.clone()).flatten()
    }
    fn release_hold(&self) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.unavailable_witness(); return false; };
        if !self.permits() || !hold.entered || hold.released || hold.snapshot.is_none() {
            self.unavailable_witness(); return false;
        }
        let Some(sender) = hold.sender.take() else { self.unavailable_witness(); return false; };
        hold.released = true;
        if sender.send(()).is_err() { self.unavailable_witness(); return false; }
        true
    }
}

// Literal synthetic fixture DATA. Never an executable generator, fallback
// project, credential source, or substitute for original core/native evidence.
const CONFIG: &[u8] = br#"{
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
"#;
const CONFIG_PREREQUISITE: &[u8] = br#"{
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
"#;
const CONFIG_CANCEL: &[u8] = br#"{
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
"#;
const PROJECT: &[u8] = br#"// !$*UTF8*$!
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
"#;
const SCHEME: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1500" version="1.3">
 <BuildAction parallelizeBuildables="NO" buildImplicitDependencies="NO"><BuildActionEntries>
  <BuildActionEntry buildForTesting="NO" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="000000000000000000000005" BuildableName="MRKObserved.app" BlueprintName="MRKObserved" ReferencedContainer="container:MRKObserved.xcodeproj"/>
  </BuildActionEntry>
 </BuildActionEntries></BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="NO"/>
</Scheme>
"#;
const MAIN: &[u8] = br#"#import <UIKit/UIKit.h>
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
"#;
const PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
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
"#;
const WORKSPACE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Workspace version="1.0"><FileRef location="self:"/></Workspace>
"#;
pub(super) fn config(case: Case) -> &'static [u8] { match case {
    Case::ToolchainPrerequisite => CONFIG_PREREQUISITE, Case::Cancel => CONFIG_CANCEL, _ => CONFIG,
} }

const STALE_VERSION: &[u8] = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n";
const DIRS: &[(&str, u32, &[&str])] = &[
    ("ios", 0o700, &["MRKObserved", "MRKObserved.xcodeproj"]),
    ("ios/MRKObserved", 0o700, &["Info.plist", "main.m"]),
    ("ios/MRKObserved.xcodeproj", 0o700, &["project.pbxproj", "project.xcworkspace", "xcshareddata"]),
    ("ios/MRKObserved.xcodeproj/project.xcworkspace", 0o700, &["contents.xcworkspacedata"]),
    ("ios/MRKObserved.xcodeproj/xcshareddata", 0o700, &["xcschemes"]),
    ("ios/MRKObserved.xcodeproj/xcshareddata/xcschemes", 0o700, &["MRKObserved.xcscheme"]),
    ("release", 0o755, &["mobile-release.json"]),
];
fn files(case: Case, stale: bool) -> [(&'static str, &'static [u8]); 9] { [
    (".gitignore", b"# MRK Mac Aqua user ignore\nuser-output/\n.mobile-release/\n"),
    ("keep.txt", super::KEEP), ("version.properties", if stale { STALE_VERSION } else { super::VERSION }),
    ("release/mobile-release.json", config(case)), ("ios/MRKObserved.xcodeproj/project.pbxproj", PROJECT),
    ("ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme", SCHEME),
    ("ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata", WORKSPACE),
    ("ios/MRKObserved/main.m", MAIN), ("ios/MRKObserved/Info.plist", PLIST),
] }
/// Source originals only. Archive contents remain the real core's retained
/// inventory; the helper performs independent finite post-exit readback.
struct Output { operation: String, archive: bool }
pub(super) struct Fixture {
    case: Case, files: [super::FileFact; 9], directories: Vec<[u64; 6]>,
    stale: bool, output: Option<Output>, finalized: bool,
}
impl Fixture {
    pub(super) fn capture(root: &std::path::Path, uid: u32, case: Case) -> Result<Self, ()> {
        let files = files(case, false).into_iter().map(|(path, body)| super::file_fact(&root.join(path), body, uid))
            .collect::<Result<Vec<_>, _>>()?.try_into().map_err(|_| ())?;
        let directories = DIRS.iter().map(|(path, mode, entries)| super::directory(&root.join(path), uid, *mode, entries))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { case, files, directories, stale: false, output: None, finalized: false })
    }
    pub(super) fn root_entries(&self) -> Vec<&str> {
        let mut entries = vec![".gitignore", "ios", "keep.txt", "release", "version.properties"];
        if self.output.is_some() { entries.push(".mobile-release"); } entries
    }
    pub(super) fn source_identity(&self) -> [u64; 6] { self.directories[0] }
    pub(super) fn release_identity(&self) -> [u64; 6] { self.directories[6] }
    pub(super) fn ignore(&self) -> super::FileFact { self.files[0].clone() }
    pub(super) fn config(&self) -> super::FileFact { self.files[3].clone() }
    pub(super) fn verify(&self, root: &std::path::Path, uid: u32) -> Result<(), ()> {
        for ((path, bytes), original) in files(self.case, self.stale).into_iter().zip(&self.files) {
            if &super::file_fact(&root.join(path), bytes, uid)? != original { return Err(()); }
        }
        for ((path, mode, entries), original) in DIRS.iter().zip(&self.directories) {
            if &super::directory(&root.join(path), uid, *mode, entries)? != original { return Err(()); }
        }
        if let Some(output) = &self.output {
            super::directory(&root.join(".mobile-release"), uid, 0o700, &["desktop-ios-archive"])?;
            super::directory(&root.join(".mobile-release/desktop-ios-archive"), uid, 0o700, &[&output.operation])?;
            super::directory(&root.join(".mobile-release/desktop-ios-archive").join(&output.operation), uid, 0o700,
                if output.archive { &["archive.xcarchive"] } else { &[] })?;
        }
        Ok(())
    }
    pub(super) fn mutate_version(&mut self, root: &std::path::Path, uid: u32, end: Instant,
        failed: &AtomicBool) -> Result<(), ()> {
        use std::{fs::OpenOptions, io::{Read, Seek, SeekFrom, Write}, os::{fd::AsFd, unix::fs::OpenOptionsExt}};
        let current = || Instant::now() < end && !failed.load(Ordering::SeqCst);
        if self.case != Case::VersionStale || self.stale || self.output.is_some() || self.finalized || !current() { return Err(()); }
        self.verify(root, uid)?;
        let path = root.join("version.properties");
        let mut file = OpenOptions::new().read(true).write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC).open(&path).map_err(|_| ())?;
        let original = &self.files[2];
        let result = (|| {
            if super::identity(&file.metadata().map_err(|_| ())?)? != original.identity
                || super::identity(&std::fs::symlink_metadata(&path).map_err(|_| ())?)? != original.identity { return Err(()); }
            mrk_macos_installed_native::empty_acl(file.as_fd()).map_err(|_| ())?;
            mrk_macos_installed_native::no_xattrs(file.as_fd()).map_err(|_| ())?;
            let mut bytes = Vec::with_capacity(super::VERSION.len() + 1);
            (&mut file).take(super::VERSION.len() as u64 + 1).read_to_end(&mut bytes).map_err(|_| ())?;
            if bytes != super::VERSION || super::identity(&file.metadata().map_err(|_| ())?)? != original.identity { return Err(()); }
            // One literal byte on the prebound original, never replacement,
            // truncation, restoration or a retry after a partial/error return.
            file.seek(SeekFrom::Start((super::VERSION.len() - 2) as u64)).map_err(|_| ())?;
            if !current() || file.write(b"8").map_err(|_| ())? != 1 || !current() { return Err(()); }
            file.sync_all().map_err(|_| ())?;
            let after = super::identity(&file.metadata().map_err(|_| ())?)?;
            if !current() || after[..7] != original.identity[..7]
                || super::identity(&std::fs::symlink_metadata(&path).map_err(|_| ())?)? != after { return Err(()); }
            Ok(after)
        })();
        let closed = nix::unistd::close(std::os::fd::OwnedFd::from(file)).is_ok();
        if !closed || !current() { return Err(()); }
        let after = result?;
        let observed = super::file_fact(&path, STALE_VERSION, uid)?;
        if observed.identity != after || !current() { return Err(()); }
        self.files[2] = observed; self.stale = true; self.verify(root, uid)?;
        current().then_some(()).ok_or(())
    }
    pub(super) fn finalize(&mut self, root: &std::path::Path, uid: u32, snapshot: &Snapshot) -> Result<(), ()> {
        if self.finalized || !snapshot.facts.final_for() || !terminal_for(self.case, snapshot)
            || self.stale != (self.case == Case::VersionStale) { return Err(()); }
        use wire::OutputDisposition as O;
        self.output = match snapshot.terminal.disposition.output {
            O::NotCreated => None,
            O::RetainedIncomplete | O::RetainedLocalResult => Some(Output { operation: snapshot.facts.operation_id.clone(),
                archive: snapshot.terminal.disposition.output == O::RetainedLocalResult }),
            O::Unknown => return Err(()),
        };
        self.verify(root, uid)?; self.finalized = true; Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, ReadVersion, VersionRead, Prepare, Review, Acknowledge, Acknowledged,
    MutateVersion, Start, Running, Cancel, Hold, ReleaseHold, Final }
#[derive(Clone, Default)]
pub(super) struct Record {
    version_requested: bool, version: Option<Value>, context: Option<wire::Context>,
    version_mutated: bool,
    prepare_requested: bool, prepare_returned: bool, review_visible: bool, acknowledged: bool,
    start_requested: bool, start_returned: bool, cancel_requested: bool, cancel_returned: bool,
    status_requested: u16, status_returned: u16, status: Option<wire::Status>,
    prepared: Option<wire::Projection>, held: Option<Snapshot>, held_dom: bool, reciprocal_blocked: bool,
    released: bool, terminal: Option<Snapshot>, final_dom: bool,
}
fn version_value(case: Case) -> Value {
    json!({"schemaVersion":2,"source":"version.properties","version":{"name":"1.2.3","build":7},
        "observationScope":"single-request-non-atomic","assurance":{"basis":"static-text","projectCodeExecuted":false,
            "toolsProbed":false,"credentialsRead":false,"gitObserved":false,"storeContacted":false,
            "writesPerformed":false,"releaseReadiness":"unknown"},
        "savedConfig":{"bytes":config(case).len(),"sha256":super::digest(config(case))},
        "savedVersion":{"bytes":super::VERSION.len(),"sha256":super::digest(super::VERSION)}})
}
fn context_matches(case: Case, project: &str, context: &wire::Context) -> bool {
    context.project_id == project && context.platform == wire::Platform::Ios && context.operation == wire::Operation::IOSUnsignedArchive
        && serde_json::to_value(&context.saved_config).ok() == Some(version_value(case)["savedConfig"].clone())
        && serde_json::to_value(&context.saved_version).ok() == Some(json!({"source":"version.properties","name":"1.2.3","build":7,
            "bytes":super::VERSION.len(),"sha256":super::digest(super::VERSION)}))
}
fn terminal_for(case: Case, snapshot: &Snapshot) -> bool {
    let t = &snapshot.terminal;
    if !t.settled() { return false; }
    use wire::{CommandOutcome as C, Outcome as O, Reason as R, OutputDisposition as D};
    let zero = |c: &wire::CommandData| c.outcome == C::Exited && c.exit_code == Some(0);
    let not_dispatched = |c: &wire::CommandData| c.outcome == C::NotDispatched && c.exit_code.is_none();
    let commands = &t.activity.commands;
    match case {
        Case::ToolchainPrerequisite => t.outcome == O::Failed && t.reason == R::CommandFailed
            && zero(&commands.xcode_version) && zero(&commands.ios_sdk)
            && commands.prepare.outcome == C::Exited && commands.prepare.exit_code == Some(1)
            && not_dispatched(&commands.archive) && t.result.is_none() && t.activity.findings.is_empty()
            && t.disposition.output == D::RetainedIncomplete,
        Case::VersionStale => t.outcome == O::Refused && t.reason == R::SavedVersionChanged
            && [&commands.xcode_version, &commands.ios_sdk, &commands.prepare, &commands.archive].into_iter().all(not_dispatched)
            && t.result.is_none() && t.activity.findings.is_empty() && t.disposition.output == D::NotCreated,
        Case::Cancel => t.outcome == O::Cancelled && t.reason == R::Cancelled
            && zero(&commands.xcode_version) && zero(&commands.ios_sdk)
            // Known original finality does not invent an exit status for a
            // stopped command. Unknown here is result DATA, not custody.
            && matches!(commands.prepare.outcome, C::NotDispatched | C::Exited | C::Unknown)
            && not_dispatched(&commands.archive) && t.result.is_none() && t.disposition.output == D::RetainedIncomplete,
        Case::UnsignedArchive | Case::Finality => t.outcome == O::Complete && t.reason == R::None
            && zero(&commands.xcode_version) && zero(&commands.ios_sdk) && zero(&commands.archive)
            && commands.prepare.outcome == C::NotConfigured && commands.prepare.exit_code.is_none()
            && t.activity.selection.as_ref().is_some_and(|s| s.symbols_policy == wire::SymbolsPolicy::Required)
            && t.result.is_some() && t.disposition.output == D::RetainedLocalResult,
    }
}
impl Record {
    pub(super) fn version_mutated(&mut self) -> bool {
        if self.version_mutated || !self.review_visible || !self.acknowledged || self.start_requested { return false; }
        self.version_mutated = true; true
    }
    fn request(&mut self, case: Case, step: Step, command: Command, value: &Value, project: Option<&str>) -> bool {
        match command {
            Command::Status => {
                if wire::status_request(value).is_err() || self.status_requested >= 64 { return false; }
                self.status_requested += 1; true
            },
            Command::Prepare => {
                if !matches!(step, Step::Prepare | Step::Review) || self.prepare_requested || self.version.is_none() { return false; }
                let Ok(input) = wire::prepare(value) else { return false; };
                let context = input.context();
                if !project.is_some_and(|project| context_matches(case, project, &context)) { return false; }
                self.context = Some(context); self.prepare_requested = true; true
            },
            Command::Start => {
                if !matches!(step, Step::Start | Step::Running) || !self.prepare_returned || !self.review_visible || !self.acknowledged || self.start_requested { return false; }
                let (Ok(input), Some(prepared)) = (wire::start(value), self.prepared.as_ref()) else { return false; };
                if input.operation_id != prepared.operation_id || input.owner_generation != prepared.owner_generation { return false; }
                self.start_requested = true; true
            },
            Command::Cancel => {
                if case != Case::Cancel || !matches!(step, Step::Cancel | Step::Running) || !self.start_requested || self.cancel_requested { return false; }
                let (Ok(input), Some(prepared)) = (wire::cancel(value), self.prepared.as_ref()) else { return false; };
                if input.operation_id != prepared.operation_id || input.owner_generation != prepared.owner_generation { return false; }
                self.cancel_requested = true; true
            },
        }
    }
    fn status(&mut self, status: &wire::Status) -> bool {
        if wire::status_bytes(status).is_err() { return false; }
        if let Some(op) = &status.operation {
            if self.context.as_ref() != Some(&op.context) || op.phase == wire::Phase::Unknown { return false; }
            if let Some(original) = &self.prepared {
                if original.operation_id != op.operation_id || original.owner_generation != op.owner_generation { return false; }
            } else if !self.prepare_requested || op.phase != wire::Phase::AwaitingConsent || !op.intent_usable { return false; }
            else { self.prepared = Some(op.clone()); }
        } else if self.prepared.is_some() && !self.status.as_ref().is_some_and(|old| status.status_revision < old.status_revision) { return false; }
        if let Some(previous) = &self.status {
            // A real invoke result may arrive after a newer same-owner relay
            // sample. It cannot undo observation or supply a new permission.
            if status.status_revision < previous.status_revision { return true; }
            if status.status_revision == previous.status_revision && status.operation != previous.operation { return false; }
        }
        self.status = Some(status.clone()); true
    }
    fn result(&mut self, command: Command, result: &Result<wire::Status, BridgeError>) -> bool {
        let Ok(status) = result else { return false; };
        let valid = match command {
            Command::Prepare => self.prepare_requested && !self.prepare_returned
                && status.operation.as_ref().is_some_and(|op| op.phase == wire::Phase::AwaitingConsent && op.intent_usable),
            Command::Start => self.start_requested && !self.start_returned,
            Command::Cancel => self.cancel_requested && !self.cancel_returned,
            Command::Status => self.status_returned < self.status_requested,
        };
        if !valid || !self.status(status) { return false; }
        match command { Command::Prepare => self.prepare_returned = true, Command::Start => self.start_returned = true,
            Command::Cancel => self.cancel_returned = true, Command::Status => self.status_returned += 1 }
        true
    }
    fn original(&mut self, case: Case, snapshot: Snapshot) -> bool {
        let Some(op) = self.status.as_ref().and_then(|s| s.operation.as_ref()) else { return false; };
        if !self.start_requested || !self.start_returned || op.phase != wire::Phase::Terminal || !snapshot.facts.final_for()
            || snapshot.facts.operation_id != op.operation_id || snapshot.facts.owner_generation != op.owner_generation
            || !terminal_for(case, &snapshot) || op.outcome != Some(snapshot.terminal.outcome)
            || op.reason != snapshot.terminal.reason || op.activity.as_ref() != Some(&snapshot.terminal.activity)
            || op.disposition.as_ref() != Some(&snapshot.terminal.disposition) || op.result != snapshot.terminal.result { return false; }
        if self.held.as_ref().is_some_and(|held| held.terminal != snapshot.terminal
            || held.facts.operation_id != snapshot.facts.operation_id || held.facts.owner_generation != snapshot.facts.owner_generation) { return false; }
        if let Some(previous) = &self.terminal { return previous == &snapshot; }
        self.terminal = Some(snapshot); true
    }
    pub(super) fn terminal(&self) -> Option<&Snapshot> { self.terminal.as_ref().filter(|_| self.final_dom) }
    pub(super) fn advance(&mut self, step: Step, control: &Control, document: &DocumentBinding) -> Option<Step> {
        match step {
            Step::VersionRead if self.version.is_none() => None,
            Step::Review if !self.prepare_returned => None,
            Step::Running => {
                if self.terminal.is_some() { return Some(Step::Final); }
                if control.case == Case::Cancel && !self.cancel_requested && self.start_returned
                    && self.status.as_ref().and_then(|s| s.operation.as_ref()).is_some_and(|op|
                        op.phase == wire::Phase::Running && op.stage == Some(wire::Stage::Preparing)) { return Some(Step::Cancel); }
                if control.case == Case::Finality && !self.released {
                    if let Some(snapshot) = control.held_snapshot() {
                        if !self.prepared.as_ref().is_some_and(|op| snapshot.facts.operation_id == op.operation_id
                            && snapshot.facts.owner_generation == op.owner_generation) { control.unavailable_witness(); return None; }
                        if self.held.as_ref().is_some_and(|old| old != &snapshot) { control.unavailable_witness(); return None; }
                        let status = document.environment_diagnostics_status();
                        if !status.as_ref().is_ok_and(|s| !s.capability.available
                            && s.capability.reason == crate::environment_diagnostics_protocol::Availability::Busy) {
                            control.unavailable_witness(); return None;
                        }
                        self.held = Some(snapshot); self.reciprocal_blocked = true; return Some(Step::Hold);
                    }
                }
                None
            },
            Step::ReleaseHold => {
                if !self.held_dom || !self.reciprocal_blocked || self.released || !control.release_hold() {
                    control.unavailable_witness(); return None;
                }
                self.released = true; Some(Step::Running)
            },
            _ => Some(step),
        }
    }
}

/// Inert protocol/comparison regressions in the existing native test target.
/// No Observation constructor, diagnostic writer, native owner or task starts;
/// these synthetic values never leave the checks as an observed receipt.
pub(super) fn data_checks() -> bool {
    for case in Case::ALL {
        if Case::parse(OsStr::new(case.name())) != Some(case)
            || Case::parse(OsStr::new(&format!("{}-other", case.name()))).is_some() { return false; }
    }
    if Case::parse(OsStr::new("first-save")).is_some() || Case::parse(OsStr::new("IOS-UNSIGNED-ARCHIVE")).is_some() { return false; }
    let control = Control::new(Case::UnsignedArchive);
    let document = Arc::new(()); let owner = Arc::new(()); let foreign = Arc::new(());
    let token = Admission { control: control.clone(), document: Arc::downgrade(&document), owner: Arc::downgrade(&owner) };
    if !token.document_matches(&document) || token.document_matches(&foreign) || control.permits()
        || control.claim().is_ok() || token.consume(&owner).is_ok() { return false; }
    let dead = Arc::downgrade(&foreign); drop(foreign);
    let token = Admission { control: control.clone(), document: dead, owner: Arc::downgrade(&owner) };
    if token.document_matches(&document) || token.consume(&owner).is_ok() || control.claimed.load(Ordering::SeqCst) { return false; }

    let case = Case::UnsignedArchive;
    let observed = version_value(case);
    let input = json!({"projectId":"inert-ios-parser","draftRevision":1,"baselineGeneration":1,
        "savedConfig":observed["savedConfig"],"savedVersion":{"source":"version.properties","name":"1.2.3","build":7,
            "bytes":super::VERSION.len(),"sha256":super::digest(super::VERSION)}});
    let Ok(preparation) = wire::prepare(&input) else { return false; };
    let context = preparation.context();
    if !context_matches(case, "inert-ios-parser", &context) || context_matches(Case::Cancel, "inert-ios-parser", &context)
        || context_matches(case, "foreign-project", &context) { return false; }
    let mut old_pair = context.clone(); old_pair.saved_version.build = 8;
    if context_matches(case, "inert-ios-parser", &old_pair) { return false; }
    let operation = "a".repeat(32); let generation = "b".repeat(32);
    let prepared = wire::Projection { operation_id: operation.clone(), owner_generation: generation.clone(), context: context.clone(),
        phase: wire::Phase::AwaitingConsent, intent_usable: true, outcome: None, reason: wire::Reason::None,
        stage: None, activity: None, disposition: None, result: None };
    let mut status = wire::Status { schema_version: 1, status_revision: 1, availability: wire::Availability::Busy, operation: Some(prepared) };
    let mut record = Record::default();
    if record.request(case, Step::Prepare, Command::Prepare, &input, Some("inert-ios-parser")) { return false; }
    record.version = Some(observed);
    if !record.request(case, Step::Prepare, Command::Prepare, &input, Some("inert-ios-parser"))
        || record.request(case, Step::Prepare, Command::Prepare, &input, Some("inert-ios-parser"))
        || !record.result(Command::Prepare, &Ok(status.clone()))
        || record.result(Command::Prepare, &Ok(status.clone())) { return false; }
    let start = json!({"operationId":operation,"ownerGeneration":generation,"consentVersion":wire::CONSENT});
    if record.request(case, Step::Start, Command::Start, &start, Some("inert-ios-parser")) { return false; }
    record.review_visible = true; record.acknowledged = true;
    let mut other = start.clone(); other["ownerGeneration"] = json!("c".repeat(32));
    if record.request(case, Step::Start, Command::Start, &other, Some("inert-ios-parser"))
        || !record.request(case, Step::Start, Command::Start, &start, Some("inert-ios-parser"))
        || record.request(case, Step::Start, Command::Start, &start, Some("inert-ios-parser")) { return false; }

    let mut value = wire::tests::complete();
    value["context"] = serde_json::to_value(&context).unwrap();
    value["result"]["usedConfig"] = value["context"]["savedConfig"].clone();
    value["result"]["usedVersion"] = value["context"]["savedVersion"].clone();
    value["activity"]["selection"] = json!({"containerKind":"project","container":"ios/MRKObserved.xcodeproj",
        "scheme":"MRKObserved","configuration":"Release","bundleId":super::APP_ID,"symbolsPolicy":"required","preparationConfigured":false});
    let Ok(terminal) = wire::terminal(&value, &context, &operation) else { return false; };
    let facts = OriginalFacts { operation_id: operation, owner_generation: generation,
        inspection_joined: true, acquisition_joined: true, attempted: true, child_waited_success: true,
        stdin_closed: true, stdout_eof_closed: true, stderr_eof_closed: true, io_joined: true, core_lifetime_settled: true,
        runtime_ledger_settled: true, tools_ledger_settled: true, native_settlement_joined: true, native_integrity: true,
        driver_joined: true, manager_joined: true, observer_joined: true, watchdog_joined: true,
        retired_before_cutoff: true, active_retained: false, resource_unknown: false, work_ms: 300_000, hard_ms: 310_000 };
    if !facts.final_for() || facts.held() { return false; }
    let held = OriginalFacts { observer_joined: false, watchdog_joined: false, retired_before_cutoff: false,
        active_retained: true, ..facts.clone() };
    if !held.held() || held.final_for() { return false; }
    let mutations: &[fn(&mut OriginalFacts)] = &[
        |f| f.inspection_joined = false, |f| f.acquisition_joined = false, |f| f.child_waited_success = false,
        |f| f.stdin_closed = false, |f| f.stdout_eof_closed = false, |f| f.stderr_eof_closed = false, |f| f.io_joined = false,
        |f| f.core_lifetime_settled = false, |f| f.runtime_ledger_settled = false, |f| f.tools_ledger_settled = false,
        |f| f.native_settlement_joined = false, |f| f.native_integrity = false, |f| f.driver_joined = false,
        |f| f.manager_joined = false, |f| f.resource_unknown = true, |f| f.work_ms += 1, |f| f.hard_ms += 1,
    ];
    for mutate in mutations {
        let mut late = facts.clone(); mutate(&mut late);
        let mut incomplete = held.clone(); mutate(&mut incomplete);
        if late.final_for() || incomplete.held() { return false; }
    }
    let snapshot = Snapshot { facts, terminal };
    if !terminal_for(case, &snapshot) || !terminal_for(Case::Finality, &snapshot)
        || [Case::ToolchainPrerequisite, Case::VersionStale, Case::Cancel].into_iter().any(|case| terminal_for(case, &snapshot)) { return false; }
    // A valid core terminal is insufficient before original status publication.
    if record.original(case, snapshot.clone()) { return false; }
    let op = status.operation.as_mut().unwrap();
    op.phase = wire::Phase::Terminal; op.intent_usable = false; op.outcome = Some(snapshot.terminal.outcome);
    op.stage = Some(snapshot.terminal.activity.stage); op.activity = Some(snapshot.terminal.activity.clone());
    op.disposition = Some(snapshot.terminal.disposition.clone()); op.result = snapshot.terminal.result.clone();
    status.status_revision += 1;
    if !record.result(Command::Start, &Ok(status.clone())) { return false; }
    let mut foreign = snapshot.clone(); foreign.facts.owner_generation = "c".repeat(32);
    let mut provisional = snapshot.clone(); provisional.facts = held.clone();
    if record.original(case, foreign) || record.original(case, provisional)
        || !record.original(case, snapshot.clone()) || record.terminal().is_some() { return false; }
    let mut held_record = record.clone(); held_record.held = Some(Snapshot { facts: held, terminal: snapshot.terminal.clone() });
    if !held_record.original(Case::Finality, snapshot.clone()) { return false; }
    held_record.held.as_mut().unwrap().terminal.activity.commands.archive.exit_code = Some(1);
    !held_record.original(Case::Finality, snapshot)
}

pub(super) fn snapshot_failure(value: &Value, root: &std::path::Path, case: Case, base: &Value) -> Option<&'static str> {
    let config_value = &value["config"]; let hints = &value["discovery"]["hints"];
    if value["root"].as_str() != root.to_str() { return Some("snapshot-value-root"); }
    if value["observationScope"] != "single-request-non-atomic" { return Some("snapshot-value-scope"); }
    if config_value["path"] != "release/mobile-release.json" { return Some("snapshot-config-path"); }
    if !super::assurance(value, "static-text") { return Some("snapshot-value-assurance"); }
    if !value["issues"].as_array().is_some_and(Vec::is_empty) { return Some("snapshot-value-issues"); }
    if !hints["android"].is_null() || hints["ios"]["projects"] != json!(["ios/MRKObserved.xcodeproj"])
        || hints["ios"]["workspaces"] != json!([]) || hints["ios"]["schemes"] != json!(["MRKObserved"])
        || hints["ios"]["bundleIds"] != json!([super::APP_ID]) || hints["ios"]["bundleId"] != super::APP_ID {
        return Some("ios-fixture-contract");
    }
    if hints["versionSource"] != "version.properties" || hints["versionNameKey"] != "VERSION_NAME"
        || hints["versionBuildKey"] != "BUILD_NUMBER" { return Some("snapshot-hints-version"); }
    if value["discovery"]["partial"] != false || value["discovery"]["state"] != "unverified" {
        return Some("snapshot-discovery-state");
    }
    if config_value["state"] != "format-valid" { return Some("snapshot-config-state"); }
    if config_value["data"] != *base { return Some("snapshot-config-data"); }
    if config_value["content"] != json!({"bytes":config(case).len(),"sha256":super::digest(config(case))}) {
        return Some("snapshot-config-content");
    }
    if !config_value["issues"].as_array().is_some_and(Vec::is_empty) { return Some("snapshot-config-issues"); }
    None
}

impl Observation {
    pub(crate) fn attach_ios(self: &Arc<Self>, document: &DocumentBinding, owner: &IOSArchiveOwner) -> Result<(), BridgeError> {
        match &self.ios { Some(control) => control.attach(self, document, owner), None => Ok(()) }
    }
    pub(crate) fn release_version_request(&self, value: &Value) {
        let Some(control) = &self.ios else { return; };
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !matches!(r.step, super::Step::Ios(Step::ReadVersion | Step::VersionRead))
            || r.project.as_ref().map(|p| json!({"projectId":p.id})).as_ref() != Some(value) {
            self.fail_with("ios-version-contract"); return;
        }
        let Some(ios) = r.ios_record.as_mut() else { self.fail_with("ios-version-contract"); return; };
        if ios.version_requested || ios.version.is_some() || !control.permits() { self.fail_with("ios-version-contract"); return; }
        ios.version_requested = true;
    }
    pub(crate) fn release_version(&self, result: &Result<crate::release_version_protocol::Observation, BridgeError>) {
        let Some(control) = &self.ios else { return; };
        let Some(mut r) = self.record() else { return; };
        let Some(ios) = r.ios_record.as_mut() else { self.fail_with("ios-version-contract"); return; };
        let value = result.as_ref().ok().and_then(|value| serde_json::to_value(value).ok());
        if !self.timely() || !ios.version_requested || ios.version.is_some() || value != Some(version_value(control.case)) {
            self.fail_with("ios-version-contract"); return;
        }
        ios.version = value;
    }
    pub(crate) fn ios_request(&self, command: Command, value: &Value) {
        let Some(control) = &self.ios else { return; };
        let Some(mut r) = self.record() else { return; };
        let step = match r.step { super::Step::Ios(step) => step, _ if command == Command::Status => Step::Navigate,
            _ => { self.fail_with("ios-request-contract"); return; } };
        let project = r.project.as_ref().map(|p| p.id.clone());
        if !self.timely() || !r.ios_record.as_mut().is_some_and(|ios| ios.request(control.case, step, command, value, project.as_deref())) {
            self.fail_with("ios-request-contract");
        }
    }
    pub(crate) fn ios_result(&self, command: Command, result: &Result<wire::Status, BridgeError>) {
        if self.ios.is_none() { return; }
        let Some(mut r) = self.record() else { return; };
        if !self.timely() || !r.ios_record.as_mut().is_some_and(|ios| ios.result(command, result)) {
            self.fail_with("ios-status-contract");
        }
    }
    pub(crate) fn ios_status(&self, status: &wire::Status, owner: &IOSArchiveOwner) {
        let Some(control) = &self.ios else { return; };
        // Read the actual original owner without holding this observer Record.
        // Busy native guards yield no sample, never a guessed join or fallback.
        let terminal = status.operation.as_ref().is_some_and(|op| op.phase == wire::Phase::Terminal);
        let snapshot = terminal.then(|| owner.installed_ios_snapshot()).flatten();
        let Some(mut r) = self.record() else { return; };
        let Some(ios) = r.ios_record.as_mut() else { self.fail_with("ios-status-contract"); return; };
        if !self.timely() || !ios.status(status) { self.fail_with("ios-status-contract"); return; }
        if terminal && ios.start_returned {
            // A transient borrow refusal can be retried by this SAME ordinary
            // relay. It is not positive evidence and never changes the cutoff.
            if let Some(snapshot) = snapshot {
                if !ios.original(control.case, snapshot) { self.fail_with("ios-finality-contract"); }
            }
        }
    }
}

pub(super) fn script(step: Step) -> Option<&'static str> { Some(match step {
    Step::Navigate => "return nav('Releases');",
    Step::ReadVersion => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="observe-version"]');
        if(!b||b.disabled)return wait();show(b);b.click();return ready();"#,
    Step::VersionRead => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="review"]');
        const v=[...r.querySelectorAll(':scope > p')].find(p=>text(p).startsWith('Saved version '));if(!v||!b||b.disabled)return wait();show(v);
        return {state:'ready',version:text(v),reviewAvailable:true};"#,
    Step::Prepare => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="review"]');
        if(!b||b.disabled)return wait();if(r.dataset.phase!=='idle')throw 0;show(b);b.click();return ready();"#,
    Step::Review => r#"const r=ios();if(!r)return wait();if(r.dataset.phase!=='awaiting-consent')return wait();
        const check=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),start=r.querySelector('[data-mrk-ios-archive-action="start"]');
        if(!check||!start)return wait();show(check);return {state:'ready',checked:check.checked,startAvailable:!start.disabled,
            identityVisible:text(r).includes('org.example.mrk.observed')&&text(r).includes('ios/MRKObserved.xcodeproj')
                &&text(r).includes('scheme MRKObserved')&&text(r).includes('saved version 1.2.3')&&text(r).includes('build 7')};"#,
    Step::Acknowledge => r#"const r=ios();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]');
        if(!c||c.disabled)return wait();if(c.type!=='checkbox'||c.checked||r.dataset.phase!=='awaiting-consent')throw 0;show(c);c.click();return ready();"#,
    Step::Acknowledged => r#"const r=ios();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),b=r.querySelector('[data-mrk-ios-archive-action="start"]');
        if(!c||!b||!c.checked||b.disabled)return wait();show(b);return {state:'ready',checked:c.checked,startAvailable:!b.disabled};"#,
    Step::Start => r#"const r=ios();if(!r)return wait();const c=r.querySelector('[data-mrk-ios-archive-action="acknowledge"]'),b=r.querySelector('[data-mrk-ios-archive-action="start"]');
        if(!c||!b||b.disabled)return wait();if(!c.checked||r.dataset.phase!=='awaiting-consent')throw 0;show(b);b.click();return ready();"#,
    Step::Cancel => r#"const r=ios();if(!r)return wait();const b=r.querySelector('[data-mrk-ios-archive-action="cancel"]');
        if(!b||b.disabled||r.dataset.phase!=='running'||r.dataset.stage!=='preparing')return wait();show(b);b.click();return ready();"#,
    Step::Hold => r#"const r=ios();if(!r)return wait();if(!['running','stopping'].includes(r.dataset.phase)||r.dataset.stage!=='disposing-work')return wait();
        const read=r.querySelector('[data-mrk-ios-archive-action="observe-version"]'),review=r.querySelector('[data-mrk-ios-archive-action="review"]');
        const refresh=[...r.querySelectorAll('button')].find(b=>text(b)==='Refresh saved configuration');if(!read||!review||!refresh)return wait();show(r);
        return {state:'ready',publicSuccessHidden:r.dataset.outcome===''&&!r.querySelector('.offline-report'),
            readBlocked:read.disabled,reviewBlocked:review.disabled,refreshBlocked:refresh.disabled};"#,
    Step::Final => r#"const r=ios();if(!r||r.dataset.phase!=='terminal')return wait();const p=r.querySelector('.session-progress'),report=r.querySelector('.offline-report');
        if(!p)return wait();show(p);return {state:'ready',phase:r.dataset.phase,outcome:r.dataset.outcome,
            commands:[...p.querySelectorAll(':scope > ul > li')].map(text),resultPresent:!!report,
            archive:report?text(report.querySelector('p > code')):null};"#,
    Step::Running | Step::MutateVersion | Step::ReleaseHold => return None,
}) }
impl Record {
    pub(super) fn dom(&mut self, case: Case, step: Step, value: &Value) -> Result<Option<Step>, ()> {
        let only_ready = || value == &json!({"state":"ready"});
        let next = match step {
            Step::Navigate if only_ready() => Step::ReadVersion,
            Step::ReadVersion if only_ready() => Step::VersionRead,
            Step::VersionRead if self.version.is_some() && *value == json!({"state":"ready",
                "version":"Saved version 1.2.3 · build 7 · source version.properties.","reviewAvailable":true}) => Step::Prepare,
            Step::Prepare if only_ready() => Step::Review,
            Step::Review if self.prepare_returned && self.prepared.is_some() && *value == json!({"state":"ready",
                "checked":false,"startAvailable":false,"identityVisible":true}) => { self.review_visible = true; Step::Acknowledge },
            Step::Acknowledge if only_ready() => Step::Acknowledged,
            Step::Acknowledged if self.review_visible && *value == json!({"state":"ready","checked":true,"startAvailable":true}) => {
                self.acknowledged = true; if case == Case::VersionStale { Step::MutateVersion } else { Step::Start }
            },
            Step::Start if only_ready() => Step::Running,
            Step::Cancel if only_ready() => Step::Running,
            Step::Hold if case == Case::Finality && self.held.is_some() && self.reciprocal_blocked && !self.released
                && *value == json!({"state":"ready","publicSuccessHidden":true,"readBlocked":true,"reviewBlocked":true,"refreshBlocked":true}) => {
                    self.held_dom = true; Step::ReleaseHold
                },
            Step::Final => {
                let snapshot = self.terminal.as_ref().ok_or(())?;
                let commands = &snapshot.terminal.activity.commands;
                let words = |label: &str, command: &wire::CommandData| match command.outcome {
                    wire::CommandOutcome::Exited => format!("{label}: known exit {}.", command.exit_code.unwrap_or(i32::MIN)),
                    wire::CommandOutcome::NotConfigured => format!("{label}: not configured."),
                    wire::CommandOutcome::NotDispatched => format!("{label}: not dispatched."),
                    wire::CommandOutcome::Unknown => format!("{label}: no usable original outcome."),
                };
                let archive = snapshot.terminal.result.as_ref().map(|result| result.archive.clone());
                if *value != json!({"state":"ready","phase":"terminal","outcome":snapshot.terminal.outcome,
                    "commands":[words("Xcode version",&commands.xcode_version),words("iOS SDK selection",&commands.ios_sdk),
                        words("Saved preparation",&commands.prepare),words("Unsigned archive",&commands.archive)],
                    "resultPresent":snapshot.terminal.result.is_some(),"archive":archive}) { return Err(()); }
                self.final_dom = true; return Ok(None);
            },
            _ => return Err(()),
        };
        Ok(Some(next))
    }
    pub(super) fn report(&self, case: Case) -> Option<Value> {
        let terminal = self.terminal()?;
        if !self.prepare_requested || !self.prepare_returned || !self.review_visible || !self.acknowledged
            || !self.start_requested || !self.start_returned || self.status_requested != self.status_returned
            || self.cancel_requested != (case == Case::Cancel) || self.cancel_returned != self.cancel_requested
            || self.released != (case == Case::Finality) || self.held_dom != self.released || self.reciprocal_blocked != self.released
            || self.held.is_some() != self.released || !terminal_for(case, terminal) { return None; }
        if self.version_mutated != (case == Case::VersionStale) { return None; }
        Some(json!({"protocol":wire::PROTOCOL,"savedVersionObservation":self.version,"context":self.context,
            "prepareRequestedOnce":true,"prepareReturned":true,"reviewVisible":true,"acknowledged":true,
            "startRequestedOnce":true,"startReturned":true,"statusCallsReturned":self.status_returned,
            "staleVersionWriterReturnedAndClosed":self.version_mutated,
            "original":terminal,"finalResultVisible":self.final_dom,
            "prerequisiteOnly":case == Case::ToolchainPrerequisite,
            "cancel":if case == Case::Cancel { Some(json!({"requestedOnce":true,"returned":true,
                "stageAtClick":"preparing","prepareOutcome":terminal.terminal.activity.commands.prepare,
                "activeCommandKillClaimed":false})) } else { None },
            "hold":self.held.as_ref().map(|snapshot| json!({"original":snapshot,"publicSuccessHidden":self.held_dom,
                "conflictingUiBlocked":self.held_dom,"environmentDiagnosticsBlocked":self.reciprocal_blocked,
                "originalReleasedOnce":self.released})),
            "workMs":300000,"hardMs":310000,"observationMs":315000,"outerInvocationMs":325000}))
    }
}
