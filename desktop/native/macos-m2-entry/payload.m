/* Synthetic full AppKit bundle, not Tauri and not a credential helper. */
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include "fixture.h"

static int root_original = -1, gate_original = -1;
static BOOL entry_pid_preserved, inherited_without_cloexec, marked_cloexec, executable_is_payload;
static NSString *text(const char *value) { return [NSString stringWithUTF8String:value]; }
static NSNumber *truth(int value) { return value ? @YES : @NO; }
static BOOL publish(NSString *name, NSDictionary *value) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:&error];
    if (!data || error || data.length > 4095) return NO;
    NSString *body = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] stringByAppendingString:@"\n"];
    return body && mrk_record(root_original, name.UTF8String, body.UTF8String);
}

/* Five fixed progress witnesses, once per site through the admitted root.
   The latch is consumed before formatting/writing, including failed attempts. */
enum appkit_progress {
    APPKIT_SHARED_RETURNED = 1U << 0,
    APPKIT_POLICY_RETURNED = 1U << 1,
    APPKIT_BEFORE_RUN = 1U << 2,
    APPKIT_DID_FINISH = 1U << 3,
    APPKIT_RUN_RETURNED = 1U << 4
};
static unsigned appkit_attempted;
static void publish_appkit_progress(enum appkit_progress progress, BOOL policy_accepted) {
    const char *name, *phase, *policy = "null", *selected = "null";
    switch (progress) {
    case APPKIT_SHARED_RETURNED:
        name = "payload-appkit-shared.json"; phase = "shared-application-returned"; break;
    case APPKIT_POLICY_RETURNED:
        name = "payload-appkit-policy.json"; phase = "activation-policy-returned";
        policy = policy_accepted ? "true" : "false";
        selected = policy_accepted ? "null" : "67"; break;
    case APPKIT_BEFORE_RUN:
        name = "payload-appkit-before-run.json"; phase = "setup-complete-before-run"; break;
    case APPKIT_DID_FINISH:
        name = "payload-appkit-did-finish.json"; phase = "did-finish-launching-entered"; break;
    case APPKIT_RUN_RETURNED:
        name = "payload-appkit-run-returned.json"; phase = "run-returned"; selected = "74"; break;
    default: return;
    }
    unsigned bit = (unsigned)progress;
    if (appkit_attempted & bit) return;
    appkit_attempted |= bit;
    char record[768];
    int n = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"source\":\"%s\",\"case\":\"ls-full-payload\",\"phase\":\"%s\","
        "\"policySwitchAccepted\":%s,\"selectedReturnCode\":%s}\n",
        MRK_SOURCE, phase, policy, selected);
    if (n > 0 && (size_t)n < sizeof(record))
        (void)mrk_record(root_original, name, record);
    /* Readable DATA is not final fsync/close, process exit or worker finality. */
}

@interface M2Payload : NSObject <NSApplicationDelegate>
@property(strong) NSWindow *window;
@property(strong) NSTimer *observationLimit;
@property BOOL didFinishLaunching;
@property BOOL readyPublished;
@property BOOL normalQuitRequested;
@end

@implementation M2Payload
- (void)publishObservation {
    if (self.readyPublished || !self.didFinishLaunching) return;
    self.readyPublished = YES;
    [self.observationLimit invalidate]; self.observationLimit = nil;
    NSRunningApplication *running = NSRunningApplication.currentApplication;
    NSDictionary *facts = @{
        @"schemaVersion": @1, @"source": text(MRK_SOURCE),
        @"scope": @"synthetic-appkit-payload-not-tauri",
        @"processIdentifier": @((long long)getpid()),
        @"entryPidPreserved": truth(entry_pid_preserved),
        @"originalAccount": truth(mrk_account()),
        @"gateIdentity": truth(mrk_gate_matches(root_original, gate_original)),
        @"gateInheritedWithoutCLOEXEC": truth(inherited_without_cloexec),
        @"gateMarkedCLOEXEC": truth(marked_cloexec),
        @"exclusiveWouldBlock": truth(mrk_exclusive_probe(root_original) == 0),
        @"executableIsPayload": truth(executable_is_payload),
        @"mainBundleIsPayload": truth([NSBundle.mainBundle.bundleURL.path isEqualToString:text(MRK_PAYLOAD_APP)]),
        @"mainBundleIDIsPayload": truth([NSBundle.mainBundle.bundleIdentifier isEqualToString:text(MRK_PAYLOAD_ID)]),
        @"runningObjectExists": truth(running != nil),
        @"runningExecutableIsPayload": truth([running.executableURL.path isEqualToString:text(MRK_PAYLOAD_EXE)]),
        @"runningExecutableIsEntry": truth([running.executableURL.path isEqualToString:text(MRK_ENTRY_APP "/Contents/MacOS/entry")]),
        @"runningBundleIsPayload": truth([running.bundleURL.path isEqualToString:text(MRK_PAYLOAD_APP)]),
        @"runningBundleIsEntry": truth([running.bundleURL.path isEqualToString:text(MRK_ENTRY_APP)]),
        @"runningIDIsPayload": truth([running.bundleIdentifier isEqualToString:text(MRK_PAYLOAD_ID)]),
        @"runningIDIsEntry": truth([running.bundleIdentifier isEqualToString:text(MRK_ENTRY_ID)]),
        @"didFinishLaunching": truth(self.didFinishLaunching),
        @"windowVisible": truth(self.window.visible), @"appActive": truth(NSApp.active)
    };
    if (!publish(@"payload-start.json", facts)) _exit(72);
}
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    publish_appkit_progress(APPKIT_DID_FINISH, NO);
    self.didFinishLaunching = YES;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 560, 180)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.title = @"Mobile Release Kit entry feasibility";
    NSTextField *label = [NSTextField labelWithString:@"Synthetic AppKit payload only. No project, credentials or Store operation."];
    label.frame = NSMakeRect(24, 72, 512, 50);
    [self.window.contentView addSubview:label];
    [self.window center]; [self.window makeKeyAndOrderFront:nil];
    [NSApp activate]; /* Request, not proof: the observed active flag is separate. */
    self.observationLimit = [NSTimer scheduledTimerWithTimeInterval:5.0 repeats:NO block:^(NSTimer *timer) {
        (void)timer; [self publishObservation];
    }];
    if (NSApp.active && self.window.visible) [self publishObservation];
}
- (void)applicationDidBecomeActive:(NSNotification *)notification {
    (void)notification;
    if (self.didFinishLaunching && self.window.visible) [self publishObservation];
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    (void)sender; self.normalQuitRequested = YES; return NSTerminateNow;
}
- (void)applicationWillTerminate:(NSNotification *)notification {
    (void)notification;
    [self.observationLimit invalidate]; self.observationLimit = nil;
    BOOL recorded = publish(@"payload-quit.json", @{
        @"schemaVersion": @1, @"source": text(MRK_SOURCE),
        @"normalQuitDelegateObserved": truth(self.normalQuitRequested),
        @"gateStillHeldAtWillTerminate": truth(mrk_gate_matches(root_original, gate_original)
            && mrk_exclusive_probe(root_original) == 0)
    });
    if (!mrk_close(&root_original) || !recorded) _exit(73);
    /* AppKit terminate does not return through main. Never close/unlock gate. */
}
@end

/* One best-effort phase record, only after the original main root admission.
   This never opens/re-admits a root, changes a selected refusal, or probes a lock. */
enum main_outcome { MAIN_GATE_REFUSED, MAIN_HANDOFF_REFUSED, MAIN_ADMITTED };
static void publish_main_outcome(enum main_outcome outcome) {
    const char *phase, *selected;
    switch (outcome) {
    case MAIN_GATE_REFUSED: phase = "main-gate-refused"; selected = "65"; break;
    case MAIN_HANDOFF_REFUSED: phase = "main-handoff-refused"; selected = "66"; break;
    case MAIN_ADMITTED: phase = "main-admitted-before-appkit"; selected = "null"; break;
    default: return;
    }
    int handoff_known = outcome != MAIN_GATE_REFUSED;
    char record[768];
    int n = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"source\":\"%s\",\"case\":\"ls-full-payload\",\"phase\":\"%s\","
        "\"selectedReturnCode\":%s,\"gateMatchAccepted\":%s,\"entryPidPreserved\":%s,"
        "\"gateInheritedWithoutCLOEXEC\":%s,\"gateMarkedCLOEXEC\":%s,\"executableIsPayload\":%s}\n",
        MRK_SOURCE, phase, selected, handoff_known ? "true" : "false",
        !handoff_known ? "null" : entry_pid_preserved ? "true" : "false",
        !handoff_known ? "null" : inherited_without_cloexec ? "true" : "false",
        !handoff_known ? "null" : marked_cloexec ? "true" : "false",
        !handoff_known ? "null" : executable_is_payload ? "true" : "false");
    if (n > 0 && (size_t)n < sizeof(record))
        (void)mrk_record(root_original, "payload-main.json", record);
    /* Readable phase DATA is not final fsync/close, process exit or SH evidence. */
}

int main(int argc, char **argv) {
    @autoreleasepool {
        int original_pid = -1;
        if (argc != 3 || !mrk_account() || !mrk_decimal(argv[1], 3, &gate_original)
            || !mrk_decimal(argv[2], 1, &original_pid)) return 64;
        root_original = mrk_root();
        if (root_original < 0) return 65;
        int gate_matched = mrk_gate_matches(root_original, gate_original);
        if (!gate_matched) {
            publish_main_outcome(MAIN_GATE_REFUSED);
            return 65;
        }
        entry_pid_preserved = getpid() == original_pid;
        inherited_without_cloexec = fcntl(gate_original, F_GETFD) == 0;
        marked_cloexec = !fcntl(gate_original, F_SETFD, FD_CLOEXEC)
            && fcntl(gate_original, F_GETFD) == FD_CLOEXEC;
        char executable[PATH_MAX]; uint32_t capacity = sizeof(executable);
        executable_is_payload = !_NSGetExecutablePath(executable, &capacity)
            && !strcmp(executable, MRK_PAYLOAD_EXE);
        if (!entry_pid_preserved || !inherited_without_cloexec || !marked_cloexec) {
            publish_main_outcome(MAIN_HANDOFF_REFUSED);
            return 66;
        }
        publish_main_outcome(MAIN_ADMITTED);
        NSApplication *app = NSApplication.sharedApplication;
        publish_appkit_progress(APPKIT_SHARED_RETURNED, NO);
        const BOOL policy_accepted = [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        const int selected_policy_return = policy_accepted ? 0 : 67;
        publish_appkit_progress(APPKIT_POLICY_RETURNED, policy_accepted);
        if (!policy_accepted) return selected_policy_return;
        M2Payload *delegate = [M2Payload new]; app.delegate = delegate;
        NSMenu *main = [NSMenu new], *menu = [NSMenu new];
        NSMenuItem *application = [NSMenuItem new]; [main addItem:application];
        NSMenuItem *quit = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
        quit.target = app; [menu addItem:quit]; application.submenu = menu; app.mainMenu = main;
        publish_appkit_progress(APPKIT_BEFORE_RUN, NO);
        [app run];
        const int selected_run_return = 74;
        publish_appkit_progress(APPKIT_RUN_RETURNED, NO);
        return selected_run_return; /* Unexpected run-loop return is not normal Quit/finality. */
    }
}
