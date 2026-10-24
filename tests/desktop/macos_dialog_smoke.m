// Nonshipping local/CI smoke: actual AppKit and the source AX reader only.
// It opens only its own window/fixture panel and never selects a user project.
#define MRK_INSTALLED_OBSERVATION 1
#include "../../desktop/native/macos-installed-native/src/native.m"

static uint64_t smoke_end;
static float smoke_allowance = 0.5f;
static uint64_t smoke_last_required;

static int smoke_admit(void *context, uint64_t required, int after, MRKOpenTimeout *timeout) {
    (void)context; (void)after;
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (now >= smoke_end || required > smoke_end - now) return MRK_OPEN_DEADLINE;
    if (required) smoke_last_required = required;
    if (timeout) {
        timeout->seconds = smoke_allowance == 0.1f ? nextafterf(0.1f, 0.0f) : smoke_allowance;
        timeout->required_ns = (uint64_t)ceil((double)timeout->seconds * 1e9);
    }
    return 0;
}

typedef struct {
    MRKInstalledPanel *original;
    uint8_t parent[64], panel[64], prompt[64], target[4097];
    MRKOpenResult result;
} SmokeOpen;

static int smoke_recheck(void *context, int stage) {
    SmokeOpen *s = context;
    __block MRKOpenRecheck result = {0};
    dispatch_sync(dispatch_get_main_queue(), ^{
        mrk_panel_observe_open_recheck(s->original, s->parent, s->panel, s->prompt,
            s->target, sizeof(s->target), 0, stage, &result);
    });
    if (!result.known) return MRK_OPEN_CUSTODY;
    if (result.error) return result.error;
    if (result.prompt != 1 || result.proof.matched != MRK_PROOF_ALL) return MRK_OPEN_CHANGED;
    return smoke_admit(context, 0, 0, NULL);
}

// Full native Open on this fixture only: real identity, both rechecks, one
// AXPress and the actual original callback/path. No app service or user files.
static void smoke_open_project(NSWindow *window, const char *directory) {
    SmokeOpen *s = calloc(1, sizeof(*s));
    if (!s || strlcpy((char *)s->target, directory, sizeof(s->target)) >= sizeof(s->target)) exit(2);
    s->original = mrk_panel_reserve();
    if (!s->original || mrk_panel_observe_arm_open_identity(s->original, s->target, sizeof(s->target))
        || mrk_panel_start(s->original, 1)) exit(3);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500000000), dispatch_get_main_queue(), ^{
        smoke_end = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) + 2000000000ull;
        int identity = mrk_panel_observe_open_identity(s->original, s->parent, s->panel, s->prompt,
            sizeof(s->parent), s->target, sizeof(s->target), 0);
        if (identity) {
            printf("{\"case\":\"open-project-completion\",\"passed\":false,\"identityError\":%d}\n", identity);
            exit(1);
        }
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool {
                mrk_observation_prompt_press(s->parent, s->panel, s->prompt, sizeof(s->parent),
                    s->target, sizeof(s->target), 0, smoke_admit, smoke_recheck, s, &s->result);
            }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300000000), dispatch_get_main_queue(), ^{
                int response = 0; uint8_t selected[4097] = {0}; MRKCompletionWire completion = {0};
                int poll = mrk_panel_poll(s->original, &response, selected, sizeof(selected));
                mrk_panel_observe_completion_data(s->original, &completion);
                BOOL passed = s->result.error == 0 && s->result.flags == 15
                    && s->result.owned == s->result.released && poll == 1 && response == 1
                    && !memcmp(selected, s->target, sizeof(selected))
                    && completion.flags == 15 && completion.response == MRK_COMPLETION_ACCEPT
                    && completion.selection == MRK_SELECTION_MATCH;
                int close = mrk_panel_close(s->original);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100000000), dispatch_get_main_queue(), ^{
                    int ignored = 0; uint8_t path[4097] = {0};
                    int closed = mrk_panel_poll(s->original, &ignored, path, sizeof(path));
                    BOOL released = close == 0 && closed == 2 && mrk_panel_release(s->original) == 0;
                    printf("{\"case\":\"open-project-completion\",\"passed\":%s,\"axError\":%d,\"error\":%u,\"site\":%u,\"flags\":%u,\"calls\":%u,\"completion\":%u,\"selection\":%u,\"released\":%s}\n",
                        passed && released ? "true" : "false", s->result.ax_error, s->result.error,
                        s->result.site, s->result.flags, s->result.calls, completion.flags, completion.selection,
                        released ? "true" : "false");
                    [window close]; free(s); exit(passed && released ? 0 : 1);
                });
            });
        });
    });
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 2 && !strcmp(argv[1], "--request-access")) {
            NSDictionary *options = @{(NSString *)kAXTrustedCheckOptionPrompt: @YES};
            BOOL trusted = AXIsProcessTrustedWithOptions((CFDictionaryRef)options);
            printf("{\"accessibilityTrusted\":%s}\n", trusted ? "true" : "false");
            return trusted ? 0 : 77;
        }
        if (argc == 2 && !strcmp(argv[1], "--allowance-contract")) {
            smoke_end = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) + 2000000000ull;
            MRKPrompt *s = calloc(1, sizeof(MRKPrompt)); s->admit = smoke_admit;
            AXUIElementRef app = AXUIElementCreateApplication(getpid());
            s->result.site = MRK_OPEN_CONTROL_PROJECTION;
            BOOL query = mrk_ax_before(s, app) && smoke_last_required == 500000000;
            // The real caller installs the action timeout at ADMISSION, then
            // changes to PRESS immediately before AXUIElementPerformAction.
            s->result.site = MRK_OPEN_ADMISSION;
            BOOL press = mrk_ax_before(s, app) && smoke_last_required > 0 && smoke_last_required <= 100000000;
            smoke_end = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
            BOOL deadline = !mrk_ax_before(s, app) && s->result.error == MRK_OPEN_DEADLINE;
            CFRelease(app); free(s);
            printf("{\"case\":\"query-and-press-allowances\",\"passed\":%s}\n", query && press && deadline ? "true" : "false");
            return query && press && deadline ? 0 : 1;
        }
        BOOL full_open = argc == 3 && !strcmp(argv[1], "--open-project");
        if (argc != 2 && !full_open) return 2;
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(100,100,480,300)
            styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
        window.title = @"Mobile Release Kit local dialog test";
        window.releasedWhenClosed = NO;
        [window setAccessibilityIdentifier:@"mrk-smoke-parent"];
        [window makeKeyAndOrderFront:nil];
        if (full_open) {
            [NSApp activateIgnoringOtherApps:YES];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100000000), dispatch_get_main_queue(), ^{
                smoke_open_project(window, argv[2]);
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10000000000ll),
                dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ _exit(124); });
            [NSApp run]; return 1;
        }
        NSOpenPanel *panel = [NSOpenPanel openPanel];
            panel.canChooseFiles = NO; panel.canChooseDirectories = YES;
            panel.allowsMultipleSelection = NO; panel.prompt = @"Select fixture";
            panel.directoryURL = [NSURL fileURLWithPath:[NSString stringWithUTF8String:argv[1]] isDirectory:YES];
            [panel beginSheetModalForWindow:window completionHandler:^(NSModalResponse response) { (void)response; }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 500000000), dispatch_get_main_queue(), ^{
            NSString *panelID = [[panel accessibilityIdentifier] copy];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                @autoreleasepool {
                    smoke_end = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) + 2000000000ull;
                    MRKPrompt *s = calloc(1, sizeof(MRKPrompt)); s->admit = smoke_admit;
                    s->elementType = AXUIElementGetTypeID(); s->cleanupKnown = YES;
                    AXUIElementRef app = AXUIElementCreateApplication(getpid()), parent = NULL, sheet = NULL;
                    BOOL projected = mrk_ax_projection(s, app, CFSTR("mrk-smoke-parent"), (CFStringRef)panelID, &parent, &sheet);
                    MRKControlPass pass = {0};
                    if (projected) s->result.site = MRK_OPEN_CONTROL_PROJECTION;
                    BOOL passed = projected && mrk_ax_control_roster(s, sheet, CFSTR("Select fixture"), NO, &pass);
                    printf("{\"case\":\"open-panel\",\"passed\":%s,\"accessibilityTrusted\":%s,\"axError\":%d,\"error\":%u,\"site\":%u,\"nodes\":%u,\"calls\":%u}\n",
                        passed ? "true" : "false", AXIsProcessTrusted() ? "true" : "false",
                        s->result.ax_error, s->result.error, s->result.site,s->result.initial_nodes_examined,s->result.calls);
                    for (unsigned i=0;i<s->count;i++) if(s->owned[i].value) CFRelease(s->owned[i].value);
                    CFRelease(app); free(s); fflush(stdout);
                    dispatch_async(dispatch_get_main_queue(), ^{ [panel cancel:nil]; [window close]; exit(passed ? 0 : 1); });
                }
            });
        });
        // Fixture watchdog only; a timeout is failure and never qualification.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10000000000ll), dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ _exit(124); });
        [NSApp run];
    }
}
