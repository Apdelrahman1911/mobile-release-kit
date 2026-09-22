// Probe-only translation unit; never linked into the installed application.
// Reuse the exact component's construction, completion and ordinary retirement.
#include "../src/native.m"
#include <time.h>
#include <math.h>
#include <stdbool.h>

enum { ELEMENTS = 32, CHILDREN = 16, DEPTH = 4, QUERIES = 256, HOLDERS = 192 };
typedef struct {
    id object; unsigned depth, via; const char *role;
    int parent, window, enabled, press, allowed, children; BOOL read;
} Row;
typedef struct {
    MRKInstalledPanel *state; NSWindow *parent, *panel;
    void (^completion)(NSModalResponse);
    Class stringClass, arrayClass, urlClass;
    id holders[HOLDERS], releasing; unsigned held, released, count, queries, returns, queryLimit;
    Row rows[ELEMENTS]; const char *reason; const char *directory;
    double end, readEnd; BOOL known, bodyEntered, bodyReturned, pre, post, timely;
    BOOL complete, cleanupPhase, closeReturned, completionReturned, panelReleased, parentReleased;
    BOOL poolReturned, prepared, releaseEntered; int startStatus, directoryStatus, closeStatus, releaseStatus;
    // Diagnostic-only: freeze when parent readiness ends. These are sequential
    // last-in-budget observations, never an atomic refusal snapshot or authority.
    BOOL parentReadinessPhase;
    unsigned readinessEvents, readinessMain, readinessPair;
} Probe;
static Probe p; // Original holders remain rooted even on exception/Unknown.
static NSAutoreleasePool *pool;

static double now(void) {
    struct timespec value;
    return clock_gettime(CLOCK_MONOTONIC, &value) ? INFINITY : value.tv_sec + value.tv_nsec / 1e9;
}
static void reason(Probe *s, const char *value) {
    if (!strcmp(s->reason, "none")) s->reason = value;
    s->complete = NO;
}
static void unknown(Probe *s, const char *value) {
    reason(s, value); s->known = NO;
    if (s->state && !s->releaseEntered) s->state->unknown = YES;
}
static BOOL originals(Probe *s) {
    return s->state && s->parent && s->panel && s->completion
        && s->state->parent == s->parent && s->state->window == s->panel
        && s->state->completion == s->completion && mrk_original_eligible(s->state);
}
static BOOL enter_query(Probe *s) {
    if (!s->known || !originals(s)) { unknown(s, "original-custody"); return NO; }
    if (now() >= (s->cleanupPhase ? s->end : s->readEnd)) {
        reason(s, "read-deadline"); s->timely = NO; return NO;
    }
    if (s->queries == s->queryLimit) { reason(s, "query-limit"); return NO; }
    ++s->queries; return YES;
}
static BOOL returned_query(Probe *s) {
    ++s->returns;
    if (!originals(s)) { unknown(s, "original-changed"); return NO; }
    if (now() >= (s->cleanupPhase ? s->end : s->readEnd)) {
        reason(s, "read-deadline"); s->timely = NO; return NO;
    }
    return YES;
}
// Every new hierarchy/proof read is counted, including capability, type,
// collection and normalization messages. Retain/release are custody, not reads.
// Sixteen queries are reserved for the final original proof, never a new search.
#define READ(target, expression) do { \
    if (!enter_query(s)) return NO; \
    (target) = (expression); \
    if (!returned_query(s)) return NO; \
} while (0)
static id hold(Probe *s, id value) {
    if (!value) return nil;
    if (s->held == HOLDERS) { unknown(s, "holder-limit"); return nil; }
    s->holders[s->held++] = value; // An unreturned retain never grants release.
    if ([value retain] != value) { unknown(s, "retain-return"); return nil; }
    return value;
}
static BOOL proof(Probe *s) {
    if (!originals(s)) { unknown(s, "original-custody"); return NO; }
    id value; BOOL flag; const char *path;
    READ(value, [s->parent attachedSheet]);
    if (value != s->panel) { unknown(s, "parent-attachment"); return NO; }
    READ(value, [s->panel sheetParent]);
    if (value != s->parent) { unknown(s, "panel-attachment"); return NO; }
    READ(flag, [s->panel isVisible]);
    if (!flag) { unknown(s, "panel-not-visible"); return NO; }
    NSOpenPanel *panel = (NSOpenPanel *)s->panel; // Original constructed NSOpenPanel, not a discovered proxy.
    READ(flag, [panel canChooseFiles]); if (flag) { unknown(s, "configuration"); return NO; }
    READ(flag, [panel canChooseDirectories]); if (!flag) { unknown(s, "configuration"); return NO; }
    READ(flag, [panel allowsMultipleSelection]); if (flag) { unknown(s, "configuration"); return NO; }
    READ(flag, [panel canCreateDirectories]); if (flag) { unknown(s, "configuration"); return NO; }
    READ(flag, [panel resolvesAliases]); if (flag) { unknown(s, "configuration"); return NO; }
    READ(flag, [panel treatsFilePackagesAsDirectories]); if (flag) { unknown(s, "configuration"); return NO; }
    READ(value, [panel directoryURL]); value = hold(s, value);
    if (!value || !s->known) { unknown(s, "directory-unavailable"); return NO; }
    READ(flag, [value isKindOfClass:s->urlClass]);
    if (!flag) { unknown(s, "directory-type"); return NO; }
    READ(flag, [value isFileURL]); if (!flag) { unknown(s, "directory-type"); return NO; }
    READ(path, [value fileSystemRepresentation]);
    if (!path || strnlen(path, 4097) >= 4097 || strcmp(path, s->directory)) {
        unknown(s, "directory-changed"); return NO;
    }
    return originals(s);
}
static int relationship(Probe *s, id value, id via) {
    if (!value) return 2;
    if (value == s->panel) return 3;
    if (value == s->parent) return 4;
    return via && value == via ? 5 : 6;
}
static BOOL append(Probe *s, id object, unsigned depth, unsigned via) {
    if (!object) { unknown(s, "nil-element"); return NO; }
    for (unsigned n = 0; n < s->count; ++n) if (s->rows[n].object == object) {
        reason(s, "repeated-element"); return NO; // No repeated traversal or cycle expansion.
    }
    if (s->count == ELEMENTS) { reason(s, "element-limit"); return NO; }
    Row *row = &s->rows[s->count];
    row->depth = depth; row->via = via;
    row->role = "unobserved"; row->children = -3;
    ++s->count; // The published row is closed DATA even if retain throws below.
    row->object = hold(s, object);
    return s->known;
}
static BOOL walk(Probe *s) {
    if (!append(s, s->panel, 0, ELEMENTS)) return NO;
    for (unsigned n = 0; n < s->count; ++n) {
        Row *r = &s->rows[n]; id object = r->object, value; BOOL flag; NSUInteger count;
        READ(flag, [object respondsToSelector:@selector(accessibilityRole)]);
        if (!flag) r->role = "unsupported";
        else {
            READ(value, [object accessibilityRole]); value = hold(s, value);
            if (!value) r->role = "nil";
            else {
                READ(flag, [value isKindOfClass:s->stringClass]);
                if (!flag) { unknown(s, "role-type"); return NO; }
                r->role = "other";
                READ(flag, [value isEqualToString:NSAccessibilityButtonRole]);
                if (flag) r->role = "button";
                else { READ(flag, [value isEqualToString:NSAccessibilitySheetRole]);
                    if (flag) r->role = "sheet";
                    else { READ(flag, [value isEqualToString:NSAccessibilityGroupRole]);
                        if (flag) r->role = "group";
                        else { READ(flag, [value isEqualToString:NSAccessibilityWindowRole]);
                            if (flag) r->role = "window";
                        }
                    }
                }
            }
        }
        READ(flag, [object respondsToSelector:@selector(accessibilityParent)]);
        r->parent = 1;
        if (flag) { READ(value, [object accessibilityParent]); value = hold(s, value);
            r->parent = relationship(s, value, r->via < ELEMENTS ? s->rows[r->via].object : nil); }
        READ(flag, [object respondsToSelector:@selector(accessibilityWindow)]);
        r->window = 1;
        if (flag) { READ(value, [object accessibilityWindow]); value = hold(s, value);
            r->window = relationship(s, value, nil); }
        READ(flag, [object respondsToSelector:@selector(isAccessibilityEnabled)]);
        r->enabled = 1;
        if (flag) { READ(flag, [object isAccessibilityEnabled]); r->enabled = flag ? 3 : 2; }
        READ(flag, [object respondsToSelector:@selector(accessibilityPerformPress)]);
        r->press = flag ? 3 : 2;
        READ(flag, [object respondsToSelector:@selector(isAccessibilitySelectorAllowed:)]);
        r->allowed = 1;
        if (flag) { READ(flag, [object isAccessibilitySelectorAllowed:@selector(accessibilityPerformPress)]);
            r->allowed = flag ? 3 : 2; }
        // Capability/allowance DATA only. No accepting action is ever sent.
        READ(flag, [object respondsToSelector:@selector(accessibilityChildren)]);
        if (!flag) { r->children = -2; reason(s, "children-unsupported"); return NO; }
        READ(value, [object accessibilityChildren]); value = hold(s, value);
        if (!value) { r->children = -1; reason(s, "children-nil"); return NO; }
        READ(flag, [value isKindOfClass:s->arrayClass]);
        if (!flag) { r->children = 18; unknown(s, "children-type"); return NO; }
        READ(count, [value count]); r->children = count > CHILDREN ? 17 : (int)count;
        if (count > CHILDREN) { reason(s, "children-limit"); return NO; }
        if (count && r->depth == DEPTH) { reason(s, "depth-limit"); return NO; }
        for (NSUInteger i = 0; i < count; ++i) {
            id child; READ(child, [value objectAtIndex:i]);
            if (!append(s, child, r->depth + 1, n)) return NO;
        }
        NSUInteger after; READ(after, [value count]);
        if (after != count) { unknown(s, "children-changed"); return NO; }
        r->read = YES;
    }
    return YES;
}
#undef READ
static void pump(void) {
    double remaining = p.end - now();
    if (!(remaining > 0)) return;
    (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, fmin(0.01, remaining), true);
    if (now() >= p.end) return;
    NSDate *until = [NSDate distantPast];
    if (now() >= p.end) return;
    // Service only our application's AppKit lifecycle events. Never dispatch
    // keyboard, mouse, synthetic or accepting input, or drain an unbounded queue.
    NSEvent *event = [NSApp nextEventMatchingMask:NSEventMaskAppKitDefined
        untilDate:until inMode:NSDefaultRunLoopMode dequeue:YES];
    if (now() >= p.end) return;
    if (event) {
        BOOL activated = NO;
        if (p.parentReadinessPhase) {
            p.readinessEvents |= 1;
            activated = [event subtype] == NSEventSubtypeApplicationActivated;
            if (now() >= p.end) return;
        }
        [NSApp sendEvent:event];
        if (now() >= p.end) return;
        if (p.parentReadinessPhase) p.readinessEvents |= activated ? 7 : 3;
    }
    if (now() >= p.end) return;
    [NSApp updateWindows];
}
static void sample_parent_readiness(void) {
    if (now() >= p.end) return;
    BOOL active = [NSApp isActive];
    if (now() >= p.end) return;
    // A new first return replaces the prior pair with an explicitly partial
    // sample. No first return preserves the older sample; no late fill occurs.
    p.readinessPair = active ? 3 : 1;
    if (now() >= p.end) return;
    BOOL eligible = [p.parent canBecomeMainWindow];
    if (now() >= p.end) return;
    p.readinessPair |= eligible ? 12 : 4;
}
static BOOL prepare(void) {
    p.stringClass = [NSString class]; p.arrayClass = [NSArray class]; p.urlClass = [NSURL class];
    [NSApplication sharedApplication];
    if (![NSApp setActivationPolicy:NSApplicationActivationPolicyRegular]) {
        reason(&p, "activation-policy"); return NO;
    }
    [NSApp finishLaunching];
    p.parent = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 640, 480)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
        backing:NSBackingStoreBuffered defer:NO];
    if (!p.parent) { reason(&p, "parent-create"); return NO; }
    [p.parent setReleasedWhenClosed:NO]; [p.parent setTitle:@"MRK read-only panel probe"];
    [NSApp activate];
    [p.parent makeKeyAndOrderFront:nil]; [p.parent makeMainWindow];
    // Activation is a request. Only this original getter's in-budget return,
    // not diagnostic classifications, may satisfy the unchanged parent guard.
    BOOL originalMain = NO;
    p.parentReadinessPhase = YES;
    while (now() < p.end) {
        NSWindow *main = [NSApp mainWindow];
        if (now() >= p.end) break;
        p.readinessMain = !main ? 1 : main == p.parent ? 2 : 3;
        if (main == p.parent) { originalMain = YES; break; }
        sample_parent_readiness();
        pump();
    }
    p.parentReadinessPhase = NO;
    if (!originalMain) { reason(&p, "parent-main-window"); return NO; }
    if (now() >= p.end) { reason(&p, "preparation-deadline"); return NO; }
    p.state = mrk_panel_reserve();
    if (!p.state) { reason(&p, "panel-reserve"); return NO; }
    if (mrk_panel_observe_arm_open_identity(p.state)) { reason(&p, "panel-arm"); return NO; }
    p.startStatus = mrk_panel_start(p.state, 1);
    p.panel = p.state->window; p.completion = p.state->completion;
    if (p.startStatus || !originals(&p)) return NO;
    // Readiness only, not repeated AX-tree exploration or a repeated setter.
    while (now() < p.end) {
        BOOL attached = mrk_observation_attached(p.state);
        if (now() >= p.end || !originals(&p)) return NO;
        if (attached) break;
        pump();
    }
    if (now() >= p.end || !originals(&p)) return NO;
    uint32_t diagnostic = 0;
    p.directoryStatus = mrk_panel_observe_action(p.state, 2, p.directory, &diagnostic);
    if (p.directoryStatus) return NO;
    while (now() < p.end) {
        BOOL ready = mrk_observation_directory_ready(p.state);
        if (now() >= p.end || !originals(&p)) return NO;
        if (ready) break;
        pump();
    }
    return now() < p.end && originals(&p);
}
static void retire(void) {
    if (!p.known || !p.bodyReturned || !p.post || !originals(&p) || now() >= p.end) return;
    p.closeStatus = mrk_panel_close(p.state); p.closeReturned = YES;
    if (p.closeStatus) { unknown(&p, "ordinary-close"); return; }
    int result = -1; uint8_t path[4097] = {0}; int status = 0;
    while (now() < p.end) {
        status = mrk_panel_poll(p.state, &result, path, sizeof(path));
        if (status == 2) break;
        if (status < 0 || (status == 1 && (result != 0 || path[0]))) {
            unknown(&p, "ordinary-completion"); return;
        }
        pump();
    }
    if (status != 2 || p.state->unknown || p.state->callbackActive || !p.state->responded
        || p.state->response != 0 || p.state->selected[0]) { unknown(&p, "ordinary-completion"); return; }
    p.completionReturned = YES; // Programmatic Other, NEVER an accepted selection.
    while (p.released < p.held && now() < p.end) {
        unsigned slot = p.held - p.released - 1; p.releasing = p.holders[slot];
        p.holders[slot] = nil; // No retry after an exception in this original release.
        [p.releasing release]; p.releasing = nil; ++p.released;
    }
    if (p.released != p.held || now() >= p.end) return;
    p.releaseEntered = YES;
    p.releaseStatus = mrk_panel_release(p.state);
    if (p.releaseStatus) { unknown(&p, "ordinary-release"); return; }
    p.panelReleased = YES; p.state = nil; p.panel = nil; p.completion = NULL;
    if (now() >= p.end) return;
    [p.parent orderOut:nil]; if (now() >= p.end) return;
    [p.parent close]; if (now() >= p.end) return;
    [p.parent release]; p.parent = nil;
    p.parentReleased = YES;
    if (now() >= p.end) return;
    [pool drain]; pool = nil; p.poolReturned = YES;
}
static const char *boolean(BOOL value) { return value ? "true" : "false"; }
static BOOL emit(void) {
    printf("MRK_PANEL_REACHABILITY={\"schemaVersion\":1,\"scope\":\"fresh-normal-parent-not-installed-tauri\","
        "\"readOnly\":true,\"semanticOpenIdentity\":false,\"acceptingActionSent\":false,"
        "\"prepared\":%s,\"bodyEntered\":%s,\"bodyReturned\":%s,\"preProof\":%s,\"postProof\":%s,"
        "\"custodyKnown\":%s,\"timely\":%s,\"complete\":%s,\"reason\":\"%s\","
        "\"selectorQueries\":%u,\"selectorReturns\":%u,\"holders\":%u,\"holdersReleased\":%u,"
        "\"startStatus\":%d,\"directoryStatus\":%d,\"closeStatus\":%d,\"releaseStatus\":%d,"
        "\"closeReturned\":%s,\"completionReturned\":%s,\"panelReleased\":%s,\"parentReleased\":%s,\"poolReturned\":%s,"
        "\"parentReadinessInBudgetEventProgress\":%u,\"parentReadinessLastInBudgetMainWindow\":%u,"
        "\"parentReadinessLastInBudgetActiveEligible\":%u,\"rows\":[",
        boolean(p.prepared), boolean(p.bodyEntered), boolean(p.bodyReturned), boolean(p.pre), boolean(p.post),
        boolean(p.known), boolean(p.timely), boolean(p.complete), p.reason, p.queries, p.returns, p.held, p.released,
        p.startStatus, p.directoryStatus, p.closeStatus, p.releaseStatus, boolean(p.closeReturned),
        boolean(p.completionReturned), boolean(p.panelReleased), boolean(p.parentReleased), boolean(p.poolReturned),
        p.readinessEvents, p.readinessMain, p.readinessPair);
    for (unsigned n = 0; n < p.count; ++n) {
        Row *r = &p.rows[n];
        printf("%s{\"ordinal\":%u,\"depth\":%u,\"viaOrdinal\":%u,\"role\":\"%s\",\"parent\":%d,\"window\":%d,"
            "\"enabled\":%d,\"pressCapability\":%d,\"pressAllowance\":%d,\"children\":%d,\"rowRead\":%s}",
            n ? "," : "", n, r->depth, r->via, r->role, r->parent, r->window, r->enabled,
            r->press, r->allowed, r->children, boolean(r->read));
    }
    printf("]}\n"); return !ferror(stdout) && fflush(stdout) == 0;
}
int main(int argc, char **argv) {
    p.reason = "none"; p.known = YES; p.timely = YES;
    p.startStatus = p.directoryStatus = p.closeStatus = p.releaseStatus = -1;
    double start = now(); p.end = start + 45.0;
    uint32_t uid = 0; struct stat fixture;
    if (argc != 2 || mrk_user(&uid) || !pthread_main_np() || !isfinite(start)
        || argv[1][0] != '/' || strnlen(argv[1], 4097) >= 4097
        || lstat(argv[1], &fixture) || !S_ISDIR(fixture.st_mode)
        || fixture.st_uid != uid || (fixture.st_mode & 07777) != 0700) {
        reason(&p, "input"); (void)emit(); return 70;
    }
    p.directory = argv[1];
    @try {
        pool = [[NSAutoreleasePool alloc] init];
        p.prepared = prepare();
        if (!p.prepared) {
            unknown(&p, "preparation");
        }
        else {
            p.readEnd = fmin(p.end, now() + 2.0); p.queryLimit = QUERIES - 16;
            p.bodyEntered = YES; p.pre = proof(&p);
            BOOL traversed = p.pre && walk(&p);
            p.bodyReturned = YES; p.timely = p.timely && now() < p.readEnd;
            p.cleanupPhase = YES; p.queryLimit = QUERIES;
            if (p.known && p.returns == p.queries) p.post = proof(&p);
            p.complete = traversed && p.pre && p.post && p.timely && p.known;
            retire();
        }
    } @catch (NSException *error) { (void)error; unknown(&p, "exception"); }
    BOOL success = p.complete && p.known && p.poolReturned && now() < p.end;
    if (!success && !strcmp(p.reason, "none")) reason(&p, "ordinary-cleanup");
    BOOL output = emit();
    // Unknown native holders are never unwound by an autorelease pool or a
    // guessed close. They survive to this owned process's actual exit/owner join.
    _exit(success && output ? 0 : 70);
}
