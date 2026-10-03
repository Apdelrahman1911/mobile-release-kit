/* One NSWorkspace launch. No PID lookup, process scan, forceQuit or TCC change. */
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include "fixture.h"

static _Atomic unsigned completion_entered, completion_body_done;
static unsigned handoff_count;
static NSRunningApplication *original_app;
static BOOL launch_error;
static NSString *text(const char *value) { return [NSString stringWithUTF8String:value]; }
static NSNumber *truth(int value) { return value ? @YES : @NO; }
static int same_stat(struct stat a, struct stat b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec
        && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
        && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec
        && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}
/* Diagnostic DATA only, not a self-authenticating process/finality receipt. */
static int read_record(int root, const char *name, NSDictionary **value) {
    int fd = openat(root, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat before, after, named; char bytes[4096]; size_t offset = 0;
    int ok = !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_nlink == 1
        && before.st_uid == MRK_UID && before.st_gid == MRK_GID
        && (before.st_mode & 07777) == 0400 && before.st_size > 0 && before.st_size <= (off_t)sizeof(bytes);
    while (ok && offset < (size_t)before.st_size) {
        ssize_t count = read(fd, bytes + offset, (size_t)before.st_size - offset);
        if (count <= 0) { ok = 0; break; } offset += (size_t)count;
    }
    if (ok) ok = !fstat(fd, &after) && !fstatat(root, name, &named, AT_SYMLINK_NOFOLLOW)
        && same_stat(before, after) && same_stat(before, named);
    if (!mrk_close(&fd)) ok = 0;
    if (!ok) return -1;
    NSError *error = nil;
    id decoded = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:offset]
        options:0 error:&error];
    if (error || ![decoded isKindOfClass:NSDictionary.class]
        || ![decoded[@"source"] isEqualToString:text(MRK_SOURCE)]) return -1;
    *value = decoded; return 1;
}
static void progress_events(void) {
    (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
}
static BOOL admit_work(double deadline, BOOL *failed) {
    /* Irreversible, including a failed clock read. Cleanup cannot renew work. */
    if (*failed || !mrk_before(deadline)) { *failed = YES; return NO; }
    return YES;
}

int main(int argc, char **argv) {
    (void)argv;
    @autoreleasepool {
        if (argc != 1 || !mrk_account()) return 64;
        int root = mrk_root();
        double started = mrk_now();
        if (root < 0 || started < 0 || mrk_exclusive_probe(root) != 1) return 65;
        const double work_end = started + 30.0, final_end = started + 45.0;
        NSString *first = @"none";
        NSDictionary *payload_start = nil, *payload_quit = nil;
        BOOL pid_matches = NO, blocked_alive = NO, quit_sent = NO, terminated = NO, available_after = NO;
        BOOL requested = NO, returned_reference = NO, reference_bundle_entry = NO, reference_bundle_payload = NO;
        BOOL reference_executable_entry = NO, reference_executable_payload = NO;
        BOOL work_deadline_failed = NO;
        @try {
            NSWorkspaceOpenConfiguration *configuration = [NSWorkspaceOpenConfiguration configuration];
            configuration.activates = YES;
            configuration.addsToRecentItems = NO;
            configuration.createsNewApplicationInstance = YES;
            configuration.allowsRunningApplicationSubstitution = NO;
            configuration.promptsUserIfNeeded = NO;
            configuration.arguments = @[];
            configuration.environment = @{
                @"PATH": @"/usr/bin:/bin:/usr/sbin:/sbin", @"HOME": @"/Users/runner",
                @"USER": @"runner", @"LOGNAME": @"runner", @"LANG": @"en_US.UTF-8",
                @"LC_ALL": @"en_US.UTF-8", @"TZ": @"UTC",
                @"TMPDIR": text(MRK_ROOT "/app-tmp/")
            };
            NSWorkspace *workspace = NSWorkspace.sharedWorkspace;
            NSURL *entry_url = [NSURL fileURLWithPath:text(MRK_ENTRY_APP) isDirectory:YES];
            if (admit_work(work_end, &work_deadline_failed)) {
                requested = YES;
                [workspace openApplicationAtURL:entry_url
                    configuration:configuration completionHandler:^(NSRunningApplication *app, NSError *error) {
                        atomic_fetch_add_explicit(&completion_entered, 1, memory_order_relaxed);
                        /* Apple documents a concurrent callback queue. Only main mutates app state. */
                        dispatch_async(dispatch_get_main_queue(), ^{
                            ++handoff_count;
                            if (handoff_count == 1) { original_app = app; launch_error = error != nil; }
                        });
                        atomic_fetch_add_explicit(&completion_body_done, 1, memory_order_release);
                    }];
                while (admit_work(work_end, &work_deadline_failed)) {
                    progress_events();
                    /* The event pump may have crossed the original deadline. */
                    if (!admit_work(work_end, &work_deadline_failed)) break;
                    if (!handoff_count || !atomic_load_explicit(&completion_body_done, memory_order_acquire)) continue;
                    if (handoff_count != 1 || atomic_load(&completion_entered) != 1 || launch_error || !original_app) {
                        first = @"launch-completion"; break;
                    }
                    returned_reference = YES;
                    int read = read_record(root, "payload-start.json", &payload_start);
                    if (!admit_work(work_end, &work_deadline_failed)) break;
                    if (read < 0) { first = @"payload-record"; break; }
                    if (original_app.terminated) { first = @"payload-terminated-before-observation"; break; }
                    if (!read) continue;
                    NSNumber *pid = payload_start[@"processIdentifier"];
                    pid_matches = [pid isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)pid) == CFNumberGetTypeID()
                        && !CFNumberIsFloatType((__bridge CFNumberRef)pid)
                        && pid.longLongValue > 1 && pid.longLongValue == original_app.processIdentifier;
                    reference_bundle_entry = [original_app.bundleURL.path isEqualToString:text(MRK_ENTRY_APP)];
                    reference_bundle_payload = [original_app.bundleURL.path isEqualToString:text(MRK_PAYLOAD_APP)];
                    reference_executable_entry = [original_app.executableURL.path isEqualToString:text(MRK_ENTRY_APP "/Contents/MacOS/entry")];
                    reference_executable_payload = [original_app.executableURL.path isEqualToString:text(MRK_PAYLOAD_EXE)];
                    blocked_alive = pid_matches && !original_app.terminated && mrk_exclusive_probe(root) == 0;
                    /* Native properties / record IO are not admitted merely because
                       the iteration started in time. Accept only the completed work. */
                    if (!admit_work(work_end, &work_deadline_failed)) break;
                    if (!pid_matches || !blocked_alive) first = @"original-reference-or-shared-bridge";
                    break;
                }
            }
            if ((work_deadline_failed || !payload_start) && [first isEqualToString:@"none"])
                first = @"observation-deadline";
        } @catch (...) { if ([first isEqualToString:@"none"]) first = @"native-exception"; }
        @try {
            /* A late completion may still supply the original for safe cleanup,
               but can never renew work or erase the original work deadline. */
            while (requested && !handoff_count && mrk_before(final_end))
                progress_events();
            returned_reference = original_app != nil;
            /* Only the object returned by this one launch is ever asked to quit. */
            if (original_app && !original_app.terminated && mrk_before(final_end))
                quit_sent = [original_app terminate];
            while (original_app && !original_app.terminated && mrk_before(final_end))
                progress_events();
            terminated = original_app && original_app.terminated;
            if (terminated) {
                available_after = mrk_exclusive_probe(root) == 1;
                if (read_record(root, "payload-quit.json", &payload_quit) != 1
                    && [first isEqualToString:@"none"]) first = @"quit-record";
            }
            if ((!quit_sent || !terminated || !available_after) && [first isEqualToString:@"none"])
                first = @"normal-quit-or-last-holder";
        } @catch (...) { if ([first isEqualToString:@"none"]) first = @"cleanup-native-exception"; }
        BOOL root_closed = mrk_close(&root);
        if (!root_closed && [first isEqualToString:@"none"]) first = @"root-close";
        BOOL timely = mrk_before(final_end);
        if (!timely && [first isEqualToString:@"none"]) first = @"final-deadline";
        BOOL complete = [first isEqualToString:@"none"] && !work_deadline_failed && timely && root_closed
            && requested && returned_reference && pid_matches && blocked_alive && quit_sent
            && terminated && available_after && payload_start && payload_quit
            && handoff_count == 1 && atomic_load(&completion_entered) == 1 && atomic_load(&completion_body_done) == 1;
        NSDictionary *result = @{
            @"schemaVersion": @1, @"source": text(MRK_SOURCE), @"scope": @"synthetic-nsworkspace-entry-feasibility",
            @"launchRequested": truth(requested), @"launchReferenceReturned": truth(returned_reference),
            @"launchErrorReported": truth(launch_error), @"completionCount": @(atomic_load(&completion_entered)),
            @"completionBodyDoneCount": @(atomic_load(&completion_body_done)), @"completionHandoffCount": @(handoff_count),
            @"referencePIDMatchesPayload": truth(pid_matches), @"referenceBundleIsEntry": truth(reference_bundle_entry),
            @"referenceBundleIsPayload": truth(reference_bundle_payload), @"referenceExecutableIsEntry": truth(reference_executable_entry),
            @"referenceExecutableIsPayload": truth(reference_executable_payload),
            @"exclusiveBlockedWhilePayloadAlive": truth(blocked_alive), @"normalQuitRequestSent": truth(quit_sent),
            @"terminationObserved": truth(terminated), @"exclusiveAvailableAfterTermination": truth(available_after),
            @"rootCloseReturned": truth(root_closed), @"timely": truth(timely), @"observationComplete": truth(complete),
            @"workDeadlineFailed": truth(work_deadline_failed),
            @"payloadStart": payload_start ?: NSNull.null, @"payloadQuit": payload_quit ?: NSNull.null,
            @"originalAppExitStatus": NSNull.null,
            @"allWorkerFinality": @"not-established-by-NSRunningApplication", @"firstFailure": first
        };
        NSError *error = nil;
        NSData *body = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:&error];
        if (!body || error || body.length > 16384) return 70;
        NSString *line = [@"MRK_M2_ENTRY=" stringByAppendingString:
            [[[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] stringByAppendingString:@"\n"]];
        const char *bytes = line.UTF8String; size_t size = strlen(bytes), offset = 0;
        while (offset < size) { ssize_t count = write(STDOUT_FILENO, bytes + offset, size - offset);
            if (count <= 0) return 71; offset += (size_t)count; }
        return complete ? 0 : 1;
    }
}
