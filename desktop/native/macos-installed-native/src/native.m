#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <Block.h>
#include <sys/acl.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

int mrk_platform(void) {
    struct utsname u; char version[64] = {0}; size_t length = sizeof(version);
    if (uname(&u) || strcmp(u.sysname, "Darwin") || strcmp(u.machine, "arm64")) return ENOTSUP;
    if (sysctlbyname("kern.osproductversion", version, &length, NULL, 0) || length == 0 || length >= sizeof(version)
        || strncmp(version, "26.", 3)) return ENOTSUP;
    return 0;
}
int mrk_user(uint32_t *uid) {
    if (!uid || getuid() == 0 || getuid() != geteuid() || getgid() != getegid() || issetugid()) return EPERM;
    int platform = mrk_platform(); if (platform) return platform;
    *uid = getuid(); return 0;
}
int mrk_acl_empty(int fd) {
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) return errno ? errno : EIO;
    // Darwin differs from Linux: zero means an entry WAS returned; a valid
    // empty ACL reports -1/EINVAL for ACL_FIRST_ENTRY. Never admit an ACE by
    // interpreting Darwin's success as Linux's end-of-list convention.
    int saved = 0;
    if (acl_valid(acl)) saved = errno ? errno : EIO;
    else {
        acl_entry_t entry; errno = 0;
        int found = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
        saved = found == 0 ? EPERM : found == -1 && errno == EINVAL ? 0 : (errno ? errno : EIO);
    }
    if (acl_free(acl)) return errno ? errno : EIO;
    return saved;
}
int mrk_no_xattrs(int fd) {
    ssize_t count = flistxattr(fd, NULL, 0, 0);
    return count < 0 ? (errno ? errno : EIO) : count == 0 ? 0 : EPERM;
}
int mrk_entries(int fd, uint8_t *out, size_t capacity, size_t *used) {
    _Alignas(struct dirent) char block[65536]; long base = 0;
    if (!out || !used || capacity != sizeof(block)) return EINVAL;
    *used = 0;
    _Static_assert(sizeof(((struct dirent *)0)->d_ino) == sizeof(uint64_t), "fixed Darwin inode64 layout required");
    int count = getdirentries(fd, block, sizeof(block), &base);
    if (count < 0) return errno ? errno : EIO;
    size_t offset = 0;
    while (offset < (size_t)count) {
        if ((size_t)count - offset < offsetof(struct dirent, d_name) + 1) return EIO;
        struct dirent *entry = (struct dirent *)(block + offset);
        size_t header = offsetof(struct dirent, d_name);
        if (entry->d_reclen < header + 1 || entry->d_reclen > (size_t)count - offset
            || entry->d_namlen == 0 || entry->d_namlen > 255 || header + entry->d_namlen >= entry->d_reclen
            || entry->d_name[entry->d_namlen] || memchr(entry->d_name, 0, entry->d_namlen)) return EIO;
        size_t next = *used + 11 + entry->d_namlen;
        if (next > capacity) return EOVERFLOW;
        uint64_t inode = entry->d_ino; uint16_t length = entry->d_namlen;
        memcpy(out + *used, &inode, 8); out[*used + 8] = entry->d_type;
        memcpy(out + *used + 9, &length, 2); memcpy(out + *used + 11, entry->d_name, length);
        *used = next; offset += entry->d_reclen;
    }
    return 0;
}
int mrk_sync(int fd, int file) {
    if (fsync(fd)) return errno ? errno : EIO;
    if (file && fcntl(fd, F_FULLFSYNC)) return errno ? errno : EIO;
    return 0;
}
int mrk_publish(int from, const char *source, int to, const char *destination) {
    if (renameatx_np(from, source, to, destination, RENAME_EXCL)) return errno ? errno : EIO;
    return 0;
}
int mrk_main_thread(void) { return pthread_main_np(); }

// Closed ABI result: Other=0, Accept=1, Decline=2. This same pure mapping is
// exercised by narrow native-crate test definitions; no panel is fabricated.
int mrk_panel_response(int kind, int64_t code, int programmatic) {
    if (programmatic) return 0;
    if (kind == 1) {
        if (code == NSModalResponseOK) return 1;
        if (code == NSModalResponseCancel) return 2;
    } else if (kind == 2) {
        if (code == NSAlertSecondButtonReturn) return 1;
        if (code == NSAlertFirstButtonReturn) return 2;
    }
    return 0; // Stop/Abort/unknown are never evidence of genuine user Cancel.
}

@interface MRKInstalledPanel : NSObject {
@public
    NSWindow *parent;
    NSWindow *window;
    NSAlert *alert;
    void (^completion)(NSModalResponse);
    BOOL attempted, started, responded, reported, callbackActive, closeAttempted, closed, unknown;
    int kind, response;
    char selected[4097];
}
@end
@implementation MRKInstalledPanel
@end

void *mrk_panel_reserve(void) {
    if (!pthread_main_np()) return NULL;
    @try { return [[MRKInstalledPanel alloc] init]; } @catch (NSException *e) { (void)e; return NULL; }
}
int mrk_panel_start(void *opaque, int kind) {
    if (!pthread_main_np() || !opaque || (kind != 1 && kind != 2)) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->attempted || s->unknown) return EALREADY;
    s->attempted = YES; s->kind = kind;
    @try {
        // This application has exactly one normal window; never attach to a
        // picker, another sheet or a renderer-supplied object/path.
        NSWindow *main = [NSApp mainWindow];
        if (!main || [main isKindOfClass:[NSPanel class]] || [main attachedSheet]) return EPERM;
        s->started = YES;
        s->parent = [main retain];
        if (kind == 1) {
            NSOpenPanel *panel = [NSOpenPanel openPanel]; s->window = [panel retain];
            [panel setTitle:@"Choose a mobile project folder"];
            [panel setCanChooseFiles:NO]; [panel setCanChooseDirectories:YES];
            [panel setAllowsMultipleSelection:NO]; [panel setCanCreateDirectories:NO];
            [panel setResolvesAliases:NO]; [panel setTreatsFilePackagesAsDirectories:NO];
        } else {
            s->alert = [[NSAlert alloc] init];
            [s->alert setMessageText:@"Quit and discard unsaved drafts?"];
            [s->alert setInformativeText:@"Cancel keeps working. Quit stops owned operations and waits for their original cleanup. A Save already accepted may still commit; quitting does not undo committed files."];
            [s->alert setAlertStyle:NSAlertStyleWarning];
            [[s->alert addButtonWithTitle:@"Cancel"] setKeyEquivalent:@"\r"];
            [[s->alert addButtonWithTitle:@"Quit"] setKeyEquivalent:@""];
            s->window = [[s->alert window] retain];
        }
        [s->window setReleasedWhenClosed:NO];
        // The original state is retained by the copied native completion. No
        // raw Rust callback or path publication can outlive the real document.
        s->completion = Block_copy(^(NSModalResponse code) {
            s->callbackActive = YES;
            @try {
                if (s->responded) { s->unknown = YES; }
                else {
                    // closeAttempted was recorded BEFORE any programmatic
                    // endSheet/close. Its Cancel-shaped callback remains Other.
                    s->response = mrk_panel_response(kind, code, s->closeAttempted);
                    if (s->response == 1 && kind == 1) {
                        NSURL *url = [(NSOpenPanel *)s->window URL];
                        const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
                        if (!path || path[0] != '/' || strnlen(path, sizeof(s->selected)) >= sizeof(s->selected)) s->unknown = YES;
                        else memcpy(s->selected, path, strlen(path) + 1);
                    }
                    s->responded = YES;
                }
            } @catch (NSException *e) { (void)e; s->unknown = YES; }
            // No native call/run-loop pumping after this final completion fact.
            s->callbackActive = NO;
        });
        if (kind == 1) [(NSOpenPanel *)s->window beginSheetModalForWindow:s->parent completionHandler:s->completion];
        else [s->alert beginSheetModalForWindow:s->parent completionHandler:s->completion];
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_poll(void *opaque, int *result, uint8_t *path, size_t capacity) {
    if (!pthread_main_np() || !opaque || !result || !path || capacity != 4097) return -1;
    MRKInstalledPanel *s = opaque;
    if (s->unknown) return -1;
    @try {
        // Main-loop serialization observes the actual completion return, not
        // just a flag sampled concurrently with an executing callback.
        if (s->closed) return 2;
        if (s->responded && !s->reported && !s->callbackActive) {
            s->reported = YES; *result = s->response;
            memcpy(path, s->selected, sizeof(s->selected)); return 1;
        }
        if (s->closeAttempted && s->responded && !s->callbackActive && ![s->window isVisible] && ![s->window sheetParent]) {
            s->closed = YES; return 2;
        }
        if (s->responded && !s->callbackActive) {
            *result = s->response; memcpy(path, s->selected, sizeof(s->selected)); return 1;
        }
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return -1; }
}
int mrk_panel_close(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->closeAttempted) return EALREADY;
    s->closeAttempted = YES;
    @try {
        if (!s->started && !s->window && !s->parent && !s->alert && !s->completion) { s->closed = YES; return 0; }
        if (!s->responded && s->window && [s->window sheetParent]) [s->parent endSheet:s->window returnCode:NSModalResponseCancel];
        if (s->window) { [s->window orderOut:nil]; [s->window close]; }
        return s->unknown ? EIO : 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_release(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->unknown || s->callbackActive || !s->closed) return EBUSY;
    @try {
        // Only original references, after original close/completion returned.
        // Unknown retains the object; there is no replacement or Drop fallback.
        if (s->completion) { Block_release(s->completion); s->completion = NULL; }
        [s->window release]; s->window = nil; [s->alert release]; s->alert = nil;
        [s->parent release]; s->parent = nil; [s release]; return 0;
    } @catch (NSException *e) { (void)e; return EIO; }
}
