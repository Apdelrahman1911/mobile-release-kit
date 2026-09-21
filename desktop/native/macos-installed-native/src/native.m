#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <Block.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/vnode.h>
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
// Public bulk attributes are four-byte packed, NOT a padded C struct.
// The same pure decoder is exercised by the native crate's cfg(test) FFI.
#define MRK_DIRECTORY_ATTRS (ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_FILEID | ATTR_CMN_RETURNED_ATTRS)
_Static_assert(sizeof(attribute_set_t) == 20 && sizeof(attrreference_t) == 8
               && sizeof(fsobj_type_t) == 4 && sizeof(uint64_t) == 8,
               "fixed public Darwin bulk-attribute field widths required");
int mrk_decode_directory_entries(const uint8_t *block, size_t bytes, int count,
                                 uint8_t *out, size_t capacity, size_t *used) {
    if (!used) return EINVAL;
    *used = 0;
    const size_t name_field = sizeof(uint32_t) + sizeof(attribute_set_t);
    const size_t type_field = name_field + sizeof(attrreference_t);
    const size_t inode_field = type_field + sizeof(fsobj_type_t);
    const size_t fixed = inode_field + sizeof(uint64_t);
    if (!block || !out || bytes > 65536 || capacity > 65536 || count < 0
        || (size_t)count > bytes / fixed) return EINVAL;
    size_t offset = 0, written = 0;
    for (int n = 0; n < count; ++n) {
        if (bytes - offset < sizeof(uint32_t)) return EIO;
        uint32_t length; memcpy(&length, block + offset, sizeof(length));
        if (length < fixed + 2 || length % 4 || length > bytes - offset) return EIO;
        const uint8_t *entry = block + offset;
        attribute_set_t actual; memcpy(&actual, entry + sizeof(uint32_t), sizeof(actual));
        if (actual.commonattr != MRK_DIRECTORY_ATTRS || actual.volattr || actual.dirattr
            || actual.fileattr || actual.forkattr) return EIO;
        attrreference_t name; fsobj_type_t kind; uint64_t inode;
        memcpy(&name, entry + name_field, sizeof(name));
        memcpy(&kind, entry + type_field, sizeof(kind));
        memcpy(&inode, entry + inode_field, sizeof(inode));
        if (name.attr_dataoffset < (int32_t)(fixed - name_field)
            || (uint32_t)name.attr_dataoffset > length - name_field
            || name.attr_length < 2 || name.attr_length > 256 || !inode
            || (kind != VREG && kind != VDIR)) return EIO;
        // attr_dataoffset is relative to the name reference itself.
        size_t name_at = name_field + (uint32_t)name.attr_dataoffset;
        if (name.attr_length > length - name_at) return EIO;
        uint16_t name_length = (uint16_t)(name.attr_length - 1);
        const uint8_t *text = entry + name_at;
        if (text[name_length] || memchr(text, 0, name_length) || memchr(text, '/', name_length)) return EIO;
        if (capacity - written < 11 || name_length > capacity - written - 11) return EOVERFLOW;
        memcpy(out + written, &inode, sizeof(inode));
        out[written + 8] = kind == VDIR ? DT_DIR : DT_REG;
        memcpy(out + written + 9, &name_length, sizeof(name_length));
        memcpy(out + written + 11, text, name_length);
        written += 11 + name_length;
        offset += length;
    }
    // Unused native-buffer tail is not a record. Never publish partial success.
    *used = written;
    return 0;
}
int mrk_entries(int fd, uint8_t *out, size_t capacity, size_t *used) {
    uint8_t block[65536] = {0};
    if (!out || !used || capacity != sizeof(block)) return EINVAL;
    *used = 0;
    struct attrlist request = { .bitmapcount = ATTR_BIT_MAP_COUNT,
                               .commonattr = MRK_DIRECTORY_ATTRS };
    // Same original borrowed FD/cursor. No dup, DIR allocation, reopen,
    // private inode symbol, ABI override, retry, rewind or extra close owner.
    int count = getattrlistbulk(fd, &request, block, sizeof(block), 0);
    if (count < 0) return errno ? errno : EIO;
    return mrk_decode_directory_entries(block, sizeof(block), count, out, capacity, used);
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
