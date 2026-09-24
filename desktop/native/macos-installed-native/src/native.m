#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <Block.h>
#include <sys/acl.h>
#include <sys/stat.h>
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
#ifdef MRK_INSTALLED_OBSERVATION
#import <ApplicationServices/ApplicationServices.h>
#include <math.h>
#include <stdatomic.h>
#include <stdlib.h>
#endif

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
// Closed first-party diagnostic ABI, shared with Rust and the fixed probe.
// 1 allocation; 2 snapshot; 3/4/5 owner/group/mode completeness; 6 presence;
// 7 conversion; 8 object; 9 validation; 10 first entry; 11 ACE; 12 free.
// Values are saved observations, not accepted-error or ownership capabilities.
static int mrk_acl_failure(int at, int returned, int observed_errno,
                           int *phase, int *call_result, int *native_errno) {
    *phase = at; *call_result = returned; *native_errno = observed_errno;
    return observed_errno ? observed_errno : EIO;
}
int mrk_acl_empty(int fd, int *phase, int *call_result, int *native_errno,
                  int *free_result, int *free_errno) {
    if (!phase || !call_result || !native_errno || !free_result || !free_errno) return EINVAL;
    *phase = *call_result = *native_errno = *free_result = *free_errno = 0;
    errno = 0;
    filesec_t fsec = filesec_init();
    if (!fsec) return mrk_acl_failure(1, 0, errno, phase, call_result, native_errno);
    acl_t acl = NULL; int owned_acl = 0, saved = 0, rc = 0, observed_errno = 0;
    struct stat snapshot = {0}; uid_t owner = 0; gid_t group = 0; mode_t mode = 0; int present = 0;
    // acl_get_fd_np collapses a genuinely absent ACL to NULL/ENOENT. Observe
    // successful same-FD snapshot + explicit presence instead, never errno alone.
    errno = 0; rc = fstatx_np(fd, &snapshot, fsec); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(2, rc, observed_errno, phase, call_result, native_errno); goto done; }
    // A fresh but unpopulated filesec is not proof of absence, including after
    // libc allocation/early-out paths. All three ordinary properties must exist.
    errno = 0; rc = filesec_get_property(fsec, FILESEC_OWNER, &owner); observed_errno = errno;
    if (rc != 0 || owner != snapshot.st_uid) { saved = mrk_acl_failure(3, rc, rc ? observed_errno : 0, phase, call_result, native_errno); goto done; }
    errno = 0; rc = filesec_get_property(fsec, FILESEC_GROUP, &group); observed_errno = errno;
    if (rc != 0 || group != snapshot.st_gid) { saved = mrk_acl_failure(4, rc, rc ? observed_errno : 0, phase, call_result, native_errno); goto done; }
    errno = 0; rc = filesec_get_property(fsec, FILESEC_MODE, &mode); observed_errno = errno;
    if (rc != 0 || mode != snapshot.st_mode) { saved = mrk_acl_failure(5, rc, rc ? observed_errno : 0, phase, call_result, native_errno); goto done; }
    errno = 0; rc = filesec_query_property(fsec, FILESEC_ACL, &present); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(6, rc, observed_errno, phase, call_result, native_errno); goto done; }
    if (!present) goto done; // Successful, complete snapshot: there is no ACL.
    // Presence is a zero/nonzero flag, not necessarily the integer1 on Darwin.
    errno = 0; rc = filesec_get_property(fsec, FILESEC_ACL, &acl); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(7, rc, observed_errno, phase, call_result, native_errno); goto done; }
    if (!acl || (void *)acl == _FILESEC_REMOVE_ACL || (void *)acl == _FILESEC_UNSET_PROPERTY) {
        saved = mrk_acl_failure(8, 0, 0, phase, call_result, native_errno); goto done;
    }
    owned_acl = 1;
    errno = 0; rc = acl_valid(acl); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(9, rc, observed_errno, phase, call_result, native_errno); goto done; }
    acl_entry_t entry;
    errno = 0; rc = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); observed_errno = errno;
    // Darwin success0 means an ACE exists. Only -1/EINVAL on a valid ACL is
    // an empty first entry. Principal, rights and inheritance never allow an ACE.
    if (rc == 0) { *phase = 11; *call_result = 0; *native_errno = 0; saved = EPERM; }
    else if (!(rc == -1 && observed_errno == EINVAL)) {
        saved = mrk_acl_failure(10, rc, observed_errno, phase, call_result, native_errno);
    }
done:
    if (owned_acl) {
        errno = 0; rc = acl_free(acl); observed_errno = errno;
        if (rc != 0) {
            *free_result = rc; *free_errno = observed_errno;
            if (!saved) (void)mrk_acl_failure(12, rc, observed_errno, phase, call_result, native_errno);
            saved = observed_errno ? observed_errno : EIO; // Free failure vetoes even an otherwise empty ACL.
        }
    }
    filesec_free(fsec); // Exactly once; void API must actually return. No FD ownership transfer.
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

#ifdef MRK_INSTALLED_OBSERVATION
// Closed result: 0=returned snapshot, 1=entry refused, 2=AppKit read error.
// The supplied address is comparison DATA, never an object to dereference.
int mrk_observation_original_window(uintptr_t original, uint32_t *flags) {
    if (!flags) return 1;
    *flags = 0;
    if (!pthread_main_np() || !original) return 1;
    @try {
        NSApplication *app = NSApp; // Do not initialize or activate an application.
        if (!app) return 0;
        uint32_t observed = 1u; // application present
        if ([app isActive]) observed |= 2u;
        NSWindow *main = [app mainWindow];
        if (main) {
            observed |= 4u;
            if ((uintptr_t)(void *)main == original) observed |= 8u;
            if (![main isKindOfClass:[NSPanel class]]) observed |= 16u;
            if (![main attachedSheet]) observed |= 32u;
        }
        *flags = observed; // Publish no partial flags if an AppKit read throws.
        return 0;
    } @catch (NSException *e) { (void)e; return 2; }
}
#endif

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

#ifdef MRK_INSTALLED_OBSERVATION
// Saved scalar DATA only. Zero means unobserved, not a nil getter result.
typedef struct {
    uint32_t flags, checked, matched, parent, panel, children, originals, site, error;
} MRKIdentityProof;
typedef struct {
    uint32_t flags, parent, prompt, site, error;
    MRKIdentityProof binding;
} MRKIdentityWire;
_Static_assert(sizeof(MRKIdentityWire) == 56, "fixed original identity scalar ABI");
enum { MRK_ID_ARMED = 1u, MRK_ID_CONFIG_ATTEMPTED = 2u, MRK_ID_PARENT_ENTERED = 4u,
    MRK_ID_PARENT_RETURNED = 8u, MRK_ID_CONFIG_COMPLETE = 16u,
    MRK_ID_PROMPT_ENTERED = 32u, MRK_ID_PROMPT_RETURNED = 64u };
enum { MRK_ID_OBJECTS = 1u, MRK_ID_TAGS, MRK_ID_PARENT_SET, MRK_ID_PARENT_GET, MRK_ID_COMPLETE,
    MRK_ID_PROMPT_SET, MRK_ID_PROMPT_GET };
enum { MRK_ID_UNOBSERVED, MRK_ID_NIL, MRK_ID_MATCH, MRK_ID_DIFFERENT, MRK_ID_TYPE_INVALID };
enum { MRK_PANEL_ID_UNOBSERVED, MRK_PANEL_ID_NIL, MRK_PANEL_ID_TYPE_INVALID, MRK_PANEL_ID_EMPTY,
    MRK_PANEL_ID_LIMIT, MRK_PANEL_ID_NUL, MRK_PANEL_ID_ENCODING, MRK_PANEL_ID_VALID,
    MRK_PANEL_ID_MATCH, MRK_PANEL_ID_DIFFERENT };
enum { MRK_PROOF_OBJECTS = 1u, MRK_PROOF_ATTACHMENT, MRK_PROOF_DIRECTORY, MRK_PROOF_PARENT_ID,
    MRK_PROOF_PANEL_ID, MRK_PROOF_PARENT_SHEETS, MRK_PROOF_PANEL_SHEETS, MRK_PROOF_PANEL_SHEET,
    MRK_PROOF_CHILDREN, MRK_PROOF_PARENT, MRK_PROOF_ROLE, MRK_PROOF_STABLE,
    MRK_PROOF_FINAL, MRK_PROOF_COMPLETE, MRK_PROOF_ALL = 0xfffu };
#endif

@interface MRKInstalledPanel : NSObject {
@public
    NSWindow *parent;
    NSWindow *window;
    NSAlert *alert;
    void (^completion)(NSModalResponse);
    BOOL attempted, started, responded, reported, callbackActive, closeAttempted, closed, unknown;
    int kind, response;
    char selected[4097];
#ifdef MRK_INSTALLED_OBSERVATION
    // Instrumentation only; never callback/cleanup/selection authority.
    BOOL observationDirectoryReturned, observationActionAttempted, observationActionReturned;
    char observationDirectory[4097], observationTarget[4097];
    char observationParentTag[64], observationPanelTag[64];
    char observationPrompt[8];
    MRKIdentityWire observationIdentity;
    unsigned observationRechecks;
#endif
}
@end
@implementation MRKInstalledPanel
@end
#ifdef MRK_INSTALLED_OBSERVATION
static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s);
#endif

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
#ifdef MRK_INSTALLED_OBSERVATION
        if ((s->observationIdentity.flags & MRK_ID_ARMED) && !mrk_panel_configure_open_identity(s)) {
            // Objects already exist. This is never the pre-construction EPERM.
            s->unknown = YES; return EIO;
        }
#endif
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

#ifdef MRK_INSTALLED_OBSERVATION
// No separate window lookup: sample only the retained originals. Presence
// bits distinguish an unqueried relationship from a measured false result.
enum { MRK_PARENT_PRESENT = 1u << 12, MRK_PANEL_PRESENT = 1u << 13,
    MRK_PARENT_REFERENCES_PANEL = 1u << 14, MRK_PANEL_REFERENCES_PARENT = 1u << 15,
    MRK_PANEL_VISIBLE = 1u << 16, MRK_ATTACHMENT_ALL = 0x1f000u };
static uint32_t mrk_observation_attachment(MRKInstalledPanel *s) {
    uint32_t sample = (s->parent ? MRK_PARENT_PRESENT : 0u) | (s->window ? MRK_PANEL_PRESENT : 0u);
    if (s->parent && s->window) {
        if ([s->parent attachedSheet] == s->window) sample |= MRK_PARENT_REFERENCES_PANEL;
        if ([s->window sheetParent] == s->parent) sample |= MRK_PANEL_REFERENCES_PARENT;
    }
    if (s->window && [s->window isVisible]) sample |= MRK_PANEL_VISIBLE;
    return sample;
}
static BOOL mrk_observation_attached(MRKInstalledPanel *s) {
    return mrk_observation_attachment(s) == MRK_ATTACHMENT_ALL;
}
static BOOL mrk_target_path(const char *path) {
    size_t length = strnlen(path, 4097);
    if (!length || length > 4096 || path[0] != '/') return NO;
    if (length == 1) return YES;
    for (size_t start = 1, end = 1; end <= length; ++end) {
        if (end != length && path[end] != '/') continue;
        size_t count = end - start;
        if (!count || count > 255 || (count == 1 && path[start] == '.')
            || (count == 2 && path[start] == '.' && path[start + 1] == '.')) return NO;
        start = end + 1;
    }
    return YES;
}
static BOOL mrk_observation_directory_ready(MRKInstalledPanel *s) {
    // This is browse-parent readiness, never selected-target authority.
    if (s->kind != 1 || !s->window || !s->observationDirectoryReturned || !s->observationDirectory[0]
        || !mrk_target_path(s->observationTarget)) return NO;
    NSURL *url = [(NSOpenPanel *)s->window directoryURL];
    const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
    return path && strnlen(path, sizeof(s->observationDirectory)) < sizeof(s->observationDirectory)
        && strcmp(path, s->observationDirectory) == 0;
}
int mrk_panel_observe(void *opaque, int *kind, uint32_t *flags, int *response, uint8_t *path, size_t capacity) {
    if (!pthread_main_np() || !opaque || !kind || !flags || !response || !path || capacity != 4097) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->unknown) return EIO;
    @try {
        // Closed seventeen-bit ABI with the Rust PanelObservation decoder. Reads
        // do not set reported, manufacture completion, or authorize retirement.
        uint32_t attachment = mrk_observation_attachment(s);
        *kind = s->kind; *response = s->response;
        *flags = attachment | (s->started ? 1u : 0u) | (attachment == MRK_ATTACHMENT_ALL ? 2u : 0u)
            | (s->observationDirectory[0] ? 4u : 0u) | (s->observationDirectoryReturned ? 8u : 0u)
            | (mrk_observation_directory_ready(s) ? 16u : 0u) | (s->observationActionAttempted ? 32u : 0u)
            | (s->observationActionReturned ? 64u : 0u) | (s->responded ? 128u : 0u)
            | (s->responded && !s->callbackActive ? 256u : 0u) | (s->closeAttempted ? 512u : 0u)
            | (s->window && ![s->window isVisible] && ![s->window sheetParent] ? 1024u : 0u)
            | (s->closed ? 2048u : 0u);
        memcpy(path, s->selected, sizeof(s->selected)); return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
// Closed DATA from this one original return. No exception object, subsequent
// query, native status replacement, or permission is carried by these sites.
enum {
    MRK_ACTION_THREAD = 1, MRK_ACTION_POINTER, MRK_ACTION_CODE, MRK_ACTION_ARGUMENT,
    MRK_ACTION_UNKNOWN, MRK_ACTION_STARTED, MRK_ACTION_WINDOW, MRK_ACTION_PARENT,
    MRK_ACTION_COMPLETION, MRK_ACTION_RESPONDED, MRK_ACTION_CALLBACK,
    MRK_ACTION_CLOSE_ATTEMPTED, MRK_ACTION_CLOSED, MRK_ACTION_ATTEMPTED, MRK_ACTION_KIND,
    MRK_ACTION_ATTACHMENT, MRK_ACTION_DIRECTORY_BOUND, MRK_ACTION_DIRECTORY_PATH,
    MRK_ACTION_DIRECTORY_TEXT, MRK_ACTION_DIRECTORY_URL, MRK_ACTION_DIRECTORY_SET,
    MRK_ACTION_DIRECTORY_UNBOUND, MRK_ACTION_DIRECTORY_RETURNED, MRK_ACTION_DIRECTORY_READY,
    MRK_ACTION_ALERT_BUTTONS, MRK_ACTION_ALERT, MRK_ACTION_BUTTON_COUNT, MRK_ACTION_BUTTON_INDEX,
    MRK_ACTION_BUTTON_WINDOW, MRK_ACTION_BUTTON_ENABLED, MRK_ACTION_BUTTON_HIDDEN,
    MRK_ACTION_PROJECT_CANCEL, MRK_ACTION_PROJECT_OPEN, MRK_ACTION_QUIT_CANCEL, MRK_ACTION_QUIT_CONFIRM
};
_Static_assert(EPERM == 1 && EIO == 5 && EINVAL == 22 && EAGAIN == 35 && EALREADY == 37, "Darwin action diagnostic errno ABI");
static int mrk_observation_action_return(uint32_t *diagnostic, uint32_t domain, uint32_t site, int status) {
    if (diagnostic) *diagnostic = (domain << 16) | site;
    return status; // The original status, not a diagnostic classification.
}
int mrk_panel_observe_action(void *opaque, int action, const char *directory, uint32_t *diagnostic) {
    if (diagnostic) *diagnostic = 0;
    volatile uint32_t site = MRK_ACTION_THREAD;
#define MRK_ACTION_RETURN(status) return mrk_observation_action_return(diagnostic, 1u, site, (status))
    // Split only the existing short-circuit predicates, in their original order.
    if (!pthread_main_np()) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_POINTER; if (!opaque) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_CODE; if (action < 1 || action > 5 || action == 3) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_ARGUMENT; if ((action == 2) != (directory != NULL)) MRK_ACTION_RETURN(EINVAL);
    MRKInstalledPanel *s = opaque;
    site = MRK_ACTION_UNKNOWN; if (s->unknown) MRK_ACTION_RETURN(EIO);
    site = MRK_ACTION_STARTED; if (!s->started) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_WINDOW; if (!s->window) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_PARENT; if (!s->parent) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_COMPLETION; if (!s->completion) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_RESPONDED; if (s->responded) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_CALLBACK; if (s->callbackActive) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_CLOSE_ATTEMPTED; if (s->closeAttempted) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_CLOSED; if (s->closed) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_ATTEMPTED; if (s->observationActionAttempted) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_KIND;
    if ((action <= 3 && s->kind != 1) || (action >= 4 && s->kind != 2)) MRK_ACTION_RETURN(EPERM);
    @try {
        // EAGAIN is only pre-action readiness, never permission to repeat an
        // attempted action. The caller's original endpoint is not renewed.
        site = MRK_ACTION_ATTACHMENT; if (!mrk_observation_attached(s)) MRK_ACTION_RETURN(EAGAIN);
        if (action == 2) {
            site = MRK_ACTION_DIRECTORY_BOUND;
            if (s->observationDirectory[0] || s->observationTarget[0]) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_DIRECTORY_PATH;
            size_t length = strnlen(directory, sizeof(s->observationDirectory));
            if (length < 2 || !mrk_target_path(directory)) MRK_ACTION_RETURN(EINVAL);
            site = MRK_ACTION_DIRECTORY_TEXT;
            NSString *text = [NSString stringWithUTF8String:directory];
            NSURL *url = nil;
            if (text) { site = MRK_ACTION_DIRECTORY_URL; url = [NSURL fileURLWithPath:text isDirectory:YES]; }
            if (!url) MRK_ACTION_RETURN(EINVAL);
            // The input stays the fixture ROOT. Browse its parent so the root
            // itself is a selectable row; never change the expected result.
            NSURL *browse = [url URLByDeletingLastPathComponent];
            const char *parentPath = browse && [browse isFileURL] ? [browse fileSystemRepresentation] : NULL;
            if (!parentPath || parentPath[0] != '/' || strnlen(parentPath, sizeof(s->observationDirectory)) >= sizeof(s->observationDirectory)
                || strcmp(parentPath, directory) == 0) MRK_ACTION_RETURN(EINVAL);
            memcpy(s->observationTarget, directory, length + 1);
            memcpy(s->observationDirectory, parentPath, strlen(parentPath) + 1);
            site = MRK_ACTION_DIRECTORY_SET;
            [(NSOpenPanel *)s->window setDirectoryURL:browse];
            s->observationDirectoryReturned = YES; MRK_ACTION_RETURN(0);
        }
        NSButton *button = nil;
        if (action >= 4) {
            site = MRK_ACTION_ALERT_BUTTONS;
            NSArray<NSButton *> *buttons = [s->alert buttons];
            site = MRK_ACTION_ALERT; if (!s->alert) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_BUTTON_COUNT; if ([buttons count] != 2) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_BUTTON_INDEX;
            button = [buttons objectAtIndex:action == 4 ? 0 : 1];
            site = MRK_ACTION_BUTTON_WINDOW; if ([button window] != s->window) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_BUTTON_ENABLED; if (![button isEnabled]) MRK_ACTION_RETURN(EAGAIN);
            site = MRK_ACTION_BUTTON_HIDDEN; if ([button isHidden]) MRK_ACTION_RETURN(EAGAIN);
        }
        s->observationActionAttempted = YES;
        if (action == 1) { site = MRK_ACTION_PROJECT_CANCEL; [(NSOpenPanel *)s->window cancel:nil]; }
        else { site = action == 4 ? MRK_ACTION_QUIT_CANCEL : MRK_ACTION_QUIT_CONFIRM; [button performClick:nil]; }
        s->observationActionReturned = YES;
        // No call of s->completion, endSheet:, close_once or selected-path
        // mutation. Only AppKit's original completion supplies the outcome.
        MRK_ACTION_RETURN(0);
    } @catch (NSException *e) {
        (void)e; s->unknown = YES;
        return mrk_observation_action_return(diagnostic, 2u, site, EIO);
    }
#undef MRK_ACTION_RETURN
}

// Main-only original proof and off-main public AX input have separate ABIs.
// Only copied bounded identity/control DATA crosses threads; never an AppKit object.
enum { MRK_OPEN_NONE, MRK_OPEN_THREAD, MRK_OPEN_INPUT, MRK_OPEN_INELIGIBLE, MRK_OPEN_UNSUPPORTED,
    MRK_OPEN_AMBIGUOUS, MRK_OPEN_MALFORMED, MRK_OPEN_LIMIT, MRK_OPEN_DEADLINE, MRK_OPEN_CUSTODY,
    MRK_OPEN_INVALID_ELEMENT, MRK_OPEN_CANNOT_COMPLETE, MRK_OPEN_OTHER,
    MRK_OPEN_CHANGED, MRK_OPEN_EXCEPTION, MRK_OPEN_CLEANUP_UNKNOWN };
enum { MRK_OPEN_ENTRY = 1u, MRK_OPEN_APPLICATION, MRK_OPEN_WINDOWS, MRK_OPEN_PARENT_ID,
    MRK_OPEN_SHEET, MRK_OPEN_TOPOLOGY, MRK_OPEN_CONTROL_PROJECTION, MRK_OPEN_BUTTON, MRK_OPEN_CONTROL_RECHECK,
    MRK_OPEN_INITIAL_PROOF, MRK_OPEN_FINAL_PROOF, MRK_OPEN_ADMISSION, MRK_OPEN_PRESS, MRK_OPEN_CLEANUP,
    MRK_OPEN_CONTROL_TITLE_LIMIT, MRK_OPEN_CONTROL_CHILD_COUNT_LIMIT, MRK_OPEN_CONTROL_CHILD_COPY_LIMIT,
    MRK_OPEN_CONTROL_NODE_LIMIT, MRK_OPEN_CONTROL_DEPTH_LIMIT, MRK_OPEN_SELECTION, MRK_OPEN_SELECTION_WRITE };
enum { MRK_OPEN_ATTEMPTED = 1u, MRK_OPEN_RETURNED = 2u, MRK_OPEN_TRIGGERED = 4u, MRK_OPEN_KNOWN = 8u };
enum { MRK_ROLE_NOT_READ, MRK_ROLE_SHEET, MRK_ROLE_GROUP, MRK_ROLE_SPLIT_GROUP, MRK_ROLE_BUTTON,
    MRK_ROLE_BROWSER, MRK_ROLE_TABLE, MRK_ROLE_OUTLINE, MRK_ROLE_SCROLL_AREA, MRK_ROLE_OPAQUE, MRK_ROLE_ROW };
typedef struct { uint32_t flags, site, error, checks, calls, initial_nodes_examined, recheck_nodes_examined, owned, released;
    int32_t ax_error; uint32_t last_role, last_depth, selection_checks, selection_flags, selection_nodes_examined; } MRKOpenResult;
enum { MRK_TARGET_UNREAD, MRK_TARGET_ENTERED, MRK_TARGET_NOT_READY, MRK_TARGET_MATCH,
    MRK_TARGET_DIFFERENT, MRK_TARGET_MALFORMED, MRK_TARGET_MULTIPLE };
typedef struct { uint32_t known, error, prompt; MRKIdentityProof proof; uint32_t selected_target; } MRKOpenRecheck;
_Static_assert(sizeof(MRKOpenResult) == 60 && sizeof(MRKOpenRecheck) == 52, "fixed selection/press scalar ABI");
typedef struct { float seconds; uint64_t required_ns; } MRKOpenTimeout;
typedef int (*MRKOpenAdmission)(void *, uint64_t, int, MRKOpenTimeout *);
typedef int (*MRKOpenRecheckCall)(void *, int);

int mrk_observation_ax_trusted(void) {
    if (!pthread_main_np()) return -1;
    CFDictionaryRef options = NULL; int trusted = -1;
    @try {
        const void *keys[] = { kAXTrustedCheckOptionPrompt };
        const void *values[] = { kCFBooleanFalse };
        options = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (options) trusted = AXIsProcessTrustedWithOptions(options) ? 1 : 0;
    } @catch (NSException *e) { (void)e; trusted = -1; }
    @try { if (options) CFRelease(options); }
    @catch (NSException *e) { (void)e; trusted = -1; }
    return trusted; // A false result never prompts, waits, or opens a panel.
}

int mrk_panel_observe_arm_open_identity(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->attempted || s->unknown || s->observationIdentity.flags) return EALREADY;
    s->observationIdentity.flags = MRK_ID_ARMED; // Passive: no AppKit message or tag generation.
    return 0;
}
void mrk_panel_observe_identity_data(void *opaque, MRKIdentityWire *data) {
    // Used immediately after an original FFI return, while its retained Panel
    // is still borrowed. No usable()/AppKit query, release or ownership change.
    if (opaque && data) memcpy(data, &((MRKInstalledPanel *)opaque)->observationIdentity, sizeof(*data));
}
static BOOL mrk_identity_tag(const char tag[64], const char *prefix) {
    size_t offset = strlen(prefix), length = offset + 36;
    if (length >= 64 || strnlen(tag, 64) != length || memcmp(tag, prefix, offset)) return NO;
    for (size_t i = 0; i < 36; i++) {
        char c = tag[offset + i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return NO; }
        else if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) return NO;
    }
    for (size_t i = length; i < 64; i++) if (tag[i]) return NO;
    return YES;
}
static uint32_t mrk_identity_class(id value, NSString *tag) {
    if (!value) return MRK_ID_NIL;
    if (![value isKindOfClass:[NSString class]]) return MRK_ID_TYPE_INVALID;
    return [(NSString *)value isEqualToString:tag] ? MRK_ID_MATCH : MRK_ID_DIFFERENT;
}
// Strict bounded UTF-8, independently checked again by Rust and CF creation.
// No lossy/ASCII conversion, interior NUL, overlong form or nonzero padding.
static BOOL mrk_identity_utf8(const uint8_t bytes[64]) {
    size_t length = strnlen((const char *)bytes, 64);
    if (!length || length >= 64) return NO;
    for (size_t i = length; i < 64; i++) if (bytes[i]) return NO;
    for (size_t i = 0; i < length;) {
        uint32_t value = bytes[i++], minimum = 0; unsigned remaining = 0;
        if (value < 0x80) continue;
        if (value >= 0xc2 && value <= 0xdf) { value &= 0x1f; remaining = 1; minimum = 0x80; }
        else if (value >= 0xe0 && value <= 0xef) { value &= 0x0f; remaining = 2; minimum = 0x800; }
        else if (value >= 0xf0 && value <= 0xf4) { value &= 7; remaining = 3; minimum = 0x10000; }
        else return NO;
        if (remaining > length - i) return NO;
        while (remaining--) {
            uint8_t next = bytes[i++]; if ((next & 0xc0) != 0x80) return NO;
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return NO;
    }
    return YES;
}
static uint32_t mrk_original_identifier(id value, uint8_t bytes[64]) {
    memset(bytes, 0, 64);
    if (!value) return MRK_PANEL_ID_NIL;
    if (![value isKindOfClass:[NSString class]]) return MRK_PANEL_ID_TYPE_INVALID;
    NSString *text = value; NSUInteger length = [text length];
    if (!length) return MRK_PANEL_ID_EMPTY;
    if (length > 63) return MRK_PANEL_ID_LIMIT;
    for (NSUInteger i = 0; i < length; i++) if ([text characterAtIndex:i] == 0) return MRK_PANEL_ID_NUL;
    NSUInteger bytes_needed = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (!bytes_needed) return MRK_PANEL_ID_ENCODING;
    if (bytes_needed > 63) return MRK_PANEL_ID_LIMIT;
    NSUInteger used = 0; NSRange remainder = NSMakeRange(0, length);
    if (![text getBytes:bytes maxLength:63 usedLength:&used encoding:NSUTF8StringEncoding
        options:0 range:NSMakeRange(0, length) remainingRange:&remainder]
        || remainder.length || used != bytes_needed || !mrk_identity_utf8(bytes)) return MRK_PANEL_ID_ENCODING;
    NSString *roundtrip = [[[NSString alloc] initWithBytes:bytes length:used encoding:NSUTF8StringEncoding] autorelease];
    return roundtrip && [roundtrip isEqualToString:text] ? MRK_PANEL_ID_VALID : MRK_PANEL_ID_ENCODING;
}
static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s) {
    MRKIdentityWire *d = &s->observationIdentity;
    d->flags |= MRK_ID_CONFIG_ATTEMPTED; d->site = MRK_ID_OBJECTS;
    d->error = MRK_OPEN_INELIGIBLE;
    if (!s->parent || !s->window || s->kind != 1 || s->unknown || s->responded
        || s->callbackActive || s->closeAttempted || s->closed) return NO;
    @try {
        d->site = MRK_ID_TAGS; d->error = MRK_OPEN_INPUT;
        NSString *parentTag = [@"mrk-parent-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
        if (![parentTag getCString:s->observationParentTag maxLength:64 encoding:NSASCIIStringEncoding]
            || !mrk_identity_tag(s->observationParentTag, "mrk-parent-")) return NO;
        // NSSavePanel.prompt identifies the real default Open button. This
        // observation-only short title is not identity/authentication authority.
        memcpy(s->observationPrompt, "MRK", 3);
        memcpy(s->observationPrompt + 3, s->observationParentTag + strlen("mrk-parent-"), 4);
        for (unsigned i = 3; i < 7; ++i)
            if (s->observationPrompt[i] >= 'a' && s->observationPrompt[i] <= 'f') s->observationPrompt[i] -= 'a' - 'A';
        NSString *prompt = [NSString stringWithCString:s->observationPrompt encoding:NSASCIIStringEncoding];
        if (!prompt) return NO;
        d->site = MRK_ID_PARENT_SET; d->flags |= MRK_ID_PARENT_ENTERED;
        [s->parent setAccessibilityIdentifier:parentTag];
        d->flags |= MRK_ID_PARENT_RETURNED;
        d->site = MRK_ID_PARENT_GET;
        d->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        d->site = MRK_ID_PROMPT_SET; d->flags |= MRK_ID_PROMPT_ENTERED;
        [(NSOpenPanel *)s->window setPrompt:prompt]; d->flags |= MRK_ID_PROMPT_RETURNED;
        d->site = MRK_ID_PROMPT_GET;
        d->prompt = mrk_identity_class([(NSOpenPanel *)s->window prompt], prompt);
        if (d->prompt != MRK_ID_MATCH) { d->error = MRK_OPEN_CHANGED; return NO; }
        // Only the parent identifier is set. No panel-identifier setter or
        // invented identifier return; that value is read at admitted preparation.
        d->flags |= MRK_ID_CONFIG_COMPLETE; d->site = MRK_ID_COMPLETE; d->error = MRK_OPEN_NONE;
        return YES;
    } @catch (NSException *e) {
        (void)e; d->error = MRK_OPEN_EXCEPTION;
        @throw; // The SAME original start catch records unknown/EIO.
    }
}
static BOOL mrk_original_eligible(MRKInstalledPanel *s) {
    return !s->unknown && s->started && s->kind == 1 && s->parent && s->window && s->completion
        && !s->responded && !s->callbackActive && !s->closeAttempted && !s->closed
        && !s->observationActionAttempted && !s->observationActionReturned
        && (s->observationIdentity.flags & (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE)) == (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE);
}
static BOOL mrk_proof_check(MRKIdentityProof *p, unsigned bit, BOOL matched, uint32_t error) {
    p->checked |= 1u << bit;
    if (matched) { p->matched |= 1u << bit; return YES; }
    p->matched &= ~(1u << bit); p->error = error; return NO;
}
static BOOL mrk_original_topology(MRKInstalledPanel *s, MRKIdentityProof *p) {
    p->site = MRK_PROOF_PARENT_SHEETS;
    id sheets = [s->parent sheets];
    if (![sheets isKindOfClass:[NSArray class]]) return mrk_proof_check(p, 5, NO, MRK_OPEN_MALFORMED);
    NSUInteger count = [sheets count];
    if (!mrk_proof_check(p, 5, count == 1 && [sheets objectAtIndex:0] == s->window,
        count > 1 ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_CHANGED)) return NO;
    p->site = MRK_PROOF_PANEL_SHEETS;
    sheets = [s->window sheets];
    if (![sheets isKindOfClass:[NSArray class]]) return mrk_proof_check(p, 6, NO, MRK_OPEN_MALFORMED);
    if ([sheets count]) return mrk_proof_check(p, 6, NO, MRK_OPEN_AMBIGUOUS);
    p->site = MRK_PROOF_PANEL_SHEET;
    if (!mrk_proof_check(p, 6, [s->window attachedSheet] == nil, MRK_OPEN_AMBIGUOUS)) return NO;
    p->site = MRK_PROOF_CHILDREN;
    id children = [s->parent accessibilityChildren];
    if (![children isKindOfClass:[NSArray class]]) return mrk_proof_check(p, 7, NO, MRK_OPEN_MALFORMED);
    count = [children count]; p->children = (uint32_t)(count > 16 ? 17 : count) + 1;
    if (count > 16) return mrk_proof_check(p, 7, NO, MRK_OPEN_LIMIT);
    unsigned originals = 0;
    for (NSUInteger i = 0; i < count; i++) if ([children objectAtIndex:i] == s->window) originals++;
    p->originals = originals == 0 ? 1 : originals == 1 ? 2 : 3;
    if (!mrk_proof_check(p, 7, originals == 1, originals > 1 ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED)) return NO;
    p->site = MRK_PROOF_PARENT;
    if (!mrk_proof_check(p, 8, [s->window accessibilityParent] == s->parent, MRK_OPEN_UNSUPPORTED)) return NO;
    p->site = MRK_PROOF_ROLE;
    id role = [s->window accessibilityRole];
    if (![role isKindOfClass:[NSString class]]) return mrk_proof_check(p, 9, NO, MRK_OPEN_MALFORMED);
    return mrk_proof_check(p, 9, [role isEqualToString:NSAccessibilitySheetRole], MRK_OPEN_UNSUPPORTED);
}
static int mrk_original_proof(MRKInstalledPanel *s, MRKIdentityProof *p, BOOL freeze) {
    p->flags = 1; p->site = MRK_PROOF_OBJECTS; p->error = MRK_OPEN_INELIGIBLE;
    if (!mrk_proof_check(p, 0, mrk_original_eligible(s), MRK_OPEN_INELIGIBLE)) return p->error;
    @try {
        p->site = MRK_PROOF_ATTACHMENT;
        if (!mrk_proof_check(p, 1, mrk_observation_attached(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_DIRECTORY;
        if (!mrk_proof_check(p, 2, mrk_observation_directory_ready(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_PARENT_ID;
        if (!mrk_identity_tag(s->observationParentTag, "mrk-parent-")) { p->error = MRK_OPEN_INPUT; return p->error; }
        NSString *parentTag = [NSString stringWithCString:s->observationParentTag encoding:NSASCIIStringEncoding];
        p->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        if (!mrk_proof_check(p, 3, p->parent == MRK_ID_MATCH, MRK_OPEN_UNSUPPORTED)) return p->error;
        p->site = MRK_PROOF_PANEL_ID; uint8_t current[64] = {0};
        p->panel = mrk_original_identifier([s->window accessibilityIdentifier], current);
        if (!mrk_proof_check(p, 4, p->panel == MRK_PANEL_ID_VALID,
            p->panel == MRK_PANEL_ID_LIMIT ? MRK_OPEN_LIMIT : MRK_OPEN_UNSUPPORTED)) return p->error;
        if (!memcmp(current, s->observationParentTag, 64)) {
            p->panel = MRK_PANEL_ID_DIFFERENT; mrk_proof_check(p, 4, NO, MRK_OPEN_INPUT); return p->error;
        }
        if (freeze) memcpy(s->observationPanelTag, current, 64); // First valid value; never retag/rebind.
        else {
            p->panel = !memcmp(current, s->observationPanelTag, 64) ? MRK_PANEL_ID_MATCH : MRK_PANEL_ID_DIFFERENT;
            if (!mrk_proof_check(p, 4, p->panel == MRK_PANEL_ID_MATCH, MRK_OPEN_CHANGED)) return p->error;
        }
        if (!mrk_original_topology(s, p)) return p->error;
        // One fixed final native proof, not a retry. Reads may reenter; original
        // custody and every public edge must still hold on actual return.
        p->site = MRK_PROOF_ATTACHMENT;
        if (!mrk_proof_check(p, 1, mrk_observation_attached(s), MRK_OPEN_CHANGED)) return p->error;
        p->site = MRK_PROOF_DIRECTORY;
        if (!mrk_proof_check(p, 2, mrk_observation_directory_ready(s), MRK_OPEN_CHANGED)) return p->error;
        if (!mrk_original_topology(s, p)) return p->error;
        p->site = MRK_PROOF_PARENT_ID;
        p->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        if (!mrk_proof_check(p, 3, p->parent == MRK_ID_MATCH, MRK_OPEN_CHANGED)) return p->error;
        p->site = MRK_PROOF_STABLE;
        p->panel = mrk_original_identifier([s->window accessibilityIdentifier], current);
        if (p->panel == MRK_PANEL_ID_VALID)
            p->panel = !memcmp(current, s->observationPanelTag, 64) ? MRK_PANEL_ID_MATCH : MRK_PANEL_ID_DIFFERENT;
        BOOL stable = p->panel == MRK_PANEL_ID_MATCH;
        // Bit4 records the first validated/frozen value. Preserve that fact
        // if this later getter changes; bit10 and the final class say why.
        if (!mrk_proof_check(p, 10, stable, MRK_OPEN_CHANGED)) return p->error;
        p->site = MRK_PROOF_FINAL;
        if (!mrk_proof_check(p, 11, mrk_original_eligible(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_COMPLETE; p->error = MRK_OPEN_NONE; return MRK_OPEN_NONE;
    } @catch (NSException *e) { (void)e; s->unknown = YES; p->error = MRK_OPEN_EXCEPTION; return MRK_OPEN_EXCEPTION; }
}
static BOOL mrk_prompt_valid(const uint8_t *parent, const uint8_t *prompt) {
    if (!prompt || memcmp(prompt, "MRK", 3) || prompt[7]) return NO;
    for (unsigned i = 0; i < 4; ++i) {
        char c = parent[strlen("mrk-parent-") + i];
        if (c >= 'a' && c <= 'f') c -= 'a' - 'A';
        if (prompt[3 + i] != c) return NO;
    }
    return YES;
}
int mrk_panel_observe_open_identity(void *opaque, uint8_t *parent, uint8_t *panel, uint8_t *prompt, size_t capacity,
    uint8_t *target, size_t target_capacity) {
    if (!pthread_main_np()) return MRK_OPEN_THREAD;
    if (!opaque || !parent || !panel || !prompt || capacity != 64 || !target || target_capacity != 4097) return MRK_OPEN_INPUT;
    memset(parent, 0, capacity); memset(panel, 0, capacity); memset(prompt, 0, 8);
    memset(target, 0, target_capacity);
    MRKInstalledPanel *s = opaque; MRKIdentityProof *p = &s->observationIdentity.binding;
    if (p->site) return MRK_OPEN_INELIGIBLE;
    int status = mrk_original_proof(s, p, YES);
    if (!status) {
        memcpy(parent, s->observationParentTag, capacity); memcpy(panel, s->observationPanelTag, capacity);
        memcpy(prompt, s->observationPrompt, 8);
        memcpy(target, s->observationTarget, target_capacity);
    }
    return status;
}
void mrk_panel_observe_open_recheck(void *opaque, const uint8_t *parent, const uint8_t *panel,
    const uint8_t *prompt, const uint8_t *target, size_t target_capacity, unsigned stage, MRKOpenRecheck *out) {
    if (!out) return;
    MRKOpenRecheck r = {0}; r.error = MRK_OPEN_CUSTODY;
    MRKInstalledPanel *s = opaque;
    @try {
        if (!pthread_main_np() || !s || !parent || !panel || !prompt || !target || target_capacity != 4097
            || (stage != 1 && stage != 2)) goto done;
        if (s->unknown || memcmp(parent, s->observationParentTag, 64) || memcmp(panel, s->observationPanelTag, 64)
            || memcmp(prompt, s->observationPrompt, 8) || memcmp(target, s->observationTarget, target_capacity)
            || s->observationRechecks != stage - 1) {
            s->unknown = YES; goto done;
        }
        s->observationRechecks = stage; // Original read-only body is one-shot, not an action.
        r.error = mrk_original_proof(s, &r.proof, NO);
        if (!r.error) {
            NSString *expected = [NSString stringWithCString:s->observationPrompt encoding:NSASCIIStringEncoding];
            id actual = [(NSOpenPanel *)s->window prompt];
            r.prompt = mrk_identity_class(actual, expected) == MRK_ID_MATCH ? 1u : 2u;
            if (r.prompt != 1) r.error = MRK_OPEN_CHANGED;
        }
        if (!r.error && stage == 2) {
            // Exactly one read of the real selected URLs after the row setter.
            // Nil/empty is not-ready, not a wrong-object claim. Never write the
            // ordinary s->selected output or redispatch this spent stage.
            r.selected_target = MRK_TARGET_ENTERED;
            id urls = [(NSOpenPanel *)s->window URLs];
            if (!urls) r.selected_target = MRK_TARGET_NOT_READY;
            else if (![urls isKindOfClass:[NSArray class]]) r.selected_target = MRK_TARGET_MALFORMED;
            else {
                NSUInteger count = [urls count];
                if (!count) r.selected_target = MRK_TARGET_NOT_READY;
                else if (count != 1) r.selected_target = MRK_TARGET_MULTIPLE;
                else {
                    id url = [urls objectAtIndex:0];
                    const char *path = [url isKindOfClass:[NSURL class]] && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
                    r.selected_target = !path || !mrk_target_path(path) ? MRK_TARGET_MALFORMED
                        : strcmp(path, s->observationTarget) == 0 ? MRK_TARGET_MATCH : MRK_TARGET_DIFFERENT;
                }
            }
            switch (r.selected_target) {
                case MRK_TARGET_NOT_READY: r.error = MRK_OPEN_INELIGIBLE; break;
                case MRK_TARGET_DIFFERENT: r.error = MRK_OPEN_CHANGED; break;
                case MRK_TARGET_MALFORMED: r.error = MRK_OPEN_MALFORMED; break;
                case MRK_TARGET_MULTIPLE: r.error = MRK_OPEN_AMBIGUOUS; break;
                default: break;
            }
            // Reads can reenter. A matching URL alone cannot survive a changed
            // original owner/panel; actual completion remains final authority.
            if (!mrk_observation_attached(s) || !mrk_original_eligible(s)) {
                if (!r.error) r.error = MRK_OPEN_INELIGIBLE;
            }
            if (s->unknown) r.error = MRK_OPEN_CUSTODY;
        }
        if (!s->unknown && r.error != MRK_OPEN_CUSTODY && r.error != MRK_OPEN_EXCEPTION) r.known = 1;
    } @catch (NSException *e) { (void)e; if (s) s->unknown = YES; r.error = MRK_OPEN_EXCEPTION; }
done:
    *out = r; // The actual main/TLS guard is released by Rust before its receipt.
}

enum { MRK_PROMPT_CALLS = 512, MRK_PROMPT_CF = 256, MRK_CONTROL_NODES = 17, MRK_CONTROL_DEPTH = 8 };
typedef union { CFTypeRef value; CFArrayRef array; } MRKPromptOwned;
typedef struct {
    AXUIElementRef nodes[MRK_CONTROL_NODES];
    unsigned parents[MRK_CONTROL_NODES], depths[MRK_CONTROL_NODES], roles[MRK_CONTROL_NODES];
    unsigned chain[MRK_CONTROL_DEPTH + 1], chain_count, candidate;
} MRKControlPass;
typedef struct {
    MRKOpenAdmission admit; MRKOpenRecheckCall recheck; void *context; MRKOpenResult result;
    CFTypeID elementType;
    MRKPromptOwned owned[MRK_PROMPT_CF]; unsigned count;
    AXUIElementRef button; // Borrowed only from the first pass's retained original CFArray.
    BOOL cleanupKnown;
} MRKPrompt;
// One registered worker per original process. On exception/uncertain CF cleanup
// the exact fixed ledger remains retained for process lifetime, never Drop/retry.
static MRKPrompt mrk_prompt_original;
static atomic_flag mrk_prompt_claimed = ATOMIC_FLAG_INIT;
static BOOL mrk_ax_fail(MRKPrompt *s, uint32_t error) {
    if (!s->result.error) s->result.error = error;
    return NO;
}
static BOOL mrk_ax_control_limit(MRKPrompt *s, uint32_t site) {
    // Shared array callers outside either control pass and an earlier failure
    // keep their site. Cleanup preserves the first phase and both counters.
    if ((s->result.site == MRK_OPEN_CONTROL_PROJECTION || s->result.site == MRK_OPEN_CONTROL_RECHECK)
        && !s->result.error) s->result.site = site;
    return mrk_ax_fail(s, MRK_OPEN_LIMIT);
}
static uint32_t mrk_ax_role(CFStringRef role) {
    if (CFEqual(role, kAXSheetRole)) return MRK_ROLE_SHEET;
    if (CFEqual(role, kAXGroupRole)) return MRK_ROLE_GROUP;
    if (CFEqual(role, kAXSplitGroupRole)) return MRK_ROLE_SPLIT_GROUP;
    if (CFEqual(role, kAXButtonRole)) return MRK_ROLE_BUTTON;
    if (CFEqual(role, kAXBrowserRole)) return MRK_ROLE_BROWSER;
    if (CFEqual(role, kAXTableRole)) return MRK_ROLE_TABLE;
    if (CFEqual(role, kAXOutlineRole)) return MRK_ROLE_OUTLINE;
    if (CFEqual(role, kAXScrollAreaRole)) return MRK_ROLE_SCROLL_AREA;
    return MRK_ROLE_OPAQUE;
}
static BOOL mrk_ax_status(MRKPrompt *s, AXError error) {
    if (error == kAXErrorSuccess) return YES;
    if (!s->result.ax_error) s->result.ax_error = error; // Actual first failing AX return, even after an earlier deadline.
    switch (error) {
        case kAXErrorAttributeUnsupported: case kAXErrorActionUnsupported: case kAXErrorNoValue:
        case kAXErrorNotImplemented: case kAXErrorAPIDisabled: return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
        case kAXErrorInvalidUIElement: return mrk_ax_fail(s, MRK_OPEN_INVALID_ELEMENT);
        case kAXErrorIllegalArgument: return mrk_ax_fail(s, MRK_OPEN_INPUT);
        case kAXErrorCannotComplete: return mrk_ax_fail(s, MRK_OPEN_CANNOT_COMPLETE);
        default: return mrk_ax_fail(s, MRK_OPEN_OTHER);
    }
}
static MRKPromptOwned *mrk_ax_slot(MRKPrompt *s) {
    if (s->count == MRK_PROMPT_CF) { mrk_ax_fail(s, MRK_OPEN_LIMIT); return NULL; }
    return &s->owned[s->count++]; // Register actual out-slot BEFORE every Create/Copy.
}
static BOOL mrk_ax_admit(MRKPrompt *s, uint64_t required_ns, int after, MRKOpenTimeout *timeout) {
    int result = s->admit(s->context, required_ns, after, timeout);
    if (!result) return YES;
    if (result != MRK_OPEN_DEADLINE && result != MRK_OPEN_INELIGIBLE && result != MRK_OPEN_CUSTODY) {
        s->cleanupKnown = NO; result = MRK_OPEN_CUSTODY;
    }
    if (result == MRK_OPEN_CUSTODY) s->cleanupKnown = NO;
    return mrk_ax_fail(s, (uint32_t)result);
}
static BOOL mrk_ax_before(MRKPrompt *s, AXUIElementRef element) {
    if (s->result.calls > MRK_PROMPT_CALLS - 2) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
    MRKOpenTimeout timeout = {0};
    if (!mrk_ax_admit(s, 0, 0, &timeout)) return NO;
    if (!isfinite(timeout.seconds) || timeout.seconds <= 0 || (double)timeout.seconds > 0.1
        || timeout.required_ns == 0 || timeout.required_ns > 100000000
        || timeout.required_ns != (uint64_t)ceil((double)timeout.seconds * 1000000000.0))
        return mrk_ax_fail(s, MRK_OPEN_INPUT);
    s->result.calls++;
    BOOL installed = mrk_ax_status(s, AXUIElementSetMessagingTimeout(element, timeout.seconds));
    // Same endpoint after the setter; never give the upcoming call more time
    // than remains. The callback is atomic/clock-only, with no owner lock.
    BOOL admitted = mrk_ax_admit(s, timeout.required_ns, 0, NULL);
    return installed && admitted;
}
static BOOL mrk_ax_type(MRKPrompt *s, CFTypeRef value, CFTypeID type) {
    return value && CFGetTypeID(value) == type ? YES : mrk_ax_fail(s, MRK_OPEN_MALFORMED);
}
static CFTypeRef mrk_ax_copy(MRKPrompt *s, AXUIElementRef element, CFStringRef attribute, BOOL optional) {
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->result.calls++;
    AXError status = AXUIElementCopyAttributeValue(element, attribute, &slot->value);
    // Optional Title exists only for labelled objects. An actual absent value
    // with no returned object is a nonmatch; IPC/malformed errors are not absence.
    BOOL absent = optional && !slot->value && (status == kAXErrorNoValue || status == kAXErrorAttributeUnsupported);
    BOOL returned = absent || mrk_ax_status(s, status), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!returned || !admitted || absent) return NULL;
    if (!slot->value) { mrk_ax_fail(s, MRK_OPEN_MALFORMED); return NULL; }
    return slot->value;
}
static CFArrayRef mrk_ax_array(MRKPrompt *s, AXUIElementRef element, CFStringRef attribute, CFIndex limit, BOOL allow_empty) {
    // A returned zero count is an ordinary empty array, not an illegal index0
    // Copy converted to absence. Count and bounded Copy both spend the common
    // timeout/call budget; a changed or truncated array cannot prove a search.
    if (!mrk_ax_before(s, element)) return NULL;
    CFIndex expected = -1; s->result.calls++;
    AXError count_status = AXUIElementGetAttributeValueCount(element, attribute, &expected);
    BOOL counted = mrk_ax_status(s, count_status), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!counted || !admitted) return NULL;
    if (expected < 0) { mrk_ax_fail(s, MRK_OPEN_MALFORMED); return NULL; }
    if (expected > limit) { mrk_ax_control_limit(s, MRK_OPEN_CONTROL_CHILD_COUNT_LIMIT); return NULL; }
    if (!expected) { if (!allow_empty) mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED); return NULL; }
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->result.calls++;
    AXError status = AXUIElementCopyAttributeValues(element, attribute, 0, limit + 1, &slot->array);
    BOOL copied = mrk_ax_status(s, status); admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!copied || !admitted || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NULL;
    CFIndex count = CFArrayGetCount(slot->array);
    if (count < 0 || count > limit) { mrk_ax_control_limit(s, MRK_OPEN_CONTROL_CHILD_COPY_LIMIT); return NULL; }
    if (count != expected) { mrk_ax_fail(s, MRK_OPEN_CHANGED); return NULL; }
    // Each caller validates an element when that node begins. In the control
    // pass this keeps a failed type/parent/role read paired with its own counter,
    // depth and cleared role, never a previous sibling's diagnostic state.
    return slot->array;
}
static BOOL mrk_ax_equal_attribute(MRKPrompt *s, AXUIElementRef element, CFStringRef attribute, CFTypeRef expected) {
    CFTypeRef actual = mrk_ax_copy(s, element, attribute, NO);
    if (!actual || !mrk_ax_type(s, actual, CFGetTypeID(expected))) return NO;
    return CFEqual(actual, expected) ? YES : mrk_ax_fail(s, MRK_OPEN_CHANGED);
}
static BOOL mrk_ax_projection(MRKPrompt *s, AXUIElementRef app, CFStringRef parent_text, CFStringRef panel_text,
    AXUIElementRef *parent, AXUIElementRef *sheet) {
    s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
    s->result.site = MRK_OPEN_WINDOWS;
    CFArrayRef windows = mrk_ax_array(s, app, kAXWindowsAttribute, 4, NO); if (!windows) return NO;
    AXUIElementRef found_parent = NULL, found_sheet = NULL;
    s->result.site = MRK_OPEN_PARENT_ID;
    for (CFIndex i = 0; i < CFArrayGetCount(windows); ++i) {
        AXUIElementRef candidate = (AXUIElementRef)CFArrayGetValueAtIndex(windows, i);
        s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
        if (!mrk_ax_type(s, candidate, s->elementType)) return NO;
        CFTypeRef name = mrk_ax_copy(s, candidate, kAXIdentifierAttribute, NO);
        if (!name || !mrk_ax_type(s, name, CFStringGetTypeID())) return NO;
        if (CFStringGetLength(name) >= 64) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
        if (CFEqual(name, parent_text)) {
            if (found_parent) return mrk_ax_fail(s, MRK_OPEN_AMBIGUOUS);
            found_parent = candidate;
        }
    }
    if (!found_parent) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    if (*parent && !CFEqual(*parent, found_parent)) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    s->result.checks |= 1u; s->result.site = MRK_OPEN_SHEET;
    CFArrayRef children = mrk_ax_array(s, found_parent, kAXChildrenAttribute, 16, NO); if (!children) return NO;
    for (CFIndex i = 0; i < CFArrayGetCount(children); ++i) {
        AXUIElementRef candidate = (AXUIElementRef)CFArrayGetValueAtIndex(children, i);
        s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
        if (!mrk_ax_type(s, candidate, s->elementType)) return NO;
        CFTypeRef role = mrk_ax_copy(s, candidate, kAXRoleAttribute, NO);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        s->result.last_role = mrk_ax_role(role);
        if (CFEqual(role, kAXSheetRole)) {
            if (found_sheet) return mrk_ax_fail(s, MRK_OPEN_AMBIGUOUS);
            found_sheet = candidate;
        }
    }
    if (!found_sheet) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    if (*sheet && !CFEqual(*sheet, found_sheet)) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    s->result.site = MRK_OPEN_TOPOLOGY;
    s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
    if (!mrk_ax_equal_attribute(s, found_sheet, kAXIdentifierAttribute, panel_text)
        || !mrk_ax_equal_attribute(s, found_sheet, kAXParentAttribute, found_parent)) return NO;
    s->result.checks |= 2u; *parent = found_parent; *sheet = found_sheet; return YES;
}
static BOOL mrk_ax_control_roster(MRKPrompt *s, AXUIElementRef sheet, CFStringRef prompt, BOOL rechecking, MRKControlPass *pass) {
    // Only Sheet -> (Group|SplitGroup)* -> Button is eligible. Other roles are
    // outside this projection, never observed-empty or expandable subtrees.
    pass->nodes[0] = sheet;
    unsigned queued = 1, matches = 0;
    uint32_t *examined = rechecking ? &s->result.recheck_nodes_examined : &s->result.initial_nodes_examined;
    for (unsigned at = 0; at < queued; ++at) {
        AXUIElementRef node = pass->nodes[at];
        s->result.last_depth = pass->depths[at]; s->result.last_role = MRK_ROLE_NOT_READ;
        if (at) (*examined)++; // Once per begun nonroot node of this pass only.
        if (!mrk_ax_type(s, node, s->elementType)) return NO;
        for (unsigned previous = 0; previous < queued; ++previous)
            if (previous != at && pass->nodes[previous] && CFEqual(node, pass->nodes[previous]))
                return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        if (at && !mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]])) return NO;
        CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        pass->roles[at] = s->result.last_role = mrk_ax_role(role);
        if (!at && pass->roles[at] != MRK_ROLE_SHEET) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
        if (CFEqual(role, kAXButtonRole)) {
            CFTypeRef title = mrk_ax_copy(s, node, kAXTitleAttribute, YES);
            if (s->result.error) return NO;
            if (title) {
                if (!mrk_ax_type(s, title, CFStringGetTypeID())) return NO;
                if (CFStringGetLength(title) > 512) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_TITLE_LIMIT);
                if (CFEqual(title, prompt)) { matches++; pass->candidate = at; }
            }
        }
        if (at && !CFEqual(role, kAXGroupRole) && !CFEqual(role, kAXSplitGroupRole)) continue;
        CFArrayRef children = mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0);
        if (!children) { if (s->result.error) return NO; continue; } // Only actual Count0 may be empty.
        CFIndex count = CFArrayGetCount(children);
        if (pass->depths[at] == MRK_CONTROL_DEPTH) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_DEPTH_LIMIT);
        if ((unsigned)count > MRK_CONTROL_NODES - queued) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_NODE_LIMIT);
        for (CFIndex child = 0; child < count; ++child) {
            pass->nodes[queued] = (AXUIElementRef)CFArrayGetValueAtIndex(children, child);
            pass->parents[queued] = at; pass->depths[queued] = pass->depths[at] + 1; queued++;
        }
    }
    s->result.checks |= 4u; // Entire eligible control projection, never a first-match exit.
    if (matches != 1) return mrk_ax_fail(s, matches ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED);
    for (unsigned node = pass->candidate; ; node = pass->parents[node]) {
        if (pass->chain_count == MRK_CONTROL_DEPTH + 1) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        pass->chain[pass->chain_count++] = node;
        if (!node) break;
    }
    s->result.checks |= 8u; return YES;
}
static BOOL mrk_ax_control_path(MRKPrompt *s, AXUIElementRef parent, const MRKControlPass *original) {
    for (unsigned left = original->chain_count; left; --left) {
        unsigned at = original->chain[left - 1]; AXUIElementRef node = original->nodes[at];
        s->result.last_depth = original->depths[at]; s->result.last_role = MRK_ROLE_NOT_READ;
        if (!mrk_ax_type(s, node, s->elementType)) return NO;
        if (!mrk_ax_equal_attribute(s, node, kAXParentAttribute, at ? original->nodes[original->parents[at]] : parent)) return NO;
        CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        s->result.last_role = mrk_ax_role(role);
        if (s->result.last_role != original->roles[at]
            || (!at ? s->result.last_role != MRK_ROLE_SHEET : at == original->candidate ? s->result.last_role != MRK_ROLE_BUTTON
                : s->result.last_role != MRK_ROLE_GROUP && s->result.last_role != MRK_ROLE_SPLIT_GROUP))
            return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    }
    return YES;
}
static BOOL mrk_ax_button(MRKPrompt *s, AXUIElementRef parent, const MRKControlPass *original, CFStringRef prompt) {
    AXUIElementRef button = s->button;
    if (!CFEqual(button, original->nodes[original->candidate])) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    if (!mrk_ax_control_path(s, parent, original) || !mrk_ax_equal_attribute(s, button, kAXTitleAttribute, prompt)) return NO;
    CFTypeRef enabled = mrk_ax_copy(s, button, kAXEnabledAttribute, NO);
    if (!enabled || !mrk_ax_type(s, enabled, CFBooleanGetTypeID())) return NO;
    if (!CFBooleanGetValue(enabled)) return mrk_ax_fail(s, MRK_OPEN_INELIGIBLE);
    s->result.checks |= 16u;
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, button)) return NO;
    s->result.calls++;
    AXError status = AXUIElementCopyActionNames(button, &slot->array);
    // This public API has no range-limited variant. Its <=16 bound is expressly
    // post-return, not a preallocation promise; its out-slot is already owned.
    BOOL copied = mrk_ax_status(s, status), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!copied || !admitted
        || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NO;
    CFIndex count = CFArrayGetCount(slot->array); unsigned presses = 0;
    if (count < 0 || count > 16) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
    for (CFIndex i = 0; i < count; ++i) {
        CFTypeRef action = CFArrayGetValueAtIndex(slot->array, i);
        if (!mrk_ax_type(s, action, CFStringGetTypeID())) return NO;
        if (CFEqual(action, kAXPressAction)) presses++;
    }
    if (presses != 1) return mrk_ax_fail(s, presses ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED);
    s->result.checks |= 32u;
    return YES;
}
static BOOL mrk_ax_original(MRKPrompt *s, int stage) {
    s->result.site = stage == 1 ? MRK_OPEN_INITIAL_PROOF : MRK_OPEN_FINAL_PROOF;
    int code = s->recheck(s->context, stage);
    if (code == MRK_OPEN_CUSTODY) s->cleanupKnown = NO;
    return code ? mrk_ax_fail(s, (uint32_t)code) : YES;
}
static BOOL mrk_ax_row_target(MRKPrompt *s, AXUIElementRef row, const char *target, BOOL *matches) {
    *matches = NO;
    CFTypeRef value = mrk_ax_copy(s, row, kAXURLAttribute, NO);
    if (!value || !mrk_ax_type(s, value, CFURLGetTypeID())) return NO;
    MRKPromptOwned *scheme = mrk_ax_slot(s); if (!scheme) return NO;
    scheme->value = CFURLCopyScheme((CFURLRef)value);
    if (!mrk_ax_type(s, scheme->value, CFStringGetTypeID())) return NO;
    uint8_t path[4097] = {0};
    if (!CFEqual(scheme->value, CFSTR("file")) || CFURLGetBaseURL((CFURLRef)value)
        || !CFURLGetFileSystemRepresentation((CFURLRef)value, false, path, sizeof(path))
        || !mrk_target_path((const char *)path)) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
    *matches = strcmp((const char *)path, target) == 0; return YES;
}
static BOOL mrk_ax_selection_roster(MRKPrompt *s, AXUIElementRef sheet, const char *target, MRKControlPass *pass) {
    // One fixed initial-view projection, with the SAME17-slot/8-depth bounds
    // as each control pass. Browser/other layouts are not expanded or changed.
    pass->nodes[0] = sheet; unsigned queued = 1, matches = 0;
    for (unsigned at = 0; at < queued; ++at) {
        AXUIElementRef node = pass->nodes[at];
        if (at) s->result.selection_nodes_examined++;
        if (!mrk_ax_type(s, node, s->elementType)) return NO;
        for (unsigned other = 0; other < queued; ++other)
            if (other != at && pass->nodes[other] && CFEqual(node, pass->nodes[other])) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        if (at && !mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]])) return NO;
        CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        unsigned kind = pass->roles[at] = CFEqual(role, kAXRowRole) ? MRK_ROLE_ROW : mrk_ax_role(role);
        if (!at && kind != MRK_ROLE_SHEET) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
        BOOL row_parent = at && (pass->roles[pass->parents[at]] == MRK_ROLE_TABLE || pass->roles[pass->parents[at]] == MRK_ROLE_OUTLINE);
        if (row_parent != (kind == MRK_ROLE_ROW)) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        if (kind == MRK_ROLE_ROW) {
            BOOL matched = NO;
            if (!mrk_ax_row_target(s, node, target, &matched)) return NO;
            if (matched) { matches++; pass->candidate = at; }
            continue;
        }
        BOOL rows = kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE;
        if (at && !rows && kind != MRK_ROLE_GROUP && kind != MRK_ROLE_SPLIT_GROUP && kind != MRK_ROLE_SCROLL_AREA) continue;
        CFArrayRef children = mrk_ax_array(s, node, rows ? kAXRowsAttribute : kAXChildrenAttribute, 16, at != 0);
        if (!children) { if (s->result.error) return NO; continue; }
        CFIndex count = CFArrayGetCount(children);
        if (count && pass->depths[at] == MRK_CONTROL_DEPTH) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
        if ((unsigned)count > MRK_CONTROL_NODES - queued) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
        for (CFIndex i = 0; i < count; ++i) {
            pass->nodes[queued] = (AXUIElementRef)CFArrayGetValueAtIndex(children, i);
            pass->parents[queued] = at; pass->depths[queued] = pass->depths[at] + 1; queued++;
        }
    }
    if (matches != 1) return mrk_ax_fail(s, matches ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED);
    for (unsigned at = pass->candidate;; at = pass->parents[at]) {
        if (pass->chain_count > MRK_CONTROL_DEPTH) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
        pass->chain[pass->chain_count++] = at;
        if (!at) break;
    }
    s->result.selection_checks |= 1u; return YES;
}
static BOOL mrk_ax_select_row(MRKPrompt *s, AXUIElementRef parent, const MRKControlPass *pass, const char *target) {
    if (s->result.selection_flags || s->result.selection_checks != 1u) return mrk_ax_fail(s, MRK_OPEN_INELIGIBLE);
    // Only this retained chain and URL may authorize the one selection write.
    for (unsigned i = 0; i < pass->chain_count; ++i) {
        unsigned at = pass->chain[i]; AXUIElementRef node = pass->nodes[at];
        if (!mrk_ax_equal_attribute(s, node, kAXParentAttribute, at ? pass->nodes[pass->parents[at]] : parent)) return NO;
        CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        unsigned kind = CFEqual(role, kAXRowRole) ? MRK_ROLE_ROW : mrk_ax_role(role);
        if (kind != pass->roles[at]) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    }
    AXUIElementRef row = pass->nodes[pass->candidate], container = pass->nodes[pass->parents[pass->candidate]];
    BOOL matched = NO;
    if (!mrk_ax_row_target(s, row, target, &matched)) return NO;
    if (!matched) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    s->result.selection_checks |= 2u;
    if (!mrk_ax_before(s, container)) return NO;
    Boolean settable = false; s->result.calls++;
    AXError status = AXUIElementIsAttributeSettable(container, kAXSelectedRowsAttribute, &settable);
    BOOL returned = mrk_ax_status(s, status), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!returned || !admitted) return NO;
    if (!settable) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    s->result.selection_checks |= 4u;
    MRKPromptOwned *selected = mrk_ax_slot(s); if (!selected) return NO;
    const void *rows[] = { row };
    selected->array = CFArrayCreate(NULL, rows, 1, &kCFTypeArrayCallBacks);
    if (!mrk_ax_type(s, selected->value, CFArrayGetTypeID()) || !mrk_ax_before(s, container)) return NO;
    // Attempt/return/status are not a selected-URL effect or an Open result.
    // Every error spends this mutation permanently, including CannotComplete.
    s->result.site = MRK_OPEN_SELECTION_WRITE; s->result.calls++; s->result.selection_flags |= 1u;
    status = AXUIElementSetAttributeValue(container, kAXSelectedRowsAttribute, selected->array);
    s->result.selection_flags |= 2u;
    if (status == kAXErrorSuccess) s->result.selection_flags |= 4u;
    returned = mrk_ax_status(s, status); admitted = mrk_ax_admit(s, 0, 0, NULL);
    return returned && admitted;
}
static void mrk_ax_open(MRKPrompt *s, const uint8_t *parent_tag, const uint8_t *panel_tag, const uint8_t *prompt, const char *target) {
    if (!mrk_ax_admit(s, 0, 0, NULL) || !mrk_ax_original(s, 1)) return;
    s->result.calls++; s->elementType = AXUIElementGetTypeID(); // Count and reuse this local AX API too.
    MRKPromptOwned *parent_text = mrk_ax_slot(s), *panel_text = mrk_ax_slot(s), *prompt_text = mrk_ax_slot(s), *application = mrk_ax_slot(s);
    if (!parent_text || !panel_text || !prompt_text || !application) return;
    s->result.site = MRK_OPEN_APPLICATION;
    parent_text->value = CFStringCreateWithCString(NULL, (const char *)parent_tag, kCFStringEncodingASCII);
    panel_text->value = CFStringCreateWithBytes(NULL, panel_tag, (CFIndex)strnlen((const char *)panel_tag, 64), kCFStringEncodingUTF8, false);
    prompt_text->value = CFStringCreateWithCString(NULL, (const char *)prompt, kCFStringEncodingASCII);
    s->result.calls++; application->value = AXUIElementCreateApplication(getpid()); // THIS PID only.
    if (!mrk_ax_type(s, parent_text->value, CFStringGetTypeID()) || !mrk_ax_type(s, panel_text->value, CFStringGetTypeID())
        || !mrk_ax_type(s, prompt_text->value, CFStringGetTypeID()) || !mrk_ax_type(s, application->value, s->elementType)) return;
    AXUIElementRef parent = NULL, sheet = NULL;
    if (!mrk_ax_projection(s, (AXUIElementRef)application->value, parent_text->value, panel_text->value, &parent, &sheet)) return;
    s->result.site = MRK_OPEN_SELECTION;
    MRKControlPass selection = {0};
    if (!mrk_ax_selection_roster(s, sheet, target, &selection) || !mrk_ax_select_row(s, parent, &selection, target)) return;
    s->result.site = MRK_OPEN_CONTROL_PROJECTION;
    MRKControlPass initial = {0}, rechecked = {0}; // Separate immutable first-chain backing; no scratch reuse.
    if (!mrk_ax_control_roster(s, sheet, prompt_text->value, NO, &initial)) return;
    s->button = initial.nodes[initial.candidate]; // Assigned once; original CFArray ledger owns all ancestors too.
    s->result.site = MRK_OPEN_BUTTON;
    if (!mrk_ax_button(s, parent, &initial, prompt_text->value)) return;
    if (!mrk_ax_projection(s, (AXUIElementRef)application->value, parent_text->value, panel_text->value, &parent, &sheet)) return;
    s->result.site = MRK_OPEN_CONTROL_RECHECK;
    if (!mrk_ax_control_roster(s, sheet, prompt_text->value, YES, &rechecked)) return;
    if (initial.chain_count != rechecked.chain_count) { mrk_ax_fail(s, MRK_OPEN_CHANGED); return; }
    for (unsigned i = 0; i < initial.chain_count; ++i)
        if (!CFEqual(initial.nodes[initial.chain[i]], rechecked.nodes[rechecked.chain[i]])
            || initial.roles[initial.chain[i]] != rechecked.roles[rechecked.chain[i]]) {
            mrk_ax_fail(s, MRK_OPEN_CHANGED); return;
        }
    if (!mrk_ax_button(s, parent, &initial, prompt_text->value)) return;
    s->result.checks |= 64u; // Complete second projection, same original chain and revalidated eligibility.
    if (!mrk_ax_original(s, 2)) return;
    s->result.site = MRK_OPEN_ADMISSION;
    AXUIElementRef button = s->button;
    if (!mrk_ax_before(s, button)) return;
    // Last permit is atomic/clock-only. No query, wait, lock or replacement
    // follows it. Every error (even CannotComplete) permanently spends Press.
    s->result.site = MRK_OPEN_PRESS; s->result.calls++; s->result.flags |= MRK_OPEN_ATTEMPTED;
    AXError status = AXUIElementPerformAction(button, kAXPressAction);
    s->result.flags |= MRK_OPEN_RETURNED;
    if (status == kAXErrorSuccess) s->result.flags |= MRK_OPEN_TRIGGERED;
    mrk_ax_status(s, status); mrk_ax_admit(s, 0, 1, NULL);
}
void mrk_observation_prompt_press(const uint8_t *parent, const uint8_t *panel, const uint8_t *prompt, size_t capacity,
    const uint8_t *target, size_t target_capacity,
    MRKOpenAdmission admission, MRKOpenRecheckCall recheck, void *context, MRKOpenResult *out) {
    if (!out) return;
    MRKOpenResult refused = {0}; refused.site = MRK_OPEN_ENTRY;
    if (pthread_main_np()) { refused.error = MRK_OPEN_THREAD; *out = refused; return; }
    if (!parent || !panel || !prompt || capacity != 64 || !target || target_capacity != 4097 || !admission || !recheck || !context
        || !mrk_identity_tag((const char *)parent, "mrk-parent-") || !mrk_identity_utf8(panel)
        || !memcmp(parent, panel, capacity) || !mrk_prompt_valid(parent, prompt) || !mrk_target_path((const char *)target)) {
        refused.error = MRK_OPEN_INPUT; *out = refused; return;
    }
    size_t target_length = strnlen((const char *)target, target_capacity);
    if (target_length < 2) { refused.error = MRK_OPEN_INPUT; *out = refused; return; }
    for (size_t i = target_length; i < target_capacity; ++i)
        if (target[i]) { refused.error = MRK_OPEN_INPUT; *out = refused; return; }
    if (atomic_flag_test_and_set(&mrk_prompt_claimed)) { refused.error = MRK_OPEN_CUSTODY; *out = refused; return; }
    MRKPrompt *s = &mrk_prompt_original; s->admit = admission; s->recheck = recheck; s->context = context;
    s->cleanupKnown = YES; s->result.site = MRK_OPEN_ENTRY;
    @try { mrk_ax_open(s, parent, panel, prompt, (const char *)target); }
    @catch (NSException *e) { (void)e; mrk_ax_fail(s, MRK_OPEN_EXCEPTION); s->cleanupKnown = NO; }
    s->result.owned = s->count; // Reserved original slots, NOT a fabricated CFRelease count.
    if (s->cleanupKnown) {
        for (unsigned left = s->count; left; --left) {
            // Deadline8 still permits same-original late cleanup before45s.
            // Custody9 (including original45s expiry) retains every remaining
            // slot instead of beginning another release after its owner ends.
            mrk_ax_admit(s, 0, (s->result.flags & MRK_OPEN_ATTEMPTED) != 0, NULL);
            if (!s->cleanupKnown) break;
            MRKPromptOwned *slot = &s->owned[left - 1];
            @try { if (slot->value) CFRelease(slot->value); slot->value = NULL; s->result.released++; }
            @catch (NSException *e) {
                (void)e; s->cleanupKnown = NO;
                if (!s->result.error) { s->result.site = MRK_OPEN_CLEANUP; mrk_ax_fail(s, MRK_OPEN_CLEANUP_UNKNOWN); }
                break; // This release is never retried; remaining ledger stays retained.
            }
        }
    }
    mrk_ax_admit(s, 0, (s->result.flags & MRK_OPEN_ATTEMPTED) != 0, NULL);
    if (s->cleanupKnown && s->result.released == s->result.owned) s->result.flags |= MRK_OPEN_KNOWN;
    s->admit = NULL; s->recheck = NULL; s->context = NULL; // No dangling worker-stack callback in the retained CF ledger.
    *out = s->result; // All ordinary CF releases returned, or exact originals stay registered above.
}
#endif
