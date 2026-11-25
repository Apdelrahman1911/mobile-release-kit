// Fixed nonroot APFS ACL probe. Never linked into the installed app/Installer.
// Only the three exclusive names below may be created, changed or removed.
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

extern int mrk_user(uint32_t *uid);
extern int mrk_acl_empty(int fd, int *phase, int *call_result, int *native_errno,
                         int *free_result, int *free_errno);
static struct timespec end;
static int timely(void) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0
        && (now.tv_sec < end.tv_sec || (now.tv_sec == end.tv_sec && now.tv_nsec < end.tv_nsec));
}
static int setup_call(const char *phase, int returned) {
    int observed_errno = errno;
    if (returned != 0) {
        (void)printf("MRK_ACL_PROBE_SETUP_FAILURE=phase=%s;call=%d;errno=%d\n", phase, returned, observed_errno);
        return 0;
    }
    return 1;
}
static void setup_null(const char *phase) {
    int observed_errno = errno;
    (void)printf("MRK_ACL_PROBE_SETUP_FAILURE=phase=%s;pointer=null;errno=%d\n", phase, observed_errno);
}
// Comma sequencing clears errno BEFORE the call; setup_call captures it before
// any output. Labels are only the fixed literals below, never paths or ACL text.
#define CALL(label, expression) (errno = 0, setup_call((label), (expression)))
static int same(struct stat a, struct stat b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink;
}
struct entry { const char *name; int directory, made, fd, known; struct stat id; };
static int create_original(int parent, struct entry *item) {
    if (!timely()) return 0;
    if (item->directory) {
        if (mkdirat(parent, item->name, 0700)) return 0;
        item->made = 1;
        item->fd = openat(parent, item->name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    } else {
        item->fd = openat(parent, item->name, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK, 0600);
        if (item->fd >= 0) item->made = 1;
    }
    if (item->fd < 0) return 0;
    struct stat named;
    if (fstat(item->fd, &item->id) || fstatat(parent, item->name, &named, AT_SYMLINK_NOFOLLOW)
        || !same(item->id, named) || item->id.st_uid != getuid()
        || (item->id.st_mode & 07777) != (item->directory ? 0700 : 0600)
        || (item->directory ? !S_ISDIR(item->id.st_mode) : !S_ISREG(item->id.st_mode) || item->id.st_nlink != 1)) return 0;
    item->known = 1; return timely();
}
// Independent public-API precondition observation. No errno-as-absence rule.
static int presence(int fd, int *present) {
    errno = 0; filesec_t fsec = filesec_init();
    if (!fsec) { setup_null("filesec-init"); return 0; }
    struct stat s = {0}; uid_t uid = 0; gid_t gid = 0; mode_t mode = 0;
    int ok = CALL("fstatx", fstatx_np(fd, &s, fsec))
        && CALL("filesec-owner", filesec_get_property(fsec, FILESEC_OWNER, &uid)) && uid == s.st_uid
        && CALL("filesec-group", filesec_get_property(fsec, FILESEC_GROUP, &gid)) && gid == s.st_gid
        && CALL("filesec-mode", filesec_get_property(fsec, FILESEC_MODE, &mode)) && mode == s.st_mode
        && CALL("filesec-presence", filesec_query_property(fsec, FILESEC_ACL, present));
    filesec_free(fsec); return ok && timely();
}
static int observe(const char *name, int fd, int expected) {
    int phase = 0, returned = 0, observed_errno = 0, freed = 0, free_errno = 0;
    int code = mrk_acl_empty(fd, &phase, &returned, &observed_errno, &freed, &free_errno);
    int ok = timely() && freed == 0 && free_errno == 0;
    if (expected == 0) ok = ok && code == 0 && phase == 0 && returned == 0 && observed_errno == 0;
    // First-party closed ABI phase11=actual ACE; phase2=fstatx snapshot failure.
    else if (expected == EPERM) ok = ok && code == EPERM && phase == 11 && returned == 0 && observed_errno == 0;
    else ok = ok && expected == EBADF && code == EBADF && phase == 2 && returned != 0 && observed_errno == EBADF;
    if (printf("MRK_ACL_PROBE_CASE=%s;ok=%d;phase=%d;result=%d;call=%d;errno=%d;freeCall=%d;freeErrno=%d\n",
               name, ok, phase, code, returned, observed_errno, freed, free_errno) < 0) ok = 0;
    return ok;
}
static int set_test_acl(int fd, int ace) {
    errno = 0; acl_t acl = acl_init(ace ? 1 : 0);
    if (!acl) { setup_null("acl-init"); return 0; }
    int ok = 1;
    if (ace) {
        // Fixed synthetic qualifier; no account lookup or mutation.
        const uuid_t who = {0x28,0x6a,0x19,0x82,0xa3,0x14,0x47,0x53,0x91,0x8d,0x65,0xf2,0xcc,0x09,0xba,0x31};
        acl_entry_t entry; acl_permset_t perms;
        ok = CALL("acl-create-entry", acl_create_entry(&acl, &entry)) && CALL("acl-set-tag", acl_set_tag_type(entry, ACL_EXTENDED_ALLOW))
            && CALL("acl-set-qualifier", acl_set_qualifier(entry, who)) && CALL("acl-get-perms", acl_get_permset(entry, &perms))
            && CALL("acl-clear-perms", acl_clear_perms(perms)) && CALL("acl-add-perm", acl_add_perm(perms, ACL_READ_ATTRIBUTES))
            && CALL("acl-set-perms", acl_set_permset(entry, perms));
    } else {
        acl_entry_t entry; errno = 0;
        ok = acl_valid(acl) == 0 && acl_get_entry(acl, ACL_FIRST_ENTRY, &entry) == -1 && errno == EINVAL;
    }
    if (ok) ok = CALL("acl-valid", acl_valid(acl)) && CALL("acl-set-fd", acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED));
    int released = CALL("acl-free", acl_free(acl));
    return ok && released && timely();
}
static int retire_original(int parent, struct entry *item) {
    int ok = 1;
    if (item->made) {
        struct stat named, actual;
        // Keep unknown entries. The one original stays open across unlink.
        if (!item->known || item->fd < 0 || fstat(item->fd, &actual)
            || fstatat(parent, item->name, &named, AT_SYMLINK_NOFOLLOW)
            || !same(item->id, actual) || !same(actual, named)
            || unlinkat(parent, item->name, item->directory ? AT_REMOVEDIR : 0)) ok = 0;
    }
    if (item->fd >= 0) {
        int original = item->fd; item->fd = -1;
        if (close(original)) ok = 0; // One attempt only; no FD-number retry.
    }
    return ok;
}
int main(int argc, char **argv) {
    uint32_t uid = 0; int root = -1, ok = 0, completed = 0, cleaned = 1;
    struct entry items[3] = {{.name="fresh-file",.fd=-1}, {.name="fresh-directory",.directory=1,.fd=-1}, {.name="ace-file",.fd=-1}};
    struct stat before = {0}, actual = {0}; struct statfs fs = {0};
    if (argc != 2 || mrk_user(&uid) || clock_gettime(CLOCK_MONOTONIC, &end)) goto finish;
    end.tv_sec += 30; // This probe's original endpoint; never reset after a call.
    if (lstat(argv[1], &before) || !S_ISDIR(before.st_mode) || before.st_uid != uid
        || (before.st_mode & 07777) != 0700) goto finish;
    root = open(argv[1], O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (root < 0 || fstat(root, &actual) || !same(before, actual) || fstatfs(root, &fs)
        || strcmp(fs.f_fstypename, "apfs") || !(fs.f_flags & MNT_LOCAL)
        || (fs.f_flags & (MNT_UNION|MNT_AUTOMOUNTED|MNT_IGNORE_OWNERSHIP))) goto finish;
    int found = 0;
    if (!presence(root, &found) || !observe("parent-no-ace", root, 0)) goto finish;
    ++completed;
    if (!create_original(root, &items[0]) || !create_original(root, &items[1])) goto finish;
    if (!presence(items[0].fd, &found) || found || !observe("fresh-file-no-acl", items[0].fd, 0)) goto finish;
    ++completed;
    if (!presence(items[1].fd, &found) || found || !observe("fresh-directory-no-acl", items[1].fd, 0)) goto finish;
    ++completed;
    if (!set_test_acl(items[0].fd, 0) || !presence(items[0].fd, &found)
        || !observe("explicit-empty-no-ace", items[0].fd, 0)) goto finish;
    ++completed;
    if (!create_original(root, &items[2]) || !set_test_acl(items[2].fd, 1)
        || !presence(items[2].fd, &found) || !found || !observe("real-ace-refused", items[2].fd, EPERM)) goto finish;
    ++completed;
    // Raw native metadata call only; not a fabricated Rust borrow/close/race.
    if (!observe("invalid-fd-refused", -1, EBADF)) goto finish;
    ++completed; ok = 1;
finish:
    for (int n = 2; n >= 0; --n) if (!retire_original(root, &items[n])) cleaned = 0;
    if (root >= 0) {
        // Children alter directory link count legitimately; parent replacement
        // or permission changes do not. No parent ACL or modes were normalized.
        struct stat named = {0}, final = {0};
        if (fstat(root, &final) || lstat(argv[1], &named) || !same(final, named)
            || final.st_dev != before.st_dev || final.st_ino != before.st_ino
            || final.st_uid != before.st_uid || final.st_gid != before.st_gid || final.st_mode != before.st_mode) cleaned = 0;
        int original = root; root = -1; if (close(original)) cleaned = 0;
    }
    ok = ok && completed == 6 && cleaned && timely();
    if (printf("MRK_ACL_PROBE_FINAL=cases=%d;cleanup=%d;passed=%d\n", completed, cleaned, ok) < 0
        || fflush(stdout) || ferror(stdout)) return 1;
    // Output must also return before this SAME original endpoint.
    return ok && timely() ? 0 : 1;
}
