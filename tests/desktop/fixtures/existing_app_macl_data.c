// Inert original-body DATA: every filesystem call below is an in-memory stub.
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

static int kind, extra, wrong_name, changed_roster, changed_stat;
static int list_fail, read_fail, short_read, lists, reads, stats;
static size_t value_size;
static int mock_fstat(int fd, struct stat *out) {
    assert(fd == 31); ++stats; memset(out, 0, sizeof(*out));
    out->st_mode = (kind ? S_IFREG : S_IFDIR) | 0555;
    out->st_dev = 2; out->st_ino = 3; out->st_nlink = 1;
    out->st_ctimespec.tv_nsec = changed_stat && stats > 1 ? 1 : 0;
    return 0;
}
static ssize_t mock_flistxattr(int fd, char *out, size_t cap, int flags) {
    assert(fd == 31 && flags == 0); ++lists;
    if (lists == list_fail) { errno = EIO; return -1; }
    if (value_size == (size_t)-1) return 0;
    if (extra) return 40;
    const char *name = wrong_name || (changed_roster && lists > 2) ? "com.apple.test" : "com.apple.macl";
    size_t n = strlen(name) + 1;
    if (out) { assert(cap >= n); memcpy(out, name, n); }
    return (ssize_t)n;
}
static ssize_t mock_fgetxattr(int fd, const char *name, void *out, size_t cap, uint32_t position, int flags) {
    assert(fd == 31 && !strcmp(name, "com.apple.macl") && position == 0 && flags == 0); ++reads;
    if (reads == read_fail) { errno = EIO; return -1; }
    if (!out) return (ssize_t)value_size;
    assert(cap == value_size && cap <= 1024); memset(out, 7, cap);
    return (ssize_t)(short_read ? value_size - 1 : value_size);
}
#define fstat mock_fstat
#define flistxattr mock_flistxattr
#define fgetxattr mock_fgetxattr
/* MRK_EXISTING_APP_MACL_ORIGINAL */
#undef fstat
#undef flistxattr
#undef fgetxattr

static unsigned cases;
static void reset(size_t size) {
    kind=extra=wrong_name=changed_roster=changed_stat=0;
    list_fail=read_fail=short_read=lists=reads=stats=0; value_size=size;
}
static void check(int accepted) {
    uint8_t bytes[1024] = {0}; size_t used = 9999;
    int result=mrk_existing_app_macl(31,bytes,sizeof(bytes),&used); ++cases;
    assert((result == 0) == accepted);
    if (accepted) {
        assert(used == (value_size == (size_t)-1 ? 0 : value_size));
        for (size_t i=0;i<used;++i) assert(bytes[i] == 7);
    } else assert(used == 0);
}
int main(void) {
    reset((size_t)-1); check(1); assert(mrk_no_xattrs(31) == 0);
    for (size_t size=1;size<=1024;size*=2) { reset(size); check(1); assert(mrk_no_xattrs(31) == EPERM); }
    reset(72); check(1); assert(mrk_no_xattrs(31) == EPERM);
    reset(0); check(0); reset(1025); check(0);
    reset(72); kind=1; check(0);
    reset(72); extra=1; check(0);
    reset(72); wrong_name=1; check(0);
    reset(72); changed_roster=1; check(0);
    reset(72); changed_stat=1; check(0);
    reset((size_t)-1); changed_stat=1; check(0);
    for (int call=1;call<=3;++call) { reset(72); list_fail=call; check(0); }
    for (int call=1;call<=2;++call) { reset((size_t)-1); list_fail=call; check(0); }
    for (int call=1;call<=2;++call) { reset(72); read_fail=call; check(0); }
    reset(72); short_read=1; check(0);
    uint8_t bytes[1024]; size_t used=0;
    assert(mrk_existing_app_macl(31,bytes,1023,&used) == EINVAL);
    assert(mrk_existing_app_macl(31,NULL,1024,&used) == EINVAL);
    assert(mrk_existing_app_macl(31,bytes,1024,NULL) == EINVAL);
    printf("MRK_EXISTING_APP_MACL_DATA=%u\n",cases);
}
