// CLOCK_UPTIME_RAW is the actual Rust1.98.1 Apple Instant clock. No wall clock,
// guessed tick ratio, deadline restart, or observer-now replacement is used.
#include "vault_helper_control.h"
#include <time.h>
#include <limits.h>
int mrk_vault_uptime(uint64_t *out) {
    struct timespec now;
    if (!out || clock_gettime(CLOCK_UPTIME_RAW, &now) || now.tv_sec < 0
        || now.tv_nsec < 0 || now.tv_nsec >= 1000000000
        || (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / 1000000000u) return 0;
    *out = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
    return 1;
}
#if defined(MRK_WRAPPING_VAULT_HELPER)
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
static struct {
    uint32_t begun, valid, clock_known, stopped, effect, input_retiring, input_closed, input_broken, notice_attempted;
    pid_t pid, parent;
    uint64_t origin, last, work, maximum, first, cleanup;
    uint8_t nonce[16], stop[40];
    size_t used;
} control;
static uint64_t get64(const uint8_t *p) {
    uint64_t n=0; for (unsigned i=0;i<8;i++) n |= (uint64_t)p[i] << (8*i); return n;
}
static void put64(uint8_t *p,uint64_t n) { for (unsigned i=0;i<8;i++) p[i]=(uint8_t)(n>>(8*i)); }
static void put32(uint8_t *p,uint32_t n) { for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(n>>(8*i)); }
static int original(void) {
    return pthread_main_np()==1 && control.begun && control.pid==getpid();
}
static int now_checked(uint64_t *now) {
    if (!original() || !control.clock_known || !mrk_vault_uptime(now) || *now<control.last) {
        if (original()) { control.valid=0; control.clock_known=0; } return 0;
    }
    control.last=*now; return 1;
}
static void first_at(uint64_t at) {
    if (!control.first || at<control.first) control.first=at;
    uint64_t end = control.first > UINT64_MAX-2000000000u ? 0 : control.first+2000000000u;
    if (!end) { control.valid=0; control.clock_known=0; return; }
    if (end<control.cleanup) control.cleanup=end;
}
// A <=PIPE_BUF nonblocking write is all-or-EAGAIN. It is only an early notice;
// native cleanup uses the local first timestamp even when its pipe is full.
static void notice(void) {
    if (!control.first || control.notice_attempted) return;
    control.notice_attempted=1;
    uint8_t out[32]={0}; memcpy(out,"MRKVKN01",8);
    put64(out+8,control.first); put64(out+16,control.cleanup);
    put32(out+24,control.effect); put32(out+28,control.valid);
    ssize_t n=write(STDOUT_FILENO,out,sizeof(out));
    if (n==(ssize_t)sizeof(out) || (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK))) return;
    // Do not retry a partial/ambiguous original write or splice a new frame.
    // Diagnostic pipe failure must not disable original-only policy restore.
    control.valid=0;
}
void mrk_vault_control_failure(void) {
    uint64_t now;
    if (!now_checked(&now)) return;
    first_at(now); notice();
}
void mrk_vault_control_failure_at(uint64_t at) {
    uint64_t now;
    if (!now_checked(&now)) return;
    // Rust supplied a conservative F from its ONE retained same-clock bracket.
    // Invalid mapping is absorbing Unknown, not replacement with this receipt time.
    if (!at || at<control.origin || at>now) { control.valid=0; control.clock_known=0; return; }
    first_at(at); notice();
}
void mrk_vault_control_effect(uint32_t effect) {
    if (!original()) return;
    if (!((control.effect==0 && effect==3) || (control.effect==3 && (effect==1 || effect==2)))) {
        control.valid=0; return;
    }
    control.effect=effect;
}
int mrk_vault_control_begin(const uint8_t nonce[16],uint64_t work,uint64_t cleanup) {
    uint64_t now;
    if (pthread_main_np()!=1 || control.begun || !nonce || !mrk_vault_uptime(&now)
        || !now || work<=now || work-now>10000000000u || cleanup<work
        || cleanup-work>2000000000u || getppid()<=1) return 0;
    control.begun=1; control.valid=1; control.clock_known=1; control.pid=getpid(); control.parent=getppid();
    control.origin=now; control.last=now; control.work=work; control.maximum=cleanup; control.cleanup=cleanup;
    memcpy(control.nonce,nonce,16); return 1;
}
static void poll_stop(uint64_t now) {
    if (control.input_retiring || control.input_closed || control.input_broken || !control.clock_known) return;
    uint8_t extra;
    uint8_t *target=control.used<sizeof(control.stop)?control.stop+control.used:&extra;
    size_t count=control.used<sizeof(control.stop)?sizeof(control.stop)-control.used:1;
    ssize_t n=read(STDIN_FILENO,target,count);
    if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return;
    if (n<=0 || control.used==sizeof(control.stop)) {
        first_at(now); control.stopped=1; control.valid=0; control.input_broken=1; notice(); return;
    }
    control.used+=(size_t)n;
    // The first control byte revokes forward work even if a malformed sender
    // fragments it. Original-only restoration can still finish on its cutoff.
    first_at(now); control.stopped=1;
    if (control.used!=sizeof(control.stop)) { notice(); return; }
    uint64_t at=get64(control.stop+24), end=get64(control.stop+32);
    if (memcmp(control.stop,"MRKVKS01",8) || memcmp(control.stop+8,control.nonce,16)
        || !at || at>now || end<at || end-at>2000000000u || end>control.maximum) {
        first_at(now); control.valid=0; control.input_broken=1; notice(); return;
    }
    first_at(at); control.stopped=1; if (end<control.cleanup) control.cleanup=end;
    notice();
}
uint32_t mrk_vault_control_admit(uint32_t cleanup) {
    uint64_t now;
    if (cleanup>1 || !now_checked(&now)) return 3;
    // Original-only restoration may outlive the parent. Forward calls may not.
    if (!cleanup && getppid()!=control.parent) { first_at(now); control.stopped=1; notice(); }
    poll_stop(now);
    if (!control.clock_known) return 3;
    if (now>=control.work && !control.first) { first_at(control.work); notice(); }
    if (cleanup) return now<control.cleanup?1:2;
    if (!control.valid) return 3;
    return !control.stopped && !control.first && now<control.work?1:2;
}
int mrk_vault_control_snapshot(uint64_t *first,uint64_t *cleanup,uint32_t *effect,uint32_t *valid) {
    if (!original() || !first || !cleanup || !effect || !valid) return 0;
    *first=control.first; *cleanup=control.cleanup; *effect=control.effect; *valid=control.valid;
    return 1;
}
int mrk_vault_control_terminal_start(void) {
    if (!original() || !control.input_closed) return 0;
    control.notice_attempted=1; return 1;
}
int mrk_vault_control_input_retiring(void) {
    if (!original() || control.input_retiring || control.input_closed) return 0;
    // End the control reader's borrow BEFORE Rust spends the original descriptor.
    // A failed/ambiguous close must never cause a read of a possibly reused number.
    control.input_retiring=1; return 1;
}
int mrk_vault_control_input_closed(void) {
    if (!original() || !control.input_retiring || control.input_closed) return 0;
    control.input_closed=1; return 1; // Only the actual successful returned close.
}
#endif
