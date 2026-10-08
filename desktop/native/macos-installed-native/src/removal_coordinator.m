// Task-specific removal main-sheet and fixed peer adapters. The original sheet
// below grants no live peer capability by itself.
#include "removal_coordinator.h"
#import <AppKit/AppKit.h>
#include <Block.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { R_EMPTY=0, R_ENTERED=1, R_OWNED=2, R_CLOSING=3, R_CLOSED=4, R_UNKNOWN=5 };
enum { R_PARENT=0, R_ALERT=1, R_SHEET=2, R_COMPLETION=3, R_REFERENCES=4 };
typedef struct {
    uint64_t start, work, hard;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    uint32_t refs[R_REFERENCES];
    NSWindow *parent, *sheet;
    NSAlert *alert;
    void (^completion)(NSModalResponse);
    uint8_t nonce[16];
    uint32_t attempted, started, callback_entered, callback_active, callback_returned;
    uint32_t response, close_attempted, closed, unknown, failed, retire_attempted;
} MRKRemovalConfirmation;
_Static_assert(sizeof(MRKRemovalConfirmation) <= 256, "bounded removal main original");

static int confirmation_original(MRKRemovalConfirmation *b) {
    return b && pthread_main_np()==1 && b->pid==getpid() && b->uid==getuid()
        && b->uid!=0 && b->gid==getgid() && getuid()==geteuid() && getgid()==getegid();
}
int mrk_removal_monotonic(uint64_t *now) {
    struct timespec sample;
    if(!now)return 0;*now=0;
    if(clock_gettime(CLOCK_MONOTONIC,&sample)!=0 || sample.tv_sec<0
        || sample.tv_nsec<0 || sample.tv_nsec>=1000000000L
        || (uint64_t)sample.tv_sec>((UINT64_C(1)<<61)-1)/UINT64_C(1000000000))return 0;
    const uint64_t value=(uint64_t)sample.tv_sec*UINT64_C(1000000000)+(uint64_t)sample.tv_nsec;
    if(!value || value>((UINT64_C(1)<<61)-1))return 0;
    *now=value;return 1;
}
// Clock validity/expiry refuses admission without fabricating native settlement.
// Actual late callback facts are recorded first, even after a work cutoff.
static int confirmation_cut(MRKRemovalConfirmation *b, int cleanup) {
    uint64_t now=0;
    if (!confirmation_original(b) || !mrk_removal_monotonic(&now)) {
        if(b)b->failed=1; return 0;
    }
    if(now<b->start || now>=(cleanup?b->hard:b->work)) {b->failed=1;return 0;}
    return 1;
}
static int confirmation_before(MRKRemovalConfirmation *b, unsigned slot) {
    if(slot>=R_REFERENCES || b->refs[slot]!=R_EMPTY || b->failed || b->unknown
        || !confirmation_cut(b,0))return 0;
    b->refs[slot]=R_ENTERED;return 1;
}
static int confirmation_got(MRKRemovalConfirmation *b,unsigned slot,int present) {
    b->refs[slot]=present?R_OWNED:R_CLOSED;
    if(!present){b->failed=1;return 0;}
    return confirmation_cut(b,0);
}
size_t mrk_removal_confirmation_bytes(void) {
    // The four project references and copied block captures are counted here.
    // AppKit/framework/allocator private storage is not claimed as bounded.
    return sizeof(MRKRemovalConfirmation)+128;
}
void *mrk_removal_confirmation_reserve(uint64_t start,uint64_t work,uint64_t hard) {
    if(pthread_main_np()!=1 || getuid()==0 || getuid()!=geteuid() || getgid()!=getegid()
        || start==0 || work<start || hard<start || work-start!=UINT64_C(110000000000)
        || hard-start!=UINT64_C(120000000000) || hard>((UINT64_C(1)<<61)-1))return NULL;
    MRKRemovalConfirmation *b=calloc(1,sizeof(*b));
    if(!b)return NULL;
    b->start=start;b->work=work;b->hard=hard;b->pid=getpid();b->uid=getuid();b->gid=getgid();
    if(!confirmation_cut(b,0)){free(b);return NULL;}
    // Ordinary documented CSPRNG; no token/renderer-provided nonce. Allocation
    // has no native references yet and can be consumed on this known refusal.
    arc4random_buf(b->nonce,sizeof(b->nonce));
    uint8_t combined=0;for(unsigned i=0;i<16;i++)combined|=b->nonce[i];
    if(!combined || !confirmation_cut(b,0)){free(b);return NULL;}
    return b;
}
int mrk_removal_confirmation_start(void *original) {
    MRKRemovalConfirmation *b=original;
    if(!confirmation_original(b) || b->attempted || b->close_attempted || b->unknown)return 0;
    b->attempted=1;
    @try {
        if(!confirmation_cut(b,0))return 0;
        NSWindow *main=[NSApp mainWindow];
        if(!main || [main isKindOfClass:[NSPanel class]] || [main attachedSheet]){b->failed=1;return 0;}
        if(!confirmation_before(b,R_PARENT))return 0;
        b->parent=[main retain];
        if(!confirmation_got(b,R_PARENT,b->parent!=nil) || !confirmation_before(b,R_ALERT))return 0;
        b->alert=[[NSAlert alloc] init];
        if(!confirmation_got(b,R_ALERT,b->alert!=nil))return 0;
        [b->alert setMessageText:@"Quit and prepare to remove Mobile Release Kit?"];
        [b->alert setInformativeText:@"The authenticated installer is requesting removal of this installation. Continue stops this app's owned operations, prepares its services, and quits after cleanup. Your projects, signing inputs, and Store releases are not deleted. Cancel leaves the app open. Unsaved drafts may be discarded when you quit."];
        [b->alert setAlertStyle:NSAlertStyleWarning];
        [[b->alert addButtonWithTitle:@"Cancel"] setKeyEquivalent:@"\r"];
        [[b->alert addButtonWithTitle:@"Continue and Quit"] setKeyEquivalent:@""];
        if(!confirmation_before(b,R_SHEET))return 0;
        b->sheet=[[b->alert window] retain];
        if(!confirmation_got(b,R_SHEET,b->sheet!=nil))return 0;
        [b->sheet setReleasedWhenClosed:NO];
        if(!confirmation_before(b,R_COMPLETION))return 0;
        b->completion=Block_copy(^(NSModalResponse code) {
            // A copied block references this still-owned book, never Rust. The
            // main-only original cannot retire until this callback has returned.
            if(b->callback_entered){b->unknown=1;return;}
            b->callback_entered=1;b->callback_active=1;
            // No Objective-C messages or run-loop pumping in the callback.
            b->response=!b->close_attempted && code==NSAlertSecondButtonReturn?1:
                (!b->close_attempted && code==NSAlertFirstButtonReturn?2:0);
            if(!b->close_attempted && b->response==0)b->failed=1;
            (void)confirmation_cut(b,0);
            b->callback_returned=1;b->callback_active=0;
        });
        if(!confirmation_got(b,R_COMPLETION,b->completion!=NULL))return 0;
        if(!confirmation_cut(b,0))return 0;
        // Mark the possible callback BEFORE entry; an exception must never
        // claim that an AppKit callback cannot still run.
        b->started=1;
        [b->alert beginSheetModalForWindow:b->parent completionHandler:b->completion];
        return confirmation_cut(b,0);
    } @catch (...) {
        for(unsigned i=0;i<R_REFERENCES;i++)if(b->refs[i]==R_ENTERED)b->refs[i]=R_UNKNOWN;
        b->unknown=1;b->failed=1;return 0;
    }
}
int mrk_removal_confirmation_poll(void *original) {
    MRKRemovalConfirmation *b=original;
    if(!confirmation_original(b) || b->unknown || !confirmation_cut(b,1))return -1;
    @try {
        if(b->closed)return 3;
        if(b->callback_active)return 0;
        if(b->close_attempted && (!b->started || b->callback_returned)
            && (!b->sheet || (![b->sheet isVisible] && ![b->sheet sheetParent]))
            && (!b->parent || [b->parent attachedSheet]!=b->sheet)) {
            b->closed=1;return confirmation_cut(b,1)?3:-1;
        }
        if(b->callback_returned)return !b->failed && confirmation_cut(b,0)?(int)b->response:-2;
        return b->failed?-2:0;
    } @catch (...) {b->unknown=1;b->failed=1;return -1;}
}
int mrk_removal_confirmation_close(void *original) {
    MRKRemovalConfirmation *b=original;
    if(!confirmation_original(b) || b->close_attempted || b->unknown || !confirmation_cut(b,1))return 0;
    b->close_attempted=1;
    @try {
        if(!b->started && !b->sheet){b->closed=1;return 1;}
        if(!b->callback_returned && b->sheet && [b->sheet sheetParent]==b->parent)
            [b->parent endSheet:b->sheet returnCode:NSModalResponseCancel];
        if(b->sheet){[b->sheet orderOut:nil];[b->sheet close];}
        return confirmation_cut(b,1);
    } @catch (...) {b->unknown=1;b->failed=1;return 0;}
}
static int confirmation_release(MRKRemovalConfirmation *b,unsigned slot) {
    if(b->refs[slot]==R_EMPTY || b->refs[slot]==R_CLOSED)return 1;
    if(b->refs[slot]!=R_OWNED || !confirmation_cut(b,1))return 0;
    b->refs[slot]=R_CLOSING;
    @try {
        switch(slot){
            case R_COMPLETION: Block_release(b->completion);b->completion=NULL;break;
            case R_SHEET: [b->sheet release];b->sheet=nil;break;
            case R_ALERT: [b->alert release];b->alert=nil;break;
            case R_PARENT: [b->parent release];b->parent=nil;break;
            default:b->refs[slot]=R_UNKNOWN;b->unknown=1;return 0;
        }
        b->refs[slot]=R_CLOSED;return confirmation_cut(b,1);
    } @catch (...) {b->refs[slot]=R_UNKNOWN;b->unknown=1;b->failed=1;return 0;}
}
int mrk_removal_confirmation_retire(void *original,uint32_t *accepted,uint8_t nonce[16]) {
    MRKRemovalConfirmation *b=original;
    if(!confirmation_original(b) || !accepted || !nonce)return 0;
    *accepted=0;memset(nonce,0,16);
    if(b->retire_attempted || b->unknown || b->callback_active || !b->closed
        || (b->started && !b->callback_returned) || !confirmation_cut(b,1))return 0;
    b->retire_attempted=1;
    int all=1;
    // Independent close attempts; a failed first close is not permission to
    // leak other safely owned references or to retry an unknown release.
    const unsigned order[]={R_COMPLETION,R_SHEET,R_ALERT,R_PARENT};
    for(unsigned i=0;i<R_REFERENCES;i++)if(!confirmation_release(b,order[i]))all=0;
    for(unsigned i=0;i<R_REFERENCES;i++)if(b->refs[i]!=R_EMPTY && b->refs[i]!=R_CLOSED)all=0;
    if(!all || b->unknown || !confirmation_cut(b,1))return 0;
    (void)confirmation_cut(b,0); // Late cleanup is never fresh removal consent.
    *accepted=(!b->failed && b->response==1 && b->callback_returned)?1:0;
    if(*accepted)memcpy(nonce,b->nonce,16);
    // Return facts are written before this known sole free. Caller still owes
    // same-cutoff native POST/finality before publishing any protocol message.
    memset(b,0,sizeof(*b));free(b);return 1;
}

// Fixed readable-image peer adapter. No PID-only, cached-credential, copied
// image, passed socket, JSON parser, process launch or signing-key operation.
#include "install_producer.h"
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/xattr.h>

#define P_NONE UINT32_MAX
#define P_MAGIC UINT64_C(0x4d524b524d505231)
#define P_ROOT "/Library/Application Support/MobileReleaseKit"
#define P_OUTER P_ROOT "/Mobile Release Kit.app"
#define P_PAYLOAD P_OUTER "/Contents/Helpers/MobileReleaseKitPayload.app"
#define P_REQUESTS "/Library/Application Support/MobileReleaseKit-RemovalRequests"
static const char *const p_code_paths[15]={
    "/","/Library","/Library/Application Support",P_ROOT,P_OUTER,
    P_OUTER "/Contents",P_OUTER "/Contents/Helpers",P_PAYLOAD,
    P_PAYLOAD "/Contents",P_PAYLOAD "/Contents/MacOS",P_PAYLOAD "/Contents/Helpers",
    P_OUTER "/Contents/MacOS",P_OUTER "/Contents/MacOS/mrk-macos-entry",
    P_PAYLOAD "/Contents/MacOS/mobile-release-kit-desktop",
    P_PAYLOAD "/Contents/Helpers/mrk-macos-remove"
};
enum { P_LISTENER=0,P_CHANNEL=1,P_WATCH=2,
    P_OWN_STATIC=0,P_PEER_STATIC=9,P_AUDIT=15,P_ATTRIBUTES=16,P_GUEST=17,
    P_PEER_INFO=18,P_PEER_LEAF=19,P_FRESH_OWN_INFO=20,P_FRESH_OWN_LEAF=21,
    P_FRESH_PEER_INFO=22,P_FRESH_PEER_LEAF=23 };
typedef struct {
    uint64_t magic;
    pid_t pid;uid_t uid;gid_t gid;pthread_t thread;
    uint32_t entered,sources_ready,connect_started,copied,retire_attempted;
    uint32_t io_direction,io_expected,io_prefix,peer_token_valid,close_attempted;
    mrk_removal_peer_inputs input;
    mrk_removal_peer_report report;
    mrk_install_producer_signer signer;
    struct stat borrowed[MRK_REMOVE_PEER_BORROWED],fd_identity[MRK_REMOVE_PEER_FDS],socket_identity;
    int fd[MRK_REMOVE_PEER_FDS];
    CFTypeRef cf[MRK_REMOVE_PEER_CFS];
    audit_token_t token;
    char request_path[128],json_path[160],socket_path[104];
    uint8_t frame[MRK_REMOVE_PEER_FRAME];
} MRKRemovalPeer;
typedef struct {mrk_removal_peer_gate gate;void *context;} PeerCall;
_Static_assert(sizeof(audit_token_t)==32,"complete documented audit token");
_Static_assert(sizeof(((struct sockaddr_un *)0)->sun_path)==104,"fixed Darwin socket path");
_Static_assert(sizeof(MRKRemovalPeer)<=16384,"bounded peer book and supplied original frame");
_Static_assert(MAXPATHLEN==1024,"bounded documented F_GETPATH result");
_Static_assert(sizeof(mrk_removal_stat_data)==72,"fixed Rust original metadata ABI");
_Static_assert(sizeof(mrk_removal_peer_report)==360,"fixed Rust returned report ABI");
_Static_assert(sizeof(mrk_removal_peer_inputs)==384,"fixed Rust borrowed inputs ABI");

static int p_nonzero(const uint8_t *p,size_t n){uint8_t any=0;for(size_t i=0;i<n;i++)any|=p[i];return any!=0;}
static int p_same(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode
        &&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink
        &&a->st_size==b->st_size&&a->st_flags==b->st_flags
        &&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec
        &&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static int p_directory_same_identity(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode
        &&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_flags==b->st_flags;
}
static mrk_removal_stat_data p_stat_data(const struct stat *s){
    return (mrk_removal_stat_data){.device=(uint64_t)s->st_dev,.inode=s->st_ino,.links=s->st_nlink,
        .size=(uint64_t)s->st_size,.modified_seconds=s->st_mtimespec.tv_sec,.changed_seconds=s->st_ctimespec.tv_sec,
        .mode=s->st_mode,.uid=s->st_uid,.gid=s->st_gid,.flags=s->st_flags,
        .modified_nanoseconds=(uint32_t)s->st_mtimespec.tv_nsec,.changed_nanoseconds=(uint32_t)s->st_ctimespec.tv_nsec};
}
static int p_original(MRKRemovalPeer *b){
    return b&&b->magic==P_MAGIC&&b->pid==getpid()&&pthread_equal(b->thread,pthread_self())
        &&b->uid==getuid()&&b->gid==getgid()&&getuid()==geteuid()&&getgid()==getegid()
        &&((b->input.role==MRK_REMOVE_PARENT&&b->uid==0&&b->gid==0)
            ||(b->input.role==MRK_REMOVE_APP&&b->uid!=0));
}
static int p_fail(MRKRemovalPeer *b,uint32_t code,int unknown){
    if(b){if(!b->report.failed){b->report.first_code=code;b->report.first_failure=b->report.last;}
        b->report.failed=1;if(unknown)b->report.unknown=1;}return 0;
}
static int p_clock(MRKRemovalPeer *b,int cleanup){
    uint64_t now=0;
    if(!p_original(b)||!mrk_removal_monotonic(&now)||now<b->report.last||now<b->input.start)
        return p_fail(b,1,1);
    b->report.last=now;
    if(now>=(cleanup?b->input.hard:b->input.work))return p_fail(b,2,cleanup);
    return 1;
}
static int p_fd_path(int fd,const char *path){
    char actual[MAXPATHLEN]={0};struct stat named={0},held={0};
    return fcntl(fd,F_GETPATH,actual)==0&&memchr(actual,0,sizeof(actual))&&strcmp(actual,path)==0
        &&lstat(path,&named)==0&&fstat(fd,&held)==0&&p_same(&held,&named);
}
static int p_borrowed_post(MRKRemovalPeer *b){
    if(!b->sources_ready)return 1;
    for(unsigned i=0;i<MRK_REMOVE_PEER_BORROWED;i++){
        struct stat now={0};int fd=b->input.borrowed[i];
        if(fstat(fd,&now)!=0||!p_same(&b->borrowed[i],&now)||fcntl(fd,F_GETFD)!=FD_CLOEXEC)return p_fail(b,3,0);
        if(i<15&&!p_fd_path(fd,p_code_paths[i]))return p_fail(b,4,0);
        if(i==17&&!p_fd_path(fd,P_REQUESTS))return p_fail(b,4,0);
        if(i==18&&!p_fd_path(fd,b->request_path))return p_fail(b,4,0);
        if(i==19&&!p_fd_path(fd,b->json_path))return p_fail(b,4,0);
    }
    if(b->report.bind_returned){
        struct stat named={0};
        if(fstatat(b->input.borrowed[18],"s",&named,AT_SYMLINK_NOFOLLOW)!=0
            ||!p_same(&named,&b->socket_identity))return p_fail(b,5,0);
    }
    return 1;
}
static int p_point(MRKRemovalPeer *b,PeerCall *scope,int before,unsigned phase,unsigned slot,int cleanup){
    // POST must deliver actual adoption/consumption even when its clock/source
    // check fails. A stopped operation cannot thereby start any fresh work.
    int valid=p_clock(b,cleanup);
    if(before&&(!valid||(!cleanup&&(b->report.failed||b->report.unknown))))return 0;
    if(!p_borrowed_post(b)&&!cleanup){valid=0;if(before)return 0;}
    if(!scope||!scope->gate)return p_fail(b,6,1);
    int answer=scope->gate(scope->context,(uint32_t)before,phase,slot,(uint32_t)cleanup,&b->report);
    if(answer!=1)return p_fail(b,7,answer!=0);
    int after=p_clock(b,cleanup);
    return valid&&after;
}
static int p_before(MRKRemovalPeer *b,PeerCall *s,unsigned phase,unsigned slot,int cleanup){
    if(!p_point(b,s,1,phase,slot,cleanup))return 0;
    if(b->report.calls==UINT32_MAX||b->report.calls!=b->report.returned)return p_fail(b,8,1);
    b->report.calls++;return 1;
}
static int p_return(MRKRemovalPeer *b,PeerCall *s,unsigned phase,unsigned slot,int cleanup){
    if(b->report.returned==UINT32_MAX||b->report.calls!=b->report.returned+1)return p_fail(b,8,1);
    b->report.returned++;
    // The real return/adoption precedes clock/source/owner POST even on failure.
    int ready=p_point(b,s,0,phase,slot,cleanup);
    return ready&&(cleanup||!b->report.failed);
}
static int p_cf_before(MRKRemovalPeer *b,PeerCall *s,unsigned phase,unsigned slot){
    if(slot>=MRK_REMOVE_PEER_CFS||b->cf[slot]
        ||(b->report.cf_states[slot]!=R_EMPTY&&b->report.cf_states[slot]!=R_CLOSED))return p_fail(b,9,1);
    if(!p_before(b,s,phase,slot,0))return 0;b->report.cf_states[slot]=R_ENTERED;return 1;
}
static int p_cf_return(MRKRemovalPeer *b,PeerCall *s,unsigned phase,unsigned slot,CFTypeRef value,OSStatus status){
    b->cf[slot]=value;b->report.cf_states[slot]=value?R_OWNED:R_CLOSED;
    if(status!=errSecSuccess||!value)p_fail(b,10,0);
    return p_return(b,s,phase,slot,0);
}
static int p_cf_release(MRKRemovalPeer *b,PeerCall *s,unsigned slot,int cleanup){
    if(b->report.cf_states[slot]==R_EMPTY||b->report.cf_states[slot]==R_CLOSED)return 1;
    if(b->report.cf_states[slot]!=R_OWNED||!b->cf[slot])return p_fail(b,11,1);
    if(!p_before(b,s,MRK_RP_RELEASE,slot,cleanup))return 0;b->report.cf_states[slot]=R_CLOSING;
    @try{CFRelease(b->cf[slot]);b->cf[slot]=NULL;b->report.cf_states[slot]=R_CLOSED;}
    @catch(...){b->report.cf_states[slot]=R_UNKNOWN;p_fail(b,12,1);}
    return p_return(b,s,MRK_RP_RELEASE,slot,cleanup);
}
static int p_hash_fd(MRKRemovalPeer *b,PeerCall *s,unsigned slot,const uint8_t *raw,size_t raw_size,const uint8_t expected[32]){
    const struct stat *st=&b->borrowed[slot];uint8_t block[65536],actual[32];CC_SHA256_CTX hash;
    if(st->st_size<=0||(uint64_t)st->st_size>UINT64_C(536870912)||!p_nonzero(expected,32)
        ||(raw&&raw_size!=(size_t)st->st_size)||CC_SHA256_Init(&hash)!=1)return p_fail(b,13,0);
    uint64_t position=0;
    while(position<(uint64_t)st->st_size){
        size_t count=(size_t)((uint64_t)st->st_size-position);if(count>sizeof(block))count=sizeof(block);
        if(!p_before(b,s,MRK_RP_SOURCE,slot,0))return 0;
        ssize_t got=pread(b->input.borrowed[slot],block,count,(off_t)position);
        if(got!=(ssize_t)count||(raw&&memcmp(block,raw+(size_t)position,count))
            ||(got==(ssize_t)count&&CC_SHA256_Update(&hash,block,(CC_LONG)count)!=1))p_fail(b,14,0);
        if(!p_return(b,s,MRK_RP_SOURCE,slot,0))return 0;position+=count;
    }
    if(!p_before(b,s,MRK_RP_SOURCE,slot,0))return 0;
    ssize_t eof=pread(b->input.borrowed[slot],block,1,(off_t)position);
    if(eof!=0||CC_SHA256_Final(actual,&hash)!=1||memcmp(actual,expected,32))p_fail(b,15,0);
    return p_return(b,s,MRK_RP_SOURCE,slot,0);
}
static int p_source(MRKRemovalPeer *b,PeerCall *s){
    if(!p_before(b,s,MRK_RP_SOURCE,P_NONE,0))return 0;
    int good=mrk_install_producer_source(&b->signer)==1;
    uint64_t code_bytes=0;
    for(unsigned i=0;good&&i<MRK_REMOVE_PEER_BORROWED;i++){
        int fd=b->input.borrowed[i];struct stat *st=&b->borrowed[i];struct statfs fs;
        good=fd>=3&&fstat(fd,st)==0&&fcntl(fd,F_GETFD)==FD_CLOEXEC&&st->st_uid==0&&st->st_gid==0
            &&st->st_flags==0&&st->st_nlink>0&&st->st_size>=0
            &&fstatfs(fd,&fs)==0&&(fs.f_flags&MNT_LOCAL)&&strcmp(fs.f_fstypename,"apfs")==0;
        for(unsigned j=0;good&&j<i;j++)if(fd==b->input.borrowed[j])good=0;
        if(!good)break;
        if(i<12||i==17||i==18){
            mode_t mode=(i>=4&&i<12)?0555:0755;
            good=S_ISDIR(st->st_mode)&&(st->st_mode&07777)==mode;
        }else{
            good=S_ISREG(st->st_mode)&&st->st_nlink==1
                &&(st->st_mode&07777)==(i<15?0555:0444);
            int flags=fcntl(fd,F_GETFL);good=good&&flags>=0&&(flags&O_ACCMODE)==O_RDONLY&&!(flags&(O_APPEND|O_ASYNC));
        }
        if(i>=12&&i<15){code_bytes+=(uint64_t)st->st_size;good=good&&st->st_size>0&&code_bytes<=UINT64_C(536870912);}
    }
    good=good&&b->borrowed[14].st_size<=INT64_C(67108864)
        &&b->borrowed[15].st_size==(off_t)b->input.installed_size
        &&b->borrowed[16].st_size==(off_t)b->input.installed_signature_size
        &&b->borrowed[19].st_size>0&&b->borrowed[19].st_size<=MRK_REMOVE_PEER_JSON;
    if(!good)p_fail(b,16,0);
    if(good)b->sources_ready=1;
    if(!p_return(b,s,MRK_RP_SOURCE,P_NONE,0))return 0;
    if(!p_hash_fd(b,s,15,b->input.installed,b->input.installed_size,b->input.installed_sha256))return 0;
    uint8_t signature_hash[32],remove_hash[32];
    if(!CC_SHA256(b->input.installed_signature,(CC_LONG)b->input.installed_signature_size,signature_hash)
        ||!p_hash_fd(b,s,16,b->input.installed_signature,b->input.installed_signature_size,signature_hash)
        ||!CC_SHA256(b->input.remove,(CC_LONG)b->input.remove_size,remove_hash)
        ||memcmp(remove_hash,b->input.remove_sha256,32))return p_fail(b,17,0);
    if(b->input.installed_signature_size!=b->signer.rsa_bits/8||b->input.remove_signature_size!=b->signer.rsa_bits/8)
        return p_fail(b,18,0);
    for(unsigned i=0;i<3;i++)if(!p_hash_fd(b,s,12+i,NULL,0,b->input.code_sha256[i]))return 0;
    if(!p_hash_fd(b,s,19,NULL,0,b->input.request_sha256))return 0;
    b->report.request_directory=p_stat_data(&b->borrowed[18]);
    return 1;
}

static unsigned p_own_code(MRKRemovalPeer *b){return b->input.role==MRK_REMOVE_PARENT?14:13;}
static unsigned p_peer_code(MRKRemovalPeer *b){return b->input.role==MRK_REMOVE_PARENT?13:14;}
static const char *p_identifier(unsigned code){return code==14?"dev.mobile-release-kit.desktop.remove":"dev.mobile-release-kit.desktop";}
static int p_number(CFDictionaryRef info,CFStringRef key,uint32_t *out){
    CFTypeRef value=CFDictionaryGetValue(info,key);int64_t number=0;
    if(!value||CFGetTypeID(value)!=CFNumberGetTypeID()||CFNumberIsFloatType((CFNumberRef)value)
        ||!CFNumberGetValue((CFNumberRef)value,kCFNumberSInt64Type,&number)||number<0||number>UINT32_MAX)return 0;
    *out=(uint32_t)number;return 1;
}
static int p_info_shape(CFDictionaryRef info){return info&&CFGetTypeID(info)==CFDictionaryGetTypeID()&&CFDictionaryGetCount(info)<=128;}
static int p_info(MRKRemovalPeer *b,CFDictionaryRef info,CFDataRef der,unsigned code,int dynamic,CFDictionaryRef same_static){
    if(!p_info_shape(info)||!der||CFGetTypeID(der)!=CFDataGetTypeID()
        ||CFDataGetLength(der)<=0||CFDataGetLength(der)>MRK_INSTALL_PRODUCER_CERTIFICATE_MAX
        ||mrk_install_producer_source_leaf_matches(CFDataGetBytePtr(der),(size_t)CFDataGetLength(der))!=1)return p_fail(b,19,0);
    uint32_t flags=0,status=0;
    if(!p_number(info,kSecCodeInfoFlags,&flags)||!(flags&kSecCodeSignatureRuntime))return p_fail(b,20,0);
    if(dynamic&&(!p_number(info,kSecCodeInfoStatus,&status)||!(status&kSecCodeStatusValid)||(status&kSecCodeStatusDebugged)))return p_fail(b,21,0);
    CFTypeRef ent=CFDictionaryGetValue(info,kSecCodeInfoEntitlementsDict),raw=CFDictionaryGetValue(info,kSecCodeInfoEntitlements);
    if((ent&&(CFGetTypeID(ent)!=CFDictionaryGetTypeID()||CFDictionaryGetCount((CFDictionaryRef)ent)))
        ||(!ent&&raw)||(raw&&(CFGetTypeID(raw)!=CFDataGetTypeID()||CFDataGetLength((CFDataRef)raw)>4096)))return p_fail(b,22,0);
    CFTypeRef identifier=CFDictionaryGetValue(info,kSecCodeInfoIdentifier),executable=CFDictionaryGetValue(info,kSecCodeInfoMainExecutable);
    char actual[MAXPATHLEN]={0},name[128]={0};
    if(!identifier||CFGetTypeID(identifier)!=CFStringGetTypeID()
        ||!CFStringGetCString((CFStringRef)identifier,name,sizeof(name),kCFStringEncodingASCII)||strcmp(name,p_identifier(code))
        ||!executable||CFGetTypeID(executable)!=CFURLGetTypeID()
        ||!CFURLGetFileSystemRepresentation((CFURLRef)executable,false,(UInt8 *)actual,sizeof(actual))
        ||!memchr(actual,0,sizeof(actual))||strcmp(actual,p_code_paths[code]))return p_fail(b,23,0);
    CFTypeRef unique=CFDictionaryGetValue(info,kSecCodeInfoUnique);
    // Documented current cdhash is opaque20. Never truncate another algorithm.
    if(!unique||CFGetTypeID(unique)!=CFDataGetTypeID()||CFDataGetLength((CFDataRef)unique)!=20)return p_fail(b,24,0);
    if(dynamic){
        CFTypeRef expected=p_info_shape(same_static)?CFDictionaryGetValue(same_static,kSecCodeInfoUnique):NULL;
        if(!expected||CFGetTypeID(expected)!=CFDataGetTypeID()||!CFEqual(unique,expected))return p_fail(b,25,0);
    }
    return 1;
}
static int p_certificate(MRKRemovalPeer *b,PeerCall *s,unsigned info_slot,unsigned leaf_slot){
    CFDictionaryRef info=(CFDictionaryRef)b->cf[info_slot];
    if(!p_info_shape(info))return p_fail(b,26,0);
    CFTypeRef chain=CFDictionaryGetValue(info,kSecCodeInfoCertificates);
    if(!chain||CFGetTypeID(chain)!=CFArrayGetTypeID()||CFArrayGetCount((CFArrayRef)chain)<1||CFArrayGetCount((CFArrayRef)chain)>8)return p_fail(b,27,0);
    CFTypeRef leaf=CFArrayGetValueAtIndex((CFArrayRef)chain,0);
    if(!leaf||CFGetTypeID(leaf)!=SecCertificateGetTypeID())return p_fail(b,28,0);
    if(!p_cf_before(b,s,MRK_RP_CERTIFICATE,leaf_slot))return 0;
    CFDataRef data=SecCertificateCopyData((SecCertificateRef)leaf);
    return p_cf_return(b,s,MRK_RP_CERTIFICATE,leaf_slot,data,errSecSuccess);
}
static int p_static(MRKRemovalPeer *b,PeerCall *s,unsigned base,unsigned code){
    // Static source-purpose and actual executable-original correspondence are
    // independent of the caller's prior ordinary-owned packaging verifier.
    if(!p_cf_before(b,s,MRK_RP_STATIC_URL,base))return 0;
    CFURLRef url=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8 *)p_code_paths[code],strlen(p_code_paths[code]),false);
    if(!p_cf_return(b,s,MRK_RP_STATIC_URL,base,url,errSecSuccess)||!p_cf_before(b,s,MRK_RP_STATIC_CODE,base+1))return 0;
    SecStaticCodeRef static_code=NULL;OSStatus status=SecStaticCodeCreateWithPath(url,kSecCSDefaultFlags,&static_code);
    if(!p_cf_return(b,s,MRK_RP_STATIC_CODE,base+1,static_code,status))return 0;
    char team[11]={0},leaf[41]={0},requirement[768]={0};static const char hex[]="0123456789abcdef";
    memcpy(team,b->signer.team,10);
    for(unsigned i=0;i<20;i++){leaf[i*2]=hex[b->signer.leaf_sha1[i]>>4];leaf[i*2+1]=hex[b->signer.leaf_sha1[i]&15];}
    int n=snprintf(requirement,sizeof(requirement),
        "anchor apple generic and identifier \"%s\" and certificate leaf[subject.OU] = \"%s\" and certificate leaf = H\"%s\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
        p_identifier(code),team,leaf);
    if(n<=0||(size_t)n>=sizeof(requirement))return p_fail(b,29,0);
    if(!p_cf_before(b,s,MRK_RP_REQUIREMENT_TEXT,base+2))return 0;
    CFStringRef text=CFStringCreateWithCString(NULL,requirement,kCFStringEncodingASCII);
    if(!p_cf_return(b,s,MRK_RP_REQUIREMENT_TEXT,base+2,text,errSecSuccess)||!p_cf_before(b,s,MRK_RP_REQUIREMENT,base+3))return 0;
    SecRequirementRef rule=NULL;status=SecRequirementCreateWithString(text,kSecCSDefaultFlags,&rule);
    if(!p_cf_return(b,s,MRK_RP_REQUIREMENT,base+3,rule,status)||!p_before(b,s,MRK_RP_STATIC_VALIDITY,base+1,0))return 0;
    status=SecStaticCodeCheckValidity(static_code,kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode|kSecCSNoNetworkAccess,rule);
    if(status!=errSecSuccess)p_fail(b,30,0);
    if(!p_return(b,s,MRK_RP_STATIC_VALIDITY,base+1,0)||!p_cf_before(b,s,MRK_RP_STATIC_INFO,base+4))return 0;
    CFDictionaryRef info=NULL;status=SecCodeCopySigningInformation(static_code,kSecCSSigningInformation,&info);
    if(!p_cf_return(b,s,MRK_RP_STATIC_INFO,base+4,info,status)||!p_certificate(b,s,base+4,base+5))return 0;
    return p_info(b,info,(CFDataRef)b->cf[base+5],code,0,NULL);
}
static int p_dynamic(MRKRemovalPeer *b,PeerCall *s,unsigned code_slot,unsigned base,unsigned info_slot,unsigned leaf_slot){
    if(!p_before(b,s,MRK_RP_DYNAMIC_VALIDITY,code_slot,0))return 0;
    OSStatus status=SecCodeCheckValidity((SecCodeRef)b->cf[code_slot],kSecCSStrictValidate|kSecCSNoNetworkAccess,(SecRequirementRef)b->cf[base+3]);
    if(status!=errSecSuccess)p_fail(b,31,0);
    if(!p_return(b,s,MRK_RP_DYNAMIC_VALIDITY,code_slot,0)||!p_cf_before(b,s,MRK_RP_DYNAMIC_INFO,info_slot))return 0;
    CFDictionaryRef info=NULL;
    status=SecCodeCopySigningInformation((SecStaticCodeRef)b->cf[code_slot],kSecCSSigningInformation|kSecCSDynamicInformation,&info);
    if(!p_cf_return(b,s,MRK_RP_DYNAMIC_INFO,info_slot,info,status)||!p_certificate(b,s,info_slot,leaf_slot))return 0;
    return p_info(b,info,(CFDataRef)b->cf[leaf_slot],base==P_OWN_STATIC?p_own_code(b):p_peer_code(b),1,(CFDictionaryRef)b->cf[base+4]);
}
static int p_self(MRKRemovalPeer *b,PeerCall *s){
    if(!p_cf_before(b,s,MRK_RP_SELF,6))return 0;
    SecCodeRef self=NULL;OSStatus status=SecCodeCopySelf(kSecCSDefaultFlags,&self);
    return p_cf_return(b,s,MRK_RP_SELF,6,self,status)&&p_dynamic(b,s,6,P_OWN_STATIC,7,8);
}
static int p_fd_adopt(MRKRemovalPeer *b,PeerCall *s,unsigned phase,unsigned slot,int fd){
    b->fd[slot]=fd;b->report.fd_states[slot]=fd>=0?R_OWNED:R_CLOSED;
    if(fd<0)p_fail(b,32,0);
    else if(fd<3||fstat(fd,&b->fd_identity[slot]))p_fail(b,33,1);
    return p_return(b,s,phase,slot,0);
}
static int p_fd_before(MRKRemovalPeer *b,PeerCall *s,unsigned phase,unsigned slot){
    if(slot>=MRK_REMOVE_PEER_FDS||b->fd[slot]!=-1||b->report.fd_states[slot]!=R_EMPTY)return p_fail(b,34,1);
    if(!p_before(b,s,phase,slot,0))return 0;b->report.fd_states[slot]=R_ENTERED;return 1;
}
static int p_owned_fd(MRKRemovalPeer *b,unsigned slot,int flags_ready){
    struct stat now={0};int fd=b->fd[slot];
    if(b->report.fd_states[slot]!=R_OWNED||fd<3||fstat(fd,&now))return p_fail(b,35,1);
    const struct stat *original=&b->fd_identity[slot];
    // XNU soo_stat reports queued receive bytes and dynamic 0666 readiness
    // bits; kqueue_stat reports pending-event count. These generated originals
    // are NOT immutable filesystem leaves. All other captured fields remain
    // equal; only these documented live counters/readiness bits are excluded.
    // A kqueue's zero inode is not unique authority: the private same-worker
    // descriptor, actual watch registration/returns and custody remain required.
    const mode_t type=slot==P_WATCH?S_IFIFO:S_IFSOCK;
    const mode_t mutable_mode=slot==P_WATCH?0:0666;
    if((original->st_mode&~mutable_mode)!=type||(now.st_mode&~mutable_mode)!=type
        ||now.st_dev!=original->st_dev||now.st_ino!=original->st_ino
        ||now.st_uid!=original->st_uid||now.st_gid!=original->st_gid
        ||now.st_nlink!=original->st_nlink||now.st_flags!=original->st_flags||now.st_size<0
        ||now.st_mtimespec.tv_sec!=original->st_mtimespec.tv_sec||now.st_mtimespec.tv_nsec!=original->st_mtimespec.tv_nsec
        ||now.st_ctimespec.tv_sec!=original->st_ctimespec.tv_sec||now.st_ctimespec.tv_nsec!=original->st_ctimespec.tv_nsec)
        return p_fail(b,35,1);
    if(flags_ready){
        if(fcntl(fd,F_GETFD)!=FD_CLOEXEC)return p_fail(b,36,1);
        if(slot!=P_WATCH){int flags=fcntl(fd,F_GETFL),kind=0,nosignal=0;socklen_t len=sizeof(kind),other=sizeof(nosignal);
            if(flags<0||!(flags&O_NONBLOCK)||(flags&(O_APPEND|O_ASYNC))||getsockopt(fd,SOL_SOCKET,SO_TYPE,&kind,&len)
                ||len!=sizeof(kind)||kind!=SOCK_STREAM||getsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&nosignal,&other)
                ||other!=sizeof(nosignal)||nosignal!=1)return p_fail(b,37,1);
        }
    }
    return 1;
}
static int p_flags(MRKRemovalPeer *b,PeerCall *s,unsigned slot){
    unsigned phase=slot==P_WATCH?MRK_RP_WATCH_FLAGS:MRK_RP_SOCKET_FLAGS;
    if(!p_owned_fd(b,slot,0)||!p_before(b,s,phase,slot,0))return 0;
    int fd=b->fd[slot],good=fcntl(fd,F_SETFD,FD_CLOEXEC)==0;
    if(slot!=P_WATCH){int flags=fcntl(fd,F_GETFL),one=1;
        good=good&&flags>=0&&fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0&&setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))==0;
    }
    if(!good||!p_owned_fd(b,slot,1))p_fail(b,38,1);
    return p_return(b,s,phase,slot,0);
}
static int p_named_socket(MRKRemovalPeer *b,int initial){
    struct stat held={0},named={0};
    if(fstatat(b->input.borrowed[18],"s",&held,AT_SYMLINK_NOFOLLOW)||lstat(b->socket_path,&named)
        ||!p_same(&held,&named)||!S_ISSOCK(held.st_mode)||held.st_uid||held.st_gid
        ||held.st_nlink!=1||held.st_flags||(held.st_mode&07777)!=0666)return p_fail(b,39,0);
    if(initial)b->socket_identity=held;
    else if(!p_same(&held,&b->socket_identity))return p_fail(b,40,0);
    b->report.socket_name=p_stat_data(&held);return 1;
}
static int p_address(MRKRemovalPeer *b,struct sockaddr_un *address){
    size_t n=strlen(b->socket_path);
    if(n!=98||n+1>sizeof(address->sun_path))return p_fail(b,41,0);
    memset(address,0,sizeof(*address));address->sun_family=AF_UNIX;
    address->sun_len=(uint8_t)(offsetof(struct sockaddr_un,sun_path)+n+1);
    memcpy(address->sun_path,b->socket_path,n+1);return 1;
}
static int p_socket_bound(MRKRemovalPeer *b,int connected){
    if(!p_owned_fd(b,connected?P_CHANNEL:P_LISTENER,1)||!p_named_socket(b,0))return 0;
    struct sockaddr_un address;memset(&address,0,sizeof(address));socklen_t n=sizeof(address);
    int fd=b->fd[connected?P_CHANNEL:P_LISTENER];
    int rc=b->input.role==MRK_REMOVE_APP?getpeername(fd,(struct sockaddr *)&address,&n):getsockname(fd,(struct sockaddr *)&address,&n);
    const size_t expected=offsetof(struct sockaddr_un,sun_path)+strlen(b->socket_path)+1;
    // Darwin may report sun_len without its optional terminal NUL. The bytes
    // through the fixed98-byte public name must match, with no extra component.
    if(rc||n<expected-1||n>expected||address.sun_family!=AF_UNIX
        ||memcmp(address.sun_path,b->socket_path,98)||(n==expected&&address.sun_path[98]))return p_fail(b,42,0);
    return 1;
}
static int p_open(MRKRemovalPeer *b,PeerCall *s){
    unsigned slot=b->input.role==MRK_REMOVE_PARENT?P_LISTENER:P_CHANNEL;
    if(!p_fd_before(b,s,MRK_RP_SOCKET,slot))return 0;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(!p_fd_adopt(b,s,MRK_RP_SOCKET,slot,fd)||!p_flags(b,s,slot))return 0;
    if(b->input.role==MRK_REMOVE_APP){
        // App only observes the already-published exact socket; no chmod or
        // publication rebaseline is permitted in this role.
        if(!p_named_socket(b,1))return 0;b->report.bind_returned=1;return 1;
    }
    struct sockaddr_un address;if(!p_address(b,&address))return 0;
    struct stat absent;errno=0;
    if(fstatat(b->input.borrowed[18],"s",&absent,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return p_fail(b,43,0);
    if(!p_before(b,s,MRK_RP_BIND,slot,0))return 0;
    int rc=bind(fd,(struct sockaddr *)&address,address.sun_len);
    // Actual own bind is the ONLY request-directory mutation admitted here.
    // Publish its real full facts to the caller's already-held request Book
    // before source POST; neither role can refresh a later foreign change.
    if(rc==0){
        struct stat parent={0},named={0};
        if(fstat(b->input.borrowed[18],&parent)||!p_directory_same_identity(&parent,&b->borrowed[18])
            ||fstatat(b->input.borrowed[18],"s",&named,AT_SYMLINK_NOFOLLOW)||!S_ISSOCK(named.st_mode)
            ||named.st_uid||named.st_gid||named.st_nlink!=1||named.st_flags)p_fail(b,44,1);
        else {b->borrowed[18]=parent;b->socket_identity=named;b->report.bind_returned=1;
            b->report.request_directory=p_stat_data(&parent);b->report.socket_name=p_stat_data(&named);}
    }else p_fail(b,45,0);
    if(!p_return(b,s,MRK_RP_BIND,slot,0))return 0;
    if(!p_before(b,s,MRK_RP_SOCKET_MODE,slot,0))return 0;
    // Fixed relative own original only; prior type/named facts plus root-only
    // parent exclude an ordinary caller's replacement, and POST is mandatory.
    rc=fchmodat(b->input.borrowed[18],"s",0666,AT_SYMLINK_NOFOLLOW);
    if(rc==0){struct stat named={0};
        if(fstatat(b->input.borrowed[18],"s",&named,AT_SYMLINK_NOFOLLOW)
            ||named.st_dev!=b->socket_identity.st_dev||named.st_ino!=b->socket_identity.st_ino
            ||named.st_uid||named.st_gid||named.st_nlink!=1||!S_ISSOCK(named.st_mode)||named.st_flags
            ||(named.st_mode&07777)!=0666)p_fail(b,46,1);
        else{b->socket_identity=named;b->report.socket_name=p_stat_data(&named);}
    }else p_fail(b,47,0);
    if(!p_return(b,s,MRK_RP_SOCKET_MODE,slot,0)||!p_named_socket(b,0)||!p_before(b,s,MRK_RP_LISTEN,slot,0))return 0;
    if(listen(fd,1))p_fail(b,48,0);
    return p_return(b,s,MRK_RP_LISTEN,slot,0)&&p_socket_bound(b,0);
}
static int p_connect(MRKRemovalPeer *b,PeerCall *s){
    if(b->input.role==MRK_REMOVE_PARENT){
        if(!p_socket_bound(b,0)||!p_fd_before(b,s,MRK_RP_ACCEPT,P_CHANNEL))return -1;
        int fd=accept(b->fd[P_LISTENER],NULL,NULL),saved=errno;
        if(fd<0&&(saved==EAGAIN||saved==EWOULDBLOCK)){
            // No original was acquired; same listener is pending. Empty here
            // does not relabel an entered/unknown acquisition as consumed.
            b->report.fd_states[P_CHANNEL]=R_EMPTY;
            return p_return(b,s,MRK_RP_ACCEPT,P_CHANNEL,0)?0:-1;
        }
        if(!p_fd_adopt(b,s,MRK_RP_ACCEPT,P_CHANNEL,fd)||!p_flags(b,s,P_CHANNEL))return -1;
        return p_socket_bound(b,1)?1:-1;
    }
    if(!p_owned_fd(b,P_CHANNEL,1)||!p_named_socket(b,0))return -1;
    if(!b->connect_started){
        struct sockaddr_un address;if(!p_address(b,&address)||!p_before(b,s,MRK_RP_CONNECT,P_CHANNEL,0))return -1;
        b->connect_started=1;
        int rc=connect(b->fd[P_CHANNEL],(struct sockaddr *)&address,address.sun_len),saved=errno;
        if(rc!=0&&saved!=EINPROGRESS)p_fail(b,49,0);
        if(!p_return(b,s,MRK_RP_CONNECT,P_CHANNEL,0))return -1;
        if(rc==0)return p_socket_bound(b,1)?1:-1;
        return 0;
    }
    if(!p_before(b,s,MRK_RP_CONNECT_STATUS,P_CHANNEL,0))return -1;
    int error=0;socklen_t n=sizeof(error);
    int rc=getsockopt(b->fd[P_CHANNEL],SOL_SOCKET,SO_ERROR,&error,&n);
    if(rc||n!=sizeof(error)||error)p_fail(b,50,0);
    if(!p_return(b,s,MRK_RP_CONNECT_STATUS,P_CHANNEL,0))return -1;
    struct sockaddr_un remote;memset(&remote,0,sizeof(remote));n=sizeof(remote);
    rc=getpeername(b->fd[P_CHANNEL],(struct sockaddr *)&remote,&n);
    if(rc&&errno==ENOTCONN)return 0;
    if(rc)return p_fail(b,51,0),-1;
    return p_socket_bound(b,1)?1:-1;
}
static int p_token(MRKRemovalPeer *b,PeerCall *s,int initial){
    if(!p_socket_bound(b,1)||!p_before(b,s,MRK_RP_TOKEN,P_CHANNEL,0))return 0;
    audit_token_t actual;memset(&actual,0,sizeof(actual));socklen_t n=sizeof(actual);
    int rc=getsockopt(b->fd[P_CHANNEL],SOL_LOCAL,LOCAL_PEERTOKEN,&actual,&n);
    if(rc||n!=sizeof(actual))p_fail(b,52,0);
    else {
        pid_t pid=audit_token_to_pid(actual);uid_t euid=audit_token_to_euid(actual),ruid=audit_token_to_ruid(actual);
        gid_t egid=audit_token_to_egid(actual),rgid=audit_token_to_rgid(actual);
        int role=pid>1&&pid!=b->pid&&euid==ruid&&egid==rgid
            &&(b->input.role==MRK_REMOVE_PARENT?euid!=0:(euid==0&&egid==0));
        if(!role||(!initial&&(!b->peer_token_valid||memcmp(&actual,&b->token,sizeof(actual)))))p_fail(b,53,0);
        else if(initial){
            b->token=actual;b->peer_token_valid=1;b->report.token_ready=1;
            b->report.peer_pid=(uint32_t)pid;b->report.peer_uid=euid;b->report.peer_gid=egid;
        }
    }
    return p_return(b,s,MRK_RP_TOKEN,P_CHANNEL,0);
}
static int p_guest(MRKRemovalPeer *b,PeerCall *s){
    if(!b->peer_token_valid||!p_cf_before(b,s,MRK_RP_AUDIT_DATA,P_AUDIT))return 0;
    CFDataRef token=CFDataCreate(NULL,(const UInt8 *)&b->token,sizeof(b->token));
    if(!p_cf_return(b,s,MRK_RP_AUDIT_DATA,P_AUDIT,token,errSecSuccess)
        ||!p_cf_before(b,s,MRK_RP_AUDIT_ATTRIBUTES,P_ATTRIBUTES))return 0;
    const void *key=kSecGuestAttributeAudit,*value=token;
    CFDictionaryRef attributes=CFDictionaryCreate(NULL,&key,&value,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    if(!p_cf_return(b,s,MRK_RP_AUDIT_ATTRIBUTES,P_ATTRIBUTES,attributes,errSecSuccess)
        ||!p_cf_before(b,s,MRK_RP_GUEST,P_GUEST))return 0;
    SecCodeRef guest=NULL;
    // Documented full-token selection, NEVER kSecGuestAttributePid or a diskless
    // alternate. This is independent of the untrusted request's data fields.
    OSStatus status=SecCodeCopyGuestWithAttributes(NULL,attributes,kSecCSDefaultFlags,&guest);
    return p_cf_return(b,s,MRK_RP_GUEST,P_GUEST,guest,status)
        &&p_dynamic(b,s,P_GUEST,P_PEER_STATIC,P_PEER_INFO,P_PEER_LEAF);
}
static int p_refresh_code(MRKRemovalPeer *b,PeerCall *s){
    int good=p_dynamic(b,s,6,P_OWN_STATIC,P_FRESH_OWN_INFO,P_FRESH_OWN_LEAF)
        &&p_dynamic(b,s,P_GUEST,P_PEER_STATIC,P_FRESH_PEER_INFO,P_FRESH_PEER_LEAF);
    // Even a failed second query cannot skip the first query's known closes.
    const unsigned order[]={P_FRESH_PEER_LEAF,P_FRESH_PEER_INFO,P_FRESH_OWN_LEAF,P_FRESH_OWN_INFO};
    for(unsigned i=0;i<4;i++)if(!p_cf_release(b,s,order[i],1))good=0;
    return good&&!b->report.failed;
}
static int p_watch_poll(MRKRemovalPeer *b,PeerCall *s,int cleanup){
    if(!b->report.watch_ready||!p_owned_fd(b,P_WATCH,1)||!p_before(b,s,MRK_RP_WATCH_POLL,P_WATCH,cleanup))return -1;
    struct kevent event;memset(&event,0,sizeof(event));const struct timespec zero={0,0};
    int n=kevent(b->fd[P_WATCH],NULL,0,&event,1,&zero);
    if(n<0)p_fail(b,54,0);
    else if(n){
        const uint16_t allowed=EV_ADD|EV_ENABLE|EV_ONESHOT|EV_EOF|EV_CLEAR;
        if(n!=1||event.ident!=b->report.peer_pid||event.filter!=EVFILT_PROC||event.udata!=b
            ||(event.flags&~allowed)||!(event.flags&EV_EOF)||event.fflags!=NOTE_EXIT)p_fail(b,55,1);
        else b->report.exit_observed=1;
    }
    if(!p_return(b,s,MRK_RP_WATCH_POLL,P_WATCH,cleanup))return -1;
    return b->report.exit_observed?1:0;
}
static int p_watch(MRKRemovalPeer *b,PeerCall *s){
    if(!p_fd_before(b,s,MRK_RP_KQUEUE,P_WATCH))return 0;
    int fd=kqueue();if(!p_fd_adopt(b,s,MRK_RP_KQUEUE,P_WATCH,fd)||!p_flags(b,s,P_WATCH))return 0;
    if(!p_before(b,s,MRK_RP_WATCH_REGISTER,P_WATCH,0))return 0;
    struct kevent change,receipt;memset(&receipt,0,sizeof(receipt));const struct timespec zero={0,0};
    EV_SET(&change,(uintptr_t)b->report.peer_pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_RECEIPT,NOTE_EXIT,0,b);
    int n=kevent(fd,&change,1,&receipt,1,&zero);
    if(n!=1||receipt.ident!=b->report.peer_pid||receipt.filter!=EVFILT_PROC
        ||receipt.flags!=EV_ERROR||receipt.data!=0||receipt.udata!=b)p_fail(b,56,0);
    else b->report.watch_ready=1;
    // The receipt echoes NOTE_EXIT! It is ONLY a registration acknowledgement.
    return p_return(b,s,MRK_RP_WATCH_REGISTER,P_WATCH,0);
}
static int p_authenticate(MRKRemovalPeer *b,PeerCall *s){
    if(!p_token(b,s,1)||!p_guest(b,s)||!p_watch(b,s)||!p_token(b,s,0)||!p_refresh_code(b,s))return 0;
    int exit=p_watch_poll(b,s,0);if(exit!=0)return p_fail(b,57,exit<0&&b->report.unknown);
    return p_token(b,s,0);
}
static int p_recheck(MRKRemovalPeer *b,PeerCall *s){
    if(b->report.stage!=4||b->report.exit_observed||!p_token(b,s,0)||!p_refresh_code(b,s))return 0;
    int exit=p_watch_poll(b,s,0);if(exit!=0)return p_fail(b,58,exit<0&&b->report.unknown);
    return p_token(b,s,0);
}
static unsigned p_direction(MRKRemovalPeer *b){
    int parent_sends=b->report.frame_index==0||b->report.frame_index==3;
    return (parent_sends==(b->input.role==MRK_REMOVE_PARENT))?1:2;
}
static uint32_t p_length(const uint8_t *frame){return ((uint32_t)frame[0]<<24)|((uint32_t)frame[1]<<16)|((uint32_t)frame[2]<<8)|frame[3];}
static int p_frame_begin(MRKRemovalPeer *b,PeerCall *s,const uint8_t *frame,size_t size){
    if(b->report.frame_index>=4||b->report.frame_started||(!b->copied&&b->io_direction==2))return p_fail(b,59,0);
    if(!p_recheck(b,s))return 0;
    unsigned direction=p_direction(b);
    if(direction==1){
        if(!frame||size<5||size>MRK_REMOVE_PEER_FRAME||p_length(frame)==0||p_length(frame)>4096||p_length(frame)+4!=size)return p_fail(b,60,0);
        memcpy(b->frame,frame,size);b->io_expected=(uint32_t)size;
    }else{if(frame||size)return p_fail(b,61,0);memset(b->frame,0,sizeof(b->frame));b->io_expected=4;}
    b->io_direction=direction;b->io_prefix=direction==1;b->copied=0;
    b->report.frame_size=0;b->report.frame_offset=0;b->report.frame_started=1;return 1;
}
// DATA selector shared with the actual terminal-send path. The returned count
// is the original send result, never a caller's claimed completion. This only
// chooses the required POST; it cannot authenticate a peer or create a watch.
static int p_whole_ack_send(uint32_t role,uint32_t index,uint32_t direction,
    uint32_t expected,uint32_t before,int64_t returned){
    return role==MRK_REMOVE_PARENT&&index==3&&direction==1
        &&expected>=5&&expected<=MRK_REMOVE_PEER_FRAME&&before<expected
        &&returned>0&&(uint64_t)returned==(uint64_t)(expected-before);
}
int mrk_removal_peer_ack_post_data(uint32_t role,uint32_t index,uint32_t direction,
    uint32_t expected,uint32_t before,int64_t returned,int32_t watch_result){
    if(!p_whole_ack_send(role,index,direction,expected,before,returned))return 0;
    // Only the real original watch's pending/NOTE_EXIT returns permit this
    // terminal POST. An error or any unknown result must still refuse.
    return watch_result==0||watch_result==1?1:-1;
}
static int p_frame_poll(MRKRemovalPeer *b,PeerCall *s){
    if(!b->report.frame_started||b->report.frame_index>=4||!p_recheck(b,s))return -1;
    unsigned phase=b->io_direction==1?MRK_RP_SEND:MRK_RP_RECEIVE;
    if(b->io_expected<=b->report.frame_offset||b->io_expected>sizeof(b->frame)
        ||!p_before(b,s,phase,P_CHANNEL,0))return -1;
    const uint32_t offset_before=b->report.frame_offset;
    const size_t need=b->io_expected-offset_before;
    ssize_t n=b->io_direction==1?send(b->fd[P_CHANNEL],b->frame+b->report.frame_offset,need,0)
        :recv(b->fd[P_CHANNEL],b->frame+b->report.frame_offset,need,0);
    int saved=errno;
    if(n==0){b->report.eof=1;p_fail(b,62,0);}
    else if(n<0&&saved!=EAGAIN&&saved!=EWOULDBLOCK)p_fail(b,63,0);
    else if(n>0){if((size_t)n>need)p_fail(b,64,1);else b->report.frame_offset+=(uint32_t)n;}
    if(!p_return(b,s,phase,P_CHANNEL,0))return -1;
    if(p_whole_ack_send(b->input.role,b->report.frame_index,b->io_direction,b->io_expected,offset_before,(int64_t)n)){
        // The same authenticated App may receive the whole Ack and quit before
        // this POST. Keep the owned channel/name, actual return, raw clock,
        // source/owner POST and original watch; do not re-query a departed task.
        // Partial sends and every other frame still require the live recheck.
        if(!p_socket_bound(b,1))return -1;
        int exit=p_watch_poll(b,s,0);
        if(mrk_removal_peer_ack_post_data(b->input.role,b->report.frame_index,b->io_direction,
            b->io_expected,offset_before,(int64_t)n,exit)!=1)return -1;
    }else if(!p_recheck(b,s))return -1;
    if(n<0)return 0;
    if(b->report.frame_offset!=b->io_expected)return 0;
    if(b->io_direction==2&&!b->io_prefix){
        uint32_t size=p_length(b->frame);if(!size||size>4096)return p_fail(b,65,0),-1;
        b->io_prefix=1;b->io_expected=size+4;return 0;
    }
    if(b->io_direction==2&&b->report.frame_index!=1){
        // Only Confirmed may already be followed by its same sender's next
        // Prepared frame. Challenge/Prepared/Ack have no pipelined successor
        // from that sender. Reject extra bytes without allocating or consuming
        // another frame; EOF is a refusal, never process-exit evidence.
        if(!p_before(b,s,MRK_RP_RECEIVE,P_CHANNEL,0))return -1;
        uint8_t extra=0;ssize_t more=recv(b->fd[P_CHANNEL],&extra,1,MSG_PEEK);int error=errno;
        if(more>=0||(error!=EAGAIN&&error!=EWOULDBLOCK)){
            if(more==0)b->report.eof=1;p_fail(b,81,0);
        }
        if(!p_return(b,s,MRK_RP_RECEIVE,P_CHANNEL,0)||!p_recheck(b,s))return -1;
    }
    b->report.frame_size=b->io_expected;b->report.frame_index++;b->report.frame_started=0;return 1;
}
static int p_fd_close(MRKRemovalPeer *b,PeerCall *s,unsigned slot){
    if(b->report.fd_states[slot]==R_EMPTY||b->report.fd_states[slot]==R_CLOSED)return 1;
    if(b->report.fd_states[slot]!=R_OWNED||!p_owned_fd(b,slot,0))return p_fail(b,66,1);
    if(!p_before(b,s,MRK_RP_CLOSE,slot,1))return 0;
    b->report.fd_states[slot]=R_CLOSING;int rc=close(b->fd[slot]);
    if(rc==0){b->fd[slot]=-1;b->report.fd_states[slot]=R_CLOSED;}
    else{b->report.fd_states[slot]=R_UNKNOWN;p_fail(b,67,1);} // NO close retry after EINTR/error.
    return p_return(b,s,MRK_RP_CLOSE,slot,1);
}
static int p_close(MRKRemovalPeer *b,PeerCall *s){
    if(b->close_attempted)return p_fail(b,68,1);b->close_attempted=1;int all=1;
    // Source/code failure does not skip independently known safe consumption.
    // Actual unavailable/error returns retain their own ledger slots forever.
    for(unsigned i=MRK_REMOVE_PEER_CFS;i>0;i--)if(!p_cf_release(b,s,i-1,1))all=0;
    const unsigned order[]={P_CHANNEL,P_LISTENER,P_WATCH};
    for(unsigned i=0;i<3;i++)if(!p_fd_close(b,s,order[i]))all=0;
    for(unsigned i=0;i<MRK_REMOVE_PEER_CFS;i++)if(b->report.cf_states[i]!=R_EMPTY&&b->report.cf_states[i]!=R_CLOSED)all=0;
    for(unsigned i=0;i<MRK_REMOVE_PEER_FDS;i++)if(b->report.fd_states[i]!=R_EMPTY&&b->report.fd_states[i]!=R_CLOSED)all=0;
    if(all&&!b->report.unknown)b->report.closed=1;
    return b->report.closed;
}
size_t mrk_removal_peer_bytes(void){
    // Supplied book/frame +maximum hash stack +bounded Security strings/path
    // and certificate bytes. Framework/allocator internals are NOT claimed.
    // This is charged to aggregate64MiB, separately from task/closure64KiB.
    return sizeof(MRKRemovalPeer)+65536+8192+MRK_INSTALL_PRODUCER_CERTIFICATE_MAX;
}
void *mrk_removal_peer_new(const mrk_removal_peer_inputs *input){
    if(!input||input->version!=1||(input->role!=MRK_REMOVE_PARENT&&input->role!=MRK_REMOVE_APP)
        ||getuid()!=geteuid()||getgid()!=getegid()||(input->role==MRK_REMOVE_PARENT?(getuid()!=0||getgid()!=0):getuid()==0)
        ||!input->start||input->work<input->start||input->hard<input->start
        ||input->work-input->start!=UINT64_C(110000000000)||input->hard-input->start!=UINT64_C(120000000000)
        ||input->hard>((UINT64_C(1)<<61)-1)||!p_nonzero(input->request_id,16)
        ||!input->installed||!input->installed_size||input->installed_size>65536
        ||!input->remove||!input->remove_size||input->remove_size>16384
        ||!input->installed_signature||!input->remove_signature
        ||(input->installed_signature_size!=256&&input->installed_signature_size!=384&&input->installed_signature_size!=512)
        ||(input->remove_signature_size!=256&&input->remove_signature_size!=384&&input->remove_signature_size!=512))return NULL;
    MRKRemovalPeer *b=calloc(1,sizeof(*b));if(!b)return NULL;
    b->magic=P_MAGIC;b->pid=getpid();b->uid=getuid();b->gid=getgid();b->thread=pthread_self();b->input=*input;
    b->report.version=1;b->report.role=input->role;b->report.last=input->start;
    for(unsigned i=0;i<MRK_REMOVE_PEER_FDS;i++)b->fd[i]=-1;
    char id[33]={0};static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<16;i++){id[2*i]=hex[input->request_id[i]>>4];id[2*i+1]=hex[input->request_id[i]&15];}
    int a=snprintf(b->request_path,sizeof(b->request_path),P_REQUESTS "/r-%s",id);
    int c=snprintf(b->json_path,sizeof(b->json_path),"%s/request.json",b->request_path);
    int d=snprintf(b->socket_path,sizeof(b->socket_path),"%s/s",b->request_path);
    if(a!=96||c!=109||d!=98||!p_clock(b,0)){memset(b,0,sizeof(*b));free(b);return NULL;}
    return b;
}
int mrk_removal_peer_run(void *raw,uint32_t operation,const uint8_t *frame,size_t size,mrk_removal_peer_gate gate,void *context,mrk_removal_peer_report *out){
    MRKRemovalPeer *b=raw;
    if(!p_original(b)||!out||!gate)return -1;
    if(b->entered||b->retire_attempted){p_fail(b,69,1);*out=b->report;return -1;}
    b->entered=1;b->report.operation=operation;PeerCall scope={gate,context};int result=-1;
    @try{
        if(operation!=MRK_REMOVE_CLOSE&&(b->report.failed||b->report.unknown||b->close_attempted))goto done;
        switch(operation){
            case MRK_REMOVE_SOURCE:
                if(b->report.stage!=0||frame||size){p_fail(b,70,0);break;}
                if(p_source(b,&scope)&&p_static(b,&scope,P_OWN_STATIC,p_own_code(b))
                    &&p_static(b,&scope,P_PEER_STATIC,p_peer_code(b))&&p_self(b,&scope)){b->report.stage=1;result=1;}break;
            case MRK_REMOVE_OPEN:
                if(b->report.stage!=1||frame||size){p_fail(b,71,0);break;}
                if(p_open(b,&scope)){b->report.stage=2;result=1;}break;
            case MRK_REMOVE_CONNECT:
                if(b->report.stage!=2||frame||size){p_fail(b,72,0);break;}
                result=p_connect(b,&scope);if(result==1)b->report.stage=3;break;
            case MRK_REMOVE_AUTHENTICATE:
                if(b->report.stage!=3||frame||size){p_fail(b,73,0);break;}
                if(p_authenticate(b,&scope)){b->report.stage=4;result=1;}break;
            case MRK_REMOVE_FRAME_BEGIN:
                if(b->report.stage!=4){p_fail(b,74,0);break;}
                result=p_frame_begin(b,&scope,frame,size)?1:-1;break;
            case MRK_REMOVE_FRAME_POLL:
                if(b->report.stage!=4||frame||size){p_fail(b,75,0);break;}
                result=p_frame_poll(b,&scope);break;
            case MRK_REMOVE_RECHECK:
                if(frame||size){p_fail(b,76,0);break;}result=p_recheck(b,&scope)?1:-1;break;
            case MRK_REMOVE_EXIT:
                if(b->input.role!=MRK_REMOVE_PARENT||b->report.stage!=4||b->report.frame_index!=4||b->report.frame_started||frame||size){p_fail(b,77,0);break;}
                // After actualack we do not re-query a departed task or create a
                // replacement watch. Only this original registered NOTE_EXIT.
                result=b->report.exit_observed?1:p_watch_poll(b,&scope,1);break;
            case MRK_REMOVE_CLOSE:
                if(frame||size){p_fail(b,78,0);break;}result=p_close(b,&scope)?1:-1;break;
            default:p_fail(b,79,0);break;
        }
        if(result>=0&&!p_point(b,&scope,0,MRK_RP_BOUNDARY,P_NONE,operation==MRK_REMOVE_CLOSE||operation==MRK_REMOVE_EXIT))result=-1;
    done:;
    }@catch(...){
        for(unsigned i=0;i<MRK_REMOVE_PEER_CFS;i++)if(b->report.cf_states[i]==R_ENTERED||b->report.cf_states[i]==R_CLOSING)b->report.cf_states[i]=R_UNKNOWN;
        for(unsigned i=0;i<MRK_REMOVE_PEER_FDS;i++)if(b->report.fd_states[i]==R_ENTERED||b->report.fd_states[i]==R_CLOSING)b->report.fd_states[i]=R_UNKNOWN;
        p_fail(b,80,1);
    }
    b->entered=0;*out=b->report;
    if(b->report.unknown)return -1;
    if(b->report.failed&&operation!=MRK_REMOVE_CLOSE)return -2;
    return result>=0?result:-2;
}
int mrk_removal_peer_copy(void *raw,uint8_t out[MRK_REMOVE_PEER_FRAME],size_t *size){
    MRKRemovalPeer *b=raw;if(!p_original(b)||!out||!size)return 0;*size=0;
    if(b->entered||b->report.failed||b->report.unknown||b->report.stage!=4||b->report.frame_started||b->copied
        ||b->io_direction!=2||b->report.frame_size<5||b->report.frame_size>MRK_REMOVE_PEER_FRAME||!p_clock(b,0)||!p_borrowed_post(b))return 0;
    memcpy(out,b->frame,b->report.frame_size);*size=b->report.frame_size;b->copied=1;
    // This copies DATA only. Rust owes actual same-peer recheck+ownerPOST before
    // one fixed Challenge decoder can reach the private cutoff constructor.
    return 1;
}
int mrk_removal_peer_retire(void *raw,mrk_removal_peer_report *out){
    MRKRemovalPeer *b=raw;if(!p_original(b)||!out||b->entered||b->retire_attempted||!b->report.closed||b->report.unknown
        ||b->report.calls!=b->report.returned||!p_clock(b,1))return 0;
    for(unsigned i=0;i<MRK_REMOVE_PEER_CFS;i++)if(b->cf[i]||(b->report.cf_states[i]!=R_EMPTY&&b->report.cf_states[i]!=R_CLOSED))return 0;
    for(unsigned i=0;i<MRK_REMOVE_PEER_FDS;i++)if(b->fd[i]!=-1||(b->report.fd_states[i]!=R_EMPTY&&b->report.fd_states[i]!=R_CLOSED))return 0;
    b->retire_attempted=1;b->report.operation=MRK_REMOVE_CLOSE;*out=b->report;
    memset(b,0,sizeof(*b));free(b);return 1;
}
