// Fixed Android registration IPC. No process spawn, payload path, descriptor,
// publisher pointer or filesystem callback crosses this native service boundary.
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <ServiceManagement/ServiceManagement.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/event.h>
#include "vault_helper_control.h"

#ifndef MRK_ANDROID_APP_REQUIREMENT
#define MRK_ANDROID_APP_REQUIREMENT ""
#endif
#ifndef MRK_ANDROID_HELPER_REQUIREMENT
#define MRK_ANDROID_HELPER_REQUIREMENT ""
#endif
#if defined(MRK_E2_NATIVE_FIXTURE)
#include "e2_native_fixture_fixed.h"
#include "e2_native_fixture_identity.h"
#define MRK_ANDROID_SERVICE_NAME @MRK_E2_FIXTURE_SERVICE
#else
#define MRK_ANDROID_SERVICE_NAME @"dev.mobile-release-kit.desktop.android-register"
#endif
#if defined(MRK_E2_NATIVE_FIXTURE)
#include "e2_native_fixture_fixed.h"
#define MRK_ANDROID_SERVICE_PLIST @MRK_E2_FIXTURE_PLIST
#else
#define MRK_ANDROID_SERVICE_PLIST @"dev.mobile-release-kit.desktop.android-register.plist"
#endif
#define MRK_ANDROID_MAX_FRAME 65536u
#define MRK_ANDROID_STATUS_BYTES 256u
#define MRK_ANDROID_QUERY_REQUEST_BYTES 128u
#define MRK_ANDROID_PREPARE_BYTES 64u
#define MRK_ANDROID_QUERY_REPLY_BYTES (256u+8192u)
#define MRK_ANDROID_MAINTENANCE_BYTES 384u
typedef struct {
    uint32_t version,bytes;uint8_t instance[16],operation[16],nonce[16];
    uint64_t number;uint32_t account,slot;uint64_t acceptance,origin,work,hard,cut,cutoff;
    uint8_t source[40],release[64],target[24],reserved[8];
} mrk_maintenance_binding_data;
typedef int32_t (*mrk_image_take_read)(const mrk_maintenance_binding_data *,int32_t *);
typedef struct {
    uint32_t version,bytes,role,reserved;uint8_t instance[16],source[40],release[64],target[24];
    mrk_image_take_read take_read;
} mrk_image_host_data;
_Static_assert(sizeof(mrk_maintenance_binding_data)==256 && sizeof(mrk_image_host_data)==168,
    "E1/Rust native DATA ABI");
#define MRK_ANDROID_CLIENT_MAGIC UINT64_C(0x4d524b4152434c31)

typedef void (*mrk_android_notify)(const void *, uint64_t, uint32_t);
typedef uint32_t (*mrk_android_admit)(const void *, uint32_t);
typedef int (*mrk_android_exchange)(const void *, uint32_t, const uint8_t *, size_t, uint64_t, uint8_t *);
typedef struct {
    const void *(*retain)(const void *);
    void (*release)(const void *);
    int (*acquire)(const void *,const uint8_t *,size_t,uint64_t *,uint8_t **);
    void (*backing)(const void *,uint64_t);
    void (*finish)(const void *,uint64_t,uint32_t);
    int (*idle)(const void *);
} mrk_android_client_data_api;
typedef struct {
    const void *data;
    void (*backing)(const void *,uint64_t);
    void (*release)(const void *);
    uint64_t generation;
} mrk_android_backing_capture;
typedef struct { void *client; uint32_t bytes; } mrk_android_reply_capture;
_Static_assert(2*sizeof(mrk_android_backing_capture)+3*sizeof(mrk_android_reply_capture)+2*sizeof(void *)<=128u,
    "supplied client callback capture high-water; runtime block internals are separate");

@protocol MRKAndroidRegister
// Always has a reply. There is no reverse call/exported client object. In
// particular, never use a synchronous request cycle between client and helper.
- (void)exchange:(NSData *)input reply:(void (^)(NSData *))reply;
// Distinct closed read-only role on the same authenticated fixed service.
- (void)query:(NSData *)input reply:(void (^)(NSData *))reply;
// First immutable connection admission; never a cleanup retry or role setter.
- (void)prepare:(NSData *)input reply:(void (^)(NSData *))reply;
// Four closed private maintenance methods; only BeginDrain carries a handle.
- (void)challengeA:(NSData *)input reply:(void (^)(NSData *))reply;
- (void)challengeB:(NSData *)input reply:(void (^)(NSData *))reply;
- (void)beginDrain:(NSData *)input reply:(void (^)(NSData *,NSFileHandle *))reply;
- (void)tailReceived:(NSData *)input;
@end

typedef struct {
    uint32_t version, entered, native_call, returned, unknown, slots[8];
    uint32_t calls, returns, first_call;
    int32_t first_code;
    uint32_t callbacks, callback_returns, peer, reserved;
} mrk_android_client_facts_data;
_Static_assert(sizeof(mrk_android_client_facts_data) == 84, "Rust/C fixed fact layout");

typedef struct {
    uint64_t magic;
    const void *context;
    mrk_android_notify notify;
    mrk_android_admit admit;
    mrk_android_client_data_api data;
    mrk_android_client_facts_data facts;
    id objects[8];
    pthread_t thread;
    uint32_t thread_bound, reply_count, error_count, role, reply_bytes;
    // Slot7 is tagged raw watcher custody, never an ObjC id cast.
    int watcher_fd,tail_fd;pid_t peer_pid;uint32_t maintenance_phase,tail_valid,tail_eof,peer_exited;
    struct stat tail_identity;
#if defined(MRK_E2_NATIVE_FIXTURE)
    void *fixture_identity;mrk_e2_fixture_identity_facts fixture_identity_facts;
#endif
#if defined(MRK_E2_NATIVE_FIXTURE) && MRK_E2_NATIVE_FIXTURE == 1
    // 0=inert,1=inside the fixed one-shot call,2=actual common-call return.
    // Neither this marker nor phase4 proves that BeginDrain's selector ran.
    uint32_t e2_missing_b;
#endif
    uint8_t reply[MRK_ANDROID_QUERY_REPLY_BYTES];
} mrk_android_client;
_Static_assert(sizeof(mrk_android_client) <= 16384u, "project-owned client inline allocation bound");

static uint64_t android_now(void) {
    uint64_t now=0; return mrk_vault_uptime(&now) ? now : 0;
}
static int client_valid(mrk_android_client *c) {
    return c && c->magic==MRK_ANDROID_CLIENT_MAGIC && c->notify && c->admit && c->context
        && c->data.retain && c->data.release && c->data.acquire && c->data.backing && c->data.finish && c->data.idle
        && ((c->role==1 && c->reply_bytes==MRK_ANDROID_STATUS_BYTES)
            || (c->role==2 && c->reply_bytes==MRK_ANDROID_QUERY_REPLY_BYTES)
            || (c->role==3 && c->reply_bytes==MRK_ANDROID_MAINTENANCE_BYTES));
}
static void client_failure(mrk_android_client *c, int error, uint32_t unknown) {
    if (!client_valid(c)) return;
    // Publish earliest native F BEFORE status/native-book/queue projection.
    uint64_t first=android_now(); c->notify(c->context,first,unknown);
    if (!c->facts.first_call) {
        c->facts.first_call=c->facts.calls;
        c->facts.first_code=error?error:EIO;
    }
    if (unknown) c->facts.unknown=1;
}
static int client_point(mrk_android_client *c,uint32_t cleanup) {
    return client_valid(c) && cleanup<=1 && (!c->facts.unknown || cleanup)
        && c->admit(c->context,cleanup)==1;
}

#if defined(MRK_E2_NATIVE_FIXTURE)
static uint32_t client_identity_point(void *raw,uint32_t phase,uint32_t edge,uint32_t cleanup,uint64_t now,uint32_t outcome) {
    (void)phase;mrk_android_client *c=raw;
    if (!client_valid(c) || edge>1 || cleanup>1 || outcome>2) return 2;
    const uint32_t unknown=!now || now>((UINT64_C(1)<<61)-1) || outcome==2;
    if (unknown || outcome) {
        c->notify(c->context,now,unknown); // actual raw F precedes any projection
        if (!c->facts.first_call) { c->facts.first_call=c->facts.calls;c->facts.first_code=EIO; }
        if (unknown) c->facts.unknown=1;
    }
    return client_point(c,cleanup)?1:(unknown?2:0);
}
int mrk_android_e2_fixture_client_identity_facts(void *raw,mrk_e2_fixture_identity_facts *out) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !out || c->facts.native_call) return 0;
    *out=c->fixture_identity_facts;return 1;
}
#endif

static int client_enter(mrk_android_client *c,uint32_t cleanup) {
    if (!client_valid(c) || c->facts.native_call || c->facts.calls>=400000u
        || !c->thread_bound || !pthread_equal(c->thread,pthread_self())) {
        client_failure(c,EINVAL,1); return 0;
    }
    if (!client_point(c,cleanup)) return 0;
    c->facts.calls++; c->facts.native_call=1; c->facts.returned=0; return 1;
}
static int client_leave(mrk_android_client *c,int result) {
    if (!c->facts.native_call || c->facts.returns>=c->facts.calls) {
        client_failure(c,EINVAL,1); return 0;
    }
    c->facts.returns++; c->facts.native_call=0; c->facts.returned=1; return result;
}
static void client_exception(mrk_android_client *c) {
    client_failure(c,EIO,1);
    for (unsigned i=0;i<8;i++) if (c->facts.slots[i]==1 || c->facts.slots[i]==3) c->facts.slots[i]=5;
}
static int client_take(mrk_android_client *c,unsigned slot,id object) {
    if (!object) {
        c->facts.slots[slot]=4; client_failure(c,ENOMEM,0); return 0;
    }
    // Actual reference custody precedes any post-return STOP or validation.
    c->objects[slot]=object; c->facts.slots[slot]=2; return 1;
}
int mrk_android_identity_available(void) {
    // Empty is deliberately unavailable. No ad-hoc, entitlement-only, any-team
    // or unsigned requirement is synthesized when shipping identity is missing.
    return sizeof(MRK_ANDROID_APP_REQUIREMENT)>1 && sizeof(MRK_ANDROID_HELPER_REQUIREMENT)>1;
}
size_t mrk_android_client_bytes(void) { return sizeof(mrk_android_client); }
void *mrk_android_client_new(const void *context,mrk_android_notify notify,mrk_android_admit admit,
    const mrk_android_client_data_api *data) {
    if (!context || !notify || !admit || !data || !data->retain || !data->release || !data->acquire
        || !data->backing || !data->finish || !data->idle) return NULL;
    mrk_android_client *c=calloc(1,sizeof(*c));
    if (c) {
        c->magic=MRK_ANDROID_CLIENT_MAGIC; c->context=context; c->notify=notify; c->admit=admit; c->data=*data;
        c->facts.version=1; c->facts.peer=UINT32_MAX;
#if defined(MRK_E2_NATIVE_FIXTURE)
        c->fixture_identity_facts.version=1;c->fixture_identity_facts.bytes=sizeof(c->fixture_identity_facts);
        c->fixture_identity_facts.role=2;
#endif
        c->role=1; c->reply_bytes=MRK_ANDROID_STATUS_BYTES;c->watcher_fd=-1;c->tail_fd=-1;c->peer_pid=-1;
    }
    return c;
}
// The context role is selected ONLY while the fresh inert allocation is being
// returned to its same registered owner. There is no setter/reset/reuse API.
void *mrk_android_query_client_new(const void *context,mrk_android_notify notify,mrk_android_admit admit,
    const mrk_android_client_data_api *data) {
    mrk_android_client *c=mrk_android_client_new(context,notify,admit,data);
    if (c) { c->role=2; c->reply_bytes=MRK_ANDROID_QUERY_REPLY_BYTES; }
    return c;
}
void *mrk_android_maintenance_client_new(const void *context,mrk_android_notify notify,mrk_android_admit admit,
    const mrk_android_client_data_api *data) {
    mrk_android_client *c=mrk_android_client_new(context,notify,admit,data);
    if (c) { c->role=3;c->reply_bytes=MRK_ANDROID_MAINTENANCE_BYTES; }
    return c;
}
int mrk_android_client_begin(void *raw) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || c->facts.entered
#if !defined(MRK_E2_NATIVE_FIXTURE)
        || !mrk_android_identity_available()
#endif
        || getuid()==0 || getuid()!=geteuid()) return 0;
    c->facts.entered=1; c->thread=pthread_self(); c->thread_bound=1;
    if (!client_enter(c,0)) return 0;
    int ready=0;
    @try {
        c->facts.slots[0]=1;
        if (!client_take(c,0,[[NSAutoreleasePool alloc] init])) goto done;
        if (!client_point(c,0)) goto done;
#if defined(MRK_E2_NATIVE_FIXTURE)
        const mrk_e2_fixture_checkpoint_api identity_api={c,client_identity_point};
        c->fixture_identity=mrk_e2_fixture_client_identity_new(&identity_api,&c->fixture_identity_facts);
        if (!c->fixture_identity || !mrk_e2_fixture_identity_prepare(c->fixture_identity,&identity_api,&c->fixture_identity_facts)
            || !c->fixture_identity_facts.ready) goto done;
#endif
        c->facts.slots[1]=1;
        if (!client_take(c,1,[[NSXPCInterface interfaceWithProtocol:@protocol(MRKAndroidRegister)] retain])) goto done;
        if (c->role==3) {
            [(NSXPCInterface *)c->objects[1] setClasses:[NSSet setWithObject:[NSFileHandle class]]
                forSelector:@selector(beginDrain:reply:) argumentIndex:1 ofReply:YES];
        }
        if (!client_point(c,0)) goto done;
        c->facts.slots[2]=1;
        if (!client_take(c,2,[[NSXPCConnection alloc] initWithMachServiceName:MRK_ANDROID_SERVICE_NAME options:NSXPCConnectionPrivileged])) goto done;
        NSXPCConnection *connection=c->objects[2];
        [connection setRemoteObjectInterface:c->objects[1]];
        if (!client_point(c,0)) goto done;
        // Exactly once before resume; public API, fixed source/build requirement.
#if defined(MRK_E2_NATIVE_FIXTURE)
        if (!mrk_e2_fixture_identity_recheck(c->fixture_identity,0,&identity_api,&c->fixture_identity_facts)) goto done;
        CFStringRef requirement=mrk_e2_fixture_resident_requirement(c->fixture_identity);
        if (!requirement) { client_failure(c,EIO,1);goto done; }
        [connection setCodeSigningRequirement:(NSString *)requirement];
        if (!mrk_e2_fixture_identity_recheck(c->fixture_identity,0,&identity_api,&c->fixture_identity_facts)) goto done;
#else
        [connection setCodeSigningRequirement:@MRK_ANDROID_HELPER_REQUIREMENT];
#endif
        if (!client_point(c,0)) goto done;
        [connection resume];
        ready=client_point(c,0);
    } @catch (NSException *exception) {
        (void)exception; client_exception(c);
    }
done:
    return client_leave(c,ready);
}
// This is the whole original synchronous proxy invocation. Apple's documented
// contract says both reply/error blocks run ON THIS CALLING THREAD before the
// message to the proxy returns. The enclosing returned message, not a flag set
// inside either block, establishes callback return. Proxy/data/pool releases
// remain additional explicit originals; an exception retains Unknown.
//
// https://developer.apple.com/documentation/foundation/nsxpcconnection/synchronousremoteobjectproxywitherrorhandler(_:)
static int maintenance_peer_poll(mrk_android_client *c);
static int client_exchange(void *raw,const uint8_t *input,size_t count,uint32_t cleanup,uint32_t preparing,uint8_t *output) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !input || c->facts.slots[2]!=2 || cleanup>1
        || !(preparing<=1 || preparing==3 || preparing==4 || preparing==5 || preparing==7)
        || (preparing!=7 && !output)) return 0;
    const uint32_t maintenance=preparing>=3,receipt=preparing==7;
    if (maintenance != (c->role==3)) return 0;
    const uint32_t response_bytes=preparing==1?MRK_ANDROID_PREPARE_BYTES:c->reply_bytes;
    if (maintenance) {
        const uint32_t kind=((uint32_t)input[12]<<24)|((uint32_t)input[13]<<16)|((uint32_t)input[14]<<8)|input[15];
        if (count!=MRK_ANDROID_MAINTENANCE_BYTES || memcmp(input,"MRKMNT01",8)
            || kind!=(preparing==3?1:preparing==4?3:preparing)
            || (!receipt && cleanup) || (receipt && !cleanup)) return 0;
        const uint32_t drain_phase=c->maintenance_phase==3
#if defined(MRK_E2_NATIVE_FIXTURE) && MRK_E2_NATIVE_FIXTURE == 1
            || (c->maintenance_phase==2 && c->e2_missing_b==1)
#endif
            ;
        if ((preparing==3 && c->maintenance_phase!=0) || (preparing==4 && c->maintenance_phase!=2)
            || (preparing==5 && !drain_phase)
            || (receipt && (c->maintenance_phase!=4 || !c->tail_valid || c->facts.slots[6]!=2))) return 0;
    } else if (preparing==1) {
        if (cleanup || count!=MRK_ANDROID_PREPARE_BYTES || memcmp(input,"MRKATP01",8)!=0
            || (c->role==1 && input[32]!=1) || (c->role==2 && input[32]!=2 && input[32]!=3)) return 0;
    } else if (c->role==1) {
        if (count<32 || count>MRK_ANDROID_MAX_FRAME || (cleanup && input[28]==0)) return 0;
    } else {
        if (count!=MRK_ANDROID_QUERY_REQUEST_BYTES) return 0;
        uint32_t kind=((uint32_t)input[12]<<24)|((uint32_t)input[13]<<16)|((uint32_t)input[14]<<8)|input[15];
        if (cleanup && kind!=4 && kind!=5) return 0;
    }
    // Cleanup accepts only fixed STATUS/STOP DATA, never Scan/Read/Finish or Push.
    // No second pool/proxy/request allocation while an old backing is retained.
    if (c->data.idle(c->context)!=1) { client_failure(c,EBUSY,0); return 0; }
    if (!client_enter(c,cleanup)) return 0;
    int ready=0;
    uint64_t request_generation=0;
    for (unsigned i=3;i<=5;i++) {
        if (c->facts.slots[i]!=0 && c->facts.slots[i]!=4) {
            client_failure(c,EINVAL,1); goto done;
        }
        c->facts.slots[i]=0; c->objects[i]=nil;
    }
    c->reply_count=0; c->error_count=0; memset(c->reply,0,sizeof(c->reply));
    if (maintenance) c->maintenance_phase=preparing==3?1:preparing==4?3:preparing==5?4:5;
    @try {
        c->facts.slots[3]=1;
        if (!client_take(c,3,[[NSAutoreleasePool alloc] init])) goto done;
        if (!client_point(c,cleanup)) goto done;
        uint8_t *request_arena=NULL;
        if (c->data.acquire(c->context,input,count,&request_generation,&request_arena)!=1
            || !request_arena || !request_generation) { client_failure(c,EBUSY,0); goto done; }
        const void *leased=c->data.retain(c->context);
        if (!leased) { client_failure(c,ENOMEM,1); goto done; }
        const mrk_android_backing_capture backing={leased,c->data.backing,c->data.release,request_generation};
        c->facts.slots[5]=1;
        // The lease owns the SAME Rust Arc DATA, not this native client/book.
        // On nil/exception its possible capture remains retained and Unknown;
        // there is no guessed release, arena replacement or copying fallback.
        NSData *request_data=[[NSData alloc] initWithBytesNoCopy:request_arena length:count
            deallocator:^(void *bytes,NSUInteger length) {
                (void)bytes;(void)length;
                backing.backing(backing.data,backing.generation);
                backing.release(backing.data); // Last use of this retained DATA.
            }];
        if (!client_take(c,5,request_data)) { client_failure(c,ENOMEM,1); goto done; }
        if (!client_point(c,cleanup)) goto done;
        c->facts.slots[4]=1;
        id proxy=nil;
        if (receipt) {
            // Documented one-way route has NO error/reply block. In particular,
            // never capture the raw book in an asynchronously delivered block.
            proxy=[(NSXPCConnection *)c->objects[2] remoteObjectProxy];
        } else proxy=[(NSXPCConnection *)c->objects[2] synchronousRemoteObjectProxyWithErrorHandler:^(NSError *error) {
            (void)error;
            c->facts.callbacks++;
            if (!pthread_equal(c->thread,pthread_self())) client_failure(c,EINVAL,1);
            // Never format/publish a raw NSError or retain its private message.
            c->error_count++; client_failure(c,ENOTCONN,0);
            c->facts.callback_returns++;
        }];
        if (!client_take(c,4,[proxy retain])) goto done;
        if (!client_point(c,cleanup)) goto done;
        void (^receive)(NSData *)=^(NSData *reply) {
            c->facts.callbacks++;
            @try {
                if (!pthread_equal(c->thread,pthread_self()) || c->reply_count || !reply
                    || [reply length]!=response_bytes || ![reply bytes]) {
                    client_failure(c,EPROTO,1);
                } else {
                    memcpy(c->reply,[reply bytes],response_bytes); c->reply_count++;
                }
            } @catch (NSException *exception) {
                (void)exception; client_exception(c);
            }
            c->facts.callback_returns++;
        };
        // The same already-registered watcher is sampled at the last native
        // work cut before BeginDrain. An observed exit can never cut a new peer.
        if (preparing==5 && (!maintenance_peer_poll(c) || c->peer_exited || !client_point(c,0))) {
            client_failure(c,ENOTCONN,0);goto done;
        }
        if (receipt) [(id<MRKAndroidRegister>)c->objects[4] tailReceived:c->objects[5]];
        else if (preparing==3) [(id<MRKAndroidRegister>)c->objects[4] challengeA:c->objects[5] reply:receive];
        else if (preparing==4) [(id<MRKAndroidRegister>)c->objects[4] challengeB:c->objects[5] reply:receive];
        else if (preparing==5) [(id<MRKAndroidRegister>)c->objects[4] beginDrain:c->objects[5] reply:^(NSData *reply,NSFileHandle *handle) {
            // SAME synchronous-return contract as the DATA receive block.
            receive(reply);
            @try {
                if (handle) {
                    if (c->facts.slots[6]!=0 || ![handle isKindOfClass:[NSFileHandle class]]) client_failure(c,EPROTO,1);
                    else { c->facts.slots[6]=1;if (!client_take(c,6,[handle retain])) client_failure(c,EIO,1); }
                }
            } @catch (NSException *exception) { (void)exception;client_exception(c); }
        }];
        else if (preparing==1) [(id<MRKAndroidRegister>)c->objects[4] prepare:c->objects[5] reply:receive];
        else if (c->role==1) [(id<MRKAndroidRegister>)c->objects[4] exchange:c->objects[5] reply:receive];
        else [(id<MRKAndroidRegister>)c->objects[4] query:c->objects[5] reply:receive];
        // The ACTUAL enclosing synchronous call returned on the same original
        // worker. There are no client interruption/invalidation/reverse handlers.
        if (c->facts.callbacks!=c->facts.callback_returns || (!receipt && c->reply_count!=1) || (receipt && c->reply_count!=0) || c->error_count
            || c->facts.unknown) { client_failure(c,EPROTO,c->facts.unknown); goto done; }
        if (!client_point(c,cleanup)) goto done;
        c->facts.peer=[(NSXPCConnection *)c->objects[2] effectiveUserIdentifier];
        if (c->facts.peer!=0) { client_failure(c,EPERM,0); goto done; }
        if (maintenance) {
            const pid_t peer=[(NSXPCConnection *)c->objects[2] processIdentifier];
            if (peer<=1 || (preparing!=3 && peer!=c->peer_pid)) { client_failure(c,EPROTO,1);goto done; }
            if (preparing==3) c->peer_pid=peer;
        }
        ready=1;
    } @catch (NSException *exception) {
        (void)exception; client_exception(c);
    }
done:
    client_leave(c,ready);
    // The return value cannot skip these original per-call object closes. They
    // execute in reverse custody order, including the per-call autorelease pool.
    const unsigned call_release_order[3]={4,5,3};
    for (unsigned ordinal=0;ordinal<3;ordinal++) {
        const unsigned slot=call_release_order[ordinal];
        if (c->facts.slots[slot]!=2) continue;
        if (!client_point(c,1)) { ready=0; break; }
        if (!client_enter(c,1)) { ready=0; break; }
        c->facts.slots[slot]=3;
        @try {
            [c->objects[slot] release]; c->objects[slot]=nil; c->facts.slots[slot]=4;
        } @catch (NSException *exception) {
            (void)exception; client_exception(c); ready=0;
        }
        client_leave(c,c->facts.slots[slot]==4);
    }
    const uint32_t request_known=!c->facts.unknown && c->facts.native_call==0
        && c->facts.calls==c->facts.returns && c->facts.callbacks==c->facts.callback_returns
        && c->facts.slots[3]==4 && c->facts.slots[4]==4 && c->facts.slots[5]==4;
    if (ready && request_known && !receipt) memcpy(output,c->reply,response_bytes);
    // Ends only this original DATA borrow. Deallocator delivery may still be
    // pending; native returns do not credit/reuse its retained backing.
    if (request_generation) c->data.finish(c->context,request_generation,request_known);
    return ready && request_known;
}
int mrk_android_client_exchange(void *raw,const uint8_t *input,size_t count,uint32_t cleanup,uint8_t *output) {
    return client_exchange(raw,input,count,cleanup,0,output);
}
int mrk_android_client_prepare(void *raw,const uint8_t *input,uint8_t *output) {
    return client_exchange(raw,input,MRK_ANDROID_PREPARE_BYTES,0,1,output);
}
int mrk_android_maintenance_exchange(void *raw,uint32_t method,const uint8_t *input,uint8_t *output) {
    if (method!=3 && method!=4 && method!=5 && method!=7) return 0;
#if defined(MRK_E2_NATIVE_FIXTURE) && MRK_E2_NATIVE_FIXTURE == 1
    // Ordinary method5 still REQUIRES B, including in a fixture build. Only
    // the fixed entry below can spend the phase2 exception.
    mrk_android_client *c=raw;
    if (method==5 && (!client_valid(c) || c->maintenance_phase!=3 || c->e2_missing_b)) return 0;
#endif
    return client_exchange(raw,input,MRK_ANDROID_MAINTENANCE_BYTES,method==7,method,output);
}
#if defined(MRK_E2_NATIVE_FIXTURE) && MRK_E2_NATIVE_FIXTURE == 1
int mrk_android_e2_fixture_missing_b(void *raw,const uint8_t *input,uint8_t *output) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !input || !output || c->role!=3 || c->e2_missing_b
        || c->thread_bound!=1 || !pthread_equal(c->thread,pthread_self())
        || c->facts.entered!=1 || c->facts.returned!=1 || c->facts.native_call || c->facts.unknown
        || c->facts.calls!=c->facts.returns || c->facts.callbacks!=c->facts.callback_returns
        || c->facts.peer!=0 || c->maintenance_phase!=2 || c->facts.slots[7]!=2
        || c->watcher_fd<3 || c->peer_pid<=1 || c->facts.slots[6]!=0 || c->objects[6]!=nil
        || c->tail_fd!=-1 || c->tail_valid || c->tail_eof) return 0;
    c->e2_missing_b=1; // One possible attempt is spent BEFORE the common call.
    const int returned=client_exchange(raw,input,MRK_ANDROID_MAINTENANCE_BYTES,0,5,output);
    c->e2_missing_b=2; // Actual call return only; Rust must decode the real reply.
    return returned;
}
#endif
static int maintenance_peer_poll(mrk_android_client *c) {
    if (c->facts.slots[7]!=2 || c->watcher_fd<3 || c->peer_pid<=1) return 0;
    if (c->peer_exited) return 1;
    struct kevent event;memset(&event,0,sizeof(event));const struct timespec zero={0,0};
    const int count=kevent(c->watcher_fd,NULL,0,&event,1,&zero);
    if (count==0) return 1;
    const uint16_t allowed=EV_ADD|EV_ENABLE|EV_ONESHOT|EV_EOF|EV_CLEAR;
    if (count!=1 || event.ident!=(uintptr_t)c->peer_pid || event.filter!=EVFILT_PROC
        || (event.flags&~allowed) || !(event.flags&EV_EOF) || event.fflags!=NOTE_EXIT || event.udata) {
        client_failure(c,EPROTO,1);return 0;
    }
    c->peer_exited=1;return 1;
}
#if defined(MRK_E2_NATIVE_FIXTURE) && MRK_E2_NATIVE_FIXTURE == 1
int mrk_android_e2_fixture_no_tail_exit(void *raw,uint32_t *exited) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !exited || c->role!=3 || c->e2_missing_b!=2
        || c->thread_bound!=1 || !pthread_equal(c->thread,pthread_self())
        || c->facts.entered!=1 || c->facts.returned!=1 || c->facts.native_call || c->facts.unknown
        || c->facts.calls!=c->facts.returns || c->facts.callbacks!=c->facts.callback_returns
        || c->maintenance_phase!=4 || c->reply_count!=1 || c->error_count
        || c->facts.slots[7]!=2 || c->watcher_fd<3 || c->peer_pid<=1
        || c->facts.slots[6]!=0 || c->objects[6]!=nil || c->tail_fd!=-1
        || c->tail_valid || c->tail_eof) return 0;
    *exited=0;
    if (!client_enter(c,1)) return 0;
    // No new watcher, EOF source, PID lookup, admission or release. The same
    // already-owned NOTE_EXIT registration remains owned until normal release.
    const int ready=maintenance_peer_poll(c) && client_point(c,1);
    if (ready) *exited=c->peer_exited;
    return client_leave(c,ready);
}
#endif
int mrk_android_maintenance_watch(void *raw) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || c->role!=3 || c->maintenance_phase!=1 || c->peer_pid<=1
        || c->facts.slots[7]!=0 || !client_enter(c,0)) return 0;
    int ready=0;c->facts.slots[7]=1;
    // One original kqueue. No PID search, signal, replacement or absence proof.
    c->watcher_fd=kqueue();
    if (c->watcher_fd<0) { c->facts.slots[7]=4;client_failure(c,errno,0);goto done; }
    c->facts.slots[7]=2;
    if (c->watcher_fd<3 || fcntl(c->watcher_fd,F_SETFD,FD_CLOEXEC)
        || fcntl(c->watcher_fd,F_GETFD)!=FD_CLOEXEC) { client_failure(c,errno,1);goto done; }
    struct kevent change,receipt;memset(&receipt,0,sizeof(receipt));
    EV_SET(&change,(uintptr_t)c->peer_pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_ONESHOT|EV_RECEIPT,NOTE_EXIT,0,NULL);
    const struct timespec zero={0,0};
    const int count=kevent(c->watcher_fd,&change,1,&receipt,1,&zero);
    if (count!=1 || receipt.ident!=(uintptr_t)c->peer_pid || receipt.filter!=EVFILT_PROC
        || receipt.flags!=EV_ERROR || receipt.data!=0 || receipt.udata) { client_failure(c,EPROTO,0);goto done; }
    if (!maintenance_peer_poll(c) || c->peer_exited || !client_point(c,0)) { client_failure(c,ENOTCONN,0);goto done; }
    c->maintenance_phase=2;ready=1;
done:return client_leave(c,ready);
}
static int maintenance_pipe_same(mrk_android_client *c,int fd,const struct stat *before) {
    struct stat now;const int flags=fcntl(fd,F_GETFL);
    return fd>=3 && flags>=0 && (flags&O_ACCMODE)==O_RDONLY && (flags&O_NONBLOCK)
        && !(flags&(O_APPEND|O_ASYNC)) && fcntl(fd,F_GETFD)==FD_CLOEXEC && !fstat(fd,&now)
        && S_ISFIFO(now.st_mode) && now.st_uid==0 && now.st_dev==before->st_dev
        && now.st_ino==before->st_ino && now.st_mode==before->st_mode
        && now.st_uid==before->st_uid && now.st_gid==before->st_gid
        && now.st_nlink==before->st_nlink && now.st_flags==before->st_flags;
}
int mrk_android_maintenance_receive(void *raw) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || c->role!=3 || c->maintenance_phase!=4 || c->facts.slots[6]!=2
        || c->tail_valid || !client_enter(c,1)) return 0;
    int ready=0;
    @try {
        c->tail_fd=[(NSFileHandle *)c->objects[6] fileDescriptor];
        if (c->tail_fd<3 || c->tail_fd==c->watcher_fd || fstat(c->tail_fd,&c->tail_identity)
            || !maintenance_pipe_same(c,c->tail_fd,&c->tail_identity)) { client_failure(c,EPROTO,1);goto done; }
        c->tail_valid=1;ready=client_point(c,1);
    } @catch (NSException *exception) { (void)exception;client_exception(c); }
done:return client_leave(c,ready);
}
int mrk_android_maintenance_step(void *raw,uint8_t *output,uint32_t capacity,uint32_t *bytes,uint32_t *eof,uint32_t *exited) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || c->role!=3 || c->maintenance_phase!=5 || !output || !bytes || !eof || !exited
        || capacity==0 || capacity>MRK_ANDROID_MAINTENANCE_BYTES+1 || !c->tail_valid
        || c->facts.slots[6]!=2 || !client_enter(c,1)) return 0;
    *bytes=0;*eof=0;*exited=0;int ready=0;
    if (!maintenance_pipe_same(c,c->tail_fd,&c->tail_identity)) { client_failure(c,EPROTO,1);goto done; }
    if (!c->tail_eof) {
        const ssize_t got=read(c->tail_fd,output,capacity);
        if (got<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) { client_failure(c,errno,0);goto done; }
        if (got==0) c->tail_eof=1;
        if (got>0) *bytes=(uint32_t)got;
    }
    if (!maintenance_peer_poll(c) || !client_point(c,1)) goto done;
    *eof=c->tail_eof;*exited=c->peer_exited;ready=1;
done:return client_leave(c,ready);
}
int mrk_android_client_facts(void *raw,mrk_android_client_facts_data *out) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !out || c->facts.native_call) return 0;
    *out=c->facts; return 1;
}
int mrk_android_client_release_one(void *raw,uint32_t slot) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || slot>=8 || c->facts.slots[slot]!=2 || !client_enter(c,1)) return 0;
#if defined(MRK_E2_NATIVE_FIXTURE)
    if (slot==0) {
        for (unsigned i=1;i<8;i++) if (c->facts.slots[i]!=0 && c->facts.slots[i]!=4) return client_leave(c,0);
        if (c->facts.callbacks!=c->facts.callback_returns || c->data.idle(c->context)!=1) return client_leave(c,0);
        const mrk_e2_fixture_checkpoint_api api={c,client_identity_point};
        if (c->fixture_identity && !mrk_e2_fixture_identity_close(&c->fixture_identity,&api,&c->fixture_identity_facts))
            return client_leave(c,0);
        if (c->fixture_identity || c->fixture_identity_facts.unknown
            || (c->fixture_identity_facts.allocated && !c->fixture_identity_facts.consumed)) return client_leave(c,0);
    }
#endif
    c->facts.slots[slot]=3; int ready=0;
    if (c->role==3 && slot==7) {
        const int original=c->watcher_fd;c->watcher_fd=-1; // spend BEFORE consuming close
        if (original>=3 && close(original)==0) { c->facts.slots[slot]=4;ready=1; }
        else { c->facts.slots[slot]=5;client_failure(c,errno,1); }
        return client_leave(c,ready); // No ObjC message, EINTR retry or fd probe.
    }
    @try {
        if (c->role==3 && slot==6) {
            c->tail_fd=-1; // The original NSFileHandle owns the one consuming call.
            NSError *error=nil;const BOOL closed=[(NSFileHandle *)c->objects[slot] closeAndReturnError:&error];
            if (!closed || error) { client_failure(c,EIO,1);goto done; }
            if (!client_point(c,1)) goto done;
        }
        if (slot==2) {
            // Invalidation is not a callback/worker-finality receipt. The only
            // user callbacks were synchronous and actually returned above.
            [((NSXPCConnection *)c->objects[slot]) invalidate];
            if (!client_point(c,1)) goto done;
        }
        [c->objects[slot] release]; c->objects[slot]=nil; c->facts.slots[slot]=4; ready=1;
    } @catch (NSException *exception) {
        (void)exception; client_exception(c);
    }
done:
    if (!ready && c->facts.slots[slot]==3) { c->facts.slots[slot]=5; client_failure(c,EIO,1); }
    return client_leave(c,ready);
}
int mrk_android_client_retire(void *raw) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || c->facts.native_call || c->facts.unknown || c->facts.calls!=c->facts.returns
        || c->facts.callbacks!=c->facts.callback_returns || !client_point(c,1)
        || c->data.idle(c->context)!=1) return 0;
    for (unsigned i=0;i<8;i++) if (c->facts.slots[i]!=0 && c->facts.slots[i]!=4) return 0;
#if defined(MRK_E2_NATIVE_FIXTURE)
    if (c->fixture_identity || c->fixture_identity_facts.unknown
        || (c->fixture_identity_facts.allocated && !c->fixture_identity_facts.consumed)) return 0;
#endif
    c->magic=0; free(c); return 1;
}

#if defined(MRK_ANDROID_REGISTRATION_HELPER)
#import <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>
// One resident listener, eight LIVE native/control contexts, one selected
// payload owner in Rust DATA. No callback receives an original worker or FD.
#define MRK_ANDROID_SERVICE_MAGIC UINT64_C(0x4d524b4152535632)
#define MRK_ANDROID_CONNECTION_LIMIT 8u
typedef struct {
    const void *(*retain)(const void *);
    void (*release)(const void *);
    void (*notify)(const void *,uint64_t,uint32_t);
    uint64_t (*enter)(const void *,uint32_t,uint32_t,uint64_t);
    int (*returned)(const void *,uint32_t,uint64_t,uint64_t,uint32_t);
    uint64_t (*claim)(const void *,uint64_t);
    int (*response)(const void *,uint64_t,uint32_t,const uint8_t *,size_t,uint64_t,uint8_t **,size_t *);
    void (*backing)(const void *,uint64_t);
    void (*finish)(const void *,uint64_t,uint32_t);
    int (*maintenance_body)(const void *,uint32_t,uint32_t,uint64_t,uint32_t);
    int (*tail_binding)(const void *,mrk_maintenance_binding_data *);
    int (*tail_receipt)(const void *,const uint8_t *,size_t,uint64_t);
    int (*tail_ready)(const void *);
    int (*tail_closed)(const void *,uint64_t,uint32_t);
} mrk_android_domain_api;
// Distinct typed callbacks: these own/loan ServiceRegistry, NEVER ServiceDomain.
typedef struct {
    const void *(*retain)(const void *);
    void (*release)(const void *);
    uint64_t (*loan_enter)(const void *,uint64_t);
    int (*loan_return)(const void *,uint64_t,uint64_t,uint32_t);
    int (*closed)(const void *);
    uint64_t (*tail_enter)(const void *,uint64_t);
    int (*tail_return)(const void *,uint64_t,uint64_t,uint32_t);
    void (*failure)(const void *,uint64_t);
} mrk_android_registry_api;
typedef struct {
    const void *(*reserve)(const void *,uint32_t,uint64_t,uint32_t *,uint64_t *);
    const void *(*retain)(const void *);
    void (*release)(const void *);
    void (*notify)(const void *,uint64_t,uint32_t);
    uint64_t (*enter)(const void *,uint32_t,uint32_t,uint64_t);
    int (*returned)(const void *,uint32_t,uint64_t,uint64_t,uint32_t);
    uint64_t (*claim)(const void *,uint64_t);
    int (*response)(const void *,uint64_t,uint32_t,const uint8_t *,size_t,uint64_t,uint8_t **,size_t *);
    void (*backing)(const void *,uint64_t);
    void (*finish)(const void *,uint64_t,uint32_t);
    int (*maintenance_body)(const void *,uint32_t,uint32_t,uint64_t,uint32_t);
    int (*tail_binding)(const void *,mrk_maintenance_binding_data *);
    int (*tail_receipt)(const void *,const uint8_t *,size_t,uint64_t);
    int (*tail_ready)(const void *);
    int (*tail_closed)(const void *,uint64_t,uint32_t);
    mrk_android_registry_api registry;
} mrk_android_service_api;
typedef struct mrk_android_service mrk_android_service;
@interface MRKAndroidData : NSObject {
@public const void *value; mrk_android_domain_api api;
}
- (id)initWithValue:(const void *)input api:(mrk_android_domain_api)functions;
@end
@interface MRKAndroidEndpoint : NSObject <MRKAndroidRegister> {
@public
    const void *value;mrk_android_domain_api api;
    // Native response originals, deliberately OUTSIDE the DATA carrier. These
    // fixed slots never allocate a second pool/reply behind a held backing.
    id response_objects[2];
    uint32_t response_slots[2];
    mrk_image_take_read take_read;NSFileHandle *tail_handle;int32_t tail_fd;
    _Atomic uint32_t tail_state; //0 none,1 entering,2 published,3 control close,4 settled,5 unknown
    uint32_t tail_handle_slot;
}
- (id)initWithValue:(const void *)input api:(mrk_android_domain_api)functions takeRead:(mrk_image_take_read)take;
@end
@interface MRKAndroidListener : NSObject <NSXPCListenerDelegate> {
@public
    mrk_android_service *owner;
    const void *registry;
    mrk_android_registry_api registry_api;
}
- (id)initWithOwner:(mrk_android_service *)input context:(const void *)context api:(mrk_android_registry_api)functions;
@end
typedef struct {
    _Atomic uint32_t state; // 0 empty,1 original admission,2 live,3 closing,4 released,5 unknown
    uint64_t number;
    id objects[4]; // original carrier, connection, interface, endpoint references
    uint32_t slots[4],invalidation;
} mrk_android_connection;
struct mrk_android_service {
    uint64_t magic;
    const void *context;
    mrk_android_service_api api;
    // ONE reusable main-thread pool slot, drained in the same call/context.
    // 0 reserved,1 alloc entered,2 allocated,3 init entered,4 live,
    // 5 consuming call entered,6 actual consumption returned,7 unknown.
    NSAutoreleasePool *pool;
    uint32_t main_slots[3]; // pool, delegate, listener
    uint64_t pool_generation;
    NSXPCListener *listener;
    MRKAndroidListener *delegate;
    mrk_android_connection connections[MRK_ANDROID_CONNECTION_LIMIT];
    pthread_t control_thread;
    _Atomic uint32_t control_bound,accepting,unknown,main_released;
    uint32_t begun,main_call,listener_close,main_references;
    mrk_image_host_data host;
#if defined(MRK_E2_NATIVE_FIXTURE)
    void *fixture_identity;
    mrk_e2_fixture_identity_facts fixture_identity_facts;
#endif
};
typedef struct {
    uint32_t version,operation,known,selectors_entered,selectors_returned;
    uint32_t slots[3],listener_close,control_state,consumed,run_result;
    uint64_t pool_generation;
} mrk_android_service_report;
_Static_assert(sizeof(mrk_android_service_report)==56u,"Rust/C resident returning-report layout");
_Static_assert(sizeof(mrk_android_service)+2*sizeof(mrk_android_service_report)
    +sizeof(mrk_android_registry_api)+2*sizeof(void *)<=16384u,"resident project-owned native cells/capture bound");
_Static_assert(2*sizeof(mrk_android_domain_api)+2*sizeof(mrk_android_backing_capture)+8*sizeof(void *)<=512u,
    "supplied per-context DATA/callback capture bound; not Foundation heap bytes");

static int service_valid(mrk_android_service *s) {
    return s && s->magic==MRK_ANDROID_SERVICE_MAGIC && s->context && s->api.reserve
        && s->api.retain && s->api.release && s->api.notify && s->api.enter && s->api.returned
        && s->api.claim && s->api.response && s->api.backing && s->api.finish
        && s->api.maintenance_body && s->api.tail_binding && s->api.tail_receipt && s->api.tail_ready && s->api.tail_closed
        && s->api.registry.retain && s->api.registry.release && s->api.registry.loan_enter
        && s->api.registry.loan_return && s->api.registry.closed && s->api.registry.tail_enter
        && s->api.registry.tail_return && s->api.registry.failure;
}
static mrk_android_domain_api domain_api(mrk_android_service *s) {
    return (mrk_android_domain_api){s->api.retain,s->api.release,s->api.notify,s->api.enter,s->api.returned,
        s->api.claim,s->api.response,s->api.backing,s->api.finish,s->api.maintenance_body,
        s->api.tail_binding,s->api.tail_receipt,s->api.tail_ready,s->api.tail_closed};
}
static void global_failure(mrk_android_service *s) {
    if (!service_valid(s)) return;
    atomic_store(&s->unknown,1);atomic_store(&s->accepting,0);s->api.registry.failure(s->context,android_now());
}
static void domain_failure(mrk_android_domain_api api,const void *domain,uint32_t unknown) {
    if (domain) api.notify(domain,android_now(),unknown?1:0);
}
static uint64_t domain_enter(mrk_android_domain_api api,const void *domain,uint32_t lane,uint32_t cleanup) {
    return domain?api.enter(domain,lane,cleanup,android_now()):0;
}
static int domain_return(mrk_android_domain_api api,const void *domain,uint32_t lane,uint64_t ticket,uint32_t known) {
    return domain && ticket && api.returned(domain,lane,ticket,android_now(),known)==1;
}
static int close_reference(mrk_android_domain_api api,const void *domain,uint32_t lane,id *object,uint32_t *state) {
    if (*state==0 || *state==4) return 1;
    if (*state!=2 || !*object) return 0;
    uint64_t ticket=domain_enter(api,domain,lane,1);
    if (!ticket) return 0; // Original remains owned, never an attempted release.
    *state=3;uint32_t known=0;
    @try { [*object release];*object=nil;*state=4;known=1; }
    @catch (NSException *exception) {
        (void)exception;domain_failure(api,domain,1);*state=5;
    }
    return domain_return(api,domain,lane,ticket,known) && known;
}

@implementation MRKAndroidData
- (id)initWithValue:(const void *)input api:(mrk_android_domain_api)functions {
    self=[super init];if (self) { value=input;api=functions; }return self;
}
- (void)dealloc {
    const void *original=value;const mrk_android_domain_api functions=api;value=NULL;
    // The original Arc remains held until the ACTUAL last native dealloc
    // return/exception publication. A dealloc-tail flag is not a callback join.
    @try { [super dealloc]; }
    @catch (NSException *exception) {
        (void)exception;if (original) domain_failure(functions,original,1);
    }
    @finally { if (original) functions.release(original); }
}
@end
@implementation MRKAndroidEndpoint
- (id)initWithValue:(const void *)input api:(mrk_android_domain_api)functions takeRead:(mrk_image_take_read)take {
    self=[super init];if (self) { value=functions.retain(input);api=functions;take_read=take;tail_fd=-1; }return self;
}
- (void)dealloc {
    // A partial initializer may have no DATA. No nil object ivar dereference.
    const void *original=value;const mrk_android_domain_api functions=api;value=NULL;
    @try { [super dealloc]; }
    @catch (NSException *exception) {
        (void)exception;if (original) domain_failure(functions,original,1);
    }
    @finally { if (original) functions.release(original); }
}
- (void)respond:(NSData *)input reply:(void (^)(NSData *))reply tailReply:(void (^)(NSData *,NSFileHandle *))tailReply kind:(uint32_t)kind {
    // The receiver owns one DATA Arc. Only this same Arc can escape; it contains
    // no endpoint/connection/native-book edge. Claim BEFORE another native ref,
    // input message access, pool or response allocation.
    const mrk_android_domain_api functions=api;
    const void *guard=value?functions.retain(value):NULL;
    if (!guard) return;
    const uint64_t generation=functions.claim(guard,android_now());
    if (!generation) { functions.release(guard);return; }
    id original_self=nil;uint32_t self_state=0,known=1,backing_entered=0;
    uint64_t ticket=0;size_t bytes=0,count=0;
    const uint8_t *input_bytes=NULL;uint8_t *arena=NULL;
    for (unsigned i=0;i<2;i++) {
        if (response_slots[i]!=0 && response_slots[i]!=4) {
            known=0;domain_failure(functions,guard,1);goto finish;
        }
        response_slots[i]=0;response_objects[i]=nil;
    }
    if (kind>5 || (kind==5?!tailReply:!reply)) { domain_failure(functions,guard,0);goto finish; }
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    self_state=1;
    @try { original_self=[self retain];self_state=original_self?2:4; }
    @catch (NSException *exception) { (void)exception;self_state=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,1,ticket,known) || !original_self) { known=0;goto finish; }
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    @try { count=input?[input length]:0; }
    @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,1,ticket,known)) { known=0;goto finish; }
    if (!input || (kind==0 && count!=MRK_ANDROID_PREPARE_BYTES)
        || (kind==1 && (count<32 || count>MRK_ANDROID_MAX_FRAME))
        || (kind==2 && count!=MRK_ANDROID_QUERY_REQUEST_BYTES)
        || (kind>=3 && count!=MRK_ANDROID_MAINTENANCE_BYTES)) { domain_failure(functions,guard,0);goto finish; }
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    @try { input_bytes=[input bytes]; }
    @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,1,ticket,known) || !input_bytes) { known=0;goto finish; }
    if (functions.response(guard,generation,kind,input_bytes,count,android_now(),&arena,&bytes)!=1 || !arena
        || (bytes!=MRK_ANDROID_PREPARE_BYTES && bytes!=MRK_ANDROID_STATUS_BYTES
            && bytes!=MRK_ANDROID_QUERY_REPLY_BYTES && bytes!=MRK_ANDROID_MAINTENANCE_BYTES)) goto finish;
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    response_slots[0]=1;
    @try {
        response_objects[0]=[[NSAutoreleasePool alloc] init];
        response_slots[0]=response_objects[0]?2:4;
    } @catch (NSException *exception) { (void)exception;response_slots[0]=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,1,ticket,known) || !response_objects[0]) { known=0;goto finish; }
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    response_slots[1]=1;
    @try {
        const void *leased=functions.retain(guard);
        const mrk_android_backing_capture backing={leased,functions.backing,functions.release,generation};
        // Before initializer entry, ambiguity keeps the original lease/capture.
        // A nil/throw is NOT proof that its deallocator did or will run.
        backing_entered=1;
        response_objects[1]=[[NSData alloc] initWithBytesNoCopy:arena length:bytes
            deallocator:^(void *buffer,NSUInteger length) {
                (void)buffer;(void)length;
                backing.backing(backing.data,backing.generation);
                backing.release(backing.data); // No DATA or native use afterward.
            }];
        response_slots[1]=response_objects[1]?2:4;
        if (!response_objects[1]) { known=0;domain_failure(functions,guard,1); }
    } @catch (NSException *exception) {
        (void)exception;response_slots[1]=5;known=0;domain_failure(functions,guard,1);
    }
    if (!domain_return(functions,guard,1,ticket,known) || !response_objects[1]) { known=0;goto finish; }
    if (kind==5) {
        mrk_maintenance_binding_data binding;
        // Only the actual same-domain Started branch exports this live DATA.
        const int started=functions.tail_binding(guard,&binding);
        if (started==1) {
            uint32_t empty=0;
            if (!take_read || !atomic_compare_exchange_strong(&tail_state,&empty,1)) {
                known=0;domain_failure(functions,guard,1);goto finish;
            }
            ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
            // Spend/possible-delivery custody remains in THIS native slot on
            // every return. No Rust callback receives or reconstructs the FD.
            const int returned=take_read(&binding,&tail_fd);
            if (!domain_return(functions,guard,1,ticket,1) || returned!=0 || tail_fd<3) {
                atomic_store(&tail_state,5);known=0;domain_failure(functions,guard,1);goto finish;
            }
            ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
            tail_handle_slot=1;
            @try {
                tail_handle=[[NSFileHandle alloc] initWithFileDescriptor:tail_fd closeOnDealloc:NO];
                tail_handle_slot=tail_handle?2:4;
            } @catch (NSException *exception) {
                (void)exception;tail_handle_slot=5;known=0;domain_failure(functions,guard,1);
            }
            if (!domain_return(functions,guard,1,ticket,known) || !tail_handle) {
                atomic_store(&tail_state,5);known=0;goto finish;
            }
            atomic_store_explicit(&tail_state,2,memory_order_release);
        } else if (started!=0) { known=0;domain_failure(functions,guard,1);goto finish; }
    }
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    @try {
        if (kind==5) tailReply(response_objects[1],atomic_load(&tail_state)==2?tail_handle:nil);
        else reply(response_objects[1]);
    }
    @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,1,ticket,known)) known=0;
finish:
    // These are THIS original responder's slots. Native service control consumes
    // only its separate endpoint reference; it never waits for/accesses these.
    known=close_reference(functions,guard,1,&response_objects[1],&response_slots[1]) && known;
    known=close_reference(functions,guard,1,&response_objects[0],&response_slots[0]) && known;
    known=known && (response_slots[0]==0 || response_slots[0]==4)
        && (response_slots[1]==0 || response_slots[1]==4);
    known=close_reference(functions,guard,1,&original_self,&self_state) && known;
    // No receiver/native-book access follows its original consuming release.
    if (!backing_entered) functions.backing(guard,generation); // positive local no-entry only
    functions.finish(guard,generation,known);
    functions.release(guard);
}
- (void)prepare:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply tailReply:nil kind:0]; }
- (void)exchange:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply tailReply:nil kind:1]; }
- (void)query:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply tailReply:nil kind:2]; }
- (void)challengeA:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply tailReply:nil kind:3]; }
- (void)challengeB:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply tailReply:nil kind:4]; }
- (void)beginDrain:(NSData *)input reply:(void (^)(NSData *,NSFileHandle *))reply {
    const mrk_android_domain_api functions=api;const void *guard=value?functions.retain(value):NULL;
    if (!guard) return;
    if (functions.maintenance_body(guard,5,0,android_now(),1)!=1) { functions.release(guard);return; }
    uint32_t known=0;
    @try { [self respond:input reply:nil tailReply:reply kind:5];known=1; }
    @catch (NSException *exception) { (void)exception;domain_failure(functions,guard,1); }
    const uint64_t returned=android_now(); // Actual inner BODY return, not reply invocation.
    // No self/native-book access after that original body's consuming release.
    if (functions.maintenance_body(guard,5,1,returned,known)==1) functions.release(guard);
}
- (void)receiptBody:(NSData *)input {
    const mrk_android_domain_api functions=api;const void *guard=value?functions.retain(value):NULL;
    if (!guard) return;
    id original=nil;uint32_t state=0,known=1;uint64_t ticket=0;size_t count=0;const uint8_t *bytes=NULL;
    // Dedicated lane3, no response arena or native response slot access.
    ticket=domain_enter(functions,guard,3,1);if (!ticket) { known=0;goto finish; }
    state=1;
    @try { original=[self retain];state=original?2:4; }
    @catch (NSException *exception) { (void)exception;state=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,3,ticket,known) || !original) { known=0;goto finish; }
    ticket=domain_enter(functions,guard,3,1);if (!ticket) { known=0;goto finish; }
    @try { count=input?[input length]:0; }
    @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,3,ticket,known) || count!=MRK_ANDROID_MAINTENANCE_BYTES) {
        known=0;domain_failure(functions,guard,1);goto finish;
    }
    ticket=domain_enter(functions,guard,3,1);if (!ticket) { known=0;goto finish; }
    @try { bytes=[input bytes]; }
    @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,3,ticket,known) || !bytes
        || functions.tail_receipt(guard,bytes,count,android_now())!=1) { known=0;goto finish; }
finish:
    known=close_reference(functions,guard,3,&original,&state) && known;
    if (!known) domain_failure(functions,guard,1);
    functions.release(guard); // No native/receiver access after consuming self.
}
- (void)tailReceived:(NSData *)input {
    const mrk_android_domain_api functions=api;const void *guard=value?functions.retain(value):NULL;
    if (!guard) return;
    if (functions.maintenance_body(guard,7,0,android_now(),1)!=1) { functions.release(guard);return; }
    uint32_t known=0;
    @try { [self receiptBody:input];known=1; }
    @catch (NSException *exception) { (void)exception;domain_failure(functions,guard,1); }
    const uint64_t returned=android_now();
    if (functions.maintenance_body(guard,7,1,returned,known)==1) functions.release(guard);
}
@end

#if defined(MRK_E2_NATIVE_FIXTURE)
/* This stack record exists only inside the actual single Registry listener loan.
 * Its context is the original DOMAIN guard, never the Registry pointer. Provider
 * phases run between MRK_ADMISSION_STEP calls, not under a pending domain ticket. */
typedef struct {
    mrk_android_domain_api functions;const void *domain;
    uint64_t ticket,last;uint32_t phase,cleanup,unknown;
} mrk_e2_listener_identity_gate;
_Static_assert(sizeof(mrk_e2_listener_identity_gate)+sizeof(mrk_e2_fixture_checkpoint_api)
    +2*sizeof(void *)<=1024u,"resident fixture caller backing is separately precharged");
static void service_identity_failure(mrk_android_service *s) {
    const uint64_t first=s->fixture_identity_facts.first_ns;
    atomic_store(&s->unknown,1);atomic_store(&s->accepting,0);
    s->api.registry.failure(s->context,first?first:android_now());
}
static uint32_t listener_identity_point(void *raw,uint32_t phase,uint32_t edge,uint32_t cleanup,uint64_t now,uint32_t outcome) {
    mrk_e2_listener_identity_gate *gate=raw;
    if (!gate || !gate->domain) return 2;
    if (gate->unknown || !phase || phase>MRK_E2_ID_RETIRE || edge>1 || cleanup>1 || outcome>2
        || !now || now<gate->last || (edge==0 && (outcome || gate->ticket))
        || (edge==1 && (!gate->ticket || gate->phase!=phase || gate->cleanup!=cleanup))) {
        gate->unknown=1;gate->functions.notify(gate->domain,now,1);return 2;
    }
    gate->last=now;
    if (outcome) gate->functions.notify(gate->domain,now,outcome==2?1:0);
    if (edge==0) {
        gate->phase=phase;gate->cleanup=cleanup;
        gate->ticket=gate->functions.enter(gate->domain,0,cleanup,now);
        if (!gate->ticket) { gate->unknown=1;gate->functions.notify(gate->domain,now,1);return 2; }
        return 1;
    }
    const uint64_t ticket=gate->ticket;gate->ticket=0;
    if (gate->functions.returned(gate->domain,0,ticket,now,outcome==2?0:1)!=1) {
        gate->unknown=1;gate->functions.notify(gate->domain,now,1);return 2;
    }
    return outcome==0?1:outcome==1?0:2;
}
static int listener_identity_recheck(mrk_android_service *s,mrk_android_domain_api functions,const void *domain) {
    if (!s->fixture_identity) return 0;
    mrk_e2_listener_identity_gate gate={.functions=functions,.domain=domain};
    const mrk_e2_fixture_checkpoint_api api={&gate,listener_identity_point};
    const int ok=mrk_e2_fixture_identity_recheck(s->fixture_identity,0,&api,&s->fixture_identity_facts);
    if (ok!=1 || gate.ticket || gate.unknown || !s->fixture_identity_facts.ready
        || s->fixture_identity_facts.failed || s->fixture_identity_facts.unknown) {
        const uint64_t first=s->fixture_identity_facts.first_ns;
        functions.notify(domain,first?first:android_now(),1);
        service_identity_failure(s);return 0;
    }
    return 1;
}
static int service_identity_settled(mrk_android_service *s) {
    const mrk_e2_fixture_identity_facts *f=&s->fixture_identity_facts;
    if (s->fixture_identity || f->version!=1 || f->bytes!=sizeof(*f) || f->role!=3
        || !f->allocated || !f->allocation_entered || !f->allocation_returned || !f->consumed
        || f->ready || f->unknown || f->in_call || f->calls!=f->returns || f->borrow_count
        || f->pool || (f->acl_frame!=0 && f->acl_frame!=4)) return 0;
    for (unsigned i=0;i<3;i++) if (f->acl_resources[i]!=0 && f->acl_resources[i]!=4) return 0;
    for (unsigned i=0;i<MRK_E2_IDENTITY_FDS;i++) if (f->fds[i]!=0 && f->fds[i]!=4) return 0;
    for (unsigned i=0;i<MRK_E2_IDENTITY_CFS;i++) if (f->cf[i]!=0 && f->cf[i]!=4) return 0;
    return 1;
}
#endif

static BOOL listener_body(mrk_android_service *s,NSXPCListener *listener,NSXPCConnection *connection) {
    if (!service_valid(s) || listener!=s->listener || !connection || !atomic_load(&s->accepting)
        || atomic_load(&s->unknown)) return NO;
    const uint64_t accepted=android_now();uid_t account=UINT32_MAX;
    // Inspection happens on this actual native connection, never a request UID.
    @try { account=[connection effectiveUserIdentifier]; }
    @catch (NSException *exception) { (void)exception;global_failure(s);return NO; }
    if (!accepted || account==0 || account==UINT32_MAX) return NO;
    uint32_t index=UINT32_MAX;uint64_t number=0;
    const void *raw=s->api.reserve(s->context,account,accepted,&index,&number);
    if (!raw) return NO;
    const mrk_android_domain_api functions=domain_api(s);
    // Raw is ONE original Arc, transferred into the carrier on positive init.
    // An independent guard covers every post-consuming observation in admission.
    const void *guard=functions.retain(raw);
    if (index>=MRK_ANDROID_CONNECTION_LIMIT || !number || !guard) {
        global_failure(s);
        // No native initializer was entered: both original DATA references have
        // positive local custody. The registry still retains the refused domain.
        if (guard) functions.release(guard);functions.release(raw);return NO;
    }
    mrk_android_connection *cell=&s->connections[index];
    uint32_t empty=0;
    if (!atomic_compare_exchange_strong(&cell->state,&empty,1)) {
        domain_failure(functions,guard,1);global_failure(s);functions.release(guard);functions.release(raw);return NO;
    }
    cell->number=number;uint32_t known=1,accepted_native=0,carrier_entered=0;uint64_t ticket=0;
    MRKAndroidData *carrier=nil;
    ticket=domain_enter(functions,guard,0,0);if (!ticket) { known=0;goto finish; }
    cell->slots[0]=1;carrier_entered=1;
    @try {
        carrier=[[MRKAndroidData alloc] initWithValue:raw api:functions];
        cell->objects[0]=carrier;cell->slots[0]=carrier?2:4;
        if (!carrier) { functions.release(raw);raw=NULL;domain_failure(functions,guard,0); }
    } @catch (NSException *exception) {
        (void)exception;cell->slots[0]=5;known=0;domain_failure(functions,guard,1);
        // The original raw Arc may have entered an incomplete initializer.
    }
    if (!domain_return(functions,guard,0,ticket,known) || !carrier) { known=0;goto finish; }
    ticket=domain_enter(functions,guard,0,0);if (!ticket) { known=0;goto finish; }
    cell->slots[1]=1;
    @try { cell->objects[1]=[connection retain];cell->slots[1]=cell->objects[1]?2:4; }
    @catch (NSException *exception) { (void)exception;cell->slots[1]=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,0,ticket,known) || !cell->objects[1]) { known=0;goto finish; }
    ticket=domain_enter(functions,guard,0,0);if (!ticket) { known=0;goto finish; }
    cell->slots[2]=1;
    @try {
        cell->objects[2]=[[NSXPCInterface interfaceWithProtocol:@protocol(MRKAndroidRegister)] retain];
        cell->slots[2]=cell->objects[2]?2:4;
    } @catch (NSException *exception) { (void)exception;cell->slots[2]=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,0,ticket,known) || !cell->objects[2]) { known=0;goto finish; }
    ticket=domain_enter(functions,guard,0,0);if (!ticket) { known=0;goto finish; }
    cell->slots[3]=1;
    @try {
        cell->objects[3]=[[MRKAndroidEndpoint alloc] initWithValue:guard api:functions takeRead:s->host.take_read];
        cell->slots[3]=cell->objects[3]?2:4;
    } @catch (NSException *exception) { (void)exception;cell->slots[3]=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,0,ticket,known) || !cell->objects[3]) { known=0;goto finish; }
    // Each actual native admission call is bounded against this original A/C.
#define MRK_ADMISSION_STEP(expression) do { \
    ticket=domain_enter(functions,guard,0,0);if (!ticket) { known=0;goto finish; } \
    @try { expression; } @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); } \
    if (!domain_return(functions,guard,0,ticket,known)) { known=0;goto finish; } \
} while (0)
    MRK_ADMISSION_STEP([(NSXPCInterface *)cell->objects[2] setClasses:[NSSet setWithObject:[NSFileHandle class]]
        forSelector:@selector(beginDrain:reply:) argumentIndex:1 ofReply:YES]);
    MRK_ADMISSION_STEP([connection setExportedInterface:cell->objects[2]]);
    MRK_ADMISSION_STEP([connection setExportedObject:cell->objects[3]]);
    // Exactly one requirement on this original connection, before resume.
#if defined(MRK_E2_NATIVE_FIXTURE)
    if (!listener_identity_recheck(s,functions,guard)) { known=0;goto finish; }
    CFStringRef fixture_requirement=mrk_e2_fixture_client_requirement(s->fixture_identity);
    if (!fixture_requirement) { known=0;domain_failure(functions,guard,1);goto finish; }
    MRK_ADMISSION_STEP([connection setCodeSigningRequirement:(NSString *)fixture_requirement]);
#else
    MRK_ADMISSION_STEP([connection setCodeSigningRequirement:@MRK_ANDROID_APP_REQUIREMENT]);
#endif
    MRK_ADMISSION_STEP([connection setInterruptionHandler:^{
        const mrk_android_domain_api action=carrier->api;
        const void *held=action.retain(carrier->value);
        action.notify(held,android_now(),0);action.release(held);
    }]);
    MRK_ADMISSION_STEP([connection setInvalidationHandler:^{
        const mrk_android_domain_api action=carrier->api;
        const void *held=action.retain(carrier->value);
        action.notify(held,android_now(),2);action.release(held);
    }]);
#if defined(MRK_E2_NATIVE_FIXTURE)
    if (!listener_identity_recheck(s,functions,guard)) { known=0;goto finish; }
#endif
    MRK_ADMISSION_STEP([connection resume]);
#undef MRK_ADMISSION_STEP
    accepted_native=1;
finish:
    if (!carrier_entered && raw) functions.release(raw); // actual initializer NoEntry
    if (!accepted_native) domain_failure(functions,guard,known?0:1);
    // Publish native reference custody only after the callback's final access to
    // the native cell. This is NOT a claim the enclosing callback has joined.
    atomic_store(&cell->state,2);
    functions.release(guard);
    return accepted_native?YES:NO;
}

@implementation MRKAndroidListener
- (id)initWithOwner:(mrk_android_service *)input context:(const void *)context api:(mrk_android_registry_api)functions {
    self=[super init];
    if (self) { owner=input;registry_api=functions;registry=functions.retain(context); }
    return self;
}
- (void)dealloc {
    const void *original=registry;
    const mrk_android_registry_api functions=registry_api;
    registry=NULL;
    // No owner/native-book read, even before or after a late deallocation.
    // The same original Registry Arc covers the ACTUAL superclass return.
    const uint64_t ticket=original?functions.tail_enter(original,android_now()):0;
    uint32_t known=0;
    @try { [super dealloc];known=1; }
    @catch (NSException *exception) { (void)exception;if (original) functions.failure(original,android_now()); }
    const uint64_t returned=android_now();
    if (original && ticket && functions.tail_return(original,ticket,returned,known)==1) {
        functions.release(original); // No DATA/native/receiver use afterward.
    }
    // Partial initializer or unknown tail keeps its original Registry charge.
}
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    const mrk_android_registry_api functions=registry_api;
    const void *guard=registry?functions.retain(registry):NULL;
    if (!guard) return NO;
    const uint64_t ticket=functions.loan_enter(guard,android_now());
    if (!ticket) { functions.release(guard);return NO; }
    // This is the FIRST owner read: the single Registry loan already covers it.
    mrk_android_service *original=owner;
    BOOL accepted=NO;uint32_t known=0;
    @try { accepted=listener_body(original,listener,connection);known=1; }
    @catch (NSException *exception) { (void)exception;functions.failure(guard,android_now()); }
    const uint64_t returned=android_now(); // private body actually returned/raised
    // Only copied DATA callbacks from here on. No self/owner/book access occurs
    // after the actual inner return, including failure and late wrapper tails.
    if (functions.loan_return(guard,ticket,returned,known)!=1) {
        functions.failure(guard,returned);return NO; // retain unknown loan/guard
    }
    functions.release(guard);
    return accepted;
}
@end

enum {
    MRK_SERVICE_NEW=1,MRK_SERVICE_BIND=2,MRK_SERVICE_BEGIN=3,MRK_SERVICE_PUMP=4,
    MRK_SERVICE_CLOSE_LISTENER=5,MRK_SERVICE_CLOSE_MAIN=6,MRK_SERVICE_RETIRE_CONTROL=7,MRK_SERVICE_CONSUME_BOOK=8
};
enum {
    MRK_POOL_ALLOC=1u<<0,MRK_POOL_INIT=1u<<1,MRK_POOL_DRAIN=1u<<2,
    MRK_DELEGATE_ALLOC=1u<<3,MRK_DELEGATE_INIT=1u<<4,
    MRK_LISTENER_ALLOC=1u<<5,MRK_LISTENER_INIT=1u<<6,
    MRK_SET_DELEGATE=1u<<7,MRK_LISTENER_RESUME=1u<<8,MRK_RUNLOOP=1u<<9,
    MRK_LISTENER_INVALIDATE=1u<<10,MRK_LISTENER_RELEASE=1u<<11,
    MRK_DELEGATE_RELEASE=1u<<12,MRK_BOOK_FREE=1u<<13,MRK_BOOK_ALLOC=1u<<14
};
static int report_start(mrk_android_service_report *r,uint32_t operation) {
    if (!r) return 0;
    memset(r,0,sizeof(*r));r->version=1;r->operation=operation;return 1;
}
static void main_report(mrk_android_service *s,mrk_android_service_report *r,uint32_t known) {
    for (unsigned i=0;i<3;i++) r->slots[i]=s->main_slots[i];
    r->listener_close=s->listener_close;r->control_state=atomic_load(&s->control_bound);
    r->pool_generation=s->pool_generation;r->known=known && !atomic_load(&s->unknown);
}
static void main_failure(mrk_android_service *s) {
    for (unsigned i=0;i<3;i++) {
        if (s->main_slots[i]==1 || s->main_slots[i]==3 || s->main_slots[i]==5) s->main_slots[i]=7;
    }
    global_failure(s);
}
// Each fixed expression is one actual selector/CF operation. These internal
// facts never prove the enclosing Rust->C call returned; Rust timestamps that
// separately, before reading this report. No callback or Registry guard spans
// an expression, and no operation is retried after an unknown slot.
#define MRK_MAIN_STEP(bit,expression) do { \
    if (r->selectors_entered&(bit)) { main_failure(s);goto failed; } \
    r->selectors_entered|=(bit); \
    @try { expression;r->selectors_returned|=(bit); } \
    @catch (NSException *exception) { (void)exception;main_failure(s);goto failed; } \
} while (0)
static int main_pool_start(mrk_android_service *s,mrk_android_service_report *r) {
    if (s->main_call || s->pool || (s->main_slots[0]!=0 && s->main_slots[0]!=6)
        || s->pool_generation==UINT64_MAX) { main_failure(s);return 0; }
    s->main_call=1;s->pool_generation++; // reserve before alloc, no second pool
    s->main_slots[0]=1;
    MRK_MAIN_STEP(MRK_POOL_ALLOC,s->pool=[NSAutoreleasePool alloc]);
    if (!s->pool) { s->main_slots[0]=7;main_failure(s);goto failed; }
    s->main_slots[0]=2;
    s->main_slots[0]=3;
    MRK_MAIN_STEP(MRK_POOL_INIT,s->pool=[s->pool init]);
    if (!s->pool) { s->main_slots[0]=7;main_failure(s);goto failed; }
    s->main_slots[0]=4;return 1;
failed:
    return 0; // exact partial pool/native originals stay owned and charged
}
static int main_pool_finish(mrk_android_service *s,mrk_android_service_report *r) {
    if (atomic_load(&s->unknown) || !s->main_call || !s->pool || s->main_slots[0]!=4) {
        main_failure(s);return 0;
    }
    s->main_slots[0]=5;
    MRK_MAIN_STEP(MRK_POOL_DRAIN,[s->pool drain]);
    s->pool=nil;s->main_slots[0]=6;s->main_call=0;return 1;
failed:
    return 0;
}
#if defined(MRK_E2_NATIVE_FIXTURE)
void *mrk_android_e2_fixture_service_new(const void *context,const mrk_android_service_api *api,const mrk_image_host_data *host,
    const mrk_e2_fixture_checkpoint_api *identity_api,mrk_android_service_report *r) {
#else
void *mrk_android_service_new(const void *context,const mrk_android_service_api *api,const mrk_image_host_data *host,mrk_android_service_report *r) {
#endif
    if (!report_start(r,MRK_SERVICE_NEW) || !context || !api || pthread_main_np()!=1
        || getuid()!=0 || geteuid()!=0) return NULL;
#if defined(MRK_E2_NATIVE_FIXTURE)
    if (!identity_api || !identity_api->context || !identity_api->point
        || mrk_e2_fixture_identity_project_bytes()>MRK_E2_IDENTITY_PROJECT_MAX) return NULL;
#else
    if (!mrk_android_identity_available()) return NULL;
#endif
    if (host) {
#if defined(MRK_ANDROID_RESIDENT_IMAGE)
        if (host->version!=1 || host->bytes!=sizeof(*host) || host->role!=2 || host->reserved || !host->take_read
            || memcmp(host->source,MRK_IMAGE_SOURCE_COMMIT,40)
            || memcmp(host->release,MRK_IMAGE_RELEASE_ID,sizeof(MRK_IMAGE_RELEASE_ID)-1)) return NULL;
#else
        return NULL;
#endif
    }
    r->selectors_entered|=MRK_BOOK_ALLOC;
    mrk_android_service *s=calloc(1,sizeof(*s));
    r->selectors_returned|=MRK_BOOK_ALLOC;
    if (!s) return NULL;
    s->magic=MRK_ANDROID_SERVICE_MAGIC;s->context=context;s->api=*api;if (host) s->host=*host;
    atomic_init(&s->control_bound,0);atomic_init(&s->accepting,0);atomic_init(&s->unknown,0);atomic_init(&s->main_released,0);
    for (unsigned i=0;i<MRK_ANDROID_CONNECTION_LIMIT;i++) atomic_init(&s->connections[i].state,0);
    // A partial/invalid book is retained, never freed behind an ambiguous report.
    if (!service_valid(s)) return s;
#if defined(MRK_E2_NATIVE_FIXTURE)
    s->fixture_identity=mrk_e2_fixture_resident_identity_new(identity_api,&s->fixture_identity_facts);
    if (!s->fixture_identity || s->fixture_identity_facts.failed || s->fixture_identity_facts.unknown
        || mrk_e2_fixture_identity_prepare(s->fixture_identity,identity_api,&s->fixture_identity_facts)!=1
        || !s->fixture_identity_facts.ready) {
        service_identity_failure(s);return s; // no control escape/listener before actual validation
    }
#endif
    r->known=1;return s;
}
void mrk_android_service_bind_control(void *raw,mrk_android_service_report *r) {
    if (!report_start(r,MRK_SERVICE_BIND)) return;
    mrk_android_service *s=raw;
    if (!service_valid(s) || pthread_main_np() || atomic_load(&s->control_bound)!=0 || atomic_load(&s->unknown)) return;
    s->control_thread=pthread_self();atomic_store(&s->control_bound,1);
    r->control_state=1;r->known=1;
}
static int control_valid(mrk_android_service *s) {
    return service_valid(s) && atomic_load(&s->control_bound)==1 && pthread_equal(s->control_thread,pthread_self());
}
void mrk_android_service_begin(void *raw,mrk_android_service_report *r) {
    if (!report_start(r,MRK_SERVICE_BEGIN)) return;
    mrk_android_service *s=raw;
    if (!service_valid(s) || s->begun || pthread_main_np()!=1 || atomic_load(&s->control_bound)!=1
        || atomic_load(&s->unknown) || getuid()!=0 || geteuid()!=0) return;
    s->begun=1;
    if (!main_pool_start(s,r)) goto failed;
    s->main_slots[1]=1;
    MRK_MAIN_STEP(MRK_DELEGATE_ALLOC,s->delegate=[MRKAndroidListener alloc]);
    if (!s->delegate) { s->main_slots[1]=7;main_failure(s);goto failed; }
    s->main_slots[1]=2;s->main_slots[1]=3;
    MRK_MAIN_STEP(MRK_DELEGATE_INIT,s->delegate=[s->delegate initWithOwner:s context:s->context api:s->api.registry]);
    if (!s->delegate || !s->delegate->registry) { s->main_slots[1]=7;main_failure(s);goto failed; }
    s->main_slots[1]=4;
    s->main_slots[2]=1;
    MRK_MAIN_STEP(MRK_LISTENER_ALLOC,s->listener=[NSXPCListener alloc]);
    if (!s->listener) { s->main_slots[2]=7;main_failure(s);goto failed; }
    s->main_slots[2]=2;s->main_slots[2]=3;
    // Mach-service listener resume returns, unlike NSXPCListener.service.
    MRK_MAIN_STEP(MRK_LISTENER_INIT,s->listener=[s->listener initWithMachServiceName:MRK_ANDROID_SERVICE_NAME]);
    if (!s->listener) { s->main_slots[2]=7;main_failure(s);goto failed; }
    s->main_slots[2]=4;
    MRK_MAIN_STEP(MRK_SET_DELEGATE,[s->listener setDelegate:s->delegate]);
    atomic_store(&s->accepting,1);
    MRK_MAIN_STEP(MRK_LISTENER_RESUME,[s->listener resume]);
    s->begun=2;
    if (!main_pool_finish(s,r)) goto failed;
    main_report(s,r,1);return;
failed:
    main_report(s,r,0);
}
int mrk_android_service_tail_progress(void *raw,uint32_t index,uint64_t number,const void *domain) {
    mrk_android_service *s=raw;
    if (!control_valid(s) || index>=MRK_ANDROID_CONNECTION_LIMIT || !number || !domain) return -1;
    const mrk_android_domain_api functions=domain_api(s);
    const int ready=functions.tail_ready(domain);
    if (ready!=1) return ready==0?0:-1;
    mrk_android_connection *cell=&s->connections[index];
    if (atomic_load(&cell->state)==1) return 0;
    if (atomic_load(&cell->state)!=2 || cell->number!=number) return -1;
    if (cell->slots[3]==0 || cell->slots[3]==4) return 1; // positive endpoint NeverCreated
    if (cell->slots[3]!=2 || !cell->objects[3]) return -1;
    MRKAndroidEndpoint *endpoint=(MRKAndroidEndpoint *)cell->objects[3];
    const uint32_t state=atomic_load_explicit(&endpoint->tail_state,memory_order_acquire);
    if (state==0 || state==4) return 1;
    if (state==1) return 0;
    if (state!=2 || endpoint->tail_handle_slot!=2 || !endpoint->tail_handle || endpoint->tail_fd<3) return -1;
    uint32_t expected=2;
    if (!atomic_compare_exchange_strong(&endpoint->tail_state,&expected,3)) return -1;
    const void *guard=functions.retain(domain);if (!guard) return -1;
    // SAME existing resident control thread is the only sender-close owner.
    // Both real native bodies and endpoint receipt were checked above.
    uint64_t ticket=domain_enter(functions,guard,2,1);uint32_t known=0;
    if (!ticket) { atomic_store(&endpoint->tail_state,5);functions.release(guard);return -1; }
    endpoint->tail_fd=-1; // spend raw comparison cell BEFORE the consuming selector
    @try {
        NSError *error=nil;
        const BOOL closed=[endpoint->tail_handle closeAndReturnError:&error];
        known=closed && !error;
        if (!known) domain_failure(functions,guard,1);
    } @catch (NSException *exception) { (void)exception;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,2,ticket,known)) known=0;
    if (known) known=close_reference(functions,guard,2,(id *)&endpoint->tail_handle,&endpoint->tail_handle_slot);
    if (!known || functions.tail_closed(guard,android_now(),1)!=1) {
        atomic_store(&endpoint->tail_state,5);domain_failure(functions,guard,1);functions.release(guard);return -1;
    }
    atomic_store_explicit(&endpoint->tail_state,4,memory_order_release);
    functions.release(guard);return 1;
}
int mrk_android_service_context_ready(void *raw,uint32_t index,uint64_t number) {
    mrk_android_service *s=raw;
    if (!control_valid(s) || index>=MRK_ANDROID_CONNECTION_LIMIT || !number) return -1;
    mrk_android_connection *cell=&s->connections[index];
    const uint32_t state=atomic_load(&cell->state);
    if (state==1) return 0;
    return state==2 && cell->number==number?1:-1;
}
int mrk_android_service_close_context(void *raw,uint32_t index,uint64_t number,const void *domain) {
    mrk_android_service *s=raw;
    if (!control_valid(s) || index>=MRK_ANDROID_CONNECTION_LIMIT || !number || !domain) return 0;
    mrk_android_connection *cell=&s->connections[index];
    uint32_t state=atomic_load(&cell->state);
    if ((state!=2 && state!=3) || cell->number!=number) return 0;
    atomic_store(&cell->state,3);
    const mrk_android_domain_api functions=domain_api(s);uint32_t known=1;
    // Invalidate once WITHOUT waiting for payload/coordinator/Arc exclusivity.
    if (cell->objects[1] && cell->slots[1]==2 && cell->invalidation==0) {
        const uint64_t ticket=domain_enter(functions,domain,2,1);
        if (!ticket) return 0;
        cell->invalidation=1;uint32_t returned=0;
        @try { [(NSXPCConnection *)cell->objects[1] invalidate];cell->invalidation=2;returned=1; }
        @catch (NSException *exception) { (void)exception;cell->invalidation=3;domain_failure(functions,domain,1); }
        known=domain_return(functions,domain,2,ticket,returned) && returned;
    }
    if (cell->invalidation==1 || cell->invalidation==3) known=0;
    // Their original owned references can end while Foundation still retains
    // endpoint/block DATA. Such framework holders keep the same Arc charged.
    known=close_reference(functions,domain,2,&cell->objects[2],&cell->slots[2]) && known;
    known=close_reference(functions,domain,2,&cell->objects[1],&cell->slots[1]) && known;
    // Do NOT wait for responder references, its DATA borrow, backing release,
    // coordinator join or DATA exclusivity. A live responder retains its own
    // endpoint original; its no-copy NSData independently retains the same DATA.
    // Reclamation checks actual response returns/backing and all required joins.
    known=close_reference(functions,domain,2,&cell->objects[3],&cell->slots[3]) && known;
    known=close_reference(functions,domain,2,&cell->objects[0],&cell->slots[0]) && known;
    for (unsigned i=0;i<4;i++) if (cell->slots[i]!=0 && cell->slots[i]!=4) known=0;
    atomic_store(&cell->state,known?4:5);return known;
}
int mrk_android_service_reclaim_context(void *raw,uint32_t index,uint64_t number) {
    mrk_android_service *s=raw;
    if (!control_valid(s) || index>=MRK_ANDROID_CONNECTION_LIMIT || !number) return 0;
    mrk_android_connection *cell=&s->connections[index];
    if (atomic_load(&cell->state)!=4 || cell->number!=number) return 0;
    for (unsigned i=0;i<4;i++) if (cell->objects[i] || (cell->slots[i]!=0 && cell->slots[i]!=4)) return 0;
    // Pure owned-cell reset AFTER genuine native returns, actual joins and exact
    // DATA exclusivity/final CF/R reconciliation in the registered Rust owner.
    memset(cell->objects,0,sizeof(cell->objects));memset(cell->slots,0,sizeof(cell->slots));
    cell->number=0;cell->invalidation=0;atomic_store(&cell->state,0);return 1;
}
void mrk_android_service_pump_once(void *raw,mrk_android_service_report *r) {
    if (!report_start(r,MRK_SERVICE_PUMP)) return;
    mrk_android_service *s=raw;
    if (!service_valid(s) || pthread_main_np()!=1 || s->begun!=2 || atomic_load(&s->unknown)
        || (s->main_references!=0 && s->main_references!=2)) return;
    if (!main_pool_start(s,r)) goto failed;
    SInt32 result=0;
    // One positive <=2ms slice, fixed valid default mode, stop after a source.
    // This is not preemption, callback drain, or a framework-thread join.
    MRK_MAIN_STEP(MRK_RUNLOOP,result=CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.002,true));
    switch (result) {
        case kCFRunLoopRunFinished:r->run_result=1;break;
        case kCFRunLoopRunStopped:r->run_result=2;break;
        case kCFRunLoopRunTimedOut:r->run_result=3;break;
        case kCFRunLoopRunHandledSource:r->run_result=4;break;
        default:main_failure(s);goto failed;
    }
    if (!main_pool_finish(s,r)) goto failed;
    main_report(s,r,1);return;
failed:
    main_report(s,r,0);
}
// The exact Rust teardown wrapper already closed admission and the sole idle
// listener-body loan under the SAME guard that issued this original entry ticket.
// Those gates never reopen; late callback wrappers cannot read the book. Do not
// re-take RegistrySlots via registry.closed after entering C: no-selector DATA
// contention is not a failed native return. Native phase/selector/unknown checks
// remain below, and Rust still reconciles the actual original return and clock.
void mrk_android_service_close_listener(void *raw,mrk_android_service_report *r) {
    if (!report_start(r,MRK_SERVICE_CLOSE_LISTENER)) return;
    mrk_android_service *s=raw;
    if (!service_valid(s) || pthread_main_np()!=1 || s->begun!=2 || s->listener_close!=0
        || s->main_references!=0 || s->main_slots[2]!=4 || !s->listener || atomic_load(&s->unknown)) return;
    if (!main_pool_start(s,r)) goto failed;
    atomic_store(&s->accepting,0);
    s->listener_close=1;
    MRK_MAIN_STEP(MRK_LISTENER_INVALIDATE,[s->listener invalidate]);
    s->listener_close=2;
    if (!main_pool_finish(s,r)) goto failed;
    main_report(s,r,1);return;
failed:
    if (s->listener_close==1) s->listener_close=3;
    main_report(s,r,0);
}
#if defined(MRK_E2_NATIVE_FIXTURE)
void mrk_android_e2_fixture_service_close_main_references(void *raw,const mrk_e2_fixture_checkpoint_api *identity_api,mrk_android_service_report *r) {
#else
void mrk_android_service_close_main_references(void *raw,mrk_android_service_report *r) {
#endif
    if (!report_start(r,MRK_SERVICE_CLOSE_MAIN)) return;
    mrk_android_service *s=raw;
    if (!service_valid(s) || pthread_main_np()!=1 || s->listener_close!=2 || s->main_references!=0
        || s->main_slots[1]!=4 || s->main_slots[2]!=4 || !s->delegate || !s->listener
        || atomic_load(&s->unknown)) return;
    if (!main_pool_start(s,r)) goto failed;
    s->main_references=1;
    s->main_slots[2]=5;
    MRK_MAIN_STEP(MRK_LISTENER_RELEASE,[s->listener release]);
    s->listener=nil;s->main_slots[2]=6;
    s->main_slots[1]=5;
    MRK_MAIN_STEP(MRK_DELEGATE_RELEASE,[s->delegate release]);
    s->delegate=nil;s->main_slots[1]=6;
#if defined(MRK_E2_NATIVE_FIXTURE)
    // Original closed/idle listener loan was authenticated under Rust's SAME
    // OP_CLOSE_MAIN entry ticket. Never re-lock RegistrySlots from this call.
    if (!s->fixture_identity || mrk_e2_fixture_identity_close(&s->fixture_identity,identity_api,&s->fixture_identity_facts)!=1
        || !service_identity_settled(s)) { main_failure(s);goto failed; }
#endif
    if (!main_pool_finish(s,r)) goto failed;
    s->main_references=2;atomic_store(&s->main_released,1);
    // C book remains owned: the original control still has to retire and its
    // actual supervisor JoinHandle::join must return before consume_book.
    main_report(s,r,1);return;
failed:
    if (s->main_references==1) s->main_references=3;
    main_report(s,r,0);
}
void mrk_android_service_retire_control(void *raw,mrk_android_service_report *r) {
    if (!report_start(r,MRK_SERVICE_RETIRE_CONTROL)) return;
    mrk_android_service *s=raw;
    if (!control_valid(s) || atomic_load(&s->unknown) || atomic_load(&s->main_released)!=1) return;
    for (unsigned i=0;i<MRK_ANDROID_CONNECTION_LIMIT;i++) {
        if (atomic_load(&s->connections[i].state)!=0) return;
    }
    // End the ORIGINAL control borrow on its registered thread. No book free.
    atomic_store(&s->control_bound,2);r->control_state=2;r->known=1;
}
void mrk_android_service_consume_book(void **original,mrk_android_service_report *r) {
    if (!report_start(r,MRK_SERVICE_CONSUME_BOOK) || !original) return;
    mrk_android_service *s=*original;
    if (!service_valid(s) || pthread_main_np()!=1 || atomic_load(&s->unknown)
        || atomic_load(&s->control_bound)!=2 || atomic_load(&s->main_released)!=1
        || s->main_call || s->main_references!=2 || s->listener_close!=2
        || s->pool || s->listener || s->delegate) return;
#if defined(MRK_E2_NATIVE_FIXTURE)
    if (!service_identity_settled(s)) return;
#endif
    for (unsigned i=0;i<3;i++) if (s->main_slots[i]!=6) return;
    for (unsigned i=0;i<MRK_ANDROID_CONNECTION_LIMIT;i++) {
        mrk_android_connection *cell=&s->connections[i];
        if (atomic_load(&cell->state)!=0 || cell->number || cell->invalidation) return;
        for (unsigned j=0;j<4;j++) if (cell->objects[j] || cell->slots[j]) return;
    }
    main_report(s,r,1);
    // Rust has already actually joined the sole original supervisor. All native
    // object releases/drain and control-return reports preceded that join.
    *original=NULL;s->magic=0;
    r->selectors_entered|=MRK_BOOK_FREE;
    free(s);
    r->selectors_returned|=MRK_BOOK_FREE;r->consumed=1;
    // ONLY caller-owned POD is touched after free; no original pointer probe,
    // callback/context lookup, dealloc-tail fiction, or image unmapping.
}
#undef MRK_MAIN_STEP
#endif
