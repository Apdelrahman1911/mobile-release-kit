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
#include "vault_helper_control.h"

#ifndef MRK_ANDROID_APP_REQUIREMENT
#define MRK_ANDROID_APP_REQUIREMENT ""
#endif
#ifndef MRK_ANDROID_HELPER_REQUIREMENT
#define MRK_ANDROID_HELPER_REQUIREMENT ""
#endif
#define MRK_ANDROID_SERVICE_NAME @"dev.mobile-release-kit.desktop.android-register"
#define MRK_ANDROID_SERVICE_PLIST @"dev.mobile-release-kit.desktop.android-register.plist"
#define MRK_ANDROID_MAX_FRAME 65536u
#define MRK_ANDROID_STATUS_BYTES 256u
#define MRK_ANDROID_QUERY_REQUEST_BYTES 128u
#define MRK_ANDROID_PREPARE_BYTES 64u
#define MRK_ANDROID_QUERY_REPLY_BYTES (256u+8192u)
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
_Static_assert(2*sizeof(mrk_android_backing_capture)+2*sizeof(mrk_android_reply_capture)+2*sizeof(void *)<=128u,
    "supplied client callback capture high-water; runtime block internals are separate");

@protocol MRKAndroidRegister
// Always has a reply. There is no reverse call/exported client object. In
// particular, never use a synchronous request cycle between client and helper.
- (void)exchange:(NSData *)input reply:(void (^)(NSData *))reply;
// Distinct closed read-only role on the same authenticated fixed service.
- (void)query:(NSData *)input reply:(void (^)(NSData *))reply;
// First immutable connection admission; never a cleanup retry or role setter.
- (void)prepare:(NSData *)input reply:(void (^)(NSData *))reply;
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
            || (c->role==2 && c->reply_bytes==MRK_ANDROID_QUERY_REPLY_BYTES));
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
        c->role=1; c->reply_bytes=MRK_ANDROID_STATUS_BYTES;
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
int mrk_android_client_begin(void *raw) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || c->facts.entered || !mrk_android_identity_available()
        || getuid()==0 || getuid()!=geteuid()) return 0;
    c->facts.entered=1; c->thread=pthread_self(); c->thread_bound=1;
    if (!client_enter(c,0)) return 0;
    int ready=0;
    @try {
        c->facts.slots[0]=1;
        if (!client_take(c,0,[[NSAutoreleasePool alloc] init])) goto done;
        if (!client_point(c,0)) goto done;
        c->facts.slots[1]=1;
        if (!client_take(c,1,[[NSXPCInterface interfaceWithProtocol:@protocol(MRKAndroidRegister)] retain])) goto done;
        if (!client_point(c,0)) goto done;
        c->facts.slots[2]=1;
        if (!client_take(c,2,[[NSXPCConnection alloc] initWithMachServiceName:MRK_ANDROID_SERVICE_NAME options:NSXPCConnectionPrivileged])) goto done;
        NSXPCConnection *connection=c->objects[2];
        [connection setRemoteObjectInterface:c->objects[1]];
        if (!client_point(c,0)) goto done;
        // Exactly once before resume; public API, fixed source/build requirement.
        [connection setCodeSigningRequirement:@MRK_ANDROID_HELPER_REQUIREMENT];
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
static int client_exchange(void *raw,const uint8_t *input,size_t count,uint32_t cleanup,uint32_t preparing,uint8_t *output) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !input || !output || c->facts.slots[2]!=2 || cleanup>1 || preparing>1) return 0;
    const uint32_t response_bytes=preparing?MRK_ANDROID_PREPARE_BYTES:c->reply_bytes;
    if (preparing) {
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
        id proxy=[(NSXPCConnection *)c->objects[2] synchronousRemoteObjectProxyWithErrorHandler:^(NSError *error) {
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
        if (preparing) [(id<MRKAndroidRegister>)c->objects[4] prepare:c->objects[5] reply:receive];
        else if (c->role==1) [(id<MRKAndroidRegister>)c->objects[4] exchange:c->objects[5] reply:receive];
        else [(id<MRKAndroidRegister>)c->objects[4] query:c->objects[5] reply:receive];
        // The ACTUAL enclosing synchronous call returned on the same original
        // worker. There are no client interruption/invalidation/reverse handlers.
        if (c->facts.callbacks!=c->facts.callback_returns || c->reply_count!=1 || c->error_count
            || c->facts.unknown) { client_failure(c,EPROTO,c->facts.unknown); goto done; }
        if (!client_point(c,cleanup)) goto done;
        c->facts.peer=[(NSXPCConnection *)c->objects[2] effectiveUserIdentifier];
        if (c->facts.peer!=0) { client_failure(c,EPERM,0); goto done; }
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
    if (ready && request_known) memcpy(output,c->reply,response_bytes);
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
int mrk_android_client_facts(void *raw,mrk_android_client_facts_data *out) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || !out || c->facts.native_call) return 0;
    *out=c->facts; return 1;
}
int mrk_android_client_release_one(void *raw,uint32_t slot) {
    mrk_android_client *c=raw;
    if (!client_valid(c) || slot>=8 || c->facts.slots[slot]!=2 || !client_enter(c,1)) return 0;
    c->facts.slots[slot]=3; int ready=0;
    @try {
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
    c->magic=0; free(c); return 1;
}

#if defined(MRK_ANDROID_REGISTRATION_HELPER)
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
} mrk_android_domain_api;
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
    void (*failure)(const void *);
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
}
- (id)initWithValue:(const void *)input api:(mrk_android_domain_api)functions;
@end
@interface MRKAndroidListener : NSObject <NSXPCListenerDelegate> {
@public mrk_android_service *owner;
}
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
    NSAutoreleasePool *pool;
    NSXPCListener *listener;
    MRKAndroidListener *delegate;
    mrk_android_connection connections[MRK_ANDROID_CONNECTION_LIMIT];
    pthread_t control_thread;
    _Atomic uint32_t control_bound,accepting,unknown;
    uint32_t begun;
};
_Static_assert(sizeof(mrk_android_service)<=16384u,"resident project-owned native cell bound");
_Static_assert(2*sizeof(mrk_android_domain_api)+2*sizeof(mrk_android_backing_capture)+8*sizeof(void *)<=512u,
    "supplied per-context DATA/callback capture bound; not Foundation heap bytes");

static int service_valid(mrk_android_service *s) {
    return s && s->magic==MRK_ANDROID_SERVICE_MAGIC && s->context && s->api.reserve
        && s->api.retain && s->api.release && s->api.notify && s->api.enter && s->api.returned
        && s->api.claim && s->api.response && s->api.backing && s->api.finish && s->api.failure;
}
static mrk_android_domain_api domain_api(mrk_android_service *s) {
    return (mrk_android_domain_api){s->api.retain,s->api.release,s->api.notify,s->api.enter,s->api.returned,
        s->api.claim,s->api.response,s->api.backing,s->api.finish};
}
static void global_failure(mrk_android_service *s) {
    if (!service_valid(s)) return;
    atomic_store(&s->unknown,1);atomic_store(&s->accepting,0);s->api.failure(s->context);
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
- (id)initWithValue:(const void *)input api:(mrk_android_domain_api)functions {
    self=[super init];if (self) { value=functions.retain(input);api=functions; }return self;
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
- (void)respond:(NSData *)input reply:(void (^)(NSData *))reply kind:(uint32_t)kind {
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
    if (!reply || kind>2) { domain_failure(functions,guard,0);goto finish; }
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
        || (kind==2 && count!=MRK_ANDROID_QUERY_REQUEST_BYTES)) { domain_failure(functions,guard,0);goto finish; }
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    @try { input_bytes=[input bytes]; }
    @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,1,ticket,known) || !input_bytes) { known=0;goto finish; }
    if (functions.response(guard,generation,kind,input_bytes,count,android_now(),&arena,&bytes)!=1 || !arena
        || (bytes!=MRK_ANDROID_PREPARE_BYTES && bytes!=MRK_ANDROID_STATUS_BYTES
            && bytes!=MRK_ANDROID_QUERY_REPLY_BYTES)) goto finish;
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
    ticket=domain_enter(functions,guard,1,1);if (!ticket) { known=0;goto finish; }
    @try { reply(response_objects[1]); }
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
- (void)prepare:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply kind:0]; }
- (void)exchange:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply kind:1]; }
- (void)query:(NSData *)input reply:(void (^)(NSData *))reply { [self respond:input reply:reply kind:2]; }
@end

@implementation MRKAndroidListener
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    mrk_android_service *s=owner;
    if (!service_valid(s) || listener!=s->listener || !connection || !atomic_load(&s->accepting)
        || atomic_load(&s->unknown)) return NO;
    const uint64_t accepted=android_now();uid_t account=UINT32_MAX;
    // Inspection happens on this actual native connection, never a request UID.
    @try { account=[connection effectiveUserIdentifier]; }
    @catch (NSException *exception) { (void)exception;return NO; }
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
        cell->objects[3]=[[MRKAndroidEndpoint alloc] initWithValue:guard api:functions];
        cell->slots[3]=cell->objects[3]?2:4;
    } @catch (NSException *exception) { (void)exception;cell->slots[3]=5;known=0;domain_failure(functions,guard,1); }
    if (!domain_return(functions,guard,0,ticket,known) || !cell->objects[3]) { known=0;goto finish; }
    // Each actual native admission call is bounded against this original A/C.
#define MRK_ADMISSION_STEP(expression) do { \
    ticket=domain_enter(functions,guard,0,0);if (!ticket) { known=0;goto finish; } \
    @try { expression; } @catch (NSException *exception) { (void)exception;known=0;domain_failure(functions,guard,1); } \
    if (!domain_return(functions,guard,0,ticket,known)) { known=0;goto finish; } \
} while (0)
    MRK_ADMISSION_STEP([connection setExportedInterface:cell->objects[2]]);
    MRK_ADMISSION_STEP([connection setExportedObject:cell->objects[3]]);
    // Public fixed requirement exactly once before resume. No weaker fallback.
    MRK_ADMISSION_STEP([connection setCodeSigningRequirement:@MRK_ANDROID_APP_REQUIREMENT]);
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
@end

void *mrk_android_service_new(const void *context,const mrk_android_service_api *api) {
    if (!context || !api || getuid()!=0 || geteuid()!=0 || !mrk_android_identity_available()) return NULL;
    mrk_android_service *s=calloc(1,sizeof(*s));
    if (!s) return NULL;
    s->magic=MRK_ANDROID_SERVICE_MAGIC;s->context=context;s->api=*api;
    atomic_init(&s->control_bound,0);atomic_init(&s->accepting,0);atomic_init(&s->unknown,0);
    for (unsigned i=0;i<MRK_ANDROID_CONNECTION_LIMIT;i++) atomic_init(&s->connections[i].state,0);
    if (!service_valid(s)) { free(s);return NULL; }return s;
}
int mrk_android_service_bind_control(void *raw) {
    mrk_android_service *s=raw;
    if (!service_valid(s) || pthread_main_np() || atomic_load(&s->control_bound)) return 0;
    s->control_thread=pthread_self();atomic_store(&s->control_bound,1);return 1;
}
static int control_valid(mrk_android_service *s) {
    return service_valid(s) && atomic_load(&s->control_bound) && pthread_equal(s->control_thread,pthread_self());
}
int mrk_android_service_begin(void *raw) {
    mrk_android_service *s=raw;
    if (!service_valid(s) || s->begun || pthread_main_np()!=1 || !atomic_load(&s->control_bound)
        || getuid()!=0 || geteuid()!=0) return 0;
    s->begun=1;
    @try {
        s->pool=[[NSAutoreleasePool alloc] init];
        s->delegate=[[MRKAndroidListener alloc] init];
        s->listener=[[NSXPCListener alloc] initWithMachServiceName:MRK_ANDROID_SERVICE_NAME];
        if (!s->pool || !s->delegate || !s->listener) { global_failure(s);return 0; }
        s->delegate->owner=s;[s->listener setDelegate:s->delegate];
        atomic_store(&s->accepting,1);[s->listener resume];return 1;
    } @catch (NSException *exception) { (void)exception;global_failure(s);return 0; }
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
int mrk_android_service_run(void *raw) {
    mrk_android_service *s=raw;
    if (!service_valid(s) || !s->begun || pthread_main_np()!=1) return 2;
    dispatch_main();return 2;
}
#endif
