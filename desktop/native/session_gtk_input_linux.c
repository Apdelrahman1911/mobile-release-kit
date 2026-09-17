/* Fixed SG1 direct GTK input. Source-only implementation; NOT an execution pass.
 * Uses public libdbus/AT-SPI wire interfaces, never libatspi initialization/cache.
 * Empty audit pins are deliberate. No environment value can open this gate.
 * The original launcher owns this helper's wait and both streams, not this main.
 */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include <glib.h>
#include <atspi/atspi-constants.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__GLIBC__)
#error "The native shell helper source admits Linux x86_64 GNU only"
#endif

static const char *const APPROVED_AUDITS[4] = {"", "", "", ""};
#define BASELINE "e6abe8fdc6df328da336301ebfa4fffb36555d58f5611873016ef4bc8df53c50"
#define API_INVENTORY ""
#define PROFILE "linux-x11-atspi-direct-gtk-sg1-v1"
#define ACCESS "org.a11y.atspi.Accessible"
#define ACTION "org.a11y.atspi.Action"
#define REGISTRY "org.a11y.atspi.Registry"
#define OBJECT_EVENT "org.a11y.atspi.Event.Object"
#define PICKER_TITLE "Choose a mobile project folder"
#define QUIT_TITLE "Quit and discard unsaved drafts?"
#define QUIT_BODY "Unsaved in-memory changes will be lost. Choose Cancel to keep working, or OK to stop owned operations and wait for cleanup before quitting. A save already accepted may still complete; quitting does not undo committed files."
#define NS UINT64_C(1000000000)
#define COMMON "v type case profile binding roots file writer writtenNs"
#define BUILD "baselineManifest sourceRoster contractSource helperSource launcherSource appBinary helperBinary launcherRuntime pythonRuntime frontend featuresSha256 apiInventory"
#define REQUIRE(x) do { if (!(x)) fail(__LINE__); } while (0)
static int refused;
static void fail(int line) { (void)line; refused = 1; } /* sticky; never cleared */
static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 || t.tv_nsec < 0 ||
        t.tv_nsec >= 1000000000L || (uint64_t)t.tv_sec > (UINT64_MAX-(uint64_t)t.tv_nsec)/NS) {
        fail(__LINE__); return 0;
    }
    return (uint64_t)t.tv_sec*NS+(uint64_t)t.tv_nsec;
}
static uint64_t endpoint(uint64_t n, uint64_t delta) {
    if (n > UINT64_MAX-delta) { fail(__LINE__); return 0; }
    return n+delta;
}
static uint64_t minimum(uint64_t a, uint64_t b) { return a < b ? a : b; }
static void nap(void) {
    struct timespec t={0,5000000};
    /* EINTR cannot turn a partial sleep into a tight metadata poll. No signal
       handlers are installed by this helper; interruption is Unknown. */
    if (nanosleep(&t,NULL)) fail(__LINE__);
}
static int checked_close(int *fd) {
    int original=*fd; *fd=-1; /* inventory consumption precedes the one attempt */
    if (original < 0 || close(original)) { fail(__LINE__); return 0; }
    return 1; /* never retry EINTR or probe/reopen the old number */
}
static void digest(const void *p, size_t n, char out[65]) {
    out[0]=0;
    GChecksum *c=g_checksum_new(G_CHECKSUM_SHA256);
    if (!c) { fail(__LINE__); return; }
    g_checksum_update(c,p,n); const char *value=g_checksum_get_string(c);
    if (value) g_strlcpy(out,value,65); else fail(__LINE__);
    g_checksum_free(c);
}
static int hex(const char *s, size_t n) {
    if (!s || strlen(s)!=n) return 0;
    for (size_t i=0;i<n;i++) if (!g_ascii_isdigit(s[i]) && (s[i]<'a'||s[i]>'f')) return 0;
    return 1;
}
static uint64_t dec(const char *s) {
    if (!s || !*s || strlen(s)>20 || (s[0]=='0'&&s[1])) { fail(__LINE__); return 0; }
    for (const char *p=s;*p;p++) if (!g_ascii_isdigit(*p)) { fail(__LINE__); return 0; }
    errno=0; char *end=NULL; unsigned long long n=strtoull(s,&end,10);
    if (errno || !end || *end) { fail(__LINE__); return 0; }
    return (uint64_t)n;
}
static void copy(char *to, size_t cap, const char *from) {
    if (!from || strlen(from)>=cap) { if (cap) to[0]=0; fail(__LINE__); return; }
    g_strlcpy(to,from,cap);
}
static int unique_name(const char *s) {
    if (!s || *s!=':' || strlen(s)>64 || !strchr(s+1,'.')) return 0;
    int length=0;
    for (const char *p=s+1;*p;p++) {
        if (*p=='.') { if (!length) return 0; length=0; }
        else { if (!g_ascii_isalnum(*p) && *p!='_' && *p!='-') return 0; length++; }
    }
    return length>0;
}
static int object_path(const char *s) {
    if (!s || *s!='/' || strlen(s)>256) return 0;
    if (!s[1]) return 1;
    int length=0;
    for (const char *p=s+1;*p;p++) {
        if (*p=='/') { if (!length) return 0; length=0; }
        else { if (!g_ascii_isalnum(*p)&&*p!='_') return 0; length++; }
    }
    return length>0;
}

/* Native DTOs contain only ASCII literal/identity/hash strings (never a path to
 * type). Token count includes keys AND values, including containers. The input
 * byte buffer is bounded first; strings are validated before retained copies.
 * These two bounded documents are the only parsed records this helper reads.
 */
typedef struct { int type,child,next; char *key,*text; } J;
typedef struct { char data[16385]; J node[2048]; unsigned used,tokens,limit; char *p,*end; } Doc;
static int new_node(Doc *d,int type) {
    if (d->used==2048 || ++d->tokens>d->limit) { fail(__LINE__); return -1; }
    int n=(int)d->used++; d->node[n]=(J){.type=type,.child=-1,.next=-1}; return n;
}
static char *json_string(Doc *d, size_t bound) {
    if (d->p>=d->end || *d->p++!='"') { fail(__LINE__); return NULL; }
    char *s=d->p;
    while (d->p<d->end && *d->p!='"') {
        unsigned char c=(unsigned char)*d->p++;
        if (c<32 || c>=127 || c=='\\' || (size_t)(d->p-s)>bound) { fail(__LINE__); return NULL; }
    }
    if (d->p==d->end) { fail(__LINE__); return NULL; }
    *d->p++=0; return s;
}
static int json_value(Doc *d,unsigned depth) {
    if (refused || depth>7 || d->p>=d->end) { fail(__LINE__); return -1; }
    char c=*d->p; int root=new_node(d,c=='"'?'s':c=='n'?'n':c=='t'||c=='f'?'b':c=='{'||c=='['?c:'u');
    if (root<0) return -1;
    if (c=='{'||c=='[') {
        d->p++; int last=-1; unsigned count=0; char stop=c=='{'?'}':']';
        while (!refused && d->p<d->end && *d->p!=stop) {
            if (++count>(c=='{'?64u:6u)) { fail(__LINE__); break; }
            char *key=NULL;
            if (c=='{') {
                if (++d->tokens>d->limit) { fail(__LINE__); break; }
                key=json_string(d,64);
                if (!key || d->p==d->end || *d->p++!=':') { fail(__LINE__); break; }
                for (int n=d->node[root].child;n>=0;n=d->node[n].next)
                    if (!strcmp(d->node[n].key,key)) fail(__LINE__);
            }
            int n=json_value(d,depth+1); if (n<0) break; d->node[n].key=key;
            if (last<0) d->node[root].child=n; else d->node[last].next=n; last=n;
            if (d->p<d->end && *d->p==',') { d->p++; if (d->p==d->end||*d->p==stop) fail(__LINE__); }
            else break;
        }
        if (d->p==d->end || *d->p++!=stop) fail(__LINE__);
    } else if (c=='"') d->node[root].text=json_string(d,512);
    else {
        char *s=d->p;
        while (d->p<d->end && *d->p!=',' && *d->p!='}' && *d->p!=']') d->p++;
        size_t n=(size_t)(d->p-s); d->node[root].text=s; d->node[root].child=(int)n;
        if (!n || n>20) { fail(__LINE__); return root; }
        if (c=='n') REQUIRE(n==4&&!memcmp(s,"null",4));
        else if (c=='t'||c=='f') REQUIRE((n==4&&!memcmp(s,"true",4))||(n==5&&!memcmp(s,"false",5)));
        else { REQUIRE(!(n>1&&*s=='0')); for (size_t k=0;k<n;k++) REQUIRE(g_ascii_isdigit(s[k])); }
    }
    return root;
}
static J *get(Doc *d,int root,const char *key) {
    if (refused || root<0 || (unsigned)root>=d->used || d->node[root].type!='{') { fail(__LINE__); return NULL; }
    for (int n=d->node[root].child;n>=0;n=d->node[n].next) if (!strcmp(d->node[n].key,key)) return &d->node[n];
    fail(__LINE__); return NULL;
}
static int obj(Doc *d,int root,const char *key) { J *j=get(d,root,key); return j?(int)(j-d->node):-1; }
static const char *str(Doc *d,int root,const char *key) {
    J *j=get(d,root,key); if (!j||j->type!='s') { fail(__LINE__); return ""; } return j->text;
}
static uint64_t decimal(Doc *d,int root,const char *key) { return dec(str(d,root,key)); }
static uint32_t integer(Doc *d,int root,const char *key) {
    J *j=get(d,root,key); char b[32];
    if (!j||j->type!='u'||j->child<1||j->child>10) { fail(__LINE__); return 0; }
    memcpy(b,j->text,(size_t)j->child); b[j->child]=0; uint64_t n=dec(b);
    REQUIRE(n<=UINT32_MAX); return (uint32_t)n;
}
static int is_null(Doc *d,int root,const char *key) { J *j=get(d,root,key); return j&&j->type=='n'; }
static void keyset(Doc *d,int root,const char *keys) {
    if (refused || root<0 || (unsigned)root>=d->used || d->node[root].type!='{') { fail(__LINE__); return; }
    int n=d->node[root].child; const char *p=keys;
    while (*p&&!refused) {
        const char *end=strchr(p,' '); size_t len=end?(size_t)(end-p):strlen(p);
        if (n<0 || strlen(d->node[n].key)!=len || memcmp(d->node[n].key,p,len)) { fail(__LINE__); return; }
        n=d->node[n].next; p=end?end+1:p+len;
    }
    REQUIRE(n<0); /* declaration order, no missing/additional keys */
}
static void parse(Doc *d,const char *bytes,size_t length,int large) {
    REQUIRE(length && length<=(large?16384u:4096u) && bytes[length-1]=='\n'); if (refused) return;
    memcpy(d->data,bytes,length); d->data[length]=0; d->p=d->data; d->end=d->data+length-1;
    d->used=d->tokens=0; d->limit=large?2048:512;
    REQUIRE(json_value(d,0)==0 && d->p==d->end);
}
static void quoted(GString *s,const char *text) {
    REQUIRE(text&&strlen(text)<=512); if (refused) return; g_string_append_c(s,'"');
    for (const unsigned char *p=(const unsigned char *)text;*p;p++) {
        if (*p<32||*p>=127||*p=='\\'||*p=='"') { fail(__LINE__); return; }
        g_string_append_c(s,(char)*p);
    }
    g_string_append_c(s,'"');
}
static void dump(Doc *d,int n,GString *s) {
    if (refused) return; REQUIRE(n>=0&&(unsigned)n<d->used); if (refused) return; J *j=&d->node[n];
    if (j->type=='s') quoted(s,j->text);
    else if (j->type!='{'&&j->type!='[') g_string_append_len(s,j->text,j->child);
    else {
        g_string_append_c(s,(char)j->type); unsigned count=0;
        for (int c=j->child;c>=0;c=d->node[c].next) {
            if (count++) g_string_append_c(s,',');
            if (j->type=='{') { quoted(s,d->node[c].key); g_string_append_c(s,':'); }
            dump(d,c,s);
        }
        g_string_append_c(s,j->type=='{'?'}':']');
    }
    REQUIRE(s->len<=16384);
}
static GString *fragment(Doc *d,int n) { GString *s=g_string_sized_new(1024); dump(d,n,s); return s; }
static void id_schema(Doc *d,int n,int directory) {
    keyset(d,n,"device inode mode owner"); decimal(d,n,"device"); REQUIRE(decimal(d,n,"inode")>0);
    uint32_t mode=integer(d,n,"mode"),owner=integer(d,n,"owner");
    if (directory) REQUIRE(mode==040700&&owner!=0);
}
static void pid_schema(Doc *d,int n) {
    keyset(d,n,"pid startTicks"); uint32_t p=integer(d,n,"pid"); REQUIRE(p>0&&p<=4194304); decimal(d,n,"startTicks");
}
static void exe_schema(Doc *d,int n) {
    keyset(d,n,"file sha256"); int file=obj(d,n,"file"); id_schema(d,file,0);
    REQUIRE((integer(d,file,"mode")&0170000)==0100000&&hex(str(d,n,"sha256"),64));
}
static void proc_schema(Doc *d,int n) { keyset(d,n,"identity executable"); pid_schema(d,obj(d,n,"identity")); exe_schema(d,obj(d,n,"executable")); }
static void svc_schema(Doc *d,int n) { keyset(d,n,"owner process"); REQUIRE(unique_name(str(d,n,"owner"))); proc_schema(d,obj(d,n,"process")); }
static void pipe_schema(Doc *d,int n) { keyset(d,n,"device inode"); decimal(d,n,"device"); REQUIRE(decimal(d,n,"inode")>0); }
static void close_schema(Doc *d,int n,uint64_t end) {
    keyset(d,n,"fd atNs result"); REQUIRE(integer(d,n,"fd")<=1048575 && decimal(d,n,"atNs")<=end &&
        !strcmp(str(d,n,"result"),"positive-consuming-close"));
}
static void common_schema(Doc *d) {
    REQUIRE(integer(d,0,"v")==1 && !strcmp(str(d,0,"profile"),PROFILE) && hex(str(d,0,"binding"),64));
    REQUIRE(!strcmp(str(d,0,"case"),"SG1"));
    int roots=obj(d,0,"roots"); keyset(d,roots,"run app native");
    const char *names[]={"run","app","native"}; uint32_t owner=0;
    for (unsigned i=0;i<3;i++) { int n=obj(d,roots,names[i]); id_schema(d,n,1); if (!i) owner=integer(d,n,"owner"); else REQUIRE(integer(d,n,"owner")==owner); }
    int file=obj(d,0,"file"); id_schema(d,file,0);
    REQUIRE(integer(d,file,"mode")==0100600&&integer(d,file,"owner")==owner);
    pid_schema(d,obj(d,0,"writer")); REQUIRE(decimal(d,0,"writtenNs")<=now_ns());
}
static const char *const dialog_kinds[]={"picker-cancel","picker-select","source-select","quit-cancel","quit-ok"};
static const char *dialog_action(unsigned n) {return n==2?"select-project":n==3?"select-source":n==5?"ok":"cancel";}
static void expected_ids(const char *admission_hash,unsigned n,char main[81],char dialog[81]) {
    REQUIRE(hex(admission_hash,64)&&n>=1&&n<=5);if(refused)return;
    REQUIRE(snprintf(main,81,"mrk-sg1:%s:main",admission_hash)==77);
    REQUIRE(snprintf(dialog,81,"mrk-sg1:%s:d%u",admission_hash,n)==75);
}
static void admission_schema(Doc *d) {
    keyset(d,0,COMMON " build readySha256 outer app helper appSpawnNs outerEndNs display fixtures pipes aliases sourceProfileSha256 installedClosureSha256 loaderClosureSha256 writerAuditSha256");
    common_schema(d); REQUIRE(!strcmp(str(d,0,"type"),"admission"));
    int build=obj(d,0,"build"); keyset(d,build,BUILD); if (refused) return;
    for (int n=d->node[build].child;n>=0&&!refused;n=d->node[n].next) REQUIRE(d->node[n].type=='s'&&hex(d->node[n].text,64));
    const char *pins[]={"readySha256","sourceProfileSha256","installedClosureSha256","loaderClosureSha256","writerAuditSha256"};
    for (unsigned n=0;n<5;n++) REQUIRE(hex(str(d,0,pins[n]),64));
    proc_schema(d,obj(d,0,"outer")); proc_schema(d,obj(d,0,"app")); proc_schema(d,obj(d,0,"helper"));
    uint64_t spawn=decimal(d,0,"appSpawnNs"),written=decimal(d,0,"writtenNs");
    REQUIRE(spawn<=written&&written<=endpoint(spawn,2*NS)&&decimal(d,0,"outerEndNs")==endpoint(spawn,90*NS));
    int x=obj(d,0,"display"); keyset(d,x,"kind display server windowManager sessionBus a11yBus registry sandbox");
    REQUIRE(!strcmp(str(d,x,"kind"),"x11")&&!strcmp(str(d,x,"sandbox"),"intact-nonroot")&&strlen(str(d,x,"display"))<=16);
    proc_schema(d,obj(d,x,"server")); proc_schema(d,obj(d,x,"windowManager")); svc_schema(d,obj(d,x,"registry"));
    const char *buses[]={"sessionBus","a11yBus"};
    for (unsigned n=0;n<2;n++) {int b=obj(d,x,buses[n]); keyset(d,b,"id process addressSha256"); REQUIRE(hex(str(d,b,"id"),32)&&hex(str(d,b,"addressSha256"),64));proc_schema(d,obj(d,b,"process"));}
    int f=obj(d,0,"fixtures"); keyset(d,f,"project source sourceSha256");id_schema(d,obj(d,f,"project"),1);id_schema(d,obj(d,f,"source"),0);
    REQUIRE(integer(d,obj(d,f,"source"),"mode")==0100600&&hex(str(d,f,"sourceSha256"),64));
    int pipes=obj(d,0,"pipes"),aliases=obj(d,0,"aliases");
    keyset(d,pipes,"appStdout appStderr helperStdout helperStderr");keyset(d,aliases,"appStdoutWrite appStderrWrite helperStdoutWrite helperStderrWrite");
    const char *pn[]={"appStdout","appStderr","helperStdout","helperStderr"},*an[]={"appStdoutWrite","appStderrWrite","helperStdoutWrite","helperStderrWrite"};
    for (unsigned n=0;n<4;n++) {pipe_schema(d,obj(d,pipes,pn[n]));close_schema(d,obj(d,aliases,an[n]),written);}
}
static void go_schema(Doc *d) {
    keyset(d,0,COMMON " admissionSha256 n kind presentedSha256 action gate operation showOrdinal producerOrdinal ownership checkpointNs inputEndNs selected");
    common_schema(d);REQUIRE(!strcmp(str(d,0,"type"),"go")&&hex(str(d,0,"admissionSha256"),64)&&hex(str(d,0,"presentedSha256"),64));
    uint32_t n=integer(d,0,"n"),show=integer(d,0,"showOrdinal"),producer=integer(d,0,"producerOrdinal");
    REQUIRE(n>=1&&n<=5&&show>=1&&show<producer&&producer<=512&&integer(d,0,"operation")==n);if(refused)return;
    REQUIRE(!strcmp(str(d,0,"kind"),dialog_kinds[n-1])&&!strcmp(str(d,0,"action"),dialog_action(n))&&!strcmp(str(d,0,"gate"),n==1?"preserved-close":"presented"));
    uint64_t checkpoint=decimal(d,0,"checkpointNs"),written=decimal(d,0,"writtenNs"),end=decimal(d,0,"inputEndNs");
    REQUIRE(checkpoint<=written&&written<end&&end==endpoint(checkpoint,2*NS));
    int ownership=obj(d,0,"ownership");keyset(d,ownership,"method operation mainId dialogId tagOrdinal checkOrdinal checkedNs transientForMain");
    char main[81]={0},dialog[81]={0};expected_ids(str(d,0,"admissionSha256"),n,main,dialog);
    uint32_t tag=integer(d,ownership,"tagOrdinal"),checked=integer(d,ownership,"checkOrdinal");
    J *transient=get(d,ownership,"transientForMain");
    REQUIRE(!strcmp(str(d,ownership,"method"),"gtk-window-get-transient-for")&&integer(d,ownership,"operation")==n&&
        !strcmp(str(d,ownership,"mainId"),main)&&!strcmp(str(d,ownership,"dialogId"),dialog)&&
        tag>=1&&tag<show&&show<checked&&checked<producer&&decimal(d,ownership,"checkedNs")<=checkpoint&&
        transient&&transient->type=='b'&&transient->child==4&&!memcmp(transient->text,"true",4));
    if(n==2||n==3)id_schema(d,obj(d,0,"selected"),n==2);else REQUIRE(is_null(d,0,"selected"));
}

static Doc admission,go_doc;
/* All successful original bytes this helper reads or publishes, including LF.
 * 16KiB admission + 5*(go/presented/input at4KiB) +4KiB ready =80KiB.
 * Parsed Doc strings may be NUL-delimited in-place; those are NOT a substitute
 * for retaining the original complete record bytes in this finite arena. */
static unsigned char record_bytes[80*1024];
static struct { char name[32]; size_t offset,length; } record_index[17];
static unsigned record_count;
static size_t record_used;
static void remember_record(const char *name,const void *bytes,size_t length) {
    REQUIRE(record_count<17&&length<=16384&&record_used<=sizeof record_bytes-length);
    for (unsigned n=0;n<record_count;n++) REQUIRE(strcmp(record_index[n].name,name));
    if (refused) return;
    copy(record_index[record_count].name,sizeof record_index[record_count].name,name);
    if (refused) return;
    record_index[record_count].offset=record_used; record_index[record_count++].length=length;
    memcpy(record_bytes+record_used,bytes,length); record_used+=length;
}
static char temp_root[257],native_root[300],project[300],source_file[300],case_id[4],binding[65],helper_hash[65];
static char admission_sha[65],presented_sha[65],go_sha[65],ready_sha[65];
static char registry_owner[65],session_id[33],a11y_id[33];
static struct stat roots[3];
static uint64_t helper_spawn,outer_end,phase_end,ready_written,presented_observed,presented_written,last_completed;
static uint64_t events,wire_messages,queries,nodes,actions,polls;
static unsigned phase_queries,phase_nodes,ordinal;
static const char *kind;
static int admitted;
typedef struct { pid_t pid,parent; uint64_t start; struct stat exe; char sha[65]; } Proc;
static Proc self_proc,registry_proc,app_proc;

static int same_stat(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid;
}
static int stable_stat(const struct stat *a,const struct stat *b) {
    return same_stat(a,b)&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static void verify_roots(void) {
    char path[300],canonical[PATH_MAX]; struct stat current;
    REQUIRE(realpath(temp_root,canonical)&&!strcmp(canonical,temp_root));
    const char *suffix[]={"","/app","/native"};
    for (unsigned n=0;n<3&&!refused;n++) {
        snprintf(path,sizeof path,"%s%s",temp_root,suffix[n]);
        REQUIRE(!lstat(path,&current)&&same_stat(&current,&roots[n])&&current.st_mode==040700&&current.st_uid==getuid());
    }
}
static int read_file(const char *path,char *bytes,size_t cap,size_t *length,struct stat *identity,int proc) {
    struct stat named,before,after,final; int good=!lstat(path,&named);
    if (!good) { fail(__LINE__); return 0; }
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0) { fail(__LINE__); return 0; } /* original retained before first fstat/read */
    good=!fstat(fd,&before)&&S_ISREG(before.st_mode)&&same_stat(&before,&named);
    if (!proc) good=good&&before.st_nlink==1&&before.st_size>=0&&(uint64_t)before.st_size<cap&&before.st_mode==0100600&&before.st_uid==getuid();
    size_t total=0; int eof=0;
    while (good && total<cap) {
        ssize_t n=read(fd,bytes+total,cap-total);
        if (n<0) { good=0; break; } if (!n) { eof=1; break; } total+=(size_t)n;
    }
    good=good&&eof&&total<cap&&!fstat(fd,&after)&&!lstat(path,&final)&&stable_stat(&before,&after)&&stable_stat(&before,&final);
    if (!proc) good=good&&total==(size_t)before.st_size;
    if (!checked_close(&fd)) good=0;
    if (!good) { fail(__LINE__); return 0; }
    bytes[total]=0; *length=total; if (identity) *identity=before; return 1;
}
static void append_id(GString *s,const struct stat *st) {
    g_string_append_printf(s,"{\"device\":\"%ju\",\"inode\":\"%ju\",\"mode\":%ju,\"owner\":%ju}",
        (uintmax_t)st->st_dev,(uintmax_t)st->st_ino,(uintmax_t)st->st_mode,(uintmax_t)st->st_uid);
}
static void check_id(Doc *d,int n,const struct stat *st) {
    id_schema(d,n,0); REQUIRE(decimal(d,n,"device")==st->st_dev&&decimal(d,n,"inode")==st->st_ino&&
        integer(d,n,"mode")==st->st_mode&&integer(d,n,"owner")==st->st_uid);
}
static int stat_sample(pid_t pid,uint64_t *start,pid_t *parent) {
    char path[80],bytes[4097]; size_t length=0;
    snprintf(path,sizeof path,"/proc/%ld/stat",(long)pid);
    if (!read_file(path,bytes,sizeof bytes,&length,NULL,1)) return 0;
    char prefix[32]; snprintf(prefix,sizeof prefix,"%ld (",(long)pid); char *tail=strrchr(bytes,')');
    REQUIRE(!strncmp(bytes,prefix,strlen(prefix))&&tail&&tail>bytes+strlen(prefix)); if (refused) return 0;
    char *save=NULL,*part=strtok_r(tail+1," \n",&save); unsigned i=0; uint64_t ticks=0; pid_t ppid=0;
    for (;part&&i<=19;i++,part=strtok_r(NULL," \n",&save)) {
        if (i==1) { uint64_t p=dec(part); REQUIRE(p<=4194304); ppid=(pid_t)p; }
        if (i==19) ticks=dec(part);
    }
    REQUIRE(i==20&&ticks>0); *start=ticks; *parent=ppid; return !refused;
}
static void proc_identity(pid_t pid,Proc *out) {
    REQUIRE(pid>0&&pid<=4194304); if (refused) return;
    uint64_t first=0,second=0; pid_t parent=0,parent2=0;
    if (!stat_sample(pid,&first,&parent)) return;
    char path[80],target[513]; snprintf(path,sizeof path,"/proc/%ld/exe",(long)pid);
    ssize_t count=readlink(path,target,sizeof target); REQUIRE(count>0&&count<=512); if (refused) return;
    target[count]=0; REQUIRE(target[0]=='/'&&!strstr(target," (deleted)")); if (refused) return;
    /* Following THIS kernel proc executable reference is intentional. It is not
       a user-selected path and is bracketed by the two start/parent samples. */
    struct stat named={0},final={0}; REQUIRE(!stat(path,&named)); if (refused) return;
    int fd=open(path,O_RDONLY|O_CLOEXEC); if (fd<0) { fail(__LINE__); return; }
    struct stat before={0},after={0}; int good=!fstat(fd,&before)&&stable_stat(&before,&named)&&S_ISREG(before.st_mode)&&before.st_size>=0&&before.st_size<=256*1024*1024;
    GChecksum *sum=g_checksum_new(G_CHECKSUM_SHA256); char block[16384]; size_t total=0; int eof=0;
    if (!sum) good=0;
    while (good) {
        ssize_t n=read(fd,block,sizeof block); if (n<0) { good=0; break; }
        if (!n) { eof=1; break; }
        total+=(size_t)n; if (total>256*1024*1024) { good=0; break; } g_checksum_update(sum,(guchar *)block,(gsize)n);
    }
    good=good&&eof&&!fstat(fd,&after)&&!stat(path,&final)&&stable_stat(&before,&after)&&stable_stat(&before,&final)&&total==(size_t)before.st_size;
    char sha[65]={0}; if (good) copy(sha,sizeof sha,g_checksum_get_string(sum)); if (sum) g_checksum_free(sum);
    if (!checked_close(&fd)) good=0;
    REQUIRE(good); if (refused || !stat_sample(pid,&second,&parent2)) return;
    REQUIRE(first==second&&parent==parent2); if (refused) return;
    *out=(Proc){.pid=pid,.parent=parent,.start=first,.exe=before}; copy(out->sha,sizeof out->sha,sha);
}
static void append_proc(GString *s,const Proc *p) {
    g_string_append_printf(s,"{\"identity\":{\"pid\":%ld,\"startTicks\":\"%"PRIu64"\"},\"executable\":{\"file\":",(long)p->pid,p->start);
    append_id(s,&p->exe); g_string_append_printf(s,",\"sha256\":\"%s\"}}",p->sha);
}
static void check_proc(Doc *d,int n,const Proc *p) {
    proc_schema(d,n); int id=obj(d,n,"identity"),exe=obj(d,n,"executable");
    REQUIRE(integer(d,id,"pid")==p->pid&&decimal(d,id,"startTicks")==p->start); check_id(d,obj(d,exe,"file"),&p->exe);
    REQUIRE(!strcmp(str(d,exe,"sha256"),p->sha));
}
static void verify_proc(Doc *d,int n) {
    int id=obj(d,n,"identity"); Proc p={0}; proc_identity((pid_t)integer(d,id,"pid"),&p); check_proc(d,n,&p);
}
static void common(GString *s,const char *type,const struct stat *file,uint64_t written) {
    g_string_append_printf(s,"{\"v\":1,\"type\":\"%s\",\"case\":\"%s\",\"profile\":\"%s\",\"binding\":\"%s\",\"roots\":{\"run\":",type,case_id,PROFILE,binding);
    append_id(s,&roots[0]); g_string_append(s,",\"app\":"); append_id(s,&roots[1]); g_string_append(s,",\"native\":"); append_id(s,&roots[2]);
    g_string_append(s,"},\"file\":"); append_id(s,file);
    g_string_append_printf(s,",\"writer\":{\"pid\":%ld,\"startTicks\":\"%"PRIu64"\"},\"writtenNs\":\"%"PRIu64"\"",(long)self_proc.pid,self_proc.start,written);
}
static uint64_t publish(const char *name,const char *type,GString *tail,char sha[65]) {
    if (refused) return 0;
    verify_roots(); if (refused) return 0;
    char path[350],pending[360]; snprintf(path,sizeof path,"%s/%s",native_root,name); snprintf(pending,sizeof pending,"%s.pending",path);
    int fd=open(pending,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) { fail(__LINE__); return 0; }
    struct stat before={0},after={0},named={0};
    REQUIRE(!fstat(fd,&before)&&before.st_nlink==1&&before.st_size==0&&before.st_mode==0100600&&before.st_uid==getuid());
    uint64_t written=now_ns(); GString *bytes=g_string_sized_new(4096);
    common(bytes,type,&before,written); g_string_append_len(bytes,tail->str,tail->len); g_string_append(bytes,"}\n");
    REQUIRE(bytes->len<=4096&&written<=minimum(phase_end,outer_end));
    ssize_t count=refused?-1:write(fd,bytes->str,bytes->len); /* ONE bounded attempt */
    REQUIRE(count==(ssize_t)bytes->len&&!fstat(fd,&after)&&same_stat(&before,&after)&&after.st_nlink==1&&after.st_size==(off_t)bytes->len);
    checked_close(&fd); /* even failed metadata/write consumes the original once */
    if (!refused) {
        REQUIRE(!renameat2(AT_FDCWD,pending,AT_FDCWD,path,RENAME_NOREPLACE));
        REQUIRE(!lstat(path,&named)&&same_stat(&before,&named)&&named.st_nlink==1&&named.st_size==(off_t)bytes->len);
        REQUIRE(now_ns()<=minimum(phase_end,outer_end));
    }
    if (!refused) { digest(bytes->str,bytes->len,sha); remember_record(name,bytes->str,bytes->len); }
    g_string_free(bytes,TRUE); return written;
}

/* The callback only checks/counters/queues ORIGINAL messages. It never queries
 * or acts. Pending replies remain with the single original DBusPendingCall.
 * libdbus may deliver a reply before filters: it is counted on steal if not seen
 * by this filter. Explicit Hello uses the same bounded original call slot.
 */
static DBusConnection *session,*a11y;
typedef struct { DBusPendingCall *handle; DBusMessage *reply; DBusConnection *connection; dbus_uint32_t serial; int seen; char sender[65]; uint64_t end; } Pending;
static Pending original_pending;
static DBusMessage *queue[32];
static unsigned qhead,qcount;
static int qsource[32];
static uint64_t qtime[32];
static int wire_walk(DBusMessageIter *i,unsigned depth,unsigned variants,unsigned *tokens) {
    if (depth>12) return 0;
    while (dbus_message_iter_get_arg_type(i)!=DBUS_TYPE_INVALID) {
        int type=dbus_message_iter_get_arg_type(i); if (++*tokens>2048) return 0;
        if (type==DBUS_TYPE_STRING||type==DBUS_TYPE_OBJECT_PATH||type==DBUS_TYPE_SIGNATURE) {
            const char *s=NULL; dbus_message_iter_get_basic(i,&s);
            if (!s||strlen(s)>512||!g_utf8_validate(s,-1,NULL)) return 0;
        } else if (type==DBUS_TYPE_VARIANT||type==DBUS_TYPE_ARRAY||type==DBUS_TYPE_STRUCT||type==DBUS_TYPE_DICT_ENTRY) {
            DBusMessageIter child,check; dbus_message_iter_recurse(i,&child); check=child;
            unsigned count=0,cap=64;
            if (type==DBUS_TYPE_VARIANT && variants>=4) return 0;
            if (type==DBUS_TYPE_ARRAY&&dbus_message_iter_get_element_type(i)==DBUS_TYPE_DICT_ENTRY) cap=16;
            if (type==DBUS_TYPE_VARIANT) cap=1;
            while (dbus_message_iter_get_arg_type(&check)!=DBUS_TYPE_INVALID) { if (++count>cap) return 0; dbus_message_iter_next(&check); }
            if (type==DBUS_TYPE_VARIANT&&count!=1) return 0;
            if (type==DBUS_TYPE_DICT_ENTRY&&count!=2) return 0;
            if (!wire_walk(&child,depth+1,variants+(type==DBUS_TYPE_VARIANT),tokens)) return 0;
        } else if (type!=DBUS_TYPE_BYTE&&type!=DBUS_TYPE_BOOLEAN&&type!=DBUS_TYPE_INT16&&type!=DBUS_TYPE_UINT16&&
                   type!=DBUS_TYPE_INT32&&type!=DBUS_TYPE_UINT32&&type!=DBUS_TYPE_INT64&&type!=DBUS_TYPE_UINT64) return 0;
        dbus_message_iter_next(i);
    }
    return 1;
}
static int wire_bound(DBusMessage *m,int queued) {
    DBusMessageIter i; unsigned tokens=0; dbus_message_iter_init(m,&i);
    if (!wire_walk(&i,0,0,&tokens)) { fail(__LINE__); return 0; }
    /* Incoming library ceiling is already 16KiB, BEFORE dispatch. Marshal only
       measures that original bounded message; it is freed before queue retention.
       Queued event payloads use a stricter 2KiB limit, never truncation. */
    char *bytes=NULL; int length=0;
    if (!dbus_message_marshal(m,&bytes,&length)) { fail(__LINE__); return 0; }
    int good=length>=0&&length<=(queued?2048:16384); dbus_free(bytes);
    if (!good) fail(__LINE__); return good;
}
static DBusHandlerResult receive_filter(DBusConnection *c,DBusMessage *m,void *data) {
    int source=(int)(intptr_t)data; int type=dbus_message_get_type(m);
    int reply=type==DBUS_MESSAGE_TYPE_METHOD_RETURN||type==DBUS_MESSAGE_TYPE_ERROR;
    if (reply && original_pending.handle && c==original_pending.connection && dbus_message_get_reply_serial(m)==original_pending.serial) {
        REQUIRE(!original_pending.seen); original_pending.seen=1; REQUIRE(++wire_messages<=8192); wire_bound(m,0);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    REQUIRE(++wire_messages<=8192);
    if (refused || !wire_bound(m,1)) return DBUS_HANDLER_RESULT_HANDLED;
    /* Hello's original connection-local notifications are not
       desktop events, but remain in wireMessages. No undocumented signal passes. */
    if (dbus_message_is_signal(m,DBUS_INTERFACE_DBUS,"NameAcquired")||dbus_message_is_signal(m,DBUS_INTERFACE_DBUS,"NameLost")) {
        const char *name=NULL;
        REQUIRE(dbus_message_get_sender(m)&&!strcmp(dbus_message_get_sender(m),DBUS_SERVICE_DBUS)&&
            dbus_message_get_args(m,NULL,DBUS_TYPE_STRING,&name,DBUS_TYPE_INVALID)&&unique_name(name));
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (dbus_message_is_signal(m,DBUS_INTERFACE_LOCAL,"Disconnected")) { fail(__LINE__); return DBUS_HANDLER_RESULT_HANDLED; }
    REQUIRE(source==2); REQUIRE(qcount<32);
    if (!refused) {
        unsigned at=(qhead+qcount)%32; queue[at]=dbus_message_ref(m); qsource[at]=source; qtime[at]=now_ns(); qcount++;
    }
    return DBUS_HANDLER_RESULT_HANDLED;
}
static void pump_connection(DBusConnection *c) {
    if (!c||refused) return;
    REQUIRE(dbus_connection_read_write(c,0));
    unsigned turns=0;
    while (!refused&&dbus_connection_get_dispatch_status(c)==DBUS_DISPATCH_DATA_REMAINS) {
        REQUIRE(++turns<=64&&now_ns()<=minimum(phase_end,outer_end));
        if (!refused) REQUIRE(dbus_connection_dispatch(c)!=DBUS_DISPATCH_NEED_MEMORY);
    }
}
static void pump(void) {
    pump_connection(session); pump_connection(a11y);
    /* During explicit Hello, the fresh original connection is not assigned to
       its permanent role yet. It is still retained in the one pending slot. */
    DBusConnection *c=original_pending.connection;
    if (original_pending.handle&&c!=session&&c!=a11y) pump_connection(c);
}
static DBusMessage *method(const char *dest,const char *path,const char *iface,const char *member) {
    DBusMessage *m=dbus_message_new_method_call(dest,path,iface,member); if (!m) fail(__LINE__); return m;
}
static void append_s(DBusMessageIter *i,const char *s) { if (!refused) REQUIRE(dbus_message_iter_append_basic(i,DBUS_TYPE_STRING,&s)); }
static DBusMessage *call(DBusConnection *c,const char *dest,const char *path,const char *iface,const char *member,DBusMessage *m) {
    if (!m&&!refused) m=method(dest,path,iface,member);
    if (!m) { fail(__LINE__); return NULL; }
    queries++; phase_queries++;
    uint64_t now=now_ns(),end=minimum(phase_end,outer_end);
    if (refused||original_pending.handle||queries>4096||phase_queries>960||(!admitted&&queries>128)||now>=end||(end-now)/1000000<1) {
        dbus_message_unref(m); fail(__LINE__); return NULL;
    }
    uint64_t ms=(end-now)/1000000; if (ms>250) ms=250;
    original_pending.connection=c; original_pending.seen=0; original_pending.end=endpoint(now,ms*1000000);
    copy(original_pending.sender,sizeof original_pending.sender,dest);
    REQUIRE(dbus_connection_send_with_reply(c,m,&original_pending.handle,(int)ms)&&original_pending.handle);
    original_pending.serial=dbus_message_get_serial(m); dbus_message_unref(m);
    if (refused) return NULL;
    while (!refused&&!dbus_pending_call_get_completed(original_pending.handle)&&now_ns()<original_pending.end) { pump(); if (!dbus_pending_call_get_completed(original_pending.handle)) nap(); }
    if (refused||!dbus_pending_call_get_completed(original_pending.handle)||now_ns()>original_pending.end||now_ns()>end) {
        /* Deliberately retain the original slot. No cancellation, unref, retry,
           replacement call, unlock or success publication after uncertainty. */
        fail(__LINE__); return NULL;
    }
    DBusMessage *reply=dbus_pending_call_steal_reply(original_pending.handle);
    original_pending.reply=reply; /* retain even a malformed/error/timeout reply */
    if (!original_pending.seen) { REQUIRE(++wire_messages<=8192); if (reply) wire_bound(reply,0); }
    REQUIRE(reply&&dbus_message_get_type(reply)==DBUS_MESSAGE_TYPE_METHOD_RETURN&&dbus_message_get_reply_serial(reply)==original_pending.serial);
    if (reply) REQUIRE(dbus_message_get_sender(reply)&&!strcmp(dbus_message_get_sender(reply),original_pending.sender));
    if (refused) return NULL; /* original slot/reply stay owned, no repair call */
    /* Keep BOTH originals through the caller's closed body/signature check.
       A normal envelope alone cannot settle a malformed body or false action.
       No second call is permitted until consume_reply positively accepts it. */
    return reply;
}
static void consume_reply(DBusMessage *reply) {
    REQUIRE(reply&&original_pending.handle&&original_pending.reply==reply);
    REQUIRE(now_ns()<=original_pending.end&&now_ns()<=minimum(phase_end,outer_end));
    if (refused) return; /* retain the original handle and stolen reply */
    dbus_pending_call_unref(original_pending.handle); original_pending.handle=NULL;
    dbus_message_unref(reply); original_pending.reply=NULL;
}
static void normal_empty(DBusMessage *reply) { if (reply) { REQUIRE(!strcmp(dbus_message_get_signature(reply),"")); consume_reply(reply); } }
static DBusConnection *connect_bus(const char *address,int source) {
    if (refused) return NULL;
    DBusError error; dbus_error_init(&error);
    DBusConnection *c=dbus_connection_open_private(address,&error);
    if (!c) { dbus_error_free(&error); fail(__LINE__); return NULL; }
    /* Opening/authentication can outlast the endpoint; the outer must refuse
       app launch, not invent cancellation. Set limits BEFORE Hello/dispatch. */
    dbus_connection_set_exit_on_disconnect(c,FALSE);
    dbus_connection_set_max_message_size(c,16384); dbus_connection_set_max_received_size(c,65536);
    dbus_connection_set_max_message_unix_fds(c,0); dbus_connection_set_max_received_unix_fds(c,0);
    REQUIRE(dbus_connection_get_max_message_size(c)==16384&&dbus_connection_get_max_received_size(c)==65536&&
        dbus_connection_get_max_message_unix_fds(c)==0&&dbus_connection_get_max_received_unix_fds(c)==0);
    REQUIRE(dbus_connection_add_filter(c,receive_filter,(void *)(intptr_t)source,NULL));
    /* Do not use dbus_bus_register's implicit blocking Hello. This direct
       driver Hello has the same <=250ms/absolute cap and message accounting
       as every other controlled method. No libdbus bus-cache API is used. */
    DBusMessage *reply=call(c,DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"Hello",NULL);
    if (reply) {
        const char *name=NULL; REQUIRE(dbus_message_get_args(reply,NULL,DBUS_TYPE_STRING,&name,DBUS_TYPE_INVALID)&&unique_name(name));
        consume_reply(reply);
    }
    dbus_error_free(&error);
    REQUIRE(queries<=128&&now_ns()<=phase_end); return c;
}
static void bus_owner(DBusConnection *c,const char *name,char out[65]) {
    if (refused) return; DBusMessage *m=method(DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"GetNameOwner"); if (!m) return;
    DBusMessageIter i; dbus_message_iter_init_append(m,&i); append_s(&i,name);
    DBusMessage *r=call(c,DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"GetNameOwner",m); const char *s=NULL;
    if (r) { REQUIRE(dbus_message_get_args(r,NULL,DBUS_TYPE_STRING,&s,DBUS_TYPE_INVALID)&&unique_name(s)); if (!refused) copy(out,65,s); consume_reply(r); }
}
static pid_t bus_pid(DBusConnection *c,const char *name) {
    if (refused) return 0; DBusMessage *m=method(DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"GetConnectionUnixProcessID"); if (!m) return 0;
    DBusMessageIter i; dbus_message_iter_init_append(m,&i); append_s(&i,name);
    DBusMessage *r=call(c,DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"GetConnectionUnixProcessID",m); dbus_uint32_t p=0;
    if (r) { REQUIRE(dbus_message_get_args(r,NULL,DBUS_TYPE_UINT32,&p,DBUS_TYPE_INVALID)&&p>0&&p<=4194304); consume_reply(r); }
    REQUIRE(p>0&&p<=4194304); return (pid_t)p;
}
static void bus_id(DBusConnection *c,char out[33]) {
    DBusMessage *r=call(c,DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"GetId",NULL); const char *s=NULL;
    if (r) { REQUIRE(dbus_message_get_args(r,NULL,DBUS_TYPE_STRING,&s,DBUS_TYPE_INVALID)&&hex(s,32)); if (!refused) copy(out,33,s); consume_reply(r); }
}
static void match(const char *rule) {
    if (refused) return; DBusMessage *m=method(DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"AddMatch"); if (!m) return;
    DBusMessageIter i; dbus_message_iter_init_append(m,&i); append_s(&i,rule);
    normal_empty(call(a11y,DBUS_SERVICE_DBUS,DBUS_PATH_DBUS,DBUS_INTERFACE_DBUS,"AddMatch",m));
}
static const char *const subscriptions[]={"object:children-changed:add","object:children-changed:remove","object:state-changed:showing","object:state-changed:visible","object:state-changed:enabled","object:state-changed:sensitive","object:state-changed:focused","object:state-changed:active","object:state-changed:defunct"};
static void subscribe(int add) {
    for (unsigned n=0;n<G_N_ELEMENTS(subscriptions)&&!refused;n++) {
        const char *member=add?"RegisterEvent":"DeregisterEvent";
        DBusMessage *m=method(registry_owner,"/org/a11y/atspi/registry",REGISTRY,member); if (!m) return;
        DBusMessageIter i,array; dbus_message_iter_init_append(m,&i); append_s(&i,subscriptions[n]);
        if (add&&!refused) {
            REQUIRE(dbus_message_iter_open_container(&i,DBUS_TYPE_ARRAY,"s",&array));
            if (!refused) REQUIRE(dbus_message_iter_close_container(&i,&array)); append_s(&i,"");
        }
        normal_empty(call(a11y,registry_owner,"/org/a11y/atspi/registry",REGISTRY,member,m));
    }
}
/* Actual observed references only. No constructed desktop/app object, cache,
 * GetItems, GetChildren, GetApplication or application-bus negotiation. */
typedef struct { char bus[65],path[257]; } Ref;
typedef struct { Ref ref; unsigned events; } Node;
static Node retained[128];
static unsigned retained_count;
static char case_node_hashes[512][65];
static int same_ref(const Ref *a,const Ref *b) { return !strcmp(a->bus,b->bus)&&!strcmp(a->path,b->path); }
static unsigned retain_ref(const Ref *r,unsigned event) {
    for (unsigned n=0;n<retained_count;n++) if (same_ref(r,&retained[n].ref)) { retained[n].events|=event; return n; }
    REQUIRE(retained_count<128&&phase_nodes<128&&unique_name(r->bus)&&object_path(r->path)); if (refused) return 0;
    char joined[324],sha[65]; snprintf(joined,sizeof joined,"%s\n%s",r->bus,r->path); digest(joined,strlen(joined),sha);
    unsigned n=0; for (;n<nodes;n++) if (!strcmp(case_node_hashes[n],sha)) break;
    if (n==nodes) { REQUIRE(nodes<512); if (refused) return 0; copy(case_node_hashes[nodes++],65,sha); }
    unsigned index=retained_count++; phase_nodes++; retained[index]=(Node){.ref=*r,.events=event}; return index;
}
static void ref_iter(DBusMessageIter *i,Ref *out) {
    if (refused) return; DBusMessageIter sub; const char *bus=NULL,*path=NULL;
    REQUIRE(dbus_message_iter_get_arg_type(i)==DBUS_TYPE_STRUCT); if (refused) return;
    dbus_message_iter_recurse(i,&sub); REQUIRE(dbus_message_iter_get_arg_type(&sub)==DBUS_TYPE_STRING); if (refused) return;
    dbus_message_iter_get_basic(&sub,&bus); REQUIRE(dbus_message_iter_next(&sub)&&dbus_message_iter_get_arg_type(&sub)==DBUS_TYPE_OBJECT_PATH); if (refused) return;
    dbus_message_iter_get_basic(&sub,&path); REQUIRE(!dbus_message_iter_next(&sub)&&unique_name(bus)&&object_path(path));
    if (!refused) { copy(out->bus,sizeof out->bus,bus); copy(out->path,sizeof out->path,path); }
}
static void append_ref(GString *s,const Ref *r) { g_string_append_printf(s,"{\"bus\":\"%s\",\"path\":\"%s\"}",r->bus,r->path); }
static DBusMessage *property(const Ref *r,const char *iface,const char *key) {
    retain_ref(r,0); if (refused) return NULL;
    DBusMessage *m=method(r->bus,r->path,DBUS_INTERFACE_PROPERTIES,"Get"); if (!m) return NULL;
    DBusMessageIter i; dbus_message_iter_init_append(m,&i); append_s(&i,iface); append_s(&i,key);
    DBusMessage *reply=call(a11y,r->bus,r->path,DBUS_INTERFACE_PROPERTIES,"Get",m);
    if (reply&&strcmp(dbus_message_get_signature(reply),"v")) { fail(__LINE__); consume_reply(reply); return NULL; } return reply;
}
static int property_int(const Ref *r,const char *iface,const char *key) {
    DBusMessage *reply=property(r,iface,key); dbus_int32_t value=-1;
    if (reply) { DBusMessageIter i,sub; dbus_message_iter_init(reply,&i); dbus_message_iter_recurse(&i,&sub);
        REQUIRE(dbus_message_iter_get_arg_type(&sub)==DBUS_TYPE_INT32); if (!refused) dbus_message_iter_get_basic(&sub,&value); consume_reply(reply); }
    return value;
}
static void property_name(const Ref *r,char out[513]) {
    DBusMessage *reply=property(r,ACCESS,"Name");
    if (reply) { DBusMessageIter i,sub; const char *name=NULL; dbus_message_iter_init(reply,&i); dbus_message_iter_recurse(&i,&sub);
        REQUIRE(dbus_message_iter_get_arg_type(&sub)==DBUS_TYPE_STRING); if (!refused) { dbus_message_iter_get_basic(&sub,&name); copy(out,513,name); } consume_reply(reply); }
}
static void property_id(const Ref *r,const char *expected,char observed[81]) {
    if(refused)return;
    DBusMessage *reply=property(r,ACCESS,"AccessibleId");
    if(reply) {
        DBusMessageIter i,sub;const char *value=NULL;
        REQUIRE(dbus_message_iter_init(reply,&i)&&dbus_message_iter_get_arg_type(&i)==DBUS_TYPE_VARIANT);
        if(!refused) {
            dbus_message_iter_recurse(&i,&sub);REQUIRE(dbus_message_iter_get_arg_type(&sub)==DBUS_TYPE_STRING);
            if(!refused) {
                dbus_message_iter_get_basic(&sub,&value);
                size_t length=value?strlen(value):0; // Existing wire_bound already caps borrowed strings at512.
                REQUIRE(value&&length<=80&&length==strlen(expected)&&(length==75||length==77));
                for(size_t n=0;n<length&&!refused;n++)REQUIRE((unsigned char)value[n]>=32&&(unsigned char)value[n]<127);
                REQUIRE(!dbus_message_iter_next(&sub)&&!dbus_message_iter_next(&i));
                if(!refused)REQUIRE(!strcmp(value,expected));
                // Retain the ACTUAL read string, never serialize the expectation.
                if(!refused)copy(observed,81,value);
            }
        }
        // A malformed or foreign value leaves BOTH original pending objects
        // retained by the existing C1 failure barrier; there is no fallback.
        consume_reply(reply);
    }
}
static Ref parent_ref(const Ref *r) {
    Ref parent={0}; DBusMessage *reply=property(r,ACCESS,"Parent");
    if (reply) { DBusMessageIter i,sub; dbus_message_iter_init(reply,&i); dbus_message_iter_recurse(&i,&sub); ref_iter(&sub,&parent);
        REQUIRE(!strcmp(parent.bus,r->bus)&&!same_ref(r,&parent)); consume_reply(reply); }
    REQUIRE(!strcmp(parent.bus,r->bus)&&!same_ref(r,&parent)); return parent;
}
static unsigned role(const Ref *r) {
    retain_ref(r,0); dbus_uint32_t result=0; DBusMessage *reply=call(a11y,r->bus,r->path,ACCESS,"GetRole",NULL);
    if (reply) { REQUIRE(dbus_message_get_args(reply,NULL,DBUS_TYPE_UINT32,&result,DBUS_TYPE_INVALID)); consume_reply(reply); } return result;
}
static uint64_t states(const Ref *r) {
    retain_ref(r,0); DBusMessage *reply=call(a11y,r->bus,r->path,ACCESS,"GetState",NULL); uint64_t result=0;
    if (reply) {
        REQUIRE(!strcmp(dbus_message_get_signature(reply),"au"));
        if (!refused) { DBusMessageIter i,sub; dbus_uint32_t *words=NULL; int count=0; dbus_message_iter_init(reply,&i); dbus_message_iter_recurse(&i,&sub);
            dbus_message_iter_get_fixed_array(&sub,&words,&count); REQUIRE(count==2&&words); if (!refused) result=(uint64_t)words[0]|((uint64_t)words[1]<<32); }
        consume_reply(reply);
    }
    return result;
}
static int visible(uint64_t state) { return (state&(UINT64_C(1)<<ATSPI_STATE_SHOWING))&&(state&(UINT64_C(1)<<ATSPI_STATE_VISIBLE)); }
static int actionable(uint64_t state) {
    return visible(state)&&(state&(UINT64_C(1)<<ATSPI_STATE_ENABLED))&&(state&(UINT64_C(1)<<ATSPI_STATE_SENSITIVE))&&!(state&(UINT64_C(1)<<ATSPI_STATE_DEFUNCT));
}
static Ref child(const Ref *r,int index) {
    Ref result={0}; if (refused) return result;
    DBusMessage *m=method(r->bus,r->path,ACCESS,"GetChildAtIndex"); if (!m) return result;
    DBusMessageIter i; dbus_int32_t n=index; dbus_message_iter_init_append(m,&i); REQUIRE(dbus_message_iter_append_basic(&i,DBUS_TYPE_INT32,&n));
    DBusMessage *reply=call(a11y,r->bus,r->path,ACCESS,"GetChildAtIndex",m);
    if (reply) { REQUIRE(!strcmp(dbus_message_get_signature(reply),"(so)")); if (!refused) { dbus_message_iter_init(reply,&i); ref_iter(&i,&result); }
        REQUIRE(!strcmp(result.bus,r->bus)); consume_reply(reply); }
    REQUIRE(!strcmp(result.bus,r->bus)); if (!refused) retain_ref(&result,0); return result;
}
static Ref application(Ref r) {
    Ref ancestors[12]; unsigned used=0;
    for (unsigned depth=0;depth<12&&!refused;depth++) {
        for (unsigned n=0;n<used;n++) REQUIRE(!same_ref(&r,&ancestors[n])); if (refused) break;
        ancestors[used++]=r; if (role(&r)==ATSPI_ROLE_APPLICATION) return r; r=parent_ref(&r);
    }
    fail(__LINE__); return r;
}
static void descendant_of(Ref r,const Ref *bound) {
    Ref visited[12]; unsigned used=0;
    for (unsigned depth=0;depth<12&&!refused;depth++) {
        if (same_ref(&r,bound)) return;
        for (unsigned n=0;n<used;n++) REQUIRE(!same_ref(&r,&visited[n])); if (refused) return;
        visited[used++]=r; r=parent_ref(&r);
    }
    fail(__LINE__);
}
static int has_interface(const Ref *r,const char *wanted) {
    DBusMessage *reply=call(a11y,r->bus,r->path,ACCESS,"GetInterfaces",NULL); int found=0;
    if (reply) {
        REQUIRE(!strcmp(dbus_message_get_signature(reply),"as"));
        if (!refused) { DBusMessageIter i,sub; dbus_message_iter_init(reply,&i); dbus_message_iter_recurse(&i,&sub); unsigned count=0;
            while (dbus_message_iter_get_arg_type(&sub)!=DBUS_TYPE_INVALID&&!refused) {
                const char *name=NULL; dbus_message_iter_get_basic(&sub,&name); REQUIRE(++count<=16&&name&&strlen(name)<=64);
                if (!refused&&!strcmp(name,wanted)) found=1; dbus_message_iter_next(&sub);
            }
        }
        consume_reply(reply);
    }
    return found;
}
static int click_index(const Ref *r) {
    int count=property_int(r,ACTION,"NActions"),found=-1; REQUIRE(count>0&&count<=4);
    for (int n=0;n<count&&!refused;n++) {
        DBusMessage *m=method(r->bus,r->path,ACTION,"GetName"); if (!m) break; DBusMessageIter i; dbus_int32_t index=n;
        dbus_message_iter_init_append(m,&i); REQUIRE(dbus_message_iter_append_basic(&i,DBUS_TYPE_INT32,&index));
        DBusMessage *reply=call(a11y,r->bus,r->path,ACTION,"GetName",m); const char *name=NULL;
        if (reply) { REQUIRE(dbus_message_get_args(reply,NULL,DBUS_TYPE_STRING,&name,DBUS_TYPE_INVALID)&&name&&strlen(name)<=512);
            if (!refused&&!strcmp(name,"click")) { REQUIRE(found<0); found=n; } consume_reply(reply); }
    }
    REQUIRE(found>=0); return found;
}
static void bool_action(const Ref *r,const char *iface,const char *member,const char *text,int index) {
    if (refused) return; actions++; REQUIRE(actions<=15); if (refused) return;
    DBusMessage *m=method(r->bus,r->path,iface,member); if (!m) return; DBusMessageIter i; dbus_message_iter_init_append(m,&i);
    if (text) append_s(&i,text); if (index>=0) { dbus_int32_t n=index; REQUIRE(dbus_message_iter_append_basic(&i,DBUS_TYPE_INT32,&n)); }
    DBusMessage *reply=call(a11y,r->bus,r->path,iface,member,m); dbus_bool_t good=FALSE;
    if (reply) { REQUIRE(dbus_message_get_args(reply,NULL,DBUS_TYPE_BOOLEAN,&good,DBUS_TYPE_INVALID)&&good); consume_reply(reply); }
}
static void key(int code,unsigned mode) {
    if (refused) return; actions++; REQUIRE(actions<=15); if (refused) return;
    const char *path="/org/a11y/atspi/registry/deviceeventcontroller",*iface="org.a11y.atspi.DeviceEventController";
    DBusMessage *m=method(registry_owner,path,iface,"GenerateKeyboardEvent"); if (!m) return;
    DBusMessageIter i; dbus_int32_t keycode=code; dbus_uint32_t type=mode; dbus_message_iter_init_append(m,&i);
    REQUIRE(dbus_message_iter_append_basic(&i,DBUS_TYPE_INT32,&keycode)); append_s(&i,""); if (!refused) REQUIRE(dbus_message_iter_append_basic(&i,DBUS_TYPE_UINT32,&type));
    normal_empty(call(a11y,registry_owner,path,iface,"GenerateKeyboardEvent",m));
}

/* Direct GTK only: retain the SAME app credentials and original frame for all
 * five dialogs. Event-derived buses are authenticated, never enumerated.
 * Read-only IDs correlate these exact refs with the app's original native
 * getter proof; they are not credentials, ownership or a discovery mechanism. */
static Ref app_ref,main_window,dialog,dialog_parent,button,entry,discovered_dialog;
static char main_id[81],dialog_id[81];
static Ref completed_dialogs[5];
static unsigned completed_count,dialog_role,found_dialog,found_button,found_entry,heading,body,cancel_buttons,ok_buttons;
static int disappearance,action_started,new_dialog_seen,go_checked;
static uint64_t native_started;
static char app_bus[65];
static unsigned candidates_seen;
static char ignored_buses[4][65];
static unsigned ignored_count;
static int prior_dialog(const Ref *r) {for(unsigned n=0;n<completed_count;n++)if(same_ref(r,&completed_dialogs[n]))return 1;return 0;}
static int any_dialog(unsigned r) {return r==ATSPI_ROLE_DIALOG||r==ATSPI_ROLE_FILE_CHOOSER||r==ATSPI_ROLE_ALERT;}
static int dialog_role_allowed(unsigned r) {return ordinal<=3?(r==ATSPI_ROLE_DIALOG||r==ATSPI_ROLE_FILE_CHOOSER):(r==ATSPI_ROLE_DIALOG||r==ATSPI_ROLE_ALERT);}
static void revalidate_app(void) {
    REQUIRE(*app_bus&&bus_pid(a11y,app_bus)==app_proc.pid);uint64_t start=0;pid_t parent=0;
    if(refused||!stat_sample(app_proc.pid,&start,&parent))return;
    char path[80];struct stat exe;snprintf(path,sizeof path,"/proc/%ld/exe",(long)app_proc.pid);
    REQUIRE(start==app_proc.start&&parent==app_proc.parent&&!stat(path,&exe)&&stable_stat(&exe,&app_proc.exe));
}
static void candidate(Ref r) {
    if(refused||!admitted)return;
    if(*app_bus&&!strcmp(r.bus,app_bus))return;
    for(unsigned n=0;n<ignored_count;n++)if(!strcmp(r.bus,ignored_buses[n]))return;
    REQUIRE(++candidates_seen<=5);if(refused)return;
    pid_t pid=bus_pid(a11y,r.bus);Proc observed={0};proc_identity(pid,&observed);if(refused)return;
    if(pid==app_proc.pid) {
        check_proc(&admission,obj(&admission,0,"app"),&observed);REQUIRE(!*app_bus);if(refused)return;
        copy(app_bus,sizeof app_bus,r.bus);app_ref=application(r);REQUIRE(!strcmp(app_ref.bus,app_bus));
        char rule[256];snprintf(rule,sizeof rule,"type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='%s'",app_bus);match(rule);
    } else {
        int x=obj(&admission,0,"display"),server=obj(&admission,x,"server"),wm=obj(&admission,x,"windowManager");
        if(pid==registry_proc.pid)check_proc(&admission,obj(&admission,obj(&admission,x,"registry"),"process"),&observed);
        else if(pid==(pid_t)integer(&admission,obj(&admission,server,"identity"),"pid"))check_proc(&admission,server,&observed);
        else if(pid==(pid_t)integer(&admission,obj(&admission,wm,"identity"),"pid"))check_proc(&admission,wm,&observed);
        else fail(__LINE__);
        REQUIRE(ignored_count<4);if(!refused)copy(ignored_buses[ignored_count++],65,r.bus);
    }
}
static void topology_ids(const Ref *original_dialog,int require_go) {
    REQUIRE(same_ref(original_dialog,&dialog)&&!same_ref(original_dialog,&main_window));if(refused)return;
    char expected_main[81]={0},expected_dialog[81]={0},observed_main[81]={0},observed_dialog[81]={0};
    expected_ids(admission_sha,ordinal,expected_main,expected_dialog);
    property_id(&main_window,expected_main,observed_main);
    property_id(original_dialog,expected_dialog,observed_dialog);if(refused)return;
    if(*main_id)REQUIRE(!strcmp(main_id,observed_main));else REQUIRE(ordinal==1&&!require_go);
    if(*dialog_id)REQUIRE(!strcmp(dialog_id,observed_dialog));else REQUIRE(!require_go&&!go_checked);
    if(require_go) {
        REQUIRE(go_checked&&integer(&go_doc,0,"n")==ordinal);if(refused)return;
        int ownership=obj(&go_doc,0,"ownership");
        REQUIRE(!strcmp(str(&go_doc,ownership,"mainId"),observed_main)&&!strcmp(str(&go_doc,ownership,"dialogId"),observed_dialog));
    }
    if(refused)return;
    if(!*main_id)copy(main_id,sizeof main_id,observed_main);
    if(!*dialog_id)copy(dialog_id,sizeof dialog_id,observed_dialog);
}
static void showing_candidate(Ref r,unsigned event,uint64_t observed) {
    if(refused||!*app_bus||strcmp(r.bus,app_bus))return;
    REQUIRE(!prior_dialog(&r));if(refused)return;
    unsigned rr=role(&r);if(refused||!any_dialog(rr))return;
    Ref app=application(r);REQUIRE(same_ref(&app,&app_ref));if(refused)return;
    uint64_t state=states(&r);
    if(visible(state)) {
        REQUIRE(dialog_role_allowed(rr)&&actionable(state)&&(state&(UINT64_C(1)<<ATSPI_STATE_MODAL)));
        retain_ref(&r,event);
        if(new_dialog_seen)REQUIRE(same_ref(&r,&discovered_dialog));
        else {discovered_dialog=r;new_dialog_seen=1;native_started=observed;phase_end=minimum(phase_end,endpoint(observed,2*NS));}
    }
}
static void native_event(DBusMessage *m,uint64_t observed) {
    if(dbus_message_is_signal(m,DBUS_INTERFACE_DBUS,"NameOwnerChanged")){fail(__LINE__);return;}
    REQUIRE(dbus_message_is_signal(m,OBJECT_EVENT,"ChildrenChanged")||dbus_message_is_signal(m,OBJECT_EVENT,"StateChanged"));
    REQUIRE(++events<=1024);if(refused)return;
    const char *sig=dbus_message_get_signature(m),*sender=dbus_message_get_sender(m),*path=dbus_message_get_path(m),*member=dbus_message_get_member(m);
    REQUIRE((!strcmp(sig,"siiv(so)")||!strcmp(sig,"siiva{sv}"))&&unique_name(sender)&&object_path(path));if(refused)return;
    DBusMessageIter i,data;const char *detail=NULL;dbus_int32_t first=0,second=0;
    dbus_message_iter_init(m,&i);dbus_message_iter_get_basic(&i,&detail);REQUIRE(dbus_message_iter_next(&i));if(refused)return;
    dbus_message_iter_get_basic(&i,&first);REQUIRE(dbus_message_iter_next(&i));if(refused)return;
    dbus_message_iter_get_basic(&i,&second);REQUIRE(dbus_message_iter_next(&i));if(refused)return;dbus_message_iter_recurse(&i,&data);
    Ref source={0};copy(source.bus,sizeof source.bus,sender);copy(source.path,sizeof source.path,path);
    if(!strcmp(member,"ChildrenChanged")) {
        REQUIRE(detail&&(!strcmp(detail,"add")||!strcmp(detail,"remove"))&&first>=0&&second==0);Ref added={0};ref_iter(&data,&added);if(refused)return;
        if(found_dialog&&!strcmp(detail,"remove")&&same_ref(&added,&dialog)) {
            REQUIRE(action_started&&same_ref(&source,&dialog_parent));if(!disappearance)disappearance=2;
        }
        if(prior_dialog(&source)||prior_dialog(&added)){REQUIRE(!strcmp(detail,"remove"));return;}
        if(!strcmp(detail,"add")) {
            candidate(!strcmp(sender,registry_owner)?added:source);
            showing_candidate(added,1,observed);
        }
    } else {
        static const char *const allowed[]={"showing","visible","enabled","sensitive","focused","active","defunct"};int known=0;
        for(unsigned n=0;n<G_N_ELEMENTS(allowed);n++)if(detail&&!strcmp(detail,allowed[n]))known=1;
        REQUIRE(known&&(first==0||first==1)&&second==0);if(refused)return;
        int type=dbus_message_iter_get_arg_type(&data);
        if(type==DBUS_TYPE_STRING){const char *zero=NULL;dbus_message_iter_get_basic(&data,&zero);REQUIRE(zero&&!strcmp(zero,"0"));}
        else if(type==DBUS_TYPE_INT32){dbus_int32_t zero=1;dbus_message_iter_get_basic(&data,&zero);REQUIRE(zero==0);}else fail(__LINE__);
        if(prior_dialog(&source)){REQUIRE(strcmp(detail,"showing")||!first);return;}
        if(found_dialog&&same_ref(&source,&dialog)&&!strcmp(detail,"defunct")&&first){REQUIRE(action_started);if(!disappearance)disappearance=1;return;}
        if(!strcmp(detail,"showing")&&first){candidate(source);showing_candidate(source,2,observed);}
    }
}
static void dispatch(void) {
    pump();while(qcount&&!refused){DBusMessage *m=queue[qhead];uint64_t observed=qtime[qhead];REQUIRE(qsource[qhead]==2);
        qhead=(qhead+1)%32;qcount--;native_event(m,observed);dbus_message_unref(m);}
}
static void scan_controls(Ref r,unsigned depth,int location,Ref ancestors[13]) {
    REQUIRE(depth<=12);if(refused)return;
    for(unsigned n=0;n<depth;n++)REQUIRE(!same_ref(&r,&ancestors[n]));if(refused)return;
    ancestors[depth]=r;retain_ref(&r,0);unsigned rr=role(&r);uint64_t state=states(&r);if(refused||!visible(state))return;
    if(any_dialog(rr))REQUIRE(depth==0&&same_ref(&r,&dialog)&&rr==dialog_role);
    char name[513]={0};property_name(&r,name);if(!strcmp(name,"Location Layer"))location=1;
    if(!strcmp(name,QUIT_TITLE))heading++;if(!strcmp(name,QUIT_BODY))body++;
    const char *expected=(ordinal==2||ordinal==3)?"Select":ordinal==5?"OK":"Cancel";
    if(rr==ATSPI_ROLE_PUSH_BUTTON) {
        if(!strcmp(name,"Cancel"))cancel_buttons++;if(!strcmp(name,"OK"))ok_buttons++;
        if(!strcmp(name,expected)){REQUIRE(++found_button==1&&actionable(state));button=r;}
    }
    if(location&&(state&(UINT64_C(1)<<ATSPI_STATE_EDITABLE))&&has_interface(&r,"org.a11y.atspi.EditableText")){REQUIRE(++found_entry==1);entry=r;}
    int count=property_int(&r,ACCESS,"ChildCount");REQUIRE(count>=0&&count<=64);
    for(int n=0;n<count&&!refused;n++)scan_controls(child(&r,n),depth+1,location,ancestors);
    if(!refused)REQUIRE(property_int(&r,ACCESS,"ChildCount")==count);
}
static void scan_buttons(void) {
    found_button=found_entry=heading=body=cancel_buttons=ok_buttons=0;Ref ancestors[13];scan_controls(dialog,0,0,ancestors);
    REQUIRE(found_button==1);if(ordinal>=4)REQUIRE(heading==1&&body==1&&cancel_buttons==1&&ok_buttons==1);
}
static void scan_application(void) {
    // Only native top-levels of the authenticated original app, never a desktop
    // scan or traversal into WebKit's separately owned document accessibility.
    revalidate_app();REQUIRE(role(&app_ref)==ATSPI_ROLE_APPLICATION);if(refused)return;
    int count=property_int(&app_ref,ACCESS,"ChildCount");REQUIRE(count>=2&&count<=8);
    unsigned frames=0,dialogs=0;Ref frame={0},actual={0};unsigned rr_dialog=0;
    for(int n=0;n<count&&!refused;n++) {
        Ref r=child(&app_ref,n);unsigned rr=role(&r);uint64_t state=states(&r);if(!visible(state))continue;
        if(rr==ATSPI_ROLE_FRAME) {
            char name[513]={0};property_name(&r,name);REQUIRE(++frames==1&&!strcmp(name,"Mobile Release Kit"));frame=r;
        } else if(any_dialog(rr)) {
            REQUIRE(++dialogs==1&&dialog_role_allowed(rr)&&actionable(state)&&(state&(UINT64_C(1)<<ATSPI_STATE_MODAL)));
            actual=r;rr_dialog=rr;
        } else fail(__LINE__);
    }
    REQUIRE(frames==1&&dialogs==1&&new_dialog_seen&&same_ref(&actual,&discovered_dialog));
    if(*main_window.bus)REQUIRE(same_ref(&frame,&main_window));else main_window=frame;
    if(found_dialog)REQUIRE(same_ref(&actual,&dialog));
    dialog=actual;dialog_role=rr_dialog;found_dialog=1;dialog_parent=parent_ref(&dialog);
    REQUIRE(same_ref(&dialog_parent,&app_ref)); // exact direct-GTK topology pin
    topology_ids(&dialog,go_checked);
    REQUIRE(property_int(&app_ref,ACCESS,"ChildCount")==count);scan_buttons();
}
static void read_record(const char *name,Doc *doc,char sha[65],uint64_t end,int go) {
    char path[350],bytes[16385]; snprintf(path,sizeof path,"%s/%s",native_root,name); struct stat st; size_t length=0; int found=0;
    for (unsigned attempt=0;attempt<400&&!refused;attempt++) {
        REQUIRE(now_ns()<end&&++polls<=20000); if (refused) break;
        if (!lstat(path,&st)) { found=1; break; }
        if (errno!=ENOENT) { fail(__LINE__); break; }
        pump(); nap();
        /* Admission can legitimately follow up to seven seconds after ready.
           Keep 400 metadata attempts without narrowing that to 400*5ms. This
           is spacing inside the SAME endpoint, not a fresh timeout. */
        if (!go&&!refused) { nap(); nap(); nap(); }
    }
    REQUIRE(found); if (refused||!read_file(path,bytes,go?4097:sizeof bytes,&length,&st,0)) return;
    digest(bytes,length,sha); remember_record(name,bytes,length); parse(doc,bytes,length,!go); if (refused) return;
    if (go) go_schema(doc); else admission_schema(doc); if (refused) return;
    REQUIRE(!strcmp(str(doc,0,"case"),case_id)&&!strcmp(str(doc,0,"binding"),binding)&&now_ns()<end);
    verify_roots(); if (refused) return;
    int r=obj(doc,0,"roots"); check_id(doc,obj(doc,r,"run"),&roots[0]); check_id(doc,obj(doc,r,"app"),&roots[1]); check_id(doc,obj(doc,r,"native"),&roots[2]); check_id(doc,obj(doc,0,"file"),&st);
    if (go) {
        REQUIRE(!go_checked&&*main_id&&*dialog_id);
        REQUIRE(!strcmp(str(doc,0,"admissionSha256"),admission_sha)&&integer(doc,0,"n")==ordinal&&!strcmp(str(doc,0,"kind"),kind)&&!strcmp(str(doc,0,"presentedSha256"),presented_sha));
        int app=obj(&admission,0,"app"),pid=obj(&admission,app,"identity"),writer=obj(doc,0,"writer");
        REQUIRE(integer(doc,writer,"pid")==integer(&admission,pid,"pid")&&decimal(doc,writer,"startTicks")==decimal(&admission,pid,"startTicks"));
        int ownership=obj(doc,0,"ownership");
        REQUIRE(!strcmp(str(doc,ownership,"mainId"),main_id)&&!strcmp(str(doc,ownership,"dialogId"),dialog_id)&&
            decimal(doc,ownership,"checkedNs")>=presented_written&&decimal(doc,0,"checkpointNs")>=presented_written&&
            decimal(doc,0,"writtenNs")<=endpoint(presented_observed,2*NS));
        if(!refused)go_checked=1;
    }
}
static void admission_check(void) {
    int b=obj(&admission,0,"build"),x=obj(&admission,0,"display");
    REQUIRE(!strcmp(str(&admission,b,"baselineManifest"),BASELINE)&&!strcmp(str(&admission,b,"apiInventory"),API_INVENTORY));
    const char *pins[]={"sourceProfileSha256","installedClosureSha256","loaderClosureSha256","writerAuditSha256"};
    for(unsigned n=0;n<4;n++)REQUIRE(!strcmp(str(&admission,0,pins[n]),APPROVED_AUDITS[n]));
    GString *build=g_string_new("MRK_NATIVE_BUILD_V1\n");
    if(!refused)for(int n=admission.node[b].child;n>=0;n=admission.node[n].next){g_string_append(build,admission.node[n].text);g_string_append_c(build,'\n');}
    char computed[65];digest(build->str,build->len,computed);g_string_free(build,TRUE);REQUIRE(!strcmp(computed,binding));
    int outer=obj(&admission,0,"outer"),app=obj(&admission,0,"app"),helper=obj(&admission,0,"helper");
    check_proc(&admission,helper,&self_proc);verify_proc(&admission,outer);
    proc_identity((pid_t)integer(&admission,obj(&admission,app,"identity"),"pid"),&app_proc);check_proc(&admission,app,&app_proc);
    REQUIRE(!strcmp(str(&admission,b,"helperBinary"),self_proc.sha)&&!strcmp(helper_hash,self_proc.sha)
        &&!strcmp(str(&admission,b,"appBinary"),app_proc.sha)
        &&!strcmp(str(&admission,obj(&admission,outer,"executable"),"sha256"),str(&admission,b,"launcherRuntime")));
    int writer=obj(&admission,0,"writer"),outerid=obj(&admission,outer,"identity");
    REQUIRE(integer(&admission,writer,"pid")==integer(&admission,outerid,"pid")&&decimal(&admission,writer,"startTicks")==decimal(&admission,outerid,"startTicks")
        &&self_proc.parent==(pid_t)integer(&admission,outerid,"pid")&&app_proc.parent==self_proc.parent);
    int reg=obj(&admission,x,"registry");REQUIRE(!strcmp(str(&admission,reg,"owner"),registry_owner));check_proc(&admission,obj(&admission,reg,"process"),&registry_proc);
    const char *addresses[]={getenv("DBUS_SESSION_BUS_ADDRESS"),getenv("AT_SPI_BUS_ADDRESS")},*buses[]={"sessionBus","a11yBus"};
    for(unsigned n=0;n<2&&!refused;n++) {
        int bus=obj(&admission,x,buses[n]);char sha[65];digest(addresses[n],strlen(addresses[n]),sha);
        REQUIRE(!strcmp(str(&admission,bus,"id"),n?a11y_id:session_id)&&!strcmp(str(&admission,bus,"addressSha256"),sha));verify_proc(&admission,obj(&admission,bus,"process"));
    }
    REQUIRE(getenv("DISPLAY")&&!strcmp(str(&admission,x,"display"),getenv("DISPLAY")));
    int pipes=obj(&admission,0,"pipes");
    for(int fd=1;fd<=2&&!refused;fd++) {
        struct stat st;int flags=fcntl(fd,F_GETFL),descriptor=fcntl(fd,F_GETFD);
        REQUIRE(!fstat(fd,&st)&&S_ISFIFO(st.st_mode)&&flags>=0&&(flags&O_NONBLOCK)&&(flags&O_ACCMODE)==O_WRONLY&&descriptor>=0);if(refused)break;
        int pipe=obj(&admission,pipes,fd==1?"helperStdout":"helperStderr");
        REQUIRE(decimal(&admission,pipe,"device")==st.st_dev&&decimal(&admission,pipe,"inode")==st.st_ino&&!fcntl(fd,F_SETFD,descriptor|FD_CLOEXEC));
    }
    verify_proc(&admission,obj(&admission,x,"server"));verify_proc(&admission,obj(&admission,x,"windowManager"));
    int f=obj(&admission,0,"fixtures");struct stat p={0},s={0};
    REQUIRE(!lstat(project,&p)&&!lstat(source_file,&s)&&p.st_mode==040700&&s.st_mode==0100600&&s.st_size==12&&s.st_nlink==1&&p.st_uid==getuid()&&s.st_uid==getuid());
    if(refused)return; /* Failed acquisition never reaches a metadata consumer. */
    check_id(&admission,obj(&admission,f,"project"),&p);check_id(&admission,obj(&admission,f,"source"),&s);
    const unsigned char synthetic[]={0xfe,0xed,0xfe,0xed,0,0,0,2,0,0,0,0};digest(synthetic,sizeof synthetic,computed);
    REQUIRE(!strcmp(str(&admission,f,"sourceSha256"),computed)&&!strcmp(str(&admission,0,"readySha256"),ready_sha));
    uint64_t spawn=decimal(&admission,0,"appSpawnNs");REQUIRE(spawn>=ready_written&&spawn<=minimum(endpoint(ready_written,5*NS),endpoint(helper_spawn,10*NS))&&now_ns()<=endpoint(spawn,2*NS));
    outer_end=decimal(&admission,0,"outerEndNs");REQUIRE(outer_end<=endpoint(helper_spawn,100*NS));if(!refused)admitted=1;
}
static void presented(void) {
    REQUIRE(*main_id&&*dialog_id&&!go_checked);if(refused)return;
    GString *tail=g_string_new(NULL);presented_observed=now_ns();
    g_string_append_printf(tail,",\"admissionSha256\":\"%s\",\"n\":%u,\"kind\":\"%s\",\"observedNs\":\"%"PRIu64"\",\"association\":{\"route\":\"direct-gtk\",\"process\":",admission_sha,ordinal,kind,presented_observed);
    append_proc(tail,&app_proc);g_string_append(tail,",\"application\":");append_ref(tail,&app_ref);
    g_string_append(tail,",\"mainWindow\":");append_ref(tail,&main_window);g_string_append(tail,",\"parent\":");append_ref(tail,&dialog_parent);
    g_string_append(tail,",\"mainId\":");quoted(tail,main_id);g_string_append(tail,",\"dialogId\":");quoted(tail,dialog_id);
    g_string_append(tail,"},\"dialog\":");append_ref(tail,&dialog);
    g_string_append(tail,",\"button\":");append_ref(tail,&button);
    g_string_append_printf(tail,",\"dialogRole\":\"%s\",\"states\":\"showing-enabled-sensitive-modal-singleton\",\"buttonRole\":\"push-button\",\"buttonAction\":\"click\"",dialog_role==ATSPI_ROLE_FILE_CHOOSER?"file-chooser":dialog_role==ATSPI_ROLE_ALERT?"alert":"dialog");
    char file[32];snprintf(file,sizeof file,"d%u.presented.json",ordinal);presented_written=publish(file,"presented",tail,presented_sha);g_string_free(tail,TRUE);
}
static void perform(void) {
    dispatch();REQUIRE(!disappearance&&go_checked);if(refused)return;verify_roots();
    Ref original_dialog=dialog,original_parent=dialog_parent,original_button=button;unsigned original_role=dialog_role;
    scan_application();REQUIRE(same_ref(&dialog,&original_dialog)&&same_ref(&dialog_parent,&original_parent)&&same_ref(&button,&original_button)&&dialog_role==original_role);
    REQUIRE(actionable(states(&dialog))&&actionable(states(&button))&&role(&button)==ATSPI_ROLE_PUSH_BUTTON);
    int index=click_index(&button),select=ordinal==2||ordinal==3;const char *location=ordinal==2?project:source_file;
    struct stat before={0},after={0};uint64_t started=now_ns();
    REQUIRE(started>=decimal(&go_doc,0,"writtenNs")&&started<phase_end);if(refused)return;action_started=1;
    if(select) {
        REQUIRE(!lstat(location,&before)&&before.st_uid==getuid()&&(ordinal==2?before.st_mode==040700:(before.st_mode==0100600&&before.st_size==12&&before.st_nlink==1)));
        check_id(&go_doc,obj(&go_doc,0,"selected"),&before);if(refused)return;
        bool_action(&original_button,"org.a11y.atspi.Component","GrabFocus",NULL,-1);REQUIRE(states(&original_button)&(UINT64_C(1)<<ATSPI_STATE_FOCUSED));
        key(4,5);key(108,3);key(4,6); // exactly one scheduled Control unlock, never repair
        if(refused)return;
        scan_buttons();REQUIRE(same_ref(&button,&original_button)&&found_entry==1&&actionable(states(&entry))&&(states(&entry)&(UINT64_C(1)<<ATSPI_STATE_FOCUSED)));
        if(refused)return;Ref original_entry=entry;descendant_of(original_entry,&original_dialog);
        bool_action(&original_entry,"org.a11y.atspi.EditableText","SetTextContents",location,-1);
        REQUIRE(states(&original_entry)&(UINT64_C(1)<<ATSPI_STATE_FOCUSED));dispatch();REQUIRE(!disappearance);
        char name[513]={0};property_name(&original_button,name);Ref parent=parent_ref(&original_dialog),bound=application(original_button);topology_ids(&original_dialog,1);
        REQUIRE(!strcmp(name,"Select")&&same_ref(&parent,&original_parent)&&same_ref(&bound,&app_ref)&&role(&original_dialog)==original_role);
        descendant_of(original_button,&original_dialog);REQUIRE(actionable(states(&original_dialog))&&actionable(states(&original_button))&&click_index(&original_button)==index);
    }
    dispatch();REQUIRE(!disappearance);if(refused)return;
    bool_action(&original_button,ACTION,"DoAction",NULL,index);
    while(!refused&&now_ns()<phase_end){dispatch();if(disappearance)break;nap();}
    REQUIRE(!refused&&now_ns()<phase_end&&disappearance);verify_roots();
    if(select){REQUIRE(!lstat(location,&after)&&stable_stat(&before,&after));check_id(&go_doc,obj(&go_doc,0,"selected"),&after);}
    if(refused)return;
    last_completed=now_ns();GString *tail=g_string_new(NULL);
    g_string_append_printf(tail,",\"admissionSha256\":\"%s\",\"n\":%u,\"kind\":\"%s\",\"presentedSha256\":\"%s\",\"goSha256\":\"%s\",\"action\":\"%s\",\"startedNs\":\"%"PRIu64"\",\"completedNs\":\"%"PRIu64"\",\"steps\":%s,\"completion\":{\"route\":\"direct-gtk\",\"disappearance\":\"%s\",\"dialog\":",
        admission_sha,ordinal,kind,presented_sha,go_sha,dialog_action(ordinal),started,last_completed,
        select?"[\"focus:true\",\"control-lock:normal\",\"keysym-l:normal\",\"control-unlock:normal\",\"set-location:true\",\"click:true\"]":"[\"click:true\"]",disappearance==1?"defunct":"removed-from-bound-root");
    append_ref(tail,&original_dialog);g_string_append(tail,"},\"selected\":");if(select)append_id(tail,&after);else g_string_append(tail,"null");
    g_string_append_printf(tail,",\"counts\":{\"events\":%"PRIu64",\"wireMessages\":%"PRIu64",\"queries\":%"PRIu64",\"nodes\":%"PRIu64",\"actions\":%"PRIu64"}",events,wire_messages,queries,nodes,actions);
    char file[32],sha[65];snprintf(file,sizeof file,"d%u.input.json",ordinal);publish(file,"input",tail,sha);g_string_free(tail,TRUE);
    if(!refused){REQUIRE(completed_count<5);completed_dialogs[completed_count++]=original_dialog;}
}
int main(int argc,char **argv) {
    (void)argv;if(argc!=1||getuid()==0||geteuid()!=getuid()||!hex(API_INVENTORY,64))return 2;
    for(unsigned n=0;n<4;n++)if(!hex(APPROVED_AUDITS[n],64))return 2;
    const char *root=getenv("MRK_SESSION_GTK_ROOT"),*case_env=getenv("MRK_SESSION_GTK_CASE"),*build=getenv("MRK_NATIVE_BINDING"),*binary=getenv("MRK_NATIVE_HELPER_SHA256"),*spawn=getenv("MRK_NATIVE_HELPER_SPAWN_NS");
    REQUIRE(root&&case_env&&build&&binary&&spawn&&strlen(root)<=256&&root[0]=='/'&&!strcmp(case_env,"SG1")&&hex(build,64)&&hex(binary,64));if(refused)return 2;
    copy(temp_root,sizeof temp_root,root);copy(case_id,sizeof case_id,case_env);copy(binding,sizeof binding,build);copy(helper_hash,sizeof helper_hash,binary);
    helper_spawn=dec(spawn);phase_end=endpoint(helper_spawn,5*NS);outer_end=endpoint(helper_spawn,100*NS);REQUIRE(helper_spawn<=now_ns());
    char canonical[PATH_MAX],app_path[300];REQUIRE(realpath(root,canonical)&&!strcmp(canonical,root));
    snprintf(native_root,sizeof native_root,"%s/native",root);snprintf(project,sizeof project,"%s/project",root);snprintf(source_file,sizeof source_file,"%s/outside/synthetic.jks",root);snprintf(app_path,sizeof app_path,"%s/app",root);
    REQUIRE(!lstat(root,&roots[0])&&!lstat(app_path,&roots[1])&&!lstat(native_root,&roots[2]));for(unsigned n=0;n<3;n++)REQUIRE(roots[n].st_mode==040700&&roots[n].st_uid==getuid());
    const char *session_address=getenv("DBUS_SESSION_BUS_ADDRESS"),*a11y_address=getenv("AT_SPI_BUS_ADDRESS");
    REQUIRE(session_address&&a11y_address&&strlen(session_address)<=512&&strlen(a11y_address)<=512);if(refused)return 2;
    proc_identity(getpid(),&self_proc);REQUIRE(!strcmp(self_proc.sha,helper_hash));if(refused)return 2;
    session=connect_bus(session_address,0);a11y=connect_bus(a11y_address,2);if(refused)return 2;
    bus_owner(a11y,REGISTRY,registry_owner);proc_identity(bus_pid(a11y,registry_owner),&registry_proc);
    match("type='signal',interface='org.a11y.atspi.Event.Object',member='ChildrenChanged'");match("type='signal',interface='org.a11y.atspi.Event.Object',member='StateChanged'");
    match("type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.a11y.atspi.Registry'");subscribe(1);bus_id(session,session_id);bus_id(a11y,a11y_id);
    GString *tail=g_string_new(",\"helper\":");append_proc(tail,&self_proc);g_string_append_printf(tail,",\"registry\":{\"owner\":\"%s\",\"process\":",registry_owner);append_proc(tail,&registry_proc);
    g_string_append_printf(tail,"},\"sessionBusId\":\"%s\",\"a11yBusId\":\"%s\",\"subscriptions\":\"direct-gtk-events-v1\"",session_id,a11y_id);
    REQUIRE(queries<=128&&now_ns()<phase_end);ready_written=publish("ready.json","ready",tail,ready_sha);g_string_free(tail,TRUE);
    phase_end=minimum(endpoint(ready_written,7*NS),endpoint(helper_spawn,12*NS));read_record("admission.json",&admission,admission_sha,phase_end,0);if(!refused)admission_check();
    for(ordinal=1;ordinal<=5&&!refused;ordinal++) {
        kind=dialog_kinds[ordinal-1];phase_queries=phase_nodes=retained_count=0;
        found_dialog=found_button=found_entry=heading=body=cancel_buttons=ok_buttons=0;
        dialog=(Ref){0};dialog_parent=(Ref){0};button=(Ref){0};entry=(Ref){0};discovered_dialog=(Ref){0};
        dialog_id[0]=0;disappearance=action_started=new_dialog_seen=go_checked=0;native_started=0;phase_end=outer_end;
        // app_ref, main_window, main_id and app_proc survive this boundary.
        while(!refused&&now_ns()<phase_end){dispatch();if(new_dialog_seen&&*app_ref.bus)break;nap();}
        REQUIRE(now_ns()<phase_end&&*app_ref.bus&&native_started);if(refused)break;
        scan_application();click_index(&button);dispatch();REQUIRE(!disappearance);if(refused)break;
        presented();uint64_t go_end=minimum(endpoint(presented_observed,2*NS),outer_end);phase_end=go_end;
        char file[32];snprintf(file,sizeof file,"d%u.go.json",ordinal);read_record(file,&go_doc,go_sha,go_end,1);if(refused)break;
        phase_end=decimal(&go_doc,0,"inputEndNs");REQUIRE(phase_end<=outer_end&&now_ns()<phase_end);perform();
    }
    if(!refused) {
        phase_end=minimum(endpoint(last_completed,2*NS),outer_end);subscribe(0);dispatch();
        REQUIRE(completed_count==5&&actions==15&&now_ns()<phase_end&&qcount==0&&original_pending.handle==NULL&&original_pending.reply==NULL);
        if(!refused) {
            // These void libdbus close/unref APIs require the reviewed installed
            // ownership/normal-close contract. Not raw-fd probes or Drop claims.
            DBusConnection *connections[]={session,a11y};
            for(unsigned n=0;n<2;n++){dbus_connection_close(connections[n]);dbus_connection_unref(connections[n]);}
            session=a11y=NULL;return 0;
        }
    }
    // Unknown retains pending native originals for this failed owner. No kill,
    // cancellation, retry/unlock, replacement call or successful next case.
    fputs("sg1_native_original_unknown\n",stderr);return 2;
}
