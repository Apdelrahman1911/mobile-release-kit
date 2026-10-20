// Fixed HTTPS GitHub browser handoff. No shell, arbitrary URL or native callback.
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
extern int mrk_user(uint32_t *uid);
static int alpha(uint8_t c) {return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9');}
static int repo(const uint8_t *r,size_t n) {
    if(!r||!n||n>140)return 0;
    size_t slash=n;for(size_t i=0;i<n;i++)if(r[i]=='/'){if(slash!=n)return 0;slash=i;}
    if(slash<1||slash>39||slash+1>=n||n-slash-1>100||!alpha(r[0])||!alpha(r[slash-1]))return 0;
    for(size_t i=0;i<slash;i++)if(!alpha(r[i])&&(r[i]!='-'||(i&&r[i-1]=='-')))return 0;
    const uint8_t *name=r+slash+1;size_t len=n-slash-1;
    if((len==1&&name[0]=='.')||(len==2&&name[0]=='.'&&name[1]=='.'))return 0;
    if(len>=4&&name[len-4]=='.'&&(name[len-3]=='g'||name[len-3]=='G')&&(name[len-2]=='i'||name[len-2]=='I')&&(name[len-1]=='t'||name[len-1]=='T'))return 0;
    for(size_t i=0;i<len;i++)if(!alpha(name[i])&&name[i]!='.'&&name[i]!='_'&&name[i]!='-')return 0;
    return 1;
}
static int sha(const uint8_t *p,size_t n) {if(!p||n!=40)return 0;for(size_t i=0;i<n;i++)if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return 0;return 1;}
static int number(const uint8_t *p,size_t n) {if(!p||!n||n>20||p[0]<'1'||p[0]>'9')return 0;uint64_t value=0;for(size_t i=0;i<n;i++){if(p[i]<'0'||p[i]>'9')return 0;uint64_t digit=(uint64_t)(p[i]-'0');if(value>(UINT64_MAX-digit)/10)return 0;value=value*10+digit;}return 1;}
int mrk_github_browser(int kind,const uint8_t *repository,size_t repository_len,
    const uint8_t *first,size_t first_len,const uint8_t *second,size_t second_len) {
    if(!repo(repository,repository_len))return EINVAL;
    if(kind==1||kind==2){if(!number(first,first_len)||second_len!=0)return EINVAL;}
    else if(kind==3){if(!sha(first,first_len)||!sha(second,second_len)||memcmp(first,second,40)==0)return EINVAL;}
    else return EINVAL;
    uint32_t uid=0;int admitted=mrk_user(&uid);if(admitted)return admitted;
    if(![NSThread isMainThread])return EPERM;
    @try {
        @autoreleasepool {
            // ASCII only; no interpolation can introduce scheme/authority,
            // percent escapes, path traversal, fragments or arbitrary query.
            NSString *r=[[[NSString alloc] initWithBytes:repository length:repository_len encoding:NSASCIIStringEncoding] autorelease];
            NSString *a=[[[NSString alloc] initWithBytes:first length:first_len encoding:NSASCIIStringEncoding] autorelease];
            NSString *text=nil;
            if(kind==3){
                NSString *b=[[[NSString alloc] initWithBytes:second length:second_len encoding:NSASCIIStringEncoding] autorelease];
                if(!b)return ENOMEM;text=[NSString stringWithFormat:@"https://github.com/%@/compare/%@...%@",r,a,b];
            } else text=[NSString stringWithFormat:@"https://github.com/%@/pull/%@%@",r,a,kind==2?@"/files":@""];
            if(!r||!a||!text)return ENOMEM;
            NSURL *url=[NSURL URLWithString:text];NSWorkspace *workspace=[NSWorkspace sharedWorkspace];
            if(!url||!workspace)return ENOMEM;
            // Browser login is independent of the app's selected API account.
            return [workspace openURL:url]?0:EIO;
        }
    } @catch(NSException *exception){(void)exception;return EIO;}
}
