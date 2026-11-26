"""Android registration XPC client: peer-requirement gate (#30).

Executable checks only on disposable inputs. No mach service, launchd job,
helper registration, Keychain item or credential is touched. Real signing
identity values never enter this test; the requirement template is filled
with synthetic Team ID / certificate digests.
"""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "desktop/native/macos-installed-native"
SYNTHETIC_TEAM = "ABCDE12345"
SYNTHETIC_CERTIFICATE = "0123456789abcdef0123456789abcdef01234567"


def unit(text, start, end):
    first = text.index(start)
    return text[first:text.index(end, first + len(start))]


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("/usr/bin/clang"), "macOS clang required")
class AndroidIpcRequirementTests(unittest.TestCase):
    def setUp(self):
        self.registration = (NATIVE / "src/android_registration.m").read_text()

    def compile_run(self, source, *flags):
        with tempfile.TemporaryDirectory(prefix="mrk-ipc-requirement-") as temporary:
            path = Path(temporary) / "probe.m"
            binary = Path(temporary) / "probe"
            path.write_text(source)
            subprocess.run(["/usr/bin/clang", "-fobjc-arc", "-Wall", "-Werror", *flags, str(path),
                            "-framework", "Foundation", "-o", str(binary)],
                           check=True, capture_output=True, timeout=60)
            return subprocess.run([str(binary)], check=True, capture_output=True, timeout=30).stdout.decode()

    def test_unconfigured_requirement_is_unavailable_not_permissive(self):
        # The ORIGINAL gate and its ORIGINAL empty defaults, compiled per case.
        defaults = unit(self.registration, "#ifndef MRK_ANDROID_APP_REQUIREMENT", "#if defined(MRK_E2_NATIVE_FIXTURE)")
        gate = unit(self.registration, "int mrk_android_identity_available(void) {", "\nsize_t mrk_android_client_bytes")
        body = defaults + gate + '\n#include <stdio.h>\nint main(void){printf("%d\\n",mrk_android_identity_available());}\n'
        cases = (((), "0"),
                 (("-DMRK_ANDROID_APP_REQUIREMENT=\"x\"",), "0"),
                 (("-DMRK_ANDROID_HELPER_REQUIREMENT=\"x\"",), "0"),
                 (("-DMRK_ANDROID_APP_REQUIREMENT=\"x\"", "-DMRK_ANDROID_HELPER_REQUIREMENT=\"y\""), "1"))
        for flags, expected in cases:
            with self.subTest(flags=flags):
                self.assertEqual(self.compile_run(body, *flags).strip(), expected)

    def test_client_checks_identity_then_sets_one_requirement_before_resume(self):
        begin = unit(self.registration, "int mrk_android_client_begin(void *raw) {", "\n// Pure transport/prepare-role DATA only.")
        ordered = ("|| !mrk_android_identity_available()",
                   "initWithMachServiceName:MRK_ANDROID_SERVICE_NAME options:NSXPCConnectionPrivileged",
                   "[connection setCodeSigningRequirement:@MRK_ANDROID_HELPER_REQUIREMENT];",
                   "[connection resume];")
        positions = [begin.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(begin.count("[connection resume];"), 1)
        self.assertEqual(begin.count("setCodeSigningRequirement:@MRK_ANDROID_HELPER_REQUIREMENT"), 1)
        # An exception (e.g. an invalid requirement) is a failure, never a skip.
        self.assertIn("@catch (NSException *exception) {\n        (void)exception; client_exception(c);", begin)
        self.assertIn('#define MRK_ANDROID_SERVICE_NAME @"dev.mobile-release-kit.desktop.android-register"', self.registration)

    def test_os_enforces_the_app_requirement_shape_against_an_impostor_peer(self):
        # The app's actual requirement template from build.rs, with synthetic
        # identity values. The in-process anonymous listener is an ad-hoc peer.
        build = (NATIVE / "build.rs").read_text()
        template = re.search(r'let requirement = \|identifier: &str\| format!\(\s*"(.*?)"\);', build, re.S)
        self.assertIsNotNone(template)
        requirement = (template.group(1).replace('\\"', '"')
                       .replace("{identifier}", "dev.mobile-release-kit.desktop.android-register")
                       .replace("{team}", SYNTHETIC_TEAM).replace("{certificate}", SYNTHETIC_CERTIFICATE))
        self.assertNotIn("{", requirement)
        literal = requirement.replace("\\", "\\\\").replace('"', '\\"')
        source = r'''#import <Foundation/Foundation.h>
@protocol P - (void)ping:(void (^)(int))reply; @end
@interface S : NSObject <P, NSXPCListenerDelegate> @end
@implementation S
- (void)ping:(void (^)(int))reply { reply(42); }
- (BOOL)listener:(NSXPCListener *)l shouldAcceptNewConnection:(NSXPCConnection *)c {
  c.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(P)]; c.exportedObject = self; [c resume]; return YES; }
@end
static void one(NSXPCListener *l, const char *label, NSString *req) {
  NSXPCConnection *c = [[NSXPCConnection alloc] initWithListenerEndpoint:l.endpoint];
  c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(P)];
  @try { if (req) [c setCodeSigningRequirement:req]; }
  @catch (NSException *e) { printf("%s raised\n", label); [c invalidate]; return; }
  [c resume];
  __block long code = 0; __block int value = 0;
  id proxy = [c synchronousRemoteObjectProxyWithErrorHandler:^(NSError *e) { code = e.code; }];
  [proxy ping:^(int v) { value = v; }];
  printf("%s %d %ld\n", label, value, code); [c invalidate];
}
int main(void) { @autoreleasepool {
  S *s = [S new]; NSXPCListener *l = [NSXPCListener anonymousListener]; l.delegate = s; [l resume];
  one(l, "none", nil);
  one(l, "app-shape", @"REQUIREMENT");
  one(l, "empty", @"");
} return 0; }
'''.replace("REQUIREMENT", literal)
        lines = self.compile_run(source).splitlines()
        # Without a requirement ANY peer answers: the requirement is load-bearing.
        self.assertEqual(lines[0], "none 42 0")
        # NSXPCConnectionCodeSigningRequirementFailure: no reply reaches the app.
        self.assertEqual(lines[1], "app-shape 0 4102")
        # An empty requirement is an API exception (client_exception), not "any peer".
        self.assertEqual(lines[2], "empty raised")


if __name__ == "__main__":
    unittest.main()
