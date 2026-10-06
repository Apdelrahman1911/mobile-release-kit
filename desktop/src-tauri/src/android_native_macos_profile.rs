//! Finite original macOS Android native DATA; never a loader, process or consent.
//! Pins below were projected from complete authenticated vendor-member DATA.
//! They do not enable REFERENCES or replace original native reads/finality.
use serde::Serialize;
use crate::android_build_protocol::Profile;
use crate::android_toolchain_macos_policy::{self as policy, FileSpec, Inventory, MachArchitecture, MachCommands};

pub(crate) const JDK_ARCHIVE_BYTES: u64 = 185851019;
pub(crate) const JDK_ARCHIVE_SHA256: &str = "196d13ba5f10414bef7f6a05a9b3f00edacb18ebacef2b99485db9e2ee18f0e8";
pub(crate) const GRADLE_ARCHIVE_SHA256: &str = "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854";
#[derive(Clone, Copy, Serialize)]
pub(crate) struct MachPin {
    pub(crate) prefix_bytes: usize, pub(crate) prefix_sha256: &'static str,
    pub(crate) commands_sha256: &'static str, pub(crate) file_type: u32,
    pub(crate) install_name: Option<&'static str>,
    pub(crate) loads: &'static [&'static str], pub(crate) rpaths: &'static [&'static str],
}
impl MachPin {
    pub(crate) fn matches(&self, commands: &MachCommands) -> bool {
        self.matches_architecture(commands, MachArchitecture::Arm64)
    }
    fn matches_architecture(&self, commands: &MachCommands, architecture: MachArchitecture) -> bool {
        commands.architecture == architecture && commands.file_type == self.file_type
            && commands.header_sha256 == self.commands_sha256
            && commands.install_name.as_deref() == self.install_name
            && commands.loads.iter().map(String::as_str).eq(self.loads.iter().copied())
            && commands.rpaths.iter().map(String::as_str).eq(self.rpaths.iter().copied())
    }
    /// Exact original byte identity, with no native parser/allocation. Structural
    /// admission uses this before the original owner reserves native workspace.
    pub(crate) fn snapshot_bytes(&self, prefix: &[u8], commands: &[u8]) -> bool {
        prefix.len() == self.prefix_bytes && policy::digest_matches(prefix, self.prefix_sha256)
            && policy::digest_matches(commands, self.commands_sha256)
    }
    /// Parsed semantics are separately required inside the charged native closure.
    pub(crate) fn snapshot(&self, prefix: &[u8], commands: &MachCommands) -> bool {
        prefix.len() == self.prefix_bytes && policy::digest_matches(prefix, self.prefix_sha256) && self.matches(commands)
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub(crate) enum JdkPhase { Bootstrap, ExplicitJvmProvider, PostJli, ObservationOnly }
#[derive(Clone, Copy, Serialize)]
pub(crate) struct JdkNativePin {
    pub(crate) relative: &'static str, pub(crate) bytes: u64, pub(crate) sha256: &'static str,
    pub(crate) original_mode: u32, pub(crate) phase: JdkPhase, pub(crate) header: MachPin,
}
impl JdkNativePin {
    pub(crate) fn matches(&self, path: &str, bytes: u64, sha256: &str, mode: u32) -> bool {
        jdk_relative(path) == Some(self.relative) && bytes == self.bytes && sha256 == self.sha256
            && mode == (self.original_mode & !0o222)
    }
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct JdkJvmMemberPin {
    pub(crate) member: &'static str, pub(crate) bytes: u64, pub(crate) sha256: &'static str, pub(crate) mode: u32,
    pub(crate) counterpart: Option<&'static str>,
}
impl JdkJvmMemberPin {
    pub(crate) fn header(&self) -> Option<&'static MachPin> {
        match self.counterpart {
            Some(relative) => jdk_native(relative).map(|pin| &pin.header),
            None => (self.member == "classes/jdk/jpackage/internal/resources/jpackageapplauncher" && self.bytes == 185600
                && self.sha256 == "73403782287c715055d9f58cca4571add26f01817d710186bf6e52fa5ac1b442")
                .then_some(&JPACKAGE_TEMPLATE),
        }
    }
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct JdkJvmArchivePin {
    pub(crate) relative: &'static str, pub(crate) bytes: u64, pub(crate) sha256: &'static str,
    pub(crate) members: &'static [JdkJvmMemberPin],
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct TargetElfPin {
    pub(crate) path: &'static str, pub(crate) member: &'static str,
    pub(crate) bytes: u64, pub(crate) sha256: &'static str, pub(crate) original_mode: u32,
    pub(crate) class: u8, pub(crate) machine: u16, pub(crate) header: &'static [u8],
}
impl TargetElfPin {
    pub(crate) fn matches(&self, path: &str, bytes: u64, sha256: &str, mode: u32) -> bool {
        path == self.path && bytes == self.bytes && sha256 == self.sha256 && mode == 0o444
    }
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct ForeignLauncherPin {
    pub(crate) path: &'static str, pub(crate) member: &'static str, pub(crate) bytes: u64,
    pub(crate) sha256: &'static str, pub(crate) original_mode: u32,
}
pub(crate) const GRADLE_BAT: ForeignLauncherPin = ForeignLauncherPin {
    path: "gradle/bin/gradle.bat", member: "gradle-8.14.5/bin/gradle.bat", bytes: 3018,
    sha256: "d20e9ded0291e1ed6552d1df30022d2e5952ad493f9d3380f6a32b97f0cc80c7", original_mode: 0o755,
};
pub(crate) static JDK_NATIVE: &[JdkNativePin] = &[
    JdkNativePin { relative: "Contents/Home/bin/jar", bytes: 70448, sha256: "c55e508c52019bb483ee2e737b751ed44d5e9e86abe660c713404db43c58803d",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a69e71ca440e5664e069f67df8d05af5ecb41e7b25c94f085199651c94f26c0f", commands_sha256: "ef2ba338a4d0915c69b2fb01ca0ccf3b47effe8d13bbc544a4fcde3570c064a6", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jarsigner", bytes: 70464, sha256: "fe9a1276c5a18c115177f0e7a5bea9b3163739e280332044564089be7f766c64",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "adfb52ad634cc896febbc2db158bc8bfadb30bac8accd7ce894a59d387f0510b", commands_sha256: "f03f73bc040f338a1aef0304dfcd5decc842915cd88c5627aacde6ae8667816a", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/java", bytes: 70464, sha256: "af8b122943345320b179c75c3404d56a981017739746b75f9caf583632f0bea0",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "ede2f2280dd632c1c4322098e231f5eedf454c2241ae0103d4e6661ead98a757", commands_sha256: "481b50738668eddfc3d0a0047e5283fd2a481a57ca784a3ab32c6b4f810ab0f9", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/javac", bytes: 70464, sha256: "6f5159301c750bba340390eda5fdd4a0959445355f97c40aa9c2addb00ede5ab",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "467e3f2172ad919033c544582201051b702b4ff2964f06566d92b1c519020070", commands_sha256: "59ad97d854eb58f030501fd1771ee81d490fe4377b323f0fbf9f499b28ec9e43", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/javadoc", bytes: 70464, sha256: "16c9e93773c99393bac5bbbe12ad23472dfacdb77732da1b8720e743b787bb06",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "eed46b663fffc82c541850e7f703eb6cb8328976d2acb356ec2ebdcab8ea5732", commands_sha256: "dd8c5c38d35a33dd65095fc8c44860501be48acce7d34e51897b12bc8255692d", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/javap", bytes: 70464, sha256: "0b318cfea6a2866918cda88c64db9919e9d668aa2f7cc1bb0ccb11f49b243bbb",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "eab183dc78c24f01e837923a0be850a065dcebbebc20d90fa59b6ec66fd621fd", commands_sha256: "1039661d394725ba7da0aeb3f87aa2036469a0fe3b744772f24c476370cc5224", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jcmd", bytes: 70464, sha256: "e3aebdd820297b64e041203f766ebf28986abf0c8cf3e59ba0681d935160c0eb",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "7c5aa80d8cd9a87b0705c1382b90527ceccfd00bf6bcfee0e32782385bf5a8d7", commands_sha256: "10b5c6f119fdb56bcc2f8654f28a223a86cb16a1d26498e8e8c238ea2e593f17", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jconsole", bytes: 70464, sha256: "a7ddaf2cbea00efdbdb6eeaf1075ea2c6ae726da656831c5f832680fea80d504",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a7c19e64c0759493287fd75117dc4da7b4357f24e36bbf97ba2ed4ec14847625", commands_sha256: "e3d7e38bd048b636a4c6d65c4a7ad10a5571e488201ab3be92574903cff25bff", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jdb", bytes: 70448, sha256: "229e5965e072b20783c5bd008c39dd914bcd4223d5058767a3f4af2be0f2cb83",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "213b2be4a3a58d861d6b4bbf9c1ff8c24e5e4b02a6fea646e45874510f6cd165", commands_sha256: "e5b94ef1b77dde3fd6ad1f762a727d8b46a9c6bbfd8d985fac975d282dd28da5", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jdeprscan", bytes: 70464, sha256: "b68b8f98cda671af91f9c1efc4a014828cf34d80d8487d2e222f82b55bb373b6",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "515aaae101cac6611e19801ddaa9702c508a86a37ced72538547ac62e49ff7a5", commands_sha256: "9308b3e1b03d90e0bdd79aae53c3bfbced108848bbacb4dd404a120f65d31e92", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jdeps", bytes: 70464, sha256: "530d87e93a3321c91a0e5603077dc7a759b96e139bea8348fb1cd78c8059b90f",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "af1a8e56858102d4937d9ebf8f1116b678e722e5d2f36c2b093dbef90811494b", commands_sha256: "382543aefbe9fce3e7fce194c0dd824528ef86833d12721cc6386b1235a44ab5", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jfr", bytes: 70448, sha256: "da2a39b0eb0baae163398254c02f0e74d67b0d3b5dd4faedf500eac7bf11a630",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "596e4e7ee74a9ad7be008db88b83e1561f5e54ba59a2a8897763912cc5040292", commands_sha256: "48957eac1ba519b63a62776feaf2c5310d48438fd24be5307422fcdc684c0923", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jhsdb", bytes: 70464, sha256: "12c20fd4facc8ed4f31c813bf140b1da596797a5e0932ffba13c48f72f22bc3e",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "4519d71c6c97fdf69e1cab403427f2fb5c108acbf04889b70c02d79738745a03", commands_sha256: "f5cce32096dd9c0cb8322ebd2fc82251f9b3d0c5185ebb1eaf1d4da5492bb40f", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jimage", bytes: 70464, sha256: "66ff78759e96a1e130a0fb8cdcf37eac7d542ca49860726b0bed79f311405522",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "16c0c8e650aa89be03c281c51ff8970e746468d752255ab165af27f3e4ff5f2c", commands_sha256: "0e905d84de5ddd3790bf56971c2f38e6c7fb81df8826541e128dbfb763d19d6b", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jinfo", bytes: 70464, sha256: "939b38d404cc9055d2d3039a6fbfdfea4d783a370512bf1d7084f340e3a7337e",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a6e8e7171b048aa6f66ff8e6deeafba66a96ca4c01705587f50adc6780fd3fe7", commands_sha256: "4a3c231449dd55dd334cfb2b00b192258da743ed403d3d8bbda0f05bcd801846", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jlink", bytes: 70464, sha256: "601685bdfbfd2eb31d01e11dee94865f48910d90610829aa2c010c3ababf7650",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "db5057e2f3bbdddc6d32bfd1a43644807dc2325a59006f1ba264b9dee8ca2b17", commands_sha256: "1099be60788715e2e8471925548112910bbf9270c1eff0194ccdfbb0edb904e2", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jmap", bytes: 70464, sha256: "b491f891489a84c668915be116b28f26ef399501f249751a7ee197ba4b03e078",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "42e54588578e73186732ad7d49f66a5381cbcf1560c46e90800f1ef7a549697a", commands_sha256: "bda5570207c8134f6cec0031094269d40774ef217a6478cbe442c2d862762679", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jmod", bytes: 70464, sha256: "fc3a0982042318463a1648324f2432a71893f745f0e780b87ee75c3f6e7af4c8",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a8cb05917e7aa70550e31c26040c9d801e613d268020d7fc5216ac5ad5fe7ae8", commands_sha256: "0096e5af87d7f90af3cd93281c21fa7970d7cd377c8ff41a50fdb9b8ac0e4965", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jpackage", bytes: 70464, sha256: "c4aa90b52f2904e5abb87ea52ce108b25b733b5b2dd4a1c0cfd2fa61ac305342",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "be1203dd2929066440192d842cf8f2d89dadb685d0c87e6f1c0895c21817a432", commands_sha256: "020e586fede9fd6ce9277c3bdddf63d381e8218dd1569285e770add45d85de28", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jps", bytes: 70448, sha256: "5c09726ceee3b97982540aeaa84be190b8e6ac155d88b8507235079ba8310fe1",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "764eaec74eaff7b2d9237256906e04221df00ecf4729a81e2484813bdd114325", commands_sha256: "4bd5e82bc234409ae9bf84d17ed7ac60404056f320f24e442f805c8f603266e0", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jrunscript", bytes: 70464, sha256: "9bd7764585944634431ca97193f2c714c562b06ce6ab6aa918b84d36274a3283",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "6c69de25dc3ce0e79f0397ef07779f0508896615c145241c0972bd9cc62ff6a8", commands_sha256: "ab611d3979cec2ae3d531b5634d70471fa74ec2a6fc22e0e2c91d2cabca9f32d", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jshell", bytes: 70464, sha256: "73c4db331de31cb6c261fe5593d6d40cd2023cf6d584f0cb2b3f5fb03fa7a609",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "13922c137c85385af5a2e1952cf09fff4c06f3bc7cf5574d38b42aaa18bc503a", commands_sha256: "1e961900eaf6b4be5715dc859f6c800fcad540c9ade39d785a7b5822f56c9ce4", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jstack", bytes: 70464, sha256: "edbd8c8b0690b4844a75d2bd17ae6563baf63ef4942bedd16d5230f6e4b974a1",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "b042e6bef47c682332a7ce76e0fa99c046947a7f809a3a48842b80d784623e94", commands_sha256: "80d64976e66076fc9c74cb09d580e9fa36cd270cf920cb3c9d2f6554fa50d4d9", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jstat", bytes: 70464, sha256: "3fd61c3e2c179717a92fb19ebea8ffbe56a9eedad8eec82482695c38ce4f3cfc",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a144ae28b9b5e4760fa99649386ee8f7922e35f3d83198cabba25a93d8510ba2", commands_sha256: "b1b7d9364195a23d0e46207453f4c729972a8c18c40aa44a0e954d735a5a0ad2", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/jstatd", bytes: 70464, sha256: "13e9c26d467d2791d6dc5902d876d0a1a323e8472133d436ae64df65ce219aa0",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "f34c6aa53d12a35ae3b8785750b6fed6b20da4d9204321548a3ac0fe407a6937", commands_sha256: "384d92de1c853361a53cf7ba764e24572ab3d2115310de674c6ecf20c3a0f09a", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/keytool", bytes: 70464, sha256: "af587a253678cda7ca2704daee936af1993305ce9a9bc6d5018f37f49d425fcb",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "1944c0db18d910e87962f3aaa016564aa5adc29a10ac7ec90799a6324a40ff7c", commands_sha256: "a6219e55dbb53c08bbd481bac9d564d0d36f32ac4da863ed3ecef90f62dc31e9", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/rmiregistry", bytes: 70464, sha256: "aea46addd6ba9f6a44b119550000cac3e999bf2bd85673e5105ae0609c960850",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "da1a281f1ff098103c7f8b42ed0ff66f8b5bd38c9fdb9a2bc2e8eaf977a18de0", commands_sha256: "50cabbf5086377d2c29f6affa836dca99fa4a00351c5c373b37abc3efcf2d30d", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/bin/serialver", bytes: 70464, sha256: "fdfd5b5d9929c77750e480951212eabe800e4a2daa3b73995539242333d6f22e",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "2f72430af795d3aa01fea30abf182cbc03d0154a0eb4e5ad4aa1208534467f6d", commands_sha256: "9f0580bf73f5d27b1796d518c6c727d91c70878ec075bba6bfc6d883455d19df", file_type: 2,
            install_name: None, loads: &["@rpath/libjli.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path/../lib"] } },
    JdkNativePin { relative: "Contents/Home/lib/jspawnhelper", bytes: 72048, sha256: "269bbc5ed0956cd58014f0a02f3b31ab7b0bf3202bbdbc66457f06dbe50fbaed",
        original_mode: 0o755, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "2136eccb8c8b10fcd46b414f82a66c358ec8a6fea6b4c004134b274a41cdbc49", commands_sha256: "5820206411f05fe727c9c952031928bf75639ea5e1e7e909bbd6c265dcfecd5c", file_type: 2,
            install_name: None, loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &[] } },
    JdkNativePin { relative: "Contents/Home/lib/libattach.dylib", bytes: 71888, sha256: "d6f8a37fc720a762582b3b088197f06fb959f64119d977effe30ac842eb345ad",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "1ee039c359a984b05440cba20cec37d53a58d6fbc5f235336bcc2b6160c5374f", commands_sha256: "cf1204e6e3e6d0e51e74109aa06f76d4ead31674610d352ac7144853e2faace0", file_type: 6,
            install_name: Some("@rpath/libattach.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libawt.dylib", bytes: 551776, sha256: "cede2c8c314eb780fb2c7a2d0055de9324290449d4c0f1ef0e7fd684b84b2e8a",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "1971f636d24d6bfaf94b39e142ef4a6fca27e4b074e949830103e78b9e6d708a", commands_sha256: "95448e55077f380bad0d446aeddeb2e7574166f0fc7395d17c03197ed4f35b47", file_type: 6,
            install_name: Some("@rpath/libawt.dylib"), loads: &["@rpath/libjvm.dylib", "@rpath/libjava.dylib", "/usr/lib/libSystem.B.dylib", "@rpath/libmlib_image.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL", "/System/Library/Frameworks/Metal.framework/Versions/A/Metal", "/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libawt_lwawt.dylib", bytes: 1237072, sha256: "a540b8ca7a8c8c77f0db3f80c2b3449537b4a758bf1727f45361c4dcccf0b7ac",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "b7abc398794a3df3dde66fdd307bed2b8620391a1806e82d322ae1fcedb44013", commands_sha256: "c3afa5e4073fe15c3469906cf55fa61af1cb7c96f8332afbb33540f2fc89410a", file_type: 6,
            install_name: Some("@rpath/libawt_lwawt.dylib"), loads: &["@rpath/libawt.dylib", "@rpath/libmlib_image.dylib", "@rpath/libosxapp.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Accelerate.framework/Versions/A/Accelerate", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox", "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Metal.framework/Versions/A/Metal", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ExceptionHandling.framework/Versions/A/ExceptionHandling", "/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport", "/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL", "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore", "@rpath/libjava.dylib", "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText", "/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libdt_socket.dylib", bytes: 73968, sha256: "586dcfb17ad55d03f46aa75bf0b8ccd622a31bca3eab8cf3fdd673c3e0f380b4",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "25dfbf9858a080d336761db51c91a15743b3c7b6c4014777196ee6ca508fdff2", commands_sha256: "56bab82e7d9d746751f7bf5adc56ea45232a1c3c8cc6eda1eec2022476e2ff82", file_type: 6,
            install_name: Some("@rpath/libdt_socket.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libextnet.dylib", bytes: 70688, sha256: "af867a2643ec8ad87410d25f1ac9a1558a12f7b0607971980e7d367f44fc7c05",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "19ce2735eaecb88e1357eb2b0f812735f754c00c40d8a630f47103c6bd46a6ed", commands_sha256: "4bb722382fc9a5b0952c9c00326cc1cb750f1d1ff42bf197f603d9b177371b65", file_type: 6,
            install_name: Some("@rpath/libextnet.dylib"), loads: &["@rpath/libjava.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libfontmanager.dylib", bytes: 1495264, sha256: "767ef168afd12358fb5cfea40e81de48db6ff098ac0b749107fb2a991e5b932c",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "709e45b1c7f08af7d2066437871de13d033641576bbc75436890c9fd860dd905", commands_sha256: "6bddbaf14a03552723e7de068c63444e38505c4aca5143dc74c0616e9f400af7", file_type: 6,
            install_name: Some("@rpath/libfontmanager.dylib"), loads: &["@rpath/libfreetype.dylib", "@rpath/libawt.dylib", "@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "@rpath/libawt_lwawt.dylib", "/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics", "/usr/lib/libc++.1.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libfreetype.dylib", bytes: 655312, sha256: "15ea8e49a8664d567c8ea7a322cb27acec314c4c24b45fbadae293804a94c46e",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a42a4f338dab4bea4d122f52620562cb1732ef541424f3495b5a09e3703bed75", commands_sha256: "0a293e16bf09f4fc912bfc83a4a817ed8f9873491a1045428eef818813428c05", file_type: 6,
            install_name: Some("@rpath/libfreetype.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libinstrument.dylib", bytes: 109296, sha256: "9414eb2d038ae3e6a528190dff15d742162272af222cce70d977765b298002d7",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "72af516595aa054024ed9b2dc2f06b42427ba4fc878f6f67e12118eabd4c32c3", commands_sha256: "a811950afc23460fdd481ddee89cfdbb0bbf1bd980f5128619f517a8296b1b5a", file_type: 6,
            install_name: Some("@rpath/libinstrument.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "@rpath/libjli.dylib", "/usr/lib/libiconv.2.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libj2gss.dylib", bytes: 92912, sha256: "0a994ea5b716ce8f03558bc42380f58276bec45802389216c64602348546946c",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "2bfd8c08c11fc8f53b30dc1e561ca0a6913ef0362048cc91df00d98bf9365ee2", commands_sha256: "0170321b65c0f6971eaf7206813e925c9956bde972cd26f7583dc9acf877c894", file_type: 6,
            install_name: Some("@rpath/libj2gss.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libj2pcsc.dylib", bytes: 71776, sha256: "963aded7be912370462f5697567dd00d11ac7c547f0f5dfae5340208262f8cdb",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "d14db42aa3626c6cbdf045d48e432ff835337b412ec7efde5ac13dfd3021ac25", commands_sha256: "56f26ee391c975b3a706366d555e710217a4565649c4fd141bcdd1e2d977559d", file_type: 6,
            install_name: Some("@rpath/libj2pcsc.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libj2pkcs11.dylib", bytes: 131184, sha256: "459d504968c04ba459a4b3f1072fe68dae46a72d7e2c617fa5ffc6c9201a079b",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "bc665e93021f092dbbe35e0103c3c6091d6c0f844c62fd879c978ebd02e1a43a", commands_sha256: "51d88f235e9532055626ed261f13f3b0314a37a28a0ad1e7ec56149f23f0e362", file_type: 6,
            install_name: Some("@rpath/libj2pkcs11.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjaas.dylib", bytes: 69952, sha256: "8222b05dae683eaaae32b669d06c7fad715a212e0e03432494c194bb41f5abb3",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "22e5e64c92f1376a2a63d083971964b7205ef4707e69c876999446351a01ade3", commands_sha256: "ab0f96f517fd4341df38665cd2209499e392791a0b2f69a56e97fa36f9706b29", file_type: 6,
            install_name: Some("@rpath/libjaas.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjava.dylib", bytes: 203936, sha256: "96fefffa347ac39ca5be9c350789132e60a9fc32f32f64e45ca275a53069d180",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "86ff9751cd8864bc4f640c92f9e7d5f1d6ad6c1fbe96a5b6601cb42021d3e402", commands_sha256: "55980713cf82f5ccb411483d1713ca4e8b8341e0514795370641e021525dc028", file_type: 6,
            install_name: Some("@rpath/libjava.dylib"), loads: &["@rpath/libjvm.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration", "/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjavajpeg.dylib", bytes: 265104, sha256: "1de5afec8ff0d2c6de9247bae481aab16ad150ace09ded7f484cb3328efa6f90",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "9e8f8d3d18b549f26796cd13c0352b6bf0fb97e2519c7a4903dfb96833924286", commands_sha256: "566d1fbcc15115e954765adc0c7867d03c9705c34d9c3bce56369cce7480e4a3", file_type: 6,
            install_name: Some("@rpath/libjavajpeg.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjawt.dylib", bytes: 53424, sha256: "436546305b4797b81a53440efcdd3b2bccd0c0dff220205f0bb3b719e37ac2db",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "8a51e7243a7abd496b56918bbae3dc85b8d149ecb248cb7b5975a9b9a0157e24", commands_sha256: "3d17e8d1d9445a3f997324b3ed0185323d431cc9549c4c794a38844377876ddf", file_type: 6,
            install_name: Some("@rpath/libjawt.dylib"), loads: &["@rpath/libawt_lwawt.dylib", "@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/.", "@loader_path"] } },
    JdkNativePin { relative: "Contents/Home/lib/libjdwp.dylib", bytes: 295552, sha256: "9f62afe88f66fed3cc3eda753a606f69667737199ab57d25eaa377ac24bc266d",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "025d5d0bf1e2f73360903d765af66f931d4ea6b51f8426b45300047495c779f9", commands_sha256: "1886e2515d24177901078c5d151a6e67f98abe3dc1338dd1bbc1f6d06d9eafb6", file_type: 6,
            install_name: Some("@rpath/libjdwp.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libiconv.2.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjimage.dylib", bytes: 77584, sha256: "3de8cc93f13b0c5e3ec7a55f4e761c0f5b7e6b26416aef0b70205b9200d9e31d",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "d00eb1df3f22d3b37c351dc64e1cc014ff4f15713ce9403e350e5462e86c9acb", commands_sha256: "5bcda65633e9475b99adce393d84d145093c7ead279266aeff63efa5f51b5f6d", file_type: 6,
            install_name: Some("@rpath/libjimage.dylib"), loads: &["@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjli.dylib", bytes: 148752, sha256: "f3041707b3589a2221fd7c866ac190814c80814d78ec6fafe750fc79fe7e6ff3",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "783d5d077782a46ae06e863b908eddf3e1ec459650d76c6b394cb5efb89e2b32", commands_sha256: "ba15aa097f9675bd3f1c5e5f126ff9df0b13d28bf4c28b59a61775526be44c4e", file_type: 6,
            install_name: Some("@rpath/libjli.dylib"), loads: &["/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjsig.dylib", bytes: 70896, sha256: "312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "fe71612f678286f30767f60ef377da9110dd43bccaffef1d00cb4d9cf23b9b61", commands_sha256: "6ac13bf4d377ce935beaa1c9f3f45bed877fc862de994a6daf4d7837cb7c471d", file_type: 6,
            install_name: Some("@rpath/libjsig.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libjsound.dylib", bytes: 136000, sha256: "28d4a07c3c63db5bca3c94de49266f4093d9a83a4d343588e4d3099d1bdab0c4",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "24c523ef44509477a200348152fe3b826bfa5c01c67d539a10e95dfd15c338e3", commands_sha256: "59b21714ef5e4eb7ba54aa7cd1d9865941bfd3a7f4349b6475da26e6fe146c42", file_type: 6,
            install_name: Some("@rpath/libjsound.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/System/Library/Frameworks/AudioUnit.framework/Versions/A/AudioUnit", "/System/Library/Frameworks/CoreMIDI.framework/Versions/A/CoreMIDI", "/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox", "/usr/lib/libc++.1.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/liblcms.dylib", bytes: 410656, sha256: "a02a051e7e49ef1796b06532c4adab1b413c54558bd1fa097d2a8204381f049f",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "c249a088a2b7d9b5dd044dee3611357b289b6d610e43ed9bae5e636b904dbb27", commands_sha256: "d9bd1bd67cea2666eb9fcaa2a7ce7d1fb489436dcd16643cc7e7c8e4c13e7fb6", file_type: 6,
            install_name: Some("@rpath/liblcms.dylib"), loads: &["@rpath/libawt.dylib", "@rpath/libjvm.dylib", "@rpath/libjava.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libmanagement.dylib", bytes: 76880, sha256: "3e54899c2f6c47dd377a3db9b3a9d617e2b7d90a5268ebac6bfb2114b08bef32",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "0d158c40f7e0dc7a54f8a94c2114ef542bf555c032cbc66b695c2322205106eb", commands_sha256: "4f3d862f339e65e9f05d2c05e9300aa4d6987df77883424ab51825b299e0ea54", file_type: 6,
            install_name: Some("@rpath/libmanagement.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libmanagement_agent.dylib", bytes: 69952, sha256: "79917926692f3921a3e7f32f78cd6a7f0c2f8b570ece2e28ec6c9a414ce2ca0e",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "fa713d3b5c6717de38a4e36b9438fce2e84100a89a7772f95c38a7a1b8277b17", commands_sha256: "8690884888e0b5de9734d584935ce8e16ae898f2730ba4612e1ef37355a60a0d", file_type: 6,
            install_name: Some("@rpath/libmanagement_agent.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libmanagement_ext.dylib", bytes: 75280, sha256: "daaed83579929aa49972046d23f6e8ca8450473b9f7088ad903457632a453e1f",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "213a0935b96e25fa402c1ed0804af38747f38a4caf3e3e98abaed65a3b7c2136", commands_sha256: "b47349ce52afd805cc72be1fcdc8c05d6d9b03bbee98a1b2e5b9d0b6d7e90143", file_type: 6,
            install_name: Some("@rpath/libmanagement_ext.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libmlib_image.dylib", bytes: 507888, sha256: "b89ee32dbc71d17f8691e0d5978f29337dfd16f9fc1402836183b21b192225ea",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "43b7accc902a71c1008b4956e0b5fda9348d6a89f3b20ee7b64cfb8dbdd31123", commands_sha256: "ffd71e64406496f6ddae12a55d1eebf178f548b8d5326c98f348c276a9eab97d", file_type: 6,
            install_name: Some("@rpath/libmlib_image.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libnet.dylib", bytes: 138800, sha256: "2d1eed9237de915d58f5f241f5c3d4f7811444b150f31e4eff56fa45ae503466",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "0902c50e4b235039f6a32503afbbe5cf34c34cce4f18712a61b5f23774d2c97a", commands_sha256: "575609f4984ed613877e8f50e1f03946db69f08bcc03d9b17daeef6ad04dd376", file_type: 6,
            install_name: Some("@rpath/libnet.dylib"), loads: &["@rpath/libjvm.dylib", "@rpath/libjava.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libnio.dylib", bytes: 126432, sha256: "f58fb9a0dbdd37c5322e72fc1633998d37a85303c11c7f37812acdc94ea8cc08",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "a42942e4fc95f14aa811c1d83c457b1de112360e99ff0bfa4443372f80d3304a", commands_sha256: "1340cd81c7b2ba1f63826693554b1638ac99e77b1222615786aced39a2b6ba13", file_type: 6,
            install_name: Some("@rpath/libnio.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libnet.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libosx.dylib", bytes: 74720, sha256: "7b7043220f041ce3a51cf2d05618fd776e7421a360697c726d337de33f3e7dae",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "11855fc8a57d5c4f9c60877a41235d2bdf553db4ce68abaf24f1e8bbb969e79e", commands_sha256: "ccf3f951681d2be3f426cd57e5c46a3b6458b0c6c82391df1fa0d56661ec4058", file_type: 6,
            install_name: Some("@rpath/libosx.dylib"), loads: &["@rpath/libosxapp.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport", "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration", "@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libosxapp.dylib", bytes: 189680, sha256: "940108380533f4d499665a48b17814c7009103751976b64879106e6297f035cf",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "8a1439d49b65d14cdf076ad63cd98699437926dced9897f000fec309ecf458bf", commands_sha256: "0fcccd6bc1268ec703519c397a1c824fd0b37cfce3f2d728e73d3b4081c25ff2", file_type: 6,
            install_name: Some("@rpath/libosxapp.dylib"), loads: &["@rpath/libjava.dylib", "/System/Library/Frameworks/Accelerate.framework/Versions/A/Accelerate", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox", "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ExceptionHandling.framework/Versions/A/ExceptionHandling", "/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport", "/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL", "/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface", "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libosxkrb5.dylib", bytes: 74496, sha256: "f947c8a361de60081d345500a5d1db749dcdd6a5d637d9f2ff2c95ce90281edf",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "5c31d7c6bc75189a75ba8ce8ac39d8e872ca8469702566f032a4bf9efa5dca4b", commands_sha256: "739cebafc9cc727f0b34797754a9e1bfda57505cd377bb1808e637aa0d824892", file_type: 6,
            install_name: Some("@rpath/libosxkrb5.dylib"), loads: &["/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration", "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libosxsecurity.dylib", bytes: 75104, sha256: "d811ef63c36b09d7d8dcb3d272376eacb44d048b006fbe8171b793112a1be1ec",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "d9dcfb0de287b182c6779799427e5a68d6f1c9a2b2816321219f749d350eb167", commands_sha256: "c500e7f044a771db98a93666269abd45c5d301223b53591e0642cc026507aa74", file_type: 6,
            install_name: Some("@rpath/libosxsecurity.dylib"), loads: &["/usr/lib/libobjc.A.dylib", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libosxui.dylib", bytes: 99616, sha256: "7125eea603a7edf20d613677e533e979eafa2f5ee4ad34210ed0f86204a3a012",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "24df56495d85659cfa9a202709b021637417d71f38c2a7834faa5eb37515af48", commands_sha256: "ac0e1a60eba322b922bcc3d9f8d9ff5eb9c7ee244f46cc23c639b02ac4dc4c0b", file_type: 6,
            install_name: Some("@rpath/libosxui.dylib"), loads: &["@rpath/libawt.dylib", "@rpath/libosxapp.dylib", "@rpath/libawt_lwawt.dylib", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Metal.framework/Versions/A/Metal", "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport", "@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics", "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/.", "@loader_path"] } },
    JdkNativePin { relative: "Contents/Home/lib/libprefs.dylib", bytes: 74560, sha256: "7d58fe5f2de374a98cfa0a0b934516de3916e01a99b675a48a83a11395c8bd8d",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "8131f8229e57f86e089a0c0414ffb9d27140c7ebc3ff3941b15e0d705e92f5a6", commands_sha256: "14170c78ae26df08c66060cc66259d3150d390dc13849ce86f25c7e5fdc44206", file_type: 6,
            install_name: Some("@rpath/libprefs.dylib"), loads: &["@rpath/libjvm.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/librmi.dylib", bytes: 69648, sha256: "c9f1a107df0b5d3571344aad2bd411a7ae38ba574061f93403880f0e05b999f4",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "e2fd1c47f643109da628764161437a0cff379c0a4126458a1aa29822164ff2f6", commands_sha256: "ca5be22595ea80a27d0dac1cdf3b0de40ca70cad061ef3c65c0de6002b58b4b6", file_type: 6,
            install_name: Some("@rpath/librmi.dylib"), loads: &["@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libsaproc.dylib", bytes: 112288, sha256: "0c1673963910b0acd284f2703632d82629880e31d2200927bcc477425dc56fe2",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "7fd522459f9437945c4206896291f21a0fd5046ecd2352021075b65f2da2dc0f", commands_sha256: "8e0fa2fea573ab0056601697c33bbaec888b5a1ab461387cbe77be8efcd8a6e2", file_type: 6,
            install_name: Some("@rpath/libsaproc.dylib"), loads: &["@rpath/libjava.dylib", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libsplashscreen.dylib", bytes: 457552, sha256: "97a03f3694205e2b0e6bd44e09e8e8b24eaa26a9d23fc63c7875ba4e1245f1bf",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "9a6b5055f2aec1a32b3abf6ea85aa4325b9232b4c38fe1cfe27d70746653713a", commands_sha256: "5f8996334dd5e8c1cc774e8da64c5dff2bb40d66d86fb57cb1b8d7b76e86a7b7", file_type: 6,
            install_name: Some("@rpath/libsplashscreen.dylib"), loads: &["@rpath/libjava.dylib", "@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib", "/usr/lib/libiconv.2.dylib", "@rpath/libosxapp.dylib", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Metal.framework/Versions/A/Metal", "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libsyslookup.dylib", bytes: 36352, sha256: "ac3566ac84ee620c01aaed05cf954b8eb5c418c6c99a229aa9d2d5b6459b14f3",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "3f2c8c14571118f7f8e732a105de18c6121412f35cc1361e4590aed82c02dfbd", commands_sha256: "6eea9dcb1bec37c1488127501d1207fb76f0dba70d9094256cf8b2d04a971fa8", file_type: 6,
            install_name: Some("@rpath/libsyslookup.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &[] } },
    JdkNativePin { relative: "Contents/Home/lib/libverify.dylib", bytes: 106848, sha256: "bc8fbc7b5152404d3d0580513ee6f9de056edf1525baf0413afbd126a51cba42",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "02511543daad02fac1fa80872a6b36bde23a10f7f69463ce127d1cf2fc020cf9", commands_sha256: "604ef8a399557b7feddd81d505e946a1419565a25e2e161978a360f4f8739487", file_type: 6,
            install_name: Some("@rpath/libverify.dylib"), loads: &["@rpath/libjvm.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/libzip.dylib", bytes: 162912, sha256: "78b7745680a58cf63c527d9bf1e2db4e65d699b6c203e7974b94da221755d832",
        original_mode: 0o644, phase: JdkPhase::PostJli, header: MachPin { prefix_bytes: 4096, prefix_sha256: "d4816306ccb1eaf498e0c13c5d93aa17cc4f0951a485a060285a222eac1fe732", commands_sha256: "39afe0f7e7f9bb4be519257163c3a51b16479e6901f2aa68265cf55d8328fdd2", file_type: 6,
            install_name: Some("@rpath/libzip.dylib"), loads: &["@rpath/libjvm.dylib", "@rpath/libjava.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/server/libjsig.dylib", bytes: 70896, sha256: "312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "fe71612f678286f30767f60ef377da9110dd43bccaffef1d00cb4d9cf23b9b61", commands_sha256: "6ac13bf4d377ce935beaa1c9f3f45bed877fc862de994a6daf4d7837cb7c471d", file_type: 6,
            install_name: Some("@rpath/libjsig.dylib"), loads: &["/usr/lib/libSystem.B.dylib"], rpaths: &["@loader_path/."] } },
    JdkNativePin { relative: "Contents/Home/lib/server/libjvm.dylib", bytes: 16882064, sha256: "aee1f37674901ee3fa41886743f3382e6e1445482aab66fe34576f30d01f7749",
        original_mode: 0o644, phase: JdkPhase::ExplicitJvmProvider, header: MachPin { prefix_bytes: 4096, prefix_sha256: "5017912d5ca187bc2c633ea6a2e5bf8bbca44580f9569a2ef3555649d32bd496", commands_sha256: "27f3b95b1696f8512a173a5ee3f87cbd9af2a67efc7e62014499997ba668c862", file_type: 6,
            install_name: Some("@rpath/libjvm.dylib"), loads: &["/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"], rpaths: &["@loader_path/.", "@loader_path/.."] } },
    JdkNativePin { relative: "Contents/MacOS/libjli.dylib", bytes: 147472, sha256: "ba172dd8aab9b629864af3eddf195c076d1b49c04e8522a7a4f10c27aa6ca895",
        original_mode: 0o644, phase: JdkPhase::Bootstrap, header: MachPin { prefix_bytes: 4096, prefix_sha256: "db60a15d9d1304fbc39fdf19528f3ccfd0fe5e89a9640667d692a9fbbf6fec40", commands_sha256: "1b12b617e666a3dafbf009903e600f1fd7c9a81f0aab1356546eddd4a82b1381", file_type: 6,
            install_name: Some("@rpath/libjli.dylib"), loads: &["/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices", "/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", "/usr/lib/libobjc.A.dylib"], rpaths: &["@loader_path/."] } },
];
const JPACKAGE_TEMPLATE: MachPin = MachPin { prefix_bytes: 4096, prefix_sha256: "1d400c75f9c46bc79e138a9b2ddc1d0d0189c7aa57626728ef3ce19e80570033", commands_sha256: "2c87bed1e51b555b5204489c65070b7fec4aa5d2ffbb19d4978f7774445920f5", file_type: 2,
            install_name: None, loads: &["/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa", "/usr/lib/libc++.1.dylib", "/usr/lib/libSystem.B.dylib"], rpaths: &[] };
pub(crate) static JDK_JVM_ARCHIVES: &[JdkJvmArchivePin] = &[
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.base.jmod", bytes: 18551178, sha256: "c5b13c8664f0b2c1d466a38a458210fef11e90218d23a1b0833856bbc9fa7f72", members: &[
        JdkJvmMemberPin { member: "bin/java", bytes: 70464, sha256: "af8b122943345320b179c75c3404d56a981017739746b75f9caf583632f0bea0", mode: 0o0, counterpart: Some("Contents/Home/bin/java") },
        JdkJvmMemberPin { member: "bin/keytool", bytes: 70464, sha256: "af587a253678cda7ca2704daee936af1993305ce9a9bc6d5018f37f49d425fcb", mode: 0o0, counterpart: Some("Contents/Home/bin/keytool") },
        JdkJvmMemberPin { member: "lib/jspawnhelper", bytes: 72048, sha256: "269bbc5ed0956cd58014f0a02f3b31ab7b0bf3202bbdbc66457f06dbe50fbaed", mode: 0o0, counterpart: Some("Contents/Home/lib/jspawnhelper") },
        JdkJvmMemberPin { member: "lib/libjava.dylib", bytes: 203936, sha256: "96fefffa347ac39ca5be9c350789132e60a9fc32f32f64e45ca275a53069d180", mode: 0o0, counterpart: Some("Contents/Home/lib/libjava.dylib") },
        JdkJvmMemberPin { member: "lib/libjimage.dylib", bytes: 77584, sha256: "3de8cc93f13b0c5e3ec7a55f4e761c0f5b7e6b26416aef0b70205b9200d9e31d", mode: 0o0, counterpart: Some("Contents/Home/lib/libjimage.dylib") },
        JdkJvmMemberPin { member: "lib/libjli.dylib", bytes: 148752, sha256: "f3041707b3589a2221fd7c866ac190814c80814d78ec6fafe750fc79fe7e6ff3", mode: 0o0, counterpart: Some("Contents/Home/lib/libjli.dylib") },
        JdkJvmMemberPin { member: "lib/libjsig.dylib", bytes: 70896, sha256: "312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4", mode: 0o0, counterpart: Some("Contents/Home/lib/libjsig.dylib") },
        JdkJvmMemberPin { member: "lib/libnet.dylib", bytes: 138800, sha256: "2d1eed9237de915d58f5f241f5c3d4f7811444b150f31e4eff56fa45ae503466", mode: 0o0, counterpart: Some("Contents/Home/lib/libnet.dylib") },
        JdkJvmMemberPin { member: "lib/libnio.dylib", bytes: 126432, sha256: "f58fb9a0dbdd37c5322e72fc1633998d37a85303c11c7f37812acdc94ea8cc08", mode: 0o0, counterpart: Some("Contents/Home/lib/libnio.dylib") },
        JdkJvmMemberPin { member: "lib/libosxsecurity.dylib", bytes: 75104, sha256: "d811ef63c36b09d7d8dcb3d272376eacb44d048b006fbe8171b793112a1be1ec", mode: 0o0, counterpart: Some("Contents/Home/lib/libosxsecurity.dylib") },
        JdkJvmMemberPin { member: "lib/libverify.dylib", bytes: 106848, sha256: "bc8fbc7b5152404d3d0580513ee6f9de056edf1525baf0413afbd126a51cba42", mode: 0o0, counterpart: Some("Contents/Home/lib/libverify.dylib") },
        JdkJvmMemberPin { member: "lib/libzip.dylib", bytes: 162912, sha256: "78b7745680a58cf63c527d9bf1e2db4e65d699b6c203e7974b94da221755d832", mode: 0o0, counterpart: Some("Contents/Home/lib/libzip.dylib") },
        JdkJvmMemberPin { member: "lib/server/libjsig.dylib", bytes: 70896, sha256: "312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4", mode: 0o0, counterpart: Some("Contents/Home/lib/server/libjsig.dylib") },
        JdkJvmMemberPin { member: "lib/server/libjvm.dylib", bytes: 16882064, sha256: "aee1f37674901ee3fa41886743f3382e6e1445482aab66fe34576f30d01f7749", mode: 0o0, counterpart: Some("Contents/Home/lib/server/libjvm.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.compiler.jmod", bytes: 130713, sha256: "65a54bafb1c6d0bfc41a7230bf5f4b8b05e653a5815065343a53c3402c80f7d2", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.datatransfer.jmod", bytes: 59211, sha256: "7c82d763d44b1afb1bf5aa9f71fe4daf1cc7d6925febb54b381e6f58785b4a76", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.desktop.jmod", bytes: 13735658, sha256: "2e130b3645a8b8786d2a1ac43033fed2783262e3320a58bb701d4bb6f92da35c", members: &[
        JdkJvmMemberPin { member: "lib/libawt.dylib", bytes: 551776, sha256: "cede2c8c314eb780fb2c7a2d0055de9324290449d4c0f1ef0e7fd684b84b2e8a", mode: 0o0, counterpart: Some("Contents/Home/lib/libawt.dylib") },
        JdkJvmMemberPin { member: "lib/libawt_lwawt.dylib", bytes: 1237072, sha256: "a540b8ca7a8c8c77f0db3f80c2b3449537b4a758bf1727f45361c4dcccf0b7ac", mode: 0o0, counterpart: Some("Contents/Home/lib/libawt_lwawt.dylib") },
        JdkJvmMemberPin { member: "lib/libfontmanager.dylib", bytes: 1495264, sha256: "767ef168afd12358fb5cfea40e81de48db6ff098ac0b749107fb2a991e5b932c", mode: 0o0, counterpart: Some("Contents/Home/lib/libfontmanager.dylib") },
        JdkJvmMemberPin { member: "lib/libfreetype.dylib", bytes: 655312, sha256: "15ea8e49a8664d567c8ea7a322cb27acec314c4c24b45fbadae293804a94c46e", mode: 0o0, counterpart: Some("Contents/Home/lib/libfreetype.dylib") },
        JdkJvmMemberPin { member: "lib/libjavajpeg.dylib", bytes: 265104, sha256: "1de5afec8ff0d2c6de9247bae481aab16ad150ace09ded7f484cb3328efa6f90", mode: 0o0, counterpart: Some("Contents/Home/lib/libjavajpeg.dylib") },
        JdkJvmMemberPin { member: "lib/libjawt.dylib", bytes: 53424, sha256: "436546305b4797b81a53440efcdd3b2bccd0c0dff220205f0bb3b719e37ac2db", mode: 0o0, counterpart: Some("Contents/Home/lib/libjawt.dylib") },
        JdkJvmMemberPin { member: "lib/libjsound.dylib", bytes: 136000, sha256: "28d4a07c3c63db5bca3c94de49266f4093d9a83a4d343588e4d3099d1bdab0c4", mode: 0o0, counterpart: Some("Contents/Home/lib/libjsound.dylib") },
        JdkJvmMemberPin { member: "lib/liblcms.dylib", bytes: 410656, sha256: "a02a051e7e49ef1796b06532c4adab1b413c54558bd1fa097d2a8204381f049f", mode: 0o0, counterpart: Some("Contents/Home/lib/liblcms.dylib") },
        JdkJvmMemberPin { member: "lib/libmlib_image.dylib", bytes: 507888, sha256: "b89ee32dbc71d17f8691e0d5978f29337dfd16f9fc1402836183b21b192225ea", mode: 0o0, counterpart: Some("Contents/Home/lib/libmlib_image.dylib") },
        JdkJvmMemberPin { member: "lib/libosx.dylib", bytes: 74720, sha256: "7b7043220f041ce3a51cf2d05618fd776e7421a360697c726d337de33f3e7dae", mode: 0o0, counterpart: Some("Contents/Home/lib/libosx.dylib") },
        JdkJvmMemberPin { member: "lib/libosxapp.dylib", bytes: 189680, sha256: "940108380533f4d499665a48b17814c7009103751976b64879106e6297f035cf", mode: 0o0, counterpart: Some("Contents/Home/lib/libosxapp.dylib") },
        JdkJvmMemberPin { member: "lib/libosxui.dylib", bytes: 99616, sha256: "7125eea603a7edf20d613677e533e979eafa2f5ee4ad34210ed0f86204a3a012", mode: 0o0, counterpart: Some("Contents/Home/lib/libosxui.dylib") },
        JdkJvmMemberPin { member: "lib/libsplashscreen.dylib", bytes: 457552, sha256: "97a03f3694205e2b0e6bd44e09e8e8b24eaa26a9d23fc63c7875ba4e1245f1bf", mode: 0o0, counterpart: Some("Contents/Home/lib/libsplashscreen.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.instrument.jmod", bytes: 48218, sha256: "fa990db928823d00d7f5d446d983a0d1052b4cb4247460fbcd981f378fbd329f", members: &[
        JdkJvmMemberPin { member: "lib/libinstrument.dylib", bytes: 109296, sha256: "9414eb2d038ae3e6a528190dff15d742162272af222cce70d977765b298002d7", mode: 0o0, counterpart: Some("Contents/Home/lib/libinstrument.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.logging.jmod", bytes: 128181, sha256: "49fbd84f70d917d852ee0dbad2d239ec72dde4ecc7e408ba6104d28fb1b3420c", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.management.jmod", bytes: 907722, sha256: "a86f8d54dea42825cf4fd91bcfdd32ae0888241a5e08d068f3f733ff727ca29c", members: &[
        JdkJvmMemberPin { member: "lib/libmanagement.dylib", bytes: 76880, sha256: "3e54899c2f6c47dd377a3db9b3a9d617e2b7d90a5268ebac6bfb2114b08bef32", mode: 0o0, counterpart: Some("Contents/Home/lib/libmanagement.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.management.rmi.jmod", bytes: 99522, sha256: "f89d40da7c63b043494ca1d549f77b82a0479c3db9db3eb0210d9997b1c2c80f", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.naming.jmod", bytes: 483330, sha256: "5bc68c04d7e8c709b79adb30527a566a753a90936c77d3b9bd989a3712d7471d", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.net.http.jmod", bytes: 780867, sha256: "9d392605dbb6df1d53e6e8df5d929e453b677f3bbe3ce644e559611e0d74ca5c", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.prefs.jmod", bytes: 90192, sha256: "be17cb21c5c3fd7d424b1720d01da6083dda57af96ffba0f0b6233fad305efc5", members: &[
        JdkJvmMemberPin { member: "lib/libprefs.dylib", bytes: 74560, sha256: "7d58fe5f2de374a98cfa0a0b934516de3916e01a99b675a48a83a11395c8bd8d", mode: 0o0, counterpart: Some("Contents/Home/lib/libprefs.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.rmi.jmod", bytes: 282812, sha256: "7ab12d3c8f653e67c22d153b3721f22047b84b6af6c3dd7215c6af17b0bf6e5e", members: &[
        JdkJvmMemberPin { member: "bin/rmiregistry", bytes: 70464, sha256: "aea46addd6ba9f6a44b119550000cac3e999bf2bd85673e5105ae0609c960850", mode: 0o0, counterpart: Some("Contents/Home/bin/rmiregistry") },
        JdkJvmMemberPin { member: "lib/librmi.dylib", bytes: 69648, sha256: "c9f1a107df0b5d3571344aad2bd411a7ae38ba574061f93403880f0e05b999f4", mode: 0o0, counterpart: Some("Contents/Home/lib/librmi.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.scripting.jmod", bytes: 53024, sha256: "00c7790218521c4911969b6487b0159ce3c008484a0161b217d194ba4a83d90e", members: &[
        JdkJvmMemberPin { member: "bin/jrunscript", bytes: 70464, sha256: "9bd7764585944634431ca97193f2c714c562b06ce6ab6aa918b84d36274a3283", mode: 0o0, counterpart: Some("Contents/Home/bin/jrunscript") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.se.jmod", bytes: 9861, sha256: "5a4954612f22633eb6e8ff6d248afe71a28dcea875ded17de51195685e83d259", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.security.jgss.jmod", bytes: 635142, sha256: "d3a56dfba805cb9cbc96818b09c63041b9746818a782183455d5aad05a6113ef", members: &[
        JdkJvmMemberPin { member: "lib/libj2gss.dylib", bytes: 92912, sha256: "0a994ea5b716ce8f03558bc42380f58276bec45802389216c64602348546946c", mode: 0o0, counterpart: Some("Contents/Home/lib/libj2gss.dylib") },
        JdkJvmMemberPin { member: "lib/libosxkrb5.dylib", bytes: 74496, sha256: "f947c8a361de60081d345500a5d1db749dcdd6a5d637d9f2ff2c95ce90281edf", mode: 0o0, counterpart: Some("Contents/Home/lib/libosxkrb5.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.security.sasl.jmod", bytes: 89370, sha256: "22ff2e4627cc75819a7b2350385246d7727d43a5e5861904604919a71eb045e3", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.smartcardio.jmod", bytes: 67826, sha256: "fa14fcb5449fb8d4b3156341d8d63a3e14ea1a961a5164daae67d6c3abc69403", members: &[
        JdkJvmMemberPin { member: "lib/libj2pcsc.dylib", bytes: 71776, sha256: "963aded7be912370462f5697567dd00d11ac7c547f0f5dfae5340208262f8cdb", mode: 0o0, counterpart: Some("Contents/Home/lib/libj2pcsc.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.sql.jmod", bytes: 83694, sha256: "2a8a9c368e5bd64db223a61dd700f478fb4cbc96fe3eaa5a43d2236d69e0bd61", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.sql.rowset.jmod", bytes: 221191, sha256: "e32dfff580146e74abecf98ba3aaa47eff832d82b926698986056ad79818882f", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.transaction.xa.jmod", bytes: 11688, sha256: "c4c3798c40a017a75a3c727d12fadfe357b743b401729ea8f5102bcc7cf031eb", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.xml.crypto.jmod", bytes: 706479, sha256: "12052954b9d0b8cb49d15f4d36be080929bf4390c89b6c5237c58c471f3ec58b", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/java.xml.jmod", bytes: 5235159, sha256: "21f3c25826a06c24078bfdd7eb7b98976f70eb8f205b731f72d040cbd98563ca", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.accessibility.jmod", bytes: 58053, sha256: "2f1a266e82b92bd0c68ffe09d7edb4ace387a1af8f4e8d6f6b23845f5a7a18ab", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.attach.jmod", bytes: 42665, sha256: "1812e21e1c4580cb021b97925c37202ce09e44d25e8ce5e38e225432ecaa5955", members: &[
        JdkJvmMemberPin { member: "lib/libattach.dylib", bytes: 71888, sha256: "d6f8a37fc720a762582b3b088197f06fb959f64119d977effe30ac842eb345ad", mode: 0o0, counterpart: Some("Contents/Home/lib/libattach.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.charsets.jmod", bytes: 1713214, sha256: "4c707f9b9a1000e3356cd7134e935c3a814d25a5fb3a193d90d81c32226773f3", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.compiler.jmod", bytes: 9266695, sha256: "0d3e5c397104cf7994c01facc6f82c84cbe374b93ccb6fffc9537d53a612d2a0", members: &[
        JdkJvmMemberPin { member: "bin/javac", bytes: 70464, sha256: "6f5159301c750bba340390eda5fdd4a0959445355f97c40aa9c2addb00ede5ab", mode: 0o0, counterpart: Some("Contents/Home/bin/javac") },
        JdkJvmMemberPin { member: "bin/serialver", bytes: 70464, sha256: "fdfd5b5d9929c77750e480951212eabe800e4a2daa3b73995539242333d6f22e", mode: 0o0, counterpart: Some("Contents/Home/bin/serialver") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.crypto.cryptoki.jmod", bytes: 387773, sha256: "6034469b16af2df3e794d58576124b17bfd5e27bc16ae729a097d42a6c4dfc8d", members: &[
        JdkJvmMemberPin { member: "lib/libj2pkcs11.dylib", bytes: 131184, sha256: "459d504968c04ba459a4b3f1072fe68dae46a72d7e2c617fa5ffc6c9201a079b", mode: 0o0, counterpart: Some("Contents/Home/lib/libj2pkcs11.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.crypto.ec.jmod", bytes: 139832, sha256: "2571836a0f27019ad24b91c1b45baea3ff14b72896cd7f16c5712d41df1f44e2", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.dynalink.jmod", bytes: 166030, sha256: "23e1257378ff83ab4dab243d74ae7e370d3774c747fd3f78d2e4831915e0171e", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.editpad.jmod", bytes: 15299, sha256: "cb9786df0921480e5d027db774b01e882e14a8f869b2dce25f3ca383048d4664", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.hotspot.agent.jmod", bytes: 2294768, sha256: "8a30c9924f49113838d9b8f0a713f840f6982b1579949a4e411bfd8747251dd4", members: &[
        JdkJvmMemberPin { member: "bin/jhsdb", bytes: 70464, sha256: "12c20fd4facc8ed4f31c813bf140b1da596797a5e0932ffba13c48f72f22bc3e", mode: 0o0, counterpart: Some("Contents/Home/bin/jhsdb") },
        JdkJvmMemberPin { member: "lib/libsaproc.dylib", bytes: 112288, sha256: "0c1673963910b0acd284f2703632d82629880e31d2200927bcc477425dc56fe2", mode: 0o0, counterpart: Some("Contents/Home/lib/libsaproc.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.httpserver.jmod", bytes: 117549, sha256: "d94986a7f8233914e912065d407ca495b2b5698c5e05c6066c6b2ec3a29a3a92", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.incubator.foreign.jmod", bytes: 330457, sha256: "8f33107630784a9597c0ee15e3780cb057e8e12fe1404c5decca23df7175fb77", members: &[
        JdkJvmMemberPin { member: "lib/libsyslookup.dylib", bytes: 36352, sha256: "ac3566ac84ee620c01aaed05cf954b8eb5c418c6c99a229aa9d2d5b6459b14f3", mode: 0o0, counterpart: Some("Contents/Home/lib/libsyslookup.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.incubator.vector.jmod", bytes: 712944, sha256: "20ccbace5a4491de3dde916b49063b4dbb3fc685b172047bcf21132d05f3b65a", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.ed.jmod", bytes: 15171, sha256: "c2b3c62764d01d3026154821f5296ed95caa7b2a7cb478595fda90941369a70f", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.jvmstat.jmod", bytes: 98912, sha256: "b9ef5e76fe07b4c9b11bd095b41594f93d1ed9d2ec4a5d4b8786b271673b5b59", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.le.jmod", bytes: 465317, sha256: "2e924a6a29b7b59bf6035e5417878d2ebfd7da9d63a955c3dfb7ff14e81364d7", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.opt.jmod", bytes: 90621, sha256: "e35f5503f26d477a2b686c7a3453f0aaf78c3da59f18fd214db74af11e660e5c", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.vm.ci.jmod", bytes: 454061, sha256: "74d08c1f7e9175dbe177f1f34c6b455aa6568141a4145a195526045675688adc", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.vm.compiler.jmod", bytes: 9648, sha256: "eff467c1a1759c7a33a3d22c8c2ccb55714ec670e5a17613b652d309c692d0e3", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.internal.vm.compiler.management.jmod", bytes: 9652, sha256: "12a199c77fa95f730c1143ef6fed0555815817ca4672ced7f5bd95b47b22b7c5", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jartool.jmod", bytes: 282133, sha256: "7fc983678c884f5e12afb2bd44c8422d6fb12afaf7e982ca88199d4fbf275b92", members: &[
        JdkJvmMemberPin { member: "bin/jar", bytes: 70448, sha256: "c55e508c52019bb483ee2e737b751ed44d5e9e86abe660c713404db43c58803d", mode: 0o0, counterpart: Some("Contents/Home/bin/jar") },
        JdkJvmMemberPin { member: "bin/jarsigner", bytes: 70464, sha256: "fe9a1276c5a18c115177f0e7a5bea9b3163739e280332044564089be7f766c64", mode: 0o0, counterpart: Some("Contents/Home/bin/jarsigner") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.javadoc.jmod", bytes: 1390142, sha256: "4e8d87380429738fa9398a4c63be419974e282eaa4700ba0e7e19ff8a31a00f9", members: &[
        JdkJvmMemberPin { member: "bin/javadoc", bytes: 70464, sha256: "16c9e93773c99393bac5bbbe12ad23472dfacdb77732da1b8720e743b787bb06", mode: 0o0, counterpart: Some("Contents/Home/bin/javadoc") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jcmd.jmod", bytes: 167370, sha256: "a9ad60567d9dec840d044b9ec1be7291b2444efc5dc68a029c5bd975269d6011", members: &[
        JdkJvmMemberPin { member: "bin/jcmd", bytes: 70464, sha256: "e3aebdd820297b64e041203f766ebf28986abf0c8cf3e59ba0681d935160c0eb", mode: 0o0, counterpart: Some("Contents/Home/bin/jcmd") },
        JdkJvmMemberPin { member: "bin/jinfo", bytes: 70464, sha256: "939b38d404cc9055d2d3039a6fbfdfea4d783a370512bf1d7084f340e3a7337e", mode: 0o0, counterpart: Some("Contents/Home/bin/jinfo") },
        JdkJvmMemberPin { member: "bin/jmap", bytes: 70464, sha256: "b491f891489a84c668915be116b28f26ef399501f249751a7ee197ba4b03e078", mode: 0o0, counterpart: Some("Contents/Home/bin/jmap") },
        JdkJvmMemberPin { member: "bin/jps", bytes: 70448, sha256: "5c09726ceee3b97982540aeaa84be190b8e6ac155d88b8507235079ba8310fe1", mode: 0o0, counterpart: Some("Contents/Home/bin/jps") },
        JdkJvmMemberPin { member: "bin/jstack", bytes: 70464, sha256: "edbd8c8b0690b4844a75d2bd17ae6563baf63ef4942bedd16d5230f6e4b974a1", mode: 0o0, counterpart: Some("Contents/Home/bin/jstack") },
        JdkJvmMemberPin { member: "bin/jstat", bytes: 70464, sha256: "3fd61c3e2c179717a92fb19ebea8ffbe56a9eedad8eec82482695c38ce4f3cfc", mode: 0o0, counterpart: Some("Contents/Home/bin/jstat") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jconsole.jmod", bytes: 482846, sha256: "f93a2e0de191abfc1887109d8c880ed20633e5afd646c5ecff3ff3c53421d69e", members: &[
        JdkJvmMemberPin { member: "bin/jconsole", bytes: 70464, sha256: "a7ddaf2cbea00efdbdb6eeaf1075ea2c6ae726da656831c5f832680fea80d504", mode: 0o0, counterpart: Some("Contents/Home/bin/jconsole") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jdeps.jmod", bytes: 761505, sha256: "d91ae45f53b149f40247a680698e748e0738e7c90405edc142a333c2c788063f", members: &[
        JdkJvmMemberPin { member: "bin/javap", bytes: 70464, sha256: "0b318cfea6a2866918cda88c64db9919e9d668aa2f7cc1bb0ccb11f49b243bbb", mode: 0o0, counterpart: Some("Contents/Home/bin/javap") },
        JdkJvmMemberPin { member: "bin/jdeprscan", bytes: 70464, sha256: "b68b8f98cda671af91f9c1efc4a014828cf34d80d8487d2e222f82b55bb373b6", mode: 0o0, counterpart: Some("Contents/Home/bin/jdeprscan") },
        JdkJvmMemberPin { member: "bin/jdeps", bytes: 70464, sha256: "530d87e93a3321c91a0e5603077dc7a759b96e139bea8348fb1cd78c8059b90f", mode: 0o0, counterpart: Some("Contents/Home/bin/jdeps") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jdi.jmod", bytes: 855863, sha256: "4ecb7b3b3a0879d8b628c8c1d17cdafd0116183226e194eb690c3c7504968325", members: &[
        JdkJvmMemberPin { member: "bin/jdb", bytes: 70448, sha256: "229e5965e072b20783c5bd008c39dd914bcd4223d5058767a3f4af2be0f2cb83", mode: 0o0, counterpart: Some("Contents/Home/bin/jdb") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jdwp.agent.jmod", bytes: 129776, sha256: "8e5934f5f19a79bec5ddad6b179fb3a92c5578bb600bee7f6147a1b04c800d3d", members: &[
        JdkJvmMemberPin { member: "lib/libdt_socket.dylib", bytes: 73968, sha256: "586dcfb17ad55d03f46aa75bf0b8ccd622a31bca3eab8cf3fdd673c3e0f380b4", mode: 0o0, counterpart: Some("Contents/Home/lib/libdt_socket.dylib") },
        JdkJvmMemberPin { member: "lib/libjdwp.dylib", bytes: 295552, sha256: "9f62afe88f66fed3cc3eda753a606f69667737199ab57d25eaa377ac24bc266d", mode: 0o0, counterpart: Some("Contents/Home/lib/libjdwp.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jfr.jmod", bytes: 653424, sha256: "3829993357ec5d588a3f4f2e1f6cf64bdfb5f0d63745f481f6660f94babd16c3", members: &[
        JdkJvmMemberPin { member: "bin/jfr", bytes: 70448, sha256: "da2a39b0eb0baae163398254c02f0e74d67b0d3b5dd4faedf500eac7bf11a630", mode: 0o0, counterpart: Some("Contents/Home/bin/jfr") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jlink.jmod", bytes: 425901, sha256: "488aeb6c2b0ed5ecd7f299a40145e589a0218bfaa5912a36aad83839e6451c31", members: &[
        JdkJvmMemberPin { member: "bin/jimage", bytes: 70464, sha256: "66ff78759e96a1e130a0fb8cdcf37eac7d542ca49860726b0bed79f311405522", mode: 0o0, counterpart: Some("Contents/Home/bin/jimage") },
        JdkJvmMemberPin { member: "bin/jlink", bytes: 70464, sha256: "601685bdfbfd2eb31d01e11dee94865f48910d90610829aa2c010c3ababf7650", mode: 0o0, counterpart: Some("Contents/Home/bin/jlink") },
        JdkJvmMemberPin { member: "bin/jmod", bytes: 70464, sha256: "fc3a0982042318463a1648324f2432a71893f745f0e780b87ee75c3f6e7af4c8", mode: 0o0, counterpart: Some("Contents/Home/bin/jmod") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jpackage.jmod", bytes: 695574, sha256: "2eb37c39930a3d8d046e180c8ad65630a0b83dc5b63791c115c78f856e14dd6b", members: &[
        JdkJvmMemberPin { member: "bin/jpackage", bytes: 70464, sha256: "c4aa90b52f2904e5abb87ea52ce108b25b733b5b2dd4a1c0cfd2fa61ac305342", mode: 0o0, counterpart: Some("Contents/Home/bin/jpackage") },
        JdkJvmMemberPin { member: "classes/jdk/jpackage/internal/resources/jpackageapplauncher", bytes: 185600, sha256: "73403782287c715055d9f58cca4571add26f01817d710186bf6e52fa5ac1b442", mode: 0o0, counterpart: None },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jshell.jmod", bytes: 691552, sha256: "8441d5ef733f33aba718ad2ed48610ddd39f43efadeca596b20010bd316de2b0", members: &[
        JdkJvmMemberPin { member: "bin/jshell", bytes: 70464, sha256: "73c4db331de31cb6c261fe5593d6d40cd2023cf6d584f0cb2b3f5fb03fa7a609", mode: 0o0, counterpart: Some("Contents/Home/bin/jshell") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jsobject.jmod", bytes: 10757, sha256: "6d15a02fabc9c9d24100b296dd1918f41d37a0d7d829d3edf5a90f4761a068ef", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.jstatd.jmod", bytes: 42575, sha256: "3f98f2dacdf9530e36f359962277463519ea18cbb61460bf5131a93fb96a585b", members: &[
        JdkJvmMemberPin { member: "bin/jstatd", bytes: 70464, sha256: "13e9c26d467d2791d6dc5902d876d0a1a323e8472133d436ae64df65ce219aa0", mode: 0o0, counterpart: Some("Contents/Home/bin/jstatd") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.localedata.jmod", bytes: 10252728, sha256: "633545f4957ed2891cd2d35478397b9a08bb18137d5ff845c7439edb64f4d143", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.management.agent.jmod", bytes: 102338, sha256: "24621a245cd5d7e6ee84f14a168ec6ea06922e55d1eebcabcfbcc09abe56317d", members: &[
        JdkJvmMemberPin { member: "lib/libmanagement_agent.dylib", bytes: 69952, sha256: "79917926692f3921a3e7f32f78cd6a7f0c2f8b570ece2e28ec6c9a414ce2ca0e", mode: 0o0, counterpart: Some("Contents/Home/lib/libmanagement_agent.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.management.jfr.jmod", bytes: 62410, sha256: "7c72a851837eaf38fbc0e1c9306c10be25d6262aa01cd745efee8059a1e179ee", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.management.jmod", bytes: 80055, sha256: "bdb1d3929ac992562e667c32aeac4d26c7b23affc1419a717acdc04466d858ca", members: &[
        JdkJvmMemberPin { member: "lib/libmanagement_ext.dylib", bytes: 75280, sha256: "daaed83579929aa49972046d23f6e8ca8450473b9f7088ad903457632a453e1f", mode: 0o0, counterpart: Some("Contents/Home/lib/libmanagement_ext.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.naming.dns.jmod", bytes: 69884, sha256: "9e186d77fc05166aed951ac607569eaca5b1fee6e9caa70a7ace7a378cfbc536", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.naming.rmi.jmod", bytes: 30997, sha256: "b190a44217052d7dc2fcdc9b77986f8964b8e0da0b67fec0f50ca495f1a614ae", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.net.jmod", bytes: 35355, sha256: "8d5a877d2a481231624572e6a14f705de2aa650b04dd62a25d855222a5d8baa7", members: &[
        JdkJvmMemberPin { member: "lib/libextnet.dylib", bytes: 70688, sha256: "af867a2643ec8ad87410d25f1ac9a1558a12f7b0607971980e7d367f44fc7c05", mode: 0o0, counterpart: Some("Contents/Home/lib/libextnet.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.nio.mapmode.jmod", bytes: 10225, sha256: "640d5b4cb5a975c9fdf6d87d10ea09a887f9260ee8fdf1196b8e3a1e20eb3a52", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.random.jmod", bytes: 29530, sha256: "eba11c06b11e7ab8970ae61a6e52b498c76cab8b055a0146515cd17d4eb64c4e", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.sctp.jmod", bytes: 31222, sha256: "b224332e3f4867dad790b8fa8dbf4d8f7ae512ad57aea2ef133251205bc3fc64", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.security.auth.jmod", bytes: 80035, sha256: "3fb7d9684c3202f85cdb95681ae6d50fa2956289748f7458cfdde3606b53e6f8", members: &[
        JdkJvmMemberPin { member: "lib/libjaas.dylib", bytes: 69952, sha256: "8222b05dae683eaaae32b669d06c7fad715a212e0e03432494c194bb41f5abb3", mode: 0o0, counterpart: Some("Contents/Home/lib/libjaas.dylib") },
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.security.jgss.jmod", bytes: 32855, sha256: "fe87ba695930c3210259990d3252062c05234539336a17cf8a37e440f505364b", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.unsupported.desktop.jmod", bytes: 21630, sha256: "d256fd3b3214b8af0910f98948db73cd35575f4e83d1c1b0e36f6af869ce0d8a", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.unsupported.jmod", bytes: 25015, sha256: "084eb63668c949ff7f740a7f96d56f891ca6bd9a25db1acbbc5d20a6ef18db6f", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.xml.dom.jmod", bytes: 49991, sha256: "77607422ce0c32d442c09d7968fe69df1a0c37038c4f69582648d6fbcc7fe5a9", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/jmods/jdk.zipfs.jmod", bytes: 112825, sha256: "d12fab8df559f83488adfb877eaf84670f9c9a74c07ac2f84a36c18840f01aaa", members: &[
    ] },
    JdkJvmArchivePin { relative: "Contents/Home/lib/jrt-fs.jar", bytes: 110514, sha256: "1c86328755f2040440d0677b124818991b60b36a37efdbca383bd6a0d64e976f", members: &[
    ] },
];
pub(crate) static SDK_TARGET_ELFS: &[TargetElfPin] = &[
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/blas/arm64-v8a/libblasV8.so", member: "android-15/renderscript/lib/blas/arm64-v8a/libblasV8.so", bytes: 1453592,
        sha256: "6da7926b4509125c41c57b8ef94186eaecf86ee4b3d82448bf2ea9b7b3ce1c44", original_mode: 0o644, class: 64, machine: 183,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,183,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,24,39,22,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,28,0,27,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/blas/armeabi-v7a/libblasV8.so", member: "android-15/renderscript/lib/blas/armeabi-v7a/libblasV8.so", bytes: 905428,
        sha256: "79611c8abff2b3c5871b1635e292df51f15edb5d55a13eb33dc6d2b8cc79ff3f", original_mode: 0o644, class: 32, machine: 40,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,40,0,1,0,0,0,0,0,0,0,52,0,0,0,156,204,13,0,0,2,0,5,52,0,32,0,8,0,40,0,27,0,26,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/blas/x86/libblasV8.so", member: "android-15/renderscript/lib/blas/x86/libblasV8.so", bytes: 1721288,
        sha256: "eb1233432f36e652742b53c4f51402e956f397c28a40e33cf16876446efd4a6c", original_mode: 0o644, class: 32, machine: 3,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,3,0,1,0,0,0,0,0,0,0,52,0,0,0,104,63,26,0,0,0,0,0,52,0,32,0,8,0,40,0,28,0,27,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/blas/x86_64/libblasV8.so", member: "android-15/renderscript/lib/blas/x86_64/libblasV8.so", bytes: 2053256,
        sha256: "68231ae39ffbe51a0411d176db5b6d25e1bdff2243767e2fc32ef9e78309879e", original_mode: 0o644, class: 64, machine: 62,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,62,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,136,77,31,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,28,0,27,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/arm64-v8a/libc.so", member: "android-15/renderscript/lib/intermediates/arm64-v8a/libc.so", bytes: 1135488,
        sha256: "dba9e91341c1ac3213f939e8ea796c2ef08e8ceb8c46a2c33919902b7bdf66f6", original_mode: 0o755, class: 64, machine: 183,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,183,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,0,76,17,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,30,0,27,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/arm64-v8a/libm.so", member: "android-15/renderscript/lib/intermediates/arm64-v8a/libm.so", bytes: 265496,
        sha256: "06058af55fc85804d8a5f9b7b38ef726e22953e0a79b3b59cbcfad490872da85", original_mode: 0o755, class: 64, machine: 183,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,183,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,216,6,4,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,25,0,24,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/armeabi-v7a/libc.so", member: "android-15/renderscript/lib/intermediates/armeabi-v7a/libc.so", bytes: 786416,
        sha256: "112d910aaaa214789a430bfd508cf068d8deeb12be598638877621522c393940", original_mode: 0o755, class: 32, machine: 40,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,40,0,1,0,0,0,0,0,0,0,52,0,0,0,200,250,11,0,0,2,0,5,52,0,32,0,9,0,40,0,33,0,30,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/armeabi-v7a/libm.so", member: "android-15/renderscript/lib/intermediates/armeabi-v7a/libm.so", bytes: 140720,
        sha256: "034f9ae227cbbe6775019b88bcec08f6436b8579c7f9f1d3c46d1b6c832ba2cb", original_mode: 0o755, class: 32, machine: 40,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,40,0,1,0,0,0,0,0,0,0,52,0,0,0,160,33,2,0,0,2,0,5,52,0,32,0,8,0,40,0,26,0,25,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86/libc.so", member: "android-15/renderscript/lib/intermediates/x86/libc.so", bytes: 1057296,
        sha256: "40a4fde26723d09961af85e51b475275d9d90af168fc0b18379e09bbabffc5b0", original_mode: 0o755, class: 32, machine: 3,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,3,0,1,0,0,0,0,0,0,0,52,0,0,0,56,29,16,0,0,0,0,0,52,0,32,0,8,0,40,0,31,0,28,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86/libm.so", member: "android-15/renderscript/lib/intermediates/x86/libm.so", bytes: 232532,
        sha256: "fe45ea2bbd8e60517ca68c751171bb05f0c5a630b20cebb5a115a5fc611873fc", original_mode: 0o755, class: 32, machine: 3,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,3,0,1,0,0,0,0,0,0,0,52,0,0,0,68,136,3,0,0,0,0,0,52,0,32,0,8,0,40,0,26,0,25,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86_64/libc.so", member: "android-15/renderscript/lib/intermediates/x86_64/libc.so", bytes: 1106040,
        sha256: "ab4d975e69f32a91442972b5ce38897a029b4f4c493b53276eed2a4f83388b04", original_mode: 0o755, class: 64, machine: 62,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,62,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,248,216,16,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,30,0,27,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86_64/libm.so", member: "android-15/renderscript/lib/intermediates/x86_64/libm.so", bytes: 323448,
        sha256: "3d25fdb833cd12af7418c17d2dc06e11dfd7d1a2319c2bcb787186a5a88c63a2", original_mode: 0o755, class: 64, machine: 62,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,62,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,56,233,4,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,25,0,24,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/arm64-v8a/libRSSupport.so", member: "android-15/renderscript/lib/packaged/arm64-v8a/libRSSupport.so", bytes: 1236904,
        sha256: "742f14255f7fef22836543d15efa58109ec5a4476cc348bcc77e19d6aa767a65", original_mode: 0o755, class: 64, machine: 183,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,183,0,1,0,0,0,0,176,7,0,0,0,0,0,64,0,0,0,0,0,0,0,40,217,18,0,0,0,0,0,0,0,0,0,64,0,56,0,10,0,64,0,26,0,24,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/arm64-v8a/librsjni.so", member: "android-15/renderscript/lib/packaged/arm64-v8a/librsjni.so", bytes: 72000,
        sha256: "78431e398edb78091f31079f47478df270d50e32c2bc52869542db17ec7c1c03", original_mode: 0o755, class: 64, machine: 183,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,183,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,192,18,1,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,26,0,25,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/arm64-v8a/librsjni_androidx.so", member: "android-15/renderscript/lib/packaged/arm64-v8a/librsjni_androidx.so", bytes: 70192,
        sha256: "2223c4b74b487e3cf863ea53004aae901c033a0be87d8f1b83fb7397db2ff0cb", original_mode: 0o755, class: 64, machine: 183,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,183,0,1,0,0,0,0,96,0,0,0,0,0,0,64,0,0,0,0,0,0,0,112,12,1,0,0,0,0,0,0,0,0,0,64,0,56,0,9,0,64,0,23,0,21,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/armeabi-v7a/libRSSupport.so", member: "android-15/renderscript/lib/packaged/armeabi-v7a/libRSSupport.so", bytes: 866420,
        sha256: "76dfbfb158c03fa4257f4826e5cc776967d22a10472daad97471a5d4b002f56e", original_mode: 0o755, class: 32, machine: 40,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,40,0,1,0,0,0,0,48,5,0,52,0,0,0,100,52,13,0,0,2,0,5,52,0,32,0,10,0,40,0,26,0,24,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/armeabi-v7a/librsjni.so", member: "android-15/renderscript/lib/packaged/armeabi-v7a/librsjni.so", bytes: 59888,
        sha256: "ca754bc0d51764af3286ce6ef088473479062738648c596c8ff61fa21ab3530e", original_mode: 0o755, class: 32, machine: 40,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,40,0,1,0,0,0,0,0,0,0,52,0,0,0,184,229,0,0,0,2,0,5,52,0,32,0,8,0,40,0,27,0,26,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/armeabi-v7a/librsjni_androidx.so", member: "android-15/renderscript/lib/packaged/armeabi-v7a/librsjni_androidx.so", bytes: 54256,
        sha256: "b85df50798c21d3e68e7f1ad4e62fcd296cf6378a8c9c37ec3c2bc98ec05f604", original_mode: 0o755, class: 32, machine: 40,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,40,0,1,0,0,0,0,64,0,0,52,0,0,0,8,208,0,0,0,2,0,5,52,0,32,0,9,0,40,0,25,0,23,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/x86/libRSSupport.so", member: "android-15/renderscript/lib/packaged/x86/libRSSupport.so", bytes: 1284312,
        sha256: "dbfc5ae177ef690758ad47e3f5da37fb68f8e4d1aee118e35989a81ff5315fa7", original_mode: 0o755, class: 32, machine: 3,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,3,0,1,0,0,0,0,16,7,0,52,0,0,0,200,148,19,0,0,0,0,0,52,0,32,0,11,0,40,0,26,0,24,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/x86/librsjni.so", member: "android-15/renderscript/lib/packaged/x86/librsjni.so", bytes: 57956,
        sha256: "297f7750e7b435938aa32459867c6a4d8623215034bbd66328c0628f9d1604bf", original_mode: 0o755, class: 32, machine: 3,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,3,0,1,0,0,0,0,0,0,0,52,0,0,0,84,222,0,0,0,0,0,0,52,0,32,0,8,0,40,0,26,0,25,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/x86/librsjni_androidx.so", member: "android-15/renderscript/lib/packaged/x86/librsjni_androidx.so", bytes: 65288,
        sha256: "e462b50adf7864728229b340f594bcedb89fd3447167bd3b059880b6441d4aaa", original_mode: 0o755, class: 32, machine: 3,
        header: &[127,69,76,70,1,1,1,0,0,0,0,0,0,0,0,0,3,0,3,0,1,0,0,0,0,80,0,0,52,0,0,0,72,251,0,0,0,0,0,0,52,0,32,0,9,0,40,0,24,0,22,0,6,0,0,0,52,0,0,0,52,0,0,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/x86_64/libRSSupport.so", member: "android-15/renderscript/lib/packaged/x86_64/libRSSupport.so", bytes: 1301136,
        sha256: "f3fd63755dfbfcbc68b70c09a3b5d7dd22abc17e4d696f21e6505fba5c1eda8e", original_mode: 0o755, class: 64, machine: 62,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,62,0,1,0,0,0,0,48,8,0,0,0,0,0,64,0,0,0,0,0,0,0,16,212,19,0,0,0,0,0,0,0,0,0,64,0,56,0,11,0,64,0,26,0,24,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/x86_64/librsjni.so", member: "android-15/renderscript/lib/packaged/x86_64/librsjni.so", bytes: 67912,
        sha256: "d08807dd6762afe99625fcf9f0915be8aecad30fc4e5f0b7296407f09dcd0fd3", original_mode: 0o755, class: 64, machine: 62,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,62,0,1,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,200,2,1,0,0,0,0,0,0,0,0,0,64,0,56,0,8,0,64,0,26,0,25,0] },
    TargetElfPin { path: "sdk/build-tools/35.0.0/renderscript/lib/packaged/x86_64/librsjni_androidx.so", member: "android-15/renderscript/lib/packaged/x86_64/librsjni_androidx.so", bytes: 74256,
        sha256: "49165a8e0b5a2253d35e36ba4a44077dec03d0ee0fc99a2dc0edfa537c70f7c5", original_mode: 0o755, class: 64, machine: 62,
        header: &[127,69,76,70,2,1,1,0,0,0,0,0,0,0,0,0,3,0,62,0,1,0,0,0,0,112,0,0,0,0,0,0,64,0,0,0,0,0,0,0,80,28,1,0,0,0,0,0,0,0,0,0,64,0,56,0,9,0,64,0,23,0,21,0] },
];
pub(crate) fn jdk_relative(path: &str) -> Option<&str> {
    let (bundle, relative) = path.strip_prefix("jdk/")?.split_once('/')?;
    (policy::component(bundle) && bundle.len() > 4 && bundle.ends_with(".jdk")
        && policy::relative(relative)).then_some(relative)
}
pub(crate) fn jdk_native(relative: &str) -> Option<&'static JdkNativePin> {
    JDK_NATIVE.iter().find(|pin| pin.relative == relative)
}
pub(crate) fn jdk_jvm_archive(path: &str) -> Option<&'static JdkJvmArchivePin> {
    let relative = jdk_relative(path)?;
    JDK_JVM_ARCHIVES.iter().find(|pin| pin.relative == relative)
}
pub(crate) fn target_elf_reserved(path: &str) -> Option<&'static TargetElfPin> {
    SDK_TARGET_ELFS.iter().find(|pin| pin.path == path)
}
pub(crate) fn android_target_elf(spec: &FileSpec, prefix: &[u8]) -> Result<bool, ()> {
    let Some(pin) = target_elf_reserved(&spec.path) else { return Ok(false); };
    let class = if pin.class == 64 { 2 } else { 1 };
    (pin.matches(&spec.path, spec.size, &spec.sha256, spec.mode)
        && prefix.get(..64) == Some(pin.header) && prefix.starts_with(b"\x7fELF")
        && prefix[4] == class && prefix[5..8] == [1, 1, 0]
        && u16::from_le_bytes([prefix[16], prefix[17]]) == 3
        && u16::from_le_bytes([prefix[18], prefix[19]]) == pin.machine).then_some(true).ok_or(())
}
pub(crate) fn gradle_foreign_launcher(spec: &FileSpec) -> Result<bool, ()> {
    if spec.path != GRADLE_BAT.path { return Ok(false); }
    (spec.size == GRADLE_BAT.bytes && spec.sha256 == GRADLE_BAT.sha256 && spec.mode == 0o444)
        .then_some(true).ok_or(())
}
pub(crate) fn finite_nonhost_inventory(files: &[FileSpec]) -> bool {
    let present = files.iter().any(|file| target_elf_reserved(&file.path).is_some());
    (!present || SDK_TARGET_ELFS.iter().all(|pin| files.iter().any(|file|
        pin.matches(&file.path, file.size, &file.sha256, file.mode))))
        && files.iter().all(|file| gradle_foreign_launcher(file).is_ok())
}
fn selected_file<'a>(inventory: &'a Inventory, relative: &str) -> Option<&'a FileSpec> {
    let bundle = inventory.data.roles.java_home()?.strip_suffix("Contents/Home")?;
    inventory.file_under(bundle, relative)
}
fn jdk_release(inventory: &Inventory) -> bool {
    inventory.data.versions.jdk_vendor == "temurin" && inventory.data.versions.jdk_version == "17.0.20.1"
        && selected_file(inventory, "Contents/Home/release").is_some_and(|file|
            file.size == 1638 && file.sha256 == "cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b"
                && file.mode == 0o444)
        // Exact 29-byte "-server KNOWN\n-client IGNORE\n" original config.
        // This is not inferred from a caller phase or a Java-looking filename.
        && selected_file(inventory, "Contents/Home/lib/jvm.cfg").is_some_and(|file|
            file.size == 29 && file.sha256 == "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0"
                && file.mode == 0o444)
}
pub(crate) fn jdk_post_jli_provider<'a>(
    path: &str, commands: &MachCommands, inventory: &'a Inventory,
) -> Result<Option<&'a str>, ()> {
    let Some(relative) = jdk_relative(path) else { return Ok(None); };
    // Synthetic/other source-reviewed tuples get ordinary closure only. They
    // acquire no post-JLI exception, even if a caller supplies matching paths.
    if inventory.data.versions.jdk_vendor != "temurin"
        || inventory.data.versions.jdk_version != "17.0.20.1" { return Ok(None); }
    if !jdk_release(inventory) { return Err(()); }
    let pin = jdk_native(relative).ok_or(())?;
    let actual = selected_file(inventory, relative).ok_or(())?;
    if actual.path != path || !pin.matches(path, actual.size, &actual.sha256, actual.mode)
        || !pin.header.matches(commands) { return Err(()); }
    // Whole finite original identity closure: a changed/missing JLI, launcher,
    // VM or other installed native can never establish this sealed phase.
    if !JDK_NATIVE.iter().all(|pin| selected_file(inventory, pin.relative).is_some_and(|file|
        pin.matches(&file.path, file.size, &file.sha256, file.mode))) { return Err(()); }
    let jli = jdk_native("Contents/Home/lib/libjli.dylib").ok_or(())?;
    let provider = jdk_native("Contents/Home/lib/server/libjvm.dylib").ok_or(())?;
    if jli.phase != JdkPhase::Bootstrap || provider.phase != JdkPhase::ExplicitJvmProvider
        || jli.header.install_name != Some("@rpath/libjli.dylib")
        || provider.header.install_name != Some("@rpath/libjvm.dylib")
        || !jli.header.loads.iter().chain(provider.header.loads).all(|load| policy::system_load(load))
        // These are the genuine pinned vectors, not a generic parent-rpath
        // exception. The provider's parent is the same protected Home/lib root.
        || jli.header.rpaths != ["@loader_path/."]
        || provider.header.rpaths != ["@loader_path/.", "@loader_path/.."] {
        return Err(());
    }
    if pin.phase != JdkPhase::PostJli { return Ok(None); }
    if !commands.loads.iter().any(|load| load == "@rpath/libjvm.dylib") { return Err(()); }
    Ok(Some(&selected_file(inventory, provider.relative).ok_or(())?.path))
}
pub(crate) fn record_authority() -> impl Serialize {
    (JDK_ARCHIVE_BYTES, JDK_ARCHIVE_SHA256, GRADLE_ARCHIVE_SHA256,
        JDK_NATIVE, JDK_JVM_ARCHIVES, JPACKAGE_TEMPLATE, SDK_TARGET_ELFS, GRADLE_BAT)
}

// The Intel companion is complete JDK comparison DATA from the fixed inspected
// archive, not a complete Android supplier and not a native/JLI phase grant.
#[path = "android_native_macos_intel_jdk.rs"]
mod intel_jdk;

#[derive(Clone, Copy)]
struct JdkTemplateComparison {
    archive: &'static str,
    member: &'static str,
    bytes: u64,
    sha256: &'static str,
    header: &'static MachPin,
}

/// Closed, borrowed byte-comparison DATA. It neither opens originals nor lends
/// the existing ARM post-JLI/provider rule to the Intel observation table.
#[derive(Clone, Copy)]
pub(crate) struct JdkComparisonProfile {
    profile: Profile,
    architecture: MachArchitecture,
    archive: (u64, &'static str),
    release: (u64, &'static str),
    jvm_cfg: (u64, &'static str),
    native: &'static [JdkNativePin],
    archives: &'static [JdkJvmArchivePin],
    template: JdkTemplateComparison,
}

/// Original inner ZIP/JMOD fields, not installed-file permission bits. Its
/// strings are borrowed; parsing or constructing this value supplies no custody.
pub(crate) struct JdkMemberComparison<'a> {
    pub(crate) name: &'a str,
    pub(crate) bytes: u64,
    pub(crate) sha256: &'a str,
    pub(crate) mode: u32,
}

pub(crate) fn jdk_comparison_profile(profile: Profile) -> Option<JdkComparisonProfile> {
    match profile {
        Profile::MacArm64 => Some(JdkComparisonProfile {
            profile, architecture: MachArchitecture::Arm64,
            archive: (JDK_ARCHIVE_BYTES, JDK_ARCHIVE_SHA256),
            release: (1638, "cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b"),
            jvm_cfg: (29, "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0"),
            native: JDK_NATIVE, archives: JDK_JVM_ARCHIVES,
            template: JdkTemplateComparison {
                archive: "Contents/Home/jmods/jdk.jpackage.jmod",
                member: "classes/jdk/jpackage/internal/resources/jpackageapplauncher",
                bytes: 185600, sha256: "73403782287c715055d9f58cca4571add26f01817d710186bf6e52fa5ac1b442",
                header: &JPACKAGE_TEMPLATE,
            },
        }),
        Profile::MacX64 => Some(JdkComparisonProfile {
            profile, architecture: MachArchitecture::X86_64,
            archive: (intel_jdk::ARCHIVE_BYTES, intel_jdk::ARCHIVE_SHA256),
            release: intel_jdk::RELEASE, jvm_cfg: intel_jdk::JVM_CFG,
            native: intel_jdk::NATIVE, archives: intel_jdk::JVM_ARCHIVES,
            template: JdkTemplateComparison {
                archive: "Contents/Home/jmods/jdk.jpackage.jmod",
                member: "classes/jdk/jpackage/internal/resources/jpackageapplauncher",
                bytes: intel_jdk::TEMPLATE_BYTES, sha256: intel_jdk::TEMPLATE_SHA256,
                header: &intel_jdk::TEMPLATE_HEADER,
            },
        }),
        Profile::LinuxX64 => None,
    }
}

impl JdkComparisonProfile {
    pub(crate) fn profile(&self) -> Profile { self.profile }
    pub(crate) fn architecture(&self) -> MachArchitecture { self.architecture }
    pub(crate) fn original_archive(&self) -> (u64, &'static str) { self.archive }
    pub(crate) fn native_members(&self) -> &'static [JdkNativePin] { self.native }
    pub(crate) fn jvm_archives(&self) -> &'static [JdkJvmArchivePin] { self.archives }
    pub(crate) fn native(&self, relative: &str) -> Option<&'static JdkNativePin> {
        self.native.iter().find(|pin| pin.relative == relative)
    }
    pub(crate) fn jvm_archive(&self, path: &str) -> Option<&'static JdkJvmArchivePin> {
        let relative = jdk_relative(path)?;
        self.archives.iter().find(|pin| pin.relative == relative)
    }
    /// Full original regular-file type/mode here, deliberately not an installed
    /// FileSpec's read-only permission bits. No declaration substitutes for readback.
    pub(crate) fn metadata_original_matches(&self, relative: &str, bytes: u64, sha256: &str, mode: u32) -> bool {
        let expected = match relative {
            "Contents/Home/release" => self.release,
            "Contents/Home/lib/jvm.cfg" => self.jvm_cfg,
            _ => return false,
        };
        mode == 0o100644 && (bytes, sha256) == expected
    }
    fn header_matches(&self, pin: &MachPin, prefix: &[u8], commands: &MachCommands) -> bool {
        prefix.len() == pin.prefix_bytes && policy::digest_matches(prefix, pin.prefix_sha256)
            && pin.matches_architecture(commands, self.architecture)
    }
    /// Same existing canonical installed tuple and expected read-only mode; only
    /// the selected profile's exact CPU/header pins participate in comparison.
    pub(crate) fn native_matches(&self, file: &FileSpec, prefix: &[u8], commands: &MachCommands) -> bool {
        let Some(relative) = jdk_relative(&file.path) else { return false; };
        self.native(relative).is_some_and(|pin|
            pin.matches(&file.path, file.size, &file.sha256, file.mode)
                && self.header_matches(&pin.header, prefix, commands))
    }
    pub(crate) fn member_header(&self, archive_path: &str, member: &str) -> Option<&'static MachPin> {
        let archive = self.jvm_archive(archive_path)?;
        let row = archive.members.iter().find(|row| row.member == member)?;
        match row.counterpart {
            Some(relative) => {
                let pin = self.native(relative)?;
                ((row.bytes, row.sha256) == (pin.bytes, pin.sha256)).then_some(&pin.header)
            }
            None => ((archive.relative, row.member, row.bytes, row.sha256)
                == (self.template.archive, self.template.member, self.template.bytes, self.template.sha256))
                .then_some(self.template.header),
        }
    }
    /// A counterpart is in the SAME selected bundle as this exact original
    /// archive. The separately pinned template cannot acquire a provider by a
    /// missing-counterpart fallback. This never calls local_loads or grants JLI.
    pub(crate) fn member_matches(&self, archive_file: &FileSpec, observed: &JdkMemberComparison<'_>,
        counterpart: Option<&FileSpec>, prefix: &[u8], commands: &MachCommands) -> bool {
        let Some(archive) = self.jvm_archive(&archive_file.path) else { return false; };
        if (archive_file.size, archive_file.sha256.as_str(), archive_file.mode)
            != (archive.bytes, archive.sha256, 0o444) { return false; }
        let Some(row) = archive.members.iter().find(|row| row.member == observed.name) else { return false; };
        if (observed.bytes, observed.sha256, observed.mode) != (row.bytes, row.sha256, row.mode) { return false; }
        let Some(header) = self.member_header(&archive_file.path, observed.name) else { return false; };
        if !self.header_matches(header, prefix, commands) { return false; }
        match (row.counterpart, counterpart) {
            (Some(relative), Some(file)) => {
                let Some(bundle) = archive_file.path.strip_suffix(archive.relative) else { return false; };
                file.path.strip_prefix(bundle) == Some(relative)
                    && self.native(relative).is_some_and(|pin|
                        (pin.bytes, pin.sha256) == (row.bytes, row.sha256)
                            && pin.matches(&file.path, file.size, &file.sha256, file.mode))
            }
            (None, None) => true,
            _ => false,
        }
    }
}

#[path = "android_native_macos_intel_tools.rs"]
mod intel_tools;

/// Fixed, non-JDK SOURCE scopes; neither a search path nor a runnable tool role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolComparisonScope {
    AgpAapt2, GradleFileEvents, GradleJansi, GradleNativePlatform, Bundletool,
}
/// This companion has no bootstrap/provider/post-JLI phase to lend to a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolComparisonPhase { ObservationOnly }

/// Exact archive metadata, not installed-file permission bits or original custody.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ToolMemberComparison<'a> {
    pub(crate) name: &'a str, pub(crate) bytes: u64,
    pub(crate) sha256: &'a str, pub(crate) mode: u32,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ToolArchiveComparison<'a> {
    pub(crate) component: &'a str, pub(crate) bytes: u64, pub(crate) sha256: &'a str,
    pub(crate) containing_jar: Option<ToolMemberComparison<'a>>,
}
struct ToolNativePin {
    member: ToolMemberComparison<'static>, slice: policy::MachSlice,
    command_bytes: usize, header: MachPin,
}
struct ToolScopePin {
    scope: ToolComparisonScope, component: &'static str,
    archive_bytes: u64, archive_sha256: &'static str,
    containing_jar: Option<ToolMemberComparison<'static>>,
    native: &'static [ToolNativePin],
}
/// Borrowed DATA only. No IO, mutable catalogue, permission change or native grant.
#[derive(Clone, Copy)]
pub(crate) struct ToolComparisonProfile { pin: &'static ToolScopePin }

pub(crate) fn tool_comparison_profile(profile: Profile, scope: ToolComparisonScope)
    -> Option<ToolComparisonProfile> {
    match profile {
        Profile::MacX64 => {
            let index = match scope {
                ToolComparisonScope::AgpAapt2 => 0,
                ToolComparisonScope::GradleFileEvents => 1,
                ToolComparisonScope::GradleJansi => 2,
                ToolComparisonScope::GradleNativePlatform => 3,
                ToolComparisonScope::Bundletool => 4,
            };
            Some(ToolComparisonProfile { pin: &intel_tools::SCOPES[index] })
        }
        Profile::MacArm64 | Profile::LinuxX64 => None,
    }
}
impl ToolComparisonProfile {
    pub(crate) fn profile(&self) -> Profile { Profile::MacX64 }
    pub(crate) fn scope(&self) -> ToolComparisonScope { self.pin.scope }
    pub(crate) fn phase(&self) -> ToolComparisonPhase { ToolComparisonPhase::ObservationOnly }

    /// Compare one exact captured snapshot, not a complete source or native closure.
    /// The caller's already parsed commands remain DATA. Future native work must
    /// reserve/read its own originals and satisfy the independent loader policy.
    /// In particular this DOES NOT call/relax native_slice: the recorded JNA i386
    /// sibling still refuses there. ZIP mode0 is not an installed0444 permission.
    pub(crate) fn snapshot_matches(&self, archive: &ToolArchiveComparison<'_>,
        member: &ToolMemberComparison<'_>, slice: policy::MachSlice,
        prefix: &[u8], raw_commands: &[u8], commands: &MachCommands) -> bool {
        let expected = self.pin;
        if (archive.component, archive.bytes, archive.sha256)
            != (expected.component, expected.archive_bytes, expected.archive_sha256) { return false; }
        match (&expected.containing_jar, &archive.containing_jar) {
            (Some(pin), Some(row)) if (row.name, row.bytes, row.sha256, row.mode)
                == (pin.name, pin.bytes, pin.sha256, pin.mode) => {},
            (None, None) => {},
            _ => return false,
        }
        let Some(pin) = expected.native.iter().find(|pin| pin.member.name == member.name)
            else { return false; };
        if (member.bytes, member.sha256, member.mode)
            != (pin.member.bytes, pin.member.sha256, pin.member.mode)
            || slice != pin.slice || slice.size < 32
            || prefix.len() != pin.header.prefix_bytes || raw_commands.len() != pin.command_bytes {
            return false;
        }
        let Some(end) = slice.offset.checked_add(slice.size) else { return false; };
        end <= member.bytes && prefix.len() as u64 <= member.bytes
            && raw_commands.len() as u64 <= slice.size
            && pin.header.snapshot_bytes(prefix, raw_commands)
            && pin.header.matches_architecture(commands, MachArchitecture::X86_64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_file(profile: &JdkComparisonProfile, relative: &str) -> FileSpec {
        let pin = profile.native(relative).unwrap();
        FileSpec { path: format!("jdk/Test.jdk/{relative}"), size: pin.bytes,
            sha256: pin.sha256.into(), mode: pin.original_mode & !0o222 }
    }
    fn archive_file(profile: &JdkComparisonProfile, relative: &str) -> FileSpec {
        let path = format!("jdk/Test.jdk/{relative}");
        let pin = profile.jvm_archive(&path).unwrap();
        FileSpec { path, size: pin.bytes, sha256: pin.sha256.into(), mode: 0o444 }
    }
    fn intel_commands(prefix: &[u8], commands: &[u8], bytes: u64) -> MachCommands {
        let slice = policy::native_slice(prefix, bytes, MachArchitecture::X86_64).unwrap();
        assert_eq!(slice.offset, 0);
        policy::native_commands(commands, slice, MachArchitecture::X86_64).unwrap()
    }

    #[test]
    fn paired_jdk_comparison_profiles_bind_cpu_and_original_bytes() {
        let arm = jdk_comparison_profile(Profile::MacArm64).unwrap();
        let intel = jdk_comparison_profile(Profile::MacX64).unwrap();
        assert!(jdk_comparison_profile(Profile::LinuxX64).is_none());
        assert_eq!(arm.profile(), Profile::MacArm64);
        assert_eq!(intel.profile(), Profile::MacX64);
        assert_eq!(arm.architecture(), MachArchitecture::Arm64);
        assert_eq!(intel.architecture(), MachArchitecture::X86_64);
        assert_eq!(arm.original_archive(), (JDK_ARCHIVE_BYTES, JDK_ARCHIVE_SHA256));
        assert_eq!(intel.original_archive(), (180578248,
            "c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a"));
        assert!(std::ptr::eq(arm.native_members(), JDK_NATIVE));
        assert!(std::ptr::eq(arm.jvm_archives(), JDK_JVM_ARCHIVES));
        assert_eq!(intel.native_members().len(), 71);
        assert_eq!(intel.native_members().iter().filter(|pin| pin.header.file_type == 2).count(), 29);
        assert_eq!(intel.native_members().iter().filter(|pin| pin.header.file_type == 6).count(), 42);
        assert!(intel.native_members().iter().all(|pin| pin.phase == JdkPhase::ObservationOnly));
        assert!(arm.native_members().iter().all(|pin| pin.phase != JdkPhase::ObservationOnly));
        assert!(!policy::native_catalog_supports(Profile::MacX64));

        let file = native_file(&intel, "Contents/Home/bin/java");
        let prefix = intel_jdk::JAVA_PREFIX;
        let raw = intel_jdk::JAVA_COMMANDS;
        let commands = intel_commands(prefix, raw, file.size);
        assert!(intel.native_matches(&file, prefix, &commands));
        assert!(!arm.native_matches(&file, prefix, &commands));
        assert!(policy::native_slice(prefix, file.size, MachArchitecture::Arm64).is_none());
        // The old unqualified MachPin API retains its ARM default, not the
        // target of the new observation table from which this pin was obtained.
        assert!(!intel.native("Contents/Home/bin/java").unwrap().header.matches(&commands));
        assert!(!intel.native_matches(&file, &prefix[..prefix.len() - 1], &commands));
        let mut changed_prefix = prefix.to_vec(); changed_prefix[4095] ^= 1;
        assert!(!intel.native_matches(&file, &changed_prefix, &commands));
        for mutate in 0..6 {
            let mut changed = commands.clone();
            match mutate {
                0 => changed.architecture = MachArchitecture::Arm64,
                1 => changed.header_sha256 = "0".repeat(64),
                2 => changed.file_type = 6,
                3 => changed.loads.swap(0, 1),
                4 => changed.rpaths.swap(0, 1),
                _ => changed.install_name = Some("@rpath/other.dylib".into()),
            }
            assert!(!intel.native_matches(&file, prefix, &changed));
        }
        for changed in [FileSpec { size: file.size + 1, ..file.clone() },
            FileSpec { sha256: "0".repeat(64), ..file.clone() },
            FileSpec { mode: 0o755, ..file.clone() },
            FileSpec { mode: 0o100555, ..file.clone() },
            FileSpec { path: "jdk/Test.jdk/Contents/Home/bin/../bin/java".into(), ..file.clone() },
            FileSpec { path: "jdk/Test.jdk/Contents/Home/bin/missing".into(), ..file.clone() }] {
            assert!(!intel.native_matches(&changed, prefix, &commands));
        }
        let release = "edbe3a2e6b6a3186010a3b75257685d943a8baa013a92174c9a48b8c1a73886b";
        assert!(intel.metadata_original_matches("Contents/Home/release", 1637, release, 0o100644));
        assert!(!arm.metadata_original_matches("Contents/Home/release", 1637, release, 0o100644));
        for (relative, bytes, sha256, mode) in [
            ("Contents/Home/release", 1638, release, 0o100644),
            ("Contents/Home/release", 1637, "cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b", 0o100644),
            ("Contents/Home/release", 1637, release, 0o644),
            ("Contents/Home/release", 1637, release, 0o120644),
            ("Contents/Home/./release", 1637, release, 0o100644),
        ] {
            assert!(!intel.metadata_original_matches(relative, bytes, sha256, mode));
        }
        let cfg = "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0";
        assert!(arm.metadata_original_matches("Contents/Home/lib/jvm.cfg", 29, cfg, 0o100644));
        assert!(intel.metadata_original_matches("Contents/Home/lib/jvm.cfg", 29, cfg, 0o100644));
    }

    #[test]
    fn intel_jvm_counterparts_and_template_never_borrow_arm_pins() {
        let intel = jdk_comparison_profile(Profile::MacX64).unwrap();
        let arm = jdk_comparison_profile(Profile::MacArm64).unwrap();
        assert_eq!(intel.jvm_archives().len(), 74);
        assert_eq!(intel.jvm_archives().iter().map(|archive| archive.members.len()).sum::<usize>(), 71);
        let mut linked = 0;
        for archive in intel.jvm_archives() {
            let path = format!("jdk/Test.jdk/{}", archive.relative);
            for row in archive.members {
                assert!(intel.member_header(&path, row.member).is_some());
                if let Some(relative) = row.counterpart {
                    linked += 1;
                    let pin = intel.native(relative).unwrap();
                    assert_eq!((row.bytes, row.sha256), (pin.bytes, pin.sha256));
                    assert!(std::ptr::eq(intel.member_header(&path, row.member).unwrap(), &pin.header));
                } else {
                    assert_eq!((archive.relative, row.member, row.bytes, row.sha256, row.mode),
                        ("Contents/Home/jmods/jdk.jpackage.jmod",
                         "classes/jdk/jpackage/internal/resources/jpackageapplauncher", 188160,
                         "2fc0206e6e6fb80c90d2b1893d2e145e1b9a6162fa1ce5b0349307566b75d7fd", 0));
                }
            }
        }
        assert_eq!(linked, 70);
        let home_jli = intel.native("Contents/Home/lib/libjli.dylib").unwrap();
        let app_jli = intel.native("Contents/MacOS/libjli.dylib").unwrap();
        assert_ne!((home_jli.bytes, home_jli.sha256), (app_jli.bytes, app_jli.sha256));
        assert!(intel.native("Contents/Home/lib/../MacOS/libjli.dylib").is_none());

        let archive = archive_file(&intel, "Contents/Home/jmods/java.base.jmod");
        let file = native_file(&intel, "Contents/Home/bin/java");
        let member = JdkMemberComparison { name: "bin/java", bytes: file.size, sha256: &file.sha256, mode: 0 };
        let commands = intel_commands(intel_jdk::JAVA_PREFIX, intel_jdk::JAVA_COMMANDS, file.size);
        assert!(intel.member_matches(&archive, &member, Some(&file), intel_jdk::JAVA_PREFIX, &commands));
        assert!(!arm.member_matches(&archive, &member, Some(&file), intel_jdk::JAVA_PREFIX, &commands));
        assert!(!intel.member_matches(&archive, &member, None, intel_jdk::JAVA_PREFIX, &commands));
        for (name, bytes, sha256, mode) in [
            ("bin/missing", member.bytes, member.sha256, 0),
            (member.name, member.bytes + 1, member.sha256, 0),
            (member.name, member.bytes, "0", 0),
            (member.name, member.bytes, member.sha256, 0o100755),
        ] {
            assert!(!intel.member_matches(&archive, &JdkMemberComparison { name, bytes, sha256, mode },
                Some(&file), intel_jdk::JAVA_PREFIX, &commands));
        }
        for changed in [FileSpec { size: archive.size + 1, ..archive.clone() },
            FileSpec { sha256: "0".repeat(64), ..archive.clone() },
            FileSpec { mode: 0o555, ..archive.clone() },
            FileSpec { path: "jdk/Elsewhere.jdk/Contents/Home/jmods/java.base.jmod".into(), ..archive.clone() }] {
            assert!(!intel.member_matches(&changed, &member, Some(&file), intel_jdk::JAVA_PREFIX, &commands));
        }
        for changed in [FileSpec { path: "jdk/Elsewhere.jdk/Contents/Home/bin/java".into(), ..file.clone() },
            FileSpec { size: file.size + 1, ..file.clone() },
            FileSpec { sha256: "0".repeat(64), ..file.clone() },
            FileSpec { mode: 0o755, ..file.clone() }] {
            assert!(!intel.member_matches(&archive, &member, Some(&changed), intel_jdk::JAVA_PREFIX, &commands));
        }
        let template_archive = archive_file(&intel, "Contents/Home/jmods/jdk.jpackage.jmod");
        let template = JdkMemberComparison {
            name: "classes/jdk/jpackage/internal/resources/jpackageapplauncher",
            bytes: intel_jdk::TEMPLATE_BYTES, sha256: intel_jdk::TEMPLATE_SHA256, mode: 0,
        };
        let template_commands = intel_commands(intel_jdk::TEMPLATE_PREFIX, intel_jdk::TEMPLATE_COMMANDS, template.bytes);
        assert!(intel.member_matches(&template_archive, &template, None, intel_jdk::TEMPLATE_PREFIX, &template_commands));
        assert!(!arm.member_matches(&template_archive, &template, None, intel_jdk::TEMPLATE_PREFIX, &template_commands));
        assert!(!intel.member_matches(&archive, &template, None, intel_jdk::TEMPLATE_PREFIX, &template_commands));
        assert!(!intel.member_matches(&template_archive, &template, Some(&file), intel_jdk::TEMPLATE_PREFIX, &template_commands));
        for (name, bytes, sha256, mode) in [
            ("classes/other/jpackageapplauncher", template.bytes, template.sha256, 0),
            (template.name, 185600, template.sha256, 0),
            (template.name, template.bytes, "73403782287c715055d9f58cca4571add26f01817d710186bf6e52fa5ac1b442", 0),
            (template.name, template.bytes, template.sha256, 0o755),
        ] {
            assert!(!intel.member_matches(&template_archive, &JdkMemberComparison { name, bytes, sha256, mode },
                None, intel_jdk::TEMPLATE_PREFIX, &template_commands));
        }
    }

    fn tool_original(profile: ToolComparisonProfile) -> ToolArchiveComparison<'static> {
        ToolArchiveComparison { component: profile.pin.component, bytes: profile.pin.archive_bytes,
            sha256: profile.pin.archive_sha256, containing_jar: profile.pin.containing_jar }
    }

    #[test]
    fn intel_non_jdk_snapshots_bind_fixed_archive_scope_and_target() {
        assert_eq!(intel_tools::SCOPES.len(), 5);
        assert_eq!(intel_tools::FIXTURES.len(), 7);
        assert_eq!(intel_tools::SCOPES.iter().map(|pin| pin.native.len()).sum::<usize>(), 7);
        for pin in &intel_tools::SCOPES {
            assert!(tool_comparison_profile(Profile::MacArm64, pin.scope).is_none());
            assert!(tool_comparison_profile(Profile::LinuxX64, pin.scope).is_none());
            assert_eq!(intel_tools::FIXTURES.iter().filter(|row| row.0 == pin.scope).count(), pin.native.len());
        }
        for &(scope, name, prefix, raw) in intel_tools::FIXTURES {
            let profile = tool_comparison_profile(Profile::MacX64, scope).unwrap();
            assert_eq!(profile.profile(), Profile::MacX64);
            assert_eq!(profile.scope(), scope);
            assert_eq!(profile.phase(), ToolComparisonPhase::ObservationOnly);
            let original = tool_original(profile);
            let pin = profile.pin.native.iter().find(|pin| pin.member.name == name).unwrap();
            let member = pin.member;
            let slice = pin.slice;
            // Captured bytes are parsed by the actual existing parser, never a
            // fabricated native implementation. JNA remains inert slice DATA.
            let commands = policy::native_commands(raw, slice, MachArchitecture::X86_64).unwrap();
            assert!(policy::native_commands(raw, slice, MachArchitecture::Arm64).is_none());
            assert!(profile.snapshot_matches(&original, &member, slice, prefix, raw, &commands));
            assert!(!pin.header.matches(&commands)); // old default remains ARM
            for other in &intel_tools::SCOPES {
                if other.scope != scope {
                    let wrong = tool_comparison_profile(Profile::MacX64, other.scope).unwrap();
                    assert!(!wrong.snapshot_matches(&original, &member, slice, prefix, raw, &commands));
                }
            }
            for changed in [ToolArchiveComparison { component: "jdk", ..original },
                ToolArchiveComparison { bytes: original.bytes + 1, ..original },
                ToolArchiveComparison { sha256: "0", ..original }] {
                assert!(!profile.snapshot_matches(&changed, &member, slice, prefix, raw, &commands));
            }
            if let Some(parent) = original.containing_jar {
                let missing = ToolArchiveComparison { containing_jar: None, ..original };
                assert!(!profile.snapshot_matches(&missing, &member, slice, prefix, raw, &commands));
                for changed_parent in [ToolMemberComparison { name: "lib/other.jar", ..parent },
                    ToolMemberComparison { bytes: parent.bytes + 1, ..parent },
                    ToolMemberComparison { sha256: "0", ..parent },
                    ToolMemberComparison { mode: parent.mode ^ 0o200, ..parent }] {
                    let changed = ToolArchiveComparison { containing_jar: Some(changed_parent), ..original };
                    assert!(!profile.snapshot_matches(&changed, &member, slice, prefix, raw, &commands));
                }
            } else {
                let changed = ToolArchiveComparison { containing_jar: Some(ToolMemberComparison {
                    name: "invented.jar", bytes: 1, sha256: "0", mode: 0 }), ..original };
                assert!(!profile.snapshot_matches(&changed, &member, slice, prefix, raw, &commands));
            }
            for changed in [ToolMemberComparison { name: "../aapt2", ..member },
                ToolMemberComparison { name: "unknown-native", ..member },
                ToolMemberComparison { bytes: member.bytes + 1, ..member },
                ToolMemberComparison { sha256: "0", ..member },
                ToolMemberComparison { mode: member.mode ^ 0o200, ..member }] {
                assert!(!profile.snapshot_matches(&original, &changed, slice, prefix, raw, &commands));
            }
            for changed in [policy::MachSlice { offset: slice.offset + 1, ..slice },
                policy::MachSlice { size: slice.size - 1, ..slice },
                policy::MachSlice { offset: u64::MAX, ..slice }] {
                assert!(!profile.snapshot_matches(&original, &member, changed, prefix, raw, &commands));
            }
            assert!(!profile.snapshot_matches(&original, &member, slice, &prefix[..prefix.len()-1], raw, &commands));
            let mut changed_prefix = prefix.to_vec();
            *changed_prefix.last_mut().unwrap() ^= 1;
            assert!(!profile.snapshot_matches(&original, &member, slice, &changed_prefix, raw, &commands));
            let mut changed_raw = raw.to_vec();
            *changed_raw.last_mut().unwrap() ^= 1;
            assert!(!profile.snapshot_matches(&original, &member, slice, prefix, &changed_raw, &commands));
            assert!(!profile.snapshot_matches(&original, &member, slice, prefix, &raw[..raw.len()-1], &commands));
            let mut extra = raw.to_vec(); extra.extend_from_slice(&[0; 8]);
            // native_commands hashes its exact declared header, whereas this
            // comparison requires the complete original snapshot with no suffix.
            assert!(!profile.snapshot_matches(&original, &member, slice, prefix, &extra, &commands));
            for change in 0..6 {
                let mut changed = commands.clone();
                match change {
                    0 => changed.architecture = MachArchitecture::Arm64,
                    1 => changed.header_sha256 = "0".repeat(64),
                    2 => changed.file_type = if commands.file_type == 6 { 2 } else { 6 },
                    3 => changed.install_name = Some("@rpath/not-the-original.dylib".into()),
                    4 => changed.loads.push("/usr/lib/not-the-original.dylib".into()),
                    _ => changed.rpaths.push("@loader_path/not-the-original".into()),
                }
                assert!(!profile.snapshot_matches(&original, &member, slice, prefix, raw, &changed));
            }
            if commands.loads.len() > 1 {
                let mut changed = commands.clone(); changed.loads.swap(0, 1);
                assert!(!profile.snapshot_matches(&original, &member, slice, prefix, raw, &changed));
            }
            if commands.rpaths.len() > 1 {
                let mut changed = commands.clone(); changed.rpaths.swap(0, 1);
                assert!(!profile.snapshot_matches(&original, &member, slice, prefix, raw, &changed));
            }
        }
    }

    #[test]
    fn intel_non_jdk_opaque_siblings_and_loader_labels_never_grant_native_authority() {
        use crate::android_supplier_macos_source::{JdkLayout, SourceLayouts};
        assert!(!policy::native_catalog_supports(Profile::MacX64));
        assert!(policy::native_catalog_supports(Profile::MacArm64));
        assert!(!crate::android_supplier_macos::available_for(Profile::MacX64));
        let layout = SourceLayouts { jdk: JdkLayout::Bundle,
            jdk_vendor: "Eclipse Adoptium", jdk_version: "17.0.20.1" };
        assert!(matches!(crate::android_supplier_macos::recipe_for(Profile::MacX64, &layout),
            Err(crate::android_supplier_macos::Failure::Unavailable)));
        // No ARM supplier-cache initialization or replacement fixture reference.
        let arm = jdk_comparison_profile(Profile::MacArm64).unwrap();
        let intel_jdk = jdk_comparison_profile(Profile::MacX64).unwrap();
        assert!(std::ptr::eq(arm.native_members(), JDK_NATIVE));
        assert_eq!(arm.architecture(), MachArchitecture::Arm64);
        assert_eq!(intel_jdk.architecture(), MachArchitecture::X86_64);
        assert!(intel_jdk.native_members().iter().all(|pin| pin.phase == JdkPhase::ObservationOnly));
        for &(scope, name, prefix, raw) in intel_tools::FIXTURES {
            let profile = tool_comparison_profile(Profile::MacX64, scope).unwrap();
            let original = tool_original(profile);
            let pin = profile.pin.native.iter().find(|pin| pin.member.name == name).unwrap();
            let commands = policy::native_commands(raw, pin.slice, MachArchitecture::X86_64).unwrap();
            assert_eq!(profile.phase(), ToolComparisonPhase::ObservationOnly);
            assert!(profile.snapshot_matches(&original, &pin.member, pin.slice, prefix, raw, &commands));
            for excluded in ["net/rubygrapefruit/platform/aarch64-macos/libgradle-fileevents.dylib",
                "com/sun/jna/linux-x86-64/libjnidispatch.so", "Contents/Home/lib/libjli.dylib",
                "unknown-native", "macos/./aapt2"] {
                let changed = ToolMemberComparison { name: excluded, ..pin.member };
                assert!(!profile.snapshot_matches(&original, &changed, pin.slice, prefix, raw, &commands));
            }
            if name == "com/sun/jna/darwin/libjnidispatch.jnilib" {
                assert_eq!(pin.member.mode, 0);
                assert_eq!((pin.slice.offset, pin.slice.size), (94208, 86724));
                assert_eq!(&prefix[..8], &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]);
                assert_eq!(u32::from_be_bytes(prefix[8..12].try_into().unwrap()), 7);
                assert!(policy::native_slice(prefix, pin.member.bytes, MachArchitecture::X86_64).is_none());
                assert!(policy::native_slice(prefix, pin.member.bytes, MachArchitecture::Arm64).is_none());
                // Replacing the unsupported sibling is NOT a normalization step.
                let mut changed = prefix.to_vec();
                changed[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
                assert!(!profile.snapshot_matches(&original, &pin.member, pin.slice, &changed, raw, &commands));
                let installed = ToolMemberComparison { mode: 0o444, ..pin.member };
                assert!(!profile.snapshot_matches(&original, &installed, pin.slice, prefix, raw, &commands));
            } else {
                assert_eq!(policy::native_slice(prefix, pin.member.bytes, MachArchitecture::X86_64), Some(pin.slice));
            }
            if scope == ToolComparisonScope::GradleJansi {
                let label = "/Users/gnodet/work/git/jansi-native/target/native-build/target/lib/libjansi-1.8.jnilib";
                assert_eq!(commands.install_name.as_deref(), Some(label));
                assert!(!policy::system_load(label));
                let mut dependency = commands.clone(); dependency.loads.push(label.into());
                assert!(!profile.snapshot_matches(&original, &pin.member, pin.slice, prefix, raw, &dependency));
                let mut relabeled = commands.clone(); relabeled.install_name = Some("libjansi.jnilib".into());
                assert!(!profile.snapshot_matches(&original, &pin.member, pin.slice, prefix, raw, &relabeled));
            }
        }
    }
}
