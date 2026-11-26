//! The finite protected OS-image role. No DLL is loaded by these APIs. A role
//! cannot be attached to a payload original or minted from a caller pathname.
use super::*;

macro_rules! images {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum SystemImage { $($variant),+ }
        impl SystemImage {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub fn name(self) -> &'static str { match self { $(Self::$variant => $name),+ } }
            pub fn from_name(name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|image| name.eq_ignore_ascii_case(image.name()))
            }
        }
    };
}
// Accepted embedded-payload SYSTEM_IMAGES physical names. Named API contracts
// are OS resolver DATA, not physical-file candidates or a prefix wildcard.
images! {
    Advapi32 => "advapi32.dll", Bcrypt => "bcrypt.dll", Crypt32 => "crypt32.dll",
    Iphlpapi => "iphlpapi.dll", Kernel32 => "kernel32.dll", Ole32 => "ole32.dll",
    Oleaut32 => "oleaut32.dll", Propsys => "propsys.dll", Rpcrt4 => "rpcrt4.dll",
    User32 => "user32.dll", Version => "version.dll", Winmm => "winmm.dll", Ws232 => "ws2_32.dll",
    Ntdll => "ntdll.dll", Kernelbase => "kernelbase.dll", Ucrtbase => "ucrtbase.dll",
    Msvcrt => "msvcrt.dll", Sechost => "sechost.dll", Bcryptprimitives => "bcryptprimitives.dll",
    Cryptbase => "cryptbase.dll", Msasn1 => "msasn1.dll", Nsi => "nsi.dll", Mswsock => "mswsock.dll",
    Combase => "combase.dll", Gdi32 => "gdi32.dll", Gdi32full => "gdi32full.dll", Win32u => "win32u.dll",
    MsvcpWin => "msvcp_win.dll", Shcore => "shcore.dll", Shlwapi => "shlwapi.dll", Imm32 => "imm32.dll",
}

pub(super) fn selected_names(names: &[String]) -> Result<()> {
    //31 OS names, three location branches, and the legacy directory; no wider
    // family or refresh of the global directory/record budgets.
    if names.is_empty() || names.len() > 35 { return Err(Error::Bounds); }
    for (index, name) in names.iter().enumerate() {
        if !decode::component(name) || names[..index].iter().any(|prior| prior.eq_ignore_ascii_case(name)) {
            return Err(Error::Unsafe);
        }
    }
    Ok(())
}

impl NativeBook {
    pub fn open_system_image(&mut self, system: &KnownLocation, parent: &Original,
        image: SystemImage, name: &str) -> Result<Original> {
        self.clear()?;
        if !Arc::ptr_eq(&self.identity, &system.book) || !matches!(system.kind, LocationKind::System)
            || SystemImage::from_name(name) != Some(image) || !decode::component(name) { return Err(Error::State); }
        let parent_index = self.index(parent)?;
        let parent = self.slot(parent_index)?;
        let expected = format!("{}\\{}", system.device, system.components.join("\\"));
        // Known-location APIs may spell System32 as system32. The directory's
        // canonical spelling/full identity is still checked exactly by metadata;
        // this closed namespace comparison folds ASCII case only, never aliases.
        if parent.kind != Kind::Directory || !parent.canonical.eq_ignore_ascii_case(&expected) { return Err(Error::Unsafe); }
        let canonical = format!("{}\\{name}", parent.canonical);
        if canonical.encode_utf16().count() >= NAME_UNITS { return Err(Error::Bounds); }
        // Registration and role precede the original native acquisition. No
        // public role-changing method or general allow-hardlinks flag exists.
        let original = self.reserve(Kind::File, Some(parent_index), name, canonical)?;
        self.slot_mut(original.index)?.system_image = Some(image);
        self.call(Call::Open(original.index), null_mut(), Vec::new())?;
        self.noninherited(original.index)?;
        Ok(original)
    }
}
