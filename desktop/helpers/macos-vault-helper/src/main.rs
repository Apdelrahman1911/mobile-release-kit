//! Fixed private helper main, no user commands or renderer entry points.
#[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
compile_error!("the fixed vault helper supports only the reviewed macOS LP64 arm64/x86_64 profiles");
const _:()=assert!(mrk_macos_installed_native::VAULT_HELPER_BUILD);
#[no_mangle]
pub extern "C" fn mrk_wrapping_vault_helper_role()->u32{3}
fn main(){std::process::exit(mrk_macos_installed_native::vault_helper::main_entry());}
