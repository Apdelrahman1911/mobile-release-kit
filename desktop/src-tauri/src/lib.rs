//! Milestone 1 is a passive-query bridge, not a native release-operation owner.
#[cfg(all(feature = "development-runtime", not(debug_assertions)))]
compile_error!("development-runtime is forbidden when debug assertions are disabled");

pub mod error;
pub mod protocol;
pub mod runtime;
pub mod supervisor;
pub mod bridge;
#[cfg(feature = "desktop-shell")]
pub mod shell;
