//! Typed desktop services. Passive queries and finite configuration transactions
//! have separate original-resource owners; neither is a generic release runner.
#[cfg(all(feature = "development-runtime", not(debug_assertions)))]
compile_error!("development-runtime is forbidden when debug assertions are disabled");

pub mod error;
pub mod protocol;
pub mod runtime;
pub mod supervisor;
pub mod bridge;
mod document_lifetime;
mod edit_commands;
pub mod edit_protocol;
pub mod edit_owner;
#[cfg(feature = "desktop-shell")]
pub mod shell;
