//! TLS backend-specific functionality.

#[cfg(target_os = "macos")]
pub mod security_framework;

#[cfg(target_os = "windows")]
pub mod schannel;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub mod openssl;
