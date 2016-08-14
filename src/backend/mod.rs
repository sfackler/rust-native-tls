//! TLS backend-specific functionality.

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub mod openssl;
