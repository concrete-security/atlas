//! Logging initialization for atls-core.
//!
//! This module provides cross-platform logging support:
//! - On native targets: Uses `env_logger`, controlled by `DEBUG_ATLS` env var
//! - On WASM targets: Uses `console_log` for browser/Node.js console output
//!
//! Logging is automatically initialized on first use of `atls_connect`.
//! Users can also call `init()` manually for early initialization.

use std::sync::OnceLock;

static INIT: OnceLock<()> = OnceLock::new();

/// Initialize the logging subsystem.
///
/// This function is idempotent and can be called multiple times safely.
/// It will only initialize logging once.
///
/// # Behavior
///
/// ## Native (non-WASM)
/// - If `DEBUG_ATLS=1` or `DEBUG_ATLS=true` env var is set, enables DEBUG level
/// - If the `debug-logging` feature is enabled, enables DEBUG level
/// - Otherwise, logging is set to ERROR level (effectively silent)
///
/// ## WASM
/// - If the `debug-logging` feature is enabled, enables DEBUG level
/// - Otherwise, logging is set to ERROR level (effectively silent)
/// - Logs are output to the browser/Node.js console
pub fn init() {
    INIT.get_or_init(|| {
        init_impl();
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn init_impl() {
    use log::LevelFilter;

    let debug_enabled = cfg!(feature = "debug-logging") || is_debug_env_set();

    let level = if debug_enabled {
        LevelFilter::Debug
    } else {
        LevelFilter::Error
    };

    env_logger::Builder::new()
        .filter_module("atls_core", level)
        .format_timestamp_millis()
        .try_init()
        .ok(); // Ignore error if already initialized
}

#[cfg(not(target_arch = "wasm32"))]
fn is_debug_env_set() -> bool {
    std::env::var("DEBUG_ATLS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(target_arch = "wasm32")]
fn init_impl() {
    use log::LevelFilter;

    let level = if cfg!(feature = "debug-logging") {
        LevelFilter::Debug
    } else {
        LevelFilter::Error
    };

    console_log::init_with_level(level.to_level().unwrap_or(log::Level::Error)).ok();
}
