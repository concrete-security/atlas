//! Platform-specific time helpers.

/// Current UNIX time in whole seconds.
///
/// Native builds read the system clock; wasm builds use `js_sys::Date`.
/// Returns 0 if the system clock is before the UNIX epoch (practically
/// unreachable) — time-sensitive checks then fail closed.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current UNIX time in whole seconds.
#[cfg(target_arch = "wasm32")]
pub(crate) fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
