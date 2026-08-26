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

/// Arbitrary offset added to the monotonic reading so timestamps before the
/// clock's raw origin (which starts near zero at process/page start) remain
/// representable — e.g. tests backdating attestation evidence.
const MONO_EPOCH_OFFSET_MILLIS: u64 = 1 << 32;

#[cfg(not(target_arch = "wasm32"))]
static MONO_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Milliseconds elapsed on a monotonic clock (arbitrary epoch).
///
/// Used for measuring elapsed time (e.g. attestation-evidence age), where a
/// wall-clock step must not shrink the measured age. Native builds use
/// `Instant`, which is immune to wall-clock adjustments.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn mono_millis() -> u64 {
    MONO_EPOCH_OFFSET_MILLIS
        + MONO_START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
}

/// Milliseconds elapsed on a monotonic clock (arbitrary epoch).
///
/// wasm builds use `performance.now()` (monotonic; available in both window
/// and worker contexts). If no `performance` global exists, falls back to
/// `Date.now()`, which is *not* monotonic — consumers must treat an apparent
/// backwards step as maximal staleness (fail closed).
#[cfg(target_arch = "wasm32")]
pub(crate) fn mono_millis() -> u64 {
    use wasm_bindgen::{JsCast, JsValue};

    let global = js_sys::global();
    if let Ok(performance) = js_sys::Reflect::get(&global, &JsValue::from_str("performance")) {
        if let Ok(now_fn) = js_sys::Reflect::get(&performance, &JsValue::from_str("now")) {
            if let Some(now_fn) = now_fn.dyn_ref::<js_sys::Function>() {
                if let Ok(value) = now_fn.call0(&performance) {
                    if let Some(millis) = value.as_f64() {
                        return MONO_EPOCH_OFFSET_MILLIS + millis as u64;
                    }
                }
            }
        }
    }

    // Date.now() is large enough on its own; the offset keeps the scale
    // consistent across sources.
    MONO_EPOCH_OFFSET_MILLIS + js_sys::Date::now() as u64
}
