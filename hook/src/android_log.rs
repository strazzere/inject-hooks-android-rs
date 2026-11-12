#[cfg(target_os = "android")]
use std::os::raw::c_char;

// `ANDROID_LOG_DEBUG` is only referenced from `logd!`, which expands to
// nothing in release builds (no debug_assertions), so it's legitimately
// unused there.
#[allow(dead_code)]
pub const ANDROID_LOG_DEBUG: i32 = 3;
pub const ANDROID_LOG_INFO: i32 = 4;

// The one and only declaration of this symbol in the crate - previously
// `log.rs` and `hooks/injection_log.rs` each declared it separately with
// different pointer types (`*const i8` vs `*const c_char`, which is `u8` on
// some targets), tripping `clashing_extern_declarations`. It's also gated to
// `target_os = "android"` so non-Android builds (including host test
// binaries) don't fail to link over a symbol that only exists in Android's
// liblog.
#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_print(prio: i32, tag: *const c_char, fmt: *const c_char, ...) -> i32;
}

/// Logs a single pre-formatted message under `tag` at the given priority.
/// No-op (falls back to stderr) off Android so the rest of the crate stays
/// portable enough to build and test on a regular host.
pub fn log_print(prio: i32, tag: &str, msg: &str) {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;

        let Ok(tag) = CString::new(tag) else { return };
        let Ok(fmt) = CString::new("%s") else { return };
        let msg = CString::new(msg)
            .unwrap_or_else(|_| CString::new("log message contained null byte").unwrap());

        unsafe {
            __android_log_print(prio, tag.as_ptr(), fmt.as_ptr(), msg.as_ptr());
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = prio;
        eprintln!("[{}] {}", tag, msg);
    }
}
