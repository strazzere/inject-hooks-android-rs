#[macro_export]
macro_rules! logd {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            const ANDROID_LOG_DEBUG: i32 = 3;
            use std::ffi::CString;
            extern "C" {
                fn __android_log_print(prio: i32, tag: *const i8, fmt: *const i8, ...) -> i32;
            }

            let tag = CString::new("hook").expect("CString::new failed");
            let msg = format!($($arg)*);
            if let Ok(c_msg) = CString::new(msg) {
                let fmt = CString::new("%s").unwrap();
                unsafe {
                    __android_log_print(ANDROID_LOG_DEBUG, tag.as_ptr() as *const i8, fmt.as_ptr() as *const i8, c_msg.as_ptr());
                }
            } else {
                let fallback = CString::new("logd! message contained null byte").unwrap();
                let fmt = CString::new("%s").unwrap();
                unsafe {
                    __android_log_print(ANDROID_LOG_DEBUG, tag.as_ptr() as *const i8, fmt.as_ptr() as *const i8, fallback.as_ptr());
                }
            }
        }
    }};
}
