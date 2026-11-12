#[macro_export]
macro_rules! logd {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            $crate::android_log::log_print(
                $crate::android_log::ANDROID_LOG_DEBUG,
                "hook",
                &format!($($arg)*),
            );
        }
    }};
}
