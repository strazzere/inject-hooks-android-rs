use crate::android_log::{log_print, ANDROID_LOG_INFO};

pub unsafe fn init() {
    log_injection();
}

pub unsafe fn log_injection() {
    const SEP: &str = "========================================";

    // Log injection success
    log_print(ANDROID_LOG_INFO, "HOOK_INJECT", SEP);
    log_print(ANDROID_LOG_INFO, "HOOK_INJECT", "HOOK LIBRARY SUCCESSFULLY INJECTED!");
    log_print(ANDROID_LOG_INFO, "HOOK_INJECT", SEP);

    // Log process info
    log_print(ANDROID_LOG_INFO, "HOOK_INJECT", &format!("Process ID: {}", std::process::id()));

    // Log library address
    log_print(
        ANDROID_LOG_INFO,
        "HOOK_INJECT",
        &format!("Library loaded at: {:p}", log_injection as *const ()),
    );

    // Log executable path
    if let Ok(exe_path) = std::env::current_exe() {
        log_print(ANDROID_LOG_INFO, "HOOK_INJECT", &format!("Current executable: {:?}", exe_path));
    }

    log_print(ANDROID_LOG_INFO, "HOOK_INJECT", SEP);
}
