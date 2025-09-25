use std::ffi::CString;

pub unsafe fn init() {
    log_injection();
}

pub unsafe fn log_injection() {
    // Use direct Android logging that works in release mode
    const ANDROID_LOG_INFO: i32 = 4;
    extern "C" {
        fn __android_log_print(prio: i32, tag: *const std::os::raw::c_char, fmt: *const std::os::raw::c_char, ...) -> i32;
    }

    let tag = CString::new("HOOK_INJECT").expect("CString::new failed");
    let fmt = CString::new("%s").unwrap();

    // Log injection success
    let msg1 = CString::new("========================================").unwrap();
    __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), msg1.as_ptr());
    
    let msg2 = CString::new("HOOK LIBRARY SUCCESSFULLY INJECTED!").unwrap();
    __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), msg2.as_ptr());
    
    let msg3 = CString::new("========================================").unwrap();
    __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), msg3.as_ptr());

    // Log process info
    let pid_msg = format!("Process ID: {}", std::process::id());
    if let Ok(c_pid_msg) = CString::new(pid_msg) {
        __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), c_pid_msg.as_ptr());
    }

    // Log library address
    let addr_msg = format!("Library loaded at: {:p}", &log_injection as *const _);
    if let Ok(c_addr_msg) = CString::new(addr_msg) {
        __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), c_addr_msg.as_ptr());
    }

    // Log executable path
    if let Ok(exe_path) = std::env::current_exe() {
        let exe_msg = format!("Current executable: {:?}", exe_path);
        if let Ok(c_exe_msg) = CString::new(exe_msg) {
            __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), c_exe_msg.as_ptr());
        }
    }

    let msg4 = CString::new("========================================").unwrap();
    __android_log_print(ANDROID_LOG_INFO, tag.as_ptr(), fmt.as_ptr(), msg4.as_ptr());
}
