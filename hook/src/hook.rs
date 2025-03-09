
use libc::dlsym;
use std::ffi::CString;

use crate::{logd, patch::{make_thumb_trampoline, patch_thumb_hook}};

pub unsafe fn hook_function(target: &str, replacement: *const u8) -> Option<*const u8> {
    let symbol = CString::new(target).unwrap();
    let orig = dlsym(libc::RTLD_DEFAULT, symbol.as_ptr());
    if orig.is_null() {
        logd!("[-] {} not found", target);
        return None;
    }

    let orig_ptr = orig as usize;
    let is_thumb = orig_ptr & 1 == 1;
    let real_fn = (orig_ptr & !1) as *mut u8;

    logd!("[+] Patching {} at {:#x}", target, real_fn as usize);

    if !is_thumb {
        logd!("ARM mode not supported yet.");
        return None;
    }

    logd!("Patching in Thumb mode");

    let trampoline = make_thumb_trampoline(orig as *const u8);
    if trampoline.is_null() {
        logd!("[-] Failed to create trampoline for {}", target);
        return None;
    }
    // Do the in-place patch
    patch_thumb_hook(real_fn, replacement);

    Some(trampoline)
}