
use std::os::raw::c_void;
use libc::{mprotect, PROT_EXEC, PROT_READ, PROT_WRITE};

// TODO : Lots of this should be gated behind arm only compilation


// This is safer than utilizing the trampolines
pub unsafe fn patch_got_entry(addr: *mut *const c_void, replacement: *const c_void) -> *const c_void {
    let page_size = 4096;
    let page = (addr as usize) & !(page_size - 1);

    mprotect(page as *mut c_void, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    let original = *addr;

    if cfg!(target_arch = "aarch64") {
        *addr = replacement;
    } else {
        // For 32-bit ARM, set the Thumb bit
        *addr = (replacement as usize | 1) as *const c_void;
    }

    mprotect(page as *mut c_void, page_size, PROT_READ | PROT_EXEC);

    original
}

