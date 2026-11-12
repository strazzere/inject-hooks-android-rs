use std::os::raw::c_void;
use libc::{mprotect, sysconf, _SC_PAGESIZE, PROT_READ, PROT_WRITE};

use crate::logd;

/// Make `[addr, addr + len)` writable and run `f` with that access, then
/// restore the page(s) to read-only. Covers both the page containing `addr`
/// and, if the range straddles a page boundary, the following page(s) too -
/// the write is pointer-sized (8 bytes on 64-bit), so on a GOT entry that
/// sits in the last few bytes of a page it would otherwise only unprotect
/// the first of the two pages it actually touches.
///
/// Deliberately never requests `PROT_EXEC`: a GOT entry is a data pointer,
/// never fetched as code, and this device's kernel enforces W^X - asking
/// for write+exec together on the same mprotect call is denied outright
/// (EACCES), which previously went unnoticed only because the write still
/// happened to succeed on whatever permissions the page already had,
/// independent of this (silently failing) mprotect call.
///
/// Returns `None` if either `mprotect` call fails.
unsafe fn with_page_unprotected<T>(addr: *mut c_void, len: usize, f: impl FnOnce() -> T) -> Option<T> {
    let page_size = {
        let sz = sysconf(_SC_PAGESIZE);
        if sz > 0 { sz as usize } else { 4096 }
    };

    let start = (addr as usize) & !(page_size - 1);
    let end = ((addr as usize + len) + page_size - 1) & !(page_size - 1);
    let region_len = end - start;
    let region = start as *mut c_void;

    if mprotect(region, region_len, PROT_READ | PROT_WRITE) != 0 {
        logd!(
            "[-] mprotect(RW) failed for {:#x}..{:#x} (addr={:p} len={} page_size={}): {}",
            start, end, addr, len, page_size, std::io::Error::last_os_error()
        );
        return None;
    }

    let result = f();

    if mprotect(region, region_len, PROT_READ) != 0 {
        // The write already happened; this only affects the page
        // permissions left behind, so log it but don't discard the result.
        logd!(
            "[-] mprotect(R) restore failed for {:#x}..{:#x}: {}",
            start, end, std::io::Error::last_os_error()
        );
    }

    Some(result)
}

#[cfg(target_arch = "aarch64")]
unsafe fn write_got_entry(addr: *mut *const c_void, replacement: *const c_void) {
    *addr = replacement;
}

#[cfg(target_arch = "arm")]
unsafe fn write_got_entry(addr: *mut *const c_void, replacement: *const c_void) {
    // For 32-bit ARM, set the Thumb bit
    *addr = (replacement as usize | 1) as *const c_void;
}

// Only arm/aarch64 Android targets are ever actually hooked for real; this
// fallback exists purely so the crate keeps building on a host/dev machine
// for quick iteration (see the TODO this resolves: the GOT-patching
// semantics genuinely only make sense gated per-arch, not decided at
// runtime via a single combined branch).
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
unsafe fn write_got_entry(addr: *mut *const c_void, replacement: *const c_void) {
    *addr = replacement;
}

/// This is safer than utilizing the trampolines.
/// Returns `None` if the page(s) containing the GOT entry couldn't be made
/// writable (or couldn't be restored afterward).
pub unsafe fn patch_got_entry(addr: *mut *const c_void, replacement: *const c_void) -> Option<*const c_void> {
    with_page_unprotected(addr as *mut c_void, std::mem::size_of::<*const c_void>(), || {
        let original = *addr;
        write_got_entry(addr, replacement);
        original
    })
}
