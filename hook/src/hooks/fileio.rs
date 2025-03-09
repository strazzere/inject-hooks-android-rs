use libc::{c_char, c_void, FILE, size_t};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::ffi::CStr;
use std::sync::Mutex;
use std::slice;
use memchr::memmem;

use crate::elf::{find_got_entry_for_symbol, find_module_base};
use crate::logd;
use crate::patch::patch_got_entry;

#[derive(Eq, PartialEq, Hash)]
struct UnsafeFilePtr(*mut FILE);
unsafe impl Send for UnsafeFilePtr {}
unsafe impl Sync for UnsafeFilePtr {}

static TRACKED_FILES: Lazy<Mutex<HashSet<UnsafeFilePtr>>> = Lazy::new(|| Mutex::new(HashSet::new()));

type FopenType = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut FILE;
type FreadType = unsafe extern "C" fn(*mut c_void, size_t, size_t, *mut FILE) -> size_t;

static mut REAL_FOPEN: Option<FopenType> = None;
static mut REAL_FREAD: Option<FreadType> = None;

pub unsafe fn init() {
    hook_file_io();
}
pub unsafe fn hook_file_io() {
    logd!("Attempting got patching on fopen");

    // This could be generalized to look up what process it currently is injected into
    let base = match find_module_base("/system/bin/target_process") {
        Some(b) => b,
        None => {
            logd!("[-] Failed to find module base for /system/bin/target_process");
            return;
        }
    };

    // Find symbol you want to hook
    let fopen_got_offset = find_got_entry_for_symbol("/system/bin/target_process", "fopen")
    .expect("Could not find GOT entry for fopen");

    logd!("[*] Calculated GOT entry address: {:#x}", fopen_got_offset);
    let fopen_got_ptr = (base + fopen_got_offset as usize) as *mut *const c_void;
    logd!("[*] GOT before: {:?}", *fopen_got_ptr);

    // Replace GOT ptr with our ptr
    let fopen_orig = patch_got_entry(fopen_got_ptr, hooked_fopen as *const c_void);
    logd!("[*] GOT after: {:?}", *fopen_got_ptr);

    logd!("[+] fopen GOT patch applied: {:#x} -> {:?}", fopen_got_offset, hooked_fopen as *const c_void);
    REAL_FOPEN = Some(std::mem::transmute(fopen_orig));

    logd!("[*] GOT entry for 'fopen' offset = 0x{:x}", fopen_got_offset);
    logd!("[*] Base of target_process = 0x{:x}", base);
    logd!("[*] Absolute GOT address = 0x{:x}", base + fopen_got_offset as usize);


    let fread_got_offset = find_got_entry_for_symbol("/system/bin/target_process", "fread")
    .expect("Could not find GOT entry for fread");

    logd!("[*] Calculated GOT entry address: {:#x}", fread_got_offset);

    let fread_got_ptr = (base + fread_got_offset as usize) as *mut *const c_void;
    logd!("[*] GOT before: {:?}", *fread_got_ptr);
    let fread_orig = patch_got_entry(fread_got_ptr, hooked_fread as *const c_void);
    logd!("[*] GOT after: {:?}", *fread_got_ptr);

    logd!("[+] fread GOT patch applied: {:#x} -> {:?}", fread_got_offset, hooked_fread as *const c_void);
    REAL_FREAD = Some(std::mem::transmute(fread_orig));

    logd!("[*] GOT entry for 'fread' offset = 0x{:x}", fread_got_offset);
    logd!("[*] Base of target_process = 0x{:x}", base);
    logd!("[*] Absolute GOT address = 0x{:x}", base + fread_got_offset as usize);
}

thread_local! {
    static IN_FOPEN_HOOK: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

#[no_mangle]
pub unsafe extern "C" fn hooked_fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    if IN_FOPEN_HOOK.with(|c| c.get()) {
        logd!("[~] Reentrant fopen call");
        return REAL_FOPEN.expect("REAL_FOPEN missing")(path, mode);
    }
    IN_FOPEN_HOOK.with(|c| c.set(true));

    let real_fopen = REAL_FOPEN.expect("REAL_FOPEN missing");
    let file = real_fopen(path, mode);

    let path_str = path.as_ref().map(|_| CStr::from_ptr(path).to_string_lossy()).unwrap_or("<null>".into());
    let mode_str = mode.as_ref().map(|_| CStr::from_ptr(mode).to_string_lossy()).unwrap_or("<null>".into());

    logd!("[+] fopen checking: {} w/ {} ", path_str, mode_str);
    if !file.is_null()
        && path_str.contains("/data/local/temp/")
        && path_str.ends_with(".target")
    {
        logd!("[+] fopen matched: {}", path_str);
        TRACKED_FILES.lock().unwrap().insert(UnsafeFilePtr(file));
    }

    IN_FOPEN_HOOK.with(|c| c.set(false));
    file
}

#[no_mangle]
pub unsafe extern "C" fn hooked_fread(
    ptr: *mut c_void,
    size: size_t,
    nmemb: size_t,
    stream: *mut FILE,
) -> size_t {
    let real_fread = REAL_FREAD.expect("REAL_FREAD missing");
    let n = real_fread(ptr, size, nmemb, stream);

    if ptr.is_null() || size == 0 || nmemb == 0 {
        logd!("fread: invalid parameters");
        return n;
    }

    if !TRACKED_FILES.lock().unwrap().contains(&UnsafeFilePtr(stream)) {
        return n;
    }

    let total_len = size.checked_mul(nmemb).unwrap_or(0);
    if total_len == 0 || total_len > 1024 * 1024 {
        logd!("fread: skipping large or empty buffer: {}", total_len);
        return n;
    }

    logd!("fread: size={} nmemb={} total={} stream={:?}", size, nmemb, total_len, stream);

    let buf = slice::from_raw_parts_mut(ptr as *mut u8, total_len);

    let _orig_str = match std::str::from_utf8(buf) {
        Ok(s) => {
            logd!("fread: UTF-8 parse OK, length {}", s.len());
            s
        }
        Err(_) => {
            logd!("fread: UTF-8 parse FAILED");
            return n;
        }
    };

    let mut modified = false;

    // If this specific phrase is sound, change it's value
    // current target is secret_key="{anything}"
    let key = b"secret_key=\"";
    let mut key_matches = vec![];
    for pos in memmem::find_iter(buf, key) {
        let val_start = pos + key.len();
        if val_start >= buf.len() {
            continue;
        }
        if let Some(len) = buf[val_start..].iter().position(|&b| b == b'"') {
            let val_end = val_start + len;
            key_matches.push((val_start, val_end));
        }
    }
    for (start, end) in key_matches {
        if &buf[start..end] != b"0" {
            logd!("[patch] {:?} found: {}..{} → patching", key, start, end);
            // Note we're cheating a bit here with the a potentially unsafe copy into
            // the quotes
            buf[start..end].copy_from_slice(b"d1ff");
            modified = true;
        }
    }

    if modified {
        logd!("Success: patched fread buffer in-place");
    } else {
        logd!("fread: no patching needed");
    }

    n
}