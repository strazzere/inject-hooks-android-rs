use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use libc::{pid_t, mmap, munmap, RTLD_NOW, RTLD_LOCAL, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS};

use crate::ptrace::{ptrace_attach, ptrace_detach, ptrace_write, call_remote_function};
use crate::utils::get_remote_function_addr;

/// Choose a reasonable default path for libc based on target pointer width.
fn default_libc_path() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "/system/lib64/libc.so"
    } else {
        "/system/lib/libc.so"
    }
}

/// Choose a reasonable default path for the dynamic linker.
fn default_linker_path() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "/system/bin/linker64"
    } else {
        "/system/bin/linker"
    }
}

/// Resolve a path if it is a symlink, returning an absolute, canonical path.
/// Falls back gracefully to the original if resolution fails.
fn resolve_if_symlink(path: &str) -> String {
    let p = Path::new(path);

    // Fast path: if we can read symlink metadata and it's not a symlink, return as-is.
    match fs::symlink_metadata(p) {
        Ok(meta) if !meta.file_type().is_symlink() => return path.to_string(),
        Ok(_) => { /* it's a symlink; continue to resolve */ }
        Err(_) => {
            // If we can't stat it, still return the original (maps lookup may still succeed).
            return path.to_string();
        }
    }

    // Preferred: fully canonicalize (resolves chains of symlinks & relative hops).
    if let Ok(abs) = fs::canonicalize(p) {
        return abs.to_string_lossy().into_owned();
    }

    // Fallback: single-hop read_link + join with parent if necessary.
    match fs::read_link(p) {
        Ok(target) => {
            let resolved: PathBuf = if target.is_absolute() {
                target
            } else {
                p.parent().unwrap_or_else(|| Path::new("/")).join(target)
            };
            resolved.to_string_lossy().into_owned()
        }
        Err(_) => path.to_string(),
    }
}

/// Public helpers: return the *resolved* (non-symlink) full paths.
/// Use these when comparing against `/proc/<pid>/maps`.
pub fn get_libc_path() -> String {
    resolve_if_symlink(default_libc_path())
}

pub fn get_linker_path() -> String {
    resolve_if_symlink(default_linker_path())
}

pub fn inject_library(pid: pid_t, library_path: &str) -> Result<u64, Box<dyn std::error::Error>> {
    ptrace_attach(pid)?;

    let handle = call_dlopen(pid, library_path)?;

    #[cfg(debug_assertions)]
    {
        if handle == 0 {
            println!("Injection failed...");
        } else {
            println!("Injection ended successfully...");
        }
    }

    ptrace_detach(pid)?;
    Ok(handle)
}

fn call_mmap(pid: pid_t, length: usize) -> Result<u64, Box<dyn std::error::Error>> {
    let local = mmap as usize as u64;
    let remote = get_remote_function_addr(pid, get_libc_path().as_str(), local).ok_or("Failed to resolve mmap")?;

    let args = [
        0,
        length as u64,
        (PROT_READ | PROT_WRITE) as u64,
        (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
        0,
        0,
    ];

    #[cfg(debug_assertions)]
    println!("mmap: call at 0x{:x} with size {}", remote, length);

    Ok(call_remote_function(pid, remote, &args)?)
}

fn call_munmap(pid: pid_t, addr: u64, length: usize) -> Result<u64, Box<dyn std::error::Error>> {
    let local = munmap as usize as u64;
    let remote = get_remote_function_addr(pid, get_libc_path().as_str(), local).ok_or("Failed to resolve munmap")?;

    let args = [addr, length as u64];

    #[cfg(debug_assertions)]
    println!("munmap: call at 0x{:x} addr=0x{:x}, size={}", remote, addr, length);

    Ok(call_remote_function(pid, remote, &args)?)
}

fn call_dlopen(pid: pid_t, lib_path: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let local = libc::dlopen as usize as u64;
    let remote = get_remote_function_addr(pid, get_linker_path().as_str(), local).ok_or("Failed to resolve dlopen")?;

    let mmap_addr = call_mmap(pid, 0x400)?;
    let c_path = CString::new(lib_path)?;

    ptrace_write(pid, mmap_addr as *mut u8, c_path.as_bytes_with_nul());

    let args = [mmap_addr, (RTLD_NOW | RTLD_LOCAL) as u64];

    #[cfg(debug_assertions)]
    println!("dlopen: remote=0x{:x}, path='{}'", remote, lib_path);

    let result = call_remote_function(pid, remote, &args)?;

    call_munmap(pid, mmap_addr, 0x400)?;
    Ok(result)
}
