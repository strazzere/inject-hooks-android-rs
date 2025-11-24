use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use libc::{pid_t, mmap, munmap, RTLD_NOW, RTLD_LOCAL, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS};

#[cfg(target_arch = "aarch64")]
use libc::PROT_EXEC;

use crate::ptrace::{ptrace_attach, ptrace_detach, ptrace_write};
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use crate::ptrace::call_remote_function;
use crate::utils::get_remote_function_addr;

/// Choose a reasonable default path for libc based on target pointer width
fn default_libc_path() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "/system/lib64/libc.so"
    } else {
        "/system/lib/libc.so"
    }
}

/// Choose a reasonable default path for the dynamic linker
fn default_linker_path() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "/system/bin/linker64"
    } else {
        "/system/bin/linker"
    }
}

/// Resolve a path if it is a symlink, returning an absolute, canonical path
/// Falls back gracefully to the original if resolution fails
fn resolve_if_symlink(path: &str) -> String {
    let p = Path::new(path);

    match fs::symlink_metadata(p) {
        Ok(meta) if !meta.file_type().is_symlink() => return path.to_string(),
        Ok(_) => { /* it's a symlink; continue to resolve */ }
        Err(_) => {
            // If we can't stat it, still return the original (maps lookup may still succeed)
            return path.to_string();
        }
    }

    // Preferred: fully canonicalize (resolves chains of symlinks & relative hops)
    if let Ok(abs) = fs::canonicalize(p) {
        return abs.to_string_lossy().into_owned();
    }

    // Fallback: single-hop read_link + join with parent if necessary
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

/// Public helpers: return the *resolved* (non-symlink) full paths
pub fn get_libc_path() -> String {
    resolve_if_symlink(default_libc_path())
}

pub fn get_linker_path() -> String {
    resolve_if_symlink(default_linker_path())
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
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

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
fn call_mmap(pid: pid_t, length: usize) -> Result<u64, Box<dyn std::error::Error>> {
    #[cfg(target_arch = "aarch64")]
    {
        println!("[mmap] Calling mmap via library function");

        let local = mmap as usize as u64;
        let remote = get_remote_function_addr(pid, get_libc_path().as_str(), local).ok_or("Failed to resolve mmap")?;

        let args = [
            0,
            length as u64,
            (PROT_READ | PROT_WRITE | PROT_EXEC) as u64,
            (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
            !0u64, // fd (-1)
            0,
        ];

        println!("[mmap] Calling mmap at 0x{:x} with args: {:?}", remote, args);
        Ok(call_remote_function(pid, remote, &args, remote)?)
    }

    #[cfg(target_arch = "arm")]
    {
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

        let result = call_remote_function(pid, remote, &args, 0)?;
        println!("[mmap] mmap returned: 0x{:x}", result);
        Ok(result)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
fn call_munmap(pid: pid_t, addr: u64, length: usize) -> Result<u64, Box<dyn std::error::Error>> {
    #[cfg(target_arch = "aarch64")]
    {
        // Use library function for aarch64 (same approach as 32-bit ARM)
        println!("[munmap] Calling munmap via library function");

        let local = munmap as usize as u64;
        let remote = get_remote_function_addr(pid, get_libc_path().as_str(), local).ok_or("Failed to resolve munmap")?;

        let args = [addr, length as u64];

        println!("[munmap] Calling munmap at 0x{:x} with args: {:?}", remote, args);
        Ok(call_remote_function(pid, remote, &args, remote)?)
    }

    #[cfg(target_arch = "arm")]
    {
        // Use library function for 32-bit ARM
        let local = munmap as usize as u64;
        let remote = get_remote_function_addr(pid, get_libc_path().as_str(), local).ok_or("Failed to resolve munmap")?;

        let args = [addr, length as u64];

        #[cfg(debug_assertions)]
        println!("munmap: call at 0x{:x} addr=0x{:x}, size={}", remote, addr, length);

        Ok(call_remote_function(pid, remote, &args, 0)?)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
fn call_dlopen(pid: pid_t, lib_path: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let local = libc::dlopen as usize as u64;

    // First try to find dlopen in the linker
    let linker_path = get_linker_path();
    println!("[dlopen] Trying linker first: {}", linker_path);

    let remote = get_remote_function_addr(pid as i32, &linker_path, local)
        .or_else(|| {
            // If not found in linker, try libdl files
            println!("[dlopen] Not found in linker, trying libdl files");
            let possible_libs = if cfg!(target_pointer_width = "64") {
                vec![
                    "/apex/com.android.runtime/lib64/bionic/libdl.so",
                    "/system/lib64/libdl.so",
                ]
            } else {
                vec![
                    "/apex/com.android.runtime/lib/bionic/libdl.so",
                    "/system/lib/libdl.so",
                ]
            };

            possible_libs.iter()
                .find_map(|lib_path| {
                    println!("[dlopen] Trying libdl: {}", lib_path);
                    get_remote_function_addr(pid as i32, lib_path, local)
                })
        })
        .ok_or("Failed to resolve dlopen in linker or libdl")?;

    // Get mmap address for the new call_remote_function signature
    let local_mmap = mmap as usize as u64;
    let mmap_remote = get_remote_function_addr(pid as i32, get_libc_path().as_str(), local_mmap)
        .ok_or("Failed to resolve mmap for dlopen")?;

    let mmap_addr = call_mmap(pid, 0x400)?;
    let c_path = CString::new(lib_path)?;

    ptrace_write(pid, mmap_addr as *mut u8, c_path.as_bytes_with_nul())?;

    let args = [mmap_addr, (RTLD_NOW | RTLD_LOCAL) as u64];

    #[cfg(debug_assertions)]
    println!("dlopen: remote=0x{:x}, path='{}'", remote, lib_path);

    let result = call_remote_function(pid, remote, &args, mmap_remote)?;
    println!("[dlopen] dlopen returned: 0x{:x}", result);

    call_munmap(pid, mmap_addr, 0x400)?;
    Ok(result)
}
