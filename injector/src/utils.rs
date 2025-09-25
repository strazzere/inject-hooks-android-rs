use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process;

fn verbose() -> bool {
    // Any presence of INJECT_VERBOSE enables logs
    env::var("INJECT_VERBOSE").is_ok()
}

macro_rules! vlog {
    ($($arg:tt)*) => {
        if crate::utils::verbose() {
            eprintln!($($arg)*);
        }
    }
}

/// ---------- PID helpers ----------

pub fn get_pid(process_name: &str) -> Option<i32> {
    let target = process_name;
    let target_base = Path::new(process_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(process_name);

    vlog!("[pid] looking for process: target='{}' base='{}'", target, target_base);

    let entries = std::fs::read_dir("/proc").ok()?;

    for entry in entries.flatten() {
        let pid: i32 = match entry.file_name().to_string_lossy().parse::<i32>() {
            Ok(p) if p > 0 => p,
            _ => continue,
        };

        // 1) /proc/<pid>/comm
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(mut f) = File::open(&comm_path) {
            let mut s = String::new();
            if f.read_to_string(&mut s).is_ok() {
                let name = s.trim();
                if name == target || name == target_base {
                    vlog!("[pid] match via comm: pid={} name='{}'", pid, name);
                    return Some(pid);
                }
            }
        }

        // 2) /proc/<pid>/cmdline
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(mut file) = File::open(&cmdline_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                if let Some(first) = contents.split('\0').next() {
                    let first_base = Path::new(first)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(first);
                    if first == target || first_base == target_base {
                        vlog!(
                            "[pid] match via cmdline: pid={} argv0='{}' base='{}'",
                            pid,
                            first,
                            first_base
                        );
                        return Some(pid);
                    }
                }
            }
        }
    }

    vlog!("[pid] no matching process found for '{}'", process_name);
    None
}

/// ---------- SELinux helpers ----------

pub fn is_selinux_enabled() -> bool {
    if let Ok(file) = File::open("/proc/filesystems") {
        for line in BufReader::new(file).lines().flatten() {
            if line.contains("selinuxfs") {
                vlog!("[selinux] selinuxfs present");
                return true;
            }
        }
    }
    vlog!("[selinux] not present");
    false
}

pub fn disable_selinux() {
    if let Ok(file) = File::open("/proc/mounts") {
        for line in BufReader::new(file).lines().flatten() {
            if line.contains("selinuxfs") {
                if let Some(mount_point) = line.split_whitespace().nth(1) {
                    let path = format!("{}/enforce", mount_point);
                    vlog!("[selinux] trying to write '0' to {}", path);
                    if let Ok(mut f) = File::create(&path) {
                        if let Err(e) = f.write_all(b"0") {
                            vlog!("[selinux] write failed: {}", e);
                        }
                    }
                }
                break;
            }
        }
    }
}

/// ---------- Address helpers (public API uses u64 to match other modules) ----------

#[inline]
fn parse_hex_addr_to_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

fn dump_module_candidates_from_maps(pid: i32, module_name: &str) {
    let maps_path = format!("/proc/{}/maps", pid);

    if let Ok(file) = File::open(&maps_path) {
        eprintln!("[maps] candidates for pid={} module='{}':", pid, module_name);
        for line in BufReader::new(file).lines().flatten() {
            if line.contains(module_name) {
                eprintln!("  {}", line);
            }
        }
    } else {
        eprintln!("[maps] unable to open {}", maps_path);
    }
}

pub fn get_module_base_addr(pid: i32, module_name: &str) -> Option<u64> {
    let maps_path = format!("/proc/{}/maps", pid);

    let file = match File::open(&maps_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[maps] open failed: {} ({})", maps_path, e);
            return None;
        }
    };

    let reader = BufReader::new(file);
    vlog!("[maps] scanning {} for '{}'", maps_path, module_name);

    let mut first_match_line: Option<String> = None;

    for line in reader.lines().flatten() {
        // Example: 12c00000-12d00000 r-xp 00000000 fc:00 12345 /system/lib/libc.so
        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(r) => r, None => continue
        };
        let _perms = parts.next();
        let _offset = parts.next();
        let _dev = parts.next();
        let _inode = parts.next();
        let path = parts.next_back();

        let path_match = match path {
            Some(p) if !p.is_empty() => {
                p == module_name
                    || Path::new(p)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|bn| bn == module_name)
                        .unwrap_or(false)
                    || p.contains(module_name)
            }
            _ => false,
        };

        if path_match {
            if first_match_line.is_none() {
                first_match_line = Some(line.clone());
            }
            if let Some(base_str) = range.split('-').next() {
                if let Some(addr) = parse_hex_addr_to_u64(base_str) {
                    vlog!(
                        "[maps] chose base 0x{:x} from line:\n       {}",
                        addr,
                        line
                    );
                    return Some(addr);
                } else {
                    vlog!("[maps] failed to parse base '{}'", base_str);
                }
            }
        }
    }

    eprintln!(
        "[maps] no base found for pid={} module='{}'",
        pid, module_name
    );
    if let Some(line) = first_match_line {
        eprintln!("[maps] NOTE: saw at least one candidate but couldn't parse: {}", line);
    } else {
        dump_module_candidates_from_maps(pid, module_name);
    }
    None
}

pub fn get_remote_function_addr(remote_pid: i32, module_name: &str, local_addr: u64) -> Option<u64> {
    vlog!(
        "[resolve] remote_pid={} module='{}' local_addr=0x{:x}",
        remote_pid,
        module_name,
        local_addr
    );

    let local_base = match get_module_base_addr(process::id() as i32, module_name) {
        Some(b) => {
            vlog!("[resolve] local_base( '{}') = 0x{:x}", module_name, b);
            b
        }
        None => {
            eprintln!("[resolve] failed to find local base for module '{}'", module_name);
            return None;
        }
    };

    let remote_base = match get_module_base_addr(remote_pid, module_name) {
        Some(b) => {
            vlog!("[resolve] remote_base('{}') = 0x{:x}", module_name, b);
            b
        }
        None => {
            eprintln!(
                "[resolve] failed to find remote base for module '{}' in pid={}",
                module_name, remote_pid
            );
            return None;
        }
    };

    if local_addr < local_base {
        eprintln!(
            "[resolve] local_addr < local_base for '{}': 0x{:x} < 0x{:x}",
            module_name, local_addr, local_base
        );
        return None;
    }

    let offset = local_addr - local_base;
    let remote = remote_base + offset;

    vlog!(
        "[resolve] offset=0x{:x} => remote_addr=0x{:x} (remote_base=0x{:x})",
        offset,
        remote,
        remote_base
    );

    Some(remote)
}