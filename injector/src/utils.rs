use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::process;

pub fn get_pid(process_name: &str) -> Option<i32> {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return None,
    };

    for entry in entries.flatten() {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() {
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(mut file) = File::open(&cmdline_path) {
                let mut contents = String::new();
                if file.read_to_string(&mut contents).is_ok() {
                    let name = contents.split("\0").next().unwrap_or("");
                    if name == process_name {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
}

pub fn is_selinux_enabled() -> bool {
    if let Ok(file) = File::open("/proc/filesystems") {
        for line in BufReader::new(file).lines().flatten() {
            if line.contains("selinuxfs") {
                return true;
            }
        }
    }
    false
}

pub fn disable_selinux() {
    if let Ok(file) = File::open("/proc/mounts") {
        for line in BufReader::new(file).lines().flatten() {
            if line.contains("selinuxfs") {
                if let Some(mount_point) = line.split_whitespace().nth(1) {
                    let path = format!("{}/enforce", mount_point);
                    if let Ok(mut f) = File::create(&path) {
                        let _ = f.write_all(b"0");
                    }
                }
                break;
            }
        }
    }
}

pub fn get_module_base_addr(pid: i32, module_name: &str) -> Option<u64> {
    let maps_path = format!("/proc/{}/maps", pid);
    if let Ok(file) = File::open(maps_path) {
        for line in BufReader::new(file).lines().flatten() {
            if line.contains(module_name) {
                if let Some(base_str) = line.split('-').next() {
                    return u64::from_str_radix(base_str, 16).ok();
                }
            }
        }
    }
    None
}

pub fn get_remote_function_addr(remote_pid: i32, module_name: &str, local_addr: u64) -> Option<u64> {
  let local_base = get_module_base_addr(process::id() as i32, module_name)?;
  let remote_base = get_module_base_addr(remote_pid, module_name)?;

  if local_addr < local_base {
      #[cfg(debug_assertions)]
      eprintln!(
          "[warn] local_addr < local_base for module {}: {:x} < {:x}",
          module_name, local_addr, local_base
      );
      return None;
  }

  let offset = local_addr - local_base;
  Some(remote_base + offset)
}
