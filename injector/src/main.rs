mod injector;
mod utils;
mod ptrace;

use injector::inject_library;
use utils::{disable_selinux, get_pid, is_selinux_enabled};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} [process name, full path] [library path]", args[0]);
        std::process::exit(1);
    }

    let process_name = &args[1];
    let library_path = &args[2];

    if let Some(pid) = get_pid(process_name) {
        #[cfg(debug_assertions)]
        println!("process name: {}, library path: {}, pid: {}", process_name, library_path, pid);

        if is_selinux_enabled() {
            disable_selinux();
        }

        let result = inject_library(pid, library_path);
        match result {
            Ok(0) => println!("Injection returned 0 (likely failed)..."),
            Ok(handle) => println!("Injection succeeded with handle: 0x{:x}", handle),
            Err(e) => eprintln!("Injection failed: {}", e),
        }
        
    } else {
        eprintln!("Process not found: {}", process_name);
    }
}
