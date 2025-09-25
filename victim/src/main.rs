use std::process;
use std::thread;
use std::time::Duration;
use std::ffi::CString;

// Import C library functions
extern "C" {
    fn fopen(filename: *const std::os::raw::c_char, mode: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
    fn fread(ptr: *mut std::os::raw::c_void, size: usize, count: usize, stream: *mut std::os::raw::c_void) -> usize;
    fn fwrite(ptr: *const std::os::raw::c_void, size: usize, count: usize, stream: *mut std::os::raw::c_void) -> usize;
    fn fclose(stream: *mut std::os::raw::c_void) -> i32;
}

fn main() {
    let pid = process::id();
    println!("I hope nothing bad happens to me! My PID is: {}", pid);
    
    // Get the current executable path
    let exe_path = std::env::current_exe()
        .expect("Failed to get current executable path");
    
    println!("My executable is at: {:?}", exe_path);
    
    loop {
        // Check if our own executable file still exists using fopen/fread/fclose
        let path_cstr = CString::new(exe_path.to_string_lossy().as_bytes()).unwrap();
        let mode_cstr = CString::new("rb").unwrap();

        unsafe {
            let file = fopen(path_cstr.as_ptr(), mode_cstr.as_ptr());
            if !file.is_null() {
                println!("It looks like everything is ok - I can still find my own file!");
                // Try to read a small amount from the file
                let mut buffer = [0u8; 4];
                let bytes_read = fread(buffer.as_mut_ptr() as *mut std::os::raw::c_void, 1, 4, file);
                println!("Read {} bytes from file", bytes_read);

                fclose(file);
            } else {
                println!("I think something is getting weird - I can't find my own file!");
            }
        }
        
        // Sleep for 5 seconds
        thread::sleep(Duration::from_secs(5));
    }
}
