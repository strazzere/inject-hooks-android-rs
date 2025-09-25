use std::fs;
use std::process;
use std::thread;
use std::time::Duration;

fn main() {
    let pid = process::id();
    println!("I hope nothing bad happens to me! My PID is: {}", pid);
    
    // Get the current executable path
    let exe_path = std::env::current_exe()
        .expect("Failed to get current executable path");
    
    println!("My executable is at: {:?}", exe_path);
    
    loop {
        // Check if our own executable file still exists
        match fs::metadata(&exe_path) {
            Ok(_) => {
                println!("It looks like everything is ok - I can still find my own file!");
            }
            Err(_) => {
                println!("I think something is getting weird - I can't find my own file!");
            }
        }
        
        // Sleep for 1 second
        thread::sleep(Duration::from_secs(5));
    }
}
