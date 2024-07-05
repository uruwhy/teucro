#[cfg(target_os = "windows")]

use std::io::prelude::*;
use std::fs::File;
use std::ffi::CStr;
use proc_macro::TokenStream;
use syn::{
    parse_macro_input,
    LitStr,
    Token,
    parse::{Parse, ParseStream},
};
use quote::quote;
use windows::Win32::{
    System::{
        SystemServices::{
            IMAGE_DOS_HEADER,
            IMAGE_DOS_SIGNATURE,
            IMAGE_NT_SIGNATURE,
            IMAGE_EXPORT_DIRECTORY,
        },
        Diagnostics::Debug::{
            IMAGE_NT_HEADERS64,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            IMAGE_SECTION_HEADER,
            IMAGE_FILE_DLL,
            IMAGE_DIRECTORY_ENTRY_EXPORT,
        },
    },
};

macro_rules! ptr_from_offset {
    ($rva:expr, $base_addr:expr, $t:ty) => {
        ($base_addr + ($rva as isize)) as *const $t
    };
}

// extract_shellcode!("path to DLL", "shellcode dest path")
struct ExtractShellcodeMacroInput {
    dll_path: LitStr,
    _comma: Token![,],
    shellcode_dest_path: LitStr,
    _comma2: Token![,],
    export_func: LitStr
}

impl Parse for ExtractShellcodeMacroInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            dll_path: input.parse()?,
            _comma: input.parse()?,
            shellcode_dest_path: input.parse()?,
            _comma2: input.parse()?,
            export_func: input.parse()?
        })
    }
}

unsafe fn extract_text_section_and_get_export_offset(dll_path: &str, dest_path: &str, export: &str) -> u32 {
    println!("Extracting text section from DLL: {}", dll_path);
    let file_data: Vec<u8> = std::fs::read(dll_path).unwrap();

    // Parse DLL to access .text section
    let library_base_ptr: *const u8 = file_data.as_ptr();
    let library_base_addr_val: isize = library_base_ptr as isize;

    // Verify DOS header
    let dos_header_ptr: *const IMAGE_DOS_HEADER = library_base_ptr as *const IMAGE_DOS_HEADER;
    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Invalid DOS header - magic number mismatch.");
    }

    // Verify NT headers
    let nt_headers_ptr: *const IMAGE_NT_HEADERS64 = ptr_from_offset!((*dos_header_ptr).e_lfanew, library_base_addr_val, IMAGE_NT_HEADERS64);
    if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
        panic!("Invalid NT headers - IMAGE_NT_SIGNATURE mismatch.");
    } else if (*nt_headers_ptr).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        panic!("Only 64-bit binaries supported.");
    }

    // Verify module is a DLL
    if (*nt_headers_ptr).FileHeader.Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL {
        panic!("Module is not a DLL.");
    }

    println!("Validated DOS and NT headers");

    // Check that module has exports
    let export_dir_rva: u32 = (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].VirtualAddress;
    let export_dir_size: u32 = (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].Size;
    if export_dir_rva == 0 {
        panic!("Could not find module's export directory: Null RVA.");
    }
    if export_dir_size == 0 {
        panic!("Could not find module's export directory: export size of 0.");
    }

    // Iterate over sections to find .text section and which section contains the export dir
    // Section table begins at end of NT headers
    let section_table: *const IMAGE_SECTION_HEADER = ptr_from_offset!(
        (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader,
        core::ptr::addr_of!((*nt_headers_ptr).OptionalHeader) as isize,
        IMAGE_SECTION_HEADER
    );

    println!("Searching for .text section and export dir section");
    let target_section_name: &[u8] = b".text\0\0\0"; // pad to 8 bytes for slice comparison
    let mut extracted: bool = false;
    let mut found_export_section: bool = false;
    let mut export_dir_offset: u32 = 0;
    let mut export_section_raw_offset: u32 = 0;
    let mut export_section_rva: u32 = 0;
    let mut text_section_raw_offset: u32 = 0;
    let mut text_section_rva: u32 = 0;
    let mut text_section_size: u32 = 0;
    for i in 0..(*nt_headers_ptr).FileHeader.NumberOfSections {
        let curr_section: *const IMAGE_SECTION_HEADER = section_table.add(i as usize);
        if (*curr_section).Name == target_section_name {
            // Write text section to output file
            let data_start_ptr: *const u8 = ptr_from_offset!((*curr_section).PointerToRawData, library_base_addr_val, u8);
            text_section_size = (*curr_section).Misc.VirtualSize;
            let data: &[u8] = std::slice::from_raw_parts(data_start_ptr, text_section_size as usize);
            text_section_raw_offset = (*curr_section).PointerToRawData;
            text_section_rva = (*curr_section).VirtualAddress;
            println!("Found .text section starting at raw offset 0x{:x} and RVA 0x{:x} (0x{:x} bytes)", text_section_raw_offset, text_section_rva, text_section_size);

            let mut dest_file = File::create(dest_path).unwrap();
            dest_file.write_all(data).unwrap();
            println!("Wrote .text section to dest file {}", dest_path);

            extracted = true;
        }
        if (*curr_section).VirtualAddress <= export_dir_rva && export_dir_rva + export_dir_size <= (*curr_section).VirtualAddress + (*curr_section).Misc.VirtualSize {
            let section_name = std::str::from_utf8(&(*curr_section).Name).unwrap();
            println!("Section {} contains export directory.", section_name);

            // Reference: https://stackoverflow.com/a/10138719
            export_section_raw_offset = (*curr_section).PointerToRawData;
            export_section_rva = (*curr_section).VirtualAddress;
            export_dir_offset = export_dir_rva + export_section_raw_offset - export_section_rva;
            println!("Export dir offset: 0x{:x}", export_dir_offset);
            found_export_section = true;
        }
        if extracted && found_export_section {
            break;
        }
    }

    if !extracted {
        panic!("Failed to find and extract .text section.");
    }

    if !found_export_section {
        panic!("Failed to find export directory.");
    }

    // Get address for desired export
    println!("Grabbing address for exported function {}", export);

    // Access export directory
    let export_dir_ptr: *const IMAGE_EXPORT_DIRECTORY = ptr_from_offset!(export_dir_offset, library_base_addr_val, IMAGE_EXPORT_DIRECTORY);

    println!("Export directory info:");
    println!("Base:                  {:#010x}", (*export_dir_ptr).Base);
    println!("NumberOfFunctions:     {:#010x}", (*export_dir_ptr).NumberOfFunctions);
    println!("NumberOfNames:         {:#010x}", (*export_dir_ptr).NumberOfNames);
    println!("AddressOfFunctions:    {:#010x}", (*export_dir_ptr).AddressOfFunctions);
    println!("AddressOfNames:        {:#010x}", (*export_dir_ptr).AddressOfNames);
    println!("AddressOfNameOrdinals: {:#010x}", (*export_dir_ptr).AddressOfNameOrdinals);

    // Get the exported functions, exported names, and name ordinals.
    let exported_func_list_ptr: *const u32 = ptr_from_offset!(
        (*export_dir_ptr).AddressOfFunctions + export_section_raw_offset - export_section_rva,
        library_base_addr_val,
        u32
    );
    let exported_names_list_ptr: *const u32 = ptr_from_offset!(
        (*export_dir_ptr).AddressOfNames + export_section_raw_offset - export_section_rva,
        library_base_addr_val,
        u32
    );
    let exported_ordinals_list_ptr: *const u16 = ptr_from_offset!(
        (*export_dir_ptr).AddressOfNameOrdinals + export_section_raw_offset - export_section_rva,
        library_base_addr_val,
        u16
    );

    // Iterate through exported function names.
    // Note that we use NumberOfNames since we are only looking at functions
    // exported by name, not ordinal (NumberOfFunctions includes both)
    let num_names = (*export_dir_ptr).NumberOfNames;
    println!("Number of names: {}", num_names);

    for i in 0..num_names {
        // Get function name. Each entry of AddressOfNames is an RVA for the exported name
        let func_name_rva: u32 = *(exported_names_list_ptr.add(i as usize));
        let func_name_offset: u32 = func_name_rva + export_section_raw_offset - export_section_rva;

        let func_name_ptr: *const i8 = ptr_from_offset!(func_name_offset, library_base_addr_val, i8);
        let func_name_cstr = CStr::from_ptr(func_name_ptr);

        let func_name_str = match func_name_cstr.to_str() {
            Ok(s) => s,
            Err(e) => {
                panic!("Failed to convert export name C-string to rust string: {}", e);
            }
        };

        if func_name_str == export {
            // Use the ordinal to get the API address
            let ordinal: u16 = *(exported_ordinals_list_ptr.add(i as usize));
            let func_rva: u32 = *(exported_func_list_ptr.add(ordinal as usize));
            let func_raw_offset: u32 = func_rva + text_section_raw_offset - text_section_rva;
            let func_offset_from_text: u32 = func_raw_offset - text_section_raw_offset;

            if func_rva < text_section_rva || func_rva >= text_section_rva + text_section_size {
                panic!("Target export {} is outside of the .text section (RVA 0x{:x}). Cannot process further.", func_name_str, func_rva);
            }

            println!("Found target export {} with raw offset 0x{:x} and RVA 0x{:x}", func_name_str, func_raw_offset, func_rva);
            println!("Target export raw offset from .text section is 0x{:x}", func_offset_from_text);

            // Check if the address is a forwarder, meaning it's within the export directory
            if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                panic!("Export API is a forwarder - not supported.");
            } else {
                return func_offset_from_text;
            }
        }
    }

    panic!("Failed to find export.");
}


// Parse .text section of provided executable to get shellcode and write it to the specified location on disk
// to embed via separate calls to include_bytes! or obfuscation macro.
// Sets return token to the specified exported function offset from the beginning of the .text section as u32.
#[proc_macro]
pub fn extract_shellcode_and_get_export_offset(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as ExtractShellcodeMacroInput);
    let dll_path = String::from((&parsed.dll_path).value());
    let dest_path = String::from((&parsed.shellcode_dest_path).value());
    let export_func = String::from((&parsed.export_func).value());
    let export_offset: u32 = unsafe { extract_text_section_and_get_export_offset(&dll_path, &dest_path, &export_func) };

    quote! {
        #export_offset as u32
    }.into()
}

// TODO macro to obfuscate/encrypt resources
