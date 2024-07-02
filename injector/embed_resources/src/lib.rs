#[cfg(target_os = "windows")]

use std::io::prelude::*;
use std::fs::File;
use proc_macro::TokenStream;
use syn::{
    parse_macro_input,
    LitStr,
    Token,
    parse::{Parse, ParseStream},
};
use windows::Win32::{
    System::{
        SystemServices::{
            IMAGE_DOS_HEADER,
            IMAGE_DOS_SIGNATURE,
            IMAGE_NT_SIGNATURE,
        },
        Diagnostics::Debug::{
            IMAGE_NT_HEADERS64,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            IMAGE_SECTION_HEADER,
        },
    },
};

macro_rules! ptr_from_rva {
    ($rva:expr, $base_addr:expr, $t:ty) => {
        ($base_addr + ($rva as isize)) as *const $t
    };
}

// extract_shellcode!("path to binary", "shellcode dest path")
struct ExtractShellcodeMacroInput {
    binary_path: LitStr,
    _comma: Token![,],
    shellcode_dest_path: LitStr
}

impl Parse for ExtractShellcodeMacroInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            binary_path: input.parse()?,
            _comma: input.parse()?,
            shellcode_dest_path: input.parse()?
        })
    }
}

unsafe fn extract_text_section(binary_path: &str, dest_path: &str) {
    println!("Extracting text section from binary: {}", binary_path);
    let file_data: Vec<u8> = std::fs::read(binary_path).unwrap();

    // Parse binary to access .text section
    let binary_base_ptr: *const u8 = file_data.as_ptr();
    let binary_base_addr_val: isize = binary_base_ptr as isize;

    // Verify DOS header
    let dos_header_ptr: *const IMAGE_DOS_HEADER = binary_base_ptr as *const IMAGE_DOS_HEADER;
    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Invalid DOS header - magic number mismatch.");
    }

    // Verify NT headers
    let nt_headers_ptr: *const IMAGE_NT_HEADERS64 = ptr_from_rva!((*dos_header_ptr).e_lfanew, binary_base_addr_val, IMAGE_NT_HEADERS64);
    if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
        panic!("Invalid NT headers - IMAGE_NT_SIGNATURE mismatch.");
    } else if (*nt_headers_ptr).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        panic!("Only 64-bit binaries supported.");
    }

    println!("Validated DOS and NT headers");

    // Iterate over sections to find .text section
    // Section table begins at end of NT headers
    let section_table: *const IMAGE_SECTION_HEADER = ptr_from_rva!(
        (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader,
        core::ptr::addr_of!((*nt_headers_ptr).OptionalHeader) as isize,
        IMAGE_SECTION_HEADER
    );

    println!("Searching for .text section");
    let target_section_name: &[u8] = b".text\0\0\0"; // pad to 8 bytes for slice comparison
    let mut extracted: bool = false;
    for i in 0..(*nt_headers_ptr).FileHeader.NumberOfSections {
        let curr_section: *const IMAGE_SECTION_HEADER = section_table.add(i as usize);
        if (*curr_section).Name == target_section_name {
            // Write text section to output file
            let data_start_ptr: *const u8 = ptr_from_rva!((*curr_section).PointerToRawData, binary_base_addr_val, u8);
            let data_size = (*curr_section).SizeOfRawData;
            let data: &[u8] = std::slice::from_raw_parts(data_start_ptr, data_size as usize);
            println!("Found .text section starting at RVA 0x{:x} ({} bytes)", (*curr_section).PointerToRawData, data_size);

            let mut dest_file = File::create(dest_path).unwrap();
            dest_file.write_all(data).unwrap();
            println!("Wrote .text section to dest file {}", dest_path);

            extracted = true;
            break;
        }
    }

    if !extracted {
        panic!("Failed to find and extract .text section.");
    }
}


// Parse .text section of provided executable to get shellcode and write it to the specified location on disk
// to embed via separate calls to include_bytes!
#[proc_macro]
pub fn extract_shellcode(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as ExtractShellcodeMacroInput);
    let binary_path = String::from((&parsed.binary_path).value());
    let dest_path = String::from((&parsed.shellcode_dest_path).value());
    unsafe { extract_text_section(&binary_path, &dest_path) };

    TokenStream::new()
}

// TODO macro to obfuscate/encrypt resources
