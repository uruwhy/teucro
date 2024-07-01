#[cfg(target_os = "windows")]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input,
    LitStr,
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

fn unsafe extract_text_section(binary_path: &str, dest_path: &str) {
    println!("Extracting text section from binary: {}", binary_path);
    let file_data: Vec<u8> = std::fs::read(binary_path).unwrap();

    // Parse binary to access .text section
    let binary_base_ptr: *const u8 = file_data.as_ptr();

    // Verify DOS header
    let dos_header_ptr: *const IMAGE_DOS_HEADER = binary_base_ptr as *const IMAGE_DOS_HEADER;
    if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Invalid DOS header - magic number mismatch.");
    }

    // Verify NT headers
    let nt_headers_ptr: *const IMAGE_NT_HEADERS64 = ptr_from_rva!((*dos_header_ptr).e_lfanew, binary_base_ptr, IMAGE_NT_HEADERS64);
    if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
        panic!("Invalid NT headers - IMAGE_NT_SIGNATURE mismatch.");
    } else if (*nt_headers_ptr).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        panic!("Only 64-bit binaries supported.");
    }

    // Iterate over sections to find .text section
    // Section table begins at end of NT headers
    let section_table: *const IMAGE_SECTION_HEADER = ptr_from_rva!(
        (*nt_headers_ptr).FileHeader.SizeOfOptionalHeader,
        core::ptr::addr_of!((*nt_headers_ptr).OptionalHeader),
        IMAGE_SECTION_HEADER,
    );

    let section_index: u16 = 0;


}


// Parse .text section of provided executable to get shellcode and write it to the specified location on disk
// to embed via separate calls to include_bytes!
#[proc_macro]
pub fn extract_shellcode(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as ExtractShellcodeMacroInput);
    let binary_path = String::from((&parsed.binary_path).value());
    let dest_path = String::from((&parsed.shellcode_dest_path).value());


}

// TODO macro to obfuscate/encrypt resources
