#[cfg(target_os = "windows")]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input,
    LitStr,
};

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

// Parse .text section of provided executable to get shellcode and write it to the specified location on disk
// to embed via separate calls to include_bytes!
#[proc_macro]
pub fn extract_shellcode(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as LitStr);
    let string_to_hash = parsed.value();
    let hash = djb2_hash(string_to_hash.as_bytes());
    let hash_literal = Literal::u32_suffixed(hash);
}

// TODO macro to obfuscate/encrypt resources
