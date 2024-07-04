use embed_resources::*;

fn main() {
    let func_addr = extract_shellcode_and_get_export_rva!("..\\loader\\loader.dll", "..\\loader\\loader.bin", "ReflectiveLoader");

    let shellcode = include_bytes!("../../loader/loader.bin");


    println!("Done");
}
