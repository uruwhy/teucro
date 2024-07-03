use embed_resources::*;

fn main() {
    extract_shellcode!("C:\\Windows\\System32\\notepad.exe", "C:\\Users\\Public\\notepadtest.bin");

    println!("Done");
}
