# Teucro Reflective DLL Injection (WIP)
Reflective DLL injection proof of concept derived from [Stephen Fewer's Reflective DLL Injection technique](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master).
Most of the heavy lifting is taken from Stephen's repository, though the approach I took is slightly different:
- The loader shellcode (written in C) is separate from the injected DLL, to allow for more flexibility when loading pre-made DLLs
- The injector (written in Rust) will take the compiled loader binary, extract the `.text` section to get the position-independent shellcode,
  and will write it to the target process memory.
- The injector will encrypt and embed the target DLL at compile-time using Rust macros (specific to this proof-of-concept. Of course, you could expand this functionality
  to have the injector pull the DLL from a C2 server or an encrypted file on disk)
- The injector will write the encrypted DLL to the target process memory
- The injector will spawn a remote thread in the target process to execute the loader shellcode, passing in the base address of the target process' allocated memory region containing the
  encrypted DLL
- The loader shellcode will use the host process' PEB to resolve required Kernel32 imports for loading the DLL, decrypt the DLL in the host process memory, and reflectively load
  the DLL.

## Build

Will build shellcode and both debug and release Rust components
```PowerShell
nmake
```

To clean up artifacts except Rust 3rd party dependencies
```PowerShell
nmake clean
```

If you want to clean up Rust 3rd party dependencies (this will cause the next build to be noticeably longer):
```PowerShell
cargo clean
```

## Roadmap
- [x] Shellcode stub that will parse PEB and grab required APIs
- [x] Create basic Rust shellcode injector that grabs loader shellcode and DLL to inject at build time
- [x] Test shellcode stub and have it load a dummy DLL
- [ ] Remaining shellcode functionality - load DLL in memory
- [ ] Handle TLS callbacks
- [ ] Have Rust shellcode injector encrypt DLL prior to injection and have shellcode decrypt prior to loading in memory
- [ ] Extra shellcode defense evasion - Hell's Gate for direct syscalls in loader shellcode
- [ ] Extra injector defense evasion - Hell's Gate for direct syscalls in Rust injector

## References:
- [Stephen Fewer's Reflective DLL Injection technique](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master)
- [Executing Position Independent Shellcode from Object Files in Memory](https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/)
- [Analysing the Process Environment Block](https://void-stack.github.io/blog/post-Exploring-PEB/)
- [Writing your own RDI /sRDI loader using C and ASM](https://blog.malicious.group/writing-your-own-rdi-srdi-loader-using-c-and-asm/)
