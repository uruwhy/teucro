# Teucro Reflective DLL Injection
Reflective DLL injection proof of concept derived from [Stephen Fewer's Reflective DLL Injection technique](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master).
Most of the heavy lifting is taken from Stephen's repository, though the approach I took is slightly different:
- The loader shellcode (written in C) is separate from the injected DLL, to allow for more flexibility when loading pre-made DLLs
- The injector (written in Rust) will take the compiled loader binary, extract the `.text` section to get the position-independent shellcode,
  and will write it to the target process memory.
- The injector will encrypted and embed the target DLL at compile-time using Rust macros (specific to this proof-of-concept. Of course, you could expand this functionality
  to have the injector pull the DLL from a C2 server or an encrypted file on disk)
- The injector will write the encrypted DLL to the target process memory
- The injector will spawn a remote thread in the target process to execute the loader shellcode, passing in the base address of the target process' allocated memory region containing the
  encrypted DLL
- The loader shellcode will use the host process' PEB to resolve required Kernel32 imports for loading the DLL, decrypt the DLL in the host process memory, and reflectively load
  the DLL.

# References:
- [Stephen Fewer's Reflective DLL Injection technique](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master)
- [Analysing the Process Environment Block](https://void-stack.github.io/blog/post-Exploring-PEB/)
