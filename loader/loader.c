// Reference: https://github.com/stephenfewer/ReflectiveDLLInjection
// Taken and adapted from:
//      https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
// Additional references:
//      https://void-stack.github.io/blog/post-Exploring-PEB/

#include "loader.h"

#pragma intrinsic( _ReturnAddress )

// Original author's note:
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)_ReturnAddress(); }

__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpParameter ) {
    // Function pointers
    LOADLIBRARYA pLoadLibraryA     = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc     = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    USHORT usCounter;
    USHORT nameLenCounter;

    // Initial location of DLL to inject in memoory
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)lpParameter;

    // process environment block pointers
    ULONG_PTR pebAddress;

    ULONG_PTR pPebLdrData;

    // variables for processing the kernel's export table
    ULONG_PTR uiAddressArray;
    ULONG_PTR uiNameArray;
    ULONG_PTR uiExportDir;
    ULONG_PTR uiNameOrdinals;
    DWORD dwHashValue;

    // variables for loading the target image
    ULONG_PTR uiHeaderValue;
    PLDR_DATA_TABLE_ENTRY pebModuleEntry;
    ULONG_PTR pebModuleName;
    ULONG_PTR pebModuleNameHash;
    ULONG_PTR uiValueD;
    ULONG_PTR uiValueE;


    // Process the kernel's exports for required loader functions

    // Access the PEB
    #ifdef WIN_X64
    pebAddress = __readgsqword( 0x60 );
    #else
    #ifdef WIN_X86
    pebAddress = __readfsdword( 0x30 );
    #else WIN_ARM
    pebAddress = *(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
    #endif
    #endif

    // Get the loaded modules for the host process
    // References: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    pPebLdrData = (ULONG_PTR)((_PPEB)pebAddress)->pLdr;

    // Iterate through and process module entries in the PEB
    pebModuleEntry = (PLDR_DATA_TABLE_ENTRY)((PPEB_LDR_DATA)pPebLdrData)->InMemoryOrderModuleList.Flink;
    while (pebModuleEntry) {
        // get pointer to current module name (unicode string)
        pebModuleName = (ULONG_PTR)(pebModuleEntry)->BaseDllName.pBuffer;
        // Determine length for the loop
        nameLenCounter = pebModuleEntry->BaseDllName.Length;
        // will store the hash of the module name - clear for each entry
        pebModuleNameHash = 0;

        // Perform hash comparisons to check if we need to process this module
        // TODO
    }
}
}
