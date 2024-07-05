// Reference: https://github.com/stephenfewer/ReflectiveDLLInjection
// Taken and adapted from:
//      https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.h
//      https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveDLLInjection.h

#ifndef _REFLECTIVELOADER_H
#define _REFLECTIVELOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HMODULE (WINAPI * LOADLIBRARYA)( LPCSTR );
typedef FARPROC (WINAPI * GETPROCADDRESS)( HMODULE, LPCSTR );
typedef LPVOID  (WINAPI * VIRTUALALLOC)( LPVOID, SIZE_T, DWORD, DWORD );
typedef DWORD  (NTAPI * NTFLUSHINSTRUCTIONCACHE)( HANDLE, PVOID, ULONG );
typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

#define KERNEL32DLL_HASH                0x7040ee75
#define NTDLLDLL_HASH                   0x22d3b5ed

#define LOADLIBRARYA_HASH               0x5fbff0fb
#define GETPROCADDRESS_HASH             0xcf31bb1f
#define VIRTUALALLOC_HASH               0x382c0f97
#define NTFLUSHINSTRUCTIONCACHE_HASH    0x80183adf

#define IMAGE_REL_BASED_ARM_MOV32A      5
#define IMAGE_REL_BASED_ARM_MOV32T      7

#define ARM_MOV_MASK                    (DWORD)(0xFBF08000)
#define ARM_MOV_MASK2                   (DWORD)(0xFBF08F00)
#define ARM_MOVW                        0xF2400000
#define ARM_MOVT                        0xF2C00000

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

// Reference: http://www.cse.yorku.ca/~oz/hash.html
__forceinline unsigned long djb2_hash(char* input) {
    register unsigned long hash = 5381;
    int c;

    while ((c = *input++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

__forceinline unsigned long djb2_hash_case_insensitive_wide(wchar_t* input, size_t count) {
    register unsigned long hash = 5381;
    char* input_narrow = (char*)input;
    int c = *input_narrow;

    while (c && count > 0) {
        if (c <= 90 && c >= 65) {
            c += 32; // convert to lowercase.
        }
        hash = ((hash << 5) + hash) + c;
        count--;
        input_narrow += sizeof(wchar_t);
        c = *input_narrow;
    }
    return hash;
}

// https://learn.microsoft.com/es-es/windows/win32/api/ntdef/ns-ntdef-_unicode_string
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA { //, 7 elements, 0x28 bytes
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK { // 2 elements, 0x8 bytes
    struct _PEB_FREE_BLOCK * pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB { // 65 elements, 0x210 bytes
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct {
    WORD	offset:12;
    WORD	type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;

#endif
