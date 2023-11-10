#ifndef IATHOOK_TEB_GETFUNCTION_H_
#define IATHOOK_TEB_GETFUNCTION_H_

#include "teb/function.h"

inline void GetFunctionAddressesFromTeb(const PFuncAddr data)
{
    PPEB p_peb = NtCurrentPeb();

    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)(p_peb->Ldr);

    ldr = CONTAINING_RECORD(p_peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // Read the loader data

    PVOID kernel32_base = NULL;

    while (ldr != 0)
    {
        wchar_t* dll_name = (wchar_t*)(((UNICODE_STRING*)((unsigned long long)(ldr) + sizeof(PVOID) * 11))->Buffer);

        if (dll_name == NULL) break;
        //wcout << dll_name << endl;
        wchar_t c;
        DWORD hash = 0;
        for (int i = 0; i < 13; i++)
        {
            c = dll_name[i];
            if (L'A' <= c && c <= L'Z')
            {
                c = c - L'A' + L'a';
            }
            hash = (hash * 26 + c) % (DWORD)(1e9 + 7);
        }
        if (hash == 448935215) // hash of L"kernel32.dll"
        {
            kernel32_base = ldr->DllBase; // Store the address of kernel32
            break;
        }

        ldr = CONTAINING_RECORD(ldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    }

    PIMAGE_DOS_HEADER p_image_dos_header = (PIMAGE_DOS_HEADER)kernel32_base;
    PIMAGE_NT_HEADERS p_image_nt_headers = (PIMAGE_NT_HEADERS)((PUCHAR)kernel32_base + p_image_dos_header->e_lfanew);

    // Get the export directory of kernel32
    PIMAGE_EXPORT_DIRECTORY p_image_export_directory;

    p_image_export_directory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)kernel32_base + p_image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG function_table = (PULONG)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfFunctions);

    PULONG name = (PULONG)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfNames);

    PUSHORT ordinal = (PUSHORT)((PUCHAR)kernel32_base + p_image_export_directory->AddressOfNameOrdinals);

    for (unsigned int i = 0; i < p_image_export_directory->NumberOfNames; i++)
    {
        PUCHAR ptr = (PUCHAR)kernel32_base + name[i]; // Pointer to function name
        DWORD hash = 0;

        // Compute the hash
        while (*ptr)
        {
            hash = (hash * 26 + *ptr) % (DWORD)(1e9 + 7);
            ptr++;
        }
        hash = (hash * 26 + 0) % (DWORD)(1e9 + 7);

        // Hash of LoadLibraryExA
        if (hash == 0x1ad4f305)
        {
            data->fnLoadLibraryExA = (pLoadLibraryExA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetProcAddress
        if (hash == 0xd38cd23)
        {
            data->fnGetProcAddress = (pGetProcAddress)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindFirstFileA
        if (hash == 0x10b03781)
        {
            data->fnFindFirstFileA = (pFindFirstFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindNextFileA
        if (hash == 0x4d01d59)
        {
            data->fnFindNextFileA = (pFindNextFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FindClose
        if (hash == 0x309c47e0)
        {
            data->fnFindClose = (pFindClose)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateFileA
        if (hash == 0xc75869c)
        {
            data->fnCreateFileA = (pCreateFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetFileSize
        if (hash == 0x236f23d6)
        {
            data->fnGetFileSize = (pGetFileSize)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of ReadFile
        if (hash == 0xc9a21e1)
        {
            data->fnReadFile = (pReadFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of WriteFile
        if (hash == 0x5ce6ec2)
        {
            data->fnWriteFile = (pWriteFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CloseHandle
        if (hash == 0x158bec59)
        {
            data->fnCloseHandle = (pCloseHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of VirtualAlloc
        if (hash == 0x22b92187)
        {
            data->fnVirtualAlloc = (pVirtualAlloc)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of VirtualFree
        if (hash == 0x25e4c2e3)
        {
            data->fnVirtualFree = (pVirtualFree)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateFileMappingA
        if (hash == 0x2da1e929)
        {
            data->fnCreateFileMappingA = (pCreateFileMappingA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of MapViewOfFile
        if (hash == 0x3a2ef895)
        {
            data->fnMapViewOfFile = (pMapViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of FlushViewOfFile
        if (hash == 0x29b0e5d7)
        {
            data->fnFlushViewOfFile = (pFlushViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of UnmapViewOfFile
        if (hash == 0x12107238)
        {
            data->fnUnmapViewOfFile = (pUnmapViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetEnvironmentVariableA
        if (hash == 0x32b50861)
        {
            data->fnGetEnvironmentVariableA = (pGetEnvironmentVariableA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CloseHandle
        if (hash == 0x158bec59)
        {
            data->fnCloseHandle = (pCloseHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateThread
        if (hash == 0x4d89b8a)
        {
            data->fnCreateThread = (pCreateThread)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateMutexA
        if (hash == 0x46d6e46)
        {
            data->fnCreateMutexA = (pCreateMutexA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of CreateThread
        if (hash == 0x1965f2c6)
        {
            data->fnWaitForSingleObject = (pWaitForSingleObject)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of WriteConsoleA
        if (hash == 0x786a6cd)
        {
            data->fnWriteConsoleA = (pWriteConsoleA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

        // Hash of GetStdHandle
        if (hash == 0x34dcbbd3)
        {
            data->fnGetStdHandle = (pGetStdHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
        }

    }
}

#endif