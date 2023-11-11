#include "iathookclosehandle.h"

namespace hook
{
    IatHookCloseHandle::IatHookCloseHandle(int pid):
        IatHook(pid)
    {
        SetDefaultBytesCode();
    }

    IatHookCloseHandle::IatHookCloseHandle(const std::string_view &process_name):
        IatHook(process_name)
    {
        SetDefaultBytesCode();
    }

    void IatHookCloseHandle::SetBytesCode(const std::vector<UCHAR> bytes_code)
    {
        bytes_code_ = bytes_code;
    }

    std::vector<UCHAR> IatHookCloseHandle::GetBytesCode() const
    {
        return bytes_code_;
    }

    void IatHookCloseHandle::SetDefaultBytesCode()
    {
        // Get bytes code of "static void HookedCloseHandle(HANDLE h_object)";
        // Find HookedCloseHandle function ulti we find 48 81 C4 xx xx xx xx C3 (add rsp, xxxxxxxx; ret) or 48 81 C4 xx xx xx xx 5B C3 (add rsp, xxxxxxxx; pop rbp; ret)
        // The xx xx xx xx can be found in 48 81 EC xx xx xx xx (sub rsp, xxxxxxxx)
        #ifdef _DEBUG
            PUCHAR p_hooked_close_handle = (PUCHAR)&IatHookCloseHandle::HookedCloseHandleFunction + 5 + *(DWORD *)((size_t) & IatHookCloseHandle::HookedCloseHandleFunction + 1);
        #else
            PUCHAR p_hooked_close_handle = (PUCHAR)&IatHookCloseHandle::HookedCloseHandleFunction;
        #endif // DEBUG

        size_t end_addr = 0;
        DWORD stack_reserve = (DWORD)(-1);
        size_t i = 0;

        for (i = 0; ; i++)
        {
            if ((ulti::MemoryToInt32(p_hooked_close_handle + i) & 0x00ffffff) == (DWORD)0x00ec8148)
            {
                stack_reserve = ulti::MemoryToInt32(p_hooked_close_handle + i + 3);
                break;
            }
        }

        for (;;i++)
        {
            if (((*(char*)(p_hooked_close_handle + i + 1) & 0xff) == 0xc3 && (*(char*)(p_hooked_close_handle + i) & 0xf0) == 0x50))
            {
                end_addr = i + 1;
                break;
            }
            if ((*(char*)(p_hooked_close_handle + i) & 0xff) == 0xc3)
            {
                end_addr = i;
                break;
            }
            if ( (ulti::MemoryToInt32(p_hooked_close_handle + i) & 0x00ffffff) == (DWORD)0x00c48148  &&
                        ulti::MemoryToInt32(p_hooked_close_handle + i + 3) == stack_reserve)
            {
                if (*(char *)(p_hooked_close_handle + i + 7) == 0xc3) // ret
                {
                    end_addr = i + 8;
                    break;
                }
                else if (*(char*)(p_hooked_close_handle + i + 8) == 0xc3 && *(char*)(p_hooked_close_handle + i + 7) == 0x5b)    // pop rbp ; ret
                {
                    end_addr = i + 9;
                    break;
                }
            }
        }

        bytes_code_.clear();
        bytes_code_.resize(i);
        memcpy(bytes_code_.data(), p_hooked_close_handle, i);
    }

    void IatHookCloseHandle::HookCloseHandle()
    {
        std::shared_ptr<pe::Pe64Memory> pe_64_memory = IatHook::GetPeMemory();

        LPVOID va_close_handle_iat = (void *)(pe_64_memory->GetBaseAddress() + GetFunctionRvaOnIat("kernel32.dll", "CloseHandle"));

        ULONGLONG address = ulti::MemoryToUint64(pe_64_memory->ReadData(va_close_handle_iat, 8).data());


        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_64_memory->MemoryAlloc(bytes_code_.size(), PAGE_EXECUTE_READWRITE);

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        pe_64_memory->WriteData(code_ptr, bytes_code_);

        // Replace the CloseHandle() address by code_ptr in va_close_handle_iat
        pe_64_memory->WriteData(va_close_handle_iat, (PUCHAR)&code_ptr, 8);
        return;
    }

    void IatHookCloseHandle::HookedCloseHandleFunction(HANDLE h_object)
    {
        FuncAddr iat;
        char c[5];
        c[0] = 'g';
        c[1] = 'g';
        c[2] = '\n';
        DWORD bytes_written = 0;
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
                iat.fnLoadLibraryExA = (pLoadLibraryExA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of GetProcAddress
            if (hash == 0xd38cd23)
            {
                iat.fnGetProcAddress = (pGetProcAddress)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of FindFirstFileA
            if (hash == 0x10b03781)
            {
                iat.fnFindFirstFileA = (pFindFirstFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of FindNextFileA
            if (hash == 0x4d01d59)
            {
                iat.fnFindNextFileA = (pFindNextFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of FindClose
            if (hash == 0x309c47e0)
            {
                iat.fnFindClose = (pFindClose)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CreateFileA
            if (hash == 0xc75869c)
            {
                iat.fnCreateFileA = (pCreateFileA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of GetFileSize
            if (hash == 0x236f23d6)
            {
                iat.fnGetFileSize = (pGetFileSize)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of ReadFile
            if (hash == 0xc9a21e1)
            {
                iat.fnReadFile = (pReadFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of WriteFile
            if (hash == 0x5ce6ec2)
            {
                iat.fnWriteFile = (pWriteFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CloseHandle
            if (hash == 0x158bec59)
            {
                iat.fnCloseHandle = (pCloseHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of VirtualAlloc
            if (hash == 0x22b92187)
            {
                iat.fnVirtualAlloc = (pVirtualAlloc)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of VirtualFree
            if (hash == 0x25e4c2e3)
            {
                iat.fnVirtualFree = (pVirtualFree)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CreateFileMappingA
            if (hash == 0x2da1e929)
            {
                iat.fnCreateFileMappingA = (pCreateFileMappingA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of MapViewOfFile
            if (hash == 0x3a2ef895)
            {
                iat.fnMapViewOfFile = (pMapViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of FlushViewOfFile
            if (hash == 0x29b0e5d7)
            {
                iat.fnFlushViewOfFile = (pFlushViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of UnmapViewOfFile
            if (hash == 0x12107238)
            {
                iat.fnUnmapViewOfFile = (pUnmapViewOfFile)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of GetEnvironmentVariableA
            if (hash == 0x32b50861)
            {
                iat.fnGetEnvironmentVariableA = (pGetEnvironmentVariableA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CloseHandle
            if (hash == 0x158bec59)
            {
                iat.fnCloseHandle = (pCloseHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CreateThread
            if (hash == 0x4d89b8a)
            {
                iat.fnCreateThread = (pCreateThread)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CreateMutexA
            if (hash == 0x46d6e46)
            {
                iat.fnCreateMutexA = (pCreateMutexA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of CreateThread
            if (hash == 0x1965f2c6)
            {
                iat.fnWaitForSingleObject = (pWaitForSingleObject)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of WriteConsoleA
            if (hash == 0x786a6cd)
            {
                iat.fnWriteConsoleA = (pWriteConsoleA)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

            // Hash of GetStdHandle
            if (hash == 0x34dcbbd3)
            {
                iat.fnGetStdHandle = (pGetStdHandle)((PUCHAR)kernel32_base + function_table[ordinal[i]]);
            }

        }

        iat.fnWriteConsoleA(iat.fnGetStdHandle(STD_OUTPUT_HANDLE), c, 3, &bytes_written, NULL);

        // do something

        iat.fnCloseHandle(h_object);
        return;
    }

}