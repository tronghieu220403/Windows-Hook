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
        // Find HookedCloseHandle function ulti we find 48 81 C4 xx xx xx xx C3 (add rsp, xxxxxxxx; ret)
        // The xx xx xx xx can be found in 48 81 EC xx xx xx xx (sub rsp, xxxxxxxx)
        PUCHAR p_hooked_close_handle = (PUCHAR)&IatHookCloseHandle::HookedCloseHandleFunction;
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
            if ( (ulti::MemoryToInt32(p_hooked_close_handle + i) & 0x00ffffff) == (DWORD)0x00c48148 && 
                    (ulti::MemoryToInt32(p_hooked_close_handle + i + 4) & 0xff000000) == (DWORD)0xc3000000 &&
                        ulti::MemoryToInt32(p_hooked_close_handle + i + 3) == stack_reserve)
            {
                end_addr = i + 8;
                break;
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
        GetFunctionAddressesFromTeb(&iat);

        iat.fnWriteConsoleA(iat.fnGetStdHandle(STD_OUTPUT_HANDLE), c, 3, &bytes_written, NULL);

        // do something

        iat.fnCloseHandle(h_object);
        return;
    }

}