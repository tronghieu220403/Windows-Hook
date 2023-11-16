#include "hook.h"

namespace hook
{
    Hook::Hook(int pid):
        pe_memory_(std::make_shared<pe::PeMemory>(pid))
    {

    }

    Hook::Hook(const std::string_view& process_name):
        pe_memory_(std::make_shared<pe::PeMemory>(process_name))
    {

    }

    size_t Hook::GetVirutalAddressOfFunctionOnIat(const std::string_view &dll_name, const std::string_view &function_name)
    {
        DWORD function_rva = pe_memory_->PeMemory::GetImportDirectoryTable()->ImportDirectoryTable::GetRvaOfFunction(dll_name, function_name);
        if (function_rva == 0)
        {
            return 0;
        }

        return pe_memory_->ProcessInfo::GetBaseAddress() + function_rva;
    }


    std::shared_ptr<pe::PeMemory> Hook::GetPeMemory() const
    {
        return pe_memory_;
    }

    void Hook::SetHookingBytesCode(PVOID function_address)
    {
        #ifdef _DEBUG
            PUCHAR p_hooked_close_handle = (PUCHAR)function_address + 5 + *(DWORD *)((size_t)function_address + 1);
        #else
            PUCHAR p_hooked_close_handle = (PUCHAR)function_address;
        #endif // DEBUG

        size_t end_addr = 0;
        size_t i = 0;

        // Get bytes code of "static void HookedCloseHandle(HANDLE h_object)";
        // Find HookedCloseHandle function ulti we find 5x C3 (pop something; ret)

        for (;;i++)
        {
            if (((*(char*)(p_hooked_close_handle + i + 1) & 0xff) == 0xc3 && (*(char*)(p_hooked_close_handle + i) & 0xf0) == 0x50))
            {
                end_addr = i + 2;
                break;
            }
        }

        bytes_code_.resize(end_addr);
        ::memcpy(bytes_code_.data(), p_hooked_close_handle, end_addr);
    }

    void Hook::SetHookingBytesCode(const std::vector<UCHAR> bytes_code)
    {
        bytes_code_ = bytes_code;
    }

    std::vector<UCHAR> Hook::GetHookingBytesCode() const
    {
        return bytes_code_;
    }

    void Hook::SetPeMemory(const std::shared_ptr<pe::PeMemory> &pe_memory)
    {
        pe_memory_ = pe_memory;
    }
}
