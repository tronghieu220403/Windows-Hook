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

        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;

#ifdef _WIN64
        /* machine_mode:    */ auto machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
#elif _WIN32
        /* machine_mode:    */ auto machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
#endif

        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            /* machine_mode:    */ machine_mode,
            /* runtime_address: */ 0,
            /* buffer:          */ (PUCHAR)p_hooked_close_handle + offset,
            /* length:          */ 100,
            /* instruction:     */ &instruction
        ))) {
            offset += instruction.info.length;
            if (std::string(instruction.text) == "ret")
            {
                break;
            }
        }

        bytes_code_.resize(offset - 1);
        ::memcpy(bytes_code_.data(), p_hooked_close_handle, offset-1);
    }

    void Hook::SetHookingBytesCode(const std::vector<UCHAR> bytes_code)
    {
        bytes_code_ = bytes_code;
    }

    std::vector<UCHAR> Hook::GetHookingBytesCode() const
    {
        return bytes_code_;
    }

    void Hook::SetHookDllPath(const std::string_view& hook_dll_path)
    {
        hook_dll_path_ = hook_dll_path;
    }

    std::string Hook::GetHookDllPath() const
    {
        return hook_dll_path_;
    }

    bool Hook::LoadHookDllToTarget()
    {
        LPVOID mem_ptr = pe_memory_->ProcessMemory::MemoryAlloc(0x300, PAGE_READWRITE);
        std::vector<UCHAR> data(hook_dll_path_.begin(), hook_dll_path_.end());
        if (pe_memory_->ProcessMemory::WriteData(mem_ptr, data) == false)
        {
            return false;
        }
        process::ProcessControl pc(pe_memory_->GetName());
        if (pc.CreateThread((LPTHREAD_START_ROUTINE)&LoadLibraryA, mem_ptr) == 0)
        {
            return false;
        }
        return true;
    }
    

    void Hook::SetPeMemory(const std::shared_ptr<pe::PeMemory> &pe_memory)
    {
        pe_memory_ = pe_memory;
    }
}
