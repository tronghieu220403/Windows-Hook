#include "iathook.h"

namespace hook
{
    IatHook::IatHook(int pid):
        pe_64_memory_(std::make_shared<pe::Pe64Memory>(pid))
    {

    }

    IatHook::IatHook(const std::string_view& process_name):
        pe_64_memory_(std::make_shared<pe::Pe64Memory>(process_name))
    {

    }

    ULONGLONG IatHook::GetFunctionAddressOnIat(const std::string_view &dll_name, const std::string_view &function_name)
    {
        DWORD function_rva = pe_64_memory_->GetImportDirectoryTable()->GetRvaOfFunction(dll_name, function_name);
        if (function_rva == (DWORD)(-1))
        {
            return;
        }
        ULONGLONG fucntion_va = pe_64_memory_->GetBaseAddress() + function_rva;

        return fucntion_va;
    }

    void IatHook::HookCloseHandle()
    {
        ULONGLONG address = ulti::MemoryToUint64(pe_64_memory_->ReadData(GetFunctionAddressOnIat("kernel32.dll", "CloseHandle"), 8).data());

        // Get bytes code of "static void HookedCloseHandle(HANDLE h_object)";

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.

        // Push the bytes code of HookedCloseHandle into that allocated memory.

        // Make the call to that allocated memory in target.

        return;
    }

    void IatHook::HookedCloseHandle(HANDLE h_object)
    {
        FuncAddr iat;
        GetFunctionAddressesFromTeb(&iat);

        // do something

        iat.fnCloseHandle(h_object);
        return;
    }

    std::shared_ptr<pe::Pe64Memory> IatHook::GetPeMemory() const
    {
        return pe_64_memory_;
    }

    void IatHook::SetPeMemory(const std::shared_ptr<pe::Pe64Memory> &pe_64_memory)
    {
        pe_64_memory_ = pe_64_memory;
    }
}
