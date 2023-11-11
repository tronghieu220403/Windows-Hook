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

    ULONGLONG IatHook::GetFunctionRvaOnIat(const std::string_view &dll_name, const std::string_view &function_name)
    {
        DWORD function_rva = pe_64_memory_->GetImportDirectoryTable()->GetRvaOfFunction(dll_name, function_name);
        if (function_rva == (DWORD)(-1))
        {
            return (ULONGLONG)(-1);
        }

        return pe_64_memory_->GetBaseAddress() + function_rva;
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
