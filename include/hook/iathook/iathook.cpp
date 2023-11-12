#include "iathook.h"

namespace hook
{
    IatHook::IatHook(int pid):
        pe_memory_(std::make_shared<pe::PeMemory>(pid))
    {

    }

    IatHook::IatHook(const std::string_view& process_name):
        pe_memory_(std::make_shared<pe::PeMemory>(process_name))
    {

    }

    size_t IatHook::GetVirutalAddressOfFunctionOnIat(const std::string_view &dll_name, const std::string_view &function_name)
    {
        DWORD function_rva = pe_memory_->PeMemory::GetImportDirectoryTable()->ImportDirectoryTable::GetRvaOfFunction(dll_name, function_name);
        if (function_rva == 0)
        {
            return 0;
        }

        return pe_memory_->ProcessInfo::GetBaseAddress() + function_rva;
    }


    std::shared_ptr<pe::PeMemory> IatHook::GetPeMemory() const
    {
        return pe_memory_;
    }

    void IatHook::SetPeMemory(const std::shared_ptr<pe::PeMemory> &pe_memory)
    {
        pe_memory_ = pe_memory;
    }
}
