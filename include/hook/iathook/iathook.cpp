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

    size_t IatHook::GetFunctionRvaOnIat(const std::string_view &dll_name, const std::string_view &function_name)
    {
        DWORD function_rva = pe_memory_->GetImportDirectoryTable()->GetRvaOfFunction(dll_name, function_name);
        if (function_rva == (DWORD)(-1))
        {
            return (size_t)(-1);
        }

        return pe_memory_->GetBaseAddress() + function_rva;
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
