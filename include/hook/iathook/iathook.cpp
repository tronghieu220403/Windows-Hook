#include "iathook.h"

namespace hook
{
    IatHook::IatHook(int pid):
        process_memory_(std::make_shared<process::ProcessMemory>(pid))
    {

    }

    IatHook::IatHook(const std::string_view& process_name):
        process_memory_(std::make_shared<process::ProcessMemory>(process_name))
    {

    }

    void IatHook::HookFunction(const std::string_view &dll_name, const std::string_view &function_name, LPVOID old_function_address)
    {
        
    }
}
