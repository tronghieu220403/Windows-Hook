#ifndef IATHOOK_HOOK_IATHOOK_IATHOOK_H_
#define IATHOOK_HOOK_IATHOOK_IATHOOK_H_

#include "ulti/everything.h"
#include "process/processmemory.h"

namespace hook
{
    class IatHook
    {
    private:
        std::shared_ptr<process::ProcessMemory> process_memory_;
    public:

        IatHook(int pid);
        IatHook(const std::string_view& process_name);

        void HookFunction(const std::string_view& dll_name,
                            const std::string_view& function_name,
                            LPVOID old_function_address);
        
        std::shared_ptr<process::ProcessMemory> GetProcessMemory() const;

    protected:
        void SetProcessMemory(const std::shared_ptr<process::ProcessMemory>& process_memory);
    };
}

#endif