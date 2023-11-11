#ifndef IATHOOK_HOOK_IATHOOK_IATHOOK_H_
#define IATHOOK_HOOK_IATHOOK_IATHOOK_H_

#include "ulti/everything.h"
#include "pestructure/pememory/pe64memory.h"
#include "teb/getfunction.h"

namespace hook
{
    class IatHook
    {
    private:
        std::shared_ptr<pe::Pe64Memory> pe_64_memory_;
    public:

        IatHook(int pid);
        IatHook(const std::string_view& process_name);

        ULONGLONG GetFunctionRvaOnIat(const std::string_view& dll_name, const std::string_view& function_name);
        
        std::shared_ptr<pe::Pe64Memory> GetPeMemory() const;

    protected:
        void SetPeMemory(const std::shared_ptr<pe::Pe64Memory>& pe_64_memory_);
    };
}

#endif