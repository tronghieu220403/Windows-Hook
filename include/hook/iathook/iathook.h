#ifndef IATHOOK_HOOK_IATHOOK_IATHOOK_H_
#define IATHOOK_HOOK_IATHOOK_IATHOOK_H_

#include "ulti/everything.h"
#include "pestructure/pememory/pememory.h"
#include "teb/getfunction.h"

namespace hook
{
    class IatHook
    {
    private:
        std::shared_ptr<pe::PeMemory> pe_memory_;
    public:

        IatHook(int pid);
        IatHook(const std::string_view& process_name);

        size_t GetVirutalAddressOfFunctionOnIat(const std::string_view& dll_name, const std::string_view& function_name);
        
        std::shared_ptr<pe::PeMemory> GetPeMemory() const;

    protected:
        void SetPeMemory(const std::shared_ptr<pe::PeMemory>& pe_64_memory_);
    };
}

#endif