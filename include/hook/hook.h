#ifndef USERMODEHOOK_HOOK_HOOK_H_
#define USERMODEHOOK_HOOK_HOOK_H_

#include "ulti/everything.h"
#include "pestructure/pememory/pememory.h"
#include "teb/getfunction.h"
#include "Zydis/Zydis.h"

namespace hook
{
    class Hook
    {
    private:
        std::shared_ptr<pe::PeMemory> pe_memory_;
        std::vector<UCHAR> bytes_code_;
    public:

        Hook(int pid);
        Hook(const std::string_view& process_name);

        size_t GetVirutalAddressOfFunctionOnIat(const std::string_view& dll_name, const std::string_view& function_name);
        
        std::shared_ptr<pe::PeMemory> GetPeMemory() const;

        void SetHookingBytesCode(const PVOID function_address);
        void SetHookingBytesCode(const std::vector<UCHAR> bytes_code);
        std::vector<UCHAR> GetHookingBytesCode() const;

    protected:
        void SetPeMemory(const std::shared_ptr<pe::PeMemory>& pe_64_memory_);
    };
}

#endif