#ifndef IATHOOK_HOOK_IATHOOK_IATHOOK_H_
#define IATHOOK_HOOK_IATHOOK_IATHOOK_H_

#include "ulti/everything.h"
#include "pememory/pe64memory.h"
#include "teb/getfunction.h"

namespace hook
{
    typedef void (WINAPI *pCloseHandle) (
        _In_ HANDLE hObject
    );

    class IatHook
    {
    private:
        std::shared_ptr<pe::Pe64Memory> pe_64_memory_;
    public:

        IatHook(int pid);
        IatHook(const std::string_view& process_name);

        ULONGLONG GetFunctionAddressOnIat(const std::string_view& dll_name, const std::string_view& function_name);
        
        void HookCloseHandle();
        static void HookedCloseHandle(HANDLE h_object);

        std::shared_ptr<pe::Pe64Memory> GetPeMemory() const;

    protected:
        void SetPeMemory(const std::shared_ptr<pe::Pe64Memory>& pe_64_memory_);
    };
}

#endif