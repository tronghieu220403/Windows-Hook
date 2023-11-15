#ifndef USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOKCLOSEHANDLE_H_
#define USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOKCLOSEHANDLE_H_

#include "hook/inlinehook/inlinehook.h"

namespace hook
{
    class InlineHookCloseHandle: public InlineHook
    {
    private:
    public:

        InlineHookCloseHandle(int pid);
        InlineHookCloseHandle(const std::string_view& process_name);

        void SetDefaultBytesCode();
        
        void HookCloseHandle();
        static void HookedCloseHandleFunction(HANDLE h_object);

    };
}

#endif