#ifndef USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOKCLOSEHANDLE_H_
#define USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOKCLOSEHANDLE_H_

#include "hook/inlinehook/inlinehook.h"

namespace hook
{
    #define CLOSE_HANDLE_N_PARAMS 1
    typedef HANDLE (WINAPI* pFunction)(
        size_t param1
        );

    class InlineHookCloseHandle: public InlineHook
    {
    private:
    public:

        InlineHookCloseHandle(int pid);
        InlineHookCloseHandle(const std::string_view& process_name);

        static void HookedCloseHandleFunction();

    };
}

#endif