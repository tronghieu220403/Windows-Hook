#ifndef USERMODEHOOK_HOOK_IATHOOK_IATHOOKCLOSEHANDLE_H_
#define USERMODEHOOK_HOOK_IATHOOK_IATHOOKCLOSEHANDLE_H_

#include "hook/iathook/iathook.h"

namespace hook
{
    class IatHookCloseHandle: public IatHook
    {
    private:
    public:

        IatHookCloseHandle(int pid);
        IatHookCloseHandle(const std::string_view& process_name);

        void SetDefaultBytesCode();
        
        void HookCloseHandle();
        static void HookedCloseHandleFunction(HANDLE h_object);

    };
}

#endif