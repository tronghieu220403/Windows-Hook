#ifndef IATHOOK_HOOK_IATHOOK_IATHOOKCLOSEHANDLE_H_
#define IATHOOK_HOOK_IATHOOK_IATHOOKCLOSEHANDLE_H_

#include "hook/iathook/iathook.h"

namespace hook
{
    class IatHookCloseHandle: public IatHook
    {
    private:
        std::vector<UCHAR> bytes_code_;
    public:

        IatHookCloseHandle(int pid);
        IatHookCloseHandle(const std::string_view& process_name);

        void SetBytesCode(const std::vector<UCHAR> bytes_code);
        std::vector<UCHAR> GetBytesCode() const;
        void SetDefaultBytesCode();
        
        void HookCloseHandle();
        static void HookedCloseHandleFunction(HANDLE h_object);

    };
}

#endif