#ifndef USERMODEHOOK_HOOK_IATHOOK_IATHOOK_H_
#define USERMODEHOOK_HOOK_IATHOOK_IATHOOK_H_

#include "ulti/everything.h"
#include "hook/hook.h"

namespace hook
{
    class IatHook: public Hook
    {
    public:
        IatHook(int pid);
        IatHook(const std::string_view& process_name);

    };
}

#endif