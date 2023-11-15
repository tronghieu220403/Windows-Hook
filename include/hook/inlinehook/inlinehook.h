#ifndef USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_
#define USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_

#include "ulti/everything.h"
#include "hook/hook.h"

namespace hook
{
    class InlineHook: public Hook
    {
    public:
        InlineHook(int pid);
        InlineHook(const std::string_view& process_name);
    };
}

#endif