#include "inlinehook.h"

namespace hook
{
    InlineHook::InlineHook(int pid):
        Hook(pid)
    {

    }

    InlineHook::InlineHook(const std::string_view& process_name):
        Hook(process_name)
    {

    }

}
