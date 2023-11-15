#include "iathook.h"

namespace hook
{
    IatHook::IatHook(int pid):
        Hook(pid)
    {

    }

    IatHook::IatHook(const std::string_view& process_name):
        Hook(process_name)
    {

    }

}
