#include "inlinehookclosehandle.h"

namespace hook
{
    InlineHookCloseHandle::InlineHookCloseHandle(int pid):
        InlineHook(pid, "CloseHandle", "KERNEL32.dll", (PVOID)(&InlineHookCloseHandle::HookedCloseHandleFunction))
    {
    }

    InlineHookCloseHandle::InlineHookCloseHandle(const std::string_view &process_name):
        InlineHook(process_name, "CloseHandle", "KERNEL32.dll", (PVOID)(&InlineHookCloseHandle::HookedCloseHandleFunction))
    {
    }

    void InlineHookCloseHandle::HookedCloseHandleFunction()
    {
        FuncAddr iat;

        DWORD bytes_written = 0;

        GetFunctionAddressesFromTeb(&iat);

        char dll_name[9] = {0};
        dll_name[0] = 'h';
        dll_name[1] = 'i';
        dll_name[2] = 'e';
        dll_name[3] = 'u';
        dll_name[4] = '.';
        dll_name[5] = 'd';
        dll_name[6] = 'l';
        dll_name[7] = 'l';        
        HMODULE dll = iat.fnLoadLibraryExA(dll_name, NULL, NULL);

        char function_name[16] = {0};
        function_name[0] = 'P';
        function_name[1] = 'r';
        function_name[2] = 'i';
        function_name[3] = 'n';
        function_name[4] = 't';
        function_name[5] = 'P';
        function_name[6] = 'a';
        function_name[7] = 'r';
        function_name[8] = 'a';
        function_name[9] = 'm';
        function_name[10] = 'e';
        function_name[11] = 't';
        function_name[12] = 'e';
        function_name[13] = 'r';
        function_name[14] = 's';

        pFunction fnPrintParameters = (pFunction)(iat.fnGetProcAddress(dll, function_name));

        fnPrintParameters(CLOSE_HANDLE_N_PARAMS);

        return;
    }

}

