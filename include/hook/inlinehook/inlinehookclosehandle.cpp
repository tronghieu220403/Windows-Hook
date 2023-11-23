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

    void InlineHookCloseHandle::HookedCloseHandleFunction(HANDLE h_object)
    {
        FuncAddr iat;
        char endline[1];
        endline[0] = '\n';

        DWORD bytes_written = 0;

        GetFunctionAddressesFromTeb(&iat);

        HANDLE std_output_handle = iat.fnGetStdHandle(STD_OUTPUT_HANDLE);

        size_t value = (size_t)h_object;
        
        char number[20];
        for (int i = 0; i < 20; i++)
        {
            number[i] = '\0';
        }
        int size = 0;
        while (value > 0)
        {
            number[19 - size] = '0' + value % 10;
            size++;
            value = value / 10;
        }
        if (size == 0)
        {
            size = 1;
            number[19] = '0';
        }

        iat.fnWriteConsoleA(std_output_handle, number + 20 - size, size, &bytes_written, NULL);
        iat.fnWriteConsoleA(std_output_handle, endline, 1, &bytes_written, NULL);

        for (int i = 0; i < 20; i++)
        {
            number[i] = '\0';
        }

        return;
    }

}

