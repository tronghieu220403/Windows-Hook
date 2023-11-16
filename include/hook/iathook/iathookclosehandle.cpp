#include "iathookclosehandle.h"

namespace hook
{
    IatHookCloseHandle::IatHookCloseHandle(int pid):
        IatHook(pid)
    {
        IatHookCloseHandle::SetDefaultBytesCode();
    }

    IatHookCloseHandle::IatHookCloseHandle(const std::string_view &process_name):
        IatHook(process_name)
    {
        IatHookCloseHandle::SetDefaultBytesCode();
    }

    void IatHookCloseHandle::SetDefaultBytesCode()
    {
        Hook::SetHookingBytesCode((PVOID)&IatHookCloseHandle::HookedCloseHandleFunction);    
    }

    void IatHookCloseHandle::HookCloseHandle()
    {
        std::shared_ptr<pe::PeMemory> pe_memory = IatHook::GetPeMemory();
        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();

        if (pe_memory->GetBaseAddress() == 0)
        {
            return;
        }

        LPVOID va_close_handle_iat = (void *)(Hook::GetVirutalAddressOfFunctionOnIat("KERNEL32.dll", "CloseHandle"));

        if (va_close_handle_iat == NULL)
        {
            return;
        }

        size_t address = ulti::MemoryToUint64(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, sizeof(LPVOID)).data());

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_memory->ProcessMemory::MemoryAlloc(bytes_code.size(), PAGE_EXECUTE_READWRITE);

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        if (pe_memory->ProcessMemory::WriteData(code_ptr, bytes_code) == false)
        {
            return;
        }

        // Replace the CloseHandle() address by code_ptr in va_close_handle_iat
        if (pe_memory->ProcessMemory::WriteData(va_close_handle_iat, (PUCHAR)&code_ptr, sizeof(LPVOID)) == false)
        {
            return;
        }

        return;
    }

    void IatHookCloseHandle::HookedCloseHandleFunction(HANDLE h_object)
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

        iat.fnCloseHandle(h_object);
        return;
    }

}