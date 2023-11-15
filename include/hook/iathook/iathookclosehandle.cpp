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
        #ifdef _DEBUG
            PUCHAR p_hooked_close_handle = (PUCHAR)&IatHookCloseHandle::HookedCloseHandleFunction + 5 + *(DWORD *)((size_t) & IatHookCloseHandle::HookedCloseHandleFunction + 1);
        #else
            PUCHAR p_hooked_close_handle = (PUCHAR)&IatHookCloseHandle::HookedCloseHandleFunction;
        #endif // DEBUG

        size_t end_addr = 0;
        size_t i = 0;

        // Get bytes code of "static void HookedCloseHandle(HANDLE h_object)";
        // Find HookedCloseHandle function ulti we find 5x C3 (pop something; ret)

        for (;;i++)
        {
            if (((*(char*)(p_hooked_close_handle + i + 1) & 0xff) == 0xc3 && (*(char*)(p_hooked_close_handle + i) & 0xf0) == 0x50))
            {
                end_addr = i + 2;
                break;
            }
        }

        std::vector<UCHAR> bytes_code;
        bytes_code.resize(end_addr);
        ::memcpy(bytes_code.data(), p_hooked_close_handle, end_addr);
        Hook::SetBytesCode(bytes_code);
    }

    void IatHookCloseHandle::HookCloseHandle()
    {
        std::shared_ptr<pe::PeMemory> pe_memory = IatHook::GetPeMemory();
        std::vector<UCHAR> bytes_code = Hook::GetBytesCode();

        if (pe_memory->GetBaseAddress() == 0)
        {
            return;
        }

        LPVOID va_close_handle_iat = (void *)(Hook::GetVirutalAddressOfFunctionOnIat("KERNEL32.dll", "CloseHandle"));

        if (va_close_handle_iat == NULL)
        {
            return;
        }

        #ifdef _WIN64
            size_t address = ulti::MemoryToUint64(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, 8).data());
        #elif _WIN32
            size_t address = ulti::MemoryToUint32(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, 4).data());
        #endif

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_memory->ProcessMemory::MemoryAlloc(bytes_code.size(), PAGE_EXECUTE_READWRITE);

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        if (pe_memory->ProcessMemory::WriteData(code_ptr, bytes_code) == false)
        {
            return;
        }

        // Replace the CloseHandle() address by code_ptr in va_close_handle_iat
        #ifdef _WIN64
        if (pe_memory->ProcessMemory::WriteData(va_close_handle_iat, (PUCHAR)&code_ptr, 8) == false)
        {
            std::cout << GetLastError() << std::endl;
            return;
        }
        #elif _WIN32
        if (pe_memory->ProcessMemory::WriteData(va_close_handle_iat, (PUCHAR)&code_ptr, 4) == false)
        {
            return;
        }
        #endif

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