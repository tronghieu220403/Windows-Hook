#include "inlinehookclosehandle.h"

namespace hook
{
    InlineHookCloseHandle::InlineHookCloseHandle(int pid):
        InlineHook(pid)
    {
        InlineHookCloseHandle::SetDefaultBytesCode();
    }

    InlineHookCloseHandle::InlineHookCloseHandle(const std::string_view &process_name):
        InlineHook(process_name)
    {
        InlineHookCloseHandle::SetDefaultBytesCode();
    }

    void InlineHookCloseHandle::SetDefaultBytesCode()
    {
        #ifdef _DEBUG
            PUCHAR p_hooked_close_handle = (PUCHAR)&InlineHookCloseHandle::HookedCloseHandleFunction + 5 + *(DWORD *)((size_t) & InlineHookCloseHandle::HookedCloseHandleFunction + 1);
        #else
            PUCHAR p_hooked_close_handle = (PUCHAR)&InlineHookCloseHandle::HookedCloseHandleFunction;
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

    void InlineHookCloseHandle::HookCloseHandle()
    {
        std::shared_ptr<pe::PeMemory> pe_memory = InlineHook::GetPeMemory();
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
            size_t function_address = ulti::MemoryToUint64(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, 8).data());
        #elif _WIN32
            size_t function_address = ulti::MemoryToUint32(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, 4).data());
        #endif

        // Modify jump at the end of the hooking function to jump to somewhere in CloseHandle, 
        // must try to replace some of the ending line of the hooking function to conserse the flow of code since some first line of CloseHandle has been replaced by the push hooking_function_address; ret; nop * x
        // Since jump do not allow any value greater than max of DWORD -> use push address_ptr; ret
        #ifdef _WIN64
            std::vector<UCHAR> jmp_bytes_code_hooking_function(9); // 1 for push opcode, 8 for address_ptr, 1 for ret
        #elif _WIN32
            std::vector<UCHAR> jmp_bytes_code_hooking_function(5); // 1 for push opcode, 4 for address_ptr, 1 for ret
        #endif

        int x = 0; // modify this value

        std::vector<UCHAR> edited_bytes_code;
        std::copy(bytes_code.begin(), bytes_code.end() - x, std::back_inserter(edited_bytes_code));
        std::copy(jmp_bytes_code_hooking_function.begin(), jmp_bytes_code_hooking_function.end(), std::back_inserter(edited_bytes_code));

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_memory->ProcessMemory::MemoryAlloc(edited_bytes_code.size(), PAGE_EXECUTE_READWRITE);

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        if (pe_memory->ProcessMemory::WriteData(code_ptr, edited_bytes_code) == false)
        {
            return;
        }

        // Modify jump in the CloseHandle() to jump to the beginning of hooking function
        // Since jump do not allow any value greater than max of DWORD -> use push hooking_function_address; ret; nop * x

        #ifdef _WIN64
            std::vector<UCHAR> jmp_bytes_code_close_handle(9); // 1 for push opcode, 8 for address_ptr, 1 for ret
        #elif _WIN32
            std::vector<UCHAR> jmp_bytes_code_close_handle(5); // 1 for push opcode, 4 for address_ptr, 1 for ret
        #endif

        if (pe_memory->ProcessMemory::WriteData((LPVOID)function_address, jmp_bytes_code_close_handle) == false)
        {
            return;
        }

        return;
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

        iat.fnCloseHandle(h_object);
        return;
    }

}