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
        InlineHook::SetHookingBytesCode((PVOID)(&InlineHookCloseHandle::HookedCloseHandleFunction));
    }

    void InlineHookCloseHandle::HookCloseHandle()
    {
        std::shared_ptr<pe::PeMemory> pe_memory = InlineHook::GetPeMemory();

        if (pe_memory->GetBaseAddress() == 0)
        {
            return;
        }

        LPVOID va_close_handle_iat = (void *)(Hook::GetVirutalAddressOfFunctionOnIat("KERNEL32.dll", "CloseHandle"));

        if (va_close_handle_iat == NULL)
        {
            return;
        }

        size_t close_handle_address = ulti::MemoryToUint32(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, sizeof(LPVOID)).data());

        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_memory->ProcessMemory::MemoryAlloc(0x3000, PAGE_EXECUTE_READWRITE);

        // take some bytes in the closehandle, modify it and push it to the bytes_code
        std::vector<UCHAR> saved_original_bytes_code = TakeInstructions((LPVOID)close_handle_address, (PUCHAR)code_ptr + bytes_code.size());
        ulti::InsertVector(bytes_code, bytes_code.size(), saved_original_bytes_code);

        // jmp back to the close handle to continue execute
        std::vector<UCHAR> last_jmp = InlineHook::GetJumpInstruction((PUCHAR)code_ptr + bytes_code.size(), (LPVOID)(close_handle_address + saved_original_bytes_code.size()));

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        if (pe_memory->ProcessMemory::WriteData(code_ptr, bytes_code) == false)
        {
            return;
        }

        // Modify jump in the CloseHandle in kernel32.dll to jump to the beginning of hooking function
        // Better be jump dword
        if (pe_memory->ProcessMemory::WriteData((LPVOID)close_handle_address, InlineHook::GetJumpInstruction((LPVOID)close_handle_address, code_ptr)) == false)
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

        return;
    }

}

