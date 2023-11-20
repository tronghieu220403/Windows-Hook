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

        size_t function_address = ulti::MemoryToUint32(pe_memory->ProcessMemory::ReadData(va_close_handle_iat, sizeof(LPVOID)).data());

        // Look at the address of CloseHandle in kernel32.dll, since the function is inherited from an other DLL so the instruction at that address in kernel32 is always be "jmp [some address]"

        // For this case (same case for many other functions that are inherited from other DLLs), we only need to find the exact value of "some address" in the instruction above and then jump to it at the end of the hooking function.

        #ifdef _WIN32
            size_t real_close_handle_virtual_address = *(size_t *)(static_cast<size_t>(*(DWORD *)((PUCHAR)(function_address + 2))) + JMP_DWORD_OPCODE_SIZE + function_address);
        #elif _WIN64
            size_t real_close_handle_virtual_address = *(size_t *)(static_cast<size_t>(*(DWORD *)((PUCHAR)(function_address + 3))) + JMP_DWORD_OPCODE_SIZE + function_address);
        #endif
        InlineHook::SetJumpBackFromHookingFunction(real_close_handle_virtual_address);
        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_memory->ProcessMemory::MemoryAlloc(bytes_code.size(), PAGE_EXECUTE_READWRITE);

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        if (pe_memory->ProcessMemory::WriteData(code_ptr, bytes_code) == false)
        {
            return;
        }

        // Modify jump in the CloseHandle in kernel32.dll to jump to the beginning of hooking function

        if (pe_memory->ProcessMemory::WriteData((LPVOID)function_address, InlineHook::GetJumpInstruction((size_t)code_ptr)) == false)
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

