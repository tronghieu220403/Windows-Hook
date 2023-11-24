#include "inlinehook.h"

namespace hook
{
    InlineHook::InlineHook(int pid, const std::string_view& function_name, const std::string_view& dll_name, const PVOID hooking_function):
        Hook(pid),
        dll_name_(dll_name),
        function_name_(function_name),
        hooking_function_(hooking_function)
    {
        Hook::SetHookingBytesCode(hooking_function_);
    }

    InlineHook::InlineHook(const std::string_view& process_name, const std::string_view& function_name, const std::string_view& dll_name, const PVOID hooking_function):
        Hook(process_name),
        dll_name_(dll_name),
        function_name_(function_name),
        hooking_function_(hooking_function)
    {
        Hook::SetHookingBytesCode(hooking_function_);
    }

    bool InlineHook::StartHook()
    {
        std::shared_ptr<pe::PeMemory> pe_memory = InlineHook::GetPeMemory();

        if (pe_memory->GetBaseAddress() == 0)
        {
            return false;
        }

        HMODULE kernel32_dll_module = LoadLibraryA(&dll_name_[0]);
        size_t close_handle_address = (size_t)GetProcAddress(kernel32_dll_module, &function_name_[0]);
        
        if (close_handle_address == 0)
        {
            return false;
        }

        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();

        // Save register value (only x64)
        #ifdef _WIN64
            Hook::SetHookingBytesCode(bytes_code);
            InlineHook::SaveRegisters();
            bytes_code = Hook::GetHookingBytesCode();
        #endif

        // VirtualAllocEx a memory in target process with READWRITE_EXECUTION.
        LPVOID code_ptr = pe_memory->ProcessMemory::MemoryAllocNear((LPVOID)close_handle_address, 0x3000, PAGE_EXECUTE_READWRITE);

        if (code_ptr == nullptr)
        {
            return false;
        }

        // take some bytes in the closehandle, modify it and push it to the bytes_code
        std::vector<UCHAR> saved_original_bytes_code = TakeInstructions((LPVOID)close_handle_address, (PUCHAR)code_ptr + bytes_code.size(), JMP_DWORD_OPCODE_SIZE);
        ulti::InsertVector(bytes_code, bytes_code.size(), saved_original_bytes_code);

        // jmp back to the close handle to continue execute
        std::vector<UCHAR> last_jmp = InlineHook::GetJumpInstruction((PUCHAR)code_ptr + bytes_code.size(), (LPVOID)(close_handle_address + saved_original_bytes_code.size()));
        ulti::InsertVector(bytes_code, bytes_code.size(), last_jmp);

        Hook::SetHookingBytesCode(bytes_code);

        // Push the bytes code of HookedCloseHandle into that allocated memory.
        if (pe_memory->ProcessMemory::WriteData(code_ptr, bytes_code) == false)
        {
            return false;
        }

        // Modify jump in the CloseHandle in kernel32.dll to jump to the beginning of hooking function
        // Better be jump dword
        if (pe_memory->ProcessMemory::WriteData((LPVOID)close_handle_address, InlineHook::GetJumpInstruction((LPVOID)close_handle_address, code_ptr)) == false)
        {
            return false;
        }

        return true;
    }


    std::vector<UCHAR> InlineHook::TakeInstructions(LPVOID curr_addr, LPVOID new_address, size_t lower_bound)
    {
        std::vector<UCHAR> saved_original_bytes_code;
        std::vector<UCHAR> data = Hook::GetPeMemory()->ReadData((void *)curr_addr, 30);
        ZyanUSize offset = 0;
        size_t runtime_address = (size_t)curr_addr;
        ZydisDisassembledInstruction instruction;

#ifdef _WIN64
        /* machine_mode:    */ auto machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
#elif _WIN32
        /* machine_mode:    */ auto machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
#endif
        
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            /* machine_mode:    */ machine_mode,
            /* runtime_address: */ 0,
            /* buffer:          */ (void *)&data[offset],
            /* length:          */ data.size() - offset,
            /* instruction:     */ &instruction
        ))) 
        {

            std::vector<UCHAR> changed_bytes_code = assembly::AssemblyInstructionModificator((const ZydisDisassembledInstruction&)instruction).ChangeAddress(runtime_address, (size_t)new_address + offset);

            size_t old_size = saved_original_bytes_code.size();
            if (!changed_bytes_code.empty())
            {
                saved_original_bytes_code.resize(old_size + changed_bytes_code.size());
                memcpy(&saved_original_bytes_code[old_size], &changed_bytes_code[0], changed_bytes_code.size());
            }
            else
            {
                saved_original_bytes_code.resize(old_size + instruction.info.length);
                memcpy(&saved_original_bytes_code[old_size], &data[offset], instruction.info.length);
            }

            offset += instruction.info.length;
            runtime_address += instruction.info.length;
            if (offset + 1 >= lower_bound)
            {
                break;
            }
        }

        return saved_original_bytes_code;
    }

    void InlineHook::SaveRegisters()
    {
        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();
        ulti::InsertVector(bytes_code, 0, push_param_);
        ulti::InsertVector(bytes_code, bytes_code.size(), pop_param_);
        Hook::SetHookingBytesCode(bytes_code);
    }

    std::vector<UCHAR> InlineHook::GetJumpInstruction(LPVOID curr_addr, LPVOID new_address)
    {
        std::vector<UCHAR> jmp(JMP_DWORD_OPCODE_SIZE);
        jmp[0] = 0xe9;
        LONGLONG distance = (LONGLONG)new_address - ((LONGLONG)curr_addr + JMP_DWORD_OPCODE_SIZE);

        LONGLONG cmp = distance < 0 ? 0 - distance : distance;

        *(DWORD *)(&jmp[1]) = distance;
        return jmp;
    }

    std::string InlineHook::GetDllName() const
    {
        return dll_name_;
    }

    void InlineHook::SetDllName(const std::string_view& dll_name)
    {
        dll_name_ = dll_name;
    }

    std::string InlineHook::GetFunctionName() const
    {
        return function_name_;
    }

    void InlineHook::SetFunctionName(const std::string_view& function_name)
    {
        function_name_ = function_name;
    }

    PVOID InlineHook::GetHookingFunction() const
    {
        return hooking_function_;
    }

    void InlineHook::SetHookingFunction(const PVOID hooking_function)
    {
        hooking_function_ = hooking_function;
    }

}
