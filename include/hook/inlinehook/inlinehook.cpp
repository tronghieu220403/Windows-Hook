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

    void InlineHook::SetHookingBytesCode(PVOID function_address)
    {
        Hook::SetHookingBytesCode(function_address);
        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();
        bytes_code.pop_back(); // remove ret from bytes code
        
        std::vector<UCHAR> jmp_bytes_code_hooking_function = InlineHook::GetJumpInstruction(0);

        std::copy(jmp_bytes_code_hooking_function.begin(), jmp_bytes_code_hooking_function.end(), std::back_inserter(bytes_code));

        Hook::SetHookingBytesCode(bytes_code);
    }

    void InlineHook::SetJumpBackFromHookingFunction(size_t virual_address)
    {
        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();

        memcpy(&bytes_code[bytes_code.size() - 2 - sizeof(LPVOID)], &virual_address, sizeof(LPVOID));

        Hook::SetHookingBytesCode(bytes_code);
    }

    // The purpose of this function: 
    // In some case that the first instruction is not jmp, we must append some lines before the last jump of hooking function to conserse the flow of code.
    // Why? Since some first lines of the original function that has been replaced by "mov rax, hooking_function_address; jmp rax" (for x64), or "mov eax, hooking_function_address; jmp eax (for x86), we have to restore it by writing to the end of hooking function before the jump
    // For example:
    // +) Original function: "sub rsp, 16h; push eax"
    // +) After replace: "mov rax, hooking_function_address; jmp rax; push eax" (replace "sub rsp, 16h" by "mov rax, hooking_function_address; jmp rax") (just an example because bytes code of that two instructions is not equal)
    // +) So in the hooking function we must: "hooking body; push eax; jmp "rip in "push eax"")
    // +) If not, the flow will be like "hooking body; push eax; ...". This can lead to wrong execution of original function because the original "sub rsp, 16h" is missing!
    // +) When we add all the replaced instructions, it now makes sense, the flow of code will look like "hooking body; sub rsp, 16h; push eax; ..." (this is normal execution)
    void InlineHook::AddBytesCodeBeforeLastJump(std::vector<UCHAR> added_bytes_code)
    {

        std::vector<UCHAR> bytes_code = Hook::GetHookingBytesCode();
        std::vector<UCHAR> new_bytes_code(bytes_code.begin(), bytes_code.end() - PUSH_JMP_SIZE); // initialization: no last jmp instruction
        std::copy(added_bytes_code.begin(), added_bytes_code.end(), std::back_inserter(new_bytes_code));
        std::copy(bytes_code.end() - PUSH_JMP_SIZE, bytes_code.end(), std::back_inserter(new_bytes_code));

        Hook::SetHookingBytesCode(new_bytes_code);
    }

    std::vector<UCHAR> InlineHook::GetJumpInstruction(size_t virual_address)
    {

        // Since jump do not allow any value greater than max of DWORD -> use mov rax, address_ptr; jmp rax (rax for x64, eax for x86);
        std::vector<UCHAR> jmp_bytes_code(PUSH_JMP_SIZE); 

        #ifdef _WIN64
            
            // push opcode
            jmp_bytes_code[0] = 0x48;
            jmp_bytes_code[1] = 0xb8;

            // jmp
            memcpy(&jmp_bytes_code[2], &virual_address, 8);

        #elif _WIN32

            // push opcode
            jmp_bytes_code[0] = 0xb8;

            memcpy(&jmp_bytes_code[1], &virual_address, 4);

        #endif

        jmp_bytes_code[PUSH_JMP_SIZE - 2] = 0xff;
        jmp_bytes_code[PUSH_JMP_SIZE - 1] = 0xe0;

        return jmp_bytes_code;
    }
}
