#ifndef USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_
#define USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_

#include "ulti/everything.h"
#include "hook/hook.h"

namespace hook
{
    #define JMP_DWORD_OPCODE_SIZE 6
    #define PUSH_JMP_RAX_X64_SIZE 12 // 2 for push opcode, 8 for address_ptr, 2 for jmp rax
    #define PUSH_JMP_EAX_X86_SIZE 7 // 1 for push opcode, 4 for address_ptr, 2 for jmp eax
    #ifdef _WIN64
        #define PUSH_JMP_SIZE PUSH_JMP_RAX_X64_SIZE
    #elif _WIN32
        #define PUSH_JMP_SIZE PUSH_JMP_EAX_X86_SIZE
    #endif

    class InlineHook: public Hook
    {
    private:
    public:
        InlineHook(int pid);
        InlineHook(const std::string_view& process_name);

        void SetHookingBytesCode(PVOID function_address);

        void SetJumpBackFromHookingFunction(size_t virual_address);

        void AddBytesCodeBeforeLastJump(std::vector<UCHAR> added_bytes_code);

        std::vector<UCHAR> GetJumpInstruction(size_t virual_address);
    };
}

#endif