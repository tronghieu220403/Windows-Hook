#ifndef USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_
#define USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_

#include "ulti/everything.h"
#include "hook/hook.h"
#include "Zydis/Zydis.h"
#include "asm/instructionmodificator.h"

namespace hook
{
    #define RET_OPCODE 0xc3
    #define INT_3_OPCODE 0xcc
    #define JMP_DWORD_OPCODE_SIZE 6
    #define MOV_JMP_RAX_X64_SIZE 12 // 2 for push opcode, 8 for address_ptr, 2 for jmp rax
    #define MOV_JMP_EAX_X86_SIZE 7 // 1 for push opcode, 4 for address_ptr, 2 for jmp eax
    #ifdef _WIN64
        #define MOV_JMP_SIZE MOV_JMP_RAX_X64_SIZE
    #elif _WIN32
        #define MOV_JMP_SIZE MOV_JMP_EAX_X86_SIZE
    #endif

    class InlineHook: public Hook
    {
    public:
        InlineHook(int pid);
        InlineHook(const std::string_view& process_name);

        std::vector<UCHAR> TakeInstructions(LPVOID curr_addr, LPVOID new_address, size_t lower_bound);

        std::vector<UCHAR> GetJumpInstruction(LPVOID curr_addr, LPVOID new_address);
        
    private:
#ifdef _WIN64
        static const inline std::vector<UCHAR> push_param_ =
        {
            0x51,           // push rcx
            0x52,           // push rdx
            0x41, 0x50,     // push r8
            0x41, 0x51,     // push r9
            0x50,           // push rax
            0x53, 	        // push rbx
            0x55, 	        // push rbp
            0x57,           // push rdi
            0x56,	        // push rsi
            0x41, 0x54,	    // push r12
            0x41, 0x55,	    // push r13
            0x41, 0x56,	    // push r14
            0x41, 0x57	    // push r15
        };  
        static const inline std::vector<UCHAR> pop_param_ = 
        { 
            0x41, 0x5f,	    // pop r15
            0x41, 0x5e,	    // pop r14
            0x41, 0x5d, 	// pop r13
            0x41, 0x5c,	    // pop r12
            0x5e,	        // pop rsi
            0x5f,	        // pop rdi
            0x5d,	        // pop rbp
            0x5b,	        // pop rbx
            0x58,           // pop rax
            0x41, 0x59,     // pop r9
            0x41, 0x58,     // pop r8
            0x5a,           // pop rdx
            0x59            // pop rcx
        };  
#elif _WIN32
        static const inline std::vector<UCHAR> push_param_ = 
        {
            0x50,           // push eax
            0x51,           // push ecx
            0x52,           // push edx
            0x53, 	        // push ebx
            0x55, 	        // push ebp
            0x56,           // push esi
            0x57,	        // push edi
        };

        static const inline std::vector<UCHAR> pop_param_ = 
        {
            0x5f,           // pop edi
            0x5e,           // pop esi
            0x5d,           // pop ebp
            0x5b, 	        // pop ebx
            0x5a, 	        // pop edx
            0x59,           // pop ecx
            0x58,	        // pop eax
        };

#endif

    };
}

#endif