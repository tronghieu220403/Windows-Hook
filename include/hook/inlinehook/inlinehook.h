#ifndef USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_
#define USERMODEHOOK_HOOK_INLINEHOOK_INLINEHOOK_H_

#include "ulti/everything.h"
#include "hook/hook.h"
#include "Zydis/Zydis.h"
#include "asm/instructionmodificator.h"

namespace hook
{
    #define JMP_DWORD_OPCODE_SIZE 5

    class InlineHook: public Hook
    {
    private: 
        std::string dll_name_;
        std::string function_name_;
        PVOID hooking_function_ = nullptr;
    public:
        InlineHook(int pid, const std::string_view& function_name, const std::string_view& dll_name, const PVOID hooking_function);
        InlineHook(const std::string_view& process_name, const std::string_view& function_name, const std::string_view& dll_name, const PVOID hooking_function);

        bool StartHook();

        std::vector<UCHAR> TakeInstructions(LPVOID curr_addr, LPVOID new_address, size_t lower_bound);

        void SaveRegisters();

        std::vector<UCHAR> GetJumpInstruction(LPVOID curr_addr, LPVOID new_address);
        
        std::string GetDllName() const;
        void SetDllName(const std::string_view& dll_name);

        std::string GetFunctionName() const;
        void SetFunctionName(const std::string_view& function_name);

        PVOID GetHookingFunction() const;
        void SetHookingFunction(const PVOID hooking_function);

    private:
#ifdef _WIN64
        static const inline std::vector<UCHAR> push_param_ =
        {
            0x41, 0x51,     // push r9
            0x41, 0x50,     // push r8
            0x52,           // push rdx
            0x51,           // push rcx
            0x50,           // push rax
            0x53, 	        // push rbx
            0x55, 	        // push rbp
            0x57,           // push rdi
            0x56,	        // push rsi
            0x41, 0x54,	    // push r12
            0x41, 0x55,	    // push r13
            0x41, 0x56,	    // push r14
            0x41, 0x57	    // push r15
            //,0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 // mov rax, 4141414141414141h
            //,0x50 // push rax
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
            0x59,           // pop rcx
            0x5a,           // pop rdx
            0x41, 0x58,     // pop r8
            0x41, 0x59      // pop r9
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