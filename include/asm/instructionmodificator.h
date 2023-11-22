#ifndef USERMODEHOOK_ASM_INSTRUCTIONMODIFICATOR_H_
#define USERMODEHOOK_ASM_INSTRUCTIONMODIFICATOR_H_

#include "ulti/everything.h"
#include "Zydis/Zydis.h"
#include "asm/instruction.h"
#include "asm/asmencoder.h"

namespace assembly
{
    class AssemblyInstructionModificator
    {
    private:
        AssemblyInstruction asm_instrucion_;
    public:
        AssemblyInstructionModificator(const AssemblyInstruction& asm_instrucion);
        AssemblyInstructionModificator(const ZydisDisassembledInstruction& instruction);

        std::vector<UCHAR> ChangeAddress(size_t curr_addr, size_t new_address);
        std::vector<UCHAR> MovChangeAdddress(size_t curr_addr, size_t new_address);
        std::vector<UCHAR> LeaChangeAdddress(size_t curr_addr);
        std::vector<UCHAR> JmpChangeAdddress(size_t curr_addr, size_t new_address);
        std::vector<UCHAR> CallChangeAdddress(size_t curr_addr, size_t new_address);
    };
}

#endif