#ifndef USERMODEHOOK_ASM_INSTRUCTION_H_
#define USERMODEHOOK_ASM_INSTRUCTION_H_

#include "ulti/everything.h"
#include "Zydis/Zydis.h"

namespace assembly
{
    class AssemblyInstruction
    {
    private:
        ZydisDisassembledInstruction zydis_instruction_;
    public:
        AssemblyInstruction() = default;
        AssemblyInstruction(const ZydisDisassembledInstruction& instruction);

        ZydisDisassembledInstruction GetZydisDisassembledInstruction() const;
        void SetZydisDisassembledInstruction(const ZydisDisassembledInstruction& instruction);

    };
}

#endif