#include "instruction.h"

namespace assembly
{
    AssemblyInstruction::AssemblyInstruction(const ZydisDisassembledInstruction &instruction):
        zydis_instruction_(instruction)
    {
    }

    ZydisDisassembledInstruction AssemblyInstruction::GetZydisDisassembledInstruction() const
    {
        return zydis_instruction_;
    }

    void AssemblyInstruction::SetZydisDisassembledInstruction(const ZydisDisassembledInstruction& instruction)
    {
        zydis_instruction_ = instruction;
    }

}
