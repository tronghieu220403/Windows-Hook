#include "instructionmodificator.h"

namespace assembly
{
    AssemblyInstructionModificator::AssemblyInstructionModificator(const AssemblyInstruction &asm_instrucion):
        asm_instrucion_(asm_instrucion)
    {
    }

    AssemblyInstructionModificator::AssemblyInstructionModificator(const ZydisDisassembledInstruction &zydis_instrucion):
        asm_instrucion_(zydis_instrucion)
    {
    }

    std::vector<UCHAR> AssemblyInstructionModificator::ChangeAddress(size_t curr_addr, size_t new_address)
    {
        ZydisDisassembledInstruction instruction = asm_instrucion_.GetZydisDisassembledInstruction();
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA)
        {
            return LeaChangeAdddress(curr_addr);
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP)
        {
            return JmpChangeAdddress(curr_addr, new_address);
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
        {
            return CallChangeAdddress(0xff00000, 0x0700000);
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV)
        {
            return MovChangeAdddress(0xff00000, 0x0700000);
        }
        return std::vector<UCHAR>();
    }

    std::vector<UCHAR> AssemblyInstructionModificator::MovChangeAdddress(size_t curr_addr, size_t new_address)
    {
        ZydisDisassembledInstruction instruction = asm_instrucion_.GetZydisDisassembledInstruction();

        std::string txt(instruction.text);

        if (instruction.info.operand_count_visible != 2)
        {
            return std::vector<UCHAR>();
        }

        ZydisEncoderRequest req;
        ::memset(&req, 0, sizeof(req));

        size_t mem_id = 0;
        size_t reg_id = 1;

        if (instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            mem_id = 1;
            reg_id = 0;
        }

        if (instruction.operands[mem_id].type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.operands[reg_id].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            req.mnemonic = instruction.info.mnemonic;
            req.machine_mode = instruction.info.machine_mode;
            req.operand_count = instruction.info.operand_count_visible;

            req.operands[mem_id].type = instruction.operands[mem_id].type;
            req.operands[reg_id].type = instruction.operands[reg_id].type;

            if ( (instruction.operands[mem_id].mem.base == 0 || instruction.operands[mem_id].mem.base == ZYDIS_REGISTER_RIP || instruction.operands[mem_id].mem.base == ZYDIS_REGISTER_EIP)
                && instruction.operands[mem_id].mem.index == 0 && instruction.operands[mem_id].mem.disp.has_displacement == 1)
            {
                DWORD new_distance = (DWORD)(curr_addr + instruction.operands[mem_id].mem.disp.value - new_address);
                req.operands[mem_id].mem.base = req.machine_mode==ZYDIS_MACHINE_MODE_LONG_64 ? ZYDIS_REGISTER_RIP : ZYDIS_REGISTER_EIP;
                req.operands[mem_id].mem.displacement = new_distance;
                req.operands[mem_id].mem.size = 8;
                req.operands[reg_id].reg.value = instruction.operands[reg_id].reg.value;

                return AssemblyEncoder(req).GetEncodedBytesCode();
            }
        }

        return std::vector<UCHAR>();
    }

    std::vector<UCHAR> AssemblyInstructionModificator::LeaChangeAdddress(size_t curr_addr)
    {
        ZydisDisassembledInstruction instruction = asm_instrucion_.GetZydisDisassembledInstruction();

        ZydisEncoderRequest req;
        ::memset(&req, 0, sizeof(req));

        if (instruction.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            return std::vector<UCHAR>();
        }

        if (!instruction.operands[1].mem.disp.has_displacement)
        {
            return std::vector<UCHAR>();
        }

        if ( (instruction.operands[1].mem.base != ZYDIS_REGISTER_RIP && instruction.operands[0].mem.base != ZYDIS_REGISTER_EIP) || instruction.operands[1].mem.index != 0 )
        {
            return std::vector<UCHAR>();
        }

        req.mnemonic = ZYDIS_MNEMONIC_MOV;
        req.machine_mode = instruction.info.machine_mode;
        req.operand_count = 2;
        req.operands[0].type = instruction.operands[0].type;
        req.operands[0].reg.value = instruction.operands[0].reg.value;
        req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[1].imm.u = curr_addr + instruction.info.length + instruction.operands[1].mem.disp.value;

        return AssemblyEncoder(req).GetEncodedBytesCode();
    }

    std::vector<UCHAR> AssemblyInstructionModificator::JmpChangeAdddress(size_t curr_addr, size_t new_address)
    {
        ZydisDisassembledInstruction instruction = asm_instrucion_.GetZydisDisassembledInstruction();

        if (instruction.info.operand_count_visible != 1)
        {
            return std::vector<UCHAR>();
        }

        ZydisEncoderRequest req;
        ::memset(&req, 0, sizeof(req));

        if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            req.mnemonic = instruction.info.mnemonic;
            req.machine_mode = instruction.info.machine_mode;
            req.operand_count = 1;
            req.operands[0].type = instruction.operands[0].type;
            DWORD immerdiate_value = (DWORD)(curr_addr + instruction.operands[0].imm.value.u - new_address);
            req.operands[0].imm.u = immerdiate_value;
        }
        else if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (instruction.operands[0].mem.disp.has_displacement == 1 && 
                instruction.operands[0].mem.index == 0 &&
                (instruction.operands[0].mem.base == 0 || instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP || instruction.operands[0].mem.base == ZYDIS_REGISTER_EIP))
            {
                req.mnemonic = instruction.info.mnemonic;
                req.machine_mode = instruction.info.machine_mode;
                req.operand_count = 1;
                req.operands[0].type = instruction.operands[0].type;
                DWORD new_distance = (DWORD)(curr_addr + instruction.operands[0].mem.disp.value - new_address);
                req.operands[0].mem.displacement = new_distance;
                req.operands[0].mem.size = sizeof(DWORD);
                req.operands[0].mem.base = req.machine_mode == ZYDIS_MACHINE_MODE_LONG_64 ? ZYDIS_REGISTER_RIP : ZYDIS_REGISTER_EIP;
            }
        }

        return AssemblyEncoder(req).GetEncodedBytesCode();
    }

    std::vector<UCHAR> AssemblyInstructionModificator::CallChangeAdddress(size_t curr_addr, size_t new_address)
    {
        ZydisDisassembledInstruction instruction = asm_instrucion_.GetZydisDisassembledInstruction();

        if (instruction.info.operand_count_visible != 1)
        {
            return std::vector<UCHAR>();
        }

        ZydisEncoderRequest req;
        ::memset(&req, 0, sizeof(req));

        if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            req.mnemonic = instruction.info.mnemonic;
            req.machine_mode = instruction.info.machine_mode;
            req.operand_count = 1;
            req.operands[0].type = instruction.operands[0].type;
            DWORD immerdiate_value = (DWORD)(curr_addr + instruction.operands[0].imm.value.u - new_address);
            req.operands[0].imm.u = immerdiate_value;//immerdiate_value;
        }
        else if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (instruction.operands[0].mem.disp.has_displacement == 1 &&
                instruction.operands[0].mem.index == 0 &&
                (instruction.operands[0].mem.base == 0 || instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP || instruction.operands[0].mem.base == ZYDIS_REGISTER_EIP))
            {
                req.mnemonic = instruction.info.mnemonic;
                req.machine_mode = instruction.info.machine_mode;
                req.operand_count = 1;
                req.operands[0].type = instruction.operands[0].type;
                DWORD new_distance = (DWORD)(curr_addr + instruction.operands[0].mem.disp.value - new_address);            
                req.operands[0].mem.displacement = new_distance;
                req.operands[0].mem.size = 4;
                
                req.operands[0].mem.base = req.machine_mode==ZYDIS_MACHINE_MODE_LONG_64 ? ZYDIS_REGISTER_RIP : ZYDIS_REGISTER_EIP;
            }
        }
        return AssemblyEncoder(req).GetEncodedBytesCode();
    }
}
