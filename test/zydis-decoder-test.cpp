
#include <Windows.h>

#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>

#include <iostream>
#include <vector>
#include <string>

using namespace std;

vector<UCHAR> EncodeInstruction(ZydisEncoderRequest req)
{
    ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize encoded_length = sizeof(encoded_instruction);

    vector<UCHAR> bytes_code;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
    {
        return vector<UCHAR>();
    }

    for (ZyanUSize i = 0; i < encoded_length; ++i)
    {
        bytes_code.push_back(encoded_instruction[i]);
    }

    return bytes_code;
}

vector<UCHAR> handle_lea(ZydisDisassembledInstruction instruction, size_t curr_addr)
{
    string txt(instruction.text);
    cout << txt << endl;

    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));

    if (instruction.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
    {
        return vector<UCHAR>();
    }

    if (!instruction.operands[1].mem.disp.has_displacement)
    {
        return vector<UCHAR>();
    }

    if ( (instruction.operands[1].mem.base != ZYDIS_REGISTER_RIP && instruction.operands[0].mem.base != ZYDIS_REGISTER_EIP) || instruction.operands[1].mem.index != 0 )
    {
        return vector<UCHAR>();
    }

    req.mnemonic = ZYDIS_MNEMONIC_MOV;
    req.machine_mode = instruction.info.machine_mode;
    req.operand_count = 2;
    req.operands[0].type = instruction.operands[0].type;
    req.operands[0].reg.value = instruction.operands[0].reg.value;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    req.operands[1].imm.u = curr_addr + instruction.info.length + instruction.operands[1].mem.disp.value;

    vector<UCHAR> bytes_code;

    for (auto c : EncodeInstruction(req))
    {
        bytes_code.push_back(c);
    }

    return bytes_code;

}

vector<UCHAR> handle_jmp(ZydisDisassembledInstruction instruction, size_t curr_addr, size_t new_address)
{
    string txt(instruction.text);
    cout << txt << endl;

    if (instruction.info.operand_count_visible != 1)
    {
        return vector<UCHAR>();
    }

    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));
    vector<UCHAR> bytes_code;

    if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {

        req.mnemonic = instruction.info.mnemonic;
        req.machine_mode = instruction.info.machine_mode;
        req.operand_count = 1;
        req.operands[0].type = instruction.operands[0].type;
        DWORD immerdiate_value = (DWORD)(curr_addr + instruction.operands[0].imm.value.u - new_address);
        req.operands[0].imm.u = immerdiate_value;

        for (auto c : EncodeInstruction(req))
        {
            bytes_code.push_back(c);
        }
        return bytes_code;
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

            for (auto c : EncodeInstruction(req))
            {
                bytes_code.push_back(c);
            }

            return bytes_code;

        }
    }

    return vector<UCHAR>();
}

vector<UCHAR> handle_call(ZydisDisassembledInstruction instruction, size_t curr_addr, size_t new_address)
{
    string txt(instruction.text);
    cout << txt << endl;

    if (instruction.info.operand_count_visible != 1)
    {
        return vector<UCHAR>();
    }

    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));
    vector<UCHAR> bytes_code;

    if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        req.mnemonic = instruction.info.mnemonic;
        req.machine_mode = instruction.info.machine_mode;
        req.operand_count = 1;
        req.operands[0].type = instruction.operands[0].type;
        DWORD immerdiate_value = (DWORD)(curr_addr + instruction.operands[0].imm.value.u - new_address);
        req.operands[0].imm.u = immerdiate_value;//immerdiate_value;
        for (auto c : EncodeInstruction(req))
        {
            bytes_code.push_back(c);
        }
        return bytes_code;
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
            for (auto c : EncodeInstruction(req))
            {
                bytes_code.push_back(c);
            }
            return bytes_code;
        }
    }
    return vector<UCHAR>();
}

vector<UCHAR> handle_mov(ZydisDisassembledInstruction instruction, size_t curr_addr, size_t new_address)
{
    string txt(instruction.text);
    cout << txt << endl;

    if (instruction.info.operand_count_visible != 2)
    {
        return vector<UCHAR>();
    }

    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));
    vector<UCHAR> bytes_code;

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
            for (auto c : EncodeInstruction(req))
            {
                bytes_code.push_back(c);
            }
            return bytes_code;
        }
    }

    return vector<UCHAR>();
}


int main()
{
    ZyanU8 data[] =
    {
        // lea instruction
        0x48, 0x8d, 0x05, 0x1f, 0x71, 0x41, 0x00 // lea rax,[0x417126]
        // 
        // jmp instruction
        ,0xE9, 0x3F, 0xFF, 0xFF, 0xFF // jmp 0xFFFFFFFFFFFFFF44
        ,0xff, 0x25, 0xdf, 0x2f, 0x00, 0x00 // jmp qword ptr [0x2FE5]
        //
        // call instruction
        ,0xE8, 0xB3, 0x65, 0x00, 0x00 // call 0x65B8
        ,0xff, 0x15, 0xdf, 0x2f, 0x00, 0x00 // call [0x2FE5]  
        ,0x66, 0xff, 0x2d, 0xdf, 0x2f, 0x80, 0xf // jmp far
        //
        // mov instruciton
        ,0x48, 0x8b, 0x05, 0xd8, 0x2f, 0x00, 0x00 //  mov rax, qword ptr [var]
        ,0x48, 0x89, 0x05, 0xd8, 0x2f, 0x00, 0x00 //  mov QWORD ptr [var], rax
    };

    // The runtime address (instruction pointer) was chosen arbitrarily here in order to better
    // visualize relative addressing. In your actual program, set this to e.g. the memory address
    // that the code being disassembled was read from.
    ZyanU64 runtime_address = 0x007FFFFFFF400000;

    // Loop over the instructions in our buffer.
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
        /* runtime_address: */ 0,
        /* buffer:          */ data + offset,
        /* length:          */ sizeof(data) - offset,
        /* instruction:     */ &instruction
    ))) {
        vector<UCHAR> bytes_code;

        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA)
        {
            bytes_code = handle_lea(instruction, 0xff00000000);
            for (size_t i = 0; i < bytes_code.size(); i++)
            {
                cout << hex << (ULONGLONG)bytes_code[i] << " ";
            }
            //cout << endl;
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP)
        {
            bytes_code = handle_jmp(instruction, 0xff00000, 0x0700000);
            for (size_t i = 0; i < bytes_code.size(); i++)
            {
                cout << hex << (ULONGLONG)bytes_code[i] << " ";
            }
            cout << endl;
        }

        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
        {
            bytes_code = handle_call(instruction, 0xff00000, 0x0700000);
            for (size_t i = 0; i < bytes_code.size(); i++)
            {
                cout << hex << (ULONGLONG)bytes_code[i] << " ";
            }
            cout << endl;
        }
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV)
        {
            bytes_code = handle_mov(instruction, 0xff00000, 0x0700000);
            for (size_t i = 0; i < bytes_code.size(); i++)
            {
                cout << hex << (ULONGLONG)bytes_code[i] << " ";
            }
            cout << endl;
        }

        offset += instruction.info.length;
        runtime_address += instruction.info.length;

        cout << endl;

    }

    return 0;
}