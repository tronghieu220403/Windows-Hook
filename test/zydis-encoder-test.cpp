

#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <Zydis/Zydis.h>

void lea_handle()
{

}

int main()
{
    ZydisEncoderRequest req;
    memset(&req, 0, sizeof(req));

    req.mnemonic = ZYDIS_MNEMONIC_MOV;
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.operand_count = 2;
    req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
    req.operands[1].mem.base = ZYDIS_REGISTER_RIP;
    req.operands[1].mem.displacement = (DWORD)(0xf8002fd8);
    req.operands[1].mem.size = 8;

    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = ZYDIS_REGISTER_RAX;

    ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize encoded_length = sizeof(encoded_instruction);

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
    {
        puts("Failed to encode instruction");
        return 1;
    }

    for (ZyanUSize i = 0; i < encoded_length; ++i)
    {
        printf("%02X ", encoded_instruction[i]);
    }
    puts("");

    return 0;
}