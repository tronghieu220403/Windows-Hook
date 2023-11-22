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

    std::vector<UCHAR> InlineHook::TakeInstructions(LPVOID curr_addr, LPVOID new_address)
    {
        std::vector<UCHAR> saved_original_bytes_code;
        std::vector<UCHAR> data = Hook::GetPeMemory()->ReadData((void *)curr_addr, 30);
        ZyanUSize offset = 0;
        size_t runtime_address = (size_t)curr_addr;
        ZydisDisassembledInstruction instruction;

        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
                                #ifdef _WIN64
            /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
                                #else
            /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
                                #endif
            /* runtime_address: */ 0,
            /* buffer:          */ &data[offset],
            /* length:          */ data.size() - offset,
            /* instruction:     */ &instruction
        ))) {
            
            std::vector<UCHAR> changed_bytes_code = assembly::AssemblyInstructionModificator((const ZydisDisassembledInstruction&)instruction).ChangeAddress(runtime_address, (size_t)new_address + offset);

            size_t old_size = saved_original_bytes_code.size();
            if (!changed_bytes_code.empty())
            {
                saved_original_bytes_code.resize(old_size + changed_bytes_code.size());
                memcpy(&saved_original_bytes_code[old_size], &changed_bytes_code[0], changed_bytes_code.size());
            }
            else
            {
                saved_original_bytes_code.resize(old_size + instruction.info.length);
                memcpy(&saved_original_bytes_code[old_size], &data[offset], instruction.info.length);
            }

            offset += instruction.info.length;
            runtime_address += instruction.info.length;
            if (offset >= 5)
            {
                break;
            }
        }

        return saved_original_bytes_code;
    }

    std::vector<UCHAR> InlineHook::GetJumpInstruction(LPVOID curr_addr, LPVOID new_address)
    {
        std::vector<UCHAR> jmp(5);
        jmp[0] = 0xe9;
        DWORD distance = (DWORD)((size_t)new_address - ((size_t)curr_addr + 5));
        *(DWORD *)(&jmp[1]) = distance;
    }
}
