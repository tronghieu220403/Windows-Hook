/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Joel Hoener

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

/**
 * @file
 * Demonstrates disassembling using the "all-in-one" disassembler API.
 */

#include <Windows.h>

#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>

#include <iostream>
#include <vector>

using namespace std;



int main()
{
    ZyanU8 data[] =
    {
        // 0xE9, 0x5B,0xDF,0x02,0x00
        0x48, 0xFF, 0x25, 0xB1, 0x66, 0x04, 0x00,
        //,0x79, 0x10
        0x48, 0x8D, 0x15, 0x15, 0x33, 0x02, 0x00
        ,0x41, 0x8D, 0x5E, 0x05
        , 0x4C, 0x8D, 0x44, 0x24, 0x30
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
        string txt(instruction.text);
        cout << txt << endl;
        
        ZYDIS_MNEMONIC_JMP;    
        ZYDIS_MNEMONIC_CALL;
        ZYDIS_MNEMONIC_LEA;
        cout << "Type: " << (ULONGLONG)instruction.info.mnemonic << endl;

        ZYDIS_OPERAND_TYPE_REGISTER;
        ZYDIS_OPERAND_TYPE_MEMORY;
        ZYDIS_OPERAND_TYPE_POINTER;
        cout << "Operand 0 type " << (ULONGLONG)instruction.operands[0].type << endl;
        cout << "Operand 1 type " << (ULONGLONG)instruction.operands[1].type << endl;
        //cout << hex << "0x" << (ULONGLONG)instruction.operands[1].imm.value.u << endl;
        // cout << (ULONGLONG)instruction.operands[1] << endl; // unused
        cout << (ULONGLONG)instruction.operands[1].reg.value << endl; // unused

        cout << "Register number: " << (ULONGLONG)instruction.operands[2].reg.value << endl; 

        ZYDIS_REGISTER_R14;
        ZYDIS_REGISTER_EBX;

        offset += instruction.info.length;
        runtime_address += instruction.info.length;

    }

    return 0;
}