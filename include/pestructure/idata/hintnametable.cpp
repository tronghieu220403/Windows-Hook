#include "hintnametable.h"

namespace pe
{
    HintNameTable::HintNameTable(PUCHAR pe_data, DWORD rva)
    {
        SetHintNameTable(pe_data, rva);
    }

    void HintNameTable::SetHintNameTable(PUCHAR pe_data, DWORD rva)
    {
        HintNameEntry entry;

        while(true)
        {
            entry = HintNameEntry(pe_data, rva);
            if (entry.GetNameField().value.size() == 0)
            {
                break;
            }
            entry_vector_.push_back(entry);
            rva += entry.GetSize();
        }
    }

    std::string HintNameTable::ToString(int pad)
    {
        std::string s;
        std::string pad_str(pad * 4, ' ');
        s.append(pad_str + "Hint/Name Talbe:\n\n");
        for (auto &entry: entry_vector_)
        {
            s.append(entry.ToString(pad+1) + "\n");
        }
        return s;
    }
}
