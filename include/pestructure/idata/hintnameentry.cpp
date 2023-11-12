#include "hintnameentry.h"

namespace pe
{
    HintNameEntry::HintNameEntry(PUCHAR pe_data, DWORD rva)
    {
        HintNameEntry::SetHintNameEntry(pe_data, rva);
    }

    void HintNameEntry::SetHintNameEntry(PUCHAR pe_data, DWORD rva)
    {
        hint_ = ulti::Field{"Hint", 
            ulti::MemoryToUint16(pe_data + rva), 
            2};
        rva += 2;
        name_ =
            ulti::FieldStr{"Name", 
            ulti::MemoryToString(pe_data + rva)};
        if ( ((size_t)rva + name_.value.size() + 1) % 2 == 1)
        {
            pad_ = 2;
        }
    }

    ulti::Field HintNameEntry::GetHintField() const
    {
        return hint_;
    }

    ulti::FieldStr HintNameEntry::GetNameField() const
    {
        return name_;
    }

    int HintNameEntry::GetSize() const
    {
        return static_cast<int>(name_.value.size()) + 2 + pad_;
    }

    std::string HintNameEntry::ToString(int pad)
    {
        std::string s;
        std::string pad_str(pad * 4, ' ');
        s.append(pad_str + "Hint: " + ulti::ToHex(GetHintField().value) + "\n");
        s.append(pad_str + "Name: " + GetNameField().value + "\n");
        return s;
    }

}
