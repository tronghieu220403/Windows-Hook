#include "importlookupentry.h"

namespace pe
{
    ImportLookupEntry::ImportLookupEntry(WORD version)
    {
        if (version != 0x20B && version != 0x10B)
        {
            return;
        }
        version_ = version;
    }

    void ImportLookupEntry::SetVersion(WORD version)
    {
        version_ = version;
    }


    ImportLookupEntry::ImportLookupEntry(PUCHAR pe_data, DWORD rva, WORD version)
    {
        if (version != 0x20B && version != 0x10B)
        {
            return;
        }
        version_ = version;
        SetImportLookupEntryData(pe_data, rva);
    }

    void ImportLookupEntry::SetImportLookupEntryData(PUCHAR pe_data, DWORD rva)
    {
        if (version_ != 0x20B && version_ != 0x10B)
        {
            return;
        }
        field_vector_.clear();
        if (version_ == 0x10B)
        {
            if ((ulti::MemoryToUint32(pe_data + rva) & 0x80000000) == 1)
            {
                // Import by ordinal
                field_vector_.push_back(ulti::Field{
                    "Ordinal Number",
                    ulti::MemoryToUint32(pe_data + rva) & 0x0000ffff,
                    2
                });
            }
            else
            {
                DWORD hint_rva = ulti::MemoryToUint32(pe_data + rva) & 0xffffffff;
                field_vector_.push_back(ulti::Field{
                    "Hint/Name Table RVA",
                    hint_rva,
                    4
                });
                entry_ = HintNameEntry(pe_data, hint_rva);
            }
        }
        else
        {
            if ((ulti::MemoryToUint64(pe_data + rva) & 0x8000000000000000) == 1)
            {
                // Import by ordinal
                field_vector_.push_back(ulti::Field{
                    "Ordinal Number",
                    ulti::MemoryToUint64(pe_data + rva) & 0x000000000000ffff,
                    2
                });
            }
            else
            {
                // Import by name
                DWORD hint_rva = ulti::MemoryToUint32(pe_data + rva) & 0xffffffff;
                field_vector_.push_back(ulti::Field{
                    "Hint/Name Table RVA",
                    hint_rva,
                    4
                });
                entry_ = HintNameEntry(pe_data, hint_rva);
            }
        }
    }

    bool ImportLookupEntry::IsOrdinalFlag() const
    {
        return false;
    }

    bool ImportLookupEntry::IsNameFlag() const
    {
        return false;
    }

    bool ImportLookupEntry::HasFunction(const std::string_view &function_name)
    {
        return entry_.GetNameField().value == function_name;
    }

    ulti::Field ImportLookupEntry::GetFieldByName(const std::string &name)
    {
        for (auto& field: field_vector_)
        {
            if (field.name == name)
            {
                return field;
            }
        }
        return ulti::Field();
    }

    std::string ImportLookupEntry::ToString(int pad)
    {
        std::string s;
        std::string pad_str(pad * 4, ' ');
        for (auto& field: field_vector_)
        {
            s.append(pad_str + field.name + ": " + ulti::ToHex(field.value) + "\n");
            if (field.name == "Hint/Name Table RVA")
            {
                s.append("\n" + entry_.ToString(pad+1));
            }
        }
        return s;

    }

}
