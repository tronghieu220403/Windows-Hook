#include "importdirectoryentry.h"

namespace pe
{
    ImportDirectoryEntry::ImportDirectoryEntry(PUCHAR pe_data, DWORD rva, WORD version)
    {
        if (version != 0x20B && version != 0x10B)
        {
            return;
        }
        version_ = version;

        SetImportDirectoryEntry(pe_data, rva);
    }

    void ImportDirectoryEntry::SetVersion(WORD version)
    {
        version_ = version;
    }

    void ImportDirectoryEntry::SetImportDirectoryEntry(PUCHAR pe_data, DWORD rva)
    {
        if (version_ != 0x20B && version_ != 0x10B)
        {
            return;
        }

        field_vector_.clear();
        rva -= 4;

        DWORD ilt_rva = ulti::MemoryToUint32(pe_data + (rva += 4));

        field_vector_.push_back(
            ulti::Field{"Import Lookup Table RVA", 
            ilt_rva, 
            4}
        );
        import_lookup_table_ = ImportLookupTable(pe_data, ilt_rva, version_);

        field_vector_.push_back(
            ulti::Field{"Time/Date Stamp", 
            ulti::MemoryToUint32(pe_data + (rva += 4)), 
            4}
        );

        field_vector_.push_back(
            ulti::Field{"Forwarder Chain", 
            ulti::MemoryToUint32(pe_data + (rva += 4)), 
            4}
        );

        DWORD name_rva = ulti::MemoryToUint32(pe_data + (rva += 4));
        field_vector_.push_back(
            ulti::Field{"Name RVA", 
            name_rva, 
            4}
        );

        field_str_vector_.push_back(
            ulti::FieldStr{"Dll Name", 
            ulti::MemoryToString(pe_data + name_rva)}
        );

        field_vector_.push_back(
            ulti::Field{"Import Address Table RVA", 
            ulti::MemoryToUint32(pe_data + (rva += 4)), 
            4}
        );
    }

    std::string ImportDirectoryEntry::GetDllName() const
    {
        return field_str_vector_[0].value;
    }

    DWORD ImportDirectoryEntry::GetRvaLocationInIatByName(std::string function_name)
    {
        return 0;
    }

    std::string ImportDirectoryEntry::ToString(int pad)
    {
        std::string s;
        std::string pad_str(pad * 4, ' ');

        for (auto& field: field_str_vector_)
        {
            s.append(pad_str + field.name + ": " + field.value + "\n");
        }        
        for (auto& field: field_vector_)
        {
            s.append(pad_str + field.name + ": " + ulti::ToHex(field.value) + "\n");
        }

        s.append("\n");
        s.append(import_lookup_table_.ToString(pad+1));
        return s;
    }

}
