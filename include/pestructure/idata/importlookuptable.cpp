#include "importlookuptable.h"

namespace pe
{
    ImportLookupTable::ImportLookupTable(WORD version)
    {
        if (version != 0x20B && version != 0x10B)
        {
            return;
        }
        version_ = version;
    }

    void ImportLookupTable::SetVersion(WORD version)
    {
        version_ = version;
    }

    ImportLookupTable::ImportLookupTable(PUCHAR pe_data, DWORD rva, WORD version)
    {
        if (version != 0x20B && version != 0x10B)
        {
            return;
        }
        version_ = version;
        ImportLookupTable::SetImportLookupTableData(pe_data, rva);
    }

    void ImportLookupTable::SetImportLookupTableData(PUCHAR pe_data, DWORD rva)
    {
        if (version_ != 0x20B && version_ != 0x10B)
        {
            return;
        }

        int data_size = version_ == 0x10B ? 4 : 8;

        import_lookup_entry_vector_.clear();
        while(true)
        {
            bool end_of_table = true;
            for (int i = 0; i < data_size; i++)
            {
                if (pe_data[rva + i] != 0)
                {
                    end_of_table = false;
                    break;
                }
            }
            if (end_of_table == true)
            {
                break;
            }
            import_lookup_entry_vector_.push_back(ImportLookupEntry(pe_data, rva, version_));
            rva += data_size;
        }
    }

    DWORD ImportLookupTable::GetFunctionOrdinal(const std::string_view &function_name)
    {
        for (int i = 0; i < import_lookup_entry_vector_.size(); i++)
        {
            if (import_lookup_entry_vector_[i].HasFunction(function_name))
            {
                return i;
            }
        }

        return (DWORD)(-1);
    }

    std::string ImportLookupTable::ToString(int pad)
    {
        std::string s;
        std::string pad_str(pad * 4, ' ');
        s.append(pad_str + "Import Lookup Table:\n\n");
        for (auto& entry: import_lookup_entry_vector_)
        {
            s.append(entry.ToString(pad+1) + "\n");
        }
        return s;
    }
}
