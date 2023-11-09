#include "importdirectorytable.h"

namespace pe
{
    ImportDirectoryTable::ImportDirectoryTable(PUCHAR pe_data, DWORD rva, WORD version)
    {
        if (version != 0x20B && version != 0x10B)
        {
            return;
        }
        SetVersion(version);

        SetImportDirectoryTableData(pe_data, rva);

    }
    void ImportDirectoryTable::SetVersion(WORD version)
    {
        version_ = version;
    }

    void ImportDirectoryTable::SetImportDirectoryTableData(PUCHAR pe_data, DWORD rva)
    {
        if (version_ != 0x20B && version_ != 0x10B)
        {
            return;
        }
        entry_vector_.clear();
        while(true)
        {
            bool end_of_table = true;
            for (int i = 0; i < 20; i++)
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
            entry_vector_.push_back(ImportDirectoryEntry(pe_data, rva, version_));
            rva += 20;
        }
    }

    DWORD ImportDirectoryTable::GetRvaOfFunction(const std::string_view& dll_name, const std::string_view& function_name)
    {
        for (auto& entry: entry_vector_)
        {
            if (entry.GetDllName() == dll_name)
            {
                if (entry.GetRvaLocationInIatByName(function_name))
                {

                }
            }
        }

        return 0;
    }

    std::string ImportDirectoryTable::ToString(int pad)
    {
        std::string s;
        std::string pad_str(pad * 4, ' ');
        s.append(pad_str + "Import Directory Table:\n\n");
        for (auto& entry: entry_vector_)
        {
            s.append(entry.ToString(pad+1)+"\n");
        }
        return s;

    }

}
