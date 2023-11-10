#ifndef IATHOOK_PESTRUCTURE_IDATA_IMPORTDIRECTORYTABLE_H_
#define IATHOOK_PESTRUCTURE_IDATA_IMPORTDIRECTORYTABLE_H_

#include "ulti/everything.h"
#include "pestructure/idata/importdirectoryentry.h"

namespace pe
{
    class ImportDirectoryTable
    {
    private:
        std::vector<ImportDirectoryEntry> entry_vector_;
        WORD version_ = 0;
    public:

        ImportDirectoryTable() = default;
        explicit ImportDirectoryTable(PUCHAR pe_data, DWORD rva, WORD version);

        void SetVersion(WORD version);

        void SetImportDirectoryTableData(PUCHAR pe_data, DWORD rva);

        DWORD GetRvaOfFunction(const std::string_view& dll_name, const std::string_view& function_name);

        std::string ToString(int pad);

    };
}

#endif