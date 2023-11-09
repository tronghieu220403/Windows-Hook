#ifndef IATHOOK_PEHEADER_IMPORTDIRECTORY_IMPORTLOOKUPTABLE_H_
#define IATHOOK_PEHEADER_IMPORTDIRECTORY_IMPORTLOOKUPTABLE_H_

#include "ulti/everything.h"
#include "pestructure/idata/importlookupentry.h"

namespace pe
{
    class ImportLookupTable
    {
    private:
        std::vector<ImportLookupEntry> import_lookup_entry_vector_;
        WORD version_;
    public:

        ImportLookupTable() = default;
        explicit ImportLookupTable(WORD version);
        explicit ImportLookupTable(PUCHAR pe_data, DWORD rva, WORD version);

        void SetVersion(WORD version);

        void SetImportLookupTableData(PUCHAR pe_data, DWORD rva);

        DWORD GetFunctionOrdinal(const std::string_view& function_name);

        std::string ToString(int pad);
        
    };
}

#endif