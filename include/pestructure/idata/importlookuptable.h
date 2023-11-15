#ifndef USERMODEHOOK_PESTRUCTURE_IMPORTDIRECTORY_IMPORTLOOKUPTABLE_H_
#define USERMODEHOOK_PESTRUCTURE_IMPORTDIRECTORY_IMPORTLOOKUPTABLE_H_

#include "ulti/everything.h"
#include "pestructure/idata/importlookupentry.h"

namespace pe
{
    class ImportLookupTable
    {
    private:
        std::vector<ImportLookupEntry> import_lookup_entry_vector_;
        WORD version_ = 0;
    public:

        ImportLookupTable() = default;
        explicit ImportLookupTable(WORD version);
        explicit ImportLookupTable(PUCHAR pe_data, DWORD rva, WORD version);

        DWORD GetFunctionOrdinal(const std::string_view &function_name);

        void SetVersion(WORD version);

        void SetImportLookupTableData(PUCHAR pe_data, DWORD rva);

        std::string ToString(int pad);
        
    };
}

#endif