#ifndef IATHOOK_PESTRUCTURE_IDATA_IMPORTLOOKUPENTRY_H_
#define IATHOOK_PESTRUCTURE_IDATA_IMPORTLOOKUPENTRY_H_

#include "ulti/everything.h"
#include "pestructure/idata/hintnametable.h"

namespace pe
{
    class ImportLookupEntry
    {
    private:
        std::vector<ulti::Field> field_vector_;
        HintNameTable entry_;
        WORD version_;
    public:

        ImportLookupEntry() = default;
        explicit ImportLookupEntry(WORD version);
        explicit ImportLookupEntry(PUCHAR pe_data, DWORD rva, WORD version);

        void SetVersion(WORD version);

        void SetImportLookupEntryData(PUCHAR pe_data, DWORD rva);

        bool IsOrdinalFlag() const;
        bool IsNameFlag() const;

        

        ulti::Field GetFieldByName(const std::string& name);

        std::string ToString(int pad);
        
    };
}

#endif