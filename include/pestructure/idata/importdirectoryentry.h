#ifndef USERMODEHOOK_PESTRUCTURE_IDATA_IMPORTDIRECTORYENTRY_H_
#define USERMODEHOOK_PESTRUCTURE_IDATA_IMPORTDIRECTORYENTRY_H_

#include "ulti/everything.h"
#include "pestructure/idata/importlookuptable.h"

namespace pe
{
    class ImportDirectoryEntry
    {
    private:
        std::vector<ulti::FieldStr> field_str_vector_;
        std::vector<ulti::Field> field_vector_;
        ImportLookupTable import_lookup_table_;
        WORD version_ = 0;
    public:

        ImportDirectoryEntry() = default;
        explicit ImportDirectoryEntry(PUCHAR pe_data, DWORD rva, WORD version);

        void SetVersion(WORD version);

        void SetImportDirectoryEntry(PUCHAR pe_data, DWORD rva);

        std::string GetDllName() const;
        DWORD GetRvaLocationInIatByName(const std::string_view& function_name);

        std::string ToString(int pad);


    };
}

#endif