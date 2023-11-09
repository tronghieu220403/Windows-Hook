#ifndef IATHOOK_PESTRUCTURE_IDATA_HINTNAMETABLE_H_
#define IATHOOK_PESTRUCTURE_IDATA_HINTNAMETABLE_H_

#include "ulti/everything.h"
#include "pestructure/idata/hintnameentry.h"

namespace pe
{
    class HintNameTable
    {
    private:
        std::vector<HintNameEntry> entry_vector_;
    public:

        HintNameTable() = default;
        explicit HintNameTable(PUCHAR pe_data, DWORD rva);

        void SetHintNameTable(PUCHAR pe_data, DWORD rva);

        std::string ToString(int pad);
        
    };
}

#endif