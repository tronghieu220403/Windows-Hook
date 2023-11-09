#ifndef IATHOOK_PESTRUCTURE_IDATA_HINTNAMEENTRY_H_
#define IATHOOK_PESTRUCTURE_IDATA_HINTNAMEENTRY_H_

#include "ulti/everything.h"
#include "pestructure/idata/hintnameentry.h"

namespace pe
{
    class HintNameEntry
    {
    private:
        ulti::Field hint_;
        ulti::FieldStr name_;
        int pad_ = 1;
    public:

        HintNameEntry() = default;
        explicit HintNameEntry(PUCHAR pe_data, DWORD rva);

        void SetHintNameEntry(PUCHAR pe_data, DWORD rva);

        ulti::Field GetHintField() const;
        ulti::FieldStr GetNameField() const;
        int GetSize() const;

        std::string ToString(int pad);
        
    };
}

#endif