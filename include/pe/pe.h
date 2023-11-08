#pragma once

#ifndef IATHOOK_PE_PE_H_
#define IATHOOK_PE_PE_H_

#include "ulti/everything.h"

namespace pe
{
    struct SECTION
    {
        IMAGE_SECTION_HEADER header;
        std::vector<UCHAR> data;
    };

    class PeOnMemory
    {
        private:
            std::vector<UCHAR> data_;
            std::string name_;

            DWORD entry_point_;
            WORD magic_;
            
        public:

            PeOnMemory() = default;
            PeOnMemory(const PUCHAR data);

            std::vector<UCHAR> GetData() const;
            void SetData(const std::vector<UCHAR> data);

            void FlushChange();
        
        protected:

    };

    DWORD Align(DWORD value, DWORD alignment);
}

#endif