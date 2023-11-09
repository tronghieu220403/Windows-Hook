#pragma once

#ifndef IATHOOK_PE_PE_H_
#define IATHOOK_PE_PE_H_

#include "process/processcontrol.h"
#include "ulti/everything.h"

namespace iathook
{
    struct SECTION
    {
        IMAGE_SECTION_HEADER header;
        std::vector<UCHAR> data;
    };

    class PeOnMemory: public ProcessControl
    {
        private:
            std::vector<UCHAR> data_;

            DWORD entry_point_;
            WORD magic_;
            
        public:

            PeOnMemory() = default;
            PeOnMemory(const ProcessControl& process_control);

            std::vector<UCHAR> GetData() const;
            void SetData(const std::vector<UCHAR> data);
        
        protected:

    };

    DWORD Align(DWORD value, DWORD alignment);
}

#endif