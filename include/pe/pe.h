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

    class Pe64OnMemory: public ProcessControl
    {
        private:
            std::vector<UCHAR> data_;

            DWORD entry_point_;
            
            IMAGE_NT_HEADERS64 nt_headers_64_ = {0};

            WORD magic_ = 0;

            DWORD p_iat_ = 0;
        public:

            Pe64OnMemory() = default;
            Pe64OnMemory(const ProcessControl& process_control);

            void ReadPeOnMemory();

            bool IsValid();
            bool IsArch64();

            std::vector<UCHAR> GetData() const;
            void SetData(const std::vector<UCHAR> data);

        protected:

    };

    DWORD Align(DWORD value, DWORD alignment);
}

#endif