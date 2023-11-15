#pragma once

#ifndef USERMODEHOOK_PESTRUCTURE_PEMEMORY_PE64MEMORY_H_
#define USERMODEHOOK_PESTRUCTURE_PEMEMORY_PE64MEMORY_H_

#include "process/processmemory.h"
#include "ulti/everything.h"
#include "pestructure/idata/importdirectorytable.h"

namespace pe
{
    struct SECTION
    {
        IMAGE_SECTION_HEADER header;
        std::vector<UCHAR> data;
    };

    class PeMemory: public process::ProcessMemory
    {
        private:
            std::vector<UCHAR> data_;

            DWORD entry_point_;
            #ifdef _WIN64
                IMAGE_NT_HEADERS64 nt_headers_64_ = {0};
            #elif _WIN32
                IMAGE_NT_HEADERS32 nt_headers_32_ = {0};
            #endif
            WORD magic_ = 0;
            DWORD iat_rva_ = 0;

            std::shared_ptr<ImportDirectoryTable> idt_ = std::make_shared< ImportDirectoryTable>();

        public:

            PeMemory() = default;
            PeMemory(int pid);;
            PeMemory(const std::string_view& process_name);
            PeMemory(const process::ProcessMemory& process_memory);

            void ReadPeOnMemory();

            bool IsValid();
            bool IsArch64();

            std::vector<UCHAR> GetPeData() const;

            std::shared_ptr<ImportDirectoryTable> GetImportDirectoryTable() const;
            
        protected:
            void SetData(const std::vector<UCHAR> data);
            void SetImportDirectoryTable(const std::shared_ptr<ImportDirectoryTable>& idt);

    };

    DWORD Align(DWORD value, DWORD alignment);
}

#endif