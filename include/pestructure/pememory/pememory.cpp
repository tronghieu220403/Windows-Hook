#include "pememory.h"

namespace pe
{
    PeMemory::PeMemory(int pid):
        process::ProcessMemory(pid)
    {
        ReadPeOnMemory();
    }

    PeMemory::PeMemory(const std::string_view &process_name):
        process::ProcessMemory(process_name)
    {
        ReadPeOnMemory();
    }

    PeMemory::PeMemory(const process::ProcessMemory& process_control):
        process::ProcessMemory(process_control)
    {
        ReadPeOnMemory();
    }

    void PeMemory::ReadPeOnMemory()
    {
        std::vector<UCHAR> dos_header_data = process::ProcessMemory::ReadData((void* )ProcessMemory::GetBaseAddress(), sizeof(IMAGE_DOS_HEADER));
        if (dos_header_data.size() != sizeof(IMAGE_DOS_HEADER))
        {
            return;
        }
        DWORD e_lfanew = ((PIMAGE_DOS_HEADER)dos_header_data.data())->e_lfanew;

        std::vector<UCHAR> p_nt_headers_data = process::ProcessMemory::ReadData((void *)(process::ProcessMemory::GetBaseAddress() + e_lfanew), sizeof(IMAGE_NT_HEADERS64));

        #ifdef _WIN64
            magic_ = ((PIMAGE_NT_HEADERS64)p_nt_headers_data.data())->OptionalHeader.Magic;
            if (magic_ != 0x20b)
            {
                return;
            }
            
            memcpy(&nt_headers_64_, p_nt_headers_data.data(), sizeof(IMAGE_NT_HEADERS64));

            iat_rva_ = nt_headers_64_.OptionalHeader.DataDirectory[1].VirtualAddress;

            // Read all data of pe to _data vector
            DWORD size = nt_headers_64_.OptionalHeader.SizeOfImage;
            data_ = ProcessMemory::ReadData((void* )ProcessMemory::GetBaseAddress(), size);

            // Create Import Directory Table info field
            idt_ = std::make_shared<ImportDirectoryTable>(data_.data(), iat_rva_, magic_);
        #elif _WIN32
            magic_ = ((PIMAGE_NT_HEADERS32)p_nt_headers_data.data())->OptionalHeader.Magic;
            if (magic_ != 0x10b)
            {
                return;
            }
            
            memcpy(&nt_headers_32_, p_nt_headers_data.data(), sizeof(IMAGE_NT_HEADERS32));

            iat_rva_ = nt_headers_32_.OptionalHeader.DataDirectory[1].VirtualAddress;

            // Read all data of pe to _data vector
            DWORD size = nt_headers_32_.OptionalHeader.SizeOfImage;
            data_ = ProcessMemory::ReadData((void* )ProcessMemory::GetBaseAddress(), size);

            // Create Import Directory Table info field
            idt_ = std::make_shared<ImportDirectoryTable>(data_.data(), iat_rva_, magic_);

        #endif
    }

    bool PeMemory::IsValid()
    {
        return true;
    }

    bool PeMemory::IsArch64()
    {
        return magic_ == 0x20b;
    }

    std::vector<UCHAR> PeMemory::GetPeData() const
    {
        return data_;
    }

    std::shared_ptr<ImportDirectoryTable> PeMemory::GetImportDirectoryTable() const
    {
        return idt_;
    }

    void PeMemory::SetData(const std::vector<UCHAR> data)
    {
        data_ = data;
    }

    void PeMemory::SetImportDirectoryTable(const std::shared_ptr<ImportDirectoryTable> &idt)
    {
        idt_ = idt;
    }

    DWORD Align(DWORD value, DWORD alignment)
    {
        return 0;
    }

}
