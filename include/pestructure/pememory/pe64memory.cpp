#include "pe64memory.h"

namespace pe
{
    Pe64Memory::Pe64Memory(int pid):
        process::ProcessMemory(pid)
    {
        ReadPeOnMemory();
    }

    Pe64Memory::Pe64Memory(const std::string_view &process_name):
        process::ProcessMemory(process_name)
    {
        ReadPeOnMemory();
    }

    Pe64Memory::Pe64Memory(const process::ProcessMemory& process_control):
        process::ProcessMemory(process_control)
    {
        ReadPeOnMemory();
    }

    void Pe64Memory::ReadPeOnMemory()
    {
        std::vector<UCHAR> dos_header_data = process::ProcessMemory::ReadData(0, sizeof(IMAGE_DOS_HEADER));
        if (dos_header_data.size() != sizeof(IMAGE_DOS_HEADER))
        {
            return;
        }
        DWORD e_lfanew = ((PIMAGE_DOS_HEADER)dos_header_data.data())->e_lfanew;

        std::vector<UCHAR> p_nt_headers_data = process::ProcessMemory::ReadData(e_lfanew, sizeof(IMAGE_NT_HEADERS64));

        magic_ = ((PIMAGE_NT_HEADERS64)p_nt_headers_data.data())->OptionalHeader.Magic;
        if (magic_ != 0x20b)
        {
            return;
        }
        
        memcpy(&nt_headers_64_, p_nt_headers_data.data(), sizeof(IMAGE_NT_HEADERS64));

        iat_rva_ = nt_headers_64_.OptionalHeader.DataDirectory[1].VirtualAddress;

        // Read all data of pe to _data vector
        DWORD size = nt_headers_64_.OptionalHeader.SizeOfImage;
        data_ = ProcessMemory::ReadData(0, size);

        // Create Import Directory Table info field
        idt_ = std::make_shared<ImportDirectoryTable>(data_.data(), iat_rva_, magic_);
    }

    bool Pe64Memory::IsValid()
    {
        return true;
    }

    bool Pe64Memory::IsArch64()
    {
        return magic_ == 0x20b;
    }

    std::vector<UCHAR> Pe64Memory::GetData() const
    {
        return data_;
    }

    std::shared_ptr<ImportDirectoryTable> Pe64Memory::GetImportDirectoryTable() const
    {
        return idt_;
    }

    void Pe64Memory::SetData(const std::vector<UCHAR> data)
    {
        data_ = data;
    }

    void Pe64Memory::SetImportDirectoryTable(const std::shared_ptr<ImportDirectoryTable> &idt)
    {
        idt_ = idt;
    }

    DWORD Align(DWORD value, DWORD alignment)
    {
        return 0;
    }

}
