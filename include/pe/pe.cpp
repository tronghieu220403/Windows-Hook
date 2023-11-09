#include "pe/pe.h"
#include "pe.h"

namespace iathook
{

    Pe64OnMemory::Pe64OnMemory(const ProcessControl& process_control):
        ProcessControl(process_control)
    {
        ReadPeOnMemory();
    }

    void Pe64OnMemory::ReadPeOnMemory()
    {
        std::vector<UCHAR> dos_header_data = ProcessControl::ReadData(0, sizeof(IMAGE_DOS_HEADER));
        if (dos_header_data.size() != sizeof(IMAGE_DOS_HEADER))
        {
            return;
        }
        DWORD e_lfanew = ((PIMAGE_DOS_HEADER)dos_header_data.data())->e_lfanew;

        std::vector<UCHAR> p_nt_headers_data = ProcessControl::ReadData(e_lfanew, sizeof(IMAGE_NT_HEADERS64));

        magic_ = ((PIMAGE_NT_HEADERS64)p_nt_headers_data.data())->OptionalHeader.Magic;
        if (magic_ != 0x20b)
        {
            return;
        }
        
        memcpy(&nt_headers_64_, p_nt_headers_data.data(), sizeof(IMAGE_NT_HEADERS64));

        p_iat_ = nt_headers_64_.OptionalHeader.DataDirectory[1].VirtualAddress;
    }

    bool Pe64OnMemory::IsValid()
    {
        return false;
    }

    bool Pe64OnMemory::IsArch64()
    {
        return false;
    }

    std::vector<UCHAR> Pe64OnMemory::GetData() const
    {
        return data_;
    }

    void Pe64OnMemory::SetData(const std::vector<UCHAR> data)
    {
        data_ = data;
    }

    DWORD Align(DWORD value, DWORD alignment)
    {
        return 0;
    }

}
