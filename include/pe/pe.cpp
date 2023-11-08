#include "pe/pe.h"
#include "pe.h"

namespace pe
{
    PeOnMemory::PeOnMemory(const PUCHAR data)
    {
        
    }

    std::vector<UCHAR> PeOnMemory::GetData() const
    {
        return data_;
    }

    void PeOnMemory::SetData(const std::vector<UCHAR> data)
    {
        data_ = data;
    }

    void PeOnMemory::FlushChange()
    {

    }
}
DWORD pe::Align(DWORD value, DWORD alignment)
{
    return 0;
}
