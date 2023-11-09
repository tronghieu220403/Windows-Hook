#include "pe/pe.h"
#include "pe.h"

namespace iathook
{

    PeOnMemory::PeOnMemory(const ProcessControl& process_control):
        ProcessControl(process_control)
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
    DWORD Align(DWORD value, DWORD alignment)
    {
        return 0;
    }

}
