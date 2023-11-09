#include "processcontrol.h"

namespace iathook
{

    ProcessControl::ProcessControl(int pid):
        ProcessInfo(pid)
    {
        OpenProcessControlHandle();
    }

    ProcessControl::ProcessControl(const ProcessInfo &process_info):
        ProcessInfo(process_info)
    {
        OpenProcessControlHandle();
    }

    void ProcessControl::OpenProcessControlHandle()
    {
        process_control_handle_ = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetPid());
    }

    void ProcessControl::CloseProcessControlHandle()
    {
        if (process_control_handle_ != NULL && process_control_handle_ != (HANDLE)(-1))
        {
            CloseHandle(process_control_handle_);
            process_control_handle_ = NULL;
        }
    }

    HANDLE ProcessControl::GetProcessControlHandle() const
    {
        return process_control_handle_;
    }

    DWORD ProcessControl::GetMemoryProtection(unsigned long long virtual_address, unsigned long long size)
    {
        MEMORY_BASIC_INFORMATION mem_info;

        if (VirtualQueryEx(process_control_handle_, (LPVOID)(GetBaseAddress() + virtual_address), &mem_info, size) != 0)
        {
            return mem_info.Protect;
        }

        return 0;
    }

    bool ProcessControl::SetMemoryProtection(unsigned long long virtual_address, unsigned long long size, DWORD new_protection)
    {
        DWORD old_protect;
        return VirtualProtectEx(process_control_handle_, (LPVOID)((unsigned long long)GetBaseAddress() + virtual_address), size, new_protection, &old_protect) != 0;
    }

    std::vector<UCHAR> ProcessControl::ReadData(size_t virtual_address, size_t size)
    {
        std::vector<UCHAR> buffer(size);
        if (ReadProcessMemory(process_control_handle_, (LPVOID)(GetBaseAddress() + virtual_address), buffer.data(), size, NULL) == 0)
        {
            return std::vector<UCHAR>();
        }
        return buffer;
    }

    bool ProcessControl::WriteData(size_t virtual_address, std::vector<UCHAR> data)
    {
        return ProcessControl::WriteData(virtual_address, data.data(), data.size());
    }

    bool ProcessControl::WriteData(size_t virtual_address, const PUCHAR data, size_t size)
    {
        // WriteProcessMemory() internally does change the MemoryProtection to writable if it can not write.
        if (WriteProcessMemory(process_control_handle_, (LPVOID)(GetBaseAddress() + virtual_address), data, size, NULL) == 0)
        {
            return false;
        }
        return true;
    }

    ProcessControl::~ProcessControl()
    {
        CloseProcessControlHandle();
    }

    void ProcessControl::SetProcessControlHandle(HANDLE process_control_handle)
    {
        CloseProcessControlHandle();
        process_control_handle_ = process_control_handle;
    }
}