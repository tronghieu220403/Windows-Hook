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

    DWORD ProcessControl::SetMemoryProtection(unsigned long long virtual_address, unsigned long long size, DWORD new_protection)
    {
        DWORD old_protect;
        return VirtualProtectEx(process_control_handle_, (LPVOID)((unsigned long long)GetBaseAddress() + virtual_address), size, new_protection, &old_protect);
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