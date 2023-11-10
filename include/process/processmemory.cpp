#include "processmemory.h"

namespace process
{

    ProcessMemory::ProcessMemory(int pid):
        ProcessInfo(pid)
    {
        OpenProcessControlHandle();
    }

    ProcessMemory::ProcessMemory(const std::string_view& process_name):
        ProcessInfo(process_name)
    {
        OpenProcessControlHandle();
    }

    ProcessMemory::ProcessMemory(const ProcessInfo &process_info):
        ProcessInfo(process_info)
    {
        OpenProcessControlHandle();
    }

    void ProcessMemory::OpenProcessControlHandle()
    {
        process_control_handle_ = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetPid());
    }

    void ProcessMemory::CloseProcessControlHandle()
    {
        if (process_control_handle_ != NULL && process_control_handle_ != (HANDLE)(-1))
        {
            CloseHandle(process_control_handle_);
            process_control_handle_ = NULL;
        }
    }

    HANDLE ProcessMemory::GetProcessControlHandle() const
    {
        return process_control_handle_;
    }

    DWORD ProcessMemory::GetMemoryProtection(unsigned long long rva, unsigned long long size)
    {
        MEMORY_BASIC_INFORMATION mem_info;

        if (VirtualQueryEx(process_control_handle_, (LPVOID)(GetBaseAddress() + rva), &mem_info, size) != 0)
        {
            return mem_info.Protect;
        }

        return 0;
    }

    bool ProcessMemory::SetMemoryProtection(unsigned long long rva, unsigned long long size, DWORD new_protection)
    {
        DWORD old_protect;
        return VirtualProtectEx(process_control_handle_, (LPVOID)((unsigned long long)GetBaseAddress() + rva), size, new_protection, &old_protect) != 0;
    }

    std::vector<UCHAR> ProcessMemory::ReadData(size_t rva, size_t size)
    {
        std::vector<UCHAR> buffer(size);
        if (ReadProcessMemory(process_control_handle_, (LPVOID)(GetBaseAddress() + rva), buffer.data(), size, NULL) == 0)
        {
            return std::vector<UCHAR>();
        }
        return buffer;
    }

    bool ProcessMemory::WriteData(size_t rva, std::vector<UCHAR> data)
    {
        return ProcessMemory::WriteData(rva, data.data(), data.size());
    }

    bool ProcessMemory::WriteData(size_t rva, const PUCHAR data, size_t size)
    {
        // WriteProcessMemory() internally does change the MemoryProtection to writable if it can not write.
        if (WriteProcessMemory(process_control_handle_, (LPVOID)(GetBaseAddress() + rva), data, size, NULL) == 0)
        {
            return false;
        }
        return true;
    }

    ProcessMemory::~ProcessMemory()
    {
        CloseProcessControlHandle();
    }

    void ProcessMemory::SetProcessControlHandle(HANDLE process_control_handle)
    {
        CloseProcessControlHandle();
        process_control_handle_ = process_control_handle;
    }
}