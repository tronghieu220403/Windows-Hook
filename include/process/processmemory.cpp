#include "processmemory.h"

namespace process
{

    ProcessMemory::ProcessMemory(int pid):
        ProcessInfo(pid)
    {
        OpenProcessControlHandle();
    }

    ProcessMemory::ProcessMemory(const std::string_view &process_name):
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
        process_control_handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetPid());
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
        MEMORY_BASIC_INFORMATION mem_info = { 0 };

        if (VirtualQueryEx(process_control_handle_, (LPVOID)(GetBaseAddress() + rva), &mem_info, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
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

    std::vector<UCHAR> ProcessMemory::ReadData(void* virtual_address, size_t size)
    {
        std::vector<UCHAR> buffer(size);
        if (ReadProcessMemory(process_control_handle_, (LPVOID)(virtual_address), buffer.data(), size, NULL) == 0)
        {
            return std::vector<UCHAR>();
        }
        return buffer;
    }

    bool ProcessMemory::WriteData(void* virtual_address, std::vector<UCHAR> data)
    {
        return ProcessMemory::WriteData(virtual_address, data.data(), data.size());
    }

    bool ProcessMemory::WriteData(void* virtual_address, const PUCHAR data, size_t size)
    {
        // WriteProcessMemory() internally does change the MemoryProtection to writable if it can not write.
        if (WriteProcessMemory(process_control_handle_, (LPVOID)(virtual_address), data, size, NULL) == 0)
        {
            return false;
        }
        return true;
    }

    size_t ProcessMemory::GetNearestFreeMemory()
    {
        return 0;
    }

    LPVOID ProcessMemory::MemoryAlloc(size_t size, DWORD protect)
    {
        return VirtualAllocEx(process_control_handle_, NULL, size, MEM_COMMIT, protect);;
    }

    bool ProcessMemory::MemoryFree(LPVOID addr)
    {
        return VirtualFreeEx(process_control_handle_, (LPVOID)addr, 0, MEM_RELEASE);
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