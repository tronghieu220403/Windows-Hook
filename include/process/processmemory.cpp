#include "processmemory.h"

namespace process
{

    ProcessMemory::ProcessMemory(int pid):
        ProcessInfo(pid)
    {
        ProcessMemory::Open();
    }

    ProcessMemory::ProcessMemory(const std::string_view &process_name):
        ProcessInfo(process_name)
    {
        ProcessMemory::Open();
    }

    ProcessMemory::ProcessMemory(const ProcessInfo &process_info):
        ProcessInfo(process_info)
    {
        ProcessMemory::Open();
    }

    void ProcessMemory::Open()
    {
        process_memory_handle_ = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetPid());
    }

    void ProcessMemory::Close()
    {
        if (process_memory_handle_ != NULL && process_memory_handle_ != (HANDLE)(-1))
        {
            ::CloseHandle(process_memory_handle_);
            process_memory_handle_ = NULL;
        }
    }

    HANDLE ProcessMemory::GetProcessControlHandle() const
    {
        return process_memory_handle_;
    }

    DWORD ProcessMemory::GetMemoryProtection(void* virtual_address, size_t size)
    {
        MEMORY_BASIC_INFORMATION mem_info = { 0 };

        if (::VirtualQueryEx(process_memory_handle_, (LPVOID)(virtual_address), &mem_info, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
        {
            return mem_info.Protect;
        }

        return 0;
    }

    bool ProcessMemory::SetMemoryProtection(void* virtual_address, size_t size, DWORD new_protection)
    {
        DWORD old_protect;
        return ::VirtualProtectEx(process_memory_handle_, (LPVOID)(virtual_address), size, new_protection, &old_protect) != 0;
    }

    std::vector<UCHAR> ProcessMemory::ReadData(void* virtual_address, size_t size)
    {
        std::vector<UCHAR> buffer(size);
        if (::ReadProcessMemory(process_memory_handle_, (LPVOID)(virtual_address), buffer.data(), size, NULL) == 0)
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

        // First attempt
        if (::WriteProcessMemory(process_memory_handle_, (LPVOID)(virtual_address), data, size, NULL) != 0)
        {
            return true;
        }

        // Second attempt.
        // Howerver, we must change it manually due to some race condition: https://devblogs.microsoft.com/oldnewthing/20190729-00/?p=102737
        DWORD old_protection = ProcessMemory::GetMemoryProtection(virtual_address, size);
        DWORD new_proctection = 0;
        switch (old_protection)
        {
        case PAGE_EXECUTE_READ:
            new_proctection = PAGE_EXECUTE_READWRITE;
            break;
        case PAGE_READONLY:
            new_proctection = PAGE_READWRITE;
            break;
        case PAGE_EXECUTE_READWRITE:
            new_proctection = old_protection;
            break;
        case PAGE_READWRITE:
            new_proctection = old_protection;
            break;
        default:
            break;
        }

        if (new_proctection == 0)
        {
            return false;
        }

        ProcessMemory::SetMemoryProtection(virtual_address, size, new_proctection);
        if (::WriteProcessMemory(process_memory_handle_, (LPVOID)(virtual_address), data, size, NULL) == 0)
        {
            ProcessMemory::SetMemoryProtection(virtual_address, size, old_protection);
            return false;
        }
        ProcessMemory::SetMemoryProtection(virtual_address, size, old_protection);
        return true;
    }

    LPVOID process::ProcessMemory::GetNearestFreeMemory(LPVOID rva, size_t size)
    {
        SYSTEM_INFO sys_info = {};
        MEMORY_BASIC_INFORMATION mbi{};

        if (rva == NULL)
        {
            rva = (LPVOID)GetBaseAddress();
        }

        GetSystemInfo(&sys_info);
        size_t curr_rva = (size_t)rva / sys_info.dwPageSize * sys_info.dwPageSize;

        while (VirtualQueryEx(process_memory_handle_, (LPVOID)curr_rva, &mbi, sizeof(mbi)))
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= size)
            {
                return (LPVOID)mbi.BaseAddress;
            }
            curr_rva += mbi.RegionSize;
        }

        return NULL;
    }

    LPVOID ProcessMemory::MemoryAlloc(size_t size, DWORD protect)
    {
        return ::VirtualAllocEx(process_memory_handle_, NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
    }

    LPVOID ProcessMemory::MemoryAllocNear(LPVOID rva, size_t size, DWORD protect)
    {        
        LPVOID ptr = nullptr;
        SYSTEM_INFO sys_info = {};
        MEMORY_BASIC_INFORMATION mbi{};

        GetSystemInfo(&sys_info);
        size_t curr_rva = (size_t)rva / sys_info.dwPageSize * sys_info.dwPageSize;
        size_t start_rva = curr_rva;

        while (VirtualQueryEx(process_memory_handle_, (LPVOID)curr_rva, &mbi, sizeof(mbi)))
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= size)
            {
                ptr = ::VirtualAllocEx(process_memory_handle_, (LPVOID)curr_rva, size, MEM_COMMIT | MEM_RESERVE, protect);
                if (ptr != NULL)
                {
                    return (LPVOID)mbi.BaseAddress;
                }
            }
            curr_rva += size > sys_info.dwPageSize ? size : sys_info.dwPageSize;
            
            if ((size_t)curr_rva - (size_t)start_rva > (size_t)ULONG_MAX)
            {
                break;
            }

        }

        return ptr;
    }

    bool ProcessMemory::MemoryFree(LPVOID addr)
    {
        return ::VirtualFreeEx(process_memory_handle_, (LPVOID)addr, 0, MEM_RELEASE);
    }

    ProcessMemory::~ProcessMemory()
    {
        ProcessMemory::Close();
    }

    void ProcessMemory::SetProcessMemoryHandle(HANDLE process_control_handle)
    {
        ProcessMemory::Close();
        process_memory_handle_ = process_control_handle;
    }
}