#ifndef USERMODEHOOK_PROCESS_PROCESSMEMORY_H_
#define USERMODEHOOK_PROCESS_PROCESSMEMORY_H_

#include "process/processinfo.h"
#include "ulti/everything.h"

namespace process
{
	class ProcessMemory: public ProcessInfo 
    {
	private:
    
        std::string image_file_name_;
        HANDLE process_memory_handle_ = 0;
        std::vector<HMODULE> module_list_;

	public:

		ProcessMemory() = default;
		explicit ProcessMemory(int pid);
        explicit ProcessMemory(const std::string_view& process_name);
		explicit ProcessMemory(const ProcessInfo& process_info);

        void Open();
        void Close();

        DWORD GetMemoryProtection(void* rva, size_t size);
        bool SetMemoryProtection(void* rva, size_t size, DWORD new_protection);

        std::vector<UCHAR> ReadData(void* rva, size_t size);
        bool WriteData(void* rva, std::vector<UCHAR> data);
        bool WriteData(void* rva, const PUCHAR data, size_t size);

        LPVOID GetNearestFreeMemory(LPVOID rva, size_t size);
        LPVOID MemoryAlloc(size_t size, DWORD protect);
        LPVOID MemoryAllocNear(LPVOID rva, size_t size, DWORD protect);
        bool MemoryFree(LPVOID addr);

        ~ProcessMemory();

    protected:
        void SetProcessMemoryHandle(HANDLE process_control_handle);
        HANDLE GetProcessControlHandle() const;
	};
}

#endif