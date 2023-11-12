#ifndef IATHOOK_PROCESS_PROCESSMMEMORY_H_
#define IATHOOK_PROCESS_PROCESSMMEMORY_H_

#include "process/processinfo.h"
#include "ulti/everything.h"

namespace process
{
	class ProcessMemory: public ProcessInfo 
    {
	private:
    
        std::string image_file_name_;
        HANDLE process_control_handle_ = 0;
        std::vector<HMODULE> module_list_;

	public:

		ProcessMemory() = default;
		explicit ProcessMemory(int pid);
        explicit ProcessMemory(const std::string_view& process_name);
		explicit ProcessMemory(const ProcessInfo& process_info);

        void OpenProcessControlHandle();
        void CloseProcessControlHandle();
        HANDLE GetProcessControlHandle() const;

        DWORD GetMemoryProtection(size_t rva, size_t size);
        bool SetMemoryProtection(size_t rva, size_t size, DWORD new_protection);

        std::vector<UCHAR> ReadData(void* virtual_address, size_t size);
        bool WriteData(void* virtual_address, std::vector<UCHAR> data);
        bool WriteData(void* virtual_address, const PUCHAR data, size_t size);

        size_t GetNearestFreeMemory();
        LPVOID MemoryAlloc(size_t size, DWORD protect);
        bool MemoryFree(LPVOID addr);

        ~ProcessMemory();

    protected:
        void SetProcessControlHandle(HANDLE process_control_handle);
	};
}

#endif