#ifndef IATHOOK_PROCESS_PROCESSMMEMORY_H_
#define IATHOOK_PROCESS_PROCESSMMEMORY_H_

#include "process/processinfo.h"
#include "ulti/everything.h"

namespace process
{
	class ProcessMemory: public ProcessInfo 
    {
	private:
    
		ULONGLONG base_address_ = 0;
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

        DWORD GetMemoryProtection(unsigned long long rva, unsigned long long size);
        bool SetMemoryProtection(unsigned long long rva, unsigned long long size, DWORD new_protection);

        std::vector<UCHAR> ReadData(size_t rva, size_t size);
        bool WriteData(size_t rva, std::vector<UCHAR> data);
        bool WriteData(size_t rva, const PUCHAR data, size_t size);

        ~ProcessMemory();

    protected:
        void SetProcessControlHandle(HANDLE process_control_handle);
	};
}

#endif