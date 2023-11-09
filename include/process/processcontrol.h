#ifndef IATHOOK_PROCESS_PROCESSCONTROL_H_
#define IATHOOK_PROCESS_PROCESSCONTROL_H_

#include "process/processinfo.h"
#include "ulti/everything.h"

namespace iathook
{
	class ProcessControl: public ProcessInfo 
    {
	private:
		ULONGLONG base_address_ = 0;
        std::string image_file_name_;
        HANDLE process_control_handle_ = 0;
        std::vector<HMODULE> module_list_;
	public:

		ProcessControl() = default;
		explicit ProcessControl(int pid);
		explicit ProcessControl(const ProcessInfo& process_info);

        void OpenProcessControlHandle();
        void CloseProcessControlHandle();
        HANDLE GetProcessControlHandle() const;

        DWORD GetMemoryProtection(unsigned long long virtual_address, unsigned long long size);
        bool SetMemoryProtection(unsigned long long virtual_address, unsigned long long size, DWORD new_protection);

        std::vector<UCHAR> ReadData(size_t virtual_address, size_t size);
        bool WriteData(size_t virtual_address, std::vector<UCHAR> data);
        bool WriteData(size_t virtual_address, const PUCHAR data, size_t size);

        ~ProcessControl();

    protected:
        void SetProcessControlHandle(HANDLE process_control_handle);
	};
}

#endif