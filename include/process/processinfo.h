#ifndef IATHOOK_PROCESS_PROCESSINFO_H_
#define IATHOOK_PROCESS_PROCESSINFO_H_

#define UNICODE
#define _UNICODE

#include "process/process.h"
#include "ulti/everything.h"

namespace iathook
{
	class ProcessInfo: public Process {
	private:
		unsigned long long base_address_ = 0;
        std::string image_file_name_;
        HANDLE process_info_handle_;
	public:

		ProcessInfo() = default;
		explicit ProcessInfo(int id);
		explicit ProcessInfo(const std::string_view& name);
		
        unsigned long long GetBaseAddress() const;
        void UpdateBaseAddress();

        std::string GetImageFileName() const;
        void UpdateImageFileName();

        std::vector<HMODULE> GetProcessModules();

        HANDLE GetProcessInfoHandle() const;

        ~ProcessInfo();
    protected:
        void SetBaseAddress(unsigned long long base_address);
        void SetImageFileName(std::string image_file_name);
	};
}

#endif