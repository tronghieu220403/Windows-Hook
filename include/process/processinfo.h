#ifndef IATHOOK_PROCESS_PROCESSINFO_H_
#define IATHOOK_PROCESS_PROCESSINFO_H_

#include "process/process.h"
#include "ulti/everything.h"

namespace process
{
	class ProcessInfo: public Process 
    {
	private:
		unsigned long long base_address_ = 0;
        std::string image_file_name_;
        HANDLE process_info_handle_;
        std::vector<HMODULE> module_list_;
	public:

		ProcessInfo() = default;
		explicit ProcessInfo(int id);
		explicit ProcessInfo(const std::string_view& name);
		
        unsigned long long GetBaseAddress() const;
        void UpdateBaseAddress();

        std::string GetImageFileName() const;
        void UpdateImageFileName();

        std::vector<HMODULE> GetProcessModules();
        void UpdateProcessModules();

        HANDLE GetProcessInfoHandle() const;
        void CloseProcessInfoHandle();

        ~ProcessInfo();

    protected:
        void SetBaseAddress(unsigned long long base_address);
        void SetImageFileName(const std::string_view& image_file_name);
        void SetProcessModules(const std::vector<HMODULE> module_list);
        void SetProcessInfoHandle(const HANDLE process_info_handle);
	};
}

#endif