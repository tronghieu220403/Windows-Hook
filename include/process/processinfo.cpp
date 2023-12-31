#include "processinfo.h"

namespace process
{
    ProcessInfo::ProcessInfo(int id):
        Process(id)
    {
        ProcessInfo::OpenProcessInfoHandle();
        ProcessInfo::UpdateBaseAddress();
    }

    ProcessInfo::ProcessInfo(const std::string_view &name):
        Process(name)
    {
        ProcessInfo::OpenProcessInfoHandle();
        ProcessInfo::UpdateBaseAddress();
    }

    size_t ProcessInfo::GetBaseAddress() const
    {
        return base_address_;
    }

    void ProcessInfo::SetBaseAddress(size_t base_address)
    {
        base_address_ = base_address;
    }

    void ProcessInfo::UpdateBaseAddress()
    {
        Process::UpdatePid();
        if (Process::GetPid() == 0)
        {
            return;
        }
        ProcessInfo::UpdateImageFileName();
        ProcessInfo::UpdateProcessModules();
        
        ProcessInfo::SetBaseAddress(0);
        for (auto handle_module: ProcessInfo::GetProcessModules())
        {
            std::string module_name(10000, '\0');
            if (GetModuleFileNameExA(ProcessInfo::GetProcessInfoHandle(), 
                                        handle_module, 
                                        module_name.data(), 10000))
            {
                module_name.resize(strlen(&module_name[0]));
                
                size_t end_of_device = module_name.find("\\", 0);
                
                std::string dos_device_name(10000,'\0');
                ::QueryDosDeviceA(module_name.substr(0, end_of_device).data(), &dos_device_name[0], 10000);
                dos_device_name.resize(strlen(&dos_device_name[0]));

                std::string image_module_name = dos_device_name + module_name.substr(end_of_device, module_name.size());

                if (image_module_name == ProcessInfo::GetImageFileName())
                {
                    MODULEINFO module_info;
                    ::GetModuleInformation(ProcessInfo::GetProcessInfoHandle(), 
                                            handle_module, 
                                            &module_info, sizeof(MODULEINFO));
                    ProcessInfo::SetBaseAddress((size_t)module_info.lpBaseOfDll);
                    break;
                }
            }
        }
    }

    std::string ProcessInfo::GetImageFileName() const
    {
        return image_file_name_;
    }

    void ProcessInfo::SetImageFileName(const std::string_view& image_file_name)
    {
        image_file_name_ = image_file_name;
    }

    void ProcessInfo::UpdateImageFileName()
    {
        if (Process::GetPid() == 0)
        {
            return;
        }
        image_file_name_.resize(10000);
        image_file_name_.resize(::GetProcessImageFileNameA(process_info_handle_, &image_file_name_[0], 10000));
    }

    std::vector<HMODULE> ProcessInfo::GetProcessModules()
    {
        return module_list_;
    }

    void ProcessInfo::SetProcessModules(const std::vector<HMODULE> module_list)
    {
        module_list_ = module_list;
    }

    void ProcessInfo::UpdateProcessModules()
    {
        DWORD size = 0;

        module_list_.resize(10000);

        if (::EnumProcessModules(process_info_handle_, module_list_.data(), 10000, &size) == 0)
        {
            return;
        }
        module_list_.resize( size / sizeof(HMODULE));
    }

    HANDLE ProcessInfo::GetProcessInfoHandle() const
    {
        return process_info_handle_;
    }

    void ProcessInfo::OpenProcessInfoHandle()
    {
        ProcessInfo::CloseProcessInfoHandle();
        process_info_handle_ = OpenProcess(PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ, FALSE,
            Process::GetPid());
    }

    void ProcessInfo::CloseProcessInfoHandle()
    {
        if (process_info_handle_ != 0 && process_info_handle_ != (HANDLE)(-1))
        {
            ::CloseHandle(process_info_handle_);
            process_info_handle_ = 0;
        }
    }

    void ProcessInfo::SetProcessInfoHandle(const HANDLE process_info_handle)
    {
        ProcessInfo::CloseProcessInfoHandle();
        process_info_handle_ = process_info_handle;
    }

    ProcessInfo::~ProcessInfo()
    {
        ProcessInfo::CloseProcessInfoHandle();
    }
}
