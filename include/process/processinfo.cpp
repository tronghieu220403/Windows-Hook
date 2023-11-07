#include "processinfo.h"

namespace iathook
{
    ProcessInfo::ProcessInfo(int id):
        Process(id), process_info_handle_(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetPid()))
    {
    }

    ProcessInfo::ProcessInfo(const std::string_view &name):
        Process(name), process_info_handle_(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetPid()))
    {
    }

    unsigned long long ProcessInfo::GetBaseAddress() const
    {
        return base_address_;
    }

    void ProcessInfo::SetBaseAddress(unsigned long long base_address)
    {
        base_address_ = base_address;
    }

    void ProcessInfo::UpdateBaseAddress()
    {
        Process::UpdatePid();
        UpdateImageFileName();
        std::vector<HMODULE> module_list = GetProcessModules();

        for (auto handle_module: module_list)
        {
            std::string module_name(10000, '\0');
            if (GetModuleFileNameExA(
                        ProcessInfo::GetProcessInfoHandle(), 
                        handle_module, 
                        module_name.data(), 10000))
            {
                module_name.resize(strlen(&module_name[0]));
                
                int end_of_device = module_name.find("\\", 0);
                
                std::string dos_device_name(10000,'\0');
                QueryDosDeviceA(module_name.substr(0, end_of_device).data(), &dos_device_name[0], 10000);
                dos_device_name.resize(strlen(&dos_device_name[0]));

                std::string image_module_name = dos_device_name + module_name.substr(end_of_device, module_name.size());

                if (image_module_name == image_file_name_)
                {
                    MODULEINFO module_info;
                    GetModuleInformation(
                            ProcessInfo::GetProcessInfoHandle(), 
                            handle_module, 
                            &module_info, sizeof(MODULEINFO));
                    SetBaseAddress((unsigned long long)module_info.lpBaseOfDll);
                    break;
                }
            }
        }
    }

    std::string ProcessInfo::GetImageFileName() const
    {
        return image_file_name_;
    }

    void ProcessInfo::SetImageFileName(std::string image_file_name)
    {
        image_file_name_ = image_file_name;
    }
    
    void ProcessInfo::UpdateImageFileName()
    {
        std::string image_file_name(10000,0);

        image_file_name.resize(GetProcessImageFileNameA(process_info_handle_, &image_file_name[0], 10000));
    }

    std::vector<HMODULE> ProcessInfo::GetProcessModules()
    {
        std::vector<HMODULE> module_list(10000);
        DWORD size = 0;

        if (EnumProcessModules(process_info_handle_, module_list.data(), 10000, &size) == 0)
        {
            return std::vector<HMODULE>();
        }
        module_list.resize( size / sizeof(HMODULE));
        return module_list;
    }

    HANDLE ProcessInfo::GetProcessInfoHandle() const
    {
        return process_info_handle_;
    }

    ProcessInfo::~ProcessInfo()
    {
        if (process_info_handle_ != 0 && process_info_handle_ != (HANDLE)(-1))
        {
            CloseHandle(process_info_handle_);
        }
    }
}
