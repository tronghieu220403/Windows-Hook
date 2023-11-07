#include "ulti/everything.h"

using namespace std;

int main()
{
    int pid = 28108;
    HANDLE process_info_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    string process_name_path(10000, '\0');
    process_name_path.resize(GetProcessImageFileNameA(process_info_handle, &process_name_path[0], 10000));
    process_name_path.resize(strlen(process_name_path.data()));
    cout << process_name_path << endl << endl;

    vector<HMODULE> module_list(10000);
    DWORD size = 0;

    if (EnumProcessModules(process_info_handle, module_list.data(), 10000, &size) == 0)
    {
        return 0;
    }
    module_list.resize( size / sizeof(HMODULE));
    for (auto handle_module: module_list)
    {
        string module_name(10000, '\0');
        if ( GetModuleFileNameExA( process_info_handle, handle_module, module_name.data(), 10000))
        {
            module_name.resize(strlen(&module_name[0]));
            int end_of_device = module_name.find("\\", 0);
            
            std::string dos_device_name(10000,'\0');
            QueryDosDeviceA(module_name.substr(0, end_of_device).data(), &dos_device_name[0], 10000);
            dos_device_name.resize(strlen(&dos_device_name[0]));

            std::string image_file_name = dos_device_name + module_name.substr(end_of_device, module_name.size());

            if (image_file_name == process_name_path)
            {
                MODULEINFO module_info;
                GetModuleInformation(process_info_handle, handle_module, &module_info, sizeof(MODULEINFO));
                cout << hex << module_info.lpBaseOfDll << endl;
                break;
            }
        }

    }

    CloseHandle(process_info_handle);
}