#include <string.h>
#include <WS2tcpip.h>
#include <TlHelp32.h>
#include <psapi.h>

#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>

using namespace std;

int main()
{
    int pid = 9688;
    HANDLE process_info_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    LPVOID base_address = NULL;

    string process_name_path(10000, '\0');
    process_name_path.resize(GetProcessImageFileNameA(process_info_handle, &process_name_path[0], 10000));
    process_name_path.resize(strlen(process_name_path.data()));
    // cout << process_name_path << endl;

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
                base_address = module_info.lpBaseOfDll;
                break;
            }
        }

    }

    cout << base_address << endl;

    MEMORY_BASIC_INFORMATION mem_info;

    if (VirtualQueryEx(process_info_handle, (LPVOID)((unsigned long long)base_address), &mem_info, 1000) != 0)
    {
        cout << "0x" << hex << mem_info.AllocationProtect << endl;
        cout << "0x" << hex << mem_info.Protect << endl;
    }
    else
    {
        cout << "Failed: " << GetLastError() << endl;
    }
    
    // VirtualAllocEx() WriteProcessMemory() and ReadProcessMemory()

    // char c = *(char *)((LPVOID)base_address);
    // cout << c << endl;

    /*
    DWORD lpflOldProtect;

    if (VirtualProtectEx(process_info_handle, (LPVOID)((unsigned long long)base_address), 0x1000, PAGE_READONLY, &lpflOldProtect) == 0)
    {
        cout << "false" << endl;
        cout << GetLastError() << endl;
    }
    else
    {
        cout << "true" << endl;
        cout << "0x" << hex << lpflOldProtect << endl;
    }

    if (VirtualQueryEx(process_info_handle, (LPVOID)((unsigned long long)base_address), &mem_info, 1000) != 0)
    {
        cout << "0x" << hex << mem_info.AllocationProtect << endl;
    }
    */
    CloseHandle(process_info_handle);
}