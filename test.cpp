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

size_t offset = 0;

void test()
{
    int pid = 1176;
    
    HANDLE process_info_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    LPVOID base_address = NULL;

    string process_name_path(10000, '\0');
    process_name_path.resize(GetProcessImageFileNameA(process_info_handle, &process_name_path[0], 10000));
    process_name_path.resize(strlen(process_name_path.data()));
    // cout << process_name_path << endl;

    vector<HMODULE> module_list(10000);
    DWORD size = 0;

    if (EnumProcessModules(process_info_handle, module_list.data(), 10000, &size) == 0)
    {
        return;
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

    cout << "Target base address: 0x" << hex << base_address << endl;

    size_t addr = (unsigned long long)base_address + offset;

    MEMORY_BASIC_INFORMATION mem_info;

    if (VirtualQueryEx(process_info_handle, (LPVOID)(addr), &mem_info, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
    {
        cout << "Query oke,protection: 0x" << hex << mem_info.Protect << endl;
    }
    else
    {
        cout << "Query failed: " << GetLastError() << endl;
    }

    // VirtualAllocEx() WriteProcessMemory() and ReadProcessMemory()

    DWORD lpflOldProtect;

    if (VirtualProtectEx(process_info_handle, (LPVOID)addr, 0x1000, PAGE_EXECUTE_READWRITE, &lpflOldProtect) == 0)
    {
        cout << "Set protect fail" << " ";
        cout << (ULONG)GetLastError() << endl;
    }
    else
    {
        cout << "Set PAGE_EXECUTE_READWRITE (0x80) success." << endl;
    }
    
    if (VirtualQueryEx(process_info_handle, (LPVOID)((unsigned long long)addr), &mem_info, 1000) != 0)
    {
        cout << "New protection: " << "0x" << hex << mem_info.Protect << endl;
    }

    char c[3];
    size_t n_bytes;
    std::vector<UCHAR> c;
    DWORD image_size = 0x00024000;
    c.resize(image_size);
    MEMORY_BASIC_INFORMATION mem_info;
    
    if (ReadProcessMemory(process_info_handle, (LPVOID)(addr), c.data(), image_size, &n_bytes) == 0)
    {
        cout << "Read false" << endl;
        return;
    }
    else
    {
        cout << "Read: 0x" << hex << n_bytes << " bytes." << endl;
    }
    cout << hex << (ULONG)(c[0]) << endl;
    cout << hex << (ULONG)(c[1]) << endl;

    CloseHandle(process_info_handle);
}

int main()
{
    test();
    return 0;
}