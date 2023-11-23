#include <windows.h>
#include <iostream>

using namespace std;

int main()
{

    HMODULE test_dll = LoadLibraryA("E:\\Code\\VS2022\\Test-Dll\\x64\\Release\\Test-Dll");

    cout << (size_t)GetProcAddress(test_dll, "TestFunction") << endl;

    HMODULE test_dll_2 = LoadLibraryA("Test-Dll");
    cout << (size_t)GetProcAddress(test_dll_2, "TestFunction") << endl;

    while(true)
    {
        HANDLE p = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
        CloseHandle(p);
        Sleep(10000);
    }
    return 0;
}