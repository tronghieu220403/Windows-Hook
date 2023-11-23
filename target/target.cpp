#include <windows.h>
#include <ddkernel.h>
#include <iostream>

using namespace std;

int main()
{

    while(true)
    {
        HANDLE p = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
        CloseHandle(p);
        Sleep(1000);
    }

    return 0;
}