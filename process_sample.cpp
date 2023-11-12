#include <windows.h>

using namespace std;

int main()
{
    while(true)
    {
        HANDLE p = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, 10820);
        CloseHandle(p);
        Sleep(10000);
    }
    return 0;
}