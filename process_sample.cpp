#include <windows.h>

using namespace std;

int main()
{
    while(true)
    {
        CloseHandle(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, 8272));
        Sleep(10000);
    }
    return 0;
}