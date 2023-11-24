#include "hookdll.h"

EXPORT_FUNCTION void PrintParameters(int count)
{
    using namespace std;
    va_list list;
    int i = 0;
    int printed = 0;

    va_start(list, count);
    while (printed < count)
    {
        size_t value = va_arg(list, size_t);

        // print parameter saved on register
        // should define position of the register for both x86 and x64
        if (i == ? ? )  // rcx
        {
            cout << hex << value << endl;
        }
        if (i == ? ? )  // rdx
        {
            cout << hex << value << endl;
        }
        if (i == ? ? )  // r8
        {
            cout << hex << value << endl;
        }
        if (i == ? ? )  // r9
        {
            cout << hex << value << endl;
        }

        // print parameter on the stack
        if (i >= ? ? )
        {
            cout << hex << value << endl;
            i++;
        }
    }

    va_end(list);

}

