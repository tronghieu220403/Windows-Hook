#include "hookdll.h"

void PrintNumber(size_t value)
{
    char number[20];
    HANDLE std_output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD bytes_written = 0;

    for (int i = 0; i < 20; i++)
    {
        number[i] = '\0';
    }
    int size = 0;
    while (value > 0)
    {
        number[19 - size] = '0' + value % 10;
        size++;
        value = value / 10;
    }
    if (size == 0)
    {
        size = 1;
        number[19] = '0';
    }

    WriteConsoleA(std_output_handle, number + 20 - size, size, &bytes_written, NULL);

}

void PrintEndline()
{
    char endline[1];
    endline[0] = '\n';
    DWORD bytes_written = 0;
    HANDLE std_output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteConsoleA(std_output_handle, endline, 1, &bytes_written, NULL);
}

EXPORT_FUNCTION void PrintParameters(int count, ...)
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
        /*
        if (value == 0x4141414141414141)
        {
            PrintNumber(i);
            PrintEndline();
            printed++;
        }
        */
        if (i == 63)  // rcx
        {
            PrintNumber(value);
            PrintEndline();
            printed++;
        }
        if (i == 64)  // rdx
        {
            PrintNumber(value);
            PrintEndline();
            printed++;
        }
        if (i == 65)  // r8
        {
            PrintNumber(value);
            PrintEndline();
            printed++;
        }
        if (i == 66)  // r9
        {
            PrintNumber(value);
            PrintEndline();
            printed++;
        }

        // print parameter on the stack
        if (i >= 68)
        {
            PrintNumber(value);
            PrintEndline();
            printed++;
        }
        i++;
    }

    va_end(list);

}

