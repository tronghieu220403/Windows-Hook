#include "everything.h"

namespace ulti
{
    ULONGLONG MemoryToUint64(const void* data)
    {
        ULONGLONG res = 0;
        memcpy(&res, data, 8);
        return res;
    }

    LONGLONG MemoryToInt64(const void* data)
    {
        LONGLONG res = 0;
        memcpy(&res, data, 8);
        return res;
    }

    DWORD MemoryToUint32(const void* data)
    {
        DWORD res = 0;
        memcpy(&res, data, 4);
        return res;
    }

    int MemoryToInt32(const void* data)
    {
        int res = 0;
        memcpy(&res, data, 4);
        return res;
    }

    WORD MemoryToUint16(const void* data)
    {
        int res = 0;
        memcpy(&res, data, 2);
        return res;
    }

    std::string MemoryToString(const void* data)
    {
        std::string res;
        char* string_data = (char *)data;
        for (int i = 0; string_data[i] != 0; i++)
        {
            res.push_back(char(string_data[i]));
        }
        return res;
    }

    std::wstring MemoryToWstring(const void *data)
    {
        std::wstring res;
        char* wstring_data = (char *)data;
        for (int i = 0; wstring_data[i] != 0; i++)
        {
            res.push_back(WCHAR(wstring_data[i]));
        }
        return res;
    }

    std::wstring MemoryToWstring(const void *data, int size)
    {
        std::wstring res;
        char* wstring_data = (char *)data;
        for (int i = 0; i < size; i++)
        {
            res.push_back(WCHAR(wstring_data[i]));
        }
        return res;
    }

    std::string ToHex(ULONGLONG value)
    {
        return "0x" + std::format("{:x}", value);
    }

}