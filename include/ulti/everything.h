#ifndef IATHOOK_ULTI_EVERYTHING_H_
#define IATHOOK_ULTI_EVERYTHING_H_

#include <string.h>
#include <WS2tcpip.h>
#include <TlHelp32.h>
#include <psapi.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <format>
#include <filesystem>

namespace ulti
{

    typedef struct Field
    {
        std::string name;
        ULONGLONG value;
        WORD size;
    } Field, * FieldPtr;

    typedef struct FieldStr
    {
        std::string name;
        std::string value;
    } FieldStr, * FieldStrPtr;

    ULONGLONG MemoryToUint64(const void* data);
    LONGLONG MemoryToInt64(const void* data);
    DWORD MemoryToUint32(const void* data);
    int MemoryToInt32(const void* data);
    WORD MemoryToUint16(const void* data);
    std::string MemoryToString(const void* data);
    std::wstring MemoryToWstring(const WCHAR *data);
    std::wstring MemoryToWstring(const WCHAR *data, int size);
    std::string ToHex(ULONGLONG value);
}




#endif