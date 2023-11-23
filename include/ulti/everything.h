#ifndef IATHOOK_ULTI_EVERYTHING_H_
#define IATHOOK_ULTI_EVERYTHING_H_

#include <string.h>
#include <WS2tcpip.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <imagehlp.h>
#include <Windows.h>

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
    long MemoryToInt32(const void* data);
    WORD MemoryToUint16(const void* data);
    std::string MemoryToString(const void* data);
    std::wstring MemoryToWstring(const void *data);
    std::wstring MemoryToWstring(const void *data, int size);
    std::string ToHex(ULONGLONG value);

    template <typename T> void InsertVector(std::vector<T>& dst, size_t location, const std::vector<T>& src)
    {
        if (location > dst.size())
        {
            return;
        }
        long long dst_old_size = dst.size();
        dst.resize(dst.size() + src.size());
        for (long long i = dst_old_size - 1; i >= (long long)location; i--)
        {
            dst[i + src.size()] = dst[i];
        }
        memcpy(&dst[location], &src[0], src.size() * sizeof(T));
    }
}

#endif