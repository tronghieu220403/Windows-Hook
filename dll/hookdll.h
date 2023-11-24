#pragma once

#include <iostream>
#include <stdarg.h>

#define EXPORT_FUNCTION __declspec(dllexport)

extern "C"
{
	EXPORT_FUNCTION void PrintParameters(int count, ...);
}
