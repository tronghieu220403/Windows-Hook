// Build -> Propertises:
// Code Generation -> Security Check: Disable Security Check (/GS-)
// Optimization -> Optimization: /O2
// Optimization -> Inline Function Expansion: /Ob2

#include <iostream>

#include "hook/iathook/iathookclosehandle.h"

int main()
{
	hook::IatHookCloseHandle iat_hook_close_handle("victim.exe");
	iat_hook_close_handle.HookCloseHandle();
}