/*
* Use the following pre define: ZYDIS_STATIC_BUILD; ZYCORE_STATIC_BUILD

* Build -> Propertises:
* C/C++ -> Output Files -> Object File Name: $(IntDir)%(RelativeDir)
* Code Generation -> Security Check: Disable Security Check (/GS-)
* Optimization -> Optimization: /O2
* Optimization -> Inline Function Expansion: /Ob2
*/

#include <iostream>

#include "hook/iathook/iathookclosehandle.h"
#include "hook/inlinehook/inlinehookclosehandle.h"

void IatHook()
{
	hook::IatHookCloseHandle iat_hook_close_handle("Test-Process.exe");
	iat_hook_close_handle.HookCloseHandle();
}

void InlineHook()
{
	hook::InlineHookCloseHandle inline_hook_close_handle("Test-Process.exe");
	inline_hook_close_handle.hook::Hook::SetHookDllPath("hieu.dll");
	if (inline_hook_close_handle.InlineHook::StartHook() == false)
	{
		std::cout << "Hook error" << std::endl;
	}
}

int main()
{
	InlineHook();
}