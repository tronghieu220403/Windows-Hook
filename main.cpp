#include <iostream>

#include "hook/iathook/iathookclosehandle.h"

using namespace std;

int main()
{
	// Build -> Propertise:
	// Code Generation -> Security Check: Disable Security Check (/GS-)
	// Optimization -> Optimization: /O2
	// Optimization -> Inline Function Expansion: /Ob2

	hook::IatHookCloseHandle iat_hook_close_handle("Test-Process.exe");
	cout << "0x" << hex << iat_hook_close_handle.GetPeMemory()->GetBaseAddress() << endl;
	cout << "0x" << hex << iat_hook_close_handle.GetVirutalAddressOfFunctionOnIat("KERNEL32.dll", "CloseHandle") << endl;
	cout << iat_hook_close_handle.GetBytesCode().size();
	iat_hook_close_handle.HookCloseHandle();
}