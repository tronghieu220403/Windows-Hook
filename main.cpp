#include <iostream>

#include "process/processmemory.h"
#include "pestructure/pememory/pe64memory.h"
#include "hook/iathook/iathook.h"

using namespace std;

int main()
{
	hook::IatHook iat_hook("process_sample.exe");
	cout << hex << iat_hook.GetFunctionAddressOnIat("KERNEL32.dll", "OpenProcess") << endl;

	//cout << p.GetImportDirectoryTable()->GetRvaOfFunction("KERNEL32.dll", "OpenProcess");
	

}