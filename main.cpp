#include <iostream>

#include "process/processmemory.h"
#include "pestructure/pememory/pe64memory.h"

using namespace std;

int main()
{
	pe::Pe64Memory p(19400);
	cout << hex << p.GetBaseAddress() << endl;
	DWORD protection = p.GetMemoryProtection(0, 0x1000);
	if (protection == 0)
	{
		cout << "error" << endl << (unsigned long)GetLastError();
	}
	else
	{
		cout << hex << nouppercase << protection;
	}

}