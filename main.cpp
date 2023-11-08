#include <iostream>

#include "process/processcontrol.h"

using namespace std;

int main()
{
	iathook::ProcessControl p(9688);
	cout << hex << p.GetBaseAddress() << endl;
	DWORD protection = p.GetMemoryProtection(0, 0x1000);
	if (protection == 0)
	{
		cout << "error" << endl << GetLastError();
	}
	else
	{
		cout << hex << nouppercase << protection;
	}

}