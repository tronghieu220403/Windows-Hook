#include <iostream>

#include "hook/iathook/iathookclosehandle.h"

using namespace std;

int main()
{
	hook::IatHookCloseHandle iat_hook_close_handle("process_sample.exe");
	// cout << hex << iat_hook_close_handle.GetFunctionRvaOnIat("KERNEL32.dll", "CloseHandle") << endl;
	vector<UCHAR> bytes_code = iat_hook_close_handle.GetBytesCode();

	for (int i = 0; i < bytes_code.size(); i++)
	{
		cout << hex << bytes_code[i] << " ";
		if (i % 16 == 0)
		{
			cout << endl;
		}
	}

}