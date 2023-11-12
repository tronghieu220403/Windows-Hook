#include "process/process.h"

namespace process
{
	Process::Process(): pid_(0) {};

	Process::Process(int pid): pid_(pid) {};

	Process::Process(const std::string_view& name): name_(name), pid_(Process::FindProcessByName(name)) {};

	int Process::GetPid() const{
		return pid_;
	}

	void Process::SetPid(int pid){
		pid_ = pid;
	};

    void Process::UpdatePid()
    {
        if (!name_.empty())
        {
            pid_ = Process::FindProcessByName(name_);
        }
    };

    std::string Process::GetName() const
    {
        return name_;
    }

    void Process::SetName(const std::string_view &name)
    {
        name_ = name;
    }

    int Process::FindProcessByName(const std::string_view& name)
    {
        int pid = 0;

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        std::wstring wsTmp(name.begin(), name.end());

        if (::Process32FirstW(snapshot, &entry) == TRUE)
        {
            while (Process32Next(snapshot, &entry) == TRUE)
            {
                if (::wcscmp(entry.szExeFile, &wsTmp[0]) == 0)
                {
                    pid = entry.th32ProcessID;
                    break;
                }
            }
        }
        ::CloseHandle(snapshot);
        return pid;
	};

}