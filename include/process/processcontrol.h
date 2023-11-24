#ifndef USERMODEHOOK_PROCESS_PROCESSCONTROL_H_
#define USERMODEHOOK_PROCESS_PROCESSCONTROL_H_

#include "process/processinfo.h"
#include "ulti/everything.h"

namespace process
{
	class ProcessControl: public ProcessInfo 
    {
	private:
        HANDLE process_control_handle_ = 0;
	public:

		ProcessControl() = default;
		explicit ProcessControl(int pid);
        explicit ProcessControl(const std::string_view& process_name);
		explicit ProcessControl(const ProcessInfo& process_info);

        void Open();
        void Close();

        DWORD CreateThread(LPTHREAD_START_ROUTINE thread_function_address, LPVOID param);

        ~ProcessControl();
    protected:
        void SetProcessControlHandle(HANDLE process_control_handle);
        HANDLE GetProcessControlHandle() const;
	};
}

#endif