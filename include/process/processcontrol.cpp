#include "processcontrol.h"

namespace process
{

    ProcessControl::ProcessControl(int pid):
        ProcessInfo(pid)
    {
        ProcessControl::Open();
    }

    ProcessControl::ProcessControl(const std::string_view &process_name):
        ProcessInfo(process_name)
    {
        ProcessControl::Open();
    }

    ProcessControl::ProcessControl(const ProcessInfo& process_info):
        ProcessInfo(process_info)
    {
        ProcessControl::Open();
    }


    void ProcessControl::Open()
    {
        process_control_handle_ = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, GetPid());
    }


    void ProcessControl::Close()
    {
        if (process_control_handle_ != nullptr)
        {
            ::CloseHandle(process_control_handle_);
            process_control_handle_ = nullptr;
        }
    }

    DWORD ProcessControl::CreateThread(LPTHREAD_START_ROUTINE thread_function_address, LPVOID param)
    {
        DWORD thread_id = 0;

        CreateRemoteThread(
        /*[in]  HANDLE                 */ process_control_handle_,
        /*[in]  LPSECURITY_ATTRIBUTES  */ NULL,
        /*[in]  SIZE_T                 */ NULL,
        /*[in]  LPTHREAD_START_ROUTINE */ thread_function_address,
        /*[in]  LPVOID                 */ param,
        /*[in]  DWORD                  */ NULL,
        /*[out] LPDWORD                */ &thread_id
        );

        return thread_id;
    }

    void ProcessControl::SetProcessControlHandle(HANDLE process_control_handle)
    {
        ProcessControl::Close();
        process_control_handle_ = process_control_handle;
    }

    HANDLE ProcessControl::GetProcessControlHandle() const
    {
        return process_control_handle_;
    }

    ProcessControl::~ProcessControl()
    {
        ProcessControl::Close();
    }
}