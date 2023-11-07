#ifndef IATHOOK_PROCESS_PROCESS_H_
#define IATHOOK_PROCESS_PROCESS_H_

#define UNICODE
#define _UNICODE

#include <string.h>
#include <WS2tcpip.h>
#include <TlHelp32.h>

#include <string>
#include <fstream>

namespace iathook
{
	class Process {
	private:
		int pid_;
        std::string name_;
	public:

		Process();
		explicit Process(int id);
		explicit Process(const std::string_view& name);
		
		int GetPid() const;
		void SetPid(int id);
		void UpdatePid();

        std::string GetName() const;
        void SetName(const std::string_view& name);

		static int FindProcessByName(const std::string_view& name);

	};
}

#endif