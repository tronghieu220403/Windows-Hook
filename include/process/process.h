#ifndef IATHOOK_PROCESS_PROCESS_H_
#define IATHOOK_PROCESS_PROCESS_H_

#include "ulti/everything.h"

namespace process
{
	class Process {
	private:
		int pid_;
        std::string name_;
	public:

		Process();
		explicit Process(int pid);
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