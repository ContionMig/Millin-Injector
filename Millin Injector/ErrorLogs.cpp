#include "Common.h"

namespace ErrorLogs
{
	bool initialize = false;
	std::vector<std::string> SavedLogs = {	};

	inline std::string getCurrentDateTime(std::string s)
	{
		using namespace std;
		time_t now = time(0);
		struct tm  tstruct;
		char  buf[80];
		tstruct = *localtime(&now);
		if (s == "now")
			strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
		else if (s == "date")
			strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
		else if (s == "at")
			strftime(buf, sizeof(buf), "%Y%m%d", &tstruct);
		return string(buf);
	}

	inline void LogFiles(const char* fmt, ...)
	{
		char text[256];
		va_list ap;

		va_start(ap, fmt);
		vsprintf_s(text, fmt, ap);
		va_end(ap);

		printf("[LOG] %s\n", text);
		Helpers::CreateFolder((Helpers::CurrentPath().c_str() + (std::string)"\\Logs").c_str());
		std::string filePath = Helpers::CurrentPath().c_str() + (std::string)"\\Logs\\log_" + getCurrentDateTime("date") + ".txt";
		std::string now = getCurrentDateTime("now");

		std::ofstream myfile;
		myfile.open(filePath, std::ios_base::out | std::ios_base::app);
		if (myfile.is_open())
		{
			myfile << now.c_str() << '\t' << text << " " << GetLastError() << '\n';
			myfile.close();
		}

		if (initialize)
		{
			if (SavedLogs.size() > 0)
			{
				for (int i = 0; i < SavedLogs.size(); i++)
					Menu::MainConsole.AddLog("%s", SavedLogs[i].c_str());

				SavedLogs.clear();
			}

			Menu::MainConsole.AddLog("%s: [LOG] %s", now.c_str(), text);
		}
		else
		{
			char buff[100];
			snprintf(buff, sizeof(buff), "%s: [LOG] %s", now.c_str(), text);
			SavedLogs.push_back(std::string(buff));
		}
	}
}