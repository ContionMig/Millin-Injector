#pragma once
#include "Common.h"

namespace ErrorLogs
{
	extern bool initialize;
	extern std::vector<std::string> SavedLogs;

	extern inline std::string getCurrentDateTime(std::string s);
	extern inline void LogFiles(const char* fmt, ...);
}