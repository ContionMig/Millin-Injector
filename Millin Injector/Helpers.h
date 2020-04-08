#pragma once
#include "Common.h"

namespace Helpers
{
	extern inline std::string CurrentPath();
	extern inline bool CreateFolder(std::string Path);

	extern inline std::wstring String2WString(const std::string s);
	extern inline std::string WString2String(const std::wstring wstr);

	extern inline bool RanAsAdmin(HANDLE hProcess = (HANDLE)-1);
	extern inline bool CheckAlive(DWORD PID);

	extern inline bool DoesFileExist(const std::string& name);
	extern inline bool DirectoryExists(const std::string& name);

	extern std::string StringFormat(const char* fmt, ...);
	extern int IsFile64BitDLL(std::string Path);

	extern DWORD_PTR ModuleBase(DWORD PID, std::string FullPath);
	extern void ClearPEModule(LPVOID pOptions);
}