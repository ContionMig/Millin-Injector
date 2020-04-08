#pragma once
#include "Common.h"
#include "Struct.h"

namespace Process
{
	extern Processes ProcessList;
	extern ProcessInfo SelectedProcess;
	extern ImportList Imports;

	extern HANDLE ProcessHandle(std::wstring ProcessName);
	extern HANDLE ProcessHandle(DWORD PID, DWORD Perms = PROCESS_ALL_ACCESS);
	
	extern DWORD GetProcessID(std::wstring ProcessName);
	extern std::string GetProcessName(DWORD PID);
	
	extern DWORD ParentProcessID(DWORD PID);
	extern CreateProcessS CreateProgram(std::string Path);
	
	extern std::vector<DWORD> GetThreadIDs(DWORD PID);
	extern size_t GetRamUsage(DWORD PID);

	extern BOOL CALLBACK EnumWindowCallback(HWND hWnd, LPARAM lparam);

	extern void RefreshProcessList();
	extern void RefreshSelect(LPVOID pOptions);
	extern void RefeshSelectImport();
}