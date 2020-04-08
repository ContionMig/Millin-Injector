#pragma once
#include "Common.h"

struct InjectionOptions
{
	int OptionChoice;
	int DelayS;
	bool FullPermsHandle;

	bool CheckBoxVarible = false;
	bool CheckBoxVarible2 = false;
	bool CheckBoxVarible3 = false;
	bool CheckBoxVarible4 = false;

	bool CheckBoxVarible5 = false;
	bool CheckBoxVarible6 = false;
	bool CheckBoxVarible7 = false;

	int ComboVariable = 1;

	int DurationMS;
	char CustomEntryPoint[1000] = "CallingMessagebox";

	std::string sFilePath;
};

namespace Injection
{
	extern void LoadLibraryInject(LPVOID Options);

	extern void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
	extern void ManualMapInject(LPVOID pOptions);
}