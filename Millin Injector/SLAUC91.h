#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace SLAUC91HideDLL
{
	BOOL RemoveDLL(DWORD PID, std::wstring DLLtoRemove, int ListType);
}