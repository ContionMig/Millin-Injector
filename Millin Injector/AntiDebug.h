#pragma once
#include "Common.h"

namespace AntiDebug
{
	extern inline BOOLEAN DebuggerPresent();
	extern inline BOOLEAN CheckNtGlobalFlag();
	extern inline BOOLEAN CheckNtClose();
	extern inline BOOLEAN CheckSystemDebugControl();
	extern inline BOOLEAN CheckSystemDebugger();
	extern inline BOOLEAN CheckObjectList();
	extern inline BOOLEAN HideFromDebugger(HANDLE hThread);
	extern inline BOOLEAN CheckProcessDebugObjectHandle();
	extern inline BOOLEAN CheckProcessDebugPort();
	extern inline BOOLEAN CheckProcessDebugFlags();
	extern inline BOOLEAN CheckDevices();
	extern inline BOOLEAN CheckProcess();
}