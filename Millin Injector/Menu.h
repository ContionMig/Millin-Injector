#pragma once
#include "Common.h"
#include "Console.h"

namespace Menu
{
	extern sConsole MainConsole;
	extern char DLLPath[MAX_PATH];

	extern void Main();
	extern  void ShowStyleEditor(ImGuiStyle* ref = 0);
	extern void CherryTheme();
	extern void ExtasyHostingTheme();
}