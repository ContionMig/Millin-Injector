#pragma once
#include "Common.h"

namespace ImGui
{
	extern bool ImGuiSaveStyle(const char* filename, const ImGuiStyle& style);
	extern bool ImGuiLoadStyle(const char* filename, ImGuiStyle& style);
}