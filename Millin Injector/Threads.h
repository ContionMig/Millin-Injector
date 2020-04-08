#pragma once
#include "Common.h"

namespace Threads
{
	extern HANDLE hRenderThread;
	extern DWORD RenderThreadID;
	extern void RenderThread();
}