#include "AntiDump.h"

namespace AntiDump
{
	VOID ChangeSizeOfImagine()
	{
		DWORD OldProtect = 0;
		char* pBaseAddr = (char*)GetModuleHandle(NULL);
		VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &OldProtect);
		SecureZeroMemory(pBaseAddr, 4096);
	}
}