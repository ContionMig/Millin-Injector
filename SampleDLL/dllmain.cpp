// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdlib.h>

extern "C" __declspec(dllexport) int CallingMessagebox() {
    return  MessageBox(NULL, L"THERE HELLO", L"WAN OBI", MB_OK);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        MessageBox(NULL, L"HELLO THERE", L"OBI WAN", MB_OK);
    }

    return TRUE;
}

