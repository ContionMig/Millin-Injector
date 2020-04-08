#include "AntiVM.h"

namespace AntiVM
{
	BOOLEAN CheckLoadedDLLs()
	{
		/* Some vars */
		HMODULE hDll;

		/* Array of strings of blacklisted dlls */
		LPCWSTR szDlls[] = {
			(L"sbiedll.dll"),		// Sandboxie
			(L"dbghelp.dll"),		// WindBG
			(L"api_log.dll"),		// iDefense Lab
			(L"dir_watch.dll"),		// iDefense Lab
			(L"pstorec.dll"),		// SunBelt Sandbox
			(L"vmcheck.dll"),		// Virtual PC
			(L"wpespy.dll"),			// WPE Pro
			(L"cmdvrt64.dll"),		// Comodo Container
			(L"cmdvrt32.dll"),		// Comodo Container

		};

		WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
		for (int i = 0; i < dwlength; i++)
		{
			hDll = GetModuleHandle(szDlls[i]);
			if (hDll)
				return true;
		}
		return false;
	}

	BOOLEAN CheckRegKeys()
	{
		/* Array of strings of blacklisted registry keys */
		std::wstring szKeys[] = {
			(L"HARDWARE\\ACPI\\DSDT\\VBOX__"),
			(L"HARDWARE\\ACPI\\FADT\\VBOX__"),
			(L"HARDWARE\\ACPI\\RSDT\\VBOX__"),
			(L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
			(L"SYSTEM\\ControlSet001\\Services\\VBoxGuest"),
			(L"SYSTEM\\ControlSet001\\Services\\VBoxMouse"),
			(L"SYSTEM\\ControlSet001\\Services\\VBoxService"),
			(L"SYSTEM\\ControlSet001\\Services\\VBoxSF"),
			(L"SYSTEM\\ControlSet001\\Services\\VBoxVideo"),
			(L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"),
			(L"SOFTWARE\\Wine")
		};

		WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);
		for (int i = 0; i < dwlength; i++)
		{
			std::wstring RegistryPath = (std::wstring)szKeys[i];

			HKEY Key;
			LONG Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegistryPath.c_str(), 0, KEY_ALL_ACCESS, &Key);
			RegCloseKey(Key);

			if (Result == ERROR_SUCCESS)
				return true;
		}
	}

	BOOLEAN CheckDevices()
	{
		LPCWSTR devices[] = {
			(L"\\\\.\\VBoxMiniRdrDN"),
			(L"\\\\.\\VBoxGuest"),
			(L"\\\\.\\pipe\\VBoxMiniRdDN"),
			(L"\\\\.\\VBoxTrayIPC"),
			(L"\\\\.\\pipe\\VBoxTrayIPC")
		};

		WORD iLength = sizeof(devices) / sizeof(devices[0]);
		for (int i = 0; i < iLength; i++)
		{
			HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE)
				return true;
		}
		return false;
	}

	BOOLEAN CheckWindows()
	{
		HWND hClass = FindWindow(TEXT("VBoxTrayToolWndClass"), NULL);
		HWND hWindow = FindWindow(NULL, TEXT("VBoxTrayToolWnd"));

		if (hClass || hWindow)
			return true;
		else
			return false;
	}

	BOOLEAN CheckProcess()
	{
		std::string szProcesses[] = {
			("VBoxService.exe"),
			("VBoxTray.exe"),
			("VMSrvc.exe"),
			("VMUSrvc.exe"),
			("xenservice.exe")
		};

		WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
		for (int i = 0; i < iLength; i++)
		{
			if (Process::GetProcessID(Helpers::String2WString(szProcesses[i])))
				return true;
		}
		return false;
	}
}