#include "Common.h"
#include "AntiDebug.h"
#include "SLAUC91.h"

namespace Injection
{
	void LoadLibraryInject(LPVOID pOptions)
	{
		InjectionOptions* Options = (InjectionOptions*)pOptions;
		ErrorLogs::LogFiles("[important] LoadLibrary: Starting Injection");
		auto start = std::chrono::high_resolution_clock::now();

		if (Helpers::IsFile64BitDLL(Options->sFilePath) != Process::SelectedProcess.Is64)
			return ErrorLogs::LogFiles("[important] DLL Image Type Does Not Match The Process Or File is Not A DLL. x64 Can't Be Injected To x32 Or The Other Way Round");

		if (!Helpers::DoesFileExist(Options->sFilePath))
			return ErrorLogs::LogFiles("[important] Selected DLL Does Not Seem To Exist");

		if (!Helpers::CheckAlive(Process::SelectedProcess.PID))
			return ErrorLogs::LogFiles("[important] Selected Program Seems Dead");

		if (Options->DelayS)
			std::this_thread::sleep_for(std::chrono::seconds(Options->DelayS));

		PCWSTR FilePath = Helpers::String2WString(Options->sFilePath).c_str();
		HANDLE ProcessHandle = Options->FullPermsHandle ? Process::ProcessHandle(Process::SelectedProcess.PID)
			: Process::ProcessHandle(Process::SelectedProcess.PID, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
		
		if (ProcessHandle == INVALID_HANDLE_VALUE)
			return ErrorLogs::LogFiles("[important] RemoteThread: ProcessHandle Invalid");

		ErrorLogs::LogFiles("ProcessHandle Created: 0x%llx", ProcessHandle);
		DWORD dwSize = (lstrlenW(FilePath) + 1) * sizeof(wchar_t);
		if (Options->OptionChoice == 0)
		{
			LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(ProcessHandle, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
			if (pszLibFileRemote == NULL)
			{
				CloseHandle(ProcessHandle);
				return ErrorLogs::LogFiles("[important] RemoteThread: pszLibFileRemote NULL <- VirtualAllocEx");
			}

			if (!WriteProcessMemory(ProcessHandle, pszLibFileRemote, (PVOID)FilePath, dwSize, NULL))
			{
				CloseHandle(ProcessHandle);
				VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
				return ErrorLogs::LogFiles("[important] RemoteThread: WriteProcessMemory Failed");
			}

			LPVOID pfnThreadRtn = GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
			if (!pfnThreadRtn)
			{
				CloseHandle(ProcessHandle);
				VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
				return ErrorLogs::LogFiles("[important] RemoteThread: pfnThreadRtn NULL");
			}

			HANDLE hThread = NULL;
			DWORD ThreadID = NULL;

			auto Injstart = std::chrono::high_resolution_clock::now();
			ptNtQueryInformationThread pfnNtQueryInformationThread = (ptNtQueryInformationThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationThread");
			
			if (Options->ComboVariable == 0)
			{
				if (!Options->CheckBoxVarible2)
				{
					hThread = CreateRemoteThread(ProcessHandle, NULL, 0, (PTHREAD_START_ROUTINE)pfnThreadRtn, pszLibFileRemote, 0, &ThreadID);
					if (!hThread)
					{
						CloseHandle(ProcessHandle);
						VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
						return ErrorLogs::LogFiles("[important] RemoteThread: CreateRemoteThread Thread NULL");
					}

					DWORD_PTR dwStartAddress = 0;
					pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
					ErrorLogs::LogFiles("CreateRemoteThread - Thread Created In Process | ThreadID: %d Start Address: 0x%llx", ThreadID, dwStartAddress);
				}
				else
				{
					hThread = CreateRemoteThread(ProcessHandle, NULL, 0, (PTHREAD_START_ROUTINE)(Process::SelectedProcess.BaseAddress + (Process::SelectedProcess.BaseSize / 2)), pszLibFileRemote, CREATE_SUSPENDED, &ThreadID);
					if (!hThread)
					{
						CloseHandle(ProcessHandle);
						VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
						return ErrorLogs::LogFiles("[important] RemoteThread: CreateRemoteThread Thread NULL");
					}

					CONTEXT ctx;
					ctx.ContextFlags = CONTEXT_ALL;
					GetThreadContext(hThread, &ctx);

					ctx.Rcx = (DWORD64)pfnThreadRtn;
					if (!SetThreadContext(hThread, &ctx))
						ErrorLogs::LogFiles("CreateRemoteThread - Thread Context Set Failed");
					else
						ErrorLogs::LogFiles("CreateRemoteThread - Thread Context Set.");

					auto dwResumeRet = ResumeThread(hThread);
					DWORD_PTR dwStartAddress = 0;
					pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
					ErrorLogs::LogFiles("CreateRemoteThread - Thread Created In Process | ThreadID: %d Fake Start Address: 0x%llx Actual Start Address: 0x%llx", ThreadID, dwStartAddress, pfnThreadRtn);
				}
			}
			else if (Options->ComboVariable == 1)
			{
				ptNtCreateThreadEx pfnNtCreateThreadEx = (ptNtCreateThreadEx)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");
				if (!Options->CheckBoxVarible2)
				{
					pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)pfnThreadRtn, pszLibFileRemote, NULL, NULL, NULL, NULL, NULL);
					if (!hThread)
					{
						CloseHandle(ProcessHandle);
						VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
						return ErrorLogs::LogFiles("[important] RemoteThread: NtCreateThreadEx Thread NULL");
					}
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Created In Process | Handle: 0x%llx", hThread);
				}
				else
				{
					pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)(Process::SelectedProcess.BaseAddress + (Process::SelectedProcess.BaseSize / 3)), pszLibFileRemote, true, NULL, NULL, NULL, NULL);
					if (!hThread)
					{
						CloseHandle(ProcessHandle);
						VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
						return ErrorLogs::LogFiles("[important] NtCreateThreadEx: CreateRemoteThread Thread NULL");
					}

					CONTEXT ctx;
					ctx.ContextFlags = CONTEXT_ALL;
					GetThreadContext(hThread, &ctx);

					ctx.Rcx = (DWORD64)pfnThreadRtn;
					if (!SetThreadContext(hThread, &ctx))
						ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set Failed");
					else
						ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set.");

					auto dwResumeRet = ResumeThread(hThread);
					DWORD_PTR dwStartAddress = 0;
					pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Created In Process | ThreadID: %d Fake Start Address: 0x%llx Actual Start Address: 0x%llx", ThreadID, dwStartAddress, pfnThreadRtn);
				}
			}
			else if (Options->ComboVariable == 2)
			{
				ptRtlCreateUserThread pfnRtlCreateUserThread = (ptRtlCreateUserThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlCreateUserThread");
				if (!Options->CheckBoxVarible2)
				{
					pfnRtlCreateUserThread(ProcessHandle, NULL, 0, 0, 0, 0, pfnThreadRtn, pszLibFileRemote, &hThread, NULL);
					if (!hThread)
					{
						CloseHandle(ProcessHandle);
						VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
						return ErrorLogs::LogFiles("[important] RemoteThread: RtlCreateUserThread Thread NULL");
					}
					ErrorLogs::LogFiles("RtlCreateUserThread - Thread Created In Process | Handle: 0x%llx", hThread);
				}
				else
				{
					pfnRtlCreateUserThread(ProcessHandle, NULL, true, 0, 0, 0, (LPTHREAD_START_ROUTINE)(Process::SelectedProcess.BaseAddress + (Process::SelectedProcess.BaseSize / 4)), pszLibFileRemote, &hThread, NULL);
					if (!hThread)
					{
						CloseHandle(ProcessHandle);
						VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
						return ErrorLogs::LogFiles("[important] NtCreateThreadEx: CreateRemoteThread Thread NULL");
					}

					CONTEXT ctx;
					ctx.ContextFlags = CONTEXT_ALL;
					GetThreadContext(hThread, &ctx);

					ctx.Rcx = (DWORD64)pfnThreadRtn;
					if (!SetThreadContext(hThread, &ctx))
						ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set Failed");
					else
						ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set.");

					auto dwResumeRet = ResumeThread(hThread);
					DWORD_PTR dwStartAddress = 0;
					pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Created In Process | ThreadID: %d Fake Start Address: 0x%llx Actual Start Address: 0x%llx", ThreadID, dwStartAddress, pfnThreadRtn);
				}
			}

			if (Options->CheckBoxVarible3)
				AntiDebug::HideFromDebugger(hThread);

			if (Options->CheckBoxVarible4)
			{
				sClearPEModule PEModuleOptions;
				PEModuleOptions.FullPath = Options->sFilePath;
				PEModuleOptions.hProcess = ProcessHandle;

				//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Helpers::ClearPEModule, &PEModuleOptions, 0, NULL);
				Helpers::ClearPEModule(&PEModuleOptions);
			}

			if (Options->CheckBoxVarible5)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 0))
					ErrorLogs::LogFiles("Unlinked Module From Load Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Load Order List", ProcessHandle);
			}
			if (Options->CheckBoxVarible6)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 1))
					ErrorLogs::LogFiles("Unlinked Module From Memory Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Memory Order List", ProcessHandle);
			}
			if (Options->CheckBoxVarible7)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 2))
					ErrorLogs::LogFiles("Unlinked Module From Initialization Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Initialization Order List", ProcessHandle);
			}

			ErrorLogs::LogFiles("LoadLibrary: Waiting For Thread To Finish");
			WaitForSingleObject(hThread, INFINITE);

			auto Injstop = std::chrono::high_resolution_clock::now();
			auto Injduration = std::chrono::duration_cast<std::chrono::milliseconds>(Injstop - Injstart);
			ErrorLogs::LogFiles("LoadLibrary: Thread Ended In %d MS, Cleaning Up", Injduration);

			VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);
			CloseHandle(hThread);
		}
		else if (Options->OptionChoice == 1)
		{
			auto pVa = VirtualAllocEx(ProcessHandle, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // TO-DO: VirtualFreeEx
			if (!WriteProcessMemory(ProcessHandle, pVa, (PVOID)FilePath, dwSize, nullptr))
			{
				CloseHandle(ProcessHandle);
				return ErrorLogs::LogFiles("APCinjection: WriteProcessMemory Failed");
			}

			std::vector<DWORD> tids = Process::GetThreadIDs(GetProcessId(ProcessHandle));
			for (const auto& tid : tids) {
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
				if (hThread != INVALID_HANDLE_VALUE)
					QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryW"), hThread, (ULONG_PTR)pVa);

				CloseHandle(hThread);
			}

			if (Options->CheckBoxVarible4)
			{
				sClearPEModule PEModuleOptions;
				PEModuleOptions.FullPath = Options->sFilePath;
				PEModuleOptions.hProcess = ProcessHandle;

				//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Helpers::ClearPEModule, &PEModuleOptions, 0, NULL);
				Helpers::ClearPEModule(&PEModuleOptions);
			}

			if (Options->CheckBoxVarible5)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 0))
					ErrorLogs::LogFiles("Unlinked Module From Load Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Load Order List", ProcessHandle);
			}
			if (Options->CheckBoxVarible6)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 1))
					ErrorLogs::LogFiles("Unlinked Module From Memory Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Memory Order List", ProcessHandle);
			}
			if (Options->CheckBoxVarible7)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 2))
					ErrorLogs::LogFiles("Unlinked Module From Initialization Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Initialization Order List", ProcessHandle);
			}
		}
		else if (Options->OptionChoice == 2)
		{
			if (Options->CheckBoxVarible)
			{
				ErrorLogs::LogFiles("SetWindowsHookEx: Using Entry Point");
				HANDLE hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
				if (hFile == INVALID_HANDLE_VALUE)
					ErrorLogs::LogFiles("SetWindowsHookEx: CreateFile failed in read mode");

				HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
				if (hFileMapping == 0)
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: CreateFileMapping failed");
					CloseHandle(hFile);
				}

				LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
				if (lpFileBase == 0)
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: MapViewOfFile failed");
					CloseHandle(hFileMapping);
					CloseHandle(hFile);
				}

				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
				if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: DOS Signature (MZ) Matched");
					PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);
					if (peHeader->Signature == IMAGE_NT_SIGNATURE)
					{
						ErrorLogs::LogFiles("SetWindowsHookEx: PE Signature (PE) Matched");

						HMODULE dll = LoadLibraryEx(FilePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
						if (dll == NULL)
							return ErrorLogs::LogFiles("[important] SetWindowsHookEx: LoadLibrary Failed");

						HOOKPROC addr = (HOOKPROC)(peHeader->OptionalHeader.AddressOfEntryPoint);

						DWORD pid = NULL;
						HWND targetWnd = FindWindow(NULL, Helpers::String2WString(Process::SelectedProcess.WindowName).c_str());

						if (Options->ComboVariable == 0)
						{
							ErrorLogs::LogFiles("SetWindowsHookEx: Hooked - WH_CBT");
							HHOOK handle = SetWindowsHookEx(WH_CBT, addr, dll, GetWindowThreadProcessId(targetWnd, &pid));
							std::this_thread::sleep_for(std::chrono::milliseconds(Options->DurationMS));
							UnhookWindowsHookEx(handle);
							ErrorLogs::LogFiles("SetWindowsHookEx: Unhooked - WH_CBT");
						}
						else if (Options->ComboVariable == 1)
						{
							ErrorLogs::LogFiles("SetWindowsHookEx: Hooked - WH_GETMESSAGE");
							DWORD ThreadID = GetWindowThreadProcessId(targetWnd, &pid);
							HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, ThreadID);
							PostThreadMessage(ThreadID, WM_NULL, NULL, NULL);
							std::this_thread::sleep_for(std::chrono::milliseconds(2));
							UnhookWindowsHookEx(handle);
							ErrorLogs::LogFiles("SetWindowsHookEx: Unhooked - WH_GETMESSAGE");
						}
						else if (Options->ComboVariable == 2)
						{
							ErrorLogs::LogFiles("SetWindowsHookEx: Hooked - WH_KEYBOARD");
							DWORD ThreadID = GetWindowThreadProcessId(targetWnd, &pid);
							HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, ThreadID);
							std::this_thread::sleep_for(std::chrono::milliseconds(Options->DurationMS));
							UnhookWindowsHookEx(handle);
							ErrorLogs::LogFiles("SetWindowsHookEx: Unhooked - WH_KEYBOARD");
						}

						FreeLibrary(dll);
					}
					UnmapViewOfFile(lpFileBase);
					CloseHandle(hFileMapping);
					CloseHandle(hFile);
				}
				else
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: DOS Signature (MZ) Not Matched");
					UnmapViewOfFile(lpFileBase);
					CloseHandle(hFileMapping);
					CloseHandle(hFile);
				}
			}
			else
			{
				ErrorLogs::LogFiles("SetWindowsHookEx: Using Custom Function");
				HMODULE dll = LoadLibraryEx(FilePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
				if (dll == NULL) {
					CloseHandle(ProcessHandle);
					return ErrorLogs::LogFiles("[important] SetWindowsHookEx: LoadLibrary Failed");
				}

				HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, (LPCSTR)Options->CustomEntryPoint);
				if (addr == NULL)
				{
					FreeLibrary(dll);
					CloseHandle(ProcessHandle);
					return ErrorLogs::LogFiles("[important] SetWindowsHookEx: GetProcAddress Failed");
				}

				DWORD pid = NULL;
				HWND targetWnd = FindWindow(NULL, Helpers::String2WString(Process::SelectedProcess.WindowName).c_str());

				if (Options->ComboVariable == 0)
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: Hooked - WH_CBT");
					HHOOK handle = SetWindowsHookEx(WH_CBT, addr, dll, GetWindowThreadProcessId(targetWnd, &pid));
					std::this_thread::sleep_for(std::chrono::milliseconds(Options->DurationMS));
					UnhookWindowsHookEx(handle);
					ErrorLogs::LogFiles("SetWindowsHookEx: Unhooked - WH_CBT");
				}
				else if (Options->ComboVariable == 1)
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: Hooked - WH_GETMESSAGE");
					DWORD ThreadID = GetWindowThreadProcessId(targetWnd, &pid);
					HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, ThreadID);
					PostThreadMessage(ThreadID, WM_NULL, NULL, NULL);
					std::this_thread::sleep_for(std::chrono::milliseconds(2));
					UnhookWindowsHookEx(handle);
					ErrorLogs::LogFiles("SetWindowsHookEx: Unhooked - WH_GETMESSAGE");
				}
				else if (Options->ComboVariable == 2)
				{
					ErrorLogs::LogFiles("SetWindowsHookEx: Hooked - WH_KEYBOARD");
					DWORD ThreadID = GetWindowThreadProcessId(targetWnd, &pid);
					HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, ThreadID);
					std::this_thread::sleep_for(std::chrono::milliseconds(Options->DurationMS));
					UnhookWindowsHookEx(handle);
					ErrorLogs::LogFiles("SetWindowsHookEx: Unhooked - WH_KEYBOARD");
				}

				FreeLibrary(dll);
			}

			if (Options->CheckBoxVarible4)
			{
				sClearPEModule PEModuleOptions;
				PEModuleOptions.FullPath = Options->sFilePath;
				PEModuleOptions.hProcess = ProcessHandle;

				//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Helpers::ClearPEModule, &PEModuleOptions, 0, NULL);
				Helpers::ClearPEModule(&PEModuleOptions);
			}

			if (Options->CheckBoxVarible5)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 0))
					ErrorLogs::LogFiles("Unlinked Module From Load Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Load Order List", ProcessHandle);
			}
			if (Options->CheckBoxVarible6)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 1))
					ErrorLogs::LogFiles("Unlinked Module From Memory Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Memory Order List", ProcessHandle);
			}
			if (Options->CheckBoxVarible7)
			{
				if (SLAUC91HideDLL::RemoveDLL(GetProcessId(ProcessHandle), FilePath, 2))
					ErrorLogs::LogFiles("Unlinked Module From Initialization Order List", ProcessHandle);
				else
					ErrorLogs::LogFiles("Failed To Unlinked Module From Initialization Order List", ProcessHandle);
			}
		}

		if (ProcessHandle)
			CloseHandle(ProcessHandle);

		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
		ErrorLogs::LogFiles("[important] LoadLibrary: Injection Done In %d MS", duration);
	}

	void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
	{
		if (!pData)
			return;

		BYTE* pBase = reinterpret_cast<BYTE*>(pData);
		auto* pOptionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

		auto _LoadLibraryA = pData->pLoadLibraryA;
		auto _GetProcAddress = pData->pGetProcAddress;
		auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptionalHeader->AddressOfEntryPoint);

		BYTE* LocationDelta = pBase - pOptionalHeader->ImageBase;
		if (LocationDelta)
		{
			if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
				return;

			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
				{
					if (RELOC_FLAG(*pRelativeInfo))
					{
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}

		if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name)
			{
				char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
				HINSTANCE hDll = _LoadLibraryA(szMod);

				ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
				ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

				if (!pThunkRef)
					pThunkRef = pFuncRef;

				for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
				{
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
					{
						*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
					}
					else
					{
						auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
						*pFuncRef = _GetProcAddress(hDll, pImport->Name);
					}
				}
				++pImportDescr;
			}
		}

		if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}

		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
	}

	void ManualMapInject(LPVOID pOptions)
	{
		InjectionOptions* Options = (InjectionOptions*)pOptions;
		const char* szDllFile = Options->sFilePath.c_str();

		BYTE* pSourceData = nullptr;
		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;

		ErrorLogs::LogFiles("[important] ManualMap: Starting Injection");
		auto start = std::chrono::high_resolution_clock::now();

		if (!Helpers::DoesFileExist(Options->sFilePath))
			return ErrorLogs::LogFiles("[important] Selected DLL Does Not Seem To Exist");

		if (!Helpers::CheckAlive(Process::SelectedProcess.PID))
			return ErrorLogs::LogFiles("[important] Selected Program Seems Dead");

		if (Options->DelayS)
			std::this_thread::sleep_for(std::chrono::seconds(Options->DelayS));

		PCWSTR FilePath = Helpers::String2WString(Options->sFilePath).c_str();
		HANDLE ProcessHandle = Options->FullPermsHandle ? Process::ProcessHandle(Process::SelectedProcess.PID)
			: Process::ProcessHandle(Process::SelectedProcess.PID, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);

		if (ProcessHandle == INVALID_HANDLE_VALUE)
			return ErrorLogs::LogFiles("[important] RemoteThread: ProcessHandle Invalid");

		ErrorLogs::LogFiles("ProcessHandle Created: 0x%llx", ProcessHandle);
		std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
		if (File.fail())
		{
			File.close();
			CloseHandle(ProcessHandle);
			return ErrorLogs::LogFiles("[important] Failed To Open: %s", szDllFile);
		}

		auto FileSize = File.tellg();
		pSourceData = new BYTE[static_cast<UINT_PTR>(FileSize)];

		if (!pSourceData)
		{
			File.close();
			CloseHandle(ProcessHandle);
			return ErrorLogs::LogFiles("[important] Failed To allocate memory for pSourceData");
		}

		File.seekg(0, std::ios::beg);
		File.read(reinterpret_cast<char*>(pSourceData), FileSize);
		File.close();

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_magic != 0x5A4D)
		{
			delete[] pSourceData;
			CloseHandle(ProcessHandle);
			return ErrorLogs::LogFiles("[important] Invalid PE File");
		}

		MANUAL_MAPPING_DATA data{ 0 };
		data.pLoadLibraryA = LoadLibraryA;
		data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
		pOldOptionalHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(ProcessHandle, nullptr, pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			delete[] pSourceData;
			CloseHandle(ProcessHandle);
			return ErrorLogs::LogFiles("[important] Failed To Allocate Memory -> pTargetBase");
		}

		auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		{
			if (pSectionHeader->SizeOfRawData)
			{
				if (!WriteProcessMemory(ProcessHandle, pTargetBase + pSectionHeader->VirtualAddress, pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
				{
					delete[] pSourceData;
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					CloseHandle(ProcessHandle);
					return ErrorLogs::LogFiles("[important] Failed To WriteProcessMemory");
				}
			}
		}

		memcpy(pSourceData, &data, sizeof(data));
		WriteProcessMemory(ProcessHandle, pTargetBase, pSourceData, 0x1000, nullptr);
		delete[] pSourceData;

		void* pShellcode = VirtualAllocEx(ProcessHandle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
			CloseHandle(ProcessHandle);
			return ErrorLogs::LogFiles("[important] Failed To Allocate Memory -> pShellcode");
		}

		WriteProcessMemory(ProcessHandle, pShellcode, Shellcode, 0x1000, nullptr);

		HANDLE hThread = NULL;
		DWORD ThreadID = NULL;

		auto Injstart = std::chrono::high_resolution_clock::now();
		ptNtQueryInformationThread pfnNtQueryInformationThread = (ptNtQueryInformationThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationThread");
		if (Options->ComboVariable == 0)
		{
			if (!Options->CheckBoxVarible2)
			{
				hThread = CreateRemoteThread(ProcessHandle, NULL, 0, (PTHREAD_START_ROUTINE)pShellcode, pTargetBase, 0, &ThreadID);
				if (!hThread)
				{
					CloseHandle(ProcessHandle);
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					return ErrorLogs::LogFiles("RemoteThread: CreateRemoteThread Thread NULL");
				}

				DWORD_PTR dwStartAddress = 0;
				pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
				ErrorLogs::LogFiles("CreateRemoteThread - Thread Created In Process | ThreadID: %d Start Address: 0x%llx", ThreadID, dwStartAddress);
			}
			else
			{
				hThread = CreateRemoteThread(ProcessHandle, NULL, 0, (PTHREAD_START_ROUTINE)(Process::SelectedProcess.BaseAddress + (Process::SelectedProcess.BaseSize / 2)), pTargetBase, CREATE_SUSPENDED, &ThreadID);
				if (!hThread)
				{
					CloseHandle(ProcessHandle);
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					return ErrorLogs::LogFiles("RemoteThread: CreateRemoteThread Thread NULL");
				}

				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hThread, &ctx);

				ctx.Rcx = (DWORD64)pShellcode;
				if (!SetThreadContext(hThread, &ctx))
					ErrorLogs::LogFiles("CreateRemoteThread - Thread Context Set Failed");
				else
					ErrorLogs::LogFiles("CreateRemoteThread - Thread Context Set.");

				auto dwResumeRet = ResumeThread(hThread);
				DWORD_PTR dwStartAddress = 0;
				pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
				ErrorLogs::LogFiles("CreateRemoteThread - Thread Created In Process | ThreadID: %d Fake Start Address: 0x%llx Actual Start Address: 0x%llx", ThreadID, dwStartAddress, pShellcode);
			}
		}
		else if (Options->ComboVariable == 1)
		{
			ptNtCreateThreadEx pfnNtCreateThreadEx = (ptNtCreateThreadEx)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");
			if (!Options->CheckBoxVarible2)
			{
				pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)pShellcode, pTargetBase, NULL, NULL, NULL, NULL, NULL);
				if (!hThread)
				{
					CloseHandle(ProcessHandle);
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					return ErrorLogs::LogFiles("RemoteThread: NtCreateThreadEx Thread NULL");
				}
				ErrorLogs::LogFiles("NtCreateThreadEx - Thread Created In Process | Handle: 0x%llx", hThread);
			}
			else
			{
				pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)(Process::SelectedProcess.BaseAddress + (Process::SelectedProcess.BaseSize / 3)), pTargetBase, true, NULL, NULL, NULL, NULL);
				if (!hThread)
				{
					CloseHandle(ProcessHandle);
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					return ErrorLogs::LogFiles("NtCreateThreadEx: CreateRemoteThread Thread NULL");
				}

				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hThread, &ctx);

				ctx.Rcx = (DWORD64)pShellcode;
				if (!SetThreadContext(hThread, &ctx))
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set Failed");
				else
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set.");

				auto dwResumeRet = ResumeThread(hThread);
				DWORD_PTR dwStartAddress = 0;
				pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
				ErrorLogs::LogFiles("NtCreateThreadEx - Thread Created In Process | ThreadID: %d Fake Start Address: 0x%llx Actual Start Address: 0x%llx", ThreadID, dwStartAddress, pShellcode);
			}
		}
		else if (Options->ComboVariable == 2)
		{
			ptRtlCreateUserThread pfnRtlCreateUserThread = (ptRtlCreateUserThread)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlCreateUserThread");
			if (!Options->CheckBoxVarible2)
			{
				pfnRtlCreateUserThread(ProcessHandle, NULL, 0, 0, 0, 0, pShellcode, pTargetBase, &hThread, NULL);
				if (!hThread)
				{
					CloseHandle(ProcessHandle);
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					return ErrorLogs::LogFiles("RemoteThread: RtlCreateUserThread Thread NULL");
				}
				ErrorLogs::LogFiles("RtlCreateUserThread - Thread Created In Process | Handle: 0x%llx", hThread);
			}
			else
			{
				pfnRtlCreateUserThread(ProcessHandle, NULL, true, 0, 0, 0, (LPTHREAD_START_ROUTINE)(Process::SelectedProcess.BaseAddress + (Process::SelectedProcess.BaseSize / 4)), pTargetBase, &hThread, NULL);
				if (!hThread)
				{
					CloseHandle(ProcessHandle);
					VirtualFreeEx(ProcessHandle, pTargetBase, 0, MEM_RELEASE);
					return ErrorLogs::LogFiles("NtCreateThreadEx: CreateRemoteThread Thread NULL");
				}

				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hThread, &ctx);

				ctx.Rcx = (DWORD64)pShellcode;
				if (!SetThreadContext(hThread, &ctx))
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set Failed");
				else
					ErrorLogs::LogFiles("NtCreateThreadEx - Thread Context Set.");

				auto dwResumeRet = ResumeThread(hThread);
				DWORD_PTR dwStartAddress = 0;
				pfnNtQueryInformationThread(hThread, 9, &dwStartAddress, sizeof(dwStartAddress), NULL);
				ErrorLogs::LogFiles("NtCreateThreadEx - Thread Created In Process | ThreadID: %d Fake Start Address: 0x%llx Actual Start Address: 0x%llx", ThreadID, dwStartAddress, pShellcode);
			}
		}

		if (Options->CheckBoxVarible3)
			AntiDebug::HideFromDebugger(hThread);

		ErrorLogs::LogFiles("ManualMap: Waiting For Thread To Finish");
		WaitForSingleObject(hThread, INFINITE);

		auto Injstop = std::chrono::high_resolution_clock::now();
		auto Injduration = std::chrono::duration_cast<std::chrono::milliseconds>(Injstop - Injstart);
		ErrorLogs::LogFiles("ManualMap: Thread Ended In %d MS, Cleaning Up", Injduration);

		VirtualFreeEx(ProcessHandle, pShellcode, 0, MEM_RELEASE);
		CloseHandle(hThread);
		CloseHandle(ProcessHandle);

		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
		ErrorLogs::LogFiles("[important] ManualMap: Injection Done In %d MS", duration);
	}
}