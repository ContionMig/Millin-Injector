#include "Common.h"
#include <psapi.h>

namespace Process
{
	Processes ProcessList;
	ProcessInfo SelectedProcess;
	ImportList Imports;

	HANDLE ProcessHandle(std::wstring ProcessName)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		if (Process32First(snapshot, &process))
		{
			do
			{
				if (std::wstring(process.szExeFile) == ProcessName)
				{
					CloseHandle(snapshot);
					return OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.th32ProcessID);
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return NULL;
	}

	HANDLE ProcessHandle(DWORD PID, DWORD Perms)
	{
		return OpenProcess(Perms, FALSE, PID);
	}

	DWORD GetProcessID(std::wstring ProcessName)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		if (Process32First(snapshot, &process))
		{
			do
			{
				if (std::wstring(process.szExeFile) == ProcessName)
				{
					CloseHandle(snapshot);
					return process.th32ProcessID;
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return NULL;
	}

	std::string GetProcessName(DWORD PID)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		if (Process32First(snapshot, &process))
		{
			do
			{
				if (process.th32ProcessID == PID)
				{
					CloseHandle(snapshot);
					return Helpers::WString2String(std::wstring(process.szExeFile));
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return NULL;
	}

	DWORD ParentProcessID(DWORD PID)
	{
		HANDLE hSnapshot;
		PROCESSENTRY32 pe32;

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) return 0;
		do {
			if (pe32.th32ProcessID == PID)
			{
				CloseHandle(hSnapshot);
				return pe32.th32ParentProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
		CloseHandle(hSnapshot);
		return 0;
	}

	CreateProcessS CreateProgram(std::string Path)
	{
		CreateProcessS Information;
		STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };
		PROCESS_INFORMATION ProcessInfo;
		if (CreateProcessA(Path.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
		{
			Information.PID = ProcessInfo.dwProcessId;
			Information.hProcess = ProcessInfo.hProcess;
			return Information;
		}
	}

	std::vector<DWORD> GetThreadIDs(DWORD PID)
	{
		std::vector<DWORD> tids;
		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return { 0 };

		PROCESSENTRY32 pe = { sizeof(pe) };
		if (::Process32First(hSnapshot, &pe))
		{
			do
			{
				if (pe.th32ProcessID == PID)
				{
					THREADENTRY32 te = { sizeof(te) };
					if (Thread32First(hSnapshot, &te))
					{
						do {
							if (te.th32OwnerProcessID == PID)
							{
								tids.push_back(te.th32ThreadID);
							}
						} while (Thread32Next(hSnapshot, &te));
					}
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}

		CloseHandle(hSnapshot);
		return tids;
	}

	size_t GetRamUsage(DWORD PID)
	{
		HANDLE hProcess = ProcessHandle(PID, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!hProcess)
			return 0;

		PROCESS_MEMORY_COUNTERS_EX ProcessMemoryCounter;
		GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&ProcessMemoryCounter, sizeof(ProcessMemoryCounter));
		CloseHandle(hProcess);
		return (ProcessMemoryCounter.PrivateUsage / 1024 / 1024);
	}

	BOOL CALLBACK EnumWindowCallback(HWND hWnd, LPARAM lparam) {
		int length = GetWindowTextLength(hWnd);
		LPTSTR buffer = new TCHAR[1000];
		GetWindowText(hWnd, buffer, length + 1);
		std::string windowTitle(Helpers::WString2String(buffer));

		DWORD processID;
		GetWindowThreadProcessId(hWnd, &processID);
		if (IsWindowVisible(hWnd) && length != 0) 
		{
			for (int i = 0; i < ProcessList.GetSize(); i++)
			{
				if (ProcessList.PID[i] == processID)
					ProcessList.WindowName[i] = windowTitle;
			}
		}
		return TRUE;
	}

	void RefreshProcessList()
	{
		ErrorLogs::LogFiles("Refreshing Process List");
		auto start = std::chrono::high_resolution_clock::now();

		LPTSTR Path = new TCHAR[1000];

		Process::ProcessList.Clear();
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);
		if (Process32First(snapshot, &process))
		{
			do {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.th32ProcessID);
				if (hProcess != INVALID_HANDLE_VALUE && GetModuleFileNameEx(hProcess, NULL, Path, MAX_PATH))
				{
					Process::ProcessList.FullPath.push_back(Helpers::WString2String(Path));
					Process::ProcessList.WindowName.push_back(" ");
					Process::ProcessList.PID.push_back(process.th32ProcessID);
					Process::ProcessList.Threads.push_back(process.cntThreads);
					Process::ProcessList.Ram.push_back(Process::GetRamUsage(process.th32ProcessID));
					Process::ProcessList.Name.push_back(Helpers::WString2String(std::wstring(process.szExeFile)));
				}
			} while (Process32Next(snapshot, &process));
			CloseHandle(snapshot);
		}

		EnumWindows(EnumWindowCallback, NULL);

		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
		ErrorLogs::LogFiles("Done Refreshing Process List: %d MS", duration);
	}

	void RefreshSelect(LPVOID pOptions)
	{
		int ShowAllModules = *(int*)(pOptions);
		ErrorLogs::LogFiles("Refreshing Selected Process");
		auto start = std::chrono::high_resolution_clock::now();
		Process::SelectedProcess.Clear();

		if (!Helpers::DoesFileExist(SelectedProcess.FullPath))
			return ErrorLogs::LogFiles("DoesFileExist Failed: %s", SelectedProcess.FullPath.c_str());

		if (!Helpers::CheckAlive(SelectedProcess.PID))
			return ErrorLogs::LogFiles("CheckAlive Failed");

		SelectedProcess.ProcessHandle = ProcessHandle(SelectedProcess.PID);
		if (SelectedProcess.ProcessHandle == INVALID_HANDLE_VALUE)
			return ErrorLogs::LogFiles("ProcessHandle Failed");

		BOOL is64Process = FALSE;
		if (!IsWow64Process(SelectedProcess.ProcessHandle, &is64Process))
			ErrorLogs::LogFiles("IsWow64Process Failed");
		else
			SelectedProcess.Is64 = !is64Process;

		SelectedProcess.Elevated = Helpers::RanAsAdmin(SelectedProcess.ProcessHandle);

		if (ShowAllModules)
		{
			MEMORY_BASIC_INFORMATION MBI{ 0 };
			NpftQueryVirtualMemory pfnNtQueryVirtualMemory = (NpftQueryVirtualMemory)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryVirtualMemory");
			while (NT_SUCCESS(pfnNtQueryVirtualMemory(SelectedProcess.ProcessHandle, MBI.BaseAddress, MemoryBasicInformation, &MBI, sizeof(MEMORY_BASIC_INFORMATION), nullptr)))
			{
				// https://github.com/SLAUC91/DLLFinder/blob/master/DLLFinder/Process.cpp
				if (!(MBI.State & MEM_COMMIT))
				{
					MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;
					continue;
				}

				SECTION_INFO section_info;
				if (!NT_SUCCESS(pfnNtQueryVirtualMemory(SelectedProcess.ProcessHandle, MBI.BaseAddress, MemoryMappedFilenameInformation, &section_info, sizeof(SECTION_INFO), nullptr)))
				{
					MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;
					continue;
				}

				void* hDll = MBI.BaseAddress;
				SIZE_T SizeOfImage = MBI.RegionSize;
				MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;

				while (NT_SUCCESS(pfnNtQueryVirtualMemory(SelectedProcess.ProcessHandle, MBI.BaseAddress, MemoryBasicInformation, &MBI, sizeof(MEMORY_BASIC_INFORMATION), nullptr)))
				{
					SECTION_INFO section_info2;
					if (!NT_SUCCESS(pfnNtQueryVirtualMemory(SelectedProcess.ProcessHandle, MBI.BaseAddress, MemoryMappedFilenameInformation, &section_info2, sizeof(SECTION_INFO), nullptr)))
						break;

					if (wcscmp(section_info.szData, section_info2.szData))
						break;

					MBI.BaseAddress = reinterpret_cast<BYTE*>(MBI.BaseAddress) + MBI.RegionSize;
					SizeOfImage += MBI.RegionSize;
				}

				wchar_t* pDllName = &section_info.szData[section_info.Len / sizeof(wchar_t) - 1];
				while (*(pDllName-- - 2) != '\\');
				if (!_wcsicmp(pDllName, Helpers::String2WString(SelectedProcess.Name).c_str()))
				{
					SelectedProcess.BaseAddress = (DWORD_PTR)hDll;
					SelectedProcess.BaseSize = (DWORD_PTR)SizeOfImage;
				}

				if (!_wcsicmp(pDllName, L"DXCore.dll"))
					SelectedProcess.RenderingModule += "DirectX Core, ";
				else if (!_wcsicmp(pDllName, L"d3d9.dll"))
					SelectedProcess.RenderingModule += "DirectX 9, ";
				else if (!_wcsicmp(pDllName, L"d3d10.dll"))
					SelectedProcess.RenderingModule += "DirectX 10, ";
				else if (!_wcsicmp(pDllName, L"d3d11.dll"))
					SelectedProcess.RenderingModule += "DirectX 11, ";
				else if (!_wcsicmp(pDllName, L"opengl32.dll"))
					SelectedProcess.RenderingModule += "OpenGL, ";

				SelectedProcess.Modules.push_back(ModuleInfo(Helpers::WString2String(pDllName), Helpers::WString2String(section_info.szData).c_str(), (DWORD_PTR)hDll, (DWORD_PTR)SizeOfImage));
				SelectedProcess.TotalModules++;
			}
		}
		else
		{
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, SelectedProcess.PID);
			if (snapshot != INVALID_HANDLE_VALUE)
			{
				MODULEENTRY32W moduleInfo = { 0 };
				moduleInfo.dwSize = sizeof(MODULEENTRY32W);

				if (Module32FirstW(snapshot, &moduleInfo))
				{
					do
					{
						if (!_wcsicmp(moduleInfo.szModule, Helpers::String2WString(SelectedProcess.Name).c_str()))
						{
							SelectedProcess.BaseAddress = (DWORD_PTR)moduleInfo.modBaseAddr;
							SelectedProcess.BaseSize = (DWORD_PTR)moduleInfo.dwSize;
						}

						if (!_wcsicmp(moduleInfo.szModule, L"DXCore.dll"))
							SelectedProcess.RenderingModule += "DirectX Core, ";
						else if (!_wcsicmp(moduleInfo.szModule, L"d3d9.dll"))
							SelectedProcess.RenderingModule += "DirectX 9, ";
						else if (!_wcsicmp(moduleInfo.szModule, L"d3d10.dll"))
							SelectedProcess.RenderingModule += "DirectX 10, ";
						else if (!_wcsicmp(moduleInfo.szModule, L"d3d11.dll"))
							SelectedProcess.RenderingModule += "DirectX 11, ";
						else if (!_wcsicmp(moduleInfo.szModule, L"opengl32.dll"))
							SelectedProcess.RenderingModule += "OpenGL, ";

						SelectedProcess.Modules.push_back(ModuleInfo(Helpers::WString2String(moduleInfo.szModule), Helpers::WString2String(moduleInfo.szExePath).c_str(), (DWORD_PTR)moduleInfo.modBaseAddr, (DWORD_PTR)moduleInfo.modBaseSize));
						SelectedProcess.TotalModules++;
					} while (Module32NextW(snapshot, &moduleInfo));
					CloseHandle(snapshot);
				}
			}
		}

		Process::Imports.FullPath = Process::SelectedProcess.Modules[0].FullPath;
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Process::RefeshSelectImport, NULL, NULL, NULL);

		SelectedProcess.Initialize = true;

		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
		ErrorLogs::LogFiles("Done Refreshing Selected: %d MS", duration);
	}

	void RefeshSelectImport()
	{
		// https://gist.github.com/mrexodia/1f9c5aa6570f6c782194
		Imports.Clear();

		auto hFile = CreateFileA(Imports.FullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
			return ErrorLogs::LogFiles("[Imports] CreateFile Failed");

		//map the file
		auto hMappedFile = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
		if (!hMappedFile)
			return ErrorLogs::LogFiles("[Imports] CreateFileMappingA Failed");

		//map the sections appropriately
		auto fileMap = MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
		if (!fileMap)
			return ErrorLogs::LogFiles("[Imports] MapViewOfFile Failed");

		auto pidh = PIMAGE_DOS_HEADER(fileMap);
		if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
			return ErrorLogs::LogFiles("[Imports] pidh->e_magic != IMAGE_DOS_SIGNATURE");

		auto pnth = PIMAGE_NT_HEADERS(ULONG_PTR(fileMap) + pidh->e_lfanew);
		if (pnth->Signature != IMAGE_NT_SIGNATURE)
			return ErrorLogs::LogFiles("[Imports] pnth->Signature != IMAGE_NT_SIGNATURE");

		if (pnth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return ErrorLogs::LogFiles("[Imports] pnth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC"); 

		auto importDir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		Imports.importDescriptor.push_back(Helpers::StringFormat("RVA : %08X\n", importDir.VirtualAddress));
		Imports.importDescriptor.push_back(Helpers::StringFormat("Size: %08X\n\n", importDir.Size));

		if (!importDir.VirtualAddress || !importDir.Size)
			return ErrorLogs::LogFiles("[Imports] No Import directory!");

		auto importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ULONG_PTR(fileMap) + importDir.VirtualAddress);
		if (!IsBadReadPtr((char*)fileMap + importDir.VirtualAddress, 0x1000))
		{
			for (; importDescriptor->FirstThunk; importDescriptor++)
			{
				Imports.importDescriptor.push_back(Helpers::StringFormat("OriginalFirstThunk: %08X\n", importDescriptor->OriginalFirstThunk));
				if (!IsBadReadPtr((char*)fileMap + importDescriptor->Name, 0x1000))
					Imports.importDescriptor.push_back(Helpers::StringFormat("              Name: %08X \"%s\"\n", importDescriptor->Name, (char*)fileMap + importDescriptor->Name));
				else
					Imports.importDescriptor.push_back(Helpers::StringFormat("              Name: %08X INVALID\n", importDescriptor->Name));
				Imports.importDescriptor.push_back(Helpers::StringFormat("        FirstThunk: %08X\n", importDescriptor->FirstThunk));

				auto thunkData = PIMAGE_THUNK_DATA(ULONG_PTR(fileMap) + importDescriptor->FirstThunk);
				for (; thunkData->u1.AddressOfData; thunkData++)
				{
					auto rva = ULONG_PTR(thunkData) - ULONG_PTR(fileMap);

					auto data = thunkData->u1.AddressOfData;
					if (data & IMAGE_ORDINAL_FLAG)
						Imports.importDescriptor.push_back(Helpers::StringFormat("              Ordinal: %08X\n", data & ~IMAGE_ORDINAL_FLAG));
					else
					{
						auto importByName = PIMAGE_IMPORT_BY_NAME(ULONG_PTR(fileMap) + data);
						if (!IsBadReadPtr(importByName, 0x1000))
							Imports.importDescriptor.push_back(Helpers::StringFormat("             Function: %08X \"%s\"\n", data, (char*)importByName->Name));
						else
							Imports.importDescriptor.push_back(Helpers::StringFormat("             Function: %08X INVALID\n", data));
					}
				}

				Imports.importDescriptor.push_back("");
			}
		}
		else
			return ErrorLogs::LogFiles("[Imports] INVALID IMPORT DESCRIPTOR!");
	}
}