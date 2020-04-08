#include "Common.h"
#include <olectl.h>
#include <memory>
#include <stdexcept>

namespace Helpers
{
	inline std::string CurrentPath()
	{
		char buffer[MAX_PATH];
		GetModuleFileNameA(NULL, buffer, MAX_PATH);
		std::string::size_type pos = std::string(buffer).find_last_of("\\/");
		return std::string(buffer).substr(0, pos);
	}

	inline bool CreateFolder(std::string Path)
	{
		std::wstring wPath = String2WString(Path);
		return CreateDirectory(wPath.c_str(), NULL);
	}

	inline std::wstring String2WString(const std::string s)
	{
		int len;
		int slength = (int)s.length() + 1;
		len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
		wchar_t* buf = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
		std::wstring r(buf);
		delete[] buf;
		return r;
	}

	inline std::string WString2String(const std::wstring wstr)
	{
		std::string str(wstr.begin(), wstr.end());
		return str;
	}

	inline bool RanAsAdmin(HANDLE hProcess)
	{
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
				fRet = Elevation.TokenIsElevated;
		}
		if (hToken)
			CloseHandle(hToken);

		return fRet;
	}

	inline bool CheckAlive(DWORD PID)
	{
		HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, PID);
		DWORD Return = WaitForSingleObject(hProcess, 0);
		CloseHandle(hProcess);
		return Return == WAIT_TIMEOUT;
	}

	inline bool DoesFileExist(const std::string& name) {
		// You can use GetFileAttributesA Instead
		std::ifstream file(name.c_str());
		return file.good();
	}

	std::string StringFormat(const char* fmt, ...)
	{
		// You can use std::format instead
		char text[256];
		va_list ap;

		va_start(ap, fmt);
		vsprintf_s(text, fmt, ap);
		va_end(ap);

		return (std::string)text;
	}

	inline bool DirectoryExists(const std::string& name)
	{
		DWORD FileAttributes = GetFileAttributes(String2WString(name).c_str());
		return (FileAttributes != INVALID_FILE_ATTRIBUTES &&
			(FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
	}

	DWORD_PTR ModuleBase(DWORD PID, std::string FullPath)
	{
		DWORD_PTR ModuleBase = 0;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID);
		if (snapshot != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W moduleInfo = { 0 };
			moduleInfo.dwSize = sizeof(MODULEENTRY32W);

			if (Module32FirstW(snapshot, &moduleInfo))
			{
				do
				{
					if (!_wcsicmp(moduleInfo.szExePath, Helpers::String2WString(FullPath).c_str()))
					{
						ModuleBase = (DWORD_PTR)moduleInfo.modBaseAddr;
					}
				} while (Module32NextW(snapshot, &moduleInfo));
				CloseHandle(snapshot);
			}
		}
		return ModuleBase;
	}

	void ClearPEModule(LPVOID pOptions)
	{
		sClearPEModule* Options = (sClearPEModule*)pOptions;

		PCWSTR FilePath = Helpers::String2WString(Options->FullPath).c_str();
		HANDLE hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			ErrorLogs::LogFiles("CreateThread: CreateFile failed in read mode");

		HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == 0)
		{
			ErrorLogs::LogFiles("CreateThread: CreateFileMapping failed");
			CloseHandle(hFile);
		}

		LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (lpFileBase == 0)
		{
			ErrorLogs::LogFiles("CreateThread: MapViewOfFile failed");
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
		}

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);
		if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			ErrorLogs::LogFiles("CreateThread: pNTHeader->Signature == IMAGE_NT_SIGNATURE");
			if (pNTHeader->FileHeader.SizeOfOptionalHeader)
			{
				int Loop = 0;
				DWORD_PTR ModuleBase = Helpers::ModuleBase(GetProcessId(Options->hProcess), Options->FullPath);
				while (!ModuleBase)
				{
					if (Loop > 10)
						return ErrorLogs::LogFiles("ClearPEModule: Could Not Locate Module");

					std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					ModuleBase = Helpers::ModuleBase(GetProcessId(Options->hProcess), Options->FullPath);
					Loop++;
				}

				if (ModuleBase)
				{
					DWORD Protect;
					WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
					BYTE pSourceData[4080] = { 0 };

					VirtualProtectEx(Options->hProcess, (void*)ModuleBase, Size, PAGE_EXECUTE_READWRITE, &Protect);
					WriteProcessMemory(Options->hProcess, (void*)ModuleBase, pSourceData, Size, nullptr);
					VirtualProtectEx(Options->hProcess, (void*)ModuleBase, Size, Protect, &Protect);
					ErrorLogs::LogFiles("CreateThread: Removed PE Headers");
				}
			}
		}
	}

	int IsFile64BitDLL(std::string Path)
	{
		if (!DoesFileExist(Path))
		{
			ErrorLogs::LogFiles("IsFile64BitDLL: File Doesnt Seem to Exist");
			return -1;
		}

		PCWSTR FilePath = Helpers::String2WString(Path).c_str();
		HANDLE hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			ErrorLogs::LogFiles("IsFile64BitDLL: CreateFile failed in read mode");

		HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == 0)
		{
			ErrorLogs::LogFiles("IsFile64BitDLL: CreateFileMapping failed");
			CloseHandle(hFile);
		}

		LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (lpFileBase == 0)
		{
			ErrorLogs::LogFiles("IsFile64BitDLL: MapViewOfFile failed");
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
		}

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);
			if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
			{
				if (pNTHeader->FileHeader.Characteristics != IMAGE_FILE_DLL)
				{
					ErrorLogs::LogFiles("IsFile64BitDLL: pNTHeader->FileHeader.Characteristics == IMAGE_FILE_DLL");
					return -1;
				}

				if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
					return false;
				else if (pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 ||
					pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
					return true;
				else
					ErrorLogs::LogFiles("IsFile64BitDLL: FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 or IMAGE_FILE_MACHINE_ARM64");
			}
			else
			{
				ErrorLogs::LogFiles("IsFile64BitDLL: pNTHeader->Signature != IMAGE_NT_SIGNATURE");
				CloseHandle(hFileMapping);
				CloseHandle(hFile);
			}
		}
		else
		{
			ErrorLogs::LogFiles("IsFile64BitDLL: pDosHeader->e_magic != IMAGE_DOS_SIGNATURE");
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
		}

		return -1;
	}
}