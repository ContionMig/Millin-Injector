#include "AntiDebug.h"

namespace AntiDebug
{
	inline BOOLEAN DebuggerPresent()
	{
		BOOL isDebuggerPresent = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
		if (isDebuggerPresent)
			return isDebuggerPresent;

		return IsDebuggerPresent();
	}

	inline BOOLEAN CheckNtGlobalFlag()
	{
		PVOID pPeb = (PVOID)__readgsqword(0x0C * sizeof(PVOID));
		DWORD offsetNtGlobalFlag = 0;
		offsetNtGlobalFlag = 0xBC;
		DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
		if (NtGlobalFlag & (0x10 | 0x20 | 0x40))
			return true;

		return false;
	}

	inline BOOLEAN CheckNtClose()
	{
		__try
		{
			CloseHandle((HANDLE)0x1234);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return true;
		}
		return false;
	}

	inline BOOLEAN CheckSystemDebugControl()
	{
		enum SYSDBG_COMMAND { SysDbgQueryModuleInformation = 0 };
		typedef NTSTATUS(__stdcall* ZW_SYSTEM_DEBUG_CONTROL)(IN SYSDBG_COMMAND Command, IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnLength OPTIONAL);
		static const NTSTATUS STATUS_DEBUGGER_INACTIVE = (NTSTATUS)0xC0000354L;
		ZW_SYSTEM_DEBUG_CONTROL ZwSystemDebugControl = (ZW_SYSTEM_DEBUG_CONTROL)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSystemDebugControl");
		if (ZwSystemDebugControl == NULL)
			return false;
		
		return ZwSystemDebugControl(SysDbgQueryModuleInformation, NULL, 0, NULL, 0, NULL) != STATUS_DEBUGGER_INACTIVE;
	}

	inline BOOLEAN CheckSystemDebugger()
	{
		typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
		{
			BOOLEAN DebuggerEnabled;
			BOOLEAN DebuggerNotPresent;
		} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
		enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
		typedef NTSTATUS(__stdcall* ZW_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
		ZW_QUERY_SYSTEM_INFORMATION ZwQuerySystemInformation;
		SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;
		ZwQuerySystemInformation = (ZW_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");
		if (ZwQuerySystemInformation && NT_SUCCESS(ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL)))
			if (Info.DebuggerEnabled || !Info.DebuggerNotPresent)
				return true;
		
		return false;
	}

	inline BOOLEAN CheckObjectList()
	{
		__try
		{
			typedef NTSTATUS(NTAPI* pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

			POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
			void* pMemory = NULL;
			NTSTATUS Status;
			ULONG Size = 0;

			// Get NtQueryObject
			pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress(
				GetModuleHandle(TEXT("ntdll.dll")),
				"NtQueryObject");

			// Get the size of the list
			Status = NtQO(NULL, ObjectTypesInformation, //ObjectAllTypesInformation
				&Size, sizeof(ULONG), &Size);

			// Allocate room for the list
			pMemory = VirtualAlloc(NULL, SIZE_T(Size), MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE);

			if (pMemory == NULL)
				return false;

			// Now we can actually retrieve the list
			Status = NtQO(GetCurrentProcess(), ObjectTypesInformation, pMemory, Size, NULL);

			// Status != STATUS_SUCCESS
			if (Status != STATUS_SUCCESS)
			{
				VirtualFree(pMemory, 0, MEM_RELEASE);
				return false;
			}

			// We have the information we need
			pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;

			unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;

			ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

			for (UINT i = 0; i < NumObjects; i++)
			{
				POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

				// The debug object will always be present
				wchar_t DebugObject[] = L"DebugObject";
				auto DebugObjectLength = wcslen(DebugObject) * sizeof(wchar_t);
				if (pObjectTypeInfo->TypeName.Length == DebugObjectLength && !memcmp(pObjectTypeInfo->TypeName.Buffer, DebugObject, DebugObjectLength))  //UNICODE_STRING is not NULL-terminated (pointed to by deepzero!)
				{
					// Are there any objects?
					if (pObjectTypeInfo->TotalNumberOfObjects || pObjectTypeInfo->TotalNumberOfHandles)
					{
						VirtualFree(pMemory, 0, MEM_RELEASE);
						return true;
					}
					else
					{
						VirtualFree(pMemory, 0, MEM_RELEASE);
						return false;
					}
				}

				// Get the address of the current entries
				// string so we can find the end
				pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

				// Add the size
				pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;

				// Skip the trailing null and alignment bytes
				ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(int)sizeof(void*);

				// Not pretty but it works
				if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
					tmp += sizeof(void*);
				pObjInfoLocation = ((unsigned char*)tmp);

			}

			VirtualFree(pMemory, 0, MEM_RELEASE);
			return false;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			puts("exception!");
			return false;
		}
	}

	inline BOOLEAN HideFromDebugger(HANDLE hThread)
	{
		typedef NTSTATUS(NTAPI* NT_SET_INFORMATION_THREAD)(
			IN HANDLE ThreadHandle,
			IN ULONG ThreadInformationClass,
			IN PVOID ThreadInformation,
			IN ULONG ThreadInformationLength
			);
		NT_SET_INFORMATION_THREAD NtSIT = (NT_SET_INFORMATION_THREAD)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetInformationThread");
		return NT_SUCCESS(NtSIT(hThread, 0x11, 0, 0));
	}

	inline BOOLEAN CheckProcessDebugObjectHandle()
	{
		typedef int (WINAPI* pNtQueryInformationProcess)
			(HANDLE, UINT, PVOID, ULONG, PULONG);

		DWORD_PTR DebugHandle = 0;
		int Status;
		ULONG ReturnSize = 0;

		// Get NtQueryInformationProcess
		pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");

		Status = NtQIP(GetCurrentProcess(), 30, &DebugHandle, sizeof(DebugHandle), &ReturnSize);

		if (Status != 0x00000000)
			return false;


		if (DebugHandle)
		{
			CloseHandle((HANDLE)DebugHandle);
			return true;
		}

		else
			return false;
	}

	inline BOOLEAN CheckProcessDebugPort()
	{
		// Much easier in ASM but C/C++ looks so much better
		typedef int (WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

		DWORD_PTR DebugPort = 0;
		ULONG ReturnSize = 0;
		int Status;

		// Get NtQueryInformationProcess
		pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");

		Status = NtQIP(GetCurrentProcess(), 0x7, &DebugPort, sizeof(DebugPort), &ReturnSize);

		if (Status != 0x00000000)
			return false;

		if (DebugPort)
			return true;
		else
			return false;
	}

	inline BOOLEAN CheckProcessDebugFlags()
	{
		// Much easier in ASM but C/C++ looks so much better
		typedef int (WINAPI* pNtQueryInformationProcess)
			(HANDLE, UINT, PVOID, ULONG, PULONG);

		DWORD NoDebugInherit = 0;
		int Status;

		// Get NtQueryInformationProcess
		pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");


		Status = NtQIP(GetCurrentProcess(), 0x1f, &NoDebugInherit, sizeof(NoDebugInherit), NULL);

		if (Status != 0x00000000)
		{
			return false;
		}

		if (NoDebugInherit == FALSE)
			return true;
		else
			return false;
	}

	inline BOOLEAN CheckDevices()
	{
		const char DebuggingDrivers[9][20] = {
			"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
			"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
			"\\\\.\\SIWVID", "\\\\.\\SYSER",
			"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
			"\0"
		};


		for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
			HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
			if (h != INVALID_HANDLE_VALUE)
			{
				CloseHandle(h);
				return true;
			}
			CloseHandle(h);
		}
		return false;
	}

	inline BOOLEAN CheckProcess()
	{
		std::string szProcesses[] = {
			("ollydbg.exe"),			// OllyDebug debugger
			("tcpview.exe"),			// Part of Sysinternals Suite
			("autoruns.exe"),			// Part of Sysinternals Suite
			("autorunsc.exe"),			// Part of Sysinternals Suite
			("filemon.exe"),			// Part of Sysinternals Suite
			("procmon.exe"),			// Part of Sysinternals Suite
			("regmon.exe"),				// Part of Sysinternals Suite
			("idaq.exe"),				// IDA Pro Interactive Disassembler
			("idaq64.exe"),				// IDA Pro Interactive Disassembler
			("ImmunityDebugger.exe"),	// ImmunityDebugger
			("Wireshark.exe"),			// Wireshark packet sniffer
			("dumpcap.exe"),			// Network traffic dump tool
			("HookExplorer.exe"),		// Find various types of runtime hooks
			("ImportREC.exe"),			// Import Reconstructor
			("PETools.exe"),			// PE Tool
			("LordPE.exe"),				// LordPE
			("SysInspector.exe"),		// ESET SysInspector
			("proc_analyzer.exe"),		// Part of SysAnalyzer iDefense
			("sysAnalyzer.exe"),		// Part of SysAnalyzer iDefense
			("sniff_hit.exe"),			// Part of SysAnalyzer iDefense
			("joeboxcontrol.exe"),		// Part of Joe Sandbox
			("joeboxserver.exe"),		// Part of Joe Sandbox
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