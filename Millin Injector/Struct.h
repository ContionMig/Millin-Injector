#pragma once
#include "Common.h"
#include <gdiplus.h>


#define RELOC_FLAG RELOC_FLAG64
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

struct CreateProcessS
{
	DWORD PID;
	HANDLE hProcess;
};

struct sClearPEModule
{
	HANDLE hProcess;
	std::string FullPath;
};

struct ModuleInfo
{
	std::string Name;
	std::string FullPath;

	DWORD_PTR BaseAddress;
	DWORD_PTR BaseSize;

	ModuleInfo(std::string Name = "Header", std::string FullPath = "Feature", DWORD_PTR BaseAddress = 0, DWORD_PTR BaseSize = 0)
		: Name(Name), FullPath(FullPath), BaseAddress(BaseAddress), BaseSize(BaseSize)
	{
	}
};

struct ImportList
{
	std::string FullPath;
	std::vector<std::string> importDescriptor;

	void Clear()
	{
		importDescriptor.clear();
	}
};

struct ProcessInfo
{
	HANDLE ProcessHandle;
	DWORD PID;

	std::string Name;
	std::string WindowName;
	std::string FullPath;
	std::string RenderingModule;

	DWORD_PTR BaseAddress;
	DWORD_PTR BaseSize;

	bool Is64;
	bool Elevated;

	int TotalModules;
	int TotalThreads;

	std::vector<ModuleInfo> Modules;

	bool Initialize;
	void Clear()
	{
		Modules.clear();
		RenderingModule = "";

		BaseAddress = 0;
		BaseSize = 0;

		TotalModules = 0;

		if (ProcessHandle)
			CloseHandle(ProcessHandle);

		Initialize = false;
	}
};

struct Processes
{
	std::vector<uintptr_t> PID;
	std::vector<std::string> Name;
	std::vector<std::string> WindowName;
	std::vector<std::string> FullPath;
	std::vector<int> Ram;
	std::vector<int> Threads;

	void Clear()
	{
		PID.clear();
		Name.clear();
		Ram.clear();
		FullPath.clear();
		WindowName.clear();
		Threads.clear();
	}

	size_t GetSize()
	{
		return PID.size();
	}
};

struct BITMAP_AND_BYTES {
	Gdiplus::Bitmap* bmp;
	int32_t* bytes;
};

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfHandles;
	ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

typedef struct _LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	HINSTANCE			hMod;
};


typedef DWORD(WINAPI* ptNtCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ LPVOID ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
);

typedef DWORD(WINAPI* ptRtlCreateUserThread)(
	HANDLE      ProcessHandle,
	PSECURITY_DESCRIPTOR  SecurityDescriptor,
	BOOL      CreateSuspended,
	ULONG     StackZeroBits,
	PULONG     StackReserved,
	PULONG     StackCommit,
	LPVOID     StartAddress,
	LPVOID     StartParameter,
	HANDLE      ThreadHandle,
	LPVOID     ClientID
);

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,                 // 0x00 MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation,            // 0x01
	MemoryMappedFilenameInformation,        // 0x02 UNICODE_STRING
	MemoryRegionInformation,                // 0x03
	MemoryWorkingSetExInformation           // 0x04

} MEMORY_INFORMATION_CLASS;

typedef struct _PEB_LDR_DATA {
	ULONG			Length;
	UCHAR			Initialized;
	ULONG64			SsHandle;
	LIST_ENTRY64	InLoadOrderModuleList;
	LIST_ENTRY64	InMemoryOrderModuleList;
	LIST_ENTRY64	InInitializationOrderModuleList;
	PVOID64			EntryInProgress;
	UCHAR			ShutdownInProgress;
	PVOID64			ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	BYTE				Reserved0;
	ULONG				Reserved1;
	ULONG64				Reserved3;
	ULONG64				ImageBaseAddress;
	ULONG64				LoaderData;
	ULONG64				ProcessParameters;
}PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64		InLoadOrderModuleList;
	LIST_ENTRY64		InMemoryOrderModuleList;
	LIST_ENTRY64		InInitializationOrderModuleList;
	ULONG64				BaseAddress;
	ULONG64				EntryPoint;
	ULONG				SizeOfImage;	//bytes
	UNICODE_STRING		FullDllName;
	UNICODE_STRING		BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef DWORD(NTAPI* ptNtAlertThread)(
	IN HANDLE	ThreadHandle
);

typedef DWORD(NTAPI* ptNtSuspendThread)(
	IN HANDLE	ThreadHandle,
	OUT PULONG	PreviousSuspendCount OPTIONAL
);

typedef NTSTATUS(NTAPI* ptNtQueryInformationThread)(
	HANDLE, 
	LONG, 
	PVOID, 
	ULONG, 
	PULONG
);

struct SECTION_INFO
{
	WORD Len;
	WORD MaxLen;
	wchar_t* szData;
	BYTE pData[MAX_PATH * 2];
};

typedef DWORD(NTAPI* pfNtAlertResumeThread)(
	IN HANDLE	ThreadHandle,
	OUT PULONG	SuspendCount
);

typedef DWORD(NTAPI* NpftQueryVirtualMemory)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
);