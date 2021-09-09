#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>

#define TOKEN 0x4b8

NTSTATUS ProtectProcess(DWORD PID);
NTSTATUS ProcessElevation(ULONG srcPid, ULONG targetPid);

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