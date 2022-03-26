#include "Dispatcher.hpp"

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
#if DEBUG
	KdPrint(("[+] Driver loaded!\n"));
#endif

	DriverObject->DriverUnload = Dispatch::DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = Dispatch::DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Dispatch::DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch::DriverDispatch;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Cronos");
	PDEVICE_OBJECT DeviceObject;

	NTSTATUS status = IoCreateDevice(DriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Unable to create device! %d\n", status));
#endif
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Cronos");
	status = IoCreateSymbolicLink(&symLink, &devName);

	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Unable to create symbolic link! %d\n", status));
#endif
		IoDeleteDevice(DeviceObject);
		return status;
	}

	Ghost::GhostDriver(DriverObject);

	return status;
}