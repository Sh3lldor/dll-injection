#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include "tlhelp32.h"
#include <stdio.h>
#include <userenv.h>
#include <netsh.h>
#include <processthreadsapi.h>
#include "apc_injection.h"


int main() {
	apc_injection();
	getchar();
	return 0;
	/*
	HANDLE process;
	HANDLE specific_process;
	HANDLE remoteThread;
	tagPROCESSENTRY32 pe;
	tagTHREADENTRY32 te;
	DWORD remote_pid;
	DWORD threads;
	BOOL succeed;
	LPVOID alloc_space;
	LPVOID loadLibraryAddress;
	BOOL ok = 0;
	char process_name[20];
	char dll_path[100];
	printf("enter process name to inject -->");
	scanf("%s", &process_name);
	printf("Process name --> %s\n", process_name);
	
	process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(tagPROCESSENTRY32);
	//te.dwSize = sizeof(tagTHREADENTRY32);
	if (Process32First(process, &pe)) {
		do {
			//printf("%s, %s", process_name, pe.szExeFile);
			if (!(strcmp(process_name, pe.szExeFile))) {
				remote_pid = pe.th32ProcessID;
				//threads = pe.cntThreads;
				
				printf("PID of the process --> %d\n", remote_pid);
				ok = 1;
				break;
			}
		} while (Process32Next(process, &pe));
	}
	if (!ok) {
		printf("Cant find the specific process, Exsiting !");
		return 1;
	}
	printf("enter dll path -->");
	scanf("%s", &dll_path);
	printf("dll_path --> %s", dll_path);
	specific_process = OpenProcess(PROCESS_ALL_ACCESS, false, remote_pid);
	if (specific_process == NULL) {
		printf("Cant get handle to the process, Exsiting !");
		return 1;
	}
	alloc_space = VirtualAllocEx(specific_process, NULL, strlen(dll_path)+ 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (alloc_space == NULL) {
		printf("Cant alloc process memory");
		return 1;
	}
	succeed = WriteProcessMemory(specific_process, alloc_space, dll_path, strlen(dll_path)+1, NULL);
	if (!succeed) {
		printf("Cant write to memory of the remote process, Exsiting ! ErrCode:%d",GetLastError());
		CloseHandle(specific_process);
		return 1;
	}
	loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	remoteThread = CreateRemoteThread(specific_process, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, alloc_space, NULL, NULL);
	getchar();
	return 0;
	*/
}