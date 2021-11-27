// Version: 0.0.1 ALFA
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <direct.h>
#include "Registry.h"
#include <TlHelp32.h>
#include "MMAP.h"
int main()
{
	system("color 5F"); 
	SetConsoleTitleA("Neutrino Injector by NtKernelMC | MFT 2021");
	printf("[INFO] Searching for MTA Province...\n");
	CEasyRegistry* reg = new CEasyRegistry(HKEY_LOCAL_MACHINE, "Software\\WOW6432Node\\Multi Theft Auto: Province All\\Common", false);
	if (reg)
	{
		std::string prov_path = reg->ReadString("GTA:SA Path");
		if (prov_path.empty())
		{
			printf("[ERROR] Can`t find installed game!\n");
			Sleep(3000); ExitProcess(0);
		}
		std::string tmpDir = prov_path;
		prov_path += "\\MTA\\Multi Theft Auto.exe"; delete reg;
		printf("[INFO] Found: %s\n[INFO] Starting Multi Theft Auto.exe...\n", prov_path.c_str());
		STARTUPINFOA info = { sizeof(info) }; PROCESS_INFORMATION processInfo;
		static char tmpS[256]; memset(tmpS, 0, sizeof(tmpS));
		sprintf(tmpS, "\"%s\" upd", prov_path.c_str());
		BOOL rslt = CreateProcessA(NULL, tmpS, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, tmpDir.c_str(), &info, &processInfo);
		if (rslt)
		{
			CONTEXT ctx{ 0 }; ctx.ContextFlags = CONTEXT_ALL; 
			#pragma warning(suppress: 6387)
			rslt = GetThreadContext(processInfo.hThread, &ctx);
			if (rslt)
			{
				printf("[DBG] Saving entry point instruction...\n"); DWORD dummy = NULL;
				PVOID oldCodeMem = VirtualAllocEx(processInfo.hProcess, 0, 5, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (!oldCodeMem)
				{
					printf("\nError: Unable to allocate memory for DLL data (Error: %d)\n", GetLastError());
					Sleep(3000); ExitProcess(0);
				}
				else printf("[MEMORY] Allocated data region at address: 0x%X\n", (DWORD)oldCodeMem);
				BYTE oldCode[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
				#pragma warning(suppress: 6387)
				rslt = ReadProcessMemory(processInfo.hProcess, (PVOID)ctx.Eax, oldCode, 5, &dummy);
				if (!rslt)
				{
					printf("\nError: Unable to read memory! Last Error Code: (%d)\n", GetLastError());
					Sleep(3000); ExitProcess(0);
				}
				rslt = WriteProcessMemory(processInfo.hProcess, oldCodeMem, oldCode, 5, &dummy);
				if (rslt)
				{
					CEasyRegistry* n_reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\Neutrino", true);
					if (n_reg)
					{
						n_reg->WriteInteger("StoredData", (DWORD)oldCodeMem);
						n_reg->WriteInteger("SpinLock", ctx.Eax);
						n_reg->WriteInteger("Thread", processInfo.dwThreadId);
						printf("[DBG] Instruction writed to allocated memory!\n");
						PVOID spinlock_addr = (PVOID)ctx.Eax; BYTE SpinLockCode[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
						#pragma warning(suppress: 4477)
						#pragma warning(suppress: 6273)
						printf("[DBG] Address of OEP for spinlock: 0x%X\n", spinlock_addr);
						DWORD Delta = (DWORD)spinlock_addr - (DWORD)spinlock_addr - 5;
						memcpy(&SpinLockCode[1], &Delta, 4); DWORD oldProt = 0x0;
						rslt = VirtualProtectEx(processInfo.hProcess, spinlock_addr, 5, PAGE_EXECUTE_READWRITE, &oldProt);
						if (!rslt)
						{
							printf("\nError: Unable to change memory access! Last Error Code: (%d)\n", GetLastError());
							Sleep(3000); ExitProcess(0);
						}
						printf("[DBG] Writing spinlock shellcode to process...\n");
						#pragma warning(suppress: 6387)
						rslt = WriteProcessMemory(processInfo.hProcess, spinlock_addr, SpinLockCode, 5, &dummy);
						if (rslt)
						{
							printf("[SUCCESS] Spinlock shellcode successfully placed!\n");
							char homePath[256]; memset(homePath, 0, sizeof(homePath));
							#pragma warning(suppress: 6031)
							_getcwd(homePath, 256); n_reg->WriteString("HomeDir", homePath); 
							rslt = VirtualProtectEx(processInfo.hProcess, spinlock_addr, 5, oldProt, &oldProt);
							if (!rslt)
							{
								printf("\nError: Unable to change memory access! Last Error Code: (%d)\n", GetLastError());
								Sleep(3000); ExitProcess(0);
							}
							MmapDLL(processInfo.hProcess, "NeutrinoAgent.dll"); delete n_reg;
							Sleep(3000); ExitProcess(0);
						}
						else printf("[ERROR] #2 Can`t write to process :( Last Error Code: %d\n", GetLastError());
					}
				}
				else printf("[ERROR] #1 Can`t write to process :( Last Error Code: %d\n", GetLastError());
			}
			else printf("[ERROR] Can`t obtain thread context. Last Error Code: %d\n", GetLastError());
			CloseHandle(processInfo.hThread); CloseHandle(processInfo.hProcess);
		}
		else printf("[ERROR] Cannot create process :( Last Error Code: %d\n", GetLastError());
	}
	while (true) { Sleep(100); }
	return 1;
}