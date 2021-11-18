// Version: 0.0.1 ALFA
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <Windows.h>
#include <stdio.h>
#include "..\Registry.h"
#include "..\MMAP.h"
#include <string>
#include <winternl.h>
#include "MinHook.h"
#include <Psapi.h>
#pragma comment(lib, "libMinHook.x86.lib")
bool InjectDLL(HANDLE hProc, const std::string& DLL_Path)
{
	if (hProc == nullptr || DLL_Path.empty()) return false;
	long dll_size = DLL_Path.length() + 1;
	LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (MyAlloc == NULL) return false;
	int IsWriteOK = WriteProcessMemory(hProc, MyAlloc, DLL_Path.c_str(), dll_size, 0);
	if (IsWriteOK == 0) return false;
	DWORD dWord = NULL; 
	#pragma warning(suppress: 6387)
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
	if (ThreadReturn == NULL) return false;
	if ((hProc != NULL) && (MyAlloc != NULL) && (IsWriteOK != ERROR_INVALID_HANDLE) && (ThreadReturn != NULL)) return true;
	return false;
}
void ParseAndLoad(HANDLE hProc)
{
	CEasyRegistry* reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\Neutrino", false);
	if (reg)
	{
		std::string homePath = reg->ReadString("HomeDir");
		if (!homePath.empty())
		{
			WIN32_FIND_DATAA FindFileData{ 0 };
			HANDLE hFind = FindFirstFileExA((homePath + "\\*.dll").c_str(),
			FindExInfoStandard, &FindFileData, FindExSearchNameMatch, NULL, 0);
			if (hFind != INVALID_HANDLE_VALUE)
			{
				do
				{
					std::string full_name = homePath + "\\" + FindFileData.cFileName;
					if (full_name.find("NeutrinoAgent") == std::string::npos) InjectDLL(hProc, full_name);
				} while (FindNextFileA(hFind, &FindFileData));
				FindClose(hFind);
			}
		}
		delete reg;
	}
}
typedef HANDLE (__stdcall *ptrCreateRemoteThreadEx)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, 
LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
ptrCreateRemoteThreadEx callCreateRemoteThreadEx = nullptr;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
HANDLE __stdcall hookedCreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)
{
	HANDLE hndl = callCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize,
	lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
	char procPath[256]; memset(procPath, 0, sizeof(procPath));
	GetProcessImageFileNameA(hProcess, procPath, sizeof(procPath));
	if (strstr(procPath, "gta_sa") != nullptr || strstr(procPath, "proxy_sa") != nullptr)
	{
		static bool only_once = true;
		if (only_once)
		{
			only_once = false;
			ParseAndLoad(hProcess);
			#pragma warning(suppress: 26812)
			MH_DisableHook(MH_ALL_HOOKS);
		}
	}
	return hndl;
}
void LoadHacks()
{
	#pragma warning(suppress: 6387)
	callCreateRemoteThreadEx = (ptrCreateRemoteThreadEx)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateRemoteThreadEx");
	#pragma warning(suppress: 26812)
	MH_Initialize(); 
	MH_CreateHook(callCreateRemoteThreadEx, &hookedCreateRemoteThreadEx, reinterpret_cast<LPVOID*>(&callCreateRemoteThreadEx));
	MH_EnableHook(MH_ALL_HOOKS);
	CEasyRegistry* reg = new CEasyRegistry(HKEY_CURRENT_USER, "Software\\Neutrino", false);
	if (reg)
	{
		DWORD StoredCode = reg->ReadInteger("StoredData");
		DWORD SpinLockAddr = reg->ReadInteger("SpinLock");
		BYTE oldCode[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
		memcpy(oldCode, (PVOID)StoredCode, 5);
		DWORD oldProt = 0x0; VirtualProtect((PVOID)SpinLockAddr, 5, PAGE_EXECUTE_READWRITE, &oldProt);
		memcpy((PVOID)SpinLockAddr, oldCode, 5);
		VirtualProtect((PVOID)SpinLockAddr, 5, oldProt, &oldProt);
		DWORD thID = reg->ReadInteger("Thread");
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thID);
		if (hThread)
		{
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
		delete reg;
	}
}
int __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LoadHacks();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return 1;
}

