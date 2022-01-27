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
typedef BOOL (__stdcall *ptrCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
ptrCreateProcessW callCreateProcessW = nullptr;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL __stdcall hookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	dwCreationFlags = CREATE_SUSPENDED;
	BOOL hndl = callCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
	lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, 
	lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	if (wcsstr(lpApplicationName, L"gta_sa") != nullptr || wcsstr(lpApplicationName, L"proxy_sa") != nullptr)
	{
		SERVICE_STATUS_PROCESS ssp{ 0 };
		SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (NULL == schSCManager) return TRUE;
		SC_HANDLE schService = OpenServiceA(schSCManager, "FairPlayKD", SERVICE_ALL_ACCESS);
		if (schService == NULL)
		{
			CloseServiceHandle(schSCManager);
			return TRUE;
		}
		ControlService(schService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
		//DeleteService(schService); 
		//CreateServiceA(schSCManager, "FairPlayKD", "FairPlayKD", SERVICE_ACCESS_ALL, SERVICE_START_DEMAND)
		MessageBoxA(0, "Можете прицепить отладчик!", "HANDLE RIGHTS ESCALATING", MB_OK);
		StartServiceA(schService, 0, 0);
		CloseServiceHandle(schService); CloseServiceHandle(schSCManager);
		ParseAndLoad(lpProcessInformation->hProcess);
		#pragma warning(suppress: 26812)
		MH_DisableHook(MH_ALL_HOOKS);
	}
	return hndl;
}
void LoadHacks()
{
	#pragma warning(suppress: 6387)
	callCreateProcessW = (ptrCreateProcessW)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "CreateProcessW");
	#pragma warning(suppress: 26812)
	MH_Initialize(); 
	MH_CreateHook(callCreateProcessW, &hookedCreateProcessW, reinterpret_cast<LPVOID*>(&callCreateProcessW));
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

