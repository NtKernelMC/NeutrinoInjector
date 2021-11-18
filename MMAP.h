#pragma once
typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(__stdcall* PDLL_MAIN)(HMODULE, DWORD, PVOID);
typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;
DWORD __stdcall LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject = nullptr;
    HMODULE hModule = nullptr;
    DWORD i = 0x0, Function = 0x0, count = 0x0, delta = 0x0;
    PDWORD ptr = nullptr; PWORD list = nullptr;
    PIMAGE_BASE_RELOCATION pIBR = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pIID = nullptr;
    PIMAGE_IMPORT_BY_NAME pIBN = nullptr;
    PIMAGE_THUNK_DATA FirstThunk = nullptr, OrigFirstThunk = nullptr;
    PDLL_MAIN EntryPoint = nullptr;
    ManualInject = (PMANUAL_INJECT)p;
    pIBR = ManualInject->BaseRelocation;
    delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); 
    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            list = (PWORD)(pIBR + 1);
            for (i = 0; i < count; i++)
            {
                if (list[i])
                {
                    ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }
        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }
    pIID = ManualInject->ImportDirectory;
    while (pIID->Characteristics)
    {
        OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);
        hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);
        if (!hModule) return FALSE;
        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
                if (!Function) return FALSE;
                FirstThunk->u1.Function = Function;
            }
            else
            {
                pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function) return FALSE;
                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }
    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); 
    }
    return TRUE;
}
DWORD __stdcall LoadDllEnd()
{
    return 0;
}
int __stdcall MmapDLL(HANDLE hProcess, std::string dll_path)
{
    PIMAGE_DOS_HEADER pIDH = nullptr;
    PIMAGE_NT_HEADERS pINH = nullptr;
    PIMAGE_SECTION_HEADER pISH = nullptr;
    HANDLE hThread = nullptr, hFile = nullptr, hToken = nullptr;
    PVOID buffer = nullptr, image = nullptr, mem = nullptr;
    DWORD i = 0x0, FileSize = 0x0, ExitCode = 0x0, read = 0x0;
    TOKEN_PRIVILEGES tp { 0 }; MANUAL_INJECT ManualInject { 0 };
    if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        tp.Privileges[0].Luid.LowPart = 20;
        tp.Privileges[0].Luid.HighPart = 0;

        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }
    printf("\nOpening the DLL.\n");
    hFile = CreateFileA(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
        return -1;
    }
    FileSize = GetFileSize(hFile, NULL);
    buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());
        CloseHandle(hFile);
        return -1;
    }
    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        printf("\nError: Unable to read the DLL (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return -1;
    }
    CloseHandle(hFile); pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError: Invalid executable image.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\nError: Invalid PE header.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        printf("\nError: The image is not DLL.\n");

        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    if (!hProcess)
    {
        printf("\nError: Unable to open target process (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    printf("\nAllocating memory for the DLL.\n");
    image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (!image)
    {
        printf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    printf("\nCopying headers into target process.\n");
    if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
    printf("\nCopying sections to target process.\n");
    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), 
        (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
    }
    printf("\nAllocating memory for the loader code.\n");
    mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    #pragma warning(suppress: 6273)
    #pragma warning(suppress: 4477)
    printf("\nLoader code allocated at 0x%X\n", mem);
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));
    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)
    ((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)
    ((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA = LoadLibraryA; ManualInject.fnGetProcAddress = GetProcAddress;
    printf("\nWriting loader code to target process.\n");
    WriteProcessMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), NULL);
    WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL); 
    printf("\nExecuting loader code.\n");
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1), mem, 0, NULL);
    if (!hThread)
    {
        printf("\nError: Unable to execute loader code (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &ExitCode);
    if (!ExitCode)
    {
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    #pragma warning(suppress: 6273)
    #pragma warning(suppress: 4477)
    printf("\nDLL injected at 0x%X\n", image);
    if (pINH->OptionalHeader.AddressOfEntryPoint)
    {
        #pragma warning(suppress: 6273)
        #pragma warning(suppress: 4477)
        printf("\nDLL entry point: 0x%X\n", (PVOID)((LPBYTE)image + pINH->OptionalHeader.AddressOfEntryPoint));
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}