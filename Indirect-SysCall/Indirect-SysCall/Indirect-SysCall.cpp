#include "Common.h"

PPEB GetPEB() 
{
    PPEB pPeb;
    __asm {
        mov eax, fs: [0x30]
        mov pPeb, eax
    }
    return pPeb;
}

bool IsStringEqual(LPCWSTR s1, LPCWSTR s2) 
{
    while (*s1 && *s2) 
    {
        if (*s1 != *s2 && (*s1 ^ 0x20) != *s2) return false;
        s1++;
        s2++;
    }
    return *s1 == *s2;
}

HMODULE GetHandlePEB(LPCWSTR moduleName) 
{
    PPEB pPeb = GetPEB();
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListEntry = pLdr->InMemoryOrderModuleList.Flink;

    while (pListEntry != &pLdr->InMemoryOrderModuleList) 
    {
        PVOID* pDllBase = (PVOID*)((BYTE*)pListEntry + 0x10);
        UNICODE_STRING* pBaseDllName = (UNICODE_STRING*)((BYTE*)pListEntry + 0x24);
        if (pBaseDllName->Buffer && IsStringEqual(pBaseDllName->Buffer, moduleName)) return (HMODULE)*pDllBase;
        pListEntry = pListEntry->Flink;
    }
    return NULL;
}

PVOID GetProcAddressPEB(HMODULE hModule, CONST CHAR* funcName) 
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExport->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) 
    {
        CONST CHAR* name = (CONST CHAR*)((BYTE*)hModule + pAddressOfNames[i]);
        if (strcmp(name, funcName) == 0) 
        {
            return (PVOID)((BYTE*)hModule +
                pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

SyscallData ResolveSyscall(PVOID funcAddress) 
{
    SyscallData data = { 0, NULL, 0 };
    BYTE* pByte = (BYTE*)funcAddress;

    std::wcout << L"[DEBUG] Bytes at " << std::hex << funcAddress << L": ";
    for (int k = 0; k < 16; k++) std::wcout << std::hex << (int)pByte[k] << L" ";
    std::wcout << std::endl;

    if (pByte[0] == 0xB8) 
    {
        data.SSN = *(DWORD*)(pByte + 1);
        if (pByte[5] == 0xBA) data.EdxValue = *(DWORD*)(pByte + 6);
        else data.EdxValue = 0x7FFE0300;
        

        for (int i = 0; i < 32; i++)
        {
            if (pByte[i] == 0xFF && pByte[i + 1] == 0x12) 
            {
                data.SyscallAddress = (PVOID)(pByte + i);
                break;
            }
            if (pByte[i] == 0xFF && pByte[i + 1] == 0xD2)
            {
                data.SyscallAddress = (PVOID)(pByte + i);
                break;
            }
            if (pByte[i] == 0x64 && pByte[i + 1] == 0xFF && pByte[i + 2] == 0x15 && pByte[i + 3] == 0xC0) 
            {
                data.SyscallAddress = (PVOID)(pByte + i);
                break;
            }
        }
    }
    return data;
}

int main()
{
    std::wcout << L"[+] Starting Indirect Syscall Demo (x86/PE32)" << std::endl;

    HMODULE hNtdll = GetHandlePEB(L"ntdll.dll");
    if (!hNtdll) {
        std::wcout << L"[-] Failed to find ntdll.dll" << std::endl;
        return 1;
    }
    std::wcout << L"[+] Found ntdll.dll at: 0x" << std::hex << hNtdll << std::endl;

    PVOID pNtAlloc = GetProcAddressPEB(hNtdll, "NtAllocateVirtualMemory");
    if (!pNtAlloc) {
        std::wcout << L"[-] Failed to find NtAllocateVirtualMemory" << std::endl;
        return 1;
    }
    std::wcout << L"[+] Found NtAllocateVirtualMemory at: 0x" << std::hex << pNtAlloc << std::endl;

    SyscallData sysData = ResolveSyscall(pNtAlloc);
    if (!sysData.SyscallAddress) {
        std::wcout << L"[-] Failed to resolve syscall gadget (not standard WoW64 stub?)" << std::endl;
        return 1;
    }

    std::wcout << L"[+] SSN: 0x" << std::hex << sysData.SSN << std::endl;
    std::wcout << L"[+] Syscall Gadget (call [edx] or call edx) at: 0x" << std::hex << sysData.SyscallAddress << std::endl;
    std::wcout << L"[+] EDX Target: 0x" << std::hex << sysData.EdxValue << std::endl;

    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 0x1000;
    ULONG zeroBits = 0;
    ULONG allocType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_EXECUTE_READWRITE;
    NTSTATUS status;

    PVOID pSyscallAddr = sysData.SyscallAddress;
    DWORD ssn = sysData.SSN;
    DWORD edxValue = sysData.EdxValue;

    PVOID* pBaseAddr = &baseAddress;
    PSIZE_T pRegionSize = &regionSize;

    __asm {
        push protect
        push allocType
        push pRegionSize
        push zeroBits
        push pBaseAddr
        push hProcess

        mov eax, ssn
        mov edx, edxValue

        call pSyscallAddr

        mov status, eax
    }

    if (status >= 0) std::wcout << L"[+] Success! Memory allocated at: 0x" << std::hex << baseAddress << std::endl;
    else std::wcout << L"[-] Failed with status: 0x" << std::hex << status << std::endl;
    return 0;
}