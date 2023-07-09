#include <windows.h>
#include <detours.h>
#include <psapi.h>
#include "hooks.h"
//#include "util.h"


//MSBuild DetoursNT.sln /property:Configuration=Release /property:Platform=x64
// x86 not working

#pragma comment(lib,"ntdllp.lib") // using ntdllp.lib from WDK since it exports sprintf()
#pragma comment(lib,"kernel32.lib")


static ULONG_PTR g_ImageBase;
static DWORD g_ImageSize;
static ULONG_PTR g_NtdllBase;
static DWORD g_NtdllSize;
static ULONG_PTR g_kernel32Base;
static DWORD g_kernel32Size;

VOID GetBaseAddresses() {
    PIMAGE_DOS_HEADER piDH;
    PIMAGE_NT_HEADERS piNH;

    g_NtdllBase = (ULONG_PTR)GetModuleHandle(TEXT("ntdll.dll"));
    piDH = (PIMAGE_DOS_HEADER)g_NtdllBase;
    piNH = (PIMAGE_NT_HEADERS)(g_NtdllBase + piDH->e_lfanew);

    g_NtdllSize = piNH->OptionalHeader.SizeOfImage;

    g_kernel32Base = (ULONG_PTR)GetModuleHandle(TEXT("kernel32.dll"));
    if (g_kernel32Base) {
        piDH = (PIMAGE_DOS_HEADER)g_kernel32Base;
        piNH = (PIMAGE_NT_HEADERS)(g_kernel32Base + piDH->e_lfanew);
        g_kernel32Size = piNH->OptionalHeader.SizeOfImage;
    }
}

VOID SendModInfo(const char * name) {
    ULONG_PTR dllBase;
    DWORD dllSize;
    PIMAGE_DOS_HEADER piDH;
    PIMAGE_NT_HEADERS piNH;

    dllBase = (ULONG_PTR)GetModuleHandleA(name);
    if (dllBase != NULL) {
        piDH = (PIMAGE_DOS_HEADER)dllBase;
        piNH = (PIMAGE_NT_HEADERS)(dllBase + piDH->e_lfanew);
        dllSize = piNH->OptionalHeader.SizeOfImage;
        char addrs[100];
        // {\"Type\":2, \"Module\":{\"Name\":\"%s\",\"Base\":\"0x%p\",\"Size\":\"0x%x\"}}}
        sprintf(addrs, "{\"Type\":2,\"Module\":{\"Name\":\"%s\",\"Base\":\"0x%p\",\"Size\":\"0x%x\"}}", name, dllBase, dllSize);
        OutputDebugStringA(addrs);
    }
}

__declspec(dllexport) void __cdecl ExportedFunction(void)
{
}

EXTERN_C BOOL WINAPI NtDllMain(_In_ HINSTANCE hModule, _In_ DWORD dwReason, _In_ LPVOID lpvReserved )
{
   /* MODULEINFO moduleInfo;
    GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO));
    moduleBase = (DWORD_PTR)moduleInfo.lpBaseOfDll;
    moduleSize = moduleInfo.SizeOfImage;*/
   
  switch (dwReason)
  {
    case DLL_PROCESS_ATTACH:
        //PipeInit();
        SendModInfo("ntdll.dll");
        SendModInfo("kernel32.dll");

      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());

      OrigNtAllocateVirtualMemory = NtAllocateVirtualMemory;
      DetourAttach((PVOID*)&OrigNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);

     // OrigNtWriteVirtualMemory = NtWriteVirtualMemory;
      //DetourAttach((PVOID*)&OrigNtWriteVirtualMemory, HookedNtWriteVirtualMemory);

     // OrigNtProtectVirtualMemory = NtProtectVirtualMemory;
      //DetourAttach((PVOID*)&OrigNtProtectVirtualMemory, HookedNtProtectVirtualMemory); // NtProtectVirtualMemory is causing issues, app hangs

      DetourTransactionCommit();
      break;

    case DLL_PROCESS_DETACH:
      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());

      DetourDetach((PVOID*)&OrigNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
      //DetourDetach((PVOID*)&OrigNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
     // DetourDetach((PVOID*)&OrigNtProtectVirtualMemory, HookedNtProtectVirtualMemory);


      DetourTransactionCommit();
      break;

    case DLL_THREAD_ATTACH:

      break;

    case DLL_THREAD_DETACH:

      break;
  }

  return TRUE;
}

