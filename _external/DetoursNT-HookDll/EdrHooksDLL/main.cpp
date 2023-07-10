#include <windows.h>
#include <detours.h>
#include <psapi.h>
#include "hooks.h"
//#include "util.h"


//MSBuild DetoursNT.sln /property:Configuration=Release /property:Platform=x64
// x86 not working

//#pragma comment(lib,"ntdllp.lib") // using ntdllp.lib from WDK since it exports sprintf()
#pragma comment(lib,"kernel32.lib")
//#pragma comment(lib,"dbghelp.lib")



VOID SendModInfo(char * name) {
    ULONG_PTR dllBase;
    DWORD dllSize;
    PIMAGE_DOS_HEADER piDH;
    PIMAGE_NT_HEADERS piNH;

    HMODULE dllHand = GetModuleHandleA(name);
    dllBase = (ULONG_PTR)dllHand;
    if (dllBase != NULL) {
        piDH = (PIMAGE_DOS_HEADER)dllBase;
        piNH = (PIMAGE_NT_HEADERS)(dllBase + piDH->e_lfanew);
        dllSize = piNH->OptionalHeader.SizeOfImage;
        //if (name == NULL) {
           DWORD nSize = MAX_PATH;
            char processName[MAX_PATH];
            char* out;
            int inc = 0;
            GetModuleFileNameA(dllHand,processName,nSize);
            
            name = processName;
      
        //}
        char addrs[100];
        // {\"Type\":2, \"Module\":{\"Name\":\"%s\",\"Base\":\"0x%p\",\"Size\":\"0x%x\"}}}
        sprintf(addrs, "{\"Type\":2,\"Module\":{\"Name\":\"%s\",\"Base\":\"0x%p\",\"Size\":\"0x%x\"}}", name, dllBase, dllSize);
        OutputDebugStringA(addrs);
    }
}

__declspec(dllexport) void __cdecl ExportedFunction(void)
{
}

DWORD WINAPI MainThread(LPVOID param)
{
    // report back to client with some info for symbols
    SendModInfo(NULL);
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
    return 1;
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
        CreateThread(0, 0, MainThread, hModule, 0, 0);

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

