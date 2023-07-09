#include <windows.h>
#include <detours.h>
#include <psapi.h>
#include "hooks.h"
//#include "util.h"


//MSBuild DetoursNT.sln /property:Configuration=Release /property:Platform=x64
// x86 not working

#pragma comment(lib,"ntdllp.lib") // using ntdllp.lib from WDK since it exports sprintf()
#pragma comment(lib,"kernel32.lib")

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
        PipeInit();
     
      
      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());

      OrigNtAllocateVirtualMemory = NtAllocateVirtualMemory;
      DetourAttach((PVOID*)&OrigNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);

     // OrigNtWriteVirtualMemory = NtWriteVirtualMemory;
      //DetourAttach((PVOID*)&OrigNtWriteVirtualMemory, HookedNtWriteVirtualMemory);

      OrigNtProtectVirtualMemory = NtProtectVirtualMemory;
      //DetourAttach((PVOID*)&OrigNtProtectVirtualMemory, HookedNtProtectVirtualMemory); // NtProtectVirtualMemory is causing issues, app hangs

      DetourTransactionCommit();
      break;

    case DLL_PROCESS_DETACH:
      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());

      DetourDetach((PVOID*)&OrigNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
      //DetourDetach((PVOID*)&OrigNtWriteVirtualMemory, HookedNtWriteVirtualMemory);
      DetourDetach((PVOID*)&OrigNtProtectVirtualMemory, HookedNtProtectVirtualMemory);


      DetourTransactionCommit();
      break;

    case DLL_THREAD_ATTACH:

      break;

    case DLL_THREAD_DETACH:

      break;
  }

  return TRUE;
}

