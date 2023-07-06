#include <windows.h>
#include <detours.h>
#include "hooks.h"


#define VARNAME(Variable) (#Variable)
#pragma intrinsic(_ReturnAddress)

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread()  NtCurrentThread()


//MSBuild DetoursNT.sln /property:Configuration=Release /property:Platform=x64
// x86 not working

__declspec(dllexport) void __cdecl ExportedFunction(void)
{
}

EXTERN_C BOOL WINAPI NtDllMain(_In_ HINSTANCE hModule, _In_ DWORD dwReason, _In_ LPVOID lpvReserved )
{
  switch (dwReason)
  {
    case DLL_PROCESS_ATTACH:
      OrigNtAllocateVirtualMemory = NtAllocateVirtualMemory;
      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());
      DetourAttach((PVOID*)&OrigNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);

      DetourTransactionCommit();
      break;

    case DLL_PROCESS_DETACH:
      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());
      DetourDetach((PVOID*)&OrigNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
      DetourTransactionCommit();
      break;

    case DLL_THREAD_ATTACH:

      break;

    case DLL_THREAD_DETACH:

      break;
  }

  return TRUE;
}

