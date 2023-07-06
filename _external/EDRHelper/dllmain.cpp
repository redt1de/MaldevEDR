#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include "detours.h"

#ifdef _WIN64
#pragma comment( lib, "detoursx64" )
#else
#pragma comment( lib, "detoursx86" )
#endif


// MSBuild ./EDRHelper.sln /property:Configuration=Release /property:Platform=x64 /NOIMPLIB /NOEXP
// MSBuild ./EDRHelper.sln /property:Configuration=Release /property:Platform=x86 /NOIMPLIB /NOEXP

extern "C" __declspec(dllexport) VOID AddImport(HANDLE hProcess,LPCSTR szInjectDllFullPath)
{   
   DetourUpdateProcessWithDll(hProcess, &szInjectDllFullPath, 1);
   return;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

