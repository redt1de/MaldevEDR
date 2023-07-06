#pragma once
#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include "pipe.h"
#include <intrin.h>


thread_local BOOL firstBlood = false;
thread_local CHAR jout[1000];
thread_local wchar_t buffer[1024];



////////////////////////////////////////////////////////////// NtAllocateVirtualMemory //////////////////////////////////////////////
typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
static fnNtAllocateVirtualMemory OrigNtAllocateVirtualMemory;

EXTERN_C NTSYSAPI NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NTAPI  HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    NTSTATUS tmp = OrigNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    if (!firstBlood) { // flag to prevent a recursive hook condition via thread_local
        firstBlood = true;
        //wsprintfA(jout, "{ \"Function\":\"NtAllocateVirtualMemory\",\"EventData\":{\"Protect\":\"0x%x\"}}\r\n", Protect);
        wsprintfA(jout, "{\"Function\":\"NtAllocateVirtualMemory\",\"Mode\":\"userland\",\"Args\":{\"ProcessHandle\":\"0x%x\",\"BaseAddress\":\"0x%x\",\"ZeroBits\":\"0x%x\",\"RegionSize\":\"0x%x\",\"AllocationType\":\"0x%x\",\"Protect\":\"0x%x\"}}", ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
        WritePipeSingle(jout);
    }

    return  tmp;//OrigNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);;

}
