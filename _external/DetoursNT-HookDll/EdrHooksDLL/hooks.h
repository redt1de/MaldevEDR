#pragma once
#include <windows.h>
#include <detours.h>
#include <intrin.h>
#include <DbgHelp.h>
#include <winternl.h>
#include "pipe.h"
#include "util.h"

#define VARNAME(Variable) (#Variable)
#pragma intrinsic(_ReturnAddress)



EXTERN_C NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

static fnNtAllocateVirtualMemory OrigNtAllocateVirtualMemory;

EXTERN_C NTSTATUS NTAPI  HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    NTSTATUS retval = OrigNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    IncrementCurrentNestingLevel();
   
    do {
        if (GetCurrentNestingLevel() > 1) {
            
            break;
        }
       CHAR jout[1000]; // overflow me please, fix later
        sprintf(jout, " { \"Type\":0, \"Event\":{\"Function\":\"NtAllocateVirtualMemory\",\"mode\":\"userland\",\"ReturnAddress\":\"0x%p\",\"Args\":{\"ProcessHandle\":\"0x%x\",\"BaseAddress\":\"0x%x\",\"ZeroBits\":\"0x%x\",\"RegionSize\":\"0x%x\",\"AllocationType\":\"0x%x\",\"Protect\":\"0x%02X\"}}}", _ReturnAddress(), ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect);

        OutputDebugStringA(jout);
        //WritePipe(jout);
       //PipeTest();
    } while (false);
    
       //return  OrigNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    DecrementCurrentNestingLevel();
    return retval;

}
