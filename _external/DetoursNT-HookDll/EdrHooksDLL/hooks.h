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


extern "C" VOID BackupStuffs(CONTEXT * context);

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
       CHAR jout[1000];
       /* static CHAR jout[1000];*/
        sprintf(jout, "{\"Function\":\"NtAllocateVirtualMemory\",\"mode\":\"userland\",\"ReturnAddress\":\"0x%p\",\"Args\":{\"ProcessHandle\":\"0x%x\",\"BaseAddress\":\"0x%x\",\"ZeroBits\":\"0x%x\",\"RegionSize\":\"0x%x\",\"AllocationType\":\"0x%x\",\"Protect\":\"0x%02X\"}}", _ReturnAddress(), ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect);
        //sprintf(jout, "{\"Function\":\"NtAllocateVirtualMemory\",\"mode\":\"userland\",\"Args\":{\"ProcessHandle\":\"0x%x\"}}", ProcessHandle);
        //sprintf(jout, "{\"Function\":\"NtAllocateVirtualMemory\",\"mode\":\"userland\",\"Args\":{\"ProcessHandle\":\"ABSOLUTE CUNT\"}}");
        OutputDebugStringA(jout);
        //WritePipe(jout);
       //PipeTest();
        
    } while (false);
    
       //return  OrigNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    DecrementCurrentNestingLevel();
    return retval;

}
////////////////////////////////////////////////////////////// NtProtectVirtualMemory //////////////////////////////////////////////
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

static fnNtProtectVirtualMemory OrigNtProtectVirtualMemory;

EXTERN_C NTSTATUS NTAPI  HookedNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    NTSTATUS retVal = OrigNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

    IncrementCurrentNestingLevel();

    do {
        if (GetCurrentNestingLevel() > 1) {
            break;
        }

      /*  
        - try char[2000]
        - rtlcontext thunk
        - 
        */

       // CHAR jout[1000];
       // sprintf(jout, "{\"Function\":\"NtProtectVirtualMemory\",\"mode\":\"userland\",\"Args\":{\"ProcessHandle\":\"0x%x\",\"BaseAddress\":\"0x%x\",\"NumberOfBytesToProtect\":\"0x%x\",\"NewAccessProtection\":\"0x%x\",\"OldAccessProtection\":\"0x%x\"}}", ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
       // WritePipeSingle(jout);
    } while (false);

    DecrementCurrentNestingLevel();
    return  retVal;

}