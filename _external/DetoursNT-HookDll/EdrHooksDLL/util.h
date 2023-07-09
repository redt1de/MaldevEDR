#include <Windows.h>
#include <winternl.h>


//DWORD_PTR moduleBase;
//DWORD moduleSize;


#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread()  NtCurrentThread()

ULONG_PTR GetCurrentNestingLevel();
VOID IncrementCurrentNestingLevel();
VOID DecrementCurrentNestingLevel();

EXTERN_C int __cdecl sprintf(char* _Buffer, char* _Format, ...); // exported from ntdllp.lib, no user32.dll depends

EXTERN_C NTSTATUS NTAPI LdrGetDllHandle(IN PWSTR DllPath OPTIONAL, IN PULONG DllCharacteristics OPTIONAL, IN PUNICODE_STRING DllName, OUT PVOID* DllHandle);

BOOL isDllLoaded(const wchar_t* dllName) {

    UNICODE_STRING moduleFileName;
    RtlInitUnicodeString(&moduleFileName, dllName);

    HANDLE hModule;
    NTSTATUS status = LdrGetDllHandle(NULL, NULL, &moduleFileName, &hModule);
    if (status == 0) {
        // DLL is loaded
        return TRUE;
    }
    else {
        // DLL is not loaded
        return FALSE;
    }
}

/////////////////////// recursion stuffs ////////////////////////

PTEB GetCurrentTeb64()
{
    return (PTEB)__readgsqword(offsetof(NT_TIB64, Self));
}

PULONG_PTR GetCurrentNestingLevelPtr()
{
    // We don't have TLS APIs at our disposal, so using thread-local variables is a bit tricky.
    // Luckily, we can use some members of the TEB (which is already instantiated on a per-thread basis) for our advantage.
    // In this particular case where we only want to store a single integer value (the nesting level), we chose to "abuse"
    // the last slot in the TlsSlots array, since we know it is currently not used by any other 64-bit modules in WoW64 processes.
    return (PULONG_PTR)&GetCurrentTeb64()->TlsSlots[63];
}

ULONG_PTR GetCurrentNestingLevel()
{
    return *GetCurrentNestingLevelPtr();
}

VOID IncrementCurrentNestingLevel()
{
    (*GetCurrentNestingLevelPtr())++;
}

VOID DecrementCurrentNestingLevel()
{
    (*GetCurrentNestingLevelPtr())--;
}

/////////////////////// stack/frame corruption stuffs

//VOID NTAPI RtlPopFrame(PTEB_ACTIVE_FRAME Frame)
//{
//        NtCurrentTeb()->ActiveFrame = Frame->Previous;
//}
//
//VOID  NTAPI RtlPushFrame(PTEB_ACTIVE_FRAME Frame)
// {
//    Frame->Previous = NtCurrentTeb()->ActiveFrame;
//    NtCurrentTeb()->ActiveFrame = Frame;
// }
//
//PTEB_ACTIVE_FRAME  NTAPI RtlGetFrame(VOID)
// {
//   return NtCurrentTeb()->ActiveFrame;
//}