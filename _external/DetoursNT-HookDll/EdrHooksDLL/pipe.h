#include <windows.h>
#include <winternl.h>

HANDLE hNamedPipe;
HANDLE hMutex;
const char* pipeName = "\\\\.\\pipe\\MalDevEDR\\hooks";
CRITICAL_SECTION CriticalSection;



VOID PipeInit() {
    hNamedPipe = CreateFileA(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hNamedPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("Failed to open the named pipe. Error code: ");
        return;
    }
}

VOID PipeTest() {
      
    if (hNamedPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("pipe isnt open");
        return;
    }
    const char* message = "Hello, named pipe!";

    DWORD msgLen = 0;
    int i;
    for (i = 0; message[i] != '\0'; i++)
    {
        msgLen++; //Counting the length.
    }
        DWORD bytesWritten;
        BOOL success = CallNamedPipeA(pipeName, (LPVOID)message, msgLen, NULL, 0, &bytesWritten, 500);
        if (!success) {
            //OutputDebugStringA("Failed to write to the named pipe. Error code: ");
            //CloseHandle(pipe);
            return;
        }
    }


//EXTERN_C NTSYSAPI NTSTATUS NTAPI NtWriteFile(
//    HANDLE FileHandle,
//    HANDLE Event,
//    PIO_APC_ROUTINE ApcRoutine,
//    PVOID ApcContext,
//    PIO_STATUS_BLOCK IoStatusBlock,
//    PVOID Buffer,
//    ULONG Length,
//    PLARGE_INTEGER ByteOffset,
//    PULONG Key
//    );
//
//void WritePipe(char message[]) {
//    
//    // Prepare parameters
//    HANDLE hFile;
//    OBJECT_ATTRIBUTES ObjectAttributes;
//    IO_STATUS_BLOCK IoStatusBlock;
//    UNICODE_STRING FileName;
//
//    RtlInitUnicodeString(&FileName, L"\\??\\PIPE\\MalDevEDR\\hooks");
//    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//    NTSTATUS status = NtOpenFile(&hFile, GENERIC_WRITE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_WRITE, 0);
//    if (!NT_SUCCESS(status)) {
//       // OutputDebugStringA("pipe open error");
//        return; // Error opening file
//    }
//   
//    // Prepare to write data
//    DWORD msgLen = 0;
//    int i;
//    for (i = 0; message[i] != '\0'; i++)
//    {
//        msgLen++; //Counting the length.
//    }
//    status = NtWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, message, msgLen, NULL, NULL);
//    if (!NT_SUCCESS(status)) {
//        //OutputDebugStringA("pipe write error");
//        return; // Error writing file
//    }
//
//    // Close the file handle
//    NtClose(hFile);
//     return;
//}


//bool WritePipeSingle(const char* message)
//{
//    const char* pipeName = "\\\\.\\pipe\\MalDevEDR\\hooks";
//    HANDLE hPipe = CreateFileA(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
//    if (hPipe == INVALID_HANDLE_VALUE)
//    {
//        OutputDebugStringA("Failed to open pipe\n");
//        return false;
//    }
//   
//    // get message lenght without CRT strlen()
//    DWORD msgLen = 0;
//    int i;
//    for (i = 0; message[i] != '\0'; i++)
//    {
//        msgLen++; //Counting the length.
//    }
//    
//    DWORD bytesWritten = 0;
//    BOOL result = WriteFile(hPipe, message, msgLen, &bytesWritten, NULL);
//    if (result)
//    {
//
//    }
//    else
//    {
//        OutputDebugStringA("Failed to write pipe\n");
//    }
//   
//    CloseHandle(hPipe);
//    
//    return result;
//}
//
//
//
//
//DWORD WINAPI writeToPipe(const char* message) {
//    DWORD bytesWritten;
//
//    EnterCriticalSection(&CriticalSection);
//
//    // Open the existing named pipe
//    HANDLE pipe = CreateFileA(
//        pipeName,
//        GENERIC_WRITE,
//        0,
//        NULL,
//        OPEN_EXISTING,
//        0,
//        NULL
//    );
//
//    if (pipe == INVALID_HANDLE_VALUE) {
//        OutputDebugStringA("Failed to open pipe\n");
//        LeaveCriticalSection(&CriticalSection);
//        return 1;
//    }
//
//    // Write the message to the pipe
//    if (!WriteFile(
//        pipe,
//        message,
//        strlen(message),
//        &bytesWritten,
//        NULL
//    )) {
//        OutputDebugStringA("Failed to write to pipe\n");
//    }
//
//    // Close the pipe
//    CloseHandle(pipe);
//
//    LeaveCriticalSection(&CriticalSection);
//    return 0;
//}
