#include <windows.h>

HANDLE hNamedPipe;
HANDLE hMutex;

const char* pipeName2 = "\\\\.\\pipe\\MalDevEDR\\hooks";

bool WritePipeSingle(const char* message)
{
    HANDLE hPipe = CreateFileA(pipeName2, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {

        return false;
    }
    
    // get message lenght without CRT strlen()
    DWORD msgLen = 0;
    int i;
    for (i = 0; message[i] != '\0'; i++)
    {
        msgLen++; //Counting the length.
    }

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(hPipe, message, msgLen, &bytesWritten, NULL);
    if (result)
    {

    }
    else
    {

    }

    CloseHandle(hPipe);
    return result;
}

bool WritePipeW(wchar_t* message)
{
    HANDLE hPipe = CreateFileA(pipeName2, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {

        return false;
    }

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(hPipe, message, sizeof(message), &bytesWritten, NULL);
    if (result)
    {

    }
    else
    {

    }

    CloseHandle(hPipe);
    return result;
}