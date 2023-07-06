package dbgproc

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/redt1de/MaldevEDR/pkg/util"
	"golang.org/x/sys/windows"
)

func defaultCreateProcessCB(CreateProcessInfo) {}
func defaultLoadDllCB(LoadDllInfo)             {}
func defaultExitProcessCB(ExitProcess)         {}

func defaultErrCB(e error) {
	log.Fatal("dbgproc default error callback:" + e.Error())
}

type DbgSession struct {
	ProcessImage    string
	ProcessId       uint32
	ProcessHandle   *windows.Handle
	ThreadId        uint32
	ThreadHandle    *windows.Handle
	CreateProcessCB func(CreateProcessInfo)
	ExitProcessCB   func(ExitProcess)
	LoadDllCB       func(LoadDllInfo)
	pi              *windows.ProcessInformation
	Error           func(error)
	Logger          util.ConsoleLogger
}

func NewDebugProcess(exe string, dbgPriv bool) (*DbgSession, error) {
	if dbgPriv {
		err := AcquireDebugPrivilege()
		if err != nil {
			return nil, errors.New("failed to aquire debug privileges: " + err.Error())
		}

	}

	var pi windows.ProcessInformation
	var si windows.StartupInfo

	// Specify the executable to debug
	pCmdStr, err := windows.UTF16PtrFromString(exe) // bad
	if err != nil {
		return nil, err
	}

	// Create the process in a suspended state
	if err = windows.CreateProcess(
		pCmdStr, // Application name
		nil,     // Command line arguments
		nil,     // Process handle not inheritable
		nil,     // Thread handle not inheritable
		false,   // Set handle inheritance to FALSE
		// windows.DEBUG_PROCESS|windows.CREATE_SUSPENDED, // Creation flags
		windows.CREATE_SUSPENDED|windows.CREATE_NEW_CONSOLE,
		nil, // Use parent's environment block
		nil, // Use parent's starting directory
		&si, // Pointer to STARTUPINFO structure
		&pi, // Pointer to PROCESS_INFORMATION structure
	); err != nil {
		return nil, err
	}

	// open process for later use
	// pHand, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	// if err != nil {
	// 	return nil, errors.New("failed to obtain process handle: " + err.Error())
	// }
	pHand := pi.Process
	pThread := pi.Thread

	// // Attach debugger to the process
	// err = _DebugActiveProcess(pi.ProcessId)
	// if err != nil {
	// 	return nil, errors.New("failed to start debug session: " + err.Error())
	// }

	ret := DbgSession{
		ProcessId:       pi.ProcessId,
		ProcessImage:    exe,
		ProcessHandle:   &pHand,
		ThreadHandle:    &pThread,
		CreateProcessCB: defaultCreateProcessCB,
		LoadDllCB:       defaultLoadDllCB,
		ExitProcessCB:   defaultExitProcessCB,
		pi:              &pi,
		Error:           defaultErrCB,
		Logger:          util.ConsoleLogger{Module: "dbgproc"},
	}
	return &ret, nil

}

func (d *DbgSession) Stop() error {
	err := _DebugActiveProcessStop(d.ProcessId)
	if err != nil {
		return errors.New("failed to stop debug session: " + err.Error())
	}
	err = windows.CloseHandle(d.pi.Process)
	if err != nil {
		return errors.New("failed to close debug process handle: " + err.Error())
	}
	err = windows.CloseHandle(d.pi.Thread)
	if err != nil {
		return errors.New("failed to close debug thread handle: " + err.Error())
	}
	return nil
}

// gorouting resume, then debug loop
func (ds *DbgSession) Resume() {
	// Attach debugger to the process
	err := _DebugActiveProcess(ds.ProcessId)
	if err != nil {
		ds.Error(errors.New("failed to start debug session: " + err.Error()))
	}
	// println("RESUME 3")
	var debugEvent _DEBUG_EVENT
	debugEvent.ProcessId = ds.ProcessId
	debugEvent.ThreadId = ds.ThreadId

	go func() {
		_, err := windows.ResumeThread(ds.pi.Thread)
		if err != nil {
			ds.Error(errors.New("failed to resume debug process:" + err.Error()))

		}
	}()

	for {
		continueStatus := uint32(_DBG_CONTINUE)
		var milliseconds uint32 = syscall.INFINITE

		// Wait for a debug event...
		err := _WaitForDebugEvent(&debugEvent, milliseconds)
		if err != nil {
			ds.Error(errors.New("WaitForDebugEvent:" + err.Error()))
			continue // starting in a a goroutine, may hit this before thread is fully resumed so we just loop back around.
		}

		unionPtr := unsafe.Pointer(&debugEvent.U[0])
		switch debugEvent.DebugEventCode {
		case _CREATE_PROCESS_DEBUG_EVENT:
			debugInfo := (*_CREATE_PROCESS_DEBUG_INFO)(unionPtr)
			ds.CreateProcessCB(*(*CreateProcessInfo)(debugInfo))

		case _CREATE_THREAD_DEBUG_EVENT:
		case _EXIT_THREAD_DEBUG_EVENT:
		case _OUTPUT_DEBUG_STRING_EVENT:
		case _LOAD_DLL_DEBUG_EVENT:
			debugInfo := (*_LOAD_DLL_DEBUG_INFO)(unionPtr)
			ds.LoadDllCB(*(*LoadDllInfo)(debugInfo))
		case _UNLOAD_DLL_DEBUG_EVENT:
		case _RIP_EVENT:
		case _EXCEPTION_DEBUG_EVENT:
		case _EXIT_PROCESS_DEBUG_EVENT:
			debugInfo := (*_EXIT_PROCESS_DEBUG_INFO)(unionPtr)
			ds.ExitProcessCB(*(*ExitProcess)(debugInfo))
			return
		}

		err = _ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, continueStatus)
		if err != nil {
			ds.Error(errors.New("ContinueDebugEvent:" + err.Error()))
			// return
		}

	}

}

func AcquireDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		return fmt.Errorf("could not acquire debug privilege (OpenCurrentProcessToken): %v", err)
	}
	defer token.Close()

	privName, _ := windows.UTF16FromString("SeDebugPrivilege")
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, &privName[0], &luid)
	if err != nil {
		return fmt.Errorf("could not acquire debug privilege  (LookupPrivilegeValue): %v", err)
	}

	var tp windows.Tokenprivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("could not acquire debug privilege (AdjustTokenPrivileges): %v", err)
	}

	return nil
}
