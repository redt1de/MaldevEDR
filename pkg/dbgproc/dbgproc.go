package dbgproc

import (
	"errors"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func defaultCreateProcessCB(CreateProcessInfo) {}
func defaultLoadDllCB(LoadDllInfo)             {}
func defaultProcessExitCB(LoadDllInfo)         {}

type DbgSession struct {
	ProcessImage  string
	ProcessPid    uint32
	ProcessHandle *windows.Handle
	// allowExit       chan bool
	WantsExit       bool
	CreateProcessCB func(CreateProcessInfo)
	ExitProcessCB   func(ExitProcess)
	LoadDllCB       func(LoadDllInfo)
	pi              *windows.ProcessInformation
	// Logger          util.LogIface
}

func NewDebugProc(exe string, dbgPriv bool) (*DbgSession, error) {
	if dbgPriv {
		err := AcquireDebugPrivilege()
		if err != nil {
			return nil, errors.New("failed to aquire debug privileges: " + err.Error())
		}

	}
	pi, err := createSuspendedProcess(exe)
	if err != nil {
		return nil, errors.New("failed to create process: " + err.Error())
	}

	pHand, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	// defer windows.CloseHandle(pHand)
	if err != nil {
		return nil, errors.New("failed to obtain process handle: " + err.Error())
	}

	var ret DbgSession
	//ret.allowExit = make(chan bool)
	ret.ProcessPid = pi.ProcessId
	ret.ProcessImage = exe
	ret.ProcessHandle = &pHand
	ret.CreateProcessCB = defaultCreateProcessCB
	ret.LoadDllCB = defaultLoadDllCB
	ret.pi = pi
	// ret.Logger = &util.ConsoleLogger{}
	// err := _DebugActiveProcess(ret.Pid)
	// if err != nil {
	// 	return nil, errors.New("failed to start debug session: " + err.Error())
	// }
	// ret.Logger.WriteInfo("Creating debug process:", ret.ProcessImage, "PID:", ret.ProcessPid)
	return &ret, nil
}

func (ds *DbgSession) End() {
	//ds.allowExit <- true
	_DebugActiveProcessStop(ds.ProcessPid)
	// windows.CloseHandle(*ds.ProcessHandle)

}

func (ds *DbgSession) Start() {
	go ds.run()
	// time.Sleep(time.Millisecond * 500)
	windows.ResumeThread(ds.pi.Thread)
}

func (ds *DbgSession) run() error {
	var debugEvent _DEBUG_EVENT
	err := _DebugActiveProcess(ds.ProcessPid)
	if err != nil {
		log.Fatal("failed to start debug session: ", err)
		return errors.New("failed to start debug session: " + err.Error())
	}
	for {
		continueStatus := uint32(_DBG_CONTINUE)
		var milliseconds uint32 = syscall.INFINITE

		// Wait for a debug event...
		err := _WaitForDebugEvent(&debugEvent, milliseconds)
		if err != nil {
			log.Println("WaitForDebugEvent:", err)
			return err
		}

		unionPtr := unsafe.Pointer(&debugEvent.U[0])
		switch debugEvent.DebugEventCode {
		case _CREATE_PROCESS_DEBUG_EVENT:
			debugInfo := (*_CREATE_PROCESS_DEBUG_INFO)(unionPtr)
			ds.CreateProcessCB(*(*CreateProcessInfo)(debugInfo))
		case _CREATE_THREAD_DEBUG_EVENT:
			// debugInfo := (*_CREATE_THREAD_DEBUG_INFO)(unionPtr)
		case _EXIT_THREAD_DEBUG_EVENT:
		case _OUTPUT_DEBUG_STRING_EVENT:
		case _LOAD_DLL_DEBUG_EVENT:
			debugInfo := (*_LOAD_DLL_DEBUG_INFO)(unionPtr)
			ds.LoadDllCB(*(*LoadDllInfo)(debugInfo))
		case _UNLOAD_DLL_DEBUG_EVENT:
		case _RIP_EVENT:
		case _EXCEPTION_DEBUG_EVENT:
		case _EXIT_PROCESS_DEBUG_EVENT:
			ds.WantsExit = true
			debugInfo := (*_EXIT_PROCESS_DEBUG_INFO)(unionPtr)
			ds.ExitProcessCB(*(*ExitProcess)(debugInfo))

			//<-ds.allowExit // wait for approval to exit process
			return nil
		}

		err = _ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, continueStatus)
		if err != nil {
			log.Println("ContinueDebugEvent:", err)
			return err
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

func createSuspendedProcess(exePath string) (*windows.ProcessInformation, error) {
	var (
		pi  windows.ProcessInformation
		si  windows.StartupInfo
		psa windows.SecurityAttributes
		tsa windows.SecurityAttributes
	)

	pCmdStr, err := windows.UTF16PtrFromString(exePath) // bad
	if err != nil {
		return nil, err
	}

	// psa.SecurityDescriptor, _ = windows.NewSecurityDescriptor()

	// windows.CreateProcessAsUser(token windows.Token, appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *windows.StartupInfo, outProcInfo *windows.ProcessInformation) (err error)
	// windows.CreateProcess      (                     appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *windows.StartupInfo, outProcInfo *windows.ProcessInformation) (err error)
	if err = windows.CreateProcess(
		nil,
		pCmdStr,
		&psa,
		&tsa,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	); err != nil {
		return nil, err
	}

	return &pi, nil
}
