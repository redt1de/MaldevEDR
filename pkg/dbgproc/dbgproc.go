package dbgproc

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"github.com/redt1de/MaldevEDR/pkg/util"
	"golang.org/x/sys/windows"
)

func (ds *DbgSession) defaultCreateProcessCB(CreateProcessInfo) {}
func (ds *DbgSession) defaultLoadDllCB(LoadDllInfo)             {}
func (ds *DbgSession) defaultExitProcessCB(ExitProcess)         {}
func (ds *DbgSession) defaultDebugOutputCB(debugMsg string) {
	if ds.DebugOutput {
		ds.Logger.WriteDebug(debugMsg)
	}
}

func defaultErrCB(e error) {
	log.Fatal("dbgproc default error callback:" + e.Error())
}

type DbgSession struct {
	ExitDelay       int                         `yaml:"exit_delay"`
	DebugOutput     bool                        `yaml:"debug_output"`
	DebugPriv       bool                        `yaml:"debug_priv"`
	ProcessImage    string                      `yaml:"-"`
	ProcessId       uint32                      `yaml:"-"`
	ProcessHandle   *windows.Handle             `yaml:"-"`
	ThreadId        uint32                      `yaml:"-"`
	ThreadHandle    *windows.Handle             `yaml:"-"`
	CreateProcessCB func(CreateProcessInfo)     `yaml:"-"`
	DebugOutputCB   func(string)                `yaml:"-"`
	ExitProcessCB   func(ExitProcess)           `yaml:"-"`
	LoadDllCB       func(LoadDllInfo)           `yaml:"-"`
	pi              *windows.ProcessInformation `yaml:"-"`
	Error           func(error)                 `yaml:"-"`
	Logger          util.ConsoleLogger          `yaml:"-"`
}

func InitNewDebugProcess(cmdline string, env string, startupdir string, cfg *DbgSession) error {
	exe := strings.Split(cmdline, " ")[0]
	if cfg.DebugPriv {
		err := AcquireDebugPrivilege()
		if err != nil {
			return errors.New("failed to aquire debug privileges: " + err.Error())
		}

	}

	var pi windows.ProcessInformation

	var si windows.StartupInfo
	// si.Cb = uint32(unsafe.Sizeof(windows.StartupInfo{}))
	si.Flags = windows.STARTF_USESHOWWINDOW   //STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_SHOWNOACTIVATE //SW_MINIMIZE

	// Specify the executable to debug
	pCmdStr, err := windows.UTF16PtrFromString(cmdline) // bad
	if err != nil {
		return err
	}

	// Specify the executable to debug
	var pStartupDir *uint16 = nil
	if startupdir != "" {
		pStartupDir, err = windows.UTF16PtrFromString(startupdir) // bad
		if err != nil {
			return err
		}
	}

	// env is special. null terminated array of null terminated strings. var1=val1;var2=val2  => var1=val1+0x00+var2=val2+0x00+0x00
	var pEnv *uint16 = nil
	if env != "" {
		var envBlock []byte
		tmpEnv := strings.Split(env, ";")
		for _, e := range tmpEnv {
			envBlock = append(envBlock, []byte(e)...)
			envBlock = append(envBlock, 0x00)
		}
		envBlock = append(envBlock, 0x00)
		pEnv = (*uint16)(unsafe.Pointer(&envBlock[0]))
	}
	// Create the process in a suspended state
	if err = windows.CreateProcess(
		nil,     // Application name
		pCmdStr, // Command line arguments
		nil,     // Process handle not inheritable
		nil,     // Thread handle not inheritable
		false,   // Set handle inheritance to FALSE
		// windows.DEBUG_PROCESS|windows.CREATE_SUSPENDED, // Creation flags
		windows.CREATE_SUSPENDED|windows.CREATE_NEW_CONSOLE,
		pEnv,        // Use parent's environment block
		pStartupDir, // Use parent's starting directory
		&si,         // Pointer to STARTUPINFO structure
		&pi,         // Pointer to PROCESS_INFORMATION structure
	); err != nil {
		return err
	}

	pHand := pi.Process
	pThread := pi.Thread

	cfg.ProcessId = pi.ProcessId
	cfg.ProcessImage = exe
	cfg.ProcessHandle = &pHand
	cfg.ThreadHandle = &pThread
	cfg.CreateProcessCB = cfg.defaultCreateProcessCB
	cfg.LoadDllCB = cfg.defaultLoadDllCB
	cfg.ExitProcessCB = cfg.defaultExitProcessCB
	cfg.DebugOutputCB = cfg.defaultDebugOutputCB
	cfg.pi = &pi
	cfg.Error = defaultErrCB
	cfg.Logger = util.ConsoleLogger{Module: "dbgproc", Debug: true}
	return nil
}

func InitAttachedDebugProcess(pid uint32, cfg *DbgSession) error {
	if cfg.DebugPriv {
		err := AcquireDebugPrivilege()
		if err != nil {
			return errors.New("failed to aquire debug privileges: " + err.Error())
		}

	}

	pHand, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return errors.New("failed to obtain process handle: " + err.Error())
	}

	cfg.ProcessId = pid
	cfg.ProcessImage = "NEED A FUNC TO LOOKUP IMAGE NAME FROM PID GetProcessImageFileNameA" // <<<<<<<<<<<<<<<<<<<<<<<<<<<
	cfg.ProcessHandle = &pHand
	cfg.ThreadHandle = nil
	cfg.CreateProcessCB = cfg.defaultCreateProcessCB
	cfg.LoadDllCB = cfg.defaultLoadDllCB
	cfg.ExitProcessCB = cfg.defaultExitProcessCB
	cfg.DebugOutputCB = cfg.defaultDebugOutputCB
	cfg.pi = nil
	cfg.Error = defaultErrCB
	cfg.Logger = util.ConsoleLogger{Module: "dbgproc"}
	return nil

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
	var debugEvent _DEBUG_EVENT
	// debugEvent.ProcessId = ds.ProcessId
	// debugEvent.ThreadId = ds.ThreadId
	if ds.pi != nil {
		go func() {
			_, err := windows.ResumeThread(ds.pi.Thread)
			if err != nil {
				ds.Error(errors.New("failed to resume debug process:" + err.Error()))

			}
		}()
	}

	for {
		continueStatus := uint32(_DBG_CONTINUE)
		var milliseconds uint32 = syscall.INFINITE

		// Wait for a debug event...
		err := _WaitForDebugEvent(&debugEvent, milliseconds)
		if err != nil {
			// ds.Error(errors.New("WaitForDebugEvent:" + err.Error()))
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
			debugInfo := (*_OUTPUT_DEBUG_STRING_INFO)(unionPtr)
			bufferSize := int(debugInfo.DebugStringLength)
			buffer := make([]uint16, bufferSize)
			r1, _, _ := procReadProcessMemory.Call(uintptr(*ds.ProcessHandle), uintptr(unsafe.Pointer(debugInfo.DebugStringData)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(bufferSize), 0)
			if r1 == 1 {
				ptr := unsafe.Pointer(&buffer[0])
				size := bufferSize
				a := *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{Data: uintptr(ptr), Len: size, Cap: size}))
				if a[len(a)-1] == 0x00 {
					a = a[:len(a)-1]
				}
				ds.DebugOutputCB(strings.TrimSuffix(string(a), "\n"))
			}

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

// ReadMemory reads an arbitrary memory address.
func ReadMemory(addr uintptr, readLen int) []byte {
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), readLen)
	return readmem
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
