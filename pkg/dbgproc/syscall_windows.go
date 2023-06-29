package dbgproc

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procNtQueryInformationThread   = modntdll.NewProc("NtQueryInformationThread")
	dbgUiRemoteBreakin             = modntdll.NewProc("DbgUiRemoteBreakin")
	procGetThreadContext           = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext           = modkernel32.NewProc("SetThreadContext")
	procSuspendThread              = modkernel32.NewProc("SuspendThread")
	procResumeThread               = modkernel32.NewProc("ResumeThread")
	procContinueDebugEvent         = modkernel32.NewProc("ContinueDebugEvent")
	procWriteProcessMemory         = modkernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")
	procDebugBreakProcess          = modkernel32.NewProc("DebugBreakProcess")
	procWaitForDebugEvent          = modkernel32.NewProc("WaitForDebugEvent")
	procDebugActiveProcess         = modkernel32.NewProc("DebugActiveProcess")
	procDebugActiveProcessStop     = modkernel32.NewProc("DebugActiveProcessStop")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
	procVirtualQueryEx             = modkernel32.NewProc("VirtualQueryEx")
	procIsWow64Process             = modkernel32.NewProc("IsWow64Process")
)

func _NtQueryInformationThread(threadHandle syscall.Handle, infoclass int32, info uintptr, infolen uint32, retlen *uint32) (status _NTSTATUS) {
	r0, _, _ := syscall.Syscall6(procNtQueryInformationThread.Addr(), 5, uintptr(threadHandle), uintptr(infoclass), uintptr(info), uintptr(infolen), uintptr(unsafe.Pointer(retlen)), 0)
	status = _NTSTATUS(r0)
	return
}

// func _GetThreadContext(thread syscall.Handle, context *_CONTEXT) (err error) {
// 	r1, _, e1 := syscall.Syscall(procGetThreadContext.Addr(), 2, uintptr(thread), uintptr(unsafe.Pointer(context)), 0)
// 	if r1 == 0 {
// 		if e1 != 0 {
// 			err = errnoErr(e1)
// 		} else {
// 			err = syscall.EINVAL
// 		}
// 	}
// 	return
// }

// func _SetThreadContext(thread syscall.Handle, context *_CONTEXT) (err error) {
// 	r1, _, e1 := syscall.Syscall(procSetThreadContext.Addr(), 2, uintptr(thread), uintptr(unsafe.Pointer(context)), 0)
// 	if r1 == 0 {
// 		if e1 != 0 {
// 			err = errnoErr(e1)
// 		} else {
// 			err = syscall.EINVAL
// 		}
// 	}
// 	return
// }

func _SuspendThread(threadid syscall.Handle) (prevsuspcount uint32, err error) {
	r0, _, e1 := syscall.Syscall(procSuspendThread.Addr(), 1, uintptr(threadid), 0, 0)
	prevsuspcount = uint32(r0)
	if prevsuspcount == 0xffffffff {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _ResumeThread(threadid syscall.Handle) (prevsuspcount uint32, err error) {
	r0, _, e1 := syscall.Syscall(procResumeThread.Addr(), 1, uintptr(threadid), 0, 0)
	prevsuspcount = uint32(r0)
	if prevsuspcount == 0xffffffff {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _ContinueDebugEvent(processid uint32, threadid uint32, continuestatus uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procContinueDebugEvent.Addr(), 3, uintptr(processid), uintptr(threadid), uintptr(continuestatus))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _WriteProcessMemory(process syscall.Handle, baseaddr uintptr, buffer *byte, size uintptr, byteswritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(process), uintptr(baseaddr), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(byteswritten)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _ReadProcessMemory(process syscall.Handle, baseaddr uintptr, buffer *byte, size uintptr, bytesread *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(process), uintptr(baseaddr), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(bytesread)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _DebugBreakProcess(process syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procDebugBreakProcess.Addr(), 1, uintptr(process), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _WaitForDebugEvent(debugevent *_DEBUG_EVENT, milliseconds uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procWaitForDebugEvent.Addr(), 2, uintptr(unsafe.Pointer(debugevent)), uintptr(milliseconds), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _DebugActiveProcess(processid uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procDebugActiveProcess.Addr(), 1, uintptr(processid), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _DebugActiveProcessStop(processid uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procDebugActiveProcessStop.Addr(), 1, uintptr(processid), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _QueryFullProcessImageName(process syscall.Handle, flags uint32, exename *uint16, size *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procQueryFullProcessImageNameW.Addr(), 4, uintptr(process), uintptr(flags), uintptr(unsafe.Pointer(exename)), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func _VirtualQueryEx(process syscall.Handle, addr uintptr, buffer *_MEMORY_BASIC_INFORMATION, length uintptr) (lengthOut uintptr) {
	r0, _, _ := syscall.Syscall6(procVirtualQueryEx.Addr(), 4, uintptr(process), uintptr(addr), uintptr(unsafe.Pointer(buffer)), uintptr(length), 0, 0)
	lengthOut = uintptr(r0)
	return
}

func _IsWow64Process(process syscall.Handle, wow64process *uint32) (ok uint32) {
	r0, _, _ := syscall.Syscall(procIsWow64Process.Addr(), 2, uintptr(process), uintptr(unsafe.Pointer(wow64process)), 0)
	ok = uint32(r0)
	return
}

