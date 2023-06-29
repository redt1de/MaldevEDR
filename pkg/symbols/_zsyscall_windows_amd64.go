package symbols

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
	moddbghelp                = windows.NewLazySystemDLL("dbghelp.dll")

	procSymCleanup    = moddbghelp.NewProc("SymCleanup")
	procSymFromAddr   = moddbghelp.NewProc("SymFromAddr")
	procSymInitialize = moddbghelp.NewProc("SymInitialize")
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

func SymCleanup(hProc windows.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procSymCleanup.Addr(), 1, uintptr(hProc), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SymFromAddr(hProc windows.Handle, addr uint64, displacement uint32, symbol _SYMBOL_INFO) (err error) {

	//pSymFromAddr.Call(uintptr(hProc), uintptr(addr), uintptr(unsafe.Pointer(&displacement)), uintptr(unsafe.Pointer(symbol)))
	r1, _, e1 := syscall.Syscall6(procSymFromAddr.Addr(), 4, uintptr(hProc), uintptr(addr), uintptr(unsafe.Pointer(&displacement)), uintptr(unsafe.Pointer(&symbol)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}



func SymInitialize(hProc windows.Handle, searchpath string, invade bool) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(searchpath)
	if err != nil {
		return
	}
	var _p1 uint32
	if invade {
		_p1 = 1
	}
	r1, _, e1 := pSymInitialize.Call(uintptr(hProc), uintptr(unsafe.Pointer(_p0)), uintptr(_p1))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return err
}
