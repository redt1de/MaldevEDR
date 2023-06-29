package dllinject

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"golang.org/x/sys/windows"
)

// const DLLPATH = "Z:\\EDR\\userland-hook\\x64\\Debug\\userland-hook.dll"
const DLLPATH = "Z:\\c\\EdrDll\\x64\\Debug\\EdrDll.dll"

const PROCESS_ALL_ACCESS = 0x1F0FFF

type Injector struct {
	Pid           uint32
	ProcessHandle *windows.Handle
	Logger        util.LogIface
	end           bool
}

func NewInjector() *Injector {
	return &Injector{}
}

func (i *Injector) End() {
	i.end = true
}

func (i *Injector) Monitor() {
	pipePath := `\\.\pipe\MalDevEDR\hooks`

	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close()
	log.Printf("Server listening on pipe %v\n", pipePath)

	for {
		if i.end {
			l.Close()
			break
		}
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go handleClient(i, conn)
	}

}

type test struct {
	Status string
}

func handleClient(i *Injector, c net.Conn) {
	defer c.Close()
	d := json.NewDecoder(c)

	var event test //map[string]interface{}
	err := d.Decode(&event)
	if err != nil {
		fmt.Println(1, err)
	}
	fmt.Println(">>>>>>>>>>>>>>>>>>", event.Status)
}

func (i *Injector) Inject(dll string) error {
	dllname := append([]byte(dll), 0)
	dlllen := len(dllname)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	k32, _ := syscall.LoadLibrary("kernel32.dll")
	LoadLibraryA, _ := syscall.GetProcAddress(syscall.Handle(k32), "LoadLibraryA")

	// proc := *i.ProcessHandle
	proc, errOpenProcess := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(i.Pid))
	if errOpenProcess != nil {
		return errors.New(fmt.Sprintf("error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(proc), 0, uintptr(dlllen), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(proc), addr, uintptr(unsafe.Pointer(&dllname[0])), uintptr(dlllen))
	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	op := 0
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(proc), addr, uintptr(dlllen), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&op)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}

	///////////////////////////////  maybe try queueuserapc here

	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(proc), 0, 0, LoadLibraryA, addr, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}

	errCloseHandle := windows.CloseHandle(proc)
	if errCloseHandle != nil {
		return errors.New(fmt.Sprintf("error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

	return nil
}
