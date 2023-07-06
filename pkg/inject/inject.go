package inject

import (
	"unsafe"

	"github.com/redt1de/MaldevEDR/pkg/util"
	"golang.org/x/sys/windows"
)

var (
	HELPDLL    = "z:\\testing\\x64EDRHelper.dll"
	pAddImport = windows.NewLazyDLL(HELPDLL).NewProc("AddImport")
)

type HookEvent struct {
	Function  string                 `json:"Function,omitempty"`
	EventData map[string]interface{} `json:"EventData,omitempty"`
}

var Logger = util.ConsoleLogger{Module: "hooks"}

// DetourUpdateProcessWithDll doesnt return any meaningful error/status message so gonna have to do some checks ourselves.
func Inject(hProcess windows.Handle, dll string) {
	dllname := append([]byte(dll), 0)
	pAddImport.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&dllname[0])))
}
