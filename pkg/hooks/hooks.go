package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/pipemon"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"golang.org/x/sys/windows"
)

var ()

const PROCESS_ALL_ACCESS = 0x1F0FFF

const (
	MSG_STATUS = 1
	MSG_MODULE = 2
	MSG_EVENT  = 0
)

type HookMessage struct {
	Type   int       `json:"Type,omitempty"`
	Status Status    `json:"Status,omitempty"`
	Module Module    `json:"Module,omitempty"`
	Event  HookEvent `json:"Event,omitempty"`
}

// { "Type":2, "Module":{"Name":"%s","Base": "0x%p","Size":"0x%x"}}}
type Module struct {
	Name string `json:"name,omitempty"`
	Base string `json:"Base,omitempty"`
	Size string `json:"Size,omitempty"`
}

type Status struct {
	Status  string `json:"Status,omitempty"`
	Message string `json:"Message,omitempty"`
}

// { "Type":0, "Event":{"Function":"blah","Mode": "userland","ReturnAddress":"blah","Args":{"blah":"blah"}}}
type HookEvent struct {
	Function      string                 `json:"Function"`
	Mode          string                 `json:"Mode"`
	ReturnAddress string                 `json:"ReturnAddress"`
	ReturnSymbol  string                 `json:"ReturnSymbol,omitempty"`
	Args          map[string]interface{} `json:"Args,omitempty"`
}

type HookCfg struct {
	LibDir       string              `yaml:"libdir"`
	HelperDll    string              `yaml:"helper_dll"`
	HookDll      string              `yaml:"hook_dll"`
	Pipe         string              `yaml:"pipe"`
	Rules        []Rule              `yaml:"rules"`
	Logger       *util.ConsoleLogger `yaml:"-"`
	Verbose      bool                `yaml:"-"`
	hookmon      *pipemon.Pipe       `yaml:"-"`
	DisableRules bool                `yaml:"-"`
	Append       string              `yaml:"-"`
	Override     string              `yaml:"-"`
	RuleDbg      bool                `yaml:"-"`
	ModStore     *dbgproc.ModStore   `yaml:"-"`
}

type Rule struct {
	Name  string `yaml:"name"`
	Query string `yaml:"match"`
	Msg   string `yaml:"message"`
}

func HookerInit(cfg *HookCfg) {
	cfg.Logger = &util.ConsoleLogger{Module: "hooks"}
	cfg.hookmon = pipemon.NewPipe(cfg.Pipe, cfg.Handler)
	cfg.hookmon.Error = func(err error) {
		cfg.Logger.WriteErr("pipe error: " + err.Error())
	}

}

// DetourUpdateProcessWithDll doesnt return any meaningful error/status message so gonna have to do some checks ourselves.
func (h *HookCfg) InjectIAT(hProcess windows.Handle, dll string) error {
	if !util.FileExists(dll) {
		return errors.New("hook dll not found: " + dll)
	}
	helpme := filepath.Join(h.LibDir, h.HelperDll)
	// pAddImport := windows.NewLazyDLL(helpme).NewProc("AddImport")
	helpDll, err := windows.LoadDLL(helpme) //MustLoadDLL(helpme).FindProc("AddImport")
	if err != nil {
		return errors.New("failed to load hook dll: " + err.Error())
	}
	pAddImport, err := helpDll.FindProc("AddImport")
	if err != nil {
		return errors.New("failed to find AddImport proc in hook dll: " + err.Error())
	}
	dllname := append([]byte(dll), 0)
	pAddImport.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&dllname[0])))
	return nil
}

func (h *HookCfg) InjectRemoteThread(hProcess windows.Handle, dll string) error {

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
	// proc, errOpenProcess := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	// if errOpenProcess != nil {
	// 	return errors.New(fmt.Sprintf("error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	// }
	proc := hProcess

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(proc), 0, uintptr(dlllen), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return fmt.Errorf("error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error())
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(proc), addr, uintptr(unsafe.Pointer(&dllname[0])), uintptr(dlllen))
	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		return fmt.Errorf("error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error())
	}

	op := 0
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(proc), addr, uintptr(dlllen), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&op)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return fmt.Errorf("error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error())
	}

	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(proc), 0, 0, LoadLibraryA, addr, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		return fmt.Errorf("error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error())
	}

	errCloseHandle := windows.CloseHandle(proc)
	if errCloseHandle != nil {
		return fmt.Errorf("error calling CloseHandle:\r\n%s", errCloseHandle.Error())
	}

	return nil

}

func (h *HookCfg) Handler(c net.Conn) {
	for {
		// var pretty []byte
		msg := HookMessage{}
		d := json.NewDecoder(c)
		err := d.Decode(&msg)
		if err != nil {
			if err.Error() == "EOF" {
				break
			} else {
				h.Logger.WriteErr(err)
				continue
			}
		}
		if msg.Event.Function != "" {
			h.ParseEvent(msg.Event)
		}

	}
}
func (h *HookCfg) ParseEvent(blah HookEvent) {
	var rs string
	if blah.ReturnAddress != "" {
		ui64, _ := strconv.ParseUint(strings.TrimLeft(blah.ReturnAddress, "0x"), 16, 64)
		h.ModStore.Lock()

		for k, v := range *&h.ModStore.Mods {
			if ui64 > uint64(v.BaseAddr) && ui64 < uint64(v.BaseAddr)+uint64(v.Size) {
				rs = fmt.Sprintf("%s+0x%x", strings.ToUpper(filepath.Base(k)), ui64-uint64(v.BaseAddr))
				break
			}
		}
		h.ModStore.Unlock()
	}
	if rs != "" {
		blah.ReturnSymbol = rs
	}

	pretty, _ := json.MarshalIndent(blah, "", "  ")
	if h.DisableRules {
		h.Logger.WriteThreat("Mode", blah.Mode, ", Function:", blah.Function, ", Matches: Rules Disabled")
		if h.Verbose {
			h.Logger.Write(string(pretty))
		}

		return
	}

	if h.Override != "" {
		match, _ := h.ruleMatches(string(pretty), h.Override)
		if match {
			// cf.Logger.WriteThreat("Channel:", e.System.Channel, "Event ID:", e.System.EventID, "Task:", e.System.Task.Name, "Matches: "+q)
			h.Logger.WriteThreat("CUSTOM detected via", blah.Mode, "hook", "(User Override)")
			if h.Verbose {
				h.Logger.Write(string(pretty))
			}

		}
	} else {

		for _, r := range h.Rules {
			match, _ := h.ruleMatches(string(pretty), r.Query)
			if match {
				// h.Logger.WriteThreat("Function:", blah.Function+" via", blah.Mode, "hook Matches: "+r.Name)
				h.Logger.WriteThreat(r.Name, "detected via", blah.Mode, "hook", "("+r.Name+")")

				if h.Verbose {
					h.Logger.Write(string(pretty))
				}
				if r.Msg != "" {
					h.Logger.WriteSuccess(h.parseMsg(r.Msg, string(pretty)))
				}
			}
		}
	}

}

func (h *HookCfg) Monitor() {
	h.hookmon.Monitor()
}

func (h *HookCfg) Stop() {
	h.hookmon.Stop()
}
