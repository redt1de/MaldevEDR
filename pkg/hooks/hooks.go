package hooks

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"unsafe"

	"github.com/redt1de/MaldevEDR/pkg/pipemon"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"golang.org/x/sys/windows"
)

var ()

type HookEvent struct {
	Function string                 `json:"Function"`
	Mode     string                 `json:"Mode"`
	Args     map[string]interface{} `json:"Args,omitempty"`
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

// var Logger = util.ConsoleLogger{Module: "hooks"}

// DetourUpdateProcessWithDll doesnt return any meaningful error/status message so gonna have to do some checks ourselves.
func (h *HookCfg) Inject(hProcess windows.Handle, dll string) error {
	if !util.FileExists(dll) {
		return errors.New("hook dll not found: " + dll)
	}
	helpme := filepath.Join(h.LibDir, h.HelperDll)
	pAddImport := windows.NewLazyDLL(helpme).NewProc("AddImport")
	dllname := append([]byte(dll), 0)
	pAddImport.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&dllname[0])))
	return nil
}

func (h *HookCfg) Handler(c net.Conn) {
	for {
		var pretty []byte
		blah := HookEvent{}
		d := json.NewDecoder(c)
		err := d.Decode(&blah)
		if err != nil {
			if err.Error() == "EOF" {

				break
			} else {
				h.Logger.WriteErr(err)
			}
		}

		pretty, _ = json.MarshalIndent(blah, "", "  ")
		if h.DisableRules {
			h.Logger.WriteThreat("Mode", blah.Mode, ", Function:", blah.Function, ", Matches: Rules Disabled")
			if h.Verbose {
				h.Logger.Write(string(pretty))
			}

			continue
		}

		for _, r := range h.Rules {
			match, q := h.ruleMatches(string(pretty), r.Query)
			if match {
				// h.Logger.WriteThreat("Function:", blah.Function+" via", blah.Mode, "hook Matches: "+r.Name)
				h.Logger.WriteThreat(r.Name, "detected via", blah.Mode, "hook", "("+q+")")

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
