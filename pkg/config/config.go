package config

import (
	"io/ioutil"

	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/hooks"
	"gopkg.in/yaml.v3"
)

type EdrConfig struct {
	Etw       ewatch.EWatcher    `yaml:"etw"`
	Hooks     hooks.HookCfg      `yaml:"hooks"`
	DebugProc dbgproc.DbgSession `yaml:"debug_process"`
}

func NewEdr(fpath string) (*EdrConfig, error) {
	yfile, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	var ret EdrConfig

	err = yaml.Unmarshal(yfile, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil

}
