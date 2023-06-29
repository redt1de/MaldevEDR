package ewatch

import (
	"io/ioutil"

	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch/etw"
	"github.com/redt1de/MaldevEDR/pkg/util"

	"gopkg.in/yaml.v3"
)

type Provider struct {
	Name       string `yaml:"name"`
	Enabled    bool   `yaml:"enabled"`
	StackTrace bool   `yaml:"stacktrace"`
	// FilterMode string   `yaml:"filter_mode"`
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	Name  string `yaml:"name"`
	Query string `yaml:"match"`
	Msg   string `yaml:"message"`
}

type EWatcher struct {
	UserModeProviders []Provider `yaml:"user_providers"`
	PplProviders      []Provider `yaml:"ppl_providers"`
	GlobalRules       []Rule     `yaml:"global_rules"`
	Spawn             *dbgproc.DbgSession
	SpawnStarted      bool                 `yaml:"-"`
	Session           *etw.RealTimeSession `yaml:"-"`
	Override          string               `yaml:"-"`
	Verbose           int                  `yaml:"-"`
	Outfile           string               `yaml:"-"`
	KernelMode        bool                 `yaml:"-"`
	DisableRules      bool                 `yaml:"-"`
	Append            string               `yaml:"-"`
	RuleDbg           bool                 `yaml:"-"`
	Logger            util.LogIface
	stopChan          chan bool `yaml:"-"`
	Running           bool
	LastErr           error
}

func NewEtw(fpath string) (*EWatcher, error) {
	yfile, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	var ret EWatcher
	ret.Logger = &util.ConsoleLogger{}
	ret.stopChan = make(chan bool)
	err = yaml.Unmarshal(yfile, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil

}

func (c *EWatcher) Save(fpath string) error {
	data, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fpath, data, 0777)
	if err != nil {
		return err
	}
	return nil
}
