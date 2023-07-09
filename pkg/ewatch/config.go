package ewatch

import (
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch/etw"
	"github.com/redt1de/MaldevEDR/pkg/util"
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
	Pipe              string     `yaml:"pipe"`
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
	Logger            *util.ConsoleLogger
	stopChan          chan bool `yaml:"-"`
	Running           bool
	LastErr           error
}

func EtwInit(cfg *EWatcher) {
	cfg.Logger = &util.ConsoleLogger{Module: "etw"}
	cfg.stopChan = make(chan bool)
}
