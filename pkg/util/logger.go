package util

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	RedColor     = "\033[1;31m"
	GreenColor   = "\033[1;32m"
	YellowColor  = "\033[1;33m"
	BlueColor    = "\033[1;34m"
	MagentaColor = "\033[1;35m"
	CyanColor    = "\033[1;36m"
	Reset        = "\033[0m"
)

// type LogIface interface {
// 	Write(a ...any)
// 	WriteThreat(a ...any)
// 	WriteErr(a ...any)
// 	WriteInfo(a ...any)
// 	WriteDebug(a ...any)
// 	WriteSuccess(a ...any)
// 	WriteFatal(a ...any)
// 	DebugEnable()
// 	SetLogFile(fpath string)
// }

type ConsoleLogger struct {
	Debug   bool
	Module  string
	LogFile string
}

func (c *ConsoleLogger) WriteInfo(a ...any) {
	var tmp []any

	tmp = append(tmp, BlueColor+"[INFO]")
	if c.Module != "" {
		tmp = append(tmp, "["+strings.ToUpper(c.Module)+"]")
	}
	tmp = append(tmp, a...)
	tmp = append(tmp, Reset)
	fmt.Println(tmp...)
	if c.LogFile != "" {
		c.writeLogFile(tmp...)
	}
}

func (c *ConsoleLogger) WriteThreat(a ...any) {
	var tmp []any

	tmp = append(tmp, YellowColor+"[ALERT]")
	if c.Module != "" {
		tmp = append(tmp, "["+strings.ToUpper(c.Module)+"]")
	}
	tmp = append(tmp, a...)
	tmp = append(tmp, Reset)
	fmt.Println(tmp...)
	if c.LogFile != "" {
		c.writeLogFile(tmp...)
	}
}

func (c *ConsoleLogger) Write(a ...any) {
	fmt.Println(a...)
	if c.LogFile != "" {
		c.writeLogFile(a...)
	}
}

func (c *ConsoleLogger) WriteErr(a ...any) {
	var tmp []any

	tmp = append(tmp, RedColor+"[ERROR]")
	if c.Module != "" {
		tmp = append(tmp, "["+strings.ToUpper(c.Module)+"]")
	}
	tmp = append(tmp, a...)
	tmp = append(tmp, Reset)
	fmt.Println(tmp...)
	if c.LogFile != "" {
		c.writeLogFile(tmp...)
	}
}

func (c *ConsoleLogger) WriteFatal(a ...any) {
	var tmp []any

	tmp = append(tmp, RedColor+"[ERROR]")
	if c.Module != "" {
		tmp = append(tmp, "["+strings.ToUpper(c.Module)+"]")
	}
	tmp = append(tmp, a...)
	tmp = append(tmp, Reset)
	fmt.Println(tmp...)
	if c.LogFile != "" {
		c.writeLogFile(tmp...)
	}
	os.Exit(1)
}
func (c *ConsoleLogger) WriteSuccess(a ...any) {
	var tmp []any

	tmp = append(tmp, GreenColor+"[SUCCESS]")
	if c.Module != "" {
		tmp = append(tmp, "["+strings.ToUpper(c.Module)+"]")
	}
	tmp = append(tmp, a...)
	tmp = append(tmp, Reset)
	fmt.Println(tmp...)
	if c.LogFile != "" {
		c.writeLogFile(tmp...)
	}
}

func (c *ConsoleLogger) WriteDebug(a ...any) {
	if !c.Debug {
		return
	}

	var tmp []any

	tmp = append(tmp, CyanColor+"[DEBUG]")
	if c.Module != "" {
		tmp = append(tmp, "["+strings.ToUpper(c.Module)+"]")
	}
	tmp = append(tmp, a...)
	tmp = append(tmp, Reset)
	fmt.Println(tmp...)
	if c.LogFile != "" {
		c.writeLogFile(tmp...)
	}
}

func (c *ConsoleLogger) writeLogFile(a ...any) {
	f, err := os.OpenFile(c.LogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		c.WriteErr(err)
	}
	defer f.Close()

	out := fmt.Sprintln(a...)
	out = StripAnsi(out)
	if _, err := f.WriteString(out); err != nil {
		c.WriteErr(err)
	}
}

func StripAnsi(str string) string {
	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	var re = regexp.MustCompile(ansi)
	return re.ReplaceAllString(str, "")
}
