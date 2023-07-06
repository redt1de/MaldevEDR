/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/inject"
	"github.com/redt1de/MaldevEDR/pkg/pipemon"
	"github.com/redt1de/MaldevEDR/pkg/threatcheck"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"github.com/spf13/cobra"
)

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Runs all analysis on the specified binary.",
	Long:  `Checks the file with threatcheck, executes with debug permissions, monitors ETW for related events, FUTURE( injects a dll that hooks risky ntdll functions, and monitors kernel syscall callbacks)`,
	Run: func(cmd *cobra.Command, args []string) {

		configPath, _ := cmd.Flags().GetString("config")
		edr, err := config.NewEdr(configPath)
		if err != nil {
			log.Fatal(err)
		}

		var logger util.ConsoleLogger
		outfile, _ := cmd.Flags().GetString("output")
		// verbose, _ := cmd.Flags().GetBool("verbose")
		logger.LogFile = outfile

		fPath, _ := cmd.Flags().GetString("file")
		if !util.FileReadable(fPath) {
			log.Fatal("failed open mal file")
		}
		logger.WriteInfo("Performing full analysis on:", fPath)

		////////// ThreatCheck
		defender := threatcheck.NewDefender()
		defender.AnalyzeFile(fPath)

		// ////////// ETW

		cfg := edr.Etw
		ewatch.EtwInit(&cfg)
		cfg.Logger.LogFile = outfile

		verbose1, _ := cmd.Flags().GetBool("verbose")
		if verbose1 {
			cfg.Verbose = 1
		}

		verbose2, _ := cmd.Flags().GetBool("very-verbose")
		if verbose2 {
			cfg.Verbose = 2
		}

		cfg.Override, _ = cmd.Flags().GetString("override")
		// cfg.KernelMode, _ = cmd.Flags().GetBool("kernel")
		cfg.DisableRules, _ = cmd.Flags().GetBool("no-rules")
		cfg.Append, _ = cmd.Flags().GetString("append")
		cfg.RuleDbg, _ = cmd.Flags().GetBool("rule-dev")
		doSpawn, _ := cmd.Flags().GetString("file")
		shutdown := make(chan bool)
		dSess, err := dbgproc.NewDebugProcess(doSpawn, true)
		dSess.Logger.LogFile = outfile
		if err != nil {
			dSess.Logger.WriteFatal(err)
		}
		dSess.Error = func(e error) {
			dSess.Logger.WriteErr(e)
		}
		dSess.Logger.WriteInfo("Creating debug process:", dSess.ProcessImage, "PID:", dSess.ProcessId)
		cfg.Spawn = dSess

		dSess.ExitProcessCB = func(ep dbgproc.ExitProcess) {
			// keep the process alive until we say so, so we can lookup data in late etw events
			dSess.Logger.WriteInfo("Process exit requested, waiting for late events")
			time.Sleep(5 * time.Second)
			shutdown <- true
		}

		////////// Injector
		inject.Logger.LogFile = outfile

		hookmon := pipemon.NewPipe(`\\.\pipe\MalDevEDR\hooks`, func(c net.Conn) {
			for {
				blah := inject.HookEvent{}
				d := json.NewDecoder(c)
				err := d.Decode(&blah)
				if err != nil {
					if err.Error() == "EOF" {

						break
					} else {
						inject.Logger.WriteErr(err)
					}
				}
				inject.Logger.WriteThreat(blah.Function)

				if verbose1 || verbose2 {
					pretty, _ := json.MarshalIndent(blah.EventData, "", "  ")
					inject.Logger.Write(string(pretty))
				}
			}
		})
		hookmon.Error = func(err error) {
			inject.Logger.WriteErr("pipe error: " + err.Error())
		}
		go hookmon.Monitor()

		go cfg.Start()

		time.Sleep(100 * time.Millisecond)

		inject.Inject(*dSess.ProcessHandle, "z:\\testing\\detour64.dll")
		inject.Logger.WriteInfo("process import table patched, hooks in place")

		go dSess.Resume()

		c := make(chan os.Signal, 1)
		go func() {
			signal.Notify(c, os.Interrupt)
			for range c {
				cfg.Logger.WriteInfo("Recieved CTRL-C, shutting down...")
				cfg.Stop()
				proc, err := os.FindProcess(int(dSess.ProcessId))
				if err != nil {
					cfg.Logger.Write("failed to terminate spawned process:", err)
				}
				proc.Kill()
				os.Exit(0)
			}
		}()

		<-shutdown
		logger.WriteInfo("Shutting down...")
		cfg.Stop()
		hookmon.Stop()

	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringP("file", "f", "", "malicious file to analyze")
	analyzeCmd.Flags().BoolP("verbose", "v", false, "be verbose")
	analyzeCmd.Flags().StringP("output", "o", "", "log output to a file")
	// analyzeCmd.Flags().StringP("config", "c", "./etw.yaml", "Path to ETW config file.")
}
