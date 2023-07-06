/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/hooks"
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
		outfile, _ := cmd.Flags().GetString("output")
		verbose1, _ := cmd.Flags().GetBool("verbose")
		doSpawn, _ := cmd.Flags().GetString("file")

		edrCfg, err := config.NewEdr(configPath)
		if err != nil {
			log.Fatal(err)
		}

		var logger util.ConsoleLogger

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

		///////////////////// dbgproc
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

		// ////////// ETW

		etwCfg := edrCfg.Etw
		ewatch.EtwInit(&etwCfg)
		etwCfg.Logger.LogFile = outfile
		etwCfg.Spawn = dSess
		if verbose1 {
			etwCfg.Verbose = 1
		}

		// etwCfg.Override, _ = cmd.Flags().GetString("override")
		// cfg.KernelMode, _ = cmd.Flags().GetBool("kernel")
		// etwCfg.DisableRules, _ = cmd.Flags().GetBool("no-rules")
		// etwCfg.Append, _ = cmd.Flags().GetString("append")
		// etwCfg.RuleDbg, _ = cmd.Flags().GetBool("rule-dev")

		dSess.ExitProcessCB = func(ep dbgproc.ExitProcess) {
			// keep the process alive until we say so, so we can lookup data in late etw events
			dSess.Logger.WriteInfo("Process exit requested, waiting for late events")
			time.Sleep(5 * time.Second)
			shutdown <- true
		}

		////////// Injector
		hookCfg := edrCfg.Hooks
		hooks.HookerInit(&hookCfg)
		hookCfg.Logger.LogFile = outfile
		go hookCfg.Monitor()

		err = hookCfg.Inject(*dSess.ProcessHandle, filepath.Join(hookCfg.LibDir, hookCfg.HookDll))
		if err != nil {
			hookCfg.Logger.WriteErr(err)
		} else {
			hookCfg.Logger.WriteInfo("process import table patched, hooks in place")
		}

		//////////////////////////////////
		go etwCfg.Start()

		time.Sleep(100 * time.Millisecond)

		go dSess.Resume()

		c := make(chan os.Signal, 1)
		go func() {
			signal.Notify(c, os.Interrupt)
			for range c {
				etwCfg.Logger.WriteInfo("Recieved CTRL-C, shutting down...")
				etwCfg.Stop()
				proc, err := os.FindProcess(int(dSess.ProcessId))
				if err != nil {
					etwCfg.Logger.Write("failed to terminate spawned process:", err)
				}
				proc.Kill()
				os.Exit(0)
			}
		}()

		<-shutdown
		logger.WriteInfo("Shutting down...")
		etwCfg.Stop()
		hookCfg.Stop()

	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringP("file", "f", "", "malicious file to analyze")
	analyzeCmd.Flags().BoolP("verbose", "v", false, "be verbose")
	// analyzeCmd.Flags().StringP("output", "o", "", "log output to a file")
}
