/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
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

		var logger util.ConsoleLogger
		outfile, _ := cmd.Flags().GetString("output")
		logger.SetLogFile(outfile)

		fPath, _ := cmd.Flags().GetString("file")
		if !util.FileReadable(fPath) {
			log.Fatal("failed open mal file")
		}
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			logger.DebugEnable()
		}

		logger.WriteInfo("Performing full analysis on:", fPath)

		////////// ThreatCheck
		defender := threatcheck.NewDefender()
		defender.Logger = &logger
		defender.AnalyzeFile(fPath)

		////////// ETW
		configPath, _ := cmd.Flags().GetString("config")
		cfg, err := ewatch.NewEtw(configPath)
		if err != nil {
			var tmp util.ConsoleLogger
			tmp.WriteFatal("failed to load the config file: " + err.Error())
		}

		cfg.Logger.SetLogFile(outfile)

		verbose1, _ := cmd.Flags().GetBool("verbose")
		if verbose1 {
			cfg.Verbose = 1
		}

		verbose2, _ := cmd.Flags().GetBool("very-verbose")
		if verbose2 {
			cfg.Verbose = 1
		}

		cfg.Override, _ = cmd.Flags().GetString("override")
		// cfg.KernelMode, _ = cmd.Flags().GetBool("kernel")
		cfg.DisableRules, _ = cmd.Flags().GetBool("no-rules")
		cfg.Append, _ = cmd.Flags().GetString("append")
		cfg.RuleDbg, _ = cmd.Flags().GetBool("rule-dev")
		doSpawn, _ := cmd.Flags().GetString("file")
		shutdown := make(chan bool)
		dSess, err := dbgproc.NewDebugProc(doSpawn, true)
		if err != nil {
			cfg.Logger.WriteFatal(err)
		}
		cfg.Logger.WriteInfo("Creating debug process:", dSess.ProcessImage, "PID:", dSess.ProcessPid)
		cfg.Spawn = dSess

		cfg.Spawn.ExitProcessCB = func(ep dbgproc.ExitProcess) {
			<-shutdown // keep the process alive until we say so, so we can lookup data in late etw events
		}

		go cfg.Start()
		time.Sleep(time.Millisecond * 1000)
		// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< add dll injection here

		// need a way to get error/status from cfg.Start() so we know if its running

		dSess.Start()

		for {
			if dSess.WantsExit {
				cfg.Logger.WriteInfo("Process exit requested, waiting for late events")
				time.Sleep(time.Second * 5)
				shutdown <- true
				dSess.End()
				break
			}
		}
		if cfg.Running {
			cfg.Stop()
		}

	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringP("file", "f", "", "malicious file to analyze")
	analyzeCmd.Flags().BoolP("verbose", "v", false, "be verbose")
	analyzeCmd.Flags().StringP("output", "o", "", "log output to a file")
	analyzeCmd.Flags().StringP("config", "c", "./etw.yaml", "Path to ETW config file.")
}
