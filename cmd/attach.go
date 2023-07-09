/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/hooks"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"github.com/spf13/cobra"
)

// attachCmd represents the attach command
var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "attach to a running process",
	Long:  `This command can be used to attach to a running process. Dll injection is limited to CreateRemoteThread, since its too late for import table injection.`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		outfile, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")
		noEtw, _ := cmd.Flags().GetBool("no-etw")
		noInject, _ := cmd.Flags().GetBool("no-inject")
		noRules, _ := cmd.Flags().GetBool("no-rules")
		doOverride, _ := cmd.Flags().GetString("override")
		doAppend, _ := cmd.Flags().GetString("append")
		ruleDev, _ := cmd.Flags().GetBool("rule-dev")
		verbose2, _ := cmd.Flags().GetBool("very-verbose")
		pid, _ := cmd.Flags().GetUint32("pid")

		var mainLogger util.ConsoleLogger
		mainLogger.LogFile = outfile

		edrCfg, err := config.NewEdr(configPath)
		if err != nil {
			mainLogger.WriteFatal(err)
		}
		shutdown := make(chan bool)
		dSess := edrCfg.DebugProc
		err = dbgproc.InitAttachedDebugProcess(pid, &dSess)
		if err != nil {
			mainLogger.WriteFatal(err)
		}
		dSess.Logger.LogFile = outfile
		dSess.Error = func(e error) {
			dSess.Logger.WriteErr(e)
		}
		dSess.ExitProcessCB = func(ep dbgproc.ExitProcess) {
			// keep the process alive until we say so, so we can lookup data in late etw events
			dSess.Logger.WriteInfo("Process exit requested, waiting for late events")
			time.Sleep(3 * time.Second)
			shutdown <- true
		}

		dSess.Logger.WriteInfo("Attaching to process:", dSess.ProcessImage, "PID:", dSess.ProcessId)
		////////////// ETW
		etwCfg := edrCfg.Etw
		if !noEtw {
			ewatch.EtwInit(&etwCfg)
			etwCfg.DisableRules = noRules
			etwCfg.Append = doAppend
			etwCfg.Override = doOverride
			etwCfg.Logger.LogFile = outfile
			etwCfg.Spawn = &dSess
			etwCfg.RuleDbg = ruleDev
			if verbose {
				etwCfg.Verbose = 1
			}
			if verbose2 {
				etwCfg.Verbose = 2
			}
			go etwCfg.Start()
		}
		////////// Injector
		hookCfg := edrCfg.Hooks
		if !noInject {
			hooks.HookerInit(&hookCfg)
			hookCfg.Logger.LogFile = outfile
			hookCfg.DisableRules = noRules
			hookCfg.Verbose = verbose
			hookCfg.Append = doAppend
			hookCfg.Override = doOverride
			hookCfg.RuleDbg = ruleDev

			go hookCfg.Monitor()

			err = hookCfg.InjectRemoteThread(*dSess.ProcessHandle, filepath.Join(hookCfg.LibDir, hookCfg.HookDll))
			if err != nil {
				hookCfg.Logger.WriteErr(err)
			} else {
				hookCfg.Logger.WriteInfo("dll injected, hooks in place")
			}

		}
		go dSess.Resume()

		c := make(chan os.Signal, 1)
		go func() {
			signal.Notify(c, os.Interrupt)
			for range c {
				mainLogger.WriteInfo("Recieved CTRL-C, shutting down...")
				proc, err := os.FindProcess(int(dSess.ProcessId))
				if err != nil {
					mainLogger.Write("failed to terminate spawned process:", err)
				}
				proc.Kill()
				shutdown <- true
			}
		}()

		<-shutdown
		mainLogger.WriteInfo("Shutting down...")
		dSess.Stop()
		if !noEtw {
			etwCfg.Stop()
		}
		if !noInject {
			hookCfg.Stop()
		}

	},
}

func init() {
	rootCmd.AddCommand(attachCmd)

	attachCmd.Flags().Uint32P("pid", "p", 0, "PID of the process to attach to")
	attachCmd.Flags().StringP("override", "O", "", "override rules with a user specified matcher")
	attachCmd.Flags().StringP("append", "a", "", "append a user specified matcher to all rules")
	attachCmd.Flags().BoolP("no-rules", "R", false, "disable rule checks, helpful for rule dev (lotsa output)")
	attachCmd.Flags().BoolP("no-inject", "I", false, "dont inject the hooking dll")
	attachCmd.Flags().BoolP("no-etw", "E", false, "dont monitor ETW events")
	attachCmd.Flags().BoolP("rule-dev", "D", false, "print the final rule queries passed to expr (for rule dev)")
	attachCmd.Flags().BoolP("very-verbose", "V", false, "include ETW EventData + Metadata JSON output (useful for writing rules)")

	// attachCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
