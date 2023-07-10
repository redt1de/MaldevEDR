/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/hooks"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"github.com/spf13/cobra"
)

// spawnCmd represents the spawn command
var spawnCmd = &cobra.Command{
	Use:   "spawn",
	Short: "Spawn a malicious process and monitor various events",
	Long:  `Creates a suspended process, attaches a debugger, and resumes the process.`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		outfile, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")
		spawn, _ := cmd.Flags().GetString("spawn")
		spawnEnv, _ := cmd.Flags().GetString("spawn-env")
		spawnDir, _ := cmd.Flags().GetString("spawn-dir")
		noEtw, _ := cmd.Flags().GetBool("no-etw")
		noInject, _ := cmd.Flags().GetBool("no-inject")
		noRules, _ := cmd.Flags().GetBool("no-rules")
		doPause, _ := cmd.Flags().GetBool("spawn-pause")
		injectThread, _ := cmd.Flags().GetBool("remotethread")
		doOverride, _ := cmd.Flags().GetString("override")
		doAppend, _ := cmd.Flags().GetString("append")
		ruleDev, _ := cmd.Flags().GetBool("rule-dev")
		verbose2, _ := cmd.Flags().GetBool("very-verbose")

		var mainLogger util.ConsoleLogger
		mainLogger.LogFile = outfile

		edrCfg, err := config.NewEdr(configPath)
		if err != nil {
			mainLogger.WriteFatal(err)
		}
		shutdown := make(chan bool)

		dSess := edrCfg.DebugProc
		err = dbgproc.InitNewDebugProcess(spawn, spawnEnv, spawnDir, &dSess)
		if err != nil {
			mainLogger.WriteFatal(err)
		}
		dSess.Logger.LogFile = outfile
		dSess.Error = func(e error) {
			dSess.Logger.WriteErr(e)
		}

		dSess.LoadDllCB = func(ldi dbgproc.LoadDllInfo) {
			dSess.UpdateMods()
		}

		dSess.ExitProcessCB = func(ep dbgproc.ExitProcess) {
			// keep the process alive until we say so, so we can lookup data in late etw events
			dSess.Logger.WriteInfo("Process exit requested, waiting for late events")
			time.Sleep(time.Duration(dSess.ExitDelay) * time.Second)
			shutdown <- true
		}

		dSess.Logger.WriteInfo("Creating debug process:", dSess.ProcessImage, "PID:", dSess.ProcessId)

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
			etwCfg.ModStore = &dSess.ModStore
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
			hookCfg.ModStore = &dSess.ModStore

			dSess.DebugOutputCB = func(dbgMsg string) {
				dbgMsg = strings.ReplaceAll(dbgMsg, `\`, `\\`)
				blah := hooks.HookMessage{}
				err := json.Unmarshal([]byte(dbgMsg), &blah)
				if err == nil {
					switch blah.Type {
					case hooks.MSG_EVENT: // Event
						hookCfg.ParseEvent(blah.Event)
					case hooks.MSG_STATUS: //Status
						//fmt.Println(blah.Status)
					case hooks.MSG_MODULE: //Module
						//fmt.Println(blah.Module)
					}

					return
				}
				if dSess.DebugOutput {
					dSess.Logger.WriteDebug(dbgMsg)
				}
			}

			go hookCfg.Monitor()
			time.Sleep(100 * time.Millisecond)

			if injectThread {
				err = hookCfg.InjectRemoteThread(*dSess.ProcessHandle, filepath.Join(hookCfg.LibDir, hookCfg.HookDll))
				if err != nil {
					hookCfg.Logger.WriteErr(err)
				} else {
					hookCfg.Logger.WriteInfo("process import table patched, hooks in place")
				}
			} else {

				err = hookCfg.InjectIAT(*dSess.ProcessHandle, filepath.Join(hookCfg.LibDir, hookCfg.HookDll))
				if err != nil {
					hookCfg.Logger.WriteErr(err)
				} else {
					hookCfg.Logger.WriteInfo("process import table patched, hooks in place")
				}
			}
		}
		//////////////////////////////////

		time.Sleep(100 * time.Millisecond)

		if doPause {
			mainLogger.WriteInfo("Press 'Enter' to resume the process ...")
			bufio.NewReader(os.Stdin).ReadBytes('\n')
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
	rootCmd.AddCommand(spawnCmd)
	spawnCmd.Flags().StringP("spawn", "s", "", "cmdline to spawn a process")
	spawnCmd.Flags().StringP("spawn-env", "e", "", "environment vars for spawned a process")
	spawnCmd.Flags().StringP("spawn-dir", "d", "", "startup directory for spawned a process")
	spawnCmd.Flags().BoolP("spawn-pause", "p", false, "include a key press pause before resuming the process")
	spawnCmd.Flags().BoolP("inject-remotethread", "t", false, "use a CreateRemoteThread based injection. Default is Import Table injection.")
	spawnCmd.Flags().StringP("override", "O", "", "override rules with a user specified matcher")
	spawnCmd.Flags().StringP("append", "a", "", "append a user specified matcher to all rules")
	spawnCmd.Flags().BoolP("no-rules", "R", false, "disable rule checks, helpful for rule dev (lotsa output)")
	spawnCmd.Flags().BoolP("no-inject", "I", false, "dont inject the hooking dll")
	spawnCmd.Flags().BoolP("no-etw", "E", false, "dont monitor ETW events")
	spawnCmd.Flags().BoolP("rule-dev", "D", false, "print the final rule queries passed to expr (for rule dev)")
	spawnCmd.Flags().BoolP("very-verbose", "V", false, "include ETW EventData + Metadata JSON output (useful for writing rules)")

}
