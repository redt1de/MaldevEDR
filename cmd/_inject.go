/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/hooks"
	"github.com/spf13/cobra"
)

// injectCmd represents the inject command
var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Inject a monitoring DLL into a target process",
	Long:  `???????????????????????????????????????????`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		outfile, _ := cmd.Flags().GetString("output")
		verbose1, _ := cmd.Flags().GetBool("verbose")
		doSpawn, _ := cmd.Flags().GetString("spawn")
		spawnEnv, _ := cmd.Flags().GetString("spawn-env")
		doPid, _ := cmd.Flags().GetUint32("pid")
		custDll, _ := cmd.Flags().GetString("dll")
		noRules, _ := cmd.Flags().GetBool("no-rules")

		edrCfg, err := config.NewEdr(configPath)
		if err != nil {
			log.Fatal(err)
		}

		hookCfg := &edrCfg.Hooks
		hooks.HookerInit(hookCfg)
		hookCfg.Logger.LogFile = outfile
		hookCfg.Verbose = verbose1
		hookCfg.DisableRules = noRules

		if doSpawn != "" {
			shutdown := make(chan bool)
			dSess, err := dbgproc.NewDebugProcess(doSpawn, spawnEnv, true)
			dSess.Logger.LogFile = outfile
			if err != nil {
				dSess.Logger.WriteFatal(err)
			}
			dSess.ExitProcessCB = func(ep dbgproc.ExitProcess) {
				// keep the process alive until we say so, so we can lookup data in late etw events
				dSess.Logger.WriteInfo("Process exit requested, waiting for late events")
				time.Sleep(2 * time.Second)
				shutdown <- true
			}
			dSess.Error = func(e error) {
				if !strings.Contains(e.Error(), "The handle is invalid") {
					dSess.Logger.WriteErr(e)
				}
			}
			dSess.Logger.WriteInfo("Creating debug process:", dSess.ProcessImage, "PID:", dSess.ProcessId)

			go hookCfg.Monitor()

			time.Sleep(100 * time.Millisecond)

			dllpath := filepath.Join(hookCfg.LibDir, hookCfg.HookDll)
			if custDll != "" {
				dllpath = custDll
			}
			err = hookCfg.Inject(*dSess.ProcessHandle, dllpath)
			if err != nil {
				hookCfg.Logger.WriteErr(err)
				hookCfg.Stop()
				proc, err := os.FindProcess(int(dSess.ProcessId))
				if err != nil {
					hookCfg.Logger.Write("failed to terminate spawned process:", err)
				}
				proc.Kill()
				os.Exit(1)
			}
			hookCfg.Logger.WriteInfo("process import table patched, hooks in place")

			go dSess.Resume()

			c := make(chan os.Signal, 1)
			go func() {
				signal.Notify(c, os.Interrupt)
				for range c {
					hookCfg.Logger.WriteInfo("Recieved CTRL-C, shutting down...")
					hookCfg.Stop()
					proc, err := os.FindProcess(int(dSess.ProcessId))
					if err != nil {
						hookCfg.Logger.Write("failed to terminate spawned process:", err)
					}
					proc.Kill()
					os.Exit(0)
				}
			}()
			<-shutdown
			hookCfg.Logger.WriteInfo("Shutting down...")
			hookCfg.Stop()
		} else if doPid > 0 {
			hookCfg.Logger.WriteFatal("TODO: implement pid based dll injection hooks")

		} else {
			hookCfg.Logger.WriteFatal("you must specify --pid or --spawn")
		}

	},
}

func init() {
	rootCmd.AddCommand(injectCmd)
	injectCmd.Flags().StringP("spawn", "s", "", "cmdline to spawn a process")
	injectCmd.Flags().StringP("spawn-env", "e", "", "environment vars for spawned a process")
	injectCmd.Flags().StringP("dll", "d", "", "inject a custom DLL")
	injectCmd.Flags().Uint32P("pid", "p", 0, "injection into process by PID")
	injectCmd.Flags().BoolP("verbose", "v", false, "verbose")
	injectCmd.Flags().BoolP("no-rules", "N", false, "disable rule checks, helpful for rule dev (lotsa output)")
}
