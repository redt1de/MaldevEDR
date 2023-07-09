/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/dbgproc"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/spf13/cobra"
)

// etwCmd represents the etw command
var etwCmd = &cobra.Command{
	Use:   "etw",
	Short: "Monitor ETW channels for malicious events",
	Long:  `??????????????????????????????????????????????????????? do later`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		edr, err := config.NewEdr(configPath)
		if err != nil {
			log.Fatal(err)
		}

		cfg := edr.Etw
		ewatch.EtwInit(&cfg)
		outfile, _ := cmd.Flags().GetString("output")
		cfg.Logger.LogFile = outfile

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
		doSpawn, _ := cmd.Flags().GetString("spawn")
		spawnEnv, _ := cmd.Flags().GetString("spawn-env")
		shutdown := make(chan bool)
		if doSpawn != "" {
			dSess, err := dbgproc.NewDebugProcess(doSpawn, spawnEnv, true)
			if err != nil {
				cfg.Logger.WriteFatal(err)
			}
			cfg.Logger.WriteInfo("Creating debug process:", dSess.ProcessImage, "PID:", dSess.ProcessId)
			cfg.Spawn = dSess

			cfg.Spawn.ExitProcessCB = func(ep dbgproc.ExitProcess) {
				// keep the process alive until we say so, so we can lookup data in late etw events
				cfg.Logger.WriteInfo("Process exit requested, waiting for late events")
				time.Sleep(3 * time.Second)
				shutdown <- true
			}

			go cfg.Start()

			// time.Sleep(1000 * time.Millisecond)
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

		} else {
			go func() {
				err := cfg.Start()
				if err != nil {
					cfg.Logger.WriteFatal(err)
				}

			}()

			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			for range c {
				cfg.Logger.WriteInfo("Recieved CTRL-C, shutting down...")
				break
			}

		}
		cfg.Stop()

	},
}

func init() {
	rootCmd.AddCommand(etwCmd)
	etwCmd.Flags().BoolP("no-rules", "N", false, "disable rule checks, helpful for rule dev (lotsa output)")
	etwCmd.Flags().BoolP("verbose", "v", false, "include EventData JSON output")
	etwCmd.Flags().BoolP("very-verbose", "V", false, "include EventData + Metadata JSON output (useful for writing rules)")
	// etwCmd.Flags().BoolP("kernel", "K", false, "Kernel mode providers, requires kernel mode via kdu.exe -pse")
	etwCmd.Flags().BoolP("rule-dev", "R", false, "print the final rule queries passed to expr (for rule dev)")
	// etwCmd.Flags().StringP("config", "c", "./etw.yaml", "Path to ETW config file.")
	etwCmd.Flags().StringP("override", "O", "", "override all rules with a user specified matcher")
	etwCmd.Flags().StringP("append", "a", "", "append a matcher to all rules")
	etwCmd.Flags().StringP("spawn", "s", "", "cmdline to spawn a process")
	etwCmd.Flags().StringP("spawn-env", "e", "", "environment vars for spawned a process")
}
