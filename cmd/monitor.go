/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"os/signal"

	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/hooks"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"github.com/spf13/cobra"
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Just monitor ETW and the hook pipe.",
	Long:  `this command does not spawn,attach,inject anything. It just monitors for events system wide.`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		outfile, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")
		noEtw, _ := cmd.Flags().GetBool("no-etw")
		noInject, _ := cmd.Flags().GetBool("no-hooks")
		noRules, _ := cmd.Flags().GetBool("no-rules")
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
		////////////// ETW
		etwCfg := edrCfg.Etw
		if !noEtw {
			ewatch.EtwInit(&etwCfg)
			etwCfg.DisableRules = noRules
			etwCfg.Append = doAppend
			etwCfg.Override = doOverride
			etwCfg.Logger.LogFile = outfile
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
		}

		c := make(chan os.Signal, 1)
		go func() {
			signal.Notify(c, os.Interrupt)
			for range c {
				mainLogger.WriteInfo("Recieved CTRL-C, shutting down...")
				shutdown <- true
			}
		}()

		<-shutdown
		mainLogger.WriteInfo("Shutting down...")
		if !noEtw {
			etwCfg.Stop()
		}
		if !noInject {
			hookCfg.Stop()
		}

	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().StringP("override", "O", "", "override rules with a user specified matcher")
	monitorCmd.Flags().StringP("append", "a", "", "append a user specified matcher to all rules")
	monitorCmd.Flags().BoolP("no-rules", "R", false, "disable rule checks, helpful for rule dev (lotsa output)")
	monitorCmd.Flags().BoolP("no-hooks", "I", false, "dont monitor the hook dll pipe")
	monitorCmd.Flags().BoolP("no-etw", "E", false, "dont monitor ETW events")
	monitorCmd.Flags().BoolP("rule-dev", "D", false, "print the final rule queries passed to expr (for rule dev)")
	monitorCmd.Flags().BoolP("very-verbose", "V", false, "include ETW EventData + Metadata JSON output (useful for writing rules)")

}
