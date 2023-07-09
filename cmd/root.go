/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "MaldevEDR",
	Short: "A pseudo EDR for malware development",
	Long: `!! This is not a real EDR solution, do not use in a production environtment !! 
This tool simply provides information that is helpful during red team malware development. `,
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "./config.yaml", "path to config file")
	rootCmd.PersistentFlags().StringP("output", "o", "", "log output to a file")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "be verbose")
}
