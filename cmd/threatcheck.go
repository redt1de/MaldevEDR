package cmd

import (
	"log"

	"github.com/redt1de/MaldevEDR/pkg/threatcheck"
	"github.com/redt1de/MaldevEDR/pkg/util"
	"github.com/spf13/cobra"
)

// threatcheckCmd represents the threatcheck command
var threatcheckCmd = &cobra.Command{
	Use:   "threatcheck",
	Short: "Go implementation of Rasta Mouse's ThreatCheck",
	Long:  `Scans a file using Defenders command line, splits the file until the bad bytes are identified.`,
	Run: func(cmd *cobra.Command, args []string) {
		fPath, _ := cmd.Flags().GetString("file")
		if !util.FileReadable(fPath) {
			log.Fatal("failed open mal file")
		}

		verbose, _ := cmd.Flags().GetBool("verbose")
		defender := threatcheck.NewDefender()
		if verbose {
			defender.Logger.DebugEnable()
		}
		outfile, _ := cmd.Flags().GetString("output")
		defender.Logger.SetLogFile(outfile)

		defender.AnalyzeFile(fPath)

	},
}

func init() {
	rootCmd.AddCommand(threatcheckCmd)
	threatcheckCmd.Flags().StringP("file", "f", "", "malicious file to analyze")
	threatcheckCmd.Flags().StringP("output", "o", "", "log output to a file")
	threatcheckCmd.Flags().BoolP("verbose", "v", false, "be verbose")
}
