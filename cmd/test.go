/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/Microsoft/go-winio"
	"github.com/redt1de/MaldevEDR/pkg/ewatch/etw"
	"github.com/spf13/cobra"
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		pipePath := `\\.\pipe\MalDevEDR\events`
		f, err := winio.DialPipe(pipePath, nil)
		if err != nil {
			log.Fatalf("error opening pipe: %v", err)
		}
		defer f.Close()

		for {
			d := json.NewDecoder(f)

			var event etw.Event
			err = d.Decode(&event)
			if err != nil {
				fmt.Println(err)
				break
			}
			fmt.Println(event.System.Channel)
		}
		// var b []byte
		// _, err = f.Read(b)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Println(string(b))

		////////////////////////////////////////////

		// n, err := f.Write([]byte("message from client!"))
		// if err != nil {
		// 	log.Fatalf("write error: %v", err)
		// }
		// log.Println("wrote:", n)
	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// testCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// testCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
